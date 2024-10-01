// SPDX-License-Identifier: Apache-2.0

use super::*;

use crate::measurement;

use std::convert::TryFrom;

struct SecretPair {
    uuid: uuid::Uuid,
    secret: Vec<u8>,
}

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Build the Secret
    Build(BuildArgs),
}

#[derive(Parser, std::fmt::Debug)]
pub struct BuildArgs {
    /// tik data (path or base64)
    #[arg(long, value_name = "tik")]
    pub tik: String,

    /// tek data (path or base64)
    #[arg(long, value_name = "tek")]
    pub tek: String,

    /// Output from LAUNCH_MEASURE firmware command (such as via qemu or libvirt), or `sevctl measurement build` (path or base64)
    #[arg(long, value_name = "launch-measure")]
    pub launch_measure_blob: String,

    // Hidden CLI option to make --iv deterministic, for testing
    #[arg(long, value_name = "iv", hide = true)]
    pub iv: Option<String>,

    /// Secret values to inject. Format is UUID:/path/to/secret.txt", number_of_values = 1
    #[arg(long, value_name = "secret", number_of_values = 1)]
    pub secret: Vec<String>,

    /// Path to output secret header file
    #[arg(value_name = "header-file", required = true)]
    header_file: String,

    /// Path to output secret payload file
    #[arg(value_name = "payload-file", required = true)]
    payload_file: String,
}

fn build_secrets_table(secrets: Vec<SecretPair>) -> super::Result<Vec<u8>> {
    let entry_size: usize = 4;
    let mut payload: Vec<u8> = Vec::new();

    for secretpair in &secrets {
        payload.extend(measurement::build_entry(
            secretpair.uuid,
            secretpair.secret.to_vec(),
            entry_size,
        )?);
    }

    let table_uuid = uuid::Uuid::parse_str("1e74f542-71dd-4d66-963e-ef4287ff173b")?;
    let table = measurement::build_table(table_uuid, payload, entry_size)?;

    Ok(table)
}

/* Parse --secret option(s) into Vec of SecretPair */
fn parse_secrets(secrets: Vec<String>) -> super::Result<Vec<SecretPair>> {
    let mut ret: Vec<SecretPair> = Vec::new();

    for secret_string in &secrets {
        let idx = secret_string
            .find(':')
            .ok_or_else(|| anyhow::anyhow!("Unexpected --secret format"))?;
        let uuid_str = &secret_string[..idx];
        let filename = &secret_string[idx + 1..];
        let uuid = uuid::Uuid::parse_str(uuid_str)
            .context(format!("failed to parse string as UUID: {}", uuid_str))?;
        let secret =
            std::fs::read(filename).context(format!("reading secret path {} failed", filename))?;
        ret.push(SecretPair { uuid, secret });
    }

    Ok(ret)
}

/* Read --iv from command line, or generate it */
fn get_iv(arg_iv: Option<String>) -> super::Result<Vec<u8>> {
    if let Some(iv_b64) = arg_iv {
        base64::decode(iv_b64).context("failed to base64 decode --iv")
    } else {
        let mut ivrand = [0u8; 16];
        openssl::rand::rand_bytes(&mut ivrand)?;

        Ok(Vec::<u8>::from(ivrand))
    }
}

/* Peel measurement piece off of --launch-measure-blob data */
fn get_measurement(launch_measure_blob_arg: String) -> super::Result<Vec<u8>> {
    let blob =
        measurement::parse_base64_or_path("--launch-measure-blob", &launch_measure_blob_arg)?;
    Ok(blob[..32].to_vec())
}

pub fn build_cmd(args: BuildArgs) -> super::Result<()> {
    let flags: u32 = 0;
    let tek = measurement::parse_base64_or_path("--tek", &args.tek)?;
    let tik = measurement::parse_base64_or_path("--tik", &args.tik)?;
    let secrets = parse_secrets(args.secret)?;
    let iv = get_iv(args.iv)?;
    let measurement = get_measurement(args.launch_measure_blob)?;

    let secrets_table = build_secrets_table(secrets)?;
    let secrets_cipher = openssl::symm::encrypt(
        openssl::symm::Cipher::aes_128_ctr(),
        &tek,
        Some(&iv),
        &secrets_table,
    )?;
    log::debug!("secrets cipher base64: {}", base64::encode(&secrets_cipher));

    // AMD Secure Encrypted Virtualization API , section 6.6
    let mut msg: Vec<u8> = Vec::new();
    let table_len = u32::try_from(secrets_table.len())?;
    msg.push(0x01);
    msg.extend(&flags.to_le_bytes());
    msg.extend(&iv);
    msg.extend(&table_len.to_le_bytes());
    msg.extend(&table_len.to_le_bytes());
    msg.extend(&secrets_cipher);
    msg.extend(&measurement);
    log::debug!("payload msg base64: {}", base64::encode(&msg));

    // Sign message with tik
    let key = openssl::pkey::PKey::hmac(&tik)?;
    let mut sig = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;
    sig.update(&msg[..])?;

    // Table 55. LAUNCH_SECRET Packet Header Buffer
    let mut header: Vec<u8> = Vec::new();
    header.extend(&flags.to_le_bytes());
    header.extend(iv);
    header.extend(sig.sign_to_vec()?);
    log::debug!("header base64: {}", base64::encode(&header));

    std::fs::write(&args.header_file, header).context(format!(
        "failed to write to header to {}",
        &args.header_file
    ))?;
    println!("Wrote header to: {}", &args.header_file);

    std::fs::write(&args.payload_file, secrets_cipher).context(format!(
        "failed to write to payload to {}",
        &args.payload_file
    ))?;
    println!("Wrote payload to: {}", &args.payload_file);
    Ok(())
}
