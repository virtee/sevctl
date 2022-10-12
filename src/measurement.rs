// SPDX-License-Identifier: Apache-2.0

use structopt::StructOpt;

use anyhow::Context;

#[derive(StructOpt)]
pub enum MeasurementCmd {
    Build(BuildArgs),
}

#[derive(StructOpt, std::fmt::Debug)]
pub struct BuildArgs {
    #[structopt(long, help = "SEV host API major (int or hex)")]
    pub api_major: String,

    #[structopt(long, help = "SEV host API minor (int or hex)")]
    pub api_minor: String,

    #[structopt(long, help = "SEV host build ID (int or hex)")]
    pub build_id: String,

    #[structopt(long, help = "SEV guest policy (int or hex)")]
    pub policy: String,

    #[structopt(long, help = "Expected nonce (path or base64)")]
    pub nonce: String,

    #[structopt(long, help = "tik data (path or base64)")]
    pub tik: String,

    #[structopt(long, help = "Launch digest in base64")]
    pub launch_digest: Option<String>,

    #[structopt(long, help = "Optionally write binary content to filename")]
    pub outfile: Option<String>,
}

fn build_digest(args: &BuildArgs) -> super::Result<Vec<u8>> {
    if let Some(ld) = &args.launch_digest {
        return base64::decode(ld).context("failed to base64 decode --launch-digest");
    }
    Err(anyhow::anyhow!("--launch-digest must be specified."))
}

fn parse_hex_or_int(argname: &str, val: &str) -> super::Result<u32> {
    // Adapted from clap_num crate
    let result = if val.to_ascii_lowercase().starts_with("0x") {
        u32::from_str_radix(&val["0x".len()..], 16)
    } else {
        val.parse::<u32>()
    };

    match result {
        Ok(v) => Ok(v),
        _ => Err(anyhow::anyhow!(
            "{}={} value must be int or hex",
            argname,
            val
        )),
    }
}

fn parse_base64_or_path(argname: &str, val: &str) -> super::Result<Vec<u8>> {
    let result = if std::fs::metadata(val).is_ok() {
        std::fs::read(val).context(format!("reading path {}={} failed", argname, val))
    } else {
        base64::decode(val).context(format!("failed to base64 decode {}={}", argname, val))
    };

    match result {
        Ok(v) => {
            log::debug!("{} base64: {}", argname, base64::encode(&v));
            Ok(v)
        }
        Err(e) => Err(e),
    }
}

pub fn build_cmd(args: BuildArgs) -> super::Result<()> {
    let mut data: Vec<u8> = Vec::new();

    let digest = build_digest(&args)?;

    let api_major = parse_hex_or_int("--api-major", &args.api_major)?;
    let api_minor = parse_hex_or_int("--api-minor", &args.api_minor)?;
    let build_id = parse_hex_or_int("--build-id", &args.build_id)?;
    let policy = parse_hex_or_int("--policy", &args.policy)?;

    let nonce = parse_base64_or_path("--nonce", &args.nonce)?;
    let tik = parse_base64_or_path("--tik", &args.tik)?;

    data.push(0x4_u8);
    data.push(api_major.to_le_bytes()[0]);
    data.push(api_minor.to_le_bytes()[0]);
    data.push(build_id.to_le_bytes()[0]);
    data.extend(&policy.to_le_bytes());
    data.extend(digest);
    data.extend(&nonce);

    log::debug!("Raw measurement: {}", base64::encode(&data));

    let key = openssl::pkey::PKey::hmac(&tik)?;
    let mut sig = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;

    sig.update(&data[..])?;
    let out = sig.sign_to_vec()?;
    log::debug!("Signed measurement: {}", base64::encode(&out));

    if let Some(outfile) = &args.outfile {
        std::fs::write(outfile, &out)
            .context(format!("failed to write to --outfile={}", outfile))?;
        println!("Wrote outfile: {}", outfile);
    } else {
        println!("{}", base64::encode(out));
    }

    Ok(())
}
