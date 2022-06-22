// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

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

    #[structopt(long, help = "Path to firmware/OVMF binary")]
    pub firmware: Option<PathBuf>,
    #[structopt(long, help = "Path to kernel")]
    pub kernel: Option<PathBuf>,
    #[structopt(long, help = "Path to initrd")]
    pub initrd: Option<PathBuf>,
    #[structopt(long, help = "Kernel commandline")]
    pub cmdline: Option<String>,

    #[structopt(long, help = "Optionally write binary content to filename")]
    pub outfile: Option<String>,
}

fn sha256_bytes(content: &[u8], logname: &str) -> super::Result<Vec<u8>> {
    #![allow(clippy::unnecessary_wraps)]
    let mut hash = openssl::sha::Sha256::new();
    hash.update(content);
    let out = hash.finish();

    let mut shastr = String::new();
    for c in out.iter() {
        shastr.push_str(format!("{:02x}", c).as_str());
    }
    log::debug!("{} len={} sha256: {}", logname, content.len(), shastr);
    Ok(out.to_vec())
}

fn sha256_path(path: &Path) -> super::Result<Vec<u8>> {
    let content =
        std::fs::read(path).context(format!("failed to read file: {}", path.display()))?;
    let logname = path.file_name().unwrap().to_str().unwrap();
    sha256_bytes(&content, logname)
}

fn build_entry(guid: uuid::Uuid, payload: Vec<u8>) -> super::Result<Vec<u8>> {
    let mut entry: Vec<u8> = Vec::new();
    let header = guid.to_bytes_le();
    let len = header.len() + payload.len() + 2;

    entry.extend(&header);
    entry.extend(&(len as u16).to_le_bytes());
    entry.extend(&payload);

    sha256_bytes(&entry, "entry")?;
    Ok(entry)
}

fn build_kernel_table(args: &BuildArgs) -> super::Result<Vec<u8>> {
    if args.kernel.is_none() {
        return Ok(Vec::new());
    }

    if args.initrd.is_none() || args.cmdline.is_none() {
        return Err(anyhow::anyhow!(
            "--kernel, --initrd, --cmdline must be specified together"
        ));
    }

    let kernel = args.kernel.as_ref().unwrap();
    let initrd = args.initrd.as_ref().unwrap();
    let cmdline = args.cmdline.as_ref().unwrap();

    let table_uuid = uuid::Uuid::parse_str("9438d606-4f22-4cc9-b479-a793d411fd21")?;
    let kernel_uuid = uuid::Uuid::parse_str("4de79437-abd2-427f-b835-d5b172d2045b")?;
    let initrd_uuid = uuid::Uuid::parse_str("44baf731-3a2f-4bd7-9af1-41e29169781d")?;
    let cmdline_uuid = uuid::Uuid::parse_str("97d02dd8-bd20-4c94-aa78-e7714d36ab2a")?;

    // cmdline needs a trailing NUL byte
    let mut cmdline_bytes = cmdline.to_owned().into_bytes();
    cmdline_bytes.push(0);

    let mut payload: Vec<u8> = Vec::new();
    payload.extend(build_entry(
        cmdline_uuid,
        sha256_bytes(&cmdline_bytes, "cmdline")?,
    )?);
    payload.extend(build_entry(initrd_uuid, sha256_path(initrd)?)?);
    payload.extend(build_entry(kernel_uuid, sha256_path(kernel)?)?);
    sha256_bytes(&payload, "table payload")?;

    let mut table = build_entry(table_uuid, payload)?;
    let pad = 16 - (table.len() % 16);
    table.extend(vec![0; pad]);

    sha256_bytes(&table, "table")?;
    Ok(table)
}

fn build_digest(args: &BuildArgs) -> super::Result<Vec<u8>> {
    if let Some(ld) = &args.launch_digest {
        return base64::decode(ld).context("failed to base64 decode --launch-digest");
    }

    if args.firmware.is_none() {
        return Err(anyhow::anyhow!(
            "One of --firmware or --launch-digest must be specified."
        ));
    }

    let firmware = args.firmware.as_ref().unwrap();
    let mut content =
        std::fs::read(firmware).context(format!("failed to read file: {}", &firmware.display()))?;

    content.extend(build_kernel_table(args)?);

    sha256_bytes(&content, "firmware + table")
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
