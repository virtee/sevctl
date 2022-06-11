// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use structopt::StructOpt;

use anyhow::Context;

#[derive(StructOpt)]
pub enum MeasurementCmd {
    Build(BuildArgs),
}

#[derive(StructOpt, std::fmt::Debug)]
pub struct BuildArgs {
    #[structopt(long, help = "SEV host API major number")]
    pub api_major: u8,

    #[structopt(long, help = "SEV host API minor number")]
    pub api_minor: u8,

    #[structopt(long, help = "SEV host build ID number")]
    pub build_id: u8,

    #[structopt(long, help = "SEV guest policy integer value")]
    pub policy: u32,

    #[structopt(long, help = "Expected nonce in base64")]
    pub nonce: String,

    #[structopt(long, parse(from_os_str), help = "Path to tik file")]
    pub tik: PathBuf,

    #[structopt(long, help = "Launch digest in base64")]
    pub launch_digest: Option<String>,
}

fn build_digest(args: &BuildArgs) -> super::Result<Vec<u8>> {
    if let Some(ld) = &args.launch_digest {
        return base64::decode(ld).context("failed to base64 decode --launch-digest");
    }
    Err(anyhow::anyhow!("--launch-digest must be specified."))
}

pub fn build_cmd(args: BuildArgs) -> super::Result<()> {
    let mut data: Vec<u8> = Vec::new();

    let digest = build_digest(&args)?;

    let nonce = base64::decode(args.nonce).context("failed to base64 decode --nonce")?;
    let tik =
        std::fs::read(&args.tik).context(format!("failed to read file: {}", args.tik.display()))?;

    data.push(0x4_u8);
    data.push(args.api_major);
    data.push(args.api_minor);
    data.push(args.build_id);
    data.extend(args.policy.to_le_bytes());
    data.extend(digest);
    data.extend(&nonce);

    log::debug!("Raw measurement: {}", base64::encode(&data));

    let key = openssl::pkey::PKey::hmac(&tik)?;
    let mut sig = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;

    sig.update(&data[..])?;
    let out = sig.sign_to_vec()?;

    println!("{}", base64::encode(out));
    Ok(())
}
