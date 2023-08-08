// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::path::{Path, PathBuf};

use structopt::StructOpt;

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
    pub nonce: Option<String>,
    #[structopt(
        long,
        help = "Extract nonce from output of LAUNCH_MEASURE firmware command, such as reported by qemu query-sev-launch-measure or virsh domlaunchsecinfo (path or base64)"
    )]
    pub launch_measure_blob: Option<String>,

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

    #[structopt(long, help = "Number of virtual CPUs")]
    pub num_cpus: Option<u32>,
    #[structopt(long, help = "path to VMSA state for boot CPU")]
    pub vmsa_cpu0: Option<PathBuf>,
    #[structopt(long, help = "path to VMSA state for additional CPUs")]
    pub vmsa_cpu1: Option<PathBuf>,

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

pub fn build_entry(
    guid: uuid::Uuid,
    payload: Vec<u8>,
    entry_size: usize,
) -> super::Result<Vec<u8>> {
    let mut entry: Vec<u8> = Vec::new();
    let header = guid.to_bytes_le();
    let len = header.len() + payload.len() + entry_size;

    entry.extend(&header);
    entry.extend(&len.to_le_bytes()[..entry_size]);
    entry.extend(&payload);

    sha256_bytes(&entry, "entry")?;
    Ok(entry)
}

pub fn build_table(
    guid: uuid::Uuid,
    payload: Vec<u8>,
    entry_size: usize,
) -> super::Result<Vec<u8>> {
    let mut table = build_entry(guid, payload, entry_size)?;
    let pad = ((table.len() + 16 - 1) & !(16 - 1)) - table.len();
    table.extend(vec![0; pad]);
    Ok(table)
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

    let entry_size = 2;
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
        entry_size,
    )?);
    payload.extend(build_entry(initrd_uuid, sha256_path(initrd)?, entry_size)?);
    payload.extend(build_entry(kernel_uuid, sha256_path(kernel)?, entry_size)?);
    sha256_bytes(&payload, "table payload")?;

    let table = build_table(table_uuid, payload, entry_size)?;

    sha256_bytes(&table, "table")?;
    Ok(table)
}

fn build_cpu_state(args: &BuildArgs, policy: &u32) -> super::Result<Vec<u8>> {
    // Check if SEV-ES policy bit is set
    if (*policy & 0x04) == 0 {
        return Ok(Vec::new());
    }

    if args.num_cpus.is_none() {
        return Err(anyhow::anyhow!(
            "SEV-ES policy bit is set, CPU/VMSA info must be specified"
        ));
    }

    if args.vmsa_cpu0.is_none() || args.vmsa_cpu1.is_none() {
        return Err(anyhow::anyhow!(
            "--num-cpus, --vmsa-cpu0, --vmsa-cpu1 must be specified together"
        ));
    }

    let num_cpus = args.num_cpus.as_ref().unwrap();
    let vmsa_cpu0_filename = args.vmsa_cpu0.as_ref().unwrap();
    let vmsa_cpu1_filename = args.vmsa_cpu1.as_ref().unwrap();
    let vmsa_cpu0 = std::fs::read(vmsa_cpu0_filename).context(format!(
        "failed to read file: {}",
        vmsa_cpu0_filename.display()
    ))?;
    let vmsa_cpu1 = std::fs::read(vmsa_cpu1_filename).context(format!(
        "failed to read file: {}",
        vmsa_cpu1_filename.display()
    ))?;

    let mut ret: Vec<u8> = Vec::new();
    ret.extend(vmsa_cpu0);

    let mut count = std::cmp::max(num_cpus - 1, 0);
    while count > 0 {
        ret.extend(&vmsa_cpu1);
        count -= 1;
    }

    Ok(ret)
}

fn build_digest(args: &BuildArgs, policy: &u32) -> super::Result<Vec<u8>> {
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
    content.extend(build_cpu_state(args, policy)?);

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

pub fn parse_base64_or_path(argname: &str, val: &str) -> super::Result<Vec<u8>> {
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

    let policy = parse_hex_or_int("--policy", &args.policy)?;

    let digest = build_digest(&args, &policy)?;

    let api_major = parse_hex_or_int("--api-major", &args.api_major)?;
    let api_minor = parse_hex_or_int("--api-minor", &args.api_minor)?;
    let build_id = parse_hex_or_int("--build-id", &args.build_id)?;
    let tik = parse_base64_or_path("--tik", &args.tik)?;

    let nonce;
    if let Some(nonce_arg) = args.nonce {
        nonce = parse_base64_or_path("--nonce", &nonce_arg)?;
    } else if let Some(launch_measure_blob_arg) = args.launch_measure_blob {
        let blob = parse_base64_or_path("--launch-measure-blob", &launch_measure_blob_arg)?;
        nonce = blob[32..].to_vec();
    } else {
        return Err(anyhow::anyhow!(
            "One of --nonce or --launch-measure-blob must be specified."
        ));
    }

    /* This is duplicating logic found in sev::session::Session::verify(),
     * but we need sev crate API changes to access it for outputting
     * like this. */
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
    let mut out = sig.sign_to_vec()?;
    log::debug!("Signed measurement: {}", base64::encode(&out));
    out.extend(&nonce);
    log::debug!("Measurement + nonce: {}", base64::encode(&out));

    if let Some(outfile) = &args.outfile {
        std::fs::write(outfile, &out)
            .context(format!("failed to write to --outfile={}", outfile))?;
        println!("Wrote outfile: {}", outfile);
    } else {
        println!("{}", base64::encode(out));
    }

    Ok(())
}
