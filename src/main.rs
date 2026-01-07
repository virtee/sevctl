// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod measurement;
mod ok;
mod secret;
mod session;
mod validate;
mod vmsa;

use crate::vmsa::*;

use std::{
    fs::File,
    io::{self, Cursor},
    path::PathBuf,
    process::exit,
    time::Duration,
};

use ::sev::{
    certs::sev::{
        ca::Chain as CertSevCaChain,
        sev::{Certificate, Chain, Usage as SevUsage},
        Chain as CertSevChain, Usage,
    },
    firmware::host::{Firmware, PlatformStatusFlags, Status},
    Generation,
};

use anyhow::{Context, Result};
use clap::{arg, Parser, Subcommand, ValueEnum};
use codicon::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Sevctl {
    #[command(subcommand)]
    pub cmd: SevctlCmd,

    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum SevctlCmd {
    /// Add the cek certificate to a partial certificate chain returned by the PSP
    Addcek {
        /// Read SEV partial chain from specified file
        #[arg(short, long, value_name = "crt", required = true)]
        crt: PathBuf,

        /// Id of the processor to get the CEK
        #[arg(short, long, value_name = "id", required = true)]
        id: String,

        /// Output file
        #[arg(long, value_name = "dst")]
        dst: Option<PathBuf>,
    },
    /// Export the SEV or entire certificate chain
    Export {
        /// Export the entire certificate chain? (SEV + CA chain)
        #[arg(short, long, default_value_t = false)]
        full: bool,

        /// Certificate chain output file path
        #[arg(value_name = "destination", required = true)]
        destination: PathBuf,
    },

    /// Get latest firmware
    Firmware {
        /// firmware output file path
        #[arg(short, long, value_name = "out", required = false)]
        out: Option<PathBuf>,
    },

    /// Generate a new self-signed OCA certificate and key
    Generate {
        /// OCA certificate output file path
        #[arg(value_name = "cert", required = true)]
        cert: PathBuf,

        /// OCA key output file path
        #[arg(value_name = "key", required = true)]
        key: PathBuf,
    },

    /// Probe system for SEV support
    Ok {
        /// SEV generation
        #[arg(value_name = "gen")]
        gen: Option<ok::SevGeneration>,
    },

    /// Take ownership of the SEV platform
    Provision {
        /// Path to the owner's OCA certificate.
        #[arg(value_name = "cert", required = true)]
        cert: PathBuf,

        /// Path to the owner's OCA private key.
        #[arg(value_name = "key", required = true)]
        key: PathBuf,
        /// Path to the PEK input file.
        #[arg(short, long, value_name = "in_pek", required = false)]
        in_pek: Option<PathBuf>,

        /// Path to PEK output file.
        #[arg(short, long, value_name = "out_pek", required = false)]
        out_pek: Option<PathBuf>,
    },

    /// Reset the SEV platform state
    Reset,

    /// Rotate PDH
    Rotate,

    /// Generate a SEV launch session
    Session {
        /// Name used to identify file names
        #[arg(short, long, value_name = "name")]
        name: Option<String>,

        /// Path of the file containing the certificate chain
        #[arg(value_name = "pdh", required = true)]
        pdh: PathBuf,

        /// 32-bit integer representing the launch policy
        #[arg(value_name = "policy", required = true)]
        policy: u32,
    },

    /// Display information about the SEV platform
    Show {
        #[command(subcommand)]
        cmd: show::Show,
    },

    /// Verify certificate chain
    Verify {
        /// Read SEV chain from specified file
        #[arg(long, value_name = "sev")]
        sev: Option<PathBuf>,

        /// Read OCA certificate from specified file
        #[arg(long, value_name = "oca")]
        oca: Option<PathBuf>,

        /// Read CA chain from specified file
        #[arg(long, value_name = "ca")]
        ca: Option<PathBuf>,
    },

    /// Validate subcommands
    Validate {
        /// Path to the SEV cert chain, can be obtained by the `export` subcommand
        #[arg(value_name = "sev-cert-chain", required = true)]
        chain_path: PathBuf,

        /// Path to the attestation report binary file
        #[arg(value_name = "attestation-report", required = true)]
        ar_path: PathBuf,
    },

    /// VMSA-related subcommands
    #[command(subcommand)]
    Vmsa(VmsaCmd),

    /// Measurement subcommands
    #[command(subcommand)]
    Measurement(measurement::MeasurementCmd),

    /// Secret subcommands
    #[command(subcommand)]
    Secret(secret::SecretCmd),
}

async fn download(url: &str) -> Result<Cursor<Vec<u8>>> {
    let mut err_stack: Vec<anyhow::Error> = vec![];

    for attempt in 1..4 {
        match reqwest::get(url).await {
            Ok(rsp) if !rsp.status().is_success() => {
                err_stack.push(
                    anyhow::anyhow!(format!("{:?}", rsp.status()))
                        .context(format!("http request #{} failed", attempt)),
                );
                let retry: Option<u16> = rsp
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().unwrap().parse().ok());
                let retry = retry.unwrap_or(5);
                std::thread::sleep(Duration::from_secs(retry as _));
            }
            Ok(rsp) => match rsp.bytes().await {
                Ok(body) => {
                    return Ok(Cursor::new(body.into_iter().collect::<Vec<u8>>()));
                }
                Err(e) => return Err(anyhow::Error::new(e).context("failed to read response body")),
            },
            Err(e) => return Err(anyhow::Error::new(e).context("transport error")),
        }
    }

    // One last attempt before giving up
    let rsp = reqwest::get(url).await.map_err(|e| {
        let prev_attempts = err_stack
            .into_iter()
            .map(|e| {
                let cause = match e.source() {
                    Some(c) => format!("{}", c),
                    None => "".to_string(),
                };
                format!("{}: {}", e, cause)
            })
            .collect::<Vec<String>>();
        anyhow::anyhow!(prev_attempts.join("; "))
            .context(format!("final http request failed: {}", e))
    })?;

    if !(rsp).status().is_success() {
        return Err(anyhow::anyhow!(format!(
            "Http request {}",
            rsp.status().as_u16()
        )));
    }

    match rsp.bytes().await {
        Ok(body) => {
            return Ok(Cursor::new(body.into_iter().collect::<Vec<u8>>()));
        }
        Err(e) => Err(anyhow::Error::new(e).context("failed to read response body")),
    }
}

fn download_certificate(url: &str, usage: Usage) -> Result<Certificate> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let out = rt.block_on(download(url))?;
    return Certificate::decode(out, ()).context(format!("failed to decode {} certificate", usage));
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

fn platform_status() -> Result<Status> {
    firmware()?
        .platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to fetch platform status")
}

fn chain() -> Result<Chain> {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut chain = firmware()?
        .pdh_cert_export()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to export SEV certificates")?;

    let id = firmware()?
        .get_identifier()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error fetching identifier")?;
    let url = format!("{}/{}", CEK_SVC, id);

    chain.cek = download_certificate(&url, Usage::CEK)?;

    Ok(chain)
}

fn ca_chain_builtin(chain: &Chain) -> Result<CertSevCaChain> {
    use std::convert::TryFrom;

    Generation::try_from(chain)
        .map_err(|_| anyhow::anyhow!("could not find a matching builtin certificate"))
        .context("failed to deduce platform generation")
        .map(|g| g.into())
}

fn main() -> Result<()> {
    env_logger::init();

    let sevctl = Sevctl::parse();
    let status = match sevctl.cmd {
        SevctlCmd::Addcek { crt, id, dst } => addcek::cmd(crt, id, dst),
        SevctlCmd::Export { full, destination } => export::cmd(full, destination),
        SevctlCmd::Firmware { out } => firmware::cmd(out),
        SevctlCmd::Generate { cert, key } => generate::cmd(cert, key),
        SevctlCmd::Ok { gen } => ok::cmd(gen, sevctl.quiet),
        SevctlCmd::Measurement(option) => match option {
            measurement::MeasurementCmd::Build(args) => measurement::build_cmd(args),
        },
        SevctlCmd::Provision {
            cert,
            key,
            in_pek,
            out_pek,
        } => provision::cmd(cert, key, in_pek, out_pek),
        SevctlCmd::Reset => reset::cmd(),
        SevctlCmd::Rotate => rotate::cmd(),
        SevctlCmd::Secret(option) => match option {
            secret::SecretCmd::Build(args) => secret::build_cmd(args),
        },
        SevctlCmd::Session { name, pdh, policy } => session::cmd(name, pdh, policy),
        SevctlCmd::Show { cmd } => show::cmd(cmd),
        SevctlCmd::Verify { sev, oca, ca } => verify::cmd(sevctl.quiet, sev, oca, ca),
        SevctlCmd::Validate {
            chain_path,
            ar_path,
        } => validate::cmd(chain_path, ar_path),
        SevctlCmd::Vmsa(option) => match option {
            VmsaCmd::Build(args) => vmsa::build::cmd(args),
            VmsaCmd::Show(args) => vmsa::show::cmd(args),
            VmsaCmd::Update(args) => vmsa::update::cmd(args),
        },
    };

    if status.is_err() && sevctl.quiet {
        exit(1);
    }

    status
}

mod reset {
    use super::*;

    pub fn cmd() -> Result<()> {
        firmware()?
            .platform_reset()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("error resetting platform")
    }
}

mod show {
    use super::*;

    #[derive(Parser)]
    pub enum Show {
        /// Show the current platform flags
        Flags,

        /// Show the current number of guests
        Guests,

        /// Show the platform identifier
        Identifier,

        /// Show the platform's firmware version
        Version,
    }

    pub fn cmd(show: Show) -> Result<()> {
        let status = platform_status()?;

        match show {
            Show::Version => println!("{}", status.build),
            Show::Guests => println!("{}", status.guests),
            Show::Identifier => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;
                println!("{}", id);
            }
            Show::Flags => {
                for f in [
                    PlatformStatusFlags::OWNED,
                    PlatformStatusFlags::ENCRYPTED_STATE,
                ]
                .iter()
                {
                    println!(
                        "{}",
                        match status.flags.clone() & f.clone() {
                            PlatformStatusFlags::ENCRYPTED_STATE => "es",
                            PlatformStatusFlags::OWNED => "owned",
                            _ => continue,
                        }
                    );
                }
            }
        }

        Ok(())
    }
}

mod export {
    use super::*;
    use std::io::Write;

    pub fn cmd(full: bool, dest: PathBuf) -> Result<()> {
        let chain = chain()?;

        let mut out = Cursor::new(Vec::new());

        if full {
            let full_chain = CertSevChain {
                ca: ca_chain_builtin(&chain)?,
                sev: chain,
            };

            full_chain
                .encode(&mut out, ())
                .context("certificate chain encoding failed")?;
        } else {
            chain
                .encode(&mut out, ())
                .context("certificate chain encoding failed")?;
        }

        let mut file = File::create(dest).context("unable to create output file")?;

        file.write_all(&out.into_inner())
            .context("unable to write output file")?;

        Ok(())
    }
}

mod verify {
    use super::*;

    use ::sev::certs::sev::Verifiable;
    use std::{convert::TryInto, fmt::Display};

    use colorful::*;

    pub fn cmd(
        quiet: bool,
        sev: Option<PathBuf>,
        oca: Option<PathBuf>,
        ca: Option<PathBuf>,
    ) -> Result<()> {
        let mut schain = sev_chain(sev)?;
        let cchain = match ca {
            Some(ca) => ca_chain(ca)?,
            None => ca_chain_builtin(&schain)?,
        };
        let mut err = false;

        if let Some(filename) = oca {
            let mut file = File::open(filename).context("unable to open OCA certificate file")?;

            schain.oca = Certificate::decode(&mut file, ()).context("unable to decode OCA")?;
        }

        if !quiet {
            println!("{}", schain.pdh);
        }
        err |= status("", &schain.pek, &schain.pdh, quiet);
        err |= status("   ", &schain.oca, &schain.pek, quiet);
        err |= status("   ", &schain.cek, &schain.pek, quiet);
        err |= status("      ", &cchain.ask, &schain.cek, quiet);
        err |= status("         ", &cchain.ark, &cchain.ask, quiet);

        if !quiet {
            println!("\n • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs");
        }

        if err as i32 == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("SEV/CA certificate verification failed"))
        }
    }

    fn status<'a, P, C>(pfx: &str, p: &'a P, c: &'a C, quiet: bool) -> bool
    where
        P: Display,
        C: Display,
        &'a P: TryInto<Usage, Error = io::Error>,
        (&'a P, &'a P): Verifiable,
        (&'a P, &'a C): Verifiable,
    {
        let sig_valid = (p, c).verify().is_ok();
        let lnk = if sig_valid {
            "⬑".green()
        } else {
            "⬑̸".red()
        };

        !match p.try_into().unwrap() {
            Usage::OCA | Usage::ARK => {
                let selfsig_valid = (p, p).verify().is_ok();
                let slf = if selfsig_valid {
                    "•".green()
                } else {
                    "•̷".red()
                };
                if !quiet {
                    println!("{}{}{} {}", pfx, slf, lnk, p);
                }
                sig_valid && selfsig_valid
            }

            _ => {
                if !quiet {
                    println!("{} {} {}", pfx, lnk, p);
                }
                sig_valid
            }
        }
    }

    fn sev_chain(filename: Option<PathBuf>) -> Result<Chain> {
        Ok(match filename {
            None => chain()?,
            Some(f) => {
                let mut file =
                    File::open(f).context("unable to open SEV certificate chain file")?;

                Chain::decode(&mut file, ()).context("unable to decode chain")?
            }
        })
    }

    fn ca_chain(filename: PathBuf) -> Result<CertSevCaChain> {
        let mut file = File::open(filename).context("unable to open CA certificate chain file")?;
        CertSevCaChain::decode(&mut file, ()).context("unable to decode chain")
    }
}

mod generate {
    use super::*;
    use ::sev::certs::sev::Signer;

    pub fn cmd(oca_path: PathBuf, key_path: PathBuf) -> Result<()> {
        let (mut oca, prv) =
            Certificate::generate(SevUsage::OCA).context("unable to generate OCA key pair")?;
        prv.sign(&mut oca).context("key signing failed")?;

        // Write the certificate
        let mut crt = File::create(oca_path).context("unable to create certificate file")?;
        oca.encode(&mut crt, ())
            .context("unable to write certificate file")?;

        // Write the private key
        let mut key = File::create(key_path).context("unable to create key file")?;
        prv.encode(&mut key, ())
            .context("unable to write key file")?;

        Ok(())
    }
}

mod rotate {
    use super::*;

    pub fn cmd() -> Result<()> {
        firmware()?
            .pdh_generate()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("unable to rotate PDH")?;

        Ok(())
    }
}

mod provision {
    use super::*;

    use ::sev::certs::sev::{PrivateKey, Signer};

    pub fn cmd(
        oca_path: PathBuf,
        prv_key_path: PathBuf,
        in_pek: Option<PathBuf>,
        out_pek: Option<PathBuf>,
    ) -> Result<()> {
        let mut out = Cursor::new(Vec::new());

        let cert = File::open(oca_path.clone())
            .context(format!("failed to open {}", oca_path.display()))
            .and_then(|mut f| Certificate::decode(&mut f, ()).context("failed to decode OCA"))?;

        let prv_key = File::open(prv_key_path.clone())
            .context(format!("failed to open {}", prv_key_path.display()))
            .and_then(|mut f| {
                PrivateKey::<SevUsage>::decode(&mut f, &cert)
                    .context("failed to decode OCA private key")
            })?;

        let mut pek = match in_pek {
            None => {
                let mut fw = firmware()?;
                fw.pek_csr()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("cross signing request failed")?
            }
            Some(f) => {
                let mut file =
                    File::open(f.clone()).context(format!("failed to open {}", f.display()))?;
                Certificate::decode(&mut file, ()).context("Unable to decode certificate")?
            }
        };

        prv_key
            .sign(&mut pek)
            .context("failed to sign PEK with OCA private key")?;

        match out_pek {
            None => {
                let mut fw = firmware()?;
                fw.pek_cert_import(&pek, &cert)
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("failed to import the newly-signed PEK")?;
            }
            Some(f) => {
                let mut file =
                    File::create(f.clone()).context(format!("failed to open {}", f.display()))?;
                pek.encode(&mut out, ())
                    .context("Failed to write pek to output file")?;
                file.write_all(&out.into_inner())
                    .context("unable to write output file")?;
            }
        };

        Ok(())
    }
}

mod addcek {

    use std::convert::TryFrom;

    use super::*;

    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    pub fn cmd(crt: PathBuf, id: String, dst: Option<PathBuf>) -> Result<()> {
        let mut chain = sev_chain(crt)?;
        let mut out = Cursor::new(Vec::new());

        let url = format!("{}/{}", CEK_SVC, id);
        let dst_path: PathBuf = match dst {
            None => PathBuf::try_from("pdh.bin")?,
            Some(f) => f,
        };

        chain.cek = download_certificate(&url, Usage::CEK)?;

        chain
            .encode(&mut out, ())
            .context("certificate chain encoding failed")?;

        let mut file = File::create(dst_path).context("unable to create output file")?;
        file.write_all(&out.into_inner())
            .context("unable to write output file")?;

        Ok(())
    }

    fn sev_chain(filename: PathBuf) -> Result<Chain> {
        let mut file = File::open(filename).context("unable to open SEV certificate chain file")?;

        Chain::decode(&mut file, ()).context("unable to decode chain")
    }
}

mod firmware {
    use super::*;

    use proc_cpuinfo::CpuInfo;

    const REPO: &str =
        "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd/";

    pub fn cmd(dst: Option<PathBuf>) -> Result<()> {
        let cpu = CpuInfo::read()?;
        let cpu_info = cpu.cpu(0).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let names = [
            //specific model name
            format!(
                "amd_sev_fam{:x}h_model{:x}h.sbin",
                cpu_info.cpu_family().unwrap(),
                cpu_info.model().unwrap()
            ),
            // high byte specific model
            format!(
                "amd_sev_fam{:x}h_model{:x}xh.sbin",
                cpu_info.cpu_family().unwrap(),
                cpu_info.model().unwrap() / 16
            ),
            //generic model
            format!("sev.fw"),
        ];

        for name in names.iter() {
            match rt.block_on(download(&format!("{}/{}", REPO, name))) {
                Ok(out) => {
                    return save_firmware(out, name, dst);
                }
                Err(_err) => {
                    println!("Could not find firmware for {}", name);
                }
            }
        }

        Ok(())
    }

    fn save_firmware(out: Cursor<Vec<u8>>, name: &String, dst: Option<PathBuf>) -> Result<()> {
        println!("Find firmware version {}", name);
        let mut file = File::create(match dst {
            Some(dst_file) => dst_file,
            None => PathBuf::from(name),
        }).context("unable to create output file")?;

        file.write_all(&out.into_inner())
            .context("unable to write output file")?;
        return Ok(());
    }
}
