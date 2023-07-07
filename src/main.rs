// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod measurement;
mod ok;
mod secret;
mod session;
mod vmsa;

use anyhow::{Context, Result};

use structopt::StructOpt;

use codicon::*;

use ::sev::certs::*;
use ::sev::firmware::host::{
    types::{PlatformStatusFlags, SnpStatus, Status},
    Firmware,
};
use ::sev::Generation;

use std::fs::File;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

use crate::vmsa::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct Sevctl {
    #[structopt(subcommand)]
    pub cmd: SevctlCmd,

    #[structopt(short, long, help = "Don't print anything to the console")]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV environment")]
enum SevctlCmd {
    #[structopt(about = "Export the SEV or entire certificate chain")]
    Export {
        #[structopt(
            short,
            long,
            help = "Export the entire certificate chain? (SEV + CA chain)"
        )]
        full: bool,

        #[structopt(parse(from_os_str), help = "Certificate chain output file path")]
        destination: PathBuf,
    },

    #[structopt(about = "Generate a new self-signed OCA certificate and key")]
    Generate {
        #[structopt(parse(from_os_str), help = "OCA certificate output file path")]
        cert: PathBuf,

        #[structopt(parse(from_os_str), help = "OCA key output file path")]
        key: PathBuf,
    },

    #[structopt(about = "Probe system for SEV support")]
    Ok {
        #[structopt(subcommand)]
        gen: Option<ok::SevGeneration>,
    },

    #[structopt(about = "Take ownership of the SEV platform")]
    Provision {
        #[structopt(parse(from_os_str), help = "Path to the owner's OCA certificate")]
        cert: PathBuf,

        #[structopt(parse(from_os_str), help = "Path to the owner's OCA private key")]
        key: PathBuf,
    },

    #[structopt(about = "Reset the SEV platform state")]
    Reset,

    #[structopt(about = "Rotate PDH")]
    Rotate,

    #[structopt(about = "Generate a SEV launch session")]
    Session {
        #[structopt(short, long, help = "Name used to identify file names")]
        name: Option<String>,

        #[structopt(
            parse(from_os_str),
            help = "Path of the file containing the certificate chain"
        )]
        pdh: PathBuf,

        #[structopt(help = "32-bit integer representing the launch policy")]
        policy: u32,
    },

    #[structopt(about = "Display information about the SEV platform")]
    Show {
        #[structopt(subcommand)]
        cmd: show::Show,
    },

    #[structopt(about = "Verify certificate chain")]
    Verify {
        #[structopt(long, parse(from_os_str), help = "Read SEV chain from specified file")]
        sev: Option<PathBuf>,

        #[structopt(
            long,
            parse(from_os_str),
            help = "Read OCA certificate from specified file"
        )]
        oca: Option<PathBuf>,

        #[structopt(long, parse(from_os_str), help = "Read CA chain from specified file")]
        ca: Option<PathBuf>,
    },

    #[structopt(about = "VMSA-related subcommands")]
    Vmsa(VmsaCmd),

    #[structopt(about = "Measurement subcommands")]
    Measurement(measurement::MeasurementCmd),

    #[structopt(about = "Secret subcommands")]
    Secret(secret::SecretCmd),
}

async fn download(url: &str, usage: Usage) -> Result<sev::Certificate> {
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
                    let out = Cursor::new(body.into_iter().collect::<Vec<u8>>());
                    return sev::Certificate::decode(out, ())
                        .context(format!("failed to decode {} certificate", usage));
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

    match rsp.bytes().await {
        Ok(body) => {
            let out = Cursor::new(body.into_iter().collect::<Vec<u8>>());
            sev::Certificate::decode(out, ())
                .context(format!("failed to decode {} certificate", usage))
        }
        Err(e) => Err(anyhow::Error::new(e).context("failed to read response body")),
    }
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

fn snp_platform_status() -> Result<SnpStatus> {
    firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to fetch snp platform status")
}

fn chain() -> Result<sev::Chain> {
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

    let rt = tokio::runtime::Runtime::new().unwrap();
    chain.cek = rt.block_on(download(&url, Usage::CEK))?;

    Ok(chain)
}

fn ca_chain_builtin(chain: &sev::Chain) -> Result<ca::Chain> {
    use std::convert::TryFrom;

    Generation::try_from(chain)
        .map_err(|_| anyhow::anyhow!("could not find a matching builtin certificate"))
        .context("failed to deduce platform generation")
        .map(|g| g.into())
}

fn main() -> Result<()> {
    env_logger::init();

    let sevctl = Sevctl::from_args();
    let status = match sevctl.cmd {
        SevctlCmd::Export { full, destination } => export::cmd(full, destination),
        SevctlCmd::Generate { cert, key } => generate::cmd(cert, key),
        SevctlCmd::Ok { gen } => ok::cmd(gen, sevctl.quiet),
        SevctlCmd::Measurement(option) => match option {
            measurement::MeasurementCmd::Build(args) => measurement::build_cmd(args),
        },
        SevctlCmd::Provision { cert, key } => provision::cmd(cert, key),
        SevctlCmd::Reset => reset::cmd(),
        SevctlCmd::Rotate => rotate::cmd(),
        SevctlCmd::Secret(option) => match option {
            secret::SecretCmd::Build(args) => secret::build_cmd(args),
        },
        SevctlCmd::Session { name, pdh, policy } => session::cmd(name, pdh, policy),
        SevctlCmd::Show { cmd } => show::cmd(cmd),
        SevctlCmd::Verify { sev, oca, ca } => verify::cmd(sevctl.quiet, sev, oca, ca),
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

    #[derive(StructOpt)]
    pub enum Show {
        #[structopt(about = "Show the current platform flags")]
        Flags,

        #[structopt(about = "Show the current number of guests")]
        Guests,

        #[structopt(about = "Show the platform identifier")]
        Identifier,

        #[structopt(about = "Show the SNP platform status")]
        SnpStatus,

        #[structopt(about = "Show the VCEK DER download URL")]
        VcekUrl,

        #[structopt(about = "Show the platform's firmware version")]
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
            Show::SnpStatus => {
                let snp_status = snp_platform_status()?;
                println!("{:#?}", snp_status);
            }
            Show::VcekUrl => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;
                let snp_status = snp_platform_status()?;
                println!("https://kdsintf.amd.com/vcek/v1/Milan/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         id, snp_status.tcb.platform_version.bootloader, snp_status.tcb.platform_version.tee, snp_status.tcb.platform_version.snp, snp_status.tcb.platform_version.microcode);
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
                        match status.flags & *f {
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
            let full_chain = Chain {
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
    use colorful::*;
    use std::convert::TryInto;
    use std::fmt::Display;

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

            schain.oca = sev::Certificate::decode(&mut file, ()).context("unable to decode OCA")?;
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

    fn sev_chain(filename: Option<PathBuf>) -> Result<sev::Chain> {
        Ok(match filename {
            None => chain()?,
            Some(f) => {
                let mut file =
                    File::open(f).context("unable to open SEV certificate chain file")?;

                sev::Chain::decode(&mut file, ()).context("unable to decode chain")?
            }
        })
    }

    fn ca_chain(filename: PathBuf) -> Result<ca::Chain> {
        let mut file = File::open(filename).context("unable to open CA certificate chain file")?;
        ca::Chain::decode(&mut file, ()).context("unable to decode chain")
    }
}

mod generate {
    use super::*;

    pub fn cmd(oca_path: PathBuf, key_path: PathBuf) -> Result<()> {
        let (mut oca, prv) = sev::Certificate::generate(sev::Usage::OCA)
            .context("unable to generate OCA key pair")?;
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

    pub fn cmd(oca_path: PathBuf, prv_key_path: PathBuf) -> Result<()> {
        let mut fw = firmware()?;
        let cert = File::open(oca_path.clone())
            .context(format!("failed to open {}", oca_path.display()))
            .and_then(|mut f| {
                sev::Certificate::decode(&mut f, ()).context("failed to decode OCA")
            })?;

        let prv_key = File::open(prv_key_path.clone())
            .context(format!("failed to open {}", prv_key_path.display()))
            .and_then(|mut f| {
                PrivateKey::<sev::Usage>::decode(&mut f, &cert)
                    .context("failed to decode OCA private key")
            })?;

        let mut pek = fw
            .pek_csr()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("cross signing request failed")?;
        prv_key
            .sign(&mut pek)
            .context("failed to sign PEK with OCA private key")?;
        fw.pek_cert_import(&pek, &cert)
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("failed to import the newly-signed PEK")?;

        Ok(())
    }
}
