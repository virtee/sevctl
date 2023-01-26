// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod http;
mod measurement;
mod secret;
mod session;

use anyhow::{Context, Result};

use structopt::StructOpt;

use codicon::*;

use ::sev::certs::*;
use ::sev::firmware::host::Firmware;
use ::sev::Generation;

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV environment")]
pub enum SevCmd {
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

    #[structopt(about = "Measurement subcommands")]
    Measurement(measurement::MeasurementCmd),

    #[structopt(about = "Secret subcommands")]
    Secret(secret::SecretCmd),
}

fn download(url: &str, usage: Usage) -> Result<sev::Certificate> {
    let mut err_stack = vec![];

    for attempt in 1..4 {
        match http::get(url) {
            Ok(rsp) => {
                return sev::Certificate::decode(rsp.into_reader(), ())
                    .context(format!("failed to decode {} certificate", usage))
            }
            Err(http::Error::Status(_, rsp)) => {
                err_stack.push(
                    anyhow::anyhow!(format!("{:?}", rsp))
                        .context(format!("http request #{} failed", attempt)),
                );
                let retry: Option<u16> = rsp.header("retry-after").and_then(|h| h.parse().ok());
                let retry = retry.unwrap_or(5);
                std::thread::sleep(Duration::from_secs(retry as _));
            }
            Err(e) => return Err(anyhow::Error::new(e).context("transport error")),
        }
    }

    // One last attempt before giving up
    let rsp = http::get(url).map_err(|e| {
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

    sev::Certificate::decode(rsp.into_reader(), ())
        .context(format!("failed to decode {} certificate", usage))
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
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

    chain.cek = download(&url, Usage::CEK)?;

    Ok(chain)
}

fn ca_chain_builtin(chain: &sev::Chain) -> Result<ca::Chain> {
    use std::convert::TryFrom;

    Generation::try_from(chain)
        .map_err(|_| anyhow::anyhow!("could not find a matching builtin certificate"))
        .context("failed to deduce platform generation")
        .map(|g| g.into())
}

pub fn cmd(arg: SevCmd, q: bool) -> Result<()> {
    match arg {
        SevCmd::Export { full, destination } => export::cmd(full, destination),
        SevCmd::Generate { cert, key } => generate::cmd(cert, key),
        SevCmd::Measurement(option) => match option {
            measurement::MeasurementCmd::Build(args) => measurement::build_cmd(args),
        },
        SevCmd::Provision { cert, key } => provision::cmd(cert, key),
        SevCmd::Reset => reset::cmd(),
        SevCmd::Rotate => rotate::cmd(),
        SevCmd::Secret(option) => match option {
            secret::SecretCmd::Build(args) => secret::build_cmd(args),
        },
        SevCmd::Session { name, pdh, policy } => session::cmd(name, pdh, policy),
        SevCmd::Verify { sev, oca, ca } => verify::cmd(q, sev, oca, ca),
    }
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

mod export {
    use super::*;
    use std::io::Write;

    pub fn cmd(full: bool, dest: PathBuf) -> Result<()> {
        let chain = chain()?;

        let mut out = std::io::Cursor::new(Vec::new());

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