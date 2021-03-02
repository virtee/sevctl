// SPDX-License-Identifier: Apache-2.0

//! `sevctl` is a command line utility for managing the AMD Secure Encrypted Virtualization (SEV) platform.
//! It currently supports the entire management API for the Naples generation of processors.
//!
//! # Usage
//!
//! ## help
//!
//! Every `sevctl` (sub)command comes with a quick `--help` option for a reference on its use. For example:
//!
//! ```console
//! $ sevctl --help
//! ```
//!
//! or
//!
//! ```console
//! $ sevctl show --help
//! ```
//!
//! ## export
//!
//! Exports the SEV certificate chain to the provided file path.
//!
//! ```console
//! $ sevctl export /path/to/where/you/want/the-certificate
//! ```
//!
//! ## generate
//!
//! Generates a new (self-signed) OCA certificate and key.
//!
//! ```console
//! $ sevctl generate ~/my-cert ~/my-key
//! ```
//!
//! ## reset
//!
//! Resets the SEV platform. This will clear all persistent data managed by the platform.
//!
//! ```console
//! $ sevctl reset
//! ```
//!
//! ## rotate
//!
//! Rotates the Platform Diffie-Hellman (PDH).
//!
//! ```console
//! $ sevctl rotate
//! ```
//!
//! ## show
//!
//! Describes the state of the SEV platform.
//!
//! ```console
//! $ sevctl show flags
//! ```
//!
//! ```console
//! $ sevctl show guests
//! ```
//!
//! ## verify
//!
//! Verifies the full SEV/CA certificate chain. File paths to these certificates can be supplied as
//! command line arguments if they are stored on the local filesystem. If they are not supplied, the
//! well-known public components will be downloaded from their remote locations.
//!
//! ```console
//! $ sevctl verify
//! ```

#![deny(clippy::all)]
#![deny(missing_docs)]

mod error;

use error::{Contextual, Result};

use structopt::StructOpt;

use codicon::*;

use ::sev::certs::*;
use ::sev::firmware::{Firmware, Status};
use ::sev::Generation;

use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV environment")]
enum Sevctl {
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

    #[structopt(about = "Reset the SEV platform state")]
    Reset,

    #[structopt(about = "Rotate PDH")]
    Rotate,

    #[structopt(about = "Display information about the SEV platform")]
    Show {
        #[structopt(subcommand)]
        cmd: show::Show,
    },

    #[structopt(about = "Verify certificate chain")]
    Verify {
        #[structopt(short, long, help = "Don't print anything to the console")]
        quiet: bool,

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
}

fn download(
    rsp: reqwest::Result<reqwest::blocking::Response>,
    usage: Usage,
) -> Result<sev::Certificate> {
    let rsp = rsp.context(format!("unable to contact {} server", usage))?;

    let status = rsp.status();
    let mut rsp = rsp.error_for_status().context(&format!(
        "received failure from {} server: {}",
        usage, status
    ))?;

    let mut buf = Vec::new();
    rsp.copy_to(&mut buf)
        .context(format!("unable to complete {} download", usage))?;

    sev::Certificate::decode(&mut &buf[..], ())
        .context(format!("unable to parse downloaded {}", usage))
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

fn platform_status() -> Result<Status> {
    firmware()?
        .platform_status()
        .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
        .context("unable to fetch platform status")
}

fn chain() -> Result<sev::Chain> {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut chain = firmware()?
        .pdh_cert_export()
        .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
        .context("unable to export SEV certificates")?;

    let id = firmware()?
        .get_identifier()
        .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
        .context("error fetching identifier")?;
    let url = format!("{}/{}", CEK_SVC, id);
    chain.cek = download(reqwest::blocking::get(&url), Usage::CEK)?;

    Ok(chain)
}

fn ca_chain_builtin(chain: &sev::Chain) -> Result<ca::Chain> {
    use std::convert::TryFrom;

    Generation::try_from(chain)
        .map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                "could not find a matching builtin certificate",
            )
        })
        .context("failed to deduce platform generation")
        .map(|g| g.into())
}

fn main() {
    let status = match Sevctl::from_args() {
        Sevctl::Export { full, destination } => export::cmd(full, destination),
        Sevctl::Generate { cert, key } => generate::cmd(cert, key),
        Sevctl::Reset => reset::cmd(),
        Sevctl::Rotate => rotate::cmd(),
        Sevctl::Show { cmd } => show::cmd(cmd),
        Sevctl::Verify {
            quiet,
            sev,
            oca,
            ca,
        } => verify::cmd(quiet, sev, oca, ca),
    };

    if let Err(err) = status {
        eprintln!("error: {}", err);
        let mut err: &(dyn std::error::Error + 'static) = &err;
        while let Some(cause) = err.source() {
            eprintln!("caused by: {}", cause);
            err = cause;
        }

        exit(1);
    }
}

mod reset {
    use super::*;

    pub fn cmd() -> Result<()> {
        firmware()?
            .platform_reset()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
            .context("error resetting platform")
    }
}

mod show {
    use super::*;
    use ::sev::firmware::Flags;

    #[derive(StructOpt)]
    pub enum Show {
        #[structopt(about = "Show the current platform flags")]
        Flags,

        #[structopt(about = "Show the current number of guests")]
        Guests,

        #[structopt(about = "Show the platform's firmware version")]
        Version,
    }

    pub fn cmd(show: Show) -> Result<()> {
        let status = platform_status()?;

        match show {
            Show::Version => println!("{}", status.build),
            Show::Guests => println!("{}", status.guests),
            Show::Flags => {
                for f in [Flags::OWNED, Flags::ENCRYPTED_STATE].iter() {
                    println!(
                        "{}",
                        match status.flags & *f {
                            Flags::ENCRYPTED_STATE => "es",
                            Flags::OWNED => "owned",
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
        println!("\n • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs");

        if err as i32 == 0 {
            Ok(())
        } else {
            exit(err as i32)
        }
    }

    fn status<'a, P, C>(pfx: &str, p: &'a P, c: &'a C, quiet: bool) -> bool
    where
        P: Display,
        C: Display,
        &'a P: TryInto<Usage, Error = Error>,
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
        let mut file = File::open(&filename).context("unable to open CA certificate chain file")?;
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
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
            .context("unable to rotate PDH")?;

        Ok(())
    }
}
