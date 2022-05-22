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
//! ## ok
//!
//! Probes processor, sysfs, and KVM for AMD SEV, SEV-ES, and SEV-SNP related features on the host and emits the results.
//!
//! ```console
//! $ sevctl ok {sev, es, snp}   // Probes support for the generation specified.
//! $ sevctl ok                  // Probes support for the host hardware's generation.
//! ```
//!
//! ## provision
//!
//! Installs the operator-provided OCA certificate to take ownership of the platform.
//!
//! ```console
//! $ sevctl provision ~/owners-cert ~/owners-private-key
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
//! ## session
//!
//! Given a certificate chain file and 32-bit policy, generates base64-encoded GODH and launch session files; as
//! well as encoded (not base64) TIK and TEK files.
//!
//! ```console
//! $ sevctl session --name {name} {/pdh/cert/path} {policy}
//! ```
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
//!
//! ## vmsa build
//!
//! Build a VMSA binary blob and save to the specified filename.
//!
//! ```console
//! $ sevctl vmsa build NEW-VMSA0.bin --userspace qemu --family 25 --stepping 1 --model 1 --firmware /path/to/OVMF.amdsev.fd --cpu 0
//! ```
//!
//! ## vmsa update
//!
//! Update an existing VMSA binary file in place, with the passed options.
//!
//! ```console
//! $ sevctl vmsa build EXISTING-VMSA0.bin --userspace qemu --family 25 --stepping 1 --model 1 --firmware /path/to/OVMF.amdsev.fd --cpu 0
//! ```
//!
//! ## vmsa show
//!
//! Print an existing VMSA binary file as JSON
//!
//! ```console
//! $ sevctl vmsa show EXISTING-VMSA0.bin
//! ```

#![deny(clippy::all)]
#![deny(missing_docs)]

mod error;
mod http;
mod ok;
mod session;
mod vmsa;

use error::{Contextual, Result};

use structopt::StructOpt;

use codicon::*;

use ::sev::certs::*;
use ::sev::firmware::{Firmware, PlatformStatusFlags, Status};
use ::sev::Generation;

use std::fs::File;
use std::io::{Error, ErrorKind};
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
}

fn download(url: &str, usage: Usage) -> Result<sev::Certificate> {
    use error::Context;
    use std::error::Error;

    let mut err_stack = vec![];

    for attempt in 1..4 {
        match http::get(url) {
            Ok(rsp) => {
                return sev::Certificate::decode(rsp.into_reader(), ())
                    .context(format!("failed to decode {} certificate", usage))
            }
            Err(http::Error::Status(_, rsp)) => {
                err_stack.push(Context::new(
                    format!("http request #{} failed", attempt).as_str(),
                    format!("{:?}", rsp).into(),
                ));
                let retry: Option<u16> = rsp.header("retry-after").and_then(|h| h.parse().ok());
                let retry = retry.unwrap_or(5);
                std::thread::sleep(Duration::from_secs(retry as _));
            }
            Err(e) => return Err(Context::new("transport error", Box::new(e))),
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
        Context::new(
            &format!("final http request failed: {}", e),
            prev_attempts.join("; ").into(),
        )
    })?;

    sev::Certificate::decode(rsp.into_reader(), ())
        .context(format!("failed to decode {} certificate", usage))
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

    chain.cek = download(&url, Usage::CEK)?;

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
    let sevctl = Sevctl::from_args();
    let status = match sevctl.cmd {
        SevctlCmd::Export { full, destination } => export::cmd(full, destination),
        SevctlCmd::Generate { cert, key } => generate::cmd(cert, key),
        SevctlCmd::Ok { gen } => ok::cmd(gen, sevctl.quiet),
        SevctlCmd::Provision { cert, key } => provision::cmd(cert, key),
        SevctlCmd::Reset => reset::cmd(),
        SevctlCmd::Rotate => rotate::cmd(),
        SevctlCmd::Session { name, pdh, policy } => session::cmd(name, pdh, policy),
        SevctlCmd::Show { cmd } => show::cmd(cmd),
        SevctlCmd::Verify { sev, oca, ca } => verify::cmd(sevctl.quiet, sev, oca, ca),
        SevctlCmd::Vmsa(option) => match option {
            VmsaCmd::Build(args) => vmsa::build::cmd(args),
            VmsaCmd::Show(args) => vmsa::show::cmd(args),
            VmsaCmd::Update(args) => vmsa::update::cmd(args),
        },
    };

    if let Err(err) = status {
        if sevctl.quiet {
            exit(1);
        }
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
            Err(error::Context::new(
                "SEV/CA certificate verification failed",
                Box::<Error>::new(ErrorKind::InvalidData.into()),
            ))
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
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
            .context("cross signing request failed")?;
        prv_key
            .sign(&mut pek)
            .context("failed to sign PEK with OCA private key")?;
        fw.pek_cert_import(&pek, &cert)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
            .context("failed to import the newly-signed PEK")?;

        Ok(())
    }
}
