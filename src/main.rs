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

use clap::ArgMatches;

use codicon::*;

use ::sev::certs::*;
use ::sev::firmware::{Firmware, Status};
use ::sev::Generation;

use std::fmt::{Debug, Display};
use std::fs::File;
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

trait UnwrapOrExit<T> {
    fn unwrap_or_exit(self, context: impl Display) -> T;
}

impl<T, E: Debug> UnwrapOrExit<T> for Result<T, E> {
    fn unwrap_or_exit(self, context: impl Display) -> T {
        self.unwrap_or_else(|err| {
            eprintln!("{}: {:?}", context, err);
            exit(1)
        })
    }
}

fn download(rsp: reqwest::Result<reqwest::blocking::Response>, usage: Usage) -> sev::Certificate {
    let mut rsp = rsp.unwrap_or_exit(format!("unable to contact {} server", usage));

    if !rsp.status().is_success() {
        eprintln!("received failure from {} server: {}", usage, rsp.status());
        exit(1);
    }

    let mut buf = Vec::new();
    rsp.copy_to(&mut buf)
        .unwrap_or_exit(format!("unable to complete {} download", usage));

    sev::Certificate::decode(&mut &buf[..], ())
        .unwrap_or_exit(format!("unable to parse downloaded {}", usage))
}

fn firmware() -> Firmware {
    Firmware::open().unwrap_or_exit("unable to open /dev/sev")
}

fn platform_status() -> Status {
    firmware()
        .platform_status()
        .unwrap_or_exit("unable to fetch platform status")
}

fn chain() -> sev::Chain {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut chain = firmware()
        .pdh_cert_export()
        .unwrap_or_exit("unable to export SEV certificates");

    let id = firmware()
        .get_identifer()
        .unwrap_or_exit("error fetching identifier");
    let url = format!("{}/{}", CEK_SVC, id);
    chain.cek = download(reqwest::blocking::get(&url), Usage::CEK);

    chain
}

fn ca_chain_builtin(chain: &sev::Chain) -> ca::Chain {
    use std::convert::TryFrom;
    Generation::try_from(chain)
        .unwrap_or(Generation::Rome)
        .into()
}

fn main() {
    use clap::{App, Arg, SubCommand};

    let matches = App::new("SEV Platform Control")
        .version(VERSION)
        .author(AUTHORS.split(';').next().unwrap())
        .about("Utilities for managing the SEV environment")
        .subcommand(SubCommand::with_name("reset").about("Resets the SEV platform"))
        .subcommand(
            SubCommand::with_name("show")
                .about("Shows information about the SEV platform")
                .subcommand(
                    SubCommand::with_name("version").about("Show the current firmware version"),
                )
                .subcommand(
                    SubCommand::with_name("guests").about("Show the current number of guests"),
                )
                .subcommand(
                    SubCommand::with_name("flags").about("Show the current platform flags"),
                ),
        )
        .subcommand(
            SubCommand::with_name("export")
                .about("Export the SEV certificate chain")
                .arg(
                    Arg::with_name("file")
                        .help("SEV certificate chain output file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("full")
                        .help("Export the entire certificate chain (SEV+CA)")
                        .long("full")
                        .short("f"),
                ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify the full SEV/CA certificate chain")
                .arg(
                    Arg::with_name("quiet")
                        .help("Do not print anything to the console")
                        .long("quiet")
                        .short("q"),
                )
                .arg(
                    Arg::with_name("sev")
                        .help("Read SEV chain from the specified file")
                        .takes_value(true)
                        .long("sev"),
                )
                .arg(
                    Arg::with_name("oca")
                        .help("Read OCA from the specified file")
                        .takes_value(true)
                        .long("oca"),
                )
                .arg(
                    Arg::with_name("ca")
                        .help("Read CA chain from the specified file")
                        .takes_value(true)
                        .long("ca"),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generate a new, self-signed OCA certificate and key")
                .arg(
                    Arg::with_name("cert")
                        .help("OCA certificate output file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .help("OCA private key output file")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("rotate")
                .about("Rotate certificates and their keys")
                .subcommand(
                    SubCommand::with_name("all")
                        .about("Rotate the OCA, PEK and PDH certificates")
                        .arg(
                            Arg::with_name("adopt")
                                .help("URL of OCA signing service")
                                .takes_value(true)
                                .long("adopt"),
                        ),
                )
                .subcommand(SubCommand::with_name("pdh").about("Rotate the PDH certificate")),
        )
        .get_matches();

    match matches.subcommand() {
        ("reset", Some(m)) => reset::cmd(m),
        ("show", Some(m)) => show::cmd(m),
        ("export", Some(m)) => export::cmd(m),
        ("verify", Some(m)) => verify::cmd(m),
        ("generate", Some(m)) => generate::cmd(m),
        ("rotate", Some(m)) => rotate::cmd(m),
        _ => {
            eprintln!("{}", matches.usage());
            exit(1);
        }
    }
}

mod reset {
    use super::*;

    pub fn cmd(_: &ArgMatches) -> ! {
        firmware()
            .platform_reset()
            .unwrap_or_exit("error resetting platform");
        exit(0)
    }
}

mod show {
    use super::*;
    use ::sev::firmware::Flags;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let status = platform_status();

        match matches.subcommand_name() {
            Some("version") => println!("{}", status.build),

            Some("guests") => println!("{}", status.guests),

            Some("flags") => {
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

            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }

        exit(0)
    }
}

mod export {
    use super::*;
    use std::io::Write;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let chain = chain();

        let mut out = std::io::Cursor::new(Vec::new());

        if matches.is_present("full") {
            let full_chain = Chain {
                ca: ca_chain_builtin(&chain),
                sev: chain,
            };

            full_chain.encode(&mut out, ()).unwrap();
        } else {
            chain.encode(&mut out, ()).unwrap();
        }

        let mut file = File::create(matches.value_of("file").unwrap())
            .unwrap_or_exit("unable to create output file");

        file.write_all(&out.into_inner())
            .unwrap_or_exit("unable to write output file");

        exit(0)
    }
}

mod verify {
    use super::*;
    use colorful::*;
    use std::convert::TryInto;
    use std::fmt::Display;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let mut schain = sev_chain(matches.value_of("sev"));
        let cchain = match matches.value_of("ca") {
            Some(ca) => ca_chain(ca),
            None => ca_chain_builtin(&schain),
        };
        let quiet = matches.is_present("quiet");
        let mut err = false;

        if let Some(filename) = matches.value_of("oca") {
            let mut file =
                File::open(filename).unwrap_or_exit("unable to open OCA certificate file");

            schain.oca =
                sev::Certificate::decode(&mut file, ()).unwrap_or_exit("unable to decode OCA");
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
        exit(err as i32)
    }

    fn status<'a, P, C>(pfx: &str, p: &'a P, c: &'a C, quiet: bool) -> bool
    where
        P: Display,
        C: Display,
        &'a P: TryInto<Usage, Error = std::io::Error>,
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

    fn sev_chain(filename: Option<&str>) -> sev::Chain {
        match filename {
            None => chain(),
            Some(f) => {
                let mut file =
                    File::open(f).unwrap_or_exit("unable to open SEV certificate chain file");

                sev::Chain::decode(&mut file, ()).unwrap_or_exit("unable to decode chain")
            }
        }
    }

    fn ca_chain(filename: &str) -> ca::Chain {
        let mut file =
            File::open(&filename).unwrap_or_exit("unable to open CA certificate chain file");
        ca::Chain::decode(&mut file, ()).unwrap_or_exit("unable to decode chain")
    }
}

mod generate {
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let (mut oca, prv) = sev::Certificate::generate(sev::Usage::OCA)
            .unwrap_or_exit("unable to generate OCA key pair");
        prv.sign(&mut oca).unwrap();

        // Write the certificate
        let crt = matches.value_of("cert").unwrap();
        let mut crt = File::create(crt).unwrap_or_exit("unable to create certificate file");
        oca.encode(&mut crt, ())
            .unwrap_or_exit("unable to write certificate file");

        // Write the private key
        let key = matches.value_of("key").unwrap();
        let mut key = File::create(key).unwrap_or_exit("unable to create key file");
        prv.encode(&mut key, ())
            .unwrap_or_exit("unable to write key file");

        exit(0)
    }
}

mod rotate {
    use super::*;

    pub fn cmd(_: &ArgMatches) -> ! {
        pdh()
    }

    fn pdh() -> ! {
        firmware()
            .pdh_generate()
            .unwrap_or_exit("unable to rotate PDH");
        exit(0)
    }
}
