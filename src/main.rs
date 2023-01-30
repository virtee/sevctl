// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod ok;
mod vmsa;

mod sev_cmds;
mod snp_cmds;

use anyhow::{Context, Result};

use structopt::StructOpt;

use ::sev::firmware::host::{
    types::{PlatformStatusFlags, Status},
    Firmware,
};

use std::fs::File;
use std::path::PathBuf;
use std::process::exit;

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
    #[structopt(about = "Probe system for SEV support")]
    Ok {
        #[structopt(subcommand)]
        gen: Option<ok::SevGeneration>,
    },

    #[structopt(about = "Reset the SEV platform")]
    Reset,

    #[structopt(about = "SEV speicific commands")]
    Sev(sev_cmds::SevCmd),

    #[structopt(about = "Display information about the SEV platform")]
    Show {
        #[structopt(subcommand)]
        cmd: show::Show,
    },
    #[structopt(about = "SEV-SNP specific commands")]
    Snp(snp_cmds::SnpCmd),

    #[structopt(about = "VMSA-related subcommands")]
    Vmsa(VmsaCmd),
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

fn main() -> Result<()> {
    env_logger::init();

    let sevctl = Sevctl::from_args();
    let status = match sevctl.cmd {
        SevctlCmd::Ok { gen } => ok::cmd(gen, sevctl.quiet),
        SevctlCmd::Reset => reset::cmd(),
        SevctlCmd::Sev(args) => sev_cmds::cmd(args, sevctl.quiet),
        SevctlCmd::Show { cmd } => show::cmd(cmd),
        SevctlCmd::Snp(args) => snp_cmds::cmd(args, sevctl.quiet),
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
