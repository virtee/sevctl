// SPDX-License-Identifier: Apache-2.0

mod set_certs;

use std::path::PathBuf;

use anyhow::Result;

use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV-SNP environment")]
pub enum SnpCmd {
    #[structopt(about = "Set the hosts SEV-SNP certificate chain")]
    SetCerts {
        #[structopt(long, help = "AMD Root Key")]
        ark: Option<PathBuf>,

        #[structopt(long, help = "AMD Signing Key")]
        ask: Option<PathBuf>,

        #[structopt(long, help = "Versioned Chip Endorsement Key")]
        vcek: Option<PathBuf>,
    },
}

pub fn cmd(arg: SnpCmd, quiet: bool) -> Result<()> {
    match arg {
        SnpCmd::SetCerts { ark, ask, vcek } => set_certs::cmd(ark, ask, vcek, quiet),
    }
}
