// SPDX-License-Identifier: Apache-2.0

// Some flags are unused, but may be at some point. Silence warnings of unused
// flags.
#![allow(dead_code)]

pub mod build;
pub mod show;
pub mod update;

use super::*;

use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Write;
use std::fs;
use std::str::FromStr;
use std::string::{ParseError, String};

use uuid::{uuid, Uuid};

#[derive(StructOpt)]
pub enum VmsaCmd {
    Build(BuildUpdateCmdArgs),
    Show(VmsaShowCmdArgs),
    Update(BuildUpdateCmdArgs),
}

#[derive(StructOpt, Debug)]
pub struct VmsaShowCmdArgs {
    #[structopt(help = "VMSA binary file to print as JSON")]
    pub filename: String,
}

// cmdline arguments for the "build" and "update" subcommands.
#[derive(StructOpt, fmt::Debug)]
pub struct BuildUpdateCmdArgs {
    #[structopt(help = "File to write VMSA information to")]
    pub filename: String,

    #[structopt(long, help = "CPU number")]
    pub cpu: u64,

    #[structopt(long, help = "CPU family")]
    pub family: Option<u64>,

    #[structopt(long, help = "CPU model")]
    pub model: Option<u64>,

    #[structopt(long, help = "CPU stepping")]
    pub stepping: Option<u64>,

    #[structopt(long, parse(from_os_str), help = "OVMF firmware path")]
    pub firmware: Option<PathBuf>,

    #[structopt(long, help = "Userspace implementation")]
    pub userspace: UserspaceVmm,
}

pub enum UserspaceVmm {
    Qemu,
    Krun,
}

impl PartialEq for UserspaceVmm {
    fn eq(&self, other: &Self) -> bool {
        match self {
            UserspaceVmm::Qemu => match other {
                UserspaceVmm::Qemu => true,
                UserspaceVmm::Krun => false,
            },
            UserspaceVmm::Krun => match other {
                UserspaceVmm::Qemu => false,
                UserspaceVmm::Krun => true,
            },
        }
    }
}

impl fmt::Debug for UserspaceVmm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserspaceVmm::Qemu => write!(f, "qemu"),
            UserspaceVmm::Krun => write!(f, "krun"),
        }
    }
}

impl FromStr for UserspaceVmm {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "krun" {
            return Ok(UserspaceVmm::Krun);
        }

        // QEMU is default.

        Ok(UserspaceVmm::Qemu)
    }
}

const OVMF_SEV_INFO_BLOCK_GUID: Uuid = uuid!("00f771de-1a7e-4fcb-890e-68c77e2fb44e");

#[derive(Default)]
pub struct Ovmf {
    entries: HashMap<Uuid, Vec<u8>>,
}

impl Ovmf {
    fn load(&mut self, firmware: PathBuf) -> Result<()> {
        let bytes = fs::read(firmware).context("error reading from firmware path file")?;
        let size = bytes.len();

        let ovmf_table_footer_guid = Uuid::parse_str("96b582de-1fb2-45f7-baea-a366c55a082d")
            .context("error parsing uuid of OVMF_TABLE_FOOTER_GUID")?;

        let actual = Uuid::from_bytes_le(
            bytes[(size - 48)..(size - 32)]
                .try_into()
                .context("error parsing bytes from firmware file")?,
        );

        let expect = ovmf_table_footer_guid.to_u128_le();
        let actual = actual.to_u128_le();

        if expect != actual {
            return Err(error::Context::new(
                "actual OVMF UUID does not meet expected",
                Box::<Error>::new(ErrorKind::InvalidData.into()),
            ));
        }

        let len = usize::from(u16::from_le_bytes(
            bytes[(size - 50)..(size - 48)]
                .try_into()
                .context("couldn't parse table length")?,
        ));

        if len == 0 {
            return Err(error::Context::new(
                "OVMF table - zero length",
                Box::<Error>::new(ErrorKind::InvalidData.into()),
            ));
        }

        let entry_start = size - (len + 32);
        let entry_end = size - 50;
        let table = &bytes[entry_start..entry_end];
        let mut idx = len - 18;

        while idx > 0 {
            let uuid_b: [u8; 16] = table[idx - 16..idx]
                .try_into()
                .context("error getting UUID bytes")?;
            let uuid = Uuid::from_bytes_le(uuid_b);

            let data_len: [u8; 2] = table[idx - 18..idx - 16].try_into().context(format!(
                "error getting size of entry corresponding to UUID {}",
                uuid
            ))?;
            let data_len: usize = usize::from(u16::from_le_bytes(data_len));

            let data: &[u8] = &table[idx - data_len..idx];

            self.entries.insert(uuid, data.to_vec());

            idx -= data_len;
        }

        Ok(())
    }

    fn reset_addr(&self) -> Result<u32> {
        if !self.entries.contains_key(&OVMF_SEV_INFO_BLOCK_GUID) {
            return Err(error::Context::new(
                "OVMF table - zero length",
                Box::<Error>::new(ErrorKind::InvalidData.into()),
            ));
        }

        let entry = self.entries.get(&OVMF_SEV_INFO_BLOCK_GUID).unwrap();

        let mut s = String::with_capacity(entry.len());

        let mut i = 2;
        loop {
            write!(&mut s, "{:02x}", entry[i]).context("error unpacking reset address")?;

            if i == 0 {
                break;
            }

            i -= 1;
        }

        let reset_addr =
            u32::from_str_radix(&s, 16).context(format!("error parsing entry {}", s))?;

        Ok(reset_addr)
    }
}
