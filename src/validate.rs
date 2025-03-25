// SPDX-License-Identifier: Apache-2.0

use sev::certs::sev::{sev::Chain, Verifiable};
use sev::firmware::host::LegacyAttestationReport;

use anyhow::{Context, Result};
use std::{fs, path::PathBuf};

use codicon::*;

/// Validates the provided Platform Endorsement Key signed the specified Attestation Report.
pub fn cmd(chain_path: PathBuf, report: PathBuf) -> Result<(), anyhow::Error> {
    // Verify the binary being provided is of the correct size.
    if fs::metadata(report.clone())?.len() as usize
        != std::mem::size_of::<LegacyAttestationReport>()
    {
        return Err(anyhow::anyhow!("Unexpected report size encountered."));
    }

    let mut buf: Vec<u8> = fs::read(report)?;
    let legacy_report: LegacyAttestationReport = bincode::deserialize(&buf)?;

    buf.clear();

    let mut chainf =
        fs::File::open(chain_path).context("unable to open SEV certificate chain file")?;
    let chain = Chain::decode(&mut chainf, ()).context("unable to decode chain")?;

    // Verify using the implementation
    Ok((&chain.pek, &legacy_report).verify()?)
}
