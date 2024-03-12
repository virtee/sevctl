// SPDX-License-Identifier: Apache-2.0

use sev::certs::sev::{sev::Certificate, Verifiable};
use sev::firmware::host::LegacyAttestationReport;

use std::{fs, path::PathBuf};

static PEK_NAME: &str = "pek.cert";
static AR_NAME: &str = "attestation_report.bin";

/// Validates the provided Platform Endorsement Key signed the specified Attestation Report.
/// This assumes the PEK name to be `pek.cert` and the report name to be `attestation_report.bin`.
pub fn cmd(mut pek: PathBuf, mut report: PathBuf) -> Result<(), anyhow::Error> {
    if pek.exists() && pek.is_dir() {
        pek = pek.join(PEK_NAME);
    }

    if report.exists() && report.is_dir() {
        report = report.join(AR_NAME);
    }

    // Verify the binary being provided is of the correct size.
    if fs::metadata(report.clone())?.len() as usize
        != std::mem::size_of::<LegacyAttestationReport>()
    {
        return Err(anyhow::anyhow!("Unexpected report size encountered."));
    }

    let mut buf: Vec<u8> = fs::read(report)?;
    let legacy_report: LegacyAttestationReport = bincode::deserialize(&buf)?;

    buf.clear();

    buf = fs::read(pek)?;
    let pek_cert: Certificate = bincode::deserialize(&buf)?;

    drop(buf);

    // Verify using the implementation
    Ok((&pek_cert, &legacy_report).verify()?)
}
