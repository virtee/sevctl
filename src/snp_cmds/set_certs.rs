// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use ::sev::firmware::host::types::{CertTableEntry, SnpCertType, SnpExtConfig};
use ::sev::firmware::host::Firmware;

use anyhow::{anyhow, Context, Result};

pub fn cmd(
    ark: Option<PathBuf>,
    ask: Option<PathBuf>,
    vcek: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    let mut sev = Firmware::open().context("unable to open /dev/sev")?;

    let mut entries: Vec<CertTableEntry> = Vec::new();

    let mut size = 0;

    if let Some(path) = ark {
        let data: Vec<u8> = fs::read(path).unwrap();
        size += data.len();

        let entry = CertTableEntry {
            cert_type: SnpCertType::ARK,
            data,
        };

        entries.push(entry);
    }

    if let Some(path) = ask {
        let data: Vec<u8> = fs::read(path).unwrap();
        size += data.len();

        let entry = CertTableEntry {
            cert_type: SnpCertType::ASK,
            data,
        };

        entries.push(entry);
    }

    if let Some(path) = vcek {
        let data: Vec<u8> = fs::read(path).unwrap();
        size += data.len();

        let entry = CertTableEntry {
            cert_type: SnpCertType::VCEK,
            data,
        };

        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(anyhow!("No ARK, ASK, or VCEK path provided"));
    }

    // When setting the certificate buffer, the size needs to be 4K page
    // aligned. Therefore, round up to the nearest page size when inputting the
    // size of the certificate chain.
    if size < 0x1000 {
        size = 0x1000;
    } else {
        size = ((size % 0x1000) + 1) * 0x1000;
    }

    let config = SnpExtConfig {
        config: None,
        certs: Some(entries),
        certs_len: size as u32,
    };

    sev.snp_set_ext_config(&config)
        .context("SNP_SET_EXT_CONFIG ioctl(2) failed")?;

    if !quiet {
        println!("SUCCESS: Certificate chain set.");
    }

    Ok(())
}
