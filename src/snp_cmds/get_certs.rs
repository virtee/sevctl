// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use ::sev::firmware::host::types::SnpCertType;
use ::sev::firmware::host::*;

use anyhow::{anyhow, Context, Result};
use codicon::Write;

pub fn cmd(ark: Option<PathBuf>, ask: Option<PathBuf>, vcek: Option<PathBuf>) -> Result<()> {
    let mut sev = Firmware::open().context("unable to open /dev/sev")?;

    if ark.is_none() && ask.is_none() && vcek.is_none() {
        return Ok(());
    }

    let ext_config = sev.snp_get_ext_config().unwrap();

    if ext_config.certs.is_none() {
        return Err(anyhow!("Unable to retrieve SNP certificate chain"));
    }

    let certs = ext_config.certs.unwrap();

    for cert in certs.iter() {
        match cert.cert_type {
            SnpCertType::ARK => {
                if let Some(ref path) = ark {
                    let mut f = fs::File::create(path).context("unable to create/open ARK file")?;
                    f.write(&cert.data)
                        .context("unable to write ARK data to file")?;
                }
            }
            SnpCertType::ASK => {
                if let Some(ref path) = ask {
                    let mut f = fs::File::create(path).context("unable to create/open ASK file")?;
                    f.write(&cert.data)
                        .context("unable to write ASK data to file")?;
                }
            }
            SnpCertType::VCEK => {
                if let Some(ref path) = vcek {
                    let mut f =
                        fs::File::create(path).context("unable to create/open VCEK file")?;
                    f.write(&cert.data)
                        .context("unable to write VCEK data to file")?;
                }
            }
            _ => continue,
        }
    }

    Ok(())
}
