// SPDX-License-Identifier: Apache-2.0

use crate::VmsaShowCmdArgs;

use anyhow::Context;
use sev::vmsa::*;

pub fn cmd(args: VmsaShowCmdArgs) -> super::Result<()> {
    let vmsa = Vmsa::from_file(&args.filename).context("error reading VMSA from file")?;

    println!("{}", serde_json::to_string_pretty(&vmsa).unwrap());

    Ok(())
}
