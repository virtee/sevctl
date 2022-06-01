// SPDX-License-Identifier: Apache-2.0

use crate::error::Context;
use crate::VmsaShowCmdArgs;

use sev::vmsa::*;

pub fn cmd(args: VmsaShowCmdArgs) -> super::Result<()> {
    let vmsa = match Vmsa::from_file(&args.filename) {
        VmsaRWResult::ReadSuccess(v) => v,
        VmsaRWResult::IoErr(e) => {
            return Err(Context::new("error reading VMSA from file", Box::new(e)))
        }
        _ => unreachable!(),
    };

    println!("{}", serde_json::to_string_pretty(&vmsa).unwrap());

    Ok(())
}
