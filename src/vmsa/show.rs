// SPDX-License-Identifier: Apache-2.0

use crate::{Vmsa, VmsaShowCmdArgs};

pub fn cmd(args: VmsaShowCmdArgs) -> super::Result<()> {
    let vmsa = Vmsa::from_file(&args.filename)?;

    println!("{}", serde_json::to_string_pretty(&vmsa).unwrap());

    Ok(())
}
