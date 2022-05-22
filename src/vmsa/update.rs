// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::mem::size_of;
use std::slice::from_raw_parts_mut;

use crate::error::Contextual;
use crate::{BuildUpdateCmdArgs, Ovmf, UserspaceVmm, Vmsa};

pub fn cmd(args: BuildUpdateCmdArgs) -> super::Result<()> {
    let mut vmsa = Vmsa::from_file(&args.filename)?;

    let family: u64 = args.family.unwrap_or(0);
    let model: u64 = args.model.unwrap_or(0);
    let stepping: u64 = args.stepping.unwrap_or(0);

    if family > 0 || model > 0 || stepping > 0 {
        vmsa.cpu_sku(family, model, stepping);
    }

    if let Some(fw) = args.firmware {
        let mut ovmf = Ovmf::default();
        ovmf.load(fw)
            .context("error loading firmware blob entries in OVMF")?;

        if args.userspace == UserspaceVmm::Qemu && args.cpu != 0 {
            let ovmf_reset_addr = ovmf
                .reset_addr()
                .context("error getting OVMF reset address")?;

            vmsa.reset_addr(ovmf_reset_addr);
        }
    }

    let vmsa: &mut [u8] =
        unsafe { from_raw_parts_mut(&vmsa as *const Vmsa as *mut u8, size_of::<Vmsa>()) };
    let buf: &mut [u8] = &mut [0; 4096];
    buf[..size_of::<Vmsa>()].copy_from_slice(vmsa);

    fs::write(args.filename, buf).context("could not write VMSA buffer")?;

    Ok(())
}
