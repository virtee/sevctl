// SPDX-License-Identifier: Apache-2.0

use crate::error::Contextual;
use crate::{BuildUpdateCmdArgs, Ovmf, UserspaceVmm, Vmsa};

pub fn cmd(args: BuildUpdateCmdArgs) -> super::Result<()> {
    let mut vmsa = Vmsa::default();
    vmsa.init_amd64();
    vmsa.init_kvm();
    match args.userspace {
        UserspaceVmm::Qemu => vmsa.init_qemu(args.cpu),
        UserspaceVmm::Krun => vmsa.init_krun(args.cpu),
    };

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

    vmsa.to_file(&args.filename)?;

    Ok(())
}
