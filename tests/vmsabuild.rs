pub mod utils;

struct BuildArgs<'a> {
    cpu: u32,
    family: u32,
    model: u32,
    stepping: u32,
    firmware: &'a str,
    userspace: &'a str,
}

fn run_vmsa_build(filename: &str, buildargs: BuildArgs) {
    let sevctl_args = [
        "vmsa",
        "build",
        filename,
        "--cpu",
        &buildargs.cpu.to_string(),
        "--family",
        &buildargs.family.to_string(),
        "--model",
        &buildargs.model.to_string(),
        "--stepping",
        &buildargs.stepping.to_string(),
        "--userspace",
        buildargs.userspace,
        "--firmware",
        &utils::cargo_root_path(buildargs.firmware)[..],
    ];

    utils::run_sevctl(&sevctl_args);
}

fn test_vmsa_build(expected: &str, buildargs: BuildArgs) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let filename = file.path().to_str().unwrap();

    run_vmsa_build(filename, buildargs);
    utils::compare_files(filename, expected);
}

#[test]
fn build() {
    let stdargs = BuildArgs {
        cpu: 0,
        family: 25,
        stepping: 1,
        model: 1,
        userspace: "qemu",
        firmware: "tests/data/OVMF.amdsev.fd_trimmed_edk2-ovmf-20220126gitbb1bba3d77-4.el9",
    };

    test_vmsa_build("tests/data/vmsa0.bin", BuildArgs { cpu: 0, ..stdargs });

    test_vmsa_build("tests/data/vmsa1.bin", BuildArgs { cpu: 1, ..stdargs });
}
