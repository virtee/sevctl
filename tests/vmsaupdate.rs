pub mod utils;

struct Args<'a> {
    cpu: u32,
    family: u32,
    model: u32,
    stepping: u32,
    firmware: &'a str,
    userspace: &'a str,
}

fn run_vmsa_update(filename: &str, args: Args) {
    let sevctl_args = [
        "vmsa",
        "update",
        filename,
        "--cpu",
        &args.cpu.to_string(),
        "--family",
        &args.family.to_string(),
        "--model",
        &args.model.to_string(),
        "--stepping",
        &args.stepping.to_string(),
        "--userspace",
        args.userspace,
        "--firmware",
        &utils::cargo_root_path(args.firmware)[..],
    ];

    utils::run_sevctl(&sevctl_args);
}

fn test_vmsa_update(input_filename: &str, expected: &str, args: Args) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let filename = file.path().to_str().unwrap();
    let input_filename = &utils::cargo_root_path(input_filename)[..];
    std::fs::write(filename, std::fs::read(input_filename).unwrap()).unwrap();

    run_vmsa_update(filename, args);
    println!("filename={} expected={}", filename, expected);
    utils::compare_files(filename, expected);
}

#[test]
fn update() {
    let stdargs = Args {
        cpu: 0,
        family: 25,
        stepping: 1,
        model: 1,
        userspace: "qemu",
        firmware: "tests/data/OVMF.amdsev.fd_trimmed_edk2-ovmf-20220126gitbb1bba3d77-4.el9",
    };

    // Test that 'update' with same 'build' args doesn't mess up output
    test_vmsa_update(
        "tests/data/vmsa0.bin",
        "tests/data/vmsa0.bin",
        Args { cpu: 0, ..stdargs },
    );
    test_vmsa_update(
        "tests/data/vmsa1.bin",
        "tests/data/vmsa1.bin",
        Args { cpu: 1, ..stdargs },
    );

    // Swap --cpu values and verify we match 'build' output
    test_vmsa_update(
        "tests/data/vmsa0.bin",
        "tests/data/vmsa1.bin",
        Args { cpu: 1, ..stdargs },
    );
}
