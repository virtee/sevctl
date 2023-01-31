pub mod utils;

struct BuildArgs<'a> {
    api_major: &'a str,
    api_minor: &'a str,
    build_id: &'a str,
    policy: &'a str,
    tik: &'a str,

    nonce: Option<&'a str>,
    launch_measure_blob: Option<&'a str>,

    launch_digest: Option<&'a str>,

    firmware: Option<&'a str>,
    kernel: Option<&'a str>,
    initrd: Option<&'a str>,
    cmdline: Option<&'a str>,

    num_cpus: Option<&'a str>,
    vmsa_cpu0: Option<&'a str>,
    vmsa_cpu1: Option<&'a str>,

    outfile: Option<&'a str>,
}

fn run_build(args: &BuildArgs) -> String {
    let tik = utils::cargo_root_path(&args.tik);

    let mut sevctl_args = vec![
        "sev",
        "measurement",
        "build",
        "--api-major",
        args.api_major,
        "--api-minor",
        args.api_minor,
        "--build-id",
        args.build_id,
        "--policy",
        args.policy,
        "--tik",
        &tik,
    ];

    if let Some(nonce) = args.nonce {
        sevctl_args.push("--nonce");
        sevctl_args.push(nonce);
    }
    if let Some(lmb) = args.launch_measure_blob {
        sevctl_args.push("--launch-measure-blob");
        sevctl_args.push(lmb);
    }

    if let Some(ld) = args.launch_digest {
        sevctl_args.push("--launch-digest");
        sevctl_args.push(ld);
    }

    if let Some(firmware) = args.firmware {
        sevctl_args.push("--firmware");
        sevctl_args.push(firmware);
    }
    if let Some(kernel) = args.kernel {
        sevctl_args.push("--kernel");
        sevctl_args.push(kernel);
    }
    if let Some(initrd) = args.initrd {
        sevctl_args.push("--initrd");
        sevctl_args.push(initrd);
    }
    if let Some(cmdline) = args.cmdline {
        sevctl_args.push("--cmdline");
        sevctl_args.push(cmdline);
    }

    if let Some(num_cpus) = args.num_cpus {
        sevctl_args.push("--num-cpus");
        sevctl_args.push(num_cpus);
        sevctl_args.push("--vmsa-cpu0");
        sevctl_args.push(args.vmsa_cpu0.unwrap());
        sevctl_args.push("--vmsa-cpu1");
        sevctl_args.push(args.vmsa_cpu1.unwrap());
    }

    if let Some(val) = &args.outfile {
        sevctl_args.push("--outfile");
        sevctl_args.push(val);
    }

    utils::run_sevctl(&sevctl_args[..]).trim().to_string()
}

fn test_build(expected: &str, args: BuildArgs) {
    let mut output = run_build(&args);
    if let Some(val) = args.outfile {
        output = base64::encode(std::fs::read(val).unwrap());
    }
    assert_eq!(expected, output);
}

#[test]
fn measurement_build() {
    let stdargs = BuildArgs {
        api_major: "0x01",
        api_minor: "40",
        build_id: "40",
        policy: "0x03",
        tik: "tests/data/measurement/tik1.bin",
        nonce: Some("wxP6tRHCFrFQWxsuqZA8QA=="),
        launch_measure_blob: None,
        launch_digest: None,
        firmware: None,
        kernel: None,
        initrd: None,
        cmdline: None,
        num_cpus: None,
        vmsa_cpu0: None,
        vmsa_cpu1: None,
        outfile: None,
    };

    // Test manually passed in --launch-digest
    let args1 = BuildArgs {
        launch_digest: Some("xkvRAfyaSizgonxAjZIAkR8TmolUabBKQKb6KJCDDSM="),
        ..stdargs
    };
    let expected = "lswbxWxI9gckya16JQvdFtpYmNO4b+3inAPpqsgoBI7DE/q1EcIWsVBbGy6pkDxA";
    test_build(expected, args1);

    // Same as args1 test, but with --outfile.
    let file = tempfile::NamedTempFile::new().unwrap();
    let args_outfile = BuildArgs {
        launch_digest: Some("xkvRAfyaSizgonxAjZIAkR8TmolUabBKQKb6KJCDDSM="),
        outfile: Some(file.path().to_str().unwrap()),
        ..stdargs
    };
    test_build(expected, args_outfile);

    // Test --firmware PATH
    let args_firmware = BuildArgs {
        firmware: Some("tests/data/OVMF.amdsev.fd_trimmed_edk2-ovmf-20220126gitbb1bba3d77-4.el9"),
        ..stdargs
    };
    let expected = "oMDewIouJSpbpNRHj7Mk3p08H2dPZQdsZMU14qIymBnDE/q1EcIWsVBbGy6pkDxA";
    test_build(expected, BuildArgs { ..args_firmware });

    // Test --firmware + --kernel everything
    let args_kernel = BuildArgs {
        kernel: Some("tests/data/measurement/vmlinuz-fake"),
        initrd: Some("tests/data/measurement/initrd-fake"),
        cmdline: Some("foo bar baz fake kernel=cmdline"),
        ..args_firmware
    };
    let expected = "h3auYbWQnVW7EGLWN4Hf9SN0oEYMPU2sK4bLnefWPwvDE/q1EcIWsVBbGy6pkDxA";
    test_build(expected, args_kernel);

    // Test SEV-ES VMSA bits
    let expected = "/o0nzDKE5XgtVnUZWPhUea/WZYrTKLExR7KCwuMdbActvpWfXTFk21KMZIAAhQny";
    let args_vmsa = BuildArgs {
        policy: "0x05",
        num_cpus: Some("4"),
        vmsa_cpu0: Some("tests/data/vmsa0.bin"),
        vmsa_cpu1: Some("tests/data/vmsa1.bin"),
        api_major: "1",
        api_minor: "49",
        build_id: "6",
        nonce: None,
        launch_measure_blob: Some(&expected),
        ..args_firmware
    };
    test_build(expected, args_vmsa);
}
