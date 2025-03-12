pub mod utils;

struct BuildArgs<'a> {
    tik: &'a str,
    tek: &'a str,
    launch_measure_blob: &'a str,
    secret: &'a Vec<&'a str>,

    iv: Option<&'a str>,
}

fn run_build(args: &BuildArgs, header_file: &str, payload_file: &str) -> String {
    let tik = utils::cargo_root_path(args.tik);
    let tek = utils::cargo_root_path(args.tek);

    let mut sevctl_args = vec![
        "secret",
        "build",
        "--tik",
        &tik,
        "--tek",
        &tek,
        "--launch-measure-blob",
        args.launch_measure_blob,
    ];

    for val in args.secret {
        sevctl_args.push("--secret");
        sevctl_args.push(val);
    }

    if let Some(val) = args.iv {
        sevctl_args.push("--iv");
        sevctl_args.push(val);
    }

    sevctl_args.push(header_file);
    sevctl_args.push(payload_file);

    utils::run_sevctl(&sevctl_args[..]).trim().to_string()
}

fn test_build(args: BuildArgs) -> String {
    let header_tmp = tempfile::NamedTempFile::new().unwrap();
    let payload_tmp = tempfile::NamedTempFile::new().unwrap();
    let header_file = header_tmp.path().to_str().unwrap();
    let payload_file = payload_tmp.path().to_str().unwrap();
    run_build(&args, header_file, payload_file);

    let header = base64::encode(std::fs::read(header_file).unwrap());
    let payload = base64::encode(std::fs::read(payload_file).unwrap());
    let output = format!("header_file:\n{}\npayload_file:\n{}\n", header, payload);

    output
}

fn test_build_raw(args: BuildArgs) -> (Vec<u8>, Vec<u8>) {
    let header_tmp = tempfile::NamedTempFile::new().unwrap();
    let payload_tmp = tempfile::NamedTempFile::new().unwrap();
    let header_file = header_tmp.path().to_str().unwrap();
    let payload_file = payload_tmp.path().to_str().unwrap();
    run_build(&args, header_file, payload_file);

    let header = std::fs::read(header_file).unwrap();
    let payload = std::fs::read(payload_file).unwrap();

    (header, payload)
}

#[test]
fn secret_build() {
    let secret1 = format!(
        "736869e5-84f0-4973-92ec-06879ce3da0b:{}",
        utils::cargo_root_path("tests/data/secret/secret1.txt")
    );
    let secret2 = format!(
        "736869e5-aaaa-4973-92ec-06879ce3da0b:{}",
        utils::cargo_root_path("tests/data/secret/secret2.txt")
    );
    let secret3 = format!(
        "23058844-597b-42fb-8259-a0f5d9d495af:{}",
        utils::cargo_root_path("tests/data/secret/secret3.txt") // 16343 B file
    );
    let secret4 = format!(
        "23058844-597b-42fb-8259-a0f5d9d495af:{}",
        utils::cargo_root_path("tests/data/secret/secret4.txt") // 16344 B file
    );

    let stdargs = BuildArgs {
        tik: "tests/data/secret/tik1.bin",
        tek: "tests/data/secret/tek1.bin",
        secret: &vec![&secret1[..]],
        launch_measure_blob: "TLeA7607lZQntLjRY1/i+sbtdSZ+75zxpz4Px9hzpBLwItF5Q2o4prA++3ZZv9ZS",
        iv: Some("rFR07U3TLH2YnsUj2SVZ7A=="),
    };

    // Full test
    let args1 = BuildArgs { ..stdargs };
    let expected = "header_file:\nAAAAAKxUdO1N0yx9mJ7FI9klWey8FSzeYQ4X8K71VzNKLU/KQsIsQxLjtbhaPUewqshX5Q==\npayload_file:\n0U3e5PcXv0UW+H4tSBFKOdCYfKE1+j38Bc2fuO16mYiyI+sWx7INfn+lgYj56GL12yyinDa+lVfCCwD/2w5cPA==\n";
    assert_eq!(expected, test_build(args1));

    // Ensure random IV generates different result
    let output1 = test_build(BuildArgs {
        iv: None,
        ..stdargs
    });
    let output2 = test_build(BuildArgs {
        iv: None,
        ..stdargs
    });
    assert_ne!(output1, output2);

    // Test multi secret injection
    let args2 = BuildArgs {
        secret: &vec![&secret1[..], &secret2[..]],
        ..stdargs
    };
    let expected = "header_file:\nAAAAAKxUdO1N0yx9mJ7FI9klWeyZ3r0dOEKHUOhIRqzGYYvTJgdMtBPL1nK6GD9aGET7Ng==\npayload_file:\n0U3e5PcXv0UW+H4tSBFKObWYfKE1+j38Bc2fuO16mYiyI+sWx7INfn+lgYj56GL12yyinDa+lVfCC+WWs332lpLNUX1ZI3YK7vYgtys4X+uGxEIlkIQ90v8/w8ZFmQMe\n";
    assert_eq!(expected, test_build(args2));

    // Test maximum secret size and proper padding
    let args3 = BuildArgs {
        secret: &vec![&secret3[..]],
        ..stdargs
    };
    let (_, payload1) = test_build_raw(args3);
    let args4 = BuildArgs {
        secret: &vec![&secret4[..]],
        ..stdargs
    };
    let (_, payload2) = test_build_raw(args4);
    // The maximum secret payload length is
    // (16 + 4 + (16 + 4 + padded secret size) * secrets count)
    assert!(payload1.len() <= 16384); // 16 + 4 + (16 + 4 + pad(16343)) = 16384
    assert!(payload2.len() <= 16384); // 16 + 4 + (16 + 4 + pad(16344)) = 16384
    assert_eq!(payload1.len() % 16, 0);
    assert_eq!(payload2.len() % 16, 0);
    assert_eq!(payload1.len(), payload2.len());
}
