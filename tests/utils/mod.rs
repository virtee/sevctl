pub const SEVCTL: &'static str = env!("CARGO_BIN_EXE_sevctl");

pub fn cargo_root_path(base: &str) -> String {
    /*! Take a path relative to the project root, like `tests/data/FOO`,
    ! and make it absolute !*/
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), base)
}

pub fn compare_files(actual: &str, expected: &str) {
    let expected = cargo_root_path(expected);
    let data1 = std::fs::read(actual).unwrap();
    let data2 = std::fs::read(&expected[..]).unwrap();
    assert_eq!(data1, data2);
}

pub fn run_sevctl(arglist: &[&str]) -> String {
    let output = std::process::Command::new(SEVCTL)
        .args(arglist)
        .output()
        .unwrap();

    assert!(output.status.success());
    return String::from_utf8(output.stdout).unwrap();
}
