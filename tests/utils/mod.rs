pub const SEVCTL: &'static str = env!("CARGO_BIN_EXE_sevctl");

pub fn cargo_root_path(base: &str) -> String {
    /*! Take a path relative to the project root, like `tests/data/FOO`,
    ! and make it absolute !*/
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), base)
}

pub fn compare_files(actual: &str, expected: &str) {
    let expected = &cargo_root_path(expected)[..];
    let regenerate = std::env::var_os("SEVCTL_TEST_REGENERATE_OUTPUT").is_some();
    let data1 = std::fs::read(actual).unwrap();

    if regenerate && !std::path::Path::new(expected).exists() {
        std::fs::write(expected, &data1).unwrap();
    }
    let data2 = std::fs::read(expected).unwrap();

    if data1 != data2 && regenerate {
        std::fs::write(expected, &data1).unwrap();
        return;
    }

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
