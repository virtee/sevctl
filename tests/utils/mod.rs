pub const SEVCTL: &'static str = env!("CARGO_BIN_EXE_sevctl");

pub fn run_sevctl(arglist: &[&str]) -> String {
    let output = std::process::Command::new(SEVCTL)
        .args(arglist)
        .output()
        .unwrap();

    assert!(output.status.success());
    return String::from_utf8(output.stdout).unwrap();
}
