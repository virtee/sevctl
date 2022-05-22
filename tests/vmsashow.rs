pub mod utils;

fn run_vmsa_show(filename: &str) -> String {
    let sevctl_args = ["vmsa", "show", &utils::cargo_root_path(filename)[..]];

    utils::run_sevctl(&sevctl_args)
}

fn test_vmsa_show(vmsa_filename: &str, expected: &str) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let tmpfilename = file.path().to_str().unwrap();

    let output = run_vmsa_show(vmsa_filename);
    std::fs::write(tmpfilename, output).unwrap();
    utils::compare_files(tmpfilename, expected);
}

#[test]
fn show() {
    test_vmsa_show("tests/data/vmsa0.bin", "tests/data/vmsa0-show.txt");
    test_vmsa_show("tests/data/vmsa1.bin", "tests/data/vmsa1-show.txt");
}
