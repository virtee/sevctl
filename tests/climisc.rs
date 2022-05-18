pub mod utils;

#[test]
fn help() {
    /*! Smoke test to confirm 'help' doesn't error */

    // `sevctl help`
    let out1 = utils::run_sevctl(&["help"]);
    assert!(out1.contains(" provision "));

    // `sevctl ok help`
    let out1 = utils::run_sevctl(&["ok", "help"]);
    assert!(out1.contains(" snp "));
}
