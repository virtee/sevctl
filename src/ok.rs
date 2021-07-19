// SPDX-License-Identifier: Apache-2.0

use super::*;
use colorful::*;
use std::arch::x86_64;
use std::fmt;
use std::mem::transmute;
use std::str::from_utf8;

#[derive(StructOpt, PartialEq)]
pub enum SevGeneration {
    #[structopt(about = "Secure Encrypted Virtualization")]
    Sev,

    #[structopt(about = "SEV + Encrypted State")]
    Es,
}

type TestFn = dyn Fn() -> TestResult;

struct Test {
    name: &'static str,
    gen_mask: usize,
    run: Box<TestFn>,
    sub: Vec<Test>,
}

struct TestResult {
    name: &'static str,
    stat: TestState,
    mesg: Option<String>,
}

#[derive(PartialEq)]
enum TestState {
    Pass,
    Skip,
    Fail,
}

impl fmt::Display for TestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TestState::Pass => format!("{}", "PASS".green()),
            TestState::Skip => format!("{}", "SKIP".yellow()),
            TestState::Fail => format!("{}", "FAIL".red()),
        };

        write!(f, "{}", s)
    }
}

fn collect_tests() -> Vec<Test> {
    vec![]
}

const INDENT: usize = 2;

pub fn cmd(gen: Option<SevGeneration>, quiet: bool) -> Result<()> {
    let tests = collect_tests();

    if run_test(&tests, 0, quiet) {
        Ok(())
    } else {
        Err(error::Context::new(
            "One or more tests in sevctl-ok reported a failure",
            Box::<Error>::new(ErrorKind::InvalidData.into()),
        ))
    }
}

fn run_test(tests: &[Test], level: usize, quiet: bool) -> bool {
    true
}
