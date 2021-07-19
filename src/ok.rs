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

// SEV generation-specific bitmasks.
const SEV_MASK: usize = 1;
const ES_MASK: usize = 1 << 1;

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
    let tests = vec![Test {
        name: "AMD CPU",
        gen_mask: SEV_MASK,
        run: Box::new(|| {
            let res = unsafe { x86_64::__cpuid(0x00000000) };
            let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
            let name = from_utf8(&name[..]).unwrap_or("ERROR_FOUND");

            let stat = if name == "AuthenticAMD" {
                TestState::Pass
            } else {
                TestState::Fail
            };

            TestResult {
                name: "AMD CPU",
                stat,
                mesg: None,
            }
        }),
        sub: vec![
            Test {
                name: "Microcode support",
                gen_mask: SEV_MASK,
                run: Box::new(|| {
                    let cpu_name = {
                        let mut bytestr = Vec::with_capacity(48);
                        for cpuid in 0x8000_0002_u32..=0x8000_0004_u32 {
                            let cpuid = unsafe { x86_64::__cpuid(cpuid) };
                            let mut bytes: Vec<u8> = [cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx]
                                .iter()
                                .flat_map(|r| r.to_le_bytes().to_vec())
                                .collect();
                            bytestr.append(&mut bytes);
                        }
                        String::from_utf8(bytestr)
                            .unwrap_or_else(|_| "ERROR_FOUND".to_string())
                            .trim()
                            .to_string()
                    };

                    let stat = if cpu_name.to_uppercase().contains("EPYC") {
                        TestState::Pass
                    } else {
                        TestState::Fail
                    };

                    TestResult {
                        name: "Microcode support",
                        stat,
                        mesg: None,
                    }
                }),
                sub: vec![],
            },
            Test {
                name: "Secure Memory Encryption (SME)",
                gen_mask: SEV_MASK,
                run: Box::new(|| {
                    let res = unsafe { x86_64::__cpuid(0x8000001f) };

                    let stat = if (res.eax & 0x1) != 0 {
                        TestState::Pass
                    } else {
                        TestState::Fail
                    };

                    TestResult {
                        name: "Secure Memory Encryption (SME)",
                        stat,
                        mesg: None,
                    }
                }),
                sub: vec![],
            },
            Test {
                name: "Secure Encrypted Virtualization (SEV)",
                gen_mask: SEV_MASK,
                run: Box::new(|| {
                    let res = unsafe { x86_64::__cpuid(0x8000001f) };

                    let stat = if (res.eax & 0x1 << 1) != 0 {
                        TestState::Pass
                    } else {
                        TestState::Fail
                    };

                    TestResult {
                        name: "Secure Encrypted Virtualization (SEV)",
                        stat,
                        mesg: None,
                    }
                }),
                sub: vec![
                    Test {
                        name: "Encrypted State (SEV-ES)",
                        gen_mask: ES_MASK,
                        run: Box::new(|| {
                            let res = unsafe { x86_64::__cpuid(0x8000001f) };

                            let stat = if (res.eax & 0x1 << 3) != 0 {
                                TestState::Pass
                            } else {
                                TestState::Fail
                            };

                            TestResult {
                                name: "Encrypted State (SEV-ES)",
                                stat,
                                mesg: None,
                            }
                        }),
                        sub: vec![],
                    },
                    Test {
                        name: "Physical address bit reduction",
                        gen_mask: SEV_MASK,
                        run: Box::new(|| {
                            let res = unsafe { x86_64::__cpuid(0x8000001f) };
                            let field = res.ebx & 0b1111_1100_0000 >> 6;

                            TestResult {
                                name: "Physical address bit reduction",
                                stat: TestState::Pass,
                                mesg: Some(format!("{}", field)),
                            }
                        }),
                        sub: vec![],
                    },
                    Test {
                        name: "C-bit location",
                        gen_mask: SEV_MASK,
                        run: Box::new(|| {
                            let res = unsafe { x86_64::__cpuid(0x8000001f) };
                            let field = res.ebx & 0b01_1111;

                            TestResult {
                                name: "C-bit location",
                                stat: TestState::Pass,
                                mesg: Some(format!("{}", field)),
                            }
                        }),
                        sub: vec![],
                    },
                    Test {
                        name: "Number of encrypted guests supported simultaneously",
                        gen_mask: SEV_MASK,
                        run: Box::new(|| {
                            let res = unsafe { x86_64::__cpuid(0x8000001f) };
                            let field = res.ecx;

                            TestResult {
                                name: "Number of encrypted guests supported simultaneously",
                                stat: TestState::Pass,
                                mesg: Some(format!("{}", field)),
                            }
                        }),
                        sub: vec![],
                    },
                    Test {
                        name: "Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
                        gen_mask: SEV_MASK,
                        run: Box::new(|| {
                            let res = unsafe { x86_64::__cpuid(0x8000001f) };
                            let field = res.edx;

                            TestResult {
                                name: "Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
                                stat: TestState::Pass,
                                mesg: Some(format!("{}", field)),
                            }
                        }),
                        sub: vec![],
                    },
                ],
            },
            Test {
                name: "Page flush MSR",
                gen_mask: SEV_MASK,
                run: Box::new(|| {
                    let res = unsafe { x86_64::__cpuid(0x8000001f) };

                    let stat = if (res.eax & 0x1 << 2) != 0 {
                        TestState::Pass
                    } else {
                        TestState::Fail
                    };

                    TestResult {
                        name: "Page flush MSR",
                        stat,
                        mesg: None,
                    }
                }),
                sub: vec![],
            },
        ],
    }];

    tests
}

const INDENT: usize = 2;

pub fn cmd(gen: Option<SevGeneration>, quiet: bool) -> Result<()> {
    let tests = collect_tests();

    let mask = if let Some(SevGeneration::Sev) = gen {
        SEV_MASK
    } else {
        SEV_MASK | ES_MASK
    };

    if run_test(&tests, 0, quiet, mask) {
        Ok(())
    } else {
        Err(error::Context::new(
            "One or more tests in sevctl-ok reported a failure",
            Box::<Error>::new(ErrorKind::InvalidData.into()),
        ))
    }
}

fn run_test(tests: &[Test], level: usize, quiet: bool, mask: usize) -> bool {
    let mut passed = true;

    for t in tests {
        // Skip tests that aren't included in the specified generation.
        if (t.gen_mask & mask) != t.gen_mask {
            test_gen_not_included(t, level, quiet);
            continue;
        }

        let res = (t.run)();
        emit_result(&res, level, quiet);
        match res.stat {
            TestState::Pass => {
                if !run_test(&t.sub, level + INDENT, quiet, mask) {
                    passed = false;
                }
            }
            TestState::Fail => {
                passed = false;
                emit_skip(&t.sub, level + INDENT, quiet);
            }
            // Skipped tests are marked as skip before recursing. They are just emitted and not actually processed.
            TestState::Skip => unreachable!(),
        }
    }

    passed
}

fn emit_result(res: &TestResult, level: usize, quiet: bool) {
    if !quiet {
        let msg = match &res.mesg {
            Some(m) => format!(": {}", m),
            None => "".to_string(),
        };
        println!(
            "[ {:^4} ] {:width$}- {}{}",
            format!("{}", res.stat),
            "",
            res.name,
            msg,
            width = level
        )
    }
}

fn test_gen_not_included(test: &Test, level: usize, quiet: bool) {
    if !quiet {
        let tr_skip = TestResult {
            name: test.name,
            stat: TestState::Skip,
            mesg: None,
        };

        println!(
            "[ {:^4} ] {:width$}- {}",
            format!("{}", tr_skip.stat),
            "",
            tr_skip.name,
            width = level
        );
        emit_skip(&test.sub, level + INDENT, quiet);
    }
}

fn emit_skip(tests: &[Test], level: usize, quiet: bool) {
    if !quiet {
        for t in tests {
            let tr_skip = TestResult {
                name: t.name,
                stat: TestState::Skip,
                mesg: None,
            };

            println!(
                "[ {:^4} ] {:width$}- {}",
                format!("{}", tr_skip.stat),
                "",
                tr_skip.name,
                width = level
            );
            emit_skip(&t.sub, level + INDENT, quiet);
        }
    }
}
