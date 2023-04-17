// SPDX-License-Identifier: Apache-2.0

use super::*;
use colorful::*;
use std::arch::x86_64;
use std::fmt;
use std::fs;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::str::from_utf8;

use anyhow::anyhow;

#[derive(StructOpt, PartialEq, Eq)]
pub enum SevGeneration {
    #[structopt(about = "Secure Encrypted Virtualization")]
    Sev,

    #[structopt(about = "SEV + Encrypted State")]
    Es,

    #[structopt(about = "SEV + Secure Nested Paging")]
    Snp,
}

impl SevGeneration {
    fn to_mask(&self) -> usize {
        match self {
            SevGeneration::Sev => SEV_MASK,
            SevGeneration::Es => SEV_MASK | ES_MASK,
            SevGeneration::Snp => SEV_MASK | ES_MASK | SNP_MASK,
        }
    }

    // Get the SEV generation of the processor currently running on the machine.
    // To do this, we execute a CPUID (label 0x80000001) and read the EAX
    // register as an array of bytes (each byte representing 8 bits of a 32-bit
    // value, thus the array is 4 bytes long). The formatting for these values is
    // as follows:
    //
    //  Base model:         bits 4:7
    //  Base family:        bits 8:11
    //  Extended model:     bits 16:19
    //  Extended family:    bits 20:27
    //
    // Extract the bit values from the array, and use them to calculate the MODEL
    // and FAMILY of the processor.
    //
    // The family calculation is as follows:
    //
    //      FAMILY = Base family + Extended family
    //
    // The model calculation is a follows:
    //
    //      MODEL = Base model | (Extended model << 4)
    //
    // Compare these values with the models and families of known processor generations to
    // determine which generation the current processor is a part of.
    fn current() -> Result<Self> {
        let cpuid = unsafe { x86_64::__cpuid(0x8000_0001) };
        let bytes: Vec<u8> = cpuid.eax.to_le_bytes().to_vec();

        let base_model = (bytes[0] & 0xF0) >> 4;
        let base_family = bytes[1] & 0x0F;

        let ext_model = bytes[2] & 0x0F;

        let ext_family = {
            let low = (bytes[2] & 0xF0) >> 4;
            let high = (bytes[3] & 0x0F) << 4;

            low | high
        };

        let model = (ext_model << 4) | base_model;
        let family = base_family + ext_family;

        let id = (model, family);

        let naples = (1, 23);
        let rome = (49, 23);
        let milan = (1, 25);
        let genoa = (17, 25);

        if id == naples {
            return Ok(SevGeneration::Sev);
        } else if id == rome {
            return Ok(SevGeneration::Es);
        } else if id == milan || id == genoa {
            return Ok(SevGeneration::Snp);
        }

        Err(anyhow!("processor is not of a known SEV generation"))
    }
}

type TestFn = dyn Fn() -> TestResult;

// SEV generation-specific bitmasks.
const SEV_MASK: usize = 1;
const ES_MASK: usize = 1 << 1;
const SNP_MASK: usize = 1 << 2;

struct Test {
    name: &'static str,
    gen_mask: usize,
    run: Box<TestFn>,
    sub: Vec<Test>,
}

struct TestResult {
    name: String,
    stat: TestState,
    mesg: Option<String>,
}

#[derive(PartialEq, Eq)]
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
    let tests = vec![
        Test {
            name: "AMD CPU",
            gen_mask: SEV_MASK,
            run: Box::new(|| {
                let res = unsafe { x86_64::__cpuid(0x0000_0000) };
                let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
                let name = from_utf8(&name[..]).unwrap_or("ERROR_FOUND");

                let stat = if name == "AuthenticAMD" {
                    TestState::Pass
                } else {
                    TestState::Fail
                };

                TestResult {
                    name: "AMD CPU".to_string(),
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
                                let mut bytes: Vec<u8> =
                                    [cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx]
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
                            name: "Microcode support".to_string(),
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
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let stat = if (res.eax & 0x1) != 0 {
                            TestState::Pass
                        } else {
                            TestState::Fail
                        };

                        TestResult {
                            name: "Secure Memory Encryption (SME)".to_string(),
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
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let stat = if (res.eax & 0x1 << 1) != 0 {
                            TestState::Pass
                        } else {
                            TestState::Fail
                        };

                        TestResult {
                            name: "Secure Encrypted Virtualization (SEV)".to_string(),
                            stat,
                            mesg: None,
                        }
                    }),
                    sub: vec![
                        Test {
                            name: "Encrypted State (SEV-ES)",
                            gen_mask: ES_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & 0x1 << 3) != 0 {
                                    TestState::Pass
                                } else {
                                    TestState::Fail
                                };

                                TestResult {
                                    name: "Encrypted State (SEV-ES)".to_string(),
                                    stat,
                                    mesg: None,
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "Secure Nested Paging (SEV-SNP)",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & 0x1 << 4) != 0 {
                                    TestState::Pass
                                } else {
                                    TestState::Fail
                                };

                                TestResult {
                                    name: "Secure Nested Paging (SEV-SNP)".to_string(),
                                    stat,
                                    mesg: None,
                                }
                            }),
                            sub: vec![Test {
                                name: "VM Permission Levels",
                                gen_mask: SNP_MASK,
                                run: Box::new(|| {
                                    let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                    let stat = if (res.eax & 0x1 << 5) != 0 {
                                        TestState::Pass
                                    } else {
                                        TestState::Fail
                                    };

                                    TestResult {
                                        name: "VM Permission Levels".to_string(),
                                        stat,
                                        mesg: None,
                                    }
                                }),
                                sub: vec![Test {
                                    name: "Number of VMPLs",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| {
                                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                        let num_vmpls = (res.ebx & 0xF000) >> 12;

                                        TestResult {
                                            name: "Number of VMPLs".to_string(),
                                            stat: TestState::Pass,
                                            mesg: Some(format!("{}", num_vmpls)),
                                        }
                                    }),
                                    sub: vec![],
                                }],
                            }],
                        },
                        Test {
                            name: "Physical address bit reduction",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = (res.ebx & 0b1111_1100_0000) >> 6;

                                TestResult {
                                    name: "Physical address bit reduction".to_string(),
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
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.ebx & 0b11_1111;

                                TestResult {
                                    name: "C-bit location".to_string(),
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
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.ecx;

                                TestResult {
                                    name: "Number of encrypted guests supported simultaneously"
                                        .to_string(),
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
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.edx;

                                TestResult {
                                    name:
                                        "Minimum ASID value for SEV-enabled, SEV-ES disabled guest"
                                            .to_string(),
                                    stat: TestState::Pass,
                                    mesg: Some(format!("{}", field)),
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "SEV enabled in KVM",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| sev_enabled_in_kvm(false)),
                            sub: vec![],
                        },
                        Test {
                            name: "SEV-ES enabled in KVM",
                            gen_mask: ES_MASK,
                            run: Box::new(|| sev_enabled_in_kvm(true)),
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev readable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_r),
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev writable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_w),
                            sub: vec![],
                        },
                    ],
                },
                Test {
                    name: "Page flush MSR",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let msr_flag = if (res.eax & 0x1 << 2) != 0 {
                            "ENABLED".green()
                        } else {
                            "DISABLED".yellow()
                        };

                        let name = format!("Page flush MSR: {}", msr_flag);

                        TestResult {
                            name,
                            /*
                             * Page flush MSR can be enabled/disabled.
                             * Therefore, if the flag is disabled, it doesn't
                             * necessarily mean that Page flush MSR *isn't*
                             * supported, but rather that it is supported yet
                             * currently disabled. So instead of returning
                             * TestState::Fail (indicating that Page flush MSR
                             * isn't supported), return TestState::Pass and
                             * indicate to the caller whether it is enabled or
                             * disabled.
                             */
                            stat: TestState::Pass,
                            mesg: None,
                        }
                    }),
                    sub: vec![],
                },
            ],
        },
        Test {
            name: "KVM Support",
            gen_mask: SEV_MASK,
            run: Box::new(has_kvm_support),
            sub: vec![],
        },
        Test {
            name: "memlock limit",
            gen_mask: SEV_MASK,
            run: Box::new(memlock_rlimit),
            sub: vec![],
        },
    ];

    tests
}

const INDENT: usize = 2;

pub fn cmd(gen: Option<SevGeneration>, quiet: bool) -> Result<()> {
    let tests = collect_tests();

    let mask = match gen {
        Some(g) => g.to_mask(),
        None => SevGeneration::current()
            .unwrap_or(SevGeneration::Snp)
            .to_mask(),
    };

    if run_test(&tests, 0, quiet, mask) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "One or more tests in sevctl-ok reported a failure"
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
            name: test.name.to_string(),
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
                name: t.name.to_string(),
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

fn dev_sev_r() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().read(true)) {
        Ok(_) => (TestState::Pass, "/dev/sev readable".to_string()),
        Err(e) => (TestState::Fail, format!("/dev/sev not readable: {}", e)),
    };

    TestResult {
        name: "Reading /dev/sev".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn dev_sev_w() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().write(true)) {
        Ok(_) => (TestState::Pass, "/dev/sev writable".to_string()),
        Err(e) => (TestState::Fail, format!("/dev/sev not writable: {}", e)),
    };

    TestResult {
        name: "Writing /dev/sev".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn dev_sev_rw(file: &mut fs::OpenOptions) -> Result<()> {
    let path = "/dev/sev";

    match file.open(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::Error::new(Box::new(e))),
    }
}

fn has_kvm_support() -> TestResult {
    let path = "/dev/kvm";

    let (stat, mesg) = match File::open(path) {
        Ok(kvm) => {
            let api_version = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xAE00, 0) };
            if api_version < 0 {
                (
                    TestState::Fail,
                    "Error - accessing KVM device node failed".to_string(),
                )
            } else {
                (TestState::Pass, format!("API version: {}", api_version))
            }
        }
        Err(e) => (TestState::Fail, format!("Error reading {}: ({})", path, e)),
    };

    TestResult {
        name: "KVM supported".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn sev_enabled_in_kvm(es: bool) -> TestResult {
    let path_loc = if es {
        "/sys/module/kvm_amd/parameters/sev_es"
    } else {
        "/sys/module/kvm_amd/parameters/sev"
    };
    let path = std::path::Path::new(path_loc);

    let (stat, mesg) = if path.exists() {
        match std::fs::read_to_string(path_loc) {
            Ok(result) => {
                if result.trim() == "1" || result.trim() == "Y" {
                    (TestState::Pass, "enabled".to_string())
                } else {
                    (
                        TestState::Fail,
                        format!("Error - contents read from {}: {}", path_loc, result.trim()),
                    )
                }
            }
            Err(e) => (
                TestState::Fail,
                format!("Error - (unable to read {}): {}", path_loc, e,),
            ),
        }
    } else {
        (
            TestState::Fail,
            format!("Error - {} does not exist", path_loc),
        )
    };

    TestResult {
        name: if es {
            "SEV-ES enabled in KVM"
        } else {
            "SEV enabled in KVM"
        }
        .to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn memlock_rlimit() -> TestResult {
    let mut rlimit = MaybeUninit::uninit();
    let res = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, rlimit.as_mut_ptr()) };

    let (stat, mesg) = if res == 0 {
        let r = unsafe { rlimit.assume_init() };

        (
            TestState::Pass,
            format!("Soft: {} | Hard: {}", r.rlim_cur, r.rlim_max),
        )
    } else {
        (
            TestState::Fail,
            "Unable to retrieve memlock resource limits".to_string(),
        )
    };

    TestResult {
        name: "Memlock resource limit".to_string(),
        stat,
        mesg: Some(mesg),
    }
}
