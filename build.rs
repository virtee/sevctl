// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::{env, fs, io, process};

const COMMANDS: [&str; 1] = ["sevctl"];

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        Some(outdir) => outdir,
        None => {
            panic!("OUT_DIR environment variable not defined.");
        }
    };
    fs::create_dir_all(&outdir).unwrap();

    for command in COMMANDS {
        if let Err(err) = generate_man_page(&outdir, command) {
            println!(
                "failed to generate man page: {} (is asciidoctor installed?)",
                err
            );
        }
    }
}

fn generate_man_page<P: AsRef<Path>>(outdir: P, command: &str) -> io::Result<()> {
    if let Err(err) = process::Command::new("asciidoctor").output() {
        eprintln!("Error from running 'asciidoctor': {}", err);
        return Err(err);
    }

    let outdir = outdir.as_ref();
    let outfile = outdir.join(format!("{}.1", command));
    let cwd = env::current_dir()?;
    let txt_path = cwd.join("docs").join(format!("{}.1.adoc", command));

    let result = process::Command::new("asciidoctor")
        .arg("--doctype")
        .arg("manpage")
        .arg("--backend")
        .arg("manpage")
        .arg("--out-file")
        .arg(&outfile)
        .arg(&txt_path)
        .spawn()?
        .wait()?;
    if !result.success() {
        let msg = format!("'asciidoctor' failed with exit code {:?}", result.code());
        return Err(io::Error::new(io::ErrorKind::Other, msg));
    }
    Ok(())
}
