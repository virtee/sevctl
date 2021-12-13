// SPDX-License-Identifier: Apache-2.0

use crate::error::{Contextual, Result};

use std::convert::{From, TryFrom};
use std::fs;
use std::mem::size_of;
use std::path::PathBuf;
use std::slice::from_raw_parts;

use ::sev::certs::sev::Certificate;
use ::sev::{launch::sev, session};

use codicon::{Decoder, Encoder};

pub fn cmd(name: Option<String>, pdh: PathBuf, policy: u32) -> Result<()> {
    let (tik_fname, tek_fname, godh_fname, session_fname) = file_names(name);

    let session = session::Session::try_from(sev::Policy::from(policy))
        .context("couldn't build launch session buffer from given policy")?;
    let tik = &session.tik;
    let tek = &session.tek;

    let pdh_file = fs::File::open(pdh).context("couldn't open PDH file pointed to by path")?;
    let pdh = Certificate::decode(pdh_file, ()).unwrap();

    let start = session
        .start_pdh(pdh)
        .context("could not start session based off of provided certificate chain")?;

    let launch_blob = unsafe {
        from_raw_parts(
            &start.session as *const sev::Session as *const u8,
            size_of::<sev::Session>(),
        )
    };
    let launch_blob = base64::encode(launch_blob);

    let godh = unsafe {
        from_raw_parts(
            &start.cert as *const Certificate as *const u8,
            size_of::<Certificate>(),
        )
    };
    let godh = base64::encode(godh);

    let mut tik_file = fs::File::create(tik_fname).context("TIK file could not be created")?;
    let mut tek_file = fs::File::create(tek_fname).context("TEK file could not be created")?;

    tik.encode(&mut tik_file, ())
        .context("TIK could not be encoded into file")?;
    tek.encode(&mut tek_file, ())
        .context("TEK could not be encoded into file")?;

    fs::write(session_fname, launch_blob).context("could not write base64 encoded session")?;
    fs::write(godh_fname, godh).context("could not write base64 encoded godh")?;

    Ok(())
}

fn file_names(name: Option<String>) -> (String, String, String, String) {
    let prefix = match name {
        Some(n) => n,
        None => "vm".to_string(),
    };

    let tik = prefix.clone() + "_tik.bin";
    let tek = prefix.clone() + "_tek.bin";
    let godh = prefix.clone() + "_godh.b64";
    let session = prefix + "_session.b64";

    (tik, tek, godh, session)
}
