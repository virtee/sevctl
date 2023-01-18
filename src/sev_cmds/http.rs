// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::result::Result;

use native_tls::TlsConnector;
use url::Url;

#[derive(Debug)]
pub struct Response {
    #[allow(dead_code)]
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    pub fn header(&self, find: &str) -> Option<&str> {
        let mut find = find.to_string();
        find.make_ascii_lowercase();
        self.headers.get(&find).map(|s| s.as_str())
    }

    pub fn into_reader(self) -> impl Read + Send {
        std::io::Cursor::new(self.body)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    MalformedResponse,
    NoHost,
    NoPort,
    NoStatus,
    Status(u16, Response),
    Tls(Box<dyn std::error::Error + Send + Sync>),
    UrlParse(url::ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub fn get(url: &str) -> Result<Response, Error> {
    let url = Url::parse(url).map_err(Error::UrlParse)?;
    let host = url.host_str().ok_or(Error::NoHost)?;
    let port = url.port_or_known_default().ok_or(Error::NoPort)?;

    let connector = TlsConnector::new().map_err(|e| Error::Tls(Box::new(e)))?;
    let stream = TcpStream::connect(format!("{}:{}", host, port)).map_err(Error::Io)?;
    let mut stream = connector
        .connect(host, stream)
        .map_err(|e| Error::Tls(Box::new(e)))?;

    let buf = b"GET"
        .iter()
        .chain(b" ".iter())
        .chain(url.path().as_bytes().iter())
        .chain(b" HTTP/1.0".iter())
        .chain(b"\r\n\r\n".iter())
        .copied()
        .collect::<Vec<u8>>();

    stream.write_all(&buf).map_err(Error::Io)?;
    let mut rsp = vec![];
    stream.read_to_end(&mut rsp).map_err(Error::Io)?;

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut response = httparse::Response::new(&mut headers);

    let pos = match response.parse(&rsp).map_err(|_| Error::MalformedResponse)? {
        httparse::Status::Complete(p) => p,
        _ => return Err(Error::MalformedResponse),
    };

    let status = response.code.ok_or(Error::NoStatus)?;
    let body = rsp[pos..].to_vec();

    let headers = headers
        .iter()
        .filter_map(|h| {
            let mut key = h.name.to_string();
            key.make_ascii_lowercase();

            let val = String::from_utf8(h.value.to_vec());
            let res = match (key, val) {
                (k, Ok(v)) => Ok((k, v)),
                _ => Err(()),
            };

            res.ok()
        })
        .collect();

    let response = Response {
        status,
        headers,
        body,
    };

    // AKA not HTTP 200
    if !(200..300).contains(&status) {
        return Err(Error::Status(status, response));
    }

    Ok(response)
}
