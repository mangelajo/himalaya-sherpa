//! Wire protocol between the agent-side client and `sherpa-gate`.
//!
//! Each message is a 4-byte big-endian length followed by that many bytes of JSON.
//! Binary payloads are base64 strings. A conversation is:
//!
//! ```text
//! client: Request { argv, stdin-tty, files }
//! server: NeedStdin            (only if the command reads stdin and it is not a terminal)
//! client: Stdin { data }
//! server: Done { exit, stdout, stderr, files }
//! ```
//!
//! The server treats everything the client sends as untrusted: frames are size-limited
//! and the arguments go through the same parser as any other agent input.

use std::io::{self, Read, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 48 << 20;
/// Most files a client may send with one request (`--attach`).
pub const MAX_FILES: usize = 16;
/// Largest total size of the files sent with one request.
pub const MAX_FILES_BYTES: usize = 24 << 20;
/// Largest stdin a client sends.
pub const MAX_STDIN: usize = 24 << 20;

/// Binary data, base64-encoded on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map(Bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClientMsg {
    #[serde(rename_all = "kebab-case")]
    Request {
        version: u32,
        argv: Vec<String>,
        /// The client's stdin is a terminal: the server never asks for it.
        stdin_tty: bool,
        #[serde(default)]
        files: Vec<InFile>,
    },
    Stdin {
        data: Bytes,
    },
}

/// A file named by `--attach`, read by the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct InFile {
    pub path: String,
    pub data: Bytes,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ServerMsg {
    NeedStdin,
    #[serde(rename_all = "kebab-case")]
    Done {
        exit: i32,
        stdout: Bytes,
        stderr: Bytes,
        #[serde(default)]
        files: Vec<OutFile>,
        #[serde(default)]
        announce_files: bool,
    },
}

/// A file for the client to save (downloaded attachments).
#[derive(Debug, Serialize, Deserialize)]
pub struct OutFile {
    pub dir: Option<String>,
    pub name: String,
    pub data: Bytes,
}

impl ServerMsg {
    /// A final answer carrying only an error message.
    pub fn error(message: &str) -> Self {
        ServerMsg::Done {
            exit: 1,
            stdout: Bytes::default(),
            stderr: Bytes(format!("Error: {message}\n").into_bytes()),
            files: vec![],
            announce_files: false,
        }
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn write_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(invalid_from)?;
    if body.len() > MAX_FRAME {
        return Err(invalid(format!(
            "message of {} bytes exceeds the frame limit",
            body.len()
        )));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

fn invalid_from(e: serde_json::Error) -> io::Error {
    invalid(e.to_string())
}

pub fn read_msg<T: DeserializeOwned>(r: &mut impl Read) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(invalid(format!("frame of {n} bytes exceeds the limit")));
    }
    // Grow the buffer as data arrives instead of trusting the announced length.
    let mut buf = Vec::new();
    r.take(n as u64).read_to_end(&mut buf)?;
    if buf.len() != n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame"));
    }
    serde_json::from_slice(&buf).map_err(invalid_from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        let msg = ClientMsg::Request {
            version: VERSION,
            argv: vec!["envelope".into(), "list".into()],
            stdin_tty: false,
            files: vec![InFile {
                path: "/tmp/a b".into(),
                data: Bytes(vec![0, 255, 10]),
            }],
        };
        write_msg(&mut buf, &msg).unwrap();
        let back: ClientMsg = read_msg(&mut buf.as_slice()).unwrap();
        let ClientMsg::Request { argv, files, .. } = back else {
            panic!()
        };
        assert_eq!(argv, ["envelope", "list"]);
        assert_eq!(files[0].data.0, [0, 255, 10]);
    }

    #[test]
    fn rejects_oversized_truncated_and_garbage_frames() {
        let huge = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(read_msg::<ClientMsg>(&mut huge.as_slice()).is_err());

        let mut truncated = 100u32.to_be_bytes().to_vec();
        truncated.extend(b"{\"type\":");
        assert!(read_msg::<ClientMsg>(&mut truncated.as_slice()).is_err());

        let mut garbage = 5u32.to_be_bytes().to_vec();
        garbage.extend(b"hello");
        assert!(read_msg::<ClientMsg>(&mut garbage.as_slice()).is_err());

        let mut bad_b64 = Vec::new();
        let body = br#"{"type":"stdin","data":"***"}"#;
        bad_b64.extend((body.len() as u32).to_be_bytes());
        bad_b64.extend(body);
        assert!(read_msg::<ClientMsg>(&mut bad_b64.as_slice()).is_err());
    }
}
