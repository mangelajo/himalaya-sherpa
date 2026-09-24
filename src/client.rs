//! The agent-side client: forwards a command to `sherpa-gate` over a Unix socket.
//!
//! It holds no credentials and makes no policy decisions; the gate re-parses and
//! checks everything. What it does locally, with the agent's own privileges, is file
//! I/O: it reads the files named by `--attach` and writes downloaded attachments.

use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::gate::safe_file_name;
use crate::proto::{self, Bytes, ClientMsg, InFile, ServerMsg};

pub const SOCKET_DIR: &str = "/run/himalaya-sherpa";

/// `$SHERPA_SOCKET`, or `/run/himalaya-sherpa/<user>.sock`.
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SHERPA_SOCKET").filter(|p| !p.is_empty()) {
        return p.into();
    }
    Path::new(SOCKET_DIR).join(format!("{}.sock", crate::audit::local_user()))
}

/// The values of `--attach` options, up to a `--` separator.
pub fn attach_paths(argv: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        } else if a == "--attach" {
            if let Some(v) = it.next() {
                paths.push(v.clone());
            }
        } else if let Some(v) = a.strip_prefix("--attach=") {
            paths.push(v.to_string());
        }
    }
    paths
}

fn read_limited(r: impl Read, limit: usize, what: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > limit {
        bail!("{what} is larger than {} MiB", limit >> 20);
    }
    Ok(buf)
}

/// A path in `dir` for `name` that does not exist yet: `name`, `name (1)`, ...
fn free_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (1..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

fn save(file: &proto::OutFile) -> Result<PathBuf> {
    let dir = PathBuf::from(file.dir.as_deref().unwrap_or("."));
    let path = free_path(&dir, &safe_file_name(&file.name));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(&file.data.0)?;
    Ok(path)
}

/// Run one command through the gate and return the exit code.
pub fn run(argv: Vec<String>) -> i32 {
    match run_inner(argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            1
        }
    }
}

fn run_inner(argv: Vec<String>) -> Result<i32> {
    let mut files = Vec::new();
    for path in attach_paths(&argv) {
        let f = std::fs::File::open(&path).with_context(|| format!("cannot read attachment {path}"))?;
        let data = read_limited(f, proto::MAX_FILES_BYTES, &format!("attachment {path}"))?;
        files.push(InFile {
            path,
            data: Bytes(data),
        });
    }

    let path = socket_path();
    let stream = UnixStream::connect(&path).with_context(|| {
        format!(
            "cannot reach the email gate at {} (email access goes through himalaya-sherpa; \
             tell the user the service is not reachable)",
            path.display()
        )
    })?;
    let mut s = &stream;
    let stdin_tty = std::io::stdin().is_terminal();
    proto::write_msg(
        &mut s,
        &ClientMsg::Request {
            version: proto::VERSION,
            argv,
            stdin_tty,
            files,
        },
    )?;

    loop {
        match proto::read_msg(&mut s).context("lost the connection to the email gate")? {
            ServerMsg::NeedStdin => {
                let data = read_limited(std::io::stdin().lock(), proto::MAX_STDIN, "standard input")?;
                proto::write_msg(&mut s, &ClientMsg::Stdin { data: Bytes(data) })?;
            }
            ServerMsg::Done {
                exit,
                stdout,
                stderr,
                files,
                announce_files,
            } => {
                std::io::stdout().write_all(&stdout.0)?;
                std::io::stderr().write_all(&stderr.0)?;
                let mut failed = false;
                for f in &files {
                    match save(f) {
                        Ok(p) if announce_files => println!("Saved {} ({} B)", p.display(), f.data.0.len()),
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Error: {e:#}");
                            failed = true;
                        }
                    }
                }
                std::io::stdout().flush()?;
                return Ok(if failed && exit == 0 { 1 } else { exit });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn finds_attach_values() {
        let argv = v(&[
            "message",
            "compose",
            "--attach",
            "a.pdf",
            "--attach=b c.txt",
            "--body",
            "x",
        ]);
        assert_eq!(attach_paths(&argv), ["a.pdf", "b c.txt"]);
        assert!(attach_paths(&v(&["message", "send", "--", "--attach", "x"])).is_empty());
    }

    #[test]
    fn never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("r.csv"), "x").unwrap();
        std::fs::write(dir.path().join("r (1).csv"), "x").unwrap();
        assert_eq!(free_path(dir.path(), "r.csv"), dir.path().join("r (2).csv"));
        assert_eq!(free_path(dir.path(), "new"), dir.path().join("new"));
    }
}
