//! `sherpa-gate`: serve the gate on a Unix socket.
//!
//! Two modes: a standalone listener (containers, or hosts without systemd), and one
//! connection on stdin, for systemd socket activation with `Accept=yes`, where each
//! connection gets a fresh process that systemd starts with a fixed environment.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::config::Config;
use crate::gate::{self, Caller, Request};
use crate::proto::{self, Bytes, ClientMsg, ServerMsg};

pub struct ServeOptions {
    pub config: PathBuf,
    /// Name recorded as the caller in the audit log and outbox.
    pub agent: String,
    /// Peer uids allowed to connect. Empty: whoever can open the socket.
    pub allow_uids: Vec<u32>,
    /// Limit for each read from or write to the client.
    pub timeout: Duration,
}

fn log(opts: &ServeOptions, msg: &str) {
    // stderr goes to the journal (systemd) or the container log, never to the client.
    eprintln!("sherpa-gate[{}]: {msg}", opts.agent);
}

/// Serve one connection: read a request, run it through the gate, answer.
pub fn handle_connection(stream: &UnixStream, opts: &ServeOptions) -> Result<()> {
    stream.set_read_timeout(Some(opts.timeout))?;
    stream.set_write_timeout(Some(opts.timeout))?;
    let cred = getsockopt(stream, PeerCredentials).ok();
    let caller = Caller {
        name: opts.agent.clone(),
        uid: cred.map(|c| c.uid()),
        pid: cred.map(|c| c.pid()),
    };
    let mut w = stream;

    if !opts.allow_uids.is_empty() && !caller.uid.is_some_and(|u| opts.allow_uids.contains(&u)) {
        log(
            opts,
            &format!("refused connection from uid {:?} pid {:?}", caller.uid, caller.pid),
        );
        proto::write_msg(
            &mut w,
            &ServerMsg::error("this user is not allowed to use the email gate"),
        )?;
        return Ok(());
    }

    let (argv, stdin_tty, in_files) = match proto::read_msg(&mut w)? {
        ClientMsg::Request {
            version,
            argv,
            stdin_tty,
            files,
        } => {
            if version != proto::VERSION {
                proto::write_msg(
                    &mut w,
                    &ServerMsg::error(&format!(
                        "protocol version {version} is not supported (the gate speaks {}); update the client",
                        proto::VERSION
                    )),
                )?;
                return Ok(());
            }
            (argv, stdin_tty, files)
        }
        ClientMsg::Stdin { .. } => bail!("protocol error: expected a request"),
    };
    let total: usize = in_files.iter().map(|f| f.data.0.len()).sum();
    if in_files.len() > proto::MAX_FILES || total > proto::MAX_FILES_BYTES {
        proto::write_msg(
            &mut w,
            &ServerMsg::error(&format!(
                "too many or too large attachments (at most {} files, {} MiB in total)",
                proto::MAX_FILES,
                proto::MAX_FILES_BYTES >> 20
            )),
        )?;
        return Ok(());
    }
    let files: BTreeMap<String, Vec<u8>> = in_files.into_iter().map(|f| (f.path, f.data.0)).collect();

    // Load the policy for every connection, so an installed change applies at once.
    let cfg = match Config::load(&opts.config) {
        Ok(c) => c,
        Err(e) => {
            log(opts, &format!("{e:#}"));
            proto::write_msg(
                &mut w,
                &ServerMsg::error("the email gate is misconfigured; tell the user to run `sherpa-admin doctor`"),
            )?;
            return Ok(());
        }
    };

    let stdin = || -> Result<Option<Vec<u8>>> {
        if stdin_tty {
            return Ok(None);
        }
        let mut s = stream;
        proto::write_msg(&mut s, &ServerMsg::NeedStdin)?;
        match proto::read_msg(&mut s)? {
            ClientMsg::Stdin { data } if data.0.len() <= proto::MAX_STDIN => Ok(Some(data.0)),
            ClientMsg::Stdin { .. } => bail!("standard input is larger than {} MiB", proto::MAX_STDIN >> 20),
            ClientMsg::Request { .. } => bail!("protocol error: expected standard input"),
        }
    };
    let resp = gate::handle(
        cfg,
        Request {
            argv,
            caller,
            files,
            stdin: &stdin,
        },
    );
    proto::write_msg(
        &mut w,
        &ServerMsg::Done {
            exit: resp.exit,
            stdout: Bytes(resp.stdout),
            stderr: Bytes(resp.stderr),
            files: resp
                .files
                .into_iter()
                .map(|f| proto::OutFile {
                    dir: f.dir,
                    name: f.name,
                    data: Bytes(f.data),
                })
                .collect(),
            announce_files: resp.announce_files,
        },
    )?;
    Ok(())
}

/// Serve the connection systemd passed on stdin (`Accept=yes`).
pub fn serve_stdin(opts: &ServeOptions) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = io::stdin().as_raw_fd();
    // SAFETY: fd 0 is owned by this process for its whole lifetime; the stream is
    // leaked below so it is never closed twice.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if getsockopt(&stream, PeerCredentials).is_err() {
        std::mem::forget(stream);
        bail!("standard input is not a Unix socket; run under systemd socket activation with Accept=yes");
    }
    let result = handle_connection(&stream, opts);
    std::mem::forget(stream);
    result
}

/// Bind `path`, replacing a stale socket but never another kind of file.
pub fn bind(path: &Path, mode: u32) -> Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).with_context(|| format!("cannot remove stale {}", path.display()))?
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("cannot bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot set the mode of {}", path.display()))?;
    Ok(listener)
}

/// Accept connections until the process is stopped, one thread per connection.
pub fn serve_listener(listener: UnixListener, opts: Arc<ServeOptions>, max_connections: usize) -> Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log(&opts, &format!("accept failed: {e}"));
                continue;
            }
        };
        if active.load(Ordering::SeqCst) >= max_connections {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let _ = proto::write_msg(
                &mut &stream,
                &ServerMsg::error("the email gate is busy; try again shortly"),
            );
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (opts, active) = (opts.clone(), active.clone());
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(&stream, &opts) {
                log(&opts, &format!("connection failed: {e:#}"));
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}
