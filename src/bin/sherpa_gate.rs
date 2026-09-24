//! The email gate service. Runs as the sherpa service user, holds the credentials,
//! and serves agents over a Unix socket.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use himalaya_sherpa::config::Config;
use himalaya_sherpa::server::{self, ServeOptions};

#[derive(Parser)]
#[command(name = "sherpa-gate", version, about = "The himalaya-sherpa email gate service.")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve agents on a Unix socket.
    Serve {
        /// Agent name, recorded in the audit log and outbox.
        #[arg(long)]
        agent: String,
        /// Listen on this socket path.
        #[arg(long, required_unless_present = "stdio", conflicts_with = "stdio")]
        socket: Option<PathBuf>,
        /// Serve the single connection on stdin (systemd socket activation, Accept=yes).
        #[arg(long)]
        stdio: bool,
        /// Only accept connections from these uids (repeatable). Default: anyone who can open the socket.
        #[arg(long = "allow-uid")]
        allow_uids: Vec<u32>,
        /// Mode of the socket file, in octal.
        #[arg(long, default_value = "660", value_parser = parse_mode)]
        socket_mode: u32,
        /// Concurrent connections served (listener mode).
        #[arg(long, default_value_t = 8)]
        max_connections: usize,
        /// Seconds to wait for the client on each read or write.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// Policy file (default: $SHERPA_CONFIG or /etc/himalaya-sherpa/sherpa.toml).
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8)
        .ok()
        .filter(|m| *m <= 0o777)
        .ok_or_else(|| format!("{s:?} is not an octal file mode"))
}

fn main() -> ExitCode {
    // Everything the gate creates (outbox, staged attachments) is private.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let Cmd::Serve {
        agent,
        socket,
        stdio,
        allow_uids,
        socket_mode,
        max_connections,
        timeout,
        config,
    } = Cli::parse().command;
    let opts = ServeOptions {
        config: config.unwrap_or_else(Config::default_path),
        agent,
        allow_uids,
        timeout: Duration::from_secs(timeout),
    };
    let result = if stdio {
        server::serve_stdin(&opts)
    } else {
        let path = socket.expect("clap requires --socket without --stdio");
        server::bind(&path, socket_mode).and_then(|l| {
            eprintln!("sherpa-gate[{}]: listening on {}", opts.agent, path.display());
            server::serve_listener(l, Arc::new(opts), max_connections)
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sherpa-gate: {e:#}");
            ExitCode::FAILURE
        }
    }
}
