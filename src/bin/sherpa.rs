//! Agent-facing gate, run as the sherpa service user via sudo. Transitional: the
//! socket transport replaces it.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use himalaya_sherpa::config::Config;
use himalaya_sherpa::gate::{self, Caller, Request};

fn main() -> ExitCode {
    let stdin = || -> anyhow::Result<Option<Vec<u8>>> {
        let mut input = std::io::stdin();
        if input.is_terminal() {
            return Ok(None);
        }
        let mut buf = Vec::new();
        input.read_to_end(&mut buf)?;
        Ok(Some(buf))
    };
    let caller = Caller {
        name: std::env::var("SUDO_USER").unwrap_or_else(|_| himalaya_sherpa::audit::local_user()),
        ..Default::default()
    };
    let cfg = match Config::load(&Config::default_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    // Files named by --attach are not read here: under sudo they would be read with
    // the service user's privileges.
    let resp = gate::handle(
        cfg,
        Request {
            argv: std::env::args().skip(1).collect(),
            caller,
            files: BTreeMap::new(),
            stdin: &stdin,
        },
    );
    let _ = std::io::stdout().write_all(&resp.stdout);
    let _ = std::io::stderr().write_all(&resp.stderr);
    if !resp.files.is_empty() {
        eprintln!("Error: attachment downloads need the himalaya-sherpa socket client");
        return ExitCode::FAILURE;
    }
    ExitCode::from(resp.exit.clamp(0, 255) as u8)
}
