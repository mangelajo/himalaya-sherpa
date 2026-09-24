//! Agent-facing gate. Runs as the sherpa service user (via sudo), never as the agent.

use std::process::ExitCode;

use clap::Parser;
use himalaya_sherpa::cli::Cli;
use himalaya_sherpa::config::Config;
use himalaya_sherpa::gate::{Denied, Gate};
use himalaya_sherpa::himalaya::Failed;

fn main() -> ExitCode {
    // Files the gate creates (attachments) are readable by the agent's group only.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o027));
    let cli = Cli::parse();
    let json = cli.json;
    let result =
        Config::load(&Config::default_path()).and_then(|cfg| Gate::new(cfg, cli.account, json).run(cli.command));
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            let (code, message) = if let Some(d) = e.downcast_ref::<Denied>() {
                (3, format!("Denied by policy: {d}"))
            } else if let Some(f) = e.downcast_ref::<Failed>() {
                let m = f.message.strip_prefix("Error: ").unwrap_or(&f.message);
                (f.code.clamp(1, 255) as u8, format!("Error: {m}"))
            } else {
                (1, format!("Error: {e:#}"))
            };
            if json {
                println!("{}", serde_json::json!({ "error": message }));
            } else {
                eprintln!("{message}");
            }
            ExitCode::from(code)
        }
    }
}
