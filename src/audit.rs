//! Append-only JSON-lines audit log of every decision the gate makes.
//! Records metadata only, never message contents.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use serde_json::{Value, json};

use crate::config::Config;

pub fn caller() -> String {
    std::env::var("SUDO_USER")
        .ok()
        .or_else(|| nix::unistd::User::from_uid(nix::unistd::getuid()).ok().flatten().map(|u| u.name))
        .unwrap_or_else(|| "unknown".into())
}

pub fn record(cfg: &Config, account: Option<&str>, command: &str, decision: &str, extra: Value) {
    let mut entry = json!({
        "ts": crate::outbox::now_rfc3339(),
        "caller": caller(),
        "account": account,
        "command": command,
        "decision": decision,
    });
    if let (Some(e), Value::Object(x)) = (entry.as_object_mut(), extra) {
        e.extend(x);
    }
    let path = cfg.audit_log();
    let result = std::fs::create_dir_all(&cfg.raw.state_dir).and_then(|_| {
        let mut f = OpenOptions::new().create(true).append(true).mode(0o600).open(&path)?;
        writeln!(f, "{entry}")
    });
    if let Err(e) = result {
        eprintln!("warning: cannot write audit log {}: {e}", path.display());
    }
}
