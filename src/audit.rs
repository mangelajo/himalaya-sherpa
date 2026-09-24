//! Append-only JSON-lines audit log of every decision the gate makes.
//! Records metadata only, never message contents.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use serde_json::{Value, json};

use crate::config::Config;

/// Name of the user running this process.
pub fn local_user() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| "unknown".into())
}

/// Append one decision to the audit log. Callers must treat a failure as fatal:
/// an action that cannot be recorded must not be carried out or reported.
pub fn record(
    cfg: &Config,
    caller: &str,
    account: Option<&str>,
    command: &str,
    decision: &str,
    extra: Value,
) -> std::io::Result<()> {
    let mut entry = json!({
        "ts": crate::outbox::now_rfc3339(),
        "caller": caller,
        "account": account,
        "command": command,
        "decision": decision,
    });
    if let (Some(e), Value::Object(x)) = (entry.as_object_mut(), extra) {
        e.extend(x);
    }
    std::fs::create_dir_all(&cfg.raw.state_dir)?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(cfg.audit_log())?;
    // One write per line, so concurrent gates never interleave partial lines.
    f.write_all(format!("{entry}\n").as_bytes())
}
