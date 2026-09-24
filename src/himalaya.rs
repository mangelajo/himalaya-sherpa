//! Running the real himalaya binary with a controlled configuration and environment.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::Config;

pub struct Himalaya<'a> {
    pub cfg: &'a Config,
    pub account: Option<String>,
}

pub struct Output {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// himalaya exited with an error. Carries its (cleaned) stderr and exit code.
#[derive(Debug)]
pub struct Failed {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failed {}

/// Drop himalaya's hints about options the agent cannot use (`--log-level`, `-c`).
pub fn clean_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut out: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.contains("--log-level") || line.trim() == "Suggestions:" {
            continue;
        }
        out.push(line);
    }
    out.join("\n").trim().to_string()
}

impl Himalaya<'_> {
    pub fn command(&self, json: bool) -> Command {
        let raw = &self.cfg.raw;
        let mut cmd = Command::new(&raw.himalaya);
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &raw.state_dir)
            .env("LANG", "C.UTF-8")
            .envs(&raw.env)
            .arg("-c")
            .arg(&raw.himalaya_config);
        if let Some(account) = &self.account {
            cmd.arg("-a").arg(account);
        }
        if json {
            cmd.arg("--json");
        }
        cmd
    }

    pub fn run<S: AsRef<str>>(&self, json: bool, args: &[S], stdin: Option<&[u8]>) -> Result<Output> {
        let mut cmd = self.command(json);
        cmd.args(args.iter().map(|a| a.as_ref()))
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot run {}", self.cfg.raw.himalaya.display()))?;
        let writer = stdin.map(|data| {
            let mut pipe = child.stdin.take().expect("piped stdin");
            let data = data.to_vec();
            std::thread::spawn(move || pipe.write_all(&data))
        });
        let out = child.wait_with_output()?;
        if let Some(w) = writer {
            // A closed pipe just means himalaya did not need all of stdin.
            let _ = w.join();
        }
        Ok(Output {
            code: out.status.code().unwrap_or(1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    /// Run and return stdout, or fail with himalaya's error.
    pub fn run_ok<S: AsRef<str>>(&self, json: bool, args: &[S], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let out = self.run(json, args, stdin)?;
        if out.code != 0 {
            let mut message = clean_stderr(&out.stderr);
            if message.is_empty() {
                message = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
            return Err(Failed {
                code: out.code,
                message,
            }
            .into());
        }
        Ok(out.stdout)
    }

    /// The raw RFC 5322 bytes of a message. Does not change its seen flag.
    pub fn raw_message(&self, mailbox: Option<&str>, id: &str) -> Result<Vec<u8>> {
        let mut args = vec!["message", "read", "--raw"];
        if let Some(m) = mailbox {
            args.extend(["-m", m]);
        }
        args.push(id);
        self.run_ok(false, &args, None)
    }
}

/// Accounts defined in the himalaya configuration: (name, is default).
pub fn accounts(cfg: &Config) -> Result<Vec<(String, bool)>> {
    let path = &cfg.raw.himalaya_config;
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).with_context(|| format!("invalid TOML in {}", path.display()))?;
    let Some(accounts) = doc.get("accounts").and_then(|a| a.as_table()) else {
        bail!("no [accounts] in {}", path.display());
    };
    Ok(accounts
        .iter()
        .map(|(name, a)| {
            (
                name.clone(),
                a.get("default").and_then(|d| d.as_bool()).unwrap_or(false),
            )
        })
        .collect())
}

/// The account himalaya uses when none is given.
pub fn default_account(cfg: &Config) -> Result<String> {
    let all = accounts(cfg)?;
    if let Some((name, _)) = all.iter().find(|(_, d)| *d) {
        return Ok(name.clone());
    }
    match all.as_slice() {
        [(name, _)] => Ok(name.clone()),
        _ => bail!("no default account configured; pass -a <ACCOUNT>"),
    }
}
