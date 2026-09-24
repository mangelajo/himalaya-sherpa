//! The policy gate: validates each agent command, classifies the messages it
//! touches, and runs himalaya on the agent's behalf.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use mail_parser::MessageParser;
use regex::Regex;
use serde_json::{Value, json};

use crate::audit;
use crate::classify::{self, Action, Facts, Verdict};
use crate::cli::*;
use crate::config::{Config, SendMode, WithheldStyle};
use crate::himalaya::{self, Himalaya};
use crate::outbox::{self, Entry, Outbox, Status};
use crate::render;

/// A request refused by policy. The message is shown to the agent verbatim.
#[derive(Debug)]
pub struct Denied(pub String);

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Denied {}

fn deny<T>(msg: impl Into<String>) -> Result<T> {
    Err(Denied(msg.into()).into())
}

const DONT_WORK_AROUND: &str = "Do not retry or try to achieve this by other means.";

const AUDIT_FAILURE: &[u8] =
    b"Error: the email gate cannot write its audit log, so it returns nothing. Tell the user.\n";

/// Largest total size of attachments returned by one `attachment download`.
pub const MAX_DOWNLOAD_BYTES: usize = 48 << 20;

/// Who is calling the gate.
#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// Agent name, from the service configuration.
    pub name: String,
    /// Peer credentials of the connection, as seen by the kernel.
    pub uid: Option<u32>,
    pub pid: Option<i32>,
}

/// A file handed back to the client (downloaded attachments). The client writes it,
/// with its own privileges, under `dir` (a path of its choosing) or its current directory.
#[derive(Debug, Clone)]
pub struct OutFile {
    pub dir: Option<String>,
    pub name: String,
    pub data: Vec<u8>,
}

/// Result of one gate invocation.
#[derive(Debug, Default)]
pub struct Response {
    pub exit: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub files: Vec<OutFile>,
    /// Whether the client should print where it saved `files`.
    pub announce_files: bool,
}

/// Supplies the client's standard input when a command needs it: `None` when the
/// client's stdin is a terminal. Called at most once, and only by commands that
/// read stdin, so a client with an idle open stdin never blocks other commands.
pub type StdinSource<'a> = dyn Fn() -> Result<Option<Vec<u8>>> + 'a;

/// One command from the agent.
pub struct Request<'a> {
    /// Arguments, without the program name.
    pub argv: Vec<String>,
    pub caller: Caller,
    /// Contents of the files named by `--attach`, read by the client, keyed by the path given.
    pub files: BTreeMap<String, Vec<u8>>,
    pub stdin: &'a StdinSource<'a>,
}

/// Parse and run one agent command. Never panics on bad input; every failure becomes
/// an error response.
/// Words in a rejected command that suggest the agent is reaching for account
/// settings, raw protocol access or configuration: forwarding and filters (the classic
/// takeover and exfiltration tools), credentials, and ways around the send policy.
const SUSPICIOUS_WORDS: &[&str] = &[
    "forward",
    "forwarding",
    "auto-forwarding",
    "autoforwarding",
    "filter",
    "filters",
    "delegate",
    "delegates",
    "send-as",
    "sendas",
    "settings",
    "rule",
    "rules",
    "vacation",
    "vacation-response",
    "identity",
    "submission",
    "configure",
    "config",
    "password",
    "secret",
    "raw",
    "smtp",
    "imap",
    "jmap",
    "gmail",
    "msgraph",
    "sieve",
];

/// The leading command words of a rejected command line, without any free-text values.
pub fn command_words(argv: &[String]) -> Vec<String> {
    argv.iter()
        .take_while(|a| {
            !a.is_empty()
                && a.len() <= 40
                && a.starts_with(|c: char| c.is_ascii_lowercase())
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        .take(4)
        .cloned()
        .collect()
}

/// Suspicious words anywhere in the command line, including option names such as
/// `--config` (values are never recorded, only the matching words).
pub fn suspicious_words(argv: &[String]) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for a in argv {
        let token = a
            .trim_start_matches('-')
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        // The whole word, and each part of a hyphenated one (`forwarding-addresses`).
        for part in std::iter::once(token.as_str()).chain(token.split('-')) {
            if let Some(w) = SUSPICIOUS_WORDS.iter().find(|w| **w == part)
                && !found.contains(w)
            {
                found.push(w);
            }
        }
    }
    found
}

pub fn handle(cfg: Config, req: Request<'_>) -> Response {
    let words = command_words(&req.argv);
    let suspicious = suspicious_words(&req.argv);
    let argv = std::iter::once("himalaya".to_string()).chain(req.argv);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(e) => {
            let text = e.render().to_string().into_bytes();
            let mut resp = Response {
                exit: e.exit_code(),
                ..Default::default()
            };
            if e.use_stderr() {
                resp.stderr = text;
                // A command the gate does not offer: record it, since an agent probing for
                // settings or raw access is a strong sign of an injected instruction.
                let mut extra = json!({ "words": words, "error": format!("{:?}", e.kind()) });
                if !suspicious.is_empty() {
                    extra["suspicious"] = json!(suspicious);
                }
                if let Some(uid) = req.caller.uid {
                    extra["peer-uid"] = uid.into();
                }
                if let Some(pid) = req.caller.pid {
                    extra["peer-pid"] = pid.into();
                }
                let decision = if suspicious.is_empty() {
                    "rejected"
                } else {
                    "suspicious"
                };
                let logged = audit::record(&cfg, &req.caller.name, None, &words.join(" "), decision, extra);
                if logged.is_err() {
                    resp.stderr = AUDIT_FAILURE.to_vec();
                    resp.exit = 1;
                }
            } else {
                resp.stdout = text;
            }
            return resp;
        }
    };
    let json = cli.json;
    let gate = Gate::new(cfg, cli.account, json, req.caller, req.stdin, req.files);
    let result = gate.run(cli.command);
    if gate.audit_failed.get() {
        return Response {
            exit: 1,
            stderr: AUDIT_FAILURE.to_vec(),
            ..Default::default()
        };
    }
    let mut resp = Response {
        stdout: gate.out.take(),
        files: gate.files.take(),
        announce_files: gate.announce_files.get(),
        ..Default::default()
    };
    match result {
        Ok(code) => resp.exit = code,
        Err(e) => {
            let (code, message) = if let Some(d) = e.downcast_ref::<Denied>() {
                (3, format!("Denied by policy: {d}"))
            } else if let Some(f) = e.downcast_ref::<himalaya::Failed>() {
                let m = f.message.strip_prefix("Error: ").unwrap_or(&f.message);
                (f.code.clamp(1, 255), format!("Error: {m}"))
            } else {
                (1, format!("Error: {e:#}"))
            };
            resp.exit = code;
            resp.files.clear();
            if json {
                resp.stdout
                    .extend(format!("{}\n", json!({ "error": message })).into_bytes());
            } else {
                resp.stderr.extend(format!("{message}\n").into_bytes());
            }
        }
    }
    resp
}

/// A private directory under the state directory, removed when dropped.
fn private_tempdir(cfg: &Config, prefix: &str) -> Result<tempfile::TempDir> {
    let base = cfg.raw.state_dir.join("tmp");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&base)
        .with_context(|| format!("cannot create {}", base.display()))?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&base)
        .with_context(|| format!("cannot create a directory in {}", base.display()))
}

/// The last path component, made safe to use as a file name.
pub fn safe_file_name(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name: String = name.chars().filter(|c| !c.is_control() && *c != '/').collect();
    if name.is_empty() || name == "." || name == ".." {
        "attachment".into()
    } else {
        name
    }
}

pub struct Gate<'a> {
    pub cfg: Config,
    pub account: Option<String>,
    pub json: bool,
    pub now: i64,
    caller: Caller,
    stdin: &'a StdinSource<'a>,
    in_files: BTreeMap<String, Vec<u8>>,
    out: RefCell<Vec<u8>>,
    files: RefCell<Vec<OutFile>>,
    announce_files: Cell<bool>,
    audit_failed: Cell<bool>,
}

impl<'a> Gate<'a> {
    pub fn new(
        cfg: Config,
        account: Option<String>,
        json: bool,
        caller: Caller,
        stdin: &'a StdinSource<'a>,
        in_files: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            cfg,
            account,
            json,
            now: chrono::Utc::now().timestamp(),
            caller,
            stdin,
            in_files,
            out: RefCell::default(),
            files: RefCell::default(),
            announce_files: Cell::new(false),
            audit_failed: Cell::new(false),
        }
    }

    fn him(&self) -> Himalaya<'_> {
        Himalaya {
            cfg: &self.cfg,
            account: self.account.clone(),
        }
    }

    fn outbox(&self) -> Outbox {
        Outbox::new(self.cfg.outbox_dir())
    }

    /// Record a decision. If the audit log cannot be written, the whole response is
    /// replaced by an error (see [`handle`]): the gate fails closed.
    fn audit(&self, command: &str, decision: &str, extra: Value) {
        let mut extra = extra;
        if let Some(obj) = extra.as_object_mut() {
            if let Some(uid) = self.caller.uid {
                obj.insert("peer-uid".into(), uid.into());
            }
            if let Some(pid) = self.caller.pid {
                obj.insert("peer-pid".into(), pid.into());
            }
        }
        let result = audit::record(
            &self.cfg,
            &self.caller.name,
            self.account.as_deref(),
            command,
            decision,
            extra,
        );
        if result.is_err() {
            self.audit_failed.set(true);
        }
    }

    fn print(&self, text: &str) -> Result<i32> {
        let mut out = self.out.borrow_mut();
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        Ok(0)
    }

    /// Print a notice for the agent, as JSON when requested.
    fn notice(&self, text: &str, fields: Value) -> Result<i32> {
        if self.json {
            let mut v = fields;
            v["message"] = Value::String(text.to_string());
            self.print(&v.to_string())
        } else {
            self.print(text)
        }
    }

    fn passthrough(&self, out: &[u8]) -> Result<i32> {
        self.out.borrow_mut().write_all(out)?;
        Ok(0)
    }

    // ----- checks -------------------------------------------------------------

    fn check_account(&self) -> Result<()> {
        let allowed = &self.cfg.raw.accounts.allowed;
        if allowed.is_empty() {
            return Ok(());
        }
        let name = match &self.account {
            Some(a) => a.clone(),
            None => himalaya::default_account(&self.cfg)?,
        };
        if !allowed.contains(&name) {
            return deny(format!("account `{name}` is not available to you"));
        }
        Ok(())
    }

    fn in_list(list: &[String], mailbox: &str) -> bool {
        list.iter().any(|m| m.eq_ignore_ascii_case(mailbox))
    }

    fn check_readable(&self, mailbox: Option<&str>) -> Result<()> {
        let list = &self.cfg.raw.mailboxes.readable;
        let mb = mailbox.unwrap_or("inbox");
        if !list.is_empty() && !Self::in_list(list, mb) {
            return deny(format!(
                "mailbox `{mb}` is not available to you (readable: {})",
                list.join(", ")
            ));
        }
        Ok(())
    }

    fn check_writable(&self, mailbox: &str) -> Result<()> {
        let list = &self.cfg.raw.mailboxes.writable;
        if !list.is_empty() && !Self::in_list(list, mailbox) {
            return deny(format!(
                "you cannot add messages to mailbox `{mailbox}` (writable: {})",
                list.join(", ")
            ));
        }
        Ok(())
    }

    fn check_id(id: &str) -> Result<()> {
        if id.is_empty() || id.len() > 512 || id.starts_with('-') || id.chars().any(|c| c.is_control()) {
            return deny(format!("invalid message id {id:?}"));
        }
        Ok(())
    }

    fn classify_message(&self, mailbox: Option<&str>, id: &str) -> Result<(Vec<u8>, Verdict)> {
        Self::check_id(id)?;
        let raw = self.him().raw_message(mailbox, id)?;
        let verdict = classify::classify_raw(&self.cfg, &raw, self.now);
        Ok((raw, verdict))
    }

    fn withheld_text(&self, id: &str, verdict: &Verdict) -> String {
        format!(
            "Message {id} is withheld by policy (filter: {}). It contains content agents may not \
             read, such as a one-time code, a password reset or sign-in link. The user can read \
             it in their own mail client. {DONT_WORK_AROUND} If you need something from it, ask the user.",
            verdict.filter_names()
        )
    }

    /// Refuse to act on messages matched by any filter (they may be evidence of an
    /// account takeover attempt, so the agent must not hide or delete them).
    fn guard_mutation(&self, mailbox: Option<&str>, ids: &[String], what: &str) -> Result<()> {
        let mut blocked = Vec::new();
        for id in ids {
            let (_, verdict) = self.classify_message(mailbox, id)?;
            if verdict.action.is_some() {
                blocked.push(format!("{id} ({})", verdict.filter_names()));
            }
        }
        if !blocked.is_empty() {
            self.audit(what, "denied", json!({ "ids": ids, "blocked": blocked }));
            return deny(format!(
                "You cannot {what} these messages; they are protected by policy: {}. The user manages them.",
                blocked.join(", ")
            ));
        }
        Ok(())
    }

    fn read_stdin(&self, what: &str) -> Result<Vec<u8>> {
        match (self.stdin)()? {
            None => deny(format!("{what}: pipe the raw RFC 5322 message on standard input")),
            Some(buf) if buf.is_empty() => deny(format!("{what}: no message on standard input")),
            Some(buf) => Ok(buf),
        }
    }

    /// Write the files the client sent for `--attach` into a private directory, keeping
    /// their names (himalaya names attachments after their files).
    fn stage_attachments(&self, paths: &[String]) -> Result<Option<(tempfile::TempDir, Vec<PathBuf>)>> {
        if paths.is_empty() {
            return Ok(None);
        }
        let dir = private_tempdir(&self.cfg, "attach-")?;
        let mut staged = Vec::new();
        for (i, path) in paths.iter().enumerate() {
            let Some(data) = self.in_files.get(path) else {
                return deny(format!(
                    "attachment {path:?} was not received; the himalaya client sends the files named by --attach"
                ));
            };
            let sub = dir.path().join(i.to_string());
            std::fs::DirBuilder::new().mode(0o700).create(&sub)?;
            let file = sub.join(safe_file_name(path));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file)?;
            f.write_all(data)?;
            staged.push(file);
        }
        Ok(Some((dir, staged)))
    }

    // ----- dispatch -----------------------------------------------------------

    pub fn run(&self, cmd: Cmd) -> Result<i32> {
        match &cmd {
            Cmd::Outbox(_) | Cmd::Policy => {}
            _ => self.check_account()?,
        }
        match cmd {
            Cmd::Mailbox(MailboxCmd::List { counts, max_width }) => self.mailbox_list(counts, max_width),
            Cmd::Envelope(EnvelopeCmd::List(args)) => self.envelopes(&args, None),
            Cmd::Envelope(EnvelopeCmd::Search { list, query }) => self.envelopes(&list, Some(&query)),
            Cmd::Flag(cmd) => self.flag(cmd),
            Cmd::Message(cmd) => self.message(cmd),
            Cmd::Attachment(cmd) => self.attachment(cmd),
            Cmd::Account(AccountCmd::List) => self.account_list(),
            Cmd::Outbox(cmd) => self.outbox_cmd(cmd),
            Cmd::Policy => self.policy(),
        }
    }

    // ----- mailboxes, accounts ------------------------------------------------

    fn mailbox_list(&self, counts: bool, max_width: Option<usize>) -> Result<i32> {
        let mut args = vec!["mailbox".to_string(), "list".into()];
        if counts {
            args.push("--counts".into());
        }
        let out = self.him().run_ok(true, &args, None)?;
        let mut v: Value = serde_json::from_slice(&out).context("unexpected mailbox list output")?;
        let readable = &self.cfg.raw.mailboxes.readable;
        if let Some(list) = v["mailboxes"].as_array_mut()
            && !readable.is_empty()
        {
            list.retain(|m| {
                [&m["name"], &m["id"]]
                    .iter()
                    .any(|x| x.as_str().is_some_and(|s| Self::in_list(readable, s)))
            });
        }
        if self.json {
            return self.print(&v.to_string());
        }
        let rows: Vec<Vec<String>> = v["mailboxes"]
            .as_array()
            .map(|l| {
                l.iter()
                    .map(|m| {
                        let mut row = vec![
                            m["name"].as_str().unwrap_or_default().to_string(),
                            m["id"].as_str().unwrap_or_default().to_string(),
                        ];
                        if counts {
                            row.push(m["total"].to_string());
                            row.push(m["unread"].to_string());
                        }
                        row
                    })
                    .collect()
            })
            .unwrap_or_default();
        let headers: &[&str] = if counts {
            &["NAME", "ID", "TOTAL", "UNREAD"]
        } else {
            &["NAME", "ID"]
        };
        self.print(&render::table(headers, &rows, max_width))
    }

    fn account_list(&self) -> Result<i32> {
        let allowed = &self.cfg.raw.accounts.allowed;
        let accounts: Vec<(String, bool)> = himalaya::accounts(&self.cfg)?
            .into_iter()
            .filter(|(n, _)| allowed.is_empty() || allowed.contains(n))
            .collect();
        if self.json {
            let list: Vec<Value> = accounts
                .iter()
                .map(|(n, d)| json!({ "name": n, "default": d }))
                .collect();
            return self.print(&json!({ "accounts": list }).to_string());
        }
        let rows: Vec<Vec<String>> = accounts
            .iter()
            .map(|(n, d)| vec![n.clone(), if *d { "yes".into() } else { String::new() }])
            .collect();
        self.print(&render::table(&["NAME", "DEFAULT"], &rows, None))
    }

    // ----- envelopes ----------------------------------------------------------

    fn envelopes(&self, args: &ListArgs, query: Option<&[String]>) -> Result<i32> {
        self.check_readable(args.mailbox.as_deref())?;
        let command = if query.is_some() {
            "envelope search"
        } else {
            "envelope list"
        };
        if let Some(q) = query {
            let body = Regex::new(r"(?i)(^|[^a-z])body([^a-z]|$)").unwrap();
            if !self.cfg.raw.search.allow_body && body.is_match(&q.join(" ")) {
                self.audit(command, "denied", json!({ "reason": "body search" }));
                return deny(
                    "Searching message bodies is disabled by policy. Search by from, to, subject, date or flag instead.",
                );
            }
        }
        let mut hargs: Vec<String> = vec![
            "envelope".into(),
            if query.is_some() { "search" } else { "list" }.into(),
        ];
        if let Some(m) = &args.mailbox {
            hargs.extend(["-m".into(), m.clone()]);
        }
        if let Some(p) = args.page {
            hargs.extend(["-p".into(), p.to_string()]);
        }
        if let Some(s) = args.page_size {
            hargs.extend(["-s".into(), s.to_string()]);
        }
        if args.has_attachment {
            hargs.push("--has-attachment".into());
        }
        if let Some(q) = query
            && !q.is_empty()
        {
            hargs.push("--".into());
            hargs.extend(q.iter().cloned());
        }
        let out = self.him().run_ok(true, &hargs, None)?;
        let mut v: Value = serde_json::from_slice(&out).context("unexpected envelope list output")?;
        let Some(envs) = v["envelopes"].as_array_mut() else {
            bail!("unexpected envelope list output");
        };

        let hide = self.cfg.raw.read.hide_withheld_in_listings;
        let mut withheld = 0;
        envs.retain_mut(|e| {
            let emails = |k: &str| -> Vec<String> {
                e[k].as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x["email"].as_str())
                            .map(|s| s.to_lowercase())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let facts = Facts {
                from: emails("from"),
                to: emails("to"),
                subject: e["subject"].as_str().unwrap_or_default().to_string(),
                body: None,
                date: e["date"]
                    .as_str()
                    .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
                    .map(|d| d.timestamp()),
            };
            let verdict = classify::classify(&self.cfg, &facts, self.now);
            match verdict.action {
                Some(Action::Withhold) => {
                    withheld += 1;
                    if hide {
                        return false;
                    }
                    e["subject"] = Value::String(format!("[withheld by policy: {}]", verdict.filter_names()));
                }
                Some(Action::Redact) => {
                    e["subject"] = Value::String(classify::redact(&self.cfg, &facts.subject));
                }
                _ => {}
            }
            true
        });
        self.audit(
            command,
            "allowed",
            json!({ "mailbox": args.mailbox, "withheld": withheld }),
        );
        if self.json {
            return self.print(&v.to_string());
        }
        let envs = v["envelopes"].as_array().cloned().unwrap_or_default();
        self.print(&render::envelopes(&envs, args.recipient, args.max_width))
    }

    // ----- messages -----------------------------------------------------------

    fn message(&self, cmd: MessageCmd) -> Result<i32> {
        match cmd {
            MessageCmd::Read { id, mailbox, raw, seen } => self.read(&id, mailbox.as_deref(), raw, seen),
            MessageCmd::Send { save } => {
                let raw = self.read_stdin("message send")?;
                self.submit(raw, save)
            }
            MessageCmd::Add { mailbox, flags, send } => {
                let raw = self.read_stdin("message add")?;
                if send {
                    return self.submit(raw, Some(mailbox));
                }
                self.check_writable(&mailbox)?;
                let mut args = vec!["message".to_string(), "add".into(), "-m".into(), mailbox.clone()];
                for f in flags {
                    args.extend(["-f".into(), f.as_str().into()]);
                }
                let out = self.him().run_ok(self.json, &args, Some(&raw))?;
                self.audit("message add", "allowed", json!({ "mailbox": mailbox }));
                self.passthrough(&out)
            }
            MessageCmd::Compose(c) => self.compose("compose", None, None, &c),
            MessageCmd::Reply { id, quote, compose } => self.compose("reply", Some(&id), Some(&quote), &compose),
            MessageCmd::Forward { id, quote, compose } => self.compose("forward", Some(&id), Some(&quote), &compose),
            MessageCmd::Move(a) => self.move_copy("move", a),
            MessageCmd::Copy(a) => self.move_copy("copy", a),
            MessageCmd::Delete { mailbox, ids } => {
                self.check_readable(mailbox.as_deref())?;
                self.guard_mutation(mailbox.as_deref(), &ids, "delete")?;
                let mut args = vec!["message".to_string(), "delete".into()];
                if let Some(m) = &mailbox {
                    args.extend(["-m".into(), m.clone()]);
                }
                args.extend(ids.iter().cloned());
                let out = self.him().run_ok(self.json, &args, None)?;
                self.audit("message delete", "allowed", json!({ "mailbox": mailbox, "ids": ids }));
                self.passthrough(&out)
            }
        }
    }

    fn read(&self, id: &str, mailbox: Option<&str>, raw_out: bool, seen: bool) -> Result<i32> {
        self.check_readable(mailbox)?;
        let (raw, verdict) = self.classify_message(mailbox, id)?;
        let fields = json!({ "mailbox": mailbox, "id": id, "action": verdict.action, "filters": verdict.filters });
        match verdict.action {
            Some(Action::Withhold) => {
                self.audit("message read", "withheld", fields);
                return match self.cfg.raw.read.withheld {
                    WithheldStyle::Notice => self.notice(
                        &self.withheld_text(id, &verdict),
                        json!({ "id": id, "withheld": true, "filters": verdict.filters }),
                    ),
                    WithheldStyle::NotFound => Err(himalaya::Failed {
                        code: 1,
                        message: format!("Error: message {id} not found"),
                    }
                    .into()),
                };
            }
            Some(Action::Redact) if raw_out => {
                self.audit("message read --raw", "denied", fields);
                return deny(format!(
                    "Raw output is not available for message {id}: it is redacted by policy (filter: {}). \
                     Read it without --raw to get a redacted version.",
                    verdict.filter_names()
                ));
            }
            _ => {}
        }
        self.audit("message read", verdict.action.map_or("allowed", |a| a.as_str()), fields);
        if raw_out {
            self.passthrough(&raw)?;
        } else {
            let Some(text) = render::message(&self.cfg, &raw, id, &verdict, self.json) else {
                return deny(format!("message {id} could not be parsed"));
            };
            self.print(&text)?;
        }
        if seen && verdict.action.is_none() {
            let mut args = vec!["flag", "add", "-f", "seen"];
            if let Some(m) = mailbox {
                args.extend(["-m", m]);
            }
            args.push(id);
            self.him().run_ok(false, &args, None)?;
        }
        Ok(0)
    }

    fn compose(&self, kind: &str, id: Option<&str>, quote: Option<&QuoteArgs>, c: &ComposeArgs) -> Result<i32> {
        let mailbox = quote.and_then(|q| q.mailbox.as_deref());
        let command = format!("message {kind}");
        if let Some(id) = id {
            self.check_readable(mailbox)?;
            let (_, verdict) = self.classify_message(mailbox, id)?;
            if matches!(verdict.action, Some(Action::Withhold | Action::Redact)) {
                self.audit(&command, "denied", json!({ "id": id, "filters": verdict.filters }));
                let verb = if kind == "reply" { "reply to" } else { kind };
                return deny(format!(
                    "You cannot {verb} message {id}: its content is restricted by policy (filter: {}). {DONT_WORK_AROUND}",
                    verdict.filter_names()
                ));
            }
        }
        if let Some(save) = &c.save
            && !c.send
        {
            self.check_writable(save)?;
        }

        let mut args: Vec<String> = vec!["message".into(), kind.into()];
        if let Some(m) = mailbox {
            args.extend(["-m".into(), m.into()]);
        }
        let mut opt = |flag: &str, v: &Option<String>| {
            if let Some(v) = v {
                args.extend([flag.to_string(), v.clone()]);
            }
        };
        opt("--from", &c.from);
        opt("--subject", &c.subject);
        opt("--body", &c.body);
        opt("--signature", &c.signature);
        for (flag, list) in [("--to", &c.to), ("--cc", &c.cc), ("--bcc", &c.bcc)] {
            for v in list {
                args.extend([flag.to_string(), v.clone()]);
            }
        }
        if let Some(q) = quote {
            if let Some(p) = q.posting_style {
                args.extend([
                    "--posting-style".into(),
                    if matches!(p, PostingStyle::Top) {
                        "top"
                    } else {
                        "bottom"
                    }
                    .into(),
                ]);
            }
            if let Some(h) = &q.quote_headline {
                args.extend(["--quote-headline".into(), h.clone()]);
            }
        }
        let staged = self.stage_attachments(&c.attach)?;
        if let Some((_, files)) = &staged {
            for f in files {
                args.extend(["--attach".into(), f.display().to_string()]);
            }
        }
        if let Some(id) = id {
            args.push(id.into());
        }
        let stdin = if c.body.is_none() { (self.stdin)()? } else { None };
        let mime = self.him().run_ok(false, &args, Some(stdin.as_deref().unwrap_or(b"")))?;
        drop(staged);

        if c.send {
            return self.submit(mime, c.save.clone());
        }
        if let Some(save) = &c.save {
            let out = self
                .him()
                .run_ok(self.json, &["message", "add", "-m", save.as_str()], Some(&mime))?;
            self.audit(&command, "saved", json!({ "mailbox": save }));
            return self.passthrough(&out);
        }
        self.passthrough(&mime)
    }

    fn move_copy(&self, what: &str, a: MoveArgs) -> Result<i32> {
        self.check_readable(a.from.as_deref())?;
        self.check_writable(&a.to)?;
        for id in &a.ids {
            Self::check_id(id)?;
        }
        if what == "move" {
            self.guard_mutation(a.from.as_deref(), &a.ids, "move")?;
        }
        let mut args = vec!["message".to_string(), what.into(), "--to".into(), a.to.clone()];
        if let Some(f) = &a.from {
            args.extend(["--from".into(), f.clone()]);
        }
        args.extend(a.ids.iter().cloned());
        let out = self.him().run_ok(self.json, &args, None)?;
        self.audit(
            &format!("message {what}"),
            "allowed",
            json!({ "from": a.from, "to": a.to, "ids": a.ids }),
        );
        self.passthrough(&out)
    }

    // ----- sending ------------------------------------------------------------

    /// Apply the send policy to a raw message.
    fn submit(&self, raw: Vec<u8>, save: Option<String>) -> Result<i32> {
        let Some(msg) = MessageParser::default().parse(&raw) else {
            return deny("The message could not be parsed as RFC 5322.");
        };
        let list = |a: Option<&mail_parser::Address>| -> Vec<String> {
            a.map(|a| a.iter().filter_map(|x| x.address()).map(|s| s.to_lowercase()).collect())
                .unwrap_or_default()
        };
        let (to, cc, bcc) = (list(msg.to()), list(msg.cc()), list(msg.bcc()));
        let recipients: Vec<&String> = to.iter().chain(&cc).chain(&bcc).collect();
        if recipients.is_empty() {
            return deny("The message has no recipients (To, Cc or Bcc).");
        }
        let send = &self.cfg.raw.send;
        let id = outbox::new_id();
        let mut entry = Entry {
            id: id.clone(),
            created: outbox::now_rfc3339(),
            created_ts: self.now,
            caller: self.caller.name.clone(),
            account: self.account.clone(),
            from: list(msg.from()),
            to: to.clone(),
            cc: cc.clone(),
            bcc: bcc.clone(),
            subject: msg.subject().unwrap_or_default().to_string(),
            status: Status::Pending,
            auto: false,
            updated: None,
            note: None,
        };
        drop(msg);
        let outbox = self.outbox();
        let log = |entry: &Entry| {
            self.audit(
                "message send",
                entry.status.as_str(),
                json!({ "outbox-id": entry.id, "recipients": recipients, "auto": entry.auto }),
            )
        };

        if self.cfg.auto_send_matches(&recipients) {
            let day_ago = self.now - 86_400;
            let sent_today = outbox
                .list()?
                .iter()
                .filter(|e| e.auto && e.status == Status::Sent && e.created_ts > day_ago)
                .count();
            if sent_today < send.auto_send_max_per_day {
                let mut args = vec!["message".to_string(), "send".into()];
                if let Some(s) = &save {
                    self.check_writable(s)?;
                    args.extend(["--save".into(), s.clone()]);
                }
                let out = self.him().run(self.json, &args, Some(&raw))?;
                if out.code == 0 {
                    entry.status = Status::Sent;
                    entry.auto = true;
                    outbox.create(&entry, &raw)?;
                    log(&entry);
                    return self.passthrough(&out.stdout);
                }
                entry.note = Some(format!(
                    "automatic send failed: {}",
                    himalaya::clean_stderr(&out.stderr)
                ));
            } else {
                entry.note = Some("automatic send limit reached".into());
            }
        }

        match send.mode {
            SendMode::Deny => {
                entry.status = Status::Denied;
                entry.note.get_or_insert_with(|| "sending disabled by policy".into());
                outbox.create(&entry, &raw)?;
                log(&entry);
                deny(format!(
                    "Sending email is disabled by policy. The message was NOT sent (outbox id {id}). \
                     {DONT_WORK_AROUND} Tell the user what you wanted to send instead."
                ))
            }
            SendMode::Queue => {
                outbox.create(&entry, &raw)?;
                log(&entry);
                self.notice(
                    &format!(
                        "Message queued for human approval (outbox id {id}). It has NOT been sent yet; \
                         the user will review it and decide. Do not resend it or try other ways of \
                         delivering it. Check its status with `outbox list`."
                    ),
                    json!({ "sent": false, "queued": true, "outbox-id": id, "status": "pending" }),
                )
            }
            SendMode::Draft => {
                let mut marked = format!("X-Sherpa-Outbox-Id: {id}\r\n").into_bytes();
                marked.extend_from_slice(&raw);
                let drafts = send.drafts_mailbox.as_str();
                self.him()
                    .run_ok(false, &["message", "add", "-m", drafts, "-f", "draft"], Some(&marked))?;
                entry.status = Status::Drafted;
                outbox.create(&entry, &raw)?;
                log(&entry);
                self.notice(
                    &format!(
                        "Message saved to the user's drafts for review (outbox id {id}). It has NOT been \
                         sent; the user will send it from their mail client if they approve. Do not \
                         resend it or try other ways of delivering it."
                    ),
                    json!({ "sent": false, "drafted": true, "outbox-id": id, "status": "drafted" }),
                )
            }
            SendMode::Blackhole => {
                entry.status = Status::Blackholed;
                outbox.create(&entry, &raw)?;
                log(&entry);
                if self.json {
                    self.print(&json!({ "sent": true }).to_string())
                } else {
                    self.print("Message successfully sent")
                }
            }
        }
    }

    // ----- flags, attachments -------------------------------------------------

    fn flag(&self, cmd: FlagCmd) -> Result<i32> {
        let (verb, a) = match cmd {
            FlagCmd::Add(a) => ("add", a),
            FlagCmd::Set(a) => ("set", a),
            FlagCmd::Remove(a) => ("remove", a),
        };
        self.check_readable(a.mailbox.as_deref())?;
        self.guard_mutation(a.mailbox.as_deref(), &a.ids, "change flags of")?;
        let mut args = vec!["flag".to_string(), verb.into()];
        if let Some(m) = &a.mailbox {
            args.extend(["-m".into(), m.clone()]);
        }
        for f in &a.flags {
            args.extend(["-f".into(), f.as_str().into()]);
        }
        args.extend(a.ids.iter().cloned());
        let out = self.him().run_ok(self.json, &args, None)?;
        self.audit(
            &format!("flag {verb}"),
            "allowed",
            json!({ "mailbox": a.mailbox, "ids": a.ids }),
        );
        self.passthrough(&out)
    }

    fn attachment(&self, cmd: AttachmentCmd) -> Result<i32> {
        let (id, mailbox) = match &cmd {
            AttachmentCmd::List { id, mailbox, .. } | AttachmentCmd::Download { id, mailbox, .. } => {
                (id.clone(), mailbox.clone())
            }
        };
        self.check_readable(mailbox.as_deref())?;
        let (_, verdict) = self.classify_message(mailbox.as_deref(), &id)?;
        if matches!(verdict.action, Some(Action::Withhold | Action::Redact)) {
            self.audit("attachment", "denied", json!({ "id": id, "filters": verdict.filters }));
            return deny(format!(
                "Attachments of message {id} are not available: its content is restricted by policy (filter: {}). {DONT_WORK_AROUND}",
                verdict.filter_names()
            ));
        }
        let mut args: Vec<String> = vec!["attachment".into()];
        let mut download: Option<tempfile::TempDir> = None;
        match &cmd {
            AttachmentCmd::List { inline, .. } => {
                args.push("list".into());
                if *inline {
                    args.push("--inline".into());
                }
            }
            AttachmentCmd::Download { .. } => {
                let dir = private_tempdir(&self.cfg, "download-")?;
                args.extend(["download".into(), "--dir".into(), dir.path().display().to_string()]);
                download = Some(dir);
            }
        }
        if let Some(m) = &mailbox {
            args.extend(["-m".into(), m.clone()]);
        }
        args.push(id.clone());
        if let AttachmentCmd::Download { attachment_ids, .. } = &cmd {
            for a in attachment_ids {
                Self::check_id(a)?;
            }
            args.extend(attachment_ids.iter().cloned());
        }
        let out = self.him().run_ok(self.json, &args, None)?;
        let (Some(tmp), AttachmentCmd::Download { dir, .. }) = (&download, &cmd) else {
            self.audit("attachment list", "allowed", json!({ "id": id, "mailbox": mailbox }));
            return self.passthrough(&out);
        };
        // Hand the files to the client instead of himalaya's listing of private paths.
        let mut files = Vec::new();
        let mut total = 0;
        let mut entries: Vec<_> = std::fs::read_dir(tmp.path())?.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            if !entry.file_type()?.is_file() {
                continue;
            }
            let data = std::fs::read(entry.path())?;
            total += data.len();
            if total > MAX_DOWNLOAD_BYTES {
                return deny(format!(
                    "the attachments of message {id} are larger than {} MiB; ask the user to save them",
                    MAX_DOWNLOAD_BYTES >> 20
                ));
            }
            files.push(OutFile {
                dir: dir.clone(),
                name: safe_file_name(&entry.file_name().to_string_lossy()),
                data,
            });
        }
        self.audit(
            "attachment download",
            "allowed",
            json!({ "id": id, "mailbox": mailbox, "files": files.len(), "bytes": total }),
        );
        if self.json {
            let list: Vec<Value> = files
                .iter()
                .map(|f| json!({ "name": f.name, "size": f.data.len() }))
                .collect();
            self.print(&json!({ "attachments": list }).to_string())?;
        } else if files.is_empty() {
            self.print("No attachments downloaded.")?;
        }
        self.announce_files.set(!self.json);
        self.files.borrow_mut().extend(files);
        Ok(0)
    }

    // ----- outbox, policy -----------------------------------------------------

    /// How an outbox status is shown to the agent (a blackholed message was "sent").
    fn agent_status(&self, s: Status) -> &'static str {
        match s {
            Status::Blackholed => "sent",
            Status::Pending => "pending-approval",
            s => s.as_str(),
        }
    }

    fn outbox_cmd(&self, cmd: OutboxCmd) -> Result<i32> {
        let outbox = self.outbox();
        match cmd {
            OutboxCmd::List => {
                let entries = outbox.list()?;
                if self.json {
                    let list: Vec<Value> = entries
                        .iter()
                        .map(|e| {
                            json!({ "id": e.id, "created": e.created, "status": self.agent_status(e.status),
                                    "to": e.to, "cc": e.cc, "bcc": e.bcc, "subject": e.subject })
                        })
                        .collect();
                    return self.print(&json!({ "outbox": list }).to_string());
                }
                let rows: Vec<Vec<String>> = entries
                    .iter()
                    .map(|e| {
                        vec![
                            e.id.clone(),
                            self.agent_status(e.status).into(),
                            e.to.iter()
                                .chain(&e.cc)
                                .chain(&e.bcc)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", "),
                            e.subject.clone(),
                        ]
                    })
                    .collect();
                self.print(&render::table(&["ID", "STATUS", "RECIPIENTS", "SUBJECT"], &rows, None))
            }
            OutboxCmd::Show { id } => {
                if !outbox::valid_id(&id) {
                    return deny(format!("invalid outbox id {id:?}"));
                }
                let e = outbox.get(&id)?;
                let raw = outbox.raw(&id)?;
                let status = self.agent_status(e.status);
                if self.json {
                    return self.print(
                        &json!({ "id": e.id, "status": status, "created": e.created,
                                 "message": String::from_utf8_lossy(&raw) })
                        .to_string(),
                    );
                }
                let note = match (&e.note, e.status) {
                    (Some(n), Status::Denied | Status::Sent) if !e.auto => format!("Note: {n}\n"),
                    _ => String::new(),
                };
                self.print(&format!(
                    "Outbox-Id: {}\nStatus: {status}\nCreated: {}\n{note}\n{}",
                    e.id,
                    e.created,
                    String::from_utf8_lossy(&raw)
                ))
            }
        }
    }

    fn policy(&self) -> Result<i32> {
        let raw = &self.cfg.raw;
        let sending = match raw.send.mode {
            SendMode::Queue => {
                "Messages you send are queued until the user approves them. A queued message is not an error; do not resend it."
            }
            SendMode::Draft => {
                "Messages you send are saved to the user's drafts; the user sends them. This is not an error; do not resend."
            }
            SendMode::Deny => "Sending email is disabled. Tell the user what you would send instead.",
            SendMode::Blackhole => "Sending email is enabled.",
        };
        let mut text =
            String::from("Email access is mediated by himalaya-sherpa. You never have the account credentials.\n\n");
        text.push_str(&format!("Sending: {sending}\n"));
        if !raw.send.auto_send_to.is_empty() && raw.send.mode != SendMode::Blackhole {
            text.push_str(&format!(
                "  Sent directly (up to {}/day) when every recipient matches: {}\n",
                raw.send.auto_send_max_per_day,
                raw.send.auto_send_to.join(", ")
            ));
        }
        text.push_str("\nRestricted messages:\n");
        for f in &self.cfg.filters {
            let what = match f.action {
                Action::Withhold => "withheld (not readable)",
                Action::Redact => "readable with codes and links masked",
                Action::Protect => "readable, but cannot be flagged, moved or deleted",
            };
            text.push_str(&format!("  - {}: {what}\n", f.name));
        }
        text.push_str(&format!(
            "\nBody search: {}\n",
            if raw.search.allow_body {
                "allowed"
            } else {
                "disabled (search by from, to, subject, date, flag)"
            }
        ));
        if !raw.mailboxes.readable.is_empty() {
            text.push_str(&format!("Readable mailboxes: {}\n", raw.mailboxes.readable.join(", ")));
        }
        text.push_str("\nAttachments you download are saved in your current directory (or --dir).\n");
        text.push_str(&format!("\n{DONT_WORK_AROUND_POLICY}\n"));
        self.print(&text)
    }
}

const DONT_WORK_AROUND_POLICY: &str = "These rules protect the user's accounts. When a rule blocks you, say so to the user instead of looking for another way.";

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rejected_commands_are_summarized_without_values() {
        let argv = v(&[
            "gmail",
            "settings",
            "forwarding-addresses",
            "create",
            "attacker@evil.example",
        ]);
        assert_eq!(
            command_words(&argv),
            ["gmail", "settings", "forwarding-addresses", "create"]
        );
        assert_eq!(suspicious_words(&argv), ["gmail", "settings", "forwarding"]);
        let argv = v(&["message", "compose", "--body", "please forward this", "--config=/x"]);
        assert_eq!(command_words(&argv), ["message", "compose"]);
        assert_eq!(suspicious_words(&argv), ["config"]);
        assert!(suspicious_words(&v(&["envelope", "lst"])).is_empty());
    }
}
