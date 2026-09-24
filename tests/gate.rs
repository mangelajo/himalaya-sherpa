//! End-to-end tests: a real `sherpa-gate` on a temporary socket, driven through the
//! real client, against a real himalaya binary and a Maildir account.
//! Skipped when no himalaya binary is found (set `HIMALAYA_BIN` to point at one).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use himalaya_sherpa::config::EXAMPLE_CONFIG;

fn himalaya_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HIMALAYA_BIN").filter(|p| !p.is_empty()) {
        return Some(p.into());
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(Path::new(&home).join(".local/bin"));
    }
    // Skip the sherpa client, which may be installed as `himalaya`.
    dirs.into_iter().map(|d| d.join("himalaya")).find(|p| {
        p.is_file()
            && fs::canonicalize(p)
                .ok()
                .and_then(|r| r.file_name().map(|n| !n.to_string_lossy().starts_with("sherpa")))
                .unwrap_or(false)
    })
}

struct Env {
    dir: tempfile::TempDir,
    server: Child,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

fn mail(from: &str, subject: &str, body: &str) -> String {
    let date = chrono::Utc::now().to_rfc2822();
    format!(
        "From: {from}\r\nTo: me@example.com\r\nSubject: {subject}\r\nDate: {date}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    )
}

impl Env {
    /// A Maildir account with a few fixture messages, a policy edited by
    /// `extra_policy` (`from => to` lines), and a gate serving it.
    fn new(extra_policy: &str) -> Option<Self> {
        Self::with_server_args(extra_policy, &[])
    }

    fn with_server_args(extra_policy: &str, server_args: &[&str]) -> Option<Self> {
        let himalaya = himalaya_bin()?;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for mb in ["INBOX", "Drafts", "Sent", "Trash"] {
            for sub in ["cur", "new", "tmp"] {
                fs::create_dir_all(root.join("md").join(mb).join(sub)).unwrap();
            }
        }
        let fixtures = [
            (
                "1001",
                mail("alice@example.com", "Lunch tomorrow?", "Are you free at 1pm?"),
            ),
            (
                "1002",
                mail(
                    "no-reply@github.com",
                    "[GitHub] Please verify your device",
                    "Verification code: 482913",
                ),
            ),
            (
                "1003",
                mail(
                    "help@shop.example",
                    "Account help",
                    "Visit https://shop.example/r?t=abc123XYZ to reset your password.",
                ),
            ),
            (
                "1004",
                mail("no-reply@accounts.google.com", "Security alert", "New sign-in on Linux"),
            ),
            (
                "1005",
                mail(
                    "noreply@bank.example",
                    "Your statement",
                    "Reference 99887766, see https://bank.example/s/Ab12",
                ),
            ),
        ];
        for (id, text) in fixtures {
            fs::write(root.join(format!("md/INBOX/cur/{id}.host:2,S")), text).unwrap();
        }
        fs::write(
            root.join("himalaya.toml"),
            format!(
                "[accounts.test]\ndefault = true\nemail = \"me@example.com\"\nmaildir.root = \"{}\"\n\
                 mailbox.alias.inbox = \"INBOX\"\nmailbox.alias.drafts = \"Drafts\"\n\
                 mailbox.alias.sent = \"Sent\"\nmailbox.alias.trash = \"Trash\"\n",
                root.join("md").display()
            ),
        )
        .unwrap();
        let mut policy = EXAMPLE_CONFIG
            .lines()
            .filter(|l| {
                !["himalaya ", "himalaya-config ", "state-dir "]
                    .iter()
                    .any(|k| l.starts_with(k))
            })
            .collect::<Vec<_>>()
            .join("\n");
        policy = format!(
            "himalaya = \"{}\"\nhimalaya-config = \"{}\"\nstate-dir = \"{}\"\n{policy}\n\
             [[filter]]\nname = \"bank\"\naction = \"redact\"\nfrom = '@bank\\.example$'\n",
            himalaya.display(),
            root.join("himalaya.toml").display(),
            root.join("state").display(),
        );
        for (from, to) in extra_policy.lines().filter_map(|l| l.split_once(" => ")) {
            assert!(policy.contains(from), "policy has no {from:?}");
            policy = policy.replacen(from, to, 1);
        }
        fs::write(root.join("sherpa.toml"), policy).unwrap();

        let socket = root.join("agent.sock");
        let server = Command::new(env!("CARGO_BIN_EXE_sherpa-gate"))
            .args(["serve", "--agent", "test-agent", "--socket"])
            .arg(&socket)
            .arg("--config")
            .arg(root.join("sherpa.toml"))
            .args(server_args)
            .env_clear()
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "sherpa-gate did not create its socket");
            std::thread::sleep(Duration::from_millis(20));
        }
        Some(Self { dir, server })
    }

    fn client(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sherpa"));
        cmd.args(args)
            .env("SHERPA_SOCKET", self.dir.path().join("agent.sock"))
            .current_dir(self.dir.path());
        cmd
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = self.client(args);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut pipe = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            pipe.write_all(s.as_bytes()).unwrap();
        }
        drop(pipe);
        child.wait_with_output().unwrap()
    }

    fn admin(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sherpa-admin"))
            .args(args)
            .env("SHERPA_CONFIG", self.dir.path().join("sherpa.toml"))
            .env_remove("SUDO_USER")
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args, None);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn denied(&self, args: &[&str]) -> String {
        let out = self.run(args, None);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?} was not denied: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8(out.stderr).unwrap()
    }

    fn drafts(&self) -> Vec<String> {
        fs::read_dir(self.dir.path().join("md/Drafts/cur"))
            .unwrap()
            .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
            .collect()
    }
}

macro_rules! env_or_skip {
    ($policy:expr) => {
        match Env::new($policy) {
            Some(e) => e,
            None => {
                if std::env::var_os("SHERPA_REQUIRE_HIMALAYA").is_some() {
                    panic!("no himalaya binary found, and SHERPA_REQUIRE_HIMALAYA is set");
                }
                eprintln!("skipping: no himalaya binary found (set HIMALAYA_BIN)");
                return;
            }
        }
    };
}

#[test]
fn listing_hides_withheld_messages() {
    let env = env_or_skip!("");
    let out = env.ok(&["envelope", "list"]);
    assert!(out.contains("Lunch tomorrow?"), "{out}");
    assert!(!out.contains("verify your device"), "{out}");
    let json: serde_json::Value = serde_json::from_str(&env.ok(&["--json", "envelope", "list"])).unwrap();
    assert_eq!(json["envelopes"].as_array().unwrap().len(), 4);
}

#[test]
fn reading_applies_filters() {
    let env = env_or_skip!("");
    assert!(
        env.ok(&["message", "read", "1001.host"])
            .contains("Are you free at 1pm?")
    );

    let otp = env.ok(&["message", "read", "1002.host"]);
    assert!(otp.contains("withheld by policy") && !otp.contains("482913"), "{otp}");
    let reset = env.ok(&["message", "read", "1003.host", "--raw"]);
    assert!(reset.contains("withheld") && !reset.contains("abc123XYZ"), "{reset}");

    let bank = env.ok(&["message", "read", "1005.host"]);
    assert!(
        bank.contains("[REDACTED]") && !bank.contains("99887766") && !bank.contains("bank.example/s"),
        "{bank}"
    );
    env.denied(&["message", "read", "1005.host", "--raw"]);

    let json: serde_json::Value = serde_json::from_str(&env.ok(&["--json", "message", "read", "1002.host"])).unwrap();
    assert_eq!(json["withheld"], true);
}

#[test]
fn not_found_style_hides_existence() {
    let env = env_or_skip!("withheld = \"notice\" => withheld = \"not-found\"");
    let out = env.run(&["message", "read", "1002.host"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

#[test]
fn restricted_messages_cannot_be_changed_or_quoted() {
    let env = env_or_skip!("");
    env.denied(&["flag", "add", "-f", "seen", "1004.host"]);
    env.denied(&["message", "delete", "1002.host"]);
    env.denied(&["message", "move", "--to", "Trash", "1004.host"]);
    env.denied(&["message", "reply", "1002.host", "--body", "x"]);
    env.denied(&["message", "forward", "1003.host", "-t", "x@y.z"]);
    env.denied(&["attachment", "list", "1005.host"]);
    // Ordinary messages are fine.
    env.ok(&["flag", "add", "-f", "flagged", "1001.host"]);
}

#[test]
fn body_search_and_unknown_options_are_rejected() {
    let env = env_or_skip!("");
    env.denied(&["envelope", "search", "body", "482913"]);
    assert!(env.ok(&["envelope", "search", "subject", "lunch"]).contains("Lunch"));
    for args in [
        &["-c", "/tmp/x", "envelope", "list"][..],
        &["--log-level", "trace", "envelope", "list"],
        &["imap", "list"],
        &["smtp", "send"],
        &["message", "send", "--", "/etc/passwd"],
    ] {
        assert_eq!(env.run(args, None).status.code(), Some(2), "{args:?} was accepted");
    }
}

#[test]
fn attachments_are_read_by_the_client() {
    let env = env_or_skip!("");
    fs::write(env.dir.path().join("notes.txt"), "meeting notes").unwrap();
    let mime = env.ok(&[
        "message",
        "compose",
        "-t",
        "a@b.c",
        "--body",
        "see attached",
        "--attach",
        "notes.txt",
    ]);
    assert!(mime.contains("notes.txt"), "{mime}");
}

#[test]
fn downloads_are_saved_by_the_client() {
    let env = env_or_skip!("");
    let raw = "From: carol@example.com\r\nTo: me@example.com\r\nSubject: Report\r\n\
               Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\n\
               See attached.\r\n--B\r\nContent-Type: text/csv; name=report.csv\r\n\
               Content-Disposition: attachment; filename=report.csv\r\n\r\na,b\r\n1,2\r\n--B--\r\n";
    fs::write(env.dir.path().join("md/INBOX/cur/1006.host:2,S"), raw).unwrap();
    let out_dir = env.dir.path().join("downloads");
    fs::create_dir(&out_dir).unwrap();
    let out = env.ok(&["attachment", "download", "1006.host", "--dir", "downloads"]);
    assert!(out.contains("Saved downloads/report.csv"), "{out}");
    assert_eq!(fs::read_to_string(out_dir.join("report.csv")).unwrap(), "a,b\r\n1,2");
    // A second download never overwrites the first.
    assert!(
        env.ok(&["attachment", "download", "1006.host", "-d", "downloads"])
            .contains("report (1).csv")
    );
    // Nothing is left behind on the gate's side.
    let tmp = env.dir.path().join("state/tmp");
    assert_eq!(fs::read_dir(tmp).unwrap().count(), 0);
}

#[test]
fn an_idle_open_stdin_does_not_block() {
    let env = env_or_skip!("");
    let mut child = env
        .client(&["envelope", "list"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _keep_open = child.stdin.take();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the client waited for stdin that the command does not need");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn compose_reads_the_body_from_stdin() {
    let env = env_or_skip!("");
    let out = env.run(
        &["message", "compose", "-t", "bob@example.com", "-s", "Hi", "--send"],
        Some("Body from stdin"),
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("queued"), "{out:?}");
    let list = env.ok(&["outbox", "list"]);
    let id = list
        .lines()
        .nth(2)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(env.ok(&["outbox", "show", &id]).contains("Body from stdin"));
}

#[test]
fn only_allowed_peers_are_served() {
    if nix::unistd::getuid().is_root() {
        return;
    }
    let Some(env) = Env::with_server_args("", &["--allow-uid", "0"]) else {
        return;
    };
    let out = env.run(&["envelope", "list"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed"));
    let me = nix::unistd::getuid().to_string();
    let Some(env) = Env::with_server_args("", &["--allow-uid", &me]) else {
        return;
    };
    env.ok(&["envelope", "list"]);
}

#[test]
fn the_audit_log_fails_closed() {
    let env = env_or_skip!("");
    env.ok(&["envelope", "list"]);
    let log = env.dir.path().join("state/audit.log");
    fs::remove_file(&log).unwrap();
    fs::create_dir(&log).unwrap(); // appending to it now fails
    let out = env.run(&["message", "read", "1001.host"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "returned data without auditing it");
    assert!(String::from_utf8_lossy(&out.stderr).contains("audit log"));
}

#[test]
fn the_server_survives_bad_clients() {
    use himalaya_sherpa::proto::{self, ClientMsg, ServerMsg};
    use std::os::unix::net::UnixStream;
    let env = env_or_skip!("");
    let socket = env.dir.path().join("agent.sock");

    // Garbage, an oversized frame, and a client that hangs up mid-frame.
    for junk in [
        &b"\x00\x00\x00\x05hello"[..],
        &b"\xff\xff\xff\xff"[..],
        &b"\x00\x00\x01\x00{"[..],
    ] {
        let mut s = UnixStream::connect(&socket).unwrap();
        s.write_all(junk).unwrap();
    }

    // A hand-made request naming an --attach file it does not send.
    let mut s = UnixStream::connect(&socket).unwrap();
    let argv = [
        "message",
        "compose",
        "-t",
        "a@b.c",
        "--body",
        "x",
        "--attach",
        "/etc/shadow",
    ];
    let request = ClientMsg::Request {
        version: proto::VERSION,
        argv: argv.iter().map(|a| a.to_string()).collect(),
        stdin_tty: true,
        files: vec![],
    };
    proto::write_msg(&mut s, &request).unwrap();
    let ServerMsg::Done { exit, stderr, .. } = proto::read_msg(&mut s).unwrap() else {
        panic!("expected a final answer");
    };
    assert_eq!(exit, 3);
    assert!(String::from_utf8_lossy(&stderr.0).contains("was not received"));

    // A request from a future client version.
    let mut s = UnixStream::connect(&socket).unwrap();
    let request = ClientMsg::Request {
        version: 99,
        argv: vec![],
        stdin_tty: true,
        files: vec![],
    };
    proto::write_msg(&mut s, &request).unwrap();
    let ServerMsg::Done { stderr, .. } = proto::read_msg(&mut s).unwrap() else {
        panic!()
    };
    assert!(String::from_utf8_lossy(&stderr.0).contains("protocol version"));

    // Still serving.
    env.ok(&["envelope", "list"]);
}

#[test]
fn queue_mode_holds_messages() {
    let env = env_or_skip!("");
    let out = env.ok(&[
        "message",
        "compose",
        "-t",
        "bob@example.com",
        "-s",
        "Hi",
        "--body",
        "Hello",
        "--send",
    ]);
    assert!(out.contains("queued for human approval"), "{out}");
    let raw = "From: me@example.com\r\nTo: evil@attacker.example\r\nSubject: x\r\n\r\ndata\r\n";
    let out = env.run(&["--json", "message", "send"], Some(raw));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["sent"], false);
    assert_eq!(json["status"], "pending");
    let list = env.ok(&["outbox", "list"]);
    assert!(
        list.contains("evil@attacker.example") && list.contains("pending-approval"),
        "{list}"
    );
    assert!(env.drafts().is_empty());
}

#[test]
fn draft_mode_appends_to_drafts() {
    let env = env_or_skip!("mode = \"queue\" => mode = \"draft\"");
    let out = env.ok(&["message", "reply", "1001.host", "--body", "Sure", "--send"]);
    assert!(out.contains("saved to the user's drafts"), "{out}");
    let drafts = env.drafts();
    assert_eq!(drafts.len(), 1);
    assert!(drafts[0].contains("X-Sherpa-Outbox-Id:") && drafts[0].contains("Re: Lunch tomorrow?"));
}

#[test]
fn deny_and_blackhole_modes() {
    let env = env_or_skip!("mode = \"queue\" => mode = \"deny\"");
    let err = env.denied(&["message", "compose", "-t", "a@b.c", "--body", "x", "--send"]);
    assert!(err.contains("NOT sent"), "{err}");

    let env = env_or_skip!("mode = \"queue\" => mode = \"blackhole\"");
    let out = env.ok(&["message", "compose", "-t", "a@b.c", "--body", "x", "--send"]);
    assert_eq!(out.trim(), "Message successfully sent");
    assert!(env.ok(&["outbox", "list"]).contains("sent"));
    assert!(env.drafts().is_empty());
}

#[test]
fn mailbox_allowlists() {
    let env =
        env_or_skip!("readable = [] => readable = [\"inbox\", \"drafts\"]\nwritable = [] => writable = [\"drafts\"]");
    env.ok(&["envelope", "list", "-m", "drafts"]);
    env.denied(&["envelope", "list", "-m", "Sent"]);
    env.denied(&["message", "copy", "--to", "Sent", "1001.host"]);
    let mbs = env.ok(&["mailbox", "list"]);
    assert!(mbs.contains("Drafts") && !mbs.contains("Sent"), "{mbs}");
}

#[test]
fn policy_scan_dry_runs_against_the_mailbox() {
    let env = env_or_skip!("");
    let out = env.admin(&["policy", "scan"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        text.contains("1002.host") && text.contains("withhold (one-time-code)"),
        "{text}"
    );
    assert!(
        text.contains("Scanned 5 message(s): 2 withheld, 1 redacted, 1 protected, 1 allowed"),
        "{text}"
    );
    assert!(!text.contains("Lunch tomorrow?"), "{text}");

    // A candidate without the bank filter changes exactly one message.
    let policy = fs::read_to_string(env.dir.path().join("sherpa.toml")).unwrap();
    let candidate = env.dir.path().join("candidate.toml");
    fs::write(
        &candidate,
        &policy[..policy.find("[[filter]]\nname = \"bank\"").unwrap()],
    )
    .unwrap();
    let out = env.admin(&["policy", "scan", "--policy", candidate.to_str().unwrap(), "--compare"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("1005.host")
            && text.contains("redact (bank)")
            && text.contains("1 message(s) would be treated differently"),
        "{text}"
    );

    // Dates: every fixture is from today.
    let out = env.admin(&["policy", "scan", "--until", "2000-01-01"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Scanned 0 message(s)"));
}
