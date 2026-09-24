//! `sherpa-admin`: set up the privilege boundary, manage secrets, check the
//! installation, and review what the agent tried to send.

use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Group, Uid, User};
use toml_edit::{DocumentMut, Item, TableLike, value};

use crate::classify::Action;
use crate::config::{Config, EXAMPLE_CONFIG};
use crate::himalaya::Himalaya;
use crate::outbox::{self, Outbox, Status};

/// Where everything is installed.
pub struct Layout {
    pub etc: PathBuf,
    pub libexec: PathBuf,
    pub state: PathBuf,
    pub attachments: PathBuf,
    pub sudoers: PathBuf,
    pub bin: PathBuf,
    pub admin_bin: PathBuf,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            etc: "/etc/himalaya-sherpa".into(),
            libexec: "/usr/local/libexec/himalaya-sherpa".into(),
            state: "/var/lib/himalaya-sherpa".into(),
            attachments: "/var/lib/himalaya-sherpa-attachments".into(),
            sudoers: "/etc/sudoers.d/himalaya-sherpa".into(),
            bin: "/usr/local/bin/sherpa".into(),
            admin_bin: "/usr/local/sbin/sherpa-admin".into(),
        }
    }
}

impl Layout {
    pub fn config(&self) -> PathBuf {
        self.etc.join("sherpa.toml")
    }
    pub fn himalaya_config(&self) -> PathBuf {
        self.etc.join("himalaya.toml")
    }
    pub fn secrets(&self) -> PathBuf {
        self.etc.join("secrets")
    }
    pub fn gate(&self) -> PathBuf {
        self.libexec.join("sherpa")
    }
    pub fn himalaya(&self) -> PathBuf {
        self.libexec.join("himalaya")
    }
}

pub fn valid_secret_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

// ----- config import ------------------------------------------------------------

/// A password setting found while importing a himalaya configuration.
#[derive(Debug, Clone)]
pub struct ImportedPassword {
    pub account: String,
    /// Dotted path of the `password` key inside the account, e.g. `imap.sasl.plain.password`.
    pub key: String,
    /// The original `password.command`, if any.
    pub command: Option<String>,
    /// Name of the secret file the setting now reads.
    pub secret: String,
}

fn find_passwords(table: &mut dyn TableLike, path: &str, out: &mut Vec<(String, Option<String>, bool)>) {
    for (key, item) in table.iter_mut() {
        let here = if path.is_empty() {
            key.get().to_string()
        } else {
            format!("{path}.{}", key.get())
        };
        let Some(sub) = item.as_table_like_mut() else { continue };
        if key.get() == "password" {
            let command = sub.get("command").and_then(|c| {
                c.as_str().map(String::from).or_else(|| {
                    c.as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "))
                })
            });
            out.push((here, command, true));
        } else {
            find_passwords(sub, &here, out);
        }
    }
}

fn set_password(table: &mut dyn TableLike, key: &str, command: &str) {
    let mut parts = key.split('.');
    let first = parts.next().unwrap_or_default();
    let rest: Vec<&str> = parts.collect();
    let Some(item) = table.get_mut(first) else { return };
    let Some(sub) = item.as_table_like_mut() else { return };
    if rest.is_empty() {
        sub.clear();
        sub.insert("command", value(command));
    } else {
        set_password(sub, &rest.join("."), command);
    }
}

/// Rewrite every `password` setting of every account to read a root-owned secret
/// file instead. Accounts whose password settings share one command share a secret.
pub fn rewrite_passwords(text: &str, secrets_dir: &Path) -> Result<(String, Vec<ImportedPassword>)> {
    let mut doc: DocumentMut = text.parse().context("invalid himalaya configuration")?;
    let mut imported = Vec::new();
    let Some(accounts) = doc.get_mut("accounts").and_then(Item::as_table_like_mut) else {
        bail!("no [accounts] in the himalaya configuration");
    };
    for (name, account) in accounts.iter_mut() {
        let name = name.get().to_string();
        if !valid_secret_name(&name) {
            bail!("account name {name:?} cannot be used as a secret file name");
        }
        let Some(account) = account.as_table_like_mut() else {
            continue;
        };
        let mut found = Vec::new();
        find_passwords(account, "", &mut found);
        let mut distinct: Vec<Option<String>> = found.iter().map(|(_, c, _)| c.clone()).collect();
        distinct.dedup();
        for (key, command, _) in found {
            let secret = if distinct.len() <= 1 {
                name.clone()
            } else {
                format!("{name}.{}", key.split('.').next().unwrap_or("password"))
            };
            let path = secrets_dir.join(&secret);
            set_password(account, &key, &format!("cat {}", path.display()));
            imported.push(ImportedPassword {
                account: name.clone(),
                key,
                command,
                secret,
            });
        }
    }
    Ok((doc.to_string(), imported))
}

// ----- setup ----------------------------------------------------------------------

/// Executes (or, in dry-run mode, prints) installation steps.
struct Steps {
    dry: bool,
}

impl Steps {
    fn say(&self, what: String) {
        println!("{} {what}", if self.dry { "[dry-run]" } else { "  -" });
    }

    fn own(&self, path: &Path, uid: Uid, gid: Gid, mode: u32) -> Result<()> {
        if self.dry {
            return Ok(());
        }
        nix::unistd::chown(path, Some(uid), Some(gid)).with_context(|| format!("chown {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", path.display()))
    }

    fn mkdir(&self, path: &Path, uid: Uid, gid: Gid, mode: u32) -> Result<()> {
        self.say(format!("directory {} ({}:{} {mode:o})", path.display(), uid, gid));
        if !self.dry {
            fs::create_dir_all(path).with_context(|| format!("mkdir {}", path.display()))?;
        }
        self.own(path, uid, gid, mode)
    }

    fn write(&self, path: &Path, data: &[u8], uid: Uid, gid: Gid, mode: u32) -> Result<()> {
        self.say(format!("write {} ({}:{} {mode:o})", path.display(), uid, gid));
        if self.dry {
            return Ok(());
        }
        let tmp = path.with_file_name(format!(
            ".{}.{}.tmp",
            path.file_name().unwrap().to_string_lossy(),
            std::process::id()
        ));
        // create_new is O_CREAT|O_EXCL: it never follows a symlink planted at `tmp`.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        drop(f);
        self.own(&tmp, uid, gid, mode)?;
        fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))
    }

    fn copy(&self, from: &Path, to: &Path, uid: Uid, gid: Gid, mode: u32) -> Result<()> {
        self.say(format!(
            "install {} -> {} ({}:{} {mode:o})",
            from.display(),
            to.display(),
            uid,
            gid
        ));
        if self.dry {
            return Ok(());
        }
        let data = fs::read(from).with_context(|| format!("read {}", from.display()))?;
        self.write(to, &data, uid, gid, mode)
    }

    fn run(&self, cmd: &mut Command) -> Result<()> {
        self.say(format!("run {cmd:?}"));
        if self.dry {
            return Ok(());
        }
        let status = cmd.status().with_context(|| format!("cannot run {cmd:?}"))?;
        if !status.success() {
            bail!("{cmd:?} failed with {status}");
        }
        Ok(())
    }
}

pub struct SetupOptions {
    pub agent_user: String,
    pub service_user: String,
    pub himalaya: Option<PathBuf>,
    pub import_config: Option<PathBuf>,
    pub import_secrets: bool,
    pub shims: Vec<PathBuf>,
    pub dry_run: bool,
    /// Accept binaries and configuration the agent could have modified.
    pub allow_untrusted: bool,
}

fn user(name: &str) -> Result<User> {
    User::from_name(name)?.with_context(|| format!("no such user `{name}`"))
}

fn find_himalaya(agent: &User) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).map(|d| d.join("himalaya")).collect())
        .unwrap_or_default();
    candidates.push(agent.dir.join(".local/bin/himalaya"));
    candidates.into_iter().find(|p| p.is_file() && !is_shim(p))
}

fn is_shim(path: &Path) -> bool {
    fs::read(path)
        .map(|d| d.starts_with(b"#!/bin/sh\n# himalaya-sherpa"))
        .unwrap_or(false)
}

fn shim_script(layout: &Layout, service_user: &str) -> String {
    format!(
        "#!/bin/sh\n# himalaya-sherpa: email access goes through the policy gate.\n\
         exec sudo -n -u {service_user} {} \"$@\"\n",
        layout.gate().display()
    )
}

fn sudoers_rule(layout: &Layout, agent: &str, service: &str) -> String {
    format!(
        "# Installed by himalaya-sherpa. The agent user may run only the gate, and only as\n\
         # the service user; the environment is reset by sudo.\n\
         {agent} ALL=({service}) NOPASSWD: {}\n",
        layout.gate().display()
    )
}

/// Why `path` cannot be trusted as coming from outside the agent's control: it, or a
/// directory above it, is owned by or writable by the agent user (or world-writable).
pub fn untrusted_reason(path: &Path, agent: &User) -> Option<String> {
    let real = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => return Some(format!("cannot resolve {}: {e}", path.display())),
    };
    let mut cur = Some(real.as_path());
    while let Some(p) = cur {
        if let Ok(m) = fs::metadata(p) {
            let world_writable = m.mode() & 0o002 != 0 && m.mode() & 0o1000 == 0;
            let group_writable = m.mode() & 0o020 != 0 && m.gid() == agent.gid.as_raw();
            if m.uid() == agent.uid.as_raw() || world_writable || group_writable {
                return Some(format!(
                    "{} is writable by {} (via {})",
                    real.display(),
                    agent.name,
                    p.display()
                ));
            }
        }
        cur = p.parent();
    }
    None
}

/// Settings other than `password` that make himalaya run a command. In a config the
/// agent could edit, any of them could leak the credentials once installed.
pub fn command_settings(text: &str) -> Result<Vec<String>> {
    fn walk(table: &dyn TableLike, path: &str, out: &mut Vec<String>) {
        for (key, item) in table.iter() {
            let here = if path.is_empty() {
                key.to_string()
            } else {
                format!("{path}.{key}")
            };
            let k = key.to_ascii_lowercase();
            if k == "password" {
                continue;
            }
            if let Some(sub) = item.as_table_like() {
                walk(sub, &here, out);
            } else if k == "command"
                || k == "cmd"
                || k.contains("hook")
                || k.ends_with("-command")
                || k.ends_with("-cmd")
            {
                out.push(here);
            }
        }
    }
    let doc: DocumentMut = text.parse().context("invalid himalaya configuration")?;
    let mut out = Vec::new();
    walk(doc.as_table(), "", &mut out);
    Ok(out)
}

/// Run a password command as the agent user and return its first line.
fn fetch_secret_as(agent: &str, command: &str) -> Result<String> {
    let out = Command::new("runuser")
        .args(["-u", agent, "--", "sh", "-c", command])
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("cannot run runuser")?;
    if !out.status.success() {
        bail!("password command failed ({})", out.status);
    }
    let text = String::from_utf8(out.stdout).context("password is not UTF-8")?;
    let line = text.lines().next().unwrap_or_default().to_string();
    if line.is_empty() {
        bail!("password command printed nothing");
    }
    Ok(line)
}

pub fn write_secret(layout: &Layout, service: &User, name: &str, secret: &str) -> Result<()> {
    if !valid_secret_name(name) {
        bail!("invalid secret name {name:?}");
    }
    let steps = Steps { dry: false };
    let path = layout.secrets().join(name);
    steps.write(&path, secret.as_bytes(), Uid::from_raw(0), service.gid, 0o640)
}

pub fn require_root() -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("this command must run as root (try sudo)");
    }
    Ok(())
}

pub fn setup(opts: &SetupOptions) -> Result<()> {
    if !opts.dry_run {
        require_root()?;
    }
    let layout = Layout::default();
    let steps = Steps { dry: opts.dry_run };
    let agent = user(&opts.agent_user)?;
    if agent.uid.is_root() {
        bail!("the agent user must not be root");
    }
    if opts.service_user == opts.agent_user {
        bail!("the service user must differ from the agent user");
    }

    println!(
        "Setting up himalaya-sherpa (agent: {}, service user: {})",
        agent.name, opts.service_user
    );

    let himalaya = opts
        .himalaya
        .clone()
        .or_else(|| find_himalaya(&agent))
        .context("cannot find the himalaya binary; pass --himalaya <PATH>")?;
    let me = std::env::current_exe()?;
    let gate = me.with_file_name("sherpa");
    if !gate.is_file() {
        bail!("cannot find the sherpa binary next to {}", me.display());
    }
    // The gate runs with the credentials: its binaries must not come from anywhere
    // the agent could have tampered with.
    for bin in [&himalaya, &gate] {
        if let Some(why) = untrusted_reason(bin, &agent) {
            if !opts.allow_untrusted {
                bail!(
                    "refusing to install {}: {why}.\n\
                     The agent could have replaced it, and the gate runs it with your credentials.\n\
                     Install a copy from a trusted source (a release you verified, or a build you \
                     made as another user) and pass --himalaya / run that build's sherpa-admin.\n\
                     If you verified this file yourself, pass --allow-untrusted.",
                    bin.display()
                );
            }
            println!("  ! {why} (accepted with --allow-untrusted)");
        }
    }
    if let Ok(out) = Command::new("sha256sum").arg(&himalaya).output() {
        print!("  - himalaya sha256: {}", String::from_utf8_lossy(&out.stdout));
    }

    // 1. Service user.
    let service = match User::from_name(&opts.service_user)? {
        Some(u) => {
            println!("  - service user {} exists (uid {})", u.name, u.uid);
            u
        }
        None => {
            steps.run(Command::new("useradd").args([
                "--system",
                "--user-group",
                "--home-dir",
                &layout.state.display().to_string(),
                "--no-create-home",
                "--shell",
                "/sbin/nologin",
                "--comment",
                "himalaya-sherpa email gate",
                &opts.service_user,
            ]))?;
            if opts.dry_run {
                User {
                    name: opts.service_user.clone(),
                    uid: Uid::from_raw(999),
                    gid: Gid::from_raw(999),
                    ..agent.clone()
                }
            } else {
                user(&opts.service_user)?
            }
        }
    };
    let root = Uid::from_raw(0);
    let root_g = Gid::from_raw(0);
    let sg = service.gid;
    if Group::from_gid(agent.gid)?.is_some_and(|g| g.mem.contains(&service.name)) || agent.gid == sg {
        bail!("the agent user must not share the service user's group");
    }

    // 2. Directories.
    steps.mkdir(&layout.etc, root, sg, 0o750)?;
    steps.mkdir(&layout.secrets(), root, sg, 0o750)?;
    steps.mkdir(&layout.state, service.uid, sg, 0o700)?;
    steps.mkdir(&layout.attachments, service.uid, agent.gid, 0o2750)?;
    steps.mkdir(&layout.libexec, root, root_g, 0o755)?;

    // 3. Binaries: the real himalaya is only executable by the service user.
    steps.copy(&himalaya, &layout.himalaya(), root, sg, 0o750)?;
    steps.copy(&gate, &layout.gate(), root, root_g, 0o755)?;
    if me != layout.admin_bin {
        steps.copy(&me, &layout.admin_bin, root, root_g, 0o755)?;
    }

    // 4. Policy.
    if layout.config().exists() {
        println!("  - keeping existing {}", layout.config().display());
    } else {
        steps.write(&layout.config(), EXAMPLE_CONFIG.as_bytes(), root, sg, 0o640)?;
    }

    // 5. himalaya configuration, with passwords moved to root-owned secret files.
    let import = opts.import_config.clone().or_else(|| {
        let p = agent.dir.join(".config/himalaya/config.toml");
        (p.is_file() && !layout.himalaya_config().exists()).then_some(p)
    });
    let mut imported = Vec::new();
    if let Some(src) = &import {
        let text = fs::read_to_string(src).with_context(|| format!("read {}", src.display()))?;
        let (rewritten, found) = rewrite_passwords(&text, &layout.secrets())?;
        let commands = command_settings(&rewritten)?;
        if !commands.is_empty() {
            let list = commands.join("\n    ");
            if untrusted_reason(src, &agent).is_some() && !opts.allow_untrusted {
                bail!(
                    "{} (writable by the agent) makes himalaya run commands:\n    {list}\n\
                     Installed, they would run as the service user, next to the credentials. \
                     Review them, then re-run with --allow-untrusted, or import a config you wrote.",
                    src.display()
                );
            }
            println!("  ! the imported config runs commands; review them:\n    {list}");
        }
        steps.write(&layout.himalaya_config(), rewritten.as_bytes(), root, sg, 0o640)?;
        for p in &found {
            println!("    {}.{} now reads secret `{}`", p.account, p.key, p.secret);
        }
        imported = found;
    } else if layout.himalaya_config().exists() {
        println!("  - keeping existing {}", layout.himalaya_config().display());
    } else {
        println!(
            "  ! no himalaya configuration imported; write {} yourself",
            layout.himalaya_config().display()
        );
    }

    // 6. Secrets.
    let mut missing = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in imported.iter().filter(|p| seen.insert(p.secret.clone())) {
        if layout.secrets().join(&p.secret).exists() {
            println!("  - secret `{}` already set", p.secret);
            continue;
        }
        if opts.dry_run {
            missing.push(p.secret.clone());
            continue;
        }
        if opts.import_secrets
            && let Some(cmd) = &p.command
        {
            println!(
                "  - importing secret `{}` by running its password command as {}",
                p.secret, agent.name
            );
            match fetch_secret_as(&agent.name, cmd) {
                Ok(s) => {
                    write_secret(&layout, &service, &p.secret, &s)?;
                    continue;
                }
                Err(e) => println!("    ! {e:#}"),
            }
        }
        if std::io::stdin().is_terminal() {
            let s = rpassword::prompt_password(format!("  Password for secret `{}` (empty to skip): ", p.secret))?;
            if !s.is_empty() {
                write_secret(&layout, &service, &p.secret, &s)?;
                continue;
            }
        }
        missing.push(p.secret.clone());
    }

    // 7. sudo rule, validated before it is installed.
    let rule = sudoers_rule(&layout, &agent.name, &service.name);
    if opts.dry_run {
        steps.say(format!(
            "write {} (0440, validated with visudo):\n{rule}",
            layout.sudoers.display()
        ));
    } else {
        let tmp = std::env::temp_dir().join(format!("himalaya-sherpa-sudoers.{}", std::process::id()));
        fs::write(&tmp, &rule)?;
        let ok = Command::new("visudo")
            .args(["-cqf"])
            .arg(&tmp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let _ = fs::remove_file(&tmp);
        if !ok {
            bail!("visudo rejected the generated sudoers rule:\n{rule}");
        }
        steps.write(&layout.sudoers, rule.as_bytes(), root, root_g, 0o440)?;
    }

    // 8. Command for the agent.
    let shim = shim_script(&layout, &service.name);
    steps.write(&layout.bin, shim.as_bytes(), root, root_g, 0o755)?;
    for path in &opts.shims {
        // A shim in the agent's own directories gives no protection by being root-owned
        // (the agent can replace it), and writing there as root invites symlink races,
        // so it is written with the agent's privileges.
        let script = "umask 022; t=\"$1.sherpa.$$\"; cat > \"$t\" && chmod 755 \"$t\" && mv -f \"$t\" \"$1\"";
        let mut cmd = Command::new("runuser");
        cmd.args(["-u", &agent.name, "--", "sh", "-c", script, "sh"]).arg(path);
        steps.say(format!("write {} as {} (0755)", path.display(), agent.name));
        if !opts.dry_run {
            let mut child = cmd
                .stdin(std::process::Stdio::piped())
                .spawn()
                .context("cannot run runuser")?;
            child.stdin.take().unwrap().write_all(shim.as_bytes())?;
            if !child.wait()?.success() {
                bail!("cannot write {}", path.display());
            }
        }
    }

    println!("\nDone. Next steps:");
    for s in &missing {
        println!(
            "  * set the password: sudo {} secret set {s}",
            layout.admin_bin.display()
        );
    }
    println!(
        "  * check the installation: sudo {} doctor --agent-user {}",
        layout.admin_bin.display(),
        agent.name
    );
    println!(
        "  * as {}, run `sherpa envelope list` (or the shim) to try it",
        agent.name
    );
    println!("  * review the policy in {}", layout.config().display());
    if let Some(src) = &import {
        println!(
            "  * remove the agent's copy of the credentials: its himalaya config ({}) and any password-store \
             entries it can decrypt, then rotate the app passwords, since the agent could read them until now",
            src.display()
        );
    }
    Ok(())
}

// ----- doctor -------------------------------------------------------------------

struct Report {
    fails: usize,
    warns: usize,
}

impl Report {
    fn ok(&self, msg: impl AsRef<str>) {
        println!("[ ok ] {}", msg.as_ref());
    }
    fn warn(&mut self, msg: impl AsRef<str>) {
        self.warns += 1;
        println!("[warn] {}", msg.as_ref());
    }
    fn fail(&mut self, msg: impl AsRef<str>) {
        self.fails += 1;
        println!("[FAIL] {}", msg.as_ref());
    }
    fn check(&mut self, good: bool, ok: impl AsRef<str>, bad: impl AsRef<str>) {
        if good { self.ok(ok) } else { self.fail(bad) }
    }
}

/// Run `test <flag> <path>` as `user`.
fn as_user_test(user: &str, flag: &str, path: &Path) -> bool {
    Command::new("runuser")
        .args(["-u", user, "--", "test", flag])
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn check_mode(r: &mut Report, path: &Path, uid: Uid, gid: Option<Gid>, max_mode: u32) {
    match fs::metadata(path) {
        Err(e) => r.fail(format!("{}: {e}", path.display())),
        Ok(m) => {
            let mode = m.mode() & 0o7777;
            let owner_ok = m.uid() == uid.as_raw() && gid.is_none_or(|g| m.gid() == g.as_raw());
            let mode_ok = mode & !max_mode == 0;
            r.check(
                owner_ok && mode_ok,
                format!("{} ({}:{} {:o})", path.display(), m.uid(), m.gid(), mode),
                format!(
                    "{} has owner {}:{} mode {:o}; expected {}:{} and no more than {:o}",
                    path.display(),
                    m.uid(),
                    m.gid(),
                    mode,
                    uid,
                    gid.map(|g| g.to_string()).unwrap_or("*".into()),
                    max_mode
                ),
            );
        }
    }
}

pub fn doctor(agent_user: &str, service_user: &str) -> Result<bool> {
    require_root()?;
    let layout = Layout::default();
    let mut r = Report { fails: 0, warns: 0 };
    let agent = user(agent_user)?;
    let Some(service) = User::from_name(service_user)? else {
        r.fail(format!("service user `{service_user}` does not exist; run setup"));
        return Ok(false);
    };
    let root = Uid::from_raw(0);
    println!(
        "Checking himalaya-sherpa for agent `{}` (service user `{}`)\n",
        agent.name, service.name
    );

    // Policy.
    let cfg = match Config::load(&layout.config()) {
        Ok(c) => {
            r.ok(format!(
                "{} parses ({} filters, send mode {:?})",
                layout.config().display(),
                c.filters.len(),
                c.raw.send.mode
            ));
            Some(c)
        }
        Err(e) => {
            r.fail(format!("{e:#}"));
            None
        }
    };

    // Ownership and modes.
    check_mode(&mut r, &layout.etc, root, Some(service.gid), 0o750);
    check_mode(&mut r, &layout.config(), root, Some(service.gid), 0o640);
    check_mode(&mut r, &layout.himalaya_config(), root, Some(service.gid), 0o640);
    check_mode(&mut r, &layout.secrets(), root, Some(service.gid), 0o750);
    if let Ok(dir) = fs::read_dir(layout.secrets()) {
        for e in dir.flatten() {
            check_mode(&mut r, &e.path(), root, Some(service.gid), 0o640);
        }
    }
    check_mode(&mut r, &layout.himalaya(), root, Some(service.gid), 0o750);
    check_mode(&mut r, &layout.gate(), root, None, 0o755);
    check_mode(&mut r, &layout.state, service.uid, None, 0o700);
    check_mode(&mut r, &layout.sudoers, root, None, 0o440);

    // The boundary, tested from the agent's side.
    for (path, what) in [
        (layout.himalaya_config(), "the himalaya configuration"),
        (layout.config(), "the policy"),
        (layout.state.join("audit.log"), "the audit log"),
    ] {
        if path.exists() {
            r.check(
                !as_user_test(&agent.name, "-r", &path),
                format!("agent cannot read {what}"),
                format!("agent CAN read {what} ({})", path.display()),
            );
        }
    }
    if let Ok(dir) = fs::read_dir(layout.secrets()) {
        for e in dir.flatten() {
            r.check(
                !as_user_test(&agent.name, "-r", &e.path()),
                format!("agent cannot read secret `{}`", e.file_name().to_string_lossy()),
                format!("agent CAN read secret {}", e.path().display()),
            );
        }
    }
    r.check(
        !as_user_test(&agent.name, "-x", &layout.himalaya()),
        "agent cannot execute the gate's himalaya binary",
        "agent CAN execute the gate's himalaya binary",
    );
    for path in [
        &layout.etc,
        &layout.libexec,
        &layout.config(),
        &layout.gate(),
        &layout.himalaya(),
    ] {
        if as_user_test(&agent.name, "-w", path) {
            r.fail(format!("agent CAN write {}", path.display()));
        }
    }

    // sudo: the agent may run the gate as the service user, and nothing else.
    match Command::new("sudo").args(["-l", "-U", &agent.name]).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let rules: Vec<&str> = text
                .lines()
                .skip_while(|l| !l.contains("may run the following commands"))
                .skip(1)
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            let gate = layout.gate().display().to_string();
            let ours = rules
                .iter()
                .any(|l| l.contains(&gate) && l.contains(&format!("({})", service.name)));
            r.check(
                ours,
                "sudo rule for the gate is active",
                "sudo rule for the gate is missing",
            );
            for l in rules.iter().filter(|l| !l.contains(&gate)) {
                r.fail(format!("agent has another sudo rule, which may bypass the gate: {l}"));
            }
        }
        Err(e) => r.warn(format!("cannot list sudo rules: {e}")),
    }

    // End to end, as the agent.
    let out = Command::new("runuser")
        .args(["-u", &agent.name, "--", "sudo", "-n", "-u", &service.name])
        .arg(layout.gate())
        .args(["account", "list"])
        .output();
    match out {
        Ok(o) if o.status.success() => r.ok("agent can reach the gate (`account list` works)"),
        Ok(o) => r.fail(format!(
            "agent cannot use the gate: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => r.fail(format!("cannot run the gate as the agent: {e}")),
    }

    // Leftover credentials on the agent's side.
    let agent_cfg = agent.dir.join(".config/himalaya/config.toml");
    if agent_cfg.exists() {
        let text = fs::read_to_string(&agent_cfg).unwrap_or_default();
        if text.contains("password") {
            r.warn(format!(
                "{} still has password settings; remove it (and the secrets it points to) from the agent",
                agent_cfg.display()
            ));
        }
    }
    let store = agent.dir.join(".password-store");
    if store.exists() {
        r.warn(format!(
            "{} exists; make sure it holds no email passwords the agent can decrypt",
            store.display()
        ));
    }
    let local = agent.dir.join(".local/bin/himalaya");
    if local.exists() && !is_shim(&local) {
        r.warn(format!(
            "{} is a real himalaya binary; replace it with the shim (setup --shim)",
            local.display()
        ));
    }
    if let Some(cfg) = &cfg
        && cfg.raw.mailboxes.readable.is_empty()
    {
        r.ok("filters apply to every mailbox (no mailbox allowlist)");
    }

    println!("\n{} failure(s), {} warning(s)", r.fails, r.warns);
    Ok(r.fails == 0)
}

// ----- review -------------------------------------------------------------------

/// Drop from root to the service user, so review commands use its files and
/// himalaya runs with the same privileges as for the agent.
pub fn drop_to(service_user: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let u = user(service_user)?;
    nix::unistd::setgroups(&[u.gid])?;
    nix::unistd::setgid(u.gid)?;
    nix::unistd::setuid(u.uid)?;
    Ok(())
}

pub fn review_list(cfg: &Config, all: bool) -> Result<()> {
    let entries = Outbox::new(cfg.outbox_dir()).list()?;
    let rows: Vec<Vec<String>> = entries
        .iter()
        .filter(|e| all || e.status == Status::Pending)
        .map(|e| {
            vec![
                e.id.clone(),
                e.status.as_str().into(),
                e.account.clone().unwrap_or_else(|| "(default)".into()),
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
    if rows.is_empty() {
        println!(
            "{}",
            if all {
                "The outbox is empty."
            } else {
                "No messages waiting for approval."
            }
        );
        return Ok(());
    }
    print!(
        "{}",
        crate::render::table(&["ID", "STATUS", "ACCOUNT", "RECIPIENTS", "SUBJECT"], &rows, None)
    );
    Ok(())
}

pub fn review_show(cfg: &Config, id: &str) -> Result<()> {
    let outbox = Outbox::new(cfg.outbox_dir());
    let e = outbox.get(id)?;
    println!("{}", serde_json::to_string_pretty(&e)?);
    println!("----- message -----");
    std::io::stdout().write_all(&outbox.raw(id)?)?;
    Ok(())
}

pub enum Via {
    Send,
    Draft,
}

fn reviewer() -> String {
    std::env::var("SUDO_USER").unwrap_or_else(|_| crate::audit::caller())
}

pub fn review_approve(cfg: &Config, id: &str, via: Via) -> Result<()> {
    let outbox = Outbox::new(cfg.outbox_dir());
    let mut e = outbox.get(id)?;
    if !matches!(e.status, Status::Pending | Status::Denied) {
        bail!(
            "message {id} is {}; only pending or denied messages can be approved",
            e.status.as_str()
        );
    }
    let raw = outbox.raw(id)?;
    let him = Himalaya {
        cfg,
        account: e.account.clone(),
    };
    match via {
        Via::Send => {
            him.run_ok(false, &["message", "send"], Some(&raw)).map_err(|err| {
                anyhow::anyhow!("{err:#}\n(if this account has no send backend, approve with --via draft)")
            })?;
            e.status = Status::Sent;
            println!("Sent {id}.");
        }
        Via::Draft => {
            let mb = cfg.raw.send.drafts_mailbox.as_str();
            him.run_ok(false, &["message", "add", "-m", mb, "-f", "draft"], Some(&raw))?;
            e.status = Status::Drafted;
            println!("Saved {id} to {mb}; send it from your mail client.");
        }
    }
    e.updated = Some(outbox::now_rfc3339());
    e.note = Some(format!("approved by {}", reviewer()));
    outbox.save(&e)?;
    crate::audit::record(
        cfg,
        e.account.as_deref(),
        "review approve",
        e.status.as_str(),
        serde_json::json!({ "outbox-id": id, "reviewer": reviewer() }),
    );
    Ok(())
}

pub fn review_deny(cfg: &Config, id: &str, reason: Option<String>) -> Result<()> {
    let outbox = Outbox::new(cfg.outbox_dir());
    let mut e = outbox.get(id)?;
    if e.status != Status::Pending {
        bail!("message {id} is {}, not pending", e.status.as_str());
    }
    e.status = Status::Denied;
    e.updated = Some(outbox::now_rfc3339());
    e.note = Some(reason.unwrap_or_else(|| "denied by the user".into()));
    outbox.save(&e)?;
    crate::audit::record(
        cfg,
        e.account.as_deref(),
        "review deny",
        "denied",
        serde_json::json!({ "outbox-id": id, "reviewer": reviewer() }),
    );
    println!("Denied {id}.");
    Ok(())
}

pub fn show_log(cfg: &Config, lines: usize) -> Result<()> {
    let mut text = String::new();
    match fs::File::open(cfg.audit_log()) {
        Ok(mut f) => {
            f.read_to_string(&mut text)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("The audit log is empty.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    let all: Vec<&str> = text.lines().collect();
    for l in &all[all.len().saturating_sub(lines)..] {
        println!("{l}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_dotted_and_inline_passwords() {
        let src = r#"
[accounts.gmail]
default = true
email = "a@gmail.com"
imap.sasl.plain.password.command = "pass show mail/gmail"
smtp.auth.password.command = "pass show mail/gmail"

[accounts.work]
imap.password = { command = ["pass", "show", "work/imap"] }
smtp.password.command = "pass show work/smtp"
"#;
        let (out, found) = rewrite_passwords(src, Path::new("/etc/himalaya-sherpa/secrets")).unwrap();
        assert!(!out.contains("pass show"), "{out}");
        assert!(
            out.contains(r#"imap.sasl.plain.password.command = "cat /etc/himalaya-sherpa/secrets/gmail""#),
            "{out}"
        );
        let secrets: Vec<&str> = found.iter().map(|p| p.secret.as_str()).collect();
        assert_eq!(secrets, ["gmail", "gmail", "work.imap", "work.smtp"]);
        assert_eq!(found[2].command.as_deref(), Some("pass show work/imap"));
        // Still a valid himalaya config.
        let parsed: toml::Table = toml::from_str(&out).unwrap();
        assert!(
            parsed["accounts"]["work"]["imap"]["password"]["command"]
                .as_str()
                .unwrap()
                .starts_with("cat ")
        );
    }

    #[test]
    fn secret_names() {
        assert!(valid_secret_name("gmail"));
        assert!(valid_secret_name("work.smtp"));
        assert!(!valid_secret_name("../x"));
        assert!(!valid_secret_name(".hidden"));
        assert!(!valid_secret_name("a/b"));
    }
}

#[cfg(test)]
mod import_tests {
    use super::*;

    #[test]
    fn finds_command_settings_other_than_passwords() {
        let src = r#"
[accounts.a]
imap.password.command = "pass show a"
message.send.pre-hook = "curl evil"
backend.cmd = "x"
pgp.command = "gpg"
"#;
        let found = command_settings(src).unwrap();
        assert_eq!(
            found,
            [
                "accounts.a.message.send.pre-hook",
                "accounts.a.backend.cmd",
                "accounts.a.pgp.command"
            ]
        );
    }
}

// ----- policy -------------------------------------------------------------------

/// Parse and check a policy text. Returns the report, or the parse error.
pub fn check_policy_text(text: &str) -> Result<crate::policy::Report> {
    let cfg = Config::parse(text)?;
    Ok(crate::policy::check(&cfg, chrono::Utc::now().timestamp()))
}

/// Print the check result for a policy; true when it passes.
fn report_policy(text: &str) -> bool {
    match check_policy_text(text) {
        Ok(report) => {
            print!("{}", report.render());
            report.passed()
        }
        Err(e) => {
            println!("[FAIL] {e:#}");
            false
        }
    }
}

pub fn policy_check(path: &Path) -> Result<bool> {
    let text = fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    println!("Checking {}\n", path.display());
    Ok(report_policy(&text))
}

/// Classify real messages (.eml files, or stdin) with a policy and show what the agent would see.
pub fn policy_test(policy: &Path, files: &[PathBuf]) -> Result<()> {
    let cfg = Config::load(policy)?;
    let now = chrono::Utc::now().timestamp();
    let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
    if files.is_empty() {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        inputs.push(("<stdin>".into(), buf));
    }
    for f in files {
        inputs.push((
            f.display().to_string(),
            fs::read(f).with_context(|| format!("cannot read {}", f.display()))?,
        ));
    }
    for (name, raw) in inputs {
        let view = crate::policy::agent_view(&cfg, &raw, now);
        let action = |v: &crate::classify::Verdict| match v.action {
            Some(a) => format!("{} ({})", a.as_str(), v.filter_names()),
            None => "allow".into(),
        };
        println!("== {name}");
        println!("read:    {}", action(&view.read));
        println!(
            "listing: {}",
            if view.listing_text.is_empty() {
                "hidden".into()
            } else {
                action(&view.listing)
            }
        );
        if !view.read_text.is_empty() {
            println!("--- what the agent reads ---\n{}", view.read_text.trim_end());
        }
        println!();
    }
    Ok(())
}

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_lowercase())
}

fn show_diff(old: &Path, new: &Path) {
    let status = Command::new("diff")
        .args(["-u", "--label", "installed", "--label", "new"])
        .arg(old)
        .arg(new)
        .status();
    if status.is_err() {
        println!("(diff is not available)");
    }
}

/// Atomically install a checked policy as root:<service> 0640.
fn install_policy_bytes(layout: &Layout, service_user: &str, data: &[u8]) -> Result<()> {
    let service = user(service_user)?;
    Steps { dry: false }.write(&layout.config(), data, Uid::from_raw(0), service.gid, 0o640)?;
    println!(
        "Installed {}. It applies to the next agent command.",
        layout.config().display()
    );
    Ok(())
}

/// Check `path`, show the diff against the installed policy, and install it.
pub fn policy_install(service_user: &str, path: &Path, yes: bool) -> Result<bool> {
    require_root()?;
    let layout = Layout::default();
    let text = fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    println!("Checking {}\n", path.display());
    if !report_policy(&text) {
        println!("\nNot installed: fix the policy or its examples first.");
        return Ok(false);
    }
    if layout.config().exists() {
        println!();
        show_diff(&layout.config(), path);
    }
    if !yes && ask("\nInstall this policy? [y/N] ")? != "y" {
        println!("Not installed.");
        return Ok(false);
    }
    install_policy_bytes(&layout, service_user, text.as_bytes())?;
    Ok(true)
}

/// Edit the installed policy like visudo: edit a private copy, check it, show the
/// diff, and install it only if it passes.
pub fn policy_edit(service_user: &str) -> Result<bool> {
    require_root()?;
    let layout = Layout::default();
    let installed = layout.config();
    let original = fs::read(&installed).with_context(|| format!("cannot read {}", installed.display()))?;
    let tmp = layout.etc.join(format!(".sherpa.toml.{}.edit", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    f.write_all(&original)?;
    drop(f);
    let result = edit_loop(&layout, service_user, &installed, &tmp, &original);
    let _ = fs::remove_file(&tmp);
    result
}

fn edit_loop(layout: &Layout, service_user: &str, installed: &Path, tmp: &Path, original: &[u8]) -> Result<bool> {
    let editor = ["SUDO_EDITOR", "VISUAL", "EDITOR"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "vi".into());
    loop {
        let status = Command::new("sh")
            .args(["-c", &format!("{editor} \"$1\""), "sh"])
            .arg(tmp)
            .status()
            .with_context(|| format!("cannot run editor {editor:?}"))?;
        if !status.success() {
            bail!("editor exited with {status}; policy not changed");
        }
        let text = fs::read_to_string(tmp)?;
        if text.as_bytes() == original {
            println!("No changes.");
            return Ok(true);
        }
        println!();
        if report_policy(&text) {
            println!();
            show_diff(installed, tmp);
            match ask("\nInstall? (y)es, (e)dit again, (q)uit without saving [e]: ")?.as_str() {
                "y" | "yes" => {
                    install_policy_bytes(layout, service_user, text.as_bytes())?;
                    return Ok(true);
                }
                "q" | "quit" => {
                    println!("Discarded; the installed policy is unchanged.");
                    return Ok(false);
                }
                _ => continue,
            }
        }
        match ask("\nThe policy does not pass. (e)dit again or (q)uit without saving [e]: ")?.as_str() {
            "q" | "quit" => {
                println!("Discarded; the installed policy is unchanged.");
                return Ok(false);
            }
            _ => continue,
        }
    }
}

// ----- policy scan ----------------------------------------------------------------

pub struct ScanRequest {
    /// Candidate policy file (default: the installed policy).
    pub policy: Option<PathBuf>,
    /// Also classify with the installed policy and show what changes.
    pub compare: bool,
    pub all: bool,
    pub json: bool,
    pub options: crate::scan::ScanOptions,
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n - 1).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}

/// Dry-run a policy against real mail. Reads the candidate before dropping to the
/// service user, which is needed to reach the mail server.
pub fn policy_scan(service_user: &str, req: ScanRequest) -> Result<bool> {
    let candidate_text = match &req.policy {
        Some(p) => Some(fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?),
        None => None,
    };
    if req.compare && candidate_text.is_none() {
        bail!("--compare needs --policy <FILE> (the candidate to compare with the installed policy)");
    }
    drop_to(service_user)?;
    let installed = Config::load(&Config::default_path())?;
    let candidate = match &candidate_text {
        Some(t) => Config::parse(t).context("candidate policy")?,
        None => Config::load(&Config::default_path())?,
    };
    let baseline = req.compare.then_some(&installed);

    let interactive = std::io::stderr().is_terminal();
    let results = crate::scan::scan(&installed, &candidate, baseline, &req.options, |done, total| {
        if interactive {
            eprint!("\rscanning {done}/{total}");
        }
    })?;
    if interactive {
        eprintln!();
    }
    crate::audit::record(
        &installed,
        req.options.account.as_deref(),
        "policy scan",
        "scanned",
        serde_json::json!({
            "messages": results.len(),
            "mailboxes": req.options.mailboxes,
            "since": req.options.since.map(|d| d.to_string()),
            "until": req.options.until.map(|d| d.to_string()),
            "candidate": req.policy.as_ref().map(|p| p.display().to_string()),
        }),
    );

    let shown: Vec<&crate::scan::Scanned> = results
        .iter()
        .filter(|r| {
            req.all
                || r.error.is_some()
                || if req.compare {
                    r.changed()
                } else {
                    r.candidate.as_ref().is_some_and(|c| c.action.is_some())
                }
        })
        .collect();

    if req.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "scanned": results.len(), "messages": shown }))?
        );
        return Ok(true);
    }

    let multi = req.options.mailboxes.len() > 1;
    let mut rows = Vec::new();
    for r in &shown {
        let mut row = vec![r.date.replace('T', " ").chars().take(16).collect::<String>()];
        if multi {
            row.push(r.mailbox.clone());
        }
        row.extend([r.id.clone(), short(&r.from, 30), short(&r.subject, 50)]);
        let label = |o: &Option<crate::scan::Outcome>| match (o, &r.error) {
            (_, Some(e)) => format!("error: {}", short(e, 40)),
            (Some(o), None) => o.label(),
            (None, None) => String::new(),
        };
        if req.compare {
            row.push(label(&r.baseline));
            row.push(label(&r.candidate));
        } else {
            row.push(label(&r.candidate));
            row.push(r.candidate.as_ref().map(|c| c.listing.to_string()).unwrap_or_default());
        }
        rows.push(row);
    }
    let mut headers = vec!["DATE"];
    if multi {
        headers.push("MAILBOX");
    }
    headers.extend(["ID", "FROM", "SUBJECT"]);
    headers.extend(if req.compare {
        ["INSTALLED", "CANDIDATE"]
    } else {
        ["RESULT", "LISTING"]
    });
    if !rows.is_empty() {
        print!("{}", crate::render::table(&headers, &rows, None));
        println!();
    }

    let count = |a: Option<Action>| {
        results
            .iter()
            .filter(|r| r.candidate.as_ref().is_some_and(|c| c.action == a))
            .count()
    };
    let errors = results.iter().filter(|r| r.error.is_some()).count();
    println!(
        "Scanned {} message(s){}: {} withheld, {} redacted, {} protected, {} allowed{}.",
        results.len(),
        if req.compare { " with the candidate policy" } else { "" },
        count(Some(Action::Withhold)),
        count(Some(Action::Redact)),
        count(Some(Action::Protect)),
        count(None),
        if errors > 0 {
            format!(", {errors} could not be fetched")
        } else {
            String::new()
        }
    );
    if req.compare {
        println!(
            "{} message(s) would be treated differently by the candidate policy.",
            results.iter().filter(|r| r.changed()).count()
        );
    } else if !req.all {
        println!("Showing messages a filter matches; add --all to list every message.");
    }
    Ok(errors == 0)
}
