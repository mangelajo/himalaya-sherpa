//! Messages the agent tried to send, with their status. Stored as `<id>.eml` plus
//! `<id>.json` in the state directory, readable only by the service user.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Waiting for a human decision.
    Pending,
    /// Appended to the Drafts mailbox for the human to send.
    Drafted,
    Sent,
    Denied,
    /// The agent was told it was sent; it was not.
    Blackholed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Drafted => "drafted",
            Status::Sent => "sent",
            Status::Denied => "denied",
            Status::Blackholed => "blackholed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Entry {
    pub id: String,
    pub created: String,
    pub created_ts: i64,
    pub caller: String,
    pub account: Option<String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub status: Status,
    /// Sent directly because every recipient matched `auto-send-to`.
    #[serde(default)]
    pub auto: bool,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn new_id() -> String {
    let mut buf = [0u8; 2];
    let rand = fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_ok();
    let suffix = if rand {
        u16::from_be_bytes(buf)
    } else {
        (std::process::id() as u16) ^ (chrono::Utc::now().timestamp_subsec_nanos() as u16)
    };
    format!("{}-{suffix:04x}", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
}

pub fn valid_id(id: &str) -> bool {
    let re = regex::Regex::new(r"^\d{8}-\d{6}-[0-9a-f]{4}$").unwrap();
    re.is_match(id)
}

pub struct Outbox {
    dir: PathBuf,
}

impl Outbox {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn ensure_dir(&self) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))
    }

    fn path(&self, id: &str, ext: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            bail!("invalid outbox id {id:?}");
        }
        Ok(self.dir.join(format!("{id}.{ext}")))
    }

    pub fn raw_path(&self, id: &str) -> Result<PathBuf> {
        self.path(id, "eml")
    }

    pub fn create(&self, entry: &Entry, raw: &[u8]) -> Result<()> {
        self.ensure_dir()?;
        write_private(&self.path(&entry.id, "eml")?, raw, true)?;
        self.save(entry)
    }

    pub fn save(&self, entry: &Entry) -> Result<()> {
        self.ensure_dir()?;
        let json = serde_json::to_vec_pretty(entry)?;
        let path = self.path(&entry.id, "json")?;
        let tmp = path.with_extension("json.tmp");
        write_private(&tmp, &json, false)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Entry> {
        let path = self.path(id, "json")?;
        let text = fs::read(&path).with_context(|| format!("no outbox message {id}"))?;
        Ok(serde_json::from_slice(&text)?)
    }

    pub fn raw(&self, id: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.raw_path(id)?)?)
    }

    /// All entries, oldest first.
    pub fn list(&self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        let dir = match fs::read_dir(&self.dir) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", self.dir.display())),
        };
        for item in dir {
            let path = item?.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Ok(entry) = serde_json::from_slice::<Entry>(&fs::read(&path)?) {
                    entries.push(entry);
                }
            }
        }
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }
}

fn write_private(path: &Path, data: &[u8], create_new: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(0o600);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut f = opts.open(path).with_context(|| format!("cannot write {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}
