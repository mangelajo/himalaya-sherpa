//! Policy configuration (`/etc/himalaya-sherpa/sherpa.toml`).
//!
//! The file is owned by root and only readable by the service user, so neither
//! the agent nor the sherpa process itself can change the policy it enforces.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

use crate::classify::Action;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/himalaya-sherpa/sherpa.toml";

/// Example configuration shipped with the crate, also used by `sherpa-admin setup`.
pub const EXAMPLE_CONFIG: &str = include_str!("../etc/sherpa.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawConfig {
    #[serde(default = "default_himalaya")]
    pub himalaya: PathBuf,
    #[serde(default = "default_himalaya_config")]
    pub himalaya_config: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Extra environment variables passed to himalaya (e.g. `PASSWORD_STORE_DIR`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub accounts: AccountsPolicy,
    #[serde(default)]
    pub mailboxes: MailboxPolicy,
    #[serde(default)]
    pub send: SendPolicy,
    #[serde(default)]
    pub read: ReadPolicy,
    #[serde(default)]
    pub search: SearchPolicy,
    #[serde(default)]
    pub redact: RedactPolicy,
    #[serde(default, rename = "filter")]
    pub filters: Vec<FilterRule>,
    /// Sample messages with the outcome the policy must produce (`sherpa-admin policy check`).
    #[serde(default, rename = "example")]
    pub examples: Vec<Example>,
    /// Sample recipients with the send route the policy must choose.
    #[serde(default, rename = "send-example")]
    pub send_examples: Vec<SendExample>,
}

/// Expected outcome of reading an example message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expect {
    /// No filter matches.
    Allow,
    Protect,
    Redact,
    Withhold,
}

impl Expect {
    pub fn action(self) -> Option<Action> {
        match self {
            Expect::Allow => None,
            Expect::Protect => Some(Action::Protect),
            Expect::Redact => Some(Action::Redact),
            Expect::Withhold => Some(Action::Withhold),
        }
    }
}

/// A sample message: either built from `from`/`to`/`subject`/`body`, or given `raw`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Example {
    pub name: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    /// The body is HTML.
    #[serde(default)]
    pub html: bool,
    /// A complete RFC 5322 message, instead of the fields above.
    #[serde(default)]
    pub raw: Option<String>,
    /// How old the message is, to test `release-after-hours`.
    #[serde(default)]
    pub age_hours: Option<u64>,
    pub expect: Expect,
    /// If set, exactly these filters must match.
    #[serde(default)]
    pub expect_filters: Option<Vec<String>>,
    /// Strings the agent must never see for this message, in listings or when reading it.
    #[serde(default)]
    pub secrets: Vec<String>,
}

/// Where an outgoing message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SendRoute {
    /// Sent directly: every recipient matches `auto-send-to`.
    AutoSend,
    Deny,
    Queue,
    Draft,
    Blackhole,
}

impl SendRoute {
    pub fn as_str(self) -> &'static str {
        match self {
            SendRoute::AutoSend => "auto-send",
            SendRoute::Deny => "deny",
            SendRoute::Queue => "queue",
            SendRoute::Draft => "draft",
            SendRoute::Blackhole => "blackhole",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SendExample {
    pub name: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub expect: SendRoute,
}

fn default_himalaya() -> PathBuf {
    "/usr/local/libexec/himalaya-sherpa/himalaya".into()
}
fn default_himalaya_config() -> PathBuf {
    "/etc/himalaya-sherpa/himalaya.toml".into()
}
fn default_state_dir() -> PathBuf {
    "/var/lib/himalaya-sherpa".into()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AccountsPolicy {
    /// Accounts the agent may use. Empty means every account in the himalaya config.
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MailboxPolicy {
    /// Mailboxes (names or aliases, case-insensitive) the agent may read. Empty means all.
    #[serde(default)]
    pub readable: Vec<String>,
    /// Mailboxes the agent may move, copy, or add messages to. Empty means all.
    #[serde(default)]
    pub writable: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SendMode {
    /// Refuse, and say so.
    Deny,
    /// Store in the outbox until a human approves or denies it.
    Queue,
    /// Append to the account's Drafts mailbox so the human sends it from their client.
    Draft,
    /// Pretend it was sent. Logged, never delivered.
    Blackhole,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SendPolicy {
    #[serde(default = "default_send_mode")]
    pub mode: SendMode,
    /// Mailbox (name or alias) used by `draft` mode and `review approve --via draft`.
    #[serde(default = "default_drafts")]
    pub drafts_mailbox: String,
    /// Recipient patterns (regex on the bare address) that are sent without approval.
    /// Every recipient of a message must match for it to go out directly.
    #[serde(default)]
    pub auto_send_to: Vec<String>,
    /// Rolling 24h cap on automatically sent messages.
    #[serde(default = "default_auto_send_max")]
    pub auto_send_max_per_day: usize,
}

fn default_send_mode() -> SendMode {
    SendMode::Queue
}
fn default_drafts() -> String {
    "drafts".into()
}
fn default_auto_send_max() -> usize {
    10
}

impl Default for SendPolicy {
    fn default() -> Self {
        Self {
            mode: default_send_mode(),
            drafts_mailbox: default_drafts(),
            auto_send_to: vec![],
            auto_send_max_per_day: default_auto_send_max(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WithheldStyle {
    /// Tell the agent the message exists but is withheld, and why.
    Notice,
    /// Behave as if the message did not exist.
    NotFound,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReadPolicy {
    #[serde(default = "default_withheld_style")]
    pub withheld: WithheldStyle,
    /// Drop withheld messages from envelope listings instead of masking their subject.
    #[serde(default = "default_true")]
    pub hide_withheld_in_listings: bool,
}

fn default_withheld_style() -> WithheldStyle {
    WithheldStyle::Notice
}
fn default_true() -> bool {
    true
}

impl Default for ReadPolicy {
    fn default() -> Self {
        Self {
            withheld: default_withheld_style(),
            hide_withheld_in_listings: true,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SearchPolicy {
    /// Allow `body <pattern>` search conditions. Off by default: a body search that
    /// matches a withheld message is an oracle for its contents (e.g. digit by digit).
    #[serde(default)]
    pub allow_body: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RedactPolicy {
    /// Regexes whose matches are replaced in redacted messages. Replaces the defaults.
    #[serde(default = "default_redact_patterns")]
    pub patterns: Vec<String>,
    /// Also redact tokens of 6+ chars mixing letters and digits (codes like `A7K2QX`).
    #[serde(default = "default_true")]
    pub mixed_tokens: bool,
    #[serde(default = "default_replacement")]
    pub replacement: String,
}

fn default_redact_patterns() -> Vec<String> {
    vec![
        // Any URL: reset and magic links carry their secret in the URL.
        r"(?i)\b(?:https?|ftp)://\S+".into(),
        r"(?i)\bwww\.\S+".into(),
        // Numeric codes, including the `123 456` / `123-456` styles.
        r"\b\d{3}[ -]\d{3}\b".into(),
        r"\b\d{4,10}\b".into(),
    ]
}
fn default_replacement() -> String {
    "[REDACTED]".into()
}

impl Default for RedactPolicy {
    fn default() -> Self {
        Self {
            patterns: default_redact_patterns(),
            mixed_tokens: true,
            replacement: default_replacement(),
        }
    }
}

/// A single pattern or a list of patterns.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum Patterns {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Patterns {
    fn compile(&self, rule: &str, field: &str) -> Result<Vec<Regex>> {
        let list: Vec<&String> = match self {
            Patterns::None => vec![],
            Patterns::One(p) => vec![p],
            Patterns::Many(ps) => ps.iter().collect(),
        };
        list.into_iter()
            .map(|p| Regex::new(p).with_context(|| format!("filter `{rule}`: invalid `{field}` regex {p:?}")))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FilterRule {
    pub name: String,
    pub action: Action,
    /// Regexes on sender addresses (bare `user@domain`).
    #[serde(default)]
    pub from: Patterns,
    /// Regexes on recipient addresses (To and Cc).
    #[serde(default)]
    pub to: Patterns,
    #[serde(default)]
    pub subject: Patterns,
    /// Regexes on the body (text parts, HTML converted to text, and raw HTML so links in
    /// `href` attributes count), including attached messages.
    #[serde(default)]
    pub body: Patterns,
    /// Regexes on subject or body.
    #[serde(default)]
    pub text: Patterns,
    /// After this many hours (from the message's Date), apply `release-to` instead.
    #[serde(default)]
    pub release_after_hours: Option<u64>,
    #[serde(default = "default_release_to")]
    pub release_to: Action,
}

fn default_release_to() -> Action {
    Action::Redact
}

/// A filter rule with its regexes compiled. Every field that is set must match
/// (AND); within a field, any pattern may match (OR).
#[derive(Debug)]
pub struct Filter {
    pub name: String,
    pub action: Action,
    pub from: Vec<Regex>,
    pub to: Vec<Regex>,
    pub subject: Vec<Regex>,
    pub body: Vec<Regex>,
    pub text: Vec<Regex>,
    pub release_after_hours: Option<u64>,
    pub release_to: Action,
}

/// The validated, compiled configuration.
#[derive(Debug)]
pub struct Config {
    pub raw: RawConfig,
    pub filters: Vec<Filter>,
    pub redact: Vec<Regex>,
    pub auto_send_to: Vec<Regex>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let mut raw: RawConfig = toml::from_str(text).context("invalid sherpa configuration")?;
        let mut filters = Vec::new();
        for rule in std::mem::take(&mut raw.filters) {
            let f = Filter {
                from: rule.from.compile(&rule.name, "from")?,
                to: rule.to.compile(&rule.name, "to")?,
                subject: rule.subject.compile(&rule.name, "subject")?,
                body: rule.body.compile(&rule.name, "body")?,
                text: rule.text.compile(&rule.name, "text")?,
                name: rule.name,
                action: rule.action,
                release_after_hours: rule.release_after_hours,
                release_to: rule.release_to,
            };
            if f.from.is_empty() && f.to.is_empty() && f.subject.is_empty() && f.body.is_empty() && f.text.is_empty() {
                bail!("filter `{}` has no conditions; it would match every message", f.name);
            }
            filters.push(f);
        }
        let redact = raw
            .redact
            .patterns
            .iter()
            .map(|p| Regex::new(p).with_context(|| format!("invalid redact pattern {p:?}")))
            .collect::<Result<_>>()?;
        let auto_send_to = raw
            .send
            .auto_send_to
            .iter()
            .map(|p| Regex::new(p).with_context(|| format!("invalid auto-send-to pattern {p:?}")))
            .collect::<Result<_>>()?;
        Ok(Self {
            raw,
            filters,
            redact,
            auto_send_to,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read sherpa configuration {}", path.display()))?;
        Self::parse(&text)
    }

    /// Path of the configuration to use. `SHERPA_CONFIG` is honoured only when not
    /// running under sudo, so the agent can never point the gate at its own policy.
    pub fn default_path() -> PathBuf {
        match (std::env::var_os("SUDO_USER"), std::env::var_os("SHERPA_CONFIG")) {
            (None, Some(p)) => p.into(),
            _ => DEFAULT_CONFIG_PATH.into(),
        }
    }

    /// Whether every recipient matches an `auto-send-to` pattern.
    pub fn auto_send_matches<S: AsRef<str>>(&self, recipients: &[S]) -> bool {
        !self.auto_send_to.is_empty()
            && !recipients.is_empty()
            && recipients.iter().all(|r| {
                self.auto_send_to
                    .iter()
                    .any(|re| re.is_match(&r.as_ref().to_lowercase()))
            })
    }

    /// The route a message to `recipients` takes, ignoring the daily auto-send cap.
    pub fn send_route<S: AsRef<str>>(&self, recipients: &[S]) -> SendRoute {
        if self.auto_send_matches(recipients) {
            return SendRoute::AutoSend;
        }
        match self.raw.send.mode {
            SendMode::Deny => SendRoute::Deny,
            SendMode::Queue => SendRoute::Queue,
            SendMode::Draft => SendRoute::Draft,
            SendMode::Blackhole => SendRoute::Blackhole,
        }
    }

    pub fn outbox_dir(&self) -> PathBuf {
        self.raw.state_dir.join("outbox")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.raw.state_dir.join("audit.log")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_is_valid() {
        let cfg = Config::parse(EXAMPLE_CONFIG).unwrap();
        assert!(!cfg.filters.is_empty());
        assert_eq!(cfg.raw.send.mode, SendMode::Queue);
    }

    #[test]
    fn rejects_unknown_keys_and_empty_filters() {
        assert!(Config::parse("unknown = 1").is_err());
        let empty = "[[filter]]\nname = \"x\"\naction = \"withhold\"\n";
        assert!(Config::parse(empty).is_err());
        let typo = "[[filter]]\nname = \"x\"\naction = \"withhold\"\nsubjet = \"a\"\n";
        assert!(Config::parse(typo).is_err());
    }
}
