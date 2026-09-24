//! `sherpa-admin policy check`: validate a policy against its own examples.
//!
//! Each `[[example]]` is run through the same code paths the gate uses: envelope
//! classification for listings, full classification and rendering for reads. The
//! check then compares the outcome with `expect`, and makes sure none of the
//! example's `secrets` would reach the agent.

use std::collections::BTreeSet;

use crate::classify::{self, Action, Facts, Verdict};
use crate::config::{Config, Example, WithheldStyle};
use crate::render;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<(Level, String)>,
}

impl Report {
    fn push(&mut self, level: Level, msg: impl Into<String>) {
        self.lines.push((level, msg.into()));
    }

    pub fn failures(&self) -> usize {
        self.lines.iter().filter(|(l, _)| *l == Level::Fail).count()
    }

    pub fn warnings(&self) -> usize {
        self.lines.iter().filter(|(l, _)| *l == Level::Warn).count()
    }

    pub fn passed(&self) -> bool {
        self.failures() == 0
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (level, msg) in &self.lines {
            let tag = match level {
                Level::Ok => "[ ok ]",
                Level::Warn => "[warn]",
                Level::Fail => "[FAIL]",
            };
            out.push_str(&format!("{tag} {msg}\n"));
        }
        out.push_str(&format!(
            "\n{} failure(s), {} warning(s)\n",
            self.failures(),
            self.warnings()
        ));
        out
    }
}

fn describe(action: Option<Action>) -> &'static str {
    action.map_or("allow", |a| a.as_str())
}

/// Build the raw message for an example.
pub fn example_message(ex: &Example, now: i64) -> Result<Vec<u8>, String> {
    let fields = ex.from.is_some() || ex.to.is_some() || ex.subject.is_some() || ex.body.is_some();
    match (&ex.raw, fields) {
        (Some(_), true) => Err("set either `raw` or from/to/subject/body, not both".into()),
        (Some(raw), false) => {
            // TOML multi-line strings use \n; mail wants \r\n.
            Ok(raw.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes())
        }
        (None, false) => Err("needs `raw` or at least one of from/to/subject/body".into()),
        (None, true) => {
            let date = chrono::DateTime::from_timestamp(now - ex.age_hours.unwrap_or(0) as i64 * 3600, 0)
                .unwrap_or_default()
                .to_rfc2822();
            let ctype = if ex.html { "text/html" } else { "text/plain" };
            Ok(format!(
                "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {date}\r\nMIME-Version: 1.0\r\n\
                 Content-Type: {ctype}; charset=utf-8\r\n\r\n{}\r\n",
                ex.from.as_deref().unwrap_or("sender@example.com"),
                ex.to.as_deref().unwrap_or("me@example.com"),
                ex.subject.as_deref().unwrap_or(""),
                ex.body.as_deref().unwrap_or("").replace('\n', "\r\n"),
            )
            .into_bytes())
        }
    }
}

/// What the gate shows the agent for a message: its listing row and its read output.
pub struct AgentView {
    pub listing: Verdict,
    pub read: Verdict,
    /// Text of the envelope row (empty when hidden).
    pub listing_text: String,
    /// Text returned by `message read` (a notice when withheld).
    pub read_text: String,
}

pub fn agent_view(cfg: &Config, raw: &[u8], now: i64) -> AgentView {
    let read = classify::classify_raw(cfg, raw, now);
    let (listing, listing_text) = match Facts::from_raw(raw) {
        Some(mut facts) => {
            facts.body = None;
            let v = classify::classify(cfg, &facts, now);
            let from = facts.from.join(", ");
            let text = match v.action {
                Some(Action::Withhold) if cfg.raw.read.hide_withheld_in_listings => String::new(),
                Some(Action::Withhold) => format!("{from} [withheld by policy]"),
                Some(Action::Redact) => format!("{from} {}", classify::redact(cfg, &facts.subject)),
                _ => format!("{from} {}", facts.subject),
            };
            (v, text)
        }
        None => (Verdict::unparseable(), String::new()),
    };
    let read_text = match read.action {
        Some(Action::Withhold) => String::new(),
        _ => render::message(cfg, raw, "example", &read, false).unwrap_or_default(),
    };
    AgentView { listing, read, listing_text, read_text }
}

pub fn check(cfg: &Config, now: i64) -> Report {
    let mut r = Report::default();
    let raw = &cfg.raw;
    r.push(
        Level::Ok,
        format!(
            "policy parses: {} filter(s), send mode {:?}, {} auto-send pattern(s), {} example(s), {} send example(s)",
            cfg.filters.len(),
            raw.send.mode,
            raw.send.auto_send_to.len(),
            raw.examples.len(),
            raw.send_examples.len()
        ),
    );

    let mut names = BTreeSet::new();
    let mut triggered: BTreeSet<String> = BTreeSet::new();
    for f in &cfg.filters {
        if !names.insert(f.name.clone()) {
            r.push(Level::Fail, format!("two filters are named `{}`", f.name));
        }
    }

    // Classification examples.
    for ex in &raw.examples {
        let label = format!("example `{}`", ex.name);
        let msg = match example_message(ex, now) {
            Ok(m) => m,
            Err(e) => {
                r.push(Level::Fail, format!("{label}: {e}"));
                continue;
            }
        };
        let view = agent_view(cfg, &msg, now);
        triggered.extend(view.read.filters.iter().cloned());
        let got = view.read.action;
        let mut problems = Vec::new();
        if got != ex.expect.action() {
            problems.push(format!("expected {}, got {}", describe(ex.expect.action()), describe(got)));
        }
        if let Some(expected) = &ex.expect_filters {
            let want: BTreeSet<&String> = expected.iter().collect();
            let have: BTreeSet<&String> = view.read.filters.iter().collect();
            if want != have {
                problems.push(format!("expected filters [{}], got [{}]", join(&want), join(&have)));
            }
            for name in expected {
                if !cfg.filters.iter().any(|f| &f.name == name) {
                    problems.push(format!("no filter named `{name}`"));
                }
            }
        }
        for secret in &ex.secrets {
            if view.listing_text.contains(secret.as_str()) {
                problems.push(format!("secret {secret:?} is visible in envelope listings"));
            }
            if view.read_text.contains(secret.as_str()) {
                problems.push(format!("secret {secret:?} is visible when reading the message"));
            }
        }
        let matched = if view.read.filters.is_empty() { String::new() } else { format!(" ({})", view.read.filter_names()) };
        if problems.is_empty() {
            let mut note = String::new();
            if got == Some(Action::Withhold) && view.listing.action != Some(Action::Withhold) {
                note = "; listed, since only its body matches".into();
            }
            r.push(Level::Ok, format!("{label}: {}{matched}{note}", describe(got)));
        } else {
            r.push(Level::Fail, format!("{label}: {}{matched}", problems.join("; ")));
        }
    }

    // Send examples.
    for ex in &raw.send_examples {
        let recipients: Vec<&String> = ex.to.iter().chain(&ex.cc).chain(&ex.bcc).collect();
        if recipients.is_empty() {
            r.push(Level::Fail, format!("send example `{}`: no recipients", ex.name));
            continue;
        }
        let got = cfg.send_route(&recipients);
        if got == ex.expect {
            r.push(Level::Ok, format!("send example `{}`: {}", ex.name, got.as_str()));
        } else {
            r.push(
                Level::Fail,
                format!("send example `{}`: expected {}, got {}", ex.name, ex.expect.as_str(), got.as_str()),
            );
        }
    }

    // Coverage and risky settings.
    if raw.examples.is_empty() {
        r.push(Level::Warn, "no [[example]] messages: filter changes are untested");
    }
    for f in &cfg.filters {
        if !raw.examples.is_empty() && !triggered.contains(&f.name) {
            r.push(Level::Warn, format!("filter `{}` is not matched by any example", f.name));
        }
    }
    if raw.send_examples.is_empty() {
        r.push(Level::Warn, "no [[send-example]]: the send policy is untested");
    }
    if raw.send.mode == crate::config::SendMode::Blackhole {
        r.push(Level::Warn, "send mode `blackhole` tells the agent messages were sent when they were not");
    }
    if raw.search.allow_body && cfg.filters.iter().any(|f| f.action == Action::Withhold) {
        r.push(Level::Warn, "search.allow-body lets body searches probe the contents of withheld messages");
    }
    if raw.read.withheld == WithheldStyle::NotFound {
        r.push(Level::Ok, "withheld messages are reported as not found");
    }
    r
}

fn join(set: &BTreeSet<&String>) -> String {
    set.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EXAMPLE_CONFIG;

    const NOW: i64 = 1_790_157_600;

    /// The shipped policy must pass its own examples.
    #[test]
    fn shipped_policy_passes_its_examples() {
        let cfg = Config::parse(EXAMPLE_CONFIG).unwrap();
        let report = check(&cfg, NOW);
        assert!(report.passed(), "{}", report.render());
        assert!(cfg.raw.examples.len() >= 10);
    }

    fn with(extra: &str) -> Report {
        let cfg = Config::parse(&format!("{EXAMPLE_CONFIG}\n{extra}")).unwrap();
        check(&cfg, NOW)
    }

    #[test]
    fn wrong_expectation_fails() {
        let r = with("[[example]]\nname = \"x\"\nsubject = \"Your login code\"\nbody = \"123456\"\nexpect = \"allow\"\n");
        assert_eq!(r.failures(), 1, "{}", r.render());
        assert!(r.render().contains("expected allow, got withhold"));
    }

    #[test]
    fn leaked_secret_fails() {
        // Not matched by any filter, so the code is readable.
        let r = with("[[example]]\nname = \"x\"\nsubject = \"Hi\"\nbody = \"use 4455\"\nexpect = \"allow\"\nsecrets = [\"4455\"]\n");
        assert!(r.render().contains("visible when reading"), "{}", r.render());
    }

    #[test]
    fn send_examples_follow_mode_and_auto_send() {
        let cfg = Config::parse(&EXAMPLE_CONFIG.replace("auto-send-to = []", "auto-send-to = ['^me@example\\.com$']")).unwrap();
        assert_eq!(cfg.send_route(&["me@example.com"]), crate::config::SendRoute::AutoSend);
        assert_eq!(cfg.send_route(&["me@example.com", "x@y.z"]), crate::config::SendRoute::Queue);
        let r = with("[[send-example]]\nname = \"x\"\nto = [\"a@b.c\"]\nexpect = \"draft\"\n");
        assert!(r.render().contains("expected draft, got queue"), "{}", r.render());
    }

    #[test]
    fn example_needs_exactly_one_source() {
        let r = with("[[example]]\nname = \"x\"\nexpect = \"allow\"\n");
        assert!(r.render().contains("needs `raw`"));
        let r = with("[[example]]\nname = \"y\"\nsubject = \"a\"\nraw = \"b\"\nexpect = \"allow\"\n");
        assert!(r.render().contains("not both"));
    }
}
