//! Message classification against the configured filters, and redaction.

use mail_parser::{Message, MessageParser};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::config::{Config, Filter};

/// What the gate does with a message that matches a filter. Ordered from least to
/// most restrictive; when several filters match, the most restrictive wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Readable, but the agent cannot flag, move, or delete it.
    Protect,
    /// Readable with codes and links replaced; no raw output, attachments, replies or forwards.
    Redact,
    /// Not readable at all.
    Withhold,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Protect => "protect",
            Action::Redact => "redact",
            Action::Withhold => "withhold",
        }
    }
}

/// The parts of a message the filters look at.
#[derive(Debug, Default)]
pub struct Facts {
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub subject: String,
    /// `None` when only the envelope is known (listings); body conditions then can't match.
    pub body: Option<String>,
    /// Unix timestamp of the Date header.
    pub date: Option<i64>,
}

impl Facts {
    /// Extract facts from a raw RFC 5322 message. `None` if it cannot be parsed.
    pub fn from_raw(raw: &[u8]) -> Option<Self> {
        let msg = MessageParser::default().parse(raw)?;
        let mut facts = Facts::default();
        collect(&msg, &mut facts, 0);
        facts.subject = msg.subject().unwrap_or_default().to_string();
        facts.date = msg.date().map(|d| d.to_timestamp());
        Some(facts)
    }
}

fn addresses(addr: Option<&mail_parser::Address>) -> Vec<String> {
    addr.map(|a| a.iter().filter_map(|a| a.address()).map(|a| a.to_lowercase()).collect())
        .unwrap_or_default()
}

/// Gather addresses and body text, recursing into attached messages (a forwarded
/// OTP mail is still an OTP mail).
fn collect(msg: &Message, facts: &mut Facts, depth: usize) {
    if depth == 0 {
        facts.from = addresses(msg.from());
        facts.to = addresses(msg.to());
        facts.to.extend(addresses(msg.cc()));
    }
    let body = facts.body.get_or_insert_with(String::new);
    if depth > 0 {
        body.push_str(msg.subject().unwrap_or_default());
        body.push('\n');
    }
    for i in 0..msg.text_body_count() {
        if let Some(t) = msg.body_text(i) {
            body.push_str(&t);
            body.push('\n');
        }
    }
    for part in msg.html_bodies() {
        if let Some(html) = part.text_contents() {
            body.push_str(html);
            body.push('\n');
            body.push_str(&mail_parser::decoders::html::html_to_text(html));
            body.push('\n');
        }
    }
    if depth < 3 {
        for part in msg.attachments() {
            if let Some(inner) = part.message() {
                collect(inner, facts, depth + 1);
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    pub action: Option<Action>,
    pub filters: Vec<String>,
}

impl Verdict {
    pub fn is(&self, action: Action) -> bool {
        self.action == Some(action)
    }

    /// Unparseable messages are withheld: the gate fails closed.
    pub fn unparseable() -> Self {
        Self {
            action: Some(Action::Withhold),
            filters: vec!["unparseable".into()],
        }
    }

    pub fn filter_names(&self) -> String {
        self.filters.join(", ")
    }
}

fn any(res: &[Regex], hay: &str) -> bool {
    res.iter().any(|r| r.is_match(hay))
}

fn any_addr(res: &[Regex], addrs: &[String]) -> bool {
    addrs.iter().any(|a| any(res, a))
}

/// Whether `f` matches. Returns `None` when the answer depends on a body that is not
/// known (envelope-only facts).
fn matches(f: &Filter, facts: &Facts) -> Option<bool> {
    if !f.from.is_empty() && !any_addr(&f.from, &facts.from) {
        return Some(false);
    }
    if !f.to.is_empty() && !any_addr(&f.to, &facts.to) {
        return Some(false);
    }
    if !f.subject.is_empty() && !any(&f.subject, &facts.subject) {
        return Some(false);
    }
    if !f.text.is_empty() && !any(&f.text, &facts.subject) {
        match &facts.body {
            Some(b) if any(&f.text, b) => {}
            Some(_) => return Some(false),
            None => return None,
        }
    }
    if !f.body.is_empty() {
        match &facts.body {
            Some(b) if any(&f.body, b) => {}
            Some(_) => return Some(false),
            None => return None,
        }
    }
    Some(true)
}

pub fn classify(cfg: &Config, facts: &Facts, now: i64) -> Verdict {
    let mut verdict = Verdict::default();
    for f in &cfg.filters {
        if matches(f, facts) != Some(true) {
            continue;
        }
        let mut action = f.action;
        if let (Some(hours), Some(date)) = (f.release_after_hours, facts.date)
            && now - date > hours as i64 * 3600
        {
            action = f.release_to;
        }
        verdict.filters.push(f.name.clone());
        verdict.action = verdict.action.max(Some(action));
    }
    verdict
}

/// Classify a raw message, withholding it when it cannot be parsed.
pub fn classify_raw(cfg: &Config, raw: &[u8], now: i64) -> Verdict {
    match Facts::from_raw(raw) {
        Some(facts) => classify(cfg, &facts, now),
        None => Verdict::unparseable(),
    }
}

/// Replace codes, links and other secrets in `text`.
pub fn redact(cfg: &Config, text: &str) -> String {
    let with = cfg.raw.redact.replacement.as_str();
    let mut out = text.to_string();
    for re in &cfg.redact {
        out = re.replace_all(&out, regex::NoExpand(with)).into_owned();
    }
    if cfg.raw.redact.mixed_tokens {
        let token = Regex::new(r"\b[A-Za-z0-9_-]{6,}\b").unwrap();
        out = token
            .replace_all(&out, |c: &regex::Captures| {
                let t = &c[0];
                let digit = t.chars().any(|c| c.is_ascii_digit());
                let alpha = t.chars().any(|c| c.is_ascii_alphabetic());
                if digit && alpha {
                    with.to_string()
                } else {
                    t.to_string()
                }
            })
            .into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EXAMPLE_CONFIG};

    fn cfg() -> Config {
        Config::parse(EXAMPLE_CONFIG).unwrap()
    }

    fn mail(from: &str, subject: &str, body: &str) -> Vec<u8> {
        format!(
            "From: {from}\r\nTo: me@example.com\r\nSubject: {subject}\r\nDate: Wed, 23 Sep 2026 10:00:00 +0000\r\n\r\n{body}\r\n"
        )
        .into_bytes()
    }

    const NOW: i64 = 1_790_157_600; // 2026-09-23T10:00:00Z

    #[test]
    fn otp_is_withheld() {
        let v = classify_raw(
            &cfg(),
            &mail(
                "no-reply@github.com",
                "[GitHub] Please verify your device",
                "Verification code: 482913",
            ),
            NOW,
        );
        assert!(v.is(Action::Withhold), "{v:?}");
        let v = classify_raw(&cfg(), &mail("x@y.es", "Tu código de verificación", "Es 123456"), NOW);
        assert!(v.is(Action::Withhold), "{v:?}");
    }

    #[test]
    fn password_reset_is_withheld_even_in_html_links() {
        let raw = "From: a@shop.example\r\nSubject: Account help\r\nContent-Type: text/html\r\n\r\n<a href=\"https://shop.example/x\">Reset your password</a>\r\n";
        assert!(classify_raw(&cfg(), raw.as_bytes(), NOW).is(Action::Withhold));
    }

    #[test]
    fn forwarded_otp_is_withheld() {
        let inner = String::from_utf8(mail("a@b.c", "Your login code", "123456")).unwrap();
        let raw = format!(
            "From: friend@x.com\r\nSubject: Fwd\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--B--\r\n"
        );
        assert!(classify_raw(&cfg(), raw.as_bytes(), NOW).is(Action::Withhold));
    }

    #[test]
    fn normal_mail_passes_and_garbage_fails_closed() {
        let v = classify_raw(&cfg(), &mail("alice@example.com", "Lunch tomorrow?", "At 1pm?"), NOW);
        assert_eq!(v.action, None);
        assert!(classify_raw(&cfg(), b"", NOW).is(Action::Withhold));
    }

    #[test]
    fn security_alerts_are_protected() {
        let v = classify_raw(
            &cfg(),
            &mail("no-reply@accounts.google.com", "Security alert", "New sign-in on Linux"),
            NOW,
        );
        assert!(v.is(Action::Protect), "{v:?}");
    }

    #[test]
    fn embargo_releases_to_redact() {
        let raw = mail("no-reply@github.com", "Your login code", "482913");
        assert!(classify_raw(&cfg(), &raw, NOW + 3600).is(Action::Withhold));
        assert!(classify_raw(&cfg(), &raw, NOW + 49 * 3600).is(Action::Redact));
    }

    #[test]
    fn listing_ignores_body_only_rules() {
        let facts = Facts {
            subject: "Hello".into(),
            from: vec!["a@b.c".into()],
            ..Default::default()
        };
        assert_eq!(classify(&cfg(), &facts, NOW).action, None);
        let facts = Facts {
            subject: "Your verification code".into(),
            ..Default::default()
        };
        assert!(classify(&cfg(), &facts, NOW).is(Action::Withhold));
    }

    #[test]
    fn redaction() {
        let out = redact(
            &cfg(),
            "Code 482913 or 123 456, link https://x.io/r?t=abc and token A7K2QX9 but not the word Hello",
        );
        assert!(
            !out.contains("482913") && !out.contains("123 456") && !out.contains("x.io") && !out.contains("A7K2QX9"),
            "{out}"
        );
        assert!(out.contains("Hello"));
    }
}
