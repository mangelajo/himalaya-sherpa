//! `sherpa-admin policy scan`: dry-run a policy against real mail, to see which
//! messages it would withhold, redact or protect, optionally compared with the
//! installed policy.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::Serialize;
use serde_json::Value;

use crate::classify::Action;
use crate::config::Config;
use crate::himalaya::Himalaya;
use crate::policy::agent_view;

pub struct ScanOptions {
    pub account: Option<String>,
    /// Mailboxes to scan (names or aliases). Empty: the inbox.
    pub mailboxes: Vec<String>,
    /// First day to include.
    pub since: Option<NaiveDate>,
    /// Last day to include.
    pub until: Option<NaiveDate>,
    /// Maximum number of messages per mailbox, most recent first.
    pub limit: usize,
    /// Messages fetched in parallel.
    pub jobs: usize,
}

/// How a policy treats one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub action: Option<Action>,
    pub filters: Vec<String>,
    /// How the message appears in envelope listings: hidden, masked, redacted or shown.
    pub listing: &'static str,
}

impl Outcome {
    pub fn label(&self) -> String {
        match self.action {
            Some(a) => format!("{} ({})", a.as_str(), self.filters.join(", ")),
            None => "allow".into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Scanned {
    pub mailbox: String,
    pub id: String,
    pub date: String,
    pub from: String,
    pub subject: String,
    pub candidate: Option<Outcome>,
    /// The installed policy's outcome, when comparing.
    pub baseline: Option<Outcome>,
    pub error: Option<String>,
}

impl Scanned {
    pub fn changed(&self) -> bool {
        match (&self.candidate, &self.baseline) {
            (Some(c), Some(b)) => c.action != b.action || c.listing != b.listing,
            _ => false,
        }
    }
}

/// The search query selecting a date range. `after D` is strictly after day D and
/// `not after D` is on or before D (himalaya has no `before`).
pub fn date_query(since: Option<NaiveDate>, until: Option<NaiveDate>) -> Vec<String> {
    let mut q: Vec<String> = Vec::new();
    if let Some(d) = since {
        let day_before = d.pred_opt().unwrap_or(d);
        q.extend(["after".into(), day_before.format("%Y-%m-%d").to_string()]);
    }
    if let Some(d) = until {
        if !q.is_empty() {
            q.push("and".into());
        }
        q.extend(["not".into(), "after".into(), d.format("%Y-%m-%d").to_string()]);
    }
    q
}

fn envelopes(him: &Himalaya, mailbox: &str, query: &[String], limit: usize) -> Result<Vec<Value>> {
    let page_size = limit.clamp(1, 100);
    let mut out: Vec<Value> = Vec::new();
    for page in 1.. {
        let mut args: Vec<String> = vec![
            "envelope".into(),
            if query.is_empty() { "list" } else { "search" }.into(),
            "-m".into(),
            mailbox.into(),
            "-s".into(),
            page_size.to_string(),
            "-p".into(),
            page.to_string(),
        ];
        if !query.is_empty() {
            args.push("--".into());
            args.extend(query.iter().cloned());
        }
        let raw = him.run_ok(true, &args, None)?;
        let v: Value = serde_json::from_slice(&raw).context("unexpected envelope output")?;
        let batch = v["envelopes"].as_array().cloned().unwrap_or_default();
        let n = batch.len();
        out.extend(batch);
        if n < page_size || out.len() >= limit {
            break;
        }
    }
    out.truncate(limit);
    Ok(out)
}

fn outcome(cfg: &Config, raw: &[u8], now: i64) -> Outcome {
    let view = agent_view(cfg, raw, now);
    let listing = if view.listing_text.is_empty() {
        "hidden"
    } else {
        match view.listing.action {
            Some(Action::Withhold) => "masked",
            Some(Action::Redact) => "redacted",
            _ => "shown",
        }
    };
    Outcome {
        action: view.read.action,
        filters: view.read.filters,
        listing,
    }
}

/// Classify the selected messages with `candidate` (and `baseline`, if given).
/// `access` supplies the himalaya binary and configuration.
pub fn scan(
    access: &Config,
    candidate: &Config,
    baseline: Option<&Config>,
    opts: &ScanOptions,
    progress: impl Fn(usize, usize) + Sync,
) -> Result<Vec<Scanned>> {
    let him = Himalaya {
        cfg: access,
        account: opts.account.clone(),
    };
    let query = date_query(opts.since, opts.until);
    let mailboxes = if opts.mailboxes.is_empty() {
        vec!["inbox".to_string()]
    } else {
        opts.mailboxes.clone()
    };
    let mut todo: Vec<(String, Value)> = Vec::new();
    for mb in &mailboxes {
        for env in envelopes(&him, mb, &query, opts.limit)? {
            todo.push((mb.clone(), env));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Scanned>>> = Mutex::new((0..todo.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..opts.jobs.max(1) {
            s.spawn(|| {
                let him = Himalaya {
                    cfg: access,
                    account: opts.account.clone(),
                };
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some((mb, env)) = todo.get(i) else { break };
                    let id = env["id"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_else(|| env["id"].to_string());
                    let from = env["from"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x["email"].as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    let mut item = Scanned {
                        mailbox: mb.clone(),
                        id: id.clone(),
                        date: env["date"].as_str().unwrap_or_default().to_string(),
                        from,
                        subject: env["subject"].as_str().unwrap_or_default().to_string(),
                        candidate: None,
                        baseline: None,
                        error: None,
                    };
                    match him.raw_message(Some(mb), &id) {
                        Ok(raw) => {
                            item.candidate = Some(outcome(candidate, &raw, now));
                            item.baseline = baseline.map(|b| outcome(b, &raw, now));
                        }
                        Err(e) => item.error = Some(format!("{e:#}")),
                    }
                    results.lock().unwrap()[i] = Some(item);
                    progress(done.fetch_add(1, Ordering::SeqCst) + 1, todo.len());
                }
            });
        }
    });
    Ok(results.into_inner().unwrap().into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_ranges_are_inclusive() {
        let d = |s| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        assert_eq!(date_query(Some(d("2026-09-01")), None), ["after", "2026-08-31"]);
        assert_eq!(date_query(None, Some(d("2026-09-24"))), ["not", "after", "2026-09-24"]);
        assert_eq!(
            date_query(Some(d("2026-09-01")), Some(d("2026-09-24"))),
            ["after", "2026-08-31", "and", "not", "after", "2026-09-24"]
        );
        assert!(date_query(None, None).is_empty());
    }
}
