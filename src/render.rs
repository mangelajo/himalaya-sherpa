//! Plain-text and JSON rendering of the data the gate returns to the agent.

use mail_parser::{MessageParser, MimeHeaders};
use serde_json::{Value, json};

use crate::classify::{self, Verdict};
use crate::config::Config;

/// A simple aligned table. `max_width` truncates the widest column.
pub fn table(headers: &[&str], rows: &[Vec<String>], max_width: Option<usize>) -> String {
    let n = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(n) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    if let Some(max) = max_width {
        let sep = 3 * (n.saturating_sub(1));
        while widths.iter().sum::<usize>() + sep > max {
            let (i, w) = widths.iter().enumerate().max_by_key(|(_, w)| **w).map(|(i, w)| (i, *w)).unwrap();
            if w <= 4 {
                break;
            }
            widths[i] = w - 1;
        }
    }
    let fmt_row = |cells: Vec<String>| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let w = widths[i];
                let mut c: String = if c.chars().count() > w {
                    c.chars().take(w.saturating_sub(1)).collect::<String>() + "…"
                } else {
                    c.clone()
                };
                if i + 1 < n {
                    let pad = w - c.chars().count();
                    c.push_str(&" ".repeat(pad));
                }
                c
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let mut out = fmt_row(headers.iter().map(|h| h.to_string()).collect());
    out.push('\n');
    out.push_str(&widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("-+-"));
    out.push('\n');
    for row in rows {
        out.push_str(&fmt_row(row.clone()));
        out.push('\n');
    }
    out
}

fn addrs(v: &Value) -> String {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| match (x["name"].as_str(), x["email"].as_str()) {
                    (Some(n), Some(e)) => format!("{n} <{e}>"),
                    (None, Some(e)) => e.to_string(),
                    (Some(n), None) => n.to_string(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn flags(v: &Value) -> String {
    // himalaya reports flags as `{"raw": "\\Seen", "iana": "seen"}` (older versions: plain strings).
    let f: Vec<&str> = v
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().or_else(|| x["iana"].as_str())).collect())
        .unwrap_or_default();
    let mut s = String::new();
    if !f.contains(&"seen") {
        s.push('*');
    }
    if f.contains(&"answered") {
        s.push('R');
    }
    if f.contains(&"flagged") {
        s.push('!');
    }
    if f.contains(&"draft") {
        s.push('D');
    }
    s
}

fn date(v: &Value) -> String {
    v.as_str()
        .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        .map(|d| d.format("%Y-%m-%d %H:%M%:z").to_string())
        .unwrap_or_else(|| v.as_str().unwrap_or_default().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_accept_objects_and_strings() {
        assert_eq!(flags(&json!([{ "raw": "\\Seen", "iana": "seen" }])), "");
        assert_eq!(flags(&json!(["flagged"])), "*!");
        assert_eq!(flags(&json!([])), "*");
    }
}

/// Render himalaya's JSON envelope list as a table.
pub fn envelopes(envs: &[Value], recipient: bool, max_width: Option<usize>) -> String {
    let who = if recipient { "TO" } else { "FROM" };
    let rows: Vec<Vec<String>> = envs
        .iter()
        .map(|e| {
            vec![
                e["id"].as_str().map(String::from).unwrap_or_else(|| e["id"].to_string()),
                flags(&e["flags"]),
                e["subject"].as_str().unwrap_or_default().to_string(),
                addrs(if recipient { &e["to"] } else { &e["from"] }),
                date(&e["date"]),
            ]
        })
        .collect();
    table(&["ID", "FLAGS", "SUBJECT", who, "DATE"], &rows, max_width)
}

fn addr_json(a: Option<&mail_parser::Address>) -> Value {
    Value::Array(
        a.map(|a| {
            a.iter()
                .map(|x| json!({ "name": x.name(), "email": x.address() }))
                .collect()
        })
        .unwrap_or_default(),
    )
}

fn addr_text(a: Option<&mail_parser::Address>) -> String {
    addrs(&addr_json(a))
}

/// Render a message for the agent, redacting it when the verdict says so.
/// Returns `None` if the message cannot be parsed.
pub fn message(cfg: &Config, raw: &[u8], id: &str, verdict: &Verdict, as_json: bool) -> Option<String> {
    let msg = MessageParser::default().parse(raw)?;
    let redacting = verdict.is(classify::Action::Redact);
    let clean = |s: &str| if redacting { classify::redact(cfg, s) } else { s.to_string() };

    let subject = clean(msg.subject().unwrap_or_default());
    let mut text = String::new();
    for i in 0..msg.text_body_count() {
        if let Some(t) = msg.body_text(i) {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&t);
        }
    }
    let text = clean(&text);
    let attachments: Vec<Value> = msg
        .attachments()
        .map(|p| {
            let ct = p
                .content_type()
                .map(|c| match c.subtype() {
                    Some(s) => format!("{}/{}", c.ctype(), s),
                    None => c.ctype().to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".into());
            json!({ "name": p.attachment_name(), "content-type": ct, "size": p.len() })
        })
        .collect();

    if as_json {
        let out = json!({
            "id": id,
            "date": msg.date().map(|d| d.to_rfc3339()),
            "from": addr_json(msg.from()),
            "to": addr_json(msg.to()),
            "cc": addr_json(msg.cc()),
            "subject": subject,
            "text": text,
            "attachments": attachments,
            "policy": { "action": verdict.action.map(|a| a.as_str()), "filters": verdict.filters },
        });
        return Some(out.to_string());
    }

    let mut out = String::new();
    if let Some(d) = msg.date() {
        out.push_str(&format!("Date: {}\n", d.to_rfc822()));
    }
    out.push_str(&format!("From: {}\n", addr_text(msg.from())));
    out.push_str(&format!("To: {}\n", addr_text(msg.to())));
    if msg.cc().is_some() {
        out.push_str(&format!("Cc: {}\n", addr_text(msg.cc())));
    }
    out.push_str(&format!("Subject: {subject}\n"));
    if redacting {
        out.push_str(&format!(
            "X-Sherpa-Policy: redacted by filter(s) {}; codes and links are masked\n",
            verdict.filter_names()
        ));
    }
    out.push('\n');
    out.push_str(text.trim_end());
    out.push('\n');
    if !attachments.is_empty() {
        out.push_str(&format!("\nAttachments ({}), see `attachment list {id}`:\n", attachments.len()));
        for a in &attachments {
            out.push_str(&format!(
                "  - {} ({}, {} B)\n",
                a["name"].as_str().unwrap_or("(unnamed)"),
                a["content-type"].as_str().unwrap_or_default(),
                a["size"]
            ));
        }
    }
    Some(out)
}
