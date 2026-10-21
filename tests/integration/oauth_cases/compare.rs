//! Literal wire-message parsing and anchored wildcard comparison.

use anyhow::{Context as _, ensure};
use reqwest::header::HeaderName;
use url::form_urlencoded;

pub(super) const RULES: &[&str] = &[
    "status-code",
    "status-reason",
    "header-name",
    "header-value",
    "body",
    "reason-case",
    "duplicate-header",
];

#[derive(Debug)]
pub(super) struct Message {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl Message {
    pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
        let (head, body) = raw
            .split_once("\n\n")
            .map_or((raw, None), |(head, body)| (head, Some(body.to_owned())));
        let mut lines = head.lines();
        let line = lines.next().context("missing HTTP first line")?.to_owned();
        ensure!(!line.is_empty(), "empty HTTP first line");
        let headers = lines
            .map(|header_line| {
                let (name, value) = header_line
                    .split_once(':')
                    .context("header requires Name: value")?;
                let _name = HeaderName::from_bytes(name.as_bytes())
                    .with_context(|| format!("invalid header line {header_line:?}"))?;
                Ok((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            line,
            headers,
            body,
        })
    }

    pub(super) fn request_target(&self) -> anyhow::Result<(&str, &str)> {
        let parts: Vec<_> = self.line.split_whitespace().collect();
        let [method, path, "HTTP/1.1"] = parts.as_slice() else {
            anyhow::bail!("invalid request line");
        };
        ensure!(path.starts_with('/'), "request target must be relative");
        Ok((method, path))
    }

    pub(super) fn status(&self) -> anyhow::Result<u16> {
        let mut parts = self.line.splitn(3, ' ');
        ensure!(
            parts.next() == Some("HTTP/1.1"),
            "invalid response protocol"
        );
        let status = parts.next().context("missing response status")?.parse()?;
        ensure!(
            parts.next().is_some_and(|reason| !reason.is_empty()),
            "missing status reason"
        );
        Ok(status)
    }

    pub(super) fn compare_response(&self, actual: &Self) -> anyhow::Result<()> {
        ensure!(
            self.status()? == actual.status()? && self.line == actual.line,
            "{} / {} mismatch: expected {}, received {}",
            RULES.first().context("status code rule")?,
            RULES.get(1).context("status reason rule")?,
            self.line,
            actual.line
        );
        compare_headers(&self.headers, &actual.headers)?;
        if let Some(body) = &self.body {
            ensure!(
                matches_value(body, actual.body.as_deref().unwrap_or_default()),
                "body mismatch"
            );
        }
        Ok(())
    }
}

pub(super) fn compare_headers(
    expected: &[(String, String)],
    actual: &[(String, String)],
) -> anyhow::Result<()> {
    for (name, value) in expected {
        let candidates: Vec<_> = actual
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .collect();
        ensure!(!candidates.is_empty(), "header {name} missing");
        ensure!(
            candidates
                .iter()
                .any(|(_, candidate)| matches_value(value, candidate)),
            "header {name} value mismatch"
        );
    }
    Ok(())
}

pub(super) fn matches_value(pattern: &str, actual: &str) -> bool {
    let mut parts = pattern.split("<any>");
    let first = parts.next().unwrap_or_default();
    let Some(mut remaining) = actual.strip_prefix(first) else {
        return false;
    };
    let mut tail = parts.peekable();
    if tail.peek().is_none() {
        return remaining.is_empty();
    }
    while let Some(part) = tail.next() {
        if tail.peek().is_none() {
            return remaining.ends_with(part);
        }
        let Some(position) = remaining.find(part) else {
            return false;
        };
        let Some(rest) = remaining.get(position.saturating_add(part.len())..) else {
            return false;
        };
        remaining = rest;
    }
    false
}

pub(super) fn compare_upstream(expected: &str, actual: &wiremock::Request) -> anyhow::Result<()> {
    let (head, form) = expected.split_once("\n\n").unwrap_or((expected, ""));
    let mut lines = head.lines();
    let target = lines.next().context("missing upstream target")?;
    let (method, path) = target
        .split_once(' ')
        .context("upstream requires METHOD /path")?;
    ensure!(
        actual.method.as_str() == method && actual.url.path() == path,
        "upstream method/path mismatch"
    );
    let message = Message::parse(&format!(
        "{target}\n{}",
        lines.collect::<Vec<_>>().join("\n")
    ))?;
    let headers = actual
        .headers
        .iter()
        .map(|(name, value)| Ok((name.to_string(), value.to_str()?.to_owned())))
        .collect::<anyhow::Result<Vec<_>>>()?;
    compare_headers(&message.headers, &headers)?;
    let fields: Vec<_> = form_urlencoded::parse(&actual.body).collect();
    for line in form.lines() {
        let (name, value) = line
            .split_once('=')
            .context("upstream form requires name=value")?;
        ensure!(
            fields
                .iter()
                .any(|(key, candidate)| key == name && matches_value(value, candidate)),
            "upstream form field {name} mismatch"
        );
    }
    Ok(())
}
