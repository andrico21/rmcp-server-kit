//! Pins `file:line` citations referenced from `docs/ARCHITECTURE.md`.
//!
//! When code moves, this test fails first so docs stay accurate.
//!
//! It scans `docs/ARCHITECTURE.md` for tokens of the form
//!   `src/<file>.rs:<line>`            (single line)
//!   `src/<file>.rs:<line>-<line>`     (range)
//! and asserts that the cited file exists and has at least the cited
//! line count. There is no semantic matching; the goal is to fail
//! fast when line numbers drift, not to lock the doc to specific
//! source content. Drift fixes are easy: re-read the cited code and
//! update the number.

#![allow(
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    clippy::print_stderr
)]

use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Debug, Clone)]
struct Citation {
    file: String,    // e.g. "src/transport.rs"
    start: usize,    // 1-based
    end: usize,      // 1-based; equals `start` for single-line
    doc_line: usize, // line in ARCHITECTURE.md where the citation appears
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Parse a single token of the form `src/foo.rs:NNN` or `src/foo.rs:NNN-MMM`
/// starting at the beginning of `tail`. Returns the parsed citation and the
/// number of bytes consumed, or `None` if `tail` does not start with a valid
/// citation.
fn parse_citation_at(tail: &str, doc_line: usize) -> Option<(Citation, usize)> {
    let rest = tail.strip_prefix("src/")?;

    // Filename: ASCII alphanumeric or '_'.
    let name_len = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if name_len == 0 {
        return None;
    }
    let name = rest.get(..name_len)?;
    let after_name = rest.get(name_len..)?;

    let after_ext = after_name.strip_prefix(".rs:")?;

    // Start line digits.
    let start_digits_len = after_ext.bytes().take_while(u8::is_ascii_digit).count();
    if start_digits_len == 0 {
        return None;
    }
    let start_digits = after_ext.get(..start_digits_len)?;
    let start: usize = start_digits.parse().ok()?;
    let after_start = after_ext.get(start_digits_len..)?;

    // Optional range.
    let (end, range_consumed) = if let Some(after_dash) = after_start.strip_prefix('-') {
        let end_digits_len = after_dash.bytes().take_while(u8::is_ascii_digit).count();
        if end_digits_len == 0 {
            (start, 0)
        } else if let Some(end_digits) = after_dash.get(..end_digits_len)
            && let Ok(parsed) = end_digits.parse::<usize>()
        {
            (parsed, 1 + end_digits_len)
        } else {
            (start, 0)
        }
    } else {
        (start, 0)
    };

    let consumed = "src/".len() + name_len + ".rs:".len() + start_digits_len + range_consumed;
    Some((
        Citation {
            file: format!("src/{name}.rs"),
            start,
            end,
            doc_line,
        },
        consumed,
    ))
}

fn parse_citations(doc: &str) -> Vec<Citation> {
    let mut out = Vec::new();
    for (doc_idx, line) in doc.lines().enumerate() {
        let doc_line_no = doc_idx + 1;
        let mut tail = line;
        while let Some(rel) = tail.find("src/") {
            // Advance to the candidate.
            let candidate = tail.get(rel..).unwrap_or("");
            if let Some((cite, consumed)) = parse_citation_at(candidate, doc_line_no) {
                out.push(cite);
                tail = candidate.get(consumed..).unwrap_or("");
            } else {
                // Skip past this "src/" occurrence to avoid an infinite loop.
                tail = candidate.get(1..).unwrap_or("");
            }
        }
    }
    out
}

fn count_lines(path: &PathBuf) -> Option<usize> {
    let text = fs::read_to_string(path).ok()?;
    Some(text.lines().count())
}

fn fmt_range(c: &Citation) -> String {
    if c.end == c.start {
        format!("{}", c.start)
    } else {
        format!("{}-{}", c.start, c.end)
    }
}

#[test]
fn architecture_citations_resolve() {
    let root = workspace_root();
    let arch_path = root.join("docs").join("ARCHITECTURE.md");
    let doc = fs::read_to_string(&arch_path).expect("read docs/ARCHITECTURE.md");

    let citations = parse_citations(&doc);
    assert!(
        !citations.is_empty(),
        "no src/*.rs:NNN citations parsed from docs/ARCHITECTURE.md - parser is likely broken"
    );

    let mut line_counts: BTreeMap<String, Option<usize>> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for c in &citations {
        let count = line_counts
            .entry(c.file.clone())
            .or_insert_with(|| count_lines(&root.join(&c.file)));

        let Some(n) = *count else {
            failures.push(format!(
                "ARCHITECTURE.md:{} cites {}:{} but the file does not exist",
                c.doc_line,
                c.file,
                fmt_range(c)
            ));
            continue;
        };

        if c.end > n {
            failures.push(format!(
                "ARCHITECTURE.md:{} cites {}:{} but file only has {n} lines",
                c.doc_line,
                c.file,
                fmt_range(c)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} stale citation(s) in docs/ARCHITECTURE.md (out of {} total):\n{}",
        failures.len(),
        citations.len(),
        failures.join("\n")
    );
}
