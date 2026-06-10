//! Pins `file:line` citations referenced from the agent-facing docs
//! (`docs/ARCHITECTURE.md`, `AGENTS.md`, `docs/MINDMAP.md`).
//!
//! When code moves, this test fails first so docs stay accurate.
//!
//! Two layers of validation:
//!
//! 1. **Existence / length** (all citations): the cited file exists and
//!    has at least the cited line count.
//! 2. **Symbol anchoring** (citations with a recognizable symbol on the
//!    same doc line): at least one anchor symbol — a backticked token
//!    like `` `TlsListener` `` or a parenthesized identifier like
//!    `(build_app_router)` — must appear within `TOLERANCE` lines of the
//!    cited location in the cited file. This catches silent drift that
//!    the length check cannot (a file that only ever grows keeps every
//!    stale citation "valid" forever).
//!
//! Recognized citation forms (all require the `src/<file>.rs` path on
//! the same doc line):
//!   `src/<file>.rs:<line>`            (single line)
//!   `src/<file>.rs:<line>-<line>`     (range)
//!   `src/<file>.rs` ... `(~line <line>)`   (AGENTS.md table style)
//!   `src/<file>.rs` ... `~L<line>`         (MINDMAP.md table style)
//!
//! Out of scope: mindmap nodes whose file is implied by a parent node
//! (no path on the line), and prose without a `src/*.rs` mention.
//!
//! Drift fixes are easy: re-read the cited code and update the number.

#![allow(
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    clippy::panic,
    clippy::print_stderr
)]

use std::{collections::BTreeMap, fs, path::PathBuf};

/// How far (in lines, each direction) an anchor symbol may sit from the
/// cited line/range. The doc headers promise "approximate" citations;
/// this is the enforced meaning of approximate.
const TOLERANCE: usize = 30;

/// Anchor candidates shorter than this are ignored (too noisy).
const MIN_ANCHOR_LEN: usize = 3;

/// Identifier-like tokens that are too generic to anchor anything.
const ANCHOR_STOPLIST: &[&str] = &[
    "src", "the", "and", "for", "rs", "line", "str", "Vec", "Arc", "Some", "None", "Option",
    "String", "true", "false", "usize", "bool",
];

#[derive(Debug, Clone)]
struct Citation {
    /// e.g. "src/transport.rs"
    file: String,
    /// 1-based first cited line.
    start: usize,
    /// 1-based last cited line; equals `start` for single-line.
    end: usize,
    /// Line in the doc where the citation appears.
    doc_line: usize,
    /// Symbol candidates extracted from the same doc line. Empty means
    /// "length-check only".
    anchors: Vec<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Leading `[A-Za-z_][A-Za-z0-9_]*` run after skipping any non-identifier
/// prefix characters (`&`, `[`, `*`, spaces, ...).
fn leading_identifier(s: &str) -> Option<&str> {
    let trimmed = s.trim_start_matches(|c: char| !(c.is_ascii_alphabetic() || c == '_'));
    let len = trimmed
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if len == 0 { None } else { trimmed.get(..len) }
}

fn keep_anchor(candidate: &str, file: &str) -> bool {
    if candidate.len() < MIN_ANCHOR_LEN {
        return false;
    }
    if ANCHOR_STOPLIST.contains(&candidate) {
        return false;
    }
    // The file stem ("transport" for src/transport.rs) appears in every
    // module path and anchors nothing.
    let stem = file
        .rsplit('/')
        .next()
        .and_then(|n| n.strip_suffix(".rs"))
        .unwrap_or("");
    candidate != stem
}

/// Extract anchor candidates from a doc line: the leading identifier of
/// every backticked segment (plus, for `path::to::item` forms, the final
/// segment), and every `(identifier)` group.
fn extract_anchors(line: &str, file: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |candidate: &str| {
        if keep_anchor(candidate, file) && !out.iter().any(|a| a == candidate) {
            out.push(candidate.to_owned());
        }
    };

    // Backticked segments: odd-indexed pieces of a split on '`'.
    for (idx, segment) in line.split('`').enumerate() {
        if idx % 2 != 1 {
            continue;
        }
        if let Some(ident) = leading_identifier(segment) {
            push(ident);
        }
        // `transport::healthz` / `RbacPolicy::check(...)`: the segment
        // after the last `::` (up to any argument list) is usually the
        // most specific anchor.
        let head = segment.split('(').next().unwrap_or(segment);
        if let Some(last) = head.rsplit("::").next()
            && last != head
            && let Some(ident) = leading_identifier(last)
        {
            push(ident);
        }
    }

    // Parenthesized single identifiers: "(build_app_router)".
    let mut tail = line;
    while let Some(open) = tail.find('(') {
        let inner = tail.get(open + 1..).unwrap_or("");
        let len = inner
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if len > 0
            && inner.get(len..).is_some_and(|rest| rest.starts_with(')'))
            && let Some(ident) = inner.get(..len)
        {
            push(ident);
        }
        tail = inner;
    }

    out
}

/// Parse a single token of the form `src/foo.rs:NNN` or `src/foo.rs:NNN-MMM`
/// starting at the beginning of `tail`. Returns the citation (without
/// anchors) and the number of bytes consumed, or `None` if `tail` does not
/// start with a valid citation. A bare `src/foo.rs` without `:NNN` returns
/// the file name with `start == 0` so callers can pair it with `~line`
/// style locators found elsewhere on the same line.
fn parse_path_at(tail: &str) -> Option<(String, usize, usize, usize)> {
    let rest = tail.strip_prefix("src/")?;

    let name_len = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if name_len == 0 {
        return None;
    }
    let name = rest.get(..name_len)?;
    let after_name = rest.get(name_len..)?;

    let file = format!("src/{name}.rs");
    let base_consumed = "src/".len() + name_len + ".rs".len();

    let Some(after_ext) = after_name.strip_prefix(".rs:") else {
        // Bare path (no :NNN) — still a valid file mention.
        if after_name.starts_with(".rs") {
            return Some((file, 0, 0, base_consumed));
        }
        return None;
    };

    let start_digits_len = after_ext.bytes().take_while(u8::is_ascii_digit).count();
    if start_digits_len == 0 {
        return Some((file, 0, 0, base_consumed));
    }
    let start: usize = after_ext.get(..start_digits_len)?.parse().ok()?;
    let after_start = after_ext.get(start_digits_len..)?;

    let (end, range_consumed) = if let Some(after_dash) = after_start.strip_prefix('-') {
        let end_digits_len = after_dash.bytes().take_while(u8::is_ascii_digit).count();
        if end_digits_len == 0 {
            (start, 0)
        } else if let Some(parsed) = after_dash
            .get(..end_digits_len)
            .and_then(|d| d.parse::<usize>().ok())
        {
            (parsed, 1 + end_digits_len)
        } else {
            (start, 0)
        }
    } else {
        (start, 0)
    };

    let consumed = base_consumed + ":".len() + start_digits_len + range_consumed;
    Some((file, start, end, consumed))
}

/// Find a `(~line NNN)` (AGENTS.md) or `~LNNN` (MINDMAP.md) locator on a
/// doc line.
fn parse_tilde_line(line: &str) -> Option<usize> {
    let mut tail = line;
    while let Some(pos) = tail.find('~') {
        let after = tail.get(pos + 1..).unwrap_or("");
        let digits_part = if let Some(rest) = after.strip_prefix("line ") {
            rest
        } else if let Some(rest) = after.strip_prefix('L') {
            rest
        } else {
            tail = after;
            continue;
        };
        let len = digits_part.bytes().take_while(u8::is_ascii_digit).count();
        if len > 0
            && let Some(n) = digits_part.get(..len).and_then(|d| d.parse::<usize>().ok())
        {
            return Some(n);
        }
        tail = after;
    }
    None
}

fn parse_citations(doc: &str) -> Vec<Citation> {
    let mut out = Vec::new();
    for (doc_idx, line) in doc.lines().enumerate() {
        let doc_line_no = doc_idx + 1;
        let mut bare_file: Option<String> = None;

        let mut tail = line;
        while let Some(rel) = tail.find("src/") {
            let candidate = tail.get(rel..).unwrap_or("");
            if let Some((file, start, end, consumed)) = parse_path_at(candidate) {
                if start > 0 {
                    out.push(Citation {
                        anchors: extract_anchors(line, &file),
                        file,
                        start,
                        end,
                        doc_line: doc_line_no,
                    });
                } else if bare_file.is_none() {
                    bare_file = Some(file);
                }
                tail = candidate.get(consumed..).unwrap_or("");
            } else {
                tail = candidate.get(1..).unwrap_or("");
            }
        }

        // Pair a bare path with a `~line N` / `~LN` locator on the same line.
        if let Some(file) = bare_file
            && let Some(n) = parse_tilde_line(line)
        {
            out.push(Citation {
                anchors: extract_anchors(line, &file),
                file,
                start: n,
                end: n,
                doc_line: doc_line_no,
            });
        }
    }
    out
}

fn check_doc(doc_name: &str, doc: &str) -> (usize, Vec<String>) {
    let root = workspace_root();
    let citations = parse_citations(doc);

    let mut file_lines: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for c in &citations {
        let lines = file_lines.entry(c.file.clone()).or_insert_with(|| {
            fs::read_to_string(root.join(&c.file))
                .ok()
                .map(|t| t.lines().map(str::to_owned).collect())
        });

        let Some(lines) = lines else {
            failures.push(format!(
                "{doc_name}:{} cites {}:{} but the file does not exist",
                c.doc_line,
                c.file,
                fmt_range(c)
            ));
            continue;
        };
        let n = lines.len();

        if c.end > n {
            failures.push(format!(
                "{doc_name}:{} cites {}:{} but file only has {n} lines",
                c.doc_line,
                c.file,
                fmt_range(c)
            ));
            continue;
        }

        if c.anchors.is_empty() {
            continue;
        }

        // Window: [start - TOLERANCE, end + TOLERANCE], clamped, 1-based.
        let win_start = c.start.saturating_sub(TOLERANCE).max(1);
        let win_end = c.end.saturating_add(TOLERANCE).min(n);
        let window: String = lines
            .get(win_start - 1..win_end)
            .unwrap_or_default()
            .join("\n");

        if !c.anchors.iter().any(|a| window.contains(a.as_str())) {
            failures.push(format!(
                "{doc_name}:{} cites {}:{} but none of the anchor symbols {:?} \
                 appear within {TOLERANCE} lines of the cited location \
                 (searched lines {win_start}-{win_end}); update the citation",
                c.doc_line,
                c.file,
                fmt_range(c),
                c.anchors,
            ));
        }
    }

    (citations.len(), failures)
}

fn fmt_range(c: &Citation) -> String {
    if c.end == c.start {
        format!("{}", c.start)
    } else {
        format!("{}-{}", c.start, c.end)
    }
}

fn run_doc_test(doc_rel_path: &str) {
    let root = workspace_root();
    let path = root.join(doc_rel_path);
    let doc = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {doc_rel_path}: {e}"));

    let (total, failures) = check_doc(doc_rel_path, &doc);
    assert!(
        total > 0,
        "no src/*.rs citations parsed from {doc_rel_path} - parser is likely broken"
    );
    assert!(
        failures.is_empty(),
        "{} stale citation(s) in {doc_rel_path} (out of {total} total):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn architecture_citations_resolve() {
    run_doc_test("docs/ARCHITECTURE.md");
}

#[test]
fn agents_citations_resolve() {
    run_doc_test("AGENTS.md");
}

#[test]
fn mindmap_citations_resolve() {
    run_doc_test("docs/MINDMAP.md");
}

#[test]
fn anchored_citations_exist() {
    // Guard the guard: if anchor extraction silently breaks (returns no
    // anchors for every citation), the symbol check degrades to the old
    // length-only behavior without anyone noticing. ARCHITECTURE.md is
    // dense with backticked symbols, so a healthy parser must find a
    // meaningful number of anchored citations there.
    let root = workspace_root();
    let doc = fs::read_to_string(root.join("docs/ARCHITECTURE.md")).expect("read ARCHITECTURE.md");
    let citations = parse_citations(&doc);
    let anchored = citations.iter().filter(|c| !c.anchors.is_empty()).count();
    assert!(
        anchored >= 10,
        "expected >=10 symbol-anchored citations in docs/ARCHITECTURE.md, found {anchored} \
         (out of {} citations) - anchor extraction is likely broken",
        citations.len()
    );
}
