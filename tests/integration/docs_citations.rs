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
//!    same doc line): at least one anchor symbol - a backticked token
//!    like `` `TlsListener` `` or a parenthesized identifier like
//!    `(build_app_router)` - must appear within `TOLERANCE` lines of the
//!    cited location in the cited file. This catches silent drift that
//!    the length check cannot (a file that only ever grows keeps every
//!    stale citation "valid" forever).
//!
//! Recognized citation forms (all require the `src/<file>.rs` path on
//! the same doc line):
//!   `src/<file>.rs:<line>`            (single line)
//!   `src/<file>.rs:<line>-<line>`     (range)
//!   `src/<file>.rs` ... `(~line <line>)`   (AGENTS.md table style)
//!   `src/<file>.rs` ... `~L<line>`         (MINDMAP.md table style).
//!
//! Out of scope: mindmap nodes whose file is implied by a parent node
//! (no path on the line), and prose without a `src/*.rs` mention.
//!
//! Drift fixes are easy: re-read the cited code and update the number.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use std::{fs, path::PathBuf};

    use anyhow::Context as _;
    use rmcp_server_kit::{
        config::{ObservabilityConfig, ServerConfig},
        rbac::RbacConfig,
    };
    use serde::Deserialize;

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
        /// e.g. "src/transport.rs".
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

    #[derive(Debug)]
    struct TomlFence {
        line: usize,
        info: String,
        body: String,
    }

    #[derive(Debug, Deserialize)]
    struct GuideOperatorConfig {
        server: Option<ServerConfig>,
        rbac: Option<RbacConfig>,
        observability: Option<ObservabilityConfig>,
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Leading `[A-Za-z_][A-Za-z0-9_]*` run after skipping any non-identifier
    /// prefix characters (`&`, `[`, `*`, spaces, ...).
    fn leading_identifier(input: &str) -> Option<&str> {
        let trimmed = input.trim_start_matches(|ch: char| !(ch.is_ascii_alphabetic() || ch == '_'));
        let len = trimmed
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
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
            .and_then(|name| name.strip_suffix(".rs"))
            .unwrap_or("");
        candidate != stem
    }

    /// Extract anchor candidates from a doc line: the leading identifier of
    /// every backticked segment (plus, for `path::to::item` forms, the final
    /// segment), and every `(identifier)` group.
    fn extract_anchors(line: &str, file: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |candidate: &str| {
            if keep_anchor(candidate, file) && !out.iter().any(|anchor| anchor == candidate) {
                out.push(candidate.to_owned());
            }
        };

        // Backticked segments: odd-indexed pieces of a split on '`'.
        for segment in line.split('`').skip(1).step_by(2) {
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
            let inner = tail
                .get(open..)
                .and_then(|rest| rest.strip_prefix('('))
                .unwrap_or("");
            let len = inner
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
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
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_len == 0 {
            return None;
        }
        let name = rest.get(..name_len)?;
        let after_name = rest.get(name_len..)?;

        let file = format!("src/{name}.rs");
        let base_consumed = "src/"
            .len()
            .saturating_add(name_len)
            .saturating_add(".rs".len());

        let Some(after_ext) = after_name.strip_prefix(".rs:") else {
            // Bare path (no :NNN) - still a valid file mention.
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

        let (end, range_consumed) =
            after_start
                .strip_prefix('-')
                .map_or((start, 0), |after_dash| {
                    let end_digits_len = after_dash.bytes().take_while(u8::is_ascii_digit).count();
                    if end_digits_len == 0 {
                        (start, 0)
                    } else if let Some(parsed) = after_dash
                        .get(..end_digits_len)
                        .and_then(|digits| digits.parse::<usize>().ok())
                    {
                        (parsed, end_digits_len.saturating_add(1))
                    } else {
                        (start, 0)
                    }
                });

        let consumed = base_consumed
            .saturating_add(":".len())
            .saturating_add(start_digits_len)
            .saturating_add(range_consumed);
        Some((file, start, end, consumed))
    }

    /// Find a `(~line NNN)` (AGENTS.md) or `~LNNN` (MINDMAP.md) locator on a
    /// doc line.
    fn parse_tilde_line(line: &str) -> Option<usize> {
        let mut tail = line;
        while let Some(pos) = tail.find('~') {
            let after = tail
                .get(pos..)
                .and_then(|rest| rest.strip_prefix('~'))
                .unwrap_or("");
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
                && let Some(found) = digits_part
                    .get(..len)
                    .and_then(|digits| digits.parse::<usize>().ok())
            {
                return Some(found);
            }
            tail = after;
        }
        None
    }

    fn parse_citations(doc: &str) -> Vec<Citation> {
        let mut out = Vec::new();
        for (doc_idx, line) in doc.lines().enumerate() {
            let doc_line_no = doc_idx.saturating_add(1);
            let mut bare_file: Option<String> = None;

            let mut tail = line;
            while let Some(rel) = tail.find("src/") {
                let candidate = tail.get(rel..).unwrap_or("");
                if let Some((file, start, end, consumed)) = parse_path_at(candidate) {
                    if start == 0 {
                        if bare_file.is_none() {
                            bare_file = Some(file);
                        }
                    } else {
                        out.push(Citation {
                            anchors: extract_anchors(line, &file),
                            file,
                            start,
                            end,
                            doc_line: doc_line_no,
                        });
                    }
                    tail = candidate.get(consumed..).unwrap_or("");
                } else {
                    tail = candidate.get(1..).unwrap_or("");
                }
            }

            // Pair a bare path with a `~line N` / `~LN` locator on the same line.
            if let Some(file) = bare_file
                && let Some(found) = parse_tilde_line(line)
            {
                out.push(Citation {
                    anchors: extract_anchors(line, &file),
                    file,
                    start: found,
                    end: found,
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

        for citation in &citations {
            let cached_lines = file_lines.entry(citation.file.clone()).or_insert_with(|| {
                fs::read_to_string(root.join(&citation.file))
                    .ok()
                    .map(|text| text.lines().map(str::to_owned).collect())
            });

            let Some(lines) = cached_lines else {
                failures.push(format!(
                    "{doc_name}:{} cites {}:{} but the file does not exist",
                    citation.doc_line,
                    citation.file,
                    fmt_range(citation)
                ));
                continue;
            };
            let line_count = lines.len();

            if citation.end > line_count {
                failures.push(format!(
                    "{doc_name}:{} cites {}:{} but file only has {line_count} lines",
                    citation.doc_line,
                    citation.file,
                    fmt_range(citation)
                ));
                continue;
            }

            if citation.anchors.is_empty() {
                continue;
            }

            // Window: [start - TOLERANCE, end + TOLERANCE], clamped, 1-based.
            let win_start = citation.start.saturating_sub(TOLERANCE).max(1);
            let win_end = citation.end.saturating_add(TOLERANCE).min(line_count);
            let window: String = lines
                .get(win_start.saturating_sub(1)..win_end)
                .unwrap_or_default()
                .join("\n");

            if !citation
                .anchors
                .iter()
                .any(|anchor| window_has_anchor(&window, anchor))
            {
                failures.push(format!(
                    "{doc_name}:{} cites {}:{} but none of the anchor symbols {:?} \
                     appear within {TOLERANCE} lines of the cited location \
                     (searched lines {win_start}-{win_end}); update the citation",
                    citation.doc_line,
                    citation.file,
                    fmt_range(citation),
                    citation.anchors,
                ));
            }
        }

        (citations.len(), failures)
    }

    /// True when `anchor` occurs in `window` as a standalone identifier: the
    /// characters immediately surrounding the match (when present) must not
    /// be identifier characters. Plain substring matching let generic
    /// anchors like `serve` match inside `server` / `observed`, silently
    /// masking stale citations.
    fn window_has_anchor(window: &str, anchor: &str) -> bool {
        const fn is_ident(byte: u8) -> bool {
            byte.is_ascii_alphanumeric() || byte == b'_'
        }
        let bytes = window.as_bytes();
        window.match_indices(anchor).any(|(pos, _)| {
            let before_ok = pos
                .checked_sub(1)
                .is_none_or(|index| !bytes.get(index).copied().is_some_and(is_ident));
            let after_ok = !bytes
                .get(pos..)
                .and_then(|rest| rest.get(anchor.len()))
                .copied()
                .is_some_and(is_ident);
            before_ok && after_ok
        })
    }

    fn fmt_range(citation: &Citation) -> String {
        if citation.end == citation.start {
            format!("{}", citation.start)
        } else {
            format!("{}-{}", citation.start, citation.end)
        }
    }

    fn run_doc_test(doc_rel_path: &str) -> anyhow::Result<()> {
        let root = workspace_root();
        let path = root.join(doc_rel_path);
        let doc = match fs::read_to_string(&path) {
            Ok(doc) => doc,
            Err(error) => anyhow::bail!("read {doc_rel_path}: {error}"),
        };

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
        Ok(())
    }

    fn extract_toml_fences(doc: &str) -> Vec<TomlFence> {
        let mut fences = Vec::new();
        let mut open: Option<TomlFence> = None;

        for (idx, line) in doc.lines().enumerate() {
            let line_no = idx.saturating_add(1);
            let trimmed = line.trim_start();

            if let Some(mut fence) = open.take() {
                if trimmed == "```" {
                    fences.push(fence);
                } else {
                    fence.body.push_str(line);
                    fence.body.push('\n');
                    open = Some(fence);
                }
                continue;
            }

            if let Some(raw_info) = trimmed.strip_prefix("```") {
                let info = raw_info.trim();
                if info == "toml" || info.starts_with("toml,") {
                    open = Some(TomlFence {
                        line: line_no,
                        info: info.to_owned(),
                        body: String::new(),
                    });
                }
            }
        }

        fences
    }

    fn assert_operator_root_keys(block: &TomlFence, table: &toml::Table) {
        for key in table.keys() {
            assert!(
                matches!(key.as_str(), "server" | "rbac" | "observability"),
                "docs/GUIDE.md:{} has unknown operator-config root table/key `{key}`",
                block.line
            );
        }
    }

    fn assert_operator_config_block_parses(block: &TomlFence) -> anyhow::Result<()> {
        let table: toml::Table = match toml::from_str(&block.body) {
            Ok(table) => table,
            Err(error) => anyhow::bail!(
                "docs/GUIDE.md:{} operator TOML is not valid TOML: {error}\n{}",
                block.line,
                block.body
            ),
        };
        assert_operator_root_keys(block, &table);

        let parsed: GuideOperatorConfig = match toml::from_str(&block.body) {
            Ok(parsed) => parsed,
            Err(error) => anyhow::bail!(
                "docs/GUIDE.md:{} operator TOML does not match rmcp-server-kit config schema: {error}\n{}",
                block.line,
                block.body
            ),
        };
        assert!(
            parsed.server.is_some() || parsed.rbac.is_some() || parsed.observability.is_some(),
            "docs/GUIDE.md:{} operator TOML block must contain server, rbac, or observability config",
            block.line
        );
        Ok(())
    }

    fn assert_cargo_toml_block_parses(block: &TomlFence) -> anyhow::Result<()> {
        if let Err(error) = toml::from_str::<toml::Value>(&block.body) {
            anyhow::bail!(
                "docs/GUIDE.md:{} Cargo TOML is not valid TOML: {error}\n{}",
                block.line,
                block.body
            );
        }
        Ok(())
    }

    fn assert_toml_fragment_parses(block: &TomlFence) -> anyhow::Result<()> {
        if let Err(error) = toml::from_str::<toml::Value>(&block.body) {
            anyhow::bail!(
                "docs/GUIDE.md:{} TOML fragment is not valid TOML: {error}\n{}",
                block.line,
                block.body
            );
        }
        Ok(())
    }

    fn extract_embedded_config(source: &str) -> anyhow::Result<&str> {
        let Some((_, tail)) = source.split_once("const EMBEDDED_CONFIG: &str = r#\"") else {
            anyhow::bail!("examples/config_file_server.rs no longer declares EMBEDDED_CONFIG");
        };
        let Some((config, _)) = tail.split_once("\"#;") else {
            anyhow::bail!(
                "examples/config_file_server.rs EMBEDDED_CONFIG raw string is not terminated"
            );
        };
        Ok(config)
    }

    /// Pins that every TOML fence in `docs/GUIDE.md` parses with its declared role.
    #[test]
    fn guide_toml_fences_parse() -> anyhow::Result<()> {
        let root = workspace_root();
        let doc = fs::read_to_string(root.join("docs/GUIDE.md")).context("read GUIDE.md")?;
        let fences = extract_toml_fences(&doc);

        assert_eq!(fences.len(), 18, "GUIDE.md TOML fence count drifted");
        for block in &fences {
            match block.info.as_str() {
                "toml" => assert_operator_config_block_parses(block)?,
                "toml,cargo" => assert_cargo_toml_block_parses(block)?,
                "toml,fragment" => assert_toml_fragment_parses(block)?,
                other => anyhow::bail!(
                    "docs/GUIDE.md:{} uses unsupported TOML fence info string `{other}`; use `toml` for complete operator config, `toml,cargo` for Cargo snippets, or `toml,fragment` for intentionally incomplete excerpts",
                    block.line
                ),
            }
        }
        Ok(())
    }

    /// Pins that the example's embedded config matches the kit config schema.
    #[test]
    fn config_file_server_embedded_toml_parses() -> anyhow::Result<()> {
        let root = workspace_root();
        let source = fs::read_to_string(root.join("examples/config_file_server.rs"))
            .context("read config_file_server.rs")?;
        let config = extract_embedded_config(&source)?;
        let parsed: GuideOperatorConfig = match toml::from_str(config) {
            Ok(parsed) => parsed,
            Err(error) => anyhow::bail!(
                "examples/config_file_server.rs EMBEDDED_CONFIG does not match rmcp-server-kit config schema: {error}\n{config}"
            ),
        };
        assert!(
            parsed.server.is_some(),
            "embedded config must include [server]"
        );
        assert!(
            parsed.observability.is_some(),
            "embedded config must include [observability]"
        );
        assert!(parsed.rbac.is_some(), "embedded config must include [rbac]");
        Ok(())
    }

    /// The kit's section structs reject unknown *keys*, but only an
    /// application-owned root type can reject a misspelled *table name*
    /// (`[serverr]`). `config_file_server` is the canonical consumer example, so
    /// it must keep modelling that; without the attribute a mistyped section is
    /// silently dropped and the server starts with defaults for it.
    #[test]
    fn config_file_server_root_denies_unknown_tables() -> anyhow::Result<()> {
        let root = workspace_root();
        let source = fs::read_to_string(root.join("examples/config_file_server.rs"))
            .context("read config_file_server.rs")?;

        let struct_pos = source
            .find("struct AppConfig")
            .context("examples/config_file_server.rs must define the AppConfig root type")?;
        let preamble = source
            .get(..struct_pos)
            .context("struct_pos is a char boundary returned by find")?;

        assert!(
            preamble.contains("#[serde(deny_unknown_fields)]"),
            "examples/config_file_server.rs: the application-owned `AppConfig` root must carry \
             #[serde(deny_unknown_fields)] so a misspelled table name is rejected rather than \
             silently ignored"
        );
        Ok(())
    }

    /// Pins that every `src/*.rs` citation in `docs/ARCHITECTURE.md` resolves.
    #[test]
    fn architecture_citations_resolve() -> anyhow::Result<()> {
        run_doc_test("docs/ARCHITECTURE.md")?;
        Ok(())
    }

    /// Pins that every `src/*.rs` citation in `AGENTS.md` resolves.
    #[test]
    fn agents_citations_resolve() -> anyhow::Result<()> {
        run_doc_test("AGENTS.md")?;
        Ok(())
    }

    /// Pins that every `src/*.rs` citation in `docs/MINDMAP.md` resolves.
    #[test]
    fn mindmap_citations_resolve() -> anyhow::Result<()> {
        run_doc_test("docs/MINDMAP.md")?;
        Ok(())
    }

    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: tests/integration/docs_citations.rs::anchor_matching_requires_identifier_boundaries keeps the uniform test signature while it only asserts"
    )]
    /// Pins that anchor matching only accepts whole identifier tokens.
    fn anchor_matching_requires_identifier_boundaries() -> anyhow::Result<()> {
        assert!(window_has_anchor("pub async fn serve<H, F>(", "serve"));
        assert!(window_has_anchor("calls serve() here", "serve"));
        assert!(
            !window_has_anchor("the server observed traffic", "serve"),
            "substring inside larger identifiers must not match"
        );
        assert!(!window_has_anchor("preserved", "serve"));
        assert!(window_has_anchor("get(healthz)", "healthz"));
        assert!(!window_has_anchor("healthz_returns_ok", "healthz"));
        Ok(())
    }

    /// Pins that `docs/ARCHITECTURE.md` keeps a healthy number of
    /// symbol-anchored citations.
    #[test]
    fn anchored_citations_exist() -> anyhow::Result<()> {
        // Guard the guard: if anchor extraction silently breaks (returns no
        // anchors for every citation), the symbol check degrades to the old
        // length-only behavior without anyone noticing. ARCHITECTURE.md is
        // dense with backticked symbols, so a healthy parser must find a
        // meaningful number of anchored citations there.
        let root = workspace_root();
        let doc = fs::read_to_string(root.join("docs/ARCHITECTURE.md"))
            .context("read ARCHITECTURE.md")?;
        let citations = parse_citations(&doc);
        let anchored = citations
            .iter()
            .filter(|citation| !citation.anchors.is_empty())
            .count();
        assert!(
            anchored >= 10,
            "expected >=10 symbol-anchored citations in docs/ARCHITECTURE.md, found {anchored} \
             (out of {} citations) - anchor extraction is likely broken",
            citations.len()
        );
        Ok(())
    }
}
