//! Shared fail-safe plain-fence contract for the numbered OAuth guide.

use anyhow::{Context as _, ensure};

/// Check every case-looking opener against the executable section contract.
///
/// # Errors
/// Returns source context for misplaced or malformed case fences.
pub(crate) fn validate_document(markdown: &str) -> anyhow::Result<()> {
    for fence in document_fences(markdown)? {
        if fence.info.to_ascii_lowercase().contains("case") {
            validate_info(&fence.info).with_context(|| {
                format!(
                    "line {} under {}: case fence {:?}",
                    fence.line, fence.heading, fence.info
                )
            })?;
        }
    }
    Ok(())
}

pub(crate) struct Fence {
    pub line: usize,
    pub heading: String,
    pub info: String,
    pub body: String,
}

fn fence_text(mut line: &str) -> &str {
    loop {
        line = line.trim_start();
        if let Some(rest) = line.strip_prefix(['>', '-', '*', '+']) {
            line = rest;
            continue;
        }
        let rest = line.trim_start_matches(|character: char| character.is_ascii_digit());
        if rest.len() < line.len()
            && let Some(tail) = rest.strip_prefix(['.', ')'])
        {
            line = tail;
            continue;
        }
        return line;
    }
}

/// # Errors
/// Returns the first invalid numbered heading or lone carriage return.
fn check_skeleton(markdown: &str) -> anyhow::Result<()> {
    for (index, line) in markdown.split('\n').enumerate() {
        ensure!(
            !line.contains('\r'),
            "line {}: lone carriage return",
            index.saturating_add(1)
        );
    }
    let mut expected = 1_usize;
    for (index, line) in markdown
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with("## "))
    {
        ensure!(
            expected <= 13 && line.starts_with(&format!("## {expected}. ")),
            "line {}: heading {line:?}; {}; a heading inside a code block or a renamed section desynchronises the example scanner",
            index.saturating_add(1),
            if expected > 13 {
                "surplus heading; the document has 13 sections".to_owned()
            } else {
                format!("expected ## {expected}.")
            }
        );
        expected = expected.saturating_add(1);
    }
    ensure!(
        expected == 14,
        "line {}: heading missing at end of document; expected ## {expected}. ; a heading inside a code block or a renamed section desynchronises the example scanner",
        markdown.lines().count().saturating_add(1)
    );
    Ok(())
}

/// Scan plain fences once for executable cases and schema-only documentation checks.
///
/// # Errors
/// Returns source context for unsupported layouts or a broken heading skeleton.
pub(crate) fn document_fences(markdown: &str) -> anyhow::Result<Vec<Fence>> {
    let normalized = markdown.replace("\r\n", "\n");
    check_skeleton(&normalized)?;
    let mut heading = "(no section heading)";
    let mut open: Option<Fence> = None;
    let mut fences = Vec::new();
    for (index, line) in normalized.lines().enumerate() {
        let number = index.saturating_add(1);
        if line.starts_with("## ") {
            if heading.starts_with("## 7. ")
                && let Some(fence) = &open
            {
                anyhow::bail!(
                    "line {} under {heading}: unclosed fence {:?}",
                    fence.line,
                    fence.info
                );
            }
            open = None;
            heading = line;
        }
        let inside = heading.starts_with("## 7. ");
        let content = fence_text(line);
        let looks = content.starts_with("```") || content.starts_with("~~~");
        let case_looking = looks
            && content
                .to_ascii_lowercase()
                .match_indices("case")
                .any(|(offset, _)| {
                    content
                        .get(offset.saturating_add(4)..)
                        .is_some_and(|tail| tail.trim_start_matches(' ').starts_with('='))
                });
        ensure!(
            inside || !case_looking,
            "line {number} under {heading}: case fence outside section 7: {line:?}"
        );
        ensure!(
            !inside || !line.contains("<!--"),
            "line {number}: HTML comments are not supported in section 7; rewrite as ordinary prose"
        );
        let plain_info = line
            .strip_prefix("```")
            .filter(|tail| !tail.contains(['`', '\t']));
        if inside && looks {
            ensure!(
                plain_info.is_some(),
                "line {number}: section 7 allows plain fences only; found indent width={}, backtick count={}, tab={}; rewrite as a column-0 triple-backtick fence: {line:?}",
                line.chars()
                    .take_while(|character| *character == ' ')
                    .count(),
                content
                    .chars()
                    .take_while(|character| *character == '`')
                    .count(),
                line.contains('\t')
            );
        }
        if let Some(fence) = &mut open {
            if line
                .strip_prefix("```")
                .is_some_and(|tail| tail.bytes().all(|byte| byte == b' '))
            {
                let mut closed = open.take().context("open plain fence")?;
                let _newline = closed.body.pop();
                fences.push(closed);
                continue;
            }
            ensure!(
                !inside || !looks,
                "line {number}: section 7 allows plain fences only; nested fences are not supported; close the outer fence before opening another"
            );
            fence.body.push_str(line);
            fence.body.push('\n');
            continue;
        }
        if let Some(tail) = plain_info {
            open = Some(Fence {
                line: number,
                heading: heading.to_owned(),
                info: tail.trim_matches(' ').to_owned(),
                body: String::new(),
            });
        }
    }
    Ok(fences)
}

/// Parse the restricted case-fence info grammar.
///
/// # Errors
/// Returns the offending info when its ID or exact grammar is invalid.
fn validate_info(info: &str) -> anyhow::Result<()> {
    let parts: Vec<_> = info.split(',').collect();
    let id = parts
        .get(1)
        .and_then(|part| part.strip_prefix("case="))
        .with_context(|| format!("case ID must be second in {info:?}"))?;
    ensure!(
        !id.is_empty()
            && id.len() <= 16
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "case {id:?}: invalid ID in {info:?}"
    );
    ensure!(
        matches!(
            parts.as_slice(),
            ["toml" | "sh", _]
                | ["sh", _, "alt"]
                | ["http", _, "request" | "response" | "upstream"]
        ),
        "case {id}: invalid info {info:?}"
    );
    Ok(())
}
