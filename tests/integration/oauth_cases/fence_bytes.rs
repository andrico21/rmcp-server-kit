//! Exhaustive ASCII boundary coordinates for the shared document scanner.

use anyhow::{Context as _, ensure};

use super::{complete_document, coverage::Coverage, document_fences};

/// # Errors
/// Returns the byte coordinate whose closer, opener or heading verdict differs.
pub(super) fn boundaries() -> anyhow::Result<()> {
    let mut coverage = Coverage::default();
    coverage.plan("closer-byte", 126_usize.saturating_mul(5));
    coverage.plan("opener-byte", 126);
    coverage.plan("heading-byte", 126);
    coverage.plan("outside-closer-byte", 126);
    for byte in (0_u8..=127).filter(|byte| !matches!(byte, b'\n' | b'\r')) {
        let suffix = char::from(byte);
        for indent in ["", " ", "   ", "    ", "\t"] {
            // Given: every ASCII suffix at every supported indentation coordinate.
            let candidate = format!("{indent}```{suffix}");
            let markdown = complete_document(&format!(
                "## 7. Cases\n```text\nbefore\n{candidate}\n## 8. End\n"
            ));
            // When: scan an open fence with the candidate as its only closer.
            let result = document_fences(&markdown);
            // Then: only a column-zero closer with an ASCII space suffix closes.
            if indent.is_empty() && byte == b' ' {
                let fences = result?;
                ensure!(fences.len() == 1, "closer byte {byte}: missing fence");
                ensure!(fences.first().context("closed fence")?.body == "before");
            } else {
                let error = result
                    .err()
                    .with_context(|| format!("closer {candidate:?} accepted"))?;
                ensure!(
                    error.to_string().contains("line 10:"),
                    "{candidate:?}: {error:#}"
                );
            }
            coverage.record("closer-byte", true);
        }
        opener(byte)?;
        coverage.record("opener-byte", true);
        heading(byte)?;
        coverage.record("heading-byte", true);
        outside_closer(byte)?;
        coverage.record("outside-closer-byte", true);
    }
    coverage.check()?;
    carriage_returns()?;
    single_headings()
}

/// # Errors
/// Returns an outside-section suffix that prematurely truncates a plain fence.
fn outside_closer(byte: u8) -> anyhow::Result<()> {
    let candidate = format!("```{}", char::from(byte));
    let markdown = complete_document(&format!(
        "## 7. Cases\n## 8. End\n```text\nbefore\n{candidate}\nafter\n```\n"
    ));
    let fences = document_fences(&markdown)?;
    let expected = if byte == b' ' {
        "before".to_owned()
    } else {
        format!("before\n{candidate}\nafter")
    };
    ensure!(
        fences.len() == 1 && fences.first().context("outside fence")?.body == expected,
        "outside closer byte {byte}: body truncated"
    );
    Ok(())
}

/// # Errors
/// Returns the info byte whose extraction differs from the plain-info language.
fn opener(byte: u8) -> anyhow::Result<()> {
    let info = format!("{}text", char::from(byte));
    let markdown = complete_document(&format!("## 7. Cases\n```{info}\nbody\n```\n## 8. End\n"));
    let result = document_fences(&markdown);
    if matches!(byte, b'`' | b'\t') {
        let error = result.err().context("unsupported info byte accepted")?;
        ensure!(
            error.to_string().contains("line 8:"),
            "byte {byte}: {error:#}"
        );
    } else {
        let fences = result?;
        let fence = fences.first().context("opener fence missing")?;
        ensure!(
            fences.len() == 1 && fence.info == info.trim_start_matches(' ') && fence.body == "body",
            "opener byte {byte}: extraction differs"
        );
    }
    Ok(())
}

/// # Errors
/// Returns the separator byte that changes heading recognition unexpectedly.
fn heading(byte: u8) -> anyhow::Result<()> {
    let markdown = complete_document(&format!("## 7. Cases\n##{}8. End\n", char::from(byte)));
    let result = document_fences(&markdown);
    if byte == b' ' {
        ensure!(result?.is_empty(), "heading produced a fence");
    } else {
        let error = result
            .err()
            .context("non-space heading separator accepted")?;
        ensure!(
            error.to_string().contains("line 10:") && error.to_string().contains("expected ## 8."),
            "heading byte {byte}: {error:#}"
        );
    }
    Ok(())
}

/// # Errors
/// Returns a CRLF normalization or lone carriage-return regression.
fn carriage_returns() -> anyhow::Result<()> {
    for (ending, passes) in [("\r\n", true), ("\rX\n", false)] {
        let markdown = complete_document(&format!(
            "## 7. Cases\n```text\nbody\n```{ending}## 8. End\n"
        ));
        match document_fences(&markdown) {
            Ok(fences) => ensure!(passes && fences.len() == 1, "CR closer accepted"),
            Err(error) => ensure!(
                !passes && error.to_string().contains("line 10: lone carriage return"),
                "{error:#}"
            ),
        }
    }
    Ok(())
}

/// # Errors
/// Returns an individually renamed heading lacking a source-line diagnostic.
fn single_headings() -> anyhow::Result<()> {
    let plain = complete_document("## 7. Cases\n## 8. End\n");
    let mut coverage = Coverage::default();
    coverage.plan("single-heading", 13_usize.saturating_mul(2));
    for number in 1..=13_usize {
        for replacement in [
            format!("## {}. ", number.saturating_add(20)),
            "## renamed ".to_owned(),
        ] {
            let original = format!("## {number}. ");
            let line = plain
                .lines()
                .position(|line| line.starts_with(&original))
                .context("heading fixture")?
                .saturating_add(1);
            let error = document_fences(&plain.replace(&original, &replacement))
                .err()
                .context("renamed heading accepted")?;
            ensure!(
                error.to_string().contains(&format!("line {line}:"))
                    && error
                        .to_string()
                        .contains(&format!("expected ## {number}.")),
                "{error:#}"
            );
            coverage.record("single-heading", true);
        }
    }
    coverage.check()?;
    Ok(())
}
