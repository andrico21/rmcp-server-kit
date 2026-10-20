//! Bounded reference models for numbered headings and plain fence closers.

use core::fmt::Write as _;

use anyhow::{Context as _, ensure};

use super::{complete_document, coverage::Coverage, document_fences};

const HEADINGS: [usize; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// # Errors
/// Returns an accepted permutation or a diagnostic missing its first offending line.
pub(super) fn heading_order() -> anyhow::Result<()> {
    let mut rows = Vec::new();
    for index in 0..HEADINGS.len().saturating_sub(1) {
        for other in index.saturating_add(1)..HEADINGS.len() {
            let mut swapped = HEADINGS;
            swapped.swap(index, other);
            rows.push(swapped.to_vec());
        }
    }
    let mut last = HEADINGS.to_vec();
    let seven = last.remove(6);
    last.push(seven);
    rows.push(last);
    let mut first = HEADINGS.to_vec();
    first.rotate_right(1);
    rows.push(first);
    let mut reversed = HEADINGS.to_vec();
    reversed.reverse();
    rows.push(reversed);
    let mut coverage = Coverage::default();
    coverage.plan("heading-order", rows.len());
    for order in rows {
        // Given: every heading exists once; only its position differs.
        let mut markdown = String::new();
        for number in &order {
            writeln!(markdown, "## {number}. Section")?;
        }
        let (index, expected) = HEADINGS
            .iter()
            .enumerate()
            .find(|(index, n)| order.get(*index) != Some(n))
            .context("permutation must differ")?;
        // When: the shared scanner reads the permuted skeleton.
        let error = document_fences(&markdown)
            .err()
            .context("heading order accepted")?;
        // Then: the earliest wrong heading is loud, with its required replacement.
        let diagnostic = format!("{error:#}");
        ensure!(
            diagnostic.contains(&format!("line {}:", index.saturating_add(1)))
                && diagnostic.contains(&format!("expected ## {expected}.")),
            "heading order {order:?}: {diagnostic}"
        );
        coverage.record("heading-order", true);
    }
    coverage.check()?;
    Ok(())
}

/// Independent D3 closer model.
///
/// Short runs are content; exactly three column-zero
/// backticks followed only by spaces close; all other fence-looking lines fail.
/// In particular trailing text is rejected as nested immediately, not at EOF.
#[derive(Clone, Copy)]
enum Outcome {
    Content,
    Close,
    Reject,
}

fn reference(arity: usize, indent: &str, suffix: &str) -> Outcome {
    match arity {
        0..=2 => Outcome::Content,
        3 if indent.is_empty() && suffix.chars().all(|character| character == ' ') => {
            Outcome::Close
        }
        3.. => Outcome::Reject,
    }
}

/// # Errors
/// Returns the closer coordinate whose verdict or preserved content differs.
pub(super) fn closer_product() -> anyhow::Result<()> {
    let mut coverage = Coverage::default();
    coverage.plan(
        "closer-product",
        6_usize.saturating_mul(4).saturating_mul(5),
    );
    for arity in 0..=5_usize {
        for suffix in ["", "   ", "\t", "text"] {
            for indent in ["", " ", "   ", "    ", "\t"] {
                // Given: a candidate closer followed by body content and a real closer.
                let candidate = format!("{indent}{}{suffix}", "`".repeat(arity));
                let middle =
                    format!("## 7. Cases\n```text\nbefore\n{candidate}\nafter\n```\n## 8. End\n");
                // When: scan the complete product of arity, suffix and indentation.
                let result = document_fences(&complete_document(&middle));
                // Then: compare with the independent bounded language definition.
                match reference(arity, indent, suffix) {
                    Outcome::Content => {
                        let fences = result?;
                        ensure!(fences.len() == 1, "content closed: {candidate:?}");
                        let fence = fences.first().context("content fence missing")?;
                        ensure!(
                            fence.body == format!("before\n{candidate}\nafter"),
                            "content lost: {candidate:?}"
                        );
                    }
                    Outcome::Close => {
                        // The subsequent bare fence opens again and is unclosed at section end.
                        let error = result.err().context("extra open fence accepted")?;
                        ensure!(
                            error.to_string().contains("unclosed fence"),
                            "{candidate:?}: {error:#}"
                        );
                        let closed = complete_document(&format!(
                            "## 7. Cases\n```text\nbefore\n{candidate}\n## 8. End\n"
                        ));
                        let fences = document_fences(&closed)?;
                        ensure!(fences.len() == 1, "closer lost: {candidate:?}");
                        ensure!(
                            fences.first().context("closed fence missing")?.body == "before",
                            "closer body differs"
                        );
                    }
                    Outcome::Reject => {
                        let error = result.err().context("unsupported closer accepted")?;
                        ensure!(
                            error.to_string().contains("line 10:")
                                && error.to_string().contains("plain fences only"),
                            "{candidate:?}: {error:#}"
                        );
                    }
                }
                coverage.record("closer-product", true);
            }
        }
    }
    coverage.check()?;
    // A two-backtick case-looking opener is ordinary text under the existing D3 subset.
    let fences = document_fences(&complete_document(
        "## 7. Cases\n``toml,case=R6\n## 8. End\n",
    ))?;
    ensure!(fences.is_empty(), "short opener became a fence");
    let outside = complete_document("## 7. Cases\n## 8. End\n```text\nbefore\n````\nafter\n```\n");
    let outside_fences = document_fences(&outside)?;
    ensure!(
        outside_fences.len() == 1
            && outside_fences
                .first()
                .context("outside fence missing")?
                .body
                == "before\n````\nafter",
        "outside longer run prematurely closed the fence"
    );
    Ok(())
}

/// # Errors
/// Returns a malformed layout whose diagnostic omits its actionable coordinates.
pub(super) fn diagnostics() -> anyhow::Result<()> {
    for (line, detail) in [
        (" ```", "indent width=1"),
        ("   ```", "indent width=3"),
        ("    ```", "indent width=4"),
        ("````", "backtick count=4"),
        ("```\t", "tab=true"),
        ("\t```", "tab=true"),
    ] {
        let markdown = complete_document(&format!("## 7. Cases\n```text\na\n{line}\n## 8. End\n"));
        let error = document_fences(&markdown)
            .err()
            .context("unsupported layout accepted")?;
        ensure!(
            error.to_string().contains(detail),
            "missing {detail}: {error:#}"
        );
    }
    let markdown = complete_document("## 7. Cases\n## 8. End\n");
    let error = document_fences(&format!("{markdown}## 14. Extra\n"))
        .err()
        .context("surplus heading accepted")?;
    ensure!(
        error.to_string().contains("surplus heading")
            && error.to_string().contains("13 sections")
            && error.to_string().matches("## 14.").count() == 1,
        "surplus diagnostic: {error:#}"
    );
    Ok(())
}
