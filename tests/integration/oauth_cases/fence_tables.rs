//! Independent plain-fence and numbered-document controls shared by both targets.

use anyhow::{Context as _, ensure};

use super::case_info::{document_fences, validate_document};

#[path = "fence_product.rs"]
mod product;

#[path = "fence_bytes.rs"]
mod bytes;

#[path = "fence_coverage.rs"]
mod coverage;

use coverage::Coverage;

pub(crate) fn complete_document(middle: &str) -> String {
    let prefix = "## 1. Section\n## 2. Section\n## 3. Section\n## 4. Section\n## 5. Section\n## 6. Section\n";
    let suffix = "## 9. Section\n## 10. Section\n## 11. Section\n## 12. Section\n## 13. Section\n";
    format!("{prefix}{middle}\n{suffix}\n")
}

const ROWS: &[(&str, &str, bool)] = &[
    ("plain", "```text\na\n```\n", true),
    ("plain", "```text   \na\n```   \n", true),
    ("plain", "```\na\n```\n", true),
    ("plain", "``\na\n``\n", true),
    ("plain", "### 7.1 Subsection\n", true),
    ("plain", "    ## 8. Content\n", true),
    ("plain", "```text\n    ## 8. Content\n```\n", true),
    ("indent", " ```text\na\n```\n", false),
    ("indent", "   ```text\na\n```\n", false),
    ("indent", "    ```text\n    a\n    ```\n", false),
    ("indent", "\t```text\n\ta\n\t```\n", false),
    ("indent", "\t```text\na\n```\n", false),
    ("indent", "  \t```text\na\n```\n", false),
    ("indent", "```text\na\n ```\n", false),
    ("indent", "```text\na\n   ```\n", false),
    ("indent", "```text\na\n    ```\n```\n", false),
    ("indent", "```text\na\n```\t\n", false),
    ("indent", "```\ttext\na\n```\n", false),
    ("tilde", "~~~text\n```\n~~~\n", false),
    ("tilde", "```text\n~~~\n```\n", false),
    ("length", "````text\n```\n````\n", false),
    ("length", "```text\na\n````\n", false),
    ("length", "````toml,case=R6\nx\n````\n", false),
    ("containers", "> ```text\n> a\n> ```\n", false),
    ("containers", "> ```text\n> a\n\n", false),
    ("containers", ">> ```text\n>> a\n>> ```\n", false),
    ("containers", "- ```text\n  a\n  ```\n", false),
    ("containers", "1. ```sh\n   a\n   ```\n", false),
    ("containers", "2) ```text\na\n```\n", false),
    ("containers", "* ```text\na\n```\n", false),
    ("containers", "+ ```text\na\n```\n", false),
    ("containers", "- note\n  ```text\n  a\n  ```\n", false),
    (
        "containers",
        "- ```http,case=R6,request\nPOST /mcp HTTP/1.1\n```\n",
        false,
    ),
    ("inline", "```R6``` is the pilot\n", false),
    ("inline", "``` aa ` b\nfoo\n", false),
    ("html", "<!-- note -->\n", false),
    ("html", "<!--\n```\n-->\n", false),
    ("html", "```text\n<!-- note -->\n```\n", false),
    ("nested", "```text\n```json\n```\n", false),
    ("inline", "```text\n``` ```\n```\n", false),
    ("unclosed", "```text\na\n", false),
    ("crlf", "ordinary\rtext\n", false),
];

/// Ambiguous layouts fail loudly while plain fences preserve bodies and source locations.
///
/// # Errors
/// Returns the independent row whose extraction or rejection differs.
#[test]
fn cases_are_visible_when_unrelated_fences_close() -> anyhow::Result<()> {
    product::heading_order()?;
    product::closer_product()?;
    product::diagnostics()?;
    bytes::boundaries()?;
    let mut covered = Coverage::default();
    for &(rule, _, _) in ROWS {
        covered.plan(rule, 1);
    }
    for &(rule, content, passes) in ROWS {
        // Given: one independent section-seven layout.
        let markdown = complete_document(&format!("## 7. Cases\n{content}## 8. End\n"));
        // When: scan through the exact function used by both consumers.
        let result = document_fences(&markdown);
        // Then: no unsupported layout is silently skipped.
        ensure!(
            result.is_ok() == passes,
            "{rule}: {content:?}: acceptance differs"
        );
        if let Err(error) = result {
            let reason = match rule {
                "html" => "HTML comments",
                "nested" => "nested fences",
                "unclosed" => "unclosed fence",
                "crlf" => "carriage return",
                "plain" | "indent" | "tilde" | "length" | "containers" | "inline" => {
                    "plain fences only"
                }
                _ => anyhow::bail!("unknown fence row {rule}"),
            };
            ensure!(
                format!("{error:#}").contains("line") && format!("{error:#}").contains(reason),
                "missing location: {error:#}"
            );
        }
        covered.record(rule, true);
    }
    let plain = complete_document("## 7. Cases\n```text\nbody\n```\n## 8. End\n");
    for markdown in [plain.clone(), plain.replace('\n', "\r\n")] {
        let fences = document_fences(&markdown)?;
        let block = fences.first().context("plain fence missing")?;
        ensure!(
            fences.len() == 1 && block.body == "body" && block.info == "text" && block.line == 8,
            "plain/CRLF extraction differs"
        );
    }
    let skeletons = [
        ("## 7. Cases\n", ""),
        ("## 6. Section", "## 6. Section\n## 6. Duplicate"),
        ("## 7. Cases", "## 17. Cases"),
        ("## 7. Cases", "## 7. Cases\n## 7.1 Sub"),
        ("## 13. Section", "## 13. Section\n## 14. Extra"),
        ("body", "## 8. Hidden"),
        ("## 13. Section", ""),
    ];
    covered.plan("skeleton", skeletons.len());
    for (from, to) in skeletons {
        let error = document_fences(&plain.replace(from, to))
            .err()
            .context("bad skeleton accepted")?;
        ensure!(
            format!("{error:#}").contains("heading"),
            "skeleton context: {error:#}"
        );
        covered.record("skeleton", true);
    }
    outside_cases(&plain, &mut covered)?;
    check_ids(&mut covered)?;
    covered.check()?;
    coverage::skipped_row()?;
    Ok(())
}

/// # Errors
/// Returns an outside-section row with incorrect extraction or rejection.
fn outside_cases(plain: &str, covered: &mut Coverage) -> anyhow::Result<()> {
    let prefixes = [
        "", " ", "    ", "\t", "> ", ">> ", "- ", "* ", "+ ", "1. ", "2) ", "> - ",
    ];
    let markers = ["```", "~~~", "````"];
    let keys = ["case=", "Case=", "CASE =", "case   ="];
    covered.plan(
        "outside-case",
        prefixes
            .len()
            .saturating_mul(markers.len())
            .saturating_mul(keys.len()),
    );
    for prefix in prefixes {
        for marker in markers {
            for key in keys {
                let markdown = format!("{plain}{prefix}{marker}toml,{key}OUT\nx\n{marker}\n");
                let error = validate_document(&markdown)
                    .err()
                    .context("outside case accepted")?;
                ensure!(
                    format!("{error:#}").contains("outside section 7"),
                    "outside diagnostic: {error:#}"
                );
                covered.record("outside-case", true);
            }
        }
    }
    let outside_rows = [
        ("```toml\n[server]\n```\n", 2),
        ("  ```toml\n[server]\n  ```\n", 1),
        ("  ```toml\n[server]\n```\n", 1),
        ("\t```toml\n[server]\n\t```\n", 1),
        ("> ```toml\n> [server]\n> ```\n", 1),
        ("- ```toml\n  [server]\n  ```\n", 1),
        ("~~~toml\nx\n~~~\n", 1),
    ];
    covered.plan("outside-plain", outside_rows.len());
    for (outside, count) in outside_rows {
        let fences = document_fences(&format!("{plain}{outside}"))?;
        ensure!(
            fences.len() == count,
            "outside plain extraction: {outside:?}"
        );
        covered.record("outside-plain", true);
    }
    Ok(())
}

/// # Errors
/// Returns a case identifier whose acceptance differs from the grammar.
fn check_ids(covered: &mut Coverage) -> anyhow::Result<()> {
    let rows = [
        ("R.6", false),
        ("ABCDEFGHIJKLMNOPQ", false),
        ("", false),
        ("R\u{e9}", false),
        ("ABCDEFGHIJKLMNOP", true),
    ];
    covered.plan("case-id", rows.len());
    for (id, passes) in rows {
        let markdown = complete_document(&format!(
            "## 7. Cases\n```toml,case={id}\nx\n```\n## 8. End\n"
        ));
        ensure!(
            validate_document(&markdown).is_ok() == passes,
            "case ID {id:?}"
        );
        covered.record("case-id", true);
    }
    Ok(())
}
