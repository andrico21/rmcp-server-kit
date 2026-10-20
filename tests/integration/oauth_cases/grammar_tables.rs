//! Section boundaries and malformed case-fence controls.

use anyhow::{Context as _, ensure};

use super::{
    fixtures::{document, exchange, fence},
    grammar::parse_cases,
};

/// Case-looking malformed fences are errors with source context rather than silent omissions.
#[test]
fn grammar_rejects_when_case_fences_are_malformed() -> anyhow::Result<()> {
    // Given: a complete valid case and independent malformed fence infos.
    let valid = document(&exchange("POST /mcp HTTP/1.1", "HTTP/1.1 401 Unauthorized"));
    for info in [
        "toml, case=X",
        "toml,case=",
        "toml,case=X/../x;$",
        "toml,case=12345678901234567",
        "http,Case=X,upstream",
        "http,CASE=X,upstream",
    ] {
        let markdown = valid.replace("## 8. End", &format!("{}## 8. End", fence(info, "unused")));
        let _lexical_error = super::case_info::validate_document(&markdown)
            .err()
            .with_context(|| format!("lexical validator accepted {info:?}"))?;
        // When: parse case-looking input.
        let error = parse_cases(&markdown)
            .err()
            .with_context(|| format!("accepted {info:?}"))?;
        // Then: the offending info is quoted, including empty IDs.
        ensure!(
            format!("{error:#}").contains(info),
            "info omitted: {error:#}"
        );
    }
    for indentation in [" ", "  ", "\t"] {
        let markdown = valid.replace("```toml,case=X", &format!("{indentation}```toml,case=X"));
        let _lexical_error = super::case_info::validate_document(&markdown)
            .err()
            .context("lexical validator skipped indented case")?;
        let _error = parse_cases(&markdown)
            .err()
            .context("indented case accepted")?;
        let extra = valid.replace(
            "## 8. End",
            &format!("{indentation}```toml,case=EXTRA\n[server]\n```\n## 8. End"),
        );
        let _extra_error = parse_cases(&extra)
            .err()
            .context("indented extra case silently skipped")?;
    }
    Ok(())
}

/// Only section seven owns cases, and misplaced examples name their heading.
#[test]
fn cases_reject_when_placed_outside_section_seven() -> anyhow::Result<()> {
    let valid = document(&exchange("POST /mcp HTTP/1.1", "HTTP/1.1 401 Unauthorized"));
    for heading in ["## 6. Earlier", "## 8. Later"] {
        // Given: a misplaced complete example, with or without a valid section seven.
        for markdown in [
            valid.replace("## 7. Cases", heading),
            format!("{valid}{heading}\n{}", fence("toml,case=OUT", "[server]")),
        ] {
            // When: parse section-scoped examples.
            let error = parse_cases(&markdown)
                .err()
                .context("outside case accepted")?;
            // Then: the placement diagnostic identifies the heading.
            ensure!(
                format!("{error:#}").contains(heading),
                "heading omitted: {error:#}"
            );
        }
    }
    ensure!(
        parse_cases("## 6. Earlier\nno cases\n## 8. Later").is_err(),
        "zero cases accepted"
    );
    ensure!(parse_cases(&valid)?.len() == 1, "section seven rejected");
    Ok(())
}

/// Only prose, never another fence, may separate request and response.
#[test]
fn pairing_rejects_when_another_fence_interrupts_exchange() -> anyhow::Result<()> {
    for (between, passes) in [
        ("prose\n".to_owned(), true),
        (fence("text", "illustration"), false),
        (fence("rust,ignore", "example()"), false),
    ] {
        // Given: one complete exchange with one intervening block.
        let tail = exchange("POST /mcp HTTP/1.1", "HTTP/1.1 401 Unauthorized")
            .replace("prose\n", &between);
        // When: pair the exchange fences.
        let result = parse_cases(&document(&tail));
        // Then: intervening fences fail with case context.
        ensure!(
            result.is_ok() == passes,
            "intervening fence acceptance differs"
        );
        if let Err(error) = result {
            ensure!(format!("{error:#}").contains('X'), "case omitted");
        }
    }
    Ok(())
}

/// Header token validation happens while parsing the case, not during network execution.
#[test]
fn headers_reject_when_names_are_not_http_tokens() -> anyhow::Result<()> {
    for (header, passes) in [
        ("X-Name: yes", true),
        ("Bad Name: yes", false),
        ("Bad(Name): yes", false),
    ] {
        let input = document(&exchange(
            &format!("POST /mcp HTTP/1.1\n{header}"),
            "HTTP/1.1 401 Unauthorized",
        ));
        let result = parse_cases(&input);
        ensure!(
            result.is_ok() == passes,
            "header {header:?} acceptance differs"
        );
        if let Err(error) = result {
            ensure!(format!("{error:#}").contains(header), "header line omitted");
        }
    }
    Ok(())
}
