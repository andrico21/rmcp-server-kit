//! Executed documentation inventory, extended alongside new case examples.

use std::{fs::read_to_string, path::Path};

use anyhow::{Context as _, ensure};

use super::grammar::Case;

const EXPECTED_CASES: &[(&str, usize)] = &[("R6", 2)];

pub(super) fn check(cases: &[Case]) -> anyhow::Result<()> {
    let observed: Vec<_> = cases
        .iter()
        .map(|case| (case.id.as_str(), case.exchanges.len()))
        .collect();
    ensure!(
        observed == EXPECTED_CASES,
        "executed case catalogue differs: {observed:?}; expected {EXPECTED_CASES:?}"
    );
    Ok(())
}

/// Missing or surplus cases and exchanges cannot satisfy the exact executed inventory.
#[test]
fn catalogue_rejects_when_a_case_or_exchange_is_missing() -> anyhow::Result<()> {
    // Given: the runtime document and its independently pinned inventory.
    let markdown =
        read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/OAUTH_PROXY.md"))?;
    let mut cases = super::grammar::parse_cases(&markdown)?;
    // When/Then: check complete, missing-case, and missing-exchange inventories.
    check(&cases)?;
    let error = check(&[]).err().context("missing catalogue accepted")?;
    ensure!(error.to_string().contains("R6"));
    let case = cases.first_mut().context("R6 missing")?;
    let _removed = case.exchanges.pop().context("second R6 exchange missing")?;
    ensure!(check(&cases).is_err(), "missing exchange accepted");
    Ok(())
}

/// Extra exchanges or case IDs require an explicit inventory update.
#[test]
fn catalogue_rejects_when_an_exchange_or_case_is_added() -> anyhow::Result<()> {
    // Given: independent catalogue variants built from a minimal valid case.
    let exchange = "```http,case=R6,request\nGET / HTTP/1.1\n```\n```http,case=R6,response\nHTTP/1.1 200 OK\n```\n";
    let base = format!(
        "```toml,case=R6\n[server]\n```\n```sh,case=R6\n# no overrides\n```\n{exchange}{exchange}"
    );
    for (extra, reason) in [
        (exchange.to_owned(), "extra exchange"),
        (base.replace("case=R6", "case=A1"), "A1"),
        (base.replace("case=R6", "case=R6A"), "R6A"),
        (base.replace("case=R6", "case=R7"), "R7"),
        (base.replace("case=R6", "case=Z9"), "Z9"),
    ] {
        let markdown = super::fence_tables::complete_document(&format!(
            "## 7. Cases\n{base}{extra}## 8. End\n"
        ));
        let cases = super::grammar::parse_cases(&markdown)?;
        // When: compare the changed inventory with EXPECTED_CASES.
        let error = check(&cases)
            .err()
            .with_context(|| format!("{reason} accepted"))?;
        // Then: the inventory error includes the observed excess.
        ensure!(
            error.to_string().contains("catalogue differs")
                && error.to_string().contains(if reason == "extra exchange" {
                    "R6"
                } else {
                    reason
                }),
            "{reason}: {error:#}"
        );
    }
    Ok(())
}
