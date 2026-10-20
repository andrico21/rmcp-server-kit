//! Paired, generated controls for executed library-call exchanges.

use alloc::collections::BTreeMap;

use anyhow::{Context as _, ensure};
use tokio::task::spawn_blocking;

use super::{
    fixtures::fence, grammar::parse_cases, identity::Identity, library::RULES, library_rows::rows,
    runtime::run_case,
};

/// Library-call exchanges execute only `exchange_token` and assert their own upstream request.
// cancel-safe: each run_case owns its mock, listener and bounded requests.
#[tokio::test]
async fn library_table_distinguishes_when_call_or_upstream_drifts() -> anyhow::Result<()> {
    let identity = spawn_blocking(Identity::generate).await??;
    let mut coverage = BTreeMap::<&str, (bool, bool)>::new();
    for row in rows().iter().flatten() {
        // Given: an independent case document; no state is carried between rows.
        let document = super::fence_tables::complete_document(&format!(
            "## 7. Cases\n{}{}{}## 8. End\n",
            fence("toml,case=X", &row.config),
            fence("sh,case=X", "# no overrides"),
            row.exchanges
        ));
        let cases = parse_cases(&document)?;
        // When: execute every exchange through the real library and loopback IdP.
        let result = run_case(cases.first().context("case")?, &identity).await;
        // Then: acceptance matches, and a rejection names the case, exchange and reason.
        ensure!(
            result.is_ok() == row.passes,
            "{}: {result:#?}\n{}",
            row.rule,
            row.exchanges
        );
        if let Err(error) = &result {
            let message = format!("{error:#}");
            ensure!(
                message.contains("case X exchange ") && message.contains(&row.needle),
                "{}: rejection lacks context {:?}: {message}",
                row.rule,
                row.needle
            );
        }
        let covered = coverage.entry(row.rule).or_default();
        if row.passes {
            covered.0 = true;
        } else {
            covered.1 = true;
        }
    }
    for rule in RULES {
        ensure!(
            coverage.get(rule) == Some(&(true, true)),
            "library rule {rule} lacks paired coverage"
        );
    }
    ensure!(
        coverage.len() == RULES.len(),
        "library rule coverage drifted"
    );
    Ok(())
}
