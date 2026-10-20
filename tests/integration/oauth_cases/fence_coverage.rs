//! Generated-versus-executed row accounting for fence rule groups.

extern crate alloc;

use anyhow::ensure;

use self::alloc::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Coverage {
    planned: BTreeMap<&'static str, usize>,
    executed: BTreeMap<&'static str, usize>,
}

impl Coverage {
    pub(super) fn plan(&mut self, rule: &'static str, rows: usize) {
        let count = self.planned.entry(rule).or_default();
        *count = count.saturating_add(rows);
    }

    pub(super) fn record(&mut self, rule: &'static str, executed: bool) {
        if executed {
            let count = self.executed.entry(rule).or_default();
            *count = count.saturating_add(1);
        }
    }

    /// # Errors
    /// Returns a rule group with any unexecuted or surplus assertion rows.
    pub(super) fn check(&self) -> anyhow::Result<()> {
        ensure!(
            self.planned == self.executed,
            "fence row coverage differs: planned={:?}, executed={:?}",
            self.planned,
            self.executed
        );
        Ok(())
    }
}

/// # Errors
/// Returns success only when one skipped row cannot satisfy a multi-row group.
pub(super) fn skipped_row() -> anyhow::Result<()> {
    let mut coverage = Coverage::default();
    coverage.plan("case-id", 2);
    coverage.record("case-id", true);
    coverage.record("case-id", false);
    ensure!(coverage.check().is_err(), "skipped row counted");
    Ok(())
}
