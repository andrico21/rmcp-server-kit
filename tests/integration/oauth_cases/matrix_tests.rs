//! The documented settings matrices and env blocks agree with the executed cases.

use std::{fs::read_to_string, path::Path};

use anyhow::{Context as _, ensure};

use super::{
    environment::guide_specs,
    grammar::{Case, parse_cases},
    knobs::{NEW_ENV_VARS, NEW_KNOBS, check_env_vars, check_knobs},
    matrix::{PROXY, RESOURCE},
    matrix_check::{check_layout, check_matrix},
};

/// Section seven of a numbered guide, from its heading to the next numbered heading.
pub(super) fn section_seven(markdown: &str) -> anyhow::Result<&str> {
    let start = markdown.find("\n## 7. ").context("section 7 heading")?;
    let rest = markdown
        .get(start.saturating_add(1)..)
        .context("section 7 body")?;
    let end = rest.find("\n## 8. ").context("section 8 heading")?;
    rest.get(..end).context("section 7 slice")
}

fn documents() -> anyhow::Result<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok((
        read_to_string(root.join("docs/OAUTH_PROXY.md")).context("read OAuth guide")?,
        read_to_string(root.join("docs/GUIDE.md")).context("read GUIDE")?,
    ))
}

fn documented_cases(markdown: &str) -> anyhow::Result<Vec<Case>> {
    let cases = parse_cases(markdown)?;
    super::catalogue::check(&cases)?;
    Ok(cases)
}

/// Every checked matrix cell equals its case config, and every new knob is configured by a case.
#[test]
fn settings_matrices_match_case_configs() -> anyhow::Result<()> {
    let _subscriber = tracing_subscriber::fmt().with_test_writer().try_init();
    // Given: the executed case catalogue and the GUIDE env table.
    let (markdown, guide) = documents()?;
    let cases = documented_cases(&markdown)?;
    let section = section_seven(&markdown)?;
    // When: compare both matrices, the settings lines and the knob coverage.
    let resource = check_matrix(section, &RESOURCE, &cases)?;
    let proxy = check_matrix(section, &PROXY, &cases)?;
    check_layout(section, &cases)?;
    check_knobs(&cases, &guide_specs(&guide)?, NEW_KNOBS)?;
    // Then: every row carries checked cells.
    ensure!(resource > 0 && proxy > 0, "matrices checked zero cells");
    tracing::info!(
        resource,
        proxy,
        cases = cases.len(),
        "settings matrices checked"
    );
    Ok(())
}

/// Every new env var appears in at least one case env block, main or alternative.
#[test]
fn case_env_blocks_cover_every_new_env_var() -> anyhow::Result<()> {
    let _subscriber = tracing_subscriber::fmt().with_test_writer().try_init();
    // Given: the executed case catalogue and the GUIDE env table.
    let (markdown, guide) = documents()?;
    let cases = documented_cases(&markdown)?;
    let specs = guide_specs(&guide)?;
    // When: collect the env block union.
    check_env_vars(&cases, &specs, NEW_ENV_VARS)?;
    // Then: each new variable targets one of the new knobs.
    for name in NEW_ENV_VARS {
        let target = &specs.get(*name).context("GUIDE variable")?.target;
        ensure!(
            NEW_KNOBS.contains(&target.as_str()),
            "{name} targets {target}, which is not a new knob"
        );
    }
    Ok(())
}
