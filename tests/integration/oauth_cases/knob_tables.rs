//! Paired controls for new-knob and new-env-var coverage over inline cases.

use alloc::collections::BTreeMap;

use anyhow::ensure;

use super::{
    environment::guide_specs,
    grammar::Case,
    knobs::{check_env_vars, check_knobs},
};

const GUIDE: &str = "<!-- BEGIN ENV_OVERRIDE_TABLE -->\n| `K_LIST` | `server.auth.oauth.challenge_scopes` | list | normal |\n| `K_FILE` | `server.auth.oauth.proxy.sealing_secret` | path | secret |\n<!-- END ENV_OVERRIDE_TABLE -->";
const KNOBS: &[&str] = &[
    "server.auth.oauth.challenge_scopes",
    "server.auth.oauth.proxy.sealing_secret",
    "server.auth.oauth.proxy.expose_admin_endpoints",
];
const ALL: &str = "[server.auth.oauth]\nchallenge_scopes = ['a']\n[server.auth.oauth.proxy]\nsealing_secret = 'x'\nexpose_admin_endpoints = true\n";
const NO_SECRET: &str = "[server.auth.oauth]\nchallenge_scopes = ['a']\n[server.auth.oauth.proxy]\nexpose_admin_endpoints = true\n";
const NO_ADMIN: &str = "[server.auth.oauth]\nchallenge_scopes = ['a']\n[server.auth.oauth.proxy]\nsealing_secret = 'x'\n";

const VARS: &[&str] = &["K_LIST", "K_FILE"];

/// One row: rule, cases as (TOML, env blocks), required names, and the fragment a rejection names.
type Row = (
    &'static str,
    &'static [(&'static str, &'static [&'static str])],
    &'static [&'static str],
    Option<&'static str>,
);

const ROWS: &[Row] = &[
    ("knob", &[(ALL, &["# none"])], KNOBS, None),
    ("knob", &[(NO_SECRET, &["K_FILE=/run/fake"])], KNOBS, None),
    (
        "knob",
        &[(NO_SECRET, &["# main", "K_FILE=/run/fake"])],
        KNOBS,
        None,
    ),
    (
        "knob",
        &[
            (NO_ADMIN, &["# none"]),
            (
                "[server]\n[server.auth.oauth.proxy]\nexpose_admin_endpoints = false\n",
                &["# none"],
            ),
        ],
        KNOBS,
        None,
    ),
    (
        "knob",
        &[(NO_ADMIN, &["# none"])],
        KNOBS,
        Some("proxy.expose_admin_endpoints is configured by no case"),
    ),
    (
        "knob",
        &[(NO_SECRET, &["K_LIST=a"])],
        KNOBS,
        Some("proxy.sealing_secret is configured by no case"),
    ),
    (
        "knob",
        &[(NO_SECRET, &["K_OTHER=/run/fake"])],
        KNOBS,
        Some("proxy.sealing_secret is configured by no case"),
    ),
    (
        "env-var",
        &[(ALL, &["K_LIST=a\nK_FILE=/run/fake"])],
        VARS,
        None,
    ),
    (
        "env-var",
        &[(ALL, &["K_LIST=a"]), (ALL, &["# main", "K_FILE=/run/fake"])],
        VARS,
        None,
    ),
    (
        "env-var",
        &[(ALL, &["K_LIST=a"])],
        VARS,
        Some("new env var K_FILE appears in no case env block"),
    ),
    (
        "env-var",
        &[(ALL, &["K_LIST=a\nK_FILE=/run/fake\nK_UNKNOWN=x"])],
        &["K_LIST", "K_FILE", "K_UNKNOWN"],
        Some("K_UNKNOWN is not in the GUIDE env table"),
    ),
];

/// Coverage accepts a knob set by TOML or any env block and rejects an unconfigured knob or unshown var.
#[test]
fn knob_and_env_coverage_distinguish_when_a_case_configures_or_omits_them() -> anyhow::Result<()> {
    let specs = guide_specs(GUIDE)?;
    let mut coverage = BTreeMap::<&str, (bool, bool)>::new();
    for &(rule, inputs, names, rejection) in ROWS {
        // Given: inline cases with their TOML and env blocks.
        let cases: Vec<_> = inputs
            .iter()
            .map(|&(toml, env)| Case {
                id: "K".into(),
                toml: toml.into(),
                env: env.iter().map(|block| (*block).to_owned()).collect(),
                exchanges: Vec::new(),
            })
            .collect();
        // When: check the rule's coverage.
        let result = if rule == "knob" {
            check_knobs(&cases, &specs, names)
        } else {
            check_env_vars(&cases, &specs, names)
        };
        // Then: acceptance matches and a rejection names the uncovered knob or variable.
        match (&result, rejection) {
            (Ok(()), None) => {}
            (Err(error), Some(fragment)) => {
                ensure!(error.to_string().contains(fragment), "{rule}: {error:#}");
            }
            (Ok(()), Some(fragment)) => anyhow::bail!("{rule}: accepted although {fragment}"),
            (Err(error), None) => anyhow::bail!("{rule}: rejected: {error:#}"),
        }
        let covered = coverage.entry(rule).or_default();
        if rejection.is_none() {
            covered.0 = true;
        } else {
            covered.1 = true;
        }
    }
    ensure!(
        coverage.len() == 2 && coverage.values().all(|pair| *pair == (true, true)),
        "coverage rows lack pairs: {coverage:?}"
    );
    Ok(())
}
