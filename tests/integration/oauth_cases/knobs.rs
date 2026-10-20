//! Every new knob is configured, and every new env var is shown, by some case.

use alloc::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, ensure};

use super::{
    environment::{EnvSpec, lookup, parse_env},
    grammar::Case,
};

/// Knobs introduced with the authorization-server work, as dotted TOML paths.
pub(super) const NEW_KNOBS: &[&str] = &[
    "server.auth.oauth.accept_resource_audience",
    "server.auth.oauth.additional_audiences",
    "server.auth.oauth.challenge_scopes",
    "server.auth.oauth.insufficient_scope_challenge",
    "server.auth.oauth.omit_error_on_missing_credential",
    "server.auth.oauth.proxy.mode",
    "server.auth.oauth.proxy.consent_ttl",
    "server.auth.oauth.proxy.expose_admin_endpoints",
    "server.auth.oauth.proxy.require_auth_on_admin_endpoints",
    "server.auth.oauth.proxy.sealing_secret",
    "server.auth.oauth.proxy.sealing_secret_previous",
];

/// Env vars introduced for those knobs.
pub(super) const NEW_ENV_VARS: &[&str] = &[
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__CHALLENGE_SCOPES",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__INSUFFICIENT_SCOPE_CHALLENGE",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ADDITIONAL_AUDIENCES",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ACCEPT_RESOURCE_AUDIENCE",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__OMIT_ERROR_ON_MISSING_CREDENTIAL",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__MODE",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__CONSENT_TTL",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_FILE",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_PREVIOUS",
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_PREVIOUS_FILE",
];

fn env_names(case: &Case) -> anyhow::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for block in &case.env {
        names.extend(parse_env(block)?.into_keys());
    }
    Ok(names)
}

/// Each knob has its TOML key, or an env var targeting it, in at least one case.
pub(super) fn check_knobs(
    cases: &[Case],
    specs: &BTreeMap<String, EnvSpec>,
    knobs: &[&str],
) -> anyhow::Result<()> {
    for knob in knobs {
        let mut configured_by = None;
        for case in cases {
            let config = toml::Value::Table(toml::from_str::<toml::Table>(&case.toml)?);
            let by_env = env_names(case)?
                .iter()
                .any(|name| specs.get(name).is_some_and(|spec| spec.target == *knob));
            if lookup(&config, knob).is_some() || by_env {
                configured_by = Some(case.id.as_str());
                break;
            }
        }
        let case =
            configured_by.with_context(|| format!("new knob {knob} is configured by no case"))?;
        tracing::info!(knob, case, "new knob configured");
    }
    Ok(())
}

/// The union of all env block names contains every listed variable, each a GUIDE variable.
pub(super) fn check_env_vars(
    cases: &[Case],
    specs: &BTreeMap<String, EnvSpec>,
    names: &[&str],
) -> anyhow::Result<()> {
    let mut union = BTreeSet::new();
    for case in cases {
        union.extend(env_names(case)?);
    }
    for name in names {
        ensure!(
            specs.contains_key(*name),
            "{name} is not in the GUIDE env table"
        );
        ensure!(
            union.contains(*name),
            "new env var {name} appears in no case env block"
        );
        tracing::info!(name, "new env var shown");
    }
    Ok(())
}
