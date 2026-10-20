//! GUIDE-derived environment contracts without process-global mutation.

use alloc::collections::BTreeMap;

use anyhow::{Context as _, ensure};

use super::grammar::Case;

pub(super) struct EnvSpec {
    pub target: String,
    pub secret: bool,
}

pub(super) fn guide_specs(guide: &str) -> anyhow::Result<BTreeMap<String, EnvSpec>> {
    let (_, after) = guide
        .split_once("<!-- BEGIN ENV_OVERRIDE_TABLE -->")
        .context("GUIDE env table start")?;
    let (table, _) = after
        .split_once("<!-- END ENV_OVERRIDE_TABLE -->")
        .context("GUIDE env table end")?;
    let mut specs = BTreeMap::new();
    for line in table
        .lines()
        .filter(|line| line.trim_start().starts_with("| `"))
    {
        let cells: Vec<_> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        ensure!(cells.len() == 4, "GUIDE env table requires four cells");
        let name = cells.first().context("env name")?.trim_matches('`');
        let target = cells
            .get(1)
            .context("env target")?
            .trim_matches('`')
            .to_owned();
        let secret = cells.get(3).context("env notes")?.contains("secret");
        ensure!(
            specs
                .insert(name.to_owned(), EnvSpec { target, secret })
                .is_none(),
            "duplicate GUIDE env name {name}"
        );
    }
    ensure!(!specs.is_empty(), "GUIDE env table has zero variables");
    Ok(specs)
}

pub(super) fn parse_env(block: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for line in block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        let (name, raw) = assignment
            .split_once('=')
            .context("env line requires NAME=value")?;
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                && !name.starts_with(char::is_numeric),
            "invalid env variable name {name}"
        );
        let value = if raw.starts_with(['\'', '"']) {
            let quote = raw.chars().next().context("quote")?;
            raw.strip_prefix(quote)
                .and_then(|inner| inner.strip_suffix(quote))
                .context("unclosed quoted env value")?
                .to_owned()
        } else {
            ensure!(
                !raw.contains(char::is_whitespace),
                "unquoted env value contains whitespace for {name}"
            );
            raw.to_owned()
        };
        ensure!(
            values.insert(name.to_owned(), value).is_none(),
            "duplicate env variable {name}"
        );
    }
    Ok(values)
}

pub(super) fn lookup<'value>(
    root: &'value toml::Value,
    target: &str,
) -> Option<&'value toml::Value> {
    target
        .split('.')
        .try_fold(root, |value, key| value.get(key))
}

fn matches_toml(raw: &str, value: &toml::Value) -> anyhow::Result<bool> {
    match value {
        toml::Value::String(text) => Ok(raw == text),
        toml::Value::Boolean(boolean) => Ok(raw == boolean.to_string()),
        toml::Value::Integer(integer) => Ok(raw == integer.to_string()),
        toml::Value::Array(items) => {
            let strings = items
                .iter()
                .map(|item| item.as_str().context("env list must contain strings"))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(raw.split(',').map(str::trim).collect::<Vec<_>>() == strings)
        }
        toml::Value::Float(_) | toml::Value::Datetime(_) | toml::Value::Table(_) => {
            anyhow::bail!("unsupported env target value")
        }
    }
}

pub(super) fn check_env(case: &Case, specs: &BTreeMap<String, EnvSpec>) -> anyhow::Result<()> {
    let config: toml::Value = toml::from_str(&case.toml)?;
    for block in &case.env {
        for (name, raw) in parse_env(block)? {
            let spec = specs
                .get(&name)
                .with_context(|| format!("unknown GUIDE variable {name}"))?;
            if !spec.secret && !name.ends_with("_FILE") {
                let value = lookup(&config, &spec.target)
                    .with_context(|| format!("{name}: TOML target {} missing", spec.target))?;
                ensure!(
                    matches_toml(&raw, value)?,
                    "env {name} differs from TOML {}",
                    spec.target
                );
            }
        }
    }
    let main = parse_env(case.env.first().context("main env block")?)?;
    for (name, spec) in specs {
        let new_knob = spec
            .target
            .strip_prefix("server.auth.oauth.")
            .is_some_and(|key| {
                matches!(
                    key,
                    "challenge_scopes"
                        | "insufficient_scope_challenge"
                        | "additional_audiences"
                        | "accept_resource_audience"
                        | "omit_error_on_missing_credential"
                        | "proxy.mode"
                        | "proxy.sealing_secret"
                        | "proxy.sealing_secret_previous"
                        | "proxy.consent_ttl"
                )
            });
        if new_knob && lookup(&config, &spec.target).is_some() {
            ensure!(
                main.keys().any(|key| specs
                    .get(key)
                    .is_some_and(|candidate| candidate.target == spec.target)),
                "env {name}: configured new knob {} missing from main sh block",
                spec.target
            );
        }
    }
    Ok(())
}
