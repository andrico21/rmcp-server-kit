//! Paired accepted and rejected matrix variants over a small independent fixture.

use alloc::collections::BTreeMap;

use anyhow::{Context as _, ensure};

use super::{
    grammar::Case,
    matrix::{PROXY, RESOURCE, RULES},
    matrix_check::{check_layout, check_matrix},
};

pub(super) const A1_ROW: &str = r#"| [A1](#a1---first) | `"https://mcp.example"` | `"mcp-example"` | - | - | - | `"groups"` | `["mcp:read"]` | - | - | - | - | groups mapper |"#;
pub(super) const B2_ROW: &str = r#"| [B2](#b2---second-case) | - | `"mcp-example"` | - | `true` | - | scopes | - | - | - | table | - | audience mapper |"#;
pub(super) const P_ROW: &str = r#"| [B2](#b2---second-case) | `"authorization_server"` | set | - | set (file) | set | `"30d"` | - | `https://mcp.example/callback` |"#;
const RES_HEAD: &str = "| Case | `public_url` | `audience` | `audience_validation_mode` | `accept_resource_audience` | `additional_audiences` | Roles from | `challenge_scopes` | `insufficient_scope_challenge` | `omit_error_on_missing_credential` | `token_exchange` | `authorization_servers` | Keycloak side |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |";
const PROXY_HEAD: &str = "| Case | `mode` | `client_secret` | `strip_resource_param` | `sealing_secret` | `sealing_secret_previous` | `consent_ttl` | `expose_admin_endpoints` | Keycloak redirect URIs |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |";
const A1_TOML: &str = "[server]\npublic_url = \"https://mcp.example\"\n[server.auth.oauth]\naudience = \"mcp-example\"\nchallenge_scopes = [\"mcp:read\"]\nrole_claim = \"groups\"\n";
const B2_TOML: &str = "[server.auth.oauth]\naudience = \"mcp-example\"\naccept_resource_audience = true\n[[server.auth.oauth.scopes]]\nscope = \"mcp:read\"\nrole = \"viewer\"\n[server.auth.oauth.token_exchange]\ntoken_url = \"https://idp.example/token\"\n[server.auth.oauth.proxy]\nclient_secret = \"fake-client-secret\"\nmode = \"authorization_server\"\nconsent_ttl = \"30d\"\n";
const B2_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_FILE=/run/fake\nRMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_PREVIOUS=fake-previous";
pub(super) const SETTINGS_A1: &str =
    "Settings: [resource server](#settings-matrix-resource-server) row A1.";

fn section() -> String {
    format!(
        "## 7. Configuration examples\n\nPreamble prose.\n\n{}\n\n{RES_HEAD}\n{A1_ROW}\n{B2_ROW}\n\n{}\n\n{PROXY_HEAD}\n{P_ROW}\n\n### A1 - First\n\n{SETTINGS_A1}\n\n```toml,case=A1\n```\n\n### B2 - Second case\n\nSettings: [resource server](#settings-matrix-resource-server) and [proxy](#settings-matrix-proxy) row B2.\n\n```toml,case=B2\n```\n",
        RESOURCE.heading, PROXY.heading
    )
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Target {
    Section,
    Toml(usize),
    Env(usize),
}

pub(super) type Edit = (Target, String, String);

pub(super) fn edit(target: Target, from: &str, to: &str) -> Edit {
    (target, from.to_owned(), to.to_owned())
}

pub(super) fn row(rule: &'static str, edits: Vec<Edit>, names: &'static [&'static str]) -> Row {
    Row { rule, edits, names }
}

/// An empty `names` list marks an accepted row; otherwise every name is in the error.
pub(super) struct Row {
    rule: &'static str,
    edits: Vec<Edit>,
    names: &'static [&'static str],
}

fn apply(edits: &[Edit]) -> anyhow::Result<(String, Vec<Case>)> {
    let mut section = section();
    let make_case = |id: &str, toml: &str, env: &str| Case {
        id: id.into(),
        toml: toml.into(),
        env: vec![env.into()],
        exchanges: Vec::new(),
    };
    let mut cases = vec![
        make_case(
            "A1",
            A1_TOML,
            "RMCP_SERVER_KIT__SERVER__PUBLIC_URL=https://mcp.example",
        ),
        make_case("B2", B2_TOML, B2_ENV),
    ];
    for (target, from, to) in edits {
        let text = match *target {
            Target::Section => &mut section,
            Target::Toml(index) => &mut cases.get_mut(index).context("case")?.toml,
            Target::Env(index) => cases
                .get_mut(index)
                .and_then(|case| case.env.first_mut())
                .context("env")?,
        };
        ensure!(
            text.contains(from.as_str()),
            "fixture edit {from:?} does not apply"
        );
        *text = text.replacen(from.as_str(), to, 1);
    }
    Ok((section, cases))
}

fn check(section: &str, cases: &[Case]) -> anyhow::Result<()> {
    let _resource = check_matrix(section, &RESOURCE, cases)?;
    let _proxy = check_matrix(section, &PROXY, cases)?;
    check_layout(section, cases)
}

/// Every matrix rule accepts its equivalent variant and rejects its drift, naming case and column.
#[test]
fn settings_matrix_rules_distinguish_when_cells_rows_or_headers_drift() -> anyhow::Result<()> {
    let mut coverage = BTreeMap::<&str, (bool, bool)>::new();
    for Row { rule, edits, names } in super::matrix_rows::rows() {
        // Given: the fixture with one rule's edits applied.
        let (section, cases) = apply(&edits)?;
        // When: check both matrices and the settings lines.
        let result = check(&section, &cases);
        // Then: accepted rows pass and rejected rows name every expected fragment.
        match &result {
            Ok(()) => ensure!(names.is_empty(), "{rule}: {edits:?} accepted"),
            Err(error) => {
                let text = format!("{error:#}");
                ensure!(
                    !names.is_empty() && names.iter().all(|name| text.contains(name)),
                    "{rule}: {edits:?} gave {text}"
                );
            }
        }
        let covered = coverage.entry(rule).or_default();
        if names.is_empty() {
            covered.0 = true;
        } else {
            covered.1 = true;
        }
    }
    for rule in RULES {
        ensure!(
            coverage.get(rule) == Some(&(true, true)),
            "matrix rule {rule} lacks paired rows"
        );
    }
    ensure!(
        coverage.len() == RULES.len(),
        "matrix rule coverage drifted"
    );
    Ok(())
}
