//! Inline environment grammar and documentation-drift contracts.

use anyhow::{Context as _, ensure};

use super::{
    environment::{check_env, guide_specs, parse_env},
    grammar::Case,
};

/// Environment assignments preserve literal quoting and reject malformed shell syntax.
#[test]
fn env_assignments_parse_when_values_contain_equals_or_quotes() -> anyhow::Result<()> {
    let values = parse_env(
        "# comment\n\nexport FIRST=a=b\nSECOND='literal spaces'\nTHIRD=\"a=b\"\nEMPTY=\n",
    )?;
    ensure!(
        values.get("FIRST").map(String::as_str) == Some("a=b"),
        "equals lost"
    );
    ensure!(
        values.get("SECOND").map(String::as_str) == Some("literal spaces"),
        "single quotes lost"
    );
    ensure!(
        values.get("THIRD").map(String::as_str) == Some("a=b"),
        "double quotes lost"
    );
    ensure!(
        values.get("EMPTY").map(String::as_str) == Some(""),
        "empty assignment lost"
    );
    for invalid in [
        "NO_EQUALS",
        "A='unclosed",
        "A=space value",
        "1NAME=x",
        "A=1\nA=2",
    ] {
        let _error = parse_env(invalid).err().context("invalid env accepted")?;
    }
    Ok(())
}

/// Environment drift and missing new-knob overrides cannot pass silently.
#[test]
fn env_contract_rejects_when_documented_value_drifts() -> anyhow::Result<()> {
    let specs = guide_specs(
        "<!-- BEGIN ENV_OVERRIDE_TABLE -->\n| `BOOL` | `server.auth.oauth.omit_error_on_missing_credential` | bool | normal |\n| `LIST` | `server.list` | list | normal |\n| `TEXT` | `server.text` | string | normal |\n| `SECRET_FILE` | `server.secret` | path | secret |\n<!-- END ENV_OVERRIDE_TABLE -->",
    )?;
    for (env, passes) in [
        (
            "BOOL=true\nLIST=a, b\nTEXT=literal\nSECRET_FILE=/unused",
            false,
        ),
        (
            "BOOL=true\nLIST='a, b'\nTEXT=literal\nSECRET_FILE=/unused",
            true,
        ),
        ("BOOL=false\nLIST=a,b\nTEXT=literal", false),
        ("BOOL=true\nLIST=a,c\nTEXT=literal", false),
        ("BOOL=true\nLIST=a,b\nTEXT=wrong", false),
        ("LIST=a,b\nTEXT=literal", false),
        ("BOOL=true\nLIST=a,b\nTEXT=literal\nUNKNOWN=x", false),
    ] {
        let case = Case { id:"INLINE".into(), toml:"[server]\nlist=['a','b']\ntext='literal'\n[server.auth.oauth]\nomit_error_on_missing_credential=true".into(), env:vec![env.into()], exchanges:vec![] };
        ensure!(
            check_env(&case, &specs).is_ok() == passes,
            "env contract acceptance differs"
        );
    }
    Ok(())
}

/// Both env variants compare ordinary values literally but never compare secret material.
#[test]
fn env_table_distinguishes_when_main_or_alternative_values_drift() -> anyhow::Result<()> {
    // Given: independent TOML values with no secret in the file.
    let specs = guide_specs(
        "<!-- BEGIN ENV_OVERRIDE_TABLE -->\n| `TEXT` | `server.text` | string | normal |\n| `LIST` | `server.list` | list | normal |\n| `BOOL` | `server.flag` | bool | normal |\n| `NUMBER` | `server.number` | integer | normal |\n| `SECRET` | `server.secret` | string | secret |\n| `SECRET_FILE` | `server.secret` | path | secret |\n<!-- END ENV_OVERRIDE_TABLE -->",
    )?;
    for (name, value, passes) in [
        ("TEXT", "literal", true),
        ("TEXT", "other", false),
        ("TEXT", "<any>", false),
        ("LIST", "'first, second'", true),
        ("LIST", "second,first", false),
        ("LIST", "first,<any>", false),
        ("BOOL", "true", true),
        ("BOOL", "false", false),
        ("BOOL", "<any>", false),
        ("BOOL", "True", false),
        ("NUMBER", "17", true),
        ("NUMBER", "19", false),
        ("SECRET", "arbitrary-value", true),
        ("SECRET_FILE", "/unread/path", true),
        ("UNKNOWN", "value", false),
    ] {
        for alternative in [false, true] {
            let block = format!("{name}={value}");
            let env = if alternative {
                vec!["# main".into(), block]
            } else {
                vec![block]
            };
            let case = Case {
                id: "ENV".into(),
                toml: "[server]\ntext='literal'\nlist=['first','second']\nflag=true\nnumber=17"
                    .into(),
                env,
                exchanges: Vec::new(),
            };
            // When: check the main or alternative block against the same TOML.
            let result = check_env(&case, &specs);
            // Then: wildcard syntax has no special meaning in env values.
            ensure!(
                result.is_ok() == passes,
                "{name}={value}, alternative={alternative}: {result:?}"
            );
        }
    }
    Ok(())
}

/// The previous sealing key is supplied only when the main env block names its variable.
#[test]
fn previous_sealing_table_supplies_key_when_named_only_in_environment() -> anyhow::Result<()> {
    use super::{configuration::operator_config, fixtures::CONFIG};
    for (names, previous_expected) in [
        (
            &["SEALING_SECRET_FILE", "SEALING_SECRET_PREVIOUS_FILE"][..],
            true,
        ),
        (&["SEALING_SECRET", "SEALING_SECRET_PREVIOUS"][..], true),
        (&["SEALING_SECRET_FILE"][..], false),
        (
            &["SEALING_SECRET_FILE", "SEALING_SECRET_PREVIOUSFILE"][..],
            false,
        ),
    ] {
        // Given: AS mode with both keys absent from TOML and named only by env.
        let env = names
            .iter()
            .map(|name| format!("RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__{name}=unused"))
            .collect::<Vec<_>>()
            .join("\n");
        let case = Case {
            id: "AS".into(),
            toml: format!("{CONFIG}\nmode='authorization_server'"),
            env: vec![env],
            exchanges: Vec::new(),
        };
        // When: apply the documented test additions and validate.
        let config = operator_config(&case, "http://localhost:12345")?;
        let proxy = config
            .server
            .auth
            .as_ref()
            .and_then(|auth| auth.oauth.as_ref())
            .and_then(|oauth| oauth.proxy.as_ref())
            .context("proxy table")?;
        // Then: only a named previous-key variable supplies the fixed previous key.
        ensure!(
            proxy.sealing_secret_previous.is_some() == previous_expected,
            "{names:?}: previous key presence differs"
        );
    }
    Ok(())
}

/// Mounted-file and value secrets enable AS validation without reading operator files.
#[test]
fn sealing_table_accepts_when_secret_is_named_only_in_environment() -> anyhow::Result<()> {
    use super::{configuration::operator_config, fixtures::CONFIG};
    for suffix in ["SEALING_SECRET", "SEALING_SECRET_FILE", "UNRELATED"] {
        // Given: AS mode deliberately omits the sealing secret in TOML.
        let case = Case {
            id: "AS".into(),
            toml: format!("{CONFIG}\nmode='authorization_server'"),
            env: vec![format!(
                "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__{suffix}=unused"
            )],
            exchanges: Vec::new(),
        };
        // When: supply only documented test additions and validate.
        let result = operator_config(&case, "http://localhost:12345");
        // Then: both documented secret delivery mechanisms work; absent secrets fail closed.
        ensure!(
            result.is_ok() == (suffix != "UNRELATED"),
            "secret delivery {suffix} acceptance differs"
        );
    }
    Ok(())
}
