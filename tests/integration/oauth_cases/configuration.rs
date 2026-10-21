//! Operator configuration transformation and IdP endpoint mounting.

use anyhow::Context as _;
use rmcp_server_kit::{
    config::{
        ObservabilityConfig, ServerConfig, validate_observability_config, validate_server_config,
    },
    rbac::RbacConfig,
};
use serde::Deserialize;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use super::{environment::parse_env, grammar::Case, identity::Identity, mock::DualStackMock};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorConfig {
    pub server: ServerConfig,
    pub rbac: Option<RbacConfig>,
    pub observability: Option<ObservabilityConfig>,
}

pub(super) fn rewrite(text: &str, base: &str) -> String {
    text.replace("https://idp.example", base)
        .replace("https://login.microsoftonline.com", base)
}

pub(super) fn operator_config(case: &Case, base: &str) -> anyhow::Result<OperatorConfig> {
    let mut raw: toml::Value = toml::from_str(&rewrite(&case.toml, base))?;
    let oauth = raw
        .get_mut("server")
        .and_then(|value| value.get_mut("auth"))
        .and_then(|value| value.get_mut("oauth"))
        .and_then(toml::Value::as_table_mut)
        .context("case requires server.auth.oauth")?;
    let _http_setting = oauth.insert("allow_http_oauth_urls".into(), toml::Value::Boolean(true));
    let _allowlist = oauth.insert(
        "ssrf_allowlist".into(),
        toml::Value::try_from(json!({"hosts":["localhost"],"cidrs":["127.0.0.0/8"]}))?,
    );
    if let Some(proxy) = oauth.get_mut("proxy").and_then(toml::Value::as_table_mut) {
        let env = parse_env(case.env.first().context("main env block")?)?;
        for (key, secret) in [
            (
                "sealing_secret",
                "case-test-sealing-secret-0123456789abcdef",
            ),
            (
                "sealing_secret_previous",
                "case-test-previous-secret-0123456789abcd",
            ),
        ] {
            if !proxy.contains_key(key)
                && env.keys().any(|name| {
                    name.strip_prefix("RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__")
                        .is_some_and(|suffix| {
                            suffix == key.to_ascii_uppercase()
                                || suffix == format!("{}_FILE", key.to_ascii_uppercase())
                        })
                })
            {
                let _secret_setting = proxy.insert(key.into(), toml::Value::String(secret.into()));
            }
        }
    }
    let config: OperatorConfig = raw.try_into()?;
    validate_server_config(&config.server)?;
    if let Some(observability) = &config.observability {
        validate_observability_config(observability)?;
    }
    Ok(config)
}

// cancel-safe: all mounts belong to the case-owned mock.
pub(super) async fn mount_endpoints(
    mock: &DualStackMock,
    config: &OperatorConfig,
    identity: &Identity,
) -> anyhow::Result<()> {
    let oauth = config
        .server
        .auth
        .as_ref()
        .and_then(|auth| auth.oauth.as_ref())
        .context("OAuth configuration")?;
    let jwks = url::Url::parse(&oauth.jwks_uri)?;
    mock.mount(|| {
        Mock::given(method("GET"))
            .and(path(jwks.path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&identity.jwks))
    })
    .await;
    let mut tokens = Vec::new();
    if let Some(proxy) = &oauth.proxy {
        tokens.push(proxy.token_url.as_str());
        for (optional_endpoint, response) in [
            (proxy.revocation_url.as_deref(), json!({})),
            (proxy.introspection_url.as_deref(), json!({"active":false})),
        ] {
            if let Some(endpoint) = optional_endpoint {
                let url = url::Url::parse(endpoint)?;
                mock.mount(|| {
                    Mock::given(method("POST"))
                        .and(path(url.path()))
                        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                })
                .await;
            }
        }
    }
    if let Some(exchange) = &oauth.token_exchange {
        tokens.push(exchange.token_url.as_str());
    }
    tokens.sort_unstable();
    tokens.dedup();
    for endpoint in tokens {
        let url = url::Url::parse(endpoint)?;
        mock.mount(|| Mock::given(method("POST")).and(path(url.path())).respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"at","token_type":"Bearer","expires_in":300_u32,"refresh_token":"rt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"})))).await;
    }
    Ok(())
}
