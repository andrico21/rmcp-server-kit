//! Library-call exchanges: the harness performs the documented `oauth::` call.

use anyhow::{Context as _, ensure};
use rmcp_server_kit::oauth::{OAuthConfig, OauthHttpClient, exchange_token};

use super::{compare::compare_upstream, configuration::rewrite, mock::DualStackMock};

/// Library-call contracts; each needs an accepted and a rejected executed row.
pub(super) const RULES: &[&str] = &[
    "function-name",
    "requires-config",
    "upstream-target",
    "upstream-header",
    "upstream-form",
    "subject-token",
    "client-auth",
    "exchange-local",
];
/// The only library function a documented snippet may ask the harness to call.
pub(super) const SUPPORTED: &str = "exchange_token";
/// Subject token passed to every executed exchange; documented upstream fences name it.
pub(super) const SUBJECT_TOKEN: &str = "subject-token";

/// Every `oauth::<name>(` call shown in a snippet, in source order.
pub(super) fn library_calls(snippet: &str) -> Vec<&str> {
    snippet
        .match_indices("oauth::")
        .filter_map(|(start, marker)| {
            let rest = snippet.get(start.saturating_add(marker.len())..)?;
            let end = rest
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(rest.len());
            let (name, after) = rest.split_at_checked(end)?;
            (!name.is_empty() && after.starts_with('(')).then_some(name)
        })
        .collect()
}

/// The single supported call a snippet shows, or an error naming what it shows instead.
pub(super) fn supported_call(snippet: &str) -> anyhow::Result<&'static str> {
    let calls = library_calls(snippet);
    let [name] = calls.as_slice() else {
        anyhow::bail!(
            "library snippet shows {} `oauth::` calls {calls:?}; exactly one `oauth::{SUPPORTED}(...)` is executed",
            calls.len()
        );
    };
    ensure!(
        *name == SUPPORTED,
        "unsupported library function `oauth::{name}`; only `oauth::{SUPPORTED}` is executed"
    );
    Ok(SUPPORTED)
}

/// Performs the snippet's call against the case's parsed configuration and asserts
/// the request the mock IdP recorded during this exchange alone.
// cancel-safe: the exchange owns no shared state; recordings are read, never reset.
pub(super) async fn execute(
    snippet: &str,
    fence: &str,
    oauth: &OAuthConfig,
    upstream: (&DualStackMock, &str),
) -> anyhow::Result<()> {
    let function = supported_call(snippet)?;
    let exchange = oauth.token_exchange.as_ref().with_context(|| {
        format!("`oauth::{function}` requires [server.auth.oauth.token_exchange]")
    })?;
    let offsets = upstream.0.offsets().await?;
    let http = OauthHttpClient::with_config(oauth)?;
    let _exchanged = exchange_token(&http, exchange, SUBJECT_TOKEN)
        .await
        .with_context(|| format!("`oauth::{function}` failed against the mock IdP"))?;
    let expected = rewrite(fence, upstream.1);
    ensure!(
        upstream
            .0
            .requests_since(&offsets)
            .await?
            .iter()
            .any(|recording| compare_upstream(&expected, recording).is_ok()),
        "library-call upstream request mismatch"
    );
    Ok(())
}
