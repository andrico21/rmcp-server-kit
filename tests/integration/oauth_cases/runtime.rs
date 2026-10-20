//! Real server execution of validated, isolated documentation cases.

use alloc::sync::Arc;
use core::time::Duration;
use std::path::PathBuf;

use anyhow::{Context as _, ensure};
use reqwest::Client;
use rmcp::{
    ServerHandler,
    model::{ServerCapabilities, ServerConfig as HandlerConfig},
};
use rmcp_server_kit::{
    oauth::OAuthConfig,
    rbac::RbacPolicy,
    transport::{McpServerConfig, serve_with_listener},
};
use tokio::{
    fs,
    net::TcpListener,
    sync::oneshot,
    task::{JoinSet, spawn_blocking},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::{
    compare::{Message, compare_upstream},
    configuration::{mount_endpoints, operator_config, rewrite},
    environment::{check_env, guide_specs},
    grammar::{Case, Exchange, parse_cases},
    identity::Identity,
    mock::DualStackMock,
};

#[derive(Clone)]
struct EchoHandler;

impl ServerHandler for EchoHandler {
    fn get_info(&self) -> HandlerConfig {
        HandlerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

// cancel-safe: JoinSet aborts server tasks; cancellation guard stops framework children.
pub(super) async fn run_case(case: &Case, identity: &Identity) -> anyhow::Result<usize> {
    let mock = DualStackMock::start().await?;
    let upstream_base = mock.base();
    let config = operator_config(case, &upstream_base)?;
    mount_endpoints(&mock, &config, identity).await?;
    let oauth = config
        .server
        .auth
        .as_ref()
        .and_then(|auth| auth.oauth.as_ref())
        .context("case OAuth configuration")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut bridged = config.server.apply_to_mcp_config(McpServerConfig::new(
        addr.to_string(),
        "oauth-cases",
        "1",
    ))?;
    if let Some(rbac) = &config.rbac {
        bridged = bridged.with_rbac(Arc::new(RbacPolicy::new(rbac)));
    }
    let validated = bridged.with_bind_addr(addr.to_string()).validate()?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let stop = CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    let mut tasks = JoinSet::new();
    let _server = tasks.spawn(serve_with_listener(
        listener,
        validated,
        || EchoHandler,
        Some(ready_tx),
        Some(stop.clone()),
    ));
    ensure!(
        timeout(Duration::from_secs(10), ready_rx).await?? == addr,
        "ready address differs"
    );
    let client = super::network::client()?;
    let mut executed = 0_usize;
    for exchange in &case.exchanges {
        executed = executed.saturating_add(1);
        execute(
            exchange,
            (&client, &format!("http://{addr}")),
            (&mock, &upstream_base),
            (identity, oauth),
        )
        .await
        .with_context(|| format!("case {} exchange {executed}", case.id))?;
        tracing::info!(case = %case.id, exchange = executed, "documented exchange executed");
    }
    stop.cancel();
    while let Some(joined) = timeout(Duration::from_secs(10), tasks.join_next()).await? {
        joined??;
    }
    Ok(executed)
}

// cancel-safe: requests are isolated; dropping the future closes its response without carrying state.
async fn execute(
    exchange: &Exchange,
    client: (&Client, &str),
    upstream: (&DualStackMock, &str),
    jwt: (&Identity, &OAuthConfig),
) -> anyhow::Result<()> {
    match exchange {
        Exchange::Http {
            request,
            response,
            upstream: expected_upstream,
        } => {
            let offsets = upstream.0.offsets().await?;
            let raw = jwt
                .0
                .substitute(&rewrite(request, upstream.1), &jwt.1.issuer)?;
            let message = Message::parse(&raw)?;
            let (method, target) = message.request_target()?;
            let mut builder = client
                .0
                .request(method.parse()?, format!("{}{target}", client.1));
            for (name, value) in &message.headers {
                builder = builder.header(name, value);
            }
            if let Some(body) = message.body {
                builder = builder.body(body);
            }
            let actual = builder.send().await?;
            let status = actual.status();
            let headers = actual
                .headers()
                .iter()
                .map(|(name, value)| Ok((name.to_string(), value.to_str()?.to_owned())))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let body = actual.text().await?;
            let wire = Message {
                line: format!(
                    "HTTP/1.1 {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown")
                ),
                headers,
                body: Some(body),
            };
            let expected = Message::parse(&rewrite(response, upstream.1))?;
            tracing::info!(
                status = status.as_u16(),
                challenge = wire
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
                    .map(|(_, value)| value.as_str()),
                "documented response received"
            );
            expected.compare_response(&wire)?;
            if let Some(upstream_fence) = expected_upstream {
                let expected_request = rewrite(upstream_fence, upstream.1);
                ensure!(
                    upstream
                        .0
                        .requests_since(&offsets)
                        .await?
                        .iter()
                        .any(|recording| compare_upstream(&expected_request, recording).is_ok()),
                    "upstream request mismatch"
                );
            }
        }
        Exchange::Library {
            snippet,
            upstream: library_upstream,
        } => super::library::execute(snippet, library_upstream, jwt.1, upstream).await?,
    }
    Ok(())
}

/// Every documented case executes at least one isolated real HTTP exchange.
// cancel-safe: case-owned cancellation guards and JoinSets release listeners on failure.
#[tokio::test]
async fn documented_cases_match_when_served_through_real_transport() -> anyhow::Result<()> {
    let _subscriber = tracing_subscriber::fmt().with_test_writer().try_init();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let markdown = fs::read_to_string(root.join("docs/OAUTH_PROXY.md"))
        .await
        .context("read OAuth cases document")?;
    let guide = fs::read_to_string(root.join("docs/GUIDE.md")).await?;
    let cases = parse_cases(&markdown)?;
    super::catalogue::check(&cases)?;
    let specs = guide_specs(&guide)?;
    let identity = spawn_blocking(Identity::generate).await??;
    let expected = cases.iter().map(|case| case.exchanges.len()).sum::<usize>();
    let mut executed = 0_usize;
    for case in &cases {
        check_env(case, &specs).with_context(|| format!("case {} env", case.id))?;
        executed = executed.saturating_add(
            run_case(case, &identity)
                .await
                .with_context(|| format!("case {}", case.id))?,
        );
    }
    ensure!(
        executed == expected && executed > 0,
        "executed exchange count differs from document"
    );
    tracing::info!(
        cases = cases.len(),
        exchanges = executed,
        "documented OAuth catalogue executed"
    );
    Ok(())
}

/// A signed initialize and proxy token request exercise rewritten JWKS and upstream assertions.
// cancel-safe: run_case owns listener cancellation and bounded request futures.
#[tokio::test]
async fn inline_case_executes_when_jwks_and_token_paths_are_rewritten() -> anyhow::Result<()> {
    let markdown = "## 7. Cases\n```toml,case=INLINE\n[server]\npublic_url='https://mcp.example'\n[server.auth]\nenabled=true\n[server.auth.oauth]\nissuer='https://idp.example/realms/example'\naudience='mcp-example'\njwks_uri='https://idp.example/custom/certs'\n[[server.auth.oauth.scopes]]\nscope='mcp:read'\nrole='viewer'\n[server.auth.oauth.proxy]\nauthorize_url='https://idp.example/authorize'\ntoken_url='https://idp.example/custom/token'\nclient_id='mcp-proxy'\n```\n```sh,case=INLINE\n# no opt-in knobs\n```\n```http,case=INLINE,request\nPOST /mcp HTTP/1.1\nHost: mcp.example\nContent-Type: application/json\nAccept: application/json, text/event-stream\nAuthorization: Bearer <jwt {\"aud\":\"mcp-example\",\"scope\":\"mcp:read\"}>\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"inline\",\"version\":\"1\"}}}\n```\n```http,case=INLINE,response\nHTTP/1.1 200 OK\n```\n```http,case=INLINE,request\nPOST /token HTTP/1.1\nHost: mcp.example\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=authorization_code&code=inline-code&client_id=external\n```\n```http,case=INLINE,response\nHTTP/1.1 200 OK\n```\n```http,case=INLINE,upstream\nPOST /custom/token\n\ngrant_type=authorization_code\nclient_id=mcp-proxy\ncode=inline-code\n```\n## 8. End";
    let cases = parse_cases(&super::fence_tables::complete_document(markdown))?;
    let identity = spawn_blocking(Identity::generate).await??;
    ensure!(
        run_case(cases.first().context("inline case")?, &identity).await? == 2,
        "inline exchanges missing"
    );
    Ok(())
}
