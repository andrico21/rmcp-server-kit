//! Origin validation semantics (issue #24): normalized tuple matching, the
//! `null` opt-in, pre-auth rejection, coverage of non-`/mcp` routes, and CORS
//! alignment with the same matcher.
//!
//! Each test spawns a real server on an ephemeral loopback port - the same
//! harness pattern as `tests/e2e.rs` - and drives it with `reqwest`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::{net::SocketAddr, time::Duration};

use rmcp::{ServerHandler, model::ServerConfig};
use rmcp_server_kit::{
    auth::{ApiKeyEntry, AuthConfig},
    transport::{McpServerConfig, serve_with_listener},
};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct TestHandler;

impl ServerHandler for TestHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::default()
    }
}

struct Harness {
    base: String,
    shutdown: CancellationToken,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Spawn a server on an ephemeral loopback port and wait for its readiness
/// signal, mirroring `tests/e2e.rs`'s deterministic harness.
async fn spawn(config: McpServerConfig) -> Harness {
    // Ensure ring crypto provider is available for reqwest's TLS stack
    // (mirrors tests/e2e.rs; harmless when already installed).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound: SocketAddr = listener.local_addr().unwrap();
    let config = config.with_bind_addr(bound.to_string());

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let shutdown = CancellationToken::new();
    let shutdown_for_server = shutdown.clone();

    let join = tokio::spawn(async move {
        serve_with_listener(
            listener,
            config.validate().expect("test config valid"),
            || TestHandler,
            Some(ready_tx),
            Some(shutdown_for_server),
        )
        .await
    });

    let signalled = tokio::time::timeout(Duration::from_secs(30), ready_rx)
        .await
        .expect("server did not signal readiness")
        .expect("server task aborted before readiness");
    assert_eq!(signalled, bound, "readiness address mismatch");
    drop(join); // detached; the shutdown token in `Harness::drop` stops it

    Harness {
        base: format!("http://{bound}"),
        shutdown,
    }
}

const ALLOWED: &str = "https://example.com";

fn base_config() -> McpServerConfig {
    McpServerConfig::new("127.0.0.1:0", "origin-test", "0.0.1")
        .with_shutdown_timeout(Duration::from_millis(100))
}

/// POST a valid `initialize` to `/mcp`, optionally carrying an `Origin` header.
async fn mcp_initialize(base: &str, origin: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request
        .body(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"origin-test","version":"0.1"}}}"#,
        )
        .send()
        .await
        .unwrap()
}

async fn get_healthz(base: &str, origin: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(format!("{base}/healthz"));
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.send().await.unwrap()
}

#[tokio::test]
async fn accepts_the_exact_allowed_origin() {
    // The issue's first case: the origin derived from `public_url`.
    let harness = spawn(base_config().with_public_url(ALLOWED)).await;
    let resp = mcp_initialize(&harness.base, Some(ALLOWED)).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn accepts_case_differing_scheme_and_host() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;

    let scheme = mcp_initialize(&harness.base, Some("HTTPS://example.com")).await;
    assert_eq!(
        scheme.status(),
        200,
        "scheme comparison must be case-insensitive"
    );

    let host = mcp_initialize(&harness.base, Some("https://EXAMPLE.COM")).await;
    assert_eq!(
        host.status(),
        200,
        "host comparison must be case-insensitive"
    );
}

#[tokio::test]
async fn accepts_explicit_default_port_as_equivalent() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    let resp = mcp_initialize(&harness.base, Some("https://example.com:443")).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn rejects_non_default_port_mismatch() {
    // Unlike rmcp's omitted-port wildcard, a configured origin must not match
    // a different explicit port.
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    let resp = mcp_initialize(&harness.base, Some("https://example.com:444")).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn rejects_disallowed_origin_with_the_stable_body() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    let resp = mcp_initialize(&harness.base, Some("https://evil.example")).await;

    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.text().await.unwrap(),
        "Forbidden: Origin not allowed",
        "the rejection body is a stable contract"
    );
}

#[tokio::test]
async fn absent_origin_is_allowed_on_every_route() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    assert_eq!(get_healthz(&harness.base, None).await.status(), 200);
    assert_eq!(mcp_initialize(&harness.base, None).await.status(), 200);
}

#[tokio::test]
async fn rejects_malformed_origin() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    let resp = mcp_initialize(&harness.base, Some("https://example.com/extra/path")).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn rejects_non_utf8_origin() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    let value = reqwest::header::HeaderValue::from_bytes(b"\xff\xfe")
        .expect("obs-text header value is representable");

    let resp = reqwest::Client::new()
        .post(format!("{}/mcp", harness.base))
        .header("content-type", "application/json")
        .header("origin", value)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-UTF-8 origins must fail closed");
}

#[tokio::test]
async fn null_origin_is_rejected_by_default_and_opt_in_accepted() {
    let default = spawn(base_config().with_allowed_origins([ALLOWED])).await;
    assert_eq!(
        mcp_initialize(&default.base, Some("null")).await.status(),
        403
    );

    let opted_in = spawn(base_config().with_allowed_origins([ALLOWED, "null"])).await;
    assert_eq!(
        mcp_initialize(&opted_in.base, Some("null")).await.status(),
        200
    );
}

#[tokio::test]
async fn origin_rejection_precedes_auth() {
    let (_, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let config = base_config()
        .with_allowed_origins([ALLOWED])
        .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
            "ops-key", hash, "ops",
        )]));
    let harness = spawn(config).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/mcp", harness.base))
        .header("origin", "https://evil.example")
        .header("authorization", "Bearer invalid-key")
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "origin must be checked before auth (not 401)"
    );
    assert!(
        resp.headers().get("www-authenticate").is_none(),
        "a rejected origin must not advertise the auth scheme"
    );
}

#[tokio::test]
async fn origin_layer_covers_non_mcp_routes() {
    let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await;

    assert_eq!(
        get_healthz(&harness.base, Some("https://evil.example"))
            .await
            .status(),
        403
    );
    assert_eq!(
        get_healthz(&harness.base, Some(ALLOWED)).await.status(),
        200
    );
}

#[tokio::test]
async fn cors_preflight_uses_the_same_normalized_matcher() {
    // The allowlist entry is the explicit-default-port form; the request uses
    // the implicit form. Raw-string CORS matching would fail here, so a
    // passing preflight proves both layers share the normalized matcher.
    let harness = spawn(base_config().with_allowed_origins(["https://example.com:443"])).await;

    let resp = reqwest::Client::new()
        .request(reqwest::Method::OPTIONS, format!("{}/mcp", harness.base))
        .header("origin", "https://example.com")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "preflight must pass, got {}",
        resp.status()
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://example.com"),
        "CORS must grant the normalized-equivalent origin"
    );
}

#[test]
fn config_validation_rejects_entries_that_cannot_match() {
    for bad in [
        "https://example.com/path",
        "https://example.com?x=1",
        "https://example.com#frag",
        "example.com",
        "ftp://example.com",
        "https://example.com//",
    ] {
        let err = base_config()
            .with_allowed_origins([bad])
            .validate()
            .expect_err("invalid origin entry must fail validation");
        assert!(
            err.to_string().contains("allowed_origins"),
            "error must name the field for {bad:?}: {err}"
        );
    }

    // The tolerated forms still pass.
    base_config()
        .with_allowed_origins(["https://example.com/", "null", "http://localhost:3000"])
        .validate()
        .expect("equivalent and null entries are valid");
}
