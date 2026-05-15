//! M-H2 (TOCTOU SSRF) integration tests.
//!
//! Two complementary suites:
//!
//! 1. **Resolver-contract tests** prove that the
//!    `SsrfScreeningResolver` installed via `ClientBuilder::dns_resolver`
//!    behaves correctly on the three observable outcomes documented in
//!    `src/ssrf_resolver.rs`:
//!    - Blocked IP -> error string carries the `ssrf:` prefix so log
//!      forensics can distinguish policy denials from generic DNS
//!      failures.
//!    - Empty / unresolvable host -> surfaces as a normal DNS error
//!      (no `ssrf:` prefix); we do not pretend a name resolved when it
//!      did not.
//!    - Verbatim pass-through under the test-only loopback bypass:
//!      addresses returned by the system resolver reach `reqwest`
//!      unmodified, so a real `127.0.0.1` listener answers.
//!
//! 2. **Env-proxy matrix** proves that `ClientBuilder::no_proxy()` is
//!    in effect on every `OauthHttpClient`. Without `.no_proxy()`,
//!    setting `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` would route
//!    requests through the proxy and bypass our resolver entirely
//!    (Oracle review N1). The matrix points each variant at TEST-NET-1
//!    (`192.0.2.1:1`) -- a documented, unroutable decoy. Even if the
//!    environment leaks one through, the connection cannot succeed,
//!    so the only way to observe the resolver firing is for `reqwest`
//!    to ignore the proxy entirely. Each variant asserts the resolver
//!    short-circuited the request with an `ssrf:` error.
//!
//! Resolver type itself is `pub(crate)`; tests therefore drive the
//! production constructor `OauthHttpClient::with_config(&OAuthConfig)`
//! and observe behaviour via the test-only `__test_get` accessor.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![cfg(all(feature = "oauth", feature = "test-helpers"))]

use std::time::Duration;

use rmcp_server_kit::oauth::{OAuthConfig, OauthHttpClient};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// `reqwest 0.13` requires a process-wide rustls crypto provider even
/// for plain-HTTP requests (the TLS stack is initialised eagerly). The
/// `_ =` discards the "already installed" error from earlier tests in
/// the same process.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a vanilla `OauthHttpClient` with `allow_http_oauth_urls`
/// flipped so plain-HTTP loopback URLs (used by the matrix listener)
/// are not rejected on the scheme check before reaching the resolver.
fn build_client(allow_loopback: bool) -> OauthHttpClient {
    install_crypto_provider();
    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");
    if allow_loopback {
        client.__test_allow_loopback_ssrf()
    } else {
        client
    }
}

/// Walk the `source()` chain so the `ssrf:` diagnostic produced by
/// `SsrfScreeningResolver::resolve` (which lives several layers under
/// `reqwest::Error`) is visible to assertions. `format!("{err}")` only
/// renders the outermost wrapper.
fn render_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut current = err.source();
    while let Some(inner) = current {
        out.push_str(" :: ");
        out.push_str(&inner.to_string());
        current = inner.source();
    }
    out
}

// ---------------------------------------------------------------------------
// Resolver-contract test #1 (AlwaysErr): blocked-IP path emits "ssrf:"
// ---------------------------------------------------------------------------
//
// `localhost` resolves to a loopback IP. With the loopback bypass OFF
// the resolver must reject every address and surface the diagnostic
// prefix that lets operators distinguish a deliberate policy denial
// from a generic DNS failure.
#[tokio::test]
async fn resolver_contract_always_err_loopback_blocked() {
    let client = build_client(false);
    let err = client
        .__test_get("http://localhost/")
        .await
        .expect_err("loopback must be blocked without bypass");
    let chain = render_chain(&err);
    assert!(
        chain.contains("ssrf:"),
        "diagnostic must carry ssrf: prefix; got: {chain}"
    );
    assert!(
        chain.contains("loopback") || chain.contains("blocked IP"),
        "diagnostic must name the block reason; got: {chain}"
    );
}

// ---------------------------------------------------------------------------
// Resolver-contract test #2 (Empty): unresolvable host = DNS error
// ---------------------------------------------------------------------------
//
// `.invalid` is reserved by RFC 6761 to never resolve. The system
// resolver returns an error; our resolver propagates it (it does NOT
// invent an `ssrf:` diagnostic, because no IP was actually evaluated).
// Asserting the *absence* of the `ssrf:` prefix is what makes this a
// regression guard against accidentally classifying NXDOMAIN as a
// policy denial.
#[tokio::test]
async fn resolver_contract_empty_dns_failure_not_classified_as_ssrf() {
    let client = build_client(false);
    let err = client
        .__test_get("http://nonexistent-host-for-mcpx-tests.invalid/")
        .await
        .expect_err("unresolvable host must surface as error");
    let chain = render_chain(&err);
    assert!(
        !chain.contains("ssrf:"),
        "DNS failure must not be tagged as ssrf policy denial; got: {chain}"
    );
}

// ---------------------------------------------------------------------------
// Resolver-contract test #3 (Verbatim): bypass-on -> real listener answers
// ---------------------------------------------------------------------------
//
// Bind an ephemeral 127.0.0.1 listener, accept one connection, and
// reply with a minimal HTTP/1.1 response. With the test-only loopback
// bypass enabled, the resolver must pass the system-returned address
// through verbatim so the connection actually reaches the listener.
//
// This is the inverse of test #1 and proves we did not over-block.
#[tokio::test]
async fn resolver_contract_verbatim_passthrough_with_bypass() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    // Spawn a one-shot server. It accepts a single connection, drains
    // the request preamble, writes a 200 OK, and exits.
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        // Best-effort read; reqwest may pipeline so we do not enforce
        // a specific byte count here.
        let _ = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let _ = sock.write_all(response).await;
        let _ = sock.shutdown().await;
    });

    let client = build_client(true);
    let url = format!("http://127.0.0.1:{port}/");
    let response = client
        .__test_get(&url)
        .await
        .expect("loopback must succeed with bypass enabled");
    assert!(
        response.status().is_success(),
        "expected 2xx; got {}",
        response.status()
    );

    // Drain the body so the server's write completes cleanly.
    let _ = response.bytes().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

// ---------------------------------------------------------------------------
// Env-proxy matrix: 6 variants of {HTTP_PROXY, HTTPS_PROXY, ALL_PROXY}
// ---------------------------------------------------------------------------
//
// For each env var, with both an `http://` and a representative target
// scheme, set the variable to a TEST-NET-1 decoy proxy and prove the
// resolver still fires (i.e. `.no_proxy()` defeated reqwest's
// auto-proxy detection). If `.no_proxy()` were missing, reqwest would
// route DNS through the decoy proxy and the failure mode would change
// (connect timeout / proxy error), with no `ssrf:` diagnostic.
//
// `temp-env::with_vars` is sync; it sets the vars before invoking the
// closure and restores them after. The closure spawns a per-variant
// tokio runtime so each case is isolated.
//
// Variant matrix:
//   1. HTTP_PROXY  set, target http://localhost
//   2. HTTPS_PROXY set, target http://localhost
//   3. ALL_PROXY   set, target http://localhost
//   4. http_proxy  (lowercase) set, target http://localhost
//   5. https_proxy (lowercase) set, target http://localhost
//   6. all_proxy   (lowercase) set, target http://localhost
//
// All six must surface the resolver's `ssrf:` diagnostic.

const DECOY_PROXY: &str = "http://192.0.2.1:1"; // TEST-NET-1 (RFC 5737)
const TARGET_URL: &str = "http://localhost/";

fn run_with_env(var: &str, value: &str) -> String {
    // Build a one-thread runtime inside the env scope so the env vars
    // are observable to reqwest's proxy autodetection at client build
    // time.
    temp_env::with_var(var, Some(value), || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let client = build_client(false);
            let err = client
                .__test_get(TARGET_URL)
                .await
                .expect_err("loopback target must be rejected");
            render_chain(&err)
        })
    })
}

#[test]
fn no_proxy_defeats_http_proxy_uppercase() {
    let chain = run_with_env("HTTP_PROXY", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "HTTP_PROXY must not bypass resolver; got: {chain}"
    );
}

#[test]
fn no_proxy_defeats_https_proxy_uppercase() {
    let chain = run_with_env("HTTPS_PROXY", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "HTTPS_PROXY must not bypass resolver; got: {chain}"
    );
}

#[test]
fn no_proxy_defeats_all_proxy_uppercase() {
    let chain = run_with_env("ALL_PROXY", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "ALL_PROXY must not bypass resolver; got: {chain}"
    );
}

#[test]
fn no_proxy_defeats_http_proxy_lowercase() {
    let chain = run_with_env("http_proxy", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "http_proxy must not bypass resolver; got: {chain}"
    );
}

#[test]
fn no_proxy_defeats_https_proxy_lowercase() {
    let chain = run_with_env("https_proxy", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "https_proxy must not bypass resolver; got: {chain}"
    );
}

#[test]
fn no_proxy_defeats_all_proxy_lowercase() {
    let chain = run_with_env("all_proxy", DECOY_PROXY);
    assert!(
        chain.contains("ssrf:"),
        "all_proxy must not bypass resolver; got: {chain}"
    );
}
