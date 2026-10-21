//! Origin validation semantics (issue #24): normalized tuple matching, the
//! `null` opt-in, pre-auth rejection, coverage of non-`/mcp` routes, and CORS
//! alignment with the same matcher.
//!
//! Each test spawns a real server on an ephemeral loopback port - the same
//! harness pattern as `tests/integration/e2e.rs` - and drives it with `reqwest`.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg(test)]
mod tests {

    use core::{net::SocketAddr, time::Duration};

    use anyhow::Context as _;
    use reqwest::header::HeaderValue;
    use rmcp::{ServerHandler, model::ServerConfig};
    use rmcp_server_kit::{
        auth::{ApiKeyEntry, AuthConfig, generate_api_key},
        transport::{McpServerConfig, serve_with_listener},
    };
    use rustls::crypto::ring;
    use tokio::{net::TcpListener, sync::oneshot, time::timeout};
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

    // Drop audit (2026-10-04): cancels the shutdown token only; no blocking/async work, no panic paths.
    impl Drop for Harness {
        fn drop(&mut self) {
            self.shutdown.cancel();
        }
    }

    /// Spawn a server on an ephemeral loopback port and wait for its readiness
    /// signal, mirroring `tests/integration/e2e.rs`'s deterministic harness.
    async fn spawn(config: McpServerConfig) -> anyhow::Result<Harness> {
        // Ensure ring crypto provider is available for reqwest's TLS stack
        // (mirrors tests/integration/e2e.rs; harmless when already installed).
        drop(ring::default_provider().install_default());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind ephemeral listener")?;
        let bound: SocketAddr = listener.local_addr().context("listener local addr")?;
        let validated = config
            .with_bind_addr(bound.to_string())
            .validate()
            .context("test config valid")?;

        let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let join = tokio::spawn(async move {
            serve_with_listener(
                listener,
                validated,
                || TestHandler,
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
        });

        let signalled = timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("server did not signal readiness")?
            .context("server task aborted before readiness")?;
        assert_eq!(signalled, bound, "readiness address mismatch");
        drop(join); // detached; the shutdown token in `Harness::drop` stops it

        Ok(Harness {
            base: format!("http://{bound}"),
            shutdown,
        })
    }

    const ALLOWED: &str = "https://example.com";

    fn base_config() -> McpServerConfig {
        McpServerConfig::new("127.0.0.1:0", "origin-test", "0.0.1")
            .with_shutdown_timeout(Duration::from_millis(100))
    }

    /// POST a valid `initialize` to `/mcp`, optionally carrying an `Origin` header.
    async fn mcp_initialize(base: &str, origin: Option<&str>) -> anyhow::Result<reqwest::Response> {
        let mut request = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(origin_value) = origin {
            request = request.header("origin", origin_value);
        }
        request
            .body(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"origin-test","version":"0.1"}}}"#,
            )
            .send()
            .await
            .context("initialize request")
    }

    /// GET `/healthz`, optionally carrying an `Origin` header.
    async fn get_healthz(base: &str, origin: Option<&str>) -> anyhow::Result<reqwest::Response> {
        let mut request = reqwest::Client::new().get(format!("{base}/healthz"));
        if let Some(origin_value) = origin {
            request = request.header("origin", origin_value);
        }
        request.send().await.context("healthz request")
    }

    /// Pins that the exact `public_url` origin is accepted.
    #[tokio::test]
    async fn accepts_the_exact_allowed_origin() -> anyhow::Result<()> {
        // The issue's first case: the origin derived from `public_url`.
        let harness = spawn(base_config().with_public_url(ALLOWED)).await?;
        let resp = mcp_initialize(&harness.base, Some(ALLOWED)).await?;
        assert_eq!(resp.status(), 200);
        Ok(())
    }

    /// Pins that scheme and host comparison is case-insensitive.
    #[tokio::test]
    async fn accepts_case_differing_scheme_and_host() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;

        let scheme = mcp_initialize(&harness.base, Some("HTTPS://example.com")).await?;
        assert_eq!(
            scheme.status(),
            200,
            "scheme comparison must be case-insensitive"
        );

        let host = mcp_initialize(&harness.base, Some("https://EXAMPLE.COM")).await?;
        assert_eq!(
            host.status(),
            200,
            "host comparison must be case-insensitive"
        );
        Ok(())
    }

    /// Pins that an explicit `:443` equals the implicit default port.
    #[tokio::test]
    async fn accepts_explicit_default_port_as_equivalent() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        let resp = mcp_initialize(&harness.base, Some("https://example.com:443")).await?;
        assert_eq!(resp.status(), 200);
        Ok(())
    }

    /// Pins that a differing explicit port does not match a configured origin.
    #[tokio::test]
    async fn rejects_non_default_port_mismatch() -> anyhow::Result<()> {
        // Unlike rmcp's omitted-port wildcard, a configured origin must not match
        // a different explicit port.
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        let resp = mcp_initialize(&harness.base, Some("https://example.com:444")).await?;
        assert_eq!(resp.status(), 403);
        Ok(())
    }

    /// Pins the 403 status and stable rejection body for a disallowed origin.
    #[tokio::test]
    async fn rejects_disallowed_origin_with_the_stable_body() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        let resp = mcp_initialize(&harness.base, Some("https://evil.example")).await?;

        assert_eq!(resp.status(), 403);
        assert_eq!(
            resp.text().await.context("rejection body")?,
            "Forbidden: Origin not allowed",
            "the rejection body is a stable contract"
        );
        Ok(())
    }

    /// Pins that a missing Origin header is allowed on `/healthz` and `/mcp`.
    #[tokio::test]
    async fn absent_origin_is_allowed_on_every_route() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        assert_eq!(get_healthz(&harness.base, None).await?.status(), 200);
        assert_eq!(mcp_initialize(&harness.base, None).await?.status(), 200);
        Ok(())
    }

    /// Pins that an origin carrying a path is rejected.
    #[tokio::test]
    async fn rejects_malformed_origin() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        let resp = mcp_initialize(&harness.base, Some("https://example.com/extra/path")).await?;
        assert_eq!(resp.status(), 403);
        Ok(())
    }

    /// Pins that a non-UTF-8 Origin header fails closed with 403.
    #[tokio::test]
    async fn rejects_non_utf8_origin() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        let value = HeaderValue::from_bytes(b"\xff\xfe")
            .context("obs-text header value is representable")?;

        let resp = reqwest::Client::new()
            .post(format!("{}/mcp", harness.base))
            .header("content-type", "application/json")
            .header("origin", value)
            .body("{}")
            .send()
            .await
            .context("non-utf8 origin request")?;
        assert_eq!(resp.status(), 403, "non-UTF-8 origins must fail closed");
        Ok(())
    }

    /// Pins the `null` origin default-reject and explicit opt-in.
    #[tokio::test]
    async fn null_origin_is_rejected_by_default_and_opt_in_accepted() -> anyhow::Result<()> {
        let default = spawn(base_config().with_allowed_origins([ALLOWED])).await?;
        assert_eq!(
            mcp_initialize(&default.base, Some("null")).await?.status(),
            403
        );

        let opted_in = spawn(base_config().with_allowed_origins([ALLOWED, "null"])).await?;
        assert_eq!(
            mcp_initialize(&opted_in.base, Some("null")).await?.status(),
            200
        );
        Ok(())
    }

    /// Pins that origin rejection (403) precedes auth (401).
    #[tokio::test]
    async fn origin_rejection_precedes_auth() -> anyhow::Result<()> {
        let (_, hash) = generate_api_key().context("generate api key")?;
        let config =
            base_config()
                .with_allowed_origins([ALLOWED])
                .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                    "ops-key", hash, "ops",
                )]));
        let harness = spawn(config).await?;

        let resp = reqwest::Client::new()
            .post(format!("{}/mcp", harness.base))
            .header("origin", "https://evil.example")
            .header("authorization", "Bearer invalid-key")
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .context("rejected-origin request")?;

        assert_eq!(
            resp.status(),
            403,
            "origin must be checked before auth (not 401)"
        );
        assert!(
            resp.headers().get("www-authenticate").is_none(),
            "a rejected origin must not advertise the auth scheme"
        );
        Ok(())
    }

    /// Pins that origin enforcement also covers non-`/mcp` routes.
    #[tokio::test]
    async fn origin_layer_covers_non_mcp_routes() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;

        assert_eq!(
            get_healthz(&harness.base, Some("https://evil.example"))
                .await?
                .status(),
            403
        );
        assert_eq!(
            get_healthz(&harness.base, Some(ALLOWED)).await?.status(),
            200
        );
        Ok(())
    }

    /// Pins that CORS preflight uses the same normalized origin matcher.
    #[tokio::test]
    async fn cors_preflight_uses_the_same_normalized_matcher() -> anyhow::Result<()> {
        // The allowlist entry is the explicit-default-port form; the request uses
        // the implicit form. Raw-string CORS matching would fail here, so a
        // passing preflight proves both layers share the normalized matcher.
        let harness =
            spawn(base_config().with_allowed_origins(["https://example.com:443"])).await?;

        let resp = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("{}/mcp", harness.base))
            .header("origin", "https://example.com")
            .header("access-control-request-method", "POST")
            .send()
            .await
            .context("preflight request")?;

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
        Ok(())
    }

    /// Send a CORS preflight for `/mcp` from [`ALLOWED`], optionally asking for
    /// request headers.
    async fn preflight(
        base: &str,
        method: &str,
        request_headers: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut request = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("{base}/mcp"))
            .header("origin", ALLOWED)
            .header("access-control-request-method", method);
        if let Some(names) = request_headers {
            request = request.header("access-control-request-headers", names);
        }
        timeout(Duration::from_secs(10), request.send())
            .await
            .context("preflight timed out")?
            .context("preflight request")
    }

    /// The lowercased, trimmed names listed across every
    /// `access-control-expose-headers` value of `resp`.
    fn exposed_names(resp: &reqwest::Response) -> anyhow::Result<Vec<String>> {
        let mut names = Vec::new();
        for value in resp.headers().get_all("access-control-expose-headers") {
            let text = value.to_str().context("expose-headers is ASCII")?;
            names.extend(
                text.split(',')
                    .map(|name| name.trim().to_ascii_lowercase())
                    .filter(|name| !name.is_empty()),
            );
        }
        Ok(names)
    }

    /// Pins the browser CORS flow on a real listener.
    ///
    /// Preflights grant the MCP request headers and methods, `initialize`
    /// exposes `mcp-session-id`, an unlisted header is refused, and a request
    /// without `Origin` is unchanged.
    #[tokio::test]
    async fn browser_preflight_and_initialize_expose_the_session_id() -> anyhow::Result<()> {
        let harness = spawn(base_config().with_allowed_origins([ALLOWED])).await?;

        // (1) The MCP headers, including an `Mcp-Param-*` name, are granted.
        let sent = "content-type,mcp-protocol-version,mcp-param-region";
        let granted = preflight(&harness.base, "POST", Some(sent)).await?;
        assert!(
            granted.status().is_success(),
            "preflight must pass, got {}",
            granted.status()
        );
        assert_eq!(
            granted
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok()),
            Some(sent),
            "the allowed request headers must be mirrored"
        );

        // (2) `DELETE` (session termination) is an allowed method.
        let delete = preflight(&harness.base, "DELETE", None).await?;
        let methods = delete
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .context("preflight must list the allowed methods")?;
        assert!(
            methods
                .split(',')
                .any(|method| method.trim().eq_ignore_ascii_case("DELETE")),
            "DELETE must be allowed, got {methods:?}"
        );

        // (3) A browser can read the session id from `initialize`.
        let initialized = timeout(
            Duration::from_secs(10),
            mcp_initialize(&harness.base, Some(ALLOWED)),
        )
        .await
        .context("initialize with origin timed out")??;
        assert_eq!(initialized.status(), 200);
        assert!(
            initialized.headers().get("mcp-session-id").is_some(),
            "initialize must return a session id"
        );
        let exposed = exposed_names(&initialized)?;
        assert!(
            exposed.iter().any(|name| name == "mcp-session-id"),
            "mcp-session-id must be exposed to the browser, got {exposed:?}"
        );

        // (4) A header outside the allowlist gets no grant.
        let refused = preflight(&harness.base, "POST", Some("x-evil")).await?;
        assert!(
            refused
                .headers()
                .get("access-control-allow-headers")
                .is_none(),
            "an unlisted request header must not be granted"
        );

        // (5) A non-browser client (no `Origin`) sees the 3.20.0 headers.
        let plain = timeout(Duration::from_secs(10), mcp_initialize(&harness.base, None))
            .await
            .context("initialize without origin timed out")??;
        assert_eq!(plain.status(), 200);
        assert!(
            plain
                .headers()
                .get("access-control-expose-headers")
                .is_none(),
            "a request without Origin must not get expose-headers"
        );
        let vary = plain
            .headers()
            .get_all("vary")
            .iter()
            .map(|value| value.to_str().context("vary is ASCII"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        assert_eq!(vary, ["origin"], "vary must stay exactly `origin`");
        Ok(())
    }

    /// Pins that a browser on an allowed origin can read the `401` challenge:
    /// the CORS layer wraps auth, so the rejection carries the CORS grant and
    /// exposes `www-authenticate`.
    #[tokio::test]
    async fn browser_gets_the_401_challenge_through_cors() -> anyhow::Result<()> {
        let (_, hash) = generate_api_key().context("generate api key")?;
        let config =
            base_config()
                .with_allowed_origins([ALLOWED])
                .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                    "k", hash, "r",
                )]));
        let harness = spawn(config).await?;

        let resp = timeout(
            Duration::from_secs(10),
            reqwest::Client::new()
                .post(format!("{}/mcp", harness.base))
                .header("origin", ALLOWED)
                .header("content-type", "application/json")
                .body("{}")
                .send(),
        )
        .await
        .context("unauthenticated request timed out")?
        .context("unauthenticated request")?;

        assert_eq!(resp.status(), 401);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some(ALLOWED),
            "the 401 must carry the CORS grant"
        );
        let exposed = exposed_names(&resp)?;
        assert!(
            exposed.iter().any(|name| name == "www-authenticate"),
            "www-authenticate must be exposed to the browser, got {exposed:?}"
        );
        assert!(
            resp.headers().get("www-authenticate").is_some(),
            "the 401 must carry the challenge"
        );
        Ok(())
    }

    /// Pins that `validate` rejects origin entries that can never match.
    #[test]
    fn config_validation_rejects_entries_that_cannot_match() -> anyhow::Result<()> {
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
                .err()
                .context("invalid origin entry must fail validation")?;
            assert!(
                err.to_string().contains("allowed_origins"),
                "error must name the field for {bad:?}: {err}"
            );
        }

        // The tolerated forms still pass.
        drop(
            base_config()
                .with_allowed_origins(["https://example.com/", "null", "http://localhost:3000"])
                .validate()
                .context("equivalent and null entries are valid")?,
        );
        Ok(())
    }
}
