//! Security headers on the `/metrics` listener (D-15).
//!
//! The public [`serve_metrics`] serves the eleven default OWASP headers and no
//! HSTS, while `serve()` forwards the operator's effective overrides and
//! omissions to the metrics listener.
//!
//! The metrics listener binds inside [`serve_metrics`] and does not expose the
//! chosen port, so each test pre-reserves an ephemeral port, passes the
//! concrete address, and polls for readiness.

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use anyhow::Context;
    use rmcp::{ServerHandler, model::ServerConfig};
    use rmcp_server_kit::{
        RmcpServerKitError,
        metrics::{McpMetrics, serve_metrics},
        transport::{McpServerConfig, SecurityHeadersConfig, serve_with_listener},
    };
    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_util::sync::CancellationToken;

    /// The eleven non-HSTS header defaults emitted by
    /// `security_headers_middleware`.
    const DEFAULT_HEADERS: [(&str, &str); 11] = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "deny"),
        ("cache-control", "no-store, max-age=0"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        (
            "permissions-policy",
            "accelerometer=(), camera=(), geolocation=(), microphone=()",
        ),
        ("x-permitted-cross-domain-policies", "none"),
        (
            "content-security-policy",
            "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        ),
        ("x-dns-prefetch-control", "off"),
    ];

    /// A no-op handler: these tests only exercise the metrics listener.
    #[derive(Clone, Default)]
    struct TestHandler;

    impl ServerHandler for TestHandler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::default()
        }
    }

    /// Reserve an ephemeral port and release it, so a listener can bind a
    /// concrete address the test can scrape.
    async fn reserve_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind ephemeral port")?;
        let port = listener.local_addr().context("read ephemeral addr")?.port();
        drop(listener);
        Ok(port)
    }

    /// Poll `url` (bounded readiness loop) and return the response headers.
    async fn fetch_headers(url: &str) -> anyhow::Result<reqwest::header::HeaderMap> {
        let client = reqwest::Client::new();
        let mut last_status = None;
        for _ in 0..100 {
            if let Ok(response) = client.get(url).send().await {
                if response.status().is_success() {
                    let headers = response.headers().clone();
                    // Drain the body so the server-side connection finishes and
                    // graceful shutdown cannot stall on our scrape.
                    let _body = response.text().await.unwrap_or_default();
                    return Ok(headers);
                }
                last_status = Some(response.status());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        anyhow::bail!("{url} never became ready (last status {last_status:?})");
    }

    /// The public `serve_metrics` listener plus the handles needed to stop it.
    struct MetricsHarness {
        bind: String,
        shutdown: CancellationToken,
        join: JoinHandle<Result<(), RmcpServerKitError>>,
    }

    impl MetricsHarness {
        /// Cancel the listener, await its task and propagate a panic or error.
        async fn finish(self) -> anyhow::Result<()> {
            self.shutdown.cancel();
            self.join.await.context("metrics task panicked")??;
            Ok(())
        }
    }

    /// Install the process-wide rustls provider that reqwest's
    /// `rustls-no-provider` build requires before any client is constructed.
    fn install_crypto_provider() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    }

    /// Spawn the public `serve_metrics` on a fresh ephemeral port.
    async fn spawn_serve_metrics() -> anyhow::Result<MetricsHarness> {
        install_crypto_provider();
        let port = reserve_port().await?;
        let bind = format!("127.0.0.1:{port}");
        let metrics = Arc::new(McpMetrics::new()?);
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(serve_metrics(bind.clone(), metrics, shutdown.clone()));
        Ok(MetricsHarness {
            bind,
            shutdown,
            join,
        })
    }

    /// The `serve()` server plus the handles needed to stop it.
    struct ServeHarness {
        shutdown: CancellationToken,
        join: JoinHandle<Result<(), RmcpServerKitError>>,
    }

    impl ServeHarness {
        /// Cancel the server, await its task and propagate a panic or error.
        async fn finish(self) -> anyhow::Result<()> {
            self.shutdown.cancel();
            self.join.await.context("server task panicked")??;
            Ok(())
        }
    }

    /// Start a `serve()` instance (with its metrics listener) on ephemeral
    /// ports and wait until it signals readiness.
    async fn spawn(config: McpServerConfig) -> anyhow::Result<ServeHarness> {
        install_crypto_provider();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind main listener")?;
        let bound: SocketAddr = listener.local_addr().context("read main addr")?;
        let config = config.with_bind_addr(bound.to_string());

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let join = tokio::spawn(async move {
            serve_with_listener(
                listener,
                config.validate()?,
                || TestHandler,
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
        });

        let signalled = tokio::time::timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("server did not signal readiness within 30s")?
            .context("server task aborted before readiness")?;
        assert_eq!(signalled, bound, "readiness address mismatch");

        Ok(ServeHarness { shutdown, join })
    }

    /// Pins that the public `serve_metrics` emits the eleven non-HSTS default
    /// headers and none of HSTS, `Server` or `X-Powered-By`.
    #[tokio::test]
    async fn public_serve_metrics_emits_default_security_headers() -> anyhow::Result<()> {
        let harness = spawn_serve_metrics().await?;
        let headers = fetch_headers(&format!("http://{}/metrics", harness.bind)).await?;

        for (name, value) in DEFAULT_HEADERS {
            let actual = headers
                .get(name)
                .with_context(|| format!("missing header {name}"))?
                .to_str()
                .with_context(|| format!("header {name} is not valid UTF-8"))?;
            assert_eq!(actual, value, "header {name}");
        }
        for absent in ["strict-transport-security", "server", "x-powered-by"] {
            assert!(
                headers.get(absent).is_none(),
                "header {absent} must not be present on the plaintext listener"
            );
        }

        harness.finish().await
    }

    /// Pins that `serve()` forwards the operator's security-header overrides
    /// and omissions to the `/metrics` listener.
    #[tokio::test]
    async fn serve_forwards_operator_overrides_to_metrics() -> anyhow::Result<()> {
        let metrics_port = reserve_port().await?;
        let metrics_bind = format!("127.0.0.1:{metrics_port}");

        let mut security_headers = SecurityHeadersConfig::default();
        security_headers.x_frame_options = Some("sameorigin".to_owned());
        security_headers.referrer_policy = Some(String::new());

        let config = McpServerConfig::new("127.0.0.1:0", "metrics-headers-test", "0.0.1")
            .with_shutdown_timeout(Duration::from_millis(100))
            .with_metrics(metrics_bind.clone())
            .with_security_headers(security_headers);

        let harness = spawn(config).await?;
        let headers = fetch_headers(&format!("http://{metrics_bind}/metrics")).await?;

        let frame_options = headers
            .get("x-frame-options")
            .context("x-frame-options override missing")?
            .to_str()
            .context("x-frame-options is not valid UTF-8")?;
        assert_eq!(frame_options, "sameorigin", "x-frame-options override");
        assert!(
            headers.get("referrer-policy").is_none(),
            "referrer_policy = Some(\"\") must omit the header"
        );

        harness.finish().await
    }
}
