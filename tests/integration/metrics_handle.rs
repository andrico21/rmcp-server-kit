//! Metrics handle injection (issue #25): a caller-supplied [`McpMetrics`] is
//! served with its custom collectors, the fallback registry still works, and a
//! handle missing a framework collector is repaired at startup.
//!
//! The metrics listener binds inside `serve_metrics` and does not expose the
//! chosen port, so each test pre-reserves an ephemeral port, passes the
//! concrete address, and polls for readiness.
#[cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{net::SocketAddr, time::Duration};

    use anyhow::Context as _;
    use prometheus::{IntCounterVec, opts};
    use reqwest::Client;
    use rmcp::{ServerHandler, model::ServerConfig};
    use rmcp_server_kit::{
        metrics::McpMetrics,
        transport::{McpServerConfig, serve_with_listener},
    };
    use rustls::crypto::ring;
    use tokio::{
        net::TcpListener,
        sync::oneshot,
        time::{sleep, timeout},
    };
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

    // Drop audit (2026-10-04): the harness owns only the shutdown token and
    // cancelling it releases the spawn task; no lock or fd is held here.
    impl Drop for Harness {
        fn drop(&mut self) {
            self.shutdown.cancel();
        }
    }

    /// Reserve an ephemeral port and release it, so the metrics listener can be
    /// handed a concrete address it can be scraped on.
    async fn reserve_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind ephemeral port")?;
        let port = listener.local_addr().context("read ephemeral addr")?.port();
        drop(listener);
        Ok(port)
    }

    async fn spawn(config: McpServerConfig) -> anyhow::Result<Harness> {
        drop(ring::default_provider().install_default());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind main listener")?;
        let bound: SocketAddr = listener.local_addr().context("read main addr")?;
        let bound_config = config.with_bind_addr(bound.to_string());

        let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let join = tokio::spawn(async move {
            serve_with_listener(
                listener,
                bound_config.validate().context("test config valid")?,
                || TestHandler,
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
            .context("serve_with_listener")
        });

        let signalled = timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("server did not signal readiness")?
            .context("server task aborted before readiness")?;
        assert_eq!(signalled, bound, "readiness address mismatch");
        drop(join);

        Ok(Harness {
            base: format!("http://{bound}"),
            shutdown,
        })
    }

    /// Poll the metrics endpoint (readiness loop, bounded) and return its body.
    async fn scrape(metrics_bind: &str) -> anyhow::Result<String> {
        let url = format!("http://{metrics_bind}/metrics");
        let client = Client::new();
        for _ in 0..100_u32 {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
            {
                return response.text().await.context("read metrics body");
            }
            sleep(Duration::from_millis(20)).await;
        }
        anyhow::bail!("metrics endpoint never became ready at {url}");
    }

    fn base_config() -> McpServerConfig {
        McpServerConfig::new("127.0.0.1:0", "metrics-test", "0.0.1")
            .with_shutdown_timeout(Duration::from_millis(100))
    }

    /// Pins that a caller-supplied handle is served with its custom collectors
    /// and the framework families.
    #[tokio::test]
    async fn supplied_handle_is_served_alongside_its_custom_collectors() -> anyhow::Result<()> {
        let metrics = Arc::new(McpMetrics::new().context("build metrics")?);
        let custom = IntCounterVec::new(
            opts!("custom_counter_total", "caller-registered counter"),
            &["kind"],
        )
        .context("build custom counter")?;
        metrics
            .registry
            .register(Box::new(custom.clone()))
            .context("register custom collector")?;
        custom.with_label_values(&["test"]).inc();

        let port = reserve_port().await?;
        let metrics_bind = format!("127.0.0.1:{port}");
        let harness = spawn(
            base_config()
                .with_metrics(metrics_bind.clone())
                .with_metrics_handle(Arc::clone(&metrics)),
        )
        .await?;

        // Drive one request so the framework counter has a sample to serve
        // (Prometheus prunes empty families).
        drop(
            reqwest::get(format!("{}/healthz", harness.base))
                .await
                .context("drive one framework request")?,
        );

        let body = scrape(&metrics_bind).await?;
        assert!(
            body.contains("custom_counter_total"),
            "caller-registered collector must be served: {body}"
        );
        assert!(
            body.contains("rmcp_server_kit_http_requests_total"),
            "framework families must still be served: {body}"
        );
        Ok(())
    }

    /// Pins that the fallback registry serves the framework families when no
    /// handle is supplied.
    #[tokio::test]
    async fn fallback_registry_is_served_when_no_handle_is_given() -> anyhow::Result<()> {
        let port = reserve_port().await?;
        let metrics_bind = format!("127.0.0.1:{port}");
        let harness = spawn(base_config().with_metrics(metrics_bind.clone())).await?;

        // Drive one request so the framework counter has a sample to serve.
        drop(
            reqwest::get(format!("{}/healthz", harness.base))
                .await
                .context("drive one framework request")?,
        );

        let body = scrape(&metrics_bind).await?;
        assert!(
            body.contains("rmcp_server_kit_http_requests_total"),
            "fallback registry must serve the framework families: {body}"
        );
        assert!(
            body.contains("/healthz"),
            "the request that was just made must be recorded: {body}"
        );
        Ok(())
    }

    /// Pins that startup re-registers a framework collector missing from a
    /// supplied handle.
    #[tokio::test]
    async fn startup_repairs_a_handle_that_lost_a_framework_collector() -> anyhow::Result<()> {
        let metrics = Arc::new(McpMetrics::new().context("build metrics")?);
        // Simulate a handle whose framework collector was dropped: the middleware
        // would keep incrementing it while `/metrics` served nothing from it.
        metrics
            .registry
            .unregister(Box::new(metrics.http_requests_total.clone()))
            .context("unregister framework collector")?;

        let port = reserve_port().await?;
        let metrics_bind = format!("127.0.0.1:{port}");
        let harness = spawn(
            base_config()
                .with_metrics(metrics_bind.clone())
                .with_metrics_handle(Arc::clone(&metrics)),
        )
        .await?;

        drop(
            reqwest::get(format!("{}/healthz", harness.base))
                .await
                .context("drive one framework request")?,
        );

        let body = scrape(&metrics_bind).await?;
        assert!(
            body.contains("rmcp_server_kit_http_requests_total"),
            "the missing framework collector must be re-registered at startup: {body}"
        );
        assert!(
            body.contains("/healthz"),
            "and its samples must reach /metrics: {body}"
        );
        Ok(())
    }

    /// Pins that a handle configured without a metrics listener is rejected by
    /// validation.
    #[test]
    fn handle_without_an_enabled_listener_is_rejected() -> anyhow::Result<()> {
        let metrics = Arc::new(McpMetrics::new().context("build metrics")?);
        let error = base_config()
            .with_metrics_handle(metrics)
            .validate()
            .err()
            .context("a handle without a listener is a misconfiguration")?;
        assert!(
            error.to_string().contains("metrics_handle"),
            "validation error must name the field: {error}"
        );
        Ok(())
    }
}
