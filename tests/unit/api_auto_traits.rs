//! Compile-time `Send` assertions for the futures returned by the crate's
//! public `async fn` entry points.
//!
//! `cargo semver-checks` cannot observe auto-trait changes on the opaque future
//! types produced by an `async fn` (snapshot fact G-12 / N-25), so a future that
//! silently stops being `Send` would not be caught by the semver gate. These
//! tests construct each public server-entry-point future and never poll it: if
//! the `Send` auto trait regresses, this target fails to *compile*.
//!
//! Covered entry points: [`serve`], [`serve_with_listener`], [`serve_stdio`],
//! and - under the `metrics` feature - [`serve_metrics`]. The `metrics`
//! assertion is `cfg`-gated rather than adding `required-features` to the whole
//! target, so the non-metrics assertions still run in every feature config.
//!
//! `Sync` is deliberately not asserted: all four futures hold `Send`-only
//! internals (`Pin<Box<dyn Future + Send>>` from axum, a `Box<dyn FnOnce(..) +
//! Send>` reload callback, rmcp's `impl Future + Send`), so they are `Send` but
//! not `Sync` on the current tree. Pinning a `!Sync` fact would be a negative
//! assertion the type system cannot express; the migration record fixes the
//! observed truth instead.

#[cfg(feature = "metrics")]
extern crate alloc;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    #[cfg(feature = "metrics")]
    use alloc::sync::Arc;

    use anyhow::Context as _;
    use rmcp::{
        ServerHandler,
        model::{ServerCapabilities, ServerConfig},
    };
    use rmcp_server_kit::transport::{
        McpServerConfig, Validated, serve, serve_stdio, serve_with_listener,
    };
    use tokio::net::TcpListener;

    /// Minimal MCP handler used only to name the `H: ServerHandler` bound of the
    /// `serve*` entry points.
    #[derive(Clone)]
    struct ProbeHandler;

    impl ServerHandler for ProbeHandler {
        /// Report an empty tool-capable server; the future is never polled, so
        /// the advertised capabilities are irrelevant.
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }
    }

    /// Compile-time proof that `T: Send`.
    fn assert_send<T>(_: &T)
    where
        T: Send,
    {
    }

    /// Build a validated probe configuration on an ephemeral loopback address.
    fn probe_config() -> anyhow::Result<Validated<McpServerConfig>> {
        McpServerConfig::new("127.0.0.1:0", "api-auto-traits", "0.0.0")
            .validate()
            .context("probe configuration must validate")
    }

    /// Pins `Send` on the future returned by `serve`.
    #[tokio::test]
    async fn serve_future_is_send() -> anyhow::Result<()> {
        let config = probe_config()?;
        let future = serve(config, || ProbeHandler);
        assert_send(&future);
        Ok(())
    }

    /// Pins `Send` on the future returned by `serve_with_listener`.
    #[tokio::test]
    async fn serve_with_listener_future_is_send() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("probe listener must bind")?;
        let config = probe_config()?;
        let future = serve_with_listener(listener, config, || ProbeHandler, None, None);
        assert_send(&future);
        Ok(())
    }

    /// Pins `Send` on the future returned by `serve_stdio`.
    #[tokio::test]
    async fn serve_stdio_future_is_send() -> anyhow::Result<()> {
        let future = serve_stdio(ProbeHandler);
        assert_send(&future);
        Ok(())
    }

    /// Pins `Send` on the future returned by `serve_metrics` (feature
    /// `metrics`).
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn serve_metrics_future_is_send() -> anyhow::Result<()> {
        use rmcp_server_kit::metrics::{McpMetrics, serve_metrics};
        use tokio_util::sync::CancellationToken;

        let metrics = Arc::new(McpMetrics::new().context("probe metrics registry")?);
        let shutdown = CancellationToken::new();
        let future = serve_metrics("127.0.0.1:0".to_owned(), metrics, shutdown);
        assert_send(&future);
        Ok(())
    }
}
