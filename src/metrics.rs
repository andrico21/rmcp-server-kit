//! Prometheus metrics for MCP servers.
//!
//! Provides a shared [`crate::metrics::McpMetrics`] registry with standard HTTP counters.
//! The transport layer exposes these via a `/metrics` endpoint on a
//! dedicated listener when `metrics_enabled` is true.
//!
//! # Public surface and the `prometheus` crate
//!
//! [`crate::metrics::McpMetrics::registry`] and the `IntCounterVec` / `HistogramVec` fields are
//! intentionally exposed so downstream crates can register additional custom
//! collectors against the same registry. This re-exports the [`prometheus`]
//! crate types as part of `rmcp-server-kit`'s public API; pin the same major version to
//! avoid type-identity mismatches when registering custom metrics.

extern crate alloc;

use alloc::sync::Arc;

use axum::{http::Extensions, middleware::from_fn, routing::get};
use prometheus::{
    Encoder as _, HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder, opts,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::{
    error::RmcpServerKitError,
    transport::{SecurityHeadersConfig, security_headers_middleware},
};

/// Default Prometheus histogram buckets for HTTP request latency
/// (seconds).
///
/// Tuned for low-latency service work: sub-millisecond through five
/// seconds, covering health-check fast paths up to slow outbound
/// dependencies. Operators that need different buckets can register
/// their own histogram against [`McpMetrics::registry`].
const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Collected Prometheus metrics for an MCP server.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct McpMetrics {
    /// Prometheus registry holding all counters and histograms.
    pub registry: Registry,
    /// Total HTTP requests by method, path, and status code.
    pub http_requests_total: IntCounterVec,
    /// HTTP request duration in seconds by method and path.
    pub http_request_duration_seconds: HistogramVec,
    /// Rate-limiter denials by limiter. Label `limiter` is one of
    /// `tool`, `auth_pre`, `auth_post`, `extra_route` - matching the
    /// four built-in per-IP limiters. Incremented at each deny site
    /// alongside the existing warn-level log.
    pub rate_limited_total: IntCounterVec,
}

impl McpMetrics {
    /// Create a new metrics registry with default MCP counters.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Metrics`] if counter registration fails (should
    /// not happen unless duplicate registrations occur).
    #[inline]
    pub fn new() -> Result<Self, RmcpServerKitError> {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            opts!("rmcp_server_kit_http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;
        registry
            .register(Box::new(http_requests_total.clone()))
            .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "rmcp_server_kit_http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(HTTP_DURATION_BUCKETS.to_vec()),
            &["method", "path"],
        )
        .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;

        let rate_limited_total = IntCounterVec::new(
            opts!(
                "rmcp_server_kit_rate_limited_total",
                "Rate-limiter denials by limiter"
            ),
            &["limiter"],
        )
        .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;
        registry
            .register(Box::new(rate_limited_total.clone()))
            .map_err(|error| RmcpServerKitError::Metrics(error.to_string()))?;

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            rate_limited_total,
        })
    }

    /// Encode all collected metrics as Prometheus text format.
    ///
    /// On encoder failure the response is a **non-empty, stable marker body**
    /// rather than an empty string, and the failure is logged at ERROR: with
    /// caller-registered collectors admitted, one malformed collector must not
    /// silently blank an entire scrape.
    #[must_use]
    #[inline]
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        if let Err(error) = encoder.encode(&metric_families, &mut buf) {
            return encode_failure_body(&error);
        }
        // TextEncoder always produces valid UTF-8; fall back to empty on
        // the near-impossible chance it doesn't.
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Marker body served when Prometheus encoding fails. Public within the crate
/// so tests can assert its stability; scrapers and alert rules can key on it.
pub(crate) const ENCODE_FAILURE_MARKER: &str =
    "# rmcp-server-kit: prometheus encoding failed - see server logs\n";

/// Build the failure body and log the underlying encoder error at ERROR.
///
/// The text encoder's only failure mode is an IO error from the sink (it
/// performs no content validation), so this branch is unreachable with the
/// in-memory `Vec` sink [`McpMetrics::encode`] uses - it exists so that a
/// future writer-backed path, or a prometheus version that adds validation,
/// cannot serve an empty scrape.
fn encode_failure_body(error: &prometheus::Error) -> String {
    tracing::error!(error = %error, "prometheus encoding failed; serving error marker body");
    ENCODE_FAILURE_MARKER.to_owned()
}

/// Increment the rate-limiter deny counter for `limiter`, if the shared
/// [`McpMetrics`] handle is present in the request extensions.
///
/// The handle is inserted by the transport's metrics middleware (the
/// outermost layer on the merged router) only when `metrics_enabled` is
/// true; absent the extension this is a no-op, so deny sites behave
/// identically with metrics disabled. `limiter` is one of `tool`,
/// `auth_pre`, `auth_post`, `extra_route`.
pub(crate) fn record_rate_limit_deny(ext: &Extensions, limiter: &str) {
    if let Some(handle) = ext.get::<Arc<McpMetrics>>() {
        handle
            .rate_limited_total
            .with_label_values(&[limiter])
            .inc();
    }
}

/// Spawn a dedicated HTTP listener that serves Prometheus metrics on `/metrics`.
///
/// The listener exits and releases the bound port when `shutdown` is
/// cancelled, keeping the metrics endpoint tied to the parent server's
/// graceful-shutdown lifecycle (M7).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if the TCP listener cannot bind or the
/// underlying axum server fails.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
// cancel-safe: the parent server cancels via `shutdown.cancelled()` inside
// axum graceful shutdown; dropping this future directly only drops the
// listener/app, with no metrics registry mutation or detached work.
pub async fn serve_metrics(
    bind: String,
    metrics: Arc<McpMetrics>,
    shutdown: CancellationToken,
) -> Result<(), RmcpServerKitError> {
    serve_metrics_with_security_headers(bind, metrics, shutdown, SecurityHeadersConfig::default())
        .await
}

/// Spawn a dedicated plaintext HTTP listener that serves Prometheus metrics on
/// `/metrics`, decorated with the same OWASP security headers as the main
/// router.
///
/// This is the [`serve_metrics`] body with an operator-supplied
/// [`SecurityHeadersConfig`]. The metrics listener is always plaintext - the
/// main server's TLS setting does not apply to it - so `is_tls` is fixed to
/// `false` and no `Strict-Transport-Security` header is emitted. Overrides and
/// omissions in `security_headers` are honoured exactly as on the main router.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if the TCP listener cannot bind or the
/// underlying axum server fails.
// cancel-safe: same as [`serve_metrics`] - the parent server cancels via
// `shutdown.cancelled()` inside axum graceful shutdown; dropping this future
// only drops the listener/app, with no metrics registry mutation.
pub(crate) async fn serve_metrics_with_security_headers(
    bind: String,
    metrics: Arc<McpMetrics>,
    shutdown: CancellationToken,
    security_headers: SecurityHeadersConfig,
) -> Result<(), RmcpServerKitError> {
    let cfg = Arc::new(security_headers);
    let app = axum::Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = Arc::clone(&metrics);
                async move { handle.encode() }
            }),
        )
        .layer(from_fn(move |req, next| {
            security_headers_middleware(false, Arc::clone(&cfg), req, next)
        }));

    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|error| RmcpServerKitError::Startup(format!("metrics bind {bind}: {error}")))?;
    tracing::info!("metrics endpoint listening on http://{bind}/metrics");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|error| RmcpServerKitError::Startup(format!("metrics serve: {error}")))?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::time::Instant;

    use anyhow::Context as _;
    use tokio::{
        net::TcpStream,
        time::{sleep, timeout},
    };

    use super::*;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/metrics.rs::encode_failure_returns_stable_non_empty_marker keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a failed encode serves the stable non-empty marker body.
    fn encode_failure_returns_stable_non_empty_marker() -> anyhow::Result<()> {
        // The encoder's only failure mode is an IO error from the sink, so the
        // failure branch is driven here through `encode_failure_body` - the
        // exact function `encode` returns through - rather than through a
        // collector, which cannot make the encoder fail.
        let body = encode_failure_body(&prometheus::Error::Msg("encoder exploded".to_owned()));

        assert!(
            !body.is_empty(),
            "a failed encode must never serve an empty body"
        );
        assert!(
            body.contains("rmcp-server-kit: prometheus encoding failed"),
            "marker body must be stable for scrapers/alerts: {body:?}"
        );
        assert_eq!(body, ENCODE_FAILURE_MARKER);
        Ok(())
    }

    /// Pins that `new` registers the HTTP request counters and histogram.
    #[test]
    fn new_creates_registry_with_counters() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        // Incrementing a counter should make it appear in gather output.
        metrics
            .http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        metrics
            .http_request_duration_seconds
            .with_label_values(&["GET", "/test"])
            .observe(0.1);
        assert_eq!(metrics.registry.gather().len(), 2);
        Ok(())
    }

    /// Pins that an empty registry still encodes valid output.
    #[test]
    fn encode_empty_registry() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        let output = metrics.encode();
        // Empty counters/histograms produce no samples but the output is valid.
        assert!(output.is_empty() || output.contains("rmcp_server_kit_"));
        Ok(())
    }

    /// Pins that an incremented counter shows up in the encoded output.
    #[test]
    fn counter_increment_shows_in_encode() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        metrics
            .http_requests_total
            .with_label_values(&["GET", "/healthz", "200"])
            .inc();
        let output = metrics.encode();
        assert!(output.contains("rmcp_server_kit_http_requests_total"));
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("path=\"/healthz\""));
        assert!(output.contains("status=\"200\""));
        assert!(output.contains(" 1")); // count = 1
        Ok(())
    }

    /// Pins that an observed histogram sample shows up in the encoded output.
    #[test]
    fn histogram_observe_shows_in_encode() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        metrics
            .http_request_duration_seconds
            .with_label_values(&["POST", "/mcp"])
            .observe(0.042);
        let output = metrics.encode();
        assert!(output.contains("rmcp_server_kit_http_request_duration_seconds"));
        assert!(output.contains("method=\"POST\""));
        assert!(output.contains("path=\"/mcp\""));
        Ok(())
    }

    /// Pins that repeated increments accumulate in the encoded counter.
    #[test]
    fn multiple_increments_accumulate() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        let counter = metrics
            .http_requests_total
            .with_label_values(&["POST", "/mcp", "200"]);
        counter.inc();
        counter.inc();
        counter.inc();
        let output = metrics.encode();
        assert!(output.contains(" 3")); // count = 3
        Ok(())
    }

    /// Pins that a clone observes the same underlying registry.
    #[test]
    fn clone_shares_registry() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        let metrics_clone = metrics.clone();
        metrics
            .http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        // The clone should see the same counter value.
        let output = metrics_clone.encode();
        assert!(output.contains(" 1"));
        Ok(())
    }

    /// Pins that the rate-limited counter registers and encodes.
    #[test]
    fn rate_limited_counter_registers_and_encodes() -> anyhow::Result<()> {
        let metrics = McpMetrics::new()?;
        metrics
            .rate_limited_total
            .with_label_values(&["tool"])
            .inc();
        let output = metrics.encode();
        assert!(output.contains("rmcp_server_kit_rate_limited_total"));
        assert!(output.contains("limiter=\"tool\""));
        assert!(output.contains(" 1"));
        Ok(())
    }

    /// Pins that the deny counter increments only when the handle is present.
    #[test]
    fn record_rate_limit_deny_increments_via_extension() -> anyhow::Result<()> {
        let metrics = Arc::new(McpMetrics::new()?);
        let mut ext = Extensions::new();
        let _previous = ext.insert(Arc::clone(&metrics));
        record_rate_limit_deny(&ext, "auth_pre");
        record_rate_limit_deny(&ext, "auth_pre");
        assert_eq!(
            metrics
                .rate_limited_total
                .with_label_values(&["auth_pre"])
                .get(),
            2
        );
        // Absent handle: silent no-op (metrics disabled path).
        let empty = Extensions::new();
        record_rate_limit_deny(&empty, "auth_pre");
        assert_eq!(
            metrics
                .rate_limited_total
                .with_label_values(&["auth_pre"])
                .get(),
            2
        );
        Ok(())
    }

    /// Pins that cancelling the shutdown token releases the metrics listener port.
    #[tokio::test]
    async fn serve_metrics_releases_port_on_shutdown() -> anyhow::Result<()> {
        // Pick an ephemeral port, then drop the probe so serve_metrics
        // can claim it.
        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr().context("probe local addr")?;
        drop(probe);

        let metrics = Arc::new(McpMetrics::new()?);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(serve_metrics(
            addr.to_string(),
            Arc::clone(&metrics),
            shutdown.clone(),
        ));

        // Wait until the listener is actually accepting connections.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "metrics listener never accepted on {addr}"
            );
            sleep(Duration::from_millis(20)).await;
        }

        // Cancel and await graceful shutdown.
        shutdown.cancel();
        let join = timeout(Duration::from_secs(5), handle)
            .await
            .context("serve_metrics did not return within timeout")?;
        join.context("join error")?
            .context("serve_metrics returned Err")?;

        // Port must be immediately rebindable.
        let rebind = TcpListener::bind(addr)
            .await
            .context("port not released after shutdown")?;
        drop(rebind);
        Ok(())
    }
}
