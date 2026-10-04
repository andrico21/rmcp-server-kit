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
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(clippy::absolute_paths, reason = "lint-migration: src/metrics.rs")
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(clippy::min_ident_chars, reason = "lint-migration: src/metrics.rs")
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::missing_inline_in_public_items,
        reason = "lint-migration: src/metrics.rs"
    )
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::module_name_repetitions,
        reason = "lint-migration: src/metrics.rs"
    )
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "lint-migration: src/metrics.rs"
    )
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(
        clippy::std_instead_of_alloc,
        reason = "lint-migration: src/metrics.rs"
    )
)]
#![cfg_attr(
    all(feature = "metrics", target_os = "linux"),
    expect(clippy::unused_trait_names, reason = "lint-migration: src/metrics.rs")
)]

use std::sync::Arc;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder, opts,
};

use crate::{
    error::RmcpServerKitError,
    transport::{SecurityHeadersConfig, security_headers_middleware},
};

/// Default Prometheus histogram buckets for HTTP request latency
/// (seconds). Tuned for low-latency service work: sub-millisecond
/// through five seconds, covering health-check fast paths up to slow
/// outbound dependencies. Operators that need different buckets can
/// register their own histogram against
/// [`McpMetrics::registry`].
const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Collected Prometheus metrics for an MCP server.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
    pub fn new() -> Result<Self, RmcpServerKitError> {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            opts!("rmcp_server_kit_http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;
        registry
            .register(Box::new(http_requests_total.clone()))
            .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "rmcp_server_kit_http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(HTTP_DURATION_BUCKETS.to_vec()),
            &["method", "path"],
        )
        .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;

        let rate_limited_total = IntCounterVec::new(
            opts!(
                "rmcp_server_kit_rate_limited_total",
                "Rate-limiter denials by limiter"
            ),
            &["limiter"],
        )
        .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;
        registry
            .register(Box::new(rate_limited_total.clone()))
            .map_err(|e| RmcpServerKitError::Metrics(e.to_string()))?;

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
pub(crate) fn record_rate_limit_deny(ext: &axum::http::Extensions, limiter: &str) {
    if let Some(m) = ext.get::<Arc<McpMetrics>>() {
        m.rate_limited_total.with_label_values(&[limiter]).inc();
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
// cancel-safe: the parent server cancels via `shutdown.cancelled()` inside
// axum graceful shutdown; dropping this future directly only drops the
// listener/app, with no metrics registry mutation or detached work.
pub async fn serve_metrics(
    bind: String,
    metrics: Arc<McpMetrics>,
    shutdown: tokio_util::sync::CancellationToken,
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
    shutdown: tokio_util::sync::CancellationToken,
    security_headers: SecurityHeadersConfig,
) -> Result<(), RmcpServerKitError> {
    let cfg = Arc::new(security_headers);
    let app = axum::Router::new()
        .route(
            "/metrics",
            axum::routing::get(move || {
                let m = Arc::clone(&metrics);
                async move { m.encode() }
            }),
        )
        .layer(axum::middleware::from_fn(move |req, next| {
            security_headers_middleware(false, Arc::clone(&cfg), req, next)
        }));

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| RmcpServerKitError::Startup(format!("metrics bind {bind}: {e}")))?;
    tracing::info!("metrics endpoint listening on http://{bind}/metrics");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| RmcpServerKitError::Startup(format!("metrics serve: {e}")))?;
    Ok(())
}

#[cfg_attr(
    all(test, feature = "metrics", target_os = "linux"),
    expect(clippy::expect_used, reason = "lint-migration: src/metrics.rs")
)]
#[cfg_attr(
    all(test, feature = "metrics", target_os = "linux"),
    expect(clippy::std_instead_of_core, reason = "lint-migration: src/metrics.rs")
)]
#[cfg_attr(
    all(test, feature = "metrics", target_os = "linux"),
    expect(clippy::unwrap_used, reason = "lint-migration: src/metrics.rs")
)]
#[cfg_attr(
    all(test, feature = "metrics", target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(test, feature = "metrics"),
    expect(unused_results, reason = "lint-migration: src/metrics.rs")
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_failure_returns_stable_non_empty_marker() {
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
    }

    #[test]
    fn new_creates_registry_with_counters() {
        let m = McpMetrics::new().unwrap();
        // Incrementing a counter should make it appear in gather output.
        m.http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        m.http_request_duration_seconds
            .with_label_values(&["GET", "/test"])
            .observe(0.1);
        assert_eq!(m.registry.gather().len(), 2);
    }

    #[test]
    fn encode_empty_registry() {
        let m = McpMetrics::new().unwrap();
        let output = m.encode();
        // Empty counters/histograms produce no samples but the output is valid.
        assert!(output.is_empty() || output.contains("rmcp_server_kit_"));
    }

    #[test]
    fn counter_increment_shows_in_encode() {
        let m = McpMetrics::new().unwrap();
        m.http_requests_total
            .with_label_values(&["GET", "/healthz", "200"])
            .inc();
        let output = m.encode();
        assert!(output.contains("rmcp_server_kit_http_requests_total"));
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("path=\"/healthz\""));
        assert!(output.contains("status=\"200\""));
        assert!(output.contains(" 1")); // count = 1
    }

    #[test]
    fn histogram_observe_shows_in_encode() {
        let m = McpMetrics::new().unwrap();
        m.http_request_duration_seconds
            .with_label_values(&["POST", "/mcp"])
            .observe(0.042);
        let output = m.encode();
        assert!(output.contains("rmcp_server_kit_http_request_duration_seconds"));
        assert!(output.contains("method=\"POST\""));
        assert!(output.contains("path=\"/mcp\""));
    }

    #[test]
    fn multiple_increments_accumulate() {
        let m = McpMetrics::new().unwrap();
        let counter = m
            .http_requests_total
            .with_label_values(&["POST", "/mcp", "200"]);
        counter.inc();
        counter.inc();
        counter.inc();
        let output = m.encode();
        assert!(output.contains(" 3")); // count = 3
    }

    #[test]
    fn clone_shares_registry() {
        let m = McpMetrics::new().unwrap();
        let m2 = m.clone();
        m.http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        // The clone should see the same counter value.
        let output = m2.encode();
        assert!(output.contains(" 1"));
    }

    #[test]
    fn rate_limited_counter_registers_and_encodes() {
        let m = McpMetrics::new().unwrap();
        m.rate_limited_total.with_label_values(&["tool"]).inc();
        let output = m.encode();
        assert!(output.contains("rmcp_server_kit_rate_limited_total"));
        assert!(output.contains("limiter=\"tool\""));
        assert!(output.contains(" 1"));
    }

    #[test]
    fn record_rate_limit_deny_increments_via_extension() {
        let m = Arc::new(McpMetrics::new().unwrap());
        let mut ext = axum::http::Extensions::new();
        ext.insert(Arc::clone(&m));
        record_rate_limit_deny(&ext, "auth_pre");
        record_rate_limit_deny(&ext, "auth_pre");
        assert_eq!(
            m.rate_limited_total.with_label_values(&["auth_pre"]).get(),
            2
        );
        // Absent handle: silent no-op (metrics disabled path).
        let empty = axum::http::Extensions::new();
        record_rate_limit_deny(&empty, "auth_pre");
        assert_eq!(
            m.rate_limited_total.with_label_values(&["auth_pre"]).get(),
            2
        );
    }

    // M7 regression: cancelling the shutdown token must release the
    // metrics listener's bound port so a subsequent bind to the same
    // address succeeds. Prior to M7 the metrics endpoint ran without
    // graceful_shutdown wiring and would leak the port until process
    // exit.
    #[tokio::test]
    async fn serve_metrics_releases_port_on_shutdown() {
        // Pick an ephemeral port, then drop the probe so serve_metrics
        // can claim it.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let metrics = Arc::new(McpMetrics::new().unwrap());
        let shutdown = tokio_util::sync::CancellationToken::new();
        let handle = tokio::spawn(serve_metrics(
            addr.to_string(),
            Arc::clone(&metrics),
            shutdown.clone(),
        ));

        // Wait until the listener is actually accepting connections.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "metrics listener never accepted on {addr}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Cancel and await graceful shutdown.
        shutdown.cancel();
        let join = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("serve_metrics did not return within timeout");
        join.expect("join error")
            .expect("serve_metrics returned Err");

        // Port must be immediately rebindable.
        let rebind = tokio::net::TcpListener::bind(addr)
            .await
            .expect("port not released after shutdown");
        drop(rebind);
    }
}
