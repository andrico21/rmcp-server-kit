//! Metrics handle injection (issue #25): a caller-supplied [`McpMetrics`] is
//! served with its custom collectors, the fallback registry still works, and a
//! handle missing a framework collector is repaired at startup.
//!
//! The metrics listener binds inside `serve_metrics` and does not expose the
//! chosen port, so each test pre-reserves an ephemeral port, passes the
//! concrete address, and polls for readiness.

#![cfg(feature = "metrics")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use prometheus::{IntCounterVec, opts};
use rmcp::{ServerHandler, model::ServerConfig};
use rmcp_server_kit::{
    metrics::McpMetrics,
    transport::{McpServerConfig, serve_with_listener},
};
use tokio::net::TcpListener;
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

/// Reserve an ephemeral port and release it, so the metrics listener can be
/// handed a concrete address it can be scraped on.
async fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn spawn(config: McpServerConfig) -> Harness {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound: SocketAddr = listener.local_addr().unwrap();
    let config = config.with_bind_addr(bound.to_string());

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
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
    drop(join);

    Harness {
        base: format!("http://{bound}"),
        shutdown,
    }
}

/// Poll the metrics endpoint (readiness loop, bounded) and return its body.
async fn scrape(metrics_bind: &str) -> String {
    let url = format!("http://{metrics_bind}/metrics");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return response.text().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("metrics endpoint never became ready at {url}");
}

fn base_config() -> McpServerConfig {
    McpServerConfig::new("127.0.0.1:0", "metrics-test", "0.0.1")
        .with_shutdown_timeout(Duration::from_millis(100))
}

#[tokio::test]
async fn supplied_handle_is_served_alongside_its_custom_collectors() {
    let metrics = Arc::new(McpMetrics::new().unwrap());
    let custom = IntCounterVec::new(
        opts!("custom_counter_total", "caller-registered counter"),
        &["kind"],
    )
    .unwrap();
    metrics.registry.register(Box::new(custom.clone())).unwrap();
    custom.with_label_values(&["test"]).inc();

    let port = reserve_port().await;
    let metrics_bind = format!("127.0.0.1:{port}");
    let harness = spawn(
        base_config()
            .with_metrics(metrics_bind.clone())
            .with_metrics_handle(Arc::clone(&metrics)),
    )
    .await;

    // Drive one request so the framework counter has a sample to serve
    // (Prometheus prunes empty families).
    let _ = reqwest::get(format!("{}/healthz", harness.base))
        .await
        .unwrap();

    let body = scrape(&metrics_bind).await;
    assert!(
        body.contains("custom_counter_total"),
        "caller-registered collector must be served: {body}"
    );
    assert!(
        body.contains("rmcp_server_kit_http_requests_total"),
        "framework families must still be served: {body}"
    );
}

#[tokio::test]
async fn fallback_registry_is_served_when_no_handle_is_given() {
    let port = reserve_port().await;
    let metrics_bind = format!("127.0.0.1:{port}");
    let harness = spawn(base_config().with_metrics(metrics_bind.clone())).await;

    // Drive one request so the framework counter has a sample to serve.
    let _ = reqwest::get(format!("{}/healthz", harness.base))
        .await
        .unwrap();

    let body = scrape(&metrics_bind).await;
    assert!(
        body.contains("rmcp_server_kit_http_requests_total"),
        "fallback registry must serve the framework families: {body}"
    );
    assert!(
        body.contains("/healthz"),
        "the request that was just made must be recorded: {body}"
    );
}

#[tokio::test]
async fn startup_repairs_a_handle_that_lost_a_framework_collector() {
    let metrics = Arc::new(McpMetrics::new().unwrap());
    // Simulate a handle whose framework collector was dropped: the middleware
    // would keep incrementing it while `/metrics` served nothing from it.
    metrics
        .registry
        .unregister(Box::new(metrics.http_requests_total.clone()))
        .unwrap();

    let port = reserve_port().await;
    let metrics_bind = format!("127.0.0.1:{port}");
    let harness = spawn(
        base_config()
            .with_metrics(metrics_bind.clone())
            .with_metrics_handle(Arc::clone(&metrics)),
    )
    .await;

    let _ = reqwest::get(format!("{}/healthz", harness.base))
        .await
        .unwrap();

    let body = scrape(&metrics_bind).await;
    assert!(
        body.contains("rmcp_server_kit_http_requests_total"),
        "the missing framework collector must be re-registered at startup: {body}"
    );
    assert!(
        body.contains("/healthz"),
        "and its samples must reach /metrics: {body}"
    );
}

#[test]
fn handle_without_an_enabled_listener_is_rejected() {
    let metrics = Arc::new(McpMetrics::new().unwrap());
    let error = base_config()
        .with_metrics_handle(metrics)
        .validate()
        .expect_err("a handle without a listener is a misconfiguration");
    assert!(
        error.to_string().contains("metrics_handle"),
        "validation error must name the field: {error}"
    );
}
