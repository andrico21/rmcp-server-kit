//! TOML configuration pipeline example.
//!
//! Demonstrates the full config-file path: a downstream-owned root config,
//! TOML deserialization, opt-in environment overrides, tracing
//! initialization, validation, bridging into `McpServerConfig`, and the
//! runtime-only wiring the bridge intentionally cannot carry.
//!
//! Run with the embedded config:
//!
//! ```bash
//! cargo run --example config_file_server
//! ```
//!
//! Or pass a real TOML file path:
//!
//! ```bash
//! cargo run --example config_file_server -- ./config.toml
//! ```
//!
//! Then, in another shell:
//!
//! ```bash
//! curl http://127.0.0.1:8080/healthz
//! curl http://127.0.0.1:8080/readyz
//! ```

use std::{path::PathBuf, sync::Arc, time::Duration};

use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use rmcp_server_kit::{
    config::{ObservabilityConfig, ServerConfig, validate_server_config},
    rbac::{RbacConfig, RbacPolicy},
    transport::{McpServerConfig, serve},
};
use serde::Deserialize;

const EMBEDDED_CONFIG: &str = r#"
[server]
listen_addr = "127.0.0.1"
listen_port = 8080
shutdown_timeout = "5s"
request_timeout = "120s"
session_idle_timeout = "20m"
sse_keep_alive = "15s"
allowed_origins = ["http://127.0.0.1:8080"]
tool_rate_limit = 120
tool_rate_limit_burst = 120
max_request_body = 1048576
compression_enabled = true
compression_min_size = 1024
expose_build_metadata = true
admin_enabled = false

[observability]
log_level = "info,rmcp_server_kit=debug"
log_format = "pretty"
metrics_enabled = true
metrics_bind = "127.0.0.1:9092"

[rbac]
enabled = false

[[rbac.roles]]
name = "viewer"
allow = ["resource_list"]
hosts = ["*"]
"#;

/// Application-owned root config.
///
/// rmcp-server-kit deliberately provides reusable sections, not a kit-owned
/// root type. Real applications compose these sections into their own schema.
#[derive(Debug, Deserialize)]
struct AppConfig {
    server: ServerConfig,
    observability: ObservabilityConfig,
    rbac: RbacConfig,
}

#[derive(Clone)]
struct ConfigFileHandler;

impl ServerHandler for ConfigFileHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> rmcp_server_kit::Result<()> {
    // With no argument, use the embedded config so this example runs without
    // external files. Passing a path demonstrates the real-file path using
    // `std::fs::read_to_string` at startup.
    let raw_config = match std::env::args_os().nth(1) {
        Some(path) => std::fs::read_to_string(PathBuf::from(path))?,
        None => EMBEDDED_CONFIG.to_owned(),
    };
    let mut app_config: AppConfig = toml::from_str(&raw_config)?;

    // Environment overrides are opt-in and per-section; callers concatenate
    // the returned audit reports in their downstream-owned root config code.
    let mut override_report = app_config.server.apply_env_overrides()?;
    override_report.extend(app_config.observability.apply_env_overrides()?);
    override_report.extend(app_config.rbac.apply_env_overrides()?);

    // Initialize tracing first, then log the override report so env-shadowing
    // leaves a startup trail. Secret targets report `value = None`.
    let _ = rmcp_server_kit::observability::init_tracing_from_config(&app_config.observability);
    for entry in &override_report {
        tracing::info!(
            env_var = %entry.env_var,
            target = %entry.target_field,
            source = ?entry.source,
            value = ?entry.value,
            "env override applied"
        );
    }

    validate_server_config(&app_config.server)?;
    let base = McpServerConfig::new(
        "127.0.0.1:0",
        "rmcp-server-kit-config-file-example",
        env!("CARGO_PKG_VERSION"),
    );
    let mcp_config = app_config.server.apply_to_mcp_config(base)?;

    // Runtime-only state cannot live in TOML. Build it from the deserialized
    // section and attach it after the bridge.
    let rbac_policy = Arc::new(RbacPolicy::new(&app_config.rbac));
    let mcp_config = mcp_config.with_rbac(rbac_policy);

    // Metrics are also runtime-only and feature-gated; the bridge preserves
    // any metrics settings already on the base, so wire ObservabilityConfig
    // explicitly when the binary enables the `metrics` feature.
    #[cfg(feature = "metrics")]
    let mcp_config = if app_config.observability.metrics_enabled {
        mcp_config.with_metrics(app_config.observability.metrics_bind.as_str())
    } else {
        mcp_config
    };

    #[cfg(not(feature = "metrics"))]
    if app_config.observability.metrics_enabled {
        tracing::warn!(
            "observability.metrics_enabled=true ignored because this binary was built without the metrics feature"
        );
    }

    // Application-level builder calls chained after `apply_to_mcp_config` win
    // over TOML, matching the documented precedence chain.
    let mcp_config = mcp_config.with_request_timeout(Duration::from_secs(30));

    serve(mcp_config.validate()?, || ConfigFileHandler).await
}
