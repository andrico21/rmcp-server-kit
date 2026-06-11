use std::path::PathBuf;

use serde::Deserialize;

/// Server listener configuration (reusable across MCP projects).
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Listen address (IP or hostname). Default: `127.0.0.1`.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Listen TCP port. Default: `8443`.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Path to the TLS certificate (PEM). Required for TLS/mTLS.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key (PEM). Required for TLS/mTLS.
    pub tls_key_path: Option<PathBuf>,
    /// Per-handshake deadline on the TLS accept path, parsed via
    /// `humantime`. Idle or slow-loris connections are dropped once it
    /// elapses. Startup-only (not hot-reloadable); ignored unless TLS is
    /// configured. Default: `10s`.
    #[serde(default = "default_tls_handshake_timeout")]
    pub tls_handshake_timeout: String,
    /// Cap on concurrently in-flight TLS handshakes. At saturation the
    /// acceptor stops pulling new connections from the kernel backlog
    /// (backpressure). Startup-only (not hot-reloadable); ignored unless
    /// TLS is configured. Default: `256`.
    #[serde(default = "default_max_concurrent_tls_handshakes")]
    pub max_concurrent_tls_handshakes: usize,
    /// Graceful shutdown timeout, parsed via `humantime`.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: String,
    /// Per-request timeout, parsed via `humantime`.
    #[serde(default = "default_request_timeout")]
    pub request_timeout: String,
    /// Allowed Origin header values for DNS rebinding protection (MCP spec).
    /// Requests with an Origin not in this list are rejected with 403.
    /// Requests without an Origin header are always allowed (non-browser).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Allow the stdio transport subcommand. Disabled by default because
    /// stdio mode bypasses auth, RBAC, TLS, and Origin validation.
    #[serde(default)]
    pub stdio_enabled: bool,
    /// Maximum tool invocations per source IP per minute.
    /// When set, enforced by the RBAC middleware on `tools/call` requests.
    /// Protects against both abuse and runaway LLM loops.
    pub tool_rate_limit: Option<u32>,
    /// Burst capacity for the tool rate limiter (bucket size; sustained
    /// rate stays `tool_rate_limit`). Requires `tool_rate_limit`; must
    /// be greater than zero.
    pub tool_rate_limit_burst: Option<u32>,
    /// Maximum requests per source IP per minute on application routes
    /// merged via `McpServerConfig::with_extra_router` (which bypass
    /// auth/RBAC). Opt-in; must be greater than zero when set.
    /// Keyed by the direct socket peer — no `X-Forwarded-For`
    /// interpretation. Startup-only.
    pub extra_route_rate_limit: Option<u32>,
    /// Burst capacity for the extra-route rate limiter (bucket size;
    /// sustained rate stays `extra_route_rate_limit`). Requires
    /// `extra_route_rate_limit`; must be greater than zero.
    pub extra_route_rate_limit_burst: Option<u32>,
    /// Idle timeout for MCP sessions. Sessions with no activity for this
    /// duration are closed automatically. Default: 20 minutes.
    #[serde(default = "default_session_idle_timeout")]
    pub session_idle_timeout: String,
    /// Interval for SSE keep-alive pings sent to the client. Prevents
    /// proxies and load balancers from killing idle connections.
    /// Default: 15 seconds.
    #[serde(default = "default_sse_keep_alive")]
    pub sse_keep_alive: String,
    /// Externally reachable base URL (e.g. `https://mcp.example.com`).
    /// When set, OAuth metadata endpoints advertise this URL instead of
    /// the listen address. Required when the server binds to `0.0.0.0`
    /// behind a reverse proxy or inside a container.
    pub public_url: Option<String>,
    /// Enable gzip/br response compression for MCP responses.
    #[serde(default)]
    pub compression_enabled: bool,
    /// Minimum response size (bytes) before compression kicks in.
    /// Only used when `compression_enabled` is true. Default: 1024.
    #[serde(default = "default_compression_min_size")]
    pub compression_min_size: u16,
    /// Global cap on in-flight HTTP requests. When reached, excess
    /// requests receive 503 Service Unavailable (via load shedding).
    pub max_concurrent_requests: Option<usize>,
    /// Enable `/admin/*` diagnostic endpoints.
    #[serde(default)]
    pub admin_enabled: bool,
    /// RBAC role required to access admin endpoints.
    #[serde(default = "default_admin_role")]
    pub admin_role: String,
    /// Authentication configuration (API keys, mTLS, OAuth).
    pub auth: Option<crate::auth::AuthConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_handshake_timeout: default_tls_handshake_timeout(),
            max_concurrent_tls_handshakes: default_max_concurrent_tls_handshakes(),
            shutdown_timeout: default_shutdown_timeout(),
            request_timeout: default_request_timeout(),
            allowed_origins: Vec::new(),
            stdio_enabled: false,
            tool_rate_limit: None,
            tool_rate_limit_burst: None,
            extra_route_rate_limit: None,
            extra_route_rate_limit_burst: None,
            session_idle_timeout: default_session_idle_timeout(),
            sse_keep_alive: default_sse_keep_alive(),
            public_url: None,
            compression_enabled: false,
            compression_min_size: default_compression_min_size(),
            max_concurrent_requests: None,
            admin_enabled: false,
            admin_role: default_admin_role(),
            auth: None,
        }
    }
}

/// Observability settings (reusable across MCP projects).
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ObservabilityConfig {
    /// `tracing` log level / env filter string (e.g. `info,rmcp_server_kit=debug`).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Log output format: `json`, `pretty`, or `text` (default: `pretty`).
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Optional path to an append-only audit log file.
    pub audit_log_path: Option<PathBuf>,
    /// Emit inbound HTTP request headers at DEBUG level in transport logs.
    /// Sensitive headers remain redacted when enabled.
    #[serde(default)]
    pub log_request_headers: bool,
    /// Enable the Prometheus metrics endpoint.
    #[serde(default)]
    pub metrics_enabled: bool,
    /// Bind address for the Prometheus metrics listener.
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: default_metrics_bind(),
        }
    }
}

/// Validate the generic server config fields.
///
/// # Errors
///
/// Returns `McpxError::Config` on invalid values.
pub fn validate_server_config(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::McpxError;

    if server.listen_port == 0 {
        return Err(McpxError::Config("listen_port must be nonzero".into()));
    }

    match (&server.tls_cert_path, &server.tls_key_path) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(McpxError::Config(
                "tls_cert_path and tls_key_path must both be set or both omitted".into(),
            ));
        }
        _ => {}
    }

    if let Some(0) = server.max_concurrent_requests {
        return Err(McpxError::Config(
            "max_concurrent_requests must be nonzero when set".into(),
        ));
    }

    if let Some(0) = server.extra_route_rate_limit {
        return Err(McpxError::Config(
            "server.extra_route_rate_limit must be greater than zero".into(),
        ));
    }

    if let Some(0) = server.tool_rate_limit_burst {
        return Err(McpxError::Config(
            "server.tool_rate_limit_burst must be greater than zero".into(),
        ));
    }
    if let Some(0) = server.extra_route_rate_limit_burst {
        return Err(McpxError::Config(
            "server.extra_route_rate_limit_burst must be greater than zero".into(),
        ));
    }
    if server.tool_rate_limit_burst.is_some() && server.tool_rate_limit.is_none() {
        return Err(McpxError::Config(
            "server.tool_rate_limit_burst requires server.tool_rate_limit".into(),
        ));
    }
    if server.extra_route_rate_limit_burst.is_some() && server.extra_route_rate_limit.is_none() {
        return Err(McpxError::Config(
            "server.extra_route_rate_limit_burst requires server.extra_route_rate_limit".into(),
        ));
    }
    if let Some(rl) = server.auth.as_ref().and_then(|a| a.rate_limit.as_ref()) {
        if rl.burst == Some(0) {
            return Err(McpxError::Config(
                "auth.rate_limit.burst must be greater than zero".into(),
            ));
        }
        if rl.pre_auth_burst == Some(0) {
            return Err(McpxError::Config(
                "auth.rate_limit.pre_auth_burst must be greater than zero".into(),
            ));
        }
    }

    if server.admin_enabled {
        let auth_enabled = server.auth.as_ref().is_some_and(|a| a.enabled);
        if !auth_enabled {
            return Err(McpxError::Config(
                "admin_enabled=true requires auth to be configured and enabled".into(),
            ));
        }
        if server.admin_role.trim().is_empty() {
            return Err(McpxError::Config("admin_role must not be empty".into()));
        }
    }

    for (field, value) in [
        ("server.shutdown_timeout", server.shutdown_timeout.as_str()),
        ("server.request_timeout", server.request_timeout.as_str()),
        (
            "server.session_idle_timeout",
            server.session_idle_timeout.as_str(),
        ),
        ("server.sse_keep_alive", server.sse_keep_alive.as_str()),
        (
            "server.tls_handshake_timeout",
            server.tls_handshake_timeout.as_str(),
        ),
    ] {
        if humantime::parse_duration(value).is_err() {
            return Err(McpxError::Config(format!(
                "invalid duration for {field}: {value:?}"
            )));
        }
    }

    // The handshake deadline must be a positive duration: a zero value
    // would reap every TLS handshake before it could complete. Mirrors
    // check #11 in `McpServerConfig::check`.
    if humantime::parse_duration(&server.tls_handshake_timeout)
        .is_ok_and(|d| d == std::time::Duration::ZERO)
    {
        return Err(McpxError::Config(
            "server.tls_handshake_timeout must be greater than zero".into(),
        ));
    }

    // A zero-permit handshake semaphore would never admit a handshake,
    // deadlocking the TLS accept path. Mirrors check #12 in
    // `McpServerConfig::check`.
    if server.max_concurrent_tls_handshakes == 0 {
        return Err(McpxError::Config(
            "server.max_concurrent_tls_handshakes must be greater than zero".into(),
        ));
    }

    Ok(())
}

/// Validate observability config fields.
///
/// # Errors
///
/// Returns `McpxError::Config` on invalid values.
pub fn validate_observability_config(obs: &ObservabilityConfig) -> crate::error::Result<()> {
    use tracing_subscriber::EnvFilter;

    use crate::error::McpxError;

    if EnvFilter::try_new(&obs.log_level).is_err() {
        return Err(McpxError::Config(format!(
            "invalid log_level: {:?} (expected a valid tracing filter directive, e.g. \"info\", \"debug,hyper=warn\")",
            obs.log_level
        )));
    }
    let valid_formats = ["json", "pretty", "text"];
    if !valid_formats.contains(&obs.log_format.as_str()) {
        return Err(McpxError::Config(format!(
            "invalid log_format: {:?} (expected one of: {valid_formats:?})",
            obs.log_format
        )));
    }

    Ok(())
}

// - Default value functions -

fn default_listen_addr() -> String {
    "127.0.0.1".into()
}
fn default_listen_port() -> u16 {
    8443
}
fn default_shutdown_timeout() -> String {
    "30s".into()
}
fn default_request_timeout() -> String {
    "120s".into()
}
fn default_log_level() -> String {
    "info,rmcp=warn".into()
}
fn default_log_format() -> String {
    "pretty".into()
}
fn default_metrics_bind() -> String {
    "127.0.0.1:9090".into()
}
fn default_session_idle_timeout() -> String {
    "20m".into()
}
fn default_tls_handshake_timeout() -> String {
    "10s".into()
}
const fn default_max_concurrent_tls_handshakes() -> usize {
    256
}
fn default_admin_role() -> String {
    "admin".into()
}
fn default_compression_min_size() -> u16 {
    1024
}
fn default_sse_keep_alive() -> String {
    "15s".into()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "test-only relaxations; production code uses ? and tracing"
    )]
    use super::*;

    // -- ServerConfig defaults --

    #[test]
    fn server_config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1");
        assert_eq!(cfg.listen_port, 8443);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
        assert_eq!(cfg.shutdown_timeout, "30s");
        assert_eq!(cfg.request_timeout, "120s");
        assert!(cfg.allowed_origins.is_empty());
        assert!(!cfg.stdio_enabled);
        assert!(cfg.tool_rate_limit.is_none());
        assert_eq!(cfg.session_idle_timeout, "20m");
        assert_eq!(cfg.sse_keep_alive, "15s");
        assert!(cfg.public_url.is_none());
    }

    #[test]
    fn observability_config_defaults() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_level, "info,rmcp=warn");
        assert_eq!(cfg.log_format, "pretty");
        assert!(cfg.audit_log_path.is_none());
        assert!(!cfg.log_request_headers);
        assert!(!cfg.metrics_enabled);
        assert_eq!(cfg.metrics_bind, "127.0.0.1:9090");
    }

    // -- validate_server_config --

    #[test]
    fn valid_server_config_passes() {
        let cfg = ServerConfig::default();
        assert!(validate_server_config(&cfg).is_ok());
    }

    #[test]
    fn zero_port_rejected() {
        let cfg = ServerConfig {
            listen_port: 0,
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("listen_port"));
    }

    #[test]
    fn zero_extra_route_rate_limit_rejected() {
        let cfg = ServerConfig {
            extra_route_rate_limit: Some(0),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("extra_route_rate_limit"));
    }

    #[test]
    fn zero_burst_knobs_rejected() {
        let cfg = ServerConfig {
            tool_rate_limit: Some(10),
            tool_rate_limit_burst: Some(0),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tool_rate_limit_burst"));

        let cfg = ServerConfig {
            extra_route_rate_limit: Some(10),
            extra_route_rate_limit_burst: Some(0),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("extra_route_rate_limit_burst"));
    }

    #[test]
    fn orphan_burst_knobs_rejected() {
        let cfg = ServerConfig {
            tool_rate_limit_burst: Some(5),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("requires server.tool_rate_limit"));

        let cfg = ServerConfig {
            extra_route_rate_limit_burst: Some(5),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires server.extra_route_rate_limit")
        );
    }

    #[test]
    fn zero_auth_bursts_rejected() {
        let auth = crate::auth::AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_burst(0));
        let cfg = ServerConfig {
            auth: Some(auth),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("rate_limit.burst"));

        let auth = crate::auth::AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_pre_auth_burst(0));
        let cfg = ServerConfig {
            auth: Some(auth),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("pre_auth_burst"));
    }

    #[test]
    fn tls_cert_without_key_rejected() {
        let cfg = ServerConfig {
            tls_cert_path: Some("/tmp/cert.pem".into()),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tls_cert_path"));
    }

    #[test]
    fn tls_key_without_cert_rejected() {
        let cfg = ServerConfig {
            tls_key_path: Some("/tmp/key.pem".into()),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tls_cert_path"));
    }

    #[test]
    fn tls_both_set_passes() {
        let cfg = ServerConfig {
            tls_cert_path: Some("/tmp/cert.pem".into()),
            tls_key_path: Some("/tmp/key.pem".into()),
            ..ServerConfig::default()
        };
        assert!(validate_server_config(&cfg).is_ok());
    }

    #[test]
    fn invalid_tls_handshake_timeout_rejected() {
        let cfg = ServerConfig {
            tls_handshake_timeout: "not-a-duration".into(),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tls_handshake_timeout"));
    }

    #[test]
    fn zero_tls_handshake_timeout_rejected() {
        let cfg = ServerConfig {
            tls_handshake_timeout: "0s".into(),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tls_handshake_timeout"));
    }

    #[test]
    fn zero_max_concurrent_tls_handshakes_rejected() {
        let cfg = ServerConfig {
            max_concurrent_tls_handshakes: 0,
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("max_concurrent_tls_handshakes"));
    }

    #[test]
    fn invalid_shutdown_timeout_rejected() {
        let cfg = ServerConfig {
            shutdown_timeout: "not-a-duration".into(),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("shutdown_timeout"));
    }

    #[test]
    fn invalid_request_timeout_rejected() {
        let cfg = ServerConfig {
            request_timeout: "xyz".into(),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("request_timeout"));
    }

    // -- validate_observability_config --

    #[test]
    fn valid_observability_config_passes() {
        let cfg = ObservabilityConfig::default();
        assert!(validate_observability_config(&cfg).is_ok());
    }

    #[test]
    fn invalid_log_level_rejected() {
        let cfg = ObservabilityConfig {
            log_level: "[invalid".into(),
            ..ObservabilityConfig::default()
        };
        let err = validate_observability_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("log_level"));
    }

    #[test]
    fn invalid_log_format_rejected() {
        let cfg = ObservabilityConfig {
            log_format: "yaml".into(),
            ..ObservabilityConfig::default()
        };
        let err = validate_observability_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("log_format"));
    }

    #[test]
    fn all_valid_log_levels_accepted() {
        for level in &[
            "trace",
            "debug",
            "info",
            "warn",
            "error",
            "info,rmcp=warn",
            "debug,hyper=error",
        ] {
            let cfg = ObservabilityConfig {
                log_level: (*level).into(),
                ..ObservabilityConfig::default()
            };
            assert!(
                validate_observability_config(&cfg).is_ok(),
                "level {level} should be valid"
            );
        }
    }

    #[test]
    fn all_log_formats_accepted() {
        for fmt in &["json", "pretty", "text"] {
            let cfg = ObservabilityConfig {
                log_format: (*fmt).into(),
                ..ObservabilityConfig::default()
            };
            assert!(
                validate_observability_config(&cfg).is_ok(),
                "format {fmt} should be valid"
            );
        }
    }

    // -- serde deserialization --

    #[test]
    fn server_config_deserialize_defaults() {
        let cfg: ServerConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.listen_port, 8443);
        assert_eq!(cfg.listen_addr, "127.0.0.1");
        assert_eq!(cfg.tls_handshake_timeout, "10s");
        assert_eq!(cfg.max_concurrent_tls_handshakes, 256);
    }

    #[test]
    fn observability_config_deserialize_defaults() {
        let cfg: ObservabilityConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.log_level, "info,rmcp=warn");
        assert_eq!(cfg.log_format, "pretty");
        assert!(!cfg.log_request_headers);
        assert!(!cfg.metrics_enabled);
    }
}
