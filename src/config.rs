use std::{path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::{
    error::McpxError,
    transport::{McpServerConfig, SecurityHeadersConfig},
};

#[cfg(test)]
const SERVER_CONFIG_BRIDGED_FIELDS: &[&str] = &[
    "listen_addr",
    "listen_port",
    "tls_cert_path",
    "tls_key_path",
    "tls_handshake_timeout",
    "max_concurrent_tls_handshakes",
    "shutdown_timeout",
    "request_timeout",
    "allowed_origins",
    "tool_rate_limit",
    "tool_rate_limit_burst",
    "extra_route_rate_limit",
    "extra_route_rate_limit_burst",
    "extra_route_rate_limit_exempt_paths",
    "trusted_proxies",
    "forwarded_header",
    "session_idle_timeout",
    "sse_keep_alive",
    "public_url",
    "compression_enabled",
    "compression_min_size",
    "max_concurrent_requests",
    "admin_enabled",
    "admin_role",
    "auth",
    "max_request_body",
    "expose_build_metadata",
    "security_headers",
];

#[cfg(test)]
const SERVER_CONFIG_NOT_BRIDGED_FIELDS: &[&str] = &["stdio_enabled"];

#[cfg(test)]
const MCP_SERVER_CONFIG_RUNTIME_ONLY_FIELDS: &[&str] = &[
    "name",
    "version",
    "rbac",
    "readiness_check",
    "extra_router",
    "on_reload_ready",
    "metrics_enabled",
    "metrics_bind",
];

/// Server listener configuration (reusable across MCP projects).
#[derive(Debug, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "server configuration is a flat TOML schema with independent boolean feature flags"
)]
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
    /// Maximum request body size in bytes. Default: 1 MiB.
    #[serde(default = "default_max_request_body")]
    pub max_request_body: usize,
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
    /// Exact-match request paths exempt from the extra-route rate
    /// limiter. Raw string comparison against the request path — no
    /// globs, no normalization; fail-closed (anything not listed stays
    /// limited). Requires `extra_route_rate_limit`; entries must be
    /// non-empty and start with `/`. Startup-only.
    #[serde(default)]
    pub extra_route_rate_limit_exempt_paths: Vec<String>,
    /// Trusted reverse-proxy networks (CIDRs or bare IPs) for
    /// trusted-forwarder mode. Empty (default) = off. When the direct
    /// peer is inside one of these networks, the client IP is resolved
    /// from the forwarding header (rightmost-untrusted walk) and all
    /// per-IP rate limiters key by it. Startup-only.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Which forwarding header trusted-forwarder mode reads:
    /// `"x-forwarded-for"` (default when unset) or `"forwarded"`
    /// (RFC 7239). Requires `trusted_proxies` to be nonempty.
    pub forwarded_header: Option<crate::transport::ForwardedHeaderMode>,
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
    /// Expose build metadata on the unauthenticated `/version` endpoint.
    #[serde(default = "default_expose_build_metadata")]
    pub expose_build_metadata: bool,
    /// Per-header OWASP security-header overrides.
    #[serde(default = "default_security_headers")]
    pub security_headers: SecurityHeadersConfig,
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
            max_request_body: default_max_request_body(),
            allowed_origins: Vec::new(),
            stdio_enabled: false,
            tool_rate_limit: None,
            tool_rate_limit_burst: None,
            extra_route_rate_limit: None,
            extra_route_rate_limit_burst: None,
            extra_route_rate_limit_exempt_paths: Vec::new(),
            trusted_proxies: Vec::new(),
            forwarded_header: None,
            session_idle_timeout: default_session_idle_timeout(),
            sse_keep_alive: default_sse_keep_alive(),
            public_url: None,
            compression_enabled: false,
            compression_min_size: default_compression_min_size(),
            max_concurrent_requests: None,
            admin_enabled: false,
            admin_role: default_admin_role(),
            auth: None,
            expose_build_metadata: default_expose_build_metadata(),
            security_headers: default_security_headers(),
        }
    }
}

impl ServerConfig {
    /// Apply this TOML server schema to a programmatic MCP server base.
    ///
    /// Replacement semantics are used for every bridgeable transport field:
    /// `None` and `false` values in TOML clear the corresponding value from
    /// `base`. Only runtime-only fields such as `name`, `version`, RBAC,
    /// readiness callbacks, extra routers, reload callbacks, and metrics
    /// listener settings are preserved from `base`.
    ///
    /// Chain application-code builder overrides after this method when those
    /// overrides should take precedence over TOML. This method is side-effect
    /// free and never reads process environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`McpxError::Config`] when a duration string cannot be parsed.
    pub fn apply_to_mcp_config(&self, base: McpServerConfig) -> Result<McpServerConfig, McpxError> {
        let config = base
            .with_bind_addr(format!("{}:{}", self.listen_addr, self.listen_port))
            .with_tls_paths(self.tls_cert_path.clone(), self.tls_key_path.clone())
            .with_optional_auth(self.auth.clone())
            .with_max_request_body(self.max_request_body)
            .with_request_timeout(parse_duration_field(
                "server.request_timeout",
                &self.request_timeout,
            )?)
            .with_shutdown_timeout(parse_duration_field(
                "server.shutdown_timeout",
                &self.shutdown_timeout,
            )?)
            .with_session_idle_timeout(parse_duration_field(
                "server.session_idle_timeout",
                &self.session_idle_timeout,
            )?)
            .with_sse_keep_alive(parse_duration_field(
                "server.sse_keep_alive",
                &self.sse_keep_alive,
            )?)
            .with_tls_handshake_timeout(parse_duration_field(
                "server.tls_handshake_timeout",
                &self.tls_handshake_timeout,
            )?)
            .with_max_concurrent_tls_handshakes(self.max_concurrent_tls_handshakes)
            .with_allowed_origins(self.allowed_origins.iter().map(String::as_str))
            .with_extra_route_rate_limit_exempt_paths(
                self.extra_route_rate_limit_exempt_paths
                    .iter()
                    .map(String::as_str),
            )
            .with_trusted_proxies(self.trusted_proxies.iter().map(String::as_str))
            .with_optional_tool_rate_limit(self.tool_rate_limit)
            .with_optional_tool_rate_limit_burst(self.tool_rate_limit_burst)
            .with_optional_extra_route_rate_limit(self.extra_route_rate_limit)
            .with_optional_extra_route_rate_limit_burst(self.extra_route_rate_limit_burst)
            .with_optional_forwarded_header(self.forwarded_header)
            .with_optional_public_url(self.public_url.clone())
            .with_compression_enabled(self.compression_enabled)
            .with_compression_min_size(self.compression_min_size)
            .with_optional_max_concurrent_requests(self.max_concurrent_requests)
            .with_admin_enabled(self.admin_enabled)
            .with_admin_role(&self.admin_role)
            .with_expose_build_metadata(self.expose_build_metadata)
            .with_security_headers(self.security_headers.clone());

        Ok(config)
    }
}

fn parse_duration_field(field: &str, value: &str) -> Result<Duration, McpxError> {
    humantime::parse_duration(value).map_err(|error| {
        McpxError::Config(format!("invalid duration for {field}: {value:?}: {error}"))
    })
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

    if server.max_concurrent_requests == Some(0) {
        return Err(McpxError::Config(
            "max_concurrent_requests must be nonzero when set".into(),
        ));
    }

    if server.extra_route_rate_limit == Some(0) {
        return Err(McpxError::Config(
            "server.extra_route_rate_limit must be greater than zero".into(),
        ));
    }

    validate_rate_limit_knobs(server)?;
    validate_trusted_forwarder_config(server)?;

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
    if humantime::parse_duration(&server.tls_handshake_timeout).is_ok_and(|d| d == Duration::ZERO) {
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

/// Validate the rate-limit burst knobs of a TOML [`ServerConfig`]: zero
/// bursts and orphan bursts fail fast (mirrors `McpServerConfig::check`;
/// the auth bursts have no orphan rule — their base rates always resolve).
fn validate_rate_limit_knobs(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::McpxError;

    if server.tool_rate_limit_burst == Some(0) {
        return Err(McpxError::Config(
            "server.tool_rate_limit_burst must be greater than zero".into(),
        ));
    }
    if server.extra_route_rate_limit_burst == Some(0) {
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
    if !server.extra_route_rate_limit_exempt_paths.is_empty()
        && server.extra_route_rate_limit.is_none()
    {
        return Err(McpxError::Config(
            "server.extra_route_rate_limit_exempt_paths requires server.extra_route_rate_limit"
                .into(),
        ));
    }
    for path in &server.extra_route_rate_limit_exempt_paths {
        if path.is_empty() || !path.starts_with('/') {
            return Err(McpxError::Config(format!(
                "server.extra_route_rate_limit_exempt_paths entries must be non-empty and start with '/': {path:?}"
            )));
        }
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
    Ok(())
}

/// Validate the trusted-forwarder knobs of a TOML [`ServerConfig`]
/// (mirrors `McpServerConfig::check_trusted_forwarder`).
fn validate_trusted_forwarder_config(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::McpxError;

    for entry in &server.trusted_proxies {
        crate::transport::validate_trusted_proxy_entry(entry).map_err(McpxError::Config)?;
    }
    if server.forwarded_header.is_some() && server.trusted_proxies.is_empty() {
        return Err(McpxError::Config(
            "server.forwarded_header requires server.trusted_proxies to be nonempty".into(),
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
const fn default_max_request_body() -> usize {
    1024 * 1024
}
const fn default_expose_build_metadata() -> bool {
    false
}
fn default_security_headers() -> SecurityHeadersConfig {
    SecurityHeadersConfig::default()
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
        deprecated,
        reason = "test-only relaxations; production code uses ? and tracing"
    )]
    use std::{collections::HashSet, time::Duration};

    use super::*;
    use crate::transport::McpServerConfig;

    #[derive(Deserialize)]
    struct RootConfig {
        server: ServerConfig,
    }

    fn server_from_root_toml(toml: &str) -> ServerConfig {
        toml::from_str::<RootConfig>(toml).unwrap().server
    }

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
    fn exempt_paths_toml_roundtrip_and_validation() {
        let cfg: ServerConfig = toml::from_str(
            r#"
                extra_route_rate_limit = 60
                extra_route_rate_limit_exempt_paths = ["/.well-known/oauth-authorization-server"]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.extra_route_rate_limit_exempt_paths,
            vec!["/.well-known/oauth-authorization-server".to_owned()]
        );
        assert!(validate_server_config(&cfg).is_ok());
    }

    #[test]
    fn orphan_exempt_paths_rejected() {
        let cfg = ServerConfig {
            extra_route_rate_limit_exempt_paths: vec!["/ok".into()],
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires server.extra_route_rate_limit")
        );
    }

    #[test]
    fn malformed_exempt_paths_rejected() {
        for bad in ["", "no-slash"] {
            let cfg = ServerConfig {
                extra_route_rate_limit: Some(10),
                extra_route_rate_limit_exempt_paths: vec![bad.into()],
                ..ServerConfig::default()
            };
            let err = validate_server_config(&cfg).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must be non-empty and start with '/'"),
                "entry {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn bad_trusted_proxy_entry_rejected() {
        let cfg = ServerConfig {
            trusted_proxies: vec!["not-a-cidr".into()],
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("trusted_proxies"));
    }

    #[test]
    fn zero_prefix_trusted_proxy_rejected() {
        for entry in ["0.0.0.0/0", "::/0"] {
            let cfg = ServerConfig {
                trusted_proxies: vec![entry.into()],
                ..ServerConfig::default()
            };
            let err = validate_server_config(&cfg).unwrap_err();
            assert!(
                err.to_string().contains("prefix length 0"),
                "entry {entry:?}: {err}"
            );
        }
    }

    #[test]
    fn cidr_and_bare_ip_proxy_entries_accepted() {
        let cfg = ServerConfig {
            trusted_proxies: vec!["10.0.0.0/8".into(), "192.0.2.1".into()],
            ..ServerConfig::default()
        };
        assert!(validate_server_config(&cfg).is_ok());
    }

    #[test]
    fn forwarded_header_without_proxies_rejected() {
        let cfg = ServerConfig {
            forwarded_header: Some(crate::transport::ForwardedHeaderMode::Forwarded),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("requires server.trusted_proxies"));
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
    fn t1_existing_server_example_deserializes_with_new_defaults() {
        let server = server_from_root_toml(
            r#"
                [server]
                listen_addr = "0.0.0.0"
                listen_port = 8443
                tls_cert_path = "/etc/certs/server.crt"
                tls_key_path = "/etc/certs/server.key"
                shutdown_timeout = "30s"
                request_timeout = "120s"
                allowed_origins = ["http://localhost:3000", "https://myapp.example.com"]
                tool_rate_limit = 120
            "#,
        );

        assert_eq!(server.max_request_body, 1024 * 1024);
        assert!(!server.expose_build_metadata);
        assert_eq!(server.security_headers, SecurityHeadersConfig::default());
    }

    #[test]
    fn t2_default_bridge_is_no_op_for_mcp_defaults() {
        let actual = ServerConfig::default()
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();
        let expected = McpServerConfig::new("127.0.0.1:8443", "t", "0.0.0");

        assert_default_bridge_core_fields(&actual, &expected);
        assert_default_bridge_limit_fields(&actual, &expected);
        assert_default_bridge_metadata_fields(&actual, &expected);
    }

    fn assert_default_bridge_core_fields(actual: &McpServerConfig, expected: &McpServerConfig) {
        assert_eq!(actual.bind_addr, expected.bind_addr);
        assert_eq!(actual.tls_cert_path, expected.tls_cert_path);
        assert_eq!(actual.tls_key_path, expected.tls_key_path);
        assert!(actual.auth.is_none());
        assert_eq!(actual.allowed_origins, expected.allowed_origins);
        assert_eq!(actual.trusted_proxies, expected.trusted_proxies);
        assert_eq!(actual.forwarded_header, expected.forwarded_header);
        assert_eq!(actual.public_url, expected.public_url);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.version, expected.version);
    }

    fn assert_default_bridge_limit_fields(actual: &McpServerConfig, expected: &McpServerConfig) {
        assert_eq!(actual.tool_rate_limit, expected.tool_rate_limit);
        assert_eq!(actual.tool_rate_limit_burst, expected.tool_rate_limit_burst);
        assert_eq!(
            actual.extra_route_rate_limit,
            expected.extra_route_rate_limit
        );
        assert_eq!(
            actual.extra_route_rate_limit_burst,
            expected.extra_route_rate_limit_burst
        );
        assert_eq!(
            actual.extra_route_rate_limit_exempt_paths,
            expected.extra_route_rate_limit_exempt_paths
        );
        assert_eq!(actual.max_request_body, expected.max_request_body);
        assert_eq!(
            actual.max_concurrent_requests,
            expected.max_concurrent_requests
        );
    }

    fn assert_default_bridge_metadata_fields(actual: &McpServerConfig, expected: &McpServerConfig) {
        assert_eq!(actual.session_idle_timeout, expected.session_idle_timeout);
        assert_eq!(actual.sse_keep_alive, expected.sse_keep_alive);
        assert_eq!(actual.request_timeout, expected.request_timeout);
        assert_eq!(actual.shutdown_timeout, expected.shutdown_timeout);
        assert_eq!(actual.tls_handshake_timeout, expected.tls_handshake_timeout);
        assert_eq!(
            actual.max_concurrent_tls_handshakes,
            expected.max_concurrent_tls_handshakes
        );
        assert_eq!(actual.compression_enabled, expected.compression_enabled);
        assert_eq!(actual.compression_min_size, expected.compression_min_size);
        assert_eq!(actual.admin_enabled, expected.admin_enabled);
        assert_eq!(actual.admin_role, expected.admin_role);
        assert_eq!(actual.expose_build_metadata, expected.expose_build_metadata);
        assert_eq!(actual.security_headers, expected.security_headers);
    }

    #[test]
    fn t5_hsts_preload_from_toml_rejected_by_mcp_validate() {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                strict_transport_security = "max-age=1; preload"
            "#,
        );
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();

        let err = mcp.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("preload"), "error must mention preload: {msg}");
    }

    #[test]
    fn t6_bad_security_header_from_toml_rejected_by_mcp_validate() {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                content_security_policy = "bad\nvalue"
            "#,
        );
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();

        let err = mcp.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid security_headers.content_security_policy"),
            "error must name invalid header field: {msg}"
        );
    }

    #[test]
    fn t7_zero_max_request_body_rejected_by_mcp_validate() {
        let cfg: ServerConfig = toml::from_str("max_request_body = 0").unwrap();
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();

        let err = mcp.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("max_request_body must be greater than zero")
        );
    }

    #[test]
    fn t9_unknown_security_header_key_is_ignored() {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                typo_content_security_policy = "default-src 'self'"
            "#,
        );

        assert_eq!(cfg.security_headers, SecurityHeadersConfig::default());
    }

    #[test]
    fn all_twelve_security_header_keys_deserialize_from_server_toml() {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                content_security_policy = "csp"
                strict_transport_security = "max-age=1"
                cross_origin_embedder_policy = "coep"
                cross_origin_resource_policy = "corp"
                cross_origin_opener_policy = "coop"
                permissions_policy = "permissions"
                referrer_policy = "referrer"
                x_frame_options = "frame"
                cache_control = "cache"
                x_content_type_options = "content-type"
                x_dns_prefetch_control = "dns"
                x_permitted_cross_domain_policies = "cross-domain"
            "#,
        );

        let headers = cfg.security_headers;
        assert_eq!(headers.content_security_policy.as_deref(), Some("csp"));
        assert_eq!(
            headers.strict_transport_security.as_deref(),
            Some("max-age=1")
        );
        assert_eq!(
            headers.cross_origin_embedder_policy.as_deref(),
            Some("coep")
        );
        assert_eq!(
            headers.cross_origin_resource_policy.as_deref(),
            Some("corp")
        );
        assert_eq!(headers.cross_origin_opener_policy.as_deref(), Some("coop"));
        assert_eq!(headers.permissions_policy.as_deref(), Some("permissions"));
        assert_eq!(headers.referrer_policy.as_deref(), Some("referrer"));
        assert_eq!(headers.x_frame_options.as_deref(), Some("frame"));
        assert_eq!(headers.cache_control.as_deref(), Some("cache"));
        assert_eq!(
            headers.x_content_type_options.as_deref(),
            Some("content-type")
        );
        assert_eq!(headers.x_dns_prefetch_control.as_deref(), Some("dns"));
        assert_eq!(
            headers.x_permitted_cross_domain_policies.as_deref(),
            Some("cross-domain")
        );
    }

    #[test]
    fn t10_every_server_config_field_is_classified_for_bridge() {
        let source = include_str!("config.rs");
        let (_, after_struct_start) = source
            .split_once("pub struct ServerConfig {")
            .expect("ServerConfig struct start marker");
        let (struct_body, _) = after_struct_start
            .split_once("\n}\n\nimpl ServerConfig")
            .expect("ServerConfig struct end marker");
        let actual_fields: HashSet<&str> = struct_body
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("pub ")
                    .and_then(|rest| rest.split_once(':').map(|(name, _)| name.trim()))
            })
            .collect();
        let bridged_fields: HashSet<&str> = SERVER_CONFIG_BRIDGED_FIELDS.iter().copied().collect();
        let not_bridged_fields: HashSet<&str> =
            SERVER_CONFIG_NOT_BRIDGED_FIELDS.iter().copied().collect();
        let runtime_only_fields: HashSet<&str> = MCP_SERVER_CONFIG_RUNTIME_ONLY_FIELDS
            .iter()
            .copied()
            .collect();
        let classified_fields: HashSet<&str> =
            bridged_fields.union(&not_bridged_fields).copied().collect();

        assert_eq!(actual_fields, classified_fields);
        assert!(bridged_fields.is_disjoint(&not_bridged_fields));
        assert!(runtime_only_fields.is_disjoint(&actual_fields));
        assert!(SERVER_CONFIG_NOT_BRIDGED_FIELDS.contains(&"stdio_enabled"));
        assert!(MCP_SERVER_CONFIG_RUNTIME_ONLY_FIELDS.contains(&"rbac"));
        assert!(MCP_SERVER_CONFIG_RUNTIME_ONLY_FIELDS.contains(&"metrics_bind"));
    }

    #[test]
    fn replacement_semantics_clear_base_option_and_false_bool_fields() {
        let (_token, hash) = crate::auth::generate_api_key().unwrap();
        let base = McpServerConfig::new("127.0.0.1:0", "t", "0.0.0")
            .with_tls("/tmp/base.crt", "/tmp/base.key")
            .with_auth(crate::auth::AuthConfig::with_keys(vec![
                crate::auth::ApiKeyEntry::new("base-key", hash, "admin"),
            ]))
            .with_tool_rate_limit(10)
            .with_tool_rate_limit_burst(20)
            .with_extra_route_rate_limit(30)
            .with_extra_route_rate_limit_burst(40)
            .with_trusted_proxies(["127.0.0.1/32"])
            .with_forwarded_header(crate::transport::ForwardedHeaderMode::Forwarded)
            .with_public_url("https://base.example")
            .enable_compression(512)
            .with_max_concurrent_requests(99)
            .enable_admin("admin")
            .expose_build_metadata();

        let actual = ServerConfig::default().apply_to_mcp_config(base).unwrap();

        assert!(actual.tls_cert_path.is_none());
        assert!(actual.tls_key_path.is_none());
        assert!(actual.auth.is_none());
        assert!(actual.tool_rate_limit.is_none());
        assert!(actual.tool_rate_limit_burst.is_none());
        assert!(actual.extra_route_rate_limit.is_none());
        assert!(actual.extra_route_rate_limit_burst.is_none());
        assert!(actual.forwarded_header.is_none());
        assert!(actual.public_url.is_none());
        assert!(!actual.compression_enabled);
        assert_eq!(actual.compression_min_size, 1024);
        assert!(actual.max_concurrent_requests.is_none());
        assert!(!actual.admin_enabled);
        assert_eq!(actual.admin_role, "admin");
        assert!(!actual.expose_build_metadata);
    }

    #[test]
    fn partial_tls_toml_does_not_inherit_base_key() {
        let cfg = ServerConfig {
            tls_cert_path: Some("/tmp/toml.crt".into()),
            tls_key_path: None,
            ..ServerConfig::default()
        };
        let mcp = cfg
            .apply_to_mcp_config(
                McpServerConfig::new("127.0.0.1:0", "t", "0.0.0")
                    .with_tls("/tmp/base.crt", "/tmp/base.key"),
            )
            .unwrap();

        assert_eq!(mcp.tls_cert_path, Some(PathBuf::from("/tmp/toml.crt")));
        assert!(mcp.tls_key_path.is_none());
        let err = mcp.validate().unwrap_err();
        assert!(err.to_string().contains("tls_key_path"));
    }

    #[test]
    fn partial_tls_toml_does_not_inherit_base_cert() {
        let cfg = ServerConfig {
            tls_cert_path: None,
            tls_key_path: Some("/tmp/toml.key".into()),
            ..ServerConfig::default()
        };
        let mcp = cfg
            .apply_to_mcp_config(
                McpServerConfig::new("127.0.0.1:0", "t", "0.0.0")
                    .with_tls("/tmp/base.crt", "/tmp/base.key"),
            )
            .unwrap();

        assert!(mcp.tls_cert_path.is_none());
        assert_eq!(mcp.tls_key_path, Some(PathBuf::from("/tmp/toml.key")));
        let err = mcp.validate().unwrap_err();
        assert!(err.to_string().contains("tls_cert_path"));
    }

    #[test]
    fn t11_bridge_maps_bind_addr_and_request_timeout() {
        let cfg: ServerConfig = toml::from_str(
            r#"
                listen_addr = "127.0.0.2"
                listen_port = 9000
                request_timeout = "5s"
            "#,
        )
        .unwrap();

        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();

        assert_eq!(mcp.bind_addr, "127.0.0.2:9000");
        assert_eq!(mcp.request_timeout, Duration::from_secs(5));
    }

    #[test]
    fn t12_bridge_rejects_invalid_request_timeout() {
        let cfg: ServerConfig = toml::from_str(r#"request_timeout = "not-a-duration""#).unwrap();

        let Err(err) = cfg.apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
        else {
            panic!("invalid request_timeout must fail");
        };

        assert!(err.to_string().contains("request_timeout"));
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
