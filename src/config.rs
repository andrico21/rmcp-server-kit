use core::{fmt, str::FromStr, time::Duration};
use std::{env, fs, path::PathBuf};

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

#[cfg(feature = "oauth")]
use crate::oauth;
use crate::{
    auth::AuthConfig,
    bounded_limiter::KeyEvictionPolicy,
    error::{Result as RmcpResult, RmcpServerKitError},
    forwarded::{MAX_CONFIGURABLE_SCANNED_ENTRIES, MAX_SCANNED_ENTRIES},
    session_binding,
    transport::{
        ForwardedHeaderMode, LogContextConfig, McpServerConfig, SecurityHeadersConfig,
        default_request_log_exclude_paths, validate_allowed_origin_entry,
        validate_public_url_value, validate_request_id_header, validate_security_headers,
        validate_trusted_proxy_entry,
    },
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
    "request_log_exclude_paths",
    "log_context",
    "key_eviction_policy",
    "trusted_proxies",
    "trusted_forwarder_max_entries",
    "forwarded_header",
    "session_idle_timeout",
    "session_binding",
    "session_binding_secret",
    "task_binding",
    "sse_keep_alive",
    "public_url",
    "compression_enabled",
    "compression_min_size",
    "max_concurrent_requests",
    "admin_enabled",
    "admin_role",
    "auth",
    "tool_list_filtering",
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedCheck {
    AdminAuth,
    TlsPairing,
    MtlsRequiresTls,
}

/// One environment override applied to a configuration struct.
///
/// Secret-typed targets redact their value by setting [`Self::value`] to
/// `None`; non-secret targets carry the parsed string value that was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvOverride {
    /// Environment variable name that supplied the override.
    pub env_var: String,
    /// Dotted TOML path that was overridden, such as `server.listen_port`.
    pub target_field: String,
    /// Source of the override value.
    pub source: EnvOverrideSource,
    /// Applied non-secret value, or `None` for secret-typed targets.
    pub value: Option<String>,
}

/// Source kind for an applied environment override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvOverrideSource {
    /// Read directly from an environment variable.
    Env,
    /// Read from the file named by a `_FILE`-suffixed environment variable.
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(test)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/config.rs::EnvOverrideSpec fields keep their explicit `pub(crate)` visibility because the source-scanning tests read the spec table's declared shape"
)]
pub(crate) struct EnvOverrideSpec {
    pub(crate) env_var: &'static str,
    pub(crate) target_field: &'static str,
    pub(crate) value_type: &'static str,
    pub(crate) required_feature: Option<&'static str>,
    pub(crate) redacted: bool,
}

#[cfg(test)]
pub(crate) const ENV_OVERRIDE_SPECS: &[EnvOverrideSpec] = &[
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__LISTEN_ADDR",
        target_field: "server.listen_addr",
        value_type: "String",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__LISTEN_PORT",
        target_field: "server.listen_port",
        value_type: "u16",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__PUBLIC_URL",
        target_field: "server.public_url",
        value_type: "String",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__TLS_CERT_PATH",
        target_field: "server.tls_cert_path",
        value_type: "Path",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__TLS_KEY_PATH",
        target_field: "server.tls_key_path",
        value_type: "Path",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__ADMIN_ENABLED",
        target_field: "server.admin_enabled",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__KEY_EVICTION_POLICY",
        target_field: "server.key_eviction_policy",
        value_type: "KeyEvictionPolicy",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__SESSION_BINDING_SECRET",
        target_field: "server.session_binding_secret",
        value_type: "SecretString",
        required_feature: None,
        redacted: true,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__SESSION_BINDING_SECRET_FILE",
        target_field: "server.session_binding_secret",
        value_type: "Path",
        required_feature: None,
        redacted: true,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ISSUER",
        target_field: "server.auth.oauth.issuer",
        value_type: "String",
        required_feature: Some("oauth"),
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__AUDIENCE",
        target_field: "server.auth.oauth.audience",
        value_type: "String",
        required_feature: Some("oauth"),
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__JWKS_URI",
        target_field: "server.auth.oauth.jwks_uri",
        value_type: "String",
        required_feature: Some("oauth"),
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ALLOWED_ALGORITHMS",
        target_field: "server.auth.oauth.allowed_algorithms",
        value_type: "comma-separated algorithm list",
        required_feature: Some("oauth"),
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__STRIP_RESOURCE_PARAM",
        target_field: "server.auth.oauth.proxy.strip_resource_param",
        value_type: "bool",
        required_feature: Some("oauth"),
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__LOG_FORMAT",
        target_field: "observability.log_format",
        value_type: "String",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_ENABLED",
        target_field: "observability.metrics_enabled",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_BIND",
        target_field: "observability.metrics_bind",
        value_type: "String",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__LOG_PLAINTEXT_OAUTH_TOKENS",
        target_field: "observability.log_plaintext_oauth_tokens",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__LOG_OAUTH_CLAIM_VALUES",
        target_field: "observability.log_oauth_claim_values",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__LOG_TOOL_CALL_ARGUMENTS",
        target_field: "observability.log_tool_call_arguments",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__OBSERVABILITY__LOG_UPSTREAM_ERROR_BODIES",
        target_field: "observability.log_upstream_error_bodies",
        value_type: "bool",
        required_feature: None,
        redacted: false,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__RBAC__REDACTION_SALT",
        target_field: "rbac.redaction_salt",
        value_type: "SecretString",
        required_feature: None,
        redacted: true,
    },
    EnvOverrideSpec {
        env_var: "RMCP_SERVER_KIT__RBAC__REDACTION_SALT_FILE",
        target_field: "rbac.redaction_salt",
        value_type: "Path",
        required_feature: None,
        redacted: true,
    },
];

/// Environment variable name for the `server.listen_addr` override.
pub(crate) const SERVER_LISTEN_ADDR_ENV: &str = "RMCP_SERVER_KIT__SERVER__LISTEN_ADDR";
/// Environment variable name for the `server.listen_port` override.
pub(crate) const SERVER_LISTEN_PORT_ENV: &str = "RMCP_SERVER_KIT__SERVER__LISTEN_PORT";
/// Environment variable name for the `server.public_url` override.
pub(crate) const SERVER_PUBLIC_URL_ENV: &str = "RMCP_SERVER_KIT__SERVER__PUBLIC_URL";
/// Environment variable name for the `server.tls_cert_path` override.
pub(crate) const SERVER_TLS_CERT_PATH_ENV: &str = "RMCP_SERVER_KIT__SERVER__TLS_CERT_PATH";
/// Environment variable name for the `server.tls_key_path` override.
pub(crate) const SERVER_TLS_KEY_PATH_ENV: &str = "RMCP_SERVER_KIT__SERVER__TLS_KEY_PATH";
/// Environment variable name for the `server.admin_enabled` override.
pub(crate) const SERVER_ADMIN_ENABLED_ENV: &str = "RMCP_SERVER_KIT__SERVER__ADMIN_ENABLED";
/// Environment variable name for the `server.key_eviction_policy` override.
pub(crate) const SERVER_KEY_EVICTION_POLICY_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__KEY_EVICTION_POLICY";
/// Environment variable name for the direct `server.session_binding_secret` override.
pub(crate) const SERVER_SESSION_BINDING_SECRET_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__SESSION_BINDING_SECRET";
/// Environment variable name for the file-backed `server.session_binding_secret` override.
pub(crate) const SERVER_SESSION_BINDING_SECRET_FILE_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__SESSION_BINDING_SECRET_FILE";
/// Environment variable name for the `server.auth.oauth.issuer` override.
pub(crate) const SERVER_OAUTH_ISSUER_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ISSUER";
/// Environment variable name for the `server.auth.oauth.audience` override.
pub(crate) const SERVER_OAUTH_AUDIENCE_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__AUDIENCE";
/// Environment variable name for the `server.auth.oauth.jwks_uri` override.
pub(crate) const SERVER_OAUTH_JWKS_URI_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__JWKS_URI";
/// Environment variable name for the `server.auth.oauth.proxy.strip_resource_param` override.
pub(crate) const SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__STRIP_RESOURCE_PARAM";
/// Environment variable name for the `server.auth.oauth.allowed_algorithms` override.
pub(crate) const SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ALLOWED_ALGORITHMS";
/// Environment variable name for the `observability.log_format` override.
pub(crate) const OBSERVABILITY_LOG_FORMAT_ENV: &str = "RMCP_SERVER_KIT__OBSERVABILITY__LOG_FORMAT";
/// Environment variable name for the `observability.metrics_enabled` override.
pub(crate) const OBSERVABILITY_METRICS_ENABLED_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_ENABLED";
/// Environment variable name for the `observability.metrics_bind` override.
pub(crate) const OBSERVABILITY_METRICS_BIND_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_BIND";
/// Environment variable name for the `observability.log_plaintext_oauth_tokens` override.
pub(crate) const OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_PLAINTEXT_OAUTH_TOKENS";
/// Environment variable name for the `observability.log_oauth_claim_values` override.
pub(crate) const OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_OAUTH_CLAIM_VALUES";
/// Environment variable name for the `observability.log_tool_call_arguments` override.
pub(crate) const OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_TOOL_CALL_ARGUMENTS";
/// Environment variable name for the `observability.log_upstream_error_bodies` override.
pub(crate) const OBSERVABILITY_LOG_UPSTREAM_ERROR_BODIES_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_UPSTREAM_ERROR_BODIES";
/// Environment variable name for the direct `rbac.redaction_salt` override.
pub(crate) const RBAC_REDACTION_SALT_ENV: &str = "RMCP_SERVER_KIT__RBAC__REDACTION_SALT";
/// Environment variable name for the file-backed `rbac.redaction_salt` override.
pub(crate) const RBAC_REDACTION_SALT_FILE_ENV: &str = "RMCP_SERVER_KIT__RBAC__REDACTION_SALT_FILE";

/// Server listener configuration (reusable across MCP projects).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "server configuration is a flat TOML schema with independent boolean feature flags"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
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
    /// Keyed by the direct socket peer - no `X-Forwarded-For`
    /// interpretation. Startup-only.
    pub extra_route_rate_limit: Option<u32>,
    /// Burst capacity for the extra-route rate limiter (bucket size;
    /// sustained rate stays `extra_route_rate_limit`). Requires
    /// `extra_route_rate_limit`; must be greater than zero.
    pub extra_route_rate_limit_burst: Option<u32>,
    /// Exact-match request paths exempt from the extra-route rate
    /// limiter. Raw string comparison against the request path - no
    /// globs, no normalization; fail-closed (anything not listed stays
    /// limited). Requires `extra_route_rate_limit`; entries must be
    /// non-empty and start with `/`. Startup-only.
    #[serde(default)]
    pub extra_route_rate_limit_exempt_paths: Vec<String>,
    /// Request paths to exclude from request logging. Exact-match against
    /// the request path - no globs, no normalization. Default: `["/healthz", "/readyz"]`.
    /// Entries must be non-empty and start with `/`.
    #[serde(default = "crate::transport::default_request_log_exclude_paths")]
    pub request_log_exclude_paths: Vec<String>,
    /// Configuration for client context logging (request ID, client IP, peer IP, etc.).
    #[serde(default)]
    pub log_context: LogContextConfig,
    /// Full-table policy for per-IP rate limiters. Default: `evict_lru`.
    #[serde(default)]
    pub key_eviction_policy: KeyEvictionPolicy,
    /// Trusted reverse-proxy networks (CIDRs or bare IPs) for
    /// trusted-forwarder mode. Empty (default) = off. When the direct
    /// peer is inside one of these networks, the client IP is resolved
    /// from the forwarding header (rightmost-untrusted walk) and all
    /// per-IP rate limiters key by it. Startup-only.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Maximum forwarding-chain entries scanned per request in
    /// trusted-forwarder mode. Longer chains are treated as a header bomb
    /// and resolution falls back to the direct peer. Default `16`, valid
    /// range `1..=64`. Startup-only.
    #[serde(default = "default_trusted_forwarder_max_entries")]
    pub trusted_forwarder_max_entries: usize,
    /// Which forwarding header trusted-forwarder mode reads:
    /// `"x-forwarded-for"` (default when unset) or `"forwarded"`
    /// (RFC 7239). Requires `trusted_proxies` to be nonempty.
    pub forwarded_header: Option<ForwardedHeaderMode>,
    /// Idle timeout for MCP sessions. Sessions with no activity for this
    /// duration are closed automatically. Default: 20 minutes.
    #[serde(default = "default_session_idle_timeout")]
    pub session_idle_timeout: String,
    /// Bind MCP session IDs to the authenticated identity using a stateless
    /// signed wrapper. Default: true. Disabling reinstates CWE-384 risk.
    #[serde(default = "default_session_binding")]
    pub session_binding: bool,
    /// Shared HMAC secret used for session binding across server instances.
    ///
    /// Necessary but not sufficient for cross-instance session continuity: this
    /// makes a session token minted by one instance verifiable by another. The
    /// session itself lives in rmcp's session store, so continuity also requires
    /// a shared store via [`crate::transport::McpServerConfig::with_session_store`].
    /// Without one, a session does not survive a restart or a hop to another
    /// instance even when this secret is shared.
    ///
    /// Also used by [`Self::task_binding`]; the two are domain-separated.
    pub session_binding_secret: Option<SecretString>,
    /// Bind MCP task IDs (SEP-2663) to the authenticated identity that created
    /// them, preventing cross-identity `tasks/get`, `tasks/update`, and
    /// `tasks/cancel`. Default: false, because enabling it changes the wire
    /// format of `taskId` values.
    ///
    /// This is an opt-in compatibility control, not a staged default-flip
    /// promise.
    #[serde(default)]
    pub task_binding: bool,
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
    pub auth: Option<AuthConfig>,
    /// Filter `tools/list` through RBAC visibility when RBAC is enabled.
    /// Default: true.
    #[serde(default = "default_tool_list_filtering")]
    pub tool_list_filtering: bool,
    /// Expose build metadata on the unauthenticated `/version` endpoint.
    #[serde(default = "default_expose_build_metadata")]
    pub expose_build_metadata: bool,
    /// Per-header OWASP security-header overrides.
    #[serde(default = "default_security_headers")]
    pub security_headers: SecurityHeadersConfig,
}

/// Hand-written so `tls_key_path` never reaches a log.
///
/// SECURITY: a derived `Debug` renders the private-key path verbatim, and the
/// whole config is easy to log accidentally (`tracing::debug!(?config)`, a
/// panic message, an error chain). Presence is still reported so diagnostics
/// remain useful; only the location is withheld.
///
/// Every field is listed deliberately rather than using
/// `finish_non_exhaustive`, and `server_config_debug_lists_every_field` fails
/// if a field is added here without being rendered.
impl fmt::Debug for ServerConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen_addr", &self.listen_addr)
            .field("listen_port", &self.listen_port)
            .field("tls_cert_path", &self.tls_cert_path)
            .field(
                "tls_key_path",
                &self.tls_key_path.as_ref().map(|_| "[REDACTED]"),
            )
            .field("tls_handshake_timeout", &self.tls_handshake_timeout)
            .field(
                "max_concurrent_tls_handshakes",
                &self.max_concurrent_tls_handshakes,
            )
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_request_body", &self.max_request_body)
            .field("allowed_origins", &self.allowed_origins)
            .field("stdio_enabled", &self.stdio_enabled)
            .field("tool_rate_limit", &self.tool_rate_limit)
            .field("tool_rate_limit_burst", &self.tool_rate_limit_burst)
            .field("extra_route_rate_limit", &self.extra_route_rate_limit)
            .field(
                "extra_route_rate_limit_burst",
                &self.extra_route_rate_limit_burst,
            )
            .field(
                "extra_route_rate_limit_exempt_paths",
                &self.extra_route_rate_limit_exempt_paths,
            )
            .field("request_log_exclude_paths", &self.request_log_exclude_paths)
            .field("log_context", &self.log_context)
            .field("key_eviction_policy", &self.key_eviction_policy)
            .field("trusted_proxies", &self.trusted_proxies)
            .field(
                "trusted_forwarder_max_entries",
                &self.trusted_forwarder_max_entries,
            )
            .field("forwarded_header", &self.forwarded_header)
            .field("session_idle_timeout", &self.session_idle_timeout)
            .field("session_binding", &self.session_binding)
            .field(
                "session_binding_secret",
                &self.session_binding_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("task_binding", &self.task_binding)
            .field("sse_keep_alive", &self.sse_keep_alive)
            .field("public_url", &self.public_url)
            .field("compression_enabled", &self.compression_enabled)
            .field("compression_min_size", &self.compression_min_size)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("admin_enabled", &self.admin_enabled)
            .field("admin_role", &self.admin_role)
            .field("auth", &self.auth)
            .field("tool_list_filtering", &self.tool_list_filtering)
            .field("expose_build_metadata", &self.expose_build_metadata)
            .field("security_headers", &self.security_headers)
            .finish()
    }
}

impl Default for ServerConfig {
    #[inline]
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
            request_log_exclude_paths: default_request_log_exclude_paths(),
            log_context: LogContextConfig::default(),
            key_eviction_policy: KeyEvictionPolicy::default(),
            trusted_proxies: Vec::new(),
            trusted_forwarder_max_entries: default_trusted_forwarder_max_entries(),
            forwarded_header: None,
            session_idle_timeout: default_session_idle_timeout(),
            session_binding: default_session_binding(),
            session_binding_secret: None,
            task_binding: false,
            sse_keep_alive: default_sse_keep_alive(),
            public_url: None,
            compression_enabled: false,
            compression_min_size: default_compression_min_size(),
            max_concurrent_requests: None,
            admin_enabled: false,
            admin_role: default_admin_role(),
            auth: None,
            tool_list_filtering: default_tool_list_filtering(),
            expose_build_metadata: default_expose_build_metadata(),
            security_headers: default_security_headers(),
        }
    }
}

impl ServerConfig {
    /// Applies `RMCP_SERVER_KIT__SERVER__*` environment overrides onto this config.
    ///
    /// Includes the nested OAuth variables under
    /// `RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__*`. This method is opt-in:
    /// constructors, validators, and server startup do not call it.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when an override cannot be parsed, when an
    /// OAuth override lacks a declared `[server.auth.oauth]` parent, or when an
    /// OAuth override is used in a build without the `oauth` feature.
    ///
    /// # Examples
    ///
    /// The full config-file pipeline lives in
    /// [`examples/config_file_server.rs`](https://github.com/andrico21/rmcp-server-kit/blob/main/examples/config_file_server.rs).
    ///
    /// ```no_run
    /// use rmcp_server_kit::config::ServerConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut server = ServerConfig::default();
    /// // Do not set process env in doctests: rustdoc examples share a process.
    /// let report = server.apply_env_overrides()?;
    /// let _applied_fields: Vec<&str> = report
    ///     .iter()
    ///     .map(|entry| entry.target_field.as_str())
    ///     .collect();
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn apply_env_overrides(&mut self) -> Result<Vec<EnvOverride>, RmcpServerKitError> {
        let mut applied = Vec::new();
        apply_string_env(
            SERVER_LISTEN_ADDR_ENV,
            "server.listen_addr",
            &mut self.listen_addr,
            &mut applied,
        )?;
        if let Some(raw) = read_env(SERVER_LISTEN_PORT_ENV)? {
            self.listen_port = parse_env_value(SERVER_LISTEN_PORT_ENV, &raw, "u16")?;
            applied.push(env_report(
                SERVER_LISTEN_PORT_ENV,
                "server.listen_port",
                raw,
            ));
        }
        apply_optional_string_env(
            SERVER_PUBLIC_URL_ENV,
            "server.public_url",
            &mut self.public_url,
            &mut applied,
        )?;
        apply_optional_path_env(
            SERVER_TLS_CERT_PATH_ENV,
            "server.tls_cert_path",
            &mut self.tls_cert_path,
            &mut applied,
        )?;
        apply_optional_path_env(
            SERVER_TLS_KEY_PATH_ENV,
            "server.tls_key_path",
            &mut self.tls_key_path,
            &mut applied,
        )?;
        if let Some(raw) = read_env(SERVER_ADMIN_ENABLED_ENV)? {
            self.admin_enabled = parse_env_bool(SERVER_ADMIN_ENABLED_ENV, &raw)?;
            applied.push(env_report(
                SERVER_ADMIN_ENABLED_ENV,
                "server.admin_enabled",
                raw,
            ));
        }
        if let Some(raw) = read_env(SERVER_KEY_EVICTION_POLICY_ENV)? {
            self.key_eviction_policy =
                parse_env_value(SERVER_KEY_EVICTION_POLICY_ENV, &raw, "KeyEvictionPolicy")?;
            applied.push(env_report(
                SERVER_KEY_EVICTION_POLICY_ENV,
                "server.key_eviction_policy",
                raw,
            ));
        }
        self.apply_session_binding_secret_env(&mut applied)?;
        let oauth_env = OAuthEnvOverrides::read()?;
        #[cfg(feature = "oauth")]
        self.apply_oauth_env_overrides(oauth_env, &mut applied)?;
        #[cfg(not(feature = "oauth"))]
        reject_oauth_env_overrides(&oauth_env)?;
        Ok(applied)
    }

    /// Apply the direct or file-backed session-binding secret override.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when both sources are set, when the
    /// file cannot be read, or when the secret fails validation.
    fn apply_session_binding_secret_env(
        &mut self,
        applied: &mut Vec<EnvOverride>,
    ) -> Result<(), RmcpServerKitError> {
        let direct = read_env(SERVER_SESSION_BINDING_SECRET_ENV)?;
        let file = read_env(SERVER_SESSION_BINDING_SECRET_FILE_ENV)?;
        match (direct, file) {
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(RmcpServerKitError::Config(format!(
                "{SERVER_SESSION_BINDING_SECRET_ENV} and {SERVER_SESSION_BINDING_SECRET_FILE_ENV} must not both be set"
            ))),
            (Some(value), None) => {
                validate_session_binding_secret_env(SERVER_SESSION_BINDING_SECRET_ENV, &value)?;
                self.session_binding_secret = Some(SecretString::from(value));
                applied.push(secret_env_report(
                    SERVER_SESSION_BINDING_SECRET_ENV,
                    "server.session_binding_secret",
                    EnvOverrideSource::Env,
                ));
                Ok(())
            }
            (None, Some(path)) => {
                let raw_secret = fs::read_to_string(PathBuf::from(&path)).map_err(|error| {
                    RmcpServerKitError::Config(format!(
                        "failed to read {SERVER_SESSION_BINDING_SECRET_FILE_ENV} file {path:?}: {error}"
                    ))
                })?;
                let secret = normalize_text_secret_file(raw_secret);
                validate_session_binding_secret_env(
                    SERVER_SESSION_BINDING_SECRET_FILE_ENV,
                    &secret,
                )?;
                self.session_binding_secret = Some(SecretString::from(secret));
                applied.push(secret_env_report(
                    SERVER_SESSION_BINDING_SECRET_FILE_ENV,
                    "server.session_binding_secret",
                    EnvOverrideSource::File,
                ));
                Ok(())
            }
        }
    }

    #[cfg(feature = "oauth")]
    /// Apply the OAuth environment overrides onto a declared OAuth config.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when the OAuth parent tables are
    /// missing or an override value cannot be parsed.
    fn apply_oauth_env_overrides(
        &mut self,
        oauth_env: OAuthEnvOverrides,
        applied: &mut Vec<EnvOverride>,
    ) -> Result<(), RmcpServerKitError> {
        if !oauth_env.is_set() {
            return Ok(());
        }

        let Some(auth) = self.auth.as_mut() else {
            let var = oauth_env.first_set_var();
            return Err(RmcpServerKitError::Config(format!(
                "{var} requires declaring [server.auth.oauth] before applying env overrides"
            )));
        };
        let Some(oauth) = auth.oauth.as_mut() else {
            let var = oauth_env.first_set_var();
            return Err(RmcpServerKitError::Config(format!(
                "{var} requires declaring [server.auth.oauth] before applying env overrides"
            )));
        };
        if let Some(raw) = oauth_env.issuer {
            applied.push(env_report(
                SERVER_OAUTH_ISSUER_ENV,
                "server.auth.oauth.issuer",
                raw.clone(),
            ));
            oauth.issuer = raw;
        }
        if let Some(raw) = oauth_env.audience {
            applied.push(env_report(
                SERVER_OAUTH_AUDIENCE_ENV,
                "server.auth.oauth.audience",
                raw.clone(),
            ));
            oauth.audience = raw;
        }
        if let Some(raw) = oauth_env.jwks_uri {
            applied.push(env_report(
                SERVER_OAUTH_JWKS_URI_ENV,
                "server.auth.oauth.jwks_uri",
                raw.clone(),
            ));
            oauth.jwks_uri = raw;
        }
        if let Some(raw) = oauth_env.allowed_algorithms {
            // First list-valued env override: split on `,`, trim, and drop
            // empty segments so `RS256, ES256` and `RS256,,ES256` both work.
            let names: Vec<String> = raw
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            // Resolve eagerly so an unusable value is reported against the
            // env var that set it, rather than surfacing later as an opaque
            // `oauth.allowed_algorithms` config error. The resolved list is
            // validation-only here; the OAuth layer recomputes it.
            let _resolved =
                oauth::resolve_allowed_algorithms(Some(names.as_slice())).map_err(|err| {
                    RmcpServerKitError::Config(format!(
                        "{SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV}: {err}"
                    ))
                })?;
            applied.push(env_report(
                SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV,
                "server.auth.oauth.allowed_algorithms",
                raw,
            ));
            oauth.allowed_algorithms = Some(names);
        }
        if let Some(raw) = oauth_env.proxy_strip_resource_param {
            let value = parse_env_bool(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, &raw)?;
            // Fail closed, mirroring the parent-table rule above: this variable
            // can only populate a field on an existing proxy, never create one,
            // because `authorize_url`/`token_url`/`client_id` have no env source.
            let Some(proxy) = oauth.proxy.as_mut() else {
                return Err(RmcpServerKitError::Config(format!(
                    "{SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV} requires declaring \
                     [server.auth.oauth.proxy] before applying env overrides"
                )));
            };
            applied.push(env_report(
                SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV,
                "server.auth.oauth.proxy.strip_resource_param",
                raw,
            ));
            proxy.strip_resource_param = value;
        }
        Ok(())
    }

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
    /// Returns [`RmcpServerKitError::Config`] when a duration string cannot be parsed.
    ///
    /// # Examples
    ///
    /// The full config-file pipeline lives in
    /// [`examples/config_file_server.rs`](https://github.com/andrico21/rmcp-server-kit/blob/main/examples/config_file_server.rs).
    ///
    /// ```
    /// use rmcp_server_kit::config::{ServerConfig, validate_server_config};
    /// use rmcp_server_kit::transport::McpServerConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = ServerConfig::default();
    /// validate_server_config(&server)?;
    /// let config = server.apply_to_mcp_config(McpServerConfig::new(
    ///     "placeholder:0",
    ///     "my-server",
    ///     "0.1.0",
    /// ))?;
    /// let _validated = config.validate()?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn apply_to_mcp_config(
        &self,
        base: McpServerConfig,
    ) -> Result<McpServerConfig, RmcpServerKitError> {
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
            .with_session_binding(self.session_binding)
            .with_task_binding(self.task_binding)
            .with_optional_session_binding_secret(self.session_binding_secret.clone())
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
            .with_request_log_exclude_paths(
                self.request_log_exclude_paths.iter().map(String::as_str),
            )
            .with_log_context(self.log_context.clone())
            .with_trusted_proxies(self.trusted_proxies.iter().map(String::as_str))
            .with_trusted_forwarder_max_entries(self.trusted_forwarder_max_entries)
            .with_optional_tool_rate_limit(self.tool_rate_limit)
            .with_optional_tool_rate_limit_burst(self.tool_rate_limit_burst)
            .with_optional_extra_route_rate_limit(self.extra_route_rate_limit)
            .with_optional_extra_route_rate_limit_burst(self.extra_route_rate_limit_burst)
            .with_key_eviction_policy(self.key_eviction_policy)
            .with_optional_forwarded_header(self.forwarded_header)
            .with_optional_public_url(self.public_url.clone())
            .with_compression_enabled(self.compression_enabled)
            .with_compression_min_size(self.compression_min_size)
            .with_optional_max_concurrent_requests(self.max_concurrent_requests)
            .with_admin_enabled(self.admin_enabled)
            .with_admin_role(&self.admin_role)
            .with_tool_list_filtering(self.tool_list_filtering)
            .with_expose_build_metadata(self.expose_build_metadata)
            .with_security_headers(self.security_headers.clone());

        Ok(config)
    }
}

impl ObservabilityConfig {
    /// Applies `RMCP_SERVER_KIT__OBSERVABILITY__*` environment overrides.
    ///
    /// This method is opt-in and only mutates this struct; it does not update
    /// tracing subscribers or server metrics configuration by itself.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when a boolean override cannot be parsed.
    ///
    /// # Examples
    ///
    /// The full config-file pipeline lives in
    /// [`examples/config_file_server.rs`](https://github.com/andrico21/rmcp-server-kit/blob/main/examples/config_file_server.rs).
    ///
    /// ```no_run
    /// use rmcp_server_kit::config::ObservabilityConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut observability = ObservabilityConfig::default();
    /// // Do not set process env in doctests: rustdoc examples share a process.
    /// let report = observability.apply_env_overrides()?;
    /// let _report_shape: Vec<(&str, &str, Option<&str>)> = report
    ///     .iter()
    ///     .map(|entry| {
    ///         (
    ///             entry.env_var.as_str(),
    ///             entry.target_field.as_str(),
    ///             entry.value.as_deref(),
    ///         )
    ///     })
    ///     .collect();
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn apply_env_overrides(&mut self) -> Result<Vec<EnvOverride>, RmcpServerKitError> {
        let mut applied = Vec::new();
        apply_string_env(
            OBSERVABILITY_LOG_FORMAT_ENV,
            "observability.log_format",
            &mut self.log_format,
            &mut applied,
        )?;
        if let Some(raw) = read_env(OBSERVABILITY_METRICS_ENABLED_ENV)? {
            self.metrics_enabled = parse_env_bool(OBSERVABILITY_METRICS_ENABLED_ENV, &raw)?;
            applied.push(env_report(
                OBSERVABILITY_METRICS_ENABLED_ENV,
                "observability.metrics_enabled",
                raw,
            ));
        }
        if let Some(raw) = read_env(OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV)? {
            self.log_plaintext_oauth_tokens =
                parse_env_bool(OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV, &raw)?;
            applied.push(env_report(
                OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV,
                "observability.log_plaintext_oauth_tokens",
                raw,
            ));
        }
        if let Some(raw) = read_env(OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV)? {
            self.log_oauth_claim_values =
                parse_env_bool(OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV, &raw)?;
            applied.push(env_report(
                OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV,
                "observability.log_oauth_claim_values",
                raw,
            ));
        }
        if let Some(raw) = read_env(OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV)? {
            self.log_tool_call_arguments =
                parse_env_bool(OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV, &raw)?;
            applied.push(env_report(
                OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV,
                "observability.log_tool_call_arguments",
                raw,
            ));
        }
        if let Some(raw) = read_env(OBSERVABILITY_LOG_UPSTREAM_ERROR_BODIES_ENV)? {
            self.log_upstream_error_bodies =
                parse_env_bool(OBSERVABILITY_LOG_UPSTREAM_ERROR_BODIES_ENV, &raw)?;
            applied.push(env_report(
                OBSERVABILITY_LOG_UPSTREAM_ERROR_BODIES_ENV,
                "observability.log_upstream_error_bodies",
                raw,
            ));
        }
        apply_string_env(
            OBSERVABILITY_METRICS_BIND_ENV,
            "observability.metrics_bind",
            &mut self.metrics_bind,
            &mut applied,
        )?;
        Ok(applied)
    }
}

/// Read an environment variable, distinguishing absent from non-UTF-8.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `var` is set but not valid UTF-8.
pub(crate) fn read_env(var: &str) -> Result<Option<String>, RmcpServerKitError> {
    match env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(RmcpServerKitError::Config(format!(
            "{var} must contain valid UTF-8"
        ))),
    }
}

/// Build a non-secret [`EnvOverride`] entry for an applied environment value.
fn env_report(env_var: &str, target_field: &str, value: String) -> EnvOverride {
    EnvOverride {
        env_var: env_var.to_owned(),
        target_field: target_field.to_owned(),
        source: EnvOverrideSource::Env,
        value: Some(value),
    }
}

/// Build a redacted [`EnvOverride`] entry for a secret-typed target.
pub(crate) fn secret_env_report(
    env_var: &str,
    target_field: &str,
    source: EnvOverrideSource,
) -> EnvOverride {
    EnvOverride {
        env_var: env_var.to_owned(),
        target_field: target_field.to_owned(),
        source,
        value: None,
    }
}

/// Parse `raw` as `T`, naming `env_var` and `expected` in the failure message.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `raw` does not parse as `T`.
fn parse_env_value<T>(env_var: &str, raw: &str, expected: &str) -> Result<T, RmcpServerKitError>
where
    T: FromStr,
{
    raw.parse::<T>().map_err(|_error| {
        RmcpServerKitError::Config(format!("invalid value for {env_var}: expected {expected}"))
    })
}

/// Parse `raw` as a boolean, naming `env_var` on failure.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `raw` is not `true` or `false`.
pub(crate) fn parse_env_bool(env_var: &str, raw: &str) -> Result<bool, RmcpServerKitError> {
    parse_env_value(env_var, raw, "bool")
}

/// Apply a required string environment override to `target` and record it.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `env_var` is not valid UTF-8.
fn apply_string_env(
    env_var: &str,
    target_field: &str,
    target: &mut String,
    applied: &mut Vec<EnvOverride>,
) -> Result<(), RmcpServerKitError> {
    if let Some(raw) = read_env(env_var)? {
        applied.push(env_report(env_var, target_field, raw.clone()));
        *target = raw;
    }
    Ok(())
}

/// Apply an optional string environment override to `target` and record it.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `env_var` is not valid UTF-8.
fn apply_optional_string_env(
    env_var: &str,
    target_field: &str,
    target: &mut Option<String>,
    applied: &mut Vec<EnvOverride>,
) -> Result<(), RmcpServerKitError> {
    if let Some(raw) = read_env(env_var)? {
        *target = Some(raw.clone());
        applied.push(env_report(env_var, target_field, raw));
    }
    Ok(())
}

/// Apply an optional path environment override to `target` and record it.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `env_var` is not valid UTF-8.
fn apply_optional_path_env(
    env_var: &str,
    target_field: &str,
    target: &mut Option<PathBuf>,
    applied: &mut Vec<EnvOverride>,
) -> Result<(), RmcpServerKitError> {
    if let Some(raw) = read_env(env_var)? {
        *target = Some(PathBuf::from(&raw));
        applied.push(env_report(env_var, target_field, raw));
    }
    Ok(())
}

/// Strip one trailing line ending from a secret read from a text file.
pub(crate) fn normalize_text_secret_file(mut secret: String) -> String {
    if secret.ends_with("\r\n") {
        secret.truncate(secret.len().saturating_sub(2));
    } else if secret.ends_with('\n') || secret.ends_with('\r') {
        secret.truncate(secret.len().saturating_sub(1));
    } else {
        // No trailing line ending to strip.
    }
    secret
}

/// Validate a session-binding secret read from an environment variable.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the secret fails validation.
fn validate_session_binding_secret_env(
    env_var: &str,
    value: &str,
) -> Result<(), RmcpServerKitError> {
    session_binding::validate_configured_secret(env_var, value)
}

/// Raw OAuth-related environment overrides read before being applied.
struct OAuthEnvOverrides {
    /// `issuer` override, when set.
    issuer: Option<String>,
    /// `audience` override, when set.
    audience: Option<String>,
    /// `jwks_uri` override, when set.
    jwks_uri: Option<String>,
    /// `allowed_algorithms` override, when set.
    allowed_algorithms: Option<String>,
    /// `proxy.strip_resource_param` override, when set.
    proxy_strip_resource_param: Option<String>,
}

impl OAuthEnvOverrides {
    /// Read every OAuth-related environment override.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when a variable is not valid UTF-8.
    fn read() -> Result<Self, RmcpServerKitError> {
        Ok(Self {
            issuer: read_env(SERVER_OAUTH_ISSUER_ENV)?,
            audience: read_env(SERVER_OAUTH_AUDIENCE_ENV)?,
            jwks_uri: read_env(SERVER_OAUTH_JWKS_URI_ENV)?,
            allowed_algorithms: read_env(SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV)?,
            proxy_strip_resource_param: read_env(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV)?,
        })
    }

    /// Whether any OAuth environment override is set.
    const fn is_set(&self) -> bool {
        self.issuer.is_some()
            || self.audience.is_some()
            || self.jwks_uri.is_some()
            || self.allowed_algorithms.is_some()
            || self.proxy_strip_resource_param.is_some()
    }

    /// Name of the first set OAuth environment variable.
    fn first_set_var(&self) -> &'static str {
        first_set_oauth_env(
            self.issuer.as_deref(),
            self.audience.as_deref(),
            self.jwks_uri.as_deref(),
            self.allowed_algorithms.as_deref(),
            self.proxy_strip_resource_param.as_deref(),
        )
    }
}

/// Stable doc anchor for the `ObservabilityConfig` reference section.
const _OBSERVABILITY_CONFIG_DOC_ANCHOR: &str = "ObservabilityConfig";

#[cfg(not(feature = "oauth"))]
/// Reject any OAuth environment override when the `oauth` feature is off.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] naming the first set OAuth variable.
fn reject_oauth_env_overrides(oauth_env: &OAuthEnvOverrides) -> Result<(), RmcpServerKitError> {
    if oauth_env.is_set() {
        let var = oauth_env.first_set_var();
        Err(RmcpServerKitError::Config(format!(
            "{var} requires the `oauth` feature"
        )))
    } else {
        Ok(())
    }
}

/// Return the first set OAuth environment variable of the five, for error messages.
const fn first_set_oauth_env(
    issuer: Option<&str>,
    audience: Option<&str>,
    jwks_uri: Option<&str>,
    allowed_algorithms: Option<&str>,
    proxy_strip_resource_param: Option<&str>,
) -> &'static str {
    if issuer.is_some() {
        SERVER_OAUTH_ISSUER_ENV
    } else if audience.is_some() {
        SERVER_OAUTH_AUDIENCE_ENV
    } else if jwks_uri.is_some() {
        SERVER_OAUTH_JWKS_URI_ENV
    } else if allowed_algorithms.is_some() {
        SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV
    } else if proxy_strip_resource_param.is_some() {
        SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV
    } else {
        SERVER_OAUTH_ISSUER_ENV
    }
}

/// Parse a human-readable duration, naming `field` and `value` on failure.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `value` is not a valid duration.
fn parse_duration_field(field: &str, value: &str) -> Result<Duration, RmcpServerKitError> {
    humantime::parse_duration(value).map_err(|error| {
        RmcpServerKitError::Config(format!("invalid duration for {field}: {value:?}: {error}"))
    })
}

/// Observability settings (reusable across MCP projects).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "observability configuration is a flat TOML schema with independent boolean feature flags"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[non_exhaustive]
pub struct ObservabilityConfig {
    /// `tracing` log level / env filter string (e.g. `info,rmcp_server_kit=debug`).
    /// Default: `info,rmcp=warn,rmcp_server_kit=info`.
    ///
    /// Directives match by target *prefix* (`tracing-subscriber` `EnvFilter`), so `rmcp=warn` on its
    /// own also matches `rmcp_server_kit::*`; keep an explicit `rmcp_server_kit=<level>` directive
    /// when quieting the `rmcp` SDK. The same filter also gates the audit-log file.
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
    /// Log OAuth access tokens in plaintext. Defaults to redacted; enabling
    /// writes secrets to logs and is for local debugging only. Process-wide,
    /// not per-server.
    #[serde(default)]
    pub log_plaintext_oauth_tokens: bool,
    /// Log OAuth claim values in plaintext. Defaults to redacted; enabling
    /// writes secrets to logs and is for local debugging only. Process-wide,
    /// not per-server.
    #[serde(default)]
    pub log_oauth_claim_values: bool,
    /// Log tool-call arguments and identity fields in plaintext. Defaults to
    /// redacted; enabling writes secrets to logs and is for local debugging
    /// only. Process-wide, not per-server.
    #[serde(default)]
    pub log_tool_call_arguments: bool,
    /// Log the `error_description` an authorization server returns on a failed
    /// RFC 8693 token exchange. Defaults to redacted; the value is free-form
    /// upstream text that may reflect request parameters back. Process-wide,
    /// not per-server.
    #[serde(default)]
    pub log_upstream_error_bodies: bool,
}

/// Hand-written so `audit_log_path` never reaches a log.
///
/// SECURITY: the audit log's location is operational metadata an attacker can
/// use to find or tamper with the audit trail. Presence is still reported;
/// only the path is withheld. `observability_config_debug_lists_every_field`
/// fails if a field is added without being rendered here.
impl fmt::Debug for ObservabilityConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservabilityConfig")
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field(
                "audit_log_path",
                &self.audit_log_path.as_ref().map(|_| "[REDACTED]"),
            )
            .field("log_request_headers", &self.log_request_headers)
            .field("metrics_enabled", &self.metrics_enabled)
            .field("metrics_bind", &self.metrics_bind)
            .field(
                "log_plaintext_oauth_tokens",
                &self.log_plaintext_oauth_tokens,
            )
            .field("log_oauth_claim_values", &self.log_oauth_claim_values)
            .field("log_tool_call_arguments", &self.log_tool_call_arguments)
            .field("log_upstream_error_bodies", &self.log_upstream_error_bodies)
            .finish()
    }
}

impl Default for ObservabilityConfig {
    #[inline]
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: default_metrics_bind(),
            log_plaintext_oauth_tokens: false,
            log_oauth_claim_values: false,
            log_tool_call_arguments: false,
            log_upstream_error_bodies: false,
        }
    }
}

/// A violation of an invariant that BOTH config validators must enforce.
///
/// The variants exist so the two validators cannot drift in *ordering* while
/// still reporting their own historical wording: `McpServerConfig::check`
/// distinguishes which TLS half is missing, whereas `validate_server_config`
/// emits one combined message. Callers map variants to their own text.
pub(crate) enum SharedConfigViolation {
    /// `admin_enabled` without an enabled auth config.
    AdminRequiresAuth,
    /// `tls_cert_path` set, `tls_key_path` missing.
    TlsCertWithoutKey,
    /// `tls_key_path` set, `tls_cert_path` missing.
    TlsKeyWithoutCert,
    /// `auth.mtls` configured on a listener without both TLS halves.
    MtlsRequiresTls,
}

/// Evaluate the three invariants shared by both validators, in the one order
/// both must report.
///
/// Scope is deliberately limited to these three. Everything else each
/// validator checks (TOML-only parsing, timeouts, OAuth, security headers,
/// env overrides, bridge behaviour) stays where it is: those inputs are not
/// common to both types, and folding them in here would change validation
/// behaviour that no test currently pins.
///
/// # Errors
///
/// Returns the first violated [`SharedConfigViolation`] in the fixed order.
#[expect(
    clippy::missing_const_for_fn,
    reason = "deliberate: src/config.rs::check_shared_config_invariants is parsed by a source-scanning test that matches its `pub(crate) fn` prefix"
)]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "these are the five independent predicates both validators evaluate; a params struct would carry the same five bools and only relocate the lint"
)]
pub(crate) fn check_shared_config_invariants(
    admin_enabled: bool,
    auth_enabled: bool,
    has_tls_cert: bool,
    has_tls_key: bool,
    has_mtls: bool,
) -> Result<(), SharedConfigViolation> {
    if admin_enabled && !auth_enabled {
        return Err(SharedConfigViolation::AdminRequiresAuth);
    }
    match (has_tls_cert, has_tls_key) {
        (true, false) => return Err(SharedConfigViolation::TlsCertWithoutKey),
        (false, true) => return Err(SharedConfigViolation::TlsKeyWithoutCert),
        _ => {}
    }
    if has_mtls && !(has_tls_cert && has_tls_key) {
        return Err(SharedConfigViolation::MtlsRequiresTls);
    }
    Ok(())
}

/// Validate the generic server config fields.
///
/// # Scope
///
/// This is a pre-flight for TOML files, not a substitute for the authoritative
/// check: `serve()` runs `McpServerConfig::check`, which is the only validator
/// that sees the fully bridged configuration - runtime-only state
/// (`session_store`, `event_store`, ...) has no TOML representation and cannot
/// be checked here. Every rule expressible on both types is enforced by both:
/// the shared rules call the same helpers, and a source-derived parity guard
/// (`every_shared_config_field_is_validated_by_both`) fails when a config field
/// is validated on one side only.
///
/// # Errors
///
/// Returns `RmcpServerKitError::Config` on invalid values.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[inline]
pub fn validate_server_config(server: &ServerConfig) -> RmcpResult<()> {
    if server.listen_port == 0 {
        return Err(RmcpServerKitError::Config(
            "listen_port must be nonzero".into(),
        ));
    }

    // These three checks are delegated to `check_shared_config_invariants` so
    // this validator and `McpServerConfig::check` cannot drift in ordering: a
    // config invalid in more than one of these ways reports the same first
    // error whichever validator a consumer reaches for. Wording stays local
    // because the two types report the TLS pairing failure differently.
    // Checks outside this group are not ordered against the builder: the two
    // types accept different inputs (`listen_port` has no builder analog),
    // so full first-error parity is neither achievable nor claimed.
    if let Err(violation) = check_shared_config_invariants(
        server.admin_enabled,
        server.auth.as_ref().is_some_and(|auth| auth.enabled),
        server.tls_cert_path.is_some(),
        server.tls_key_path.is_some(),
        server.auth.as_ref().is_some_and(|auth| auth.mtls.is_some()),
    ) {
        return Err(RmcpServerKitError::Config(
            match violation {
                SharedConfigViolation::AdminRequiresAuth => {
                    "admin_enabled=true requires auth to be configured and enabled"
                }
                SharedConfigViolation::TlsCertWithoutKey
                | SharedConfigViolation::TlsKeyWithoutCert => {
                    "tls_cert_path and tls_key_path must both be set or both omitted"
                }
                // A consumer calling only `validate_server_config` on TOML
                // would otherwise be told the config is valid while
                // client-certificate authentication is silently inert: a
                // plaintext listener never performs a handshake and so never
                // extracts an identity.
                SharedConfigViolation::MtlsRequiresTls => {
                    "auth.mtls requires TLS: set both tls_cert_path and tls_key_path \
                     (mTLS client certificates cannot be verified on a plaintext listener)"
                }
            }
            .into(),
        ));
    }

    if let Some(auth) = &server.auth {
        auth.validate_api_key_names()?;
    }

    // `allowed_origins` entries are checked with the same helper
    // `McpServerConfig::check` uses, so a TOML-only consumer cannot be told
    // the config is valid and then have `serve()` refuse it at startup.
    for origin in &server.allowed_origins {
        validate_allowed_origin_entry(origin).map_err(RmcpServerKitError::Config)?;
    }

    if server.max_concurrent_requests == Some(0) {
        return Err(RmcpServerKitError::Config(
            "max_concurrent_requests must be nonzero when set".into(),
        ));
    }

    if server.extra_route_rate_limit == Some(0) {
        return Err(RmcpServerKitError::Config(
            "server.extra_route_rate_limit must be greater than zero".into(),
        ));
    }

    validate_rate_limit_knobs(server)?;
    validate_mtls_knobs(server)?;
    validate_trusted_forwarder_config(server)?;

    if server.admin_enabled && server.admin_role.trim().is_empty() {
        return Err(RmcpServerKitError::Config(
            "admin_role must not be empty".into(),
        ));
    }

    if let Some(secret) = &server.session_binding_secret {
        session_binding::validate_configured_secret(
            "server.session_binding_secret",
            secret.expose_secret(),
        )?;
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
            return Err(RmcpServerKitError::Config(format!(
                "invalid duration for {field}: {value:?}"
            )));
        }
    }

    // The handshake deadline must be a positive duration: a zero value
    // would reap every TLS handshake before it could complete. Mirrors
    // check #11 in `McpServerConfig::check`.
    if humantime::parse_duration(&server.tls_handshake_timeout)
        .is_ok_and(|duration| duration == Duration::ZERO)
    {
        return Err(RmcpServerKitError::Config(
            "server.tls_handshake_timeout must be greater than zero".into(),
        ));
    }

    // A zero-permit handshake semaphore would never admit a handshake,
    // deadlocking the TLS accept path. Mirrors check #12 in
    // `McpServerConfig::check`.
    if server.max_concurrent_tls_handshakes == 0 {
        return Err(RmcpServerKitError::Config(
            "server.max_concurrent_tls_handshakes must be greater than zero".into(),
        ));
    }

    // Parity block: rules shared with `McpServerConfig::check`, called from
    // both validators (or reusing the same helper) so a TOML-only consumer
    // cannot be told the config is valid and then have `serve()` refuse it at
    // startup. Appended last so existing error ordering is unchanged.
    if server.max_request_body == 0 {
        return Err(RmcpServerKitError::Config(
            "max_request_body must be greater than zero".into(),
        ));
    }
    if let Some(url) = &server.public_url {
        validate_public_url_value(url).map_err(RmcpServerKitError::Config)?;
    }
    validate_security_headers(&server.security_headers)?;

    Ok(())
}

/// Validate the rate-limit burst knobs of a TOML [`ServerConfig`].
///
/// Zero bursts and orphan bursts fail fast (mirrors `McpServerConfig::check`;
/// the auth bursts have no orphan rule - their base rates always resolve).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when a burst knob is zero or orphaned.
fn validate_rate_limit_knobs(server: &ServerConfig) -> RmcpResult<()> {
    if server.tool_rate_limit_burst == Some(0) {
        return Err(RmcpServerKitError::Config(
            "server.tool_rate_limit_burst must be greater than zero".into(),
        ));
    }
    if server.extra_route_rate_limit_burst == Some(0) {
        return Err(RmcpServerKitError::Config(
            "server.extra_route_rate_limit_burst must be greater than zero".into(),
        ));
    }
    if server.tool_rate_limit_burst.is_some() && server.tool_rate_limit.is_none() {
        return Err(RmcpServerKitError::Config(
            "server.tool_rate_limit_burst requires server.tool_rate_limit".into(),
        ));
    }
    if server.extra_route_rate_limit_burst.is_some() && server.extra_route_rate_limit.is_none() {
        return Err(RmcpServerKitError::Config(
            "server.extra_route_rate_limit_burst requires server.extra_route_rate_limit".into(),
        ));
    }
    if !server.extra_route_rate_limit_exempt_paths.is_empty()
        && server.extra_route_rate_limit.is_none()
    {
        return Err(RmcpServerKitError::Config(
            "server.extra_route_rate_limit_exempt_paths requires server.extra_route_rate_limit"
                .into(),
        ));
    }
    for path in &server.extra_route_rate_limit_exempt_paths {
        if path.is_empty() || !path.starts_with('/') {
            return Err(RmcpServerKitError::Config(format!(
                "server.extra_route_rate_limit_exempt_paths entries must be non-empty and start with '/': {path:?}"
            )));
        }
    }
    for path in &server.request_log_exclude_paths {
        if path.is_empty() || !path.starts_with('/') {
            return Err(RmcpServerKitError::Config(format!(
                "server.request_log_exclude_paths entries must be non-empty and start with '/': {path:?}"
            )));
        }
    }
    if let Some(auth) = server.auth.as_ref() {
        auth.check_oauth_feature()?;
    }
    if let Some(rl) = server
        .auth
        .as_ref()
        .and_then(|auth| auth.rate_limit.as_ref())
    {
        (rl.max_attempts_per_minute != 0).ok_or_else(|| {
            RmcpServerKitError::Config(
                "auth.rate_limit.max_attempts_per_minute must be nonzero".into(),
            )
        })?;
        if rl.burst == Some(0) {
            return Err(RmcpServerKitError::Config(
                "auth.rate_limit.burst must be greater than zero".into(),
            ));
        }
        if rl.pre_auth_burst == Some(0) {
            return Err(RmcpServerKitError::Config(
                "auth.rate_limit.pre_auth_burst must be greater than zero".into(),
            ));
        }
        // `0` here does not mean "unlimited" -- `build_pre_auth_limiter`
        // falls back to DEFAULT_PRE_AUTH_RATE, so a typo silently *raises*
        // the pre-auth quota (e.g. 1/min + 0 yields 300/min, not 10/min)
        // and weakens the gate that shields Argon2 from CPU-spray.
        (rl.pre_auth_max_per_minute != Some(0)).ok_or_else(|| {
            RmcpServerKitError::Config(
                "auth.rate_limit.pre_auth_max_per_minute must be nonzero when set".into(),
            )
        })?;
    }
    Ok(())
}

/// Validate the mTLS/CRL knobs of a TOML [`ServerConfig`].
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when a CRL knob is zero.
fn validate_mtls_knobs(server: &ServerConfig) -> RmcpResult<()> {
    if let Some(mtls) = server.auth.as_ref().and_then(|auth| auth.mtls.as_ref()) {
        (mtls.crl_max_concurrent_fetches != 0).ok_or_else(|| {
            RmcpServerKitError::Config(
                "auth.mtls.crl_max_concurrent_fetches must be nonzero".into(),
            )
        })?;
        (mtls.crl_discovery_rate_per_min != 0).ok_or_else(|| {
            RmcpServerKitError::Config(
                "auth.mtls.crl_discovery_rate_per_min must be nonzero".into(),
            )
        })?;
        (mtls.crl_max_host_semaphores != 0).ok_or_else(|| {
            RmcpServerKitError::Config("auth.mtls.crl_max_host_semaphores must be nonzero".into())
        })?;
        (mtls.crl_max_seen_urls != 0).ok_or_else(|| {
            RmcpServerKitError::Config("auth.mtls.crl_max_seen_urls must be nonzero".into())
        })?;
        (mtls.crl_max_cache_entries != 0).ok_or_else(|| {
            RmcpServerKitError::Config("auth.mtls.crl_max_cache_entries must be nonzero".into())
        })?;
        // `0` rejects every non-empty CRL body at the streaming cap, so CRL
        // fetching never succeeds. Under the default `crl_deny_on_unavailable
        // = true` that fails every CDP-bearing handshake rather than loudly
        // reporting the misconfiguration.
        (mtls.crl_max_response_bytes != 0).ok_or_else(|| {
            RmcpServerKitError::Config("auth.mtls.crl_max_response_bytes must be nonzero".into())
        })?;
    }
    Ok(())
}

/// Validate the trusted-forwarder knobs of a TOML [`ServerConfig`]
/// (mirrors `McpServerConfig::check_trusted_forwarder`).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when a proxy entry, header, scan cap,
/// or request-id header setting is invalid.
fn validate_trusted_forwarder_config(server: &ServerConfig) -> RmcpResult<()> {
    for entry in &server.trusted_proxies {
        validate_trusted_proxy_entry(entry).map_err(RmcpServerKitError::Config)?;
    }
    if server.forwarded_header.is_some() && server.trusted_proxies.is_empty() {
        return Err(RmcpServerKitError::Config(
            "server.forwarded_header requires server.trusted_proxies to be nonempty".into(),
        ));
    }
    if server.trusted_forwarder_max_entries == 0
        || server.trusted_forwarder_max_entries > MAX_CONFIGURABLE_SCANNED_ENTRIES
    {
        return Err(RmcpServerKitError::Config(format!(
            "server.trusted_forwarder_max_entries must be in 1..={MAX_CONFIGURABLE_SCANNED_ENTRIES}, got {}",
            server.trusted_forwarder_max_entries
        )));
    }
    validate_request_id_header(&server.log_context.request_id_header)
        .map_err(|err| RmcpServerKitError::Config(format!("server.{err}")))?;
    if server.log_context.request_id && server.trusted_proxies.is_empty() {
        return Err(RmcpServerKitError::Config(
            "server.log_context.request_id requires server.trusted_proxies to be nonempty".into(),
        ));
    }
    Ok(())
}

/// Validate observability config fields.
///
/// # Errors
///
/// Returns `RmcpServerKitError::Config` on invalid values.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[inline]
pub fn validate_observability_config(obs: &ObservabilityConfig) -> RmcpResult<()> {
    use tracing_subscriber::EnvFilter;

    if EnvFilter::try_new(&obs.log_level).is_err() {
        return Err(RmcpServerKitError::Config(format!(
            "invalid log_level: {:?} (expected a valid tracing filter directive, e.g. \"info\", \"debug,hyper=warn\")",
            obs.log_level
        )));
    }
    let valid_formats = ["json", "pretty", "text"];
    if !valid_formats.contains(&obs.log_format.as_str()) {
        return Err(RmcpServerKitError::Config(format!(
            "invalid log_format: {:?} (expected one of: {valid_formats:?})",
            obs.log_format
        )));
    }

    Ok(())
}

// - Default value functions -

/// Default listen address: `127.0.0.1`.
fn default_listen_addr() -> String {
    "127.0.0.1".into()
}
/// Default listen port: `8443`.
const fn default_listen_port() -> u16 {
    8443
}
/// Default graceful-shutdown timeout: `30s`.
fn default_shutdown_timeout() -> String {
    "30s".into()
}
/// Default per-request timeout: `120s`.
fn default_request_timeout() -> String {
    "120s".into()
}
/// Default maximum request body size: 1 MiB.
const fn default_max_request_body() -> usize {
    1024 * 1024
}
/// Default forwarding-chain scan cap.
const fn default_trusted_forwarder_max_entries() -> usize {
    MAX_SCANNED_ENTRIES
}
/// Default for exposing build metadata on `/version`.
const fn default_expose_build_metadata() -> bool {
    false
}
/// Default for RBAC-filtering `tools/list`.
const fn default_tool_list_filtering() -> bool {
    true
}
/// Default OWASP security-header overrides.
fn default_security_headers() -> SecurityHeadersConfig {
    SecurityHeadersConfig::default()
}
/// Default `tracing` log filter.
fn default_log_level() -> String {
    "info,rmcp=warn,rmcp_server_kit=info".into()
}
/// Default log output format: `pretty`.
fn default_log_format() -> String {
    "pretty".into()
}
/// Default Prometheus metrics bind address.
fn default_metrics_bind() -> String {
    "127.0.0.1:9090".into()
}
/// Default MCP session idle timeout: `20m`.
fn default_session_idle_timeout() -> String {
    "20m".into()
}
/// Default for binding sessions to the authenticated identity.
const fn default_session_binding() -> bool {
    true
}
/// Default per-handshake TLS deadline: `10s`.
fn default_tls_handshake_timeout() -> String {
    "10s".into()
}
/// Default cap on concurrent TLS handshakes: `256`.
const fn default_max_concurrent_tls_handshakes() -> usize {
    256
}
/// Default RBAC role for admin endpoints: `admin`.
fn default_admin_role() -> String {
    "admin".into()
}
/// Default compression threshold: 1024 bytes.
const fn default_compression_min_size() -> u16 {
    1024
}
/// Default SSE keep-alive interval: `15s`.
fn default_sse_keep_alive() -> String {
    "15s".into()
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::std_instead_of_alloc,
    reason = "deliberate: src/config.rs::tests link `std` only; the crate root has no `extern crate alloc`"
)]
#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        io::{self, Write},
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context as _;
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::auth::{ApiKeyEntry, MtlsConfig, RateLimitConfig, generate_api_key};
    #[cfg(feature = "oauth")]
    use crate::oauth::{OAuthConfig, OAuthProxyConfig};

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RootConfig {
        server: ServerConfig,
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }
    }

    struct CapturedLogsWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    fn server_from_root_toml(toml: &str) -> anyhow::Result<ServerConfig> {
        Ok(toml::from_str::<RootConfig>(toml)
            .context("root config TOML must deserialize")?
            .server)
    }

    // -- ServerConfig defaults --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::server_config_defaults keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins the default `ServerConfig` field values surfaced to operators.
    fn server_config_defaults() -> anyhow::Result<()> {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1");
        assert_eq!(cfg.listen_port, 8443);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
        assert_eq!(cfg.shutdown_timeout, "30s");
        assert_eq!(cfg.request_timeout, "120s");
        assert_eq!(cfg.allowed_origins, Vec::<String>::new());
        assert!(!cfg.stdio_enabled);
        assert!(cfg.tool_rate_limit.is_none());
        assert_eq!(cfg.key_eviction_policy, KeyEvictionPolicy::EvictLru);
        assert_eq!(cfg.session_idle_timeout, "20m");
        assert_eq!(cfg.sse_keep_alive, "15s");
        assert!(cfg.public_url.is_none());
        assert!(cfg.tool_list_filtering);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::observability_config_defaults keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins the default `ObservabilityConfig` field values surfaced to operators.
    fn observability_config_defaults() -> anyhow::Result<()> {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_level, "info,rmcp=warn,rmcp_server_kit=info");
        assert_eq!(cfg.log_format, "pretty");
        assert!(cfg.audit_log_path.is_none());
        assert!(!cfg.log_request_headers);
        assert!(!cfg.metrics_enabled);
        assert_eq!(cfg.metrics_bind, "127.0.0.1:9090");
        assert!(!cfg.log_plaintext_oauth_tokens);
        assert!(!cfg.log_oauth_claim_values);
        assert!(!cfg.log_tool_call_arguments);
        Ok(())
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "tracing! macro expansions add branches"
    )]
    fn emit_log_filter_test_probes() {
        tracing::info!(target: "rmcp_server_kit::transport", "probe-kit");
        tracing::info!(target: "rmcp_server_kit::oauth", "probe-kit-oauth");
        tracing::info!(target: "rmcp::service", "probe-sdk-info");
        tracing::warn!(target: "rmcp::service", "probe-sdk-warn");
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::default_log_filter_keeps_framework_info keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the default log filter keeps framework info and warning probes.
    fn default_log_filter_keeps_framework_info() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                ObservabilityConfig::default().log_level,
            ))
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();

        with_default(subscriber, emit_log_filter_test_probes);

        let captured = logs.contents();
        assert!(
            captured.contains("probe-kit"),
            "captured log should contain probe-kit; got: {captured:?}"
        );
        assert!(
            captured.contains("probe-kit-oauth"),
            "captured log should contain probe-kit-oauth; got: {captured:?}"
        );
        assert!(
            captured.contains("probe-sdk-warn"),
            "captured log should contain probe-sdk-warn; got: {captured:?}"
        );
        assert!(
            !captured.contains("probe-sdk-info"),
            "captured log should NOT contain probe-sdk-info; got: {captured:?}"
        );
        Ok(())
    }

    // -- validate_server_config --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::valid_server_config_passes keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a default `ServerConfig` passes TOML validation.
    fn valid_server_config_passes() -> anyhow::Result<()> {
        let cfg = ServerConfig::default();
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that a blank `api_keys` name is rejected while a named key passes.
    fn validate_server_config_rejects_blank_api_key_name() -> anyhow::Result<()> {
        let blank = ServerConfig {
            auth: Some(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                "", "hash", "viewer",
            )])),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&blank) else {
            anyhow::bail!("blank api key name must be rejected");
        };
        let message = err.to_string();
        assert!(
            message.contains("api_keys[0]"),
            "must name offending index: {message}"
        );
        let whitespace = ServerConfig {
            auth: Some(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                "   ", "hash", "viewer",
            )])),
            ..ServerConfig::default()
        };
        assert!(
            validate_server_config(&whitespace).is_err(),
            "whitespace-only api key name must be rejected"
        );

        let ok = ServerConfig {
            auth: Some(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                "viewer-key",
                "hash",
                "viewer",
            )])),
            ..ServerConfig::default()
        };
        assert!(
            validate_server_config(&ok).is_ok(),
            "valid config must validate"
        );
        Ok(())
    }

    #[test]
    /// Pins that admin/auth precedence matches `McpServerConfig::check` ordering.
    fn admin_auth_check_precedes_tls_and_mtls_like_the_builder() -> anyhow::Result<()> {
        // A config invalid in all three ordered ways must report the same
        // first error here as `McpServerConfig::check` does, otherwise the
        // TOML and builder paths disagree about what is wrong.
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.enabled = false;
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            admin_enabled: true,
            auth: Some(auth),
            tls_cert_path: None,
            tls_key_path: None,
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("admin/auth dependency must be reported");
        };
        let message = err.to_string();
        assert!(
            message.contains("admin_enabled=true requires auth"),
            "admin/auth must fire before TLS and mTLS checks; got {message}"
        );
        Ok(())
    }

    fn classify_shared_check(err: RmcpServerKitError) -> anyhow::Result<SharedCheck> {
        match err {
            RmcpServerKitError::Config(msg) => {
                if msg.contains("admin_enabled=true requires auth") {
                    Ok(SharedCheck::AdminAuth)
                } else if msg.contains("must both be set or both omitted")
                    || msg.contains("tls_cert_path is set but tls_key_path is missing")
                    || msg.contains("tls_key_path is set but tls_cert_path is missing")
                {
                    Ok(SharedCheck::TlsPairing)
                } else if msg.contains("auth.mtls requires TLS") {
                    Ok(SharedCheck::MtlsRequiresTls)
                } else {
                    anyhow::bail!("unclassified shared-check config error: {msg}");
                }
            }
            RmcpServerKitError::Auth(msg) => {
                anyhow::bail!("expected Config error, got Auth({msg})");
            }
            RmcpServerKitError::Rbac(msg) => {
                anyhow::bail!("expected Config error, got Rbac({msg})");
            }
            RmcpServerKitError::RateLimited(msg) => {
                anyhow::bail!("expected Config error, got RateLimited({msg})");
            }
            RmcpServerKitError::RateLimitedFor {
                message,
                retry_after,
            } => {
                anyhow::bail!(
                    "expected Config error, got RateLimitedFor({message}, {retry_after:?})"
                );
            }
            RmcpServerKitError::Io(error) => {
                anyhow::bail!("expected Config error, got Io({error})");
            }
            RmcpServerKitError::Json(error) => {
                anyhow::bail!("expected Config error, got Json({error})");
            }
            RmcpServerKitError::Toml(error) => {
                anyhow::bail!("expected Config error, got Toml({error})");
            }
            RmcpServerKitError::Tls(msg) => {
                anyhow::bail!("expected Config error, got Tls({msg})");
            }
            RmcpServerKitError::Startup(msg) => {
                anyhow::bail!("expected Config error, got Startup({msg})");
            }
            RmcpServerKitError::Internal(msg) => {
                anyhow::bail!("expected Config error, got Internal({msg})");
            }
            #[cfg(feature = "metrics")]
            RmcpServerKitError::Metrics(msg) => {
                anyhow::bail!("expected Config error, got Metrics({msg})");
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum AdminSetting {
        Valid,
        EnabledWithDisabledAuth,
    }

    #[derive(Debug, Clone, Copy)]
    enum TlsSetting {
        Absent,
        CertOnly,
        KeyOnly,
    }

    #[derive(Debug, Clone, Copy)]
    enum MtlsSetting {
        Absent,
        WithoutTls,
        WithoutTlsAndInvalidCapacity,
    }

    #[derive(Debug)]
    struct SharedCheckCase {
        name: &'static str,
        admin: AdminSetting,
        tls_variants: &'static [TlsSetting],
        mtls: MtlsSetting,
        expected: SharedCheck,
    }

    const ABSENT_TLS: &[TlsSetting] = &[TlsSetting::Absent];
    const BOTH_PARTIAL_TLS_DIRECTIONS: &[TlsSetting] = &[TlsSetting::CertOnly, TlsSetting::KeyOnly];

    #[test]
    /// Pins that the TOML validator and the builder validator report the same first error for a config that is invalid in several ordered ways at once, so the two configuration paths cannot disagree about which check must run before the others.
    ///
    /// The case table below covers every ordering pair the two validators share.
    fn toml_and_builder_validators_report_the_expected_shared_check_order() -> anyhow::Result<()> {
        let cases = [
            SharedCheckCase {
                name: "case 1: admin/auth dependency only",
                admin: AdminSetting::EnabledWithDisabledAuth,
                tls_variants: ABSENT_TLS,
                mtls: MtlsSetting::Absent,
                expected: SharedCheck::AdminAuth,
            },
            SharedCheckCase {
                name: "case 2: TLS pairing only",
                admin: AdminSetting::Valid,
                tls_variants: BOTH_PARTIAL_TLS_DIRECTIONS,
                mtls: MtlsSetting::Absent,
                expected: SharedCheck::TlsPairing,
            },
            SharedCheckCase {
                name: "case 3: mTLS without TLS only",
                admin: AdminSetting::Valid,
                tls_variants: ABSENT_TLS,
                mtls: MtlsSetting::WithoutTls,
                expected: SharedCheck::MtlsRequiresTls,
            },
            SharedCheckCase {
                name: "case 4: admin/auth dependency before TLS pairing",
                admin: AdminSetting::EnabledWithDisabledAuth,
                tls_variants: BOTH_PARTIAL_TLS_DIRECTIONS,
                mtls: MtlsSetting::Absent,
                expected: SharedCheck::AdminAuth,
            },
            SharedCheckCase {
                name: "case 5: admin/auth dependency before mTLS without TLS",
                admin: AdminSetting::EnabledWithDisabledAuth,
                tls_variants: ABSENT_TLS,
                mtls: MtlsSetting::WithoutTls,
                expected: SharedCheck::AdminAuth,
            },
            SharedCheckCase {
                name: "case 6: TLS pairing before mTLS without TLS",
                admin: AdminSetting::Valid,
                tls_variants: BOTH_PARTIAL_TLS_DIRECTIONS,
                mtls: MtlsSetting::WithoutTls,
                expected: SharedCheck::TlsPairing,
            },
            SharedCheckCase {
                name: "case 7: admin/auth dependency before TLS pairing and mTLS without TLS",
                admin: AdminSetting::EnabledWithDisabledAuth,
                tls_variants: BOTH_PARTIAL_TLS_DIRECTIONS,
                mtls: MtlsSetting::WithoutTls,
                expected: SharedCheck::AdminAuth,
            },
            SharedCheckCase {
                name: "case 8: mTLS without TLS before mTLS capacity knobs",
                admin: AdminSetting::Valid,
                tls_variants: ABSENT_TLS,
                mtls: MtlsSetting::WithoutTlsAndInvalidCapacity,
                expected: SharedCheck::MtlsRequiresTls,
            },
        ];

        for case in cases {
            let case_name = case.name;
            let expected = case.expected;
            for tls in case.tls_variants {
                let config = shared_check_config(case.admin, *tls, case.mtls);

                let toml_class = classify_toml_validator_error(&config)?;
                assert_eq!(
                    toml_class, expected,
                    "{case_name} with {tls:?} must fail TOML validation at {expected:?}"
                );

                let builder_class = classify_builder_validator_error(&config)?;
                assert_eq!(
                    builder_class, expected,
                    "{case_name} with {tls:?} must fail builder validation at {expected:?}"
                );
            }
        }
        Ok(())
    }

    fn classify_toml_validator_error(config: &ServerConfig) -> anyhow::Result<SharedCheck> {
        let Err(err) = validate_server_config(config) else {
            anyhow::bail!("config must fail TOML validation");
        };
        classify_shared_check(err)
    }

    fn classify_builder_validator_error(config: &ServerConfig) -> anyhow::Result<SharedCheck> {
        let builder_config = config
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:1", "t", "0.0.0"))
            .context("valid durations must bridge into McpServerConfig")?;
        let Err(err) = builder_config.validate() else {
            anyhow::bail!("config must fail builder validation");
        };
        classify_shared_check(err)
    }

    fn shared_check_config(
        admin: AdminSetting,
        tls: TlsSetting,
        mtls: MtlsSetting,
    ) -> ServerConfig {
        let mut config = ServerConfig::default();
        apply_admin_setting(&mut config, admin);
        apply_tls_setting(&mut config, tls);
        apply_mtls_setting(&mut config, admin, mtls);
        config
    }

    fn apply_admin_setting(config: &mut ServerConfig, admin: AdminSetting) {
        match admin {
            AdminSetting::Valid => {}
            AdminSetting::EnabledWithDisabledAuth => {
                config.admin_enabled = true;
                let auth = config
                    .auth
                    .get_or_insert_with(|| AuthConfig::with_keys(vec![]));
                auth.enabled = false;
            }
        }
    }

    fn apply_tls_setting(config: &mut ServerConfig, tls: TlsSetting) {
        match tls {
            TlsSetting::Absent => {}
            TlsSetting::CertOnly => {
                config.tls_cert_path = Some("/tmp/cert.pem".into());
            }
            TlsSetting::KeyOnly => {
                config.tls_key_path = Some("/tmp/key.pem".into());
            }
        }
    }

    fn apply_mtls_setting(config: &mut ServerConfig, admin: AdminSetting, mtls: MtlsSetting) {
        match mtls {
            MtlsSetting::Absent => {}
            MtlsSetting::WithoutTls => {
                let enabled = matches!(admin, AdminSetting::Valid);
                let auth = config
                    .auth
                    .get_or_insert_with(|| AuthConfig::with_keys(vec![]));
                auth.enabled = enabled;
                auth.mtls = Some(valid_mtls_config());
            }
            MtlsSetting::WithoutTlsAndInvalidCapacity => {
                let auth = config
                    .auth
                    .get_or_insert_with(|| AuthConfig::with_keys(vec![]));
                auth.enabled = true;
                let mut mtls_config = valid_mtls_config();
                mtls_config.crl_max_concurrent_fetches = 0;
                auth.mtls = Some(mtls_config);
            }
        }
    }

    #[test]
    /// Pins that the TOML validator rejects origins the builder also rejects.
    fn allowed_origins_validated_by_toml_validator_too() -> anyhow::Result<()> {
        // Parity with `McpServerConfig::check`: an entry that cannot match must
        // fail the public TOML validator too, not only `serve()` at startup.
        let cfg = ServerConfig {
            allowed_origins: vec!["https://example.com/path".to_owned()],
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("unmatchable origin must be rejected");
        };
        assert!(
            err.to_string().contains("allowed_origins"),
            "TOML validator must reject unmatchable origins: {err}"
        );

        let ok = ServerConfig {
            allowed_origins: vec!["https://example.com/".to_owned(), "null".to_owned()],
            ..ServerConfig::default()
        };
        validate_server_config(&ok).context("equivalent and null entries stay valid")?;
        Ok(())
    }

    #[test]
    /// Pins that mTLS without a TLS cert/key pair is rejected.
    fn mtls_without_tls_rejected() -> anyhow::Result<()> {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            auth: Some(auth),
            tls_cert_path: None,
            tls_key_path: None,
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("mTLS without TLS must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("tls_cert_path") && msg.contains("tls_key_path"),
            "{msg}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::mtls_with_tls_accepted keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that mTLS with a TLS cert/key pair passes validation.
    fn mtls_with_tls_accepted() -> anyhow::Result<()> {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            auth: Some(auth),
            tls_cert_path: Some("cert.pem".into()),
            tls_key_path: Some("key.pem".into()),
            ..ServerConfig::default()
        };
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that a zero listen port is rejected.
    fn zero_port_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            listen_port: 0,
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero listen port must be rejected");
        };
        assert!(err.to_string().contains("listen_port"));
        Ok(())
    }

    #[test]
    /// Pins that a zero extra-route rate limit is rejected.
    fn zero_extra_route_rate_limit_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            extra_route_rate_limit: Some(0),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero extra-route rate limit must be rejected");
        };
        assert!(err.to_string().contains("extra_route_rate_limit"));
        Ok(())
    }

    #[test]
    /// Pins that zero burst knobs are rejected for both rate-limit families.
    fn zero_burst_knobs_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tool_rate_limit: Some(10),
            tool_rate_limit_burst: Some(0),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero tool burst must be rejected");
        };
        assert!(err.to_string().contains("tool_rate_limit_burst"));

        let cfg_extra = ServerConfig {
            extra_route_rate_limit: Some(10),
            extra_route_rate_limit_burst: Some(0),
            ..ServerConfig::default()
        };
        let Err(err_extra) = validate_server_config(&cfg_extra) else {
            anyhow::bail!("zero extra-route burst must be rejected");
        };
        assert!(
            err_extra
                .to_string()
                .contains("extra_route_rate_limit_burst")
        );
        Ok(())
    }

    #[test]
    /// Pins that burst knobs without their parent rate limit are rejected.
    fn orphan_burst_knobs_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tool_rate_limit_burst: Some(5),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("orphan tool burst must be rejected");
        };
        assert!(err.to_string().contains("requires server.tool_rate_limit"));

        let cfg_extra = ServerConfig {
            extra_route_rate_limit_burst: Some(5),
            ..ServerConfig::default()
        };
        let Err(err_extra) = validate_server_config(&cfg_extra) else {
            anyhow::bail!("orphan extra-route burst must be rejected");
        };
        assert!(
            err_extra
                .to_string()
                .contains("requires server.extra_route_rate_limit")
        );
        Ok(())
    }

    #[test]
    /// Pins exempt-path TOML round-trip and validation.
    fn exempt_paths_toml_roundtrip_and_validation() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str(
            r#"
                extra_route_rate_limit = 60
                extra_route_rate_limit_exempt_paths = ["/.well-known/oauth-authorization-server"]
            "#,
        )
        .context("exempt-path TOML must parse")?;
        assert_eq!(
            cfg.extra_route_rate_limit_exempt_paths,
            vec!["/.well-known/oauth-authorization-server".to_owned()]
        );
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that exempt paths without their parent rate limit are rejected.
    fn orphan_exempt_paths_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            extra_route_rate_limit_exempt_paths: vec!["/ok".into()],
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("orphan exempt paths must be rejected");
        };
        assert!(
            err.to_string()
                .contains("requires server.extra_route_rate_limit")
        );
        Ok(())
    }

    #[test]
    /// Pins that malformed exempt paths are rejected with an actionable message.
    fn malformed_exempt_paths_rejected() -> anyhow::Result<()> {
        for bad in ["", "no-slash"] {
            let cfg = ServerConfig {
                extra_route_rate_limit: Some(10),
                extra_route_rate_limit_exempt_paths: vec![bad.into()],
                ..ServerConfig::default()
            };
            let Err(err) = validate_server_config(&cfg) else {
                anyhow::bail!("malformed exempt path must be rejected");
            };
            assert!(
                err.to_string()
                    .contains("must be non-empty and start with '/'"),
                "entry {bad:?}: {err}"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins request-log exclude-path TOML round-trip and validation.
    fn request_log_exclude_paths_toml_roundtrip_and_validation() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str(
            r#"
                request_log_exclude_paths = ["/version"]
            "#,
        )
        .context("exclude-path TOML must parse")?;
        assert_eq!(cfg.request_log_exclude_paths, vec!["/version".to_owned()]);
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");

        let cfg_default: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(
            cfg_default.request_log_exclude_paths,
            default_request_log_exclude_paths()
        );

        let cfg_empty: ServerConfig = toml::from_str(
            "
                request_log_exclude_paths = []
            ",
        )
        .context("empty exclude-path list TOML must parse")?;
        assert_eq!(cfg_empty.request_log_exclude_paths, Vec::<String>::new());
        assert!(
            validate_server_config(&cfg_empty).is_ok(),
            "empty path list must validate"
        );
        Ok(())
    }

    #[test]
    /// Pins that malformed request-log exclude paths are rejected.
    fn malformed_request_log_exclude_paths_rejected() -> anyhow::Result<()> {
        for bad in ["", "healthz", "no-slash"] {
            let cfg = ServerConfig {
                request_log_exclude_paths: vec![bad.into()],
                ..ServerConfig::default()
            };
            let Err(err) = validate_server_config(&cfg) else {
                anyhow::bail!("malformed exclude path must be rejected");
            };
            assert!(
                err.to_string().contains(
                    "server.request_log_exclude_paths entries must be non-empty and start with '/'"
                ),
                "entry {bad:?}: {err}"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins log-context TOML round-trip and bridge into the MCP config.
    fn log_context_toml_roundtrip_and_bridge() -> anyhow::Result<()> {
        let toml_str = r#"
[log_context]
client_ip = true
peer_ip = true
request_id = false
request_id_header = "x-request-id"
request_line = true
user_agent = false
auth_scheme = true
mcp_hints = false
credential_fingerprint = false
credential_owner = false
request_completion = true
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).context("log_context TOML must parse")?;
        assert!(cfg.log_context.client_ip);
        assert!(cfg.log_context.peer_ip);
        assert!(cfg.log_context.request_line);
        assert!(cfg.log_context.auth_scheme);
        assert!(cfg.log_context.request_completion);
        assert!(!cfg.log_context.credential_owner);

        let base = McpServerConfig::new("127.0.0.1:8080", "test", "0.1.0");
        let mcp_cfg = cfg
            .apply_to_mcp_config(base)
            .context("log_context config must bridge")?;
        assert!(mcp_cfg.log_context.client_ip);
        assert!(mcp_cfg.log_context.peer_ip);

        let cfg_default: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(cfg_default.log_context, LogContextConfig::default());
        Ok(())
    }

    #[test]
    /// Pins that `credential_owner` round-trips and defaults to false.
    fn log_context_credential_owner_toml_roundtrip() -> anyhow::Result<()> {
        // Test 1: credential_owner = true parses and carries through
        let toml_str = "
[log_context]
credential_owner = true
        ";
        let cfg: ServerConfig = toml::from_str(toml_str).context("credential_owner TOML parses")?;
        assert!(
            cfg.log_context.credential_owner,
            "credential_owner must be true"
        );

        let base = McpServerConfig::new("127.0.0.1:8080", "test", "0.1.0");
        let mcp_cfg = cfg
            .apply_to_mcp_config(base)
            .context("credential_owner config must bridge")?;
        assert!(
            mcp_cfg.log_context.credential_owner,
            "must carry through to mcp_config"
        );

        // Test 2: omitted key gives false (default)
        let cfg_default: ServerConfig = toml::from_str(
            "
[log_context]
client_ip = false
        ",
        )
        .context("omitted credential_owner TOML parses")?;
        assert!(
            !cfg_default.log_context.credential_owner,
            "omitted key must default to false"
        );
        Ok(())
    }

    #[test]
    /// Pins that TOML log-context validation mirrors the builder path.
    fn log_context_toml_validation_mirrors_builder() -> anyhow::Result<()> {
        // Test 1: request_id requires trusted_proxies
        let cfg = ServerConfig {
            log_context: LogContextConfig {
                request_id: true,
                ..LogContextConfig::default()
            },
            trusted_proxies: vec![],
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("request_id without trusted_proxies must be rejected");
        };
        assert!(
            err.to_string()
                .contains("server.log_context.request_id requires server.trusted_proxies"),
            "{err}"
        );

        // Test 2: forbidden request_id_header values from the builder test list
        for bad in [
            "",
            "x request id",
            "authorization",
            "Cookie",
            "proxy-authorization",
            "forwarded",
            "X-Forwarded-For",
            "x-real-ip",
            "Mcp-Session-Id",
        ] {
            let cfg_header = ServerConfig {
                log_context: LogContextConfig {
                    request_id_header: bad.to_owned(),
                    ..LogContextConfig::default()
                },
                trusted_proxies: vec!["127.0.0.1/32".into()],
                ..ServerConfig::default()
            };
            let Err(err_header) = validate_server_config(&cfg_header) else {
                anyhow::bail!("forbidden request_id_header must be rejected");
            };
            let err_msg = err_header.to_string();
            assert!(
                err_msg.contains("server.log_context.request_id_header"),
                "Error for header '{bad}' missing 'server.log_context.request_id_header': {err_msg}"
            );
            // The key check: should NOT contain the doubled prefix
            assert!(
                !err_msg.contains("log_context.log_context"),
                "Error for header '{bad}' contains doubled 'log_context.log_context' prefix: {err_msg}"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins that an empty TOML bridges log defaults into the MCP config.
    fn empty_toml_bridges_log_defaults() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(
            cfg.request_log_exclude_paths,
            default_request_log_exclude_paths()
        );
        assert_eq!(cfg.log_context, LogContextConfig::default());

        let base = McpServerConfig::new("127.0.0.1:8080", "test", "0.1.0");
        let mcp_cfg = cfg
            .apply_to_mcp_config(base)
            .context("empty config must bridge")?;
        assert_eq!(
            mcp_cfg.request_log_exclude_paths,
            default_request_log_exclude_paths()
        );
        assert_eq!(mcp_cfg.log_context, LogContextConfig::default());
        Ok(())
    }

    #[test]
    /// Pins that a malformed trusted-proxy entry is rejected.
    fn bad_trusted_proxy_entry_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            trusted_proxies: vec!["not-a-cidr".into()],
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("malformed trusted proxy must be rejected");
        };
        assert!(err.to_string().contains("trusted_proxies"));
        Ok(())
    }

    #[test]
    /// Pins that zero-prefix trusted proxies are rejected.
    fn zero_prefix_trusted_proxy_rejected() -> anyhow::Result<()> {
        for entry in ["0.0.0.0/0", "::/0"] {
            let cfg = ServerConfig {
                trusted_proxies: vec![entry.into()],
                ..ServerConfig::default()
            };
            let Err(err) = validate_server_config(&cfg) else {
                anyhow::bail!("zero-prefix trusted proxy must be rejected");
            };
            assert!(
                err.to_string().contains("prefix length 0"),
                "entry {entry:?}: {err}"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::toml_trusted_forwarder_max_entries_bounds_are_enforced keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins the enforced bounds on `trusted_forwarder_max_entries`.
    fn toml_trusted_forwarder_max_entries_bounds_are_enforced() -> anyhow::Result<()> {
        let parse = |value: usize| -> RmcpResult<()> {
            let cfg: ServerConfig =
                toml::from_str(&format!("trusted_forwarder_max_entries = {value}"))?;
            validate_server_config(&cfg)
        };
        assert!(parse(0).is_err(), "zero must be rejected");
        assert!(
            parse(MAX_CONFIGURABLE_SCANNED_ENTRIES + 1).is_err(),
            "over-cap value must be rejected"
        );
        assert!(parse(1).is_ok(), "minimum value must be accepted");
        assert!(
            parse(MAX_CONFIGURABLE_SCANNED_ENTRIES).is_ok(),
            "cap value must be accepted"
        );
        Ok(())
    }

    #[test]
    /// Pins `trusted_forwarder_max_entries` defaults and bridging.
    fn toml_trusted_forwarder_max_entries_defaults_and_bridges() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(cfg.trusted_forwarder_max_entries, MAX_SCANNED_ENTRIES);
        let base = McpServerConfig::new("127.0.0.1:8080", "t", "0");
        let src: ServerConfig = toml::from_str("trusted_forwarder_max_entries = 32")
            .context("explicit trusted_forwarder_max_entries parses")?;
        let bridged = src
            .apply_to_mcp_config(base)
            .context("trusted_forwarder_max_entries config must bridge")?;
        assert_eq!(bridged.trusted_forwarder_max_entries, 32);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::cidr_and_bare_ip_proxy_entries_accepted keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that CIDR and bare-IP trusted proxies are accepted.
    fn cidr_and_bare_ip_proxy_entries_accepted() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            trusted_proxies: vec!["10.0.0.0/8".into(), "192.0.2.1".into()],
            ..ServerConfig::default()
        };
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that a forwarded header without trusted proxies is rejected.
    fn forwarded_header_without_proxies_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            forwarded_header: Some(ForwardedHeaderMode::Forwarded),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("forwarded header without proxies must be rejected");
        };
        assert!(err.to_string().contains("requires server.trusted_proxies"));
        Ok(())
    }

    #[test]
    /// Pins that zero auth burst knobs are rejected.
    fn zero_auth_bursts_rejected() -> anyhow::Result<()> {
        let auth =
            AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(10).with_burst(0));
        let cfg = ServerConfig {
            auth: Some(auth),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero auth burst must be rejected");
        };
        assert!(err.to_string().contains("rate_limit.burst"));

        let auth_pre = AuthConfig::with_keys(vec![])
            .with_rate_limit(RateLimitConfig::new(10).with_pre_auth_burst(0));
        let cfg_pre = ServerConfig {
            auth: Some(auth_pre),
            ..ServerConfig::default()
        };
        let Err(err_pre) = validate_server_config(&cfg_pre) else {
            anyhow::bail!("zero pre-auth burst must be rejected");
        };
        assert!(err_pre.to_string().contains("pre_auth_burst"));
        Ok(())
    }

    fn valid_mtls_config() -> MtlsConfig {
        MtlsConfig {
            ca_cert_path: "memory://ca.pem".into(),
            required: true,
            default_role: "viewer".into(),
            crl_enabled: true,
            crl_refresh_interval: None,
            crl_fetch_timeout: Duration::from_secs(30),
            crl_stale_grace: Duration::from_hours(24),
            crl_deny_on_unavailable: false,
            crl_end_entity_only: false,
            crl_allow_http: true,
            crl_enforce_expiration: true,
            crl_max_concurrent_fetches: 4,
            crl_max_response_bytes: 5 * 1024 * 1024,
            crl_discovery_rate_per_min: 60,
            crl_max_host_semaphores: 1024,
            crl_max_seen_urls: 4096,
            crl_max_cache_entries: 1024,
        }
    }

    fn assert_config_nonzero_error(err: RmcpServerKitError, field: &str) -> anyhow::Result<()> {
        let RmcpServerKitError::Config(msg) = err else {
            anyhow::bail!("expected Config error for {field}");
        };
        assert!(
            msg.contains(field) && msg.contains("must be nonzero"),
            "error must name {field} and say must be nonzero; got {msg:?}"
        );
        Ok(())
    }

    fn server_config_with_mtls(mtls: MtlsConfig) -> ServerConfig {
        ServerConfig {
            auth: Some(AuthConfig {
                enabled: true,
                api_keys: Vec::new(),
                mtls: Some(mtls),
                rate_limit: None,
                #[cfg(feature = "oauth")]
                oauth: None,
                #[cfg(not(feature = "oauth"))]
                oauth: None,
            }),
            // mTLS requires TLS, and that check runs before the capacity
            // knobs. Without these paths every caller of this helper would
            // fail on the TLS pairing error and never reach what it asserts.
            tls_cert_path: Some("cert.pem".into()),
            tls_key_path: Some("key.pem".into()),
            ..ServerConfig::default()
        }
    }

    #[test]
    /// Pins that a zero CRL max-cache-entries value is rejected.
    fn rejects_zero_crl_max_cache_entries() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_cache_entries = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_max_cache_entries must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_max_cache_entries")
    }

    #[test]
    /// Pins that a zero CRL max-concurrent-fetches value is rejected.
    fn rejects_zero_crl_max_concurrent_fetches() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_concurrent_fetches = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_max_concurrent_fetches must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_max_concurrent_fetches")
    }

    #[test]
    /// Pins that a zero CRL discovery rate is rejected.
    fn rejects_zero_crl_discovery_rate_per_min() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_discovery_rate_per_min = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_discovery_rate_per_min must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_discovery_rate_per_min")
    }

    #[test]
    /// Pins that a zero CRL max-host-semaphores value is rejected.
    fn rejects_zero_crl_max_host_semaphores() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_host_semaphores = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_max_host_semaphores must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_max_host_semaphores")
    }

    #[test]
    /// Pins that a zero CRL max-seen-urls value is rejected.
    fn rejects_zero_crl_max_seen_urls() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_seen_urls = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_max_seen_urls must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_max_seen_urls")
    }

    #[test]
    /// Pins that a zero CRL max-response-bytes value is rejected.
    fn rejects_zero_crl_max_response_bytes() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_response_bytes = 0;
        let Err(err) = validate_server_config(&server_config_with_mtls(mtls)) else {
            anyhow::bail!("zero crl_max_response_bytes must be rejected");
        };
        assert_config_nonzero_error(err, "auth.mtls.crl_max_response_bytes")
    }

    #[test]
    /// Pins that a zero auth rate limit is rejected.
    fn rejects_zero_auth_rate_limit() -> anyhow::Result<()> {
        let auth = AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(0));
        let cfg = ServerConfig {
            auth: Some(auth),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero auth rate limit must be rejected");
        };
        assert_config_nonzero_error(err, "auth.rate_limit.max_attempts_per_minute")
    }

    #[test]
    /// Pins that a zero pre-auth max-per-minute value is rejected.
    fn rejects_zero_pre_auth_max_per_minute() -> anyhow::Result<()> {
        // Regression guard: `0` is NOT "unlimited" here. The limiter builder
        // falls back to DEFAULT_PRE_AUTH_RATE, so accepting `0` would raise
        // the pre-auth quota instead of tightening it.
        let mut rl = RateLimitConfig::new(30);
        rl.pre_auth_max_per_minute = Some(0);
        let cfg = ServerConfig {
            auth: Some(AuthConfig::with_keys(vec![]).with_rate_limit(rl)),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero pre_auth_max_per_minute must be rejected");
        };
        assert_config_nonzero_error(err, "auth.rate_limit.pre_auth_max_per_minute")
    }

    #[test]
    /// Pins that a TLS cert without a key is rejected.
    fn tls_cert_without_key_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_cert_path: Some("/tmp/cert.pem".into()),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("TLS cert without key must be rejected");
        };
        assert!(err.to_string().contains("tls_cert_path"));
        Ok(())
    }

    #[test]
    /// Pins that a TLS key without a cert is rejected.
    fn tls_key_without_cert_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_key_path: Some("/tmp/key.pem".into()),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("TLS key without cert must be rejected");
        };
        assert!(err.to_string().contains("tls_cert_path"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::tls_both_set_passes keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a complete TLS cert/key pair passes validation.
    fn tls_both_set_passes() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_cert_path: Some("/tmp/cert.pem".into()),
            tls_key_path: Some("/tmp/key.pem".into()),
            ..ServerConfig::default()
        };
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that a malformed TLS handshake timeout is rejected.
    fn invalid_tls_handshake_timeout_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_handshake_timeout: "not-a-duration".into(),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("malformed tls_handshake_timeout must be rejected");
        };
        assert!(err.to_string().contains("tls_handshake_timeout"));
        Ok(())
    }

    #[test]
    /// Pins that a zero TLS handshake timeout is rejected.
    fn zero_tls_handshake_timeout_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_handshake_timeout: "0s".into(),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero tls_handshake_timeout must be rejected");
        };
        assert!(err.to_string().contains("tls_handshake_timeout"));
        Ok(())
    }

    #[test]
    /// Pins that zero max-concurrent TLS handshakes is rejected.
    fn zero_max_concurrent_tls_handshakes_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            max_concurrent_tls_handshakes: 0,
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("zero max_concurrent_tls_handshakes must be rejected");
        };
        assert!(err.to_string().contains("max_concurrent_tls_handshakes"));
        Ok(())
    }

    #[test]
    /// Pins that a malformed shutdown timeout is rejected.
    fn invalid_shutdown_timeout_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            shutdown_timeout: "not-a-duration".into(),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("malformed shutdown_timeout must be rejected");
        };
        assert!(err.to_string().contains("shutdown_timeout"));
        Ok(())
    }

    #[test]
    /// Pins that a malformed request timeout is rejected.
    fn invalid_request_timeout_rejected() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            request_timeout: "xyz".into(),
            ..ServerConfig::default()
        };
        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("malformed request_timeout must be rejected");
        };
        assert!(err.to_string().contains("request_timeout"));
        Ok(())
    }

    // -- validate_observability_config --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::valid_observability_config_passes keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a default `ObservabilityConfig` passes validation.
    fn valid_observability_config_passes() -> anyhow::Result<()> {
        let cfg = ObservabilityConfig::default();
        assert!(
            validate_observability_config(&cfg).is_ok(),
            "default observability config must validate"
        );
        Ok(())
    }

    #[test]
    /// Pins that an invalid log level is rejected.
    fn invalid_log_level_rejected() -> anyhow::Result<()> {
        let cfg = ObservabilityConfig {
            log_level: "[invalid".into(),
            ..ObservabilityConfig::default()
        };
        let Err(err) = validate_observability_config(&cfg) else {
            anyhow::bail!("invalid log_level must be rejected");
        };
        assert!(err.to_string().contains("log_level"));
        Ok(())
    }

    #[test]
    /// Pins that an invalid log format is rejected.
    fn invalid_log_format_rejected() -> anyhow::Result<()> {
        let cfg = ObservabilityConfig {
            log_format: "yaml".into(),
            ..ObservabilityConfig::default()
        };
        let Err(err) = validate_observability_config(&cfg) else {
            anyhow::bail!("invalid log_format must be rejected");
        };
        assert!(err.to_string().contains("log_format"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::all_valid_log_levels_accepted keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that every documented log level is accepted.
    fn all_valid_log_levels_accepted() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::all_log_formats_accepted keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that every documented log format is accepted.
    fn all_log_formats_accepted() -> anyhow::Result<()> {
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
        Ok(())
    }

    // -- serde deserialization --

    #[test]
    /// Pins the deserialized defaults for a bare `ServerConfig` TOML.
    fn server_config_deserialize_defaults() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(cfg.listen_port, 8443);
        assert_eq!(cfg.listen_addr, "127.0.0.1");
        assert_eq!(cfg.tls_handshake_timeout, "10s");
        assert_eq!(cfg.max_concurrent_tls_handshakes, 256);
        Ok(())
    }

    #[test]
    /// Pins that an existing server example deserializes with the new defaults.
    fn t1_existing_server_example_deserializes_with_new_defaults() -> anyhow::Result<()> {
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
        )?;

        assert_eq!(server.max_request_body, 1024 * 1024);
        assert!(!server.expose_build_metadata);
        assert_eq!(server.security_headers, SecurityHeadersConfig::default());
        Ok(())
    }

    #[test]
    /// Pins that the default bridge is a no-op against MCP defaults.
    fn t2_default_bridge_is_no_op_for_mcp_defaults() -> anyhow::Result<()> {
        let actual = ServerConfig::default()
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("default config must bridge")?;
        let expected = McpServerConfig::new("127.0.0.1:8443", "t", "0.0.0");

        assert_default_bridge_core_fields(&actual, &expected);
        assert_default_bridge_limit_fields(&actual, &expected);
        assert_default_bridge_metadata_fields(&actual, &expected);
        Ok(())
    }

    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
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

    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
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
        assert_eq!(actual.key_eviction_policy, expected.key_eviction_policy);
        assert_eq!(actual.max_request_body, expected.max_request_body);
        assert_eq!(
            actual.max_concurrent_requests,
            expected.max_concurrent_requests
        );
    }

    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    fn assert_default_bridge_metadata_fields(actual: &McpServerConfig, expected: &McpServerConfig) {
        assert_eq!(actual.session_idle_timeout, expected.session_idle_timeout);
        assert_eq!(actual.session_binding, expected.session_binding);
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
        assert_eq!(actual.tool_list_filtering, expected.tool_list_filtering);
        assert_eq!(actual.expose_build_metadata, expected.expose_build_metadata);
        assert_eq!(actual.security_headers, expected.security_headers);
    }

    #[test]
    /// Pins `session_binding` TOML round-trip and bridge.
    fn session_binding_toml_roundtrip_and_bridge() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            "
                [server]
                session_binding = false
            ",
        )?;
        let bridged = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("session_binding config must bridge")?;

        assert!(!cfg.session_binding);
        assert!(!bridged.session_binding);
        assert!(ServerConfig::default().session_binding);
        assert!(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0").session_binding);
        Ok(())
    }

    #[test]
    /// Pins `session_binding_secret` TOML round-trip and bridge.
    fn session_binding_secret_toml_roundtrip_and_bridge() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            r#"
                [server]
                session_binding_secret = "0123456789abcdef0123456789abcdef"
            "#,
        )?;
        let bridged = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("session_binding_secret config must bridge")?;

        assert!(cfg.session_binding_secret.is_some());
        assert!(bridged.session_binding_secret.is_some());
        assert!(validate_server_config(&cfg).is_ok(), "config must validate");
        Ok(())
    }

    #[test]
    /// Pins that a too-short binding secret is rejected.
    fn session_binding_secret_short_toml_rejected() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            r#"
                [server]
                session_binding_secret = "too-short"
            "#,
        )?;

        let Err(err) = validate_server_config(&cfg) else {
            anyhow::bail!("short binding secret fails");
        };

        assert!(err.to_string().contains("at least 32 UTF-8 bytes"));
        Ok(())
    }

    #[test]
    /// Pins `tool_list_filtering` TOML round-trip and bridge.
    fn tool_list_filtering_toml_roundtrip_and_bridge() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            "
                [server]
                tool_list_filtering = false
            ",
        )?;
        let bridged = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("tool_list_filtering config must bridge")?;

        assert!(!cfg.tool_list_filtering);
        assert!(!bridged.tool_list_filtering);
        assert!(ServerConfig::default().tool_list_filtering);
        assert!(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0").tool_list_filtering);
        Ok(())
    }

    #[test]
    /// Pins that an HSTS preload header from TOML is rejected by `validate`.
    fn t5_hsts_preload_from_toml_rejected_by_mcp_validate() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                strict_transport_security = "max-age=1; preload"
            "#,
        )?;
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("HSTS preload config must bridge")?;

        let Err(err) = mcp.validate() else {
            anyhow::bail!("HSTS preload must be rejected");
        };
        let msg = err.to_string();
        assert!(msg.contains("preload"), "error must mention preload: {msg}");
        Ok(())
    }

    #[test]
    /// Pins that a bad security header from TOML is rejected by `validate`.
    fn t6_bad_security_header_from_toml_rejected_by_mcp_validate() -> anyhow::Result<()> {
        let cfg = server_from_root_toml(
            r#"
                [server.security_headers]
                content_security_policy = "bad\nvalue"
            "#,
        )?;
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("bad security header config must bridge")?;

        let Err(err) = mcp.validate() else {
            anyhow::bail!("bad security header must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("invalid security_headers.content_security_policy"),
            "error must name invalid header field: {msg}"
        );
        Ok(())
    }

    #[test]
    /// Pins that a zero max request body is rejected by `validate`.
    fn t7_zero_max_request_body_rejected_by_mcp_validate() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str("max_request_body = 0")
            .context("zero max_request_body TOML must parse")?;
        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("zero max_request_body config must bridge")?;

        let Err(err) = mcp.validate() else {
            anyhow::bail!("zero max_request_body must be rejected");
        };
        assert!(
            err.to_string()
                .contains("max_request_body must be greater than zero")
        );
        Ok(())
    }

    #[test]
    /// Pins that an unknown security-header key is rejected.
    fn t9_unknown_security_header_key_is_rejected() -> anyhow::Result<()> {
        let Err(err) = toml::from_str::<RootConfig>(
            r#"
                [server.security_headers]
                typo_content_security_policy = "default-src 'self'"
            "#,
        ) else {
            anyhow::bail!("unknown security-header key must be rejected");
        };

        let msg = err.to_string();
        assert!(
            msg.contains("typo_content_security_policy"),
            "error must name the offending key: {msg}"
        );
        Ok(())
    }

    #[test]
    /// Pins that an unknown `ServerConfig` key is rejected.
    fn unknown_server_config_key_is_rejected() -> anyhow::Result<()> {
        let Err(err) = toml::from_str::<ServerConfig>(
            r#"
                tls_keypath = "/etc/certs/server.key"
            "#,
        ) else {
            anyhow::bail!("unknown server config key must be rejected");
        };

        let msg = err.to_string();
        assert!(
            msg.contains("tls_keypath"),
            "error must name the offending key: {msg}"
        );
        Ok(())
    }

    #[cfg(not(feature = "oauth"))]
    #[test]
    /// Pins that an `[auth.oauth]` table without the oauth feature explains the fix.
    fn oauth_table_without_oauth_feature_is_rejected_with_actionable_message() -> anyhow::Result<()>
    {
        // `deny_unknown_fields` on `AuthConfig` would otherwise surface this as
        // `unknown field \`oauth\``, which never mentions the cargo feature.
        // Failing closed matters: silently dropping the table starts a server
        // whose config says OAuth is on while no token validation is compiled in.
        let server = toml::from_str::<ServerConfig>(
            r#"
                listen_port = 8080

                [auth]
                enabled = true

                [auth.oauth]
                issuer = "https://auth.example.com"
            "#,
        )
        .context("[auth.oauth] must parse so validation can produce the real message")?;

        let Err(err) = validate_server_config(&server) else {
            anyhow::bail!("auth.oauth without the oauth feature must be rejected");
        };
        let msg = err.to_string();

        assert!(
            msg.contains("oauth") && msg.contains("--features oauth"),
            "error must name the missing cargo feature and how to fix it: {msg}"
        );
        Ok(())
    }

    #[test]
    /// Pins that all twelve security-header keys deserialize from server TOML.
    fn all_twelve_security_header_keys_deserialize_from_server_toml() -> anyhow::Result<()> {
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
        )?;

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
        Ok(())
    }

    /// Extract the `pub` field names of a struct from this file's own source.
    fn struct_pub_fields(marker: &str) -> anyhow::Result<Vec<String>> {
        let source = include_str!("config.rs").replace("\r\n", "\n");
        let (_, after) = source
            .split_once(marker)
            .with_context(|| format!("struct start marker {marker:?} not found"))?;
        let (body, _) = after
            .split_once("\n}\n")
            .context("struct end marker not found")?;
        Ok(body
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("pub ")
                    .and_then(|rest| rest.split_once(':').map(|(name, _)| name.trim().to_owned()))
            })
            .collect())
    }

    /// Config fields deliberately NOT exposed as environment overrides.
    ///
    /// Hand-maintained on purpose: adding a field to `ServerConfig` or
    /// `ObservabilityConfig` must be a conscious decision to expose it or not,
    /// and `every_config_field_is_env_overridable_or_excluded` fails until the
    /// field appears in `ENV_OVERRIDE_SPECS` or here. Without this list a new
    /// field silently defaults to "no override" with nothing to notice it.
    const ENV_OVERRIDE_EXCLUDED_FIELDS: &[&str] = &[
        // Structured / nested values with no single-scalar env representation.
        "server.allowed_origins",
        "server.extra_route_rate_limit_exempt_paths",
        "server.request_log_exclude_paths",
        "server.log_context",
        "server.trusted_proxies",
        "server.auth",
        "server.security_headers",
        // Tuning knobs intentionally file-only: changing them per-process via
        // the environment invites drift between replicas of the same service.
        "server.tls_handshake_timeout",
        "server.max_concurrent_tls_handshakes",
        "server.shutdown_timeout",
        "server.request_timeout",
        "server.max_request_body",
        "server.stdio_enabled",
        "server.tool_rate_limit",
        "server.tool_rate_limit_burst",
        "server.extra_route_rate_limit",
        "server.extra_route_rate_limit_burst",
        "server.trusted_forwarder_max_entries",
        "server.forwarded_header",
        "server.session_idle_timeout",
        "server.session_binding",
        // Identity-binding posture, file-only for the same reason as
        // `session_binding`: replicas must agree, and an env-flippable
        // security control invites per-process drift.
        "server.task_binding",
        "server.sse_keep_alive",
        "server.compression_enabled",
        "server.compression_min_size",
        "server.max_concurrent_requests",
        "server.admin_role",
        "server.tool_list_filtering",
        "server.expose_build_metadata",
        // `log_level` is already controlled by RUST_LOG; a second env source
        // would give two switches for one behaviour.
        "observability.log_level",
        "observability.audit_log_path",
        "observability.log_request_headers",
    ];

    #[test]
    /// Pins that every config field is either env-overridable or deliberately excluded.
    fn every_config_field_is_env_overridable_or_excluded() -> anyhow::Result<()> {
        for (marker, prefix) in [
            ("pub struct ServerConfig {", "server"),
            ("pub struct ObservabilityConfig {", "observability"),
        ] {
            for field in struct_pub_fields(marker)? {
                let target = format!("{prefix}.{field}");
                let overridable = ENV_OVERRIDE_SPECS
                    .iter()
                    .any(|spec| spec.target_field == target);
                let excluded = ENV_OVERRIDE_EXCLUDED_FIELDS.contains(&target.as_str());
                assert!(
                    overridable || excluded,
                    "`{target}` is neither env-overridable nor listed in \
                     ENV_OVERRIDE_EXCLUDED_FIELDS; classify it deliberately"
                );
                assert!(
                    !(overridable && excluded),
                    "`{target}` is both env-overridable and excluded; remove one"
                );
            }
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::shared_invariants_report_a_fixed_precedence keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that shared invariants report a fixed precedence.
    fn shared_invariants_report_a_fixed_precedence() -> anyhow::Result<()> {
        // All three violated at once: both validators must surface the same
        // one first, which is the drift this helper exists to prevent.
        assert!(matches!(
            check_shared_config_invariants(true, false, true, false, true),
            Err(SharedConfigViolation::AdminRequiresAuth)
        ));
        // Admin satisfied: TLS pairing outranks mTLS-requires-TLS.
        assert!(matches!(
            check_shared_config_invariants(false, true, true, false, true),
            Err(SharedConfigViolation::TlsCertWithoutKey)
        ));
        assert!(matches!(
            check_shared_config_invariants(false, true, false, true, true),
            Err(SharedConfigViolation::TlsKeyWithoutCert)
        ));
        // Pairing satisfied (neither half set), mTLS still unsatisfiable.
        assert!(matches!(
            check_shared_config_invariants(false, true, false, false, true),
            Err(SharedConfigViolation::MtlsRequiresTls)
        ));
        // Fully valid combinations.
        assert!(
            check_shared_config_invariants(true, true, true, true, true).is_ok(),
            "admin+auth with full TLS and mTLS must be valid"
        );
        assert!(
            check_shared_config_invariants(false, false, false, false, false).is_ok(),
            "an empty config must be valid"
        );
        Ok(())
    }

    #[test]
    /// Pins that the TOML validator surfaces the shared precedence.
    fn toml_validator_surfaces_the_shared_precedence() -> anyhow::Result<()> {
        let server = ServerConfig {
            admin_enabled: true,
            tls_cert_path: Some(PathBuf::from("/etc/certs/server.crt")),
            ..Default::default()
        };

        let Err(err) = validate_server_config(&server) else {
            anyhow::bail!("admin without auth must fail");
        };
        let message = err.to_string();
        assert!(
            message.contains("admin_enabled=true requires auth"),
            "admin must be reported before the TLS pairing failure; got {message:?}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::server_config_debug_redacts_tls_key_path keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the `ServerConfig` Debug output redacts the TLS key path.
    fn server_config_debug_redacts_tls_key_path() -> anyhow::Result<()> {
        let cfg = ServerConfig {
            tls_cert_path: Some(PathBuf::from("/etc/certs/server.crt")),
            tls_key_path: Some(PathBuf::from("/etc/secrets/server.key")),
            ..Default::default()
        };

        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("server.key") && !rendered.contains("/etc/secrets"),
            "the private-key path must never render; got {rendered}"
        );
        assert!(
            rendered.contains("tls_key_path: Some(\"[REDACTED]\")"),
            "presence must still be reported for diagnostics; got {rendered}"
        );
        assert!(
            rendered.contains("server.crt"),
            "the certificate path is not secret and must remain visible"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::observability_config_debug_redacts_audit_log_path keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the `ObservabilityConfig` Debug output redacts the audit path.
    fn observability_config_debug_redacts_audit_log_path() -> anyhow::Result<()> {
        let cfg = ObservabilityConfig {
            audit_log_path: Some(PathBuf::from("/var/log/rmcp/audit.log")),
            ..Default::default()
        };

        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("audit.log") && !rendered.contains("/var/log"),
            "the audit log location must never render; got {rendered}"
        );
        assert!(rendered.contains("audit_log_path: Some(\"[REDACTED]\")"));
        Ok(())
    }

    #[test]
    /// Pins that the hand-written `ServerConfig` Debug lists every field.
    fn server_config_debug_lists_every_field() -> anyhow::Result<()> {
        let rendered = format!("{:?}", ServerConfig::default());
        for field in struct_pub_fields("pub struct ServerConfig {")? {
            assert!(
                rendered.contains(&format!("{field}:")),
                "hand-written Debug omits `{field}`; add it (redacted if sensitive)"
            );
        }
        Ok(())
    }

    /// Fields of `struct` `marker`, including `pub(crate)` ones.
    fn struct_fields_in(source: &str, marker: &str) -> anyhow::Result<Vec<String>> {
        let (_, after) = source
            .split_once(marker)
            .with_context(|| format!("struct start marker {marker:?} not found"))?;
        let (body, _) = after
            .split_once("\n}\n")
            .context("struct end marker not found")?;
        Ok(body
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let rest = trimmed
                    .strip_prefix("pub(crate) ")
                    .or_else(|| trimmed.strip_prefix("pub "))?;
                rest.split_once(':').map(|(name, _)| name.trim().to_owned())
            })
            .collect())
    }

    /// Bodies of every function at `indent` whose signature line satisfies
    /// `wanted`, ending at the first following line that is exactly `indent}`.
    /// Line-based extraction is sound because the tree is rustfmt-clean.
    fn function_bodies(source: &str, indent: &str, wanted: &dyn Fn(&str) -> bool) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let close = format!("{indent}}}");
        let inner_indent = format!("{indent}    ");
        let mut out = Vec::new();
        let mut index = 0;
        while let Some(line) = lines.get(index) {
            let at_this_indent = line.starts_with(indent) && !line.starts_with(&inner_indent);
            if at_this_indent && wanted(line) {
                let mut body = String::from(*line);
                index = index.saturating_add(1);
                while let Some(current) = lines.get(index) {
                    if *current == close {
                        break;
                    }
                    body.push_str(current);
                    body.push('\n');
                    index = index.saturating_add(1);
                }
                out.push(body);
            }
            index = index.saturating_add(1);
        }
        out
    }

    /// Whole-word containment, so `auth` does not match `authorize`.
    fn mentions_identifier(haystack: &str, needle: &str) -> bool {
        let boundary = |character: Option<char>| {
            character.is_none_or(|next| !(next.is_alphanumeric() || next == '_'))
        };
        haystack.match_indices(needle).any(|(start, _)| {
            let end = start.saturating_add(needle.len());
            let before = haystack
                .get(..start)
                .and_then(|slice| slice.chars().next_back());
            let after = haystack.get(end..).and_then(|slice| slice.chars().next());
            boundary(before) && boundary(after)
        })
    }

    /// Fields present in BOTH config types that neither validator needs a rule
    /// for.
    ///
    /// Hand-maintained on purpose, mirroring `ENV_OVERRIDE_EXCLUDED_FIELDS`:
    /// `every_shared_config_field_is_validated_by_both` fails until a shared
    /// field is validated by both validators or listed here with a reason.
    /// Without this, a rule added to one validator silently stops at the
    /// other - the defect class that let `allowed_origins` reach `serve()`
    /// while `validate_server_config` reported `Ok`.
    const VALIDATION_PARITY_EXEMPT: &[(&str, &str)] = &[
        ("compression_enabled", "bool; no invalid state exists"),
        (
            "compression_min_size",
            "zero is meaningful (compress every response); neither validator has a rule for it",
        ),
        ("expose_build_metadata", "bool; no invalid state exists"),
        ("key_eviction_policy", "enum; every variant is valid"),
        (
            "task_binding",
            "bool; the secret it reuses is validated through `session_binding_secret`, and the pairing itself happens at router build (`resolve_binding_secret`), which is runtime state neither config type owns",
        ),
        (
            "request_timeout",
            "builder side is a Duration, which cannot be malformed; the TOML string form is parsed and rejected there",
        ),
        (
            "session_idle_timeout",
            "builder side is a Duration, which cannot be malformed; the TOML string form is parsed and rejected there",
        ),
        (
            "shutdown_timeout",
            "builder side is a Duration, which cannot be malformed; the TOML string form is parsed and rejected there",
        ),
        (
            "sse_keep_alive",
            "builder side is a Duration, which cannot be malformed; the TOML string form is parsed and rejected there",
        ),
        ("tool_list_filtering", "bool; no invalid state exists"),
    ];

    #[test]
    /// Pins that every shared config field is validated by both validators.
    fn every_shared_config_field_is_validated_by_both() -> anyhow::Result<()> {
        let toml_source = include_str!("config.rs");
        let builder_source = include_str!("transport.rs");

        let toml_fields = struct_fields_in(toml_source, "pub struct ServerConfig {")?;
        let builder_fields = struct_fields_in(builder_source, "pub struct McpServerConfig {")?;
        let shared: Vec<String> = toml_fields
            .iter()
            .filter(|field| builder_fields.contains(field))
            .cloned()
            .collect();
        assert!(
            shared.len() >= 25,
            "parity guard parsed only {} shared fields; the struct shape changed - fix the parser",
            shared.len()
        );

        // Derived surfaces: every top-level fn taking a `&ServerConfig` in
        // `config.rs` (plus the shared-invariant helper), and every `check*`
        // method on `McpServerConfig`.
        let toml_surface: String = function_bodies(toml_source, "", &|line| {
            (line.contains("fn ")
                && (line.contains("&ServerConfig") || line.contains(": ServerConfig")))
                || line.trim_start().starts_with("pub(crate) fn check_shared_")
        })
        .join("\n");
        let builder_surface: String = function_bodies(builder_source, "    ", &|line| {
            line.trim_start().starts_with("fn check")
                || line.trim_start().starts_with("pub fn check")
        })
        .join("\n");

        // Sanity: the extraction must have found the validators it knows about.
        // These fail loudly if a validator is renamed or reformatted, which is
        // the safe direction for a hand-written expectation.
        for expected in [
            "fn validate_server_config",
            "fn validate_rate_limit_knobs",
            "fn validate_mtls_knobs",
            "fn validate_trusted_forwarder_config",
            "fn check_shared_config_invariants",
        ] {
            assert!(
                toml_surface.contains(expected),
                "TOML validator surface lost `{expected}`; update the extraction rule"
            );
        }
        for expected in [
            "fn check(",
            "fn check_burst_knobs",
            "fn check_trusted_forwarder",
            "fn check_session_binding_config",
            "fn check_metrics_handle",
        ] {
            assert!(
                builder_surface.contains(expected),
                "builder validator surface lost `{expected}`; update the extraction rule"
            );
        }

        for field in &shared {
            if let Some((_, reason)) = VALIDATION_PARITY_EXEMPT
                .iter()
                .find(|(name, _)| name == field)
            {
                assert!(
                    !reason.trim().is_empty(),
                    "`{field}` is exempted without a reason"
                );
                continue;
            }
            assert!(
                mentions_identifier(&toml_surface, field),
                "`{field}` is not validated by `validate_server_config`; add the rule there, \
                 or exempt it in VALIDATION_PARITY_EXEMPT with a reason"
            );
            assert!(
                mentions_identifier(&builder_surface, field),
                "`{field}` is not validated by `McpServerConfig::check`; add the rule there, \
                 or exempt it in VALIDATION_PARITY_EXEMPT with a reason"
            );
        }

        for (field, _) in VALIDATION_PARITY_EXEMPT {
            assert!(
                shared.iter().any(|candidate| candidate == field),
                "VALIDATION_PARITY_EXEMPT lists `{field}`, which is no longer shared by both config types"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins that the hand-written `ObservabilityConfig` Debug lists every field.
    fn observability_config_debug_lists_every_field() -> anyhow::Result<()> {
        let rendered = format!("{:?}", ObservabilityConfig::default());
        for field in struct_pub_fields("pub struct ObservabilityConfig {")? {
            assert!(
                rendered.contains(&format!("{field}:")),
                "hand-written Debug omits `{field}`; add it (redacted if sensitive)"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins that every `ServerConfig` field is classified for bridging.
    fn t10_every_server_config_field_is_classified_for_bridge() -> anyhow::Result<()> {
        let source = include_str!("config.rs").replace("\r\n", "\n");
        let (_, after_struct_start) = source
            .split_once("pub struct ServerConfig {")
            .context("ServerConfig struct start marker")?;
        let (struct_body, _) = after_struct_start
            .split_once("\n}\n\nimpl ServerConfig")
            .context("ServerConfig struct end marker")?;
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
        Ok(())
    }

    #[test]
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    /// Pins bridge replacement semantics for optional and bool fields.
    fn replacement_semantics_clear_base_option_and_false_bool_fields() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key().context("api key generation must succeed")?;
        let base = McpServerConfig::new("127.0.0.1:0", "t", "0.0.0")
            .with_tls("/tmp/base.crt", "/tmp/base.key")
            .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                "base-key", hash, "admin",
            )]))
            .with_tool_rate_limit(10)
            .with_tool_rate_limit_burst(20)
            .with_extra_route_rate_limit(30)
            .with_extra_route_rate_limit_burst(40)
            .with_trusted_proxies(["127.0.0.1/32"])
            .with_forwarded_header(ForwardedHeaderMode::Forwarded)
            .with_public_url("https://base.example")
            .enable_compression(512)
            .with_max_concurrent_requests(99)
            .enable_admin("admin")
            .expose_build_metadata()
            .with_log_context(LogContextConfig {
                client_ip: true,
                request_id: true,
                ..LogContextConfig::default()
            })
            .with_request_log_exclude_paths(["/x"]);

        let actual = ServerConfig::default()
            .apply_to_mcp_config(base)
            .context("replacement config must bridge")?;

        assert!(actual.tls_cert_path.is_none());
        assert!(actual.tls_key_path.is_none());
        assert!(actual.auth.is_none());
        assert!(actual.tool_rate_limit.is_none());
        assert!(actual.tool_rate_limit_burst.is_none());
        assert!(actual.extra_route_rate_limit.is_none());
        assert!(actual.extra_route_rate_limit_burst.is_none());
        assert_eq!(actual.key_eviction_policy, KeyEvictionPolicy::EvictLru);
        assert!(actual.forwarded_header.is_none());
        assert!(actual.public_url.is_none());
        assert!(!actual.compression_enabled);
        assert_eq!(actual.compression_min_size, 1024);
        assert!(actual.max_concurrent_requests.is_none());
        assert!(!actual.admin_enabled);
        assert_eq!(actual.admin_role, "admin");
        assert!(!actual.expose_build_metadata);
        assert_eq!(
            actual.request_log_exclude_paths,
            default_request_log_exclude_paths()
        );
        assert_eq!(actual.log_context, LogContextConfig::default());
        Ok(())
    }

    #[test]
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    /// Pins that a partial TLS TOML does not inherit the base key.
    fn partial_tls_toml_does_not_inherit_base_key() -> anyhow::Result<()> {
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
            .context("partial TLS config must bridge")?;

        assert_eq!(mcp.tls_cert_path, Some(PathBuf::from("/tmp/toml.crt")));
        assert!(mcp.tls_key_path.is_none());
        let Err(err) = mcp.validate() else {
            anyhow::bail!("partial TLS pairing must be rejected");
        };
        assert!(err.to_string().contains("tls_key_path"));
        Ok(())
    }

    #[test]
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    /// Pins that a partial TLS TOML does not inherit the base cert.
    fn partial_tls_toml_does_not_inherit_base_cert() -> anyhow::Result<()> {
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
            .context("partial TLS config must bridge")?;

        assert!(mcp.tls_cert_path.is_none());
        assert_eq!(mcp.tls_key_path, Some(PathBuf::from("/tmp/toml.key")));
        let Err(err) = mcp.validate() else {
            anyhow::bail!("partial TLS pairing must be rejected");
        };
        assert!(err.to_string().contains("tls_cert_path"));
        Ok(())
    }

    #[test]
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    /// Pins that the bridge maps bind address and request timeout.
    fn t11_bridge_maps_bind_addr_and_request_timeout() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str(
            r#"
                listen_addr = "127.0.0.2"
                listen_port = 9000
                request_timeout = "5s"
            "#,
        )
        .context("bridge TOML must parse")?;

        let mcp = cfg
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("bridge TOML must bridge")?;

        assert_eq!(mcp.bind_addr, "127.0.0.2:9000");
        assert_eq!(mcp.request_timeout, Duration::from_secs(5));
        Ok(())
    }

    #[test]
    /// Pins key-eviction-policy TOML defaults and overrides.
    fn key_eviction_policy_toml_defaults_and_overrides() -> anyhow::Result<()> {
        let default_cfg: ServerConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(default_cfg.key_eviction_policy, KeyEvictionPolicy::EvictLru);

        let reject_new: ServerConfig = toml::from_str(r#"key_eviction_policy = "reject_new""#)
            .context("reject_new policy parses")?;
        assert_eq!(reject_new.key_eviction_policy, KeyEvictionPolicy::RejectNew);
        let bridged = reject_new
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .context("key_eviction_policy config must bridge")?;
        assert_eq!(bridged.key_eviction_policy, KeyEvictionPolicy::RejectNew);
        Ok(())
    }

    #[test]
    /// Pins that the bridge rejects an invalid request timeout.
    fn t12_bridge_rejects_invalid_request_timeout() -> anyhow::Result<()> {
        let cfg: ServerConfig = toml::from_str(r#"request_timeout = "not-a-duration""#)
            .context("invalid request_timeout TOML must parse")?;

        let Err(err) = cfg.apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
        else {
            anyhow::bail!("invalid request_timeout must fail");
        };

        assert!(err.to_string().contains("request_timeout"));
        Ok(())
    }

    #[test]
    /// Pins the deserialized defaults for a bare `ObservabilityConfig` TOML.
    fn observability_config_deserialize_defaults() -> anyhow::Result<()> {
        let cfg: ObservabilityConfig = toml::from_str("").context("empty TOML must parse")?;
        assert_eq!(cfg.log_level, "info,rmcp=warn,rmcp_server_kit=info");
        assert_eq!(cfg.log_format, "pretty");
        assert!(!cfg.log_request_headers);
        assert!(!cfg.metrics_enabled);
        assert!(!cfg.log_plaintext_oauth_tokens);
        assert!(!cfg.log_oauth_claim_values);
        assert!(!cfg.log_tool_call_arguments);
        Ok(())
    }

    #[test]
    /// Pins that the diagnostic knobs deserialize as true.
    fn observability_diagnostic_knobs_deserialize_true() -> anyhow::Result<()> {
        let cfg: ObservabilityConfig = toml::from_str(
            "
                log_plaintext_oauth_tokens = true
                log_oauth_claim_values = true
                log_tool_call_arguments = true
            ",
        )
        .context("diagnostic-knob TOML must parse")?;

        assert!(cfg.log_plaintext_oauth_tokens);
        assert!(cfg.log_oauth_claim_values);
        assert!(cfg.log_tool_call_arguments);
        Ok(())
    }

    fn all_env_vars() -> Vec<&'static str> {
        ENV_OVERRIDE_SPECS.iter().map(|spec| spec.env_var).collect()
    }

    fn with_env_vars<R>(vars: &[(&str, Option<&str>)], callback: impl FnOnce() -> R) -> R {
        let mut all = all_env_vars()
            .into_iter()
            .map(|var| (var, None::<&str>))
            .collect::<Vec<_>>();
        all.extend(vars.iter().copied());
        temp_env::with_vars(all, callback)
    }

    #[test]
    /// Pins that absent env overrides keep server defaults.
    fn e1_server_env_overrides_absent_keeps_defaults() -> anyhow::Result<()> {
        with_env_vars(&[], || -> anyhow::Result<()> {
            let mut cfg = ServerConfig::default();
            let report = cfg
                .apply_env_overrides()
                .context("env overrides must apply")?;
            assert_eq!(report, []);
            assert_eq!(cfg.listen_addr, "127.0.0.1");
            assert_eq!(cfg.listen_port, 8443);
            assert!(cfg.tls_cert_path.is_none());
            assert!(cfg.tls_key_path.is_none());
            assert!(cfg.public_url.is_none());
            assert!(!cfg.admin_enabled);
            assert!(cfg.auth.is_none());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    /// Pins that a listen-port env override applies and is reported.
    fn e2_listen_port_env_override_applies_and_reports() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_LISTEN_PORT_ENV, Some("9000"))],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let report = cfg
                    .apply_env_overrides()
                    .context("listen port override must apply")?;
                assert_eq!(cfg.listen_port, 9000);
                assert_eq!(report.len(), 1);
                let entry = report.first().context("one override must be reported")?;
                assert_eq!(entry.env_var, SERVER_LISTEN_PORT_ENV);
                assert_eq!(entry.target_field, "server.listen_port");
                assert_eq!(entry.source, EnvOverrideSource::Env);
                assert_eq!(entry.value.as_deref(), Some("9000"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a bad listen-port env override fails closed.
    fn e3_bad_listen_port_env_fails_closed() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_LISTEN_PORT_ENV, Some("not-a-number"))],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("bad listen port must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_LISTEN_PORT_ENV));
                assert!(msg.contains("u16"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a secret env/file conflict is rejected.
    fn session_binding_secret_env_and_file_conflict_rejected() -> anyhow::Result<()> {
        with_env_vars(
            &[
                (
                    SERVER_SESSION_BINDING_SECRET_ENV,
                    Some("0123456789abcdef0123456789abcdef"),
                ),
                (SERVER_SESSION_BINDING_SECRET_FILE_ENV, Some("/tmp/secret")),
            ],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("secret env/file conflict must be rejected");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_SESSION_BINDING_SECRET_ENV));
                assert!(msg.contains(SERVER_SESSION_BINDING_SECRET_FILE_ENV));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a blank binding secret is rejected.
    fn session_binding_secret_blank_rejected() -> anyhow::Result<()> {
        for value in ["", "\n", "   "] {
            with_env_vars(
                &[(SERVER_SESSION_BINDING_SECRET_ENV, Some(value))],
                || -> anyhow::Result<()> {
                    let mut cfg = ServerConfig::default();
                    let Err(err) = cfg.apply_env_overrides() else {
                        anyhow::bail!("blank binding secret must be rejected");
                    };
                    assert!(err.to_string().contains(SERVER_SESSION_BINDING_SECRET_ENV));
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    #[test]
    /// Pins file-source reporting and newline normalization for binding secrets.
    fn session_binding_secret_file_normalizes_newline_and_reports_file_source() -> anyhow::Result<()>
    {
        let path = env::temp_dir().join(format!(
            "rmcp-server-kit-session-binding-secret-{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("clock after epoch")?
                .as_nanos()
        ));
        fs::write(&path, "0123456789abcdef0123456789abcdef\n").context("write secret file")?;
        let path_string = path.to_string_lossy().to_string();
        let report = with_env_vars(
            &[(
                SERVER_SESSION_BINDING_SECRET_FILE_ENV,
                Some(path_string.as_str()),
            )],
            || -> anyhow::Result<Vec<EnvOverride>> {
                let mut cfg = ServerConfig::default();
                let report = cfg
                    .apply_env_overrides()
                    .context("secret file override must apply")?;
                assert_eq!(
                    cfg.session_binding_secret
                        .as_ref()
                        .map(SecretString::expose_secret),
                    Some("0123456789abcdef0123456789abcdef")
                );
                Ok(report)
            },
        )?;
        fs::remove_file(path).context("remove secret file")?;

        assert_eq!(report.len(), 1);
        let entry = report.first().context("one override must be reported")?;
        assert_eq!(entry.env_var, SERVER_SESSION_BINDING_SECRET_FILE_ENV);
        assert_eq!(entry.target_field, "server.session_binding_secret");
        assert_eq!(entry.source, EnvOverrideSource::File);
        assert!(entry.value.is_none());
        Ok(())
    }

    #[test]
    /// Pins that an oauth env var without its auth parent fails closed.
    fn e4_oauth_env_without_auth_parent_fails_closed() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_OAUTH_ISSUER_ENV, Some("https://idp/"))],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("oauth env without auth parent must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_ISSUER_ENV));
                #[cfg(feature = "oauth")]
                assert!(msg.contains("[server.auth.oauth]"));
                #[cfg(not(feature = "oauth"))]
                assert!(msg.contains("oauth` feature"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that oauth env vars populate a declared parent and validate.
    fn e5_oauth_env_populates_declared_parent_and_validates() -> anyhow::Result<()> {
        with_env_vars(
            &[
                (SERVER_OAUTH_ISSUER_ENV, Some("https://idp.example/")),
                (SERVER_OAUTH_AUDIENCE_ENV, Some("mcp")),
                (
                    SERVER_OAUTH_JWKS_URI_ENV,
                    Some("https://idp.example/.well-known/jwks.json"),
                ),
            ],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig {
                    role_claim: Some("roles".into()),
                    ..OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let report = cfg
                    .apply_env_overrides()
                    .context("oauth env overrides must apply")?;
                let oauth = cfg
                    .auth
                    .as_ref()
                    .and_then(|inner| inner.oauth.as_ref())
                    .context("oauth config must be present")?;
                assert_eq!(oauth.issuer, "https://idp.example/");
                assert_eq!(oauth.audience, "mcp");
                assert_eq!(oauth.jwks_uri, "https://idp.example/.well-known/jwks.json");
                assert!(oauth.validate().is_ok(), "oauth config must validate");
                assert_eq!(report.len(), 3);
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that a missing oauth audience fails validation.
    fn e5b_oauth_env_missing_audience_fails_validate() -> anyhow::Result<()> {
        with_env_vars(
            &[
                (SERVER_OAUTH_ISSUER_ENV, Some("https://idp.example/")),
                (
                    SERVER_OAUTH_JWKS_URI_ENV,
                    Some("https://idp.example/.well-known/jwks.json"),
                ),
            ],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig {
                    role_claim: Some("roles".into()),
                    ..OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                drop(
                    cfg.apply_env_overrides()
                        .context("oauth env overrides must apply")?,
                );
                let oauth = cfg
                    .auth
                    .as_ref()
                    .and_then(|inner| inner.oauth.as_ref())
                    .context("oauth config must be present")?;
                let Err(err) = oauth.validate() else {
                    anyhow::bail!("missing oauth audience must fail validation");
                };
                assert!(err.to_string().contains("oauth.audience must not be empty"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that a proxy env var applies to a declared proxy.
    fn e5c_oauth_proxy_env_applies_to_declared_proxy() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("true"))],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig {
                    proxy: Some(
                        OAuthProxyConfig::builder(
                            "https://idp.example/authorize",
                            "https://idp.example/token",
                            "mcp",
                        )
                        .build(),
                    ),
                    ..OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let report = cfg
                    .apply_env_overrides()
                    .context("oauth proxy env overrides must apply")?;
                let proxy = cfg
                    .auth
                    .as_ref()
                    .and_then(|inner| inner.oauth.as_ref())
                    .and_then(|oauth| oauth.proxy.as_ref())
                    .context("oauth proxy must be present")?;
                assert!(proxy.strip_resource_param);
                assert_eq!(report.len(), 1);
                let entry = report.first().context("one override must be reported")?;
                assert_eq!(entry.env_var, SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV);
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that a proxy env var without a declared proxy fails closed.
    fn e5d_oauth_proxy_env_without_declared_proxy_fails_closed() -> anyhow::Result<()> {
        // The var can only populate a field on an existing proxy: the three
        // required proxy fields have no env source, so creating one here would
        // yield a half-configured proxy.
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("true"))],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig::default());
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("proxy env without declared proxy must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV));
                assert!(msg.contains("[server.auth.oauth.proxy]"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that a non-bool proxy env var is rejected.
    fn e5e_oauth_proxy_env_rejects_non_bool() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("maybe"))],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig {
                    proxy: Some(
                        OAuthProxyConfig::builder(
                            "https://idp.example/authorize",
                            "https://idp.example/token",
                            "mcp",
                        )
                        .build(),
                    ),
                    ..OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("non-bool proxy env must be rejected");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV));
                assert!(msg.contains("bool"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that the allowed-algorithms env var parses a comma-separated list.
    fn e5f_oauth_allowed_algorithms_env_parses_comma_separated_list() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV, Some("RS256, ES384"))],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig::default());
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let report = cfg
                    .apply_env_overrides()
                    .context("allowed-algorithms env must apply")?;
                let oauth = cfg
                    .auth
                    .as_ref()
                    .and_then(|inner| inner.oauth.as_ref())
                    .context("oauth config must be present")?;
                assert_eq!(
                    oauth.allowed_algorithms.as_deref(),
                    Some(["RS256".to_owned(), "ES384".to_owned()].as_slice())
                );
                assert_eq!(report.len(), 1);
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that the allowed-algorithms env rejects a non-narrowing value.
    fn e5g_oauth_allowed_algorithms_env_rejects_non_narrowing_value() -> anyhow::Result<()> {
        // SECURITY: the env path must enforce the same narrow-only rule as
        // TOML, and the error must name the variable that caused it.
        with_env_vars(
            &[(SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV, Some("HS256"))],
            || -> anyhow::Result<()> {
                let mut auth = AuthConfig::with_keys(vec![]);
                auth.oauth = Some(OAuthConfig::default());
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("non-narrowing algorithms env must be rejected");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV));
                assert!(msg.contains("unsupported algorithm"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a bad observability bool env var fails closed.
    fn e9_bad_observability_bool_env_fails_closed() -> anyhow::Result<()> {
        with_env_vars(
            &[(OBSERVABILITY_METRICS_ENABLED_ENV, Some("maybe"))],
            || -> anyhow::Result<()> {
                let mut cfg = ObservabilityConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("bad observability bool env must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(OBSERVABILITY_METRICS_ENABLED_ENV));
                assert!(msg.contains("bool"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that observability diagnostic env overrides win over TOML.
    fn observability_diagnostic_env_overrides_win_over_toml() -> anyhow::Result<()> {
        with_env_vars(
            &[
                (OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV, Some("false")),
                (OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV, Some("false")),
                (OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV, Some("false")),
            ],
            || -> anyhow::Result<()> {
                let mut cfg: ObservabilityConfig = toml::from_str(
                    "
                        log_plaintext_oauth_tokens = true
                        log_oauth_claim_values = true
                        log_tool_call_arguments = true
                    ",
                )
                .context("diagnostic-knob TOML must parse")?;

                let report = cfg
                    .apply_env_overrides()
                    .context("diagnostic env overrides must apply")?;

                assert!(!cfg.log_plaintext_oauth_tokens);
                assert!(!cfg.log_oauth_claim_values);
                assert!(!cfg.log_tool_call_arguments);
                assert_eq!(report.len(), 3);
                assert!(report.iter().any(|entry| {
                    entry.env_var == OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV
                        && entry.target_field == "observability.log_plaintext_oauth_tokens"
                        && entry.value.as_deref() == Some("false")
                }));
                assert!(report.iter().any(|entry| {
                    entry.env_var == OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV
                        && entry.target_field == "observability.log_oauth_claim_values"
                        && entry.value.as_deref() == Some("false")
                }));
                assert!(report.iter().any(|entry| {
                    entry.env_var == OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV
                        && entry.target_field == "observability.log_tool_call_arguments"
                        && entry.value.as_deref() == Some("false")
                }));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a bad diagnostic bool env var fails closed.
    fn bad_observability_diagnostic_bool_env_fails_closed() -> anyhow::Result<()> {
        for env_var in [
            OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV,
            OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV,
            OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV,
        ] {
            with_env_vars(&[(env_var, Some("notabool"))], || -> anyhow::Result<()> {
                let mut cfg = ObservabilityConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("bad diagnostic bool env must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(env_var));
                assert!(msg.contains("bool"));
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::McpServerConfig deprecated field access is the bridge behavior this test pins"
    )]
    /// Pins that an env port override reaches the MCP bridge.
    fn e10_env_port_reaches_mcp_bridge() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_LISTEN_PORT_ENV, Some("9100"))],
            || -> anyhow::Result<()> {
                let mut server: ServerConfig = toml::from_str(r#"listen_addr = "127.0.0.2""#)
                    .context("listen_addr TOML must parse")?;
                drop(
                    server
                        .apply_env_overrides()
                        .context("port env override must apply")?,
                );
                let mcp = server
                    .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
                    .context("enriched server config must bridge")?;
                assert_eq!(mcp.bind_addr, "127.0.0.2:9100");
                assert!(mcp.validate().is_ok(), "bridged config must validate");
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that the key-eviction-policy env override applies and is reported.
    fn key_eviction_policy_env_override_applies_and_reports() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_KEY_EVICTION_POLICY_ENV, Some("reject_new"))],
            || -> anyhow::Result<()> {
                let mut cfg: ServerConfig = toml::from_str(r#"key_eviction_policy = "evict_lru""#)
                    .context("TOML policy parses")?;
                let report = cfg
                    .apply_env_overrides()
                    .context("key eviction env override must apply")?;
                assert_eq!(cfg.key_eviction_policy, KeyEvictionPolicy::RejectNew);
                assert_eq!(report.len(), 1);
                let entry = report.first().context("one override must be reported")?;
                assert_eq!(entry.env_var, SERVER_KEY_EVICTION_POLICY_ENV);
                assert_eq!(entry.target_field, "server.key_eviction_policy");
                assert_eq!(entry.value.as_deref(), Some("reject_new"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    /// Pins that a bad key-eviction-policy env value fails closed.
    fn bad_key_eviction_policy_env_fails_closed() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_KEY_EVICTION_POLICY_ENV, Some("drop_random"))],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("bad key eviction policy env must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_KEY_EVICTION_POLICY_ENV));
                assert!(msg.contains("KeyEvictionPolicy"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    /// Pins that a non-UTF-8 env value fails closed.
    fn non_unicode_env_value_fails_closed() -> anyhow::Result<()> {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

        let bad = OsString::from_vec(vec![0x66, 0x80, 0x6f]);
        temp_env::with_var(
            SERVER_LISTEN_ADDR_ENV,
            Some(bad),
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("non-UTF-8 env value must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_LISTEN_ADDR_ENV));
                assert!(msg.contains("UTF-8"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(not(feature = "oauth"))]
    #[test]
    /// Pins that an oauth env var fails closed when the feature is off.
    fn e11_oauth_env_feature_off_fails_closed() -> anyhow::Result<()> {
        with_env_vars(
            &[(SERVER_OAUTH_ISSUER_ENV, Some("https://idp/"))],
            || -> anyhow::Result<()> {
                let mut cfg = ServerConfig {
                    auth: Some(AuthConfig::with_keys(vec![])),
                    ..ServerConfig::default()
                };
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("oauth env with feature off must fail closed");
                };
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_ISSUER_ENV));
                assert!(msg.contains("oauth` feature"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/config.rs::env_override_spec_matches_expected_set keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the code-side env spec matches the expected set.
    fn env_override_spec_matches_expected_set() -> anyhow::Result<()> {
        let vars = ENV_OVERRIDE_SPECS
            .iter()
            .map(|spec| {
                (
                    spec.env_var,
                    spec.target_field,
                    spec.required_feature,
                    spec.redacted,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(vars.len(), EXPECTED_ENV_OVERRIDE_SPECS.len());
        for expected in EXPECTED_ENV_OVERRIDE_SPECS {
            assert!(vars.contains(expected), "missing env spec {expected:?}");
        }
        assert_eq!(
            ENV_OVERRIDE_SPECS
                .iter()
                .filter(|spec| spec.value_type == "Path")
                .count(),
            4
        );
        Ok(())
    }

    #[derive(Debug)]
    struct GuideEnvRow {
        env_var: String,
        target_field: String,
        value_type: String,
        notes: String,
    }

    #[derive(Debug)]
    struct GuideEnvAnnotation {
        env_var: String,
        key: String,
    }

    // `_FILE` is documented next to its sibling because both target the same
    // TOML key (`rbac.redaction_salt`); duplicating the inline annotation on
    // the key would be ambiguous rather than helpful.
    const INLINE_ENV_ANNOTATION_EXEMPTIONS: &[&str] = &[
        SERVER_SESSION_BINDING_SECRET_FILE_ENV,
        RBAC_REDACTION_SALT_FILE_ENV,
    ];

    type EnvSpecTuple = (&'static str, &'static str, Option<&'static str>, bool);

    const EXPECTED_ENV_OVERRIDE_SPECS: &[EnvSpecTuple] = &[
        (SERVER_LISTEN_ADDR_ENV, "server.listen_addr", None, false),
        (SERVER_LISTEN_PORT_ENV, "server.listen_port", None, false),
        (SERVER_PUBLIC_URL_ENV, "server.public_url", None, false),
        (
            SERVER_TLS_CERT_PATH_ENV,
            "server.tls_cert_path",
            None,
            false,
        ),
        (SERVER_TLS_KEY_PATH_ENV, "server.tls_key_path", None, false),
        (
            SERVER_ADMIN_ENABLED_ENV,
            "server.admin_enabled",
            None,
            false,
        ),
        (
            SERVER_KEY_EVICTION_POLICY_ENV,
            "server.key_eviction_policy",
            None,
            false,
        ),
        (
            SERVER_SESSION_BINDING_SECRET_ENV,
            "server.session_binding_secret",
            None,
            true,
        ),
        (
            SERVER_SESSION_BINDING_SECRET_FILE_ENV,
            "server.session_binding_secret",
            None,
            true,
        ),
        (
            SERVER_OAUTH_ISSUER_ENV,
            "server.auth.oauth.issuer",
            Some("oauth"),
            false,
        ),
        (
            SERVER_OAUTH_AUDIENCE_ENV,
            "server.auth.oauth.audience",
            Some("oauth"),
            false,
        ),
        (
            SERVER_OAUTH_JWKS_URI_ENV,
            "server.auth.oauth.jwks_uri",
            Some("oauth"),
            false,
        ),
        (
            SERVER_OAUTH_ALLOWED_ALGORITHMS_ENV,
            "server.auth.oauth.allowed_algorithms",
            Some("oauth"),
            false,
        ),
        (
            SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV,
            "server.auth.oauth.proxy.strip_resource_param",
            Some("oauth"),
            false,
        ),
        (
            OBSERVABILITY_LOG_FORMAT_ENV,
            "observability.log_format",
            None,
            false,
        ),
        (
            OBSERVABILITY_METRICS_ENABLED_ENV,
            "observability.metrics_enabled",
            None,
            false,
        ),
        (
            OBSERVABILITY_METRICS_BIND_ENV,
            "observability.metrics_bind",
            None,
            false,
        ),
        (
            OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV,
            "observability.log_plaintext_oauth_tokens",
            None,
            false,
        ),
        (
            OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV,
            "observability.log_oauth_claim_values",
            None,
            false,
        ),
        (
            OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV,
            "observability.log_tool_call_arguments",
            None,
            false,
        ),
        (
            OBSERVABILITY_LOG_UPSTREAM_ERROR_BODIES_ENV,
            "observability.log_upstream_error_bodies",
            None,
            false,
        ),
        (RBAC_REDACTION_SALT_ENV, "rbac.redaction_salt", None, true),
        (
            RBAC_REDACTION_SALT_FILE_ENV,
            "rbac.redaction_salt",
            None,
            true,
        ),
    ];

    // Guards the public operator table against drifting from the code-side
    // env spec, and guards the reverse direction by parsing `*_ENV` consts
    // from source text. Source parsing is deliberate: it catches a newly added
    // env variable constant even if no Rust code references the spec table yet.
    #[test]
    /// Pins that the GUIDE env-override table matches the code-side spec.
    fn guide_env_override_table_matches_code_spec() -> anyhow::Result<()> {
        let rows = parse_guide_env_override_table()?;
        assert_eq!(
            rows.len(),
            ENV_OVERRIDE_SPECS.len(),
            "GUIDE env override table row count {} must match ENV_OVERRIDE_SPECS row count {}",
            rows.len(),
            ENV_OVERRIDE_SPECS.len()
        );

        for (idx, (row, spec)) in rows.iter().zip(ENV_OVERRIDE_SPECS.iter()).enumerate() {
            assert_eq!(
                row.env_var, spec.env_var,
                "row {idx} env var mismatch: GUIDE has {:?}, code has {:?}",
                row.env_var, spec.env_var
            );
            assert_eq!(
                row.target_field, spec.target_field,
                "{} target mismatch: GUIDE has {:?}, code has {:?}",
                spec.env_var, row.target_field, spec.target_field
            );
            assert_eq!(
                row.value_type, spec.value_type,
                "{} type mismatch: GUIDE has {:?}, code has {:?}",
                spec.env_var, row.value_type, spec.value_type
            );

            let notes_lower = row.notes.to_ascii_lowercase();
            if let Some(feature) = spec.required_feature {
                assert!(
                    notes_lower.contains(feature),
                    "{} notes must mention required feature {feature:?}; notes were {:?}",
                    spec.env_var,
                    row.notes
                );
            } else {
                assert!(
                    !notes_lower.contains("requires") && !notes_lower.contains("feature"),
                    "{} notes must not mention a required feature; notes were {:?}",
                    spec.env_var,
                    row.notes
                );
            }

            if spec.redacted {
                assert!(
                    notes_lower.contains("secret") && notes_lower.contains("redacted"),
                    "{} notes must indicate secret/redacted handling; notes were {:?}",
                    spec.env_var,
                    row.notes
                );
            } else {
                assert!(
                    !notes_lower.contains("secret") && !notes_lower.contains("redacted"),
                    "{} notes must not indicate secret/redacted handling; notes were {:?}",
                    spec.env_var,
                    row.notes
                );
            }
        }

        let spec_vars = ENV_OVERRIDE_SPECS
            .iter()
            .map(|spec| spec.env_var)
            .collect::<HashSet<_>>();
        for env_var in parse_rmcp_env_constants_from_config_source() {
            assert!(
                spec_vars.contains(env_var.as_str()),
                "env const {env_var} is defined in src/config.rs but missing from ENV_OVERRIDE_SPECS"
            );
        }
        Ok(())
    }

    // Sibling guard for the canonical TOML example's inline `# env:` comments.
    // It is kept separate from the table test so failures name which public
    // copy drifted. Extraction is scoped to the canonical TOML example by the
    // surrounding headings: scanning the whole guide would let unrelated future
    // snippets accidentally satisfy this count/order contract.
    #[test]
    /// Pins that GUIDE TOML inline env annotations match the code-side spec.
    fn guide_toml_example_env_annotations_match_code_spec() -> anyhow::Result<()> {
        let annotations = parse_guide_toml_env_annotations()?;
        assert!(
            !annotations.is_empty(),
            "canonical TOML example contains no `# env:` annotations"
        );

        let spec_by_var = ENV_OVERRIDE_SPECS
            .iter()
            .map(|spec| (spec.env_var, spec))
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::new();

        for annotation in &annotations {
            let Some(spec) = spec_by_var.get(annotation.env_var.as_str()) else {
                anyhow::bail!(
                    "GUIDE inline env annotation {:?} is not present in ENV_OVERRIDE_SPECS",
                    annotation.env_var
                );
            };
            assert!(
                seen.insert(annotation.env_var.as_str()),
                "GUIDE inline env annotation {:?} appears more than once",
                annotation.env_var
            );
            let expected_key = spec
                .target_field
                .rsplit('.')
                .next()
                .context("target_field has at least one segment")?;
            assert_eq!(
                annotation.key, expected_key,
                "{} inline annotation is attached to TOML key {:?}, but code spec target {:?} ends in {expected_key:?}",
                annotation.env_var, annotation.key, spec.target_field
            );
        }

        let expected_count = ENV_OVERRIDE_SPECS.len() - INLINE_ENV_ANNOTATION_EXEMPTIONS.len();
        assert_eq!(
            annotations.len(),
            expected_count,
            "GUIDE inline env annotation count {} must equal ENV_OVERRIDE_SPECS count {} minus exemptions {INLINE_ENV_ANNOTATION_EXEMPTIONS:?}",
            annotations.len(),
            ENV_OVERRIDE_SPECS.len()
        );

        for spec in ENV_OVERRIDE_SPECS {
            if INLINE_ENV_ANNOTATION_EXEMPTIONS.contains(&spec.env_var) {
                assert!(
                    !seen.contains(spec.env_var),
                    "{} is deliberately exempt from inline annotation but was annotated",
                    spec.env_var
                );
            } else {
                assert!(
                    seen.contains(spec.env_var),
                    "{} is missing from GUIDE canonical TOML inline `# env:` annotations",
                    spec.env_var
                );
            }
        }
        Ok(())
    }

    fn guide_markdown() -> &'static str {
        include_str!("../docs/GUIDE.md")
    }

    fn parse_guide_env_override_table() -> anyhow::Result<Vec<GuideEnvRow>> {
        let guide = guide_markdown();
        let (_, after_begin) = guide
            .split_once("<!-- BEGIN ENV_OVERRIDE_TABLE -->")
            .context("docs/GUIDE.md is missing <!-- BEGIN ENV_OVERRIDE_TABLE --> marker")?;
        let (table, _) = after_begin
            .split_once("<!-- END ENV_OVERRIDE_TABLE -->")
            .context("docs/GUIDE.md is missing <!-- END ENV_OVERRIDE_TABLE --> marker")?;
        let rows = table
            .lines()
            .filter_map(|line| parse_guide_env_override_row(line).transpose())
            .collect::<anyhow::Result<Vec<_>>>()?;
        assert!(
            !rows.is_empty(),
            "docs/GUIDE.md ENV_OVERRIDE_TABLE markers were found but no data rows parsed"
        );
        Ok(rows)
    }

    fn parse_guide_env_override_row(line: &str) -> anyhow::Result<Option<GuideEnvRow>> {
        let trimmed = line.trim();
        if !trimmed.starts_with('|')
            || trimmed.contains("|---")
            || trimmed.contains("Environment variable")
        {
            return Ok(None);
        }
        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(
            cells.len(),
            4,
            "env override GUIDE table row must have four cells, got {} in line {line:?}",
            cells.len()
        );
        Ok(Some(GuideEnvRow {
            env_var: unwrap_markdown_code(
                cells.first().context("Environment variable cell")?,
                "Environment variable",
                line,
            )?,
            target_field: unwrap_markdown_code(
                cells.get(1).context("Target TOML path cell")?,
                "Target TOML path",
                line,
            )?,
            value_type: cells.get(2).context("value type cell")?.trim().to_owned(),
            notes: cells.get(3).context("notes cell")?.trim().to_owned(),
        }))
    }

    fn unwrap_markdown_code(cell: &str, column: &str, row: &str) -> anyhow::Result<String> {
        let inner = cell
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
            .with_context(|| format!("{column} cell must be backtick-wrapped in row {row:?}"))?;
        Ok(inner.trim().to_owned())
    }

    fn parse_guide_toml_env_annotations() -> anyhow::Result<Vec<GuideEnvAnnotation>> {
        let guide = guide_markdown();
        let (_, after_heading) = guide
            .split_once("### Complete TOML configuration reference")
            .context("docs/GUIDE.md is missing canonical TOML configuration heading")?;
        let (section, _) = after_heading
            .split_once("### Bridging TOML config to `McpServerConfig`")
            .context("docs/GUIDE.md is missing bridge heading after canonical TOML example")?;
        let (_, after_fence_start) = section
            .split_once("```toml")
            .context("canonical TOML section is missing opening ```toml fence")?;
        let (toml_block, _) = after_fence_start
            .split_once("```")
            .context("canonical TOML section is missing closing code fence")?;

        toml_block
            .lines()
            .filter_map(|line| parse_guide_toml_env_annotation_line(line).transpose())
            .collect::<anyhow::Result<Vec<_>>>()
    }

    fn parse_guide_toml_env_annotation_line(
        line: &str,
    ) -> anyhow::Result<Option<GuideEnvAnnotation>> {
        let Some((before_marker, after_marker)) = line.split_once("# env: ") else {
            return Ok(None);
        };
        let env_var = after_marker
            .split_whitespace()
            .next()
            .with_context(|| format!("missing env var after `# env:` in line {line:?}"))?;
        let key_source = before_marker
            .trim_end()
            .strip_prefix('#')
            .map_or_else(|| before_marker.trim_end(), str::trim);
        let key = key_source
            .split_once('=')
            .with_context(|| format!("missing TOML key before `# env:` in line {line:?}"))?
            .0
            .trim();

        Ok(Some(GuideEnvAnnotation {
            env_var: env_var.to_owned(),
            key: key.to_owned(),
        }))
    }

    fn parse_rmcp_env_constants_from_config_source() -> Vec<String> {
        include_str!("config.rs")
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("pub(crate) const ")
                    && trimmed
                        .strip_prefix("pub(crate) const ")
                        .and_then(|rest| rest.split_once(':'))
                        .is_some_and(|(name, _)| name.ends_with("_ENV"))
                    && trimmed.contains("RMCP_SERVER_KIT__")
            })
            .filter_map(|line| {
                line.split_once('"')
                    .and_then(|(_, rest)| rest.split_once('"'))
                    .map(|(value, _)| value.to_owned())
            })
            .collect()
    }
}
