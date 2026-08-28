use std::{path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::{
    bounded_limiter::KeyEvictionPolicy,
    error::RmcpServerKitError,
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
    "key_eviction_policy",
    "trusted_proxies",
    "trusted_forwarder_max_entries",
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

pub(crate) const SERVER_LISTEN_ADDR_ENV: &str = "RMCP_SERVER_KIT__SERVER__LISTEN_ADDR";
pub(crate) const SERVER_LISTEN_PORT_ENV: &str = "RMCP_SERVER_KIT__SERVER__LISTEN_PORT";
pub(crate) const SERVER_PUBLIC_URL_ENV: &str = "RMCP_SERVER_KIT__SERVER__PUBLIC_URL";
pub(crate) const SERVER_TLS_CERT_PATH_ENV: &str = "RMCP_SERVER_KIT__SERVER__TLS_CERT_PATH";
pub(crate) const SERVER_TLS_KEY_PATH_ENV: &str = "RMCP_SERVER_KIT__SERVER__TLS_KEY_PATH";
pub(crate) const SERVER_ADMIN_ENABLED_ENV: &str = "RMCP_SERVER_KIT__SERVER__ADMIN_ENABLED";
pub(crate) const SERVER_KEY_EVICTION_POLICY_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__KEY_EVICTION_POLICY";
pub(crate) const SERVER_OAUTH_ISSUER_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__ISSUER";
pub(crate) const SERVER_OAUTH_AUDIENCE_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__AUDIENCE";
pub(crate) const SERVER_OAUTH_JWKS_URI_ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__JWKS_URI";
pub(crate) const SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV: &str =
    "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__STRIP_RESOURCE_PARAM";
pub(crate) const OBSERVABILITY_LOG_FORMAT_ENV: &str = "RMCP_SERVER_KIT__OBSERVABILITY__LOG_FORMAT";
pub(crate) const OBSERVABILITY_METRICS_ENABLED_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_ENABLED";
pub(crate) const OBSERVABILITY_METRICS_BIND_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__METRICS_BIND";
pub(crate) const OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_PLAINTEXT_OAUTH_TOKENS";
pub(crate) const OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_OAUTH_CLAIM_VALUES";
pub(crate) const OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV: &str =
    "RMCP_SERVER_KIT__OBSERVABILITY__LOG_TOOL_CALL_ARGUMENTS";
pub(crate) const RBAC_REDACTION_SALT_ENV: &str = "RMCP_SERVER_KIT__RBAC__REDACTION_SALT";
pub(crate) const RBAC_REDACTION_SALT_FILE_ENV: &str = "RMCP_SERVER_KIT__RBAC__REDACTION_SALT_FILE";

/// Server listener configuration (reusable across MCP projects).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
            key_eviction_policy: KeyEvictionPolicy::default(),
            trusted_proxies: Vec::new(),
            trusted_forwarder_max_entries: default_trusted_forwarder_max_entries(),
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
        let oauth_env = OAuthEnvOverrides::read()?;
        #[cfg(feature = "oauth")]
        self.apply_oauth_env_overrides(oauth_env, &mut applied)?;
        #[cfg(not(feature = "oauth"))]
        reject_oauth_env_overrides(&oauth_env)?;
        Ok(applied)
    }

    #[cfg(feature = "oauth")]
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
        apply_string_env(
            OBSERVABILITY_METRICS_BIND_ENV,
            "observability.metrics_bind",
            &mut self.metrics_bind,
            &mut applied,
        )?;
        Ok(applied)
    }
}

pub(crate) fn read_env(var: &str) -> Result<Option<String>, RmcpServerKitError> {
    match std::env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(RmcpServerKitError::Config(format!(
            "{var} must contain valid UTF-8"
        ))),
    }
}

fn env_report(env_var: &str, target_field: &str, value: String) -> EnvOverride {
    EnvOverride {
        env_var: env_var.to_owned(),
        target_field: target_field.to_owned(),
        source: EnvOverrideSource::Env,
        value: Some(value),
    }
}

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

fn parse_env_value<T>(env_var: &str, raw: &str, expected: &str) -> Result<T, RmcpServerKitError>
where
    T: std::str::FromStr,
{
    raw.parse::<T>().map_err(|_| {
        RmcpServerKitError::Config(format!("invalid value for {env_var}: expected {expected}"))
    })
}

pub(crate) fn parse_env_bool(env_var: &str, raw: &str) -> Result<bool, RmcpServerKitError> {
    parse_env_value(env_var, raw, "bool")
}

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

struct OAuthEnvOverrides {
    issuer: Option<String>,
    audience: Option<String>,
    jwks_uri: Option<String>,
    proxy_strip_resource_param: Option<String>,
}

impl OAuthEnvOverrides {
    fn read() -> Result<Self, RmcpServerKitError> {
        Ok(Self {
            issuer: read_env(SERVER_OAUTH_ISSUER_ENV)?,
            audience: read_env(SERVER_OAUTH_AUDIENCE_ENV)?,
            jwks_uri: read_env(SERVER_OAUTH_JWKS_URI_ENV)?,
            proxy_strip_resource_param: read_env(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV)?,
        })
    }

    fn is_set(&self) -> bool {
        self.issuer.is_some()
            || self.audience.is_some()
            || self.jwks_uri.is_some()
            || self.proxy_strip_resource_param.is_some()
    }

    fn first_set_var(&self) -> &'static str {
        first_set_oauth_env(
            self.issuer.as_deref(),
            self.audience.as_deref(),
            self.jwks_uri.as_deref(),
            self.proxy_strip_resource_param.as_deref(),
        )
    }
}

const _OBSERVABILITY_CONFIG_DOC_ANCHOR: &str = "ObservabilityConfig";

#[cfg(not(feature = "oauth"))]
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

fn first_set_oauth_env(
    issuer: Option<&str>,
    audience: Option<&str>,
    jwks_uri: Option<&str>,
    proxy_strip_resource_param: Option<&str>,
) -> &'static str {
    if issuer.is_some() {
        SERVER_OAUTH_ISSUER_ENV
    } else if audience.is_some() {
        SERVER_OAUTH_AUDIENCE_ENV
    } else if jwks_uri.is_some() {
        SERVER_OAUTH_JWKS_URI_ENV
    } else if proxy_strip_resource_param.is_some() {
        SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV
    } else {
        SERVER_OAUTH_ISSUER_ENV
    }
}

fn parse_duration_field(field: &str, value: &str) -> Result<Duration, RmcpServerKitError> {
    humantime::parse_duration(value).map_err(|error| {
        RmcpServerKitError::Config(format!("invalid duration for {field}: {value:?}: {error}"))
    })
}

/// Observability settings (reusable across MCP projects).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "observability configuration is a flat TOML schema with independent boolean feature flags"
)]
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
            log_plaintext_oauth_tokens: false,
            log_oauth_claim_values: false,
            log_tool_call_arguments: false,
        }
    }
}

/// Validate the generic server config fields.
///
/// # Errors
///
/// Returns `RmcpServerKitError::Config` on invalid values.
pub fn validate_server_config(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::RmcpServerKitError;

    if server.listen_port == 0 {
        return Err(RmcpServerKitError::Config(
            "listen_port must be nonzero".into(),
        ));
    }

    // The next three checks are ordered to match `McpServerConfig::check`
    // (admin/auth dependency, then TLS pairing, then mTLS-requires-TLS) so
    // that a config which is invalid in more than one of these ways reports
    // the same first error whichever validator a consumer reaches for.
    // Checks outside this group are not ordered against the builder: the two
    // types accept different inputs (`listen_port` has no builder analog),
    // so full first-error parity is neither achievable nor claimed.
    if server.admin_enabled && !server.auth.as_ref().is_some_and(|a| a.enabled) {
        return Err(RmcpServerKitError::Config(
            "admin_enabled=true requires auth to be configured and enabled".into(),
        ));
    }

    match (&server.tls_cert_path, &server.tls_key_path) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(RmcpServerKitError::Config(
                "tls_cert_path and tls_key_path must both be set or both omitted".into(),
            ));
        }
        _ => {}
    }

    // Kept duplicated from `McpServerConfig::check` deliberately, and must
    // stay in this position: a consumer calling only `validate_server_config`
    // on TOML would otherwise be told the config is valid while
    // client-certificate authentication is silently inert, because a
    // plaintext listener never performs a handshake and so never extracts an
    // identity.
    if server.auth.as_ref().is_some_and(|a| a.mtls.is_some())
        && (server.tls_cert_path.is_none() || server.tls_key_path.is_none())
    {
        return Err(RmcpServerKitError::Config(
            "auth.mtls requires TLS: set both tls_cert_path and tls_key_path \
             (mTLS client certificates cannot be verified on a plaintext listener)"
                .into(),
        ));
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
    if humantime::parse_duration(&server.tls_handshake_timeout).is_ok_and(|d| d == Duration::ZERO) {
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

    Ok(())
}

/// Validate the rate-limit burst knobs of a TOML [`ServerConfig`]: zero
/// bursts and orphan bursts fail fast (mirrors `McpServerConfig::check`;
/// the auth bursts have no orphan rule — their base rates always resolve).
fn validate_rate_limit_knobs(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::RmcpServerKitError;

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
    if let Some(auth) = server.auth.as_ref() {
        auth.check_oauth_feature()?;
    }
    if let Some(rl) = server.auth.as_ref().and_then(|a| a.rate_limit.as_ref()) {
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

fn validate_mtls_knobs(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::RmcpServerKitError;

    if let Some(mtls) = server.auth.as_ref().and_then(|a| a.mtls.as_ref()) {
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
fn validate_trusted_forwarder_config(server: &ServerConfig) -> crate::error::Result<()> {
    use crate::error::RmcpServerKitError;

    for entry in &server.trusted_proxies {
        crate::transport::validate_trusted_proxy_entry(entry)
            .map_err(RmcpServerKitError::Config)?;
    }
    if server.forwarded_header.is_some() && server.trusted_proxies.is_empty() {
        return Err(RmcpServerKitError::Config(
            "server.forwarded_header requires server.trusted_proxies to be nonempty".into(),
        ));
    }
    if server.trusted_forwarder_max_entries == 0
        || server.trusted_forwarder_max_entries > crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES
    {
        return Err(RmcpServerKitError::Config(format!(
            "server.trusted_forwarder_max_entries must be in 1..={}, got {}",
            crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES,
            server.trusted_forwarder_max_entries
        )));
    }
    Ok(())
}

/// Validate observability config fields.
///
/// # Errors
///
/// Returns `RmcpServerKitError::Config` on invalid values.
pub fn validate_observability_config(obs: &ObservabilityConfig) -> crate::error::Result<()> {
    use tracing_subscriber::EnvFilter;

    use crate::error::RmcpServerKitError;

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
const fn default_trusted_forwarder_max_entries() -> usize {
    crate::forwarded::MAX_SCANNED_ENTRIES
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

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
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
        assert_eq!(cfg.key_eviction_policy, KeyEvictionPolicy::EvictLru);
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
        assert!(!cfg.log_plaintext_oauth_tokens);
        assert!(!cfg.log_oauth_claim_values);
        assert!(!cfg.log_tool_call_arguments);
    }

    // -- validate_server_config --

    #[test]
    fn valid_server_config_passes() {
        let cfg = ServerConfig::default();
        assert!(validate_server_config(&cfg).is_ok());
    }

    #[test]
    fn admin_auth_check_precedes_tls_and_mtls_like_the_builder() {
        // A config invalid in all three ordered ways must report the same
        // first error here as `McpServerConfig::check` does, otherwise the
        // TOML and builder paths disagree about what is wrong.
        let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
        auth.enabled = false;
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            admin_enabled: true,
            auth: Some(auth),
            tls_cert_path: None,
            tls_key_path: None,
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("admin_enabled=true requires auth"),
            "admin/auth must fire before TLS and mTLS checks; got {err}"
        );
    }

    fn classify_shared_check(err: RmcpServerKitError) -> SharedCheck {
        match err {
            RmcpServerKitError::Config(msg) => {
                if msg.contains("admin_enabled=true requires auth") {
                    SharedCheck::AdminAuth
                } else if msg.contains("must both be set or both omitted")
                    || msg.contains("tls_cert_path is set but tls_key_path is missing")
                    || msg.contains("tls_key_path is set but tls_cert_path is missing")
                {
                    SharedCheck::TlsPairing
                } else if msg.contains("auth.mtls requires TLS") {
                    SharedCheck::MtlsRequiresTls
                } else {
                    panic!("unclassified shared-check config error: {msg}");
                }
            }
            RmcpServerKitError::Auth(msg) => {
                panic!("expected Config error, got Auth({msg})");
            }
            RmcpServerKitError::Rbac(msg) => {
                panic!("expected Config error, got Rbac({msg})");
            }
            RmcpServerKitError::RateLimited(msg) => {
                panic!("expected Config error, got RateLimited({msg})");
            }
            RmcpServerKitError::RateLimitedFor {
                message,
                retry_after,
            } => {
                panic!("expected Config error, got RateLimitedFor({message}, {retry_after:?})");
            }
            RmcpServerKitError::Io(error) => {
                panic!("expected Config error, got Io({error})");
            }
            RmcpServerKitError::Json(error) => {
                panic!("expected Config error, got Json({error})");
            }
            RmcpServerKitError::Toml(error) => {
                panic!("expected Config error, got Toml({error})");
            }
            RmcpServerKitError::Tls(msg) => {
                panic!("expected Config error, got Tls({msg})");
            }
            RmcpServerKitError::Startup(msg) => {
                panic!("expected Config error, got Startup({msg})");
            }
            RmcpServerKitError::Internal(msg) => {
                panic!("expected Config error, got Internal({msg})");
            }
            #[cfg(feature = "metrics")]
            RmcpServerKitError::Metrics(msg) => {
                panic!("expected Config error, got Metrics({msg})");
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
    fn toml_and_builder_validators_report_the_expected_shared_check_order() {
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
            for tls in case.tls_variants {
                let config = shared_check_config(case.admin, *tls, case.mtls);

                let toml_class = classify_toml_validator_error(&config);
                assert_eq!(
                    toml_class, case.expected,
                    "{} with {:?} must fail TOML validation at {:?}",
                    case.name, tls, case.expected
                );

                let builder_class = classify_builder_validator_error(&config);
                assert_eq!(
                    builder_class, case.expected,
                    "{} with {:?} must fail builder validation at {:?}",
                    case.name, tls, case.expected
                );
            }
        }
    }

    fn classify_toml_validator_error(config: &ServerConfig) -> SharedCheck {
        let err = validate_server_config(config).expect_err("config must fail TOML validation");
        classify_shared_check(err)
    }

    fn classify_builder_validator_error(config: &ServerConfig) -> SharedCheck {
        let builder_config = config
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:1", "t", "0.0.0"))
            .expect("valid durations must bridge into McpServerConfig");
        let err = builder_config
            .validate()
            .expect_err("config must fail builder validation");
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
                    .get_or_insert_with(|| crate::auth::AuthConfig::with_keys(vec![]));
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
                    .get_or_insert_with(|| crate::auth::AuthConfig::with_keys(vec![]));
                auth.enabled = enabled;
                auth.mtls = Some(valid_mtls_config());
            }
            MtlsSetting::WithoutTlsAndInvalidCapacity => {
                let auth = config
                    .auth
                    .get_or_insert_with(|| crate::auth::AuthConfig::with_keys(vec![]));
                auth.enabled = true;
                let mut mtls_config = valid_mtls_config();
                mtls_config.crl_max_concurrent_fetches = 0;
                auth.mtls = Some(mtls_config);
            }
        }
    }

    #[test]
    fn mtls_without_tls_rejected() {
        let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            auth: Some(auth),
            tls_cert_path: None,
            tls_key_path: None,
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tls_cert_path") && msg.contains("tls_key_path"),
            "{msg}"
        );
    }

    #[test]
    fn mtls_with_tls_accepted() {
        let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let cfg = ServerConfig {
            auth: Some(auth),
            tls_cert_path: Some("cert.pem".into()),
            tls_key_path: Some("key.pem".into()),
            ..ServerConfig::default()
        };
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
    fn toml_trusted_forwarder_max_entries_bounds_are_enforced() {
        let parse = |v: usize| -> crate::error::Result<()> {
            let cfg: ServerConfig =
                toml::from_str(&format!("trusted_forwarder_max_entries = {v}")).unwrap();
            validate_server_config(&cfg)
        };
        assert!(parse(0).is_err());
        assert!(parse(crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES + 1).is_err());
        assert!(parse(1).is_ok());
        assert!(parse(crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES).is_ok());
    }

    #[test]
    fn toml_trusted_forwarder_max_entries_defaults_and_bridges() {
        let cfg: ServerConfig = toml::from_str("").unwrap();
        assert_eq!(
            cfg.trusted_forwarder_max_entries,
            crate::forwarded::MAX_SCANNED_ENTRIES
        );
        let base = crate::transport::McpServerConfig::new("127.0.0.1:8080", "t", "0");
        let src: ServerConfig =
            toml::from_str("trusted_forwarder_max_entries = 32").expect("parses");
        let bridged = src.apply_to_mcp_config(base).expect("bridges");
        assert_eq!(bridged.trusted_forwarder_max_entries, 32);
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

    fn valid_mtls_config() -> crate::auth::MtlsConfig {
        crate::auth::MtlsConfig {
            ca_cert_path: "memory://ca.pem".into(),
            required: true,
            default_role: "viewer".into(),
            crl_enabled: true,
            crl_refresh_interval: None,
            crl_fetch_timeout: Duration::from_secs(30),
            crl_stale_grace: Duration::from_secs(24 * 60 * 60),
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

    fn assert_config_nonzero_error(err: RmcpServerKitError, field: &str) {
        let RmcpServerKitError::Config(msg) = err else {
            panic!("expected Config error for {field}");
        };
        assert!(
            msg.contains(field) && msg.contains("must be nonzero"),
            "error must name {field} and say must be nonzero; got {msg:?}"
        );
    }

    fn server_config_with_mtls(mtls: crate::auth::MtlsConfig) -> ServerConfig {
        ServerConfig {
            auth: Some(crate::auth::AuthConfig {
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
    fn rejects_zero_crl_max_cache_entries() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_cache_entries = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_max_cache_entries must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_max_cache_entries");
    }

    #[test]
    fn rejects_zero_crl_max_concurrent_fetches() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_concurrent_fetches = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_max_concurrent_fetches must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_max_concurrent_fetches");
    }

    #[test]
    fn rejects_zero_crl_discovery_rate_per_min() {
        let mut mtls = valid_mtls_config();
        mtls.crl_discovery_rate_per_min = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_discovery_rate_per_min must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_discovery_rate_per_min");
    }

    #[test]
    fn rejects_zero_crl_max_host_semaphores() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_host_semaphores = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_max_host_semaphores must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_max_host_semaphores");
    }

    #[test]
    fn rejects_zero_crl_max_seen_urls() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_seen_urls = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_max_seen_urls must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_max_seen_urls");
    }

    #[test]
    fn rejects_zero_crl_max_response_bytes() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_response_bytes = 0;
        let err = validate_server_config(&server_config_with_mtls(mtls))
            .expect_err("zero crl_max_response_bytes must be rejected");
        assert_config_nonzero_error(err, "auth.mtls.crl_max_response_bytes");
    }

    #[test]
    fn rejects_zero_auth_rate_limit() {
        let auth = crate::auth::AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(0));
        let cfg = ServerConfig {
            auth: Some(auth),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg).expect_err("zero auth rate limit must be rejected");
        assert_config_nonzero_error(err, "auth.rate_limit.max_attempts_per_minute");
    }

    #[test]
    fn rejects_zero_pre_auth_max_per_minute() {
        // Regression guard: `0` is NOT "unlimited" here. The limiter builder
        // falls back to DEFAULT_PRE_AUTH_RATE, so accepting `0` would raise
        // the pre-auth quota instead of tightening it.
        let mut rl = crate::auth::RateLimitConfig::new(30);
        rl.pre_auth_max_per_minute = Some(0);
        let cfg = ServerConfig {
            auth: Some(crate::auth::AuthConfig::with_keys(vec![]).with_rate_limit(rl)),
            ..ServerConfig::default()
        };
        let err = validate_server_config(&cfg)
            .expect_err("zero pre_auth_max_per_minute must be rejected");
        assert_config_nonzero_error(err, "auth.rate_limit.pre_auth_max_per_minute");
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
        assert_eq!(actual.key_eviction_policy, expected.key_eviction_policy);
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
    fn t9_unknown_security_header_key_is_rejected() {
        let err = toml::from_str::<RootConfig>(
            r#"
                [server.security_headers]
                typo_content_security_policy = "default-src 'self'"
            "#,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("typo_content_security_policy"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn unknown_server_config_key_is_rejected() {
        let err = toml::from_str::<ServerConfig>(
            r#"
                tls_keypath = "/etc/certs/server.key"
            "#,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("tls_keypath"),
            "error must name the offending key: {msg}"
        );
    }

    #[cfg(not(feature = "oauth"))]
    #[test]
    fn oauth_table_without_oauth_feature_is_rejected_with_actionable_message() {
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
        .expect("[auth.oauth] must parse so validation can produce the real message");

        let msg = validate_server_config(&server)
            .expect_err("auth.oauth without the oauth feature must be rejected")
            .to_string();

        assert!(
            msg.contains("oauth") && msg.contains("--features oauth"),
            "error must name the missing cargo feature and how to fix it: {msg}"
        );
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
        let source = include_str!("config.rs").replace("\r\n", "\n");
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
        assert_eq!(actual.key_eviction_policy, KeyEvictionPolicy::EvictLru);
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
    fn key_eviction_policy_toml_defaults_and_overrides() {
        let default_cfg: ServerConfig = toml::from_str("").unwrap();
        assert_eq!(default_cfg.key_eviction_policy, KeyEvictionPolicy::EvictLru);

        let reject_new: ServerConfig = toml::from_str(r#"key_eviction_policy = "reject_new""#)
            .expect("reject_new policy parses");
        assert_eq!(reject_new.key_eviction_policy, KeyEvictionPolicy::RejectNew);
        let bridged = reject_new
            .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
            .unwrap();
        assert_eq!(bridged.key_eviction_policy, KeyEvictionPolicy::RejectNew);
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
        assert!(!cfg.log_plaintext_oauth_tokens);
        assert!(!cfg.log_oauth_claim_values);
        assert!(!cfg.log_tool_call_arguments);
    }

    #[test]
    fn observability_diagnostic_knobs_deserialize_true() {
        let cfg: ObservabilityConfig = toml::from_str(
            r"
                log_plaintext_oauth_tokens = true
                log_oauth_claim_values = true
                log_tool_call_arguments = true
            ",
        )
        .unwrap();

        assert!(cfg.log_plaintext_oauth_tokens);
        assert!(cfg.log_oauth_claim_values);
        assert!(cfg.log_tool_call_arguments);
    }

    fn all_env_vars() -> Vec<&'static str> {
        ENV_OVERRIDE_SPECS.iter().map(|spec| spec.env_var).collect()
    }

    fn with_env_vars<R>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> R) -> R {
        let mut all = all_env_vars()
            .into_iter()
            .map(|var| (var, None::<&str>))
            .collect::<Vec<_>>();
        all.extend(vars.iter().copied());
        temp_env::with_vars(all, f)
    }

    #[test]
    fn e1_server_env_overrides_absent_keeps_defaults() {
        with_env_vars(&[], || {
            let mut cfg = ServerConfig::default();
            let report = cfg.apply_env_overrides().unwrap();
            assert!(report.is_empty());
            assert_eq!(cfg.listen_addr, "127.0.0.1");
            assert_eq!(cfg.listen_port, 8443);
            assert!(cfg.tls_cert_path.is_none());
            assert!(cfg.tls_key_path.is_none());
            assert!(cfg.public_url.is_none());
            assert!(!cfg.admin_enabled);
            assert!(cfg.auth.is_none());
        });
    }

    #[test]
    fn e2_listen_port_env_override_applies_and_reports() {
        with_env_vars(&[(SERVER_LISTEN_PORT_ENV, Some("9000"))], || {
            let mut cfg = ServerConfig::default();
            let report = cfg.apply_env_overrides().unwrap();
            assert_eq!(cfg.listen_port, 9000);
            assert_eq!(report.len(), 1);
            assert_eq!(report[0].env_var, SERVER_LISTEN_PORT_ENV);
            assert_eq!(report[0].target_field, "server.listen_port");
            assert_eq!(report[0].source, EnvOverrideSource::Env);
            assert_eq!(report[0].value.as_deref(), Some("9000"));
        });
    }

    #[test]
    fn e3_bad_listen_port_env_fails_closed() {
        with_env_vars(&[(SERVER_LISTEN_PORT_ENV, Some("not-a-number"))], || {
            let mut cfg = ServerConfig::default();
            let err = cfg.apply_env_overrides().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(SERVER_LISTEN_PORT_ENV));
            assert!(msg.contains("u16"));
        });
    }

    #[test]
    fn e4_oauth_env_without_auth_parent_fails_closed() {
        with_env_vars(&[(SERVER_OAUTH_ISSUER_ENV, Some("https://idp/"))], || {
            let mut cfg = ServerConfig::default();
            let err = cfg.apply_env_overrides().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(SERVER_OAUTH_ISSUER_ENV));
            #[cfg(feature = "oauth")]
            assert!(msg.contains("[server.auth.oauth]"));
            #[cfg(not(feature = "oauth"))]
            assert!(msg.contains("oauth` feature"));
        });
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn e5_oauth_env_populates_declared_parent_and_validates() {
        with_env_vars(
            &[
                (SERVER_OAUTH_ISSUER_ENV, Some("https://idp.example/")),
                (SERVER_OAUTH_AUDIENCE_ENV, Some("mcp")),
                (
                    SERVER_OAUTH_JWKS_URI_ENV,
                    Some("https://idp.example/.well-known/jwks.json"),
                ),
            ],
            || {
                let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
                auth.oauth = Some(crate::oauth::OAuthConfig {
                    role_claim: Some("roles".into()),
                    ..crate::oauth::OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let report = cfg.apply_env_overrides().unwrap();
                let oauth = cfg
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.oauth.as_ref())
                    .unwrap();
                assert_eq!(oauth.issuer, "https://idp.example/");
                assert_eq!(oauth.audience, "mcp");
                assert_eq!(oauth.jwks_uri, "https://idp.example/.well-known/jwks.json");
                assert!(oauth.validate().is_ok());
                assert_eq!(report.len(), 3);
            },
        );
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn e5b_oauth_env_missing_audience_fails_validate() {
        with_env_vars(
            &[
                (SERVER_OAUTH_ISSUER_ENV, Some("https://idp.example/")),
                (
                    SERVER_OAUTH_JWKS_URI_ENV,
                    Some("https://idp.example/.well-known/jwks.json"),
                ),
            ],
            || {
                let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
                auth.oauth = Some(crate::oauth::OAuthConfig {
                    role_claim: Some("roles".into()),
                    ..crate::oauth::OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                cfg.apply_env_overrides().unwrap();
                let oauth = cfg
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.oauth.as_ref())
                    .unwrap();
                let err = oauth.validate().unwrap_err();
                assert!(err.to_string().contains("oauth.audience must not be empty"));
            },
        );
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn e5c_oauth_proxy_env_applies_to_declared_proxy() {
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("true"))],
            || {
                let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
                auth.oauth = Some(crate::oauth::OAuthConfig {
                    proxy: Some(
                        crate::oauth::OAuthProxyConfig::builder(
                            "https://idp.example/authorize",
                            "https://idp.example/token",
                            "mcp",
                        )
                        .build(),
                    ),
                    ..crate::oauth::OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let report = cfg.apply_env_overrides().unwrap();
                let proxy = cfg
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.oauth.as_ref())
                    .and_then(|oauth| oauth.proxy.as_ref())
                    .unwrap();
                assert!(proxy.strip_resource_param);
                assert_eq!(report.len(), 1);
                assert_eq!(
                    report[0].env_var,
                    SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV
                );
            },
        );
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn e5d_oauth_proxy_env_without_declared_proxy_fails_closed() {
        // The var can only populate a field on an existing proxy: the three
        // required proxy fields have no env source, so creating one here would
        // yield a half-configured proxy.
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("true"))],
            || {
                let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
                auth.oauth = Some(crate::oauth::OAuthConfig::default());
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let err = cfg.apply_env_overrides().unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV));
                assert!(msg.contains("[server.auth.oauth.proxy]"));
            },
        );
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn e5e_oauth_proxy_env_rejects_non_bool() {
        with_env_vars(
            &[(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV, Some("maybe"))],
            || {
                let mut auth = crate::auth::AuthConfig::with_keys(vec![]);
                auth.oauth = Some(crate::oauth::OAuthConfig {
                    proxy: Some(
                        crate::oauth::OAuthProxyConfig::builder(
                            "https://idp.example/authorize",
                            "https://idp.example/token",
                            "mcp",
                        )
                        .build(),
                    ),
                    ..crate::oauth::OAuthConfig::default()
                });
                let mut cfg = ServerConfig {
                    auth: Some(auth),
                    ..ServerConfig::default()
                };

                let msg = cfg.apply_env_overrides().unwrap_err().to_string();
                assert!(msg.contains(SERVER_OAUTH_PROXY_STRIP_RESOURCE_PARAM_ENV));
                assert!(msg.contains("bool"));
            },
        );
    }

    #[test]
    fn e9_bad_observability_bool_env_fails_closed() {
        with_env_vars(
            &[(OBSERVABILITY_METRICS_ENABLED_ENV, Some("maybe"))],
            || {
                let mut cfg = ObservabilityConfig::default();
                let err = cfg.apply_env_overrides().unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains(OBSERVABILITY_METRICS_ENABLED_ENV));
                assert!(msg.contains("bool"));
            },
        );
    }

    #[test]
    fn observability_diagnostic_env_overrides_win_over_toml() {
        with_env_vars(
            &[
                (OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV, Some("false")),
                (OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV, Some("false")),
                (OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV, Some("false")),
            ],
            || {
                let mut cfg: ObservabilityConfig = toml::from_str(
                    r"
                        log_plaintext_oauth_tokens = true
                        log_oauth_claim_values = true
                        log_tool_call_arguments = true
                    ",
                )
                .unwrap();

                let report = cfg.apply_env_overrides().unwrap();

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
            },
        );
    }

    #[test]
    fn bad_observability_diagnostic_bool_env_fails_closed() {
        for env_var in [
            OBSERVABILITY_LOG_PLAINTEXT_OAUTH_TOKENS_ENV,
            OBSERVABILITY_LOG_OAUTH_CLAIM_VALUES_ENV,
            OBSERVABILITY_LOG_TOOL_CALL_ARGUMENTS_ENV,
        ] {
            with_env_vars(&[(env_var, Some("notabool"))], || {
                let mut cfg = ObservabilityConfig::default();
                let err = cfg.apply_env_overrides().unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains(env_var));
                assert!(msg.contains("bool"));
            });
        }
    }

    #[test]
    fn e10_env_port_reaches_mcp_bridge() {
        with_env_vars(&[(SERVER_LISTEN_PORT_ENV, Some("9100"))], || {
            let mut server: ServerConfig = toml::from_str(r#"listen_addr = "127.0.0.2""#).unwrap();
            server.apply_env_overrides().unwrap();
            let mcp = server
                .apply_to_mcp_config(McpServerConfig::new("127.0.0.1:0", "t", "0.0.0"))
                .unwrap();
            assert_eq!(mcp.bind_addr, "127.0.0.2:9100");
            assert!(mcp.validate().is_ok());
        });
    }

    #[test]
    fn key_eviction_policy_env_override_applies_and_reports() {
        with_env_vars(
            &[(SERVER_KEY_EVICTION_POLICY_ENV, Some("reject_new"))],
            || {
                let mut cfg: ServerConfig = toml::from_str(r#"key_eviction_policy = "evict_lru""#)
                    .expect("TOML policy parses");
                let report = cfg.apply_env_overrides().unwrap();
                assert_eq!(cfg.key_eviction_policy, KeyEvictionPolicy::RejectNew);
                assert_eq!(report.len(), 1);
                assert_eq!(report[0].env_var, SERVER_KEY_EVICTION_POLICY_ENV);
                assert_eq!(report[0].target_field, "server.key_eviction_policy");
                assert_eq!(report[0].value.as_deref(), Some("reject_new"));
            },
        );
    }

    #[test]
    fn bad_key_eviction_policy_env_fails_closed() {
        with_env_vars(
            &[(SERVER_KEY_EVICTION_POLICY_ENV, Some("drop_random"))],
            || {
                let mut cfg = ServerConfig::default();
                let err = cfg.apply_env_overrides().unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains(SERVER_KEY_EVICTION_POLICY_ENV));
                assert!(msg.contains("KeyEvictionPolicy"));
            },
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_env_value_fails_closed() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let bad = OsString::from_vec(vec![0x66, 0x80, 0x6f]);
        temp_env::with_var(SERVER_LISTEN_ADDR_ENV, Some(bad), || {
            let mut cfg = ServerConfig::default();
            let err = cfg.apply_env_overrides().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(SERVER_LISTEN_ADDR_ENV));
            assert!(msg.contains("UTF-8"));
        });
    }

    #[cfg(not(feature = "oauth"))]
    #[test]
    fn e11_oauth_env_feature_off_fails_closed() {
        with_env_vars(&[(SERVER_OAUTH_ISSUER_ENV, Some("https://idp/"))], || {
            let mut cfg = ServerConfig {
                auth: Some(crate::auth::AuthConfig::with_keys(vec![])),
                ..ServerConfig::default()
            };
            let err = cfg.apply_env_overrides().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(SERVER_OAUTH_ISSUER_ENV));
            assert!(msg.contains("oauth` feature"));
        });
    }

    #[test]
    fn env_override_spec_matches_expected_set() {
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
            3
        );
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
    const INLINE_ENV_ANNOTATION_EXEMPTIONS: &[&str] = &[RBAC_REDACTION_SALT_FILE_ENV];

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
    fn guide_env_override_table_matches_code_spec() {
        let rows = parse_guide_env_override_table();
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
                    "{} notes must mention required feature {:?}; notes were {:?}",
                    spec.env_var,
                    feature,
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
    }

    // Sibling guard for the canonical TOML example's inline `# env:` comments.
    // It is kept separate from the table test so failures name which public
    // copy drifted. Extraction is scoped to the canonical TOML example by the
    // surrounding headings: scanning the whole guide would let unrelated future
    // snippets accidentally satisfy this count/order contract.
    #[test]
    fn guide_toml_example_env_annotations_match_code_spec() {
        let annotations = parse_guide_toml_env_annotations();
        assert!(
            !annotations.is_empty(),
            "canonical TOML example contains no `# env:` annotations"
        );

        let spec_by_var = ENV_OVERRIDE_SPECS
            .iter()
            .map(|spec| (spec.env_var, spec))
            .collect::<std::collections::HashMap<_, _>>();
        let mut seen = HashSet::new();

        for annotation in &annotations {
            let Some(spec) = spec_by_var.get(annotation.env_var.as_str()) else {
                panic!(
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
                .expect("target_field has at least one segment");
            assert_eq!(
                annotation.key, expected_key,
                "{} inline annotation is attached to TOML key {:?}, but code spec target {:?} ends in {:?}",
                annotation.env_var, annotation.key, spec.target_field, expected_key
            );
        }

        let expected_count = ENV_OVERRIDE_SPECS.len() - INLINE_ENV_ANNOTATION_EXEMPTIONS.len();
        assert_eq!(
            annotations.len(),
            expected_count,
            "GUIDE inline env annotation count {} must equal ENV_OVERRIDE_SPECS count {} minus exemptions {:?}",
            annotations.len(),
            ENV_OVERRIDE_SPECS.len(),
            INLINE_ENV_ANNOTATION_EXEMPTIONS
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
    }

    fn guide_markdown() -> &'static str {
        include_str!("../docs/GUIDE.md")
    }

    fn parse_guide_env_override_table() -> Vec<GuideEnvRow> {
        let guide = guide_markdown();
        let (_, after_begin) = guide
            .split_once("<!-- BEGIN ENV_OVERRIDE_TABLE -->")
            .expect("docs/GUIDE.md is missing <!-- BEGIN ENV_OVERRIDE_TABLE --> marker");
        let (table, _) = after_begin
            .split_once("<!-- END ENV_OVERRIDE_TABLE -->")
            .expect("docs/GUIDE.md is missing <!-- END ENV_OVERRIDE_TABLE --> marker");
        let rows = table
            .lines()
            .filter_map(parse_guide_env_override_row)
            .collect::<Vec<_>>();
        assert!(
            !rows.is_empty(),
            "docs/GUIDE.md ENV_OVERRIDE_TABLE markers were found but no data rows parsed"
        );
        rows
    }

    fn parse_guide_env_override_row(line: &str) -> Option<GuideEnvRow> {
        let trimmed = line.trim();
        if !trimmed.starts_with('|')
            || trimmed.contains("|---")
            || trimmed.contains("Environment variable")
        {
            return None;
        }
        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(
            cells.len(),
            4,
            "env override GUIDE table row must have four cells, got {} in line {:?}",
            cells.len(),
            line
        );
        Some(GuideEnvRow {
            env_var: unwrap_markdown_code(cells[0], "Environment variable", line),
            target_field: unwrap_markdown_code(cells[1], "Target TOML path", line),
            value_type: cells[2].trim().to_owned(),
            notes: cells[3].trim().to_owned(),
        })
    }

    fn unwrap_markdown_code(cell: &str, column: &str, row: &str) -> String {
        let inner = cell
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
            .unwrap_or_else(|| panic!("{column} cell must be backtick-wrapped in row {row:?}"));
        inner.trim().to_owned()
    }

    fn parse_guide_toml_env_annotations() -> Vec<GuideEnvAnnotation> {
        let guide = guide_markdown();
        let (_, after_heading) = guide
            .split_once("### Complete TOML configuration reference")
            .expect("docs/GUIDE.md is missing canonical TOML configuration heading");
        let (section, _) = after_heading
            .split_once("### Bridging TOML config to `McpServerConfig`")
            .expect("docs/GUIDE.md is missing bridge heading after canonical TOML example");
        let (_, after_fence_start) = section
            .split_once("```toml")
            .expect("canonical TOML section is missing opening ```toml fence");
        let (toml_block, _) = after_fence_start
            .split_once("```")
            .expect("canonical TOML section is missing closing code fence");

        toml_block
            .lines()
            .filter_map(parse_guide_toml_env_annotation_line)
            .collect()
    }

    fn parse_guide_toml_env_annotation_line(line: &str) -> Option<GuideEnvAnnotation> {
        let (before_marker, after_marker) = line.split_once("# env: ")?;
        let env_var = after_marker
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("missing env var after `# env:` in line {line:?}"));
        let key_source = before_marker
            .trim_end()
            .strip_prefix('#')
            .map_or_else(|| before_marker.trim_end(), str::trim);
        let key = key_source
            .split_once('=')
            .unwrap_or_else(|| panic!("missing TOML key before `# env:` in line {line:?}"))
            .0
            .trim();

        Some(GuideEnvAnnotation {
            env_var: env_var.to_owned(),
            key: key.to_owned(),
        })
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
