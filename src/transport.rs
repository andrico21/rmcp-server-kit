use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::IntoResponse,
};
use rmcp::{
    ServerHandler,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use rustls::RootCertStore;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{
        AuthConfig, AuthIdentity, AuthState, MtlsConfig, TlsConnInfo, auth_middleware,
        build_rate_limiter, extract_mtls_identity,
    },
    bounded_limiter::{BoundedKeyedLimiter, BoundedLimiterDeny, KeyEvictionPolicy},
    error::RmcpServerKitError,
    mtls_revocation::{self, CrlSet, DynamicClientCertVerifier},
    rbac::{RbacPolicy, ToolRateLimiter, build_tool_rate_limiter_with_policy, rbac_middleware},
    rbac_context::RbacContextHandler,
    session_binding::{process_session_binding_secret, session_binding_middleware},
};

/// Map an internal `anyhow::Error` chain into a public [`RmcpServerKitError::Startup`]
/// at the public API boundary, flattening the chain via the alternate
/// formatter so callers see the full causal path.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(anyhow_to_startup) call sites; by-value matches the closure shape"
)]
fn anyhow_to_startup(e: anyhow::Error) -> RmcpServerKitError {
    RmcpServerKitError::Startup(format!("{e:#}"))
}

/// Map a `std::io::Error` produced during server startup into a public
/// [`RmcpServerKitError::Startup`]. We deliberately do not use the [`RmcpServerKitError::Io`]
/// `From` impl here because startup-phase IO errors (bind, listener) are
/// semantically distinct from request-time IO errors and should surface
/// the originating operation in the message.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(|e| io_to_startup(...)) call sites; by-value matches the closure shape"
)]
fn io_to_startup(op: &str, e: std::io::Error) -> RmcpServerKitError {
    RmcpServerKitError::Startup(format!("{op}: {e}"))
}

/// Async readiness check callback for the `/readyz` endpoint.
///
/// Returns a JSON object with at least a `"ready"` boolean.
/// When `ready` is false, the endpoint returns HTTP 503.
pub type ReadinessCheck =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = serde_json::Value> + Send>> + Send + Sync>;

/// Direct socket peer address of the current HTTP/TLS connection.
///
/// Inserted as a request extension into every request served by [`serve`] -
/// on both the plain and the TLS listener - and extractable in any axum
/// handler, including routes mounted via
/// [`McpServerConfig::with_extra_router`] (which bypass auth/RBAC and
/// therefore often need the peer address for their own protection, e.g.
/// per-IP rate limiting).
///
/// The same address is also mirrored into
/// [`axum::extract::ConnectInfo<SocketAddr>`] on the TLS listener, so
/// third-party middleware that expects the stock axum extension (e.g.
/// per-IP rate-limit key extractors) works unmodified under TLS.
///
/// # Semantics
///
/// - **Direct peer only.** This is the socket's remote address. Behind an
///   L4/L7 proxy or load balancer it is the proxy's address; the framework
///   performs **no** `X-Forwarded-For` / `Forwarded` interpretation.
/// - **Available on HTTP and TLS** transports alike ([`serve`]).
/// - **Absent under [`serve_stdio`]** - a stdio session has no network
///   peer (stdio bypasses the HTTP stack entirely).
/// - The separate Prometheus metrics listener (feature `metrics`) is a
///   different router and does not carry this extension.
///
/// # Privacy
///
/// `PeerAddr` exposes raw peer network metadata. The framework deliberately
/// never logs it on its own; whether to log or persist peer addresses is
/// application policy.
///
/// # Example
///
/// ```no_run
/// use axum::{Router, routing::get};
/// use rmcp_server_kit::transport::{McpServerConfig, PeerAddr};
///
/// async fn whoami(peer: PeerAddr) -> String {
///     peer.addr.ip().to_string()
/// }
///
/// let _config = McpServerConfig::new("127.0.0.1:8443", "my-server", "1.0.0")
///     .with_extra_router(Router::new().route("/whoami", get(whoami)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PeerAddr {
    /// Direct socket peer of this connection.
    pub addr: SocketAddr,
}

impl PeerAddr {
    /// Construct a new [`PeerAddr`]. Framework-internal: downstream code
    /// receives `PeerAddr` via request extensions and never constructs it.
    #[must_use]
    pub(crate) const fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

/// Extract [`PeerAddr`] from request extensions.
///
/// # Rejection
///
/// Responds `500 Internal Server Error` when the extension is missing.
/// A missing `PeerAddr` means the handler is not running under [`serve`]
/// (e.g. the router was mounted on a hand-rolled listener) - a wiring
/// bug, not a client error.
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = (axum::http::StatusCode, &'static str);

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the axum FromRequestParts trait signature; this impl only reads a request extension synchronously"
    )]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().copied().ok_or((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "peer address unavailable: not running under rmcp-server-kit serve()",
        ))
    }
}

/// Resolved client IP of the current request.
///
/// Inserted as a request extension on every request served by [`serve`],
/// right after [`PeerAddr`]. Equals the direct peer's IP unless
/// **trusted-forwarder mode** is active
/// ([`McpServerConfig::with_trusted_proxies`]) and the request arrived
/// through a trusted proxy with a verifiable forwarding chain - in that
/// case it is the rightmost-untrusted address from `X-Forwarded-For`
/// (or RFC 7239 `Forwarded`, per
/// [`McpServerConfig::with_forwarded_header`]).
///
/// All built-in per-IP rate limiters key by this value. [`PeerAddr`]
/// keeps its direct-socket-peer contract unchanged; applications that
/// need provenance can compare `ClientIp.ip` with `PeerAddr.addr.ip()`.
///
/// # Security
///
/// Resolution only ever activates when the **direct peer** is inside the
/// operator's trusted-proxy CIDRs; every ambiguous chain (malformed or
/// obfuscated entries, all-trusted chains, header bombs) falls back to
/// the direct peer, never to a header value. The framework never logs
/// this value outside rate-limit deny paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ClientIp {
    /// Resolved client IP (direct peer unless trusted-forwarder resolution applied).
    pub ip: IpAddr,
}

impl ClientIp {
    /// Construct a new [`ClientIp`]. Framework-internal: downstream code
    /// receives `ClientIp` via request extensions and never constructs it.
    #[must_use]
    pub(crate) const fn new(ip: IpAddr) -> Self {
        Self { ip }
    }
}

/// Which forwarding header trusted-forwarder mode reads.
///
/// TOML wire values are kebab-case: `"x-forwarded-for"` (default when
/// unset) and `"forwarded"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ForwardedHeaderMode {
    /// De-facto standard `X-Forwarded-For` list (nginx, HAProxy, CDNs).
    XForwardedFor,
    /// RFC 7239 `Forwarded` header (`for=` parameters).
    Forwarded,
}

/// Pre-parsed trusted-forwarder configuration captured by the
/// peer-normalization middleware.
struct ForwardResolver {
    trusted: Vec<ipnet::IpNet>,
    mode: ForwardedHeaderMode,
    max_scanned_entries: usize,
}

/// Per-header overrides for the OWASP security headers emitted by the
/// global response middleware.
///
/// Each field follows a three-state semantic:
///
/// | Value         | Behaviour                                                |
/// |---------------|----------------------------------------------------------|
/// | `None`        | Use the built-in default (current behaviour).            |
/// | `Some("")`    | **Omit** the header entirely from responses.             |
/// | `Some(value)` | Emit `header: value`. Validated at config-load time.     |
///
/// All non-empty values are validated via
/// [`axum::http::HeaderValue::from_str`] inside
/// [`McpServerConfig::validate`]; invalid values fail fast before the
/// server starts accepting traffic.
///
/// `Strict-Transport-Security` has an additional rule: the substring
/// `preload` (case-insensitive) is rejected. Operators who want to
/// commit to the HSTS preload list must do so via a future explicit
/// builder method, not by smuggling it through this knob.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SecurityHeadersConfig {
    /// Override for `X-Content-Type-Options`. Default: `nosniff`.
    pub x_content_type_options: Option<String>,
    /// Override for `X-Frame-Options`. Default: `deny`.
    pub x_frame_options: Option<String>,
    /// Override for `Cache-Control`. Default: `no-store, max-age=0`.
    pub cache_control: Option<String>,
    /// Override for `Referrer-Policy`. Default: `no-referrer`.
    pub referrer_policy: Option<String>,
    /// Override for `Cross-Origin-Opener-Policy`. Default: `same-origin`.
    pub cross_origin_opener_policy: Option<String>,
    /// Override for `Cross-Origin-Resource-Policy`. Default: `same-origin`.
    pub cross_origin_resource_policy: Option<String>,
    /// Override for `Cross-Origin-Embedder-Policy`. Default: `require-corp`.
    pub cross_origin_embedder_policy: Option<String>,
    /// Override for `Permissions-Policy`. Default:
    /// `accelerometer=(), camera=(), geolocation=(), microphone=()`.
    pub permissions_policy: Option<String>,
    /// Override for `X-Permitted-Cross-Domain-Policies`. Default: `none`.
    pub x_permitted_cross_domain_policies: Option<String>,
    /// Override for `Content-Security-Policy`. Default:
    /// `default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests`.
    pub content_security_policy: Option<String>,
    /// Override for `X-DNS-Prefetch-Control`. Default: `off`.
    pub x_dns_prefetch_control: Option<String>,
    /// Override for `Strict-Transport-Security`. Default (TLS only):
    /// `max-age=63072000; includeSubDomains`. Only emitted when TLS is
    /// active; the override is ignored on plaintext deployments. The
    /// substring `preload` (any case) is rejected by the validator.
    pub strict_transport_security: Option<String>,
}

/// Configuration for the MCP server.
#[allow(
    missing_debug_implementations,
    reason = "contains callback/trait objects that don't impl Debug"
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "server configuration naturally has many boolean feature flags"
)]
#[non_exhaustive]
pub struct McpServerConfig {
    /// Socket address the MCP HTTP server binds to.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::new() / with_bind_addr(); direct field access will become pub(crate) in a future major release"
    )]
    pub bind_addr: String,
    /// Server name advertised via MCP `initialize`.
    #[deprecated(
        since = "0.13.0",
        note = "set via McpServerConfig::new(); direct field access will become pub(crate) in a future major release"
    )]
    pub name: String,
    /// Server version advertised via MCP `initialize`.
    #[deprecated(
        since = "0.13.0",
        note = "set via McpServerConfig::new(); direct field access will become pub(crate) in a future major release"
    )]
    pub version: String,
    /// Path to the TLS certificate (PEM). Required for TLS/mTLS.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tls(); direct field access will become pub(crate) in a future major release"
    )]
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key (PEM). Required for TLS/mTLS.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tls(); direct field access will become pub(crate) in a future major release"
    )]
    pub tls_key_path: Option<PathBuf>,
    /// Optional authentication config. When `Some` and `enabled`, auth
    /// is enforced on `/mcp`. `/healthz` is always open.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_auth(); direct field access will become pub(crate) in a future major release"
    )]
    pub auth: Option<AuthConfig>,
    /// Optional RBAC policy. When present and enabled, tool calls are
    /// checked against the policy after authentication.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_rbac(); direct field access will become pub(crate) in a future major release"
    )]
    pub rbac: Option<Arc<RbacPolicy>>,
    /// Filter `tools/list` responses through RBAC visibility when RBAC
    /// is enabled and an authenticated role is present. Default: `true`.
    pub tool_list_filtering: bool,
    /// Allowed Origin values for DNS rebinding protection (MCP spec MUST).
    /// When empty and `public_url` is set, the origin is auto-derived from
    /// the public URL. When both are empty, only requests with no Origin
    /// header are accepted.
    /// Example entries: `"http://localhost:3000"`, `"https://myapp.example.com"`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_allowed_origins(); direct field access will become pub(crate) in a future major release"
    )]
    pub allowed_origins: Vec<String>,
    /// Maximum tool invocations per source IP per minute.
    /// When set, enforced on every `tools/call` request.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tool_rate_limit(); direct field access will become pub(crate) in a future major release"
    )]
    pub tool_rate_limit: Option<u32>,
    /// Burst capacity for the tool rate limiter: maximum `tools/call`
    /// requests admitted back-to-back before the sustained
    /// [`tool_rate_limit`](Self::tool_rate_limit) rate applies. `None`
    /// (default) keeps governor's default of burst = rate. Requires
    /// `tool_rate_limit` to be set; must be greater than zero.
    #[deprecated(
        since = "1.12.0",
        note = "use McpServerConfig::with_tool_rate_limit_burst(); direct field access will become pub(crate) in a future major release"
    )]
    pub tool_rate_limit_burst: Option<u32>,
    /// Maximum requests per source IP per minute for routes merged via
    /// [`with_extra_router`](Self::with_extra_router). Opt-in: `None`
    /// (the default) installs no limiter. Startup-only (not
    /// hot-reloadable via [`ReloadHandle`]).
    ///
    /// Keyed by the **direct socket peer** ([`PeerAddr`] semantics - no
    /// `X-Forwarded-For` interpretation): behind a reverse proxy all
    /// clients share the proxy's bucket, and IPv6 single-host address
    /// rotation can evade per-IP keying. Treat this as an abuse speed
    /// bump for unauthenticated application endpoints, not tenant
    /// isolation. On limit: HTTP 429 with a plain-text body, matching
    /// the tool/auth limiters.
    #[deprecated(
        since = "1.11.0",
        note = "use McpServerConfig::with_extra_route_rate_limit(); direct field access will become pub(crate) in a future major release"
    )]
    pub extra_route_rate_limit: Option<u32>,
    /// Burst capacity for the extra-route limiter: maximum requests
    /// admitted back-to-back before the sustained
    /// [`extra_route_rate_limit`](Self::extra_route_rate_limit) rate
    /// applies. `None` (default) keeps governor's default of
    /// burst = rate. Requires `extra_route_rate_limit` to be set; must
    /// be greater than zero.
    #[deprecated(
        since = "1.12.0",
        note = "use McpServerConfig::with_extra_route_rate_limit_burst(); direct field access will become pub(crate) in a future major release"
    )]
    pub extra_route_rate_limit_burst: Option<u32>,
    /// Exact-match request paths exempt from the extra-route rate
    /// limiter (e.g. `/.well-known/oauth-authorization-server`, which
    /// MCP clients fetch on every connect - behind a shared egress the
    /// limiter would otherwise 429 discovery). Matching is a **raw
    /// exact string comparison** against `req.uri().path()`: no globs,
    /// no prefixes, no normalization - trailing slashes,
    /// percent-encoding, and dot-segments must match byte-for-byte.
    /// Fail-closed: any path not listed stays rate-limited (a mismatch
    /// can only mean "still limited", never "accidentally exempt").
    /// Requires [`extra_route_rate_limit`](Self::extra_route_rate_limit);
    /// each entry must be non-empty and start with `/` (validated).
    /// Startup-only.
    #[deprecated(
        since = "1.14.0",
        note = "use McpServerConfig::with_extra_route_rate_limit_exempt_paths(); direct field access will become pub(crate) in a future major release"
    )]
    pub extra_route_rate_limit_exempt_paths: Vec<String>,

    /// Full-table policy for per-IP rate limiters. Default: evict LRU.
    pub key_eviction_policy: KeyEvictionPolicy,

    /// Maximum forwarding-chain entries scanned per request in
    /// trusted-forwarder mode. Chains longer than this are treated as a
    /// header bomb and resolution falls back to the direct peer.
    ///
    /// Defaults to `16`. Valid range is `1..=64`; the ceiling exists because
    /// an unbounded value would disable the header-bomb protection entirely.
    pub trusted_forwarder_max_entries: usize,
    /// Trusted reverse-proxy networks (CIDRs or bare IPs) for
    /// **trusted-forwarder mode**. Empty (default) = mode off: every
    /// limiter keys by the direct socket peer. Nonempty = requests whose
    /// direct peer is inside one of these networks have their client IP
    /// resolved from the forwarding header (rightmost-untrusted walk);
    /// see [`ClientIp`]. Only enable when **all** ingress paths traverse
    /// the listed proxies. Startup-only.
    #[deprecated(
        since = "1.13.0",
        note = "use McpServerConfig::with_trusted_proxies(); direct field access will become pub(crate) in a future major release"
    )]
    pub trusted_proxies: Vec<String>,
    /// Which forwarding header trusted-forwarder mode reads. `None`
    /// (default) = `X-Forwarded-For`. Setting this requires
    /// [`trusted_proxies`](Self::trusted_proxies) to be nonempty
    /// (validated). Startup-only.
    #[deprecated(
        since = "1.13.0",
        note = "use McpServerConfig::with_forwarded_header(); direct field access will become pub(crate) in a future major release"
    )]
    pub forwarded_header: Option<ForwardedHeaderMode>,
    /// Optional readiness probe for `/readyz`.
    /// When `None`, `/readyz` mirrors `/healthz` (always OK).
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_readiness_check(); direct field access will become pub(crate) in a future major release"
    )]
    pub readiness_check: Option<ReadinessCheck>,
    /// Maximum request body size in bytes. Default: 1 MiB.
    /// Protects against oversized payloads causing OOM.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_max_request_body(); direct field access will become pub(crate) in a future major release"
    )]
    pub max_request_body: usize,
    /// Request processing timeout. Default: 120s.
    /// Requests exceeding this duration receive 408 Request Timeout.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_request_timeout(); direct field access will become pub(crate) in a future major release"
    )]
    pub request_timeout: Duration,
    /// Graceful shutdown timeout. Default: 30s.
    /// After the shutdown signal, in-flight requests have this long to finish.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_shutdown_timeout(); direct field access will become pub(crate) in a future major release"
    )]
    pub shutdown_timeout: Duration,
    /// Idle timeout for MCP sessions. Sessions with no activity for this
    /// duration are closed automatically. Default: 20 minutes.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_session_idle_timeout(); direct field access will become pub(crate) in a future major release"
    )]
    pub session_idle_timeout: Duration,
    /// Bind rmcp session IDs to the authenticated identity using a stateless
    /// signed wrapper. Default: `true`.
    ///
    /// Disabling this is an escape hatch for gateways that re-authenticate
    /// each request under intentionally different labels; it reinstates the
    /// CWE-384 risk that a leaked raw session ID can be replayed by another
    /// authenticated identity.
    pub session_binding: bool,
    /// Interval for SSE keep-alive pings. Prevents proxies and load
    /// balancers from killing idle connections. Default: 15 seconds.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_sse_keep_alive(); direct field access will become pub(crate) in a future major release"
    )]
    pub sse_keep_alive: Duration,
    /// Callback invoked once the server is built, delivering a
    /// [`ReloadHandle`] for hot-reloading auth keys and RBAC policy
    /// at runtime (e.g. on SIGHUP). Only useful when auth/RBAC is enabled.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_reload_callback(); direct field access will become pub(crate) in a future major release"
    )]
    pub on_reload_ready: Option<Box<dyn FnOnce(ReloadHandle) + Send>>,
    /// Additional application-specific routes merged into the top-level
    /// router.  These routes **bypass** the MCP auth and RBAC middleware,
    /// so the application is responsible for its own auth on them.
    /// Handlers can extract [`PeerAddr`] (or
    /// [`axum::extract::ConnectInfo<SocketAddr>`] for third-party
    /// middleware compatibility) regardless of whether TLS is enabled.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_extra_router(); direct field access will become pub(crate) in a future major release"
    )]
    pub extra_router: Option<axum::Router>,
    /// Externally reachable base URL (e.g. `https://mcp.example.com`).
    /// When set, OAuth metadata endpoints advertise this URL instead of
    /// the listen address. Required when binding `0.0.0.0` behind a
    /// reverse proxy or inside a container.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_public_url(); direct field access will become pub(crate) in a future major release"
    )]
    pub public_url: Option<String>,
    /// Log inbound HTTP request headers at DEBUG level.
    /// Sensitive values remain redacted.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_request_header_logging(); direct field access will become pub(crate) in a future major release"
    )]
    pub log_request_headers: bool,
    /// Expose build metadata (`build_git_sha`, `build_timestamp`,
    /// `rust_version`) on the unauthenticated `/version` endpoint.
    /// **Default: `false`** -- only `name`, `version`, and `rmcp_server_kit_version`
    /// are served otherwise, so build fingerprints are not leaked to
    /// anonymous callers. Enable via
    /// [`McpServerConfig::expose_build_metadata`].
    pub expose_build_metadata: bool,
    /// Enable gzip/br response compression on MCP responses.
    /// Defaults to `false` to preserve existing behaviour.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_compression(); direct field access will become pub(crate) in a future major release"
    )]
    pub compression_enabled: bool,
    /// Minimum response body size (in bytes) before compression kicks in.
    /// Only used when `compression_enabled` is true. Default: 1024.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_compression(); direct field access will become pub(crate) in a future major release"
    )]
    pub compression_min_size: u16,
    /// Global cap on in-flight HTTP requests across the whole server.
    /// When `Some`, requests over the cap receive 503 Service Unavailable
    /// via `tower::load_shed`. Default: `None` (unlimited).
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_max_concurrent_requests(); direct field access will become pub(crate) in a future major release"
    )]
    pub max_concurrent_requests: Option<usize>,
    /// Enable `/admin/*` diagnostic endpoints. Requires `auth` to be
    /// configured and `enabled`. Default: `false`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_admin(); direct field access will become pub(crate) in a future major release"
    )]
    pub admin_enabled: bool,
    /// RBAC role required to access admin endpoints. Default: `"admin"`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_admin(); direct field access will become pub(crate) in a future major release"
    )]
    pub admin_role: String,
    /// Enable Prometheus metrics endpoint on a separate listener.
    /// Requires the `metrics` crate feature.
    #[cfg(feature = "metrics")]
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_metrics(); direct field access will become pub(crate) in a future major release"
    )]
    pub metrics_enabled: bool,
    /// Bind address for the Prometheus metrics listener. Default: `127.0.0.1:9090`.
    #[cfg(feature = "metrics")]
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_metrics(); direct field access will become pub(crate) in a future major release"
    )]
    pub metrics_bind: String,
    /// Per-header overrides for the OWASP security headers emitted by
    /// the global response middleware. See [`SecurityHeadersConfig`]
    /// for the three-state semantic and validation rules.
    #[deprecated(
        since = "1.5.0",
        note = "use McpServerConfig::with_security_headers(); direct field access will become pub(crate) in a future major release"
    )]
    pub security_headers: SecurityHeadersConfig,
    /// Per-handshake deadline on the TLS accept path. Idle or slow-loris
    /// connections are dropped once it elapses. Default: 10s.
    ///
    /// Startup-only: bound at listener construction, NOT hot-reloadable
    /// via [`ReloadHandle`]. Ignored unless TLS is configured.
    #[deprecated(
        since = "1.9.0",
        note = "use McpServerConfig::with_tls_handshake_timeout(); direct field access will become pub(crate) in a future major release"
    )]
    pub tls_handshake_timeout: Duration,
    /// Cap on concurrently in-flight TLS handshakes. At saturation the
    /// acceptor stops pulling new connections from the kernel backlog
    /// (backpressure) instead of accepting and dropping. Default: 256.
    ///
    /// Startup-only: bound at listener construction, NOT hot-reloadable
    /// via [`ReloadHandle`]. Ignored unless TLS is configured.
    #[deprecated(
        since = "1.9.0",
        note = "use McpServerConfig::with_max_concurrent_tls_handshakes(); direct field access will become pub(crate) in a future major release"
    )]
    pub max_concurrent_tls_handshakes: usize,
}

/// Marker that wraps a value proven to satisfy its validation
/// contract.
///
/// The only way to obtain `Validated<McpServerConfig>` is by calling
/// [`McpServerConfig::validate`], which is the contract enforced at
/// the type level by [`serve`] and [`serve_with_listener`]. The
/// inner field is private, so downstream code cannot bypass
/// validation by hand-constructing the wrapper.
///
/// Use [`Validated::as_inner`] for read-only borrowing. To mutate,
/// recover the raw value with [`Validated::into_inner`] and
/// re-validate.
///
/// # Example
///
/// ```no_run
/// use rmcp_server_kit::transport::{McpServerConfig, Validated, serve};
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerCapabilities, ServerInfo};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///     }
/// }
///
/// # async fn example() -> rmcp_server_kit::Result<()> {
/// let config: Validated<McpServerConfig> =
///     McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0").validate()?;
/// serve(config, || H).await
/// # }
/// ```
///
/// Forgetting `.validate()?` is a compile error:
///
/// ```compile_fail
/// use rmcp_server_kit::transport::{McpServerConfig, serve};
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerCapabilities, ServerInfo};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///     }
/// }
///
/// # async fn example() -> rmcp_server_kit::Result<()> {
/// let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0");
/// // Missing `.validate()?` -> mismatched types: expected
/// // `Validated<McpServerConfig>`, found `McpServerConfig`.
/// serve(config, || H).await
/// # }
/// ```
#[allow(
    missing_debug_implementations,
    reason = "wraps T which may not implement Debug; manual impl below avoids leaking inner contents into logs"
)]
pub struct Validated<T>(T);

impl<T> std::fmt::Debug for Validated<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validated").finish_non_exhaustive()
    }
}

impl<T> Validated<T> {
    /// Borrow the inner value.
    #[must_use]
    pub fn as_inner(&self) -> &T {
        &self.0
    }

    /// Recover the raw value, discarding the validation proof.
    ///
    /// Re-validate before re-using the value with [`serve`] or
    /// [`serve_with_listener`].
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

#[allow(
    deprecated,
    reason = "internal builders/validators legitimately read/write the deprecated `pub` fields they were designed to manage"
)]
impl McpServerConfig {
    /// Create a new server configuration with the given bind address,
    /// server name, and version. All other fields use safe defaults.
    ///
    /// Use the chainable `with_*` / `enable_*` builder methods to
    /// customize. Call [`McpServerConfig::validate`] to obtain a
    /// [`Validated<McpServerConfig>`] proof token, which is required by
    /// [`serve`] and [`serve_with_listener`].
    #[must_use]
    pub fn new(
        bind_addr: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            name: name.into(),
            version: version.into(),
            tls_cert_path: None,
            tls_key_path: None,
            auth: None,
            rbac: None,
            tool_list_filtering: true,
            allowed_origins: Vec::new(),
            tool_rate_limit: None,
            readiness_check: None,
            max_request_body: 1024 * 1024,
            request_timeout: Duration::from_mins(2),
            shutdown_timeout: Duration::from_secs(30),
            session_idle_timeout: Duration::from_mins(20),
            session_binding: true,
            sse_keep_alive: Duration::from_secs(15),
            on_reload_ready: None,
            extra_router: None,
            public_url: None,
            log_request_headers: false,
            expose_build_metadata: false,
            compression_enabled: false,
            compression_min_size: 1024,
            max_concurrent_requests: None,
            admin_enabled: false,
            admin_role: "admin".to_owned(),
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(feature = "metrics")]
            metrics_bind: "127.0.0.1:9090".into(),
            security_headers: SecurityHeadersConfig::default(),
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            max_concurrent_tls_handshakes: DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES,
            extra_route_rate_limit: None,
            tool_rate_limit_burst: None,
            extra_route_rate_limit_burst: None,
            extra_route_rate_limit_exempt_paths: Vec::new(),
            key_eviction_policy: KeyEvictionPolicy::default(),
            trusted_forwarder_max_entries: crate::forwarded::MAX_SCANNED_ENTRIES,
            trusted_proxies: Vec::new(),
            forwarded_header: None,
        }
    }

    // ---------------------------------------------------------------
    // Builder methods (fluent, consume + return self).
    //
    // Each method is `#[must_use]` because dropping the returned
    // `McpServerConfig` discards the configuration change.
    // ---------------------------------------------------------------

    /// Attach an authentication configuration. Required for
    /// [`enable_admin`](Self::enable_admin) and any non-public deployment.
    #[must_use]
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override one or more of the OWASP security headers emitted on
    /// every response. See [`SecurityHeadersConfig`] for the three-state
    /// semantic (`None` = default, `Some("")` = omit, `Some(v)` =
    /// override). Values are validated by [`Self::validate`].
    #[must_use]
    pub fn with_security_headers(mut self, headers: SecurityHeadersConfig) -> Self {
        self.security_headers = headers;
        self
    }

    /// Override the bind address (e.g. `127.0.0.1:8080`). Useful when the
    /// final port is only known after pre-binding an ephemeral listener
    /// (tests, dynamic-port deployments).
    #[must_use]
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Attach an RBAC policy. Tool calls are checked against the policy
    /// after authentication.
    #[must_use]
    pub fn with_rbac(mut self, rbac: Arc<RbacPolicy>) -> Self {
        self.rbac = Some(rbac);
        self
    }

    /// Enable or disable RBAC-derived filtering of `tools/list` responses.
    ///
    /// Filtering is meaningful only when RBAC is enabled and the request has
    /// an authenticated non-empty role. When active, denied tools are hidden
    /// from the list and the response cache scope is forced to private.
    #[must_use]
    pub const fn with_tool_list_filtering(mut self, enabled: bool) -> Self {
        self.tool_list_filtering = enabled;
        self
    }

    /// Configure TLS by providing the certificate and private key paths
    /// (PEM). Both must be readable at startup. Without this call, the
    /// server runs plain HTTP.
    #[must_use]
    pub fn with_tls(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Set the externally reachable base URL (e.g. `https://mcp.example.com`).
    /// Required when binding `0.0.0.0` behind a reverse proxy or inside
    /// a container so OAuth metadata and auto-derived origins resolve correctly.
    #[must_use]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = Some(url.into());
        self
    }

    /// Replace the allowed Origin allow-list (DNS-rebinding protection).
    /// When empty and [`with_public_url`](Self::with_public_url) is set,
    /// the origin is auto-derived.
    #[must_use]
    pub fn with_allowed_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    /// Merge an additional axum router at the top level. Routes added
    /// here **bypass** rmcp-server-kit auth and RBAC; the application is responsible
    /// for its own protection.
    ///
    /// To support that protection (e.g. per-IP rate limiting on
    /// unauthenticated endpoints), every request served by [`serve`]
    /// carries the client peer address regardless of whether TLS is
    /// enabled: extract the framework-owned [`PeerAddr`] in your
    /// handlers, or rely on [`axum::extract::ConnectInfo<SocketAddr>`]
    /// for stock third-party middleware (e.g. per-IP rate-limit key
    /// extractors). Neither extension exists under [`serve_stdio`],
    /// which has no network peer.
    ///
    /// # Path collisions are only partially detected
    ///
    /// These routes are merged into the framework router. A route whose path
    /// **exactly overlaps** a framework route (`/mcp`, `/healthz`, `/readyz`,
    /// `/version`, and, when enabled, `/admin/status` and the OAuth
    /// `/.well-known/*` endpoints) causes `axum::Router::merge` to **panic at
    /// startup**. That panic is intentional upstream behaviour and is not
    /// converted into a [`RmcpServerKitError`]: the release profile builds
    /// with `panic = "abort"`, so catching it is not possible.
    ///
    /// A path that merely sits *under* a framework prefix without exactly
    /// overlapping an existing route -- `/admin/custom` alongside
    /// `/admin/status`, say -- does **not** panic and is **not** validated.
    /// `axum::Router` exposes no route-enumeration API, so the framework
    /// cannot inspect these paths. Avoiding such collisions is the caller's
    /// responsibility.
    ///
    /// The Prometheus `/metrics` endpoint is unaffected: it is served on its
    /// own listener, not merged here.
    #[must_use]
    pub fn with_extra_router(mut self, router: axum::Router) -> Self {
        self.extra_router = Some(router);
        self
    }

    /// Override the forwarding-chain scan cap for trusted-forwarder mode.
    ///
    /// Defaults to 16. Validated to `1..=64` by [`Self::validate`]: `0` would
    /// pin every client to the proxy address, and an unbounded value would
    /// re-open the header-bomb vector the cap exists to close.
    #[must_use]
    pub const fn with_trusted_forwarder_max_entries(mut self, max_entries: usize) -> Self {
        self.trusted_forwarder_max_entries = max_entries;
        self
    }

    /// Install an async readiness probe for `/readyz`. Without this call,
    /// `/readyz` mirrors `/healthz` (always 200 OK).
    #[must_use]
    pub fn with_readiness_check(mut self, check: ReadinessCheck) -> Self {
        self.readiness_check = Some(check);
        self
    }

    /// Override the maximum request body (bytes). Must be `> 0`.
    /// Default: 1 MiB.
    #[must_use]
    pub fn with_max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    /// Override the per-request processing timeout. Default: 2 minutes.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the graceful shutdown grace period. Default: 30 seconds.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Override the MCP session idle timeout. Default: 20 minutes.
    #[must_use]
    pub fn with_session_idle_timeout(mut self, timeout: Duration) -> Self {
        self.session_idle_timeout = timeout;
        self
    }

    /// Enable or disable stateless binding of rmcp session IDs to the
    /// authenticated identity. Enabled by default; disabling reinstates the
    /// CWE-384 risk from reusable unbound session IDs.
    #[must_use]
    pub const fn with_session_binding(mut self, enabled: bool) -> Self {
        self.session_binding = enabled;
        self
    }

    /// Override the SSE keep-alive interval. Default: 15 seconds.
    #[must_use]
    pub fn with_sse_keep_alive(mut self, interval: Duration) -> Self {
        self.sse_keep_alive = interval;
        self
    }

    /// Cap the global number of in-flight HTTP requests via
    /// `tower::load_shed`. Excess requests receive 503 Service Unavailable.
    /// Default: unlimited.
    #[must_use]
    pub fn with_max_concurrent_requests(mut self, limit: usize) -> Self {
        self.max_concurrent_requests = Some(limit);
        self
    }

    /// Override the per-handshake deadline on the TLS accept path.
    /// Idle or slow-loris connections are dropped once it elapses.
    /// Default: 10s. Must be greater than zero.
    ///
    /// Startup-only: the value is bound at listener construction and is
    /// NOT hot-reloadable via [`ReloadHandle`]. Has no effect unless TLS
    /// is configured via [`Self::with_tls`].
    #[must_use]
    pub fn with_tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    /// Override the cap on concurrently in-flight TLS handshakes. At
    /// saturation the acceptor stops pulling new connections from the
    /// kernel backlog (backpressure) instead of accepting and dropping.
    /// Default: 256. Must be greater than zero.
    ///
    /// Startup-only: the value is bound at listener construction and is
    /// NOT hot-reloadable via [`ReloadHandle`]. Has no effect unless TLS
    /// is configured via [`Self::with_tls`].
    #[must_use]
    pub fn with_max_concurrent_tls_handshakes(mut self, limit: usize) -> Self {
        self.max_concurrent_tls_handshakes = limit;
        self
    }

    /// Cap tool invocations per source IP per minute. Enforced on every
    /// `tools/call` request.
    #[must_use]
    pub fn with_tool_rate_limit(mut self, per_minute: u32) -> Self {
        self.tool_rate_limit = Some(per_minute);
        self
    }

    /// Cap requests per source IP per minute on routes merged via
    /// [`with_extra_router`](Self::with_extra_router) - the natural
    /// protection for unauthenticated application endpoints (OAuth
    /// callbacks, registration, …) that bypass auth/RBAC by design.
    ///
    /// Must be greater than zero (validated by
    /// [`validate`](Self::validate)). Startup-only. See the
    /// `extra_route_rate_limit` field docs for keying semantics and
    /// caveats (direct peer only, IPv6 rotation, proxy collapse,
    /// bounded-memory shared-fate under key spray).
    #[must_use]
    pub fn with_extra_route_rate_limit(mut self, per_minute: u32) -> Self {
        self.extra_route_rate_limit = Some(per_minute);
        self
    }

    /// Set the burst capacity for the tool rate limiter (bucket size;
    /// the sustained rate stays [`with_tool_rate_limit`](Self::with_tool_rate_limit)).
    /// Requires the tool rate limit to be set; must be greater than zero
    /// (both validated by [`validate`](Self::validate)).
    #[must_use]
    pub fn with_tool_rate_limit_burst(mut self, burst: u32) -> Self {
        self.tool_rate_limit_burst = Some(burst);
        self
    }

    /// Set the burst capacity for the extra-route rate limiter (bucket
    /// size; the sustained rate stays
    /// [`with_extra_route_rate_limit`](Self::with_extra_route_rate_limit)).
    /// Requires the extra-route rate limit to be set; must be greater
    /// than zero (both validated by [`validate`](Self::validate)).
    #[must_use]
    pub fn with_extra_route_rate_limit_burst(mut self, burst: u32) -> Self {
        self.extra_route_rate_limit_burst = Some(burst);
        self
    }

    /// Exempt specific request paths from the extra-route rate limiter.
    ///
    /// Matching is a **raw exact string comparison** against
    /// `req.uri().path()` - no globs, no prefixes, no normalization
    /// (trailing slashes, percent-encoding, and dot-segments must match
    /// byte-for-byte). The check is fail-closed: anything not listed
    /// stays rate-limited, so a mismatch can only keep a request
    /// limited, never accidentally exempt it. The exemption is checked
    /// before key extraction, so exempt requests consume no limiter
    /// budget and never appear in deny telemetry.
    ///
    /// Typical use: the RFC 8414 authorization-server metadata document
    /// (`/.well-known/oauth-authorization-server`), fetched by MCP
    /// clients on every connect.
    ///
    /// Requires the extra-route rate limit to be set
    /// ([`with_extra_route_rate_limit`](Self::with_extra_route_rate_limit));
    /// each entry must be non-empty and start with `/` (both validated
    /// by [`validate`](Self::validate)). Startup-only.
    #[must_use]
    pub fn with_extra_route_rate_limit_exempt_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extra_route_rate_limit_exempt_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Set the tracked-key full-table policy for all per-IP rate limiters.
    #[must_use]
    pub const fn with_key_eviction_policy(mut self, policy: KeyEvictionPolicy) -> Self {
        self.key_eviction_policy = policy;
        self
    }

    /// Enable **trusted-forwarder mode**: requests whose direct peer is
    /// inside one of these networks (CIDRs or bare IPs) have their
    /// client IP resolved from the forwarding header via the
    /// rightmost-untrusted walk; all per-IP rate limiters then key by
    /// the resolved [`ClientIp`]. Headers from peers outside these
    /// networks are ignored entirely.
    ///
    /// Only enable when **all** ingress paths traverse the listed
    /// proxies - otherwise direct clients keep their own buckets and
    /// proxied clients collapse into the proxy's. Entries are validated
    /// at [`validate`](Self::validate) time. Startup-only.
    #[must_use]
    pub fn with_trusted_proxies<I, S>(mut self, proxies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_proxies = proxies.into_iter().map(Into::into).collect();
        self
    }

    /// Select which forwarding header trusted-forwarder mode reads
    /// (default: `X-Forwarded-For`). Requires
    /// [`with_trusted_proxies`](Self::with_trusted_proxies) to be set
    /// (validated).
    #[must_use]
    pub fn with_forwarded_header(mut self, mode: ForwardedHeaderMode) -> Self {
        self.forwarded_header = Some(mode);
        self
    }

    /// Register a callback that receives the [`ReloadHandle`] after the
    /// server is built. Use it to wire SIGHUP-style hot reloads of API
    /// keys and RBAC policy.
    #[must_use]
    pub fn with_reload_callback<F>(mut self, callback: F) -> Self
    where
        F: FnOnce(ReloadHandle) + Send + 'static,
    {
        self.on_reload_ready = Some(Box::new(callback));
        self
    }

    /// Enable gzip/brotli response compression on MCP responses.
    /// `min_size` is the smallest body size (bytes) eligible for
    /// compression. Default min size: 1024.
    #[must_use]
    pub fn enable_compression(mut self, min_size: u16) -> Self {
        self.compression_enabled = true;
        self.compression_min_size = min_size;
        self
    }

    /// Enable `/admin/*` diagnostic endpoints. Requires
    /// [`with_auth`](Self::with_auth) to be set and enabled; otherwise
    /// [`validate`](Self::validate) returns an error. `role` is the RBAC
    /// role gate (default: `"admin"`).
    #[must_use]
    pub fn enable_admin(mut self, role: impl Into<String>) -> Self {
        self.admin_enabled = true;
        self.admin_role = role.into();
        self
    }

    /// Log inbound HTTP request headers at DEBUG level. Sensitive
    /// values remain redacted by the logging layer.
    #[must_use]
    pub fn enable_request_header_logging(mut self) -> Self {
        self.log_request_headers = true;
        self
    }

    /// Expose build metadata (`build_git_sha`, `build_timestamp`,
    /// `rust_version`) on the unauthenticated `/version` endpoint. Off by
    /// default so `/version` reveals only `name`, `version`, and
    /// `rmcp_server_kit_version`.
    #[must_use]
    pub fn expose_build_metadata(mut self) -> Self {
        self.expose_build_metadata = true;
        self
    }

    /// Enable the Prometheus metrics listener on `bind` (e.g.
    /// `127.0.0.1:9090`). Requires the `metrics` crate feature.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn with_metrics(mut self, bind: impl Into<String>) -> Self {
        self.metrics_enabled = true;
        self.metrics_bind = bind.into();
        self
    }

    /// Validate the configuration and consume `self`, returning a
    /// [`Validated<McpServerConfig>`] proof token required by [`serve`]
    /// and [`serve_with_listener`]. This is the only way to construct
    /// `Validated<McpServerConfig>`, so the type system guarantees
    /// validation has run before the server starts.
    ///
    /// Checks:
    ///
    /// 1. `admin_enabled` requires `auth` to be configured and enabled.
    /// 2. `tls_cert_path` and `tls_key_path` must both be set or both
    ///    be unset.
    /// 3. `bind_addr` must parse as a [`SocketAddr`].
    /// 4. `public_url`, when set, must start with `http://` or `https://`.
    /// 5. Each entry in `allowed_origins` must start with `http://` or
    ///    `https://`.
    /// 6. `max_request_body` must be greater than zero.
    /// 7. When the `oauth` feature is enabled and an [`OAuthConfig`] is
    ///    present, all OAuth URL fields (`jwks_uri`, `proxy.authorize_url`,
    ///    `proxy.token_url`, `proxy.introspection_url`,
    ///    `proxy.revocation_url`, `token_exchange.token_url`) must parse
    ///    and use the `https` scheme. Set
    ///    [`OAuthConfig::allow_http_oauth_urls`] to permit `http://`
    ///    targets (strongly discouraged in production - see the field-level
    ///    docs for the threat model).
    ///
    /// [`OAuthConfig`]: crate::oauth::OAuthConfig
    /// [`OAuthConfig::allow_http_oauth_urls`]: crate::oauth::OAuthConfig::allow_http_oauth_urls
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] with a human-readable message on
    /// the first validation failure.
    pub fn validate(self) -> Result<Validated<Self>, RmcpServerKitError> {
        self.check()?;
        Ok(Validated(self))
    }

    /// Validate the burst knobs: every burst must be greater than zero
    /// when set, and the two top-level bursts require their base limiter
    /// to be configured. The auth bursts
    /// (`RateLimitConfig::{burst, pre_auth_burst}`) have no orphan rule:
    /// their base rates always resolve (`max_attempts_per_minute` is
    /// mandatory; the pre-auth base derives from it when unset).
    fn check_burst_knobs(&self) -> Result<(), RmcpServerKitError> {
        if self.tool_rate_limit_burst == Some(0) {
            return Err(RmcpServerKitError::Config(
                "tool_rate_limit_burst must be greater than zero".into(),
            ));
        }
        if self.extra_route_rate_limit_burst == Some(0) {
            return Err(RmcpServerKitError::Config(
                "extra_route_rate_limit_burst must be greater than zero".into(),
            ));
        }
        if self.trusted_forwarder_max_entries == 0
            || self.trusted_forwarder_max_entries
                > crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES
        {
            return Err(RmcpServerKitError::Config(format!(
                "trusted_forwarder_max_entries must be in 1..={}, got {}",
                crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES,
                self.trusted_forwarder_max_entries
            )));
        }
        if self.tool_rate_limit_burst.is_some() && self.tool_rate_limit.is_none() {
            return Err(RmcpServerKitError::Config(
                "tool_rate_limit_burst requires tool_rate_limit to be set".into(),
            ));
        }
        if self.extra_route_rate_limit_burst.is_some() && self.extra_route_rate_limit.is_none() {
            return Err(RmcpServerKitError::Config(
                "extra_route_rate_limit_burst requires extra_route_rate_limit to be set".into(),
            ));
        }
        if !self.extra_route_rate_limit_exempt_paths.is_empty()
            && self.extra_route_rate_limit.is_none()
        {
            return Err(RmcpServerKitError::Config(
                "extra_route_rate_limit_exempt_paths requires extra_route_rate_limit to be set"
                    .into(),
            ));
        }
        for path in &self.extra_route_rate_limit_exempt_paths {
            if path.is_empty() || !path.starts_with('/') {
                return Err(RmcpServerKitError::Config(format!(
                    "extra_route_rate_limit_exempt_paths entries must be non-empty and start with '/': {path:?}"
                )));
            }
        }
        if let Some(rl) = self.auth.as_ref().and_then(|a| a.rate_limit.as_ref()) {
            if rl.burst == Some(0) {
                return Err(RmcpServerKitError::Config(
                    "auth rate_limit.burst must be greater than zero".into(),
                ));
            }
            if rl.pre_auth_burst == Some(0) {
                return Err(RmcpServerKitError::Config(
                    "auth rate_limit.pre_auth_burst must be greater than zero".into(),
                ));
            }
        }
        Ok(())
    }

    /// Validate the trusted-forwarder knobs: every `trusted_proxies`
    /// entry must parse as a CIDR (`ipnet::IpNet`) or a bare IP
    /// (normalized to a host network), and `forwarded_header` requires a
    /// nonempty proxy list (fail-fast over a silent no-op).
    fn check_trusted_forwarder(&self) -> Result<(), RmcpServerKitError> {
        for entry in &self.trusted_proxies {
            validate_trusted_proxy_entry(entry).map_err(RmcpServerKitError::Config)?;
        }
        if self.forwarded_header.is_some() && self.trusted_proxies.is_empty() {
            return Err(RmcpServerKitError::Config(
                "forwarded_header requires trusted_proxies to be nonempty".into(),
            ));
        }
        Ok(())
    }

    /// Run the validation checks without consuming `self`. Used by
    /// internal call sites (e.g. tests) that need to inspect a config
    /// without taking ownership.
    fn check(&self) -> Result<(), RmcpServerKitError> {
        // Delegated to `check_shared_config_invariants` so this validator and
        // `validate_server_config` cannot drift in ordering. Wording stays
        // local: this type names which TLS half is missing, the TOML validator
        // emits one combined message.
        //
        // 1. admin <-> auth dependency mirrors the runtime check in
        //    `build_app_router`: admin endpoints require an auth state, built
        //    only when `auth` is `Some` *and* `enabled`.
        // 2. TLS cert / key must be paired.
        // 2b. mTLS requires TLS. A plaintext listener never performs a TLS
        //     handshake, so it cannot populate `ConnectInfo<TlsConnInfo>` and
        //     the client-certificate identity is never extracted. Accepting
        //     this combination silently disables client-cert authentication
        //     for an operator who believes it is switched on.
        if let Err(violation) = crate::config::check_shared_config_invariants(
            self.admin_enabled,
            self.auth.as_ref().is_some_and(|a| a.enabled),
            self.tls_cert_path.is_some(),
            self.tls_key_path.is_some(),
            self.auth.as_ref().is_some_and(|a| a.mtls.is_some()),
        ) {
            return Err(RmcpServerKitError::Config(
                match violation {
                    crate::config::SharedConfigViolation::AdminRequiresAuth => {
                        "admin_enabled=true requires auth to be configured and enabled"
                    }
                    crate::config::SharedConfigViolation::TlsCertWithoutKey => {
                        "tls_cert_path is set but tls_key_path is missing"
                    }
                    crate::config::SharedConfigViolation::TlsKeyWithoutCert => {
                        "tls_key_path is set but tls_cert_path is missing"
                    }
                    crate::config::SharedConfigViolation::MtlsRequiresTls => {
                        "auth.mtls requires TLS: set both tls_cert_path and tls_key_path \
                         (mTLS client certificates cannot be verified on a plaintext listener)"
                    }
                }
                .into(),
            ));
        }

        // 3. bind_addr parses
        if self.bind_addr.parse::<SocketAddr>().is_err() {
            return Err(RmcpServerKitError::Config(format!(
                "bind_addr {:?} is not a valid socket address (expected e.g. 127.0.0.1:8080)",
                self.bind_addr
            )));
        }

        // 4. public_url scheme
        if let Some(ref url) = self.public_url
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            return Err(RmcpServerKitError::Config(format!(
                "public_url {url:?} must start with http:// or https://"
            )));
        }

        // 5. allowed_origins scheme
        for origin in &self.allowed_origins {
            if !(origin.starts_with("http://") || origin.starts_with("https://")) {
                return Err(RmcpServerKitError::Config(format!(
                    "allowed_origins entry {origin:?} must start with http:// or https://"
                )));
            }
        }

        // 6. max_request_body > 0
        if self.max_request_body == 0 {
            return Err(RmcpServerKitError::Config(
                "max_request_body must be greater than zero".into(),
            ));
        }

        // 6b. extra_route_rate_limit, when set, must be > 0. Unlike the
        // legacy tool_rate_limit (which clamps 0 to its default at
        // construction), new knobs fail fast on nonsensical values.
        if self.extra_route_rate_limit == Some(0) {
            return Err(RmcpServerKitError::Config(
                "extra_route_rate_limit must be greater than zero".into(),
            ));
        }

        // 6c. Burst knobs (extracted helper).
        self.check_burst_knobs()?;

        // 6d. Trusted-forwarder knobs (extracted helper).
        self.check_trusted_forwarder()?;

        // 7. OAuth URL fields enforce HTTPS (unless `allow_http_oauth_urls`)
        #[cfg(feature = "oauth")]
        if let Some(auth_cfg) = &self.auth
            && let Some(oauth_cfg) = &auth_cfg.oauth
        {
            oauth_cfg.validate()?;
        }

        // 8. Security-header overrides parse as valid HTTP header values,
        //    and HSTS does not smuggle in a `preload` directive.
        validate_security_headers(&self.security_headers)?;

        // 9. max_concurrent_requests must be > 0 when set. Zero would
        //    deadlock the global concurrency limiter and reject every
        //    request. Mirrors the TOML-side check in `src/config.rs`.
        if self.max_concurrent_requests == Some(0) {
            return Err(RmcpServerKitError::Config(
                "max_concurrent_requests must be greater than zero when set".into(),
            ));
        }

        // 10. Auth rate-limit `max_tracked_keys` must be > 0. A zero cap
        //     would force `BoundedKeyedLimiter` to evict on every insert
        //     and effectively disable rate limiting.
        if let Some(auth_cfg) = &self.auth
            && let Some(rl) = &auth_cfg.rate_limit
            && rl.max_tracked_keys == 0
        {
            return Err(RmcpServerKitError::Config(
                "auth.rate_limit.max_tracked_keys must be greater than zero".into(),
            ));
        }

        check_auth_capacity_knobs(self.auth.as_ref())?;

        // 11. tls_handshake_timeout must be > 0. A zero deadline would
        //     reap every handshake before it could complete, rejecting
        //     all TLS connections. Mirrors the TOML-side check in
        //     `src/config.rs`.
        if self.tls_handshake_timeout == Duration::ZERO {
            return Err(RmcpServerKitError::Config(
                "tls_handshake_timeout must be greater than zero".into(),
            ));
        }

        // 12. max_concurrent_tls_handshakes must be > 0. A zero-permit
        //     semaphore would never admit a handshake, deadlocking the
        //     TLS accept path. Mirrors the TOML-side check in
        //     `src/config.rs`.
        if self.max_concurrent_tls_handshakes == 0 {
            return Err(RmcpServerKitError::Config(
                "max_concurrent_tls_handshakes must be greater than zero".into(),
            ));
        }

        Ok(())
    }
}

/// Handle for hot-reloading server configuration without restart.
///
/// Obtained via [`McpServerConfig::on_reload_ready`].
/// All swap operations are lock-free and wait-free -- in-flight requests
/// finish with the old values while new requests see the update immediately.
#[allow(
    missing_debug_implementations,
    reason = "contains Arc<AuthState> with non-Debug fields"
)]
pub struct ReloadHandle {
    auth: Option<Arc<AuthState>>,
    rbac: Option<Arc<ArcSwap<RbacPolicy>>>,
    crl_set: Option<Arc<CrlSet>>,
}

impl ReloadHandle {
    /// Atomically replace the API key list used by the auth middleware.
    pub fn reload_auth_keys(&self, keys: Vec<crate::auth::ApiKeyEntry>) {
        if let Some(ref auth) = self.auth {
            auth.reload_keys(keys);
        }
    }

    /// Atomically replace the RBAC policy used by the RBAC middleware.
    pub fn reload_rbac(&self, policy: RbacPolicy) {
        if let Some(ref rbac) = self.rbac {
            rbac.store(Arc::new(policy));
            tracing::info!("RBAC policy reloaded");
        }
    }

    /// Force an immediate refresh of all cached mTLS CRLs.
    ///
    /// # Errors
    ///
    /// Returns an error if CRL refresh is unavailable or verifier rebuild fails.
    // cancel-safe: delegates to `CrlSet::force_refresh`, which stages every
    // fetch locally and publishes the cache and verifier state together under
    // `commit_lock` with no await between them. Cancellation therefore leaves
    // either the previous or the new generation, never a mixed one.
    pub async fn refresh_crls(&self) -> Result<(), RmcpServerKitError> {
        let Some(ref crl_set) = self.crl_set else {
            return Err(RmcpServerKitError::Config(
                "CRL refresh requested but mTLS CRL support is not configured".into(),
            ));
        };

        crl_set.force_refresh().await
    }
}

/// Generic MCP HTTP server.
///
/// Wraps an axum server with `/healthz` and `/mcp` endpoints.
/// When `tls_cert_path` and `tls_key_path` are both set, the server binds
/// with TLS (rustls). Optionally supports mTLS client certificate auth.
///
/// # Errors
///
/// Returns an error if the TCP listener cannot bind, TLS config is invalid,
/// or the server fails.
// NOTE: cognitive complexity reduced from 111/25 to 83/25 by
// extracting `run_server` (serve-loop tail) and `install_oauth_proxy_routes`.
// Remaining flow is a linear router builder: middleware layering, feature-
// gated auth/RBAC wiring, and PRM/metrics installation. Further extraction
// would require threading many `&mut Router` helpers and hurt readability
// of the layer order (which is security-relevant and must stay visible).
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "middleware layer order is security-critical and must remain visible at one glance; extracting `&mut Router` helpers would obscure the auth/RBAC/origin/rate-limit ordering"
)]
/// Internal bundle of values produced by [`build_app_router`] and
/// consumed by [`serve`] / [`serve_with_listener`] when driving the
/// HTTP listener.
struct AppRunParams {
    /// TLS cert/key paths when TLS is configured.
    tls_paths: Option<(PathBuf, PathBuf)>,
    /// Per-handshake deadline on the TLS accept path.
    tls_handshake_timeout: Duration,
    /// Cap on concurrently in-flight TLS handshakes.
    max_concurrent_tls_handshakes: usize,
    /// mTLS configuration when mutual-TLS auth is enabled.
    mtls_config: Option<MtlsConfig>,
    /// Graceful shutdown drain window.
    shutdown_timeout: Duration,
    /// Shared auth state used by hot-reload callbacks.
    auth_state: Option<Arc<AuthState>>,
    /// Hot-reloadable RBAC state used by reload callbacks.
    rbac_swap: Arc<ArcSwap<RbacPolicy>>,
    /// Optional callback that receives the final [`ReloadHandle`].
    on_reload_ready: Option<Box<dyn FnOnce(ReloadHandle) + Send>>,
    /// Server-internal lifecycle cancellation token. Cancelled by
    /// [`run_server`] once the shutdown trigger fires, stopping the metrics
    /// listener, the CRL refresher, and any external shutdown wiring.
    ct: CancellationToken,
    /// Cancellation token handed to the MCP service, kept SEPARATE from
    /// [`Self::ct`].
    ///
    /// Cancelling it terminates in-flight MCP sessions and SSE streams, so it
    /// must not fire at the *start* of the grace period - that truncates
    /// responses a normal SIGTERM rollout is supposed to let finish. It is
    /// cancelled only after axum has drained, or when the force-exit timer
    /// wins. The force-exit path must still cancel it, or a stuck stream turns
    /// a truncation bug into a shutdown hang.
    session_ct: CancellationToken,
    /// `"http"` or `"https"` -- used only for boot-time logging.
    scheme: &'static str,
    /// Server name -- used only for boot-time logging.
    name: String,
}

/// Build the full application axum [`axum::Router`] (MCP route +
/// middleware stack + admin + OAuth + health endpoints + security
/// headers + CORS + compression + concurrency limit + origin check)
/// and the [`AppRunParams`] needed to drive it.
///
/// This is the shared core of [`serve`] and [`serve_with_listener`].
/// It performs *no* network I/O: callers are responsible for binding
/// (or accepting a pre-bound) [`TcpListener`] and invoking
/// [`run_server`].
#[allow(
    clippy::cognitive_complexity,
    reason = "router assembly is intrinsically sequential; splitting harms readability"
)]
#[allow(
    deprecated,
    reason = "internal router assembly reads deprecated `pub` config fields by design until 1.0 makes them pub(crate)"
)]
fn build_app_router<H, F>(
    mut config: McpServerConfig,
    handler_factory: F,
) -> anyhow::Result<(axum::Router, AppRunParams)>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let ct = CancellationToken::new();
    let session_ct = CancellationToken::new();

    let allowed_hosts = derive_allowed_hosts(&config.bind_addr, config.public_url.as_deref());
    tracing::info!(allowed_hosts = %allowed_hosts.join(", "), "configured Streamable HTTP allowed hosts");

    if config.max_concurrent_requests.is_none() {
        tracing::warn!(
            "max_concurrent_requests is unset: in-flight HTTP requests are unlimited; \
             set McpServerConfig::with_max_concurrent_requests or front the server with \
             an external concurrency limit"
        );
    }

    // Build the RBAC policy swap before constructing the MCP service so the
    // universal handler wrapper and RBAC middleware share hot-reload state.
    let rbac_swap = Arc::new(ArcSwap::new(
        config
            .rbac
            .clone()
            .unwrap_or_else(|| Arc::new(RbacPolicy::disabled())),
    ));

    let rbac_for_handler = Arc::clone(&rbac_swap);
    let tool_list_filtering = config.tool_list_filtering;
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(RbacContextHandler::new(
                handler_factory(),
                Arc::clone(&rbac_for_handler),
                tool_list_filtering,
            ))
        },
        {
            let mut mgr = LocalSessionManager::default();
            mgr.session_config.keep_alive = Some(config.session_idle_timeout);
            mgr.into()
        },
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(allowed_hosts)
            .with_sse_keep_alive(Some(config.sse_keep_alive))
            .with_cancellation_token(session_ct.clone()),
    );

    // Build the MCP route, optionally wrapped with auth and RBAC middleware.
    let mut mcp_router = axum::Router::new().nest_service("/mcp", mcp_service);

    // Build auth state eagerly when auth is configured so we can wire both
    // the auth middleware *and* the optional admin router against the same
    // state. The middleware itself is installed further down in layer order.
    let auth_state: Option<Arc<AuthState>> = match config.auth {
        Some(ref auth_config) if auth_config.enabled => {
            let rate_limiter = auth_config.rate_limit.as_ref().map(build_rate_limiter);
            let pre_auth_limiter = auth_config
                .rate_limit
                .as_ref()
                .map(crate::auth::build_pre_auth_limiter);

            #[cfg(feature = "oauth")]
            let jwks_cache = auth_config
                .oauth
                .as_ref()
                .map(|c| crate::oauth::JwksCache::new(c).map(Arc::new))
                .transpose()
                .map_err(|e| std::io::Error::other(format!("JWKS HTTP client: {e}")))?;

            Some(Arc::new(AuthState {
                api_keys: ArcSwap::new(Arc::new(auth_config.api_keys.clone())),
                rate_limiter,
                pre_auth_limiter,
                #[cfg(feature = "oauth")]
                jwks_cache,
                seen_identities: crate::auth::SeenIdentitySet::new(),
                counters: crate::auth::AuthCounters::default(),
                // Absolute only when `public_url` supplies a trustworthy
                // external origin. Without it `derive_server_url` falls back
                // to the bind address, which behind a TLS-terminating proxy
                // is an internal `http://` address -- advertising that would
                // send clients somewhere they cannot reach. `None` keeps the
                // relative path, which resolves against whatever origin the
                // client was actually challenged from.
                resource_metadata_url: config.public_url.as_ref().map(|url| {
                    format!(
                        "{}/.well-known/oauth-protected-resource/mcp",
                        url.trim_end_matches('/')
                    )
                }),
            }))
        }
        _ => None,
    };

    // Optional /admin/* diagnostic routes. Merged BEFORE the
    // body-limit/timeout/RBAC/origin/auth layers so all of them apply.
    if config.admin_enabled {
        let Some(ref auth_state_ref) = auth_state else {
            return Err(anyhow::anyhow!(
                "admin_enabled=true requires auth to be configured and enabled"
            ));
        };
        let admin_state = crate::admin::AdminState {
            started_at: std::time::Instant::now(),
            name: config.name.clone(),
            version: config.version.clone(),
            auth: Some(Arc::clone(auth_state_ref)),
            rbac: Arc::clone(&rbac_swap),
        };
        let admin_cfg = crate::admin::AdminConfig {
            role: config.admin_role.clone(),
        };
        mcp_router = mcp_router.merge(crate::admin::admin_router(admin_state, &admin_cfg));
        tracing::info!(role = %config.admin_role, "/admin/* endpoints enabled");
    }

    // ----- Middleware order (CRITICAL: read carefully) ------------------
    //
    // axum/tower applies layers **bottom-up** at runtime: the LAST layer
    // added is the OUTERMOST (runs first on a request). To achieve a
    // request-time flow of:
    //
    //   body-limit -> timeout -> auth -> rbac -> handler
    //
    // we add layers in the REVERSE order:
    //
    //   1. RBAC               (innermost, runs last before handler)
    //   2. auth               (parses identity, sets extension for RBAC)
    //   3. timeout            (bounds total request time)
    //   4. body-limit         (outermost on /mcp; caps payload before
    //                          anything else reads/buffers it)
    //
    // Origin validation is installed on the OUTER router (after the
    // /mcp router is merged in), so it also protects /healthz, /readyz,
    // /version, and any OAuth proxy endpoints.
    //
    // Rationale:
    // - Body-limit must be outermost on /mcp so RBAC (which reads the
    //   JSON-RPC body) cannot be DoS'd by a 100MB payload.
    // - Auth must run before RBAC because RBAC consumes
    //   `req.extensions().get::<AuthIdentity>()` to enforce per-role
    //   policy.
    // - Origin runs before auth so we reject cross-origin requests
    //   without spending Argon2 cycles on unauthenticated callers.

    // [0] Session identity-binding layer (innermost; RBAC wraps it so invalid
    // session tool calls are still charged by the RBAC tool-rate limiter).
    if config.session_binding {
        let secret = *process_session_binding_secret();
        mcp_router = mcp_router.layer(axum::middleware::from_fn(move |req, next| {
            session_binding_middleware(secret, req, next)
        }));
    }

    // [1] RBAC + tool rate-limit layer (inside auth; wraps session binding).
    // Always installed: even when RBAC is disabled, tool rate limiting may
    // be active (MCP spec: servers MUST rate limit tool invocations).
    {
        let tool_limiter: Option<Arc<ToolRateLimiter>> = config.tool_rate_limit.map(|per_minute| {
            build_tool_rate_limiter_with_policy(
                per_minute,
                config.tool_rate_limit_burst,
                config.key_eviction_policy,
            )
        });

        if rbac_swap.load().is_enabled() {
            tracing::info!("RBAC enforcement enabled on /mcp");
        }
        if let Some(limit) = config.tool_rate_limit {
            tracing::info!(limit, "tool rate limiting enabled (calls/min per IP)");
        }

        let rbac_for_mw = Arc::clone(&rbac_swap);
        mcp_router = mcp_router.layer(axum::middleware::from_fn(move |req, next| {
            let p = rbac_for_mw.load_full();
            let tl = tool_limiter.clone();
            rbac_middleware(p, tl, req, next)
        }));
    }

    // [2] Auth layer (runs before RBAC so AuthIdentity is in extensions).
    if let Some(ref auth_config) = config.auth
        && auth_config.enabled
    {
        let Some(ref state) = auth_state else {
            return Err(anyhow::anyhow!("auth state missing despite enabled config"));
        };

        let methods: Vec<&str> = [
            auth_config.mtls.is_some().then_some("mTLS"),
            (!auth_config.api_keys.is_empty()).then_some("bearer"),
            #[cfg(feature = "oauth")]
            auth_config.oauth.is_some().then_some("oauth-jwt"),
        ]
        .into_iter()
        .flatten()
        .collect();

        tracing::info!(
            methods = %methods.join(", "),
            api_keys = auth_config.api_keys.len(),
            "auth enabled on /mcp"
        );

        let state_for_mw = Arc::clone(state);
        mcp_router = mcp_router.layer(axum::middleware::from_fn(move |req, next| {
            let s = Arc::clone(&state_for_mw);
            auth_middleware(s, req, next)
        }));
    }

    // [3] Request timeout (returns 408 on expiry). Bounds total request
    // duration including auth + handler.
    mcp_router = mcp_router.layer(tower_http::timeout::TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        config.request_timeout,
    ));

    // [4] Request body size limit (OUTERMOST on /mcp). Prevents OOM /
    // DoS from oversized payloads BEFORE any inner layer (auth, RBAC)
    // attempts to buffer or parse the body.
    mcp_router = mcp_router.layer(tower_http::limit::RequestBodyLimitLayer::new(
        config.max_request_body,
    ));

    // Compute the effective allowed-origins list for the outer
    // origin-check layer (installed on the merged router below). When
    // `allowed_origins` is empty but `public_url` is set, auto-derive
    // the origin from the public URL so MCP clients (e.g. Claude Code)
    // that send `Origin: <server-url>` are accepted without explicit
    // config.
    let mut effective_origins = config.allowed_origins.clone();
    if effective_origins.is_empty()
        && let Some(ref url) = config.public_url
    {
        // Origin = scheme + "://" + host (+ ":" + port if non-default).
        // Strip any path/query from the public URL. Offsets come from
        // `find`, so they are char-boundary-aligned; `get(..)` keeps that
        // machine-checked (a violation degrades to an empty slice).
        if let Some(scheme_end) = url.find("://") {
            let scheme_with_sep = url.get(..scheme_end + 3).unwrap_or_default();
            let after_scheme = url.get(scheme_end + 3..).unwrap_or_default();
            let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            let host = after_scheme.get(..host_end).unwrap_or_default();
            let origin = format!("{scheme_with_sep}{host}");
            tracing::info!(
                %origin,
                "auto-derived allowed origin from public_url"
            );
            effective_origins.push(origin);
        }
    }
    let allowed_origins: Arc<[String]> = Arc::from(effective_origins);
    let cors_origins = Arc::clone(&allowed_origins);
    let log_request_headers = config.log_request_headers;

    let readyz_route = if let Some(check) = config.readiness_check.take() {
        axum::routing::get(move || readyz(Arc::clone(&check)))
    } else {
        axum::routing::get(healthz)
    };

    #[allow(
        unused_mut,
        reason = "the binding is only reassigned when the `oauth` feature adds the \
                  protected-resource-metadata route below"
    )]
    let mut router = axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/readyz", readyz_route)
        .route(
            "/version",
            axum::routing::get({
                // Pre-serialize the version payload once at router-build
                // time. The handler then serves a cheap `Arc::clone` of the
                // immutable bytes per request, avoiding `serde_json::Value`
                // allocation + serialization on every `/version` hit.
                let payload_bytes: Arc<[u8]> = serialize_version_payload(
                    &config.name,
                    &config.version,
                    config.expose_build_metadata,
                );
                move || {
                    let p = Arc::clone(&payload_bytes);
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            p.to_vec(),
                        )
                    }
                }
            }),
        )
        .merge(mcp_router);

    // Merge application-specific routes (bypass MCP auth/RBAC middleware).
    // When configured, wrap them - and only them - in the per-IP rate
    // limiter BEFORE merging: axum layers wrap only the routes already
    // present on the sub-router, so the limiter can never leak onto
    // `/mcp`, health, admin, or OAuth endpoints, while top-level layers
    // (origin check, peer-address normalization, ...) still run first.
    if let Some(extra) = config.extra_router.take() {
        let extra = match config.extra_route_rate_limit {
            Some(per_minute) => {
                let max_tracked_keys =
                    NonZeroUsize::new(EXTRA_ROUTE_MAX_TRACKED_KEYS).unwrap_or(NonZeroUsize::MIN);
                let limiter = build_extra_route_rate_limiter_with_policy(
                    per_minute,
                    config.extra_route_rate_limit_burst,
                    config.key_eviction_policy,
                    max_tracked_keys,
                );
                let exempt: Arc<std::collections::HashSet<String>> = Arc::new(
                    config
                        .extra_route_rate_limit_exempt_paths
                        .iter()
                        .cloned()
                        .collect(),
                );
                tracing::info!(
                    per_minute,
                    exempt_paths = exempt.len(),
                    "extra-route per-IP rate limit enabled"
                );
                extra.layer(axum::middleware::from_fn(move |req, next| {
                    let l = Arc::clone(&limiter);
                    let e = Arc::clone(&exempt);
                    extra_route_rate_limit_middleware(l, e, req, next)
                }))
            }
            None => extra,
        };
        router = router.merge(extra);
    }

    // RFC 9728: Protected Resource Metadata endpoint.
    // When OAuth is configured, serve full metadata with authorization_servers.
    // Otherwise, serve a minimal document with just the resource URL and no
    // authorization_servers -- this tells MCP clients (e.g. Claude Code SDK)
    // that the server exists but does NOT require OAuth authentication,
    // preventing them from gating the connection behind a broken auth flow.
    let server_url = derive_server_url(&config);
    let resource_url = format!("{server_url}/mcp");

    #[cfg(feature = "oauth")]
    let prm_metadata = if let Some(ref auth_config) = config.auth
        && let Some(ref oauth_config) = auth_config.oauth
    {
        crate::oauth::protected_resource_metadata(&resource_url, &server_url, oauth_config)
    } else {
        serde_json::json!({ "resource": resource_url })
    };
    #[cfg(not(feature = "oauth"))]
    let prm_metadata = serde_json::json!({ "resource": resource_url });

    // RFC 9728 3.1: for a resource whose identifier carries a path, the
    // well-known segment is inserted between host and path, so the canonical
    // location for resource `{server_url}/mcp` is
    // `/.well-known/oauth-protected-resource/mcp`. The root path is retained
    // as a compatibility alias for clients that only probe there.
    let prm_root = prm_metadata.clone();
    router = router.route(
        "/.well-known/oauth-protected-resource",
        axum::routing::get(move || {
            let m = prm_root.clone();
            async move { axum::Json(m) }
        }),
    );
    router = router.route(
        "/.well-known/oauth-protected-resource/mcp",
        axum::routing::get(move || {
            let m = prm_metadata.clone();
            async move { axum::Json(m) }
        }),
    );

    // OAuth 2.1 proxy endpoints: when an OAuth proxy is configured, expose
    // /authorize, /token, /register, and authorization server metadata so
    // MCP clients can perform Authorization Code + PKCE against the upstream
    // IdP (e.g. Keycloak) transparently.
    #[cfg(feature = "oauth")]
    if let Some(ref auth_config) = config.auth
        && let Some(ref oauth_config) = auth_config.oauth
        && oauth_config.proxy.is_some()
    {
        router = install_oauth_proxy_routes(
            router,
            &server_url,
            oauth_config,
            auth_state.as_ref(),
            config.max_request_body,
            &config.admin_role,
        )?;
    }

    // OWASP security response headers are installed LAST (after the origin
    // layer, below) so they form the OUTERMOST response layer and therefore
    // also decorate origin-403, CORS-preflight, overload-503, and 404-fallback
    // responses. See the `security_headers_middleware` install site below.

    // CORS preflight layer (required for browser-based MCP clients).
    // Uses the same effective origins as the origin check middleware
    // (including auto-derived origin from public_url).
    if !cors_origins.is_empty() {
        let cors = tower_http::cors::CorsLayer::new()
            .allow_origin(
                cors_origins
                    .iter()
                    .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ]);
        router = router.layer(cors);
    }

    // Optional response compression (gzip + brotli). Skips small bodies
    // to avoid overhead. Applied after CORS so preflight responses remain
    // uncompressed.
    if config.compression_enabled {
        use tower_http::compression::Predicate as _;
        let predicate = tower_http::compression::DefaultPredicate::new().and(
            tower_http::compression::predicate::SizeAbove::new(u64::from(
                config.compression_min_size,
            )),
        );
        router = router.layer(
            tower_http::compression::CompressionLayer::new()
                .gzip(true)
                .br(true)
                .compress_when(predicate),
        );
        tracing::info!(
            min_size = config.compression_min_size,
            "response compression enabled (gzip, br)"
        );
    }

    // Optional global concurrency cap. `load_shed` converts the
    // `ConcurrencyLimit` back-pressure error into 503 instead of hanging.
    if let Some(max) = config.max_concurrent_requests {
        let overload_handler = tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_err: tower::BoxError| async {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "overloaded",
                            "error_description": "server is at capacity, retry later"
                        })),
                    )
                },
            ))
            .layer(tower::load_shed::LoadShedLayer::new())
            .layer(tower::limit::ConcurrencyLimitLayer::new(max));
        router = router.layer(overload_handler);
        tracing::info!(max, "global concurrency limit enabled");
    }

    // JSON fallback for unmatched routes. Without this, axum returns
    // an empty-body 404 that breaks MCP clients (e.g. Claude Code SDK)
    // when they probe OAuth endpoints like /authorize or /token.
    router = router.fallback(|| async {
        (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "not_found",
                "error_description": "The requested endpoint does not exist"
            })),
        )
    });

    // Prometheus metrics: recording middleware + separate listener.
    #[cfg(feature = "metrics")]
    if config.metrics_enabled {
        let metrics = Arc::new(
            crate::metrics::McpMetrics::new().map_err(|e| anyhow::anyhow!("metrics init: {e}"))?,
        );
        let m = Arc::clone(&metrics);
        router = router.layer(axum::middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let m = Arc::clone(&m);
                metrics_middleware(m, req, next)
            },
        ));
        let metrics_bind = config.metrics_bind.clone();
        let metrics_shutdown = ct.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::metrics::serve_metrics(metrics_bind, metrics, metrics_shutdown).await
            {
                tracing::error!("metrics listener failed: {e}");
            }
        });
    }

    // Peer-address normalization. Mirrors the TLS branch's peer address
    // into `ConnectInfo<SocketAddr>` and exposes the framework-owned
    // `PeerAddr` extension on both listener branches, so ALL routes on
    // the merged router (`/mcp`, `/healthz`, OAuth proxy endpoints,
    // admin endpoints, extra_router, ...) and all inner middleware see a
    // uniform peer-address contract regardless of TLS. Installed just
    // inside the origin check, which stays outermost by design.
    let forward_resolver: Option<Arc<ForwardResolver>> = if config.trusted_proxies.is_empty() {
        None
    } else {
        // Entries are guaranteed parseable by `check_trusted_forwarder`;
        // filter_map is defensive only.
        Some(Arc::new(ForwardResolver {
            trusted: config
                .trusted_proxies
                .iter()
                .filter_map(|entry| parse_proxy_net(entry))
                .collect(),
            mode: config
                .forwarded_header
                .unwrap_or(ForwardedHeaderMode::XForwardedFor),
            max_scanned_entries: config.trusted_forwarder_max_entries,
        }))
    };
    if forward_resolver.is_some() {
        tracing::info!(
            proxies = config.trusted_proxies.len(),
            "trusted-forwarder mode enabled: limiters key by resolved client IP"
        );
    }
    router = router.layer(axum::middleware::from_fn(move |req, next| {
        let r = forward_resolver.clone();
        normalize_peer_addr_middleware(r, req, next)
    }));

    // Origin validation layer (MCP spec: servers MUST validate the
    // Origin header to prevent DNS rebinding attacks). Installed as the
    // outermost REQUEST-side security layer so it protects ALL routes
    // (`/mcp`, `/healthz`, `/readyz`, `/version`, OAuth proxy endpoints,
    // admin endpoints, extra_router, etc.) and runs BEFORE auth so we
    // reject cross-origin attackers without spending Argon2 cycles. Only
    // the response-decorating security-headers layer below sits further out.
    //
    // Origin-less requests (e.g. server-to-server probes, curl, native
    // MCP clients) are permitted; only requests with an Origin header
    // that does not match `effective_origins` are rejected.
    router = router.layer(axum::middleware::from_fn(move |req, next| {
        let origins = Arc::clone(&allowed_origins);
        origin_check_middleware(origins, log_request_headers, req, next)
    }));

    // OWASP security response headers. Installed LAST, making this the
    // OUTERMOST response layer: every response -- normal handler output,
    // origin-403, CORS preflight, the overload-503 (already converted to a
    // Response by the HandleErrorLayer nested inside the load-shed stack),
    // and the 404 fallback -- flows back out through it and gains the headers.
    // This is response-only decoration: on the request path it is a
    // pass-through, so origin still runs before auth and the rate limiter
    // still sits inside auth.
    let is_tls = config.tls_cert_path.is_some();
    warn_security_header_overrides(&config.security_headers);
    let security_headers_cfg = Arc::new(config.security_headers.clone());
    router = router.layer(axum::middleware::from_fn(move |req, next| {
        let cfg = Arc::clone(&security_headers_cfg);
        security_headers_middleware(is_tls, cfg, req, next)
    }));

    let scheme = if config.tls_cert_path.is_some() {
        "https"
    } else {
        "http"
    };

    let tls_paths = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
        _ => None,
    };
    let tls_handshake_timeout = config.tls_handshake_timeout;
    let max_concurrent_tls_handshakes = config.max_concurrent_tls_handshakes;
    let mtls_config = config.auth.as_ref().and_then(|a| a.mtls.as_ref()).cloned();

    Ok((
        router,
        AppRunParams {
            tls_paths,
            tls_handshake_timeout,
            max_concurrent_tls_handshakes,
            mtls_config,
            shutdown_timeout: config.shutdown_timeout,
            auth_state,
            rbac_swap,
            on_reload_ready: config.on_reload_ready.take(),
            ct,
            session_ct,
            scheme,
            name: config.name.clone(),
        },
    ))
}

/// Cancels the held [`CancellationToken`] when dropped.
///
/// Startup spawns background tasks (the Prometheus metrics listener, the CRL
/// refresher, the external-shutdown bridge) before every fallible step has
/// completed. Without this guard a later failure -- a main-bind `AddrInUse`,
/// an unreadable TLS key -- returns `Err` while those tasks keep running and
/// keep their ports bound for the lifetime of the process.
///
/// The guard is deliberately never disarmed: once the serve function returns,
/// by success or by failure, the server is finished and its background tasks
/// must stop. On the success path the token has already been cancelled by the
/// shutdown signal, and cancelling twice is a no-op.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Forwards an externally-supplied shutdown token into the server-internal one.
///
/// Returns the task handle so the wiring can be exercised directly in tests.
fn spawn_external_shutdown_bridge(
    external: CancellationToken,
    internal: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // The second arm is load-bearing: without it this task parks forever
        // on a caller token that may never be cancelled, outliving a failed
        // startup even though the internal token was already cancelled.
        tokio::select! {
            () = external.cancelled() => internal.cancel(),
            () = internal.cancelled() => {}
        }
    })
}

/// Run the MCP HTTP server, binding to `config.bind_addr` and serving
/// until an OS shutdown signal (Ctrl-C / SIGTERM) is received.
///
/// This is the standard entry point for production deployments. For
/// deterministic shutdown control (e.g. integration tests), see
/// [`serve_with_listener`].
///
/// The configuration must be validated first via
/// [`McpServerConfig::validate`], which returns a [`Validated`] proof
/// token. This typestate guarantees, at compile time, that the server
/// never starts with an invalid configuration.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if binding to `config.bind_addr`
/// fails, or if the underlying axum server returns an error.
// NOT cancel-safe: dropping after `build_app_router` starts metrics, or after
// `run_server` spawns shutdown/CRL tasks, can detach them; use OS signal or
// `serve_with_listener`'s shutdown token for cooperative shutdown.
pub async fn serve<H, F>(
    config: Validated<McpServerConfig>,
    handler_factory: F,
) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config = config.into_inner();
    #[allow(
        deprecated,
        reason = "internal serve() reads `bind_addr` to construct the listener; field becomes pub(crate) in 1.0"
    )]
    let bind_addr = config.bind_addr.clone();
    let (router, params) = build_app_router(config, handler_factory).map_err(anyhow_to_startup)?;
    let _cancel_guard = CancelOnDrop(params.ct.clone());

    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| io_to_startup(&format!("bind {bind_addr}"), e))?;
    log_listening(&params.name, params.scheme, &bind_addr);

    run_server(
        router,
        listener,
        params.tls_paths,
        params.tls_handshake_timeout,
        params.max_concurrent_tls_handshakes,
        params.mtls_config,
        params.shutdown_timeout,
        params.auth_state,
        params.rbac_swap,
        params.on_reload_ready,
        params.ct,
        params.session_ct,
    )
    .await
    .map_err(anyhow_to_startup)
}

/// Run the MCP HTTP server on a pre-bound [`TcpListener`], with optional
/// readiness signalling and external shutdown control.
///
/// This variant is intended for **deterministic integration tests** and
/// for embedders that need to bind the listening socket themselves
/// (e.g. systemd socket activation). Compared to [`serve`]:
///
/// * The caller passes a `TcpListener` that is already bound. This
///   eliminates the bind race in tests that previously required
///   poll-the-`/healthz`-loop start-up detection.
/// * `ready_tx`, when `Some`, receives the socket's
///   [`SocketAddr`] *after* the router is built and immediately before
///   the server starts accepting connections. Tests can `await` the
///   matching `oneshot::Receiver` to know exactly when it is safe to
///   issue requests.
/// * `shutdown`, when `Some`, gives the caller a
///   [`CancellationToken`] that triggers the same graceful-shutdown
///   path as a real OS signal. This avoids cross-platform issues with
///   sending real `SIGTERM` from tests on Windows.
///
/// All three optional parameters degrade gracefully: if `ready_tx` is
/// `None`, no signal is sent; if `shutdown` is `None`, the server only
/// stops on an OS signal (just like [`serve`]).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if router construction fails, if reading
/// the listener's `local_addr()` fails, or if the underlying axum
/// server returns an error.
// NOT cancel-safe: the `shutdown` token is the cancellation boundary. Dropping
// after readiness fires or `run_server` starts can detach shutdown/metrics
// tasks while callers believe the listener lifetime ended.
pub async fn serve_with_listener<H, F>(
    listener: TcpListener,
    config: Validated<McpServerConfig>,
    handler_factory: F,
    ready_tx: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    shutdown: Option<CancellationToken>,
) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config = config.into_inner();
    let local_addr = listener
        .local_addr()
        .map_err(|e| io_to_startup("listener.local_addr", e))?;
    let (router, params) = build_app_router(config, handler_factory).map_err(anyhow_to_startup)?;
    let _cancel_guard = CancelOnDrop(params.ct.clone());

    log_listening(&params.name, params.scheme, &local_addr.to_string());

    // Forward external shutdown into the server-internal cancellation
    // token so `run_server`'s shutdown trigger picks it up alongside
    // any real OS signal.
    if let Some(external) = shutdown {
        let _bridge_task = spawn_external_shutdown_bridge(external, params.ct.clone());
    }

    // Signal readiness *after* the router is fully built and external
    // shutdown is wired, but *before* run_server takes ownership of
    // the listener. The receiver can immediately issue requests.
    if let Some(tx) = ready_tx {
        // Receiver may have been dropped (test gave up). That's fine.
        let _ = tx.send(local_addr);
    }

    run_server(
        router,
        listener,
        params.tls_paths,
        params.tls_handshake_timeout,
        params.max_concurrent_tls_handshakes,
        params.mtls_config,
        params.shutdown_timeout,
        params.auth_state,
        params.rbac_swap,
        params.on_reload_ready,
        params.ct,
        params.session_ct,
    )
    .await
    .map_err(anyhow_to_startup)
}

/// Emit the standard "listening on …" log lines used by both
/// [`serve`] and [`serve_with_listener`].
#[allow(
    clippy::cognitive_complexity,
    reason = "tracing::info! macro expansions inflate the score; logic is trivial"
)]
fn log_listening(name: &str, scheme: &str, addr: &str) {
    tracing::info!("{name} listening on {addr}");
    tracing::info!("  MCP endpoint: {scheme}://{addr}/mcp");
    tracing::info!("  Health check: {scheme}://{addr}/healthz");
    tracing::info!("  Readiness:   {scheme}://{addr}/readyz");
}

/// Drive the chosen axum server variant (TLS or plain) with a graceful
/// shutdown window. Consumes the router and listener.
///
/// # Shutdown semantics
///
/// A single shutdown trigger (the FIRST of: OS signal via
/// `shutdown_signal()`, or external cancellation of `ct`) starts BOTH:
///
/// 1. axum's `.with_graceful_shutdown(...)` future, which stops
///    accepting new connections and waits for in-flight requests to
///    drain;
/// 2. a `tokio::time::sleep(shutdown_timeout)` race that forces exit if
///    drainage exceeds `shutdown_timeout`.
///
/// Previously this function awaited `shutdown_signal()` independently
/// in BOTH branches of a `tokio::select!`. Because `shutdown_signal`
/// resolves once per future and consumes one signal, the force-exit
/// timer was tied to a SECOND signal (a second SIGTERM the operator
/// would never send). Under a single SIGTERM the graceful drain could
/// hang indefinitely. The current implementation derives both branches
/// from a single shared trigger so the timeout race is anchored to the
/// FIRST (and only) signal.
#[allow(
    clippy::too_many_arguments,
    clippy::cognitive_complexity,
    reason = "server start-up threads TLS, reload state, and graceful shutdown through one flow"
)]
// NOT cancel-safe: external cancellation is modeled by `ct`. Dropping/aborting
// can skip `session_ct.cancel()` and leave the spawned shutdown trigger or CRL
// refresher running with cloned cancellation tokens.
async fn run_server(
    router: axum::Router,
    listener: TcpListener,
    tls_paths: Option<(PathBuf, PathBuf)>,
    tls_handshake_timeout: Duration,
    max_concurrent_tls_handshakes: usize,
    mtls_config: Option<MtlsConfig>,
    shutdown_timeout: Duration,
    auth_state: Option<Arc<AuthState>>,
    rbac_swap: Arc<ArcSwap<RbacPolicy>>,
    mut on_reload_ready: Option<Box<dyn FnOnce(ReloadHandle) + Send>>,
    ct: CancellationToken,
    session_ct: CancellationToken,
) -> anyhow::Result<()> {
    // `shutdown_trigger` fires when the FIRST source resolves: either
    // an OS signal (Ctrl-C / SIGTERM) or external cancellation of `ct`
    // (which the test harness uses for deterministic shutdown).
    let shutdown_trigger = CancellationToken::new();
    {
        let trigger = shutdown_trigger.clone();
        let parent = ct.clone();
        tokio::spawn(async move {
            // cancel-safe: both arms (signal future, CancellationToken::cancelled)
            // are cancel-safe; the losing arm holds no state.
            tokio::select! {
                () = shutdown_signal() => {}
                () = parent.cancelled() => {}
            }
            trigger.cancel();
        });
    }

    let graceful = {
        let trigger = shutdown_trigger.clone();
        let ct = ct.clone();
        async move {
            trigger.cancelled().await;
            tracing::info!("shutting down (grace period: {shutdown_timeout:?})");
            ct.cancel();
        }
    };

    let force_exit_timer = {
        let trigger = shutdown_trigger.clone();
        async move {
            trigger.cancelled().await;
            tokio::time::sleep(shutdown_timeout).await;
        }
    };

    if let Some((cert_path, key_path)) = tls_paths {
        let crl_set = if let Some(mtls) = mtls_config.as_ref()
            && mtls.crl_enabled
        {
            let (ca_certs, roots) = load_client_auth_roots(&mtls.ca_cert_path)?;
            let (crl_set, discover_rx) =
                mtls_revocation::bootstrap_fetch(roots, &ca_certs, mtls.clone())
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            tokio::spawn(mtls_revocation::run_crl_refresher(
                Arc::clone(&crl_set),
                discover_rx,
                ct.clone(),
            ));
            Some(crl_set)
        } else {
            None
        };

        if let Some(cb) = on_reload_ready.take() {
            cb(ReloadHandle {
                auth: auth_state.clone(),
                rbac: Some(Arc::clone(&rbac_swap)),
                crl_set: crl_set.clone(),
            });
        }

        let tls_listener = TlsListener::new(
            listener,
            &cert_path,
            &key_path,
            mtls_config.as_ref(),
            crl_set,
            tls_handshake_timeout,
            max_concurrent_tls_handshakes,
        )?;
        let make_svc = router.into_make_service_with_connect_info::<TlsConnInfo>();
        // cancel-safe: dropping the serve future on force-exit is intentional
        // forced-shutdown semantics; force_exit_timer is a Sleep chain.
        tokio::select! {
            result = axum::serve(tls_listener, make_svc)
                .with_graceful_shutdown(graceful) => { session_ct.cancel(); result?; }
            () = force_exit_timer => {
                tracing::warn!("shutdown timeout exceeded, forcing exit");
                session_ct.cancel();
            }
        }
    } else {
        if let Some(cb) = on_reload_ready.take() {
            cb(ReloadHandle {
                auth: auth_state,
                rbac: Some(rbac_swap),
                crl_set: None,
            });
        }

        let make_svc = router.into_make_service_with_connect_info::<SocketAddr>();
        // cancel-safe: dropping the serve future on force-exit is intentional
        // forced-shutdown semantics; force_exit_timer is a Sleep chain.
        tokio::select! {
            result = axum::serve(listener, make_svc)
                .with_graceful_shutdown(graceful) => { session_ct.cancel(); result?; }
            () = force_exit_timer => {
                tracing::warn!("shutdown timeout exceeded, forcing exit");
                session_ct.cancel();
            }
        }
    }

    Ok(())
}

/// Install the OAuth 2.1 proxy endpoints (`/authorize`, `/token`,
/// `/register`, and authorization server metadata) on `router`. The
/// caller must ensure `oauth_config.proxy` is `Some`.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if the shared
/// [`crate::oauth::OauthHttpClient`] cannot be initialized.
#[cfg(feature = "oauth")]
fn install_oauth_proxy_routes(
    router: axum::Router,
    server_url: &str,
    oauth_config: &crate::oauth::OAuthConfig,
    auth_state: Option<&Arc<AuthState>>,
    max_request_body: usize,
    admin_role: &str,
) -> Result<axum::Router, RmcpServerKitError> {
    let Some(ref proxy) = oauth_config.proxy else {
        return Ok(router);
    };

    // Single shared HTTP client for all proxy endpoints. Cloning is
    // cheap (refcounted) and shares the underlying connection pool.
    let http = crate::oauth::OauthHttpClient::with_config(oauth_config)?;

    // Build the proxy endpoints on a DEDICATED sub-router so the request-body
    // cap below applies to exactly these routes and cannot leak onto `/mcp`,
    // health, or `/version`. Without this, the proxy routes would fall back to
    // axum's 2 MB `DefaultBodyLimit` and silently ignore the operator's
    // configured `max_request_body` (rust-review MEDIUM finding).
    let proxy_router = axum::Router::new();

    let asm = crate::oauth::authorization_server_metadata(server_url, oauth_config);
    let proxy_router = proxy_router.route(
        "/.well-known/oauth-authorization-server",
        axum::routing::get(move || {
            let m = asm.clone();
            async move { axum::Json(m) }
        }),
    );

    let proxy_authorize = proxy.clone();
    let proxy_router = proxy_router.route(
        "/authorize",
        axum::routing::get(
            move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                let p = proxy_authorize.clone();
                async move { crate::oauth::handle_authorize(&p, &query.unwrap_or_default()) }
            },
        ),
    );

    let proxy_token = proxy.clone();
    let token_http = http.clone();
    let proxy_router = proxy_router.route(
        "/token",
        axum::routing::post(move |body: String| {
            let p = proxy_token.clone();
            let h = token_http.clone();
            async move { crate::oauth::handle_token(&h, &p, &body).await }
        })
        .layer(axum::middleware::from_fn(
            oauth_token_cache_headers_middleware,
        )),
    );

    let proxy_register = proxy.clone();
    let proxy_router = proxy_router.route(
        "/register",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let p = proxy_register;
            async move { axum::Json(crate::oauth::handle_register(&p, &body)) }
        })
        .layer(axum::middleware::from_fn(
            oauth_token_cache_headers_middleware,
        )),
    );

    let admin_routes_enabled = proxy.expose_admin_endpoints
        && (proxy.introspection_url.is_some() || proxy.revocation_url.is_some());
    if proxy.expose_admin_endpoints
        && !proxy.require_auth_on_admin_endpoints
        && proxy.allow_unauthenticated_admin_endpoints
    {
        // M3 escape-hatch in effect: validate() let this through because
        // the operator explicitly opted in. Surface it loudly at startup
        // so the choice is auditable in logs.
        tracing::warn!(
            "OAuth introspect/revoke endpoints are unauthenticated by explicit \
             allow_unauthenticated_admin_endpoints opt-out; ensure an \
             authenticated reverse proxy fronts these routes"
        );
    }

    let admin_router = if admin_routes_enabled {
        build_oauth_admin_router(proxy, http, auth_state, admin_role)?
    } else {
        axum::Router::new()
    };

    // Merge admin (introspect/revoke) BEFORE applying the body-limit layer so
    // those routes inherit the cap too. `.layer` only wraps routes already
    // present on `proxy_router`, so this cannot affect the outer router.
    let proxy_router =
        proxy_router
            .merge(admin_router)
            .layer(tower_http::limit::RequestBodyLimitLayer::new(
                max_request_body,
            ));

    let router = router.merge(proxy_router);

    tracing::info!(
        introspect = proxy.expose_admin_endpoints && proxy.introspection_url.is_some(),
        revoke = proxy.expose_admin_endpoints && proxy.revocation_url.is_some(),
        max_request_body,
        "OAuth 2.1 proxy endpoints enabled (/authorize, /token, /register)"
    );
    Ok(router)
}

/// Build the optional `/introspect` + `/revoke` admin sub-router.
///
/// Layered with [`oauth_token_cache_headers_middleware`] so RFC 6749 §5.1
/// / RFC 6750 §5.4 cache headers are emitted, and conditionally with the
/// auth middleware when `proxy.require_auth_on_admin_endpoints` is set.
#[cfg(feature = "oauth")]
fn build_oauth_admin_router(
    proxy: &crate::oauth::OAuthProxyConfig,
    http: crate::oauth::OauthHttpClient,
    auth_state: Option<&Arc<AuthState>>,
    admin_role: &str,
) -> Result<axum::Router, RmcpServerKitError> {
    let mut admin_router = axum::Router::new();
    if proxy.introspection_url.is_some() {
        let proxy_introspect = proxy.clone();
        let introspect_http = http.clone();
        admin_router = admin_router.route(
            "/introspect",
            axum::routing::post(move |body: String| {
                let p = proxy_introspect.clone();
                let h = introspect_http.clone();
                async move { crate::oauth::handle_introspect(&h, &p, &body).await }
            }),
        );
    }
    if proxy.revocation_url.is_some() {
        let proxy_revoke = proxy.clone();
        let revoke_http = http;
        admin_router = admin_router.route(
            "/revoke",
            axum::routing::post(move |body: String| {
                let p = proxy_revoke.clone();
                let h = revoke_http.clone();
                async move { crate::oauth::handle_revoke(&h, &p, &body).await }
            }),
        );
    }

    let admin_router = admin_router.layer(axum::middleware::from_fn(
        oauth_token_cache_headers_middleware,
    ));

    if proxy.require_auth_on_admin_endpoints {
        let Some(state) = auth_state else {
            return Err(RmcpServerKitError::Startup(
                "oauth proxy admin endpoints require auth state".into(),
            ));
        };
        let state_for_mw = Arc::clone(state);
        let required_role: Arc<str> = Arc::from(admin_role);
        // M6: gate introspect/revoke behind the admin role. Layers are added
        // inner-first, so the role check is added BEFORE auth in order to run
        // AFTER it at runtime: auth_middleware (outermost) authenticates and
        // populates the AuthIdentity, then require_admin_role rejects any
        // authenticated-but-non-admin caller with 403.
        Ok(admin_router
            .layer(axum::middleware::from_fn(move |req, next| {
                let r = Arc::clone(&required_role);
                crate::admin::require_admin_role(r, req, next)
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let s = Arc::clone(&state_for_mw);
                auth_middleware(s, req, next)
            })))
    } else {
        Ok(admin_router)
    }
}

/// This server's externally-visible origin.
///
/// Prefers the operator-supplied `public_url`; otherwise reconstructs it from
/// the bind address, choosing the scheme from whether TLS is configured.
/// Shared by the OAuth metadata documents and the `WWW-Authenticate`
/// `resource_metadata` URL so they can never disagree.
#[allow(
    deprecated,
    reason = "internal metadata assembly reads deprecated `pub` config fields by design until 1.0 makes them pub(crate)"
)]
fn derive_server_url(config: &McpServerConfig) -> String {
    config.public_url.as_ref().map_or_else(
        || {
            let scheme = if config.tls_cert_path.is_some() {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{}", config.bind_addr)
        },
        |url| url.trim_end_matches('/').to_owned(),
    )
}

/// Build the host allow-list for rmcp's DNS rebinding protection.
///
/// Includes loopback hosts by default, then augments with host/authority
/// derived from `public_url` and the server bind address.
fn derive_allowed_hosts(bind_addr: &str, public_url: Option<&str>) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];

    if let Some(url) = public_url
        && let Ok(uri) = url.parse::<axum::http::Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|h| h == &host) {
            hosts.push(host);
        }

        let authority = authority.as_str().to_owned();
        if !hosts.iter().any(|h| h == &authority) {
            hosts.push(authority);
        }
    }

    if let Ok(uri) = format!("http://{bind_addr}").parse::<axum::http::Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|h| h == &host) {
            hosts.push(host);
        }

        let authority = authority.as_str().to_owned();
        if !hosts.iter().any(|h| h == &authority) {
            hosts.push(authority);
        }
    }

    hosts
}

// - TLS support -

/// Implement axum's `Connected` trait for `TlsConnInfo` so that
/// `ConnectInfo<TlsConnInfo>` is available in middleware when serving
/// over our custom `TlsListener`.
///
/// The identity is read directly from the wrapping
/// [`AuthenticatedTlsStream`], which guarantees one-to-one correspondence
/// between the TLS connection and its mTLS identity. This eliminates the
/// previous shared-map approach which was vulnerable to ephemeral-port
/// reuse races (an unauthenticated reconnection from the same `(IP, port)`
/// pair could alias a stale entry).
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsConnInfo
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        let addr = *target.remote_addr();
        let identity = target.io().identity().cloned();
        Self::new(addr, identity)
    }
}

/// Default per-handshake deadline on the TLS accept path. Prevents idle
/// or slow-loris connections from pinning handshake worker tasks (and
/// their semaphore permits) indefinitely.
///
/// Configurable since 1.9.0 via
/// [`McpServerConfig::with_tls_handshake_timeout`].
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default upper bound on concurrently in-flight TLS handshakes. When
/// saturated, the acceptor task stops pulling new connections from the
/// kernel backlog (backpressure) instead of accepting and dropping them
/// in user space.
///
/// Configurable since 1.9.0 via
/// [`McpServerConfig::with_max_concurrent_tls_handshakes`].
const DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES: usize = 256;

/// Capacity of the completed-handshake queue between the acceptor task and
/// `axum::serve`'s `accept()` loop. Handshake workers block on `send` when
/// the queue is full, so a slow accept loop back-pressures handshakes
/// rather than buffering completed connections unboundedly.
const TLS_ACCEPT_CHANNEL_CAPACITY: usize = 32;

/// A TLS-wrapping listener that implements axum's `Listener` trait.
///
/// TCP accepts and TLS handshakes run on a dedicated background task: each
/// accepted connection's handshake is spawned onto its own worker task,
/// bounded by a configurable concurrent-handshake cap (default
/// [`DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES`]) and a per-handshake timeout
/// (default [`DEFAULT_TLS_HANDSHAKE_TIMEOUT`]). A slow or idle client
/// therefore cannot stall other connections behind a serialized inline
/// handshake.
///
/// When mTLS is configured, client certificates are verified against the
/// configured CA and the client identity is extracted at handshake time.
/// The extracted identity is bound to the connection itself via the
/// returned [`AuthenticatedTlsStream`], so it is impossible for an
/// unrelated connection to observe it.
struct TlsListener {
    /// Bound address, captured eagerly before the `TcpListener` moves into
    /// the acceptor task.
    local_addr: SocketAddr,
    /// Completed handshakes produced by the acceptor task's workers.
    rx: mpsc::Receiver<(AuthenticatedTlsStream, SocketAddr)>,
    /// Background task driving TCP accepts and concurrent TLS handshakes.
    /// Aborted on drop so the listener releases its port deterministically.
    acceptor_task: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    fn new(
        inner: TcpListener,
        cert_path: &Path,
        key_path: &Path,
        mtls_config: Option<&MtlsConfig>,
        crl_set: Option<Arc<CrlSet>>,
        handshake_timeout: Duration,
        max_concurrent_handshakes: usize,
    ) -> anyhow::Result<Self> {
        // Install the ring crypto provider (ok to call multiple times).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let mtls_default_role;

        let tls_config = if let Some(mtls) = mtls_config {
            mtls_default_role = mtls.default_role.clone();
            let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> = if mtls.crl_enabled
            {
                let Some(crl_set) = crl_set else {
                    return Err(anyhow::anyhow!(
                        "mTLS CRL verifier requested but CRL state was not initialized"
                    ));
                };
                Arc::new(DynamicClientCertVerifier::new(crl_set))
            } else {
                let (_, root_store) = load_client_auth_roots(&mtls.ca_cert_path)?;
                if mtls.required {
                    rustls::server::WebPkiClientVerifier::builder(root_store)
                        .build()
                        .map_err(|e| anyhow::anyhow!("mTLS verifier error: {e}"))?
                } else {
                    rustls::server::WebPkiClientVerifier::builder(root_store)
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| anyhow::anyhow!("mTLS verifier error: {e}"))?
                }
            };

            tracing::info!(
                ca = %mtls.ca_cert_path.display(),
                required = mtls.required,
                crl_enabled = mtls.crl_enabled,
                "mTLS client auth configured"
            );

            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
        } else {
            mtls_default_role = "viewer".to_owned();
            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .with_no_client_auth()
            .with_single_cert(certs, key)?
        };

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        tracing::info!(
            "TLS enabled (cert: {}, key: {})",
            cert_path.display(),
            key_path.display()
        );
        let local_addr = inner.local_addr()?;
        let (tx, rx) = mpsc::channel(TLS_ACCEPT_CHANNEL_CAPACITY);
        let acceptor_task = tokio::spawn(run_tls_acceptor(
            inner,
            acceptor,
            mtls_default_role,
            tx,
            handshake_timeout,
            max_concurrent_handshakes,
        ));
        Ok(Self {
            local_addr,
            rx,
            acceptor_task,
        })
    }

    /// Extract the mTLS client cert identity from a completed TLS handshake.
    /// Returns `None` if no client certificate was presented or if the
    /// certificate could not be parsed into an [`AuthIdentity`].
    fn extract_handshake_identity(
        tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        default_role: &str,
        addr: SocketAddr,
    ) -> Option<AuthIdentity> {
        let (_, server_conn) = tls_stream.get_ref();
        let cert_der = server_conn.peer_certificates()?.first()?;
        let id = extract_mtls_identity(cert_der.as_ref(), default_role)?;
        tracing::debug!(name = %id.name, peer = %addr, "mTLS client cert accepted");
        Some(id)
    }
}

/// Drive TCP accepts and concurrent TLS handshakes for [`TlsListener`].
///
/// Each accepted connection's handshake runs on its own worker task under
/// a permit from a `max_concurrent_handshakes`-sized semaphore and a
/// `handshake_timeout` deadline. Completed handshakes are pushed to `tx`;
/// failures and timeouts are logged at DEBUG and the connection dropped.
/// The loop exits when the owning [`TlsListener`] is dropped.
// cancel-safe: aborted from `TlsListener::drop`; `accept` is cancel-safe,
// semaphore permits are RAII, and spawned handshake workers own streams and
// discard completed sends when `rx` is closed.
async fn run_tls_acceptor(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    default_role: String,
    tx: mpsc::Sender<(AuthenticatedTlsStream, SocketAddr)>,
    handshake_timeout: Duration,
    max_concurrent_handshakes: usize,
) {
    let inflight = Arc::new(Semaphore::new(max_concurrent_handshakes));
    loop {
        // Acquire the permit BEFORE accepting: at saturation, pending
        // connections wait in the kernel backlog instead of being accepted
        // and then buffered or dropped in user space.
        let Ok(permit) = Arc::clone(&inflight).acquire_owned().await else {
            // The semaphore is never closed; defensive exit.
            return;
        };
        let (stream, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("TCP accept error: {e}");
                continue;
            }
        };
        if tx.is_closed() {
            // The listener was dropped (shutdown): stop accepting.
            return;
        }
        let acceptor = acceptor.clone();
        let default_role = default_role.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let identity =
                        TlsListener::extract_handshake_identity(&tls_stream, &default_role, addr);
                    let wrapped = AuthenticatedTlsStream {
                        inner: tls_stream,
                        identity,
                    };
                    // The receiver only disappears during shutdown; discard
                    // the completed connection quietly rather than logging.
                    let _ = tx.send((wrapped, addr)).await;
                }
                Ok(Err(e)) => {
                    tracing::debug!("TLS handshake failed from {addr}: {e}");
                }
                Err(_elapsed) => {
                    tracing::debug!(
                        "TLS handshake timed out from {addr} after {handshake_timeout:?}"
                    );
                }
            }
        });
    }
}

/// A TLS stream paired with the mTLS identity extracted at handshake time.
///
/// Wraps [`tokio_rustls::server::TlsStream`] so the verified client
/// identity travels with the connection itself. This replaces the previous
/// shared `MtlsIdentities` map, eliminating the
/// `(SocketAddr) -> AuthIdentity` aliasing risk caused by ephemeral-port
/// reuse and removing the need for an LRU eviction policy.
///
/// The wrapper is `Unpin` (its inner stream is `Unpin` because
/// [`tokio::net::TcpStream`] is `Unpin`), so `AsyncRead`/`AsyncWrite`
/// delegation uses safe pin projection via `Pin::new(&mut self.inner)`.
pub(crate) struct AuthenticatedTlsStream {
    inner: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    identity: Option<AuthIdentity>,
}

impl AuthenticatedTlsStream {
    /// Returns the verified mTLS client identity, if any.
    #[must_use]
    pub(crate) const fn identity(&self) -> Option<&AuthIdentity> {
        self.identity.as_ref()
    }
}

impl std::fmt::Debug for AuthenticatedTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedTlsStream")
            .field("identity", &self.identity.as_ref().map(|id| &id.name))
            .finish_non_exhaustive()
    }
}

impl tokio::io::AsyncRead for AuthenticatedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AuthenticatedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = AuthenticatedTlsStream;
    type Addr = SocketAddr;

    /// Yield the next fully-handshaken TLS connection.
    ///
    /// Cancel-safe: this is a plain `mpsc::Receiver::recv`, so cancelling
    /// the future (axum selects it against graceful shutdown) never loses
    /// a connection.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if let Some(pair) = self.rx.recv().await {
            return pair;
        }
        // The channel only closes if the acceptor task terminated, which
        // means the TcpListener is gone and the OS already refuses new
        // connections. `Listener::accept` is infallible and panicking is
        // forbidden, so park forever: existing connections keep being
        // served and graceful shutdown still completes.
        tracing::error!("TLS acceptor task terminated; no further connections will be accepted");
        std::future::pending().await
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        // Stop accepting immediately and release the bound port. In-flight
        // handshake workers notice the closed channel and exit quietly.
        self.acceptor_task.abort();
    }
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow::anyhow!("failed to read certs from {}: {e}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("invalid cert in {}: {e}", path.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certs)
}

fn load_client_auth_roots(
    path: &Path,
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    Arc<RootCertStore>,
)> {
    let ca_certs = load_certs(path)?;
    let mut root_store = RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .map_err(|error| anyhow::anyhow!("invalid CA cert: {error}"))?;
    }

    Ok((ca_certs, Arc::new(root_store)))
}

fn load_key(path: &Path) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_file(path)
        .map_err(|e| anyhow::anyhow!("failed to read key from {}: {e}", path.display()))
}

// cancel-safe: builds a constant JSON body with no awaits and no shared state.
#[allow(
    clippy::unused_async,
    reason = "axum route handler signature requires `async fn` even when the body is synchronous"
)]
async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
    }))
}

/// Build the `/version` JSON payload for a given server name and version.
///
/// `name`, `version`, and `rmcp_server_kit_version` are always included. Build
/// metadata (`build_git_sha`, `build_timestamp`, `rust_version`) is added
/// only when `expose_build_metadata` is true, so anonymous `/version`
/// callers do not receive build fingerprints by default. The build values
/// are read at compile time from `RMCP_SERVER_KIT_BUILD_SHA`,
/// `RMCP_SERVER_KIT_BUILD_TIME`, and `RMCP_SERVER_KIT_RUSTC_VERSION`;
/// unset values resolve to `"unknown"`.
fn version_payload(name: &str, version: &str, expose_build_metadata: bool) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("name".into(), name.into());
    map.insert("version".into(), version.into());
    map.insert(
        "rmcp_server_kit_version".into(),
        env!("CARGO_PKG_VERSION").into(),
    );
    if expose_build_metadata {
        map.insert(
            "build_git_sha".into(),
            option_env!("RMCP_SERVER_KIT_BUILD_SHA")
                .unwrap_or("unknown")
                .into(),
        );
        map.insert(
            "build_timestamp".into(),
            option_env!("RMCP_SERVER_KIT_BUILD_TIME")
                .unwrap_or("unknown")
                .into(),
        );
        map.insert(
            "rust_version".into(),
            option_env!("RMCP_SERVER_KIT_RUSTC_VERSION")
                .unwrap_or("unknown")
                .into(),
        );
    }
    serde_json::Value::Object(map)
}

/// Pre-serialize the `/version` payload to immutable bytes.
///
/// This is called once at router-build time so per-request handling can
/// reuse a cheap `Arc<[u8]>` clone instead of re-serializing a
/// [`serde_json::Value`] on every hit.
///
/// Serialization of a flat `serde_json::Value` of static-string fields
/// cannot fail in practice; the fallback to `b"{}"` exists only to
/// satisfy the crate-wide `unwrap_used` / `expect_used` lint policy.
fn serialize_version_payload(name: &str, version: &str, expose_build_metadata: bool) -> Arc<[u8]> {
    let value = version_payload(name, version, expose_build_metadata);
    serde_json::to_vec(&value).map_or_else(|_| Arc::from(&b"{}"[..]), Arc::from)
}

// NOT cancel-safe in general: the kit itself mutates no state here, but this
// awaits a consumer-supplied readiness future. Cancellation drops that future
// at whatever await it is parked on, so cancel safety is the callback author's
// contract -- a readiness probe must not leave partial state behind.
async fn readyz(check: ReadinessCheck) -> impl IntoResponse {
    let status = check().await;
    let ready = status
        .get("ready")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let code = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(status))
}

/// Wait for SIGINT (ctrl-c) or SIGTERM (container stop).
///
/// On non-Unix platforms, only SIGINT is handled.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                // cancel-safe: signal-listener futures are cancel-safe per
                // tokio docs; no partial state in either arm.
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, using SIGINT only");
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

// -- Origin validation (MCP 2025-11-25 spec, section 2.0.1) --

/// Middleware that validates the `Origin` header on incoming HTTP requests.
///
/// Collapse a request into a bounded set of Prometheus label values.
///
/// Prometheus retains one time series per distinct label set, and this
/// middleware runs OUTSIDE the auth layer, so any label derived from raw
/// request input is an unauthenticated memory-growth primitive. Both label
/// values must therefore come from a closed set.
///
/// `MatchedPath` yields the route template for ordinary registered routes,
/// but it is not available everywhere: `/mcp` is mounted with `nest_service`,
/// whose tail match may carry `MatchedNestedPath` instead, and unmatched
/// requests that hit the 404 fallback carry neither. The raw URI path is
/// never used as a fallback -- that is precisely the unbounded input.
#[cfg(feature = "metrics")]
fn metrics_labels(req: &Request<Body>) -> (&'static str, String) {
    let method = match *req.method() {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PUT => "PUT",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        axum::http::Method::TRACE => "TRACE",
        axum::http::Method::CONNECT => "CONNECT",
        // HTTP permits extension methods, so anything else collapses to a
        // single bucket rather than minting a series per invented verb.
        _ => "OTHER",
    };

    let path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(
            || {
                let raw = req.uri().path();
                if raw == "/mcp" || raw.starts_with("/mcp/") {
                    "/mcp".to_owned()
                } else {
                    "<unmatched>".to_owned()
                }
            },
            |matched| matched.as_str().to_owned(),
        );

    (method, path)
}

/// Record HTTP request metrics (method, path, status, duration).
///
/// Also exposes the shared [`crate::metrics::McpMetrics`] handle to
/// inner middleware via a request extension, so the rate limiters can
/// increment `rmcp_server_kit_rate_limited_total` at their deny sites
/// (see [`crate::metrics::record_rate_limit_deny`]).
// cancel-safe: counters are incremented synchronously around the single
// `next.run(req)` await, so cancellation loses the observation rather than
// leaving a half-updated metric.
#[cfg(feature = "metrics")]
async fn metrics_middleware(
    metrics: Arc<crate::metrics::McpMetrics>,
    mut req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let (method, path) = metrics_labels(&req);
    let start = std::time::Instant::now();

    req.extensions_mut().insert(Arc::clone(&metrics));
    let response = next.run(req).await;

    let mut status_buf = core::fmt::NumBuffer::<u16>::new();
    let status = response.status().as_u16().format_into(&mut status_buf);
    let duration = start.elapsed().as_secs_f64();

    metrics
        .http_requests_total
        .with_label_values(&[method, &path, status])
        .inc();
    metrics
        .http_request_duration_seconds
        .with_label_values(&[method, &path])
        .observe(duration);

    response
}

/// OWASP security header hardening applied to every response.
///
/// Sets: `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`,
/// `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
/// `Cross-Origin-Embedder-Policy`, `Permissions-Policy`,
/// `X-Permitted-Cross-Domain-Policies`, `Content-Security-Policy`,
/// `X-DNS-Prefetch-Control`, and (when TLS is active) `Strict-Transport-Security`.
///
/// Each header's value can be customised via [`SecurityHeadersConfig`]
/// on [`McpServerConfig`]. See that type for the three-state semantic
/// (`None` = default, `Some("")` = omit, `Some(v)` = override).
// cancel-safe: the only await is `next.run(req)`; header mutation afterwards is
// synchronous, so cancellation simply drops the response before it is sent.
async fn security_headers_middleware(
    is_tls: bool,
    cfg: Arc<SecurityHeadersConfig>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    use axum::http::{HeaderName, header};

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // Strip server identity headers to reduce information leakage.
    headers.remove(header::SERVER);
    headers.remove(HeaderName::from_static("x-powered-by"));

    apply_security_header(
        headers,
        header::X_CONTENT_TYPE_OPTIONS,
        cfg.x_content_type_options.as_deref(),
        "nosniff",
    );
    apply_security_header(
        headers,
        header::X_FRAME_OPTIONS,
        cfg.x_frame_options.as_deref(),
        "deny",
    );
    apply_security_header(
        headers,
        header::CACHE_CONTROL,
        cfg.cache_control.as_deref(),
        "no-store, max-age=0",
    );
    apply_security_header(
        headers,
        header::REFERRER_POLICY,
        cfg.referrer_policy.as_deref(),
        "no-referrer",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("cross-origin-opener-policy"),
        cfg.cross_origin_opener_policy.as_deref(),
        "same-origin",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("cross-origin-resource-policy"),
        cfg.cross_origin_resource_policy.as_deref(),
        "same-origin",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("cross-origin-embedder-policy"),
        cfg.cross_origin_embedder_policy.as_deref(),
        "require-corp",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("permissions-policy"),
        cfg.permissions_policy.as_deref(),
        "accelerometer=(), camera=(), geolocation=(), microphone=()",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        cfg.x_permitted_cross_domain_policies.as_deref(),
        "none",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("content-security-policy"),
        cfg.content_security_policy.as_deref(),
        "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
    );
    apply_security_header(
        headers,
        HeaderName::from_static("x-dns-prefetch-control"),
        cfg.x_dns_prefetch_control.as_deref(),
        "off",
    );

    if is_tls {
        apply_security_header(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            cfg.strict_transport_security.as_deref(),
            "max-age=63072000; includeSubDomains",
        );
    }

    resp
}

/// Set a single security header on the response, honouring the
/// three-state override semantic (None = default, Some("") = omit,
/// Some(value) = override).
///
/// Defence-in-depth: if an override value somehow reaches this point
/// despite [`validate_security_headers`] having approved it (e.g. a
/// runtime mutation on a non-`Validated` field), we log at error level
/// and fall back to the static default rather than panicking. The
/// `Validated<McpServerConfig>` type makes that path unreachable in
/// well-typed code paths.
fn apply_security_header(
    headers: &mut axum::http::HeaderMap,
    name: axum::http::HeaderName,
    override_value: Option<&str>,
    default: &'static str,
) {
    use axum::http::HeaderValue;

    match override_value {
        None => {
            headers.insert(name, HeaderValue::from_static(default));
        }
        Some("") => {
            // Operator explicitly opted out of this header.
        }
        Some(v) => match HeaderValue::from_str(v) {
            Ok(hv) => {
                headers.insert(name, hv);
            }
            Err(err) => {
                tracing::error!(
                    header = %name,
                    error = %err,
                    "invalid security header override reached middleware; using default"
                );
                headers.insert(name, HeaderValue::from_static(default));
            }
        },
    }
}

/// Validate every non-empty entry in a [`SecurityHeadersConfig`].
///
/// - `None` and `Some("")` are accepted unconditionally (use-default and
///   omit, respectively).
/// - `Some(v)` is rejected if `axum::http::HeaderValue::from_str(v)` fails.
/// - `strict_transport_security` additionally rejects any value
///   containing `preload` (case-insensitive). Operators who genuinely
///   want to commit to the HSTS preload list must do so via a future
///   explicit `with_hsts_preload(true)` builder, not by smuggling
///   `preload` through this knob.
fn validate_security_headers(cfg: &SecurityHeadersConfig) -> Result<(), RmcpServerKitError> {
    use axum::http::HeaderValue;

    let fields: &[(&str, Option<&str>)] = &[
        (
            "x_content_type_options",
            cfg.x_content_type_options.as_deref(),
        ),
        ("x_frame_options", cfg.x_frame_options.as_deref()),
        ("cache_control", cfg.cache_control.as_deref()),
        ("referrer_policy", cfg.referrer_policy.as_deref()),
        (
            "cross_origin_opener_policy",
            cfg.cross_origin_opener_policy.as_deref(),
        ),
        (
            "cross_origin_resource_policy",
            cfg.cross_origin_resource_policy.as_deref(),
        ),
        (
            "cross_origin_embedder_policy",
            cfg.cross_origin_embedder_policy.as_deref(),
        ),
        ("permissions_policy", cfg.permissions_policy.as_deref()),
        (
            "x_permitted_cross_domain_policies",
            cfg.x_permitted_cross_domain_policies.as_deref(),
        ),
        (
            "content_security_policy",
            cfg.content_security_policy.as_deref(),
        ),
        (
            "x_dns_prefetch_control",
            cfg.x_dns_prefetch_control.as_deref(),
        ),
        (
            "strict_transport_security",
            cfg.strict_transport_security.as_deref(),
        ),
    ];

    for (field, value) in fields {
        let Some(v) = value else { continue };
        if v.is_empty() {
            continue;
        }
        if let Err(err) = HeaderValue::from_str(v) {
            return Err(RmcpServerKitError::Config(format!(
                "invalid security_headers.{field}: {err}"
            )));
        }
    }

    if let Some(v) = cfg.strict_transport_security.as_deref()
        && !v.is_empty()
        && v.to_ascii_lowercase().contains("preload")
    {
        return Err(RmcpServerKitError::Config(format!(
            "invalid security_headers.strict_transport_security: {v:?} contains the `preload` directive; \
             HSTS preload must be opted into explicitly via a dedicated builder, not via this knob"
        )));
    }

    Ok(())
}

/// Append RFC 6749 §5.1 / RFC 6750 §5.4 cache and `Vary` headers required
/// on OAuth token-issuing responses.
///
/// `Cache-Control: no-store, max-age=0` is already applied globally by
/// [`security_headers_middleware`]; this middleware adds:
///
/// - `Pragma: no-cache` -- mandated by RFC 6749 §5.1 for HTTP/1.0 caches.
/// - `Vary: Authorization` -- mandated by RFC 6750 §5.4 for endpoints
///   whose response depends on the `Authorization` header.
///
/// Applied only to the OAuth proxy token-class endpoints (`/token`,
/// `/register`, `/introspect`, `/revoke`). `Vary` is appended (not
/// inserted) so any `Vary` value already present (e.g. `Accept-Encoding`
/// from a compression layer, or `Origin` from a CORS layer) is preserved.
#[cfg(feature = "oauth")]
async fn oauth_token_cache_headers_middleware(
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    use axum::http::{HeaderValue, header};

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.append(header::VARY, HeaderValue::from_static("Authorization"));
    resp
}

/// Normalize peer-address request extensions across listener branches.
///
/// The make-service installs `ConnectInfo<SocketAddr>` on the plain
/// listener but `ConnectInfo<TlsConnInfo>` on the TLS listener (the
/// latter additionally carries the connection-bound mTLS identity and
/// stays `pub(crate)` - see the anti-aliasing rationale on
/// [`TlsConnInfo`]). Application routes - in particular those merged via
/// [`McpServerConfig::with_extra_router`], which bypass the auth
/// middleware and its private fallback - could therefore not read the
/// peer address under TLS.
///
/// This middleware makes both branches look identical to every route and
/// inner middleware:
///
/// 1. mirrors the TLS peer address into `ConnectInfo<SocketAddr>` when
///    (and only when) it is absent, so stock axum-ecosystem extractors
///    work unmodified,
/// 2. inserts the framework-owned [`PeerAddr`] extension on both
///    branches, and
/// 3. inserts the resolved [`ClientIp`] extension: the direct peer's IP,
///    unless trusted-forwarder mode is configured AND the direct peer is
///    a trusted proxy AND the forwarding chain resolves - every
///    ambiguous chain falls back to the direct peer with only a reason
///    code logged at `debug` (never raw header contents).
///
/// Precedence mirrors the auth middleware: an existing
/// `ConnectInfo<SocketAddr>` always wins and is never overwritten. The
/// peer address is deliberately not logged here.
// cancel-safe: inserts request extensions synchronously before the single
// `next.run(req)` await; the extensions die with the dropped request.
async fn normalize_peer_addr_middleware(
    resolver: Option<Arc<ForwardResolver>>,
    mut req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let direct = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let from_tls = req
        .extensions()
        .get::<ConnectInfo<TlsConnInfo>>()
        .map(|ci| ci.0.addr);
    if let Some(addr) = direct.or(from_tls) {
        if direct.is_none() {
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        req.extensions_mut().insert(PeerAddr::new(addr));
        let client_ip = match &resolver {
            Some(r) => crate::forwarded::resolve_client_ip(
                addr.ip(),
                req.headers(),
                &r.trusted,
                r.mode,
                r.max_scanned_entries,
            )
            .unwrap_or_else(|reason| {
                tracing::debug!(
                    reason = ?reason,
                    "forwarded-header resolution fell back to direct peer"
                );
                addr.ip()
            }),
            None => addr.ip(),
        };
        req.extensions_mut().insert(ClientIp::new(client_ip));
    }
    next.run(req).await
}

/// Parse a trusted-proxy entry: a CIDR (`10.0.0.0/8`) or a bare IP
/// (normalized to a `/32` / `/128` host network).
fn parse_proxy_net(entry: &str) -> Option<ipnet::IpNet> {
    if let Ok(net) = entry.parse::<ipnet::IpNet>() {
        return Some(net);
    }
    entry.parse::<IpAddr>().ok().map(ipnet::IpNet::from)
}

/// Validate one `trusted_proxies` entry. Accepts a CIDR (`ipnet::IpNet`)
/// or a bare IP; **rejects a `/0` prefix**, which would mark every peer
/// trusted and let any client spoof the resolved client IP via forwarding
/// headers. Shared by the builder ([`McpServerConfig::check_trusted_forwarder`])
/// and the TOML validator so the two validators cannot drift.
///
/// # Errors
///
/// Returns a message when the entry is unparseable or carries a `/0` prefix.
pub(crate) fn validate_trusted_proxy_entry(entry: &str) -> Result<(), String> {
    match parse_proxy_net(entry) {
        None => Err(format!(
            "trusted_proxies entry {entry:?} is neither a CIDR nor an IP address"
        )),
        Some(net) if net.prefix_len() == 0 => Err(format!(
            "trusted_proxies entry {entry:?}: prefix length 0 is forbidden (marks every peer trusted, enabling client-IP spoofing)"
        )),
        Some(_) => Ok(()),
    }
}

/// Rate-limit key for the current request: the resolved [`ClientIp`]
/// when present, else the direct peer from either `ConnectInfo` form.
/// All four built-in limiters key through this helper.
pub(crate) fn limiter_client_ip(extensions: &axum::http::Extensions) -> Option<IpAddr> {
    if let Some(client) = extensions.get::<ClientIp>() {
        return Some(client.ip);
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .or_else(|| {
            extensions
                .get::<ConnectInfo<TlsConnInfo>>()
                .map(|ci| ci.0.addr.ip())
        })
}

/// Rate-limit bucket identity for a request.
///
/// A request whose source address cannot be resolved must not become
/// *exempt* from rate limiting, so such requests share one bounded
/// [`RateLimitKey::Unattributed`] bucket instead.
///
/// This is an enum rather than a sentinel `IpAddr` (e.g. `0.0.0.0`)
/// because [`limiter_client_ip`] consults [`ClientIp`] first, and in
/// trusted-forwarder mode that value is header-derived:
/// [`crate::forwarded`] does not filter unspecified or reserved
/// addresses, so a forwarded `0.0.0.0` would collide with the sentinel
/// and share a bucket with genuinely unattributable traffic.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum RateLimitKey {
    /// A resolved client address.
    Ip(IpAddr),
    /// Source address could not be determined.
    Unattributed,
}

impl std::fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Unattributed => f.write_str("unattributed"),
        }
    }
}

/// Emitted at most once per process; see [`limiter_client_key`].
static UNATTRIBUTED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Rate-limit key for the current request.
///
/// Falls back to [`RateLimitKey::Unattributed`] when no address can be
/// resolved, which cannot happen for a request served by [`serve`] (the
/// peer-address normalisation layer inserts `ConnectInfo` on both the TLS
/// and plaintext paths) but is reachable if this crate's middleware is
/// composed into a router built elsewhere. The warning fires once per
/// process rather than per request: a broken invariant holds for *every*
/// request, so per-request logging would amplify it into its own denial
/// of service.
pub(crate) fn limiter_client_key(extensions: &axum::http::Extensions) -> RateLimitKey {
    if let Some(ip) = limiter_client_ip(extensions) {
        return RateLimitKey::Ip(ip);
    }
    if !UNATTRIBUTED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "request carries no resolvable client address; rate limiting is \
             falling back to a single shared bucket. This indicates \
             rmcp-server-kit middleware composed outside serve()."
        );
    }
    RateLimitKey::Unattributed
}

/// Per-IP rate limiter for `extra_router` routes, keyed by the direct
/// socket peer address. Same memory-bounded machinery as the tool
/// limiter ([`crate::rbac`]).
pub(crate) type ExtraRouteRateLimiter = BoundedKeyedLimiter<RateLimitKey>;

/// Cap on distinct source IPs tracked by the extra-route limiter.
/// Mirrors the tool limiter's bound: memory stays bounded at saturation
/// via idle-prune + LRU eviction, at the cost of shared-fate fairness
/// under key spray (an attacker churning many IPs can reset quieter
/// legitimate IPs to fresh buckets).
const EXTRA_ROUTE_MAX_TRACKED_KEYS: usize = 10_000;

/// Idle-eviction window for the extra-route limiter (15 minutes),
/// mirroring the tool limiter.
const EXTRA_ROUTE_IDLE_EVICTION: Duration = Duration::from_mins(15);

/// Build the per-IP limiter for `extra_router` routes.
///
/// `per_minute` and `burst` are validated nonzero by
/// [`McpServerConfig::validate`]; the `NonZeroU32` fallbacks here are
/// defensive only. `burst` overrides governor's default bucket capacity
/// (burst = rate).
fn build_extra_route_rate_limiter_with_policy(
    per_minute: u32,
    burst: Option<u32>,
    key_eviction_policy: KeyEvictionPolicy,
    max_tracked_keys: NonZeroUsize,
) -> Arc<ExtraRouteRateLimiter> {
    let rate = std::num::NonZeroU32::new(per_minute.max(1)).unwrap_or(std::num::NonZeroU32::MIN);
    let mut quota = governor::Quota::per_minute(rate);
    if let Some(b) = burst.and_then(std::num::NonZeroU32::new) {
        quota = quota.allow_burst(b);
    }
    Arc::new(BoundedKeyedLimiter::new_with_policy(
        quota,
        max_tracked_keys,
        EXTRA_ROUTE_IDLE_EVICTION,
        key_eviction_policy,
    ))
}

/// Per-IP rate limit middleware for `extra_router` routes.
///
/// Applied to the application-supplied router **before** it is merged
/// into the top-level router, so it wraps exactly the extra routes
/// (and their fallback, if any) and nothing else - `/mcp`, health,
/// admin, and OAuth endpoints are never affected. Outer layers (origin
/// check, peer-address normalization, security headers, metrics) still
/// wrap these routes and run first, so both `ConnectInfo` forms are
/// populated by the time this middleware reads them.
///
/// Semantics mirror the tool/auth limiters exactly: keyed by the
/// direct peer `IpAddr` (no `X-Forwarded-For`), fail-open when no peer
/// address is present (cannot happen under [`serve`]), and on limit a
/// plain-text 429 via [`RmcpServerKitError::RateLimitedFor`] carrying a
/// `Retry-After` header (delta-seconds), consistent with every other
/// limiter in the crate.
///
/// `exempt` holds raw exact-match paths (validated at config time)
/// checked against `req.uri().path()` **before** key extraction:
/// exempt requests consume no limiter budget and produce no deny
/// telemetry. Fail-closed - any non-listed path stays limited.
// cancel-safe: the limiter is charged synchronously before the `next.run(req)`
// await. Charging an attempt that a later timeout cancels is deliberate -- the
// request was admitted, so it must cost budget (same posture as auth/rbac).
async fn extra_route_rate_limit_middleware(
    limiter: Arc<ExtraRouteRateLimiter>,
    exempt: Arc<std::collections::HashSet<String>>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    if exempt.contains(req.uri().path()) {
        return next.run(req).await;
    }
    let peer_key = limiter_client_key(req.extensions());
    match limiter.check_key_detailed(&peer_key) {
        Ok(()) => {}
        Err(BoundedLimiterDeny::RateLimited(wait)) => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_rate_limit_deny(req.extensions(), "extra_route");
            tracing::warn!(rate_limit_key = %peer_key, "extra route request rate limited");
            return RmcpServerKitError::RateLimitedFor {
                message: "too many requests to application routes from this source".into(),
                retry_after: wait,
            }
            .into_response();
        }
        Err(BoundedLimiterDeny::CapacityFull) => {
            tracing::warn!(
                rate_limit_key = %peer_key,
                "extra route limiter rejected unseen key because tracked-key capacity is full"
            );
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "rate limiter capacity exhausted",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Per the MCP spec: if the Origin header is present and its value is not in
/// the allowed list, respond with 403 Forbidden. Requests without an Origin
/// header are allowed through (e.g. non-browser clients like curl, SDKs).
// cancel-safe: origin validation and request logging are synchronous and happen
// before the single `next.run(req)` await; nothing is published on cancellation.
async fn origin_check_middleware(
    allowed: Arc<[String]>,
    log_request_headers: bool,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    log_incoming_request(&method, &path, req.headers(), log_request_headers);

    if let Some(origin) = req.headers().get(axum::http::header::ORIGIN) {
        let origin_str = origin.to_str().unwrap_or("");
        if !allowed.iter().any(|a| a == origin_str) {
            tracing::warn!(
                origin = origin_str,
                %method,
                %path,
                allowed = ?&*allowed,
                "rejected request: Origin not allowed"
            );
            return (
                axum::http::StatusCode::FORBIDDEN,
                "Forbidden: Origin not allowed",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Emit a DEBUG log for an incoming request, optionally including the full
/// (redacted) header set.
fn log_incoming_request(
    method: &axum::http::Method,
    path: &str,
    headers: &axum::http::HeaderMap,
    log_request_headers: bool,
) {
    if log_request_headers {
        tracing::debug!(
            %method,
            %path,
            headers = %format_request_headers_for_log(headers),
            "incoming request"
        );
    } else {
        tracing::debug!(%method, %path, "incoming request");
    }
}

/// Header names whose values are never rendered into logs.
///
/// SECURITY: the first three carry credentials. The forwarding headers carry
/// client IPs and proxy topology and are attacker-controlled on any hop the
/// operator has not declared trusted, so logging them verbatim lets a caller
/// plant misleading provenance in an incident-response trail. The trusted,
/// resolved address is published separately by `resolve_client_ip`.
const REDACTED_LOG_HEADERS: [&str; 6] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
];

fn format_request_headers_for_log(headers: &axum::http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| {
            let name = k.as_str();
            if REDACTED_LOG_HEADERS.contains(&name) {
                format!("{name}: [REDACTED]")
            } else {
                format!("{name}: {}", v.to_str().unwrap_or("<non-utf8>"))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// -- stdio transport --

/// Serve an MCP server over stdin/stdout (stdio transport).
///
/// # Security warnings
///
/// - **No authentication**: the parent process has full, unrestricted access.
/// - **No RBAC**: all tools are available regardless of policy.
/// - **No TLS**: messages travel over OS pipes in plaintext.
/// - **Single client**: only the parent process can connect.
/// - **No Origin validation**: not applicable to stdio.
///
/// Use this only when the MCP client spawns the server as a trusted subprocess
/// (e.g. Claude Desktop, VS Code Copilot). For network-accessible deployments,
/// use `serve()` (Streamable HTTP) instead.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if the handler fails to initialize or the
/// transport disconnects unexpectedly.
// NOTE: reported complexity 32/25 is driven entirely by `tracing::*!`
// macro expansion in this 18-line function (info/warn/info + two matches).
// There is nothing meaningful to extract; the allow stays.
#[allow(
    clippy::cognitive_complexity,
    reason = "complexity is purely tracing macro expansion (info/warn + match arms); 18 lines of straight-line code, nothing meaningful to extract"
)]
pub async fn serve_stdio<H>(handler: H) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
{
    use rmcp::ServiceExt as _;

    tracing::info!("stdio transport: serving on stdin/stdout");
    tracing::warn!("stdio mode: auth, RBAC, TLS, and Origin checks are DISABLED");

    let transport = rmcp::transport::io::stdio();

    let service = handler
        .serve(transport)
        .await
        .map_err(|e| RmcpServerKitError::Startup(format!("stdio initialize failed: {e}")))?;

    if let Err(e) = service.waiting().await {
        tracing::warn!(error = %e, "stdio session ended with error");
    }
    tracing::info!("stdio session ended");
    Ok(())
}

#[allow(
    deprecated,
    reason = "builder methods are the sanctioned transition layer for deprecated public fields"
)]
impl McpServerConfig {
    /// Replace the TLS certificate/key paths exactly, including `None`
    /// values. Configuration bridges use this to preserve partial TLS
    /// configuration so validation reports the missing half.
    #[must_use]
    pub fn with_tls_paths(mut self, cert_path: Option<PathBuf>, key_path: Option<PathBuf>) -> Self {
        self.tls_cert_path = cert_path;
        self.tls_key_path = key_path;
        self
    }

    /// Set only the TLS certificate path. Intended for configuration
    /// bridges that must preserve partial TLS configuration so validation
    /// can report the missing key path.
    #[must_use]
    pub fn with_tls_cert_path(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self
    }

    /// Set only the TLS private-key path. Intended for configuration
    /// bridges that must preserve partial TLS configuration so validation
    /// can report the missing certificate path.
    #[must_use]
    pub fn with_tls_key_path(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Replace the optional authentication configuration exactly.
    #[must_use]
    pub fn with_optional_auth(mut self, auth: Option<AuthConfig>) -> Self {
        self.auth = auth;
        self
    }

    /// Replace the optional tool rate limit exactly.
    #[must_use]
    pub fn with_optional_tool_rate_limit(mut self, per_minute: Option<u32>) -> Self {
        self.tool_rate_limit = per_minute;
        self
    }

    /// Replace the optional tool rate-limit burst exactly.
    #[must_use]
    pub fn with_optional_tool_rate_limit_burst(mut self, burst: Option<u32>) -> Self {
        self.tool_rate_limit_burst = burst;
        self
    }

    /// Replace the optional extra-route rate limit exactly.
    #[must_use]
    pub fn with_optional_extra_route_rate_limit(mut self, per_minute: Option<u32>) -> Self {
        self.extra_route_rate_limit = per_minute;
        self
    }

    /// Replace the optional extra-route rate-limit burst exactly.
    #[must_use]
    pub fn with_optional_extra_route_rate_limit_burst(mut self, burst: Option<u32>) -> Self {
        self.extra_route_rate_limit_burst = burst;
        self
    }

    /// Replace the optional forwarded-header mode exactly.
    #[must_use]
    pub fn with_optional_forwarded_header(mut self, mode: Option<ForwardedHeaderMode>) -> Self {
        self.forwarded_header = mode;
        self
    }

    /// Replace the optional public URL exactly.
    #[must_use]
    pub fn with_optional_public_url(mut self, url: Option<String>) -> Self {
        self.public_url = url;
        self
    }

    /// Override the compression minimum response size without enabling
    /// compression. This keeps configuration bridges able to carry the
    /// inert threshold independently from the enable flag.
    #[must_use]
    pub fn with_compression_min_size(mut self, min_size: u16) -> Self {
        self.compression_min_size = min_size;
        self
    }

    /// Replace the compression enabled flag exactly.
    #[must_use]
    pub fn with_compression_enabled(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Replace the optional global in-flight request cap exactly.
    #[must_use]
    pub fn with_optional_max_concurrent_requests(mut self, limit: Option<usize>) -> Self {
        self.max_concurrent_requests = limit;
        self
    }

    /// Replace the admin endpoint enabled flag exactly.
    #[must_use]
    pub fn with_admin_enabled(mut self, enabled: bool) -> Self {
        self.admin_enabled = enabled;
        self
    }

    /// Override the RBAC role required by admin-gated endpoints without
    /// enabling `/admin/*` diagnostics.
    #[must_use]
    pub fn with_admin_role(mut self, role: impl Into<String>) -> Self {
        self.admin_role = role.into();
        self
    }

    /// Replace the build-metadata exposure flag exactly.
    #[must_use]
    pub fn with_expose_build_metadata(mut self, enabled: bool) -> Self {
        self.expose_build_metadata = enabled;
        self
    }
}

fn warn_security_header_overrides(cfg: &SecurityHeadersConfig) {
    for (field, value) in security_header_overrides(cfg) {
        let action = if value.is_empty() {
            "omitted"
        } else {
            "overridden"
        };
        tracing::warn!(
            security_header = field,
            action,
            "security header configured; inspect server.security_headers.<security_header>"
        );
    }
}

fn security_header_overrides(
    cfg: &SecurityHeadersConfig,
) -> impl Iterator<Item = (&'static str, &str)> {
    [
        (
            "x_content_type_options",
            cfg.x_content_type_options.as_deref(),
        ),
        ("x_frame_options", cfg.x_frame_options.as_deref()),
        ("cache_control", cfg.cache_control.as_deref()),
        ("referrer_policy", cfg.referrer_policy.as_deref()),
        (
            "cross_origin_opener_policy",
            cfg.cross_origin_opener_policy.as_deref(),
        ),
        (
            "cross_origin_resource_policy",
            cfg.cross_origin_resource_policy.as_deref(),
        ),
        (
            "cross_origin_embedder_policy",
            cfg.cross_origin_embedder_policy.as_deref(),
        ),
        ("permissions_policy", cfg.permissions_policy.as_deref()),
        (
            "x_permitted_cross_domain_policies",
            cfg.x_permitted_cross_domain_policies.as_deref(),
        ),
        (
            "content_security_policy",
            cfg.content_security_policy.as_deref(),
        ),
        (
            "x_dns_prefetch_control",
            cfg.x_dns_prefetch_control.as_deref(),
        ),
        (
            "strict_transport_security",
            cfg.strict_transport_security.as_deref(),
        ),
    ]
    .into_iter()
    .filter_map(|(field, value)| value.map(|v| (field, v)))
}

fn check_auth_capacity_knobs(auth: Option<&AuthConfig>) -> Result<(), RmcpServerKitError> {
    if let Some(auth_cfg) = auth {
        if let Some(rl) = &auth_cfg.rate_limit {
            (rl.max_attempts_per_minute != 0).ok_or_else(|| {
                RmcpServerKitError::Config(
                    "auth.rate_limit.max_attempts_per_minute must be nonzero".into(),
                )
            })?;
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
        if let Some(mtls) = &auth_cfg.mtls {
            check_mtls_capacity_knobs(mtls)?;
        }
        auth_cfg.check_oauth_feature()?;
    }
    Ok(())
}

fn check_mtls_capacity_knobs(mtls: &MtlsConfig) -> Result<(), RmcpServerKitError> {
    (mtls.crl_max_concurrent_fetches != 0).ok_or_else(|| {
        RmcpServerKitError::Config("auth.mtls.crl_max_concurrent_fetches must be nonzero".into())
    })?;
    (mtls.crl_discovery_rate_per_min != 0).ok_or_else(|| {
        RmcpServerKitError::Config("auth.mtls.crl_discovery_rate_per_min must be nonzero".into())
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
    Ok(())
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
        reason = "internal unit tests legitimately read/write the deprecated `pub` fields they were designed to verify"
    )]
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        response::IntoResponse,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;

    use super::*;

    // -- startup task lifecycle --

    #[tokio::test]
    async fn external_shutdown_bridge_exits_when_internal_token_cancels() {
        let external = CancellationToken::new();
        let internal = CancellationToken::new();
        let bridge = spawn_external_shutdown_bridge(external.clone(), internal.clone());

        // The caller's token is never cancelled; only the server-internal one
        // is, as happens when startup fails after the bridge is spawned.
        internal.cancel();

        let joined = tokio::time::timeout(Duration::from_secs(2), bridge).await;
        assert!(
            joined.is_ok(),
            "bridge task must exit once the internal token is cancelled, \
             otherwise it leaks for the lifetime of the process"
        );
    }

    #[tokio::test]
    async fn external_shutdown_bridge_still_forwards_external_cancel() {
        let external = CancellationToken::new();
        let internal = CancellationToken::new();
        let bridge = spawn_external_shutdown_bridge(external.clone(), internal.clone());

        external.cancel();

        let joined = tokio::time::timeout(Duration::from_secs(2), bridge).await;
        assert!(joined.is_ok(), "bridge task must exit on external cancel");
        assert!(
            internal.is_cancelled(),
            "external cancellation must still propagate to the internal token"
        );
    }

    #[test]
    fn cancel_on_drop_cancels_its_token() {
        let ct = CancellationToken::new();
        {
            let _guard = CancelOnDrop(ct.clone());
            assert!(!ct.is_cancelled());
        }
        assert!(
            ct.is_cancelled(),
            "dropping the guard must cancel background startup tasks"
        );
    }

    #[test]
    fn validate_rejects_mtls_without_tls() {
        for (cert, key) in [
            (None, None),
            (Some("cert.pem"), None),
            (None, Some("key.pem")),
        ] {
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.mtls = Some(valid_mtls_config());
            let mut cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(auth);
            cfg.tls_cert_path = cert.map(Into::into);
            cfg.tls_key_path = key.map(Into::into);

            let err = cfg
                .validate()
                .expect_err("mTLS without both TLS paths must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("tls_cert_path") && msg.contains("tls_key_path"),
                "cert={cert:?} key={key:?}: {msg}"
            );
        }
    }

    #[test]
    fn validate_accepts_mtls_with_tls() {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let mut cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(auth);
        cfg.tls_cert_path = Some("cert.pem".into());
        cfg.tls_key_path = Some("key.pem".into());

        assert!(cfg.validate().is_ok(), "mTLS with both TLS paths is valid");
    }

    // -- McpServerConfig --

    #[test]
    fn server_config_new_defaults() {
        let cfg = McpServerConfig::new("0.0.0.0:8443", "test-server", "1.0.0");
        assert_eq!(cfg.bind_addr, "0.0.0.0:8443");
        assert_eq!(cfg.name, "test-server");
        assert_eq!(cfg.version, "1.0.0");
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
        assert!(cfg.auth.is_none());
        assert!(cfg.rbac.is_none());
        assert!(cfg.allowed_origins.is_empty());
        assert!(cfg.tool_rate_limit.is_none());
        assert!(cfg.readiness_check.is_none());
        assert_eq!(cfg.max_request_body, 1024 * 1024);
        assert_eq!(cfg.request_timeout, Duration::from_mins(2));
        assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
        assert!(!cfg.log_request_headers);
        assert_eq!(cfg.tls_handshake_timeout, Duration::from_secs(10));
        assert_eq!(cfg.max_concurrent_tls_handshakes, 256);
    }

    #[test]
    fn tls_handshake_builders_set_fields() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_tls_handshake_timeout(Duration::from_secs(3))
            .with_max_concurrent_tls_handshakes(64);
        assert_eq!(cfg.tls_handshake_timeout, Duration::from_secs(3));
        assert_eq!(cfg.max_concurrent_tls_handshakes, 64);
    }

    #[test]
    fn validate_rejects_zero_tls_handshake_timeout() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_tls_handshake_timeout(Duration::ZERO);
        let err = cfg.validate().expect_err("zero handshake timeout");
        assert!(err.to_string().contains("tls_handshake_timeout"));
    }

    #[test]
    fn validate_rejects_zero_max_concurrent_tls_handshakes() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_max_concurrent_tls_handshakes(0);
        let err = cfg.validate().expect_err("zero handshake concurrency");
        assert!(err.to_string().contains("max_concurrent_tls_handshakes"));
    }

    #[test]
    fn validate_consumes_and_proves() {
        // Valid config -> Validated wrapper, original is consumed.
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        let validated = cfg.validate().expect("valid config");
        // as_inner() gives read-only access to inner fields.
        assert_eq!(validated.as_inner().name, "test-server");
        // into_inner recovers the raw value.
        let raw = validated.into_inner();
        assert_eq!(raw.name, "test-server");

        // Invalid config (zero max_request_body) -> Err.
        let mut bad = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        bad.max_request_body = 0;
        assert!(bad.validate().is_err(), "zero body cap must fail validate");
    }

    #[test]
    fn validate_rejects_zero_max_concurrent_requests() {
        let cfg =
            McpServerConfig::new("127.0.0.1:8080", "test", "1.0.0").with_max_concurrent_requests(0);
        let err = cfg.validate().expect_err("zero concurrency cap must fail");
        assert!(
            format!("{err}").contains("max_concurrent_requests"),
            "error should mention max_concurrent_requests, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_zero_max_tracked_keys() {
        // Defaults mirror auth::default_max_attempts / default_idle_eviction
        // (module-private in auth.rs); spelled out here for review clarity.
        let rl = crate::auth::RateLimitConfig {
            max_attempts_per_minute: 30,
            pre_auth_max_per_minute: None,
            max_tracked_keys: 0,
            idle_eviction: Duration::from_secs(15 * 60),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let auth_cfg = AuthConfig {
            enabled: true,
            api_keys: Vec::new(),
            mtls: None,
            rate_limit: Some(rl),
            #[cfg(feature = "oauth")]
            oauth: None,
            #[cfg(not(feature = "oauth"))]
            oauth: None,
        };
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test", "1.0.0").with_auth(auth_cfg);
        let err = cfg.validate().expect_err("zero max_tracked_keys must fail");
        assert!(
            format!("{err}").contains("max_tracked_keys"),
            "error should mention max_tracked_keys, got: {err}"
        );
    }

    #[test]
    fn derive_allowed_hosts_includes_public_host() {
        let hosts = derive_allowed_hosts("0.0.0.0:8080", Some("https://mcp.example.com/mcp"));
        assert!(
            hosts.iter().any(|h| h == "mcp.example.com"),
            "public_url host must be allowed"
        );
    }

    #[test]
    fn derive_allowed_hosts_includes_bind_authority() {
        let hosts = derive_allowed_hosts("127.0.0.1:8080", None);
        assert!(
            hosts.iter().any(|h| h == "127.0.0.1"),
            "bind host must be allowed"
        );
        assert!(
            hosts.iter().any(|h| h == "127.0.0.1:8080"),
            "bind authority must be allowed"
        );
    }

    // -- healthz --

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let resp = healthz().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert!(
            json.get("name").is_none(),
            "healthz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "healthz must not expose version"
        );
    }

    // -- readyz --

    #[tokio::test]
    async fn readyz_returns_ok_when_ready() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": true, "db": "connected"}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], true);
        assert!(
            json.get("name").is_none(),
            "readyz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "readyz must not expose version"
        );
        assert_eq!(json["db"], "connected");
    }

    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": false}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_ready_missing() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"status": "starting"}) }));
        let resp = readyz(check).await.into_response();
        // Missing "ready" field defaults to false -> 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // -- normalize_peer_addr_middleware / PeerAddr --

    /// Build a test router that reports the request's peer-address
    /// extensions as `"<ConnectInfo>|<PeerAddr>"` (empty when absent).
    fn peer_probe_router() -> axum::Router {
        async fn probe(req: Request<Body>) -> String {
            let ci = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.to_string())
                .unwrap_or_default();
            let pa = req
                .extensions()
                .get::<PeerAddr>()
                .map(|p| p.addr.to_string())
                .unwrap_or_default();
            format!("{ci}|{pa}")
        }
        axum::Router::new()
            .route("/probe", axum::routing::get(probe))
            .layer(axum::middleware::from_fn(|req, next| {
                normalize_peer_addr_middleware(None, req, next)
            }))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn normalize_preserves_existing_connect_info_and_mirrors_peer_addr() {
        // Precedence proof: when both extensions exist with DIFFERENT
        // addresses, ConnectInfo<SocketAddr> wins and is never overwritten.
        let plain: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let tls: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        let req = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(plain))
            .extension(ConnectInfo(TlsConnInfo::new(tls, None)))
            .body(Body::empty())
            .unwrap();
        let resp = peer_probe_router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, format!("{plain}|{plain}"));
    }

    #[tokio::test]
    async fn normalize_inserts_connect_info_and_peer_addr_from_tls() {
        let tls: SocketAddr = "192.168.1.7:50443".parse().unwrap();
        let req = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(TlsConnInfo::new(tls, None)))
            .body(Body::empty())
            .unwrap();
        let resp = peer_probe_router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, format!("{tls}|{tls}"));
    }

    #[tokio::test]
    async fn normalize_no_op_without_any_connect_info() {
        let req = Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap();
        let resp = peer_probe_router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "|");
    }

    #[tokio::test]
    async fn peer_addr_extractor_rejects_when_absent() {
        async fn h(peer: PeerAddr) -> String {
            peer.addr.to_string()
        }
        let app = axum::Router::new().route("/p", axum::routing::get(h));
        let req = Request::builder().uri("/p").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn peer_addr_extractor_returns_value_when_present() {
        async fn h(peer: PeerAddr) -> String {
            peer.addr.to_string()
        }
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let app = axum::Router::new().route("/p", axum::routing::get(h));
        let req = Request::builder()
            .uri("/p")
            .extension(PeerAddr::new(addr))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, addr.to_string());
    }

    #[tokio::test]
    async fn peer_addr_via_extension_extractor() {
        async fn h(axum::Extension(peer): axum::Extension<PeerAddr>) -> String {
            peer.addr.to_string()
        }
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let app = axum::Router::new().route("/p", axum::routing::get(h));
        let req = Request::builder()
            .uri("/p")
            .extension(PeerAddr::new(addr))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, addr.to_string());
    }

    // -- extra_route_rate_limit_middleware --

    /// Probe router with the extra-route limiter installed, mirroring
    /// the layer-before-merge wiring in `build_app_router`.
    fn limited_router(per_minute: u32) -> axum::Router {
        limited_router_with_burst(per_minute, None)
    }

    /// Probe router with an explicit burst capacity.
    fn limited_router_with_burst(per_minute: u32, burst: Option<u32>) -> axum::Router {
        limited_router_full(per_minute, burst, &[])
    }

    /// Probe router with explicit burst and exempt paths. `/limited`
    /// and `/exempt` are both registered so exemption interplay can be
    /// asserted on one limiter instance.
    fn limited_router_full(
        per_minute: u32,
        burst: Option<u32>,
        exempt_paths: &[&str],
    ) -> axum::Router {
        let limiter = build_extra_route_rate_limiter_with_policy(
            per_minute,
            burst,
            KeyEvictionPolicy::default(),
            NonZeroUsize::new(EXTRA_ROUTE_MAX_TRACKED_KEYS).unwrap_or(NonZeroUsize::MIN),
        );
        let exempt: Arc<std::collections::HashSet<String>> =
            Arc::new(exempt_paths.iter().map(|s| (*s).to_owned()).collect());
        axum::Router::new()
            .route("/limited", axum::routing::get(|| async { "ok" }))
            .route("/exempt", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let l = Arc::clone(&limiter);
                let e = Arc::clone(&exempt);
                extra_route_rate_limit_middleware(l, e, req, next)
            }))
    }

    fn limited_req(ip: &str) -> Request<Body> {
        limited_req_to(ip, "/limited")
    }

    fn limited_req_to(ip: &str, path: &str) -> Request<Body> {
        let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
        Request::builder()
            .uri(path)
            .extension(ConnectInfo(addr))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn extra_route_limiter_denies_over_quota() {
        let app = limited_router(2);
        for i in 0..2 {
            let resp = app.clone().oneshot(limited_req("10.1.1.1")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
        }
        let resp = app.clone().oneshot(limited_req("10.1.1.1")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_string(resp).await;
        assert!(
            body.contains("too many requests to application routes"),
            "deny body should match the limiter message, got: {body}"
        );
    }

    fn one_tracked_key() -> NonZeroUsize {
        NonZeroUsize::new(1).unwrap_or(NonZeroUsize::MIN)
    }

    #[tokio::test]
    async fn extra_route_limiter_capacity_full_returns_503_without_retry_after() {
        let limiter = build_extra_route_rate_limiter_with_policy(
            10,
            None,
            KeyEvictionPolicy::RejectNew,
            one_tracked_key(),
        );
        let exempt = Arc::new(std::collections::HashSet::new());
        let app = axum::Router::new()
            .route("/limited", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let l = Arc::clone(&limiter);
                let e = Arc::clone(&exempt);
                extra_route_rate_limit_middleware(l, e, req, next)
            }));
        let established = app.clone().oneshot(limited_req("10.1.1.1")).await.unwrap();
        assert_eq!(established.status(), StatusCode::OK);

        let denied = app.clone().oneshot(limited_req("10.1.1.2")).await.unwrap();

        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(denied.headers().get(header::RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn extra_route_limiter_isolates_keys() {
        let app = limited_router(2);
        for _ in 0..2 {
            let resp = app.clone().oneshot(limited_req("10.2.2.2")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let exhausted = app.clone().oneshot(limited_req("10.2.2.2")).await.unwrap();
        assert_eq!(exhausted.status(), StatusCode::TOO_MANY_REQUESTS);
        // A different source IP still has a fresh bucket.
        let other = app.clone().oneshot(limited_req("10.3.3.3")).await.unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extra_route_limiter_bounds_requests_without_peer() {
        // Was `fails_open_without_peer`. A request whose source address
        // cannot be resolved must NOT be exempt from rate limiting; such
        // requests share one bounded `Unattributed` bucket.
        let app = limited_router(1);
        let mk = || {
            Request::builder()
                .uri("/limited")
                .body(Body::empty())
                .unwrap()
        };
        let first = app.clone().oneshot(mk()).await.unwrap();
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "first request consumes quota"
        );
        let second = app.clone().oneshot(mk()).await.unwrap();
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "unattributable requests must share a bounded bucket, not bypass the limiter"
        );
    }

    #[test]
    fn limiter_client_key_falls_back_to_unattributed() {
        let empty = axum::http::Extensions::new();
        assert_eq!(limiter_client_key(&empty), RateLimitKey::Unattributed);
    }

    #[test]
    fn unattributed_key_is_distinct_from_unspecified_ip() {
        // Regression guard: a sentinel `0.0.0.0` would collide here,
        // because trusted-forwarder mode derives ClientIp from a header
        // and `crate::forwarded` does not filter unspecified addresses.
        let unspecified = RateLimitKey::Ip("0.0.0.0".parse::<IpAddr>().unwrap());
        assert_ne!(unspecified, RateLimitKey::Unattributed);

        let mut set = std::collections::HashSet::new();
        set.insert(unspecified);
        set.insert(RateLimitKey::Unattributed);
        assert_eq!(set.len(), 2, "the two keys must hash to distinct buckets");
    }

    #[test]
    fn rate_limit_key_display_does_not_fabricate_an_ip() {
        assert_eq!(
            RateLimitKey::Ip("10.1.2.3".parse::<IpAddr>().unwrap()).to_string(),
            "10.1.2.3"
        );
        assert_eq!(RateLimitKey::Unattributed.to_string(), "unattributed");
    }

    #[tokio::test]
    async fn extra_route_limiter_extracts_tls_conn_info() {
        let app = limited_router(2);
        let mk = || {
            let addr: SocketAddr = "192.168.9.9:55555".parse().unwrap();
            Request::builder()
                .uri("/limited")
                .extension(ConnectInfo(TlsConnInfo::new(addr, None)))
                .body(Body::empty())
                .unwrap()
        };
        for _ in 0..2 {
            assert_eq!(
                app.clone().oneshot(mk()).await.unwrap().status(),
                StatusCode::OK
            );
        }
        let resp = app.clone().oneshot(mk()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn extra_route_limiter_exempt_path_bypasses_quota() {
        // rate=1: a single non-exempt request exhausts the bucket, yet
        // repeated exempt-path requests all pass and consume no budget.
        let app = limited_router_full(1, None, &["/exempt"]);
        for i in 0..5 {
            let resp = app
                .clone()
                .oneshot(limited_req_to("10.6.6.6", "/exempt"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "exempt request {i}");
        }
        // Budget untouched by exempt traffic: first limited request OK…
        let resp = app.clone().oneshot(limited_req("10.6.6.6")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // …second is denied (exemption did not leak onto /limited).
        let resp = app.clone().oneshot(limited_req("10.6.6.6")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn extra_route_limiter_exemption_is_raw_exact_match() {
        // Trailing-slash and case variants are NOT exempt (fail-closed:
        // a mismatch keeps the request limited, never the reverse).
        let app = limited_router_full(1, None, &["/exempt"]);
        let ok = app
            .clone()
            .oneshot(limited_req_to("10.7.7.7", "/exempt/"))
            .await
            .unwrap();
        assert_eq!(
            ok.status(),
            StatusCode::NOT_FOUND,
            "variant path routes 404"
        );
        // The variant consumed limiter budget (it was not exempt):
        let denied = app
            .clone()
            .oneshot(limited_req_to("10.7.7.7", "/limited"))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn extra_route_limiter_deny_increments_counter_exempt_does_not() {
        let metrics = Arc::new(crate::metrics::McpMetrics::new().unwrap());
        let app = limited_router_full(1, None, &["/exempt"]);
        let mk = |path: &str| {
            let addr: SocketAddr = "10.8.8.8:40000".parse().unwrap();
            Request::builder()
                .uri(path)
                .extension(ConnectInfo(addr))
                .extension(Arc::clone(&metrics))
                .body(Body::empty())
                .unwrap()
        };
        let counter = || {
            metrics
                .rate_limited_total
                .with_label_values(&["extra_route"])
                .get()
        };
        // Exempt traffic: no budget, no counter.
        for _ in 0..3 {
            assert_eq!(
                app.clone().oneshot(mk("/exempt")).await.unwrap().status(),
                StatusCode::OK
            );
        }
        assert_eq!(counter(), 0, "exempt requests must not count as denies");
        // Exhaust then deny: counter increments exactly on the deny.
        assert_eq!(
            app.clone().oneshot(mk("/limited")).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(counter(), 0);
        assert_eq!(
            app.clone().oneshot(mk("/limited")).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(counter(), 1, "deny must increment the extra_route label");
    }

    #[test]
    fn validate_rejects_exempt_paths_without_base_knob() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit_exempt_paths(["/ok"]);
        let err = cfg.validate().expect_err("exempt paths without rate limit");
        assert!(err.to_string().contains("requires extra_route_rate_limit"));
    }

    #[test]
    fn validate_rejects_malformed_exempt_paths() {
        for bad in ["", "no-slash"] {
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_extra_route_rate_limit(10)
                .with_extra_route_rate_limit_exempt_paths([bad]);
            let err = cfg.validate().expect_err("malformed exempt path");
            assert!(
                err.to_string()
                    .contains("must be non-empty and start with '/'"),
                "entry {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn validate_accepts_wellformed_exempt_paths() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit(10)
            .with_extra_route_rate_limit_exempt_paths(["/.well-known/oauth-authorization-server"]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_extra_route_rate_limit() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit(0);
        let err = cfg.validate().expect_err("zero extra route rate limit");
        assert!(err.to_string().contains("extra_route_rate_limit"));
    }

    #[tokio::test]
    async fn extra_route_limiter_burst_allows_initial_spike() {
        let app = limited_router_with_burst(1, Some(3));
        for i in 0..3 {
            let resp = app.clone().oneshot(limited_req("10.4.4.4")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "burst request {i}");
        }
        let resp = app.clone().oneshot(limited_req("10.4.4.4")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn extra_route_limiter_deny_sets_retry_after() {
        let app = limited_router(1);
        let ok = app.clone().oneshot(limited_req("10.5.5.5")).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let denied = app.clone().oneshot(limited_req("10.5.5.5")).await.unwrap();
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = denied
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After present")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(retry_after >= 1, "delta-seconds must be >= 1");
    }

    #[test]
    fn validate_rejects_zero_burst_knobs() {
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_tool_rate_limit(10)
            .with_tool_rate_limit_burst(0)
            .validate()
            .expect_err("zero tool burst");
        assert!(err.to_string().contains("tool_rate_limit_burst"));

        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_extra_route_rate_limit(10)
            .with_extra_route_rate_limit_burst(0)
            .validate()
            .expect_err("zero extra route burst");
        assert!(err.to_string().contains("extra_route_rate_limit_burst"));
    }

    #[test]
    fn validate_rejects_orphan_burst_knobs() {
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_tool_rate_limit_burst(5)
            .validate()
            .expect_err("orphan tool burst");
        assert!(err.to_string().contains("requires tool_rate_limit"));

        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_extra_route_rate_limit_burst(5)
            .validate()
            .expect_err("orphan extra route burst");
        assert!(err.to_string().contains("requires extra_route_rate_limit"));
    }

    #[test]
    fn validate_rejects_zero_auth_bursts() {
        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_burst(0));
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .validate()
            .expect_err("zero auth burst");
        assert!(err.to_string().contains("rate_limit.burst"));

        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_pre_auth_burst(0));
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .validate()
            .expect_err("zero pre-auth burst");
        assert!(err.to_string().contains("pre_auth_burst"));
    }

    #[test]
    fn validate_rejects_zero_pre_auth_max_per_minute() {
        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_pre_auth_max_per_minute(0));
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .validate()
            .expect_err("zero pre-auth rate");
        assert!(err.to_string().contains("pre_auth_max_per_minute"));
    }

    fn valid_mtls_config() -> MtlsConfig {
        MtlsConfig {
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

    #[test]
    fn validate_rejects_zero_crl_max_response_bytes() {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_response_bytes = 0;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(mtls);

        // TLS paths are required alongside mTLS, else validation reports that
        // pairing error first and never reaches the capacity knobs.
        let mut cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(auth);
        cfg.tls_cert_path = Some("cert.pem".into());
        cfg.tls_key_path = Some("key.pem".into());

        let err = cfg.validate().expect_err("zero CRL response cap");
        assert!(err.to_string().contains("crl_max_response_bytes"));
    }

    /// `pre_auth_burst` without `pre_auth_max_per_minute` is LEGAL: the
    /// pre-auth base rate always resolves (max_attempts_per_minute x 10).
    #[test]
    fn validate_accepts_pre_auth_burst_without_explicit_pre_auth_rate() {
        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(crate::auth::RateLimitConfig::new(10).with_pre_auth_burst(50));
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(auth);
        assert!(cfg.validate().is_ok(), "pre_auth_burst has no orphan rule");
    }

    // -- trusted-forwarder mode (ClientIp / ForwardedHeaderMode) --

    #[test]
    fn trusted_forwarder_max_entries_bounds_are_enforced() {
        let cfg = |n: usize| {
            McpServerConfig::new("127.0.0.1:8080", "t", "0")
                .with_trusted_forwarder_max_entries(n)
                .validate()
        };
        assert!(cfg(0).is_err(), "0 would pin every client to the proxy");
        assert!(
            cfg(crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES + 1).is_err(),
            "above the ceiling would re-open the header-bomb vector"
        );
        assert!(cfg(1).is_ok());
        assert!(cfg(crate::forwarded::MAX_SCANNED_ENTRIES).is_ok());
        assert!(cfg(crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES).is_ok());
    }

    #[test]
    fn trusted_forwarder_max_entries_defaults_to_the_module_constant() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "0");
        assert_eq!(
            cfg.trusted_forwarder_max_entries,
            crate::forwarded::MAX_SCANNED_ENTRIES
        );
    }

    fn forward_resolver(trusted: &[&str], mode: ForwardedHeaderMode) -> Arc<ForwardResolver> {
        Arc::new(ForwardResolver {
            trusted: trusted.iter().map(|s| s.parse().unwrap()).collect(),
            mode,
            max_scanned_entries: crate::forwarded::MAX_SCANNED_ENTRIES,
        })
    }

    /// Probe router reporting `"<PeerAddr ip>|<ClientIp>"`.
    fn forwarded_probe_router(resolver: Option<Arc<ForwardResolver>>) -> axum::Router {
        async fn probe(req: Request<Body>) -> String {
            let pa = req
                .extensions()
                .get::<PeerAddr>()
                .map(|p| p.addr.ip().to_string())
                .unwrap_or_default();
            let ci = req
                .extensions()
                .get::<ClientIp>()
                .map(|c| c.ip.to_string())
                .unwrap_or_default();
            format!("{pa}|{ci}")
        }
        axum::Router::new()
            .route("/probe", axum::routing::get(probe))
            .layer(axum::middleware::from_fn(move |req, next| {
                let r = resolver.clone();
                normalize_peer_addr_middleware(r, req, next)
            }))
    }

    fn probe_req(peer: &str, header: Option<(&str, &str)>) -> Request<Body> {
        let addr: SocketAddr = peer.parse().unwrap();
        let mut builder = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(addr));
        if let Some((name, value)) = header {
            builder = builder.header(name, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn client_ip_equals_direct_without_resolver() {
        let app = forwarded_probe_router(None);
        let resp = app
            .oneshot(probe_req(
                "10.1.2.3:4444",
                Some(("x-forwarded-for", "203.0.113.7")),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_string(resp).await,
            "10.1.2.3|10.1.2.3",
            "feature off: header ignored, ClientIp == direct"
        );
    }

    #[tokio::test]
    async fn client_ip_resolved_for_trusted_peer() {
        let app = forwarded_probe_router(Some(forward_resolver(
            &["10.0.0.0/8"],
            ForwardedHeaderMode::XForwardedFor,
        )));
        let resp = app
            .oneshot(probe_req(
                "10.0.0.1:9999",
                Some(("x-forwarded-for", "203.0.113.7")),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_string(resp).await,
            "10.0.0.1|203.0.113.7",
            "PeerAddr stays direct while ClientIp resolves"
        );
    }

    #[tokio::test]
    async fn client_ip_falls_back_to_direct_on_malformed_header() {
        let app = forwarded_probe_router(Some(forward_resolver(
            &["10.0.0.0/8"],
            ForwardedHeaderMode::XForwardedFor,
        )));
        let resp = app
            .oneshot(probe_req(
                "10.0.0.1:9999",
                Some(("x-forwarded-for", "not-an-ip")),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_string(resp).await,
            "10.0.0.1|10.0.0.1",
            "malformed chain falls back to the direct peer"
        );
    }

    #[test]
    fn forwarded_header_mode_deserializes_kebab_case() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            mode: ForwardedHeaderMode,
        }
        let w: Wrapper = toml::from_str(r#"mode = "x-forwarded-for""#).unwrap();
        assert_eq!(w.mode, ForwardedHeaderMode::XForwardedFor);
        let w: Wrapper = toml::from_str(r#"mode = "forwarded""#).unwrap();
        assert_eq!(w.mode, ForwardedHeaderMode::Forwarded);
        assert!(
            toml::from_str::<Wrapper>(r#"mode = "XForwardedFor""#).is_err(),
            "PascalCase wire value must be rejected"
        );
    }

    #[test]
    fn validate_rejects_bad_trusted_proxy_entry() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_trusted_proxies(["not-a-cidr"]);
        let err = cfg.validate().expect_err("bad CIDR");
        assert!(err.to_string().contains("trusted_proxies"));
    }

    #[test]
    fn validate_rejects_zero_prefix_trusted_proxy() {
        for entry in ["0.0.0.0/0", "::/0"] {
            let cfg =
                McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_trusted_proxies([entry]);
            let err = cfg.validate().expect_err("zero-prefix CIDR");
            assert!(
                err.to_string().contains("prefix length 0"),
                "entry {entry}: {err}"
            );
        }
    }

    #[test]
    fn validate_accepts_cidr_and_bare_ip_proxy_entries() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_trusted_proxies([
            "10.0.0.0/8",
            "192.0.2.1",
            "2001:db8::1",
        ]);
        assert!(cfg.validate().is_ok(), "CIDRs and bare IPs are accepted");
    }

    #[test]
    fn validate_rejects_forwarded_header_without_proxies() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_forwarded_header(ForwardedHeaderMode::Forwarded);
        let err = cfg.validate().expect_err("mode without proxies");
        assert!(err.to_string().contains("requires trusted_proxies"));
    }

    // -- origin_check_middleware --

    /// Build a test router with origin check middleware and a simple handler.
    fn origin_router(origins: Vec<String>, log_request_headers: bool) -> axum::Router {
        let allowed: Arc<[String]> = Arc::from(origins);
        axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let a = Arc::clone(&allowed);
                origin_check_middleware(a, log_request_headers, req, next)
            }))
    }

    #[tokio::test]
    async fn origin_allowed_passes() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn origin_rejected_returns_403() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_origin_header_passes() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn empty_allowlist_rejects_any_origin() {
        let app = origin_router(vec![], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://anything.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn empty_allowlist_passes_without_origin() {
        let app = origin_router(vec![], false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn format_request_headers_redacts_sensitive_values() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer secret-token".parse().unwrap());
        headers.insert("cookie", "sid=abc".parse().unwrap());
        headers.insert("x-request-id", "req-123".parse().unwrap());

        let out = format_request_headers_for_log(&headers);
        assert!(out.contains("authorization: [REDACTED]"));
        assert!(out.contains("cookie: [REDACTED]"));
        assert!(out.contains("x-request-id: req-123"));
        assert!(!out.contains("secret-token"));
    }

    #[test]
    fn format_request_headers_redacts_forwarding_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("forwarded", "for=203.0.113.9;by=10.1.2.3".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.9, 10.1.2.3".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.9".parse().unwrap());
        headers.insert("x-request-id", "req-123".parse().unwrap());

        let out = format_request_headers_for_log(&headers);
        for name in ["forwarded", "x-forwarded-for", "x-real-ip"] {
            assert!(
                out.contains(&format!("{name}: [REDACTED]")),
                "{name} carries client IP / proxy topology and must not reach logs; got {out}"
            );
        }
        assert!(
            !out.contains("203.0.113.9") && !out.contains("10.1.2.3"),
            "no forwarded address may survive redaction; got {out}"
        );
        assert!(out.contains("x-request-id: req-123"));
    }

    // -- security_headers_middleware --

    fn security_router(is_tls: bool) -> axum::Router {
        security_router_with(is_tls, SecurityHeadersConfig::default())
    }

    fn security_router_with(is_tls: bool, cfg: SecurityHeadersConfig) -> axum::Router {
        let cfg = Arc::new(cfg);
        axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let c = Arc::clone(&cfg);
                security_headers_middleware(is_tls, c, req, next)
            }))
    }

    #[tokio::test]
    async fn security_headers_set_on_response() {
        let app = security_router(false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let h = resp.headers();
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "deny");
        assert_eq!(h.get("cache-control").unwrap(), "no-store, max-age=0");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
        assert_eq!(
            h.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            h.get("cross-origin-embedder-policy").unwrap(),
            "require-corp"
        );
        assert_eq!(h.get("x-permitted-cross-domain-policies").unwrap(), "none");
        assert!(
            h.get("permissions-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("camera=()"),
            "permissions-policy must restrict browser features"
        );
        assert_eq!(
            h.get("content-security-policy").unwrap(),
            "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        );
        assert_eq!(h.get("x-dns-prefetch-control").unwrap(), "off");
        // No HSTS when TLS is off.
        assert!(h.get("strict-transport-security").is_none());
    }

    #[tokio::test]
    async fn hsts_set_when_tls_enabled() {
        let app = security_router(true);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let hsts = resp.headers().get("strict-transport-security").unwrap();
        assert!(
            hsts.to_str().unwrap().contains("max-age=63072000"),
            "HSTS must set 2-year max-age"
        );
    }

    #[tokio::test]
    async fn default_csp_matches_guideline() {
        let app = security_router(false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        );
    }

    #[tokio::test]
    async fn operator_csp_override_still_wins() {
        let cfg = SecurityHeadersConfig {
            content_security_policy: Some("default-src 'self'".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, cfg);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
    }

    // -- SecurityHeadersConfig validation + override semantics --

    /// Build a minimal config with a custom SecurityHeadersConfig and
    /// drive it through `check()`. Returns the result so individual
    /// tests can assert on success or specific error messages.
    fn check_with_security_headers(
        headers: SecurityHeadersConfig,
    ) -> Result<(), RmcpServerKitError> {
        let cfg =
            McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0").with_security_headers(headers);
        cfg.check()
    }

    #[test]
    fn security_headers_config_default_validates() {
        check_with_security_headers(SecurityHeadersConfig::default())
            .expect("default SecurityHeadersConfig must validate");
    }

    #[test]
    fn security_headers_config_validate_accepts_empty_string() {
        // All twelve fields explicitly set to "" -> omit-everything mode.
        let h = SecurityHeadersConfig {
            x_content_type_options: Some(String::new()),
            x_frame_options: Some(String::new()),
            cache_control: Some(String::new()),
            referrer_policy: Some(String::new()),
            cross_origin_opener_policy: Some(String::new()),
            cross_origin_resource_policy: Some(String::new()),
            cross_origin_embedder_policy: Some(String::new()),
            permissions_policy: Some(String::new()),
            x_permitted_cross_domain_policies: Some(String::new()),
            content_security_policy: Some(String::new()),
            x_dns_prefetch_control: Some(String::new()),
            strict_transport_security: Some(String::new()),
        };
        check_with_security_headers(h).expect("Some(\"\") on every field must validate (omit-all)");
    }

    #[test]
    fn security_headers_config_validate_rejects_bad_value() {
        // 0x07 (BEL) is not a valid HTTP header value char.
        let h = SecurityHeadersConfig {
            referrer_policy: Some("\u{0007}".into()),
            ..SecurityHeadersConfig::default()
        };
        let err = check_with_security_headers(h)
            .expect_err("control char in referrer_policy must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("referrer_policy"),
            "error must name the offending field, got: {msg}"
        );
    }

    #[test]
    fn security_headers_config_validate_rejects_hsts_preload() {
        let h = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=63072000; includeSubDomains; preload".into()),
            ..SecurityHeadersConfig::default()
        };
        let err = check_with_security_headers(h).expect_err("HSTS with preload must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("strict_transport_security"),
            "error must name the field, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("preload"),
            "error must mention `preload`, got: {msg}"
        );
    }

    #[test]
    fn security_headers_config_validate_rejects_hsts_preload_uppercase() {
        // Case-insensitive match.
        let h = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=600; PRELOAD".into()),
            ..SecurityHeadersConfig::default()
        };
        check_with_security_headers(h).expect_err("HSTS preload check must be case-insensitive");
    }

    #[tokio::test]
    async fn security_headers_override_honored() {
        // Override X-Frame-Options to SAMEORIGIN.
        let h = SecurityHeadersConfig {
            x_frame_options: Some("SAMEORIGIN".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, h);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let xfo = resp.headers().get("x-frame-options").unwrap();
        assert_eq!(xfo, "SAMEORIGIN");
    }

    #[tokio::test]
    async fn security_headers_empty_string_omits() {
        // Empty string on referrer-policy -> header absent.
        let h = SecurityHeadersConfig {
            referrer_policy: Some(String::new()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, h);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            resp.headers().get("referrer-policy").is_none(),
            "Some(\"\") must omit the header"
        );
        // Other defaults should still be present.
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn security_headers_hsts_only_when_tls() {
        // HSTS override is irrelevant when TLS is off.
        let h = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=600".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, h);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.headers().get("strict-transport-security").is_none(),
            "HSTS must remain absent on plaintext deployments even with override"
        );
    }

    // -- oauth_token_cache_headers_middleware --

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_token_cache_headers_set_pragma_and_vary() {
        let app = axum::Router::new()
            .route("/token", axum::routing::post(|| async { "{}" }))
            .layer(axum::middleware::from_fn(
                oauth_token_cache_headers_middleware,
            ));
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let h = resp.headers();
        assert_eq!(
            h.get("pragma").unwrap(),
            "no-cache",
            "RFC 6749 §5.1: token responses must set Pragma: no-cache"
        );
        let vary_values: Vec<String> = h
            .get_all("vary")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        assert!(
            vary_values
                .iter()
                .any(|v| v.eq_ignore_ascii_case("Authorization")),
            "RFC 6750 §5.4: Vary must include Authorization, got {vary_values:?}"
        );
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_token_cache_headers_preserve_existing_vary() {
        // Simulates a handler/layer that already set `Vary: Accept-Encoding`
        // (e.g. compression). Our middleware must APPEND, not REPLACE.
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::post(|| async {
                    axum::response::Response::builder()
                        .header("vary", "Accept-Encoding")
                        .body(Body::from("{}"))
                        .unwrap()
                }),
            )
            .layer(axum::middleware::from_fn(
                oauth_token_cache_headers_middleware,
            ));
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let vary: Vec<String> = resp
            .headers()
            .get_all("vary")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        assert!(
            vary.iter().any(|v| v.contains("Accept-Encoding")),
            "must preserve pre-existing Vary value, got {vary:?}"
        );
        assert!(
            vary.iter().any(|v| v.contains("Authorization")),
            "must append Authorization to Vary, got {vary:?}"
        );
    }

    // -- version endpoint --

    #[test]
    fn version_omits_build_fingerprint_by_default() {
        let v = version_payload("my-server", "1.2.3", false);
        assert_eq!(v["name"], "my-server");
        assert_eq!(v["version"], "1.2.3");
        assert!(v["rmcp_server_kit_version"].is_string());
        assert!(
            v.get("build_git_sha").is_none(),
            "build sha must be hidden by default"
        );
        assert!(v.get("build_timestamp").is_none());
        assert!(v.get("rust_version").is_none());
    }

    #[test]
    fn version_exposes_all_when_enabled() {
        let v = version_payload("my-server", "1.2.3", true);
        assert!(v["build_git_sha"].is_string());
        assert!(v["build_timestamp"].is_string());
        assert!(v["rust_version"].is_string());
        assert!(v["rmcp_server_kit_version"].is_string());
    }

    // -- concurrency limit layer --

    #[tokio::test]
    async fn concurrency_limit_layer_composes_and_serves() {
        // We only assert the layer stack compiles and a single request
        // below the cap still succeeds. True back-pressure behaviour
        // requires a live HTTP server and is covered by integration tests.
        let app = axum::Router::new()
            .route("/ok", axum::routing::get(|| async { "ok" }))
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::error_handling::HandleErrorLayer::new(
                        |_err: tower::BoxError| async { StatusCode::SERVICE_UNAVAILABLE },
                    ))
                    .layer(tower::load_shed::LoadShedLayer::new())
                    .layer(tower::limit::ConcurrencyLimitLayer::new(4)),
            );
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -- compression layer --

    #[tokio::test]
    async fn compression_layer_gzip_encodes_response() {
        use tower_http::compression::Predicate as _;

        let big_body = "a".repeat(4096);
        let app = axum::Router::new()
            .route(
                "/big",
                axum::routing::get(move || {
                    let body = big_body.clone();
                    async move { body }
                }),
            )
            .layer(
                tower_http::compression::CompressionLayer::new()
                    .gzip(true)
                    .br(true)
                    .compress_when(
                        tower_http::compression::DefaultPredicate::new()
                            .and(tower_http::compression::predicate::SizeAbove::new(1024)),
                    ),
            );

        let req = Request::builder()
            .uri("/big")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
    }

    // -- TlsListener handshake timeout --

    #[tokio::test]
    async fn tls_handshake_timeout_reaps_idle_connections() {
        use tokio::io::AsyncReadExt as _;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Self-signed cert material on disk (TlsListener::new takes paths).
        let key = rcgen::KeyPair::generate().expect("generate key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("cert params")
            .self_signed(&key)
            .expect("self-signed cert");
        let dir = std::env::temp_dir().join(format!(
            "rmcp-server-kit-hs-timeout-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir).await.expect("temp dir");
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        tokio::fs::write(&cert_path, cert.pem())
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, key.serialize_pem())
            .await
            .expect("write key");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let tls = TlsListener::new(
            listener,
            &cert_path,
            &key_path,
            None,
            None,
            Duration::from_millis(200),
            8, // custom concurrency cap: proves the plumbing end-to-end
        )
        .expect("tls listener");
        let addr = axum::serve::Listener::local_addr(&tls).expect("local addr");

        // Connect and send NOTHING: the handshake worker must time out
        // after 200ms and drop the stream, which the client observes as
        // EOF or a reset well within the 2s deadline.
        let mut idle = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut buf = [0_u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut buf))
            .await
            .expect("server must reap the idle handshake within its timeout");
        match read {
            Ok(0) | Err(_) => {} // EOF or reset: connection was dropped.
            Ok(n) => panic!("unexpected {n} bytes from server during reaped handshake"),
        }

        drop(tls);
    }

    // -- M5: OWASP security headers reach early / fallback responses --

    fn assert_owasp_headers(resp: &axum::response::Response, ctx: &str) {
        let h = resp.headers();
        assert!(
            h.contains_key("x-content-type-options"),
            "{ctx}: missing X-Content-Type-Options"
        );
        assert!(
            h.contains_key("x-frame-options"),
            "{ctx}: missing X-Frame-Options"
        );
        assert!(
            h.contains_key("strict-transport-security"),
            "{ctx}: missing Strict-Transport-Security"
        );
        assert!(
            h.contains_key(header::CONTENT_SECURITY_POLICY),
            "{ctx}: missing Content-Security-Policy"
        );
    }

    fn m5_router(configure: impl FnOnce(&mut McpServerConfig)) -> axum::Router {
        #[derive(Clone)]
        struct H;
        impl ServerHandler for H {}
        // TLS paths make `is_tls` true so HSTS is emitted. The paths are never
        // read: these tests drive only the axum router via `oneshot`, not the
        // TLS listener.
        let mut config = McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0")
            .with_allowed_origins(["http://good.example"])
            .with_tls("unused.crt", "unused.key");
        configure(&mut config);
        let (router, _params) = build_app_router(config, || H).expect("build_app_router");
        router
    }

    /// An `extra_router` route that exactly overlaps a framework route makes
    /// `axum::Router::merge` panic during `build_app_router`. This pins that
    /// upstream behaviour so the documented contract on `with_extra_router`
    /// cannot silently stop holding.
    #[test]
    #[should_panic(expected = "Overlapping method route")]
    fn extra_router_exact_overlap_with_framework_route_panics() {
        #[derive(Clone)]
        struct H;
        impl ServerHandler for H {}
        let config = McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0").with_extra_router(
            axum::Router::new().route("/healthz", axum::routing::get(|| async { "mine" })),
        );
        let _ = build_app_router(config, || H);
    }

    /// The complement: a path *under* a framework prefix that does not exactly
    /// overlap an existing route is accepted without complaint. Documented as
    /// the caller's responsibility on `with_extra_router`.
    #[test]
    fn extra_router_non_overlapping_path_under_framework_prefix_is_accepted() {
        #[derive(Clone)]
        struct H;
        impl ServerHandler for H {}
        let config = McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0").with_extra_router(
            axum::Router::new().route("/admin/custom", axum::routing::get(|| async { "mine" })),
        );
        assert!(
            build_app_router(config, || H).is_ok(),
            "non-overlapping path under a framework prefix must merge cleanly"
        );
    }

    #[tokio::test]
    async fn headers_on_rejected_origin_403() {
        let app = m5_router(|_| {});
        let req = Request::builder()
            .uri("/healthz")
            .header(header::ORIGIN, "http://evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_owasp_headers(&resp, "origin-403");
    }

    #[tokio::test]
    async fn headers_on_cors_preflight() {
        let app = m5_router(|_| {});
        let req = Request::builder()
            .method(axum::http::Method::OPTIONS)
            .uri("/mcp")
            .header(header::ORIGIN, "http://good.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_owasp_headers(&resp, "cors-preflight");
    }

    #[tokio::test]
    async fn headers_on_404_fallback() {
        let app = m5_router(|_| {});
        let req = Request::builder()
            .uri("/no-such-route")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_owasp_headers(&resp, "404-fallback");
    }

    #[tokio::test]
    async fn headers_on_overload_503() {
        // A zero-permit concurrency cap sheds every request, so a single
        // oneshot deterministically surfaces the overload 503.
        let app = m5_router(|c| c.max_concurrent_requests = Some(0));
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_owasp_headers(&resp, "overload-503");
    }

    // -- M6: OAuth proxy admin endpoints enforce the admin role --

    #[cfg(feature = "oauth")]
    fn m6_auth_state() -> (Arc<AuthState>, String, String) {
        let (admin_token, admin_hash) = crate::auth::generate_api_key().unwrap();
        let (viewer_token, viewer_hash) = crate::auth::generate_api_key().unwrap();
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::from_pointee(vec![
                crate::auth::ApiKeyEntry::new("admin-key", admin_hash, "admin"),
                crate::auth::ApiKeyEntry::new("viewer-key", viewer_hash, "viewer"),
            ]),
            rate_limiter: None,
            pre_auth_limiter: None,
            jwks_cache: None,
            seen_identities: crate::auth::SeenIdentitySet::new(),
            counters: crate::auth::AuthCounters::default(),
            resource_metadata_url: None,
        });
        (state, admin_token, viewer_token)
    }

    #[cfg(feature = "oauth")]
    fn m6_admin_router(state: &Arc<AuthState>) -> axum::Router {
        let proxy = crate::oauth::OAuthProxyConfig::builder(
            "https://idp.example/authorize",
            "https://idp.example/token",
            "client",
        )
        .introspection_url("http://127.0.0.1:1/introspect")
        .revocation_url("http://127.0.0.1:1/revoke")
        .expose_admin_endpoints(true)
        .require_auth_on_admin_endpoints(true)
        .build();
        let http = crate::oauth::OauthHttpClient::new().expect("oauth http client");
        build_oauth_admin_router(&proxy, http, Some(state), "admin").expect("admin router")
    }

    #[cfg(feature = "oauth")]
    fn m6_req(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from("token=abc"))
            .unwrap()
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_proxy_admin_requires_admin_role() {
        let (state, _admin, viewer) = m6_auth_state();
        for path in ["/introspect", "/revoke"] {
            let app = m6_admin_router(&state);
            let resp = app.oneshot(m6_req(path, &viewer)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "an authenticated viewer must be rejected with 403 on {path}"
            );
        }
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_proxy_admin_allows_admin_role() {
        let (state, admin, _viewer) = m6_auth_state();
        for path in ["/introspect", "/revoke"] {
            let app = m6_admin_router(&state);
            let resp = app.oneshot(m6_req(path, &admin)).await.unwrap();
            // The admin identity clears both the auth and role gates; the
            // downstream introspection call then fails closed (no upstream),
            // so the only guarantee asserted is that it is neither 401 nor 403.
            assert_ne!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "an authenticated admin must pass the role gate on {path}"
            );
            assert_ne!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "an authenticated admin must pass the auth gate on {path}"
            );
        }
    }

    // -- F3 regression: unbounded Prometheus label cardinality --
    //
    // `metrics_middleware` runs outside the auth layer, so it observes
    // unauthenticated traffic. Labelling with the raw URI path and raw HTTP
    // method let any client mint a permanent time series per request, growing
    // in-process metric state until OOM. Both labels must now come from a
    // closed set.
    #[cfg(feature = "metrics")]
    mod metrics_labels_bounded {
        use super::*;

        fn labels_for(method: &str, uri: &str) -> (&'static str, String) {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            metrics_labels(&req)
        }

        #[test]
        fn many_unmatched_paths_collapse_to_one_label() {
            let mut seen = std::collections::HashSet::new();
            for i in 0..500 {
                let (_, path) = labels_for("GET", &format!("/nonexistent-{i}"));
                seen.insert(path);
            }
            assert_eq!(
                seen.len(),
                1,
                "unmatched paths must collapse to a single label, got {seen:?}"
            );
            assert!(seen.contains("<unmatched>"));
        }

        #[test]
        fn nested_mcp_paths_collapse_to_the_mount_point() {
            let mut seen = std::collections::HashSet::new();
            for i in 0..200 {
                let (_, path) = labels_for("POST", &format!("/mcp/{i}"));
                seen.insert(path);
            }
            let (_, root) = labels_for("POST", "/mcp");
            seen.insert(root);
            assert_eq!(
                seen.len(),
                1,
                "nested /mcp paths must collapse to one label, got {seen:?}"
            );
            assert!(seen.contains("/mcp"));
        }

        #[test]
        fn unusual_methods_collapse_to_one_bucket() {
            let mut seen = std::collections::HashSet::new();
            for verb in ["FROBNICATE", "WIBBLE", "QUUX", "M-SEARCH"] {
                let (method, _) = labels_for(verb, "/healthz");
                seen.insert(method);
            }
            assert_eq!(seen, std::collections::HashSet::from(["OTHER"]));
        }

        #[test]
        fn known_methods_keep_their_identity() {
            for verb in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
                let (method, _) = labels_for(verb, "/healthz");
                assert_eq!(method, verb);
            }
        }

        #[test]
        fn raw_path_never_leaks_into_a_label() {
            let (_, path) = labels_for("GET", "/secret-token-abc123");
            assert!(
                !path.contains("secret-token"),
                "raw request path must never become a label value: {path}"
            );
        }
    }
}
