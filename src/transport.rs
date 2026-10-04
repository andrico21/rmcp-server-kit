extern crate alloc;

use alloc::sync::Arc;
use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task,
    time::Duration,
};
use std::{
    collections::HashSet,
    io,
    io::{IoSlice, Result as IoResult},
    path::{Path, PathBuf},
    time::Instant,
};

use arc_swap::ArcSwap;
use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Request, connect_info::Connected},
    http::{Extensions, HeaderMap, HeaderName, Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    serve::{IncomingStream, Listener},
};
use rmcp::{
    ServerHandler,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::{EventStore, SessionStore, local::LocalSessionManager},
    },
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::danger::ClientCertVerifier,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, oneshot::Sender},
    task::JoinHandle,
};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "metrics")]
use crate::metrics::McpMetrics;
#[cfg(feature = "oauth")]
use crate::oauth::JwksCache;
#[cfg(feature = "oauth")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "oauth")]
use crate::oauth::{OAuthProxyConfig, OauthHttpClient};
use crate::{
    admin::AdminState,
    auth::{
        ApiKeyEntry, AuthConfig, AuthCounters, AuthIdentity, AuthLogContext, AuthState, MtlsConfig,
        SeenIdentitySet, TlsConnInfo, auth_middleware, build_pre_auth_limiter, build_rate_limiter,
        extract_mtls_identity,
    },
    bounded_limiter::{BoundedKeyedLimiter, BoundedLimiterDeny, KeyEvictionPolicy},
    error::RmcpServerKitError,
    mtls_revocation::{self, CrlSet, DynamicClientCertVerifier},
    rbac::{RbacPolicy, ToolRateLimiter, build_tool_rate_limiter_with_policy, rbac_middleware},
    rbac_context::RbacContextHandler,
    session_binding::{
        SessionBindingSecret, configured_session_binding_secret, process_session_binding_secret,
        session_binding_middleware,
    },
};

/// Map an internal `anyhow::Error` chain into a public [`RmcpServerKitError::Startup`]
/// at the public API boundary, flattening the chain via the alternate
/// formatter so callers see the full causal path.
#[expect(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(anyhow_to_startup) call sites; by-value matches the closure shape"
)]
fn anyhow_to_startup(error: anyhow::Error) -> RmcpServerKitError {
    RmcpServerKitError::Startup(format!("{error:#}"))
}

/// Map a `std::io::Error` produced during server startup into a public
/// [`RmcpServerKitError::Startup`].
///
/// We deliberately do not use the [`RmcpServerKitError::Io`]
/// `From` impl here because startup-phase IO errors (bind, listener) are
/// semantically distinct from request-time IO errors and should surface
/// the originating operation in the message.
#[expect(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(|e| io_to_startup(...)) call sites; by-value matches the closure shape"
)]
fn io_to_startup(op: &str, error: io::Error) -> RmcpServerKitError {
    RmcpServerKitError::Startup(format!("{op}: {error}"))
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
/// `PeerAddr` exposes raw peer network metadata. The framework never logs the
/// socket address (IP and port) on its own; the IP-only `peer_ip`/`client_ip`
/// fields appear only under the `log_context` knobs (see [`ClientIp`]).
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
impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = (StatusCode, &'static str);

    /// Extract [`PeerAddr`] from request extensions.
    ///
    /// No await is performed; nothing can be observed half-updated.
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the axum FromRequestParts trait signature; this impl only reads a request extension synchronously"
    )]
    #[inline]
    // cancel-safe: reads a request extension synchronously and never awaits.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().copied().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
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
/// the direct peer, never to a header value. The value is logged only (a) as
/// `rate_limit_key` on rate-limit deny lines, and (b) as `client_ip` when
/// [`LogContextConfig::client_ip`] is on, on `auth failed`, RBAC-deny,
/// `incoming request` and `request completed` lines. Raw forwarding headers
/// are never logged.
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
    /// Trusted-proxy CIDR ranges whose forwarding headers are honoured.
    trusted: Vec<ipnet::IpNet>,
    /// Which forwarding header trusted-forwarder mode reads.
    mode: ForwardedHeaderMode,
    /// Upper bound on the number of header entries scanned per request.
    max_scanned_entries: usize,
    /// Optional request-id header name propagated into logs.
    request_id_header: Option<HeaderName>,
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

/// Per-item switches for client-context fields in log lines.
///
/// Every field is off by default: client IPs, user agents and
/// identifiers are personal data, so each item is an explicit opt-in.
/// With every knob off, log lines keep their pre-3.15 shape. See
/// [`LogContextConfig::recommended`] for a curated low-risk preset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent operator-facing opt-in switch; grouping them into sub-structs would complicate the public API and the TOML surface for no safety gain"
)]
pub struct LogContextConfig {
    /// Include the resolved [`ClientIp`] on `auth failed`, RBAC-deny
    /// WARNs, `incoming request` and `request completed` lines.
    pub client_ip: bool,
    /// Include the direct socket peer IP (never the port) on the same
    /// lines as [`Self::client_ip`].
    pub peer_ip: bool,
    /// Include the value of [`Self::request_id_header`] on the same
    /// lines as [`Self::client_ip`]. Taken only from a direct peer
    /// inside `trusted_proxies` (last occurrence wins); requires
    /// non-empty `trusted_proxies` (validated).
    pub request_id: bool,
    /// Header name read when [`Self::request_id`] is enabled. Default:
    /// `x-request-id`. On OpenShift, the `IngressController`'s
    /// `spec.httpHeaders.uniqueId.name` sets this header router-side.
    pub request_id_header: String,
    /// Include `method` and `path` (no query string) on `auth failed`
    /// lines.
    pub request_line: bool,
    /// Include the sanitized `User-Agent` on `auth failed` lines.
    pub user_agent: bool,
    /// Include `auth_scheme` and `token_kind` on `auth failed` lines.
    pub auth_scheme: bool,
    /// Include `mcp_session` (presence of `Mcp-Session-Id`, never its
    /// value) and `mcp_protocol_version` on `auth failed` and
    /// `incoming request` lines.
    pub mcp_hints: bool,
    /// Include `credential_fp` on `auth failed` lines, for Bearer
    /// tokens only: the first 8 hex characters of HMAC-SHA256 keyed
    /// with the RBAC redaction salt. Set `rbac.redaction_salt` for
    /// fingerprints that are stable across replicas.
    pub credential_fingerprint: bool,
    /// Add `credential_owner` (identity label) and `credential_rejection`
    /// (`expired` | `audience` | `role` | `subject`) to `auth failed` when
    /// a credential verifies but is rejected: an API key matching an expired
    /// configured key, or a JWT whose signature and issuer verify but that is
    /// expired, has the wrong audience, maps to no role, or lacks a required
    /// subject. The label is the identity the `authenticated` line logs. Off
    /// by default and not enabled by `recommended()`.
    pub credential_owner: bool,
    /// Emit a DEBUG `request completed` line with `status` and
    /// `latency_ms`.
    pub request_completion: bool,
}

impl Default for LogContextConfig {
    #[inline]
    fn default() -> Self {
        Self {
            client_ip: false,
            peer_ip: false,
            request_id: false,
            request_id_header: "x-request-id".to_owned(),
            request_line: false,
            user_agent: false,
            auth_scheme: false,
            mcp_hints: false,
            credential_fingerprint: false,
            credential_owner: false,
            request_completion: false,
        }
    }
}

impl LogContextConfig {
    /// A curated low-risk preset: enables `client_ip`, `peer_ip`,
    /// `request_line`, `user_agent`, `auth_scheme` and `mcp_hints`.
    /// Leaves `request_id` (needs `trusted_proxies`),
    /// `credential_fingerprint`, `credential_owner` and `request_completion`
    /// off, so the result validates without any other configuration.
    #[must_use]
    #[inline]
    pub fn recommended() -> Self {
        Self {
            client_ip: true,
            peer_ip: true,
            request_id: false,
            request_line: true,
            user_agent: true,
            auth_scheme: true,
            mcp_hints: true,
            credential_fingerprint: false,
            request_completion: false,
            ..Self::default()
        }
    }
}

/// Configuration for the MCP server.
#[expect(
    missing_debug_implementations,
    reason = "contains callback/trait objects that don't impl Debug"
)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "server configuration naturally has many boolean feature flags"
)]
#[cfg_attr(
    feature = "metrics",
    expect(
        clippy::field_scoped_visibility_modifiers,
        clippy::partial_pub_fields,
        reason = "public API frozen until the next major release"
    )
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
    ///
    /// Enforced end to end: the outer limit layer rejects oversized bodies
    /// (413, before auth/RBAC buffer them) and the MCP service enforces the
    /// same value internally. One knob - there is no second limit to keep in
    /// sync.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_max_request_body(); direct field access will become pub(crate) in a future major release"
    )]
    pub max_request_body: usize,
    /// Request processing timeout. Default: 120s.
    ///
    /// Bounds the inner service response future (the time until a `Response` is
    /// produced). Response-body transfer/streaming work that occurs after the
    /// `Response` exists - including SSE body frames - is not covered by this
    /// timeout. Requests exceeding this duration receive 408 Request Timeout.
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
    /// Shared HMAC secret used when session binding must verify across
    /// multiple server instances. When unset, a process-random secret keeps
    /// single-instance behaviour unchanged. For cross-instance session
    /// continuity you also need a shared rmcp `SessionStore`
    /// (see [`Self::with_session_store`]).
    pub session_binding_secret: Option<SecretString>,
    /// Bind MCP task IDs (SEP-2663) to the authenticated identity.
    ///
    /// Off by default: enabling it changes the wire format of `taskId` values,
    /// which is safe for clients that treat them as opaque but would break a
    /// consumer that persists the client-visible ID as its own key.
    ///
    /// Shares [`Self::session_binding_secret`]; the two bindings are
    /// domain-separated so a session token can never verify as a task token.
    ///
    /// Default `false` is a compatibility choice, not a staged default-flip
    /// promise; enable it explicitly for task-using authenticated deployments
    /// that need cross-identity isolation.
    pub task_binding: bool,
    /// Optional external rmcp session store for cross-instance recovery.
    pub session_store: Option<Arc<dyn SessionStore>>,
    /// Optional external event store backing resumable SSE streams
    /// (`Last-Event-ID`).
    ///
    /// A best-effort in-process resume already works without this, but only
    /// for a live session whose events are still in rmcp''s bounded channel
    /// cache. Supplying a store adds durable, cross-instance, and stateless
    /// replay.
    ///
    /// The implementation owns stream isolation: rmcp passes only the last
    /// event id to `replay_events_after`, never the stream, so event ids must
    /// be globally unique and must identify their own stream. Replaying an
    /// event onto a different stream violates the MCP transport spec.
    pub event_store: Option<Arc<dyn EventStore>>,
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
    /// Sensitive values remain redacted. Paths listed in
    /// [`Self::request_log_exclude_paths`] are not logged.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_request_header_logging(); direct field access will become pub(crate) in a future major release"
    )]
    pub log_request_headers: bool,
    /// Per-item switches for client-context fields in `incoming
    /// request` / `request completed` / `auth failed` / RBAC-deny log
    /// lines. Off by default. Startup-only.
    pub log_context: LogContextConfig,
    /// Paths excluded from the `incoming request` / `request
    /// completed` log lines.
    ///
    /// Matching is an exact-string comparison against
    /// `req.uri().path()` (no globs, no prefixes). Default:
    /// `["/healthz", "/readyz"]`. An empty list logs every request.
    /// Entries are validated at [`validate`](Self::validate) time.
    /// Startup-only.
    pub request_log_exclude_paths: Vec<String>,
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
    /// Caller-supplied metrics registry handle (feature: `metrics`).
    ///
    /// When set, the metrics middleware records into this registry and the
    /// `/metrics` listener serves it. The framework registers its own three
    /// collectors on it at startup (evicting any descriptor-equivalent
    /// occupant first) and fails startup closed on a reserved-name conflict.
    /// Set via [`Self::with_metrics_handle`]; supplying a handle requires
    /// [`Self::with_metrics`] as well.
    #[cfg(feature = "metrics")]
    pub(crate) metrics_handle: Option<Arc<McpMetrics>>,
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
/// use rmcp::model::{ServerCapabilities, ServerConfig};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerConfig {
///         ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
/// use rmcp::model::{ServerCapabilities, ServerConfig};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerConfig {
///         ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
pub struct Validated<T>(T);

impl<T> Debug for Validated<T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Validated").finish_non_exhaustive()
    }
}

#[expect(
    clippy::missing_const_for_fn,
    reason = "public API frozen until the next major release"
)]
impl<T> Validated<T> {
    /// Borrow the inner value.
    #[must_use]
    #[inline]
    pub fn as_inner(&self) -> &T {
        &self.0
    }

    /// Recover the raw value, discarding the validation proof.
    ///
    /// Re-validate before re-using the value with [`serve`] or
    /// [`serve_with_listener`].
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Default [`McpServerConfig::request_log_exclude_paths`]: health-check
/// paths, which would otherwise dominate the request log.
pub(crate) fn default_request_log_exclude_paths() -> Vec<String> {
    vec!["/healthz".to_owned(), "/readyz".to_owned()]
}

#[expect(
    clippy::missing_const_for_fn,
    reason = "public API frozen until the next major release"
)]
#[expect(
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
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn new(
        bind_addr: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        use crate::forwarded::MAX_SCANNED_ENTRIES;

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
            session_binding_secret: None,
            task_binding: false,
            session_store: None,
            event_store: None,
            sse_keep_alive: Duration::from_secs(15),
            on_reload_ready: None,
            extra_router: None,
            public_url: None,
            log_request_headers: false,
            log_context: LogContextConfig::default(),
            request_log_exclude_paths: default_request_log_exclude_paths(),
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
            #[cfg(feature = "metrics")]
            metrics_handle: None,
            security_headers: SecurityHeadersConfig::default(),
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            max_concurrent_tls_handshakes: DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES,
            extra_route_rate_limit: None,
            tool_rate_limit_burst: None,
            extra_route_rate_limit_burst: None,
            extra_route_rate_limit_exempt_paths: Vec::new(),
            key_eviction_policy: KeyEvictionPolicy::default(),
            trusted_forwarder_max_entries: MAX_SCANNED_ENTRIES,
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
    #[inline]
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override one or more of the OWASP security headers emitted on
    /// every response. See [`SecurityHeadersConfig`] for the three-state
    /// semantic (`None` = default, `Some("")` = omit, `Some(v)` =
    /// override). Values are validated by [`Self::validate`].
    #[must_use]
    #[inline]
    pub fn with_security_headers(mut self, headers: SecurityHeadersConfig) -> Self {
        self.security_headers = headers;
        self
    }

    /// Override the bind address (e.g. `127.0.0.1:8080`). Useful when the
    /// final port is only known after pre-binding an ephemeral listener
    /// (tests, dynamic-port deployments).
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Attach an RBAC policy. Tool calls are checked against the policy
    /// after authentication.
    #[must_use]
    #[inline]
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
    #[inline]
    pub const fn with_tool_list_filtering(mut self, enabled: bool) -> Self {
        self.tool_list_filtering = enabled;
        self
    }

    /// Configure TLS by providing the certificate and private key paths
    /// (PEM). Both must be readable at startup. Without this call, the
    /// server runs plain HTTP.
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_tls(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Set the externally reachable base URL (e.g. `https://mcp.example.com`).
    /// Required when binding `0.0.0.0` behind a reverse proxy or inside
    /// a container so OAuth metadata and auto-derived origins resolve correctly.
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = Some(url.into());
        self
    }

    /// Replace the allowed Origin allow-list (DNS-rebinding protection).
    /// When empty and [`with_public_url`](Self::with_public_url) is set,
    /// the origin is auto-derived.
    #[must_use]
    #[inline]
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
    #[inline]
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
    #[inline]
    pub const fn with_trusted_forwarder_max_entries(mut self, max_entries: usize) -> Self {
        self.trusted_forwarder_max_entries = max_entries;
        self
    }

    /// Install an async readiness probe for `/readyz`. Without this call,
    /// `/readyz` mirrors `/healthz` (always 200 OK).
    #[must_use]
    #[inline]
    pub fn with_readiness_check(mut self, check: ReadinessCheck) -> Self {
        self.readiness_check = Some(check);
        self
    }

    /// Override the maximum request body (bytes). Must be `> 0`.
    /// Default: 1 MiB.
    ///
    /// Applies to both layers that can reject an oversized body: the outer
    /// limit layer in front of the router and the MCP service's own limit.
    #[must_use]
    #[inline]
    pub fn with_max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    /// Override the per-request processing timeout. Default: 2 minutes.
    ///
    /// Bounds the inner service response future - the time until a `Response`
    /// is produced. Streaming/response-body transfer after that point is not
    /// covered.
    #[must_use]
    #[inline]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the graceful shutdown grace period. Default: 30 seconds.
    #[must_use]
    #[inline]
    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Override the MCP session idle timeout. Default: 20 minutes.
    #[must_use]
    #[inline]
    pub fn with_session_idle_timeout(mut self, timeout: Duration) -> Self {
        self.session_idle_timeout = timeout;
        self
    }

    /// Enable or disable stateless binding of rmcp session IDs to the
    /// authenticated identity. Enabled by default; disabling reinstates the
    /// CWE-384 risk from reusable unbound session IDs.
    #[must_use]
    #[inline]
    pub const fn with_session_binding(mut self, enabled: bool) -> Self {
        self.session_binding = enabled;
        self
    }

    /// Set the shared HMAC secret used to bind MCP session IDs to identities.
    /// For cross-instance continuity, combine with [`Self::with_session_store`].
    #[must_use]
    #[inline]
    pub fn with_session_binding_secret(mut self, secret: SecretString) -> Self {
        self.session_binding_secret = Some(secret);
        self
    }

    /// Bind MCP task IDs to the authenticated identity that created them.
    ///
    /// Prevents one authenticated identity from reading, updating, or
    /// cancelling another's task via a leaked `taskId`. Reuses
    /// [`Self::with_session_binding_secret`]. See [`Self::task_binding`] for
    /// the compatibility caveat.
    #[must_use]
    #[inline]
    pub const fn with_task_binding(mut self, enabled: bool) -> Self {
        self.task_binding = enabled;
        self
    }

    /// Persist rmcp session state in an application-provided external store.
    /// Combine with [`Self::with_session_binding_secret`] to enable cross-instance
    /// session continuity (verification + existence).
    #[must_use]
    #[inline]
    pub fn with_session_store(mut self, session_store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(session_store);
        self
    }

    /// Back resumable SSE streams with an application-provided event store.
    ///
    /// See [`McpServerConfig::event_store`] for the stream-isolation
    /// obligation this places on the implementation.
    #[must_use]
    #[inline]
    pub fn with_event_store(mut self, event_store: Arc<dyn EventStore>) -> Self {
        self.event_store = Some(event_store);
        self
    }

    /// Override the SSE keep-alive interval. Default: 15 seconds.
    #[must_use]
    #[inline]
    pub fn with_sse_keep_alive(mut self, interval: Duration) -> Self {
        self.sse_keep_alive = interval;
        self
    }

    /// Cap the global number of in-flight HTTP requests via
    /// `tower::load_shed`. Excess requests receive 503 Service Unavailable.
    /// Default: unlimited.
    #[must_use]
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn with_max_concurrent_tls_handshakes(mut self, limit: usize) -> Self {
        self.max_concurrent_tls_handshakes = limit;
        self
    }

    /// Cap tool invocations per source IP per minute. Enforced on every
    /// `tools/call` request.
    #[must_use]
    #[inline]
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
    #[inline]
    pub fn with_extra_route_rate_limit(mut self, per_minute: u32) -> Self {
        self.extra_route_rate_limit = Some(per_minute);
        self
    }

    /// Set the burst capacity for the tool rate limiter (bucket size;
    /// the sustained rate stays [`with_tool_rate_limit`](Self::with_tool_rate_limit)).
    /// Requires the tool rate limit to be set; must be greater than zero
    /// (both validated by [`validate`](Self::validate)).
    #[must_use]
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn with_forwarded_header(mut self, mode: ForwardedHeaderMode) -> Self {
        self.forwarded_header = Some(mode);
        self
    }

    /// Register a callback that receives the [`ReloadHandle`] after the
    /// server is built. Use it to wire SIGHUP-style hot reloads of API
    /// keys and RBAC policy.
    #[must_use]
    #[inline]
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
    #[inline]
    pub fn enable_compression(mut self, min_size: u16) -> Self {
        self.compression_enabled = true;
        self.compression_min_size = min_size;
        self
    }

    /// Enable `/admin/*` diagnostic endpoints. Requires
    /// [`with_auth`](Self::with_auth) to be set and enabled; otherwise
    /// [`validate`](Self::validate) returns an error. `role` is the RBAC
    /// role gate (default: `"admin"`).
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn enable_admin(mut self, role: impl Into<String>) -> Self {
        self.admin_enabled = true;
        self.admin_role = role.into();
        self
    }

    /// Log inbound HTTP request headers at DEBUG level. Sensitive
    /// values remain redacted by the logging layer. Paths listed in
    /// [`Self::request_log_exclude_paths`] are not logged.
    #[must_use]
    #[inline]
    pub fn enable_request_header_logging(mut self) -> Self {
        self.log_request_headers = true;
        self
    }

    /// Set the per-item client-context logging switches (see
    /// [`LogContextConfig`]). Off by default; use
    /// [`LogContextConfig::recommended`] for a curated low-risk preset,
    /// or flip individual fields on the `#[non_exhaustive]` struct.
    ///
    /// ```rust
    /// use rmcp_server_kit::transport::{LogContextConfig, McpServerConfig};
    ///
    /// let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    ///     .with_log_context(LogContextConfig::recommended());
    /// assert!(config.validate().is_ok());
    /// ```
    ///
    /// Enabling individual knobs:
    ///
    /// ```rust
    /// use rmcp_server_kit::transport::{LogContextConfig, McpServerConfig};
    ///
    /// let mut ctx = LogContextConfig::default();
    /// ctx.client_ip = true;
    /// ctx.request_completion = true;
    /// let config =
    ///     McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0").with_log_context(ctx);
    /// assert!(config.validate().is_ok());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_log_context(mut self, log_context: LogContextConfig) -> Self {
        self.log_context = log_context;
        self
    }

    /// Replace the list of paths excluded from the `incoming request` /
    /// `request completed` log lines (default: `["/healthz",
    /// "/readyz"]`). Matching is an exact-string comparison against
    /// `req.uri().path()`. Pass an empty iterator to log every request,
    /// including health-check probes. Entries are validated at
    /// [`validate`](Self::validate) time. Startup-only.
    ///
    /// ```rust
    /// use rmcp_server_kit::transport::McpServerConfig;
    ///
    /// let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    ///     .with_request_log_exclude_paths(Vec::<String>::new());
    /// assert!(config.validate().is_ok());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_request_log_exclude_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.request_log_exclude_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Expose build metadata (`build_git_sha`, `build_timestamp`,
    /// `rust_version`) on the unauthenticated `/version` endpoint. Off by
    /// default so `/version` reveals only `name`, `version`, and
    /// `rmcp_server_kit_version`.
    #[must_use]
    #[inline]
    pub fn expose_build_metadata(mut self) -> Self {
        self.expose_build_metadata = true;
        self
    }

    /// Enable the Prometheus metrics listener on `bind` (e.g.
    /// `127.0.0.1:9090`). Requires the `metrics` crate feature.
    #[cfg(feature = "metrics")]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_metrics(mut self, bind: impl Into<String>) -> Self {
        self.metrics_enabled = true;
        self.metrics_bind = bind.into();
        self
    }

    /// Use a caller-constructed [`crate::metrics::McpMetrics`] handle as the
    /// served metrics registry (feature: `metrics`).
    ///
    /// Register application collectors on `handle.registry` before passing it;
    /// the framework registers (and verifies) its own three
    /// `rmcp_server_kit_*` collectors on the same registry at startup, so
    /// those names are reserved. Supplying a handle does **not** enable the
    /// listener - call [`Self::with_metrics`] as well; a handle without an
    /// enabled listener is rejected by validation.
    ///
    /// `/metrics` stays an unauthenticated listener: admitting application
    /// collectors widens what it exposes, so keep it bound to loopback or a
    /// protected monitoring network.
    #[cfg(feature = "metrics")]
    #[must_use]
    #[inline]
    pub fn with_metrics_handle(mut self, handle: Arc<McpMetrics>) -> Self {
        self.metrics_handle = Some(handle);
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
    /// 5. Each entry in `allowed_origins` must be a bare origin:
    ///    `scheme://host[:port]` with `http`/`https`, optionally with one
    ///    root trailing `/`, or the literal token `"null"`.
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
    #[inline]
    pub fn validate(self) -> Result<Validated<Self>, RmcpServerKitError> {
        self.check()?;
        Ok(Validated(self))
    }

    /// 6b2. A supplied metrics handle without an enabled listener is a
    /// misconfiguration: the handle would never be installed or served.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when a metrics handle is set
    /// while the metrics listener is disabled.
    #[cfg(feature = "metrics")]
    fn check_metrics_handle(&self) -> Result<(), RmcpServerKitError> {
        if self.metrics_handle.is_some() && !self.metrics_enabled {
            return Err(RmcpServerKitError::Config(
                "metrics_handle supplied but metrics listener is disabled; call with_metrics(...) as well".into(),
            ));
        }
        Ok(())
    }

    /// 6e. An empty `admin_role` gates `/admin/*` behind a role no identity can
    /// hold. The TOML validator has always rejected it; the builder now
    /// matches, so the two public validators cannot disagree.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when admin is enabled with an
    /// empty `admin_role`.
    fn check_admin_role(&self) -> Result<(), RmcpServerKitError> {
        if self.admin_enabled && self.admin_role.trim().is_empty() {
            return Err(RmcpServerKitError::Config(
                "admin_role must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Validate the burst knobs: every burst must be greater than zero
    /// when set, and the two top-level bursts require their base limiter
    /// to be configured. The auth bursts
    /// (`RateLimitConfig::{burst, pre_auth_burst}`) have no orphan rule:
    /// their base rates always resolve (`max_attempts_per_minute` is
    /// mandatory; the pre-auth base derives from it when unset).
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when a burst knob is zero, a
    /// burst is set without its base limiter, or an exempt-path entry is
    /// malformed.
    fn check_burst_knobs(&self) -> Result<(), RmcpServerKitError> {
        use crate::forwarded::MAX_CONFIGURABLE_SCANNED_ENTRIES;

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
            || self.trusted_forwarder_max_entries > MAX_CONFIGURABLE_SCANNED_ENTRIES
        {
            return Err(RmcpServerKitError::Config(format!(
                "trusted_forwarder_max_entries must be in 1..={MAX_CONFIGURABLE_SCANNED_ENTRIES}, got {}",
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
        for path in &self.request_log_exclude_paths {
            if path.is_empty() || !path.starts_with('/') {
                return Err(RmcpServerKitError::Config(format!(
                    "request_log_exclude_paths entries must be non-empty and start with '/': {path:?}"
                )));
            }
        }
        if let Some(rl) = self.auth.as_ref().and_then(|auth| auth.rate_limit.as_ref()) {
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
    /// nonempty proxy list (fail-fast over a silent no-op). Also
    /// validates [`LogContextConfig::request_id_header`] and that
    /// `log_context.request_id` requires `trusted_proxies`.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when a proxy entry is malformed,
    /// a forwarding header is set without proxies, or the request-id header
    /// is invalid.
    fn check_trusted_forwarder(&self) -> Result<(), RmcpServerKitError> {
        for entry in &self.trusted_proxies {
            validate_trusted_proxy_entry(entry).map_err(RmcpServerKitError::Config)?;
        }
        if self.forwarded_header.is_some() && self.trusted_proxies.is_empty() {
            return Err(RmcpServerKitError::Config(
                "forwarded_header requires trusted_proxies to be nonempty".into(),
            ));
        }
        validate_request_id_header(&self.log_context.request_id_header)
            .map_err(RmcpServerKitError::Config)?;
        if self.log_context.request_id && self.trusted_proxies.is_empty() {
            return Err(RmcpServerKitError::Config(
                "log_context.request_id requires trusted_proxies to be nonempty".into(),
            ));
        }
        Ok(())
    }

    /// Validate the session-binding secret wiring: a cross-instance binding
    /// secret is required when a session store is configured alongside
    /// enabled auth, and any configured secret must satisfy the binding
    /// format rules.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when the secret is missing for
    /// the configured binding and when a configured secret fails validation.
    fn check_session_binding_config(&self) -> Result<(), RmcpServerKitError> {
        use crate::session_binding::validate_configured_secret;

        if self.session_store.is_some()
            && self.session_binding
            && self.auth.as_ref().is_some_and(|auth| auth.enabled)
            && self.session_binding_secret.is_none()
        {
            return Err(RmcpServerKitError::Config(
                "session_store with session_binding enabled and auth configured requires \
                 session_binding_secret: a shared secret is required for cross-instance \
                 session verification"
                    .into(),
            ));
        }

        if let Some(secret) = &self.session_binding_secret {
            validate_configured_secret("session_binding_secret", secret.expose_secret())?;
        }
        Ok(())
    }

    /// Run the validation checks without consuming `self`. Used by
    /// internal call sites (e.g. tests) that need to inspect a config
    /// without taking ownership.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] on the first invariant the
    /// configuration violates: admin/auth wiring, TLS cert-key pairing, mTLS
    /// without TLS, bind address, URL, origin, or size-limit checks.
    fn check(&self) -> Result<(), RmcpServerKitError> {
        use crate::config::{SharedConfigViolation, check_shared_config_invariants};

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
        if let Err(violation) = check_shared_config_invariants(
            self.admin_enabled,
            self.auth.as_ref().is_some_and(|auth| auth.enabled),
            self.tls_cert_path.is_some(),
            self.tls_key_path.is_some(),
            self.auth.as_ref().is_some_and(|auth| auth.mtls.is_some()),
        ) {
            return Err(RmcpServerKitError::Config(
                match violation {
                    SharedConfigViolation::AdminRequiresAuth => {
                        "admin_enabled=true requires auth to be configured and enabled"
                    }
                    SharedConfigViolation::TlsCertWithoutKey => {
                        "tls_cert_path is set but tls_key_path is missing"
                    }
                    SharedConfigViolation::TlsKeyWithoutCert => {
                        "tls_key_path is set but tls_cert_path is missing"
                    }
                    SharedConfigViolation::MtlsRequiresTls => {
                        "auth.mtls requires TLS: set both tls_cert_path and tls_key_path \
                         (mTLS client certificates cannot be verified on a plaintext listener)"
                    }
                }
                .into(),
            ));
        }

        if let Some(auth) = &self.auth {
            auth.validate_api_key_names()?;
        }

        // 3. bind_addr parses
        if self.bind_addr.parse::<SocketAddr>().is_err() {
            return Err(RmcpServerKitError::Config(format!(
                "bind_addr {:?} is not a valid socket address (expected e.g. 127.0.0.1:8080)",
                self.bind_addr
            )));
        }

        // 4. public_url scheme (shared with the TOML validator).
        if let Some(url) = &self.public_url
            && let Err(message) = validate_public_url_value(url)
        {
            return Err(RmcpServerKitError::Config(message));
        }

        // 5. allowed_origins entries must be bare origins: scheme://host[:port]
        //    (http or https), optionally with one root trailing slash, or the
        //    literal token "null". Entries carrying a non-root path, query, or
        //    fragment used to be silently ineffective at runtime; they now
        //    fail fast at startup.
        for origin in &self.allowed_origins {
            validate_allowed_origin_entry(origin).map_err(RmcpServerKitError::Config)?;
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

        // 6b2. Metrics-handle knob (extracted helper).
        #[cfg(feature = "metrics")]
        self.check_metrics_handle()?;

        // 6c. Burst knobs (extracted helper).
        self.check_burst_knobs()?;

        // 6e. Admin-role parity (extracted helper).
        self.check_admin_role()?;

        // 6d. Trusted-forwarder knobs (extracted helper).
        self.check_trusted_forwarder()?;

        // 7. OAuth URL fields enforce HTTPS (unless `allow_http_oauth_urls`)
        #[cfg(feature = "oauth")]
        if let Some(auth_cfg) = &self.auth
            && let Some(oauth_cfg) = &auth_cfg.oauth
        {
            oauth_cfg.validate()?;
        }

        self.check_session_binding_config()?;

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
#[expect(
    missing_debug_implementations,
    reason = "contains Arc<AuthState> with non-Debug fields"
)]
pub struct ReloadHandle {
    /// Auth state whose API-key list can be hot-reloaded.
    auth: Option<Arc<AuthState>>,
    /// RBAC policy slot swapped atomically on reload.
    rbac: Option<Arc<ArcSwap<RbacPolicy>>>,
    /// Cached mTLS CRL set refreshed on demand.
    crl_set: Option<Arc<CrlSet>>,
}

impl ReloadHandle {
    /// Validate and atomically replace the API key list used by the auth
    /// middleware.
    ///
    /// The new keys are validated before any swap: a blank key name is
    /// rejected because it would collapse distinct principals to one
    /// session-binding fingerprint (CWE-384). On error the previously
    /// installed keys stay in place. With no auth state configured this is a
    /// successful no-op.
    ///
    /// This is the fallible counterpart to [`Self::reload_auth_keys`]; prefer
    /// it so a rejected reload is observable rather than only logged.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] naming the first blank-named
    /// index; the currently installed key list is left untouched.
    #[inline]
    pub fn try_reload_auth_keys(&self, keys: Vec<ApiKeyEntry>) -> Result<(), RmcpServerKitError> {
        self.auth
            .as_ref()
            .map_or(Ok(()), |auth| auth.try_reload_keys(keys))
    }

    /// Atomically replace the API key list used by the auth middleware.
    ///
    /// Compatibility wrapper over [`Self::try_reload_auth_keys`]. Invalid
    /// input (a blank key name) is **rejected, not installed**: the error is
    /// logged via `tracing::error!` and the previously installed keys are left
    /// untouched, so a bad reload never silently swaps in
    /// session-binding-colliding keys. Prefer [`Self::try_reload_auth_keys`]
    /// to observe and handle the failure directly.
    #[inline]
    pub fn reload_auth_keys(&self, keys: Vec<ApiKeyEntry>) {
        if let Err(error) = self.try_reload_auth_keys(keys) {
            tracing::error!(%error, "API key hot reload rejected: keys left unchanged");
        }
    }

    /// Atomically replace the RBAC policy used by the RBAC middleware.
    #[inline]
    pub fn reload_rbac(&self, policy: RbacPolicy) {
        if let Some(rbac) = &self.rbac {
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
    #[inline]
    pub async fn refresh_crls(&self) -> Result<(), RmcpServerKitError> {
        let Some(crl_set) = &self.crl_set else {
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

/// Per-feature identity-binding HMAC secrets.
///
/// Holds `(session_binding_secret, task_binding_secret)`; each entry is
/// `Some` only when the corresponding binding feature is enabled.
type BindingSecrets = (Option<SessionBindingSecret>, Option<SessionBindingSecret>);

/// Resolve the shared identity-binding HMAC secret for each binding feature.
///
/// Returns `(session_binding_secret, task_binding_secret)`, each `Some` only
/// when that feature is enabled. Built once here because the handler factory
/// (task binding) and the middleware layer (session binding) both need it, and
/// the factory is constructed first. A configured secret is therefore now
/// validated when *either* binding is on.
///
/// # Errors
///
/// Returns an error when a configured secret fails validation.
fn resolve_binding_secret(config: &McpServerConfig) -> anyhow::Result<BindingSecrets> {
    if !config.session_binding && !config.task_binding {
        return Ok((None, None));
    }
    let secret = match config.session_binding_secret.as_ref() {
        Some(configured) => configured_session_binding_secret(configured)?,
        None => process_session_binding_secret().clone(),
    };
    let pair = (
        config.session_binding.then(|| secret.clone()),
        config.task_binding.then_some(secret),
    );
    Ok(pair)
}

/// Build the OAuth protected-resource metadata URL for `public_url`.
fn mcp_resource_metadata_url(public_url: &str) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource/mcp",
        public_url.trim_end_matches('/')
    )
}

/// Response for a request shed by the global concurrency limit.
///
/// A named `async fn` (instead of a closure returning an async block) keeps
/// the tower `HandleErrorLayer` wiring free of the
/// `closure_returning_async_block` shape while behaving identically.
///
/// cancel-safe: the body never awaits; it just constructs the 503 response.
async fn overloaded_response<E>(_error: E) -> impl IntoResponse {
    use axum::Json;

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "overloaded",
            "error_description": "server is at capacity, retry later"
        })),
    )
}

/// JSON 404 fallback for unmatched routes.
///
/// A named `async fn` instead of a closure returning an async block; the
/// rendered body and status are byte-identical to the previous closure.
///
/// cancel-safe: the body never awaits; it just constructs the 404 response.
async fn not_found_fallback() -> impl IntoResponse {
    use axum::Json;

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "not_found",
            "error_description": "The requested endpoint does not exist"
        })),
    )
}

/// Compute the effective allowed-origin set for the outer origin-check layer.
///
/// Pre-parsed once at router-build time so the middleware and the CORS layer
/// match against the same normalized representation, never against the raw
/// config strings. When `allowed_origins` is empty but `public_url` is set,
/// the origin is auto-derived from the public URL so MCP clients that send
/// `Origin: <server-url>` are accepted without explicit configuration.
#[expect(
    deprecated,
    reason = "internal router assembly reads deprecated `pub` config fields by design until 1.0 makes them pub(crate)"
)]
fn effective_allowed_origins(config: &McpServerConfig) -> Arc<[AllowedOrigin]> {
    let mut effective_origins = config.allowed_origins.clone();
    if effective_origins.is_empty()
        && let Some(url) = &config.public_url
    {
        // Origin = scheme + "://" + host (+ ":" + port if non-default).
        // Strip any path/query from the public URL. Offsets come from
        // `find`, so they are char-boundary-aligned; `get(..)` keeps that
        // machine-checked (a violation degrades to an empty slice).
        if let Some(scheme_end) = url.find("://") {
            let after_scheme_at = scheme_end.saturating_add(3);
            let scheme_with_sep = url.get(..after_scheme_at).unwrap_or_default();
            let after_scheme = url.get(after_scheme_at..).unwrap_or_default();
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
    Arc::from(
        effective_origins
            .iter()
            .filter_map(|origin| parse_allowed_origin(origin))
            .collect::<Vec<_>>(),
    )
}

/// Merge application `extra_router` routes into `router`.
///
/// When a per-IP rate limit is configured, the limiter wraps only the extra
/// routes (axum layers wrap only the routes already present on the sub-router)
/// so it can never leak onto `/mcp`, health, admin, or OAuth endpoints.
#[expect(
    deprecated,
    reason = "internal router assembly reads deprecated `pub` config fields by design until 1.0 makes them pub(crate)"
)]
fn install_extra_router(router: axum::Router, config: &mut McpServerConfig) -> axum::Router {
    use axum::middleware::from_fn;

    let Some(extra) = config.extra_router.take() else {
        return router;
    };
    let extra_router = match config.extra_route_rate_limit {
        Some(per_minute) => {
            let max_tracked_keys =
                NonZeroUsize::new(EXTRA_ROUTE_MAX_TRACKED_KEYS).unwrap_or(NonZeroUsize::MIN);
            let limiter = build_extra_route_rate_limiter_with_policy(
                per_minute,
                config.extra_route_rate_limit_burst,
                config.key_eviction_policy,
                max_tracked_keys,
            );
            let exempt: Arc<HashSet<String>> = Arc::new(
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
            extra.layer(from_fn(move |req, next| {
                let limiter_clone = Arc::clone(&limiter);
                let exempt_clone = Arc::clone(&exempt);
                extra_route_rate_limit_middleware(limiter_clone, exempt_clone, req, next)
            }))
        }
        None => extra,
    };
    router.merge(extra_router)
}

/// Build the full application axum [`axum::Router`] and its [`AppRunParams`].
///
/// The router bundles the MCP route, middleware stack, admin, OAuth, health
/// endpoints, security headers, CORS, compression, concurrency limit, and
/// origin check.
///
/// This is the shared core of [`serve`] and [`serve_with_listener`].
/// It performs *no* network I/O: callers are responsible for binding
/// (or accepting a pre-bound) [`TcpListener`] and invoking
/// [`run_server`].
///
/// # Errors
///
/// Returns an error when the configuration is invalid or the router cannot be
/// assembled for the active feature set.
#[expect(
    clippy::cognitive_complexity,
    reason = "router assembly is intrinsically sequential; splitting harms readability"
)]
#[expect(
    clippy::too_many_lines,
    reason = "deliberate: src/transport.rs::build_app_router — router assembly is intrinsically sequential; the length is layer wiring, not branching logic"
)]
#[expect(
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
    use axum::{
        error_handling::HandleErrorLayer,
        http::{
            HeaderValue,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
        middleware::from_fn,
        routing::get,
    };
    use tower::{limit::ConcurrencyLimitLayer, load_shed::LoadShedLayer};
    use tower_http::{
        compression::{CompressionLayer, DefaultPredicate, predicate::SizeAbove},
        cors::{AllowOrigin, CorsLayer},
        limit::RequestBodyLimitLayer,
        timeout::TimeoutLayer,
    };

    #[cfg(feature = "metrics")]
    use crate::metrics::serve_metrics_with_security_headers;
    #[cfg(feature = "oauth")]
    use crate::oauth::protected_resource_metadata;
    use crate::{
        admin::{AdminConfig, admin_router},
        rbac::DenyLogKnobs,
    };

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
    let session_store = config.session_store.take();
    // Origin validation is owned by rmcp-server-kit's outer middleware (see
    // `origin_check_middleware`): it covers every route and runs before auth.
    // rmcp's internal `allowed_origins` is intentionally left unset to avoid
    // double enforcement with diverging semantics.
    let mut rmcp_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts)
        .with_sse_keep_alive(Some(config.sse_keep_alive))
        // Propagate the public cap into rmcp's own body limit. rmcp otherwise
        // enforces its 4 MiB default and silently under-delivers any larger
        // configured value; equal caps keep the OUTER tower layer (installed
        // before RBAC, below) as the user-visible rejection point.
        .with_max_request_body_bytes(config.max_request_body)
        .with_cancellation_token(session_ct.clone());
    rmcp_config.session_store = session_store;
    let event_store = config.event_store.take();
    let (binding_secret, task_binding_secret) = resolve_binding_secret(&config)?;
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(RbacContextHandler::new(
                handler_factory(),
                Arc::clone(&rbac_for_handler),
                tool_list_filtering,
            )
            .with_task_binding(task_binding_secret.clone()))
        },
        {
            let mut mgr = LocalSessionManager::default();
            mgr.session_config.keep_alive = Some(config.session_idle_timeout);
            if let Some(store) = event_store {
                mgr = mgr.with_event_store(store);
            }
            mgr.into()
        },
        rmcp_config,
    );

    // Build the MCP route, optionally wrapped with auth and RBAC middleware.
    let mut mcp_router = axum::Router::new().nest_service("/mcp", mcp_service);

    // Build auth state eagerly when auth is configured so we can wire both
    // the auth middleware *and* the optional admin router against the same
    // state. The middleware itself is installed further down in layer order.
    let auth_state: Option<Arc<AuthState>> = match &config.auth {
        Some(auth_config) if auth_config.enabled => {
            let rate_limiter = auth_config.rate_limit.as_ref().map(build_rate_limiter);
            let pre_auth_limiter = auth_config.rate_limit.as_ref().map(build_pre_auth_limiter);

            #[cfg(feature = "oauth")]
            let jwks_cache = auth_config
                .oauth
                .as_ref()
                .map(|oauth_cfg| JwksCache::new(oauth_cfg).map(Arc::new))
                .transpose()
                .map_err(|error| io::Error::other(format!("JWKS HTTP client: {error}")))?;

            Some(Arc::new(AuthState {
                api_keys: ArcSwap::new(Arc::new(auth_config.api_keys.clone())),
                rate_limiter,
                pre_auth_limiter,
                #[cfg(feature = "oauth")]
                jwks_cache,
                seen_identities: SeenIdentitySet::new(),
                counters: AuthCounters::default(),
                // Absolute only when `public_url` supplies a trustworthy
                // external origin. Without it `derive_server_url` falls back
                // to the bind address, which behind a TLS-terminating proxy
                // is an internal `http://` address -- advertising that would
                // send clients somewhere they cannot reach. `None` keeps the
                // relative path, which resolves against whatever origin the
                // client was actually challenged from.
                resource_metadata_url: config.public_url.as_deref().map(mcp_resource_metadata_url),
                log_context: AuthLogContext::new(&config.log_context, &rbac_swap.load()),
            }))
        }
        _ => None,
    };

    // Optional /admin/* diagnostic routes. Merged BEFORE the
    // body-limit/timeout/RBAC/origin/auth layers so all of them apply.
    if config.admin_enabled {
        let Some(auth_state_ref) = &auth_state else {
            return Err(anyhow::anyhow!(
                "admin_enabled=true requires auth to be configured and enabled"
            ));
        };
        let admin_state = AdminState {
            started_at: Instant::now(),
            name: config.name.clone(),
            version: config.version.clone(),
            auth: Some(Arc::clone(auth_state_ref)),
            rbac: Arc::clone(&rbac_swap),
        };
        let admin_cfg = AdminConfig {
            role: config.admin_role.clone(),
        };
        mcp_router = mcp_router.merge(admin_router(admin_state, &admin_cfg));
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
    if let Some(secret) = binding_secret {
        mcp_router = mcp_router.layer(from_fn(move |req, next| {
            let secret_for_mw = secret.clone();
            session_binding_middleware(secret_for_mw, req, next)
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
        let deny_log_knobs = DenyLogKnobs::from_config(&config.log_context);
        mcp_router = mcp_router.layer(from_fn(move |req, next| {
            let policy = rbac_for_mw.load_full();
            let tl = tool_limiter.clone();
            rbac_middleware(policy, tl, deny_log_knobs, req, next)
        }));
    }

    // [2] Auth layer (runs before RBAC so AuthIdentity is in extensions).
    if let Some(auth_config) = &config.auth
        && auth_config.enabled
    {
        let Some(state) = &auth_state else {
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
        mcp_router = mcp_router.layer(from_fn(move |req, next| {
            let auth_state_clone = Arc::clone(&state_for_mw);
            auth_middleware(auth_state_clone, req, next)
        }));
    }

    // [3] Request timeout (returns 408 on expiry). Bounds the inner service
    // response future: the time until a Response is produced. Response body
    // transfer/streaming (including SSE body frames) is not covered.
    mcp_router = mcp_router.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        config.request_timeout,
    ));

    // [4] Request body size limit (OUTERMOST on /mcp). Prevents OOM /
    // DoS from oversized payloads BEFORE any inner layer (auth, RBAC)
    // attempts to buffer or parse the body.
    mcp_router = mcp_router.layer(RequestBodyLimitLayer::new(config.max_request_body));

    // Compute the effective allowed-origins list for the outer
    // origin-check layer (installed on the merged router below). When
    // `allowed_origins` is empty but `public_url` is set, auto-derive
    // the origin from the public URL so MCP clients (e.g. Claude Code)
    // that send `Origin: <server-url>` are accepted without explicit
    // config.
    let allowed_origins = effective_allowed_origins(&config);
    let cors_origins = Arc::clone(&allowed_origins);
    let request_log = Arc::new(RequestLogConfig {
        log_request_headers: config.log_request_headers,
        exclude_paths: config.request_log_exclude_paths.iter().cloned().collect(),
        fields: config.log_context.clone(),
    });

    let readyz_route = config.readiness_check.take().map_or_else(
        || get(healthz),
        |check| get(move || readyz(Arc::clone(&check))),
    );

    let mut router = axum::Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", readyz_route)
        .route(
            "/version",
            get({
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
                    let payload = Arc::clone(&payload_bytes);
                    async move { ([(CONTENT_TYPE, "application/json")], payload.to_vec()) }
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
    router = install_extra_router(router, &mut config);

    // RFC 9728: Protected Resource Metadata endpoint.
    // When OAuth is configured, serve full metadata with authorization_servers.
    // Otherwise, serve a minimal document with just the resource URL and no
    // authorization_servers -- this tells MCP clients (e.g. Claude Code SDK)
    // that the server exists but does NOT require OAuth authentication,
    // preventing them from gating the connection behind a broken auth flow.
    let server_url = derive_server_url(&config);
    let resource_url = format!("{server_url}/mcp");

    #[cfg(feature = "oauth")]
    let prm_metadata = if let Some(auth_config) = &config.auth
        && let Some(oauth_config) = &auth_config.oauth
    {
        protected_resource_metadata(&resource_url, &server_url, oauth_config)
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
        get(move || {
            let metadata = prm_root.clone();
            async move { axum::Json(metadata) }
        }),
    );
    router = router.route(
        "/.well-known/oauth-protected-resource/mcp",
        get(move || {
            let metadata = prm_metadata.clone();
            async move { axum::Json(metadata) }
        }),
    );

    // OAuth 2.1 proxy endpoints: when an OAuth proxy is configured, expose
    // /authorize, /token, /register, and authorization server metadata so
    // MCP clients can perform Authorization Code + PKCE against the upstream
    // IdP (e.g. Keycloak) transparently.
    #[cfg(feature = "oauth")]
    if let Some(auth_config) = &config.auth
        && let Some(oauth_config) = &auth_config.oauth
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
        // Align CORS with the origin middleware: the predicate matches the
        // same normalized `AllowedOrigin` set, so an entry that normalizes
        // equal (case, default port, one root trailing slash) is accepted by
        // both layers, and nothing the middleware rejects is granted CORS.
        let cors_allowed = Arc::clone(&cors_origins);
        let allow_origin = AllowOrigin::predicate(move |origin: &HeaderValue, _parts: &Parts| {
            origin
                .to_str()
                .is_ok_and(|value| request_origin_allowed(value, &cors_allowed))
        });
        let cors = CorsLayer::new()
            .allow_origin(allow_origin)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([CONTENT_TYPE, AUTHORIZATION]);
        router = router.layer(cors);
    }

    // Optional response compression (gzip + brotli). Skips small bodies
    // to avoid overhead. Applied after CORS so preflight responses remain
    // uncompressed.
    if config.compression_enabled {
        use tower_http::compression::Predicate as _;
        let predicate =
            DefaultPredicate::new().and(SizeAbove::new(u64::from(config.compression_min_size)));
        router = router.layer(
            CompressionLayer::new()
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
            .layer(HandleErrorLayer::new(overloaded_response))
            .layer(LoadShedLayer::new())
            .layer(ConcurrencyLimitLayer::new(max));
        router = router.layer(overload_handler);
        tracing::info!(max, "global concurrency limit enabled");
    }

    // JSON fallback for unmatched routes. Without this, axum returns
    // an empty-body 404 that breaks MCP clients (e.g. Claude Code SDK)
    // when they probe OAuth endpoints like /authorize or /token.
    router = router.fallback(not_found_fallback);

    // Prometheus metrics: recording middleware + separate listener.
    #[cfg(feature = "metrics")]
    if config.metrics_enabled {
        // Caller-supplied handle, or a fresh registry. `.take()` moves the
        // handle out of the config (same pattern as the session/event stores).
        let metrics: Arc<McpMetrics> = if let Some(handle) = config.metrics_handle.take() {
            handle
        } else {
            Arc::new(McpMetrics::new().map_err(|error| anyhow::anyhow!("metrics init: {error}"))?)
        };
        // Security hardening: the three framework collectors must be bound to
        // the served registry whatever the caller pre-registered there.
        // Evict-then-register; a conflict on the reserved namespace fails
        // startup closed instead of serving silently empty telemetry.
        ensure_framework_metrics_registered(&metrics)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let metrics_clone = Arc::clone(&metrics);
        router = router.layer(from_fn(move |req: Request<Body>, next: Next| {
            let metrics_for_mw = Arc::clone(&metrics_clone);
            metrics_middleware(metrics_for_mw, req, next)
        }));
        let metrics_bind = config.metrics_bind.clone();
        let metrics_shutdown = ct.clone();
        // The metrics listener is plaintext whatever the main server's TLS
        // setting, so clone the operator's effective security-headers config
        // and let the listener apply it with `is_tls = false` (no HSTS).
        let metrics_security_headers = config.security_headers.clone();
        let _metrics_task = tokio::spawn(async move {
            if let Err(error) = serve_metrics_with_security_headers(
                metrics_bind,
                metrics,
                metrics_shutdown,
                metrics_security_headers,
            )
            .await
            {
                tracing::error!("metrics listener failed: {error}");
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
            request_id_header: if config.log_context.request_id {
                HeaderName::from_bytes(config.log_context.request_id_header.as_bytes()).ok()
            } else {
                None
            },
        }))
    };
    if forward_resolver.is_some() {
        tracing::info!(
            proxies = config.trusted_proxies.len(),
            "trusted-forwarder mode enabled: limiters key by resolved client IP"
        );
    }
    // Request logging sits just inside peer normalization, so `ClientIp` and
    // trusted `RequestId` exist, and outside every other inner layer, so
    // overload-503s, 404s and auth failures are logged; origin-rejected
    // requests are logged by the origin layer.
    let request_log_inner = Arc::clone(&request_log);
    router = router.layer(from_fn(move |req, next| {
        let cfg = Arc::clone(&request_log_inner);
        request_log_middleware(cfg, req, next)
    }));

    router = router.layer(from_fn(move |req, next| {
        let resolver_clone = forward_resolver.clone();
        normalize_peer_addr_middleware(resolver_clone, req, next)
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
    router = router.layer(from_fn(move |req, next| {
        let origins = Arc::clone(&allowed_origins);
        let log_cfg = Arc::clone(&request_log);
        origin_check_middleware(origins, log_cfg, req, next)
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
    router = router.layer(from_fn(move |req, next| {
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
    let mtls_config = config
        .auth
        .as_ref()
        .and_then(|auth| auth.mtls.as_ref())
        .cloned();

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

// The guard is never disarmed on purpose: cancelling on both the success and
// the failure path is intended (cancelling twice is a no-op).
// Drop audit (2026-10-04): non-blocking, sync `CancellationToken::cancel`; no
// I/O, no await, no panic path.
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Forwards an externally-supplied shutdown token into the server-internal one.
///
/// Returns the task handle so the wiring can be exercised directly in tests.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
)]
fn spawn_external_shutdown_bridge(
    external: CancellationToken,
    internal: CancellationToken,
) -> JoinHandle<()> {
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
#[inline]
pub async fn serve<H, F>(
    config: Validated<McpServerConfig>,
    handler_factory: F,
) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config_inner = config.into_inner();
    #[expect(
        deprecated,
        reason = "internal serve() reads `bind_addr` to construct the listener; field becomes pub(crate) in 1.0"
    )]
    let bind_addr = config_inner.bind_addr.clone();
    let (router, params) =
        build_app_router(config_inner, handler_factory).map_err(anyhow_to_startup)?;
    let _cancel_guard = CancelOnDrop(params.ct.clone());

    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| io_to_startup(&format!("bind {bind_addr}"), error))?;
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
#[inline]
pub async fn serve_with_listener<H, F>(
    listener: TcpListener,
    config: Validated<McpServerConfig>,
    handler_factory: F,
    ready_tx: Option<Sender<SocketAddr>>,
    shutdown: Option<CancellationToken>,
) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config_inner = config.into_inner();
    let local_addr = listener
        .local_addr()
        .map_err(|error| io_to_startup("listener.local_addr", error))?;
    let (router, params) =
        build_app_router(config_inner, handler_factory).map_err(anyhow_to_startup)?;
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
        // Receiver may have been dropped (test gave up). That's fine; the
        // error only carries this dropped-receiver case.
        if tx.send(local_addr).is_err() {
            tracing::debug!("readiness signal receiver dropped before the address was sent");
        }
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
#[expect(
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
/// # Errors
///
/// Returns an error if the TLS listener cannot be constructed, if the
/// mTLS client-auth roots cannot be loaded, or if the axum server exits
/// with an error.
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
#[expect(
    clippy::too_many_arguments,
    clippy::cognitive_complexity,
    reason = "server start-up threads TLS, reload state, and graceful shutdown through one flow"
)]
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
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
    use tokio::time::sleep;

    // `shutdown_trigger` fires when the FIRST source resolves: either
    // an OS signal (Ctrl-C / SIGTERM) or external cancellation of `ct`
    // (which the test harness uses for deterministic shutdown).
    let shutdown_trigger = CancellationToken::new();
    {
        let trigger = shutdown_trigger.clone();
        let parent = ct.clone();
        let _shutdown_trigger_task = tokio::spawn(async move {
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
        let shutdown_ct = ct.clone();
        async move {
            trigger.cancelled().await;
            tracing::info!("shutting down (grace period: {shutdown_timeout:?})");
            shutdown_ct.cancel();
        }
    };

    let force_exit_timer = {
        let trigger = shutdown_trigger.clone();
        async move {
            trigger.cancelled().await;
            sleep(shutdown_timeout).await;
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
            let _crl_refresher_task = tokio::spawn(mtls_revocation::run_crl_refresher(
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
    oauth_config: &OAuthConfig,
    auth_state: Option<&Arc<AuthState>>,
    max_request_body: usize,
    admin_role: &str,
) -> Result<axum::Router, RmcpServerKitError> {
    use axum::{
        extract::RawQuery,
        middleware::from_fn,
        routing::{get, post},
    };
    use tower_http::limit::RequestBodyLimitLayer;

    use crate::oauth::{authorization_server_metadata, handle_authorize, handle_token};

    let Some(proxy) = &oauth_config.proxy else {
        return Ok(router);
    };

    // Single shared HTTP client for all proxy endpoints. Cloning is
    // cheap (refcounted) and shares the underlying connection pool.
    let http = OauthHttpClient::with_config(oauth_config)?;

    // Build the proxy endpoints on a DEDICATED sub-router so the request-body
    // cap below applies to exactly these routes and cannot leak onto `/mcp`,
    // health, or `/version`. Without this, the proxy routes would fall back to
    // axum's 2 MB `DefaultBodyLimit` and silently ignore the operator's
    // configured `max_request_body` (rust-review MEDIUM finding).
    let base_proxy_router = axum::Router::new();

    let asm = authorization_server_metadata(server_url, oauth_config);
    let proxy_router_with_metadata = base_proxy_router.route(
        "/.well-known/oauth-authorization-server",
        get(move || {
            let metadata = asm.clone();
            async move { axum::Json(metadata) }
        }),
    );

    let proxy_authorize = proxy.clone();
    let proxy_router_with_authorize = proxy_router_with_metadata.route(
        "/authorize",
        get(move |RawQuery(query): RawQuery| {
            let proxy_authorize_clone = proxy_authorize.clone();
            async move { handle_authorize(&proxy_authorize_clone, &query.unwrap_or_default()) }
        }),
    );

    let proxy_token = proxy.clone();
    let token_http = http.clone();
    let proxy_router_with_token = proxy_router_with_authorize.route(
        "/token",
        post(move |body: String| {
            let proxy_token_clone = proxy_token.clone();
            let token_http_clone = token_http.clone();
            async move { handle_token(&token_http_clone, &proxy_token_clone, &body).await }
        })
        .layer(from_fn(oauth_token_cache_headers_middleware)),
    );

    let proxy_register = proxy.clone();
    let proxy_router = proxy_router_with_token.route(
        "/register",
        post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            use crate::oauth::handle_register;
            let proxy_config = proxy_register;
            async move { axum::Json(handle_register(&proxy_config, &body)) }
        })
        .layer(from_fn(oauth_token_cache_headers_middleware)),
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
    let merged_proxy_router = proxy_router
        .merge(admin_router)
        .layer(RequestBodyLimitLayer::new(max_request_body));

    let merged_router = router.merge(merged_proxy_router);

    tracing::info!(
        introspect = proxy.expose_admin_endpoints && proxy.introspection_url.is_some(),
        revoke = proxy.expose_admin_endpoints && proxy.revocation_url.is_some(),
        max_request_body,
        "OAuth 2.1 proxy endpoints enabled (/authorize, /token, /register)"
    );
    Ok(merged_router)
}

/// Build the optional `/introspect` + `/revoke` admin sub-router.
///
/// Layered with [`oauth_token_cache_headers_middleware`] so RFC 6749 §5.1
/// / RFC 6750 §5.4 cache headers are emitted, and conditionally with the
/// auth middleware when `proxy.require_auth_on_admin_endpoints` is set.
///
/// # Errors
///
/// Returns an error if admin endpoints require authentication but no auth
/// state was provided.
#[cfg(feature = "oauth")]
fn build_oauth_admin_router(
    proxy: &OAuthProxyConfig,
    http: OauthHttpClient,
    auth_state: Option<&Arc<AuthState>>,
    admin_role: &str,
) -> Result<axum::Router, RmcpServerKitError> {
    use axum::{middleware::from_fn, routing::post};

    use crate::{
        admin::require_admin_role,
        oauth::{handle_introspect, handle_revoke},
    };
    let mut admin_router = axum::Router::new();
    if proxy.introspection_url.is_some() {
        let proxy_introspect = proxy.clone();
        let introspect_http = http.clone();
        admin_router = admin_router.route(
            "/introspect",
            post(move |body: String| {
                let proxy_config = proxy_introspect.clone();
                let http_client = introspect_http.clone();
                async move { handle_introspect(&http_client, &proxy_config, &body).await }
            }),
        );
    }
    if proxy.revocation_url.is_some() {
        let proxy_revoke = proxy.clone();
        let revoke_http = http;
        admin_router = admin_router.route(
            "/revoke",
            post(move |body: String| {
                let proxy_config = proxy_revoke.clone();
                let http_client = revoke_http.clone();
                async move { handle_revoke(&http_client, &proxy_config, &body).await }
            }),
        );
    }

    let admin_router_with_headers =
        admin_router.layer(from_fn(oauth_token_cache_headers_middleware));

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
        Ok(admin_router_with_headers
            .layer(from_fn(move |req, next| {
                let role = Arc::clone(&required_role);
                require_admin_role(role, req, next)
            }))
            .layer(from_fn(move |req, next| {
                let mw_state = Arc::clone(&state_for_mw);
                auth_middleware(mw_state, req, next)
            })))
    } else {
        Ok(admin_router_with_headers)
    }
}

/// This server's externally-visible origin.
///
/// Prefers the operator-supplied `public_url`; otherwise reconstructs it from
/// the bind address, choosing the scheme from whether TLS is configured.
/// Shared by the OAuth metadata documents and the `WWW-Authenticate`
/// `resource_metadata` URL so they can never disagree.
#[expect(
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
    use axum::http::Uri;
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];

    if let Some(url) = public_url
        && let Ok(uri) = url.parse::<Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|entry| entry == &host) {
            hosts.push(host);
        }

        let authority_str = authority.as_str().to_owned();
        if !hosts.iter().any(|entry| entry == &authority_str) {
            hosts.push(authority_str);
        }
    }

    if let Ok(uri) = format!("http://{bind_addr}").parse::<Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|entry| entry == &host) {
            hosts.push(host);
        }

        let authority_str = authority.as_str().to_owned();
        if !hosts.iter().any(|entry| entry == &authority_str) {
            hosts.push(authority_str);
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
impl Connected<IncomingStream<'_, TlsListener>> for TlsConnInfo {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        let addr = *stream.remote_addr();
        let identity = stream.io().identity().cloned();
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

/// Default upper bound on concurrently in-flight TLS handshakes.
///
/// When saturated, the acceptor task stops pulling new connections from the
/// kernel backlog (backpressure) instead of accepting and dropping them
/// in user space.
///
/// Configurable since 1.9.0 via
/// [`McpServerConfig::with_max_concurrent_tls_handshakes`].
const DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES: usize = 256;

/// Capacity of the completed-handshake queue between the acceptor task and
/// `axum::serve`'s `accept()` loop.
///
/// Handshake workers block on `send` when the queue is full, so a slow
/// accept loop back-pressures handshakes rather than buffering completed
/// connections unboundedly.
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
    acceptor_task: JoinHandle<()>,
}

impl TlsListener {
    /// Build a TLS-wrapping listener that accepts and handshakes connections
    /// on a dedicated background task.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or key material cannot be loaded,
    /// or if the underlying listener address cannot be read.
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
        use rustls::crypto::ring::default_provider;
        if default_provider().install_default().is_err() {
            tracing::debug!("ring crypto provider was already installed");
        }

        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let mtls_default_role =
            mtls_config.map_or_else(|| "viewer".to_owned(), |cfg| cfg.default_role.clone());

        let tls_config = build_tls_server_config(certs, key, mtls_config, crl_set)?;

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
        tls_stream: &TlsStream<TcpStream>,
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
    use tokio::time::timeout;
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
            Err(err) => {
                tracing::debug!("TCP accept error: {err}");
                continue;
            }
        };
        if tx.is_closed() {
            // The listener was dropped (shutdown): stop accepting.
            return;
        }
        let handshake_acceptor = acceptor.clone();
        let handshake_role = default_role.clone();
        let completed_tx = tx.clone();
        let _handshake_task = tokio::spawn(async move {
            let _permit = permit;
            // Attribute this handshake's CRL-discovery admission to the peer IP
            // so one peer cannot drain another peer's discovery budget. rustls
            // calls `verify_client_cert` synchronously inside `accept`'s own
            // poll, and `tokio::time::timeout` polls its wrapped future first,
            // so the scope nests correctly and is not leaked on the timeout arm.
            let accept_fut = handshake_acceptor.accept(stream);
            match timeout(
                handshake_timeout,
                mtls_revocation::CURRENT_HANDSHAKE_PEER.scope(addr.ip(), accept_fut),
            )
            .await
            {
                Ok(Ok(tls_stream)) => {
                    let identity =
                        TlsListener::extract_handshake_identity(&tls_stream, &handshake_role, addr);
                    let wrapped = AuthenticatedTlsStream {
                        inner: tls_stream,
                        identity,
                    };
                    // The receiver only disappears during shutdown; discard
                    // the completed connection quietly rather than logging.
                    drop(completed_tx.send((wrapped, addr)).await);
                }
                Ok(Err(err)) => {
                    tracing::debug!("TLS handshake failed from {addr}: {err}");
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
    /// The wrapped TLS stream carrying the handshake state.
    inner: TlsStream<TcpStream>,
    /// Verified mTLS client identity extracted at handshake time, if any.
    identity: Option<AuthIdentity>,
}

impl AuthenticatedTlsStream {
    /// Returns the verified mTLS client identity, if any.
    #[must_use]
    pub(crate) const fn identity(&self) -> Option<&AuthIdentity> {
        self.identity.as_ref()
    }
}

impl Debug for AuthenticatedTlsStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AuthenticatedTlsStream")
            .field("identity", &self.identity.as_ref().map(|id| &id.name))
            .finish_non_exhaustive()
    }
}

impl AsyncRead for AuthenticatedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> task::Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Listener for TlsListener {
    type Io = AuthenticatedTlsStream;
    type Addr = SocketAddr;

    /// Yield the next fully-handshaken TLS connection.
    ///
    /// Cancel safety: this is a plain `mpsc::Receiver::recv`, so cancelling
    /// the future (axum selects it against graceful shutdown) never loses
    /// a connection.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        use core::future::pending;
        if let Some(pair) = self.rx.recv().await {
            return pair;
        }
        // The channel only closes if the acceptor task terminated, which
        // means the TcpListener is gone and the OS already refuses new
        // connections. `Listener::accept` is infallible and panicking is
        // forbidden, so park forever: existing connections keep being
        // served and graceful shutdown still completes.
        tracing::error!("TLS acceptor task terminated; no further connections will be accepted");
        pending().await
    }

    fn local_addr(&self) -> IoResult<Self::Addr> {
        Ok(self.local_addr)
    }
}

// Aborts the acceptor task; in-flight handshake workers observe the closed
// channel and exit on their own.
// Drop audit (2026-10-04): non-blocking, sync `JoinHandle::abort`; no I/O, no
// await, no panic path.
impl Drop for TlsListener {
    fn drop(&mut self) {
        // Stop accepting immediately and release the bound port. In-flight
        // handshake workers notice the closed channel and exit quietly.
        self.acceptor_task.abort();
    }
}

/// Load one or more PEM-encoded certificates from `path`.
///
/// # Errors
///
/// Returns an error if the file cannot be read, contains no certificates,
/// or contains an invalid certificate.
fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject as _;
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|err| anyhow::anyhow!("failed to read certs from {}: {err}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|err| anyhow::anyhow!("invalid cert in {}: {err}", path.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certs)
}

/// Load the CA certificate chain from `path` and build a root store.
///
/// # Errors
///
/// Returns an error if the certificate file cannot be read or if any
/// certificate is invalid.
fn load_client_auth_roots(
    path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, Arc<RootCertStore>)> {
    let ca_certs = load_certs(path)?;
    let mut root_store = RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .map_err(|error| anyhow::anyhow!("invalid CA cert: {error}"))?;
    }

    Ok((ca_certs, Arc::new(root_store)))
}

/// Load a PEM-encoded private key from `path`.
///
/// # Errors
///
/// Returns an error if the key cannot be read or parsed.
fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject as _;
    PrivateKeyDer::from_pem_file(path)
        .map_err(|err| anyhow::anyhow!("failed to read key from {}: {err}", path.display()))
}

/// Test/production seam: builds a `ServerConfig` from an explicit verifier
/// so tests can inject one without file-backed CA/CRL setup. Production
/// code reaches this only via `build_tls_server_config` below.
///
/// # Errors
///
/// Returns an error if the certificate/key pair cannot be assembled into a
/// usable `ServerConfig`.
fn build_tls_server_config_from_verifier(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    verifier: Arc<dyn ClientCertVerifier>,
    disable_resumption: bool,
) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::{
        server::NoServerSessionStorage,
        version::{TLS12, TLS13},
    };
    let mut tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    if disable_resumption {
        // SECURITY: rustls restores `peer_certificates` from cached session
        // state on resumed handshakes WITHOUT calling
        // `ClientCertVerifier::verify_client_cert` (rustls 0.23:
        // server/tls12.rs:287-290, server/tls13.rs:371-375; the only
        // verifier call sites are the full-handshake ExpectCertificate
        // states at tls12.rs:490-493 and tls13.rs:1128-1130). That function
        // is also the sole site of certificate expiry and chain validation
        // (webpki/client_verifier.rs:385-394 `verify_for_usage(.., now, ..)`),
        // so a resumed handshake re-checks neither revocation NOR
        // `notAfter`. Since this crate derives `AuthIdentity` from
        // `peer_certificates()`, a resumed connection would yield a fully
        // authenticated identity from a chain that was never re-checked.
        // Disabling the session store closes both the TLS 1.2 session-ID
        // path (`can_cache() == false` suppresses session-ID issuance) and
        // the TLS 1.3 stateful-ticket path (`put()` returning false makes
        // ticket emission bail). NOTE: this relies on `ticketer` remaining
        // disabled (rustls' default); enabling a ticketer would reintroduce
        // stateless TLS 1.3 resumption and must not be done for mTLS.
        tls_config.session_storage = Arc::new(NoServerSessionStorage {});
        tls_config.send_tls13_tickets = 0;
        tracing::info!(
            "TLS session resumption disabled for mTLS listener; every connection performs full client-certificate verification"
        );
    }

    Ok(tls_config)
}

/// Builds the production verifier (CRL-backed or plain webpki).
///
/// Session resumption is disabled whenever mTLS is configured at all: non-CRL
/// mTLS still relies on `verify_client_cert` for expiry and chain validation,
/// so scoping to `crl_enabled` alone would leave that path unprotected. The
/// non-mTLS branch is untouched -- it requests no client cert, so resumption
/// there is not security-relevant.
///
/// # Errors
///
/// Returns an error if the CRL verifier is requested without CRL state or if
/// the CA material cannot be loaded.
fn build_tls_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    mtls_config: Option<&MtlsConfig>,
    crl_set: Option<Arc<CrlSet>>,
) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::{
        server::WebPkiClientVerifier,
        version::{TLS12, TLS13},
    };
    if let Some(mtls) = mtls_config {
        let verifier: Arc<dyn ClientCertVerifier> = if mtls.crl_enabled {
            let Some(crl_state) = crl_set else {
                return Err(anyhow::anyhow!(
                    "mTLS CRL verifier requested but CRL state was not initialized"
                ));
            };
            Arc::new(DynamicClientCertVerifier::new(crl_state))
        } else {
            let (_, root_store) = load_client_auth_roots(&mtls.ca_cert_path)?;
            if mtls.required {
                WebPkiClientVerifier::builder(root_store)
                    .build()
                    .map_err(|err| anyhow::anyhow!("mTLS verifier error: {err}"))?
            } else {
                WebPkiClientVerifier::builder(root_store)
                    .allow_unauthenticated()
                    .build()
                    .map_err(|err| anyhow::anyhow!("mTLS verifier error: {err}"))?
            }
        };

        tracing::info!(
            ca = %mtls.ca_cert_path.display(),
            required = mtls.required,
            crl_enabled = mtls.crl_enabled,
            "mTLS client auth configured"
        );

        build_tls_server_config_from_verifier(certs, key, verifier, mtls_config.is_some())
    } else {
        Ok(
            rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)?,
        )
    }
}

// cancel-safe: builds a constant JSON body with no awaits and no shared state.
/// Liveness probe handler returning a static `{"status":"ok"}` payload.
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
    let _name = map.insert("name".into(), name.into());
    let _version = map.insert("version".into(), version.into());
    let _kit_version = map.insert(
        "rmcp_server_kit_version".into(),
        env!("CARGO_PKG_VERSION").into(),
    );
    if expose_build_metadata {
        let _build_sha = map.insert(
            "build_git_sha".into(),
            option_env!("RMCP_SERVER_KIT_BUILD_SHA")
                .unwrap_or("unknown")
                .into(),
        );
        let _build_time = map.insert(
            "build_timestamp".into(),
            option_env!("RMCP_SERVER_KIT_BUILD_TIME")
                .unwrap_or("unknown")
                .into(),
        );
        let _rustc_version = map.insert(
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

// NOT cancel-safe: the kit itself mutates no state here, but this awaits a
// consumer-supplied readiness future. Cancellation drops that future at
// whatever await it is parked on, so cancel safety is the callback author's
// contract -- a readiness probe must not leave partial state behind.
/// Readiness probe handler that awaits the configured check.
async fn readyz(check: ReadinessCheck) -> impl IntoResponse {
    let status = check().await;
    let ready = status
        .get("ready")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(status))
}

/// Wait for SIGINT (ctrl-c) or SIGTERM (container stop).
///
/// On non-Unix platforms, only SIGINT is handled.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
)]
// cancel-safe: signal-listener futures are cancel-safe per tokio docs and no
// partial state is carried across the select.
async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal as unix_signal};
        match unix_signal(SignalKind::terminate()) {
            Ok(mut term) => {
                // cancel-safe: signal-listener futures are cancel-safe per
                // tokio docs; no partial state in either arm.
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to register SIGTERM handler, using SIGINT only");
                if ctrl_c.await.is_err() {
                    tracing::debug!("SIGINT handling unavailable on this platform");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if ctrl_c.await.is_err() {
            tracing::debug!("SIGINT handling unavailable on this platform");
        }
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
    use axum::extract::MatchedPath;

    let method = match *req.method() {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        // HTTP permits extension methods, so anything else collapses to a
        // single bucket rather than minting a series per invented verb.
        _ => "OTHER",
    };

    let path = req.extensions().get::<MatchedPath>().map_or_else(
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

/// Bind the three framework collectors to `metrics.registry` authoritatively.
///
/// `Registry::register` compares descriptor and collector IDs, not object
/// identity (and checks descriptor IDs *before* the dimension check), so a
/// descriptor-equivalent squatter also yields `AlreadyReg`. Accepting that as
/// success would leave the framework's own `http_requests_total` etc.
/// unregistered while `metrics_middleware` kept incrementing them - silent
/// telemetry loss.
///
/// Each collector is therefore evicted (a clone) and then registered for real.
/// `unregister` deliberately leaves the registry's dim-hash map populated for
/// the process lifetime, so a squatter whose help text or variable-label names
/// differ cannot even be registered alongside - it fails its own `register`
/// with a reserved-name conflict, i.e. the namespace is protected at the
/// earliest point.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if a framework collector cannot be
/// registered (e.g. a reserved-name conflict that eviction did not clear).
#[cfg(feature = "metrics")]
fn ensure_framework_metrics_registered(metrics: &McpMetrics) -> Result<(), RmcpServerKitError> {
    use prometheus::core::Collector;

    // `Box<dyn Collector>` is not `Clone`; each factory hands out a *fresh*
    // boxed clone of the same collector. `MetricVec` clones share one
    // `Arc<MetricVecCore>`, so descriptors and sample storage stay identical.
    type BoxedFactory<'factory> = &'factory dyn Fn() -> Box<dyn Collector>;
    let factories: [BoxedFactory<'_>; 3] = [
        &|| -> Box<dyn Collector> { Box::new(metrics.http_requests_total.clone()) },
        &|| -> Box<dyn Collector> { Box::new(metrics.http_request_duration_seconds.clone()) },
        &|| -> Box<dyn Collector> { Box::new(metrics.rate_limited_total.clone()) },
    ];

    for make in factories {
        // Evict whatever occupies this collector/descriptor ID. A "collector is
        // not registered" error is expected here and non-fatal.
        drop(metrics.registry.unregister(make()));
        metrics.registry.register(make()).map_err(|error| {
            RmcpServerKitError::Startup(format!(
                "metrics registry conflict on reserved rmcp_server_kit_* name: {error}"
            ))
        })?;
    }
    Ok(())
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
    metrics: Arc<McpMetrics>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    use core::fmt::NumBuffer;

    let (method, path) = metrics_labels(&req);
    let start = Instant::now();

    let _previous_metrics = req.extensions_mut().insert(Arc::clone(&metrics));
    let response = next.run(req).await;

    let mut status_buf = NumBuffer::<u16>::new();
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
pub(crate) async fn security_headers_middleware(
    is_tls: bool,
    cfg: Arc<SecurityHeadersConfig>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use axum::http::header;

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // Strip server identity headers to reduce information leakage.
    let _removed_server = headers.remove(header::SERVER);
    let _removed_powered_by = headers.remove(HeaderName::from_static("x-powered-by"));

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
    headers: &mut HeaderMap,
    name: HeaderName,
    override_value: Option<&str>,
    default: &'static str,
) {
    use axum::http::HeaderValue;

    match override_value {
        None => {
            let _previous = headers.insert(name, HeaderValue::from_static(default));
        }
        Some("") => {
            // Operator explicitly opted out of this header.
        }
        Some(override_text) => match HeaderValue::from_str(override_text) {
            Ok(hv) => {
                let _previous = headers.insert(name, hv);
            }
            Err(err) => {
                tracing::error!(
                    header = %name,
                    error = %err,
                    "invalid security header override reached middleware; using default"
                );
                let _previous = headers.insert(name, HeaderValue::from_static(default));
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
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] naming the offending field when an
/// override value is not a valid header value, or when
/// `strict_transport_security` smuggles in `preload`.
pub(crate) fn validate_security_headers(
    cfg: &SecurityHeadersConfig,
) -> Result<(), RmcpServerKitError> {
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
        let Some(header_value) = value else { continue };
        if header_value.is_empty() {
            continue;
        }
        if let Err(err) = HeaderValue::from_str(header_value) {
            return Err(RmcpServerKitError::Config(format!(
                "invalid security_headers.{field}: {err}"
            )));
        }
    }

    if let Some(hsts_value) = cfg.strict_transport_security.as_deref()
        && !hsts_value.is_empty()
        && hsts_value.to_ascii_lowercase().contains("preload")
    {
        return Err(RmcpServerKitError::Config(format!(
            "invalid security_headers.strict_transport_security: {hsts_value:?} contains the `preload` directive; \
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
///
/// cancel-safe: the only await is `next.run(req)`; header mutation afterwards
/// is synchronous, so cancellation simply drops the response before it is sent.
#[cfg(feature = "oauth")]
async fn oauth_token_cache_headers_middleware(req: Request<Body>, next: Next) -> Response {
    use axum::http::{HeaderValue, header};

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    let _previous_pragma = headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    let _vary_appended = headers.append(header::VARY, HeaderValue::from_static("Authorization"));
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
/// peer address is deliberately not logged here (the request log runs in the
/// next layer). The request-ID header is honoured only from trusted peers;
/// when multiple instances are present, the last occurrence wins.
// cancel-safe: inserts request extensions synchronously before the single
// `next.run(req)` await; the extensions die with the dropped request.
async fn normalize_peer_addr_middleware(
    resolver: Option<Arc<ForwardResolver>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    use crate::forwarded;

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
            let _connect_info = req.extensions_mut().insert(ConnectInfo(addr));
        }
        let _peer_addr = req.extensions_mut().insert(PeerAddr::new(addr));
        let client_ip = resolver.as_ref().map_or_else(
            || addr.ip(),
            |fwd_resolver| {
                forwarded::resolve_client_ip(
                    addr.ip(),
                    req.headers(),
                    &fwd_resolver.trusted,
                    fwd_resolver.mode,
                    fwd_resolver.max_scanned_entries,
                )
                .unwrap_or_else(|reason| {
                    tracing::debug!(
                        reason = ?reason,
                        "forwarded-header resolution fell back to direct peer"
                    );
                    addr.ip()
                })
            },
        );
        let _client_ip = req.extensions_mut().insert(ClientIp::new(client_ip));
        if let Some(fwd_resolver) = &resolver
            && let Some(name) = &fwd_resolver.request_id_header
            && forwarded::is_trusted(addr.ip(), &fwd_resolver.trusted)
            && let Some(value) = req.headers().get_all(name).iter().next_back()
            && let Ok(raw) = value.to_str()
        {
            let sanitized = sanitize_for_log(raw, MAX_LOGGED_HEADER_CHARS);
            if !sanitized.is_empty() {
                let _request_id = req.extensions_mut().insert(RequestId::new(&sanitized));
            }
        }
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

/// Validate one `trusted_proxies` entry.
///
/// Accepts a CIDR (`ipnet::IpNet`)
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

/// Validate [`LogContextConfig::request_id_header`].
///
/// Requires a
/// syntactically valid HTTP header name that is neither one of
/// [`REDACTED_LOG_HEADERS`] nor `mcp-session-id` (the session ID must
/// never reach a log line). Shared by the builder
/// ([`McpServerConfig::check_trusted_forwarder`]) and the TOML
/// validator so the two cannot drift.
///
/// # Errors
///
/// Returns a message naming `request_id_header` when the name is not a
/// valid header name or is on the forbidden list.
pub(crate) fn validate_request_id_header(name: &str) -> Result<(), String> {
    let _validated_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_err| {
        format!("log_context.request_id_header {name:?} is not a valid header name")
    })?;
    let lower = name.to_ascii_lowercase();
    if REDACTED_LOG_HEADERS.contains(&lower.as_str()) || lower == "mcp-session-id" {
        return Err(format!(
            "log_context.request_id_header {name:?} is not allowed (would leak a redacted or session header into logs)"
        ));
    }
    Ok(())
}

/// Rate-limit key for the current request.
///
/// The resolved [`ClientIp`]
/// when present, else the direct peer from either `ConnectInfo` form.
/// All four built-in limiters key through this helper; it is also the
/// `client_ip` value used by client-context logging.
pub(crate) fn limiter_client_ip(extensions: &Extensions) -> Option<IpAddr> {
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

/// Extract the direct peer IP address for logging.
pub(crate) fn peer_ip_for_log(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<PeerAddr>()
        .map(|peer| peer.addr.ip())
        .or_else(|| {
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip())
        })
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

impl Display for RateLimitKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Unattributed => f.write_str("unattributed"),
        }
    }
}

/// Emitted at most once per process; see [`limiter_client_key`].
static UNATTRIBUTED_WARNED: AtomicBool = AtomicBool::new(false);

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
pub(crate) fn limiter_client_key(extensions: &Extensions) -> RateLimitKey {
    if let Some(ip) = limiter_client_ip(extensions) {
        return RateLimitKey::Ip(ip);
    }
    if !UNATTRIBUTED_WARNED.swap(true, Ordering::Relaxed) {
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
///
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
    use core::num::NonZeroU32;

    let rate = NonZeroU32::new(per_minute.max(1)).unwrap_or(NonZeroU32::MIN);
    let mut quota = governor::Quota::per_minute(rate);
    if let Some(burst_value) = burst.and_then(NonZeroU32::new) {
        quota = quota.allow_burst(burst_value);
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
    exempt: Arc<HashSet<String>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if exempt.contains(req.uri().path()) {
        return next.run(req).await;
    }
    let peer_key = limiter_client_key(req.extensions());
    match limiter.check_key_detailed(&peer_key) {
        Ok(()) => {}
        Err(BoundedLimiterDeny::RateLimited(wait)) => {
            #[cfg(feature = "metrics")]
            {
                use crate::metrics;
                metrics::record_rate_limit_deny(req.extensions(), "extra_route");
            }
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
                StatusCode::SERVICE_UNAVAILABLE,
                "rate limiter capacity exhausted",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// A configured allowed origin, normalized for comparison.
///
/// Built once at router construction by [`parse_allowed_origin`]; the origin
/// middleware and the CORS layer both match against this representation, so
/// the two layers cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowedOrigin {
    /// `(scheme, host, effective_port)` - lowercased, default ports applied.
    Tuple(String, String, u16),
    /// The literal token `null` (opt-in): accepts `Origin: null`.
    Null,
}

impl Display for AllowedOrigin {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Tuple(scheme, host, port) => write!(f, "{scheme}://{host}:{port}"),
            Self::Null => f.write_str("null"),
        }
    }
}

/// Parse an incoming `Origin` header value under the crate's strict rules.
///
/// Accepts exactly `scheme://host[:port]`. Any path (including a bare trailing
/// `/`), query, or fragment is rejected, as is any scheme other than `http` or
/// `https`. Scheme and host are lowercased and default ports are applied, so
/// comparison happens on the effective tuple rather than on the raw string.
fn parse_request_origin_tuple(value: &str) -> Option<(String, String, u16)> {
    parse_origin(value, false)
}

/// Parse a configured allowlist entry: the request rules, plus one optional
/// root trailing `/`, which is normalized away.
fn parse_config_origin_tuple(value: &str) -> Option<(String, String, u16)> {
    parse_origin(value, true)
}

/// Parse an explicit port under the crate's strict rules.
///
/// ASCII digits only - `str::parse` alone would accept `+443` and ` 443` -
/// and no leading zeros, so `0443` is rejected rather than silently
/// normalized to `443`. Port `0` is not a valid origin port.
fn parse_port_token(token: &str) -> Option<u16> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if token.len() > 1 && token.starts_with('0') {
        return None;
    }
    match token.parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(port) => Some(port),
    }
}

/// Shared parser behind [`parse_request_origin_tuple`] and
/// [`parse_config_origin_tuple`].
fn parse_origin(value: &str, allow_root_slash: bool) -> Option<(String, String, u16)> {
    let (scheme, rest) = value.split_once("://")?;
    let scheme_lower = scheme.to_ascii_lowercase();
    let default_port = match scheme_lower.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };

    if rest.is_empty() {
        return None;
    }
    let rest_trimmed = if allow_root_slash {
        rest.strip_suffix('/').unwrap_or(rest)
    } else {
        rest
    };
    if rest_trimmed.is_empty() || rest_trimmed.contains(['/', '?', '#']) {
        return None;
    }

    let (host, port) = if let Some(after_bracket) = rest_trimmed.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:8080`.
        let (inside, tail) = after_bracket.split_once(']')?;
        if inside.is_empty() {
            return None;
        }
        let port = if tail.is_empty() {
            default_port
        } else {
            parse_port_token(tail.strip_prefix(':')?)?
        };
        (format!("[{inside}]"), port)
    } else {
        if rest_trimmed.matches(':').count() > 1 {
            // Unbracketed IPv6 is not a valid origin host.
            return None;
        }
        match rest_trimmed.split_once(':') {
            Some((host, port)) => {
                if host.is_empty() {
                    return None;
                }
                (host.to_owned(), parse_port_token(port)?)
            }
            None => (rest_trimmed.to_owned(), default_port),
        }
    };

    if host.is_empty() || host.contains(|ch: char| ch.is_whitespace() || ch.is_control()) {
        return None;
    }
    if port == 0 {
        return None;
    }
    Some((scheme_lower, host.to_ascii_lowercase(), port))
}

/// Parse a configured allowlist entry into the runtime match representation.
///
/// `null` (case-insensitive) is the opt-in sentinel for `Origin: null`; every
/// other entry must be a bare origin. Startup validation rejects anything
/// else, so a malformed entry here is simply dropped.
fn parse_allowed_origin(value: &str) -> Option<AllowedOrigin> {
    if value.eq_ignore_ascii_case("null") {
        return Some(AllowedOrigin::Null);
    }
    parse_config_origin_tuple(value)
        .map(|(scheme, host, port)| AllowedOrigin::Tuple(scheme, host, port))
}

/// Validate a `public_url` value: it must be an `http`/`https` URL.
///
/// Shared by `McpServerConfig::check` and `config::validate_server_config` so
/// the two public validators cannot disagree.
///
/// # Errors
///
/// Returns a message when `url` does not start with `http://` or `https://`.
pub(crate) fn validate_public_url_value(url: &str) -> Result<(), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!(
            "public_url {url:?} must start with http:// or https://"
        ));
    }
    Ok(())
}

/// Validate one `allowed_origins` entry, returning the operator-facing message
/// on failure.
///
/// Shared by `McpServerConfig::check` and `config::validate_server_config` so
/// the two public validators cannot disagree: a TOML-file consumer must not be
/// told a config is valid and then have `serve()` refuse it at startup.
///
/// # Errors
///
/// Returns a message when `entry` is neither `scheme://host[:port]` nor the
/// literal `null`.
pub(crate) fn validate_allowed_origin_entry(entry: &str) -> Result<(), String> {
    if parse_allowed_origin(entry).is_none() {
        return Err(format!(
            "allowed_origins entry {entry:?} must be scheme://host[:port] (http or https), \
             optionally with one trailing '/', or the literal \"null\""
        ));
    }
    Ok(())
}

/// Match an incoming `Origin` value against the prebuilt allow set.
///
/// Fails closed: a malformed value matches nothing, and only an exact
/// normalized match (or the configured `null` sentinel) is accepted.
fn request_origin_allowed(value: &str, allowed: &[AllowedOrigin]) -> bool {
    if value.eq_ignore_ascii_case("null") {
        return allowed.contains(&AllowedOrigin::Null);
    }
    let Some((scheme, host, port)) = parse_request_origin_tuple(value) else {
        return false;
    };
    allowed.iter().any(|entry| {
        matches!(
            entry,
            AllowedOrigin::Tuple(entry_scheme, entry_host, entry_port)
                if *entry_scheme == scheme && *entry_host == host && *entry_port == port
        )
    })
}

/// Reject requests whose `Origin` header is present but not allowed.
///
/// Per the MCP spec: if the Origin header is present and its value is not in
/// the allowed list, respond with 403 Forbidden. Requests without an Origin
/// header are allowed through (e.g. non-browser clients like curl, SDKs).
///
/// Matching is normalized tuple equality (see [`parse_request_origin_tuple`]),
/// not raw string comparison; a non-UTF-8 or malformed value fails closed with
/// the same 403.
// cancel-safe: origin validation and request logging are synchronous and happen
// before the single `next.run(req)` await; nothing is published on cancellation.
async fn origin_check_middleware(
    allowed: Arc<[AllowedOrigin]>,
    log_cfg: Arc<RequestLogConfig>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use axum::http::header;

    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    // `Origin` is a single-value field: a request carrying more than one is
    // malformed, so fail closed rather than trusting whichever value a
    // different consumer might have read. Requests without the header pass
    // through (curl, SDKs, server-to-server clients).
    let mut origins = req.headers().get_all(header::ORIGIN).iter();
    if let Some(origin) = origins.next() {
        let duplicate_origin_headers = origins.next().is_some();
        let accepted = !duplicate_origin_headers
            && origin
                .to_str()
                .is_ok_and(|value| request_origin_allowed(value, &allowed));
        if !accepted {
            if log_cfg.logs(&path) {
                log_incoming_request(
                    &method,
                    &path,
                    req.headers(),
                    log_cfg.log_request_headers,
                    &RequestLogFields::default(),
                );
            }
            // Non-UTF-8 values are logged as a placeholder rather than
            // lossily converted.
            let logged = origin.to_str().unwrap_or("<non-utf8>");
            let allowed_rendered = allowed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                origin = logged,
                duplicate_origin_headers,
                %method,
                %path,
                allowed = %allowed_rendered,
                "rejected request: Origin not allowed"
            );
            return (StatusCode::FORBIDDEN, "Forbidden: Origin not allowed").into_response();
        }
    }
    next.run(req).await
}

/// Maximum header value length for logging before truncation.
pub(crate) const MAX_LOGGED_HEADER_CHARS: usize = 128;

/// Remove control characters and truncate a string for safe logging.
pub(crate) fn sanitize_for_log(raw: &str, max_chars: usize) -> String {
    let mut out: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_chars)
        .collect();
    if raw.chars().filter(|ch| !ch.is_control()).count() > max_chars {
        out.push_str("...(truncated)");
    }
    out
}

/// Request ID for logging and tracing purposes.
#[derive(Clone, Debug)]
pub(crate) struct RequestId(Arc<str>);

impl RequestId {
    /// Wrap `value` in a fresh request-id handle.
    pub(crate) fn new(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

/// Extract the request ID from extensions for logging.
pub(crate) fn request_id_for_log(ext: &Extensions) -> Option<Arc<str>> {
    ext.get::<RequestId>().map(|id| Arc::clone(&id.0))
}

/// Extract MCP-specific hints (session presence and protocol version) from headers for logging.
pub(crate) fn mcp_hints_for_log(headers: &HeaderMap) -> (bool, Option<String>) {
    let mcp_session = headers.contains_key("mcp-session-id");
    let protocol = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(|value| sanitize_for_log(value, MAX_LOGGED_HEADER_CHARS));
    (mcp_session, protocol)
}

/// Logging knobs controlling what [`request_log_middleware`] emits.
struct RequestLogConfig {
    /// Whether the full (redacted) header set is rendered into log lines.
    log_request_headers: bool,
    /// Paths excluded from all request logging.
    exclude_paths: HashSet<String>,
    /// Context selectors (client IP, request ID, MCP hints, completion line).
    fields: LogContextConfig,
}

impl RequestLogConfig {
    /// True when `path` is not on the exclusion list.
    fn logs(&self, path: &str) -> bool {
        !self.exclude_paths.contains(path)
    }
}

/// Per-request context values captured for the request log line.
#[derive(Clone, Default)]
struct RequestLogFields {
    /// Resolved client IP, when client-IP logging is enabled.
    client_ip: Option<IpAddr>,
    /// Direct peer IP, when peer-IP logging is enabled.
    peer_ip: Option<IpAddr>,
    /// Inbound request ID, when request-ID logging is enabled.
    request_id: Option<Arc<str>>,
    /// Whether an MCP session header was present, when hints are enabled.
    mcp_session: Option<bool>,
    /// MCP protocol version header value, when hints are enabled.
    mcp_protocol_version: Option<String>,
}

/// Build the [`RequestLogFields`] for `req` from the configured selectors.
fn request_log_fields(cfg: &LogContextConfig, req: &Request<Body>) -> RequestLogFields {
    let (mcp_session, mcp_protocol_version) = if cfg.mcp_hints {
        mcp_hints_for_log(req.headers())
    } else {
        (false, None)
    };
    RequestLogFields {
        client_ip: cfg
            .client_ip
            .then(|| limiter_client_ip(req.extensions()))
            .flatten(),
        peer_ip: cfg
            .peer_ip
            .then(|| peer_ip_for_log(req.extensions()))
            .flatten(),
        request_id: cfg
            .request_id
            .then(|| request_id_for_log(req.extensions()))
            .flatten(),
        mcp_session: cfg.mcp_hints.then_some(mcp_session),
        mcp_protocol_version,
    }
}

/// Emit request and completion DEBUG logs around the wrapped handler.
///
/// Captures method, path, status, latency, and the configured context fields.
// cancel-safe: request logging is emitted before `next.run(req)`; completion
// logging is omitted if the future is dropped (timeout or disconnect). For SSE,
// latency measures time to the response head, not body streaming duration.
async fn request_log_middleware(
    cfg: Arc<RequestLogConfig>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use tracing::field;

    let captured = if cfg.logs(req.uri().path()) {
        let fields = request_log_fields(&cfg.fields, &req);
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        log_incoming_request(
            &method,
            &path,
            req.headers(),
            cfg.log_request_headers,
            &fields,
        );
        cfg.fields
            .request_completion
            .then(|| (method, path, Instant::now(), fields))
    } else {
        None
    };

    let resp = next.run(req).await;
    if let Some((method, path, started, fields)) = captured {
        tracing::debug!(
            %method,
            %path,
            status = resp.status().as_u16(),
            latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "request completed"
        );
    }
    resp
}

/// Emit a DEBUG log for an incoming request, optionally including the full (redacted) header set.
fn log_incoming_request(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    log_request_headers: bool,
    fields: &RequestLogFields,
) {
    use tracing::field;

    if log_request_headers {
        tracing::debug!(
            %method,
            %path,
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            mcp_session = fields.mcp_session,
            mcp_protocol_version = fields.mcp_protocol_version.as_deref(),
            headers = %format_request_headers_for_log(headers),
            "incoming request"
        );
    } else {
        tracing::debug!(
            %method,
            %path,
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            mcp_session = fields.mcp_session,
            mcp_protocol_version = fields.mcp_protocol_version.as_deref(),
            "incoming request"
        );
    }
}

/// Header names whose values are never rendered into logs.
///
/// SECURITY: the first three carry credentials. The forwarding headers carry
/// client IPs and proxy topology and are attacker-controlled on any hop the
/// operator has not declared trusted, so logging them verbatim lets a caller
/// plant misleading provenance in an incident-response trail. The resolved
/// address is logged separately as `client_ip` under its knob.
const REDACTED_LOG_HEADERS: [&str; 6] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
];

/// Render the request header set for logging, redacting credential and
/// forwarding headers.
fn format_request_headers_for_log(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(key, value)| {
            let name = key.as_str();
            if REDACTED_LOG_HEADERS.contains(&name) {
                format!("{name}: [REDACTED]")
            } else {
                format!("{name}: {}", value.to_str().unwrap_or("<non-utf8>"))
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
#[expect(
    clippy::cognitive_complexity,
    reason = "complexity is purely tracing macro expansion (info/warn + match arms); 18 lines of straight-line code, nothing meaningful to extract"
)]
#[inline]
// cancel-safe: stdio framing is read by rmcp's own reader task; this fn only
// awaits the served session's terminal completion, so cancelling loses no data.
pub async fn serve_stdio<H>(handler: H) -> Result<(), RmcpServerKitError>
where
    H: ServerHandler + 'static,
{
    use rmcp::{ServiceExt as _, transport::io};

    tracing::info!("stdio transport: serving on stdin/stdout");
    tracing::warn!("stdio mode: auth, RBAC, TLS, and Origin checks are DISABLED");

    let transport = io::stdio();

    let service = handler
        .serve(transport)
        .await
        .map_err(|err| RmcpServerKitError::Startup(format!("stdio initialize failed: {err}")))?;

    if let Err(err) = service.waiting().await {
        tracing::warn!(error = %err, "stdio session ended with error");
    }
    tracing::info!("stdio session ended");
    Ok(())
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "deliberate: src/transport.rs::McpServerConfig — the second block groups the TLS-path and role accessors; merging relocates ~140 lines for no behavior gain"
)]
#[expect(
    clippy::missing_const_for_fn,
    reason = "public API frozen until the next major release"
)]
#[expect(
    deprecated,
    reason = "builder methods are the sanctioned transition layer for deprecated public fields"
)]
impl McpServerConfig {
    /// Replace the TLS certificate/key paths exactly, including `None`
    /// values. Configuration bridges use this to preserve partial TLS
    /// configuration so validation reports the missing half.
    #[must_use]
    #[inline]
    pub fn with_tls_paths(mut self, cert_path: Option<PathBuf>, key_path: Option<PathBuf>) -> Self {
        self.tls_cert_path = cert_path;
        self.tls_key_path = key_path;
        self
    }

    /// Set only the TLS certificate path. Intended for configuration
    /// bridges that must preserve partial TLS configuration so validation
    /// can report the missing key path.
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_tls_cert_path(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self
    }

    /// Set only the TLS private-key path. Intended for configuration
    /// bridges that must preserve partial TLS configuration so validation
    /// can report the missing certificate path.
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_tls_key_path(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Replace the optional authentication configuration exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_auth(mut self, auth: Option<AuthConfig>) -> Self {
        self.auth = auth;
        self
    }

    /// Choose the configured session-binding secret, or `None` for the default process secret.
    #[must_use]
    #[inline]
    pub fn with_optional_session_binding_secret(mut self, secret: Option<SecretString>) -> Self {
        self.session_binding_secret = secret;
        self
    }

    /// Replace the optional tool rate limit exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_tool_rate_limit(mut self, per_minute: Option<u32>) -> Self {
        self.tool_rate_limit = per_minute;
        self
    }

    /// Replace the optional tool rate-limit burst exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_tool_rate_limit_burst(mut self, burst: Option<u32>) -> Self {
        self.tool_rate_limit_burst = burst;
        self
    }

    /// Replace the optional extra-route rate limit exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_extra_route_rate_limit(mut self, per_minute: Option<u32>) -> Self {
        self.extra_route_rate_limit = per_minute;
        self
    }

    /// Replace the optional extra-route rate-limit burst exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_extra_route_rate_limit_burst(mut self, burst: Option<u32>) -> Self {
        self.extra_route_rate_limit_burst = burst;
        self
    }

    /// Replace the optional forwarded-header mode exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_forwarded_header(mut self, mode: Option<ForwardedHeaderMode>) -> Self {
        self.forwarded_header = mode;
        self
    }

    /// Replace the optional public URL exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_public_url(mut self, url: Option<String>) -> Self {
        self.public_url = url;
        self
    }

    /// Override the compression minimum response size without enabling
    /// compression. This keeps configuration bridges able to carry the
    /// inert threshold independently from the enable flag.
    #[must_use]
    #[inline]
    pub fn with_compression_min_size(mut self, min_size: u16) -> Self {
        self.compression_min_size = min_size;
        self
    }

    /// Replace the compression enabled flag exactly.
    #[must_use]
    #[inline]
    pub fn with_compression_enabled(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Replace the optional global in-flight request cap exactly.
    #[must_use]
    #[inline]
    pub fn with_optional_max_concurrent_requests(mut self, limit: Option<usize>) -> Self {
        self.max_concurrent_requests = limit;
        self
    }

    /// Replace the admin endpoint enabled flag exactly.
    #[must_use]
    #[inline]
    pub fn with_admin_enabled(mut self, enabled: bool) -> Self {
        self.admin_enabled = enabled;
        self
    }

    /// Override the RBAC role required by admin-gated endpoints without
    /// enabling `/admin/*` diagnostics.
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_admin_role(mut self, role: impl Into<String>) -> Self {
        self.admin_role = role.into();
        self
    }

    /// Replace the build-metadata exposure flag exactly.
    #[must_use]
    #[inline]
    pub fn with_expose_build_metadata(mut self, enabled: bool) -> Self {
        self.expose_build_metadata = enabled;
        self
    }
}

/// Warn once per non-empty operator override of a security header.
///
/// Emitted at router-build time so operators can audit which defaults were
/// replaced or omitted without reading the effective response headers.
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

/// Iterate the non-empty operator overrides in `cfg` as `(field, value)` pairs.
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
    .filter_map(|(field, value)| value.map(|text| (field, text)))
}

/// Reject auth rate-limit settings that would silently weaken their gates.
///
/// A zero `max_attempts_per_minute` would fall back to the framework default,
/// and a zero `pre_auth_max_per_minute` would *raise* the pre-auth quota; both
/// are rejected so an operator typo cannot relax the shield around Argon2.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] naming the offending field when any
/// auth rate-limit knob is zero, or when mTLS capacity knobs are invalid.
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

/// Reject zeroed mTLS/CRL capacity knobs.
///
/// A zero streaming cap or concurrency bound can make CRL fetching silently
/// never succeed, which under `crl_deny_on_unavailable = true` fails every
/// CDP-bearing handshake instead of loudly reporting the misconfiguration.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] naming the offending field when any
/// `auth.mtls` capacity knob is zero.
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

#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Context as _;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt as _;
    use rmcp::transport::streamable_http_server::session::{SessionState, SessionStoreError};
    use tower::ServiceExt as _;
    use tracing::{dispatcher::DefaultGuard, subscriber::set_default};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }

        fn lines_containing(&self, needle: &str) -> Vec<String> {
            self.contents()
                .lines()
                .filter(|line| line.contains(needle))
                .map(ToOwned::to_owned)
                .collect()
        }
    }

    struct CapturedLogsWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogsWriter {
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

    fn capture_debug_logs(logs: CapturedLogs) -> DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs)
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .finish();
        set_default(subscriber)
    }

    // -- startup task lifecycle --

    /// Pins that the shutdown bridge exits when the server-internal token is
    /// cancelled even though the external token is not.
    #[tokio::test]
    async fn external_shutdown_bridge_exits_when_internal_token_cancels() -> anyhow::Result<()> {
        use tokio::time::timeout;

        let external = CancellationToken::new();
        let internal = CancellationToken::new();
        let bridge = spawn_external_shutdown_bridge(external.clone(), internal.clone());

        // The caller's token is never cancelled; only the server-internal one
        // is, as happens when startup fails after the bridge is spawned.
        internal.cancel();

        timeout(Duration::from_secs(2), bridge).await.context(
            "bridge task must exit once the internal token is cancelled, \
                 otherwise it leaks for the lifetime of the process",
        )??;

        Ok(())
    }

    /// Pins that cancelling the external token still propagates to the
    /// server-internal token through the shutdown bridge.
    #[tokio::test]
    async fn external_shutdown_bridge_still_forwards_external_cancel() -> anyhow::Result<()> {
        use tokio::time::timeout;

        let external = CancellationToken::new();
        let internal = CancellationToken::new();
        let bridge = spawn_external_shutdown_bridge(external.clone(), internal.clone());

        external.cancel();

        timeout(Duration::from_secs(2), bridge)
            .await
            .context("bridge task must exit on external cancel")??;
        assert!(
            internal.is_cancelled(),
            "external cancellation must still propagate to the internal token"
        );

        Ok(())
    }

    /// Pins that dropping the startup guard cancels its token.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::cancel_on_drop_cancels_its_token — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn cancel_on_drop_cancels_its_token() -> anyhow::Result<()> {
        let ct = CancellationToken::new();
        {
            let _guard = CancelOnDrop(ct.clone());
            assert!(!ct.is_cancelled());
        }
        assert!(
            ct.is_cancelled(),
            "dropping the guard must cancel background startup tasks"
        );

        Ok(())
    }

    /// Pins that mTLS without both TLS paths set is rejected with an error
    /// naming both path fields.
    #[test]
    fn validate_rejects_mtls_without_tls() -> anyhow::Result<()> {
        for (cert, key) in [
            (None, None),
            (Some("cert.pem"), None),
            (None, Some("key.pem")),
        ] {
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.mtls = Some(valid_mtls_config());
            let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
                .with_auth(auth)
                .with_tls_paths(cert.map(Into::into), key.map(Into::into));

            let err = cfg
                .validate()
                .err()
                .context("mTLS without both TLS paths must be rejected")?;
            let msg = err.to_string();
            assert!(
                msg.contains("tls_cert_path") && msg.contains("tls_key_path"),
                "cert={cert:?} key={key:?}: {msg}"
            );
        }

        Ok(())
    }

    /// Pins that mTLS with both TLS paths set validates.
    #[test]
    fn validate_accepts_mtls_with_tls() -> anyhow::Result<()> {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(valid_mtls_config());
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .with_tls("cert.pem", "key.pem");

        drop(
            cfg.validate()
                .context("mTLS with both TLS paths is valid")?,
        );

        Ok(())
    }

    /// Pins that blank and whitespace-only API-key names are rejected while a
    /// normal name still validates.
    #[test]
    fn validate_rejects_blank_api_key_name() -> anyhow::Result<()> {
        let blank = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(
            AuthConfig::with_keys(vec![ApiKeyEntry::new("", "hash", "viewer")]),
        );
        let err = blank
            .validate()
            .err()
            .context("blank API-key name must be rejected")?;
        assert!(err.to_string().contains("api_keys[0]"), "{err}");

        let whitespace = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(
            AuthConfig::with_keys(vec![ApiKeyEntry::new("   ", "hash", "viewer")]),
        );
        assert!(
            whitespace.validate().is_err(),
            "whitespace-only API-key name must be rejected"
        );

        let ok = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(
            AuthConfig::with_keys(vec![ApiKeyEntry::new("viewer-key", "hash", "viewer")]),
        );
        drop(ok.validate().context("a normal name must still validate")?);

        Ok(())
    }

    /// Build an `AuthState` holding a single API key and return it together
    /// with that key's plaintext token.
    ///
    /// # Errors
    ///
    /// Returns an error when the generated API-key hash cannot be produced.
    fn reload_test_state(name: &str) -> anyhow::Result<(Arc<AuthState>, String)> {
        use crate::auth::generate_api_key;

        let (token, hash) = generate_api_key()?;
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::from_pointee(vec![ApiKeyEntry::new(name, hash, "ops")]),
            rate_limiter: None,
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        Ok((state, token))
    }

    /// Pins that a blank API-key name is rejected on hot reload.
    #[test]
    fn try_reload_auth_keys_rejects_blank_name() -> anyhow::Result<()> {
        let (state, _token) = reload_test_state("prev-key")?;
        let handle = ReloadHandle {
            auth: Some(state),
            rbac: None,
            crl_set: None,
        };
        let err = handle
            .try_reload_auth_keys(vec![ApiKeyEntry::new("", "h", "ops")])
            .err()
            .context("blank API-key name must be rejected on reload")?;
        assert!(err.to_string().contains("api_keys[0]"), "{err}");

        Ok(())
    }

    /// Pins that a rejected reload (blank name) leaves the previously
    /// installed API keys authenticating.
    #[test]
    fn reload_auth_keys_blank_name_leaves_previous_keys() -> anyhow::Result<()> {
        use crate::auth::verify_bearer_token;

        let (state, token) = reload_test_state("prev-key")?;
        let handle = ReloadHandle {
            auth: Some(Arc::clone(&state)),
            rbac: None,
            crl_set: None,
        };
        handle.reload_auth_keys(vec![ApiKeyEntry::new("  ", "h", "ops")]);

        let installed = state.api_keys.load();
        assert!(
            verify_bearer_token(&token, &installed).is_some(),
            "the previous key must still authenticate after a rejected reload"
        );

        Ok(())
    }

    // -- McpServerConfig --

    /// Pins every default `McpServerConfig::new` leaves in place across
    /// transport, auth, timeout, and session fields.
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::server_config_new_defaults — exercises deprecated config fields directly"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::server_config_new_defaults — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn server_config_new_defaults() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("0.0.0.0:8443", "test-server", "1.0.0");
        assert_eq!(cfg.bind_addr, "0.0.0.0:8443");
        assert_eq!(cfg.name, "test-server");
        assert_eq!(cfg.version, "1.0.0");
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
        assert!(cfg.auth.is_none());
        assert!(cfg.rbac.is_none());
        assert_eq!(cfg.allowed_origins, Vec::<String>::new());
        assert!(cfg.tool_rate_limit.is_none());
        assert!(cfg.readiness_check.is_none());
        assert_eq!(cfg.max_request_body, 1024 * 1024);
        assert_eq!(cfg.request_timeout, Duration::from_mins(2));
        assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
        assert!(!cfg.log_request_headers);
        assert_eq!(cfg.tls_handshake_timeout, Duration::from_secs(10));
        assert_eq!(cfg.max_concurrent_tls_handshakes, 256);
        assert!(cfg.session_store.is_none());
        assert!(cfg.session_binding_secret.is_none());

        Ok(())
    }

    #[derive(Default)]
    struct TestSessionStore;

    #[async_trait::async_trait]
    impl SessionStore for TestSessionStore {
        async fn load(&self, _session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
            Ok(None)
        }

        async fn store(
            &self,
            _session_id: &str,
            _state: &SessionState,
        ) -> Result<(), SessionStoreError> {
            Ok(())
        }

        async fn delete(&self, _session_id: &str) -> Result<(), SessionStoreError> {
            Ok(())
        }
    }

    fn test_session_store() -> Arc<dyn SessionStore> {
        Arc::new(TestSessionStore)
    }

    fn shared_session_binding_secret() -> SecretString {
        SecretString::from("0123456789abcdef0123456789abcdef")
    }

    /// Pins that a fresh config has no session store attached.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::session_store_defaults_to_none — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn session_store_defaults_to_none() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");

        assert!(cfg.session_store.is_none());

        Ok(())
    }

    /// Pins that a fresh config has no event store attached.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::event_store_defaults_to_none — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn event_store_defaults_to_none() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");

        assert!(cfg.event_store.is_none());

        Ok(())
    }

    /// Pins that an authenticated shared session store requires a shared
    /// binding secret, with the error naming both settings.
    #[test]
    fn validate_rejects_session_store_without_binding_secret() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_auth(AuthConfig::with_keys(vec![]))
            .with_session_store(test_session_store());

        let err = cfg
            .validate()
            .err()
            .context("authenticated shared-store binding needs a shared secret")?;
        let msg = err.to_string();
        assert!(msg.contains("session_store"), "{msg}");
        assert!(msg.contains("session_binding"), "{msg}");
        assert!(msg.contains("shared secret"), "{msg}");

        Ok(())
    }

    /// Pins that a shared session store plus a shared binding secret
    /// validates.
    #[test]
    fn validate_allows_session_store_with_binding_secret() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_auth(AuthConfig::with_keys(vec![]))
            .with_session_store(test_session_store())
            .with_session_binding_secret(shared_session_binding_secret());

        drop(cfg.validate()?);

        Ok(())
    }

    /// Pins that a shared session store validates when session binding is
    /// explicitly disabled.
    #[test]
    fn validate_allows_session_store_when_binding_disabled() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_auth(AuthConfig::with_keys(vec![]))
            .with_session_binding(false)
            .with_session_store(test_session_store());

        drop(cfg.validate()?);

        Ok(())
    }

    /// Pins that a binding secret without any session store validates.
    #[test]
    fn validate_allows_binding_secret_without_session_store() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_auth(AuthConfig::with_keys(vec![]))
            .with_session_binding_secret(shared_session_binding_secret());

        drop(cfg.validate()?);

        Ok(())
    }

    /// Pins that the TLS handshake timeout and concurrency builders store
    /// their values on the config.
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::tls_handshake_builders_set_fields — exercises deprecated config fields directly"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::tls_handshake_builders_set_fields — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn tls_handshake_builders_set_fields() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_tls_handshake_timeout(Duration::from_secs(3))
            .with_max_concurrent_tls_handshakes(64);
        assert_eq!(cfg.tls_handshake_timeout, Duration::from_secs(3));
        assert_eq!(cfg.max_concurrent_tls_handshakes, 64);

        Ok(())
    }

    /// Pins that a zero TLS handshake timeout is rejected.
    #[test]
    fn validate_rejects_zero_tls_handshake_timeout() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_tls_handshake_timeout(Duration::ZERO);
        let err = cfg.validate().err().context("zero handshake timeout")?;
        assert!(err.to_string().contains("tls_handshake_timeout"));

        Ok(())
    }

    /// Pins that a zero TLS handshake concurrency cap is rejected.
    #[test]
    fn validate_rejects_zero_max_concurrent_tls_handshakes() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_max_concurrent_tls_handshakes(0);
        let err = cfg.validate().err().context("zero handshake concurrency")?;
        assert!(err.to_string().contains("max_concurrent_tls_handshakes"));

        Ok(())
    }

    /// Pins that `validate` consumes the config into a `Validated` wrapper
    /// that exposes the inner value, and rejects a zero body cap.
    #[expect(
        deprecated,
        reason = "deliberate: src/transport.rs::validate_consumes_and_proves — exercises deprecated config fields directly"
    )]
    #[test]
    fn validate_consumes_and_proves() -> anyhow::Result<()> {
        // Valid config -> Validated wrapper, original is consumed.
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        let validated = cfg.validate().context("valid config")?;
        // as_inner() gives read-only access to inner fields.
        assert_eq!(validated.as_inner().name, "test-server");
        // into_inner recovers the raw value.
        let raw = validated.into_inner();
        assert_eq!(raw.name, "test-server");

        // Invalid config (zero max_request_body) -> Err.
        let mut bad = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        bad.max_request_body = 0;
        assert!(bad.validate().is_err(), "zero body cap must fail validate");

        Ok(())
    }

    /// Pins that a zero max-concurrent-requests cap is rejected with an error
    /// naming the field.
    #[test]
    fn validate_rejects_zero_max_concurrent_requests() -> anyhow::Result<()> {
        let cfg =
            McpServerConfig::new("127.0.0.1:8080", "test", "1.0.0").with_max_concurrent_requests(0);
        let err = cfg
            .validate()
            .err()
            .context("zero concurrency cap must fail")?;
        assert!(
            format!("{err}").contains("max_concurrent_requests"),
            "error should mention max_concurrent_requests, got: {err}"
        );

        Ok(())
    }

    /// Pins that a zero max-tracked-keys cap is rejected with an error naming
    /// the field.
    #[test]
    fn validate_rejects_zero_max_tracked_keys() -> anyhow::Result<()> {
        use crate::auth::RateLimitConfig;

        // Defaults mirror auth::default_max_attempts / default_idle_eviction
        // (module-private in auth.rs); spelled out here for review clarity.
        let rl = RateLimitConfig {
            max_attempts_per_minute: 30,
            pre_auth_max_per_minute: None,
            max_tracked_keys: 0,
            idle_eviction: Duration::from_mins(15),
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
        let err = cfg
            .validate()
            .err()
            .context("zero max_tracked_keys must fail")?;
        assert!(
            format!("{err}").contains("max_tracked_keys"),
            "error should mention max_tracked_keys, got: {err}"
        );

        Ok(())
    }

    /// Pins that the derived host allowlist includes the `public_url` host.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::derive_allowed_hosts_includes_public_host — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn derive_allowed_hosts_includes_public_host() -> anyhow::Result<()> {
        let hosts = derive_allowed_hosts("0.0.0.0:8080", Some("https://mcp.example.com/mcp"));
        assert!(
            hosts.iter().any(|host| host == "mcp.example.com"),
            "public_url host must be allowed"
        );

        Ok(())
    }

    /// Pins that the derived host allowlist includes both the bind host and
    /// the bind authority.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::derive_allowed_hosts_includes_bind_authority — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn derive_allowed_hosts_includes_bind_authority() -> anyhow::Result<()> {
        let hosts = derive_allowed_hosts("127.0.0.1:8080", None);
        assert!(
            hosts.iter().any(|host| host == "127.0.0.1"),
            "bind host must be allowed"
        );
        assert!(
            hosts.iter().any(|host| host == "127.0.0.1:8080"),
            "bind authority must be allowed"
        );

        Ok(())
    }

    // -- healthz --

    /// Pins that `/healthz` answers 200 with `status: ok` and leaks neither
    /// the server name nor its version.
    #[tokio::test]
    async fn healthz_returns_ok_json() -> anyhow::Result<()> {
        let resp = healthz().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            json.get("status").context("healthz must report a status")?,
            "ok"
        );
        assert!(
            json.get("name").is_none(),
            "healthz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "healthz must not expose version"
        );

        Ok(())
    }

    // -- readyz --

    /// Pins that a ready readiness check yields 200 with the check's fields
    /// and no name or version leak.
    #[tokio::test]
    async fn readyz_returns_ok_when_ready() -> anyhow::Result<()> {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": true, "db": "connected"}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            json.get("ready").context("readyz must report readiness")?,
            true
        );
        assert!(
            json.get("name").is_none(),
            "readyz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "readyz must not expose version"
        );
        assert_eq!(
            json.get("db")
                .context("readyz must pass through check fields")?,
            "connected"
        );

        Ok(())
    }

    /// Pins that a not-ready readiness check yields 503.
    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() -> anyhow::Result<()> {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": false}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        Ok(())
    }

    /// Pins that a readiness payload missing its `ready` field defaults to
    /// not-ready and yields 503.
    #[tokio::test]
    async fn readyz_returns_503_when_ready_missing() -> anyhow::Result<()> {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"status": "starting"}) }));
        let resp = readyz(check).await.into_response();
        // Missing "ready" field defaults to false -> 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        Ok(())
    }

    // -- normalize_peer_addr_middleware / PeerAddr --

    /// Build a test router that reports the request's peer-address
    /// extensions as `"<ConnectInfo>|<PeerAddr>"` (empty when absent).
    fn peer_probe_router() -> axum::Router {
        use axum::{middleware::from_fn, routing::get};

        async fn probe(req: Request<Body>) -> String {
            let ci = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.to_string())
                .unwrap_or_default();
            let pa = req
                .extensions()
                .get::<PeerAddr>()
                .map(|peer| peer.addr.to_string())
                .unwrap_or_default();
            format!("{ci}|{pa}")
        }
        axum::Router::new()
            .route("/probe", get(probe))
            .layer(from_fn(|req, next| {
                normalize_peer_addr_middleware(None, req, next)
            }))
    }

    /// Collect a response body into a `String` for assertions.
    ///
    /// # Errors
    ///
    /// Returns an error when the body stream fails or the collected bytes are
    /// not valid UTF-8.
    async fn body_string(resp: Response) -> anyhow::Result<String> {
        let bytes = resp.into_body().collect().await?.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    /// Pins that an existing plain `ConnectInfo` wins over the TLS one and is
    /// mirrored into `PeerAddr`.
    #[tokio::test]
    async fn normalize_preserves_existing_connect_info_and_mirrors_peer_addr() -> anyhow::Result<()>
    {
        // Precedence proof: when both extensions exist with DIFFERENT
        // addresses, ConnectInfo<SocketAddr> wins and is never overwritten.
        let plain: SocketAddr = "10.0.0.1:1111".parse()?;
        let tls: SocketAddr = "10.0.0.2:2222".parse()?;
        let req = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(plain))
            .extension(ConnectInfo(TlsConnInfo::new(tls, None)))
            .body(Body::empty())?;
        let resp = peer_probe_router().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await?, format!("{plain}|{plain}"));

        Ok(())
    }

    /// Pins that a TLS-only `ConnectInfo` is promoted to a plain
    /// `ConnectInfo` and mirrored into `PeerAddr`.
    #[tokio::test]
    async fn normalize_inserts_connect_info_and_peer_addr_from_tls() -> anyhow::Result<()> {
        let tls: SocketAddr = "192.168.1.7:50443".parse()?;
        let req = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(TlsConnInfo::new(tls, None)))
            .body(Body::empty())?;
        let resp = peer_probe_router().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await?, format!("{tls}|{tls}"));

        Ok(())
    }

    /// Pins that a request with no peer extension at all passes through with
    /// empty probe fields.
    #[tokio::test]
    async fn normalize_no_op_without_any_connect_info() -> anyhow::Result<()> {
        let req = Request::builder().uri("/probe").body(Body::empty())?;
        let resp = peer_probe_router().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await?, "|");

        Ok(())
    }

    /// Pins that the `PeerAddr` extractor rejects with 500 when the
    /// extension is absent.
    #[tokio::test]
    async fn peer_addr_extractor_rejects_when_absent() -> anyhow::Result<()> {
        use axum::routing::get;

        async fn peer_handler(peer: PeerAddr) -> String {
            peer.addr.to_string()
        }
        let app = axum::Router::new().route("/p", get(peer_handler));
        let req = Request::builder().uri("/p").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        Ok(())
    }

    /// Pins that the `PeerAddr` extractor returns the address inserted into
    /// the request extensions.
    #[tokio::test]
    async fn peer_addr_extractor_returns_value_when_present() -> anyhow::Result<()> {
        use axum::routing::get;

        async fn peer_handler(peer: PeerAddr) -> String {
            peer.addr.to_string()
        }
        let addr: SocketAddr = "127.0.0.1:9999".parse()?;
        let app = axum::Router::new().route("/p", get(peer_handler));
        let req = Request::builder()
            .uri("/p")
            .extension(PeerAddr::new(addr))
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await?, addr.to_string());

        Ok(())
    }

    /// Pins that `PeerAddr` is also readable through the generic
    /// `axum::Extension` extractor.
    #[tokio::test]
    async fn peer_addr_via_extension_extractor() -> anyhow::Result<()> {
        use axum::{Extension, routing::get};

        async fn peer_handler(Extension(peer): Extension<PeerAddr>) -> String {
            peer.addr.to_string()
        }
        let addr: SocketAddr = "127.0.0.1:4242".parse()?;
        let app = axum::Router::new().route("/p", get(peer_handler));
        let req = Request::builder()
            .uri("/p")
            .extension(PeerAddr::new(addr))
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await?, addr.to_string());

        Ok(())
    }

    // -- extra_route_rate_limit_middleware --

    /// Handler used by the limiter probe routers: always answers `"ok"`.
    async fn ok_handler() -> &'static str {
        "ok"
    }

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
        use axum::{middleware::from_fn, routing::get};

        let limiter = build_extra_route_rate_limiter_with_policy(
            per_minute,
            burst,
            KeyEvictionPolicy::default(),
            NonZeroUsize::new(EXTRA_ROUTE_MAX_TRACKED_KEYS).unwrap_or(NonZeroUsize::MIN),
        );
        let exempt: Arc<HashSet<String>> =
            Arc::new(exempt_paths.iter().map(|path| (*path).to_owned()).collect());
        axum::Router::new()
            .route("/limited", get(ok_handler))
            .route("/exempt", get(ok_handler))
            .layer(from_fn(move |req, next| {
                let route_limiter = Arc::clone(&limiter);
                let exempt_set = Arc::clone(&exempt);
                extra_route_rate_limit_middleware(route_limiter, exempt_set, req, next)
            }))
    }

    /// Build a limiter-probe request for `ip` targeting `/limited`.
    ///
    /// # Errors
    ///
    /// Returns an error when `ip` is not a valid IP address or the request
    /// parts are invalid.
    fn limited_req(ip: &str) -> anyhow::Result<Request<Body>> {
        limited_req_to(ip, "/limited")
    }

    /// Build a limiter-probe request for `ip` at `path`, carrying the peer
    /// `ConnectInfo` extension.
    ///
    /// # Errors
    ///
    /// Returns an error when `ip` is not a valid IP address or the request
    /// parts are invalid.
    fn limited_req_to(ip: &str, path: &str) -> anyhow::Result<Request<Body>> {
        let addr: SocketAddr = format!("{ip}:40000").parse()?;
        Ok(Request::builder()
            .uri(path)
            .extension(ConnectInfo(addr))
            .body(Body::empty())?)
    }

    /// Pins that the extra-route limiter denies requests over the per-minute
    /// quota with the documented 429 body.
    #[tokio::test]
    async fn extra_route_limiter_denies_over_quota() -> anyhow::Result<()> {
        let app = limited_router(2);
        for i in 0..2_u32 {
            let resp = app.clone().oneshot(limited_req("10.1.1.1")?).await?;
            assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
        }
        let resp = app.clone().oneshot(limited_req("10.1.1.1")?).await?;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_string(resp).await?;
        assert!(
            body.contains("too many requests to application routes"),
            "deny body should match the limiter message, got: {body}"
        );

        Ok(())
    }

    /// A `NonZeroUsize` of one, for limiter tests that track a single key.
    fn one_tracked_key() -> NonZeroUsize {
        NonZeroUsize::new(1).unwrap_or(NonZeroUsize::MIN)
    }

    /// Pins that a full capacity-limited bucket rejects a new key with 503
    /// and no `Retry-After` header.
    #[tokio::test]
    async fn extra_route_limiter_capacity_full_returns_503_without_retry_after()
    -> anyhow::Result<()> {
        use axum::{middleware::from_fn, routing::get};

        let limiter = build_extra_route_rate_limiter_with_policy(
            10,
            None,
            KeyEvictionPolicy::RejectNew,
            one_tracked_key(),
        );
        let exempt = Arc::new(HashSet::new());
        let app = axum::Router::new()
            .route("/limited", get(ok_handler))
            .layer(from_fn(move |req, next| {
                let route_limiter = Arc::clone(&limiter);
                let exempt_set = Arc::clone(&exempt);
                extra_route_rate_limit_middleware(route_limiter, exempt_set, req, next)
            }));
        let established = app.clone().oneshot(limited_req("10.1.1.1")?).await?;
        assert_eq!(established.status(), StatusCode::OK);

        let denied = app.clone().oneshot(limited_req("10.1.1.2")?).await?;

        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(denied.headers().get(header::RETRY_AFTER).is_none());

        Ok(())
    }

    /// Pins that the extra-route limiter keeps a separate bucket per source
    /// IP: one exhausted key does not deny a different peer.
    #[tokio::test]
    async fn extra_route_limiter_isolates_keys() -> anyhow::Result<()> {
        let app = limited_router(2);
        for _ in 0..2_u32 {
            let resp = app.clone().oneshot(limited_req("10.2.2.2")?).await?;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let exhausted = app.clone().oneshot(limited_req("10.2.2.2")?).await?;
        assert_eq!(exhausted.status(), StatusCode::TOO_MANY_REQUESTS);
        // A different source IP still has a fresh bucket.
        let other = app.clone().oneshot(limited_req("10.3.3.3")?).await?;
        assert_eq!(other.status(), StatusCode::OK);

        Ok(())
    }

    /// Pins that requests without a resolvable peer address still share one
    /// bounded limiter bucket instead of bypassing the limiter.
    #[tokio::test]
    async fn extra_route_limiter_bounds_requests_without_peer() -> anyhow::Result<()> {
        // Was `fails_open_without_peer`. A request whose source address
        // cannot be resolved must NOT be exempt from rate limiting; such
        // requests share one bounded `Unattributed` bucket.
        let app = limited_router(1);
        let mk = || -> anyhow::Result<Request<Body>> {
            Ok(Request::builder().uri("/limited").body(Body::empty())?)
        };
        let first = app.clone().oneshot(mk()?).await?;
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "first request consumes quota"
        );
        let second = app.clone().oneshot(mk()?).await?;
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "unattributable requests must share a bounded bucket, not bypass the limiter"
        );

        Ok(())
    }

    /// Pins that requests with no peer address fall back to the shared
    /// `Unattributed` rate-limit key.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::limiter_client_key_falls_back_to_unattributed — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn limiter_client_key_falls_back_to_unattributed() -> anyhow::Result<()> {
        let empty = Extensions::new();
        assert_eq!(limiter_client_key(&empty), RateLimitKey::Unattributed);

        Ok(())
    }

    /// Pins that the `Unattributed` key is distinct from a `0.0.0.0` sentinel
    /// key in both equality and hashing.
    #[test]
    fn unattributed_key_is_distinct_from_unspecified_ip() -> anyhow::Result<()> {
        // Regression guard: a sentinel `0.0.0.0` would collide here,
        // because trusted-forwarder mode derives ClientIp from a header
        // and `crate::forwarded` does not filter unspecified addresses.
        let unspecified = RateLimitKey::Ip("0.0.0.0".parse::<IpAddr>()?);
        assert_ne!(unspecified, RateLimitKey::Unattributed);

        let mut set = HashSet::new();
        let _unspecified_is_new = set.insert(unspecified);
        let _unattributed_is_new = set.insert(RateLimitKey::Unattributed);
        assert_eq!(set.len(), 2, "the two keys must hash to distinct buckets");

        Ok(())
    }

    /// Pins that `RateLimitKey`'s `Display` renders a real IP verbatim and
    /// never fabricates one for the unattributed key.
    #[test]
    fn rate_limit_key_display_does_not_fabricate_an_ip() -> anyhow::Result<()> {
        assert_eq!(
            RateLimitKey::Ip("10.1.2.3".parse::<IpAddr>()?).to_string(),
            "10.1.2.3"
        );
        assert_eq!(RateLimitKey::Unattributed.to_string(), "unattributed");

        Ok(())
    }

    /// Pins that the extra-route limiter keys on the peer address carried by
    /// a TLS `ConnectInfo` extension.
    #[tokio::test]
    async fn extra_route_limiter_extracts_tls_conn_info() -> anyhow::Result<()> {
        let app = limited_router(2);
        let mk = || -> anyhow::Result<Request<Body>> {
            let addr: SocketAddr = "192.168.9.9:55555".parse()?;
            Ok(Request::builder()
                .uri("/limited")
                .extension(ConnectInfo(TlsConnInfo::new(addr, None)))
                .body(Body::empty())?)
        };
        for _ in 0..2_u32 {
            assert_eq!(app.clone().oneshot(mk()?).await?.status(), StatusCode::OK);
        }
        let resp = app.clone().oneshot(mk()?).await?;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    /// Pins that exempt-path traffic passes without consuming limiter budget,
    /// so the following non-exempt requests still see a full bucket.
    #[tokio::test]
    async fn extra_route_limiter_exempt_path_bypasses_quota() -> anyhow::Result<()> {
        // rate=1: a single non-exempt request exhausts the bucket, yet
        // repeated exempt-path requests all pass and consume no budget.
        let app = limited_router_full(1, None, &["/exempt"]);
        for i in 0..5_u32 {
            let resp = app
                .clone()
                .oneshot(limited_req_to("10.6.6.6", "/exempt")?)
                .await?;
            assert_eq!(resp.status(), StatusCode::OK, "exempt request {i}");
        }
        // Budget untouched by exempt traffic: first limited request OK…
        let resp = app.clone().oneshot(limited_req("10.6.6.6")?).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        // …second is denied (exemption did not leak onto /limited).
        let denied = app.clone().oneshot(limited_req("10.6.6.6")?).await?;
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    /// Pins that exemption matching is a raw exact match: a trailing-slash
    /// variant routes 404 and still consumes limiter budget.
    #[tokio::test]
    async fn extra_route_limiter_exemption_is_raw_exact_match() -> anyhow::Result<()> {
        // Trailing-slash and case variants are NOT exempt (fail-closed:
        // a mismatch keeps the request limited, never the reverse).
        let app = limited_router_full(1, None, &["/exempt"]);
        let ok = app
            .clone()
            .oneshot(limited_req_to("10.7.7.7", "/exempt/")?)
            .await?;
        assert_eq!(
            ok.status(),
            StatusCode::NOT_FOUND,
            "variant path routes 404"
        );
        // The variant consumed limiter budget (it was not exempt):
        let denied = app
            .clone()
            .oneshot(limited_req_to("10.7.7.7", "/limited")?)
            .await?;
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    /// Pins that only denied (non-exempt) extra-route requests increment the
    /// `extra_route` rate-limit counter.
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn extra_route_limiter_deny_increments_counter_exempt_does_not() -> anyhow::Result<()> {
        let metrics = Arc::new(McpMetrics::new()?);
        let app = limited_router_full(1, None, &["/exempt"]);
        let mk = |path: &str| -> anyhow::Result<Request<Body>> {
            let addr: SocketAddr = "10.8.8.8:40000".parse()?;
            Ok(Request::builder()
                .uri(path)
                .extension(ConnectInfo(addr))
                .extension(Arc::clone(&metrics))
                .body(Body::empty())?)
        };
        let counter = || {
            metrics
                .rate_limited_total
                .with_label_values(&["extra_route"])
                .get()
        };
        // Exempt traffic: no budget, no counter.
        for _ in 0..3_u32 {
            assert_eq!(
                app.clone().oneshot(mk("/exempt")?).await?.status(),
                StatusCode::OK
            );
        }
        assert_eq!(counter(), 0, "exempt requests must not count as denies");
        // Exhaust then deny: counter increments exactly on the deny.
        assert_eq!(
            app.clone().oneshot(mk("/limited")?).await?.status(),
            StatusCode::OK
        );
        assert_eq!(counter(), 0);
        assert_eq!(
            app.clone().oneshot(mk("/limited")?).await?.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(counter(), 1, "deny must increment the extra_route label");

        Ok(())
    }

    /// Pins that exempt paths without the base extra-route rate limit are
    /// rejected.
    #[test]
    fn validate_rejects_exempt_paths_without_base_knob() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit_exempt_paths(["/ok"]);
        let err = cfg
            .validate()
            .err()
            .context("exempt paths without rate limit")?;
        assert!(err.to_string().contains("requires extra_route_rate_limit"));

        Ok(())
    }

    /// Pins that empty and slash-less exempt paths are rejected with the
    /// documented message.
    #[test]
    fn validate_rejects_malformed_exempt_paths() -> anyhow::Result<()> {
        for bad in ["", "no-slash"] {
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_extra_route_rate_limit(10)
                .with_extra_route_rate_limit_exempt_paths([bad]);
            let err = cfg.validate().err().context("malformed exempt path")?;
            assert!(
                err.to_string()
                    .contains("must be non-empty and start with '/'"),
                "entry {bad:?}: {err}"
            );
        }

        Ok(())
    }

    /// Pins that a well-formed `/.well-known/...` exempt path passes
    /// validation alongside an enabled extra-route rate limit.
    #[test]
    fn validate_accepts_wellformed_exempt_paths() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit(10)
            .with_extra_route_rate_limit_exempt_paths(["/.well-known/oauth-authorization-server"]);
        drop(cfg.validate()?);

        Ok(())
    }

    /// Pins the log-related defaults of a fresh `McpServerConfig`: an empty
    /// `LogContextConfig` and the health-check exclusion list.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::new_config_defaults_log_settings — keeps the uniform IS-7 test signature while it only constructs values"
    )]
    #[test]
    fn new_config_defaults_log_settings() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        assert_eq!(cfg.log_context, LogContextConfig::default());
        assert!(!cfg.log_context.client_ip);
        assert!(!cfg.log_context.peer_ip);
        assert!(!cfg.log_context.request_id);
        assert_eq!(cfg.log_context.request_id_header, "x-request-id");
        assert!(!cfg.log_context.request_line);
        assert!(!cfg.log_context.user_agent);
        assert!(!cfg.log_context.auth_scheme);
        assert!(!cfg.log_context.mcp_hints);
        assert!(!cfg.log_context.credential_fingerprint);
        assert!(!cfg.log_context.request_completion);
        assert_eq!(cfg.request_log_exclude_paths, vec!["/healthz", "/readyz"]);

        Ok(())
    }

    /// Pins that `LogContextConfig::recommended` enables only the low-risk
    /// context fields and that its output still validates.
    #[test]
    fn log_context_recommended_enables_low_risk_set() -> anyhow::Result<()> {
        let recommended = LogContextConfig::recommended();
        assert!(recommended.client_ip);
        assert!(recommended.peer_ip);
        assert!(recommended.request_line);
        assert!(recommended.user_agent);
        assert!(recommended.auth_scheme);
        assert!(recommended.mcp_hints);
        assert!(!recommended.request_id);
        assert!(!recommended.credential_fingerprint);
        assert!(!recommended.request_completion);
        assert!(!recommended.credential_owner);

        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_log_context(recommended);
        drop(cfg.validate()?);

        Ok(())
    }

    #[test]
    fn request_log_exclude_paths_builder_replaces_list() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_request_log_exclude_paths(["/version"]);
        assert_eq!(cfg.request_log_exclude_paths, vec!["/version"]);
        assert!(cfg.validate().is_ok());

        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_request_log_exclude_paths(Vec::<String>::new());
        assert_eq!(cfg.request_log_exclude_paths, Vec::<String>::new());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn malformed_request_log_exclude_paths_rejected() {
        for bad in ["", "healthz"] {
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_request_log_exclude_paths([bad]);
            let err = cfg.validate().expect_err("malformed exclude path");
            assert!(
                err.to_string().contains("request_log_exclude_paths"),
                "entry {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn log_context_request_id_requires_trusted_proxies() {
        let log_context = LogContextConfig {
            request_id: true,
            ..LogContextConfig::default()
        };
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_log_context(log_context.clone());
        let err = cfg
            .validate()
            .expect_err("request_id without trusted_proxies");
        assert!(
            err.to_string()
                .contains("log_context.request_id requires trusted_proxies")
        );

        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_log_context(log_context)
            .with_trusted_proxies(["127.0.0.1/32"]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn log_context_credential_owner_defaults_off_and_not_recommended() {
        let default = LogContextConfig::default();
        assert!(!default.credential_owner, "default must be off");

        let recommended = LogContextConfig::recommended();
        assert!(!recommended.credential_owner, "recommended must be off");
    }

    #[test]
    fn log_context_request_id_header_rules() {
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
            let log_context = LogContextConfig {
                request_id_header: bad.to_owned(),
                ..LogContextConfig::default()
            };
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_log_context(log_context);
            let err = cfg.validate().expect_err("forbidden request_id_header");
            assert!(
                err.to_string().contains("request_id_header"),
                "header {bad:?}: {err}"
            );

            // The rule applies whether or not request_id is enabled.
            let log_context = LogContextConfig {
                request_id_header: bad.to_owned(),
                request_id: true,
                ..LogContextConfig::default()
            };
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_log_context(log_context)
                .with_trusted_proxies(["127.0.0.1/32"]);
            let err = cfg.validate().expect_err("forbidden request_id_header");
            assert!(
                err.to_string().contains("request_id_header"),
                "header {bad:?}: {err}"
            );
        }

        for good in ["x-request-id", "unique-id", "X-Correlation-ID"] {
            let log_context = LogContextConfig {
                request_id_header: good.to_owned(),
                ..LogContextConfig::default()
            };
            let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
                .with_log_context(log_context);
            assert!(cfg.validate().is_ok(), "header {good:?} should be accepted");
        }
    }

    #[test]
    fn validate_rejects_zero_extra_route_rate_limit() {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0")
            .with_extra_route_rate_limit(0);
        let err = cfg.validate().expect_err("zero extra route rate limit");
        assert!(err.to_string().contains("extra_route_rate_limit"));
    }

    #[tokio::test]
    async fn extra_route_limiter_burst_allows_initial_spike() -> anyhow::Result<()> {
        let app = limited_router_with_burst(1, Some(3));
        for i in 0..3 {
            let resp = app.clone().oneshot(limited_req("10.4.4.4")?).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "burst request {i}");
        }
        let resp = app.clone().oneshot(limited_req("10.4.4.4")?).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    /// Pins that a denied request advertises a positive `Retry-After`
    /// delta-seconds header.
    #[tokio::test]
    async fn extra_route_limiter_deny_sets_retry_after() -> anyhow::Result<()> {
        let app = limited_router(1);
        let ok = app.clone().oneshot(limited_req("10.5.5.5")?).await?;
        assert_eq!(ok.status(), StatusCode::OK);
        let denied = app.clone().oneshot(limited_req("10.5.5.5")?).await?;
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = denied
            .headers()
            .get(header::RETRY_AFTER)
            .context("Retry-After present")?
            .to_str()
            .context("Retry-After is ASCII")?
            .parse::<u64>()
            .context("Retry-After parses as delta-seconds")?;
        assert!(retry_after >= 1, "delta-seconds must be >= 1");

        Ok(())
    }

    /// Pins that zero tool- and extra-route burst capacities are rejected with
    /// the offending knob named in the validation error.
    #[test]
    fn validate_rejects_zero_burst_knobs() -> anyhow::Result<()> {
        let tool_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_tool_rate_limit(10)
            .with_tool_rate_limit_burst(0)
            .validate()
            .err()
            .context("zero tool burst")?;
        assert!(tool_err.to_string().contains("tool_rate_limit_burst"));

        let route_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_extra_route_rate_limit(10)
            .with_extra_route_rate_limit_burst(0)
            .validate()
            .err()
            .context("zero extra route burst")?;
        assert!(
            route_err
                .to_string()
                .contains("extra_route_rate_limit_burst")
        );

        Ok(())
    }

    /// Pins that burst knobs set without their base rate limit are rejected as
    /// orphans by validation.
    #[test]
    fn validate_rejects_orphan_burst_knobs() -> anyhow::Result<()> {
        let tool_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_tool_rate_limit_burst(5)
            .validate()
            .err()
            .context("orphan tool burst")?;
        assert!(tool_err.to_string().contains("requires tool_rate_limit"));

        let route_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_extra_route_rate_limit_burst(5)
            .validate()
            .err()
            .context("orphan extra route burst")?;
        assert!(
            route_err
                .to_string()
                .contains("requires extra_route_rate_limit")
        );

        Ok(())
    }

    /// Pins that zero burst limits on the auth limiter or its pre-auth limiter
    /// are rejected, naming `rate_limit.burst` / `pre_auth_burst`.
    #[test]
    fn validate_rejects_zero_auth_bursts() -> anyhow::Result<()> {
        use crate::auth::RateLimitConfig;

        let burst_auth =
            AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(10).with_burst(0));
        let burst_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(burst_auth)
            .validate()
            .err()
            .context("zero auth burst")?;
        assert!(burst_err.to_string().contains("rate_limit.burst"));

        let pre_auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(RateLimitConfig::new(10).with_pre_auth_burst(0));
        let pre_auth_err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(pre_auth)
            .validate()
            .err()
            .context("zero pre-auth burst")?;
        assert!(pre_auth_err.to_string().contains("pre_auth_burst"));

        Ok(())
    }

    /// Pins that a zero pre-auth max-per-minute is rejected by validation.
    #[test]
    fn validate_rejects_zero_pre_auth_max_per_minute() -> anyhow::Result<()> {
        use crate::auth::RateLimitConfig;

        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(RateLimitConfig::new(10).with_pre_auth_max_per_minute(0));
        let err = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .validate()
            .err()
            .context("zero pre-auth rate")?;
        assert!(err.to_string().contains("pre_auth_max_per_minute"));

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

    /// Pins that a zero CRL max-response-bytes capacity is rejected once the
    /// required TLS pairing is present.
    #[test]
    fn validate_rejects_zero_crl_max_response_bytes() -> anyhow::Result<()> {
        let mut mtls = valid_mtls_config();
        mtls.crl_max_response_bytes = 0;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.mtls = Some(mtls);

        // TLS paths are required alongside mTLS, else validation reports that
        // pairing error first and never reaches the capacity knobs.
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_auth(auth)
            .with_tls_paths(Some("cert.pem".into()), Some("key.pem".into()));

        let err = cfg.validate().err().context("zero CRL response cap")?;
        assert!(err.to_string().contains("crl_max_response_bytes"));

        Ok(())
    }

    /// Pins that `pre_auth_burst` without `pre_auth_max_per_minute` is legal
    /// because the pre-auth base rate always resolves.
    #[test]
    fn validate_accepts_pre_auth_burst_without_explicit_pre_auth_rate() -> anyhow::Result<()> {
        use crate::auth::RateLimitConfig;

        let auth = AuthConfig::with_keys(vec![])
            .with_rate_limit(RateLimitConfig::new(10).with_pre_auth_burst(50));
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_auth(auth);
        let _validated = cfg
            .validate()
            .context("pre_auth_burst has no orphan rule")?;

        Ok(())
    }

    // -- trusted-forwarder mode (ClientIp / ForwardedHeaderMode) --

    /// Pins that `trusted_forwarder_max_entries` accepts only
    /// `1..=MAX_SCANNED_ENTRIES` and rejects the configurable ceiling plus one.
    #[test]
    fn trusted_forwarder_max_entries_bounds_are_enforced() -> anyhow::Result<()> {
        use crate::forwarded::{MAX_CONFIGURABLE_SCANNED_ENTRIES, MAX_SCANNED_ENTRIES};

        let cfg = |entries: usize| {
            McpServerConfig::new("127.0.0.1:8080", "t", "0")
                .with_trusted_forwarder_max_entries(entries)
                .validate()
        };
        assert!(cfg(0).is_err(), "0 would pin every client to the proxy");
        assert!(
            cfg(MAX_CONFIGURABLE_SCANNED_ENTRIES + 1).is_err(),
            "above the ceiling would re-open the header-bomb vector"
        );
        let _one_entry = cfg(1)?;
        let _module_default = cfg(MAX_SCANNED_ENTRIES)?;
        let _configurable_ceiling = cfg(MAX_CONFIGURABLE_SCANNED_ENTRIES)?;

        Ok(())
    }

    /// Pins that `trusted_forwarder_max_entries` defaults to the module's
    /// `MAX_SCANNED_ENTRIES` constant.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::trusted_forwarder_max_entries_defaults_to_the_module_constant keeps the uniform IS-7 test signature while it only constructs values"
    )]
    fn trusted_forwarder_max_entries_defaults_to_the_module_constant() -> anyhow::Result<()> {
        use crate::forwarded::MAX_SCANNED_ENTRIES;

        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "0");
        assert_eq!(cfg.trusted_forwarder_max_entries, MAX_SCANNED_ENTRIES);

        Ok(())
    }

    fn forward_resolver(
        trusted: &[&str],
        mode: ForwardedHeaderMode,
    ) -> anyhow::Result<Arc<ForwardResolver>> {
        use crate::forwarded::MAX_SCANNED_ENTRIES;

        Ok(Arc::new(ForwardResolver {
            trusted: trusted
                .iter()
                .map(|entry| entry.parse().context("test trusted proxy entry"))
                .collect::<anyhow::Result<Vec<_>>>()?,
            mode,
            max_scanned_entries: MAX_SCANNED_ENTRIES,
            request_id_header: None,
        }))
    }

    /// Probe router reporting `"<PeerAddr ip>|<ClientIp>"`.
    fn forwarded_probe_router(resolver: Option<Arc<ForwardResolver>>) -> axum::Router {
        async fn probe(req: Request<Body>) -> String {
            let peer_ip = req
                .extensions()
                .get::<PeerAddr>()
                .map(|peer| peer.addr.ip().to_string())
                .unwrap_or_default();
            let client_ip = req
                .extensions()
                .get::<ClientIp>()
                .map(|client| client.ip.to_string())
                .unwrap_or_default();
            format!("{peer_ip}|{client_ip}")
        }
        use axum::{middleware::from_fn, routing::get};

        axum::Router::new()
            .route("/probe", get(probe))
            .layer(from_fn(move |req, next| {
                let resolver_clone = resolver.clone();
                normalize_peer_addr_middleware(resolver_clone, req, next)
            }))
    }

    fn request_id_probe_router(resolver: Option<Arc<ForwardResolver>>) -> axum::Router {
        async fn probe(req: Request<Body>) -> String {
            request_id_for_log(req.extensions())
                .map(|id| id.to_string())
                .unwrap_or_default()
        }
        use axum::{middleware::from_fn, routing::get};

        axum::Router::new()
            .route("/probe", get(probe))
            .layer(from_fn(move |req, next| {
                let resolver_clone = resolver.clone();
                normalize_peer_addr_middleware(resolver_clone, req, next)
            }))
    }

    fn probe_req(peer: &str, header: Option<(&str, &str)>) -> anyhow::Result<Request<Body>> {
        let addr: SocketAddr = peer.parse().context("test peer address")?;
        let mut builder = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(addr));
        if let Some((name, value)) = header {
            builder = builder.header(name, value);
        }
        builder
            .body(Body::empty())
            .context("test probe request body")
    }

    fn request_id_probe_req(peer: &str, values: &[&str]) -> anyhow::Result<Request<Body>> {
        let addr: SocketAddr = peer.parse().context("test peer address")?;
        let mut builder = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(addr));
        for value in values {
            builder = builder.header("x-request-id", *value);
        }
        builder
            .body(Body::empty())
            .context("test request-id probe body")
    }

    fn request_id_resolver(header: Option<&'static str>) -> anyhow::Result<Arc<ForwardResolver>> {
        use crate::forwarded::MAX_SCANNED_ENTRIES;

        Ok(Arc::new(ForwardResolver {
            trusted: vec!["127.0.0.1/32".parse().context("test trusted peer")?],
            mode: ForwardedHeaderMode::XForwardedFor,
            max_scanned_entries: MAX_SCANNED_ENTRIES,
            request_id_header: header.map(HeaderName::from_static),
        }))
    }

    /// Pins that `sanitize_for_log` strips control characters and truncates to
    /// `MAX_LOGGED_HEADER_CHARS` with an ellipsis marker.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/transport.rs::sanitize_for_log_strips_controls_and_bounds keeps the uniform IS-7 test signature while it only constructs values"
    )]
    fn sanitize_for_log_strips_controls_and_bounds() -> anyhow::Result<()> {
        assert_eq!(sanitize_for_log("a\r\nb", MAX_LOGGED_HEADER_CHARS), "ab");
        assert_eq!(
            sanitize_for_log("\u{1b}[31m", MAX_LOGGED_HEADER_CHARS),
            "[31m"
        );
        assert_eq!(sanitize_for_log("a\tb", MAX_LOGGED_HEADER_CHARS), "ab");
        let long = "a".repeat(129);
        assert_eq!(
            sanitize_for_log(&long, MAX_LOGGED_HEADER_CHARS),
            format!("{}...(truncated)", "a".repeat(128))
        );
        assert_eq!(
            sanitize_for_log(&"a".repeat(128), MAX_LOGGED_HEADER_CHARS),
            "a".repeat(128)
        );
        assert_eq!(sanitize_for_log("", MAX_LOGGED_HEADER_CHARS), "");

        Ok(())
    }

    /// Pins that the request-id hint is taken from the last `x-request-id`
    /// value when a trusted peer sends several.
    #[tokio::test]
    async fn request_id_taken_from_trusted_peer_last_occurrence() -> anyhow::Result<()> {
        let app = request_id_probe_router(Some(request_id_resolver(Some("x-request-id"))?));
        let resp = app
            .oneshot(request_id_probe_req(
                "127.0.0.1:5555",
                &["spoofed", "router-1"],
            )?)
            .await?;
        assert_eq!(body_string(resp).await?, "router-1");

        Ok(())
    }

    /// Pins that the request-id hint is ignored when the peer is untrusted.
    #[tokio::test]
    async fn request_id_ignored_from_untrusted_peer() -> anyhow::Result<()> {
        let app = request_id_probe_router(Some(request_id_resolver(Some("x-request-id"))?));
        let resp = app
            .oneshot(request_id_probe_req("10.9.9.9:5555", &["router-1"])?)
            .await?;
        assert_eq!(body_string(resp).await?, "");

        Ok(())
    }

    /// Pins that request-id hints are stripped of control bytes, bounded to 128
    /// characters, and dropped entirely when they are not valid UTF-8.
    #[tokio::test]
    async fn request_id_sanitized_and_bounded() -> anyhow::Result<()> {
        use axum::http::HeaderValue;

        let app = request_id_probe_router(Some(request_id_resolver(Some("x-request-id"))?));
        let sanitized = app
            .clone()
            .oneshot(request_id_probe_req("127.0.0.1:5555", &["a\tb"])?)
            .await?;
        assert_eq!(body_string(sanitized).await?, "ab");

        let long = "a".repeat(200);
        let bounded = app
            .clone()
            .oneshot(request_id_probe_req("127.0.0.1:5555", &[&long])?)
            .await?;
        assert_eq!(
            body_string(bounded).await?,
            format!("{}...(truncated)", "a".repeat(128))
        );

        let addr: SocketAddr = "127.0.0.1:5555".parse().context("test peer address")?;
        let req = Request::builder()
            .uri("/probe")
            .extension(ConnectInfo(addr))
            .header(
                "x-request-id",
                HeaderValue::from_bytes(b"caf\xe9").context("non-UTF-8 header value")?,
            )
            .body(Body::empty())
            .context("test request-id body")?;
        let dropped = app.oneshot(req).await?;
        assert_eq!(body_string(dropped).await?, "");

        Ok(())
    }

    /// Pins that no request id is extracted when the resolver has no
    /// configured header.
    #[tokio::test]
    async fn request_id_not_extracted_when_knob_off() -> anyhow::Result<()> {
        let app = request_id_probe_router(Some(request_id_resolver(None)?));
        let resp = app
            .oneshot(request_id_probe_req("127.0.0.1:5555", &["router-1"])?)
            .await?;
        assert_eq!(body_string(resp).await?, "");

        Ok(())
    }

    fn knobs(configure: impl FnOnce(&mut LogContextConfig)) -> LogContextConfig {
        let mut cfg = LogContextConfig::default();
        configure(&mut cfg);
        cfg
    }

    fn reqlog_router(
        configure: impl FnOnce(McpServerConfig) -> McpServerConfig,
    ) -> anyhow::Result<axum::Router> {
        #[derive(Clone)]
        struct Handler;
        impl ServerHandler for Handler {}
        let config = configure(McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0"));
        Ok(build_app_router(config, || Handler)
            .context("build_app_router")?
            .0)
    }

    fn reqlog_req(method: Method, path: &str, peer: &str) -> anyhow::Result<Request<Body>> {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(
                peer.parse::<SocketAddr>().context("test peer address")?,
            ))
            .body(Body::empty())
            .context("test request-log body")?;
        Ok(request)
    }

    fn reqlog_req_with_headers(
        method: Method,
        path: &str,
        peer: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Request<Body>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(
                peer.parse::<SocketAddr>().context("test peer address")?,
            ));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).context("test request-log body")
    }

    async fn drive_reqlog(app: &axum::Router, req: Request<Body>) -> anyhow::Result<Response> {
        app.clone()
            .oneshot(req)
            .await
            .context("drive request-log request")
    }

    async fn reqlog_lines_after(
        app: &axum::Router,
        logs: &CapturedLogs,
        req: Request<Body>,
        message: &str,
    ) -> anyhow::Result<Vec<String>> {
        let _response = drive_reqlog(app, req).await?;
        Ok(logs.lines_containing(message))
    }

    /// Pins that probe endpoints are excluded from request logging by default
    /// while `/version` and `/mcp` are logged.
    #[tokio::test]
    async fn probe_paths_are_not_request_logged_by_default() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| cfg)?;

        for path in ["/healthz", "/readyz"] {
            let before = logs.lines_containing("incoming request").len();
            let _probe_response =
                drive_reqlog(&app, reqlog_req(Method::GET, path, "127.0.0.1:5555")?).await?;
            assert_eq!(logs.lines_containing("incoming request").len(), before);
        }

        let before_version = logs.lines_containing("incoming request").len();
        let _version_response =
            drive_reqlog(&app, reqlog_req(Method::GET, "/version", "127.0.0.1:5555")?).await?;
        assert_eq!(
            logs.lines_containing("incoming request").len(),
            before_version + 1
        );

        let before_mcp = logs.lines_containing("incoming request").len();
        let _mcp_response =
            drive_reqlog(&app, reqlog_req(Method::POST, "/mcp", "127.0.0.1:5555")?).await?;
        assert_eq!(
            logs.lines_containing("incoming request").len(),
            before_mcp + 1
        );

        Ok(())
    }

    /// Pins that replacing the request-log exclusion list changes which paths
    /// are logged.
    #[tokio::test]
    async fn request_log_exclusion_list_is_replaceable() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| cfg.with_request_log_exclude_paths(["/version"]))?;
        let healthz = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req(Method::GET, "/healthz", "127.0.0.1:5555")?,
            "incoming request",
        )
        .await?;
        assert_eq!(healthz.len(), 1);
        let _version_response =
            drive_reqlog(&app, reqlog_req(Method::GET, "/version", "127.0.0.1:5555")?).await?;
        assert_eq!(logs.lines_containing("incoming request").len(), 1);

        let replacement_logs = CapturedLogs::default();
        let _replacement_guard = capture_debug_logs(replacement_logs.clone());
        let replacement_app =
            reqlog_router(|cfg| cfg.with_request_log_exclude_paths(Vec::<String>::new()))?;
        let lines = reqlog_lines_after(
            &replacement_app,
            &replacement_logs,
            reqlog_req(Method::GET, "/healthz", "127.0.0.1:5555")?,
            "incoming request",
        )
        .await?;
        assert_eq!(lines.len(), 1);

        Ok(())
    }

    /// Pins that the request log omits client-identifying fields by default.
    #[tokio::test]
    async fn request_log_omits_client_fields_by_default() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| cfg.with_trusted_proxies(["127.0.0.1/32"]))?;
        let lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("x-forwarded-for", "203.0.113.7"), ("x-request-id", "qa-1")],
            )?,
            "incoming request",
        )
        .await?;
        assert_eq!(lines.len(), 1);
        let line = lines.first().context("incoming request line")?;
        for absent in ["client_ip", "peer_ip", "request_id", "mcp_session"] {
            assert!(
                !line.contains(absent),
                "{absent} must be absent from {line}"
            );
        }

        Ok(())
    }

    /// Pins that enabling client fields adds `client_ip`, `peer_ip`, and
    /// `request_id`, with the direct peer winning for untrusted clients.
    #[tokio::test]
    async fn request_log_carries_enabled_client_fields() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.with_trusted_proxies(["127.0.0.1/32"])
                .with_log_context(knobs(|ctx| {
                    ctx.client_ip = true;
                    ctx.peer_ip = true;
                    ctx.request_id = true;
                }))
        })?;
        let lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("x-forwarded-for", "203.0.113.7"), ("x-request-id", "qa-1")],
            )?,
            "incoming request",
        )
        .await?;
        assert_eq!(lines.len(), 1);
        let first_line = lines.first().context("first incoming request line")?;
        assert!(first_line.contains("client_ip=203.0.113.7"), "{first_line}");
        assert!(first_line.contains("peer_ip=127.0.0.1"), "{first_line}");
        assert!(first_line.contains("request_id=\"qa-1\""), "{first_line}");

        let untrusted_lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "10.9.9.9:5555",
                &[("x-forwarded-for", "203.0.113.7"), ("x-request-id", "qa-1")],
            )?,
            "incoming request",
        )
        .await?;
        let line = untrusted_lines
            .last()
            .context("second incoming request line")?;
        assert!(line.contains("client_ip=10.9.9.9"), "{line}");
        assert!(line.contains("peer_ip=10.9.9.9"), "{line}");
        assert!(!line.contains("request_id"), "{line}");

        Ok(())
    }

    /// Pins that `mcp_hints_for_log` reports the protocol-version hint bounded
    /// to 128 characters, and `None` when it is absent.
    #[test]
    fn mcp_hints_for_log_bounds_protocol_version() -> anyhow::Result<()> {
        let mut exact_headers = HeaderMap::new();
        let exact = "a".repeat(128);
        let _previous_exact =
            exact_headers.insert("mcp-protocol-version", exact.parse().context("exact hint")?);
        assert_eq!(mcp_hints_for_log(&exact_headers), (false, Some(exact)));

        let mut long_headers = HeaderMap::new();
        let long = "a".repeat(129);
        let _previous_long =
            long_headers.insert("mcp-protocol-version", long.parse().context("long hint")?);
        assert_eq!(
            mcp_hints_for_log(&long_headers),
            (false, Some(format!("{}...(truncated)", "a".repeat(128))))
        );

        let empty_headers = HeaderMap::new();
        assert_eq!(mcp_hints_for_log(&empty_headers), (false, None));

        Ok(())
    }

    /// Pins that enabling `mcp_hints` logs the session flag and protocol version
    /// while keeping the session id itself out of the log.
    #[tokio::test]
    async fn mcp_hints_on_incoming_request() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| cfg.with_log_context(knobs(|ctx| ctx.mcp_hints = true)))?;
        let lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[
                    ("mcp-session-id", "secret-session-value"),
                    ("mcp-protocol-version", "2025-06-18"),
                ],
            )?,
            "incoming request",
        )
        .await?;
        assert_eq!(lines.len(), 1);
        let first_line = lines.first().context("first incoming request line")?;
        assert!(first_line.contains("mcp_session=true"), "{first_line}");
        assert!(
            first_line.contains("mcp_protocol_version=\"2025-06-18\""),
            "{first_line}"
        );
        assert!(!logs.contents().contains("secret-session-value"));

        let second_lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req(Method::POST, "/mcp", "127.0.0.1:5555")?,
            "incoming request",
        )
        .await?;
        let line = second_lines
            .last()
            .context("second incoming request line")?;
        assert!(line.contains("mcp_session=false"), "{line}");
        assert!(!line.contains("mcp_protocol_version"), "{line}");

        Ok(())
    }

    /// Pins that forwarding headers are redacted in the logged header map while
    /// the resolved `client_ip` stays visible.
    #[tokio::test]
    async fn request_log_headers_keep_forwarding_redacted_with_client_ip() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.enable_request_header_logging()
                .with_trusted_proxies(["127.0.0.1/32"])
                .with_log_context(knobs(|ctx| ctx.client_ip = true))
        })?;
        let lines = reqlog_lines_after(
            &app,
            &logs,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[
                    ("forwarded", "for=203.0.113.7"),
                    ("x-forwarded-for", "203.0.113.7"),
                    ("x-real-ip", "203.0.113.7"),
                ],
            )?,
            "incoming request",
        )
        .await?;
        let line = lines.first().context("incoming request line")?;
        for name in ["forwarded", "x-forwarded-for", "x-real-ip"] {
            assert!(line.contains(&format!("{name}: [REDACTED]")), "{line}");
        }
        assert!(line.contains("client_ip=203.0.113.7"), "{line}");
        let headers_text = line.split("headers=").nth(1).unwrap_or_default();
        assert!(!headers_text.contains("203.0.113.7"), "{line}");

        Ok(())
    }

    /// Pins that a rejected cross-origin request logs exactly one incoming line
    /// without client fields and no completion line, and `/healthz` stays
    /// excluded.
    #[tokio::test]
    async fn origin_rejected_request_logs_once_without_client_fields() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.with_allowed_origins(["http://good.example"])
                .with_log_context(knobs(|ctx| {
                    ctx.client_ip = true;
                    ctx.peer_ip = true;
                    ctx.mcp_hints = true;
                    ctx.request_completion = true;
                }))
        })?;
        let resp = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("origin", "http://evil.example")],
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let incoming = logs.lines_containing("incoming request");
        assert_eq!(incoming.len(), 1);
        let incoming_line = incoming.first().context("incoming request line")?;
        for absent in ["client_ip", "peer_ip", "mcp_session"] {
            assert!(!incoming_line.contains(absent), "{incoming_line}");
        }
        assert_eq!(
            logs.lines_containing("rejected request: Origin not allowed")
                .len(),
            1
        );
        assert_eq!(
            logs.lines_containing("request completed"),
            Vec::<String>::new()
        );

        let before_healthz = logs.lines_containing("incoming request").len();
        let _healthz_response = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::GET,
                "/healthz",
                "127.0.0.1:5555",
                &[("origin", "http://evil.example")],
            )?,
        )
        .await?;
        assert_eq!(
            logs.lines_containing("incoming request").len(),
            before_healthz
        );

        Ok(())
    }

    /// Pins that completion logging emits one line per served request carrying
    /// method, path, status, latency, and client ip.
    #[tokio::test]
    async fn request_completion_line_reports_status_and_latency() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.with_log_context(knobs(|ctx| {
                ctx.request_completion = true;
                ctx.client_ip = true;
            }))
        })?;
        for (method, path) in [(Method::POST, "/mcp"), (Method::GET, "/version")] {
            let before_completed = logs.lines_containing("request completed").len();
            let resp =
                drive_reqlog(&app, reqlog_req(method.clone(), path, "127.0.0.1:5555")?).await?;
            let completed_lines = logs.lines_containing("request completed");
            assert_eq!(completed_lines.len(), before_completed + 1);
            let completed_line = completed_lines.last().context("completion line")?;
            assert!(
                completed_line.contains(&format!("method={method}")),
                "{completed_line}"
            );
            assert!(
                completed_line.contains(&format!("path={path}")),
                "{completed_line}"
            );
            assert!(
                completed_line.contains(&format!("status={}", resp.status().as_u16())),
                "{completed_line}"
            );
            assert!(completed_line.contains("latency_ms="), "{completed_line}");
            assert!(
                completed_line.contains("client_ip=127.0.0.1"),
                "{completed_line}"
            );
        }

        Ok(())
    }

    /// Pins that completion lines are absent by default and for excluded paths,
    /// but present for a logged path once enabled.
    #[tokio::test]
    async fn request_completion_line_absent_by_default_and_for_excluded_paths() -> anyhow::Result<()>
    {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| cfg)?;
        let _version_response =
            drive_reqlog(&app, reqlog_req(Method::GET, "/version", "127.0.0.1:5555")?).await?;
        assert_eq!(
            logs.lines_containing("request completed"),
            Vec::<String>::new()
        );

        let configured_logs = CapturedLogs::default();
        let _configured_guard = capture_debug_logs(configured_logs.clone());
        let configured_app = reqlog_router(|cfg| {
            cfg.with_log_context(knobs(|ctx| {
                ctx.request_completion = true;
            }))
        })?;
        let _healthz_response = drive_reqlog(
            &configured_app,
            reqlog_req(Method::GET, "/healthz", "127.0.0.1:5555")?,
        )
        .await?;
        assert_eq!(
            configured_logs.lines_containing("request completed"),
            Vec::<String>::new()
        );
        let _configured_version_response = drive_reqlog(
            &configured_app,
            reqlog_req(Method::GET, "/version", "127.0.0.1:5555")?,
        )
        .await?;
        assert_eq!(
            configured_logs.lines_containing("request completed").len(),
            1
        );

        Ok(())
    }

    /// Pins that auth failures through the real middleware stack carry resolved
    /// client, request-id, and credential-classification fields, honored only
    /// for trusted peers.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: src/transport.rs::auth_failure_through_real_wiring_carries_resolved_client_fields one linear end-to-end scenario; splitting would duplicate the server harness"
    )]
    async fn auth_failure_through_real_wiring_carries_resolved_client_fields() -> anyhow::Result<()>
    {
        use crate::auth::generate_api_key;

        let (_token, hash) = generate_api_key()?;
        let mut fields = LogContextConfig::recommended();
        fields.request_id = true;
        fields.credential_fingerprint = true;
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.with_trusted_proxies(["127.0.0.1/32"])
                .with_log_context(fields)
                .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                    "viewer-key",
                    hash,
                    "viewer",
                )]))
        })?;

        let resp = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[
                    ("x-forwarded-for", "203.0.113.7"),
                    ("x-request-id", "qa-1"),
                    ("user-agent", "probe/1.0"),
                ],
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let line = logs
            .lines_containing("failure_class=missing_credential")
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing auth failed line: {}", logs.contents()))?;
        assert!(line.contains("client_ip=203.0.113.7"), "{line}");
        assert!(line.contains("peer_ip=127.0.0.1"), "{line}");
        assert!(line.contains("request_id=\"qa-1\""), "{line}");
        assert!(line.contains("method=POST"), "{line}");
        assert!(line.contains("path=/mcp"), "{line}");
        assert!(line.contains("user_agent=\"probe/1.0\""), "{line}");
        assert!(line.contains("auth_scheme=none"), "{line}");

        let before_untrusted = logs.lines_containing("auth failed").len();
        let untrusted_resp = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "10.9.9.9:5555",
                &[("x-request-id", "untrusted")],
            )?,
        )
        .await?;
        assert_eq!(untrusted_resp.status(), StatusCode::UNAUTHORIZED);
        let untrusted_line = logs
            .lines_containing("auth failed")
            .remove(before_untrusted);
        assert!(
            untrusted_line.contains("client_ip=10.9.9.9"),
            "{untrusted_line}"
        );
        assert!(!untrusted_line.contains("request_id"), "{untrusted_line}");

        let before_invalid = logs.lines_containing("auth failed").len();
        let invalid_resp = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("authorization", "Bearer not-a-key")],
            )?,
        )
        .await?;
        assert_eq!(invalid_resp.status(), StatusCode::UNAUTHORIZED);
        let invalid_line = logs.lines_containing("auth failed").remove(before_invalid);
        assert!(
            invalid_line.contains("failure_class=invalid_credential"),
            "{invalid_line}"
        );
        assert!(invalid_line.contains("token_kind=opaque"), "{invalid_line}");
        assert!(invalid_line.contains("credential_fp="), "{invalid_line}");
        assert!(!invalid_line.contains("not-a-key"), "{invalid_line}");

        let unauthenticated_logs = CapturedLogs::default();
        let _unauthenticated_guard = capture_debug_logs(unauthenticated_logs.clone());
        let unauthenticated_app =
            reqlog_router(|cfg| cfg.with_auth(AuthConfig::with_keys(vec![])))?;
        let unauthenticated_resp = drive_reqlog(
            &unauthenticated_app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("x-request-id", "qa-ignored")],
            )?,
        )
        .await?;
        assert_eq!(unauthenticated_resp.status(), StatusCode::UNAUTHORIZED);
        let unauthenticated_line = unauthenticated_logs
            .lines_containing("auth failed")
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing auth failed line: {}",
                    unauthenticated_logs.contents()
                )
            })?;
        assert!(
            unauthenticated_line.ends_with("auth failed failure_class=missing_credential"),
            "{unauthenticated_line}"
        );

        Ok(())
    }

    /// Pins that an expired configured API key yields a 401 with an `expired`
    /// challenge and logs the credential owner.
    #[tokio::test]
    async fn expired_api_key_through_real_wiring_names_owner_and_returns_expired_challenge()
    -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let mut fields = LogContextConfig::recommended();
        fields.credential_owner = true;
        let expired_entry = ApiKeyEntry::new(
            "old-key",
            "$argon2id$v=19$m=19456,t=2,p=1$BwcHBwcHBwcHBwcHBwcHBw$spS8B9AhHG1LikfhGlssVMfP8mq37+8/mXnl98ps0NU",
            "viewer",
        )
        .try_with_expiry("2020-01-01T00:00:00Z")
        .context("expiry fixture")?;
        let app = reqlog_router(|cfg| {
            cfg.with_log_context(fields)
                .with_auth(AuthConfig::with_keys(vec![expired_entry]))
        })?;
        let resp = drive_reqlog(
            &app,
            reqlog_req_with_headers(
                Method::POST,
                "/mcp",
                "127.0.0.1:5555",
                &[("authorization", "Bearer golden-vector-token-0p5p3")],
            )?,
        )
        .await?;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .context("WWW-Authenticate header")?
            .to_str()
            .context("challenge is ASCII")?
            .to_owned();
        assert!(challenge.contains("error_description=\"token is expired\""));
        assert_eq!(body_string(resp).await?, "unauthorized: expired credential");
        let line = logs
            .lines_containing("failure_class=expired_credential")
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("missing expired auth failed line: {}", logs.contents())
            })?;
        assert!(line.contains("credential_owner=\"old-key\""), "{line}");
        assert!(line.contains("credential_rejection=expired"), "{line}");

        Ok(())
    }

    /// Pins that an RBAC denial through the real wiring returns 403 and logs the
    /// resolved client fields.
    #[tokio::test]
    async fn rbac_denial_through_real_wiring_carries_client_fields() -> anyhow::Result<()> {
        use crate::{
            auth::generate_api_key,
            rbac::{RbacConfig, RoleConfig},
        };

        let (token, hash) = generate_api_key()?;
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = reqlog_router(|cfg| {
            cfg.with_trusted_proxies(["127.0.0.1/32"])
                .with_log_context(knobs(|ctx| {
                    ctx.client_ip = true;
                    ctx.peer_ip = true;
                    ctx.request_id = true;
                }))
                .with_auth(AuthConfig::with_keys(vec![ApiKeyEntry::new(
                    "viewer-key",
                    hash,
                    "viewer",
                )]))
                .with_rbac(Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                    RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()]),
                ]))))
        })?;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_i32,
            "method": "tools/call",
            "params": { "name": "forbidden", "arguments": {} }
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .extension(ConnectInfo(
                "127.0.0.1:5555"
                    .parse::<SocketAddr>()
                    .context("test peer address")?,
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-forwarded-for", "203.0.113.7")
            .header("x-request-id", "qa-2")
            .body(Body::from(body))
            .context("test RBAC request body")?;

        let resp = drive_reqlog(&app, req).await?;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let line = logs
            .lines_containing("RBAC denied")
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing RBAC denied line: {}", logs.contents()))?;
        assert!(line.contains("client_ip=203.0.113.7"), "{line}");
        assert!(line.contains("peer_ip=127.0.0.1"), "{line}");
        assert!(line.contains("request_id=\"qa-2\""), "{line}");

        Ok(())
    }

    /// Pins that with no forward resolver, `ClientIp` equals the direct peer and
    /// `x-forwarded-for` is ignored.
    #[tokio::test]
    async fn client_ip_equals_direct_without_resolver() -> anyhow::Result<()> {
        let app = forwarded_probe_router(None);
        let resp = app
            .oneshot(probe_req(
                "10.1.2.3:4444",
                Some(("x-forwarded-for", "203.0.113.7")),
            )?)
            .await?;
        assert_eq!(
            body_string(resp).await?,
            "10.1.2.3|10.1.2.3",
            "feature off: header ignored, ClientIp == direct"
        );

        Ok(())
    }

    /// Pins that a trusted peer's forwarded chain resolves `ClientIp` while
    /// `PeerAddr` stays direct.
    #[tokio::test]
    async fn client_ip_resolved_for_trusted_peer() -> anyhow::Result<()> {
        let app = forwarded_probe_router(Some(forward_resolver(
            &["10.0.0.0/8"],
            ForwardedHeaderMode::XForwardedFor,
        )?));
        let resp = app
            .oneshot(probe_req(
                "10.0.0.1:9999",
                Some(("x-forwarded-for", "203.0.113.7")),
            )?)
            .await?;
        assert_eq!(
            body_string(resp).await?,
            "10.0.0.1|203.0.113.7",
            "PeerAddr stays direct while ClientIp resolves"
        );

        Ok(())
    }

    /// Pins that a malformed forwarded chain falls back to the direct peer.
    #[tokio::test]
    async fn client_ip_falls_back_to_direct_on_malformed_header() -> anyhow::Result<()> {
        let app = forwarded_probe_router(Some(forward_resolver(
            &["10.0.0.0/8"],
            ForwardedHeaderMode::XForwardedFor,
        )?));
        let resp = app
            .oneshot(probe_req(
                "10.0.0.1:9999",
                Some(("x-forwarded-for", "not-an-ip")),
            )?)
            .await?;
        assert_eq!(
            body_string(resp).await?,
            "10.0.0.1|10.0.0.1",
            "malformed chain falls back to the direct peer"
        );

        Ok(())
    }

    /// Pins that `ForwardedHeaderMode` deserializes from kebab-case wire
    /// values and rejects `PascalCase` ones.
    #[test]
    fn forwarded_header_mode_deserializes_kebab_case() -> anyhow::Result<()> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Wrapper {
            mode: ForwardedHeaderMode,
        }
        let wrapper_kebab: Wrapper = toml::from_str(r#"mode = "x-forwarded-for""#)?;
        assert_eq!(wrapper_kebab.mode, ForwardedHeaderMode::XForwardedFor);
        let wrapper_forwarded: Wrapper = toml::from_str(r#"mode = "forwarded""#)?;
        assert_eq!(wrapper_forwarded.mode, ForwardedHeaderMode::Forwarded);
        assert!(
            toml::from_str::<Wrapper>(r#"mode = "XForwardedFor""#).is_err(),
            "PascalCase wire value must be rejected"
        );

        Ok(())
    }

    /// Pins that `validate` rejects a trusted-proxy entry that is not a CIDR
    /// or bare IP.
    #[test]
    fn validate_rejects_bad_trusted_proxy_entry() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_trusted_proxies(["not-a-cidr"]);
        let err = cfg.validate().err().context("bad CIDR")?;
        assert!(err.to_string().contains("trusted_proxies"));

        Ok(())
    }

    /// Pins that `validate` rejects a zero-length trusted-proxy prefix.
    #[test]
    fn validate_rejects_zero_prefix_trusted_proxy() -> anyhow::Result<()> {
        for entry in ["0.0.0.0/0", "::/0"] {
            let cfg =
                McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_trusted_proxies([entry]);
            let err = cfg.validate().err().context("zero-prefix CIDR")?;
            assert!(
                err.to_string().contains("prefix length 0"),
                "entry {entry}: {err}"
            );
        }

        Ok(())
    }

    /// Pins that trusted-proxy configuration accepts CIDRs and bare IPs.
    #[test]
    fn validate_accepts_cidr_and_bare_ip_proxy_entries() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0").with_trusted_proxies([
            "10.0.0.0/8",
            "192.0.2.1",
            "2001:db8::1",
        ]);
        let _validated = cfg.validate().context("CIDRs and bare IPs are accepted")?;

        Ok(())
    }

    /// Pins that `validate` rejects a forwarded-header mode configured
    /// without trusted proxies.
    #[test]
    fn validate_rejects_forwarded_header_without_proxies() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:8080", "t", "1.0.0")
            .with_forwarded_header(ForwardedHeaderMode::Forwarded);
        let err = cfg.validate().err().context("mode without proxies")?;
        assert!(err.to_string().contains("requires trusted_proxies"));

        Ok(())
    }

    // -- origin_check_middleware --

    /// Axum handler shared by the middleware test routers: replies `ok`.
    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Build a test router with origin check middleware and a simple handler.
    fn origin_router(origins: Vec<String>, log_request_headers: bool) -> axum::Router {
        use axum::{middleware::from_fn, routing::get};

        let allowed: Arc<[AllowedOrigin]> = Arc::from(
            origins
                .into_iter()
                .filter_map(|origin| parse_allowed_origin(&origin))
                .collect::<Vec<_>>(),
        );
        let request_log = Arc::new(RequestLogConfig {
            log_request_headers,
            exclude_paths: HashSet::new(),
            fields: LogContextConfig::default(),
        });
        axum::Router::new()
            .route("/test", get(ok_handler))
            .layer(from_fn(move |req, next| {
                let allowed_for_middleware = Arc::clone(&allowed);
                let log_for_middleware = Arc::clone(&request_log);
                origin_check_middleware(allowed_for_middleware, log_for_middleware, req, next)
            }))
    }

    /// Pins that a request whose Origin is on the allowlist reaches the
    /// handler.
    #[tokio::test]
    async fn origin_allowed_passes() -> anyhow::Result<()> {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }

    /// Pins that a request whose Origin is not on the allowlist is rejected
    /// with 403.
    #[tokio::test]
    async fn origin_rejected_returns_403() -> anyhow::Result<()> {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://evil.com")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    /// Pins that a request without an Origin header is allowed.
    #[tokio::test]
    async fn no_origin_header_passes() -> anyhow::Result<()> {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }

    /// Pins that an empty allowlist rejects any request carrying an Origin.
    #[tokio::test]
    async fn empty_allowlist_rejects_any_origin() -> anyhow::Result<()> {
        let app = origin_router(vec![], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://anything.com")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    /// Pins that an empty allowlist still allows requests without an Origin.
    #[tokio::test]
    async fn empty_allowlist_passes_without_origin() -> anyhow::Result<()> {
        let app = origin_router(vec![], false);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }

    /// Pins that request-header logging redacts sensitive credential values.
    #[test]
    fn format_request_headers_redacts_sensitive_values() -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        let _previous_authorization =
            headers.insert("authorization", "Bearer secret-token".parse()?);
        let _previous_cookie = headers.insert("cookie", "sid=abc".parse()?);
        let _previous_request_id = headers.insert("x-request-id", "req-123".parse()?);

        let out = format_request_headers_for_log(&headers);
        assert!(out.contains("authorization: [REDACTED]"));
        assert!(out.contains("cookie: [REDACTED]"));
        assert!(out.contains("x-request-id: req-123"));
        assert!(!out.contains("secret-token"));

        Ok(())
    }

    /// Pins that request-header logging redacts client-IP and proxy-topology
    /// forwarding headers.
    #[test]
    fn format_request_headers_redacts_forwarding_headers() -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        let _previous_forwarded =
            headers.insert("forwarded", "for=203.0.113.9;by=10.1.2.3".parse()?);
        let _previous_xff = headers.insert("x-forwarded-for", "203.0.113.9, 10.1.2.3".parse()?);
        let _previous_xri = headers.insert("x-real-ip", "203.0.113.9".parse()?);
        let _previous_request_id = headers.insert("x-request-id", "req-123".parse()?);

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

        Ok(())
    }

    // -- security_headers_middleware --

    fn security_router(is_tls: bool) -> axum::Router {
        security_router_with(is_tls, SecurityHeadersConfig::default())
    }

    fn security_router_with(is_tls: bool, cfg: SecurityHeadersConfig) -> axum::Router {
        use axum::{middleware::from_fn, routing::get};

        let shared_cfg = Arc::new(cfg);
        axum::Router::new()
            .route("/test", get(ok_handler))
            .layer(from_fn(move |req, next| {
                let cfg_for_middleware = Arc::clone(&shared_cfg);
                security_headers_middleware(is_tls, cfg_for_middleware, req, next)
            }))
    }

    /// Pins the full default set of security headers emitted on a plaintext
    /// response, including the absence of HSTS.
    #[tokio::test]
    async fn security_headers_set_on_response() -> anyhow::Result<()> {
        let app = security_router(false);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .context("x-content-type-options must be set")?,
            "nosniff"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .context("x-frame-options must be set")?,
            "deny"
        );
        assert_eq!(
            headers
                .get("cache-control")
                .context("cache-control must be set")?,
            "no-store, max-age=0"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .context("referrer-policy must be set")?,
            "no-referrer"
        );
        assert_eq!(
            headers
                .get("cross-origin-opener-policy")
                .context("cross-origin-opener-policy must be set")?,
            "same-origin"
        );
        assert_eq!(
            headers
                .get("cross-origin-resource-policy")
                .context("cross-origin-resource-policy must be set")?,
            "same-origin"
        );
        assert_eq!(
            headers
                .get("cross-origin-embedder-policy")
                .context("cross-origin-embedder-policy must be set")?,
            "require-corp"
        );
        assert_eq!(
            headers
                .get("x-permitted-cross-domain-policies")
                .context("x-permitted-cross-domain-policies must be set")?,
            "none"
        );
        assert!(
            headers
                .get("permissions-policy")
                .context("permissions-policy must be set")?
                .to_str()
                .context("permissions-policy must be valid ASCII")?
                .contains("camera=()"),
            "permissions-policy must restrict browser features"
        );
        assert_eq!(
            headers
                .get("content-security-policy")
                .context("content-security-policy must be set")?,
            "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        );
        assert_eq!(
            headers
                .get("x-dns-prefetch-control")
                .context("x-dns-prefetch-control must be set")?,
            "off"
        );
        // No HSTS when TLS is off.
        assert!(headers.get("strict-transport-security").is_none());

        Ok(())
    }

    /// Pins that HSTS is emitted with a two-year max-age when TLS is enabled.
    #[tokio::test]
    async fn hsts_set_when_tls_enabled() -> anyhow::Result<()> {
        let app = security_router(true);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;

        let hsts = resp
            .headers()
            .get("strict-transport-security")
            .context("strict-transport-security must be set")?;
        assert!(
            hsts.to_str()
                .context("strict-transport-security must be valid ASCII")?
                .contains("max-age=63072000"),
            "HSTS must set 2-year max-age"
        );

        Ok(())
    }

    /// Pins that the default Content-Security-Policy matches the documented
    /// guideline.
    #[tokio::test]
    async fn default_csp_matches_guideline() -> anyhow::Result<()> {
        let app = security_router(false);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(
            resp.headers()
                .get("content-security-policy")
                .context("content-security-policy must be set")?,
            "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        );

        Ok(())
    }

    /// Pins that an operator-supplied Content-Security-Policy overrides the
    /// default.
    #[tokio::test]
    async fn operator_csp_override_still_wins() -> anyhow::Result<()> {
        let cfg = SecurityHeadersConfig {
            content_security_policy: Some("default-src 'self'".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, cfg);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(
            resp.headers()
                .get("content-security-policy")
                .context("content-security-policy must be set")?,
            "default-src 'self'"
        );

        Ok(())
    }

    // -- SecurityHeadersConfig validation + override semantics --

    /// Build a minimal config with a custom `SecurityHeadersConfig` and drive
    /// it through `check()`.
    ///
    /// Returns the result so individual tests can assert on success or
    /// specific error messages.
    ///
    /// # Errors
    ///
    /// Returns a `RmcpServerKitError` when the configured security headers
    /// fail validation.
    fn check_with_security_headers(
        headers: SecurityHeadersConfig,
    ) -> Result<(), RmcpServerKitError> {
        let cfg =
            McpServerConfig::new("127.0.0.1:8080", "test", "0.0.0").with_security_headers(headers);
        cfg.check()
    }

    /// Pins that the default `SecurityHeadersConfig` passes validation.
    #[test]
    fn security_headers_config_default_validates() -> anyhow::Result<()> {
        check_with_security_headers(SecurityHeadersConfig::default())
            .context("default SecurityHeadersConfig must validate")?;

        Ok(())
    }

    /// Pins that explicitly empty string security-header values validate
    /// (omit-everything mode).
    #[test]
    fn security_headers_config_validate_accepts_empty_string() -> anyhow::Result<()> {
        // All twelve fields explicitly set to "" -> omit-everything mode.
        let headers_config = SecurityHeadersConfig {
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
        check_with_security_headers(headers_config)
            .context("Some(\"\") on every field must validate (omit-all)")?;

        Ok(())
    }

    /// Pins that a control character in a security-header value is rejected
    /// and named in the error.
    #[test]
    fn security_headers_config_validate_rejects_bad_value() -> anyhow::Result<()> {
        // 0x07 (BEL) is not a valid HTTP header value char.
        let headers_config = SecurityHeadersConfig {
            referrer_policy: Some("\u{0007}".into()),
            ..SecurityHeadersConfig::default()
        };
        let err = check_with_security_headers(headers_config)
            .err()
            .context("control char in referrer_policy must reject")?;
        let msg = err.to_string();
        assert!(
            msg.contains("referrer_policy"),
            "error must name the offending field, got: {msg}"
        );

        Ok(())
    }

    /// Pins that an HSTS value containing `preload` is rejected and the error
    /// names the field and the offending token.
    #[test]
    fn security_headers_config_validate_rejects_hsts_preload() -> anyhow::Result<()> {
        let headers_config = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=63072000; includeSubDomains; preload".into()),
            ..SecurityHeadersConfig::default()
        };
        let err = check_with_security_headers(headers_config)
            .err()
            .context("HSTS with preload must reject")?;
        let msg = err.to_string();
        assert!(
            msg.contains("strict_transport_security"),
            "error must name the field, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("preload"),
            "error must mention `preload`, got: {msg}"
        );

        Ok(())
    }

    /// Pins that the HSTS preload rejection is case-insensitive.
    #[test]
    fn security_headers_config_validate_rejects_hsts_preload_uppercase() -> anyhow::Result<()> {
        // Case-insensitive match.
        let headers_config = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=600; PRELOAD".into()),
            ..SecurityHeadersConfig::default()
        };
        let error = check_with_security_headers(headers_config)
            .err()
            .context("HSTS preload check must be case-insensitive")?;
        assert!(
            error.to_string().to_lowercase().contains("preload"),
            "uppercase PRELOAD must still be rejected, got: {error}"
        );

        Ok(())
    }

    /// Pins that an operator override of a security header replaces the
    /// default value.
    #[tokio::test]
    async fn security_headers_override_honored() -> anyhow::Result<()> {
        // Override X-Frame-Options to SAMEORIGIN.
        let headers_config = SecurityHeadersConfig {
            x_frame_options: Some("SAMEORIGIN".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, headers_config);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let xfo = resp
            .headers()
            .get("x-frame-options")
            .context("x-frame-options must be set")?;
        assert_eq!(xfo, "SAMEORIGIN");

        Ok(())
    }

    /// Pins that an empty-string override omits its header while other
    /// defaults remain set.
    #[tokio::test]
    async fn security_headers_empty_string_omits() -> anyhow::Result<()> {
        // Empty string on referrer-policy -> header absent.
        let headers_config = SecurityHeadersConfig {
            referrer_policy: Some(String::new()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, headers_config);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            resp.headers().get("referrer-policy").is_none(),
            "Some(\"\") must omit the header"
        );
        // Other defaults should still be present.
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .context("x-content-type-options must be set")?,
            "nosniff"
        );

        Ok(())
    }

    /// Pins that HSTS stays absent on plaintext deployments even when an
    /// override is configured.
    #[tokio::test]
    async fn security_headers_hsts_only_when_tls() -> anyhow::Result<()> {
        // HSTS override is irrelevant when TLS is off.
        let headers_config = SecurityHeadersConfig {
            strict_transport_security: Some("max-age=600".into()),
            ..SecurityHeadersConfig::default()
        };
        let app = security_router_with(false, headers_config);
        let req = Request::builder().uri("/test").body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert!(
            resp.headers().get("strict-transport-security").is_none(),
            "HSTS must remain absent on plaintext deployments even with override"
        );

        Ok(())
    }

    // -- oauth_token_cache_headers_middleware --

    /// Axum handler shared by the OAuth middleware tests: replies `{}`.
    #[cfg(feature = "oauth")]
    async fn json_ok_handler() -> &'static str {
        "{}"
    }

    /// Axum handler for the Vary-preservation test: replies with a pre-set
    /// `Vary: Accept-Encoding` header.
    #[cfg(feature = "oauth")]
    async fn vary_accept_encoding_handler() -> Response {
        use axum::http::HeaderValue;

        let mut response = Response::new(Body::from("{}"));
        let _previous = response
            .headers_mut()
            .insert("vary", HeaderValue::from_static("Accept-Encoding"));
        response
    }

    /// Pins that the OAuth token-cache middleware sets `Pragma: no-cache` and
    /// appends `Authorization` to `Vary`.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_token_cache_headers_set_pragma_and_vary() -> anyhow::Result<()> {
        use axum::{middleware::from_fn, routing::post};

        let app = axum::Router::new()
            .route("/token", post(json_ok_handler))
            .layer(from_fn(oauth_token_cache_headers_middleware));
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .body(Body::from("{}"))?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let headers = resp.headers();
        assert_eq!(
            headers.get("pragma").context("pragma must be set")?,
            "no-cache",
            "RFC 6749 \u{a7}5.1: token responses must set Pragma: no-cache"
        );
        let vary_values: Vec<String> = headers
            .get_all("vary")
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        assert!(
            vary_values
                .iter()
                .any(|value| value.eq_ignore_ascii_case("Authorization")),
            "RFC 6750 \u{a7}5.4: Vary must include Authorization, got {vary_values:?}"
        );

        Ok(())
    }

    /// Pins that the OAuth token-cache middleware appends `Authorization` to a
    /// pre-existing `Vary` value instead of replacing it.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_token_cache_headers_preserve_existing_vary() -> anyhow::Result<()> {
        use axum::{middleware::from_fn, routing::post};

        // Simulates a handler/layer that already set `Vary: Accept-Encoding`
        // (e.g. compression). Our middleware must APPEND, not REPLACE.
        let app = axum::Router::new()
            .route("/token", post(vary_accept_encoding_handler))
            .layer(from_fn(oauth_token_cache_headers_middleware));
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;

        let vary: Vec<String> = resp
            .headers()
            .get_all("vary")
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        assert!(
            vary.iter().any(|value| value.contains("Accept-Encoding")),
            "must preserve pre-existing Vary value, got {vary:?}"
        );
        assert!(
            vary.iter().any(|value| value.contains("Authorization")),
            "must append Authorization to Vary, got {vary:?}"
        );

        Ok(())
    }

    // -- version endpoint --

    /// Pins that the version payload hides build fingerprint fields by
    /// default.
    #[test]
    fn version_omits_build_fingerprint_by_default() -> anyhow::Result<()> {
        let version = version_payload("my-server", "1.2.3", false);
        assert_eq!(
            version.get("name").context("name must be present")?,
            "my-server"
        );
        assert_eq!(
            version.get("version").context("version must be present")?,
            "1.2.3"
        );
        assert!(
            version
                .get("rmcp_server_kit_version")
                .context("rmcp_server_kit_version must be present")?
                .is_string()
        );
        assert!(
            version.get("build_git_sha").is_none(),
            "build sha must be hidden by default"
        );
        assert!(version.get("build_timestamp").is_none());
        assert!(version.get("rust_version").is_none());

        Ok(())
    }

    /// Pins that the version payload exposes every build field when enabled.
    #[test]
    fn version_exposes_all_when_enabled() -> anyhow::Result<()> {
        let version = version_payload("my-server", "1.2.3", true);
        assert!(
            version
                .get("build_git_sha")
                .context("build_git_sha must be present")?
                .is_string()
        );
        assert!(
            version
                .get("build_timestamp")
                .context("build_timestamp must be present")?
                .is_string()
        );
        assert!(
            version
                .get("rust_version")
                .context("rust_version must be present")?
                .is_string()
        );
        assert!(
            version
                .get("rmcp_server_kit_version")
                .context("rmcp_server_kit_version must be present")?
                .is_string()
        );

        Ok(())
    }

    // -- concurrency limit layer --

    /// Error handler for the concurrency-limit test: maps load shedding to 503.
    async fn handle_service_unavailable(_err: tower::BoxError) -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }

    /// Pins that the concurrency-limit/load-shed layer stack composes and still
    /// serves a single request below the cap.
    #[tokio::test]
    async fn concurrency_limit_layer_composes_and_serves() -> anyhow::Result<()> {
        use axum::{error_handling::HandleErrorLayer, routing::get};
        use tower::{limit::ConcurrencyLimitLayer, load_shed::LoadShedLayer};

        // We only assert the layer stack compiles and a single request
        // below the cap still succeeds. True back-pressure behaviour
        // requires a live HTTP server and is covered by integration tests.
        let app = axum::Router::new().route("/ok", get(ok_handler)).layer(
            tower::ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_service_unavailable))
                .layer(LoadShedLayer::new())
                .layer(ConcurrencyLimitLayer::new(4)),
        );
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty())?)
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }

    // -- compression layer --

    /// Pins that the compression layer gzip-encodes a large response.
    #[tokio::test]
    async fn compression_layer_gzip_encodes_response() -> anyhow::Result<()> {
        use core::future::ready;

        use axum::routing::get;
        use tower_http::compression::{
            CompressionLayer, DefaultPredicate, Predicate as _, predicate::SizeAbove,
        };

        let big_body = "a".repeat(4096);
        let app = axum::Router::new()
            .route("/big", get(move || ready(big_body.clone())))
            .layer(
                CompressionLayer::new()
                    .gzip(true)
                    .br(true)
                    .compress_when(DefaultPredicate::new().and(SizeAbove::new(1024))),
            );

        let req = Request::builder()
            .uri("/big")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_ENCODING)
                .context("content-encoding must be set")?,
            "gzip"
        );

        Ok(())
    }

    /// Pins that the compression layer brotli-encodes a large response and
    /// that the encoded body is shorter than the input.
    #[tokio::test]
    async fn compression_layer_br_encodes_response() -> anyhow::Result<()> {
        use core::future::ready;

        use axum::{body::to_bytes, routing::get};
        use tower_http::compression::{
            CompressionLayer, DefaultPredicate, Predicate as _, predicate::SizeAbove,
        };

        let big_body = "a".repeat(4096);
        let app = axum::Router::new()
            .route("/big", get(move || ready(big_body.clone())))
            .layer(
                CompressionLayer::new()
                    .gzip(true)
                    .br(true)
                    .compress_when(DefaultPredicate::new().and(SizeAbove::new(1024))),
            );

        let req = Request::builder()
            .uri("/big")
            .header(header::ACCEPT_ENCODING, "br")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_ENCODING)
                .context("content-encoding must be set")?,
            "br"
        );

        // Reading the body is what drives the encoder - a header-only
        // assertion passes without any brotli code running, so the payload
        // must actually be shorter than the 4096-byte input.
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .context("body must be readable")?;
        assert!(
            !body.is_empty() && body.len() < 4096,
            "br-encoded body should be smaller than the 4096-byte payload, got {} bytes",
            body.len()
        );

        Ok(())
    }

    // -- TlsListener handshake timeout --

    /// Pins that the TLS listener reaps connections that never complete their
    /// handshake.
    #[tokio::test]
    async fn tls_handshake_timeout_reaps_idle_connections() -> anyhow::Result<()> {
        use std::{
            env::temp_dir,
            time::{SystemTime, UNIX_EPOCH},
        };

        use rustls::crypto::ring::default_provider;
        use tokio::{
            fs::{create_dir_all, write},
            io::AsyncReadExt as _,
            time::timeout,
        };

        let _previous_provider = default_provider().install_default();

        // Self-signed cert material on disk (TlsListener::new takes paths).
        let key = rcgen::KeyPair::generate().context("generate key")?;
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .context("cert params")?
            .self_signed(&key)
            .context("self-signed cert")?;
        let dir = temp_dir().join(format!(
            "rmcp-server-kit-hs-timeout-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("clock after epoch")?
                .as_nanos()
        ));
        create_dir_all(&dir).await.context("temp dir")?;
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        write(&cert_path, cert.pem()).await.context("write cert")?;
        write(&key_path, key.serialize_pem())
            .await
            .context("write key")?;

        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let tls = TlsListener::new(
            listener,
            &cert_path,
            &key_path,
            None,
            None,
            Duration::from_millis(200),
            8, // custom concurrency cap: proves the plumbing end-to-end
        )
        .context("tls listener")?;
        let addr = Listener::local_addr(&tls).context("local addr")?;

        // Connect and send NOTHING: the handshake worker must time out
        // after 200ms and drop the stream, which the client observes as
        // EOF or a reset well within the 2s deadline.
        let mut idle = TcpStream::connect(addr).await.context("connect")?;
        let mut buf = [0_u8; 16];
        let read = timeout(Duration::from_secs(2), idle.read(&mut buf))
            .await
            .context("server must reap the idle handshake within its timeout")?;
        match read {
            Ok(0) | Err(_) => {} // EOF or reset: connection was dropped.
            Ok(n) => anyhow::bail!("unexpected {n} bytes from server during reaped handshake"),
        }

        drop(tls);

        Ok(())
    }

    // -- TLS session resumption disabled for mTLS (WO-T1) --

    use core::sync::atomic::AtomicUsize;

    use rustls::{
        CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
        client::{Resumption, danger::HandshakeSignatureValid},
        pki_types::{ServerName, UnixTime},
        server::danger::ClientCertVerified,
    };
    use tokio_rustls::client::TlsStream as ClientTlsStream;

    /// Generates a self-signed certificate and matching PKCS#8 key for the
    /// non-mTLS TLS-config tests.
    ///
    /// # Errors
    ///
    /// Returns an error when key generation or certificate self-signing fails.
    fn self_signed_test_material()
    -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let key = rcgen::KeyPair::generate().context("generate key")?;
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .context("cert params")?
            .self_signed(&key)
            .context("self-signed cert")?;
        Ok((
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        ))
    }

    /// Pins that an mTLS server config disables session resumption entirely.
    #[test]
    fn build_tls_server_config_disables_resumption_for_mtls() -> anyhow::Result<()> {
        use rustls::server::WebPkiClientVerifier;

        let (certs, key) = self_signed_test_material()?;
        let mut roots = RootCertStore::empty();
        roots
            .add(
                certs
                    .first()
                    .context("self-signed cert must be present")?
                    .clone(),
            )
            .context("add root")?;
        let verifier: Arc<dyn ClientCertVerifier> = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .context("client verifier")?;

        let cfg = build_tls_server_config_from_verifier(certs, key, verifier, true)
            .context("build tls config")?;

        assert!(
            !cfg.session_storage.can_cache(),
            "mTLS must not offer resumable sessions"
        );
        assert!(
            !cfg.session_storage.put(vec![1], vec![2]),
            "mTLS session store must reject writes"
        );
        assert!(
            cfg.session_storage.take(&[1]).is_none(),
            "mTLS session store must never yield a session"
        );
        assert_eq!(
            cfg.send_tls13_tickets, 0,
            "mTLS must not emit TLS 1.3 session tickets"
        );

        Ok(())
    }

    /// Pins that a non-mTLS server config keeps session resumption enabled.
    #[test]
    fn build_tls_server_config_keeps_resumption_for_non_mtls() -> anyhow::Result<()> {
        let (certs, key) = self_signed_test_material()?;
        let cfg = build_tls_server_config(certs, key, None, None).context("build tls config")?;
        assert!(
            cfg.session_storage.can_cache(),
            "non-mTLS listeners intentionally keep resumption enabled (deliberate scope decision)"
        );

        Ok(())
    }

    struct ResumptionTestMaterial {
        server_certs: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_certs: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
        roots: Arc<RootCertStore>,
    }

    /// A small CA-backed PKI for the resumption regression test below.
    ///
    /// Deliberately independent of `tests/integration/e2e.rs::crl_tests` (a
    /// separate test binary that cannot see this module's private helpers).
    ///
    /// # Errors
    ///
    /// Returns an error when generating or signing any fixture key or
    /// certificate fails.
    fn build_resumption_test_material() -> anyhow::Result<ResumptionTestMaterial> {
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "resumption-test-ca");
        let ca_key = rcgen::KeyPair::generate().context("ca key")?;
        let ca =
            rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).context("ca self-signed")?;

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).context("add ca root")?;

        let server_key = rcgen::KeyPair::generate().context("server key")?;
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).context("server params")?;
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        server_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_params.use_authority_key_identifier_extension = true;
        let server_cert = server_params
            .signed_by(&server_key, &ca)
            .context("server cert")?;

        let client_key = rcgen::KeyPair::generate().context("client key")?;
        let mut client_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).context("client params")?;
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "resumption-test-client");
        client_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        client_params.use_authority_key_identifier_extension = true;
        let client_cert = client_params
            .signed_by(&client_key, &ca)
            .context("client cert")?;

        Ok(ResumptionTestMaterial {
            server_certs: vec![server_cert.der().clone()],
            server_key: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            client_certs: vec![client_cert.der().clone()],
            client_key: PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
            roots: Arc::new(roots),
        })
    }

    /// Counts `verify_client_cert` calls and can be flipped to reject every
    /// subsequent verification, proving whether rustls actually invoked
    /// verification for a given handshake (full) or bypassed it (resumed).
    struct FlipVerifier {
        inner: Arc<dyn ClientCertVerifier>,
        calls: AtomicUsize,
        reject_after_first: AtomicBool,
    }

    impl FlipVerifier {
        fn new(inner: Arc<dyn ClientCertVerifier>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                calls: AtomicUsize::new(0),
                reject_after_first: AtomicBool::new(false),
            })
        }
    }

    impl Debug for FlipVerifier {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            f.debug_struct("FlipVerifier")
                .field("calls", &self.calls)
                .field("reject_after_first", &self.reject_after_first)
                .finish_non_exhaustive()
        }
    }

    impl ClientCertVerifier for FlipVerifier {
        fn offer_client_auth(&self) -> bool {
            self.inner.offer_client_auth()
        }

        fn client_auth_mandatory(&self) -> bool {
            self.inner.client_auth_mandatory()
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            self.inner.root_hint_subjects()
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            let _previous_calls = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.reject_after_first.load(Ordering::SeqCst) {
                return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
            }
            self.inner
                .verify_client_cert(end_entity, intermediates, now)
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }

        fn requires_raw_public_keys(&self) -> bool {
            self.inner.requires_raw_public_keys()
        }
    }

    /// Accepts one TLS connection and serves a minimal HTTP response.
    ///
    /// Reads the request to the blank line (or EOF) with a timeout, writes a
    /// minimal HTTP response, then shuts down cleanly. Pairs with
    /// `connect_and_drive`'s EOF read so TLS 1.3 post-handshake
    /// `NewSessionTicket` messages are actually delivered.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when accepting, reading, writing, flushing, or
    /// shutting down the connection fails.
    async fn accept_and_serve(
        listener: &TcpListener,
        acceptor: &tokio_rustls::TlsAcceptor,
    ) -> io::Result<()> {
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            time::timeout,
        };

        let (tcp, _addr) = listener.accept().await?;
        let mut tls = timeout(Duration::from_secs(5), acceptor.accept(tcp))
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("server: TLS accept timed out: {error}"),
                )
            })??;

        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            let n = timeout(Duration::from_secs(5), tls.read(&mut byte))
                .await
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("server: read timed out: {error}"),
                    )
                })??;
            if n == 0 {
                break;
            }
            let [received] = byte;
            request.push(received);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        tls.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        tls.flush().await?;
        tls.shutdown().await?;
        Ok(())
    }

    /// Connects to the server, sends a minimal HTTP request, and reads the
    /// response to EOF.
    ///
    /// The EOF read is required so the client's rustls state machine actually
    /// processes any post-handshake `NewSessionTicket` messages before the
    /// stream is dropped. Returns the live stream so the caller can inspect
    /// `handshake_kind()` afterward.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when connecting, writing, or reading fails.
    async fn connect_and_drive(
        connector: &tokio_rustls::TlsConnector,
        addr: SocketAddr,
        server_name: ServerName<'static>,
    ) -> io::Result<ClientTlsStream<TcpStream>> {
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            time::timeout,
        };

        let tcp = TcpStream::connect(addr).await?;
        let mut tls = connector.connect(server_name, tcp).await?;

        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        tls.flush().await?;

        let mut response = Vec::new();
        let _bytes_read = timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("client: read timed out: {error}"),
                )
            })??;

        Ok(tls)
    }

    /// Outcome of driving two sequential connections against one
    /// `FlipVerifier`-backed server.
    struct ScenarioOutcome {
        calls_after_first: usize,
        second_client_result: io::Result<()>,
        second_handshake_kind: Option<rustls::HandshakeKind>,
        calls_after_second: usize,
    }

    /// Stands up a fresh mTLS-verifying TLS server and matching client and
    /// drives two sequential connections against it.
    ///
    /// `disable_resumption` controls the exact fix under test. The first
    /// connection completes a full handshake; the verifier is then flipped to
    /// reject everything and a second connection is driven. The outcome
    /// reports whether the second connection resumed or re-verified.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixture PKI, TLS config, listener, or client
    /// setup fails.
    async fn run_resumption_scenario(disable_resumption: bool) -> anyhow::Result<ScenarioOutcome> {
        use rustls::server::WebPkiClientVerifier;

        let material = build_resumption_test_material()?;

        let base_verifier: Arc<dyn ClientCertVerifier> =
            WebPkiClientVerifier::builder(Arc::clone(&material.roots))
                .build()
                .context("client verifier")?;
        let flip = FlipVerifier::new(base_verifier);
        let flip_for_config: Arc<FlipVerifier> = Arc::clone(&flip);
        let verifier_handle: Arc<dyn ClientCertVerifier> = flip_for_config;

        let tls_config = build_tls_server_config_from_verifier(
            material.server_certs,
            material.server_key,
            verifier_handle,
            disable_resumption,
        )
        .context("server tls config")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let addr = listener.local_addr().context("local addr")?;

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::clone(&material.roots))
            .with_client_auth_cert(material.client_certs, material.client_key)
            .context("client config")?;
        // `rustls::client::handy::ClientSessionMemoryCache` divides its
        // requested `size` by `MAX_TLS13_TICKETS_PER_SERVER` (8) to get a
        // server-name-slot count. A `size` of 8 or less rounds down to
        // exactly one slot, whose backing `VecDeque` has capacity 1 --
        // its own eviction guard (`capacity() == len()`) then fires on the
        // very first insert and evicts the entry that insert just made,
        // so no ticket ever survives to the next connection. 256 mirrors
        // the crate's own server-side default
        // (`ServerSessionMemoryCache::new(256)`), well clear of that
        // one-slot edge for this test's single server name.
        client_config.resumption = Resumption::in_memory_sessions(256);
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let server_name = ServerName::try_from("localhost").context("server name")?;

        let (server_result_1, client_result_1) = tokio::join!(
            accept_and_serve(&listener, &acceptor),
            connect_and_drive(&connector, addr, server_name.clone()),
        );
        server_result_1.context("connection 1: server side must complete")?;
        let _client_stream_1 =
            client_result_1.context("connection 1: full handshake must succeed")?;

        let calls_after_first = flip.calls.load(Ordering::SeqCst);
        flip.reject_after_first.store(true, Ordering::SeqCst);

        let (_server_result_2, client_result_2) = tokio::join!(
            accept_and_serve(&listener, &acceptor),
            connect_and_drive(&connector, addr, server_name),
        );

        let (second_client_result, second_handshake_kind) = match client_result_2 {
            Ok(stream) => (Ok(()), stream.get_ref().1.handshake_kind()),
            Err(error) => (Err(error), None),
        };

        Ok(ScenarioOutcome {
            calls_after_first,
            second_client_result,
            second_handshake_kind,
            calls_after_second: flip.calls.load(Ordering::SeqCst),
        })
    }

    /// Regression test for the mTLS session-resumption bypass: rustls
    /// restores `peer_certificates` from cached session state on resumed
    /// handshakes without calling `ClientCertVerifier::verify_client_cert`,
    /// so a de-authorized principal (revoked or expired certificate) could
    /// keep authenticating past both checks for as long as it held a live
    /// session. `disable_resumption` (wired to mTLS listeners via
    /// `mtls_config.is_some()` in `build_tls_server_config`) closes this.
    ///
    /// The `control` half proves the harness can produce a genuine resumed
    /// handshake at all; without it, an unrelated harness bug that always
    /// forces full handshakes would make the `fixed` assertions pass for
    /// the wrong reason.
    #[tokio::test]
    async fn mtls_resumption_disabled_forces_full_reverification() -> anyhow::Result<()> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let fixed = run_resumption_scenario(true).await?;
        assert_eq!(
            fixed.calls_after_first, 1,
            "connection 1 must invoke the verifier exactly once"
        );
        assert!(
            fixed.second_client_result.is_err(),
            "connection 2 must fail once the verifier rejects everything, proving no \
             cached identity was reused"
        );
        assert_ne!(
            fixed.second_handshake_kind,
            Some(rustls::HandshakeKind::Resumed),
            "connection 2 must not be a resumed handshake when resumption is disabled"
        );
        assert_eq!(
            fixed.calls_after_second, 2,
            "connection 2 must re-invoke the verifier -- this is the fix"
        );

        let control = run_resumption_scenario(false).await?;
        assert_eq!(control.calls_after_first, 1);
        assert!(
            control.second_client_result.is_ok(),
            "control connection 2 must succeed via resumption; if it does not, the \
             `fixed` assertions above prove nothing because the client never even \
             attempted resumption"
        );
        assert_eq!(
            control.second_handshake_kind,
            Some(rustls::HandshakeKind::Resumed),
            "control connection 2 must be a genuine resumed handshake"
        );
        assert_eq!(
            control.calls_after_second, 1,
            "control verifier must NOT be re-invoked -- this is the exact bypass the fix eliminates"
        );

        Ok(())
    }

    // -- M5: OWASP security headers reach early / fallback responses --

    fn assert_owasp_headers(resp: &Response, ctx: &str) {
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
            .method(Method::OPTIONS)
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
    fn m6_auth_state(fields: LogContextConfig) -> (Arc<AuthState>, String, String) {
        let (admin_token, admin_hash) = crate::auth::generate_api_key().unwrap();
        let (viewer_token, viewer_hash) = crate::auth::generate_api_key().unwrap();
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::from_pointee(vec![
                ApiKeyEntry::new("admin-key", admin_hash, "admin"),
                ApiKeyEntry::new("viewer-key", viewer_hash, "viewer"),
            ]),
            rate_limiter: None,
            pre_auth_limiter: None,
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext {
                fields,
                fingerprint_salt: None,
            },
        });
        (state, admin_token, viewer_token)
    }

    #[cfg(feature = "oauth")]
    fn m6_admin_router(state: &Arc<AuthState>) -> axum::Router {
        let proxy = OAuthProxyConfig::builder(
            "https://idp.example/authorize",
            "https://idp.example/token",
            "client",
        )
        .introspection_url("http://127.0.0.1:1/introspect")
        .revocation_url("http://127.0.0.1:1/revoke")
        .expose_admin_endpoints(true)
        .require_auth_on_admin_endpoints(true)
        .build();
        let http = OauthHttpClient::new().expect("oauth http client");
        build_oauth_admin_router(&proxy, http, Some(state), "admin").expect("admin router")
    }

    #[cfg(feature = "oauth")]
    fn m6_req(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from("token=abc"))
            .unwrap()
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_admin_auth_failure_carries_client_context() {
        let (state, _admin, _viewer) = m6_auth_state(LogContextConfig::recommended());
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let app = m6_admin_router(&state);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/introspect")
            .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let line = logs
            .lines_containing("auth failed")
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing auth failed log: {}", logs.contents()));
        assert!(line.contains("client_ip=127.0.0.1"), "{line}");
        assert!(line.contains("peer_ip=127.0.0.1"), "{line}");
        assert!(line.contains("method=POST"), "{line}");
        assert!(line.contains("path=/introspect"), "{line}");
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_proxy_admin_requires_admin_role() {
        let (state, _admin, viewer) = m6_auth_state(LogContextConfig::default());
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
        let (state, admin, _viewer) = m6_auth_state(LogContextConfig::default());
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
            let mut seen = HashSet::new();
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
            let mut seen = HashSet::new();
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
            let mut seen = HashSet::new();
            for verb in ["FROBNICATE", "WIBBLE", "QUUX", "M-SEARCH"] {
                let (method, _) = labels_for(verb, "/healthz");
                seen.insert(method);
            }
            assert_eq!(seen, HashSet::from(["OTHER"]));
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

    /// Origin matching semantics: normalized tuple equality on both the request
    /// and config sides, the `null` opt-in, and fail-closed parsing.
    mod origin_semantics {
        use super::*;

        fn allowed(entries: &[&str]) -> Vec<AllowedOrigin> {
            entries
                .iter()
                .map(|entry| parse_allowed_origin(entry).expect("valid test entry"))
                .collect()
        }

        #[test]
        fn request_parse_normalizes_scheme_host_and_ports() {
            assert_eq!(
                parse_request_origin_tuple("https://example.com"),
                Some(("https".to_owned(), "example.com".to_owned(), 443))
            );
            assert_eq!(
                parse_request_origin_tuple("HTTPS://EXAMPLE.COM"),
                Some(("https".to_owned(), "example.com".to_owned(), 443))
            );
            assert_eq!(
                parse_request_origin_tuple("http://example.com"),
                Some(("http".to_owned(), "example.com".to_owned(), 80))
            );
            assert_eq!(
                parse_request_origin_tuple("https://example.com:444"),
                Some(("https".to_owned(), "example.com".to_owned(), 444))
            );
            assert_eq!(
                parse_request_origin_tuple("https://example.com:443"),
                parse_request_origin_tuple("https://example.com"),
                "explicit default port must equal the implicit form"
            );
        }

        #[test]
        fn request_parse_rejects_paths_queries_fragments_and_odd_schemes() {
            for value in [
                "https://example.com/",
                "https://example.com/path",
                "https://example.com?x=1",
                "https://example.com#frag",
                "ws://example.com",
                "https://",
                "https://:443",
                "",
            ] {
                assert_eq!(
                    parse_request_origin_tuple(value),
                    None,
                    "{value:?} must be rejected"
                );
            }
        }

        #[test]
        fn config_parse_tolerates_one_root_trailing_slash_only() {
            assert_eq!(
                parse_config_origin_tuple("https://example.com/"),
                parse_config_origin_tuple("https://example.com")
            );
            assert_eq!(
                parse_config_origin_tuple("https://example.com:443"),
                parse_config_origin_tuple("https://example.com")
            );
            for value in [
                "https://example.com//",
                "https://example.com/path/",
                "https://example.com?x=1",
                "https://example.com#frag",
                "ws://example.com",
            ] {
                assert_eq!(
                    parse_config_origin_tuple(value),
                    None,
                    "{value:?} must be rejected"
                );
            }
        }

        #[test]
        fn matching_uses_normalized_equality_not_raw_strings() {
            let set = allowed(&["HTTPS://Example.COM:443/"]);
            assert!(request_origin_allowed("https://example.com", &set));
            assert!(request_origin_allowed("https://EXAMPLE.com:443", &set));
            assert!(
                !request_origin_allowed("https://example.com:444", &set),
                "non-default ports must match exactly; there is no wildcard"
            );
        }

        #[test]
        fn null_is_opt_in() {
            let without = allowed(&["https://example.com"]);
            assert!(!request_origin_allowed("null", &without));
            assert!(!request_origin_allowed("NULL", &without));

            let with = allowed(&["null"]);
            assert!(request_origin_allowed("null", &with));
            assert!(request_origin_allowed("NULL", &with));
            assert!(!request_origin_allowed("https://example.com", &with));
        }

        #[test]
        fn malformed_or_non_matching_origins_fail_closed() {
            let set = allowed(&["https://example.com"]);
            for value in [
                "",
                "garbage",
                "https://example.com/",
                "https://example.com:0",
                "https://evil.example",
            ] {
                assert!(
                    !request_origin_allowed(value, &set),
                    "{value:?} must not match"
                );
            }
        }

        #[test]
        fn non_canonical_port_spellings_are_rejected() {
            // `str::parse::<u16>` alone accepts `+443` and ` 443`, and
            // normalizes `0443`; none of those is a canonical origin port.
            for value in [
                "https://example.com:+443",
                "https://example.com:0443",
                "https://example.com: 443",
                "https://example.com:-443",
                "https://example.com:44 3",
                "https://example.com:65536",
            ] {
                assert_eq!(
                    parse_request_origin_tuple(value),
                    None,
                    "{value:?} must be rejected"
                );
                assert_eq!(
                    parse_config_origin_tuple(value),
                    None,
                    "{value:?} must be rejected in config too"
                );
            }
        }

        #[tokio::test]
        async fn duplicate_origin_headers_are_rejected() {
            // `Origin` is a single-value field; a request carrying two is
            // malformed and must fail closed regardless of which value matches.
            for values in [
                ["https://example.com", "https://example.com"],
                ["https://example.com", "https://evil.example"],
            ] {
                let app = origin_router(vec!["https://example.com".into()], false);
                let req = Request::builder()
                    .uri("/test")
                    .header(header::ORIGIN, values[0])
                    .header(header::ORIGIN, values[1])
                    .body(Body::empty())
                    .unwrap();
                let resp = app.oneshot(req).await.unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::FORBIDDEN,
                    "duplicated Origin headers must fail closed: {values:?}"
                );
            }
        }
    }

    /// Evict-then-register semantics for the framework's reserved metrics
    /// namespace.
    #[cfg(feature = "metrics")]
    mod framework_metrics_guard {
        use prometheus::{IntCounterVec, opts};

        use super::*;

        /// A descriptor-equivalent replacement: same name, help, and variable
        /// labels, but its own storage.
        fn identical_squatter() -> IntCounterVec {
            IntCounterVec::new(
                opts!("rmcp_server_kit_http_requests_total", "Total HTTP requests"),
                &["method", "path", "status"],
            )
            .expect("counter builds")
        }

        #[test]
        fn identical_squatter_is_evicted_and_the_real_collector_rebound() {
            let metrics = McpMetrics::new().expect("metrics build");
            // Drop the real collector, then let a same-shape squatter take the
            // name - the state the guard exists to repair.
            metrics
                .registry
                .unregister(Box::new(metrics.http_requests_total.clone()))
                .expect("real collector was registered");
            metrics
                .registry
                .register(Box::new(identical_squatter()))
                .expect("squatter registers under the freed name");

            ensure_framework_metrics_registered(&metrics).expect("guard repairs the registry");

            // The authoritative binding is restored: incrementing the real
            // collector now reaches the served registry (with a surviving
            // squatter and no rebind, this sample would be absent - silent
            // telemetry loss).
            metrics
                .http_requests_total
                .with_label_values(&["GET", "/healthz", "200"])
                .inc();
            let gathered = metrics.registry.gather();
            let family = gathered
                .iter()
                .find(|family| family.name() == "rmcp_server_kit_http_requests_total")
                .expect("framework family is served");
            assert_eq!(
                family.get_metric().len(),
                1,
                "the real collector's sample must be served exactly once"
            );
        }

        #[test]
        fn idempotent_on_a_healthy_registry() {
            let metrics = McpMetrics::new().expect("metrics build");
            ensure_framework_metrics_registered(&metrics).expect("first call is a no-op");
            ensure_framework_metrics_registered(&metrics).expect("second call is a no-op");

            metrics
                .http_requests_total
                .with_label_values(&["GET", "/healthz", "200"])
                .inc();
            let gathered = metrics.registry.gather();
            let samples: usize = gathered
                .iter()
                .filter(|family| family.name() == "rmcp_server_kit_http_requests_total")
                .map(|family| family.get_metric().len())
                .sum();
            assert_eq!(
                samples, 1,
                "re-running the guard must not duplicate families"
            );
        }

        #[test]
        fn divergent_help_cannot_be_registered_under_a_reserved_name() {
            let metrics = McpMetrics::new().expect("metrics build");
            metrics
                .registry
                .unregister(Box::new(metrics.http_requests_total.clone()))
                .expect("real collector was registered");

            // Same name, different help => different dim hash. The registry's
            // dim-hash map survives `unregister`, so the reserved namespace is
            // protected at the earliest point: the squatter cannot even land.
            let squatter = IntCounterVec::new(
                opts!("rmcp_server_kit_http_requests_total", "different help"),
                &["method", "path", "status"],
            )
            .expect("counter builds");
            let error = metrics
                .registry
                .register(Box::new(squatter))
                .expect_err("divergent-help squatter must be rejected");
            let rendered = format!("{error}");
            assert!(
                rendered.contains("rmcp_server_kit_http_requests_total")
                    && rendered.contains("different"),
                "rejection must name the conflicting family: {rendered}"
            );

            // The guard then re-establishes the authoritative binding.
            ensure_framework_metrics_registered(&metrics)
                .expect("guard restores the real collector");
        }

        #[test]
        fn added_const_label_name_cannot_be_registered_under_a_reserved_name() {
            let metrics = McpMetrics::new().expect("metrics build");
            metrics
                .registry
                .unregister(Box::new(metrics.rate_limited_total.clone()))
                .expect("real collector was registered");

            let squatter = IntCounterVec::new(
                prometheus::Opts::new(
                    "rmcp_server_kit_rate_limited_total",
                    "Rate-limiter denials by limiter",
                )
                .const_label("squatter", "yes"),
                &["limiter"],
            )
            .expect("counter builds");
            metrics
                .registry
                .register(Box::new(squatter))
                .expect_err("const-label-divergent squatter must be rejected");

            ensure_framework_metrics_registered(&metrics)
                .expect("guard restores the real collector");
        }
    }
}
