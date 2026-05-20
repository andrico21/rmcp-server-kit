#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "test-only relaxations; production code uses ? and tracing"
    )
)]

//! `rmcp-server-kit` — production-grade reusable framework for building
//! [Model Context Protocol](https://modelcontextprotocol.io/) servers in Rust.
//!
//! Application crates depend on `rmcp-server-kit` and supply their own
//! [`rmcp::handler::server::ServerHandler`] implementation; the kit provides
//! transport, security, and observability around it.
//!
//! # What you get
//!
//! - **Streamable HTTP transport** with TLS / mTLS termination, configurable
//!   keep-alive and session idle timeouts, CORS, compression, body-size and
//!   concurrency caps, and graceful shutdown on `SIGINT`/`SIGTERM`.
//! - **Authentication**: API keys (Argon2-hashed, constant-time compared),
//!   mTLS client certificates with optional CDP-driven CRL revocation, and —
//!   under the `oauth` feature — OAuth 2.1 Bearer JWT validation against a
//!   cached JWKS endpoint.
//! - **RBAC** with per-tool argument allow-lists and per-IP per-tool rate
//!   limiting; policies and API keys are hot-reloadable at runtime via
//!   [`transport::ReloadHandle`] (lock-free [`arc_swap`] swaps).
//! - **Observability**: `tracing` with JSON or pretty formats, optional audit
//!   file sink, `/healthz` + `/readyz` probes, `/version`, `/admin/*`
//!   diagnostics, and — under the `metrics` feature — a Prometheus
//!   `/metrics` endpoint on a separate listener.
//! - **OWASP-grade defaults**: HSTS, CSP, `X-Frame-Options`, MCP `Origin`
//!   validation, and per-hop SSRF guards on outbound HTTP.
//!
//! # Quick start
//!
//! ```no_run
//! use rmcp::{
//!     handler::server::ServerHandler,
//!     model::{ServerCapabilities, ServerInfo},
//! };
//! use rmcp_server_kit::transport::{McpServerConfig, serve};
//!
//! #[derive(Clone)]
//! struct MyHandler;
//!
//! impl ServerHandler for MyHandler {
//!     fn get_info(&self) -> ServerInfo {
//!         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> rmcp_server_kit::Result<()> {
//!     let _ = rmcp_server_kit::observability::init_tracing("info");
//!
//!     let config = McpServerConfig::new(
//!         "127.0.0.1:8080",
//!         "my-mcp-server",
//!         env!("CARGO_PKG_VERSION"),
//!     );
//!
//!     serve(config.validate()?, || MyHandler).await
//! }
//! ```
//!
//! See [`examples/`](https://github.com/andrico21/rmcp-server-kit/tree/main/examples)
//! for richer setups (API-key + RBAC, OAuth resource server) and
//! [`docs/GUIDE.md`](https://github.com/andrico21/rmcp-server-kit/blob/main/docs/GUIDE.md)
//! for the full TOML configuration reference.
//!
//! # Cargo features
//!
//! All features are **off by default**:
//!
//! - `oauth` — OAuth 2.1 Bearer JWT validation, JWKS cache, and optional
//!   OAuth proxy endpoints. Pulls in [`jsonwebtoken`] and [`urlencoding`].
//!   Required to use the [`oauth`] module.
//! - `oauth-mtls-client` — RFC 8705 §2 mTLS client authentication for the
//!   OAuth token-exchange endpoint. Implies `oauth`. Without this feature,
//!   [`oauth::OAuthConfig::validate`] rejects any configuration that sets
//!   [`oauth::TokenExchangeConfig::client_cert`].
//! - `metrics` — Prometheus registry and `/metrics` listener. Pulls in
//!   the [`prometheus`] crate. Required to use the [`metrics`] module.
//! - `test-helpers` — exposes test-only helpers from [`bounded_limiter`] and
//!   [`mtls_revocation`] for downstream integration tests. **Not part of the
//!   stable API surface** — no semver guarantees across minor releases.
//!
//! # ⚠️ stdio transport is unauthenticated
//!
//! [`transport::serve_stdio`] runs MCP over the process's stdin/stdout for
//! local subprocess scenarios (desktop clients, IDE integrations). It
//! **bypasses authentication, RBAC, TLS, Origin validation, and rate
//! limiting** — the surrounding OS process boundary is the only trust
//! boundary. Never expose `serve_stdio` to untrusted callers; for any
//! network-reachable deployment use [`transport::serve`] over HTTPS instead.

/// Reusable server and observability configuration primitives.
pub mod config;
/// Generic error type and `Result` alias for server-side code.
pub mod error;
/// Tracing / JSON logs / audit file initialization.
pub mod observability;
/// Streamable HTTP transport and server entry points.
pub mod transport;

/// Authentication state (API keys, mTLS, OAuth JWT) and middleware.
pub mod auth;
/// Role-based access control policy engine and middleware.
pub mod rbac;

/// Memory-bounded keyed rate limiter (LRU + idle eviction).
pub mod bounded_limiter;

/// Cancellation primitives that detach in-flight async work on
/// cancel/timeout instead of dropping it mid-`.await`.
pub mod cancel;

/// Admin diagnostic endpoints (status, auth keys metadata, counters, RBAC).
pub mod admin;

/// Re-exports for the [`secrecy`] crate's secret-wrapper types.
pub mod secret;

pub(crate) mod ssrf;
pub(crate) mod ssrf_resolver;

/// Opt-in tool-call hooks (before/after) and result-size cap.
pub mod tool_hooks;

#[cfg(feature = "oauth")]
/// OAuth 2.1 JWKS cache, token validation, and token exchange helpers.
pub mod oauth;

#[cfg(feature = "metrics")]
/// Prometheus metrics registry shared across server components.
pub mod metrics;

/// CDP-driven CRL revocation support for mTLS.
pub mod mtls_revocation;

// Re-export the canonical error types at the crate root for ergonomic
// `rmcp_server_kit::Result<()>` / `rmcp_server_kit::McpxError` usage in downstream crates.
pub use crate::error::{McpxError, Result};
