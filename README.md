# rmcp-server-kit

[![Crates.io](https://img.shields.io/crates/v/rmcp-server-kit.svg)](https://crates.io/crates/rmcp-server-kit)
[![Docs.rs](https://docs.rs/rmcp-server-kit/badge.svg)](https://docs.rs/rmcp-server-kit)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**rmcp-server-kit** is a production-grade, reusable framework for building
[Model Context Protocol](https://modelcontextprotocol.io/) servers in Rust.
It provides a Streamable HTTP transport with TLS/mTLS, structured
observability, authentication (Bearer / mTLS / OAuth 2.1 JWT), role-based
access control (RBAC), per-IP rate limiting, and optional Prometheus
metrics -- all wired up and ready to go.

You supply a `rmcp::handler::server::ServerHandler` implementation; rmcp-server-kit
handles everything else.

## Quick Start

```toml
[dependencies]
rmcp-server-kit = "3"
rmcp = { version = "3", features = ["server", "macros"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

> The minimal example below uses default features only. Enable the
> `oauth` feature (`features = ["oauth"]`) to validate JWTs against a
> JWKS, or `metrics` for the Prometheus `/metrics` endpoint -- see the
> [Cargo features](#cargo-features) table below.

```rust
use rmcp_server_kit::{
    config::ObservabilityConfig,
    observability::init_tracing_from_config_strict,
    transport::{McpServerConfig, serve},
};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerInfo};

#[derive(Clone)]
struct MyHandler;

impl ServerHandler for MyHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main]
async fn main() -> rmcp_server_kit::Result<()> {
    let mut observability = ObservabilityConfig::default();
    observability.log_level = "info,my_server=debug".into();
    let _tracing_guard = init_tracing_from_config_strict(&observability)?;

    let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
        .with_request_timeout(std::time::Duration::from_secs(30))
        .enable_request_header_logging();
    serve(config.validate()?, || MyHandler).await
}
```

Full API documentation and worked examples live in
[docs/GUIDE.md](docs/GUIDE.md). For loading configuration from a TOML file and
bridging it into `McpServerConfig` via `ServerConfig::apply_to_mcp_config`, see
the [TOML configuration reference](docs/GUIDE.md#complete-toml-configuration-reference).
Runnable end-to-end examples ship in the repository:

```bash
cargo run --example minimal_server
cargo run --example api_key_rbac
cargo run --example config_file_server
cargo run --example oauth_server --features oauth
```

### Common configurations

**API key + RBAC + per-tool argument allowlist:**

```rust,ignore
use rmcp_server_kit::auth::{ApiKeyEntry, AuthConfig, generate_api_key};
use rmcp_server_kit::rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig};
use std::sync::Arc;

let (token, hash) = generate_api_key()?;
let auth = AuthConfig::with_keys(vec![
    ApiKeyEntry::new("viewer-key", hash, "viewer"),
]);
let viewer = RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()])
    .with_argument_allowlists(vec![ArgumentAllowlist::new_required(
        "echo", "message", vec!["hello".into(), "ping".into()],
    )]);
let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![viewer])));
```

> Use `ArgumentAllowlist::new_required` (as above), not `new`, unless omitting
> the argument is genuinely safe. `required` defaults to `false` -- permanently
> -- so an allowlist built with `new` constrains the value only when the caller
> supplies it, and a tool that substitutes its own default for a missing
> argument bypasses the allowlist entirely. See the
> [argument allowlist guide](docs/GUIDE.md#argumentallowlist).

**OAuth 2.1 resource server (JWT validation against JWKS):**

```rust,ignore
use rmcp_server_kit::auth::AuthConfig;
use rmcp_server_kit::oauth::OAuthConfig;

let oauth = OAuthConfig::builder(
    "https://auth.example.com/",
    "my-mcp-server",
    "https://auth.example.com/.well-known/jwks.json",
)
.scope("mcp:admin", "admin")
.scope("mcp:read", "viewer")
.build();

let mut auth = AuthConfig::with_keys(vec![]);
auth.oauth = Some(oauth);
```

> The OAuth fetcher and the shared `OauthHttpClient` enforce a strict
> per-hop SSRF guard and a fail-closed cap on JWKS key counts. Construct
> the client via `OauthHttpClient::with_config(&oauth_config)` so the
> configured CA bundle, the SSRF guard, and the HTTPS-downgrade-rejecting
> redirect policy are all wired in one call. See
> [`SECURITY.md`](SECURITY.md#oauth-ssrf-hardening) for the trust model.

**OAuth in-cluster IdP (private/loopback IdP target, opt-in):**

```rust,ignore
use rmcp_server_kit::oauth::{OAuthConfig, OAuthSsrfAllowlist};

// `OAuthSsrfAllowlist` is `#[non_exhaustive]`; build it via
// `Default::default()` and push into the public fields.
let mut allowlist = OAuthSsrfAllowlist::default();
allowlist.hosts.push("rhbk.ops.example.com".into());
allowlist.cidrs.push("10.0.0.0/8".into());

let oauth = OAuthConfig::builder(
    "https://rhbk.ops.example.com/realms/main",
    "my-mcp-server",
    "https://rhbk.ops.example.com/realms/main/protocol/openid-connect/certs",
)
.ssrf_allowlist(allowlist)
.build();
```

> The default fail-closed SSRF guard blocks targets that resolve into
> private (RFC 1918), loopback, CGNAT, or unique-local space. Use
> `ssrf_allowlist` only when the IdP legitimately lives there (e.g. a
> Keycloak `Service` ClusterIP). Cloud-metadata addresses (AWS / GCP /
> Alibaba) remain unbypassable regardless of the allowlist contents.
> See [`docs/GUIDE.md`](docs/GUIDE.md#allowing-in-cluster-idps) and the
> "Operator allowlist" subsection of [`SECURITY.md`](SECURITY.md#operator-allowlist)
> for the full trust model.

**Prometheus metrics on a separate listener:**

```rust,ignore
let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    .with_metrics("127.0.0.1:9090".parse().unwrap());
```

**TLS:**

```rust,ignore
let config = McpServerConfig::new("127.0.0.1:8443", "my-server", "0.1.0")
    .with_tls("/etc/certs/server.crt", "/etc/certs/server.key");
```

## Features

- **Transport**: Streamable HTTP (`/mcp`), health (`/healthz`, `/readyz`),
  admin diagnostics, graceful shutdown, configurable TLS and mTLS.
- **Auth**: API-key (Argon2 hashed), mTLS client certs, OAuth 2.1 JWT
  validation against JWKS (feature-gated).
- **RBAC**: Tool-scoped allow-lists with per-role argument constraints and
  task-local `current_role()` / `current_identity()` accessors.
- **Observability**: Tracing, JSON logs, optional audit-file sink.
- **Hardening**: Per-IP rate limiting (governor), request-body caps,
  OWASP security headers, configurable CORS and Host allow-lists.
- **Metrics**: Prometheus `/metrics` endpoint (opt-in via `metrics`
  feature).

## Cargo features

| Feature              | Default | Description                                    |
|----------------------|---------|------------------------------------------------|
| `oauth`              | No      | OAuth 2.1 JWT validation via JWKS.             |
| `oauth-mtls-client`  | No      | RFC 8705 mTLS client authentication for the OAuth token-exchange endpoint. Implies `oauth`. |
| `metrics`            | No      | Prometheus metrics registry and `/metrics`.    |
| `test-helpers`       | No      | Test-only helpers for downstream integration tests. **Never enable in a production build** -- see the warning below. |

> **`test-helpers` is not safe in production.** It is not part of the stable
> API surface and carries no semver guarantees across minor releases. Some of
> the helpers it exposes deliberately bypass SSRF screening, the JWKS refresh
> cooldown, the CDP discovery rate limiter, and CRL verifier publication. Enable
> it only in test and integration builds. See the
> [Cargo features section of the guide](docs/GUIDE.md#cargo-features) for the
> per-helper detail.

## Design decisions

<details>
<summary><strong>RFC 8693 delegation (<code>actor_token</code>) is deliberately not implemented - NO-GO</strong></summary>

<br>

**Status: NO-GO.** Reviewed and decided; recorded here so the reasoning is not
rediscovered. The crate remains fully RFC-conformant without it.

### What is missing

RFC 8693 defines two exchange semantics:

| Semantics | Meaning | Parameters |
|---|---|---|
| **Impersonation** *(implemented)* | The server acts *as* the user. Downstream sees only the user. | `subject_token` |
| **Delegation** *(not implemented)* | The server acts *on behalf of* the user while remaining visible. Downstream sees both parties. | `subject_token` + `actor_token` |

Delegation produces an `act` claim chain, letting a downstream service record
*"service X acted for user Y"* rather than just *"user Y did this"*. In practice
this crate can only say the latter.

Per RFC 8693 §2.1, `actor_token` is **OPTIONAL**, and `actor_token_type` is
*"REQUIRED when the `actor_token` parameter is present in the request but MUST
NOT be included otherwise."* Because both are optional, omitting them is
conformant. This is a missing **capability**, not a defect.

### Why NO-GO

1. **Already conformant.** Nothing is broken; no spec violation exists.
2. **No user demand.** Identified during an internal review, not requested.
3. **Thin real-world support.** Keycloak's delegation support is limited, and
   Microsoft Entra ID does not use RFC 8693 for its on-behalf-of flow at all.
4. **The blocker is credential acquisition, not serialization.** Delegation
   needs a token representing the *server's own* identity. This crate has no
   client-credentials flow and no way to obtain one. Adding it means a second
   OAuth client inside the crate - token cache, refresh scheduling, failure
   policy, SSRF/TLS handling - which is far larger than adding two form
   parameters.

### Revisit criteria

Reopen when **all** of these are known:

- [ ] A named consumer requires delegation, with a concrete audit/compliance use case
- [ ] A named authorization server in their stack that actually supports RFC 8693 delegation
- [ ] A chosen actor-token acquisition model (see below)
- [ ] An expiry/rotation strategy for that credential

### If revisited - design notes

**Acquisition model.** Preferred: an **application-supplied async callback** -
the application already owns service-identity lifecycle. Explicitly rejected:
reusing the mTLS `client_cert` identity, which is RFC 8705 §2 *client
authentication*, not an RFC 8693 actor token.

**Known defect in the first sketch.** `build_exchange_form` is **synchronous**,
so an async token provider cannot be invoked from it. The actor token must be
resolved *before* form construction, higher in the exchange path. Any future
attempt hits this immediately.

**Serde feasibility (verified).** `TokenExchangeConfig` derives
`Debug, Clone, Deserialize` with `#[serde(deny_unknown_fields)]` and is
`#[non_exhaustive]`. A `#[serde(skip)]` provider field composes correctly and
does not break existing TOML parsing. `Clone` survives with
`Option<Arc<dyn _>>`; **`Debug` only survives if the trait itself requires
`Debug`** - note `ToolHooks` sidesteps this by not deriving `Debug`.

**Mandatory security constraints:**

- Store as `secrecy::SecretString`; never logged, debug-printed, audited, or included in errors
- Least-privilege scope/audience - this is the **service** identity, so a leak
  affects every delegated exchange, not one user
- Do **not** reuse `client_secret` as actor proof; client authentication and
  actor identity are distinct credentials
- Stale or expired actor tokens must fail **closed**
- Preserve the RFC 8693 §2.1 invariant: emit `actor_token_type` **iff**
  `actor_token` is present
- Preserve byte-identical request output for any config that does not opt into
  delegation

</details>

## Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.98** or newer (tracks `edition = "2024"`).

## Repository

- **GitHub** (canonical): <https://github.com/andrico21/rmcp-server-kit>

The canonical release artifact is the [`rmcp-server-kit` crate on crates.io](https://crates.io/crates/rmcp-server-kit).

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
