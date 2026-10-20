# rmcp-server-kit Architecture

> **Audience**: AI agents and engineers who need to **modify** rmcp-server-kit safely.
> **Companion**: [`MINDMAP.md`](MINDMAP.md) for the visual view, [`../AGENTS.md`](../AGENTS.md) for the navigation hub, [`GUIDE.md`](GUIDE.md) for end-user usage.
>
> All file references use `file:line` against the current working tree.
> Each citation names its symbol in backticks on the same line and points at
> that symbol's definition line. `tests/integration/docs_citations.rs` fails
> when the definition is more than 10 lines from the citation, when a cited file
> disappears or shrinks below the cited line, or when a citation has no symbol.

---

## Table of contents

1. [Bird's-eye view](#1-birds-eye-view)
2. [Module map](#2-module-map)
3. [Request lifecycle (HTTP)](#3-request-lifecycle-http)
4. [Core types](#4-core-types)
5. [Authentication subsystem](#5-authentication-subsystem)
6. [RBAC subsystem](#6-rbac-subsystem)
7. [TLS / mTLS](#7-tls--mtls)
8. [OAuth 2.1 / JWKS (feature `oauth`)](#8-oauth-21--jwks-feature-oauth)
9. [Tool hooks (extension point)](#9-tool-hooks-extension-point)
10. [Admin diagnostics](#10-admin-diagnostics)
11. [Observability](#11-observability)
12. [Metrics (feature `metrics`)](#12-metrics-feature-metrics)
13. [Hot reload](#13-hot-reload)
14. [Error handling](#14-error-handling)
15. [Configuration](#15-configuration)
16. [Testing strategy](#16-testing-strategy)
17. [Critical invariants](#17-critical-invariants)

---

## 1. Bird's-eye view

`rmcp-server-kit` is a **library crate** providing a "batteries included" framework
around the MCP Streamable HTTP transport from the official Rust SDK
([`rmcp`](https://docs.rs/rmcp)). The consumer's job is to implement
`rmcp::handler::server::ServerHandler` and call `rmcp_server_kit::transport::serve()`.
Everything below the `serve()` call - listeners, TLS, middleware, auth,
RBAC, hooks, observability, metrics, admin endpoints - is rmcp-server-kit's
responsibility.

The crate has two transports:

| Transport          | Function                                            | Auth/RBAC/TLS  | Use case                                         |
|--------------------|-----------------------------------------------------|----------------|--------------------------------------------------|
| **Streamable HTTP**| `serve()` - `src/transport.rs:3096`                 | **Yes**        | Production network deployment                    |
| stdio              | `serve_stdio()` - `src/transport.rs:5706`           | **No**         | Local subprocess MCP (desktop apps, IDEs)        |

---

## 2. Module map

```
src/
├── lib.rs               crate root, re-exports public modules            (lib.rs:23-52)
├── transport.rs         ★ orchestrator: serve(), TLS listener, router    (~2600 LOC)
├── auth.rs              authn primitives: ApiKeyEntry, AuthState, mw     (~1600 LOC)
├── rbac.rs              authz: RbacPolicy, task-locals, mw, rate-limit   (~1500 LOC)
├── oauth.rs             OAuth 2.1 + JWKS cache (feature = "oauth")       (~3000 LOC)
├── oauth_as.rs          authorization_server proxy mode: register, consent, callback, token (feature = "oauth")
├── oauth_as/tests/      binding near-miss unit tests of oauth_as.rs
├── oauth_seal.rs        HMAC-SHA256 sealed values (Sealer) for oauth_as.rs (feature = "oauth")
├── mtls_revocation.rs   CDP-driven CRL fetcher + dynamic verifier
├── bounded_limiter.rs   Memory-bounded keyed rate limiter (LRU prune)
├── ssrf.rs              Shared SSRF guard logic (literal-IP + per-hop)
├── admin.rs             /admin/* router + admin role middleware
├── tool_hooks.rs        opt-in HookedHandler wrapping ServerHandler
├── observability.rs     tracing init, JSON logging, audit-file sink
├── metrics.rs           prometheus registry + /metrics (feature = "metrics")
├── config.rs            TOML config structs and validation
├── error.rs             RmcpServerKitError + axum IntoResponse
└── secret.rs            re-exports of `secrecy::Secret`
```

Dependency direction (top → bottom):

```
application (consumer crate)
    │
    ▼
transport ──┬─ auth ──┬─ oauth (feature)
            ├─ rbac   │
            ├─ admin ─┘
            ├─ tool_hooks
            ├─ observability
            ├─ metrics (feature)
            ├─ config
            ├─ error
            └─ secret
                │
                ▼
        rmcp + axum + tokio + rustls
```

`transport.rs` is the only module that imports nearly everything else.
There are **no circular dependencies**.

---

## 3. Request lifecycle (HTTP)

A complete HTTP request to `/mcp` flows through these layers, top-to-bottom
(outermost → innermost). The corresponding code lives in
`build_app_router` (`src/transport.rs:2347`) and in each module.

```
TCP / TLS handshake                         `TlsListener` src/transport.rs:3820
   │  - Handshakes run CONCURRENTLY on a background acceptor task
│    (`run_tls_acceptor`, src/transport.rs:3911): 256-permit in-flight
   │    cap, 10 s per-handshake timeout; axum receives only completed
   │    connections via a bounded channel.
   │  - mTLS: client cert verified during the handshake; the resulting
   │    AuthIdentity is attached to the **per-connection** TlsConnInfo
   │    extension (no shared SocketAddr-keyed map).
   ▼
axum Router                                  src/transport.rs:2347  (build_app_router)
   │
├── 0. Security headers                   `security_headers_middleware` src/transport.rs:4537
   │      Outermost response-only decoration: HSTS, CSP,
   │      X-Frame-Options=DENY, X-Content-Type-Options, ...
   │
├── 1. Origin check                       `origin_check_middleware` src/transport.rs:5361
   │      Rejects 403 if Origin/Host not allowed (MCP spec requirement)
   │
   ├── 2. Peer-address normalization         src/transport.rs (normalize_peer_addr_middleware)
   │      Mirrors the TLS branch's peer address into ConnectInfo<SocketAddr>
   │      (insert-only-when-absent) and inserts the public `PeerAddr`
   │      extension on BOTH listener branches, so every route - including
   │      extra_router routes that bypass auth/RBAC - sees a uniform
   │      peer-address contract. mTLS identity stays on the private
   │      per-connection TlsConnInfo.
   │
├── 2b. Request log                       request_log_middleware
   │      DEBUG `incoming request` / `request completed`; skips
   │      request_log_exclude_paths and emits client fields only when
   │      enabled by [server.log_context] knobs.
   │
   ├── 4. CORS / Compression / Timeouts      tower-http layers
   │      Body size cap (default 1 MiB)
   │
   ├── 5. Optional concurrency cap           src/transport.rs (build_app_router)
   │      tower::limit::ConcurrencyLimitLayer + load_shed
   │
   ├── 6. Optional metrics middleware        src/metrics.rs (records
   │      request count, duration histograms, in-flight gauge)
   │
├── 7. Auth middleware                    src/auth.rs:2782 (`auth_middleware`)
   │      Determines AuthIdentity from one of:
   │        a) Authorization: Bearer <api-key>  → Argon2 verify against
   │           AuthState.api_keys (ArcSwap<Vec<ApiKeyEntry>>)
   │        b) mTLS - read AuthIdentity from the per-connection
   │           TlsConnInfo extension (set by TlsListener at handshake time)
   │        c) Authorization: Bearer <jwt>      → JwksCache::validate
   │           (feature = "oauth")
   │      Bearer scheme parsing is case-insensitive per RFC 7235 §2.1
   │      (see `extract_bearer` in src/auth.rs).
   │      On success: sets task-locals via `current_role`, `current_identity`, …
   │
├── 8. RBAC middleware                    src/rbac.rs:1354 (`rbac_middleware`) + 1527 (`enforce_tool_policy`)
   │      For POSTs to /mcp:
   │        - Reads body up to limit
   │        - Parses JSON-RPC envelope
   │        - If method == "tools/call":
   │             RbacPolicy::check(role, operation, host)
   │             ArgumentAllowlist::argument_allowed(role, tool, argument, value)
   │      Returns 403 on deny, 429 on rate-limit
   │
├── 9. Per-IP tool rate limiter           `build_tool_rate_limiter_with_policy` src/rbac.rs:71
    │      governor::RateLimiter keyed by ClientIp (BoundedKeyedLimiter)
    │
├── 10. Session binding                   src/session_binding.rs
    │      Verifies/wraps identity-bound `Mcp-Session-Id` tokens
   │
   ▼
rmcp StreamableHttpService
   └── Your ServerHandler::call_tool(...)
        (optionally wrapped by `HookedHandler` - src/tool_hooks.rs:361-482)
       │
       │  Inside the handler you can call:
       │    rbac::current_role()      -> Option<String>
       │    rbac::current_identity()  -> Option<AuthIdentity>
       │    rbac::current_token()     -> Option<Secret<String>>
       │    rbac::current_sub()       -> Option<String>
       │  These read tokio task-locals set by the auth middleware.
       ▼
   Result serialized → response
       └── Security headers re-applied; metrics recorded; rate-limit counters update
```

Open endpoints (no auth):

| Path                                       | Handler                                       |
|--------------------------------------------|-----------------------------------------------|
| `GET  /healthz`                            | `healthz` (`src/transport.rs:4266`) |
| `GET  /readyz`                             | `readyz`  (`src/transport.rs:4331`) - runs configured readiness check |
| `GET  /version`                            | `version_payload` (`src/transport.rs:4281`) |
| `GET  /metrics`                            | served by `serve_metrics` on a **separate listener** when `feature = "metrics"` (`src/metrics.rs:220`) |
| `GET  /.well-known/oauth-protected-resource` | feature = `oauth`, mounted in `build_app_router` (`src/transport.rs:2347`) |
| `GET  /.well-known/oauth-authorization-server` | feature = `oauth` proxy, mounted by `install_oauth_proxy_routes` (`src/transport.rs:3418`) |
| `POST /register` (`authorization_server` mode) | `register` (`src/oauth_as.rs:388`) - validates redirect URIs and answers `201` with a sealed per-client `client_id` |
| `GET  /authorize` (`authorization_server` mode) | `authorize` (`src/oauth_as.rs:485`) - opens the sealed client, checks the exact `redirect_uri` and S256 PKCE, serves the consent page (or skips it on remembered consent) |
| `POST /oauth/consent` (`authorization_server` mode) | `consent` (`src/oauth_as.rs:653`) - CSRF-checked approve/deny; approval sets the state and consent cookies and redirects to the upstream IdP |
| `GET  /oauth/callback` (`authorization_server` mode) | `callback` (`src/oauth_as.rs:849`) - checks the state cookie and upstream `iss`, wraps the code, redirects to the client with this server's `iss` |
| `POST /token` (`authorization_server` mode) | `token` (`src/oauth_as.rs:1059`) - opens the wrapped code or refresh token, checks client, `redirect_uri` and PKCE, sends an allowlisted form upstream |
| `POST /introspect`, `/revoke` (`authorization_server` mode, only when exposed) | `unwrap_refresh_token_param` (`src/oauth_as.rs:1129`) swaps a sealed refresh wrapper for the upstream token, then the passthrough handlers forward |

Authenticated endpoints:

| Path                | Auth | Notes                                          |
|---------------------|------|------------------------------------------------|
| `POST /mcp`         | Yes  | The MCP JSON-RPC endpoint (Streamable HTTP)    |
| `GET  /mcp`         | Yes  | SSE stream for server → client messages        |
| `*    /admin/*`     | Yes (role: `admin`) | `AdminConfig` in `src/admin.rs:50`            |
| `POST /authorize`, `/token`, `/register`, `/introspect`, `/revoke` | feature `oauth` proxy via `build_oauth_admin_router` | `src/transport.rs:3567` |

---

## 4. Core types

### `McpServerConfig` - `src/transport.rs:482`
Top-level builder-style config consumed by `serve()`. Holds:
- bind address (`SocketAddr`)
- server name + version
- optional TLS / mTLS paths
- optional `AuthConfig`, `RbacPolicy`, `OAuthConfig`
- `ToolHooks` (opt-in)
- limits (body size, request timeout, max concurrent reqs)
- admin enable flag and admin role
- optional readiness check callback (`Arc<dyn Fn() -> bool + Send + Sync>`)
- public URL (used in OAuth metadata responses)

### `ReloadHandle` - `src/transport.rs:2019`
Returned (optionally) from `serve()` when the consumer needs runtime
hot-reload. Methods:
- `try_reload_auth_keys(new_keys)` - validates, then atomically swaps
  `AuthState.api_keys` on success; a blank-named key is rejected (`Err`) and
  the previously installed keys are retained
- `reload_auth_keys(new_keys)` - infallible compatibility wrapper: on invalid
  input it logs and retains the previous keys instead of swapping
- `reload_rbac(new_policy)` - atomically swaps the `ArcSwap<RbacPolicy>`

Both use `arc-swap`, so live requests are not blocked or interrupted.

### `AuthIdentity` - `src/auth.rs:76`
Canonical caller record passed through the request scope:
```rust
pub struct AuthIdentity {
    pub name: String,                  // human-readable principal name
    pub role: String,                  // RBAC role (matched against RoleConfig)
    pub method: AuthMethod,            // ApiKey | Mtls | OAuth
    pub raw_token: Option<Secret<String>>, // present only for Bearer auth
    pub sub: Option<String>,           // OAuth subject claim, when applicable
}
```

### `RbacPolicy` - `src/rbac.rs:709`
Holds:
- `roles: HashMap<String, RoleConfig>` - per-role tool allow/deny rules
- default-deny semantics with explicit overrides
- per-tool argument allowlists
- per-IP rate limiter shared across the server

### `HookedHandler<H>` - `src/tool_hooks.rs:335`
Generic wrapper around a consumer's `ServerHandler` that runs:
- `before_call(name, args, identity)` - may rewrite args or short-circuit
- `after_call(name, result, identity)` - may rewrite or audit the result
- enforces `max_result_bytes` (returns an error if the serialized result exceeds the cap)

### `PeerAddr` - `src/transport.rs` (public, `#[non_exhaustive]`)
Framework-owned request extension carrying the **direct socket peer
address** of the connection. Inserted by `normalize_peer_addr_middleware`
on both listener branches (plain and TLS), extractable via its
`FromRequestParts` impl or `Extension<PeerAddr>` - including from
`extra_router` routes, which bypass auth/RBAC and therefore cannot rely
on the auth middleware's private `ConnectInfo<TlsConnInfo>` fallback.
Direct peer only (no `X-Forwarded-For` interpretation); absent under
`serve_stdio`; never logged by the framework.

### `ClientIp` - `src/transport.rs` (public, `#[non_exhaustive]`)
Resolved client IP, inserted by `normalize_peer_addr_middleware` on every
request right after `PeerAddr`. Equals the direct peer's IP unless
**trusted-forwarder mode** (`trusted_proxies` config) is active and the
request arrived through a trusted proxy with a verifiable forwarding
chain - then it is the rightmost-untrusted address from
`X-Forwarded-For` / RFC 7239 `Forwarded` (`ForwardedHeaderMode`),
resolved by `src/forwarded.rs` (`pub(crate)`: rightmost-untrusted walk,
16-entry scan cap, fail-safe-to-direct on malformed/obfuscated/
all-trusted chains, reason-code-only logging). All four per-IP rate
limiters key by this value via `limiter_client_ip`; the request log emits
it as `client_ip` only when `log_context.client_ip` is enabled. `PeerAddr`
keeps its direct-socket-peer contract unchanged.

### Extra-route per-IP rate limiter - `src/transport.rs` (opt-in)
`extra_route_rate_limit` (builder `with_extra_route_rate_limit` / TOML
`server.extra_route_rate_limit`, requests/min per source IP, must be
nonzero) installs `extra_route_rate_limit_middleware` as a layer on the
application's `extra_router` **before** it is merged into the top-level
router - axum layer-before-merge scoping guarantees it wraps only the
extra routes, never `/mcp`/health/admin/OAuth endpoints, while outer
layers (origin check, peer normalization) still run first. Same
machinery and deny shape as the tool limiter: `BoundedKeyedLimiter<IpAddr>`
(10k tracked keys, 15 min idle eviction → bounded memory, shared-fate
under key spray), fail-open without a peer address, 429 plain-text via
`RmcpServerKitError::RateLimitedFor` with a `Retry-After` header (delta-seconds;
all four kit limiters share this deny contract since 1.12.0, computed
from `BoundedKeyedLimiter::check_key_wait`). Optional burst knobs set
the bucket capacity per limiter (`*_burst` builder/TOML fields;
`RateLimitConfig::{burst, pre_auth_burst}` for the auth pair).
Startup-only.

---

## 5. Authentication subsystem

**File**: `src/auth.rs` (~600 LOC).

### Construction
`AuthState` is built inside `build_app_router()` at `src/transport.rs:2347`. It contains:
- `AuthState::api_keys` hot-swap vector (`src/auth.rs:1762`)
- mTLS identities: stored **per-connection** on the
  `TlsConnInfo` extension (`src/auth.rs:1448`), read by `auth_middleware` (`src/auth.rs:2782`).
  No shared `SocketAddr`-keyed map exists - the previous design was replaced
  to avoid identity-binding races behind load balancers and to remove a
  `RwLock` from the request hot path.
- `rate_limiter: Option<Arc<KeyedLimiter>>` - **post-failure backoff**:
  governor limit on *failed* auth attempts per IP. Consulted only after a
  credential check has run and rejected the caller.
- `pre_auth_limiter: Option<Arc<KeyedLimiter>>` - **pre-auth abuse gate**:
  governor limit on *unauthenticated* requests per IP, consulted *before*
  any Argon2id work runs. Defends the bearer-verification path against
  CPU-spray attacks (an attacker submitting a flood of invalid tokens to
  pin the CPU on Argon2id verification). Defaults to `10x` the
  post-failure quota when `pre_auth_max_per_minute` is unset on
  `RateLimitConfig`. **mTLS-authenticated requests bypass this gate
  entirely** (the TLS handshake already performed expensive crypto with a
  verified peer, so mTLS callers cannot be used to mount a CPU-spray
  attack).
- `AuthState::jwks_cache` (`src/auth.rs:1783`) when `feature=oauth` is on and `oauth.issuer` is configured

### API key flow
1. Client sends `Authorization: Bearer <api-key>`.
2. `auth_middleware` (`src/auth.rs:2782`) first runs the **pre-auth abuse
   gate** keyed by the request's source IP. If the gate is exhausted the
   middleware returns `429` immediately, *without* touching Argon2id.
3. Otherwise the middleware looks up the key by an indexed prefix
   (constant-time compare via `subtle`), then verifies Argon2id against
   `ApiKeyEntry.hash`.
4. On success, builds `AuthIdentity { method: ApiKey, role: entry.role, … }`.
5. On failure, the **post-failure backoff** limiter is consulted; if
   exhausted from one IP, the middleware returns `429`.

API keys are never logged. They are wrapped in `secrecy::SecretString`
and zeroized on drop. Bearer tokens accepted as OAuth JWTs are likewise
threaded as `SecretString` from `AuthIdentity.raw_token` through
`CURRENT_TOKEN` so that they never appear in `Debug` output.

### mTLS flow
1. The `TlsListener` validates the client cert chain (configured roots).
2. It extracts CN/SAN as `name`, derives `role` from the configured
   subject→role mapping, and attaches `AuthIdentity { method: Mtls, … }`
   to the **per-connection** extension in `extract_handshake_identity`
   (`extract_handshake_identity`, `src/transport.rs:3888`).
3. `auth_middleware` reads the identity directly from that connection
   state (`auth_middleware`, `src/auth.rs:2782`); no shared SocketAddr-keyed map is
   consulted, so there is no port-reuse aliasing risk.

### OAuth JWT flow (feature = `oauth`)
See [§8](#8-oauth-21--jwks-feature-oauth).

### Helpers
- `generate_api_key()` - produces a fresh API key + Argon2 hash (used by
  e2e tests and tooling).
- `verify_api_key()` - constant-time Argon2 verification.

---

## 6. RBAC subsystem

**File**: `src/rbac.rs` (~620 LOC).

### Policy model
```
RbacPolicy {
roles: HashMap<String, RoleConfig>,   // `RbacPolicy` src/rbac.rs:709
}

RoleConfig {                              // `RoleConfig` src/rbac.rs:310
    allow_tools: Vec<String>,              // glob patterns supported
    deny_tools:  Vec<String>,              // deny overrides allow
    argument_allowlists: HashMap<String, ArgumentAllowlist>,  // per tool
    rate_limit: Option<RateLimit>,         // optional per-role override
}

ArgumentAllowlist {                       // `ArgumentAllowlist` src/rbac.rs:435
    fields: HashMap<String, FieldRule>,    // per JSON-RPC argument key
}
```

### Decision function
- `RbacPolicy::check` (`src/rbac.rs:869`) - pure allow/deny
- `RbacPolicy::argument_allowed(role, tool, argument, value)` - JSON value match (`argument_allowed`, `src/rbac.rs:954`)
- `RbacPolicy::redact_arg(value)` - HMAC-SHA256 of an argument value with
the policy's salt, returning an 8-char hex prefix (`redact_with_salt`, `src/rbac.rs:1244`).
  Used to keep raw argument values out of deny logs.
- `enforce_tool_policy(policy, identity_name, role, params)` - combines
  allow/deny + argument-allowlist checks, emitting structured deny logs.
  `enforce_tool_policy` receives `identity_name` explicitly because the task-local context is
  installed *after* enforcement (see "Task-locals" below).

### Middleware
`rbac_middleware` (`src/rbac.rs:1354`):
1. Extracts the role + identity name from the `AuthIdentity` request
   extension (set by the auth middleware).
2. For `POST /mcp`, reads the body (bounded by body-size layer), parses
   JSON-RPC, and inspects `method`. Only enforces on `tools/call`.
3. Calls `enforce_tool_policy(&policy, &identity_name, &role, params)`
(`enforce_tool_policy`, `src/rbac.rs:1636`).
4. Calls the per-IP tool rate limiter
   (`build_tool_rate_limiter_with_policy`, `src/rbac.rs:71`), returning
   `429` if exceeded. The limiter is backed
   by `BoundedKeyedLimiter` (`src/bounded_limiter.rs:158`) which bounds
   memory via LRU prune.
5. On success, propagates the request downstream. The body is restored
   into the request so rmcp can read it again.

### Argument-value redaction
Deny logs for argument-allowlist violations never contain the raw value.
Instead, an HMAC-SHA256(salt, value) prefix (4 bytes / 8 hex chars) is
logged under the `arg_hmac` field. The salt is taken from
`RbacConfig::redaction_salt` (set in TOML for stable cross-restart
hashes) or, when absent, from a process-wide random salt generated on
first use. 32 bits is enough entropy for log-line correlation while
making preimage recovery infeasible. See
`redact_with_salt` (`src/rbac.rs:1244`).

### Task-locals
The `tokio::task_local!` block (`CURRENT_ROLE`, `src/rbac.rs:118`) defines four task-locals; the accessors start at `current_role` (`src/rbac.rs:158`):
- `CURRENT_ROLE: String`
- `CURRENT_IDENTITY: String`
- `CURRENT_TOKEN: SecretString`
- `CURRENT_SUB: String`

Public accessors: `current_role()` (`src/rbac.rs:158`),
`current_identity()` (`src/rbac.rs:180`), `current_token()` (`src/rbac.rs:202`),
and `current_sub()` (`src/rbac.rs:220`). They return
`Option<T>` because the task-locals are absent outside the request scope.

`current_token()` returns `Option<SecretString>`. Call `.expose_secret()`
only when the raw value is genuinely required - e.g. when constructing
an outbound `Authorization` header for downstream token passthrough.

> ⚠️ **These do NOT propagate across `tokio::spawn`.** Capture the value
> before spawning a child task.

---

## 7. TLS / mTLS

**Custom listener**: `TlsListener` in `src/transport.rs:3820`, implementing
`axum::serve::Listener` so axum's hyper machinery accepts it as a drop-in
replacement for `TcpListener`.

Lifecycle (concurrent-acceptor design, since the 1.8.1 review fixes):
1. `TlsListener::new(...)` reads PEM cert + key, builds a `rustls::ServerConfig`,
   optionally wraps with mTLS verification using configured root CAs, then
   spawns `run_tls_acceptor` (`src/transport.rs:3911`) as the dedicated background acceptor task that owns the listener.
2. The acceptor task loops: acquires a permit from a semaphore sized by
   `max_concurrent_tls_handshakes` (default 256 via
   `DEFAULT_MAX_CONCURRENT_TLS_HANDSHAKES`; configurable since 1.9.0 via
   `McpServerConfig::with_max_concurrent_tls_handshakes`) **before**
   accepting (so at saturation, excess connections wait in the kernel
   backlog), accepts a TCP connection, and spawns a handshake worker.
3. Each worker performs the TLS handshake under `tls_handshake_timeout`
   (default 10 s via `DEFAULT_TLS_HANDSHAKE_TIMEOUT`; configurable since
   1.9.0 via `McpServerConfig::with_tls_handshake_timeout`). On success it
   parses the peer cert if present (`x509-parser`), derives
   `AuthIdentity`, binds it to the stream as `AuthenticatedTlsStream`,
   and pushes the pair into a bounded mpsc channel (capacity 32,
   internal). Failures and timeouts are logged at DEBUG and the
   connection dropped; the permit is released either way.
4. `TlsListener::accept()` is a cancel-safe `rx.recv()` that just dequeues
   completed handshakes - it never performs handshake work itself, so one
   slow or idle client can no longer stall other connections.
5. Dropping the listener aborts the acceptor task, releasing the port
   deterministically.

Both tuning knobs are **startup-only**: they bind at listener
construction and do not participate in [`ReloadHandle`] hot reload.

Configuration toggles:
- TLS version: TLSv1.2+ (set in `rustls` features).
- Cipher suites: `rustls` defaults (ring crypto provider).
- mTLS: optional; when enabled, missing/invalid client cert → connection refused.
- TLS session resumption: disabled whenever mTLS is configured at all (since
  3.14), regardless of `crl_enabled`. Non-mTLS listeners keep the rustls
  default (resumption enabled).

**Why resumption is disabled for mTLS**: `TlsListener::new` builds its
`rustls::ServerConfig` through `build_tls_server_config`
(`src/transport.rs`), which passes `disable_resumption = mtls_config.is_some()`
into the low-level seam `build_tls_server_config_from_verifier`. rustls
restores a resumed handshake's peer certificate chain from cached session
state without ever calling `ClientCertVerifier::verify_client_cert` - the
only place this crate checks CRL revocation, certificate expiry
(`notAfter`), and chain validity. Left enabled, a certificate that had been
revoked or had expired could keep authenticating for as long as a session
stayed resumable, with no observable signal distinguishing the bypassed
connection from a freshly verified one. Scoping the fix to `crl_enabled`
alone would be insufficient: non-CRL mTLS still relies on
`verify_client_cert` for expiry and chain validation.

### CRL revocation (CDP-driven)

**File**: `src/mtls_revocation.rs`. Active automatically whenever
`[mtls]` is configured and `crl_enabled = true` (the default).

Lifecycle:
1. `bootstrap_fetch(roots, ca_certs, config)` (`src/mtls_revocation.rs:2172`) is
   the public helper. `run_server` calls the crate-internal
   `bootstrap_fetch_with_server_chain(roots, ca_certs, server_chain, config)`
   *before* the listener is built. That path walks the configured CA chain,
   extracts every X.509 CRL Distribution Point (CDP) URL via
   `extract_cdp_urls`, fetches each via `reqwest` under a 10 s total
   deadline, and seeds the cache. It also derives the trusted origins from
   the CDP and AIA caIssuers and OCSP URIs named in the CA bundle and the
   server certificate chain, then logs the sorted set once at INFO.
2. The returned `Arc<CrlSet>` (`CrlSet`, `src/mtls_revocation.rs:330`) owns:
   - `verifier_state: ArcSwap<VerifierState>` - one published generation
     containing the current `Arc<dyn ClientCertVerifier>`, the URLs whose
     CRLs it enforces, and the committed cache-entry identities.
   - `commit_lock: tokio::sync::Mutex<()>` and
     `cache: tokio::sync::RwLock<HashMap<String, CachedCrl>>` keyed by URL.
   - `discover_tx: mpsc::UnboundedSender<String>` - channel used by the
     handshake path to register newly observed CDP URLs for fetch.
   - `seen_urls` and `pending_urls` mutexes - permanent and in-flight
     discovery dedupe sets.
   - `clients` - the screened and trusted CRL fetch clients
     (`CrlHttpClients`, see "SSRF hardening").
   - `global_fetch_sem`, `host_semaphores`, `discovery_limiter`,
     `discovery_limiter_per_peer`, `crl_cpu`, and `trusted_origins` - the
     network, admission, CPU, and trusted-origin bounds.
   - `roots` and `signature_algorithms` - the client-auth root store and the
     process-default provider's signature algorithms (captured once in
     `CrlSet::new`). The live verifier uses the same pair, and
     `cdp_urls_on_verified_paths` reuses them for the verified-path check
     described under "Discovery admission ordering".
   A commit publishes the rebuilt cache and `verifier_state` together under
   the cache write lock with no `.await` between them; handshake readers take
   a non-blocking cache `try_read()` and then load `verifier_state`.
3. `DynamicClientCertVerifier` (`src/mtls_revocation.rs:1745`) is the
   `Arc<dyn ClientCertVerifier>` handed to `rustls::ServerConfig`. It holds
   `{ inner: Arc<CrlSet>, dn_subjects }` and delegates every revocation
   precheck and rustls verifier decision to the `CrlSet` and its published
   `verifier_state`. Because `tokio_rustls::TlsAcceptor` clones the verifier
   `Arc` from the `ServerConfig` at construction, the dynamic verifier MUST
   be the Arc handed to rustls.
4. `run_crl_refresher(set, rx, shutdown)` (`src/mtls_revocation.rs:2427`)
   is spawned by `run_server`. It:
   - Drains the `discover_tx` receiver and fetches any newly observed CDP URLs.
   - Re-fetches each cached CRL before its `nextUpdate`, clamped to
      `[10 min, 24 h]` (overridable via `crl_refresh_interval`).
   - Commits successful refreshes through `commit_cache_update_atomically`,
     which rebuilds the rustls verifier on the bounded Tokio blocking pool and
     publishes the cache and `verifier_state` as one generation.
   - Honours `crl_fetch_timeout` per request and `crl_retry_retention`
     (`crl_stale_grace` deprecated alias) for retry-retention eviction after
     `nextUpdate`. Expired CRLs are never trusted when expiration enforcement
     is enabled.

CRL parsing and verifier rebuilds are CPU-bound, so both steady-state commits
and bootstrap rebuilds run on Tokio's blocking pool behind two permits. The
steady-state path uses `CrlSet::crl_cpu`; bootstrap uses a bootstrap-local
semaphore of the same size before the `CrlSet` exists.

Failure modes:
- Fetch failure / parse failure: if `crl_deny_on_unavailable = true`
  (default) handshakes that depend on an unavailable CRL are rejected, and
  only when *every* relevant CDP is uncached; if `false`, handshakes continue
  with a `WARN` log. A cached CRL whose refresh
  keeps failing is retained only for retry until `nextUpdate +
  crl_retry_retention`; webpki still rejects CRL use past `nextUpdate`.
- `crl_allow_http = false` rejects `http://` CDP URLs.
- CRL and AIA URLs whose host is an IPv6 literal are not fetched: the lookup of
  the bracketed host fails, so the fetch fails closed.
- `crl_end_entity_only = true` checks only the leaf, skipping intermediates.

### SSRF hardening

The shared SSRF helpers live in `src/ssrf.rs`. CRL traffic uses the scheme and
userinfo gate, the shared IP classifier, and the connect-time screening
resolver rather than redirect screening: the CRL clients are built with
`Policy::none()`.

For CRL fetches, the guard covers:
- `check_scheme` rejects non-http(s) schemes, userinfo, and `http://` unless
  `crl_allow_http = true`.
- `fetch_crl` performs a DNS pre-flight and calls `reject_blocked_crl_ip`,
  which delegates to `ip_block_reason`. A trusted origin named in the
  operator's CA bundle or server chain can skip the private-address block;
  cloud-metadata addresses stay blocked.
- `SsrfScreeningResolver` re-screens DNS answers at connect time, closing the
  resolution-to-connect gap for DNS names. CRL fetches use two clients
  (`CrlHttpClients`): the screened client has no trusted hostnames and
  serves every URL whose exact origin (scheme, host, and port) is not
  trusted; the trusted client, whose resolver admits the trusted hostnames,
  serves only URLs whose exact origin is trusted. One
  `CrlHttpClients::for_url` decision drives both the pre-flight and the
  client choice, so a DNS change cannot carry a trusted hostname onto
  another port.
- The body-size, global fetch, per-host, discovery-rate, seen-URL, pending-URL,
  and cache caps bound the remaining blast radius.

For OAuth, the guard covers:
- All six configured URL fields at startup (`issuer`, `jwks_uri`,
  `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`,
  `introspection_endpoint`) - userinfo + literal-IP rejection.
- Both OAuth client redirect closures (`OauthHttpClient::build` and
  `JwksCache::new`) - runtime per-hop range guard plus
  `https -> http` downgrade rejection and `http -> http` gating on
  `allow_http_oauth_urls`.
- Direct OAuth and JWKS requests as well as redirects, because the OAuth
  clients install `SsrfScreeningResolver` on the `reqwest` clients.

### Discovery admission ordering

`note_discovered_urls` (`src/mtls_revocation.rs:1023`) implements a
strict pending-before-send protocol to keep discovery retries correct:

1. Sort and deduplicate the advertised URL set, select the relevant set
   (`crl_end_entity_only` chooses leaf CDPs only), and reject a certificate
   advertising more than `MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE` distinct
   relevant URLs. The cap and the fail-closed precheck count every relevant
   presented CDP URL, including those of certificates that later turn out to
   be on no verified path (with `crl_end_entity_only = true` only the end
   entity's URLs are relevant).
2. Snapshot `seen_urls` and `pending_urls`, then keep only relevant URLs that
   are neither confirmed cached nor already in flight. `fetch_crl` later
   applies `check_scheme`, `reject_blocked_crl_ip`, `ip_block_reason`, and
   connect-time `SsrfScreeningResolver` screening before issuing any request.
3. When candidates remain, run the `discoverable` closure once. It is
   `CrlSet::cdp_urls_on_verified_paths`: after byte-identical duplicate
   intermediates are dropped, webpki path building from the presented chain
   to the configured roots with the same signature algorithms as the live
   verifier, client-auth usage, and no revocation, continued past the first
   success - a `verify_path` callback records each complete path and rejects
   it so webpki keeps searching within its per-call budget - so every
   verified path the budget reaches contributes. The live verifier gives up
   on a candidate at its first revocation failure while this search verifies
   each candidate in full, so a chain with dozens of distinct alternative
   paths can exhaust the budget before the path the live verifier accepts.
   A chain that does not
   verify yields `None`, which empties the candidates, so nothing is admitted
   and no limiter token is consumed. For a chain that verifies, candidates
   not named by the end entity or by an intermediate on any verified path are
   dropped (logged at `debug`). Certificates on no verified path are therefore
   excluded from discovery but, by default, not from step 1's cap or the
   precheck.
4. For each remaining candidate, attempt admission. When the handshake peer is
   attributed via the `CURRENT_HANDSHAKE_PEER` task-local (set by the
   TLS accept worker), admission consults that peer's own bucket
   (`discovery_limiter_per_peer.check_key(peer)`); with no attributed
   peer it falls back to the process-global `discovery_limiter.check()`.
   Order is load-bearing: the `governor` APIs **consume** a token rather
   than peek, so an attributed peer must consult **only** its own bucket -
   also touching the global one would let a rejected attacker still drain
   the shared budget.
5. After admission, insert the URL into `pending_urls` before
   `discover_tx.send(url)`. `promote_pending_to_seen` moves it to `seen_urls`
   only after `fetch_and_store_url` confirms the CRL is actually in the cache;
   failed fetches, cache refusals, dropped futures, and closed-channel sends
   clear the pending marker without promotion, so the URL remains retriable.

This ordering matters: a naive "mark seen, then attempt admission" or
"mark seen, then fetch" implementation would silently drop CDP URLs forever
the first time the rate limiter engaged or the fetch failed, breaking
revocation for the affected client identities. Per-peer keying additionally
stops one peer's spray from fail-closing a concurrent legitimate peer. The
current ordering is verified by `__test_check_discovery_rate`
(`__test_check_discovery_rate`, `src/mtls_revocation.rs:1379`) and by the per-peer isolation test
(`per_peer_discovery_quota_does_not_starve_other_peers`).

Hot-reload: `ReloadHandle::refresh_crls()` (in `src/transport.rs`) calls
`CrlSet::force_refresh()` to re-fetch every cached URL and commit the results
through the same atomic publication path.

Test helper: `__test_with_prepopulated_crls(...)` (doc-hidden) lets `tests/integration/e2e.rs`
seed a `CrlSet` with synthetic `rcgen`-generated CRLs and `wiremock`-served
CDP endpoints. Four e2e tests cover: unrevoked-allows, revoked-rejects,
fail-open on unreachable CDP, fail-closed on unreachable CDP.

**Plain HTTP fallback**: when no TLS cert is supplied, axum binds a
plain `TcpListener`. For production deployments, TLS is strongly
recommended.

---

## 8. OAuth 2.1 / JWKS (feature `oauth`)

**File**: `src/oauth.rs` (~640 LOC). Activated by `features = ["oauth"]`.

### Validation flow
1. Client sends `Authorization: Bearer <jwt>`.
2. `JwksCache::validate_token(token)` (`validate_token`, `src/oauth.rs:3809`):
   - Decodes the JWT header to get `kid` and `alg`.
   - `lookup_key()` looks up by `kid` in the cached JWKS
     (`lookup_key`, `src/oauth.rs:4711`).
   - If not found, calls `refresh_with_cooldown()` (`src/oauth.rs:4267`):
       - Enforces `JWKS_REFRESH_COOLDOWN` (`src/oauth.rs:3352`) so multiple
       invalid tokens cannot DoS the JWKS endpoint.
     - Deduplicates concurrent refreshes.
   - Validates signature, `iss`, `aud`, `exp`, `nbf` using `jsonwebtoken`.
3. Extracts the configured `role_claim` (or maps OAuth scopes to roles).
4. Builds `AuthIdentity { method: OAuth, role, sub, raw_token: Some(_), … }`.

### Optional OAuth 2.1 proxy
When `oauth.proxy` is configured, rmcp-server-kit mounts thin proxy endpoints under
the server's own URL via `install_oauth_proxy_routes` (`src/transport.rs:3418`):
- `/.well-known/oauth-authorization-server`
- `/authorize`, `/token`, `/register`, `/introspect`, `/revoke`

These let downstream MCP clients discover OAuth via the same origin as
`/mcp`, simplifying CORS and CSP configuration.

The proxy runs in one of two modes, selected by `OAuthProxyConfig::mode`
(`ProxyMode`, `src/oauth.rs:1289`). `passthrough` (the default) is the
3.20.0 proxy above: `/authorize` redirects to the upstream with the client id
swapped, the upstream redirects the browser straight back to the client, and
`/register` echoes the static client id. `authorization_server` returns early
from `install_oauth_proxy_routes` into
`install_routes` (`src/oauth_as.rs:184`): this server registers clients itself,
shows a per-client consent page, receives the upstream redirect at
`/oauth/callback`, re-stamps `iss` with its own issuer and binds codes and
refresh tokens to the client. It keeps no server-side state; every
registration, consent, state cookie, code and refresh wrapper is sealed by
`Sealer` (`src/oauth_seal.rs:83`) with a key derived per purpose from
`sealing_secret`. The HTML pages carry their own CSP through
`PageSecurityHeaders` (`src/transport.rs:4648`). Flows, knobs and Keycloak
settings for both modes are in [`OAUTH_PROXY.md`](OAUTH_PROXY.md).

### Hardening defaults
- Allowed algorithms: configured per `OAuthConfig` (default: `RS256`, `ES256`).
- Symmetric keys (`HS*`) are rejected by default - protects against
  algorithm-confusion attacks.
- **JWKS keys omitting the OPTIONAL `alg` member (RFC 7517 4.4) are accepted.**
  `jwk_algorithm()` returns a `JwkAlg`: `Explicit(alg)` pins one algorithm,
  `Family(..)` infers the permitted set from the key type (`RSA` -> RS*/PS*,
  `P-256` -> ES256, `P-384` -> ES384, `Ed25519` -> EdDSA). Inference reads only
  key material, never the token header, and never yields `HS*`/`none`.
  `P-521`/`ES512` is unsupported because `jsonwebtoken`'s `Algorithm` enum has
  no `ES512` variant. Required by Microsoft Entra v2.0, which publishes every
  key without `alg` (issue #17).
- JWKS responses cached with TTL; stale-while-revalidate semantics.
- HTTPS-downgrade-rejecting redirect policy on `OauthHttpClient`.
- **SSRF guard**: per-hop DNS/private-IP blocklist and URL validation
  (no userinfo, no IP literals) - see [§7 SSRF hardening](#ssrf-hardening).
- **JWKS key cap**: `max_jwks_keys` (default 256) blocks key-stuffing
  resource exhaustion.
- Prefer `OauthHttpClient::with_config(&OAuthConfig)` over the deprecated
  `OauthHttpClient::new()` so the redirect policy, SSRF guard, and CA
  bundle are wired consistently.

### Trust boundary

OAuth endpoint URLs (`issuer`, `jwks_uri`, discovery URLs) are
**operator-trusted configuration**. These URLs are subject to strict
validation and an SSRF guard, but operators must still ensure they point
to intended, authenticated Identity Providers.

---

## 9. Tool hooks (extension point)

**File**: `src/tool_hooks.rs`.

```rust
pub trait ToolHooks: Send + Sync + 'static {
    fn before_call(&self, name: &str, args: &Value, identity: Option<&AuthIdentity>)
        -> Result<Value, RmcpServerKitError>;
    fn after_call(&self, name: &str, result: &Value, identity: Option<&AuthIdentity>)
        -> Result<Value, RmcpServerKitError>;
}
```

`HookedHandler<H>` implements `rmcp::ServerHandler` for any inner `H: ServerHandler`,
delegating every method while intercepting `call_tool` (`src/tool_hooks.rs:681`):
1. Captures current identity from task-locals.
2. Calls `before_call` - may rewrite args, may return early with an error.
3. Calls inner handler.
4. Serializes result, checks `max_result_bytes` - error if exceeded.
5. Calls `after_call` - may redact / audit / transform.

Activated in `McpServerConfig` via `with_hooks(...)`. Skip if you don't need
custom audit/transformation.

---

## 10. Admin diagnostics

**File**: `src/admin.rs`.

Mounted under `/admin/*` only when `config.admin_enabled = true`. The
`require_admin_role` middleware (`src/admin.rs:182`) gates access to the
configured admin role (default: `"admin"`).

| Endpoint               | Returns                                                  |
|------------------------|----------------------------------------------------------|
| `GET /admin/status`    | server name, version, uptime, feature flags, peer count  |
| `GET /admin/auth/keys` | current API key metadata (name, role, expiry - never the secret) |
| `GET /admin/auth/counters` | per-IP auth attempts, success/failure counts          |
| `GET /admin/rbac`      | current RBAC policy snapshot                             |

Useful for debugging hot-reload state and verifying RBAC after a swap.

---

## 11. Observability

**File**: `src/observability.rs`.

`init_tracing_from_config(...)` (~`src/observability.rs:96`) initializes
`tracing-subscriber` with:
- `EnvFilter` from `RUST_LOG` (or supplied filter string)
- console layer (pretty when stdout is a TTY, JSON otherwise)
- optional **audit-file sink** (`TracingGuard`, `src/observability.rs:137`) - appends
  structured JSON events to a path; useful for compliance/forensics.

Conventions used by rmcp-server-kit itself:
- `tracing::info!` for lifecycle events (server up/down, key reloads)
- `tracing::warn!` for soft denials (rate-limit hits, RBAC denies)
- `tracing::error!` for hard failures (TLS handshake errors, internal panics caught by axum)
- All sensitive fields are redacted (API keys, tokens, full bodies).

> ⚠️ **Never log a `Secret<T>` directly.** `Debug`/`Display` of `secrecy::Secret`
> prints `Secret([REDACTED])`, but `expose_secret()` is logged as plain
> text - never log the result of that call.

---

## 12. Metrics (feature `metrics`)

**File**: `src/metrics.rs`. Activated by `features = ["metrics"]`.

`McpMetrics` (`src/metrics.rs:49`) wraps a `prometheus::Registry` and
records the following standard server metrics:
- `rmcp_server_kit_http_requests_total{method, path, status}` (counter)
- `rmcp_server_kit_http_request_duration_seconds{method, path}` (histogram,
  buckets `[1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s]`)
- `rmcp_server_kit_rate_limited_total{limiter}` (counter)
- `rmcp_server_kit_auth_failures_total{class}` (counter). `class` is one of
  `missing_credential`, `invalid_credential`, `expired_credential`,
  `rate_limited`, `pre_auth_gate`, `overloaded`. `record_counted_failure` in
  `src/auth.rs` bumps it alongside `AuthCounters`. With metrics enabled,
  matching per-class cumulative counts agree once requests settle. The admin
  counter is bumped first and the metric second, so a concurrent observation
  can differ momentarily. The pre-auth `CapacityFull` 503 bumps neither. The post-failure limiter's
  `CapacityFull` 503, which only `key_eviction_policy = "reject_new"` can
  produce, also bumps neither, and the request's own failure class goes
  uncounted too; its WARN line, `auth post-failure limiter rejected unseen
  key because tracked-key capacity is full`, is the only record. The counter is
  the alerting record for the failure classes that log at DEBUG. A PromQL
  `rate(...)` query over this counter reports a rate over time, not a value
  numerically equal to an admin counter.

`ensure_framework_metrics_registered` in `src/transport.rs` binds all four
families to the served registry at startup, so the `rmcp_server_kit_*`
namespace is reserved: a custom collector that reuses one of these names
collides with it. Operators that need additional collectors (RBAC-deny
counter, in-flight gauge, etc.) can register custom metrics against the
shared `McpMetrics::registry`, which is intentionally part of the public
API surface.

The `/metrics` endpoint is served on a **separate listener** (often a
private bind address) configured via `MetricsConfig` - see
`serve_metrics` (`src/metrics.rs:220`). This isolates
operational telemetry from the public MCP listener.

---

## 13. Hot reload

Two ArcSwaps power runtime reconfiguration:

| State            | Type                           | Defined at                  |
|------------------|---------------------------------|-----------------------------|
| API keys         | `AuthState` `api_keys` slot     | `src/auth.rs:1762`          |
| RBAC policy      | `ReloadHandle` `rbac` slot      | `src/transport.rs:2023`      |

Procedure:
1. Consumer calls `reload_handle.try_reload_auth_keys(new_keys)` (fallible,
   validated) or `reload_rbac(new_policy)`. The infallible
   `reload_auth_keys(new_keys)` wrapper retains the previous keys and logs on
   invalid input rather than swapping.
2. The new value is wrapped in `Arc<…>` and atomically swapped.
3. New requests pick up the new value on next read; in-flight requests
   continue with whichever value they already loaded.

Why `arc-swap` and not `RwLock`?
- Reads are wait-free (no atomic write contention).
- Writers never block readers.
- The ~few-microsecond eventual-consistency window is acceptable for
  policy changes.

---

## 14. Error handling

**File**: `src/error.rs`.

```rust
#[derive(thiserror::Error, Debug)]
pub enum RmcpServerKitError {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    RateLimited,
    PayloadTooLarge,
    Internal(#[from] anyhow::Error),
    // ...
}
```

`IntoResponse` (`src/error.rs:170`) maps each `RmcpServerKitError`
variant to a sanitized HTTP response:
- Status code (`401`, `403`, `400`, `429`, `413`, `500`)
- Generic body (no internal details leaked to clients per OWASP)
- Logs the full cause via `tracing::error!` with structured fields

Inside handlers, `?` propagates errors. Never panic - the `panic = "deny"`
clippy lint enforces this.

---

## 15. Configuration

Three layers, applied in a fixed order.

**Programmatic** - `McpServerConfig::new(addr, name, version)` builder (`src/transport.rs:990`). Holds everything the server needs, including the
runtime-only fields TOML cannot express: `rbac`, `readiness_check`,
`extra_router`, `on_reload_ready`, and the metrics listener. Deliberately does
**not** derive `Deserialize` - it carries callbacks and an `axum::Router`, and
deriving serde would freeze the deprecated public field surface the crate is
retiring.

**TOML** - the deserializable sections:

- `ServerConfig` - `src/config.rs:487`
- `ObservabilityConfig` - `src/config.rs:1807`
- `SecurityHeadersConfig` - `src/transport.rs:293`
- `AuthConfig`, `MtlsConfig`, `RateLimitConfig` - `src/auth.rs`
- `RbacConfig` - `src/rbac.rs`
- `OAuthConfig` - `src/oauth.rs`

There is **no kit-owned root config struct**; each downstream composes these
sections into its own root type. `[server]`, `[rbac]` and `[observability]`
are a convention from [`docs/GUIDE.md`](GUIDE.md), not a type.

`ServerConfig` was schema-only until 3.4.0 - nothing in the crate consumed it.
`ServerConfig::apply_to_mcp_config` (`src/config.rs:1061`) is the bridge that
makes it reachable. It uses **replacement semantics**: authoritative for every
bridgeable transport field, with `None`/`false` clearing whatever the base
held. Only the runtime-only fields above survive from the base. It is fallible
(duration strings parse here) and never reads the environment.

**Environment (opt-in)** - three inherent methods, one per section owning
targeted fields: `ServerConfig::apply_env_overrides` (`src/config.rs:802`),
`ObservabilityConfig::apply_env_overrides` (`src/config.rs:1162`) and
`RbacConfig::apply_env_overrides` (`src/rbac.rs:2173`). Each returns
`Vec<EnvOverride>` (`src/config.rs:92`) for audit logging, with `value: None`
for secret targets. Curated variables under the `RMCP_SERVER_KIT__`
prefix; `__` separates TOML path segments because field names already contain
single underscores.

Nothing reads the environment implicitly - `serve()`, `validate()` and every
constructor are env-free. `RUST_LOG` remains the one exception, honoured by
`init_tracing_from_config` per tracing convention.

Precedence: **struct defaults < TOML < `apply_env_overrides` < application
builder calls after the bridge < `validate()`**.
[`examples/config_file_server.rs`](../examples/config_file_server.rs) is the
compiled, runnable walkthrough.

Defaults (chosen for safe production posture):
- max body size: **1 MiB**
- request timeout: **120 s**
- session idle timeout: **20 m**
- admin role: `"admin"`, admin endpoints **off**
- build metadata on `/version`: **hidden**
- security headers: full OWASP defaults applied, HSTS `preload` rejected

---

## 16. Testing strategy

**Unit tests** live one crate per file under `tests/unit/*.rs`, plus the
in-module `#[cfg(test)] mod tests { … }` blocks next to `src/` code. They cover
pure logic (config validation, error mapping, argument allowlist matching, JWKS
algorithm selection, etc.) with no I/O or network.

**Integration / E2E** tests live one crate per file under
`tests/integration/*.rs` (the largest is `e2e.rs`). They:
- Spawn `rmcp_server_kit::transport::serve(...)` on an **ephemeral port** via
  `spawn_server()` (`tests/integration/e2e.rs:507`).
- Use `reqwest` to make real HTTP calls - origin checks, auth, RBAC,
  rate-limiting, readiness, body limits, TLS handshakes.
- Use `wiremock` for OAuth/JWKS upstreams.
- Generate test certs at runtime using `rcgen`.

Every test file is declared with an explicit `[[test]]` target in `Cargo.toml`,
and the feature-gated ones carry `required-features` instead of a crate-level
`#![cfg(feature = ...)]`: running a gated target without its features is now an
error, not a silently empty binary. There is no separate `e2e` tier; every test
is autonomous (loopback ports or `wiremock`, no live external service).

Examples worth reading:
- `auth_accepts_valid_bearer` - `tests/integration/e2e.rs:1070`
- `rbac_denies_unpermitted_tool` - `tests/integration/e2e.rs:1208`
- `rbac_allows_permitted_tool` - `tests/integration/e2e.rs:1238`
- `rbac_argument_allowlist_enforced` - `tests/integration/e2e.rs:1270`

> When changing behaviour, **add an E2E test first**. The unit tests in
> `auth.rs`/`rbac.rs` are useful but the E2E suite is what catches
> middleware-ordering regressions.

### CI and gates

`.github/workflows/ci.yml` is canonical; `.gitlab-ci.yml` mirrors it. Blocking
jobs: `fmt` (pinned `nightly-2026-10-03`), `clippy`, `test` (Linux/macOS/Windows
+ doctests), the five-row feature matrix, `cargo-semver-checks`, `cargo-deny`,
`cargo-audit`, `cargo-vet`, `taplo`, `cargo-machete`, `Rustdoc` (pinned nightly
with `--cfg docsrs`), `Rustdoc (stable)`, `MSRV (1.99.0)` (lint-capped),
`Memory bounds`, `Validate docs (citations + links)`, the `lint-ratchet`
self-tests, and the five permanent lint gates. `cargo-geiger` and the nightly
`Rustdoc (latest nightly canary)` run informational; `cargo-mutants` is
schedule-only (the `oauth`-feature modules `src/oauth_as.rs` and
`src/oauth_seal.rs` run in the separate `mutants-oauth` job).

The lint gates are stdlib-only Python under `scripts/lint-ratchet/`:
`catalog_gate.py` (every `#[expect]` reason is in the sanctioned catalog),
`allow_gate.py` (no `#[allow]`), `profile_eq.py` (the committed `[lints]` table
equals the vendored profile), `prose_gates.py` (cancel-safety notes, test
signatures, docs, emptiness-assertion messages), and `dash_gate.py` (house
dash convention outside vendored guidelines). Shared helpers live in
`common.py`; the counting ratchet and
its `baseline/` tree were retired once the last `lint-migration:` expectation
reached zero.

### Delegation-safety layers (the `ServerHandler` wrappers)

`HookedHandler` (`src/tool_hooks.rs`) and `RbacContextHandler`
(`src/rbac_context.rs`) are transparent wrappers: every `ServerHandler` method
must reach the inner handler, and rmcp's trait defaults make a dropped
delegation compile - and pass - silently. Three layers hold that line, and they
prove different things:

- **Presence and origin** - `tests/integration/delegation_guard.rs` parses the upstream
  `ServerHandler` surface out of the rmcp source pinned in `Cargo.lock`, asserts
  each wrapper's impl contains a method for every classified name, pins the
  origin of every macro-generated `RbacContextHandler` method (a
  `delegate_request!` invocation is not the same as a hand-written `fn` of the
  same name), and asserts the in-crate `SEMANTIC_DRIVERS` tables cover the whole
  classification.
- **Forwarding** - the in-crate semantic suites (the `mod tests` modules of
  both files above) drive every method and assert exact equality against the
  expected record log for that driver, or a sentinel value (or sentinel error)
  that no default body can construct.

`PassthroughDefaults<H>` (test-only, defined in both modules) is the negative
control: the same wrapper with every delegation deleted. Each driver runs twice
- once through the real wrapper, once through `PassthroughDefaults` - so every
method carries a mutation check that re-executes on every `cargo test` rather
than a one-off ritual.

Split, in one line: the guard proves **presence and origin**, the semantic
suites prove **forwarding**. Neither alone suffices - a body can exist and never
call `self.inner`.

---

## 17. Critical invariants

These are **non-negotiable**. Breaking any of them is a security regression.

1. **Origin check runs before auth.** Reordering would allow unauthenticated
   browser-origin requests to hit the auth path and amplify timing oracles.
Wired in `build_app_router` (`src/transport.rs:2347`);
`origin_check_middleware` is at `src/transport.rs:5361`.

2. **Auth runs before RBAC.** Without an `AuthIdentity`, RBAC has no role
   to evaluate. `build_app_router` installs the auth layer before the RBAC
   layer (`build_app_router`, `src/transport.rs:2347`).

3. **Per-IP rate limiter sits inside auth.** Anonymous IPs cannot
   exhaust the rate-limit budget for authenticated callers.

4. **JWKS refresh is rate-limited.** Removing `JWKS_REFRESH_COOLDOWN`
   (`JWKS_REFRESH_COOLDOWN`, `src/oauth.rs:3352`) creates a DoS vector against the issuer's JWKS endpoint.

5. **No symmetric JWT algorithms by default.** `HS*` algorithms with a
   public JWKS would enable algorithm-confusion attacks. Don't add them
   to the default allow-list.

6. **mTLS identity is bound to the connection stream, never to a shared map.**
   `AuthIdentity` travels inside `AuthenticatedTlsStream` / the per-connection
   `TlsConnInfo` extension, so two simultaneous connections from the same
   client (or a reused ephemeral port) can never observe each other's
   identity. Do not reintroduce a `SocketAddr`-keyed map - that earlier
   design was removed precisely because of port-reuse aliasing races
   (see §5).

7. **`stdio` transport bypasses ALL middleware** (auth, RBAC, TLS, origin).
   Document this loudly to consumers and never recommend it for network use.

8. **Secrets must use `secrecy::SecretString` (or `SecretBox<T>`).**
   Logging or `Debug`-printing the wrapped value yields `[REDACTED]`.
   Calling `.expose_secret()` and then logging the result re-leaks. Don't.

9. **No panics in production code paths.** `unwrap_used = "deny"`,
   `panic = "deny"`, `todo = "deny"`, `unimplemented = "deny"` are set
   in `Cargo.toml`. Use `Result<T, RmcpServerKitError>`.

10. **`unsafe_code = "forbid"`** at the crate level. There is no `unsafe`
    in this codebase and there should never be.

---

## See also

- [`MINDMAP.md`](MINDMAP.md) - the same information, but visual.
- [`../AGENTS.md`](../AGENTS.md) - quick-orientation hub for agents.
- [`GUIDE.md`](GUIDE.md) - consumer-facing usage examples.
- [`../RUST_GUIDELINES.md`](../RUST_GUIDELINES.md) - index of the vendored coding standards; the core is at [`rust-guidelines/RUST_GUIDELINES.md`](rust-guidelines/RUST_GUIDELINES.md).
