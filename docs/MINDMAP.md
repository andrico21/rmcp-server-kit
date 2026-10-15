# rmcp-server-kit - Project Mindmap

> Visual map of the `rmcp-server-kit` crate. Pair with [`AGENTS.md`](../AGENTS.md) and
> [`ARCHITECTURE.md`](ARCHITECTURE.md). All file:line references use the
> code as of `rmcp-server-kit` 1.6.0.

---

## High-level mindmap

```mermaid
mindmap
  root((rmcp-server-kit<br/>1.6.0))
    Identity
      Library crate
      No src/main.rs
      Edition 2024
      MSRV 1.99.0
      Dual MIT / Apache-2.0
      Repos
        GitHub andrico21/rmcp-server-kit
        crates.io rmcp-server-kit
    Purpose
      Reusable framework
      MCP servers in Rust
      Streamable HTTP transport
      Wraps rmcp 3
      Consumers supply ServerHandler
    Modules src/
      lib.rs
        Crate root
        Re-exports public API
      transport.rs ★
        serve fn ~L1275
        serve_stdio fn ~L2241
        McpServerConfig L73-355
        impl McpServerConfig L359-700
        ReloadHandle ~L712
        build_app_router ~L810
        TlsListener ~L1904
        shutdown_signal ~L2018
        origin_check_middleware def ~L2151 / wired ~L1228
        security_headers_middleware def ~L2082 / wired ~L1115
      auth.rs
        AuthIdentity L40-58
        AuthState struct L621
        AuthState.api_keys L623
        Argon2 hashing
        auth_middleware ~L970
      rbac.rs
        RbacPolicy L329
        ArgumentAllowlist L226
        RoleConfig L174
        Task-locals L83-145
          current_role
          current_identity
          current_token
          current_sub
        rbac_middleware L584-700
        enforce_tool_policy L701
        build_tool_rate_limiter L53
      bounded_limiter.rs
        BoundedKeyedLimiter L93
        Memory cap + LRU prune
        Backs RBAC per-IP/per-tool limiter
      oauth.rs feature=oauth
        OAuthConfig::validate L390
        JwksCache impl L878
        JwksCache::validate_token L974
        JwksCache::validate_token_with_reason L984
        select_jwks_key L2110
        refresh_with_cooldown L2262
        JWKS_REFRESH_COOLDOWN ~L1800
        JWKS key cap (fail-closed default 256)
        Discovery endpoints
        OAuth proxy routes
      ssrf.rs
        Per-hop SSRF guard
        scheme/userinfo/IP-literal blocks
        Used by JWKS, CRL, OAuth proxy fetches
      mtls_revocation.rs
        CrlSet
        note_discovered_urls
        DynamicClientCertVerifier
        bootstrap_fetch L889
        run_crl_refresher
      tool_hooks.rs
        HookedHandler L219
        impl HookedHandler L240
        before_call hook
        after_call hook
        Result-size cap
      admin.rs
        require_admin_role L133
        admin_router L160
        /admin/* router
        Diagnostics
        Admin role gated
      observability.rs
        init_tracing_from_config L39
        init_tracing L118
        JSON logs
        Audit-file sink L170
      metrics.rs feature=metrics
        McpMetrics L26
        serve_metrics L95
        Prometheus registry
        /metrics listener
        Recording middleware
      config.rs
        TOML schema
        Validation
        apply_to_mcp_config bridge
        apply_env_overrides (opt-in)
        EnvOverride audit report
      error.rs
        RmcpServerKitError
        IntoResponse mapping
      secret.rs
        secrecy re-exports
    Endpoints
      Open
        /healthz
        /version
      Conditional
        /readyz
        /metrics feature=metrics
        /.well-known/oauth-* feature=oauth
      Admin gated
        /admin/*
      Authenticated
        /mcp rmcp service
    Auth modes
      API key
        Bearer token
        Argon2 hash compare
        ArcSwap hot reload
      mTLS
        TlsListener captures cert
        Keyed by SocketAddr
        x509-parser CN/SAN
        CDP-driven CRL revocation
          Auto-discover from CA chain + client certs
          reqwest fetcher + in-memory cache
          nextUpdate refresh clamped 10min..24h
          Hot-swap verifier via ArcSwap
          Fail-closed default; fail-open opt-out
          SSRF guard
            scheme allowlist http/https only
            userinfo rejected
            private/loopback/link-local/metadata IPs blocked
            redirect=none for CRL traffic
            crl_max_concurrent_fetches default 4
            crl_max_response_bytes default 5 MiB
            crl_discovery_rate_per_min default 60 per-peer with global fallback
            commit-after-admission ordering
      OAuth 2.1 JWT
        JWKS verify
        Cache + cooldown
        Feature gated
        OauthHttpClient
          with_config preferred
          new deprecated
          HTTPS to HTTP redirect rejected
          HTTP to HTTP gated by allow_http_oauth_urls
          Hardening
            OAuthConfig::validate rejects userinfo and literal IPs across all 6 URL fields incl. issuer
            Per-hop range-based redirect-target guard on OauthHttpClient and JwksCache redirect closures
            JwksCache key cap fail-closed default 256
            Closures stay sync no async DNS
    Middleware order
      outer to inner
      0 Security headers
      1 Origin check
      2 Peer-address normalize
      2b Request log request_log_middleware
      3 CORS
      4 Compression
      5 Body size cap
      6 Timeouts
      7 Concurrency cap optional
      8 Metrics optional
      9 Auth
      10 RBAC
      11 Per-IP tool rate limit
      12 rmcp StreamableHttpService
    State plane
      ArcSwap lock-free
        AuthState.api_keys
        rbac_swap RbacPolicy
      Per-connection extension
        mTLS AuthIdentity on TlsConnInfo
      Task-local
        Set by middleware
        Read by tool handlers
        Does NOT cross spawn
    Hot reload
      ReloadHandle
        reload_auth_keys
        reload_rbac
      No restart needed
      Eventually consistent
    Cargo features
      oauth off-default
        jsonwebtoken
        reqwest
        urlencoding
      metrics off-default
        prometheus
    Tech stack
      Async tokio 1
      HTTP axum 0.8
      Tower middleware
      TLS rustls 0.23 ring
      Errors thiserror anyhow
      Tracing tracing-subscriber
      Hashing argon2
      Rate limit governor
      Secrets secrecy
      Hot swap arc-swap
      Serde + serde_json + toml
    Tests + Examples
      tests/unit/ one crate per file no I/O
      tests/integration/e2e.rs
        spawn_server L499
        Real server on ephemeral ports
        Integration cookbook
      tests/integration/delegation_guard.rs
        rmcp ServerHandler surface from the pinned source
        Wrapper impl presence and macro-origin pins
        SEMANTIC_DRIVERS completeness gate
      examples/minimal_server.rs
        Smallest consumer
        cargo run --example minimal_server
    Build / verify
      cargo build --all-features
      cargo test --all-features
      cargo +nightly-2026-10-03 fmt --all -- --check
      cargo clippy --all-targets --all-features -- -D warnings
      cargo doc --no-deps --all-features
      cargo audit
      cargo deny check
      CARGO_BUILD_WARNINGS=allow RUSTFLAGS=--cap-lints=warn cargo +1.99.0 build --all-features
      cargo semver-checks check-release
    CI / policy
      .github/workflows/ci.yml canonical
      .gitlab-ci.yml mirror
      clippy.toml thresholds
      deny.toml license + ban
      .cargo/audit.toml
      rustfmt.toml
      scripts/lint-ratchet/ catalog allow profile_eq prose dash
      .cargo/config.toml build.warnings deny
    Coding standards
      RUST_GUIDELINES.md index + docs/rust-guidelines/ vendored
      No unwrap / expect prod
      No panic / todo / unimplemented
      No println / eprintln / dbg
      No unsafe forbidden
      No clone to dodge borrowck
      No std::sync::Mutex across await
      Use tracing macros
      Use Result + RmcpServerKitError
      Use current-Rust idioms
        Vec::push_mut
        Atomic::update
        cfg_select!
    Docs in repo
      AGENTS.md hub
      docs/ARCHITECTURE.md deep ref
      docs/MINDMAP.md this file
      docs/GUIDE.md consumer guide
      docs/MIGRATION.md
      docs/RELEASING.md
      docs/RUST_1_95_NOTES.md
      README.md quick start
      CHANGELOG.md
      CONTRIBUTING.md
      SECURITY.md
      CODE_OF_CONDUCT.md
    Critical pitfalls
      Middleware order is security
      JWKS refresh rate-limited
      Task-local lost across spawn
      stdio bypasses ALL security
      mTLS keyed by SocketAddr
      ArcSwap eventually consistent
      Never log secrets / tokens
```

---

## Request lifecycle (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant TLS as `TlsListener`<br/>src/transport.rs:3737
    participant R as axum Router
    participant O as `origin_check_middleware`<br/>src/transport.rs:5244
    participant H as `security_headers_middleware`<br/>src/transport.rs:4453
    participant A as `auth_middleware`<br/>src/auth.rs:2768
    participant B as `rbac_middleware`<br/>src/rbac.rs:1354
    participant L as per-IP rate limit<br/>governor + bounded_limiter
    participant M as rmcp Streamable<br/>HTTP service
    participant T as ServerHandler<br/>(consumer impl)

    C->>TLS: HTTPS connect (TLS / mTLS)
    TLS->>TLS: record_mtls_identity (if client cert)
    TLS->>R: HTTP request + peer SocketAddr
    R->>O: route /mcp
    O->>H: origin allowed
    H->>A: security headers attached
    A->>A: API key (Argon2) | mTLS lookup | OAuth JWT
    A-->>R: 401 if invalid
    A->>B: AuthIdentity in task-local
    B->>B: parse JSON-RPC, check tool policy<br/>+ argument allowlist
    B-->>R: 403 if denied
    B->>L: per-IP per-tool token bucket
    L-->>R: 429 if exceeded
    L->>M: pass through
    M->>T: dispatch tools/call (optionally via HookedHandler)
    T-->>M: ToolResult
    M-->>C: JSON-RPC response (streamed)
```

---

## State + hot-reload plane

```mermaid
flowchart LR
    subgraph Admin["Admin / operator"]
        RH[`ReloadHandle`<br/>src/transport.rs:2019]
    end

    subgraph SharedState["Shared state (lock-free / fine-grained)"]
        AKS[(ArcSwap&lt;ApiKeys&gt;<br/>`AuthState` api_keys<br/>src/auth.rs:1751)]
        RBS[(ArcSwap&lt;RbacPolicy&gt;<br/>rbac_swap)]
        MTL[mTLS `AuthIdentity`<br/>per-connection<br/>TlsConnInfo extension<br/>src/auth.rs:76]
    end

    subgraph Hot["Request-time consumers"]
        AM[`auth_middleware`<br/>src/auth.rs:2768]
        BM[`rbac_middleware`<br/>src/rbac.rs:1354]
        TL["Task-locals<br/>`current_role` / `current_identity`<br/>`current_token` / `current_sub`<br/>src/rbac.rs:158-220"]
        TH[`HookedHandler`<br/>src/tool_hooks.rs:335]
    end

    RH -- reload_auth_keys --> AKS
    RH -- reload_rbac --> RBS

    AKS --> AM
    MTL --> AM
    AM -- sets --> TL
    AM --> BM
    RBS --> BM
    BM -- enriches --> TL
    TL --> TH
    TH --> Consumer[Consumer ServerHandler]
```

---

## Module dependency graph

```mermaid
graph TD
    lib[lib.rs<br/>public API surface]
    transport[transport.rs<br/>★ serve / serve_stdio<br/>router + middleware + TLS]
    auth[auth.rs<br/>API key + mTLS + AuthState]
    rbac[rbac.rs<br/>policy + task-locals + rate limit]
    bl[bounded_limiter.rs<br/>memory-bounded keyed limiter]
    oauth["oauth.rs<br/>JWT + JWKS<br/>(feature=oauth)"]
    ssrf[ssrf.rs<br/>per-hop SSRF guard]
    mtlsr[mtls_revocation.rs<br/>CRL fetcher + verifier]
    admin[admin.rs<br/>/admin/*]
    hooks[tool_hooks.rs<br/>HookedHandler]
    obs[observability.rs<br/>tracing + audit]
    metrics["metrics.rs<br/>Prometheus<br/>(feature=metrics)"]
    config[config.rs<br/>TOML schema<br/>+ bridge + env overrides]
    error[error.rs<br/>RmcpServerKitError]
    secret[secret.rs<br/>secrecy re-exports]

    lib --> transport
    lib --> auth
    lib --> rbac
    lib --> oauth
    lib --> admin
    lib --> hooks
    lib --> obs
    lib --> metrics
    lib --> config
    lib --> error
    lib --> secret

    transport --> auth
    transport --> rbac
    transport --> oauth
    transport --> mtlsr
    transport --> admin
    transport --> hooks
    transport --> obs
    transport --> metrics
    transport --> config
    transport --> error

    auth --> error
    auth --> secret
    rbac --> error
    rbac --> auth
    rbac --> bl
    oauth --> error
    oauth --> auth
    oauth --> ssrf
    mtlsr --> ssrf
    mtlsr --> error
    admin --> auth
    admin --> rbac
    hooks --> error
    metrics --> error
    config --> error
```

---

## Key navigation table

| Area                              | Module / file                           | Notable symbols (file:line)                                                  |
|-----------------------------------|------------------------------------------|-------------------------------------------------------------------------------|
| Server entry (HTTP)               | `src/transport.rs`                       | `serve` L3064, `McpServerConfig` L482, `ReloadHandle` ~L2019              |
| Server entry (stdio, no auth)     | `src/transport.rs`                       | `serve_stdio` L5589                                                          |
| Router builder + middleware wire  | `src/transport.rs`                       | `build_app_router` L2347; security headers, peer-addr normalization, request logging, and origin checks are wired there |
| TLS / mTLS acceptor               | `src/transport.rs`                       | `TlsListener` L3737                                                          |
| Origin / security headers (defs)  | `src/transport.rs`                       | `origin_check_middleware` L5244, `security_headers_middleware` ~L4453       |
| Graceful shutdown                 | `src/transport.rs`                       | `shutdown_signal` L4271                                                      |
| API key + mTLS auth               | `src/auth.rs`                            | `AuthIdentity` L76, `AuthState` ~L1749, `auth_middleware` L2768              |
| RBAC engine                       | `src/rbac.rs`                            | `RbacPolicy` L709, `current_role` L158, `current_identity` L180, `current_token` L202, `current_sub` L220, `rbac_middleware` L1354           |
| Memory-bounded keyed limiter      | `src/bounded_limiter.rs`                 | `BoundedKeyedLimiter` L158                                                    |
| Trusted-forwarder resolution      | `src/forwarded.rs`                       | `resolve_client_ip`, `FallbackReason` (rightmost-untrusted, fail-safe-to-direct) |
| OAuth JWT / JWKS                  | `src/oauth.rs` (feature `oauth`)         | `JwksCache` L3146, `JWKS_REFRESH_COOLDOWN` ~L3337, `select_jwks_key` L4020 |
| SSRF guard (outbound HTTP)        | `src/ssrf.rs`                            | per-hop scheme/userinfo/IP-literal blocks                                     |
| mTLS revocation (CRL)             | `src/mtls_revocation.rs`                 | `CrlSet` L330, `DynamicClientCertVerifier` L1745, `bootstrap_fetch` L2172       |
| Tool hooks / size cap             | `src/tool_hooks.rs`                      | `HookedHandler` L335                                                          |
| Admin diagnostics                 | `src/admin.rs`                           | `require_admin_role` L182, `admin_router` L209                                |
| Tracing / audit log               | `src/observability.rs`                   | `init_tracing_from_config` L96, `AuditWorkerGuard` L378                              |
| Prometheus metrics                | `src/metrics.rs` (feature `metrics`)     | `McpMetrics` L49, `serve_metrics` L220                                         |
| Configuration (TOML)              | `src/config.rs` + `src/transport.rs`     | TOML schema + `McpServerConfig`                                               |
| Error → HTTP mapping              | `src/error.rs`                           | `RmcpServerKitError` L46, `IntoResponse` L170                                           |
| Integration reference             | `tests/integration/e2e.rs`               | `spawn_server` L507                                                           |
| Runnable examples                 | `examples/`                              | `minimal_server.rs`, `api_key_rbac.rs`, `oauth_server.rs`                    |

---

## How to read this mindmap

1. **Start at the root** - confirms crate identity (library, edition, MSRV).
2. **Modules branch** - every parseable citation to a `src/*.rs` file includes its key symbol and file:line ref.
3. **Endpoints / Auth modes / Middleware order** - runtime surface of the server.
4. **State plane / Hot reload** - how `ArcSwap` and task-locals coordinate.
5. **Critical pitfalls** - checklist before proposing any change.

For prose explanations of each branch, jump to the matching section in
[`ARCHITECTURE.md`](ARCHITECTURE.md). For workflow rules and "where do I
change X?" lookups, see [`AGENTS.md`](../AGENTS.md).
