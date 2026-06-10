# Changelog

All notable changes to `rmcp-server-kit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Breaking changes bump the **major** version.

## [Unreleased]

## [1.11.0] - 2026-06-10

### Added

- **Opt-in per-IP rate limiting for `with_extra_router` routes** (closes
  [#10](https://github.com/andrico21/rmcp-server-kit/issues/10)):
  `McpServerConfig::with_extra_route_rate_limit(per_minute)` and the
  matching TOML field `server.extra_route_rate_limit`. When set, the
  application's extra router is wrapped — pre-merge, so the limiter can
  never leak onto `/mcp`, health, admin, or OAuth endpoints — in a
  per-source-IP limiter backed by the same memory-bounded machinery as
  the tool limiter (10,000 tracked keys, 15-minute idle eviction). On
  limit: `429` with a plain-text body, matching the tool/auth limiters
  (no `Retry-After`; adding it uniformly across all limiters is tracked
  separately). Keyed by the direct socket peer (no `X-Forwarded-For`
  interpretation); fails open when no peer address is present; the
  value must be greater than zero (validated at startup); startup-only
  (not hot-reloadable).

## [1.10.0] - 2026-06-10

### Added

- **Uniform client peer-address exposure for application routes**
  (requested by a downstream consumer running chained-OAuth endpoints on
  `with_extra_router` under direct TLS):
  - New public `transport::PeerAddr` request extension (`#[non_exhaustive]`,
    `Copy`/`Eq`/`Hash`) carrying the direct socket peer address, inserted
    on **both** the plain and the TLS listener and extractable via its
    `FromRequestParts` impl or `Extension<PeerAddr>` — including from
    `with_extra_router` routes, which bypass auth/RBAC. Direct peer only
    (no `X-Forwarded-For` interpretation); absent under `serve_stdio`;
    never logged by the framework.
  - The TLS listener now also mirrors the peer address into the standard
    `axum::extract::ConnectInfo<SocketAddr>` extension (insert-only-when-
    absent), so stock per-IP middleware (e.g. `tower_governor`'s
    `PeerIpKeyExtractor`) works unmodified on direct-TLS deployments
    instead of failing every request. `TlsConnInfo` (and the mTLS
    identity it carries) remains private and connection-bound.

## [1.9.0] - 2026-06-10

### Added

- **TLS accept-path tuning knobs** (closes
  [#9](https://github.com/andrico21/rmcp-server-kit/issues/9)):
  `McpServerConfig::with_tls_handshake_timeout(Duration)` and
  `McpServerConfig::with_max_concurrent_tls_handshakes(usize)`, plus the
  matching TOML fields `server.tls_handshake_timeout` (humantime string)
  and `server.max_concurrent_tls_handshakes`. Defaults are unchanged
  (10 s / 256). Both values must be greater than zero (validated in
  `McpServerConfig::validate` and `validate_server_config`) and are
  **startup-only** — they bind at listener construction and do not
  participate in `ReloadHandle` hot reload. The completed-handshake
  channel capacity remains internal.

### Fixed

- **Removed markdown backticks from the azp-only audience deprecation
  warning.** The one-shot `tracing::warn!` emitted in
  `AudienceValidationMode::Warn` carried rustdoc-style backticks into
  terminal/JSON log output; the message is now plain text, matching the
  crate's logging style. No behavior change.

## [1.8.2] - 2026-06-10

### Security

- **The SSRF IP range guard now classifies IPv6 transition prefixes.**
  NAT64 (`64:ff9b::/96`, RFC 6052) and 6to4 (`2002::/16`, RFC 3056)
  addresses are blocked when the IPv4 address they embed is itself
  blocked (closing e.g. `64:ff9b::10.0.0.1` reaching internal RFC 1918
  space through a NAT64 gateway) while remaining permitted for embedded
  public addresses, so DNS64/NAT64-only egress networks keep working.
  Teredo (`2001::/32`, RFC 4380) is blocked outright. Applies to both the
  CRL and OAuth/JWKS fetch paths; see SECURITY.md "IPv6 transition
  prefixes".

### Changed

- **`JwksCache::new` returns an error instead of panicking when
  `jwks_cache_ttl` is not a valid humantime duration.** The documented
  panic existed only for unvalidated configs (the `OAuthConfig::validate`
  pipeline rejects invalid TTLs up front); the function signature already
  returned `Result`, so the failure now surfaces through it.
- **Deduplicated OAuth SSRF target screening (internal).** The screening
  logic previously existed twice: a test-instrumented copy and a
  byte-identical production copy compiled only under
  `cfg(not(any(test, feature = "test-helpers")))` — meaning the test suite
  never compiled the production branch and a future edit could silently
  diverge the two. Both paths now delegate to one shared core
  (`screen_oauth_target_core`) compiled identically under all cfgs, with
  the loopback bypass plumbed as a parameter that production hardcodes to
  `false`. No behavior change; error messages are byte-identical.
- **Lint hardening (internal):** enabled `clippy::string_slice` (warn,
  escalated to deny in CI) and pinned `clippy::await_holding_lock` to
  deny. Manual `&str[range]` slicing in the RBAC glob matcher and the
  origin auto-derivation was rewritten with checked `get(..)` accessors —
  behavior is unchanged under the existing char-boundary invariants, and
  a future invariant violation now degrades to a non-match instead of a
  panic.
- **Corrected the `log_format` field documentation** to list all three
  accepted values (`json`, `pretty`, `text`) and the actual default
  (`pretty`); the validator already accepted all three.

### Fixed

- **TLS accept loop no longer serializes handshakes (idle-connection
  denial of service).** `TlsListener::accept` previously performed each
  TLS handshake inline before accepting the next connection, so a single
  idle TCP connection (e.g. `nc host 8443` sending no bytes) stalled ALL
  new connections indefinitely. TCP accepts and TLS handshakes now run on
  a dedicated background task that spawns each handshake onto its own
  worker, bounded by a 256-handshake in-flight cap (with kernel-backlog
  backpressure at saturation) and a 10-second per-handshake timeout. The
  handshake-time mTLS identity extraction and its binding to the
  connection stream are unchanged.
- **CRL timestamps outside the platform-representable `SystemTime` range no
  longer panic the CRL refresher.** `thisUpdate`/`nextUpdate` values are
  parsed from raw fetched CRL bytes before signature validation, so they are
  attacker-controlled; a pre-1601 timestamp (unrepresentable by Windows
  `SystemTime`) previously panicked the spawned refresher task, silently
  halting CRL discovery and refresh for the process lifetime. Conversion now
  uses checked arithmetic and clamps unrepresentable or absurd values toward
  `UNIX_EPOCH` — the safe direction (a clamped timestamp can only make a CRL
  look older, forcing an eager refresh, never fresher).
- **The per-host CRL fetch semaphore cap no longer permanently locks out new
  CRL hosts.** Previously, once `crl_max_host_semaphores` (default 1024)
  distinct CRL hosts had ever been seen, fetches for any NEW host failed
  with `crl_host_semaphore_cap_exceeded` until process restart — an
  attacker presenting client certificates with unique CDP hostnames could
  poison the map permanently. At the cap, idle entries (no in-flight fetch)
  are now evicted on demand; the cap error remains only for genuinely
  concurrent fetch floods across `crl_max_host_semaphores` distinct hosts.


## [1.8.1] - 2026-06-05

### Changed

- **Renamed build-time environment variables to match the crate name.**
  The `/version` endpoint now reads `RMCP_SERVER_KIT_BUILD_SHA`,
  `RMCP_SERVER_KIT_BUILD_TIME`, and `RMCP_SERVER_KIT_RUSTC_VERSION` (via
  `option_env!`) instead of the legacy `MCPX_BUILD_SHA`,
  `MCPX_BUILD_TIME`, and `MCPX_RUSTC_VERSION` names. Build pipelines that
  populate these variables at compile time must update their CI / build
  scripts; otherwise the affected `/version` fields silently fall back to
  `"unknown"`. The runtime JSON shape (`build_git_sha`, `build_timestamp`,
  `rust_version`, `mcpx_version`) and all public API surface are
  unchanged.

## [1.8.0] - 2026-06-04

### Changed

- **Raised the minimum supported `rmcp` version from `1.5` to `1.7`.** The
  crate is built and tested exclusively against `rmcp 1.7.x` in CI, so the
  declared floor now matches the version actually exercised rather than
  claiming support for a range that CI never verifies. The public API is
  unchanged and the code still compiles and passes the full test suite
  against `rmcp 1.5.0`; this bump tightens the dependency requirement only.
  Downstream consumers pinned below `rmcp 1.7` must update their own `rmcp`
  requirement accordingly.

## [1.7.7] - 2026-06-04

### Dependencies

- **Bumped the `shlex` constraint `1.3` → `2`.** The RBAC argument-allowlist
  splitter consumes only `shlex::split`, whose behaviour is identical across
  the two lines; shlex 2.0 merely *removed* the deprecated `quote`/`join`
  APIs (subject of RUSTSEC-2024-0006) and an unsound `DerefMut` impl, none of
  which this crate uses. The bump collapses the duplicate `shlex` copy that
  was otherwise pulled in transitively (via `cc`), so the resolved graph now
  carries a single `shlex 2.0.1`. The `rbac` tokenization regression suite
  (`src/rbac.rs`) passes unchanged, confirming behaviour parity.
- **Validated the crate against the latest semver-compatible dependency
  versions** (minor/patch only; `Cargo.lock` remains intentionally untracked
  for this library crate). Confirmed clean against notable upstream releases
  including the `rmcp` MCP SDK and `rmcp-macros` `1.5.0 → 1.7.0`, `rustls`
  `0.23.38 → 0.23.40`, `tower-http` `0.6.8 → 0.6.11`, `jsonwebtoken`
  `10.3.0 → 10.4.0`, `reqwest` `0.13.3 → 0.13.4`, `hyper` `1.9 → 1.10.1`, and
  `tokio` `1.52.1 → 1.52.3`. Full build, Clippy (`-D warnings`), and the
  complete test suite (`--all-features`) all pass unchanged.

## [1.7.6] - 2026-05-20

### Security / Hardening

- **`SeenIdentitySet` is now memory-bounded** (M2). The internal
  first-seen-identity log-dedup table in `src/auth.rs` previously used
  an unbounded `Mutex<HashSet<String>>`, which grew with attacker-
  influenced identity churn (mTLS SAN/CN or OAuth `sub`) until process
  exit. Replaced with a bounded FIFO set capped at 4096 entries
  (~256 KiB at 64-byte names). Poison-tolerant `Mutex` with explicit
  `SAFETY:` rationale. Honest clients never trigger eviction; hostile
  churn is bounded. Internal type, no public API change.

### Quality / lint hygiene

- **Spelled out test fixtures** (M1). Replaced 9 `..Default::default()`
  shorthand uses across `src/auth.rs` and `src/transport.rs` test modules
  with explicit per-field initialisation, making the assertions readable
  without cross-referencing the type's `Default` impl.
- **Demoted speculative `TODO(refactor):` markers to `NOTE:`** (L1) at
  `src/rbac.rs:647` and `src/transport.rs:850` — these are documented
  design trade-offs, not pending work.
- **Added `reason = "..."` justifications** to remaining `#[allow]` /
  `#[expect]` attributes (L2 / L3 / Q5): `src/auth.rs:1031`,
  `src/transport.rs:2124`, `src/oauth.rs:2376`, plus the test-module
  inner attributes in `src/config.rs`, `src/metrics.rs`,
  `src/observability.rs`, `src/cancel.rs`, and the crate-level
  `#![cfg_attr(test, allow(...))]` in `src/lib.rs`.
- **Added `clippy::panic_in_result_fn` to the crate-level test-only
  allow list** (Q8) in `src/lib.rs` as cheap future-proofing for
  `Result`-returning `#[tokio::test]` bodies.
- **`SAFETY:` comment** (M3) added to the `Mutex` poison-recovery path
  in `SeenIdentitySet::insert_is_first` explaining why continuing past
  poison preserves correctness.
- **Removed unused `use std::sync::Mutex`** in `src/admin.rs` (bonus
  cleanup surfaced during M2).

### Docs

- **Clarified `SeenIdentitySet` as FIFO, not LRU** (Q3). The type's
  rustdoc and the call-site comment in `AuthState::log_auth` now
  consistently say "bounded FIFO set" instead of the previously vague
  "LRU-style". Added a unit test
  (`seen_identity_set_fifo_does_not_refresh_on_repeat_hit`) that locks
  in the FIFO contract by asserting repeat hits do **not** bump an
  entry's eviction position.
- **Clarified the global CRL discovery limiter** (Q13) at
  `src/auth.rs:467-477` and `src/mtls_revocation.rs:117-125`. The
  comments now explicitly note that this limiter is **distinct** from
  the bearer pre-auth limiter (which is already keyed per-IP via a
  bounded keyed governor in the ordinary request middleware path).
- **Scoped the typed pre-tokenized argument matcher** (Q18) as a
  `NOTE(future-pr):` design block above `ArgumentAllowlist` in
  `src/rbac.rs`. Captures Oracle-approved scope: keep public
  `ArgumentAllowlist` shape stable, add a private compiled IR owned by
  `RbacPolicy::new`, with a required equivalence test matrix.
- **Marked the deferred `#[must_use]` on `with_hooks`** (Q15) with a
  `NOTE(next-minor):` comment in `src/tool_hooks.rs:239` so the next
  minor-bump owner finds the deferred semver-minor change.

## [1.7.5] - 2026-05-20

### Changed

- **Lints: tightened `clippy::expect_used` from `allow` to `deny`** at the
  crate level. The five legitimate production `.expect()` sites
  (`auth.rs` `DUMMY_PHC_HASH` PHC string construction, fixed-salt Argon2
  hash; `oauth.rs` re-parsing the already-validated `jwks_cache_ttl`;
  `rbac.rs` HMAC key construction from a 32-byte SHA-256 digest) now
  carry per-site `#[allow(clippy::expect_used, reason = "...")]`
  attributes that pin the safety argument next to the call. Closes the
  asymmetry where `unwrap_used = "deny"` was bypassable via `.expect()`
  with no machine-checked justification. Existing test files already
  carry the `expect_used` allow at file scope; one (`oauth_url_validation.rs`)
  was updated to match the convention.

- **API: removed `impl Deref<Target = T> for Validated<T>`** in
  `transport.rs`. `Validated<T>` is a typestate proof-of-validation
  newtype; exposing `Deref` made the validation marker easy to lose at
  call sites via implicit auto-deref. Use [`Validated::as_inner`] for
  read-only borrowing or [`Validated::into_inner`] to recover the raw
  value. The two `serve()` variants already called `into_inner()`
  immediately, so the change is observable only through the test
  helper and any downstream caller that wrote `*validated` or
  `validated.<field>` instead of `validated.as_inner().<field>`.

  **Migration**: replace `*validated` / `&*validated` with
  `validated.as_inner()`, and `validated.<field>` with
  `validated.as_inner().<field>`. The doc-comment on `Validated`
  reflects the new access pattern.

- **Lint attributes: upgraded four `#[allow(clippy::...)]` allows to
  `reason = "..."` form** in `rbac.rs` (`rbac_middleware`),
  `transport.rs` (`build_app_router`, `serve_stdio`), and `oauth.rs`
  (`select_jwks_key`). The justifications previously lived in adjacent
  comments only; they are now attached to the attribute itself so they
  travel with the suppression in lint reports.

- **CI: re-enabled the `cargo-semver-checks` job on pull requests.** Disabled
  for the 1.6.0 H3 break (`Option<String>` -> `Option<RfcTimestamp>` on
  `ApiKeyEntry::expires_at`); the intentional break shipped, became the
  published baseline on crates.io, and was followed by purely additive
  releases (1.7.4 added the `cancel` module and `McpxError::RetryableTimeout`).
  Locally verified clean against the published baseline (222 checks pass,
  no semver update required).

## [1.7.4] - 2026-05-19

### Added

- **`cancel` module: `run_with_cancel_and_timeout` for cancel-safe
  tool handlers.** Solves the "drop mid-`.await`" hazard when a
  `tokio::select!` arm racing `CancellationToken::cancelled()` or
  `tokio::time::sleep(timeout)` wins against a long-running future
  that owns a remote-side resource (SSH channel, in-flight HTTP
  body, DB transaction). Spawning the future onto `tokio::spawn`
  first and racing the `JoinHandle` (without `.abort()`) lets the
  inner future complete its own cleanup path while the caller
  returns cancel/timeout to the client immediately. `DetachOutcome`
  is `#[non_exhaustive]` and `#[must_use]`. The originating
  tracing span is preserved via `.instrument(Span::current())`.
  Task-local RBAC scope is intentionally NOT propagated into the
  detached task -- detached work should finish or close
  already-authorized resources rather than initiate fresh
  RBAC-gated operations; the module-level `# Caveats` rustdoc
  shows how to capture and rebind RBAC context for callers that
  genuinely need it. Originally implemented in the downstream
  `podmcp` crate to close that crate's M-6 deferred-audit finding.

## [1.7.3] - 2026-05-15

### Changed

- **Deps: routine dependency refresh.** Bumped runtime crates `rmcp`
  `1.6 -> 1.7` (via `cargo update`, semver-compatible),
  `hmac` `0.12 -> 0.13`, `sha2` `0.10 -> 0.11`. The `hmac` 0.13 release
  no longer re-exports `KeyInit` through the `Mac` trait, so
  `src/rbac.rs` was updated to import `hmac::KeyInit` explicitly at the
  single call-site that constructs `Hmac<Sha256>::new_from_slice`
  (HMAC seed for the redaction token derivation). No behavioural
  change, no public API change. Bumped dev/bench-only
  `criterion` `0.5 -> 0.8`; the bench harness uses only stable
  `criterion_group!` / `criterion_main!` / `Criterion::bench_function`
  / `black_box` APIs, so no source changes were required in
  `benches/`. Lockfile also picks up transitive `winnow` `1.0.2 ->
  1.0.3` patch. After this update every direct dependency in the
  manifest is at its latest crates.io stable; remaining lockfile
  duplications (`hmac 0.12+0.13`, `sha2 0.10+0.11`, `thiserror 1+2`,
  `rand 0.8+0.9+0.10`) are transitive-only and pinned by upstream
  leaf crates (`argon2`, `jsonwebtoken`, `rcgen`, `rsa`, `wiremock`,
  `prometheus`). The two `cargo update --verbose --dry-run`
  hold-backs (`crypto-common 0.1.6 -> 0.1.7`,
  `matchit 0.8.4 -> 0.8.6`) are unfixable from this repo:
  `matchit` is exact-version pinned (`=0.8.4`) by `axum 0.8.9` and
  `crypto-common` is held by transitive pins inside the RustCrypto
  v0.10 / `digest 0.10` ecosystem that `jsonwebtoken 10.4.0` and
  `argon2 0.5.3` still target. All 321 unit tests + 29 E2E tests
  pass on Rust 1.95.0 under `--all-features`; clippy clean with
  `-D warnings`; both benches execute end-to-end.

## [1.7.2] - 2026-05-15

### Fixed

- **Test: consolidate the M-H2 env-proxy matrix into a single
  sequential test to eliminate a Windows CI race**
  (`tests/ssrf_resolver.rs`). The six per-variant tests
  (`no_proxy_defeats_*`) each invoked `temp_env::with_var` to mutate
  process-wide environment variables (`HTTP_PROXY` / `HTTPS_PROXY` /
  `ALL_PROXY` upper- and lower-case) before constructing an
  `OauthHttpClient`. Rust's default test runner runs `#[test]` cases
  in parallel threads; the env-var mutations could leak across threads
  and into other concurrently-running tests on Windows runners
  (`Test (windows-latest)` failed on tag `1.7.1`). The matrix now
  runs as one sequential `#[test]` so all six variants are exercised
  without racing parallel tests. Coverage is preserved (still
  asserting `ssrf:` diagnostic for every variant).

## [1.7.1] - 2026-05-15

### Fixed

- **Build: replace runtime-RNG salt for the constant-time Argon2
  placeholder with a fixed salt** (`src/auth.rs`). The
  `DUMMY_PHC_HASH` was previously generated with
  `SaltString::generate(&mut argon2::password_hash::rand_core::OsRng)`,
  which depends on `rand_core 0.6`'s `getrandom` cargo feature being
  activated transitively. That feature is not turned on in any
  configuration of this crate (default, `--features metrics`,
  `--no-default-features`), so the build broke as soon as `argon2`'s
  re-exported `rand_core` was reached by name resolution. Switch to a
  fixed 16-byte salt (`SaltString::from_b64("AAAA...")`); the dummy
  hash never matches real input and is only used as a same-cost
  Argon2 verification target to flatten timing across slots, so salt
  randomness is irrelevant. Closes the post-release CI failure on
  `1.7.0` tag.

## [1.7.0] - 2026-05-15

### Security

- **M-H2: Outbound HTTP clients now close the TOCTOU window between
  pre-flight SSRF screening and connect-time DNS resolution**
  (`src/ssrf_resolver.rs`, `src/ssrf.rs`, `src/oauth.rs`,
  `src/mtls_revocation.rs`). Previously `screen_oauth_target` and
  `CrlSet::new` performed an `IpAddr` lookup, validated it against the
  cloud-metadata blocklist and operator allowlist, and then handed the
  request to `reqwest`, which independently re-resolved the hostname
  inside its own connector. A controlled-DNS attacker could pass the
  pre-flight check with a public IP and have the connector see a
  loopback / private / metadata answer microseconds later. Every
  outbound `reqwest::Client` now installs a custom
  `SsrfScreeningResolver` (`ClientBuilder::dns_resolver(...)`) that
  re-applies the same `ip_block_reason` + `CompiledSsrfAllowlist`
  policy on the addresses actually returned to the connector.
  Cloud-metadata short-circuits before the allowlist is consulted and
  remains unbypassable in every code path. The resolver fails closed
  with a `"ssrf:"`-prefixed error on policy denial so operators can
  distinguish deliberate denials from generic DNS failures. Defence in
  depth: every `ClientBuilder` also calls `.no_proxy()` to disable
  reqwest's auto-proxy detection, since `HTTP_PROXY` /
  `HTTPS_PROXY` / `ALL_PROXY` env vars would otherwise route DNS
  through the proxy and bypass the resolver entirely. Wired at all six
  outbound construction sites: `OauthHttpClient::build`,
  `build_mtls_clients`, `JwksCache::with_config`, the OAuth wiremock
  test harness, `CrlSet::new`, and `bootstrap_fetch`. Closes the last
  open finding from the 2026-05-13 deep code review.

### Added

- **`oauth-mtls-client` cargo feature** enabling RFC 8705 §2 mTLS
  client authentication for the OAuth token-exchange endpoint.
  Disabled by default; opt in via
  `rmcp-server-kit = { version = "1", features = ["oauth-mtls-client"] }`.
  See M-H4 entry under `### Security` for the full security rationale.
- **`ClientCertConfig::new(cert_path, key_path)`** constructor for the
  `#[non_exhaustive]` `ClientCertConfig` so downstream crates can build
  one without struct-literal syntax.

### Fixed

- **M4: `oauth.role_claim` now resolves first-class `Claims` fields**
  (`src/oauth.rs`). `resolve_role` previously only walked the `extra`
  map, so `role_claim = "sub"` (or `azp` / `client_id` / `aud` / `scope`)
  was silently treated as missing even when the JWT contained those
  standard fields. A new `first_class_claim_values` helper layers the
  RFC 7519 / RFC 8693 standard claims into the lookup, with `scope`
  whitespace-split per RFC 8693 §4.2 and `aud` returning every audience.
- **M7: Prometheus `/metrics` listener now participates in graceful
  shutdown** (`src/metrics.rs`, `src/transport.rs`). `serve_metrics`
  gained a `shutdown: CancellationToken` parameter and wires it into
  `axum::serve(...).with_graceful_shutdown(...)`, so cancelling the
  parent server's shutdown token now releases the metrics port instead
  of leaking it until process exit.

### Fixed

- **M5: `oauth.jwks_cache_ttl` is now validated up-front** (`src/oauth.rs`).
  Previously, a malformed `jwks_cache_ttl` (e.g. `"ten minutes"`) was
  silently swallowed by `unwrap_or(Duration::from_mins(10))` inside
  `JwksCache::new`, so the operator-configured TTL was ignored without
  any warning. `OAuthConfig::validate` now parses the string and rejects
  startup with a clear `McpxError::Config` on failure; `JwksCache::new`
  therefore relies on a typed invariant instead of a silent fallback.
- **M6: `max_concurrent_requests = Some(0)` is now rejected** at
  `McpServerConfig::validate` time (`src/transport.rs`). A zero cap would
  deadlock the global concurrency limiter and reject every request.
  Mirrors the equivalent TOML-side check already present in
  `src/config.rs`.
- **M8: `auth.rate_limit.max_tracked_keys = 0` is now rejected** at
  `McpServerConfig::validate` time (`src/transport.rs`). A zero cap would
  force the bounded keyed limiter to evict on every insert and
  effectively disable rate limiting. `BoundedKeyedLimiter::new` now also
  carries a `debug_assert!(max_tracked_keys > 0)` as defense-in-depth.

### Documentation

- **M9: `docs/GUIDE.md` configuration tables now match the actual `config.rs`
  schema**. Added previously-missing `ServerConfig` rows
  (`session_idle_timeout`, `sse_keep_alive`, `public_url`,
  `compression_enabled`, `compression_min_size`, `max_concurrent_requests`,
  `admin_enabled`, `admin_role`, `auth`), the `ObservabilityConfig`
  `log_request_headers` row, and the `OAuthConfig`
  `audience_validation_mode` row. The `stdio_enabled` row now warns that
  stdio bypasses auth/RBAC/TLS/Origin checks. The
  `strict_audience_validation` row is marked **Deprecated since 1.7.0**
  with the resolution semantics documented; the "new deployments"
  recommendation snippet now uses `audience_validation_mode = "strict"`.
- **M10: crate-level rustdoc on `src/lib.rs` expanded** with a runnable
  `no_run` quick-start example, a feature-flag overview (`oauth`,
  `metrics`, `test-helpers`), and a prominent security warning for
  `transport::serve_stdio` (which bypasses auth, RBAC, TLS, Origin
  validation, and rate limiting).

## [1.6.0] - 2026-05-13

### Security

- **Fail-closed RFC 3339 validation for API key `expires_at`** (`src/auth.rs`).
  Previously, a malformed `expires_at` string in the API key TOML file was
  silently treated as "never expires" because `chrono::DateTime::parse_from_rfc3339`
  errors inside `verify_bearer_token` were discarded. An operator who
  mistyped (e.g. `"2026-01-01"` instead of `"2026-01-01T00:00:00Z"`) would
  unknowingly ship a non-expiring key. Expiry strings are now parsed and
  validated **at TOML deserialization time** via a new `RfcTimestamp`
  newtype: any malformed value rejects server startup (or hot-reload) with
  a clear error pointing at the offending key. `verify_bearer_token` no
  longer needs to parse strings on the hot path.

### Changed (BREAKING — source compatibility)

> Shipped as **1.6.0** by maintainer policy: the only known downstream
> consumer (`atlassian-mcp-rs`, same maintainer) does not touch the
> affected API surface. `cargo-semver-checks` is temporarily disabled in
> CI with a `FIXME(H3-fix, 2026-05-13)` marker; re-enable on the next
> release with no public-API breaks.

- `ApiKeyEntry::expires_at` is now `Option<RfcTimestamp>` (was
  `Option<String>`).
- `ApiKeySummary::expires_at` is now `Option<RfcTimestamp>` (was
  `Option<String>`).
- `ApiKeyEntry::with_expiry` now takes `RfcTimestamp` (was
  `impl Into<String>`). For string input use the new
  `ApiKeyEntry::try_with_expiry(impl AsRef<str>) -> Result<Self, chrono::ParseError>`.
- `RfcTimestamp` (`Copy`) is now part of the public API in `src/auth.rs`;
  its on-the-wire form is `chrono`'s canonical RFC 3339 with `+00:00`
  (not `Z`) for UTC.

### Added

- **`RfcTimestamp` newtype** in `src/auth.rs` wrapping
  `chrono::DateTime<chrono::FixedOffset>` with a fail-closed `Deserialize`,
  `Display`/`Debug` via `to_rfc3339`, `parse`, `as_datetime`, and
  `into_inner`.
- **Mutation-coverage tests** for `glob_match` / `match_middle` boundary
  cases in `src/rbac.rs` and for `RbacPolicy::argument_allowed` glob-tool
  matching, killing five surviving mutants surfaced by the nightly
  `cargo mutants` job. Each test is annotated with the specific mutation
  it kills so the intent survives future refactors.
- **Exact-string contract tests** for `AuthFailureClass::as_str`,
  `response_body`, and `bearer_error` in `src/auth.rs`. These literals
  are part of the observable wire/log surface (metric labels, audit-log
  fields, OAuth `WWW-Authenticate` reasons); the tests pin them so a
  silent change becomes a test failure.
- **Boolean-flag contract tests** for `AuthConfig::summary` in
  `src/auth.rs`, asserting `bearer` is `true` iff `api_keys` is
  non-empty (kills the surviving `!`-deletion mutant at line 615) and
  pinning `enabled` / `mtls` / `oauth` propagation.
- **`RfcTimestamp` regression suite** (`src/auth.rs`) — eight tests covering
  malformed/valid parse, TOML deserialization fail-closed behavior,
  `try_with_expiry`, and `ApiKeySummary` JSON serialization wire format.

## [1.5.0] - 2026-04-29

### Added

- **Configurable security headers** (`src/transport.rs`) -- new
  `SecurityHeadersConfig` struct and `McpServerConfig::with_security_headers`
  builder method allow operators to override or omit any of the twelve
  OWASP security headers emitted by `security_headers_middleware`. Each
  field is `Option<String>` with a three-state semantic: `None` keeps the
  default, `Some("")` omits the header entirely, and `Some(value)` overrides.
  Non-empty values are validated via `HeaderValue::from_str` inside
  `McpServerConfig::validate()`; invalid values fail server startup. The
  `Strict-Transport-Security` field additionally rejects any value containing
  `preload` (case-insensitive) -- HSTS preload-list opt-in must be made via
  a dedicated future builder, not smuggled through this knob. Existing
  defaults are unchanged; this is a purely additive API surface change.

### Fixed

- **OAuth proxy** (`src/transport.rs`) -- `/token`, `/register`, `/introspect`,
  and `/revoke` responses now include `Pragma: no-cache` and
  `Vary: Authorization`, completing RFC 6749 §5.1 / RFC 6750 §5.4 compliance
  for OAuth proxy deployments. `Cache-Control: no-store` was already set
  globally by `security_headers_middleware`; this patch fills the remaining
  legacy-cache and `Vary` gaps. The new `oauth_token_cache_headers_middleware`
  is feature-gated (`oauth`) and only active when `OAuthConfig.proxy` is
  configured -- resource-server-only deployments are unaffected. `Vary` is
  appended (not replaced), preserving any pre-existing `Vary` value (e.g.
  `Accept-Encoding` from the compression layer).

## [1.4.1] - 2026-04-24

Patch release fixing a tokenization bug in `RbacPolicy::argument_allowed`
that prevented allowlist entries containing spaces from ever matching,
and tightening fail-closed handling of malformed shell input.

### Security

- **`Cargo.lock`** -- bump transitive `rustls-webpki` `0.103.12 -> 0.103.13`
  to pick up the fix for [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104).
  The advisory describes a reachable panic in
  `BorrowedCertRevocationList::from_der` /
  `OwnedCertRevocationList::from_der` when parsing a syntactically valid
  empty `BIT STRING` in the `onlySomeReasons` element of an
  `IssuingDistributionPoint` CRL extension. The panic is reachable
  before the CRL signature is verified, so any consumer that fetches
  CRLs via `mtls_revocation` would be exposed; consumers that do not
  use CRLs are unaffected. No code or API changes in this crate -- the
  fix is entirely a transitive dependency bump.

### Fixed

- **`src/rbac.rs`** -- `RbacPolicy::argument_allowed` now tokenizes
  argument values with POSIX-shell-like lexical rules (`shlex::split`)
  instead of `str::split_whitespace`. Allowlist entries containing
  spaces (e.g. `/usr/bin/my tool`) now match correctly when the value
  quotes the path per shell rules; previously they were unmatchable.
  Malformed shell syntax (unbalanced quotes, dangling escapes), empty
  `value`, and well-formed but empty first argv elements (e.g.
  `value = r#""""#`) now fail closed.

### Behavior change matrix

POSIX-shell-like tokenization is now the contract. The new behavior
diverges from `str::split_whitespace` in the cases below. We ship as a
patch because (a) the function signature is unchanged, (b) the
"now-allow" change unbreaks legitimately-quoted spaced paths, and
(c) every "now-deny" change is either malformed input or a
configuration that worked only by accident under whitespace splitting
and almost certainly diverged from the consumer's actual exec
tokenization downstream.

| Input class | 1.4.0 | 1.4.1 | Direction |
|---|---|---|---|
| Plain unquoted token (`ls`) | allow if listed | allow if listed | identical |
| Quoted path with embedded space (e.g. `"/usr/bin/my tool" --x`) | deny (broken) | allow if listed | stricter-correct |
| Unbalanced quote / dangling escape | accepts truncation | **deny** | stricter (security-positive) |
| Empty input string `""` | accepts `""` if listed | **deny** | stricter |
| Quoted empty token `r#""""#` | accepts `""` if listed | **deny** | stricter |
| Tab/newline separator | works incidentally | works per POSIX | identical in practice |
| Quoted-literal allowlist entry (e.g. `["'bash'"]` matching `'bash' -c true`) | allow | **deny** (shlex strips the surrounding quotes -> first token `bash`, not `'bash'`) | observable regression -- see operator notes |
| Backslash-literal allowlist entry (e.g. `[r"foo\bar"]`) | allow | **deny** (POSIX shlex treats `\` as escape -> first token becomes `foobar`) | observable regression -- see operator notes |
| Windows-style path allowlist entry (e.g. `[r"C:\Windows\System32\cmd.exe"]`) | allow | **deny** (POSIX shlex eats backslashes) | observable regression -- see operator notes |

### Notes for operators

- **POSIX-shell-like semantics only.** The matcher now models POSIX
  word-splitting + quote removal as performed by `shlex::split`. It
  does **not** model real shell *execution* (`FOO=1 cmd`, expansions,
  command substitution, redirections, operators) or Windows
  command-line tokenization (`CommandLineToArgvW`, `cmd.exe`,
  PowerShell). Consumers in those regimes still need their own
  validation at the boundary.
- **Backslash is an escape character** under POSIX rules. Allowlist
  entries that embed `\` (e.g. Windows-style paths) must be quoted at
  the policy boundary, expressed with forward slashes, or migrated to
  a typed pre-tokenized argument matcher in a future release.
- **Quoted literals in the allowlist** (e.g. `"'bash'"`) no longer
  match. These configurations were never sound -- they only worked
  because the old `split_whitespace` first token also retained the
  quote characters as literals, which any execve-aware consumer would
  immediately strip. Update such entries to the bare command name
  (`"bash"`) or its full path.
- **Performance:** `shlex::split` allocates a `Vec<String>` for the
  full input on every matched allowlist entry, where the previous
  implementation only walked to the first whitespace. Acceptable under
  existing request-body caps; observable on adversarial input.

### API surface

API surface unchanged: signature of `RbacPolicy::argument_allowed`
(`fn(&self, role: &str, tool: &str, argument: &str, value: &str) -> bool`)
is preserved. `cargo semver-checks` confirms patch-level compatibility.

### Dependencies

- Added `shlex = "1.3"` (MIT/Apache-2.0, zero transitive deps). Pinned
  to `>=1.3` to stay on the post-RUSTSEC-2024-0006 line; that advisory
  affects `shlex::quote` / `shlex::join` (CVE-2024-58266), neither of
  which is consumed here.

## [1.4.0] - 2026-04-24

Minor release adding an opt-in operator allowlist for the OAuth/JWKS
post-DNS SSRF guard, so in-cluster IdPs (e.g. Keycloak resolving to
RFC1918 addresses) can be reached without disabling SSRF protection.
Defaults are unchanged (fail-closed), and cloud-metadata addresses
remain blocked regardless of allowlist contents.

### Added

- **`src/oauth.rs`** — New `OAuthSsrfAllowlist { hosts, cidrs }` type and
  `OAuthConfigBuilder::ssrf_allowlist(...)` setter. Lets operators name
  the hostnames or CIDR blocks (IPv4 and IPv6) whose otherwise-blocked
  addresses (private/loopback/link-local/CGNAT/unique-local) the
  OAuth/JWKS fetcher is allowed to reach. Hosts are case-insensitive
  exact match; CIDRs are family-strict (no IPv4-mapped-IPv6, no `/0`,
  no zone IDs, host bits must be zero). Misconfiguration is rejected at
  `OAuthConfig::validate()` and `JwksCache::new()` so deploy-time
  feedback is immediate. When non-empty, validation logs a
  `tracing::warn!` naming the host and CIDR counts.
- **`src/ssrf.rs`** — New `CompiledSsrfAllowlist` + `CidrEntry` types
  (crate-private) and `redirect_target_reason_with_allowlist` that
  consults the allowlist on per-redirect-hop literal-IP screening while
  keeping cloud-metadata unbypassable.
- **`src/ssrf.rs`** — Cloud-metadata classifier now also covers AWS
  IPv6 (`fd00:ec2::254`), GCP IPv6 (`fd20:ce::254`), and the
  Alibaba/Tencent IPv4 metadata address (`100.100.100.200`). These
  addresses are classified as `cloud_metadata` *before* the generic
  `unique_local` / `cgnat` buckets so an operator allowlist for
  `fd00::/8` or `100.64.0.0/10` cannot silently re-allow them.

### Security

- **`src/oauth.rs`** — Cloud-metadata IPv4 (`169.254.169.254`,
  `100.100.100.200`) and IPv6 (`fd00:ec2::254`, `fd20:ce::254`) are
  now explicitly carved out of the operator allowlist path: even when
  an operator allowlists a containing CIDR, addresses classified as
  `cloud_metadata` continue to use the strict legacy error message and
  are never permitted. New unit tests pin this invariant
  (`redirect_with_fd00_8_allowlist_still_blocks_aws_v6_metadata`,
  `redirect_with_cgnat_allowlist_still_blocks_alibaba_metadata`).
- **`src/oauth.rs`** — Empty (default) allowlist preserves the
  pre-1.4.0 error message verbatim so existing operator runbooks and
  alerting on "OAuth target resolved to blocked IP" keep working.
  Configured allowlists that still block emit a more verbose error
  naming the hostname, the resolved IP, the block reason, and the two
  config fields the operator can edit.

### Changed

- **`src/oauth.rs`** — `evaluate_oauth_redirect`,
  `screen_oauth_target`, and `screen_oauth_target_with_test_override`
  now take a `&CompiledSsrfAllowlist` parameter. These are private
  helpers; no downstream impact.

### Documentation

- **`docs/GUIDE.md`** — New "Allowing in-cluster IdPs" subsection in the
  OAuth chapter showing the recommended TOML and builder snippets.
- **`SECURITY.md`** — New "Operator allowlist" subsection under OAuth
  SSRF hardening documenting the trust model, the cloud-metadata
  carve-out, and the auditing expectations.

## [1.3.2] - 2026-04-21

Security and quality patch release rolling up the post-1.3.1 multi-agent
review findings. No breaking changes; drop-in replacement for `1.3.1`.

### Security

- **`src/auth.rs`** — Bearer-scheme parsing in the auth middleware is now case-insensitive per RFC 7235 §2.1 (e.g. `bearer …` and `BEARER …` are accepted alongside `Bearer …`). Previously these were silently rejected as `invalid_credential` and counted toward the auth-failure rate limit, which could cause spurious lockouts for spec-conformant clients.
- **`src/auth.rs`** — `AuthIdentity` and `ApiKeyEntry` now have manual `Debug` implementations that redact the raw bearer token, the JWT `sub` claim, and the Argon2id hash. This prevents secret material from leaking via `format!("{:?}", …)` or `tracing::debug!(?identity, …)` calls, and is enforced by new unit tests.
- **`src/oauth.rs`** — Added post-DNS SSRF screening for the initial OAuth/JWKS request target so hostnames resolving to blocked IP ranges are rejected before connect, mirroring CRL fetch hardening.
- **`src/oauth.rs`** — Added opt-in `strict_audience_validation` so operators can disable the legacy `azp` fallback and enforce `aud`-only audience checks for new deployments.
- **`src/transport.rs` / `src/oauth.rs`** — Added opt-in `require_auth_on_admin_endpoints` so OAuth `/introspect` and `/revoke` can be mounted behind the normal auth middleware while preserving legacy behavior by default.
- **`src/rbac.rs`** — RBAC and tool rate limiting now inspect JSON-RPC batch arrays and reject the full batch if any `tools/call` entry is denied.
- **`src/oauth.rs`** — Added `jwks_max_response_bytes` (default 1 MiB) and streaming JWKS reads so oversized responses are refused without unbounded allocation.

### Changed

- **`src/metrics.rs`** — `http_request_duration_seconds` now uses an explicit, latency-tuned bucket set (`[1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s]`) instead of the Prometheus default buckets, which were skewed toward web-page rather than RPC latency. The histogram name and labels are unchanged; existing dashboards keep working but will gain finer sub-100 ms resolution.
- **`src/tool_hooks.rs`** — `with_hooks` now documents that dropping the returned wrapper silently loses the configured hooks. The natural `#[must_use]` enforcement is deferred to the next minor-version bump (adding `#[must_use]` to a public function is a SemVer-minor change per cargo-semver-checks).
- **`README.md`** — Quick-start dependency line dropped the gratuitous `features = ["oauth"]` so a copy-paste install no longer pulls in OAuth, `jsonwebtoken`, and `reqwest` for users who only need the default transport. Optional features are now described in a separate note pointing at the Cargo features table.

### Documentation

- **`docs/ARCHITECTURE.md` / `docs/MINDMAP.md`** — Refreshed mTLS sections to match the current per-connection `TlsConnInfo` design (the previous text described the long-removed `RwLock<HashMap<SocketAddr, AuthIdentity>>` map).
- **`docs/ARCHITECTURE.md`** — Metrics section now lists only the metrics actually exported by `src/metrics.rs` (`http_requests_total`, `http_request_duration_seconds`) and points operators at `McpMetrics::registry` for custom collectors. The previous list named gauges and counters that were never implemented.

## [1.3.1] - 2026-04-21

First usable release of `rmcp-server-kit`. A reusable, production-grade
framework for building [Model Context Protocol](https://modelcontextprotocol.io/)
servers in Rust on top of the official `rmcp` SDK.

Consumers supply an `rmcp::handler::server::ServerHandler` implementation;
this crate provides Streamable HTTP transport, TLS / mTLS, structured
authentication (API key, mTLS, OAuth 2.1 JWT), RBAC with per-tool
argument allowlists, per-IP rate limiting, OWASP security headers,
structured observability, optional Prometheus metrics, admin
diagnostics, and graceful shutdown.

### Highlights

- **Transport** — Streamable HTTP (`/mcp`), `/healthz`, `/readyz`,
  `/version`, admin diagnostics, graceful shutdown, configurable TLS
  and mTLS. Optional `serve_stdio()` for local subprocess MCP.
- **Authentication** — API-key (Argon2id-hashed, constant-time verify),
  mTLS client certificates with subject→role mapping, OAuth 2.1 JWT
  validation against JWKS (feature `oauth`). Pre-auth rate limiting
  defends Argon2id against CPU-spray attacks.
- **mTLS revocation** — CDP-driven CRL fetching with bounded memory,
  bounded concurrency, and bounded discovery rate. Auto-discovers CRL
  URLs from the CA chain at startup and from connecting client certs
  during handshakes. Hot-reloadable via `ReloadHandle::refresh_crls()`.
- **RBAC** — `RbacPolicy` with default-deny, per-role allow/deny tool
  lists (glob-supported), per-tool argument allowlists, HMAC-SHA256
  argument-value redaction in deny logs, task-local accessors
  (`current_role`, `current_identity`, `current_token`, `current_sub`).
- **OAuth 2.1** — JWKS cache with refresh cooldown, configurable allowed
  algorithms (RS256/ES256 default; symmetric keys rejected), HTTPS-only
  redirect policy, custom CA support, optional OAuth proxy endpoints
  (`/authorize`, `/token`, `/register`, `/introspect`, `/revoke`).
- **SSRF hardening** — Validate-time literal-IP / userinfo rejection on
  every operator-supplied URL plus a runtime per-hop IP-range guard on
  every redirect closure (CRL, JWKS, OAuth admin traffic). Blocks
  private, loopback, link-local, multicast, broadcast, and cloud-
  metadata ranges.
- **Hardening defaults** — Per-IP token-bucket rate limiting (governor)
  with memory-bounded LRU eviction, request-body cap (default 1 MiB),
  request-timeout cap, OWASP security headers (HSTS, CSP, X-Frame-
  Options, etc.), configurable CORS and Host allow-lists, JWKS key cap
  (default 256), CRL response-body cap (default 5 MiB).
- **Hot reload** — Lock-free `arc-swap`-backed reload of API keys,
  RBAC policy, and CRL set without dropping in-flight requests.
- **Tool hooks** — Opt-in `HookedHandler` wrapping `ServerHandler` with
  async `before_call` / `after_call` hooks. After-hooks run on a
  spawned task with the parent span and RBAC task-locals re-installed.
  Configurable `max_result_bytes` cap.
- **Observability** — `tracing-subscriber` initialization with
  `EnvFilter`, JSON or pretty console output, optional audit-file
  sink. Sensitive values wrapped in `secrecy::SecretString` end-to-end.
- **Metrics** (feature `metrics`) — Prometheus registry served on a
  separate listener (request count, duration histogram, in-flight
  gauge, auth failures, RBAC denies).
- **Configuration** — Programmatic builder API on `McpServerConfig`
  with compile-time `Validated<T>` typestate, plus matching TOML
  schema in `src/config.rs`.

### Cargo features

- `oauth` (default off) — OAuth 2.1 JWT validation via JWKS plus
  optional OAuth proxy endpoints.
- `metrics` (default off) — Prometheus registry and `/metrics` endpoint.
- `test-helpers` (default off) — opt-in test-only constructors used by
  downstream integration suites; not part of the stable API surface.

### Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.95** or newer (`edition = "2024"`).

### Documentation

- [`README.md`](README.md) — quick start.
- [`docs/GUIDE.md`](docs/GUIDE.md) — end-to-end consumer guide and TOML schema.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — file-cited deep architecture map.
- [`docs/MINDMAP.md`](docs/MINDMAP.md) — visual project mindmap.
- [`AGENTS.md`](AGENTS.md) — repository navigation hub for AI agents.
- [`SECURITY.md`](SECURITY.md) — coordinated disclosure policy and
  hardening posture.
