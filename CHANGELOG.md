# Changelog

All notable changes to `rmcp-server-kit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
**API-breaking** changes bump the **major** version, which tracks the `rmcp` SDK
major. Security-hardening changes that alter a runtime *default* (without
removing or retyping public API) ship in a **minor** release with a documented
migration note and a config opt-out — see the 3.1.0 notes below.

## [Unreleased]

Hardening pass from a full review against `RUST_GUIDELINES.md`. No public API
is added, removed, or retyped (`cargo semver-checks`: 223 checks, no semver
update required). Two runtime behaviours change; both are noted below.

### Security

- **Requests with an unresolvable source address are no longer exempt from rate
  limiting.** All four built-in per-IP limiters previously skipped enforcement
  entirely when no client address could be determined. They now fall back to a
  single bounded shared bucket via an internal `RateLimitKey::Unattributed`
  key, and log once per process. This is unreachable for a server started by
  `serve()` (the peer-address normalisation layer always inserts `ConnectInfo`),
  but was reachable when this crate's middleware was composed into a
  externally-built router.

  A typed key is used rather than a sentinel address: `limiter_client_ip`
  consults the trusted-forwarder-derived `ClientIp` first, and `crate::forwarded`
  does not filter unspecified addresses, so a forwarded `0.0.0.0` would have
  collided with a `0.0.0.0` sentinel.

- **Tool results that fail to serialize now fail closed against
  `max_result_bytes`.** `serialized_size` previously reported a serialization
  failure as `0` bytes, so the size cap silently did not fire and the result was
  recorded as zero-length. An unmeasurable result is now replaced when a cap is
  configured. When no cap is configured the result still passes through, since
  there is no policy to enforce; the failure is logged either way.

  The client-visible `actual_bytes` field renders `"unknown"` for unmeasurable
  results rather than a fabricated number.

- **Bearer credentials containing embedded whitespace are rejected.** RFC 7235
  §2.1 defines the credential as `token68`, which excludes whitespace; accepting
  it created a parser differential against a fronting proxy that splits on any
  whitespace. Only whitespace is rejected -- the full `token68` character class
  is deliberately **not** enforced, because `ApiKeyEntry::new` accepts an
  arbitrary caller-supplied hash and consumers may have hashed externally-issued
  opaque tokens containing other punctuation. Those continue to authenticate.

### Changed

- **RBAC host matching is now ASCII-case-insensitive.** `RbacPolicy::check` and
  `RbacPolicy::host_visible` previously compared hosts byte-exactly, so
  `Example.COM` did not match a `hosts = ["example.com"]` pattern. Since DNS
  names and IP literals are case-insensitive by specification, this corrects
  false denials. Operation names and tool-name patterns remain **case-sensitive**
  -- normalization is scoped to host matching only.

- Servers started with `max_concurrent_requests` unset now log one startup
  warning. No default is imposed; behaviour is unchanged.

- A duplicate `kid` in a JWKS document now logs a warning (last entry wins, as
  before). The logged `kid` is truncated, since it is issuer-controlled text of
  unbounded length.

### Documentation

- `RbacPolicy::argument_allowed` now documents that token comparison is
  byte-exact with no Unicode normalization, and the consequence on
  normalizing filesystems.

- `McpServerConfig::with_extra_router` now documents how path collisions are
  handled. A route that **exactly overlaps** a framework route panics at
  startup inside `axum::Router::merge`; a path merely *under* a framework
  prefix (`/admin/custom` alongside `/admin/status`) does **not** panic and is
  **not** validated. `axum::Router` exposes no route-enumeration API, so the
  framework cannot inspect these paths -- avoiding such collisions is the
  caller's responsibility. Both behaviours are now pinned by tests.

### Added

- `RmcpServerKitError::Internal` -- an internal-failure variant whose detail is
  logged server-side and collapsed to `"internal server error"` on the wire.
  Additive: the enum is `#[non_exhaustive]`.

- `McpServerConfig::with_trusted_forwarder_max_entries` and the
  `server.trusted_forwarder_max_entries` TOML key expose the
  forwarding-chain scan cap used in trusted-forwarder mode. Default `16`
  (unchanged). Validated to `1..=64`: `0` would pin every client to the proxy
  address, and an unbounded value would re-open the header-bomb vector the cap
  exists to close.

### Changed

- **`generate_api_key` now returns `RmcpServerKitError::Internal` instead of
  `Auth` when salt encoding or Argon2 hashing fails.** The `Auth` variant is
  declared client-facing and is rendered verbatim to HTTP clients, so embedding
  an upstream `password_hash::Error` chain in it violated that contract; it
  also mapped a server-side fault to `401` rather than `500`. Not a compile
  break -- the enum is `#[non_exhaustive]`, so downstream matches already carry
  a wildcard arm -- but the observable variant and HTTP status change.

- OAuth `audience_validation_mode = "permissive"` now logs once per process
  when it accepts a token via the `azp`-only fallback. Acceptance behaviour is
  unchanged; previously this mode was entirely silent, so a deployment running
  wider-than-spec audience validation left no trace. The `"warn"` mode's
  existing once-per-process warning is untouched.

- The JWKS "refresh skipped (cooldown active)" message moved from `debug` to
  `info`, so a key rotation stalled behind the refresh cooldown is visible at
  default log levels.

- A duplicate `kid` warning now carries a structured `kid_truncated` boolean
  alongside the truncated value, so log pipelines can detect truncation without
  substring-matching.

### Internal

- `host_matches` lowercases the host once per call rather than once per
  pattern, and only when a wildcard pattern is present -- an all-exact host
  pattern list stays allocation-free.

- Numeric IPv4 literal forms (decimal, hex, octal) and IPv4-mapped IPv6 are now
  pinned by tests as unreachable-as-hostnames through the OAuth literal-IP
  guard. No behaviour change: the `url` crate already normalizes these to
  `Host::Ipv4` before the guard sees them, but nothing asserted it.

## [3.7.0] - 2026-08-25

Retires the `mcpx` naming that outlived the crate rename.

### Changed

- **BREAKING (wire, not API): the `/version` response field `mcpx_version` is
  renamed to `rmcp_server_kit_version`.** The old key is **removed**, not
  duplicated. Anything scraping `/version` for `mcpx_version` must be updated.
  No Rust API is removed or retyped, so per this file's versioning policy - and
  matching the 3.1.0 precedent, which also altered the `/version` response
  shape - this ships in a minor release with a migration note.

  The name is deliberate: it matches the crate name and the convention already
  set by `RMCP_SERVER_KIT_BUILD_SHA` (1.8.1) and the `RMCP_SERVER_KIT__*` env
  overrides (3.5.0). It is **not** `rmcp_version`, which would read as the
  version of the `rmcp` SDK - a real, separate dependency of this crate.

- **`McpxError` is renamed to `RmcpServerKitError`.** A deprecated type alias
  keeps the old name compiling:

  ```rust
  #[deprecated(since = "3.7.0", note = "renamed to `RmcpServerKitError`; ...")]
  pub type McpxError = RmcpServerKitError;
  ```

  Downstream code using `McpxError` continues to build and gets a deprecation
  warning naming the replacement; verified against an external test crate.
  `cargo-semver-checks` confirms the change is additive against the published
  3.6.0 baseline (223 checks, "no semver update required").

  An alias rather than a hard rename because the major version **tracks the
  `rmcp` SDK major** (see the header of this file). Bumping to 4.0.0 for a
  rename would falsely signal an `rmcp` 4 upgrade. The alias is removed
  whenever an `rmcp` major forces the next 4.0.0.

### Migration

- Replace `McpxError` with `RmcpServerKitError`. The old name still works for
  now; the compiler will point at each site.
- If you parse `/version`, read `rmcp_server_kit_version` instead of
  `mcpx_version`.

## [3.6.0] - 2026-08-25

> **First published release since 3.3.1.** The `3.4.0` and `3.5.0` tags exist in
> git but were never published to crates.io: `release.yml` is gated on `CI` via
> `workflow_run`, CI was red on both tags, so the publish job was skipped and
> nobody noticed. 3.6.0 carries everything from both, plus the fixes that
> unblocked the pipeline. Consumers upgrading from 3.3.1 get the 3.4.0 and
> 3.5.0 sections below as well as this one. A minor bump rather than a patch,
> because relative to the last *published* version this adds public API.

### Fixed

- **Clippy failures on every feature combination except `--all-features`.**
  `apply_oauth_env_overrides` took `&mut self` and `&mut Vec<EnvOverride>` that
  the `#[cfg(not(feature = "oauth"))]` path never used mutably, tripping
  `needless_pass_by_ref_mut` twice and `needless_return` once. Invisible under
  `--all-features`, which cannot see inside `cfg(not(...))`. Reading the three
  OAuth variables now lives in an ungated helper so detection stays
  feature-independent - a set variable on a non-`oauth` build is still a hard
  error, never a silent no-op - while only the mutating half is cfg-gated. No
  behaviour or error-message change.

- **`t10_every_server_config_field_is_classified_for_bridge` failing on
  `windows-latest`.** It split on a literal `"\n}\n\nimpl ServerConfig"`; with
  `core.autocrlf` the Windows runner checks out CRLF and the marker could not
  match. Normalized before splitting. The rest of the suite was swept for the
  same class; the two `docs/GUIDE.md` parsers already use `.lines()`, which
  strips `\r`.

- **`cargo vet` exemptions refreshed** for `crc32fast`, `h2`, `log`, `syn` and
  `uuid`. `Cargo.lock` is gitignored, so CI resolves dependencies fresh while
  exemptions pin exact versions; any transitive release fails the blocking vet
  job until regenerated.

### Changed

- [`docs/RELEASING.md`](docs/RELEASING.md) pre-flight now matches what CI
  actually enforces: clippy across the whole feature matrix, `cargo test` with
  and without default features, and `cargo vet --locked` against a freshly
  generated lockfile. It also requires confirming CI is green *before* tagging
  and verifying `max_version` on crates.io afterwards, since a pushed tag is
  not a release.

### Documentation

- **Every TOML-configurable parameter is now documented.** An exhaustive diff of
  the `Deserialize` structs against [`docs/GUIDE.md`](docs/GUIDE.md) found five
  keys with no coverage anywhere in the guide: `oauth.require_subject`,
  `oauth.role_mappings`, the `claim_value` field of `RoleMapping`, and
  `rate_limit.{max_tracked_keys, idle_eviction}`. All are now documented with
  type and default, `RateLimitConfig` gained a full parameter table, and
  `role_claim` / `role_mappings` gained a worked example - `[[server.auth.oauth.role_mappings]]`
  was previously undiscoverable. `forwarded_header` now documents its accepted
  values (`"x-forwarded-for"`, `"forwarded"`) and `trusted_proxies` pairing.

- **The complete TOML example now names the environment variable that overrides
  each key**, as trailing `# env: RMCP_SERVER_KIT__...` comments, so the mapping
  is visible at the point of use rather than only in the reference table.

  A second drift guard covers these annotations: it asserts each one names a
  real variable, is attached to the TOML key that variable actually targets,
  appears at most once, and that every variable is annotated exactly once apart
  from a documented exemption for `..._REDACTION_SALT_FILE`, which shares a key
  with its non-`_FILE` sibling. Verified non-vacuous against a wrong-key
  attachment, a typo, and a deletion.

- **New runnable example `examples/config_file_server.rs`** covering the whole
  config pipeline: a downstream-owned root struct, TOML deserialization,
  `apply_env_overrides` with the audit report, `validate_server_config`,
  `apply_to_mcp_config`, the runtime-only wiring the bridge cannot carry
  (`RbacPolicy`, metrics), and a builder override chained after the bridge.
  The TOML-file path shipped in 3.4.0/3.5.0 previously had no runnable
  example - only a `rust,ignore` guide snippet, which nothing compiles.
  An example is covered by `cargo build --examples` and
  `cargo clippy --all-targets`, so it cannot rot silently.

- **Every config-pipeline code sample is now compiled.** The four public config
  entry points - `ServerConfig::{apply_env_overrides, apply_to_mcp_config}`,
  `ObservabilityConfig::apply_env_overrides` and
  `RbacConfig::apply_env_overrides` - gained rustdoc examples, so they are
  covered by `cargo test --doc` (doctest count 7 -> 11) and render on docs.rs.
  The two long `rust,ignore` pipeline snippets in the guide, which nothing
  compiled and which had already drifted to referencing a nonexistent
  `YourRootConfig` type, are replaced by a call-order outline plus pointers to
  the compiled rustdoc and to `examples/config_file_server.rs`. Also repaired
  two rustdoc-style intra-doc links in the guide that plain Markdown cannot
  resolve, so they rendered as literal bracketed text rather than links.

## [3.5.0] - 2026-08-24 (tagged, never published)

### Added

- **Three opt-in `apply_env_overrides` methods** for environment-driven configuration overlay.
  `ServerConfig::apply_env_overrides`, `ObservabilityConfig::apply_env_overrides`, and
  `RbacConfig::apply_env_overrides` each apply a named set of `RMCP_SERVER_KIT__*` env vars
  onto the corresponding struct and return a `Vec<EnvOverride>` audit report. No existing
  code path calls these methods automatically: `serve()`, `validate()`, and every config
  constructor are unaffected. This release is purely additive.

- **`EnvOverride` and `EnvOverrideSource`** -- public, `#[non_exhaustive]` types that
  describe each applied override. `EnvOverride::value` is `None` for secret-typed targets
  so secrets are never exposed in report output or `Debug` formatting.

- **14 curated environment variables** across three config structs:
  - `ServerConfig`: listen address and port, public URL, TLS certificate/key paths, admin
    toggle, and OAuth issuer/audience/JWKS URI (the three OAuth variables require
    `--features oauth`).
  - `ObservabilityConfig`: log format, metrics-enabled flag, and metrics bind address.
  - `RbacConfig`: redaction salt (direct string or `_FILE` path indirection).

  All variables follow the `RMCP_SERVER_KIT__<SECTION>__<FIELD>` naming convention with `__`
  as the nesting delimiter.

- **`_FILE` secret indirection for `rbac.redaction_salt`.** Set
  `RMCP_SERVER_KIT__RBAC__REDACTION_SALT_FILE` to a file path to read the salt from a
  Kubernetes Secret volume mount. Setting both the direct variable and the `_FILE` variable
  simultaneously is a hard startup error. Exactly one terminal line ending is stripped from
  the file contents (`\r\n`, `\n`, or `\r`); all other whitespace is preserved, so the same
  logical secret produces the same salt whether supplied inline or via a file.

- **Fail-closed parsing.** An env var set to an unparseable value causes `apply_env_overrides`
  to return `McpxError::Config` naming the exact variable and the expected type. There is no
  warn-and-ignore path.

No default values changed. `serve()`, `validate()`, and every constructor read no process
environment automatically. Existing code that does not call `apply_env_overrides` is
unaffected.

## [3.4.0] - 2026-08-24 (tagged, never published)

### Added

- **TOML controls for `server.max_request_body` and `server.expose_build_metadata`.**
  Both `ServerConfig` fields were already defined but had no route into `serve()`.
  They are now bridged via `ServerConfig::apply_to_mcp_config`. `max_request_body`
  caps the request body in bytes (default 1 MiB; must be greater than zero, validated
  by `McpServerConfig::validate()`). `expose_build_metadata` controls whether
  `build_git_sha`, `build_timestamp`, and `rust_version` appear in the unauthenticated
  `/version` response (default `false`, unchanged from 3.1.0).

- **`[server.security_headers]` TOML table — all twelve OWASP headers configurable
  from TOML.** `SecurityHeadersConfig` now derives `serde::Deserialize` with
  `#[serde(default)]`. Every one of the twelve fields is configurable under
  `[server.security_headers]` without any change to built-in defaults. The
  existing three-state semantic is preserved: an absent key keeps the built-in
  default; `""` omits the header from every response; a non-empty string is used
  verbatim and validated at startup. At startup the server emits a `warn`-level
  log entry for every header that is overridden or omitted, so a weakened policy is
  visible in logs rather than only in a config diff. HSTS `preload` (any case)
  remains rejected by the validator. Unknown keys under `[server.security_headers]`
  are silently ignored (no `deny_unknown_fields`).

- **`ServerConfig::apply_to_mcp_config`** — the bridge between the TOML schema and
  `serve()`. Accepts a `base: McpServerConfig` and returns `McpServerConfig` with
  every bridgeable transport field replaced by the TOML-sourced value. Uses
  replacement semantics throughout: `None` and `false` in TOML clear the
  corresponding field on `base`, so there is no partial-merge ambiguity. The
  runtime-only fields preserved from `base` unchanged are `name`, `version`, `rbac`,
  `readiness_check`, `extra_router`, `on_reload_ready`, `metrics_enabled`, and
  `metrics_bind`. Returns `McpxError::Config` when any duration string cannot be
  parsed by `humantime`. The method is side-effect free and never reads process
  environment variables.

- **New clearing-capable `McpServerConfig` builder setters** added to support the
  replacement-semantics bridge: `with_bind_addr`, `with_tls_paths`,
  `with_optional_auth`, `with_max_request_body`, `with_expose_build_metadata`,
  `with_session_idle_timeout`, `with_sse_keep_alive`, `with_tls_handshake_timeout`,
  `with_max_concurrent_tls_handshakes`, `with_allowed_origins`,
  `with_extra_route_rate_limit_exempt_paths`, `with_trusted_proxies`,
  `with_optional_tool_rate_limit`, `with_optional_tool_rate_limit_burst`,
  `with_optional_extra_route_rate_limit`, `with_optional_extra_route_rate_limit_burst`,
  `with_optional_forwarded_header`, `with_optional_public_url`,
  `with_compression_enabled`, `with_compression_min_size`,
  `with_optional_max_concurrent_requests`, `with_admin_enabled`, and `with_admin_role`.
  All are additive; no existing builder method is changed or removed.

No default values changed. This release is purely additive — existing configurations
that do not opt in to `[server.security_headers]`, `max_request_body`, or
`expose_build_metadata` parse and behave identically to 3.3.x.

## [3.3.1] - 2026-08-22

### Changed

- **`cargo vet` no longer audits this crate against itself.**
  `supply-chain/config.toml` set `audit-as-crates-io = true` for
  `rmcp-server-kit`, asking cargo-vet to audit our own package as though it
  were a third-party crates.io dependency. That requirement was satisfied with
  a self-exemption — an explicit trust-without-audit marker — so it asserted no
  security property, while pinning an exact version meant every release
  orphaned it. The `cargo vet` CI job consequently sat red from the 3.2.0
  release until the 3.3.0 cycle without anyone noticing, because it was
  `continue-on-error: true`.

  The policy is now `audit-as-crates-io = false`, which is the correct setting
  for a first-party crate you author and publish. The self-exemption and the
  `unpublished` marker are removed, the per-release refresh step in
  `docs/RELEASING.md` is gone, and the CI job is now **blocking** rather than
  advisory. Third-party audit coverage is unchanged (385 exemptions, was 386 —
  the difference is the self-entry).

### Testing

- **Regression test for the graceful-shutdown grace window.** The 3.3.0 fix
  that stopped in-flight MCP sessions being cancelled when the drain window
  opens shipped without a timing test. Added one that performs a real MCP
  `initialize` handshake, blocks inside `call_tool` until the test releases it,
  triggers shutdown while the call is in flight, and asserts the tool response
  still arrives.

  It is event-gated rather than duration-gated, so it does not depend on
  elapsed-time thresholds. It exercises `/mcp` specifically: routes registered
  through `with_extra_router` never reach `StreamableHttpService`, the sole
  consumer of the shutdown session token, so a test built that way would pass
  against the bug. Verified by reverting the wiring to `ct.child_token()`, at
  which point the assertion fails with an empty SSE frame.

- **Regression test for the force-exit shutdown arm.** The session token is
  cancelled in both arms of the shutdown `select!` — after axum drains, and
  when the force-exit timer wins — but only the first was covered.

  The assertion is on the client-side response body, not on the server task
  completing: when force-exit wins, the `axum::serve` future is dropped and
  `serve_with_listener` returns whether or not the token was cancelled, so a
  join-handle assertion could never fail. What the cancellation changes is that
  rmcp ends the SSE stream, so the body reaches EOF instead of hanging.
  Awaiting only `send()` would be equally useless, since the response headers
  are established before the tool result exists.

  Verified by removing the force-exit `session_ct.cancel()` while leaving the
  graceful-drain one intact: the body then never terminates and the test fails
  on its timeout.

## [3.3.0] - 2026-08-21

### Added

- **`ArgumentAllowlist::required`** (default `false`) — opt into requiring that
  a constrained argument actually be supplied. An allowlist has always
  constrained the value *only when the argument is present*, so a caller could
  skip it entirely by omitting the key. That is safe when the tool's input
  schema marks the argument required, but fails open when the handler
  substitutes a default for a missing value. With `required = true` the
  argument must be present **and** string-valued; a missing key, a non-string
  value, or an absent/non-object `arguments` object are all rejected with 403.
  Combining `required = true` with an empty `allowed` list means "must be
  supplied as a string, any value accepted". Set it via
  `ArgumentAllowlist::with_required(true)` or `required = true` in TOML.

  This is purely additive: the field is `#[serde(default)]` on an
  already-`#[non_exhaustive]` struct and `ArgumentAllowlist::new` is unchanged,
  so existing configurations parse identically and behave exactly as before
  unless they opt in.

### Security

- **mTLS: a CRL whose first fetch failed is no longer suppressed for the
  process lifetime.** A discovered CRL Distribution Point URL was committed to
  the permanent dedup set as soon as it was queued. If that first fetch then
  failed, no code path could undo it — `seen_urls` is pruned only for URLs
  whose CRL was successfully cached and later went stale — so the URL was never
  re-enqueued and revocation for that CDP was silently disabled under the
  default `crl_deny_on_unavailable = false` (or the handshake failed forever
  with it set to `true`). CDP URLs come from the client-presented certificate,
  so a holder of a revoked-but-chain-valid cert could trigger this deliberately
  by making the first fetch fail from a host they control. Queued-but-unfetched
  URLs now occupy a separate in-flight state and are promoted to the permanent
  set **only once the CRL is confirmed present in the cache** — a fetch error or
  a `crl_max_cache_entries` rejection clears the marker so a later handshake
  retries. Retry volume stays bounded by the existing
  `crl_discovery_rate_per_min` limiter, global fetch concurrency, and per-host
  semaphores. Cache removal now clears both states.

- **OAuth proxy: caller-supplied client-authentication parameters can no longer
  be smuggled upstream.** `client_id` was stripped by splitting the raw form on
  `&` and dropping segments literally starting with `client_id=`. Percent-encoded
  keys (`%63lient_id=`, `client%5Fid=`) survived that filter but decode upstream
  to `client_id`, and `client_secret` was never filtered at all — so a caller
  could ship duplicate client credentials to the IdP alongside the proxy's own
  injected values, and a first-wins upstream parser would honour the caller's.
  The query/body is now parsed and re-serialized as
  `application/x-www-form-urlencoded`, dropping every decoded `client_id`,
  `client_secret`, `client_assertion`, and `client_assertion_type` before
  proxy-owned values are injected, across all three proxy call sites. Decoded
  values and the relative order of non-client parameters (including repeated
  `scope` / `resource`) are preserved; raw byte encoding is normalized, which is
  semantically equivalent for form data.

- **RBAC: a non-string `arguments.host` no longer downgrades the host check.**
  The host was read with `as_str()`, so an array, object, number, bool, or null
  yielded `None` and routed to `check_operation`, skipping `RoleConfig.hosts`
  glob evaluation entirely — letting a caller opt out of host restrictions by
  changing the argument's shape. A present-but-non-string `host` is now denied,
  matching the existing fail-closed behaviour for non-string allowlisted
  arguments. An **absent** `host` still routes to `check_operation`, so
  genuinely hostless tools (`ping`, `list_hosts`) are unaffected.

- **Metrics: HTTP label cardinality is now bounded.** `metrics_middleware` runs
  outside the auth layer and labelled series with the raw request path and raw
  HTTP method, so unauthenticated requests to random paths minted a permanent
  Prometheus time series each, growing in-process state until exhaustion. Labels
  now come from a closed set: the matched route template where available, `/mcp`
  for the nested MCP service, `<unmatched>` otherwise, and a fixed method list
  with `OTHER` for extension verbs. The raw path is never used. Label **names**
  are unchanged, so existing dashboards keep working; label **values** for
  previously-unmatched requests change.

### Fixed

- **`Forwarded` header parsing now requires balanced quotes (RFC 7239 §4).**
  `for=` values were previously unquoted with `trim_matches('"')`, which strips
  leading and trailing quotes *independently*. Malformed values such as
  `for="203.0.113.9` (lone leading quote), `for=203.0.113.9"` (lone trailing),
  and `for="""203.0.113.9"""` were silently normalized into a valid address
  instead of being rejected. A value is now parsed strictly as RFC 7239
  `token / quoted-string`: a bare token must contain no `"` at all, and a
  quoted-string must be balanced; anything else yields
  `FallbackReason::MalformedEntry` and resolution falls back to the direct
  peer. This removes a parser differential between `rmcp-server-kit` and an
  upstream proxy, which matters because the resolved client IP feeds per-IP
  rate limiting and operator allowlists. Well-formed quoted values —
  including `for="[2001:db8::1]:443"` and quoted `unknown` / `_obfuscated`
  identifiers — are unaffected.

- **Graceful shutdown no longer cuts MCP sessions at the start of the grace
  window.** The MCP service received a child of the same cancellation token the
  shutdown path cancels immediately when the trigger fires, so in-flight
  sessions and SSE streams could terminate before `shutdown_timeout` elapsed
  during a normal SIGTERM rollout. The MCP service now holds a dedicated
  session token, cancelled only after axum finishes draining — or when the
  force-exit timer wins, so a stuck stream still cannot hang shutdown. The
  lifecycle token continues to drive the metrics listener, the CRL refresher,
  and external shutdown wiring unchanged.

### Changed

- **Metrics middleware no longer allocates a `String` per request** for the
  HTTP status label. It now renders the status code into a stack
  `core::fmt::NumBuffer` via `u16::format_into` (both stable in Rust 1.98,
  already the crate MSRV). Behavior and emitted label values are unchanged;
  only the `metrics` feature path is affected.
- **The screened-redirect JWKS/discovery `reqwest::Client` is no longer built
  in production OAuth builds.** `OauthHttpClient::inner` is read only by the
  `cfg`-gated redirect-policy regression helpers (`__test_get`,
  `__test_inner_client`), so the private field and its construction now share
  the same `cfg(any(test, feature = "test-helpers"))` gate, replacing an
  `#[allow(dead_code)]`. A minimal `oauth` build allocates one fewer HTTP
  client and connection pool. **No observable behavior change:** every
  misconfiguration error (SSRF allowlist compile, `ca_cert_path` read,
  `ca_cert_path` parse) is raised by the shared pre-work and `make_base()`,
  which the credential client still executes. The two
  `ClientBuilder::build()` failure labels were unified to
  `"oauth http client init: {e}"` so the startup error text is identical
  whether or not `inner` is compiled in; `"oauth credential client init"`
  is retired and was never independently reachable, since both clients
  consume the same base configuration.

### Fixed (tooling)

- **`cargo clippy --features oauth` (without `test-helpers`) now passes.**
  It previously failed with four `-D warnings` errors — two
  `clippy::clone_on_copy` and two `clippy::unit_arg` — because
  `TestLoopbackBypass` aliases to `()` outside test builds and the existing
  `#[allow]` covered only `clippy::clone_on_ref_ptr`. CI did not catch this:
  the `clippy` job runs `--all-features` only, and the `features-matrix` job
  runs `cargo build`/`cargo test` but not `cargo clippy`.
- **CI now lints every shipped feature combination.** A
  `cargo clippy --all-targets $FEATURES -- -D warnings` step was added to the
  feature matrix in both `.github/workflows/ci.yml` and `.gitlab-ci.yml`
  (as `feature-matrix:clippy`), covering default, `--no-default-features`,
  `--features oauth`, `--features metrics`, and `--all-features`. This closes
  the blind spot that allowed the lint failure above to go unnoticed.

### Documentation

- `RUST_GUIDELINES.md` now tracks stable Rust through **1.98**, and
  `AGENTS.md` documents the test-tier taxonomy (unit / property /
  integration-pure / integration-mocked / e2e / perf) together with the
  per-file `#![cfg(...)]` feature gates.
- The constant-time documentation on `verify_bearer_token` no longer claims
  full branchlessness. The guarantee the implementation actually provides is
  exactly one Argon2id verification per configured key regardless of which slot
  matches or whether one is expired; selecting the verification target and
  recording the matched index remain ordinary data-dependent branches on
  locals, dwarfed by the Argon2id cost. No behaviour change.
- Stale `src/` line-number citations in `AGENTS.md`, `docs/ARCHITECTURE.md`,
  and `docs/MINDMAP.md` repointed to their current locations.

## [3.2.0] - 2026-08-21

### Changed

- **MSRV raised to Rust 1.98.0** (from 1.95.0). The `rust-version` manifest
  field, the GitHub Actions MSRV gate, and the GitLab CI image now target
  1.98.0, matching the stable toolchain CI already runs. Per the project's
  SemVer policy an MSRV bump is a minor-version change. No public API change.

## [3.1.3] - 2026-08-19

### Changed

- **`OAuthConfig::{issuer, audience, jwks_uri}` are now `#[serde(default)]`.**
  A partially-specified `[server.auth.oauth]` table — e.g. one carrying only
  `role_claim`/`role_mappings`, with the URL and audience fields supplied by a
  downstream env-override layer applied after TOML parsing — now deserializes
  instead of failing at parse time on a serde "missing field" error. The three
  fields are enforced at [`OAuthConfig::validate`] time instead
  (parse-don't-validate): empty `issuer` and `jwks_uri` were already rejected by
  the HTTPS URL check, and `validate()` now **also rejects an empty `audience`**
  (`oauth.audience must not be empty`). Previously `audience` was not validated,
  so an empty value passed config validation and then failed closed silently at
  runtime under the default `AudienceValidationMode::Strict` (nothing matches an
  empty audience). Purely additive: configs that specify all three fields parse
  and validate exactly as before; the only observable change is that omitting one
  from a present `[oauth]` table now surfaces as a clear `validate()` error
  rather than a serde parse error.

## [3.1.2] - 2026-08-19

### Changed

- Maintenance release: **no library code or public-API changes since 3.1.1**
  (`cargo-semver-checks` reports no break). Refreshes the dependency lockfile
  to the latest semver-compatible versions — notably `ref-cast` 1.0.27 — and
  re-validates the crate against the current dependency set. Because
  `Cargo.lock` is not shipped for a library, consumers resolve their own
  dependency versions, so this release is behaviorally identical to 3.1.1.

## [3.1.1] - 2026-08-01

### Fixed

- **`cargo build --features oauth` no longer fails under `-D warnings`.** In a
  minimal `oauth` build (without `oauth-mtls-client` or `test-helpers`) the
  internal screened-redirect HTTP client was constructed but never read,
  tripping the `dead_code` lint under `RUSTFLAGS="-D warnings"`. The full
  feature matrix now builds cleanly with warnings denied.

  *Note:* the 3.1.0 tag was never published to crates.io — its release build
  failed on the issue above — so this is the first published release of the
  3.1.x line and includes all of the 3.1.0 changes below.

## [3.1.0] - 2026-08-01

> **⚠️ Behavioral changes — please read before upgrading.** This release hardens
> several security-relevant runtime *defaults*. Because the crate's major version
> tracks the `rmcp` SDK, these ship in a minor release; **no public API is removed
> or retyped** (`cargo-semver-checks` reports no break), but the defaults below
> change. Each has a config opt-out to restore the prior behavior.
>
> **1. OAuth JWT audience validation now defaults to `strict`.** A token whose
> configured audience appears only in the `azp` claim (not `aud`) is now
> **rejected**; previously the default (`warn`) accepted it with a one-shot
> warning. If your IdP issues `azp`-only tokens and cannot yet be reconfigured,
> restore the pre-3.1 behavior with `audience_validation_mode`:
>
> ```toml
> [server.auth.oauth]
> issuer   = "https://idp.example.com/"
> audience = "https://mcp.example.com/mcp"
> jwks_uri = "https://idp.example.com/.well-known/jwks.json"
>
> # Restore pre-3.1 acceptance of azp-only tokens (pick one):
> audience_validation_mode = "warn"        # accept azp-only, one-shot WARN per process
> # audience_validation_mode = "permissive" # accept azp-only silently
> ```
>
> The deprecated `strict_audience_validation = false` also still maps to `"warn"`.
>
> **2. `/version` no longer exposes build metadata to anonymous callers.**
> `build_git_sha`, `build_timestamp`, and `rust_version` are suppressed by
> default. Re-enable them with `[server]` → `expose_build_metadata = true`.
>
> **3. `trusted_proxies` rejects a `/0` CIDR.** A `0.0.0.0/0` or `::/0` entry now
> fails validation at startup — narrow it to your real proxy ranges, e.g.
> `[server]` → `trusted_proxies = ["10.0.0.0/8"]`.
>
> **4. OAuth `/introspect` and `/revoke` require the admin role.** When
> `[server.auth.oauth.proxy]` → `require_auth_on_admin_endpoints = true`, an
> authenticated non-admin caller now receives `403`. Grant the caller the
> configured `[server]` → `admin_role` (default `"admin"`).
>
> **5. JWKS key selection is fail-closed on `kid`.** A `kid`-bearing JWT must
> match a *named* JWKS key; it no longer falls back to an unnamed key of the same
> algorithm. Affects only non-standard IdPs that mint `kid`-bearing tokens against
> a `kid`-less JWKS.
>
> For mTLS deployments, the CRL cache/verifier fix and the `crl_stale_grace` →
> `crl_retry_retention` rename (the old key still works as an alias) affect only
> the opt-in `crl_deny_on_unavailable = true` path.

### Security

- **OAuth audience validation now defaults to `strict`.** A token whose
  configured audience appears only in the `azp` claim (not `aud`) is now
  **rejected by default**; previously the default (`warn`) accepted it with a
  one-shot warning. **Behavioral change.** To keep the previous behavior, set
  `audience_validation_mode = "warn"` (accept `azp`-only with a one-shot
  warning) or `"permissive"` (accept silently). The deprecated
  `strict_audience_validation` flag is now `Option<bool>`: `Some(false)` maps to
  `warn`, `Some(true)`/unset map to `strict`. (rust-review HIGH / H1.)
- **OAuth JWKS cache now fails closed when a refresh cannot succeed.** After a
  failed or cooldown-suppressed JWKS refresh, an expired cache no longer serves
  a stale (possibly rotated-out) signing key: the post-refresh key lookup now
  re-applies the same freshness gate as the initial lookup, so a token whose
  `kid` exists only in the expired cache is rejected rather than accepted.
  (rust-review HIGH / H2.)
- **mTLS CRL fail-closed precheck now matches the live verifier cache.** CRL
  cache updates now rebuild the rustls verifier from a candidate cache before
  publishing either the cache or `cached_urls`, preventing the fail-closed
  precheck from advertising CRL URLs the live verifier cannot enforce. The
  precheck is now any-of-N: a certificate with multiple relevant CDPs fails
  fast only when none are cached, while webpki remains the authoritative
  per-certificate revocation decision. `crl_end_entity_only` is respected by
  the precheck, and `crl_retry_retention` is documented as the preferred TOML
  key for retry-retention semantics while `crl_stale_grace` remains a
  backward-compatible alias. (rust-review HIGH / H3.)
- **SSRF: cloud-metadata is now unbypassable through IPv6 transition/compatibility
  forms.** `ip_block_reason` re-labels NAT64 (`64:ff9b::/96`) and 6to4
  (`2002::/16`) addresses embedding a cloud-metadata IPv4 (e.g.
  `64:ff9b::169.254.169.254`) as `cloud_metadata` rather than
  `nat64_embedded`/`6to4_embedded`, so an operator SSRF allowlist covering a
  transition prefix can no longer re-allow the metadata endpoint.
  (rust-review MEDIUM / M2.)
- **SSRF: deprecated IPv4-compatible IPv6 (`::a.b.c.d`, `::/96`) is now blocked.**
  These addresses previously fell through the IPv6 classifier as public; they
  now inherit the embedded IPv4 rule (`::127.0.0.1` → loopback,
  `::169.254.169.254` → cloud_metadata) with the rest of the deprecated prefix
  blocked as defence in depth, matching the guarantee already documented in
  `SECURITY.md`. (rust-review MEDIUM / M3.)
- **`trusted_proxies` now rejects a `/0` prefix.** `0.0.0.0/0` and `::/0` were
  accepted by both the TOML and builder validators; a `/0` trusted proxy marks
  every peer trusted and lets any client spoof the resolved client IP
  (rate-limit bypass, audit poisoning) via forwarding headers. Both validators
  now reject prefix-0 CIDRs via a shared helper, mirroring the SSRF allowlist
  parser. **Behavioral change** — a configuration that relied on a `/0` trusted
  proxy must narrow it to the real proxy CIDRs.
  (rust-review MEDIUM / M1.)
- **OAuth credential POSTs no longer follow redirects.** `/token`, `/introspect`,
  `/revoke`, and the RFC 8693 token-exchange requests now use a dedicated
  `redirect::Policy::none()` client, so a 307/308 from a compromised or
  open-redirecting endpoint can no longer re-send the `client_secret`-bearing
  body to another host. (rust-review MEDIUM / M7.)
- **OAuth JWKS key selection is fail-closed on `kid`.** A JWT carrying a `kid`
  must now match a *named* JWKS key exactly; it no longer falls back to an
  unnamed key of the same algorithm, closing an unknown-`kid` key-selection
  vector. **Behavior change** for non-standard IdPs that mint `kid`-bearing
  tokens against a `kid`-less JWKS. (rust-review LOW / L4.)
- **OAuth targets: internal hostname suffixes rejected pre-DNS.** OAuth/JWKS
  targets whose host ends in `.localhost`, `.local`, or `.internal` are rejected
  before resolution (an exact-host allowlist entry still overrides; a trailing
  FQDN dot is canonicalized). Exact `localhost` is unaffected — already covered
  by the post-DNS IP screen. (rust-review LOW / L3.)
- **Security response headers now cover early and fallback responses.** The
  OWASP header layer (`X-Content-Type-Options`, `X-Frame-Options`,
  `Content-Security-Policy`, and — under TLS — `Strict-Transport-Security`) was
  previously an inner layer, so origin-rejection 403s, CORS-preflight replies,
  overload 503s, and the 404 fallback were emitted without it. It is now the
  outermost response layer and decorates every response. (rust-review MEDIUM /
  M5.)
- **OAuth `/introspect` and `/revoke` now require the admin role.** When
  `require_auth_on_admin_endpoints` is set, these proxy endpoints are gated by
  the configured `admin_role` (default `admin`) in addition to authentication;
  an authenticated non-admin caller now receives `403` instead of reaching the
  upstream. **Behavioral change** for authenticated non-admin callers who could
  previously introspect/revoke tokens. (rust-review MEDIUM / M6.)

### Changed

- **Default `Content-Security-Policy` hardened** to `default-src 'none';
  form-action 'self'; object-src 'none'; frame-ancestors 'none';
  upgrade-insecure-requests` (was `default-src 'none'; frame-ancestors 'none'`).
  Operators that set a custom `content_security_policy` are unaffected.
  (rust-review LOW / L1.)
- **`X-Forwarded-For` / `Forwarded` node ports are validated.** A forwarding
  entry with an empty or non-numeric port (`203.0.113.7:`,
  `[2001:db8::1]:notaport`) is now treated as malformed, so resolution falls
  back to the direct peer instead of trusting an ambiguous identifier.
  (rust-review LOW / L2.)
- **Lint posture:** added `large_stack_arrays`, `large_stack_frames`,
  `ptr_as_ptr`, and `cast_lossless` (warn) per RUST_GUIDELINES.md §9, and
  documented why `RUSTFLAGS="-D warnings"` (not Cargo `build.warnings`, which is
  Rust 1.97+) is the correct deny-warnings mechanism at MSRV 1.95.
  (rust-review tooling / T1, T2.)

### Added

- **`OAuthConfig::require_subject`** (opt-in, default `false`). When enabled, a
  JWT without a `sub` claim is rejected. Leave `false` for OAuth
  client-credentials / machine-to-machine tokens, which legitimately carry no
  subject. (rust-review LOW / L4.)
- **`McpServerConfig::expose_build_metadata`** (opt-in, default `false`). The
  unauthenticated `/version` endpoint now serves only `name`, `version`, and
  `mcpx_version` by default; `build_git_sha`, `build_timestamp`, and
  `rust_version` are included only when this is enabled, so build fingerprints
  are not leaked to anonymous callers. **Behavior change** to the default
  `/version` response shape. (rust-review LOW / L5.)

### Removed

- **`OauthHttpClient::__test_get` is no longer present in default builds.** This
  hidden, test-only accessor was `#[doc(hidden)] pub` but ungated; because a
  literal-IP target performs no DNS lookup, the `SsrfScreeningResolver` never
  fired, making it a reachable SSRF vector in production builds. It is now gated
  behind `#[cfg(any(test, feature = "test-helpers"))]` like its sibling
  helpers, so it is absent from the default public API and remains available
  only under the `test-helpers` feature for downstream integration tests.
  (rust-review MEDIUM / M4.)

## [3.0.0] - 2026-07-30

### Changed

- **BREAKING: migrated to `rmcp` 3.0** (was 2.x). Consumers depend on
  `rmcp` directly, so bump your own `rmcp = "2"` to `rmcp = "3"` in
  lockstep. Handlers that override `call_tool` / `get_prompt` /
  `read_resource` must switch their return types to the new MRTR-aware
  enums (`CallToolResponse` / `GetPromptResponse` / `ReadResourceResponse`)
  — wrap an existing result with `.into()`; handlers using the default
  `ServerHandler` need only the version bump. Internally `HookedHandler`
  now returns `CallToolResponse` and passes MRTR `InputRequired`/`Task`
  responses through untouched (the result-size cap still applies to
  completed results). rmcp 3.0's MSRV is 1.88 (our 1.95 target is
  unaffected). See [`docs/MIGRATION.md`](docs/MIGRATION.md).

## [2.1.1] - 2026-07-29

### Changed

- **Dependency major-version upgrades.**
  - `tower-http` 0.6 → 0.7. The only call-site change is
    `compression::predicate::SizeAbove::new`, which now takes `u64`
    (previously `u16`).
  - `jsonwebtoken` 10 → 11 (behind the `oauth` feature). `jwk::KeyAlgorithm`
    is now `#[non_exhaustive]`; already covered by the existing wildcard arm
    in `jwk_algorithm`.
  - `base64` 0.22 → 0.23, pinned to `default-features = false,
    features = ["std"]` so the new default-on `simd-unsafe` engine is not
    compiled in, preserving the prior std-only, `unsafe`-free behavior.

## [2.1.0] - 2026-07-05

### Security

- **OAuth proxy endpoints now honor the configured `max_request_body`.**
  The `/token`, `/register`, `/introspect`, and `/revoke` proxy routes
  previously fell back to axum's 2 MB `DefaultBodyLimit` because the
  `RequestBodyLimitLayer` was scoped to `/mcp` only. They are now built on a
  dedicated sub-router that applies the operator-configured limit (via
  `RequestBodyLimitLayer`), so a single `max_request_body` value governs all
  inbound bodies. Oversized requests to these routes now return `413`.
  (rust-review MEDIUM.)
- **Upstream OAuth proxy responses are now size-capped.** `handle_token`,
  the introspect/revoke admin proxy, and the RFC 8693 token-exchange path
  now read upstream responses through a bounded, fail-closed streaming
  helper (`OAUTH_PROXY_MAX_RESPONSE_BYTES`, 1 MiB) instead of an unbounded
  `resp.bytes()`. An oversized or unreadable upstream response yields a
  generic `502` and is never forwarded to the client — symmetric with the
  already-bounded JWKS fetch. (rust-review LOW.)

### Added

- **`McpxError::client_message()`** — returns the exact client-facing body
  for any variant (verbatim message for `Auth`/`Rbac`/`RateLimited`/
  `RateLimitedFor`; a generic `"internal server error"` for all internal
  variants). Additive; documents and exposes the client-safe-message
  invariant that `IntoResponse` already upholds. (rust-review LOW hardening.)

### Changed

- **JSON logs no longer emit escaped `Debug` wrappers for claim/identity
  fields.** Structured fields that were logged with `?` on quote-bearing
  types (`Option<String>`, `serde_json::Value`, audience lists) now render
  as clean native strings — e.g. `"sub":"alice"` instead of
  `"sub":"Some(String(\"alice\"))"`. Added internal helpers
  (`fmt_json_aud`, `fmt_json_str`, `OneOrMany::log_display`,
  `AudienceValidationMode::as_str`); the `aud` claim is formatted so
  string-or-array audiences are preserved without loss. Log levels, fields,
  and the (stderr) output stream are unchanged. The deliberate `Debug`
  rendering of unparseable attacker-supplied CDP URLs (log-injection
  defense) is intentionally retained.

### Documentation

- Annotated the request-path async fns (`authenticate_bearer_identity`,
  `validate_token_with_reason`, `decode_claims`, `find_key`,
  `refresh_with_cooldown`, `refresh_inner`) with mandated cancel-safety
  comments (RUST_GUIDELINES §5). `JwksCache::refresh_with_cooldown` is
  documented as **NOT cancel-safe by design**: it commits the refresh
  cooldown before fetching to throttle JWKS-endpoint abuse, accepting a
  ≤10 s post-cancellation false-negative window during key rotation rather
  than reopening the invalid-JWT → JWKS-refresh DoS vector. (rust-review
  LOW; behavior unchanged.)

## [2.0.0] - 2026-07-04

### Changed

- **BREAKING: Bumped the `rmcp` SDK from 1.8 to 2.1** — a major
  ([rmcp-v1.8.0...rmcp-v2.1.0](https://github.com/modelcontextprotocol/rust-sdk/compare/rmcp-v1.8.0...rmcp-v2.1.0)).
  rmcp 2.0 realigns the Rust API with the MCP 2025-11-25 spec. The **JSON
  wire format is unchanged** (only additive `_meta` / optional fields);
  all breakage is at the Rust API level. In-crate this touched exactly the
  unified content model: `rmcp::model::Content` / `RawContent` are replaced
  by the flat `ContentBlock` (the `Annotated<T>` wrapper and the `.raw`
  accessor are gone). We updated `Content::text(...)` → `ContentBlock::text(...)`
  and the `matches!(&result.content[N].raw, RawContent::Text(_))` test
  assertions → `matches!(&result.content[N], ContentBlock::Text(_))` in
  `src/tool_hooks.rs`, `tests/e2e.rs`, and `benches/hook_latency.rs`.
  `ServerHandler`, `ServerInfo` / `ServerCapabilities` (already built via
  the builder), `StreamableHttpService`, `StreamableHttpServerConfig`,
  `ServiceExt`, `transport::io::stdio()`, and the requested feature set
  (`server`, `transport-streamable-http-server`, `transport-io`, `macros`)
  are all source-compatible and unchanged. rmcp 2.1 (over 2.0) is a
  drop-in with fixes only (SEP-414 trace-context accessors, SEP-2575 meta
  helpers, cancel-safe `AsyncRwTransport::receive`, OAuth refresh-token
  preservation) — none of which this crate consumes directly. No MSRV
  change (rmcp pins nothing above our Rust 1.95 floor).

  **Why this is a major for `rmcp-server-kit`:** rmcp types appear in this
  crate's public API (`HookedHandler<H: ServerHandler>` and its
  `ServerHandler` impl, `HookOutcome::Replace(Box<CallToolResult>)`, and
  other hook signatures returning/consuming `CallToolResult`). Downstream
  code that pattern-matches on the re-exported content model must migrate
  `RawContent`/`.raw` → `ContentBlock`. (`cargo semver-checks` reports no
  change to *our* signature names, but it cannot see the semantic break in
  the re-exported rmcp types, so the next release is bumped to **2.0.0**
  deliberately.)

- **`tower-http` intentionally stays on 0.6** (currently 0.6.11, the latest
  0.6). 0.7.0 is available but `reqwest` (which we depend on directly) and
  `axum 0.8` both hard-pin `tower-http = "^0.6.8"`, so upgrading our direct
  dependency to 0.7 would only fork a second `tower-http` major into the
  tree with no functional benefit — we use no 0.7-only feature, and the one
  0.7 API delta that would touch us (`SizeAbove` threshold `u16`→`u64`)
  is a cost, not a gain. This will be revisited once `reqwest`/`axum`
  admit `tower-http 0.7`. Other dependencies were refreshed to their latest
  semver-compatible patches (`humantime` 2.3→2.4, `rand` 0.10.1→0.10.2,
  `rustls-pki-types` 1.14→1.15, `time` 0.3.51→0.3.53, `num-bigint`
  0.4.6→0.4.7).

## [1.15.0] - 2026-06-29

### Changed

- **Bumped the `rmcp` SDK from 1.7 to 1.8.** Non-breaking for this crate
  ([rmcp-v1.7.0...rmcp-v1.8.0](https://github.com/modelcontextprotocol/rust-sdk/compare/rmcp-v1.7.0...rmcp-v1.8.0)):
  `ServerHandler`, `StreamableHttpService`, `call_tool` / `CallToolRequestParams`,
  and the `handler::server` module are all source-compatible. rmcp 1.8 adds
  transparent server-side hardening that flows through `serve()` unchanged —
  `MCP-Protocol-Version` header vs initialize-body validation, stricter tool
  input/output-schema stripping, and SEP-2164 resource-not-found code
  selection (peers on `2026-07-28`+ get `INVALID_PARAMS`, older peers keep
  `RESOURCE_NOT_FOUND`). SEP-2577 deprecates Roots/Sampling/Logging in the SDK;
  this crate does not use those APIs, so no warnings surface. `tower-http`
  stays on 0.6 (reqwest 0.13.4 still pins `^0.6.8`; 0.7 would only fork the
  tree without benefit). Other dependencies refreshed to latest semver-compatible
  patches (anyhow, rustls, bytes, zeroize, time, uuid, …).

## [1.14.0] - 2026-06-11

### Added

- **Exempt paths for the extra-route rate limiter**
  ([#11](https://github.com/andrico21/rmcp-server-kit/issues/11)):
  `McpServerConfig::with_extra_route_rate_limit_exempt_paths(paths)` +
  TOML `server.extra_route_rate_limit_exempt_paths`. Entries are matched
  by **raw exact string comparison** against the request path — no
  globs, no normalization — and the check is fail-closed (anything not
  listed stays limited) and runs before key extraction, so exempt
  requests (e.g. the RFC 8414 metadata document MCP clients fetch on
  every connect) consume no limiter budget and never appear in deny
  telemetry. Requires `extra_route_rate_limit`; entries must be
  non-empty and start with `/` (validated at startup).
- **Prometheus deny counters for all four built-in rate limiters**
  ([#11](https://github.com/andrico21/rmcp-server-kit/issues/11),
  feature `metrics`): new `McpMetrics.rate_limited_total`
  (`rmcp_server_kit_rate_limited_total`, label `limiter` in `tool` /
  `auth_pre` / `auth_post` / `extra_route`), incremented at each deny
  site alongside the existing warn-level log. The shared `McpMetrics`
  handle now travels to inner middleware via a request extension
  inserted by the metrics layer; with metrics disabled the deny sites
  are unchanged. `McpMetrics` is `#[non_exhaustive]`, so the field
  addition is semver-minor.

### Security

- **CRL URL gate now rejects embedded credentials (userinfo), and
  rejection sites no longer echo what they reject.** The shared
  scheme guard used by CDP extraction and the CRL fetcher refuses
  `https://user:pass@host/...` URLs (`userinfo_forbidden`) — making the
  userinfo rejection that `SECURITY.md` already documented actually
  enforced — and both rejection sites log only a sanitized
  scheme+host+port rendering, so credentials from a CA chain's or client
  certificate's CDP extension can never reach warn logs or error
  strings. Found by the 1.13.0 guidelines review; fix design approved by
  Oracle and Momus review gates.
- **OAuth redirect-rejection warns no longer echo the rejected target
  URL.** Both redirect-policy closures (`OauthHttpClient`, `JwksCache`)
  log the sanitized scheme+host+port instead of the full target, so a
  malicious IdP redirecting to a userinfo-bearing URL cannot plant
  credentials in the logs.

### Fixed

- **Unparsed CDP URIs are debug-logged with `Debug` formatting** (`?raw`
  instead of `%raw`), escaping control characters an attacker could
  embed in a client certificate's CDP extension to forge log lines or
  emit terminal escapes (the string only reaches this branch when
  `Url::parse` fails, which strips none of the original bytes).

### Documentation

- All non-test `tokio::select!` sites now carry explicit
  `// cancel-safe:` annotations (transport shutdown races, CRL
  bootstrap/refresher loops), completing the crate's cancel-safety
  documentation mandate.
- New `SECURITY.md` subsection "CRL discovery under adversarial load":
  documents the pre-validation CDP discovery invariant, the bounded
  griefing residual and why per-source-IP budgeting is impossible at the
  `ClientCertVerifier` layer, plus operator guidance (alert on
  `discovery_rate_limited`, size `crl_max_seen_urls` /
  `crl_max_cache_entries` to the CA estate, rely on bootstrap
  pre-seeding). The drop-newest-at-cap cache policy rationale (LRU would
  let an attacker evict the legitimate warm set) is now documented at
  the policy site and in `SECURITY.md`.

### Tooling

- **`clippy::nursery` enabled crate-wide at `warn`** (promoted to deny in
  CI via `-D warnings`), with three documented allows:
  `missing_const_for_fn` (const-ness on pub fns is a one-way semver
  promise), `redundant_pub_crate` (antagonistic to the enabled
  `unreachable_pub`), and `option_if_let_else` (readability regressions
  on the HMAC-fallback / poisoned-lock idioms). ~90 nursery findings
  fixed across the crate, including explicit early guard drops on the
  JWKS/CRL cache write paths and doc-link cleanups.
- **`str_to_string` flipped from `allow` to `warn`** and remaining
  violations fixed; `string_to_string` documented as removed from clippy
  (covered by the already-enabled `implicit_clone`).
- **`await_holding_refcell_ref` and `mem_forget` denied** (declared for
  future-proofing; the crate has no current usage of either).
- **`cargo vet` exemption baseline committed** under `supply-chain/`
  (400 exemptions); the CI vet job now runs without `|| true` and can be
  promoted to required after a green run.
- **New `taplo` CI job** (`taplo fmt --check`); all tracked TOML files
  reformatted to the repo's `.taplo.toml` policy, which now excludes the
  cargo-vet-owned `supply-chain/` directory.

## [1.13.0] - 2026-06-11

### Added

- **Trusted-forwarder mode: proxy-aware client IPs for all rate
  limiters** (completes the final deferred item from
  [#10](https://github.com/andrico21/rmcp-server-kit/issues/10)):
  `McpServerConfig::with_trusted_proxies(cidrs)` +
  `with_forwarded_header(mode)` (TOML `server.trusted_proxies`,
  `server.forwarded_header` = `"x-forwarded-for"` default /
  `"forwarded"` for RFC 7239). When the **direct peer** is inside the
  trusted CIDRs, the client IP is resolved via the rightmost-untrusted
  walk over the last forwarding-header instance (16-entry scan cap;
  malformed/obfuscated/all-trusted chains fall back to the direct peer;
  only reason codes are logged, never header contents). The result is
  the new public `transport::ClientIp` request extension, and **all
  four per-IP rate limiters now key by it** — behind a proxy, clients
  get individual buckets instead of sharing the proxy's. With the
  feature off (default), `ClientIp` equals the direct peer and behavior
  is unchanged. `PeerAddr` keeps its direct-socket-peer contract.
  Headers from untrusted peers are ignored entirely (leftmost-trust is
  never used). New dependency: `ipnet` (MIT OR Apache-2.0).

## [1.12.0] - 2026-06-11

### Added

- **`Retry-After` on every rate-limit response.** All four built-in
  limiters (auth pre-auth gate, post-failure auth limiter, `tools/call`
  limiter, extra-route limiter) now deny with a `Retry-After: n` header
  (RFC 9110 delta-seconds: best-effort wait rounded **up** to whole
  seconds, never `0`) alongside the unchanged 429 status and plain-text
  body. Backed by the new `BoundedKeyedLimiter::check_key_wait` method
  (returns the wait `Duration` on deny; `check_key` now delegates to it)
  and the new `McpxError::RateLimitedFor { message, retry_after }`
  variant. The legacy `McpxError::RateLimited(String)` variant is
  retained and remains headerless. Completes the first deferred item
  from [#10](https://github.com/andrico21/rmcp-server-kit/issues/10).
- **Optional burst knobs on every rate limiter.** Burst sets the bucket
  capacity (maximum requests admitted back-to-back); the sustained
  per-minute rate is unchanged, and burst may be smaller or larger than
  the rate. New surface: `McpServerConfig::with_tool_rate_limit_burst` /
  `with_extra_route_rate_limit_burst` (+ TOML `tool_rate_limit_burst`,
  `extra_route_rate_limit_burst`) and
  `RateLimitConfig::{with_burst, with_pre_auth_burst}` (+ TOML
  `auth.rate_limit.{burst, pre_auth_burst}`). Bursts must be greater
  than zero; the tool/extra-route bursts require their base knob, while
  `pre_auth_burst` is valid without an explicit pre-auth rate (the
  gate's base always resolves to `max_attempts_per_minute × 10`).
  Unset = today's behavior (burst = rate). Completes the second
  deferred item from
  [#10](https://github.com/andrico21/rmcp-server-kit/issues/10).

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
