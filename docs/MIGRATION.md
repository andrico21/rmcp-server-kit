# Adopting & migrating `rmcp-server-kit`

This guide shows how to wire the standalone `rmcp-server-kit` crate into a
downstream project, and how to migrate across breaking major releases.

## Migrating to 3.8: RFC 8693 token-exchange optionality

`3.8` contains **one source-breaking API change**, shipped in a minor release as
a deliberate, documented exception to the "breaking changes bump major" policy.
It affects only code that constructs `TokenExchangeConfig` in Rust.

**TOML configuration files require no change, and the token-exchange request
sent on the wire is byte-identical for any pre-3.8 configuration.**

### `TokenExchangeConfig::audience` is now `Option<String>`

RFC 8693 §2.1 marks `audience` OPTIONAL — only `grant_type`, `subject_token`,
and `subject_token_type` are REQUIRED. The crate previously made it mandatory
and always emitted it, so omission was unrepresentable and an authorization
server that rejects `audience`, or expects RFC 8707 `resource` instead, could
not be configured.

`audience` therefore left the constructor and became a setter:

```rust
// before
let tx = TokenExchangeConfig::new(
    token_url, client_id, Some(secret), None, "downstream-api".to_string(),
);

// after
let tx = TokenExchangeConfig::new(token_url, client_id, Some(secret), None)
    .with_audience("downstream-api");
```

To omit the parameter entirely, simply do not call `.with_audience(..)`.

`audience = ""` is now **rejected at startup**: an empty value is a malformed
request parameter, distinct from omission. Omit the key instead.

### New optional parameters

`with_resource`, `with_scope`, and `with_requested_token_type` expose the
remaining RFC 8693 §2.1 OPTIONAL parameters. All default to omitted except
`requested_token_type`, which defaults to `access_token` — exactly what every
release before 3.8 always sent.

`resource` is validated as an RFC 8707 absolute URI with no fragment. It is
**unrelated** to `oauth.proxy.strip_resource_param`, which governs the OAuth
proxy endpoints, not token exchange.

## Migrating to 3.9: CRL fail-closed by default

`3.9` is additive at the API level -- `cargo semver-checks` reports no breaking
change -- but it **alters two runtime defaults**. `cargo semver-checks` cannot
detect a behavioural default change, so read this section before upgrading.

### 1. `crl_deny_on_unavailable` now defaults to `true`

Previously, a client certificate advertising CRL distribution points was
**accepted** when its CRL could not be fetched or was not yet cached. That is
the exact condition an attacker holding a revoked certificate can induce, by
blocking reachability to the CA's CDP host.

From `3.9`, such a handshake is **rejected**, per RFC 5280 §6.3. Denial requires
*every* relevant CDP to be unavailable, not merely one -- otherwise blocking a
single mirror would become a denial-of-service vector.

**Who is affected:** deployments using mTLS with `crl_enabled = true` (the
default) whose client or CA certificates carry CDP extensions.

**Before upgrading, verify:**

- The CDP hosts in your client and CA certificates are reachable from the
  server's network, including through any egress proxy or firewall.
- `crl_max_cache_entries` (default `1024`) is large enough for your PKI.
  Fail-closed makes this cap **operationally visible**: a CDP that fetches
  successfully can still be rejected at the cache cap, leaving those
  handshakes denied. Large PKIs should raise it.
- The CRL SSRF guard permits your CDP hosts. Private, loopback, link-local,
  and cloud-metadata addresses are always rejected.

**To retain the previous behaviour**, opt out explicitly:

```toml
[server.auth.mtls]
crl_deny_on_unavailable = false
```

This is strongly discouraged: it accepts a revoked certificate whenever its
CRL is unreachable.

### 2. Secrets are redacted in `Debug` and log output by default

`ExchangedToken` (OAuth access tokens), the token-exchange claim log (`sub`,
`aud`, `azp`, `iss`), and `ToolCallContext` (tool arguments, identity, role,
`sub`) previously rendered their contents in plaintext. They now redact.

If you relied on that output for debugging, re-enable it per category:

```toml
[observability]
log_plaintext_oauth_tokens = false  # OAuth access tokens
log_oauth_claim_values     = false  # JWT sub / aud / azp / iss
log_tool_call_arguments    = false  # tool arguments and identity fields
```

or via `RMCP_SERVER_KIT__OBSERVABILITY__LOG_PLAINTEXT_OAUTH_TOKENS` and
friends.

> These switches are **process-wide, not per-server**. A process hosting more
> than one server shares one set. Enabling one writes secrets to your logs;
> intended for short-lived local debugging only.

### 3. `auth.mtls` without TLS is now a validation error

Configuring `auth.mtls` without both `tls_cert_path` and `tls_key_path` used to
start successfully with client-certificate authentication **silently disabled** --
a plaintext listener never performs a TLS handshake, so no client identity is
ever extracted. This combination is now rejected by
`McpServerConfig::validate()`. Supply both TLS paths, or remove `auth.mtls`.

### 4. Argument allowlists warn when `required = false`

An `ArgumentAllowlist` with a non-empty `allowed` list and `required = false`
constrains the argument only when the caller supplies it. If your tool
substitutes a default for a missing argument, a caller can bypass the allowlist
by omitting it. This now emits a startup warning naming the tool and argument.

Behaviour is unchanged in `3.9`. Prefer the new constructor:

```rust
ArgumentAllowlist::new_required("tool", "arg", vec!["allowed".into()]);
```

`required` will default to `true` in `4.0`.

### 5. Certificates advertising more than 64 CDP URLs are rejected

**Impact:** a client certificate carrying more than **64** distinct CRL
distribution point URLs is now rejected as malformed.

**This applies in both fail-open and fail-closed modes and has no opt-out.**
`crl_deny_on_unavailable = false` opts out of *revocation-unavailability*
denials; it does not opt out of malformed-certificate rejection, because the
amplification being bounded is paid identically in fail-open mode.

**Action required:** none for conforming certificates. RFC 5280
[4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) treats
multiple URIs inside one `DistributionPoint` as alternative ways to obtain the
same CRL, so a conforming certificate needs only a handful. If you genuinely
issue client certificates with more than 64 distinct CDP URLs, they will now be
rejected; reduce the count or use CRL partitioning.

**Observable signature:** a throttled `crl_cdp_url_cap_exceeded` WARN naming
the observed count and the cap.

### 6. `CrlSet::cache` and the ungated test constructors are deprecated

**Impact:** `CrlSet::cache`, `CrlSet::__test_with_prepopulated_crls`, and
`CrlSet::__test_with_kept_receiver` now carry `#[deprecated(since = "3.9.0")]`.

> **This is not a semver-breaking change, but it CAN break your build.** A
> downstream crate compiling with `-D warnings` (or `#![deny(warnings)]`) will
> fail until it adds `#[allow(deprecated)]` at the call sites. This is a
> deliberate, documented cost of signalling the 4.0 change early.

**Action required:**

- **Reading** `CrlSet::cache` remains safe and behaves as before.
- **Mutating** `CrlSet::cache` out of band is now *detected and denies
  handshakes* when `crl_deny_on_unavailable = true`. Use
  `force_refresh` or the normal discovery/refresh path instead. If you were
  mutating the cache directly in tests, expect handshake denials and a
  throttled `crl_cache_out_of_band_mutation` WARN.
- If you call the `__test_*` constructors from your own integration tests, add
  a file-level `#![allow(deprecated, reason = "...")]`.

**Planned for 4.0:** `cache` becomes `pub(crate)`, and both `__test_*`
constructors become gated behind the `test-helpers` feature. Deprecating them
now is the only non-breaking way to give downstream users notice.

## Migrating from 3.4 to 3.5

`3.5` is additive at the API level -- `cargo semver-checks` reports no breaking
change, no default values were altered, and no code change is required to
upgrade. Existing configurations parse and behave identically to 3.4.x unless
you opt in to the new features.

### No action required

Upgrade by bumping the version constraint:

```toml
rmcp-server-kit = "3"
```

Run `cargo update -p rmcp-server-kit` and verify the full test suite passes.
Nothing else is needed.

### Opting in to environment variable overrides

3.5 adds three opt-in methods that layer env overrides onto already-constructed
config structs: `ServerConfig::apply_env_overrides`,
`ObservabilityConfig::apply_env_overrides`, and `RbacConfig::apply_env_overrides`.
None are called automatically by `serve()` or `validate()`.

To opt in, call the methods after TOML deserialization and before
`apply_to_mcp_config`. See
[Environment variable overrides (opt-in)](GUIDE.md#environment-variable-overrides-opt-in)
in the guide for the full call order, the 14-variable reference table, secret
handling rules, and the metrics-wiring caveat.

## Migrating from 3.3 to 3.4

`3.4` is additive at the API level — `cargo semver-checks` reports no breaking
change, no default values were altered, and no code change is required to
upgrade. Existing configurations parse and behave identically to 3.3.x unless
you opt in to the new features.

### No action required

Upgrade by bumping the version constraint:

```toml
rmcp-server-kit = "3"
```

Run `cargo update -p rmcp-server-kit` and verify the full test suite passes.
Nothing else is needed.

### Opting in to TOML-driven transport configuration

3.4 adds `ServerConfig::apply_to_mcp_config`, which bridges the existing TOML
schema into `serve()`. To use it, replace your manual field-wiring code with a
single bridge call. See
[Bridging TOML config to `McpServerConfig`](GUIDE.md#bridging-toml-config-to-mcpserverconfig)
in the guide for a worked example and a description of replacement semantics.

If you use the `[server.security_headers]` TOML table for the first time, review
the twelve available keys and their built-in defaults in the
[Customising security headers](GUIDE.md#customising-security-headers) section.
Any header you do not mention keeps its current default, so you can opt in
incrementally.

## Migrating from 3.2 to 3.3

`3.3` is additive at the API level — `cargo semver-checks` reports no breaking
change, and no code change is required to upgrade. It does, however, tighten
three **runtime behaviours** as part of a security-hardening pass. Each is a
deliberate fail-closed change with no opt-out: an escape hatch would simply be
the original weakness behind a config flag.

Review these before rolling out.

### 1. Prometheus `path` label values changed (`metrics` feature only)

Most likely to affect you, and the only one that can break silently.

`http_requests_total` and `http_request_duration_seconds` previously used the
**raw request path** as the `path` label. Any unauthenticated client could
therefore mint an unbounded number of Prometheus time series by requesting
random paths, growing in-process memory until exhaustion.

Label values now come from a closed set:

| Request | Old `path` label | New `path` label |
|---------|------------------|------------------|
| `GET /healthz` | `/healthz` | `/healthz` |
| `POST /mcp` | `/mcp` | `/mcp` |
| `POST /mcp/<session>` | `/mcp/<session>` | `/mcp` |
| `GET /does-not-exist` | `/does-not-exist` | `<unmatched>` |
| `FROBNICATE /healthz` | `FROBNICATE` (method label) | `OTHER` |

Label **names** are unchanged, so panels keyed on `path` or `method` keep
working. **Action:** if any dashboard, recording rule, or alert matches on a
raw unmatched path, update it to `<unmatched>`, and update anything matching
per-session `/mcp/...` paths to `/mcp`.

### 2. `Forwarded` header parsing requires balanced quotes

RFC 7239 §4 defines a parameter value as `token / quoted-string`, and a
quoted-string requires balanced `DQUOTE`. Values such as `for="203.0.113.9`
(lone leading quote), `for=203.0.113.9"` (lone trailing), and
`for="""203.0.113.9"""` were previously normalised into a valid address; they
are now rejected as malformed and client-IP resolution falls back to the direct
peer.

This removes a parser differential between `rmcp-server-kit` and the upstream
proxy, which matters because the resolved client IP feeds per-IP rate limiting
and operator allowlists.

**Action:** none, if your proxy emits RFC-compliant headers — well-formed
quoted values including `for="[2001:db8::1]:443"` are unaffected. If you see a
rise in fallback-to-peer resolution after upgrading, your proxy is emitting
malformed `Forwarded` values and should be fixed.

### 3. RBAC rejects a non-string `arguments.host`

The host was previously read with `as_str()`, so an array, object, number,
bool, or null yielded `None` and the request was evaluated **without** the
role's `hosts` glob restrictions. A caller could opt out of host restrictions
simply by changing the argument's shape.

A present-but-non-string `host` is now denied with 403.

**Action:** none for well-behaved clients. A client sending
`"host": ["prod-1"]` and receiving 200 before will now receive 403 — which was
the vulnerability. An **absent** `host` is unchanged and still evaluated
without host restrictions, so genuinely hostless tools (`ping`, `list_hosts`)
continue to work.

### Also in 3.3 (no action required)

- `ArgumentAllowlist::required` — new opt-in field, defaults to `false`.
  Existing configurations parse and behave identically. See
  [`GUIDE.md`](GUIDE.md) for when to enable it.
- mTLS CRL distribution points whose first fetch fails are now retried on a
  later handshake instead of being suppressed for the process lifetime.
- OAuth proxy requests drop caller-supplied client-authentication parameters
  before injecting the configured ones.
- Graceful shutdown lets in-flight MCP sessions finish within
  `shutdown_timeout` instead of cancelling them when the drain begins.

## Migrating from 2.x to 3.0

`3.0` upgrades the underlying MCP SDK from `rmcp` 2.x to **`rmcp` 3.0**.
Because your crate depends on `rmcp` **directly** (you implement
`rmcp::handler::server::ServerHandler` and use `rmcp::model` types), this is
a breaking change you must coordinate:

1. **Bump `rmcp` in lockstep.** In your own `Cargo.toml`, change
   `rmcp = "2"` to `rmcp = "3"` (keep your existing features). Your `rmcp`
   major must match the one `rmcp-server-kit` links against, or the
   `ServerHandler` trait will not unify.

2. **Update manual handler return types — only if you override them.**
   rmcp 3.0 makes `tools/call`, `prompts/get`, and `resources/read`
   MRTR-aware (SEP-2322). If your `ServerHandler` overrides these methods,
   change the return type to the new response enum and wrap your existing
   result with `.into()`:

   ```rust
   // 2.x
   async fn call_tool(&self, req: CallToolRequestParams, cx: RequestContext<RoleServer>)
       -> Result<CallToolResult, ErrorData>
   { Ok(CallToolResult::success(content)) }

   // 3.0
   async fn call_tool(&self, req: CallToolRequestParams, cx: RequestContext<RoleServer>)
       -> Result<CallToolResponse, ErrorData>
   { Ok(CallToolResult::success(content).into()) }
   ```

   The same pattern applies to `get_prompt` (`GetPromptResponse`) and
   `read_resource` (`ReadResourceResponse`). Handlers that only implement
   `get_info` — the common case — need **no** code change beyond step 1.

3. **MSRV.** rmcp 3.0 requires Rust ≥ 1.88; `rmcp-server-kit` targets
   1.98, so no action is needed.

The `rmcp-server-kit` public API surface (config, auth, RBAC, transport)
is otherwise unchanged for 3.0.

## 1. Add the dependency

### crates.io (recommended)

Use a caret range so patch and minor releases flow in automatically:

```toml
[dependencies]
rmcp-server-kit = { version = "3", features = ["oauth"] }
```

Avoid the exact-version pin (`version = "=1.6.0"`); it prevents security
patches from reaching your build.

### Git dependency (development / pre-release)

Pin to a tagged release:

```toml
[dependencies]
rmcp-server-kit = { git = "https://github.com/andrico21/rmcp-server-kit", tag = "3.0.0", features = ["oauth"] }
```

## 2. Workspace integration

If your project is a Cargo workspace, add your application crate as a
member and let it depend on `rmcp-server-kit` from crates.io:

```toml
[workspace]
members = ["my-app"]
resolver = "3"
```

`rmcp-server-kit` is published as a standalone crate; it is **not**
intended to be vendored as a workspace member of downstream projects.

## 3. Lints

`rmcp-server-kit` owns its own `[lints]` table and enforces a strict
internal lint set (no `unwrap` / `expect` / `panic` / `println!` in
production paths, `unsafe_code = "forbid"`, `missing_docs = "warn"`).
Downstream crates are free to keep or promote their own workspace
lints independently — the two lint tables do not interact.

## 4. Build & verify

```bash
cargo update -p rmcp-server-kit
cargo build --all-features
cargo test --all-features
```

If you observe a different `rmcp` version resolution than expected, pin
`rmcp` in your own `Cargo.toml` to match the version declared in
`rmcp-server-kit`'s `[dependencies]`.

## 5. Feature flags

| Feature   | Meaning                                                  |
|-----------|----------------------------------------------------------|
| `oauth`   | Enables OAuth 2.1 JWT validation and token exchange.     |
| `metrics` | Exposes a Prometheus registry and `/metrics` endpoint.   |

Both are opt-in to keep the default dependency footprint small.

## 6. Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.98** or newer (`edition = "2024"`).
Bumping the MSRV is a minor-version change under the project's SemVer
policy.
