# Adopting & migrating `rmcp-server-kit`

This guide shows how to wire the standalone `rmcp-server-kit` crate into a
downstream project, and how to migrate across breaking major releases.

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
