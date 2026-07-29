# Adopting & migrating `rmcp-server-kit`

This guide shows how to wire the standalone `rmcp-server-kit` crate into a
downstream project, and how to migrate across breaking major releases.

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

3. **MSRV.** rmcp 3.0 requires Rust ≥ 1.88; `rmcp-server-kit` continues to
   target 1.95, so no action is needed.

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

`rmcp-server-kit` targets stable Rust **1.95** or newer (`edition = "2024"`).
Bumping the MSRV is a minor-version change under the project's SemVer
policy.
