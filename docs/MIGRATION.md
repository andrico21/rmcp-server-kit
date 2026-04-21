# Adopting `rmcp-server-kit`

This guide shows how to wire the standalone `rmcp-server-kit` crate into a
downstream project. There is no version-to-version migration history yet —
`1.3.1` is the first usable release on crates.io.

## 1. Add the dependency

### crates.io (recommended)

Use a caret range so patch and minor releases flow in automatically:

```toml
[dependencies]
rmcp-server-kit = { version = "1", features = ["oauth"] }
```

Avoid the exact-version pin (`version = "=1.3.1"`); it prevents security
patches from reaching your build.

### Git dependency (development / pre-release)

Pin to a tagged release:

```toml
[dependencies]
rmcp-server-kit = { git = "https://github.com/andrico21/rmcp-server-kit", tag = "1.3.1", features = ["oauth"] }
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
