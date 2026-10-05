# Contributing to rmcp-server-kit

Thanks for your interest in contributing!

## Coding standards

All Rust code in this repository must follow the vendored universal
guidelines: start at
[docs/rust-guidelines/RUST_GUIDELINES.md](docs/rust-guidelines/RUST_GUIDELINES.md)
(the core), then the HTTP-services, MCP-servers and project overlays it names
in its load order. The root [RUST_GUIDELINES.md](RUST_GUIDELINES.md) is the
index (provenance, hashes, open deviations, re-vendor procedure). Before
opening a PR, review the Quick Reference Checklist at the end of the core;
reviewers will enforce it. The strictest stable lint profile (core Section 9)
is committed in `Cargo.toml`, and permanent CI gates keep it honest: the
catalog, allow, profile-equality and prose gates under `scripts/lint-ratchet/`.
The `docs/RUST_1_95_NOTES.md` file is a historical record frozen at Rust 1.95;
the current toolchain policy is the MSRV work in `docs/MIGRATION.md` (3.15).

## Development prerequisites

- Rust **1.99 or newer** (stable toolchain) - `edition = "2024"`.
- `cargo-deny` (for the `ci deny` step): `cargo install cargo-deny`.
- `cargo-audit` (for the `ci audit` step): `cargo install cargo-audit`.
- `cargo-vet` (for the `ci vet` step): `cargo install cargo-vet`.
- `taplo` (for the `ci taplo` step): `cargo install taplo-cli`.
- A dated nightly toolchain is only required for `cargo fmt` (the
  `rustfmt.toml` uses a couple of unstable options). CI pins `nightly-2026-10-03`;
  install it with `rustup toolchain install nightly-2026-10-03 --component rustfmt`.

## Verification steps

Run locally before opening a PR - these mirror the blocking CI gates (the
authoritative list is [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
cargo +nightly-2026-10-03 fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --all-features --test docs_citations
lychee --offline --no-progress README.md RUST_GUIDELINES.md docs/*.md
cargo deny check
cargo audit
cargo vet --locked
taplo fmt --check
(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)
python3 scripts/lint-ratchet/catalog_gate.py
python3 scripts/lint-ratchet/allow_gate.py --enforce
python3 scripts/lint-ratchet/profile_eq.py --clippy-toml
python3 scripts/lint-ratchet/prose_gates.py --enforce
```

All of these must pass.

Warnings are denied for local builds too, by the committed
`.cargo/config.toml` (`[build] warnings = "deny"`). While iterating on
work-in-progress code you can relax this for a single command without
editing the config (and without invalidating the build cache):

```bash
CARGO_BUILD_WARNINGS=allow cargo build
```

Use this only for transient local iteration - a PR must not leave warnings
behind.

## Pull request checklist

- [ ] Commit follows the [Conventional Commits](#commit-convention) format.
- [ ] `fmt`, `clippy`, and `test` all clean.
- [ ] New public items are documented (rustdoc, `#[must_use]` where
      appropriate).
- [ ] CHANGELOG updated under `## [Unreleased]` if user-visible.
- [ ] No `unwrap()` / `expect()` / `panic!` in library code paths.
- [ ] No internal error details leaked in HTTP responses.

## Commit convention

```
<type>(<scope>): <subject>

<body>
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`.
**Scopes** (one of the top-level modules): `transport`, `auth`, `rbac`,
`config`, `error`, `observability`, `oauth`, `metrics`, `admin`,
`tool-hooks`, `secret`.

Examples:

- `feat(oauth): support RFC 8693 token-exchange with mTLS`
- `fix(transport): accept `Host: host:port` with non-default port`
- `docs(rbac): document task-local accessors`

## Coding rules (non-negotiable)

- `unsafe_code` is forbidden at the crate level.
- No `unwrap()` / `expect()` / `panic!` / `todo!` in library code.
- Accept `&str` not `&String`; `&[T]` not `&Vec<T>`.
- No `.clone()` to satisfy the borrow checker.
- No blocking I/O inside `async fn`.
- All HTTP responses must carry OWASP security headers set by the
  middleware stack.
- Secrets go through `secrecy::SecretString` / `secrecy::SecretBox`.

## Adding a cargo feature

1. Gate the new optional dependency with `optional = true`.
2. Add a `[features]` entry that activates it via `dep:<crate>`.
3. Document the feature in `README.md` and `docs/GUIDE.md`.
4. Add a `[package.metadata.docs.rs]` exercise if the feature introduces
   new public items (docs.rs already builds with `all-features = true`).
5. Extend CI: `cargo test --features <new-feature>` matrix entry.

## Licensing

Contributions are dual-licensed under MIT OR Apache-2.0, matching the
crate. By opening a PR you agree to this licensing.
