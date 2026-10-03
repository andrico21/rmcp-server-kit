# Project overlay: rmcp-server-kit

**Load order:** core `RUST_GUIDELINES.md` -> `overlays/domains/http-services.md` ->
`overlays/domains/mcp-servers.md` -> this file.

## The project (verified 2026-10-02)

- **What:** a reusable MCP server framework with auth, RBAC and Streamable HTTP
  transport, built on the `rmcp` SDK. It is a **published library** on crates.io;
  versions 3.14.2 and 3.14.3 are in the local registry cache.
- **Toolchain:** edition 2024, `rust-version = "1.98.0"`, `unsafe_code = "forbid"`.
  `rust-toolchain.toml` pins `channel = "1.98.1"`, and CI uses `1.98.0`, `stable` and
  `nightly` jobs.
- **CI:** `ci.yml`, `release.yml`.
- **Notable dependencies:** `rmcp`, `axum`, `tower`, `tower-http`, `jsonwebtoken`,
  `rustls`, `rcgen`, `secrecy`, `tokio`.

## Project-specific rules

- **Published-library rules apply in full** (core Section 9, "Library crates"):
  `#[non_exhaustive]` public types, `#[inline]` public functions, a documented public
  surface, and `cargo semver-checks` in CI on every PR.
- **Profile lints that change the public API are semver-major.** Adding `#[non_exhaustive]`,
  removing re-exports and `const` changes all break downstream code. Schedule them for the
  next major version. Until then, the affected public items carry
  `#[expect(<lint>, reason = "public API frozen until the next major release")]`. These are
  item-level exceptions with a reason, never manifest allows.
- **Re-export facades** carry one module-level `#![expect(clippy::pub_use, reason = "public facade")]`.
- **The package ships this repository's guideline file.** It appears in the crates.io
  registry copies. Once the file becomes a pointer, the published crate carries the pointer.
  Alternatively, exclude it via `package.exclude`.

## Deviations to resolve (status 2026-10-02)

1. Lints: `pedantic`/`nursery` at `warn`. Remove the allows:
   - `missing_const_for_fn`, `option_if_let_else`;
   - `doc_markdown`: use `doc-valid-idents` instead;
   - `duration_suboptimal_units`.

   `redundant_pub_crate = "allow"` matches the profile. `unneeded_field_pattern` is excluded
   by the profile.
2. Toolchain: the `rust-toolchain.toml` pin (1.98.1) and the CI `1.98.0` job contradict the
   core Version Policy. Remove them, or record the reason here (e.g. an MSRV promise to
   downstream users, which must then be stated as `rust-version`).
3. `deny.toml`: `multiple-versions = "warn"` -> `"deny"`.
4. `.cargo/config.toml`: `build.warnings = "deny"` is not set.
5. 1.99 lint impact: 25 message-less `assert!(..is_empty())` sites (`assert_is_empty`).
6. 1.99 idioms: 2 `String::from_utf8_lossy(..).into_owned()` sites.

## Common alignment steps (every project)

- **Lint tables.** Replace this project's `[lints]` / `[workspace.lints]` tables wholesale
  with the core Section 9 profile, and set `[lints] workspace = true` in every member.
  Project-only additions go *on top*; nothing is removed.
- **`clippy.toml`.** Make it match core Section 9. Add this project's proper nouns to
  `doc-valid-idents` and its unavoidable duplicates to `allowed-duplicate-crates`, each with
  a reason.
- **`.cargo/config.toml`.** Commit `[build] warnings = "deny"`.
- **CI.** Run the full core Section 12 list, including
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` and `cargo machete`.
- **Old guideline file.** Replace the project's `RUST_GUIDELINES.md` with the pointer file
  from the universal repository's README. Do not keep a stale copy.
