# Project overlay: rmcp-server-kit

**Load order:** core `RUST_GUIDELINES.md` -> `overlays/domains/http-services.md` ->
`overlays/domains/mcp-servers.md` -> this file.

## The project (verified 2026-10-06)

- **What:** a reusable MCP server framework with auth, RBAC and Streamable HTTP
  transport, built on the `rmcp` SDK (`rmcp` features `server`,
  `transport-streamable-http-server`). It is a **published library** on crates.io;
  versions 3.14.2 and 3.14.3 are in the local registry cache.
- **Toolchain:** edition 2024, `rust-version = "1.99.0"`, `unsafe_code = "forbid"`.
  No `rust-toolchain.toml` exists. CI runs `stable` everywhere, a `1.99.0` MSRV job
  (lint-capped: `--cap-lints=warn`, `CARGO_BUILD_WARNINGS=allow`, so it proves compile
  compatibility but not lint cleanliness), the dated fmt/docsrs pin `nightly-2026-10-03`,
  and a non-blocking latest-nightly rustdoc canary.
- **CI:** `ci.yml`, `release.yml` (GitHub) and `.gitlab-ci.yml` (GitLab mirror, image
  tag `rust:rust-1.99.0`).
- **Notable dependencies:** `rmcp`, `axum`, `tower`, `tower-http`, `jsonwebtoken`
  (optional, `oauth`), `rustls`, `rcgen` (dev-dependency), `secrecy`, `tokio`.
- **Vendored rules:** `docs/rust-guidelines/` holds the core, `http-services.md`,
  `mcp-servers.md` and this file byte-for-byte at the recorded pin, with `SHA256SUMS`
  checked in CI. The root `RUST_GUIDELINES.md` is the vendoring index (pin, hashes,
  deviation status, local deviations register).

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
- **The guideline files are excluded from the published crate.** `package.exclude` lists
  `RUST_GUIDELINES.md` and `docs/rust-guidelines/`, so the crates.io archive carries
  neither the vendoring index nor the vendored rules.

## Deviations to resolve (status 2026-10-06)

All six closed. Evidence: the project's `RUST_GUIDELINES.md` ("Overlay deviations: local
status" table) and its development-only record
`.omo/evidence/rust-guidelines-migration/final-report.md`.

1. Lints `pedantic`/`nursery` at `warn`; remove the listed allows; `doc_markdown` ->
   `doc-valid-idents` - **closed**: the core Section 9 profile is adopted verbatim
   (`all`/`pedantic`/`nursery`/`cargo` = `deny`); zero `#[allow]`/`#![allow]` in the tree
   (`allow_gate.py --enforce` = 0); `doc-valid-idents` is in `clippy.toml`;
   `redundant_pub_crate = "allow"` matches the profile. (PR #40.)
2. `rust-toolchain.toml` pin and CI `1.98.0` job - **closed**: the pin file is deleted,
   `rust-version` is `1.99.0`, and the GitHub `MSRV (1.99.0)` and GitLab `msrv` jobs are
   retargeted to 1.99. (PR #29.)
3. `deny.toml` `multiple-versions = "warn"` -> `"deny"` - **closed**: `"deny"`, with
   `[graph] all-features = true`, `unmaintained`/`unsound` scope `"all"`, and 21
   upstream-forced duplicates in `[bans] skip`, each with a reason; `cargo deny check`
   exits 0.
4. `.cargo/config.toml` `build.warnings = "deny"` not set - **closed**: it commits
   `[build] warnings = "deny"` (excluded from the published package). (PR #32.)
5. 1.99 lint impact: message-less `assert!(..is_empty())` sites - **closed, count
   corrected**: 26 at the overlay's own baseline `af71781`, 30 at `e05cf91`
   (`--all-features`; 27 on the default/no-oauth rows); all 30 fixed in PR #30, so the
   "25" here was wrong. Six message-less occurrences remain at HEAD (`src/auth.rs:4715`,
   `src/oauth.rs:6492,6516,6529,6593`, `src/ssrf.rs:1264`) and pass the Clippy job as
   configured - either `assert_is_empty`'s firing set is narrower than the core documents
   or these shapes are a profile gap; worth a `cargo clippy --all-targets --all-features`
   confirmation on 1.99.
6. 1.99 idioms: 2 `String::from_utf8_lossy(..).into_owned()` sites - **not applicable
   (false positive)**: both pass borrowed bytes (`src/mtls_revocation.rs:2388` takes
   `&guard`; `tests/integration/e2e_oauth_mtls.rs:250` takes `head = buf.get(..filled)`),
   so `from_utf8_lossy_owned` does not apply. Upstream erratum.

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
  from the universal repository's README. Do not keep a stale copy. (This project instead
  vendors the rules under `docs/rust-guidelines/` at a recorded pin, with checksum CI; that
  is the stricter variant of the same rule and is accepted.)
