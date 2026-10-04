# Rust guidelines (vendoring index)

This file is the **index** for the Rust rules that apply in this repository.
The rules themselves are the vendored universal guidelines under
`docs/rust-guidelines/`; the vendored core is
[`docs/rust-guidelines/RUST_GUIDELINES.md`](docs/rust-guidelines/RUST_GUIDELINES.md).
`rmcp-server-kit` is a published library, so the universal core and the
published-library rules apply in full. This index and the vendored directory are
development-only: `package.exclude` in `Cargo.toml` keeps them out of the
published crate.

## Load order

Read, in this order, before writing or reviewing Rust code here:

1. [`docs/rust-guidelines/RUST_GUIDELINES.md`](docs/rust-guidelines/RUST_GUIDELINES.md) - universal core
2. [`docs/rust-guidelines/overlays/domains/http-services.md`](docs/rust-guidelines/overlays/domains/http-services.md) - HTTP services (headers, SSRF, wire errors)
3. [`docs/rust-guidelines/overlays/domains/mcp-servers.md`](docs/rust-guidelines/overlays/domains/mcp-servers.md) - MCP servers
4. [`docs/rust-guidelines/overlays/projects/rmcp-server-kit.md`](docs/rust-guidelines/overlays/projects/rmcp-server-kit.md) - this project's overlay (always last)

The project overlay lists deviations that are still open. Treat them as tasks,
not as permission.

## Source and pin

- Upstream repository: `andrico21/rust-guidelines` (private; readable through
  `gh api`).
- Pinned commit: `1314cadf42caa88b172bc72d156eb2d3cbf65e7b` (2026-10-03).
- Nothing is ever written back to that repository. Errata in the vendored text
  are collected for the final report of the migration that introduced this
  index, never fixed here.

## Do not edit; re-vendor to update

The four files below are byte-for-byte copies of the upstream files at the
pinned commit. Do not edit them; do not "fix" a rule locally. A local edit forks
the rulebook silently, and the next re-vendor would overwrite it. To update,
follow the re-vendor procedure below.

CI verifies the checksums on every run:

```bash
(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)
```

This index is the only guideline file that may be edited. Historical documents
(released CHANGELOG sections, `docs/CODE_REVIEW.md`, `docs/RUST_1_95_NOTES.md`)
are frozen as of their dates.

## Vendored files

Paths are relative to `docs/rust-guidelines/`.

| Path | sha256 | git blob id |
| ---- | ------ | ----------- |
| `RUST_GUIDELINES.md` | `d8459547e7962dee69889a8b8d717ef50bb657ca681a519d636cfadfc9fd18a7` | `4a13d83d85599b5fbeaf44a3db96ed9c4ac1e7d1` |
| `overlays/domains/http-services.md` | `120d64975591eb62801c5f83586cebebcfe4495e939ef1b7bd376eb476859d83` | `a80c843f7f8b69e1026cc8bf50e465b253e6ea19` |
| `overlays/domains/mcp-servers.md` | `58b5a0badc579c13c80d8ae84819e242026fb1b62d78fa340eb7973014b57d7a` | `2d273357d98174573376ef9e8890683f530d8dbc` |
| `overlays/projects/rmcp-server-kit.md` | `f89cf3bbd4e5f2cdf4e58233b2892dd7968e06491876a8c99f19b61f7e144861` | `c3d9ef6b2dbbf90e8cbba067ed7620df141ba39f` |

The blob ids are the upstream git object ids at the pinned commit. Each was
verified equal to `git hash-object` of the local copy when vendored.
`docs/rust-guidelines/SHA256SUMS` carries the same hashes in `sha256sum -c`
format.

## Not vendored

- Upstream `README.md`: it names other private projects and their internals.
  Only its overlay-contract section is reproduced below.
- `overlays/domains/unsafe-ffi.md`: this crate forbids `unsafe`.
- `overlays/domains/embedded-no-std.md`: this is a `std` library, not firmware.
- `overlays/domains/kerberos-credential-protocols.md`: this crate is not a
  credential-protocol client.
- `overlays/projects/*.md` for other projects: they do not apply here.

## The overlay contract (verbatim excerpt)

From the upstream `README.md`, lines 44-58 at the pinned commit:

```
## The overlay contract

1. **The core applies to every crate.** Every overlay is read *on top of* it.
2. **Domain overlays add rules for their domain and never weaken the core.** There is
   exactly one declared override: `unsafe-ffi.md` may lower `unsafe_code` from `forbid` to
   `deny`, and only with per-item `#[expect(unsafe_code, reason = "...")]`.
3. **Project overlays add project rules and record deviations.** They never weaken the core
   or a domain overlay. A deviation is dated, temporary, and phrased as a task.
4. **Lints: add, never remove.** The core Section 9 profile is the floor. Local exceptions
   are `#[expect(lint, reason = "...")]` on the narrowest item; manifests carry no
   group-level allows.
5. **If an overlay contradicts the core outside a declared override, the core wins.** The
   overlay is then a bug to fix in this repository.
6. **Order of precedence when rules pull apart:** security, then correctness, then
   cleanliness.
```

## Overlay deviations: local status

The project overlay's "Deviations to resolve" list is a task list, not
permission. Status of each item at this vendoring:

| # | Deviation | Status | Closure / note |
| - | --------- | ------ | -------------- |
| 1 | `pedantic`/`nursery` at `warn`; remove the listed allows; `doc_markdown` -> `doc-valid-idents` | open | Closed by the Section 9 profile switch, which replaces the local lint table wholesale. |
| 2 | `rust-toolchain.toml` pin and the CI `1.98.0` job contradict the Version Policy | closed | Closed by the MSRV work: the pin file was deleted (PR #29), `rust-version` is `1.99.0`, and the GitHub and GitLab MSRV jobs plus every live 1.98 doc/CI reference are retargeted to 1.99. |
| 3 | `deny.toml`: `multiple-versions = "warn"` -> `"deny"` | closed | Closed by the core cargo-deny policy adopted in PR #31 (merged into this branch): `multiple-versions = "deny"`, `[graph] all-features`, `unmaintained` / `unsound` scope "all", licenses trimmed to the encountered set, duplicates in `skip` with a reason each. |
| 4 | `.cargo/config.toml`: `build.warnings = "deny"` not set | open | Closed by the warnings-policy work. |
| 5 | 1.99 lint impact: message-less `assert!(..is_empty())` sites | closed | All 30 test-side sites fixed on 1.99 in PR #30 (before this vendoring); they were never profile-only. The overlay's count is an erratum (30 measured, not 25) for the final report. |
| 6 | 1.99 idioms: `String::from_utf8_lossy(..).into_owned()` sites | not applicable | False positive: both sites convert borrowed bytes (`&guard`; `&buf[..filled]`), not owned bytes. Upstream erratum. |

Closure evidence for each row, and every erratum found in the vendored text,
goes to the final report of the migration; update this table when one lands.

## Drop audit (core 1208-1240)

Every `impl Drop for` in `src/` is audited against the core's async-resource
Drop rules: no blocking or async work beyond an explicitly bounded teardown, a
defined cleanup order, and no panic path. `scripts/lint-ratchet/prose_gates.py
--only drop-audit` keeps the audit comment present on each impl. Date:
2026-10-04.

| Impl | File:line | Finding |
| ---- | --------- | ------- |
| `Drop for ExposureTestGuard` | `src/diagnostics.rs:197` | Test-only. Restores the process-global switch snapshot in memory; sync, no I/O or await, no panic path. No defect. |
| `Drop for PendingUrlGuard` | `src/mtls_revocation.rs:1969` | Clears the in-flight URL marker (poison-recovering mutex); sync, no I/O or await, no panic path. Ordering is explicit via `disarm()` before promotion. No defect. |
| `Drop for TracingGuard` | `src/observability.rs:247` | Delegates to `AuditWorkerGuard` by taking the `Option`; sync, no await, no panic path. Bounded by design (5s). No defect. |
| `Drop for AuditWorkerGuard` | `src/observability.rs:441` | Signals shutdown then parks/joins the writer thread for at most `AUDIT_WRITER_JOIN_TIMEOUT` (5s); no async work or panic path. Bounded blocking is deliberate and documented. No defect. |
| `Drop for CancelOnDrop` | `src/transport.rs:2866` | Sync, non-blocking `CancellationToken::cancel`; no I/O, await or panic path. Never disarmed on purpose. No defect. |
| `Drop for TlsListener` | `src/transport.rs:3777` | Sync, non-blocking `JoinHandle::abort`; in-flight workers exit on the closed channel. No I/O, await or panic path. No defect. |

## Local deviations register

Deviations of this repository from the vendored rules are recorded here, dated
and with their reason and evidence, per the overlay contract (rule 3). Add an
entry in the same PR that introduces a deviation.

1. **2026-10-03 - RBAC deny messages stay verbose.** `src/rbac.rs` echoes tool,
   argument and role names in deny messages, and `src/error.rs` maps them to
   the wire; a source-scanning guard in `src/error.rs` pins those sites as
   allowed. This deviates from `mcp-servers.md:9-14,36` ("generic error codes
   and messages ... never the wire"). Owner decision: the messages are kept for
   operators; evidence in the migration record.
2. **2026-10-03 - The CRL fetch path has no hostname-suffix rejection.**
   `http-services.md` says to reject hostnames ending in `.local`, `.internal`
   and `.localhost`; the CRL fetcher instead screens the resolved IP at connect
   time (`SsrfScreeningResolver` plus `.no_proxy()` in `src/mtls_revocation.rs`;
   connect-time screening in `src/ssrf_resolver.rs`), with pre-flight screening
   on the bootstrap path. The OAuth path does implement the suffix rule.
   Owner-accepted: CRL integrity rests on the CA signature, and a name that
   resolves only to public IPs is not an internal-service SSRF.
3. **2026-10-03 - Client context off by default.** Core Section 10 expects auth
   attempts and RBAC denials to be logged with the source IP; `LogContextConfig`
   here keeps `client_ip` and the other client-context fields off unless an
   operator opts in (see the privacy note in `docs/GUIDE.md` and the 3.15
   migration section). Reason: client context can become personal data
   downstream; opting in is deliberate.
4. **2026-10-03 - Overlay deviation 6 does not apply.** Both
   `String::from_utf8_lossy(..).into_owned()` sites pass borrowed bytes
   (`src/mtls_revocation.rs`, `tests/integration/e2e_oauth_mtls.rs`). Upstream erratum, not
   a deviation.
5. **Informational (not a deviation):** the CSP sent by this crate is
   `default-src 'none'`, stricter than `http-services.md:30`
   (`default-src 'self'`). Stricter is allowed; recorded so no one "aligns" it.
6. **2026-10-04 - MSRV job lint-capped (compile compatibility only).** The
   GitHub `MSRV (1.99.0)` job and the GitLab `msrv` job run with
   `RUSTFLAGS="--cap-lints=warn"` and `CARGO_BUILD_WARNINGS=allow`. They prove
   that the crate compiles on `rust-version = "1.99.0"`; they do not enforce
   lint cleanliness. Lints stay enforced on the latest stable by the `clippy`
   and feature-matrix jobs, so a warning is still an error everywhere except in
   the minimum-version proof. This is the core Version Policy's MSRV job
   (core 3160-3165) and closes overlay deviation 2. Evidence: the task-2
   migration record (capped build log, CI check list).
7. **2026-10-04 - GitLab image tag not verified by the executor.** `CI_IMAGE`
   switched to
   `gitlab-ad.andrico.local:5050/ci-tools/rust-ci-images/rust:rust-1.99.0` on
   the owner's explicit instruction (Q2). The private registry cannot be
   inspected without credentials: an anonymous `skopeo inspect` returns
   `manifest unknown` even for the previously in-use `rust-1.98.0` tag, so the
   new tag could not be positively verified from this environment. GitLab
   pipelines are likewise unobservable here; GitHub CI is the gate. Verify the
   tag, or watch the first mirrored pipeline fail, once registry credentials are
   available. Evidence: the task-2 migration record.
8. **2026-10-04 - CI nightly is a dated pin with a non-blocking canary
   (D-14 v).** The GitHub `fmt` and docsrs jobs pin `nightly-2026-10-03`, the
   newest nightly that passes both `cargo +nightly-2026-10-03 fmt --all --
   --check` and `RUSTDOCFLAGS="-D warnings --cfg docsrs" cargo
   +nightly-2026-10-03 doc --no-deps --all-features`. docs.rs builds with its
   own current nightly, so a non-blocking `Rustdoc (latest nightly canary)` job
   runs the docsrs command on floating `nightly`. The pin moves only through
   the re-vendor + toolchain-bump procedure in this file.
9. **2026-10-04 - cargo-geiger runs informational (D-17).** Its GitHub job
   (`cargo-geiger (informational)`, `continue-on-error: true`) and GitLab job
   (`geiger`, `allow_failure: true`) run `cargo geiger --all-features`. It
   builds on Rust 1.99 (cargo-geiger 0.13.0) and runs, but exits non-zero
   whenever it finds unsafe code (`error: Found 251 warnings` on the current
   tree), which is why it must not gate merges. Evidence in the migration
   record.
10. **2026-10-04 - Temporary per-file `lint-migration:` expectations
   (D-6'').** The atomic profile switch lands the whole strict profile at once.
   Findings that the file-ownership lanes have not burned down yet are covered
   by generated expectations whose reason starts with `lint-migration:`. They
   sit at the file level for production lints, on `mod tests` for test-only
   lints, and at the crate root for standalone `tests/`/`benches/`/`examples/`
   crates, and each carries its file path. They are temporary and break core
   1568's narrowest-item rule while they exist; the lanes remove them. The
   `lint count gate` prevents any key from growing, and the stable `clippy` job
   still denies `unknown_lints` and `unfulfilled_lint_expectations`. Evidence:
   `scripts/lint-ratchet/baseline/`, the task-11 migration record, and
   `blocks.txt`.
11. **2026-10-04 - `pub_use` facade expectations (D-7'', core 1961-1962,
   2184).** The crate root and `secret` are public facades; their `pub use`
   re-exports are the point, so each module carries a single module-level
   `#![expect(clippy::pub_use, reason = "public facade")]` instead of an
   item-level expect (an item-level `pub_use` expect trips
   `clippy::useless_attribute`). The `secret` re-export additionally carries
   `#[expect(clippy::module_name_repetitions, reason = "public API frozen until
   the next major release")]`. Evidence: the task-11 migration record.
12. **2026-10-04 - Crate-level `dead_code_pub_in_binary` expectation (C-9).**
   `dead_code_pub_in_binary` fires on eight public `serve*` items only in the
   lib unit-test binary, and rustc accepts an expectation for it only at crate
   level. `src/lib.rs` therefore carries
   `#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "public API:
   unused inside the unit-test harness"))]`: inert in the lib build, fulfilled
   in lib-test. It is the narrowest scope rustc accepts, together with the
   facade expectation above the only inner expectations in `src/lib.rs`.
   Evidence: the task-11 migration record.
13. **2026-10-04 - `impl_trait_in_params` is frozen, not converted (task 12
   probe).** The Section 9 profile denies `clippy::impl_trait_in_params`, so
   every public `impl Trait`-in-parameter site needs a fix or an expectation.
   Converting an impl-Trait-only public fn to named generics is treated as a
   breaking change by the semver arbiter (D-7): a scratch probe converted
   `ToolCallContext::for_tool(tool_name: impl Into<String>)` to
   `for_tool<T: Into<String>>(tool_name: T)` and `cargo semver-checks
   check-release` then failed with
   `method_requires_different_generic_type_params` ("takes 1 generic types
   instead of 0"; 222 pass / 1 fail), because an argument-position `impl Trait`
   counts as zero explicit generic type parameters. The equivalent downstream
   calls (a plain call and a coercion to a `fn` pointer) still compiled against
   the converted fn, but D-7 names semver-checks the arbiter, so every public
   `impl_trait_in_params` site (47 diagnostics / 39 signature lines) is frozen
   with `#[expect(clippy::impl_trait_in_params, reason = "public API frozen
   until the next major release")]`, and mixed-shape sites (explicit generics +
   `impl Trait`) are frozen without probing. The lanes add the per-item
   expectations; this entry records the decision that governs them. Evidence:
   the task-12 migration record (`probe.txt`, `probe-converted.txt`).
14. **2026-10-04 - Lane 15 per-item frozen public-API expectations
   (`src/transport.rs`).** Under entry 13's decision this lane adds: the
   frozen `clippy::impl_trait_in_params` expectation on every public builder
   that takes `impl Trait` (`McpServerConfig::new`, `with_bind_addr`,
   `with_tls`, `with_public_url`, `enable_admin`, `with_metrics`,
   `with_tls_cert_path`, `with_tls_key_path`, `with_admin_role`); the frozen
   `clippy::missing_const_for_fn` expectation as one item-level attribute per
   `impl` block of `McpServerConfig` and of `Validated<T>`; and the frozen
   `clippy::field_scoped_visibility_modifiers` + `clippy::partial_pub_fields`
   expectation on the `pub(crate) McpServerConfig::metrics_handle` field (the
   narrowest scope rustc accepts for `partial_pub_fields`, since the lint is
   attributed to the struct). All carry the catalog reason `public API frozen
   until the next major release`. Two further item-level expectations document
   deliberate shapes rather than freezing API: `clippy::multiple_inherent_impl`
   on the second `impl McpServerConfig` block (it groups the TLS-path and role
   accessors; merging relocates ~140 lines for no behavior gain) and
   `clippy::too_many_lines` on `build_app_router` (the length is layer wiring,
   matching the pre-existing `cognitive_complexity` judgement on the same fn).
   The file's temporary test-suite expectations are covered by entry 10 and are
   removed by the test-conversion PR. Evidence: the task-15 migration record.
15. **2026-10-04 - `src/config.rs` per-item expectations (task 17).** Under
   entry 13's frozen-API decision, four public items keep names ending in the
   containing module's name and carry `module_name_repetitions` expectations:
   `ServerConfig`, `ObservabilityConfig`, `validate_server_config`,
   `validate_observability_config`. Two `deliberate:` expectations are
   recorded here because no behavior-preserving alternative exists: the five
   `pub(crate)` `EnvOverrideSpec` fields (the source-scanning tests read the
   spec table's declared shape) and `check_shared_config_invariants` staying
   non-`const` (a source-scanning test matches its `pub(crate) fn` prefix).
   Evidence: the task-17 migration record (`new-permanent-expects.txt`).

14. **2026-10-04 - `src/oauth.rs` lane expectations (frozen API + deliberate).**
   Under entry 13's decision, the 16 public `impl_trait_in_params` builder
   methods (`OAuthConfig::builder`; `OAuthConfigBuilder::{allowed_algorithms,
   authorization_server_metadata_issuer, authorization_servers, scope,
   role_claim, role_mapping, jwks_cache_ttl, ca_cert_path}`;
   `TokenExchangeConfig::{new, with_audience, with_resource, with_scope}`;
   `OAuthProxyConfigBuilder::{builder, introspection_url, revocation_url}`)
   carry the per-item frozen expectation. Two more public items are frozen
   with the same reason: `OauthHttpClient` (`module_name_repetitions`) and
   `missing_const_for_fn` on `OAuthConfig::effective_audience_validation_mode`
   and `ClientCertConfig::new` (const-ifying them is an API addition kept for
   the next major). Deliberate expectations, each cited in-line:
   `clippy::too_many_lines` on `OauthHttpClient::build` and
   `OAuthConfig::validate` (one reviewable block each);
   `clippy::field_scoped_visibility_modifiers` on `JwtRejection` (its fields
   are read by `src/auth.rs`; accessors would churn the crate-internal API);
   and, in `mod tests`, `clippy::unnecessary_wraps`, one per assertion-only
   test, so every test keeps the uniform `anyhow::Result<()>` signature
   (core's test pattern). Behavior-sensitive paths kept exact:
   `oauth_internal_suffix_blocked` (G-6 suffix rule), the 10-second JWKS
   refresh cooldown, and the redaction tests' output. Evidence: the task-16
   migration record (`status.txt`, `new-permanent-expects.txt`, `gates.txt`).

16. **2026-10-04 - `src/auth.rs` lane expectations (frozen API + deliberate).**
   Under entry 13's decision, five public items keep names ending in the
   containing module's name and carry `module_name_repetitions` expectations:
   `AuthIdentity`, `AuthMethod`, `AuthCountersSnapshot`, `AuthConfig` and
   `AuthConfigSummary`. Two public functions carry the frozen
   `clippy::impl_trait_in_params` expectation (`ApiKeyEntry::new`,
   `ApiKeyEntry::try_with_expiry`), and public builders stay non-`const` under
   the frozen `clippy::missing_const_for_fn` expectation (`RfcTimestamp::
   as_datetime`, `RfcTimestamp::into_inner`, `ApiKeyEntry::with_expiry`,
   `RateLimitConfig::{with_pre_auth_max_per_minute, with_max_tracked_keys,
   with_idle_eviction, with_burst, with_pre_auth_burst}`,
   `AuthConfig::{with_keys, with_rate_limit, check_oauth_feature}`); the
   `oauth`-only shape of `AuthConfig::check_oauth_feature` additionally freezes
   `clippy::unnecessary_wraps` and `clippy::unused_self`, and `AuthConfig`'s
   `oauth` placeholder (present only without the `oauth` feature) freezes
   `clippy::partial_pub_fields` and `clippy::field_scoped_visibility_modifiers`
   on the struct. Three `deliberate:` expectations record crate-internal
   shapes rather than freezing public API: the `pub(crate)` fields of
   `CredentialOwner` (constructed by `src/oauth.rs`), the `pub(crate)` fields
   of `AuthLogContext` (constructed by `src/transport.rs`'s test helper), and
   the crate-private `oauth` placeholder field. Constant-time arithmetic in
   `verify_slots` uses `wrapping_sub` (never `checked_*` + `?`, G-8), and the
   redaction tests' output is unchanged. Evidence: the task-18 migration
   record (`new-permanent-expects.txt`, `gates.txt`).
17. **2026-10-04 - `src/tool_hooks.rs` + `src/rbac_context.rs` per-item
   expectations (task 21).** Under entry 13's decision this lane freezes two
   public items with the catalog reason `public API frozen until the next major
   release`: `clippy::impl_trait_in_params` on `ToolCallContext::for_tool` and
   `clippy::missing_const_for_fn` on `ToolHooks::with_max_result_bytes` (the
   `Option<usize>` assignment is const-able; const-ifying is an API addition
   kept for the next major). Deliberate, item-level expectations:
   `clippy::too_many_lines` on `hooked_handler_forwards_listing_methods` (it
   keeps the positive and mutation-control halves in one driver so the control
   cannot be skipped); `clippy::panic` on
   `after_hook_panic_is_isolated_from_response_path` (the panic is the
   assertion) and on the `get_task_via_service` test helper (its three panics
   are harness invariants for an unusable frame; preserving them keeps the
   panic/assert count neutral per LC 2); and `clippy::unnecessary_wraps`, one
   per assertion-only test in both modules, so every test keeps the uniform
   `anyhow::Result<()>` signature (core's test pattern). `rbac_context.rs`
   keeps `pub(crate)` on `RbacContextHandler` because rustc's `unreachable_pub`
   (denied) forbids the `pub` that nursery's `redundant_pub_crate` suggests;
   the manifest contradiction override (Cargo.toml) is the narrowest
   resolution, so that one key intentionally remains in the file's count-gate
   baseline. The `SEMANTIC_DRIVERS` tables and impl anchors parsed by
   `tests/integration/delegation_guard.rs` were kept byte-identical. Evidence:
   the task-21 migration record (`new-permanent-expects.txt`, `gates.txt`,
   `review.txt`).

Entries to be added by the work that creates them: "new in `<version>`"
expects and profile deltas (the toolchain-drift work); the per-item frozen
public-API expectations (the lint lanes, under entry 13's decision); the GitLab
mirror skew tolerance, if it is ever required.

## Re-vendor procedure

1. Fetch all four files at the new pinned commit and prove blob-id identity:

   ```bash
   PIN=<new commit>
   for P in RUST_GUIDELINES.md overlays/domains/http-services.md \
            overlays/domains/mcp-servers.md overlays/projects/rmcp-server-kit.md; do
     gh api -H 'Accept: application/vnd.github.raw' \
       "repos/andrico21/rust-guidelines/contents/$P?ref=$PIN" \
       > "docs/rust-guidelines/$P"
     test "$(git hash-object "docs/rust-guidelines/$P")" = \
          "$(gh api "repos/andrico21/rust-guidelines/contents/$P?ref=$PIN" --jq .sha)"
   done
   ```

2. Regenerate `docs/rust-guidelines/SHA256SUMS`:

   ```bash
   (cd docs/rust-guidelines && sha256sum RUST_GUIDELINES.md \
      overlays/domains/http-services.md overlays/domains/mcp-servers.md \
      overlays/projects/rmcp-server-kit.md > SHA256SUMS)
   (cd docs/rust-guidelines && sha256sum -c SHA256SUMS)
   ```

3. Update this index: pinned commit, the hash/blob table, the deviation status
   table, register dates. Never vendor `README.md`; never edit the vendored
   bytes; never write upstream.
4. Run the gates: `cargo test --all-features --test docs_citations`,
   `lychee --offline --no-progress README.md RUST_GUIDELINES.md docs/*.md`,
   plus the usual fmt/lint/test set.

## Toolchain-bump procedure

Applies on the first CI run on a stable newer than 1.99.0, and on every
deliberate nightly bump. While file lanes are open it runs as a barrier: lane
merges pause, the drift PR owns every file, then the lanes update from `main`.

1. New lints, and new firings of existing lints (stable): fix them, or add
   item-level `#[expect(<lint>, reason = "new in <version>; pending guidelines
   re-baseline")]`. These are harmless on the 1.99-pinned jobs: the count gate
   ignores `unknown_lints` / `unfulfilled_lint_expectations`, and the MSRV job
   is lint-capped.
2. A profile lint renamed or removed: apply the rename or removal in `Cargo.toml`
   as a recorded toolchain delta (old -> new, or removed, with the toolchain
   version) in the register above. A split lint records every successor;
   "removed" is recorded only when the toolchain's changelog shows no
   replacement (cite it). An expect naming the lint is renamed in place or
   deleted; the measurement drops recorded renamed-from and removed lints. The
   profile semantic-equality check compares against the vendored profile modulo
   exactly these recorded deltas.
3. The count gate stays pinned to 1.99.0. Its baseline is regenerated only in
   the commit that bumps `rust-version`, which is an owner decision.
4. Nightly drift: the fmt and docsrs jobs use a dated nightly
   (`nightly-YYYY-MM-DD`), the newest that passes those two commands. The pin
   moves only deliberately; a non-blocking canary runs docsrs on the latest
   nightly to surface drift early; GitLab's nightly comes fixed with its image;
   the AGENTS.md cheat sheet uses the pinned name.
5. Re-vendoring a profile that names rustc lints newer than `rust-version`
   cannot break the lint-capped MSRV job; bumping `rust-version` stays an owner
   decision.
6. GitLab mirror skew: every GitLab job runs on the pinned image toolchain. If
   the procedure must add a newer-than-image expect or a profile delta, give
   every compiling GitLab job (clippy, doc, test, doctest, coverage, build,
   msrv, publish-dryrun, bench) `-A unknown-lints
   -A unfulfilled-lint-expectations`, plus `-A <name>` for each recorded
   renamed-from or removed lint: in the top-level RUSTFLAGS and RUSTDOCFLAGS, in
   any job-level override of those, and in the clippy job's arguments. This is
   mirror-only and is deleted when the image is bumped; GitHub stable remains
   the canonical enforcement.
7. Upstream re-baselining happens in `andrico21/rust-guidelines` first and
   arrives here only through the re-vendor procedure: nothing in this repository
   writes to that repository.
