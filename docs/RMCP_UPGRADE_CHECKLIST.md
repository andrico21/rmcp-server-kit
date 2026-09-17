# rmcp upgrade checklist

Run these checks whenever `rmcp` (or `rmcp-macros`) moves in `Cargo.toml` /
`Cargo.lock`. This crate is a transparent wrapper around the SDK, so rmcp's
trait defaults are inherited silently: upstream drift shows up as behaviour
differences at runtime, not as compile errors.

Related: [`../AGENTS.md`](../AGENTS.md) (build/test gates),
[`../tests/delegation_guard.rs`](../tests/delegation_guard.rs) (mechanical
trait-surface guard), [`MIGRATION.md`](MIGRATION.md) (consumer-facing notes).

## 1. Trait surface drift

- [ ] Run the guard: `cargo test --all-features --test delegation_guard`
- If it fails: review the upstream `ServerHandler` diff, add the missing
  delegations to `HookedHandler` (`src/tool_hooks.rs`) and `RbacContextHandler`
  (`src/rbac_context.rs`), update the three coverage lists per wrapper, and bump
  `EXPECTED_UPSTREAM_METHOD_COUNT`.
- Keep the classification honest: `BEHAVIORAL_WRAPPED` only when the wrapper adds
  behaviour (hooks, result-size cap, identity scoping, task-ID binding, tool-list
  filtering); `DIRECTLY_DELEGATED` must forward unchanged.
  `INTENTIONALLY_DEFAULTED` must stay empty, and the guard enforces that - a
  non-empty set is rejected outright. Legitimising an exception is a deliberate
  code change: relax the assertion in `tests/delegation_guard.rs` and record why,
  in the same commit.
- Add or extend a direct-call transparency test
  (`hooked_handler_preserves_inner_negotiate_initialize_override` and the
  `RbacContextHandler` twin) for anything whose classification changes.

### Soundness: why a record log proves forwarding

**No rmcp `ServerHandler` default body can reach a wrapper's inner handler.**
Every default body either returns a constant / `::default()` /
`Err(method_not_found)`, or calls other methods on `self` - and `self` is the
wrapper. Mechanical check: **zero** occurrences of `self.inner` in the
`server_handler_methods!` macro body. Consequence: "the inner probe recorded
method `M`" soundly proves the wrapper's `M` forwarded, *provided* the
observation cannot come from a self-re-entrant default. That set is exactly
`{negotiate_initialize, get_info, supported_protocol_versions}`.
**Re-run that mechanical check on every rmcp bump**: if a future default touches
inner state, the argument breaks - and with it every semantic driver below.

### What the guard enforces

`tests/delegation_guard.rs` holds every constant below; update them together when
an rmcp bump changes the surface:

| Constant / table | Role |
|---|---|
| `EXPECTED_UPSTREAM_METHOD_COUNT` | method count of the pinned rmcp `ServerHandler` (29 for 3.4.0) |
| `HOOKED_HANDLER_DIRECTLY_DELEGATED`, `HOOKED_HANDLER_BEHAVIORAL_WRAPPED`, `HOOKED_HANDLER_INTENTIONALLY_DEFAULTED`, `RBAC_CONTEXT_HANDLER_DIRECTLY_DELEGATED`, `RBAC_CONTEXT_HANDLER_BEHAVIORAL_WRAPPED`, `RBAC_CONTEXT_HANDLER_INTENTIONALLY_DEFAULTED` | per-wrapper classification of every upstream method |
| `HOOKED_HANDLER_IMPL_METHOD_COUNT`, `RBAC_CONTEXT_HANDLER_IMPL_METHOD_COUNT` | how many methods each wrapper's own impl must scan to; catches a mis-scoped scanner or a silently shrunk impl |
| `HOOKED_HANDLER_SOURCE`, `RBAC_CONTEXT_HANDLER_SOURCE`, `HOOKED_HANDLER_IMPL_ANCHOR`, `RBAC_CONTEXT_HANDLER_IMPL_ANCHOR` | the file and the column-0 full-generic impl anchor each scanner reads |
| `HOOKED_HANDLER_SEMANTICALLY_UNPROVABLE`, `RBAC_CONTEXT_HANDLER_SEMANTICALLY_UNPROVABLE` | methods no driver can prove; asserted **empty** - every method is reachable through dispatch or a direct call |
| `RBAC_CONTEXT_HANDLER_MACRO_ORIGINS` | per-method origin pins for the twelve macro-generated methods the three macro-body drivers discharge; a method that becomes a literal `fn` fails until it gains its own driver |
| `SEMANTIC_DRIVERS` (in the `src/tool_hooks.rs` / `src/rbac_context.rs` test modules) | method to driver-test table; the completeness gate asserts it equals `DIRECTLY_DELEGATED ∪ BEHAVIORAL_WRAPPED` per wrapper |

### Semantic drivers: the rules a new driver must follow

- Every semantic assertion is **exact equality** of the inner probe's record log
  against the expected log *for that driver*, or a sentinel value (or sentinel
  error) rmcp's defaults cannot construct. `contains`, `is_empty()` and length
  thresholds are forbidden: rmcp's self-re-entrant defaults and ambient handler
  calls (`get_info` during peer setup and capability validation,
  `supported_protocol_versions` in the request prelude,
  `accepted_subscription_filter` before `listen`) can otherwise make a
  non-forwarding body look green.
- The expected log must contain the method under test; ambient entries may only
  be *added* to it. Guarantee that by keeping the probe silent for the three
  self-re-entrant methods, by clearing after the ambient call has run, or by
  asserting the exact full sequence.
- Every driver also runs its request against `PassthroughDefaults` - the wrapper
  with all delegations deleted - and asserts the probe stayed untouched. That is
  the per-method mutation check, re-executed on every `cargo test`.

## 2. Transport / config drift

- [ ] `cargo build --all-features`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Scan `src/transport.rs` and `src/config.rs` for compile errors, new
  deprecations, and changed `StreamableHttpServerConfig` defaults; confirm the
  middleware order documented in [`ARCHITECTURE.md`](ARCHITECTURE.md) still
  matches `build_app_router`.
- [ ] Confirm the rmcp knobs this crate forwards still exist with unchanged units
  (`with_max_request_body_bytes`, `with_sse_keep_alive`, `with_allowed_hosts`,
  the `session_store` / `event_store` fields).

## 3. Protocol constants drift

- [ ] Search `src/transport.rs` and the handler wrappers for protocol-version
  defaults and security-header policy; confirm the crate's documented posture
  still holds and no new `ProtocolVersion` changes initialization rules
  (`negotiate_initialize`, per-request metadata requirements).
- [ ] `cargo test --all-features` (covers the wrapper transparency tests).

## 4. Deprecation drift

- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- Address new deprecations with narrow, reason-labelled
  `#[allow(deprecated, reason = "...")]` scopes only where the delegation must
  survive (legacy logging / subscription paths); prefer upstream replacements
  otherwise. The standing NO-GO / WATCH / REJECTED decisions are recorded in
  GitHub issue #21.

## 5. Dependency hygiene

- [ ] `cargo vet regenerate exemptions` in the same commit as the bump
- [ ] `cargo deny check`
- [ ] `cargo audit`
- [ ] `cargo semver-checks check-release`
- [ ] CHANGELOG entry under `[Unreleased]` grounded in the upstream tag-to-tag
  diff, with advisories cited by ID
