# P4 — SPIKE: the crate's posture for MCP 2026-07-28 stateless Streamable HTTP

**Status**: decision record (spike exit deliverable). No production code ships from this spike.
**Date**: 2026-09-17. **rmcp**: 3.4.0 (pinned). **Crate**: 3.12.0+unreleased.

## Evidence base

**Source-verified in rmcp 3.4.0** (`src/transport/streamable_http_server/tower.rs`):

| Fact | Location |
|---|---|
| `legacy_session_mode` field, default **true**, builder `with_legacy_session_mode` | :90 / :192 / :246 |
| `stateless_protocol_metadata_required` field, default **false**, builder | :178 / :200 / :270 |
| Absent `MCP-Protocol-Version` header ⇒ assumed `2025-03-26` | :281-285 |
| Stateless SSE replay calls `event_store.replay_events_after(last_event_id)` with **no identity context** | :1608 |
| Session creation / response-header insertion for initialize-based sessions | :1892-1896 / :1945-1949 |

**Empirically exercised by this crate's suites** (tests added while closing the delegation-coverage
work in the same release cycle; all currently green):

| Behaviour | Evidence |
|---|---|
| `server/discover` is rejected before the handler unless `params._meta` carries **both** `io.modelcontextprotocol/protocolVersion` and `.../clientCapabilities` | `hooked_handler_forwards_initialize_and_discover`, `rbac_context_handler_forwards_ping_initialize_and_discover` |
| `subscriptions/listen` is unreachable after a legacy handshake; it needs per-request `_meta` at `>= 2026-07-28` plus a non-`None` `accepted_subscription_filter` | `hooked_handler_forwards_subscription_lifecycle`, `task_status_notifications_remain_unroutable_until_binding_is_added` |
| `tasks/*` requires the server tasks extension **and** a client capability declaring it | `hooked_handler_forwards_task_methods`, `..._forwards_task_binding_on_update_and_cancel` |
| Session binding is a no-op without an identity; MAC failure ⇒ `404 unknown MCP session`; malformed/unwrapped ⇒ `403 invalid MCP session` | `src/session_binding.rs:330-345`; unit tests `src/session_binding.rs:633-734` |
| `task_binding` defaults **false** | `src/transport.rs:791` |

**Not run, and why**: the stateless-mode experiments (`legacy_session_mode = false`,
`stateless_protocol_metadata_required = true`) cannot be driven through this crate's public surface,
because `build_app_router` constructs `StreamableHttpServerConfig::default()` internally and exposes
neither flag. That gap is itself the Q1 finding; Q1's rmcp-side behaviour below is therefore
source-grounded, not reproduced.

---

## Q1 — Cohesive "advanced protocol mode" vs isolated flags

**Options**: A) expose `legacy_session_mode`, `json_response` and `stateless_protocol_metadata_required`
as isolated flags; B) a `ProtocolMode` enum; C) a `McpServerConfig::stateless_2026()` preset that sets
all related knobs coherently, with per-field overrides retained.

**Analysis.** The three knobs are not independent: `stateless_protocol_metadata_required = true`
without `legacy_session_mode = false` still routes initialize-based sessions through the stateful
path, and `legacy_session_mode = false` alone accepts legacy clients that never send metadata
(absent header ⇒ `2025-03-26`). Isolated flags (A) therefore make "I want a 2026-only stateless
server" a three-knob sequence where getting two of three right looks correct until a client is
silently accepted. A preset (C) encodes the coherent combination once and keeps overrides available;
an enum (B) is the same idea with a larger addition to the public type surface and a new flame of
`#[non_exhaustive]` churn. No emulation is available above rmcp's transport without reimplementing
its routing, and the security defaults must not change.

**Semver.** Additive (new builder + fields behind `#[non_exhaustive]`). Consumers of the current
behaviour are unaffected.

**Recommendation.** Implement C: a `stateless_2026()`-style preset that sets
`legacy_session_mode = false`, `stateless_protocol_metadata_required = true` (and `json_response`
policy) together, plus individual `with_*` overrides for the three underlying fields. Document that
the preset rejects non-2026 clients, so it is opt-in.

**Verdict: GO** — as a follow-up implementation issue (this spike ships no code).

## Q2 — First-class "2026-only stateless" preset vs handler-side version restriction

**Options**: A) document `ServerHandler::supported_protocol_versions` narrowing only; B) ship the
preset from Q1.

**Analysis.** Handler-side narrowing is not sufficient on its own: the protocol-version *header* is
optional and an absent header is treated as `2025-03-26` (source-verified above), so a server that
merely narrows its supported versions still negotiates with clients that never advertise 2026. To
actually refuse legacy clients, the transport-level knobs from Q1 must be set; the handler-side list
remains the right tool for capping what the *negotiation* may agree to.

**Semver.** Additive.

**Recommendation.** B. Document the two-layer story: transport knobs refuse/accept the lifecycle,
handler list bounds negotiation.

**Verdict: GO** (same follow-up issue as Q1).

## Q3 — `session_binding` when a 2026 request carries `Mcp-Session-Id`

**Options**: A) ignore the header under 2026; B) reject it under 2026; C) keep the current
fail-closed behaviour (validate identity binding when present, no-op when absent).

**Analysis.** `session_binding` is already a no-op when there is no identity and no session header,
and it rejects a raw/malformed/wrong-identity token. Ignoring (A) would let a client believe a
session is protected when it is not, and would weaken defense-in-depth for legacy sessions
mid-upgrade. Rejecting outright (B) breaks partially upgraded clients that still echo the header.
Keeping (C) preserves the security property and is compatible with both lifecycles; the only cost is
stricter behaviour than "stateless" implies when a header *is* present.

**Semver.** No change.

**Recommendation.** Keep C; document it in the preset's rustdoc (a 2026 request that presents a
session header is still identity-checked).

**Verdict: NO CHANGE** (documentation note attached to the Q1 follow-up).

## Q4 — Identity binding for stateless SSE replay (`Last-Event-ID`)

**Options**: A) strengthen the `EventStore` contract (identity-scoped streams / validated ids) with a
trait-level requirement; B) bind `Last-Event-ID` the way `Mcp-Session-Id` is bound; C) declare it
consumer responsibility with hard documentation.

**Analysis.** rmcp's stateless replay path calls `replay_events_after(last_event_id)` with no
identity context, so the framework cannot attribute a replay to a principal at that layer. Option B
would require minting and verifying a sealed id around a value whose correct binding depends on
consumer business context (per-identity streams vs per-tenant), i.e. the same shape of problem this
crate already declined to guess for MRTR `requestState`; a wrong guess would be worse than an
explicit contract. The crate already documents isolation and globally-unique-id requirements for
custom event stores; A and C are the same decision with different wording strength.

**Semver.** C is docs-only. A is potentially semver-relevant for `EventStore` implementors if it
becomes a trait obligation; keep it as documented requirements until an attack path is demonstrated.

**Recommendation.** C with hardened wording (must be per-identity isolated and unguessable), and A
revisited only if a concrete leaked-id replay is shown against a documented implementor.

**Verdict: GO on C; DEFER A/B.**

## Q5 — `task_binding` default under 2026 stateless

**Options**: A) keep default `false` + strong documentation recommending it under 2026; B) flip the
default with a transitional path.

**Analysis.** Flipping the default changes the wire format of every `taskId` a consumer already
exposes, and consumers that persist the client-visible id as their own key are directly affected.
That is a breaking change by this crate's own semver policy and belongs in a major with migration
notes, not in the stateless posture work. Under stateless semantics a leaked raw task id is no longer
contained by session state, which raises the stakes but does not change the compatibility argument.

**Semver.** B is breaking; A is docs-only.

**Recommendation.** A now: document prominently that stateless deployments should enable
`task_binding`; schedule B for the next major with a migration note.

**Verdict: NO-GO on flipping now; GO on documentation.**

## Q6 — Empirical client behaviour: protocol headers and metadata

**What was observed.** Against this crate's own server (real HTTP, `serve()`):

- a request without `MCP-Protocol-Version` and without `params._meta` is treated as legacy
  (`2025-03-26` semantics): `initialize` and legacy methods are reachable, and any
  metadata-requiring path (`server/discover`, `subscriptions/listen`, `tasks/*`) is refused before
  the handler;
- `server/discover` with `MCP-Protocol-Version: 2026-07-28` but **no** inline `_meta` is refused,
  and the same request with `_meta` carrying both required keys reaches the handler;
- no third-party client was exercised; per the spike's own terms that was optional and would need
  named clients with install commands.

**Recommendation.** Keep the current acceptance matrix (legacy by default, 2026 paths gated on
inline metadata) and state it in the preset's documentation.

**Verdict: NO CHANGE.**

---

## Overall summary

| Q | Verdict |
|---|---|
| Q1 advanced-mode exposure | GO (preset, as follow-up) |
| Q2 2026-only preset | GO (same follow-up) |
| Q3 `session_binding` under 2026 | NO CHANGE (document) |
| Q4 SSE replay identity | GO on consumer contract; DEFER trait change |
| Q5 `task_binding` default | NO-GO on flipping; GO on docs |
| Q6 client behaviour | NO CHANGE |

**No defaults change; no RBAC change; `session_binding` stays on by default.** Follow-up work is
limited to: (1) the stateless-2026 preset (+ the Q3/Q6 documentation notes), (2) a docs pass for
`task_binding` under stateless deployments, (3) an `EventStore` wording pass for replay isolation.
