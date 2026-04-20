# Code Review — `rmcp-server-kit` 1.0.0

> **Scope**: Full codebase audit against [`RUST_GUIDELINES.md`](../RUST_GUIDELINES.md) (sections 1–13).
> **Crate**: `rmcp-server-kit` 1.0.0 (Rust 2024, MSRV 1.95, `unsafe_code = "forbid"`).
> **Date**: 2026-04-19.
> **Reviewer**: Sisyphus (autonomous review).
> **Method**: Multi-dimensional parallel audit covering (1) panic/unwrap surface,
> (2) async / lock anti-patterns, (3) public API design, (4) security / OWASP,
> (5) lints / dependencies / CI / tests. Findings cross-checked against fresh
> file:line reads.
>
> **TL;DR**: This is a **disciplined, well-engineered codebase**. No MUST-FIX
> defects were found in production paths — no panics, no unsoundness, no
> security P0, no async deadlocks. All issues below are SHOULD-FIX hardening
> opportunities or P1/P2 defense-in-depth items. The crate is production-ready
> as released.

---

## Severity legend

| Tag       | Meaning                                                                                   |
|-----------|-------------------------------------------------------------------------------------------|
| MUST-FIX  | Blocking — correctness, soundness, or panic/security regression.                          |
| SHOULD-FIX | Hardening, API hygiene, or guideline compliance. Plan for next minor / next major.       |
| P0/P1/P2  | Security severity (P0 = exploit, P1 = info-leak / hardening, P2 = defense-in-depth).      |
| NIT       | Cosmetic / stylistic / discretionary.                                                     |

A 1.0 SemVer commitment means breaking-public-API fixes are deferred to 2.0 (called out below).

---

## 1. MUST-FIX

**None.**

Verification summary:

- **Panic surface** — Every `unwrap()` / `expect()` in production code is
  either (a) a `const NonZeroU32::new(N).unwrap()` with an inline `// SAFETY:`
  comment, (b) carries `#[allow(clippy::expect_used)]` with justification, or
  (c) is slice indexing immediately preceded by a bounds check.
  Concretely: `auth.rs:570, 614`, `rbac.rs:38, 550, 786, 795, 801, 813`,
  `transport.rs:982`, `metrics.rs:81`. All other unwraps are inside
  `#[cfg(test)]` modules.
- **Soundness** — `unsafe_code = "forbid"` at crate root (`src/lib.rs`), no
  unsafe blocks anywhere.
- **Async** — No `std::sync::Mutex` held across `.await`. No `std::fs` /
  `std::net` inside async fns on the hot request path. Argon2 verification
  already runs under `tokio::task::spawn_blocking` (`src/auth.rs`).
- **Security** — All OWASP-recommended security headers present
  (`src/transport.rs::security_headers_middleware`); secrets wrapped in
  `secrecy::SecretString`; no `expose_secret()` reaches a `tracing::*` macro;
  no `danger_accept_invalid_certs`; no insecure RNG.

---

## 2. SHOULD-FIX — Architecture & correctness

### 2.1 `JwksCache::new` returns `Box<dyn Error>` instead of `McpxError`
**File**: `src/oauth.rs:554`
**Guideline**: §2 Error handling — “use the crate-wide error type for public APIs”.

```rust,ignore
pub fn new(config: &OAuthConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
```

Every other public constructor in the crate returns `Result<_, McpxError>`.
This single outlier forces consumers into `Box<dyn>` plumbing, defeats
`?`-conversion in caller code, and breaks API hygiene.

**Remediation** (next major — public signature change):

```rust,ignore
pub fn new(config: &OAuthConfig) -> Result<Self, McpxError>
```

Map the underlying `std::io::Error` (CA bundle read), `reqwest::Error`
(client build), and `rustls::Error` (provider install) to existing
`McpxError` variants (`Io`, `Config`, or a new `OAuth` variant — see §2.2).

### 2.2 `oauth.rs::exchange_token` leaks upstream IdP `error_description` to the HTTP client (P1)
**Files**: `src/oauth.rs:1407–1422` ; `src/error.rs:56–85`

```rust,ignore
// oauth.rs (caller-visible message)
return Err(crate::error::McpxError::Auth(format!(
    "token exchange failed: {detail}"  // detail includes error_description verbatim
)));

// error.rs::IntoResponse
Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),  // sent verbatim to client
```

Untrusted upstream-IdP error text reaches the MCP client. Real IdPs
occasionally include subject identifiers, internal hostnames, or backend
trace IDs in `error_description`. This is a P1 information disclosure.

**Remediation**:

1. Keep the rich `detail` string for the existing `tracing::warn!` log site
   (line 1419) — operators need it.
2. Replace the client-facing message with a sanitized constant + the OAuth
   `error` short code only (which is enumerated by RFC 6749 §5.2 and
   intentionally machine-readable):
   ```rust,ignore
   let short_code = serde_json::from_slice::<OAuthErrorResponse>(&body_bytes)
       .map_or("server_error", |e| classify(&e.error));
   return Err(crate::error::McpxError::Auth(format!(
       "token exchange failed: {short_code}"
   )));
   ```
3. Apply the same sanitization at `oauth.rs:1198` and `oauth.rs:1337`
   (proxy `/token` paths) which currently echo `error_description` into the
   JSON response body.

### 2.3 `JwksCache::decode_claims` runs JWT crypto on the async executor
**File**: `src/oauth.rs:657–679`

`jsonwebtoken::decode` performs RSA / ECDSA signature verification
synchronously. For a single small JWT this is sub-millisecond on commodity
hardware, but a malicious client can pin a runtime worker by sending many
large JWTs (e.g., RS512 with 8 KB tokens) — analogous to why Argon2 is
already off-loaded in `auth.rs`.

**Remediation**:

```rust,ignore
async fn decode_claims(&self, token: &str) -> Result<Claims, JwtValidationFailure> {
    let (key, alg) = self.select_jwks_key(token).await?;
    let mut validation = self.validation_template.clone();
    validation.algorithms = vec![alg];
    let token = token.to_owned();   // 'static for spawn_blocking

    tokio::task::spawn_blocking(move || decode::<Claims>(&token, &key, &validation))
        .await
        .map_err(|_| JwtValidationFailure::Invalid)?
        .map(|td| td.claims)
        .map_err(|e| { /* existing classification */ })
}
```

Cost: one `String` clone + one task hop per JWT. Benefit: bounded async
worker latency under hostile load.

### 2.4 Untraced `tokio::spawn` sites lose `tracing` span + RBAC task-locals
**Files**:
- `src/tool_hooks.rs:268–274` (after-hook spawn — most impactful)
- `src/bounded_limiter.rs:195–206`
- `src/transport.rs:1169–1174`
- `src/transport.rs:1393–1401`

After-hooks fire after a tool call completes and are user-supplied; today
they execute in a bare `tokio::spawn` with no parent span and no
task-local RBAC context. This means:

- `current_role()` / `current_identity()` / `current_sub()` return `None`
  inside the after-hook — the consumer-facing API contract on `src/rbac.rs`
  is silently broken at this exact moment.
- Logs emitted by the hook are detached from the request span — making it
  impossible to correlate them with the originating call.

**Remediation** — capture the context, then either re-bind it via
`with_rbac_scope` or use the lower-level `LocalKey::scope` form, and
attach the parent span via `tracing::Instrument`:

```rust,ignore
fn spawn_after(after: Option<&Arc<AfterHookHolder>>, ctx: ToolCallContext, ...) {
    if let Some(after) = after {
        let after = Arc::clone(after);
        let role     = crate::rbac::current_role();
        let identity = crate::rbac::current_identity();
        let span     = tracing::Span::current();
        tokio::spawn(
            async move {
                crate::rbac::with_rbac_scope(role, identity, || async {
                    (after.f)(&ctx, disposition, size).await
                }).await
            }
            .instrument(span),
        );
    }
}
```

Apply the same pattern to the three `transport.rs` / `bounded_limiter.rs`
sites (less critical — they don’t run user code, but `Instrument` alone is
basically free and improves debuggability).

### 2.5 Per-request payload clone on `/version`
**File**: `src/transport.rs:1008–1014`

The current handler clones the `version_info` JSON body for every request.
On a hot health-monitoring path this is wasted work.

**Remediation**: hoist the serialized response into an `Arc<Bytes>` (or
`Arc<str>`) computed once at `serve()` startup and serve it directly:

```rust,ignore
let version_body: Bytes = serde_json::to_vec(&version_info)?.into();
let version_body = Arc::new(version_body);
.route("/version", get({
    let body = Arc::clone(&version_body);
    move || async move {
        ([(header::CONTENT_TYPE, "application/json")], body.as_ref().clone())
    }
}))
```

---

## 3. SHOULD-FIX — Public API hygiene

### 3.1 `OAuthConfigBuilder` setters missing `#[must_use]`
**File**: `src/oauth.rs:178, 184, 194, 200, 207, 217, 224, 230, 236`

The builder type itself carries `#[must_use = "builders do nothing until \`.build()\` is called"]`
at line 171, but the chained setters (which return `Self`) do not. Every
other builder in the crate annotates each setter individually
(see `auth.rs:224, 319`; `rbac.rs:198`; `transport.rs:412`;
`tool_hooks.rs:180, 186, 193, 200`). The omission silently allows
`builder.scope(..);` to compile without warning even though the configured
value is dropped on the floor.

### 3.2 `OAuthProxyConfigBuilder` setters missing `#[must_use]`
**File**: `src/oauth.rs:422, 430, 438, 450`

Same issue, same fix — add `#[must_use]` above each `pub fn` in the impl
block. This is a non-breaking, additive change; ship in next minor.

> **Drive-by**: `oauth.rs:450` is `pub const fn expose_admin_endpoints` —
> consider applying `#[must_use]` to all builder setters consistently
> regardless of `const`-ness.

---

## 4. SHOULD-FIX — Tooling / CI / dependency policy

### 4.1 Add `clippy::string_to_string = "warn"` to crate lints
**File**: `Cargo.toml` (`[lints.clippy]`, lines 131–172).

`str_to_string` is present; its sibling `string_to_string` (catches
`String::to_string()` clones) is not. Both are recommended by §10 of the
guidelines.

```toml
string_to_string = "warn"
```

### 4.2 `deny.toml` is missing recommended advisory keys
**File**: `deny.toml`.

Per guideline §10 (“supply-chain hygiene”) the following entries should
be explicit:

```toml
[advisories]
vulnerability = "deny"
unmaintained  = "warn"
notice        = "warn"

[licenses]
unlicensed = "deny"
copyleft   = "deny"
```

This makes the policy auditable rather than relying on cargo-deny
defaults (which have changed across versions).

### 4.3 CI is missing supply-chain & dead-code gates
**File**: `.github/workflows/ci.yml` ; `.gitlab-ci.yml`.

Add three jobs (all advisory at first, can be promoted to required after
one stable run):

| Tool          | Purpose                                        |
|---------------|------------------------------------------------|
| `cargo-vet`   | Cryptographic supply-chain attestation.        |
| `cargo-machete` | Detect unused dependencies.                  |
| `cargo-mutants` | Mutation testing for the test suite quality. |

`cargo-audit` and `cargo-deny` are already wired — extend with the above.

### 4.4 No property-based tests
**Guideline**: §13 “Testing — use property tests for invariants”.

This crate has zero `proptest` / `quickcheck` dev-dependency and zero
property tests. Three concrete property targets that would catch real
bugs:

1. **`rbac.rs::ArgumentAllowlist::argument_allowed`** — invariant: a
   denied argument string is never accepted regardless of allowlist
   permutation order.
2. **`config.rs` TOML round-trip** — invariant: `serialize(parse(s)) ==
   normalize(s)` for any valid config.
3. **`auth.rs::generate_api_key`** — invariant: the returned token always
   verifies against its returned hash via `verify_api_key`.

Add `proptest = "1"` as a `[dev-dependencies]` entry and one
`tests/properties.rs` integration test file.

---

## 5. P2 / NIT

### 5.1 `rand::fill` is already correct (no action)
Original audit memo flagged `auth.rs:715,720` and `rbac.rs:523` for using
implicit RNG. On re-verification, `rand::fill` (rand 0.10) is the explicit
top-level `getrandom`-backed API and is the recommended choice. **No
change required** — this finding is withdrawn.

### 5.2 Document audit-log file rotation expectations
**File**: `src/observability.rs:162–178`.

The audit-file sink opens the configured path with `O_APPEND` semantics
and never rotates. This is fine but undocumented — a small doc-comment
recommending external rotation (`logrotate(8)` / `newsyslog`) and
warning that SIGHUP-style reopen is not implemented would help operators.

### 5.3 Document blocking startup I/O is intentional
**Files**: `src/observability.rs:162–178` (audit sink open),
`src/oauth.rs:585–593` (CA bundle read).

Both are pre-`serve()` startup paths so blocking is acceptable, but a
one-line `// Pre-startup blocking I/O — runs before the runtime is
servicing requests.` comment would prevent future “drive-by async
refactor” PRs from creating noise.

---

## 6. Verified-clean checklist

| Guideline section                 | Status | Notes                                                            |
|-----------------------------------|--------|------------------------------------------------------------------|
| §1 No panics in production        | ✅     | All unwraps justified or test-only.                              |
| §2 Error handling                 | ⚠️    | `JwksCache::new` outlier → §2.1.                                 |
| §3 Async / `Send` / locks         | ✅     | No locks across `.await`. spawn_blocking for CPU work present.   |
| §3 Async — JWT crypto offload     | ⚠️    | See §2.3.                                                        |
| §4 Borrowing & ownership          | ✅     | No `&String`, `&Vec<T>`, `Arc<String>`, `Box<Vec<T>>` found.     |
| §5 Public API ergonomics          | ⚠️    | Builder `#[must_use]` gap → §3.1, §3.2.                          |
| §6 `unsafe`                       | ✅     | `unsafe_code = "forbid"`.                                        |
| §7 `tracing` (no println / dbg)   | ✅     | Verified via lints + grep.                                       |
| §8 Secrets                        | ✅     | `secrecy::SecretString` everywhere; redaction via HMAC-SHA256.   |
| §9 OWASP HTTP hardening           | ✅     | All security headers present; CORS / Host allow-list configurable. |
| §10 Lints / supply chain          | ⚠️    | Missing lint + deny.toml keys → §4.1, §4.2.                      |
| §11 Performance                   | ⚠️    | Hot-path clone on `/version` → §2.5.                             |
| §12 CI gates                      | ⚠️    | Missing vet / machete / mutants → §4.3.                          |
| §13 Tests                         | ⚠️    | No property tests → §4.4.                                        |

---

## 7. Suggested remediation sequencing

**Patch release (1.0.x — non-breaking)**:
1. §3.1, §3.2 — add `#[must_use]` to OAuth builder setters.
2. §4.1 — add `clippy::string_to_string = "warn"`.
3. §4.2 — fill out `deny.toml`.
4. §5.2, §5.3 — doc-only comments.

**Minor release (1.1.0 — additive)**:
5. §2.3 — wrap `decode_claims` in `spawn_blocking`.
6. §2.4 — instrument tracing + RBAC scope on `tokio::spawn` sites.
7. §2.5 — pre-serialize `/version` body.
8. §2.2 — sanitize OAuth error leakage (P1).
9. §4.3 — add CI jobs.
10. §4.4 — add proptest dev-dep + first property tests.

**Major release (2.0.0 — breaking)**:
11. §2.1 — change `JwksCache::new` signature to return `Result<_, McpxError>`.

---

*Report generated 2026-04-19 by Sisyphus. All file:line citations
verified against working-tree at the time of writing.*
