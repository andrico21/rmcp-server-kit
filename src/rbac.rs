//! Role-Based Access Control (RBAC) policy engine.
//!
//! Evaluates `(role, operation, host)` tuples against a set of role
//! definitions loaded from config.  Deny-overrides-allow semantics:
//! an explicit deny entry always wins over a wildcard allow.
//!
//! Includes an axum middleware that inspects MCP JSON-RPC tool calls
//! and enforces RBAC and per-IP tool rate limiting before the request
//! reaches the handler.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use std::{fs, path::PathBuf, sync::LazyLock};

use axum::{
    body::Body,
    http::{Extensions, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use http_body_util::BodyExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::Sha256;
use tracing::field;

#[cfg(feature = "metrics")]
use crate::metrics::record_rate_limit_deny;
use crate::{
    auth::AuthIdentity,
    bounded_limiter::{BoundedKeyedLimiter, BoundedLimiterDeny, KeyEvictionPolicy},
    config::{
        EnvOverride, EnvOverrideSource, RBAC_REDACTION_SALT_ENV, RBAC_REDACTION_SALT_FILE_ENV,
        normalize_text_secret_file, read_env, secret_env_report,
    },
    error::RmcpServerKitError,
    transport::{
        LogContextConfig, RateLimitKey, limiter_client_ip, limiter_client_key, peer_ip_for_log,
        request_id_for_log,
    },
};

/// Per-source-IP rate limiter for tool invocations. Memory-bounded against
/// IP-spray `DoS` via [`BoundedKeyedLimiter`].
pub(crate) type ToolRateLimiter = BoundedKeyedLimiter<RateLimitKey>;

/// Default tool rate limit: 120 invocations per minute per source IP.
// 120 is a non-zero literal, evaluated at compile time.
const DEFAULT_TOOL_RATE: NonZeroU32 = NonZeroU32::new(120).unwrap();

/// Default cap on the number of distinct source IPs tracked by the tool
/// rate limiter. Bounded to defend against IP-spray `DoS` exhausting memory.
const DEFAULT_TOOL_MAX_TRACKED_KEYS: usize = 10_000;

/// Default idle-eviction window for the tool rate limiter (15 minutes).
const DEFAULT_TOOL_IDLE_EVICTION: Duration = Duration::from_mins(15);

/// Build a per-IP tool rate limiter from a max-calls-per-minute value.
///
/// Memory-bounded with `DEFAULT_TOOL_MAX_TRACKED_KEYS` tracked keys and
/// `DEFAULT_TOOL_IDLE_EVICTION` idle eviction. Use
/// [`build_tool_rate_limiter_with_bounds`] to override.
#[must_use]
pub(crate) fn build_tool_rate_limiter_with_policy(
    max_per_minute: u32,
    burst: Option<u32>,
    key_eviction_policy: KeyEvictionPolicy,
) -> Arc<ToolRateLimiter> {
    build_tool_rate_limiter_with_bounds(
        max_per_minute,
        burst,
        DEFAULT_TOOL_MAX_TRACKED_KEYS,
        DEFAULT_TOOL_IDLE_EVICTION,
        key_eviction_policy,
    )
}

/// Build a per-IP tool rate limiter with explicit memory-bound parameters.
///
/// `burst` overrides governor's default bucket capacity (burst = rate);
/// zero rate/cap values are rejected at config-validation time; the
/// `NonZero*` fallbacks here are defensive only.
#[must_use]
pub(crate) fn build_tool_rate_limiter_with_bounds(
    max_per_minute: u32,
    burst: Option<u32>,
    max_tracked_keys: usize,
    idle_eviction: Duration,
    key_eviction_policy: KeyEvictionPolicy,
) -> Arc<ToolRateLimiter> {
    let mut quota =
        governor::Quota::per_minute(NonZeroU32::new(max_per_minute).unwrap_or(DEFAULT_TOOL_RATE));
    if let Some(burst_override) = burst.and_then(NonZeroU32::new) {
        quota = quota.allow_burst(burst_override);
    }
    Arc::new(BoundedKeyedLimiter::new_with_policy(
        quota,
        NonZeroUsize::new(max_tracked_keys).unwrap_or(NonZeroUsize::MIN),
        idle_eviction,
        key_eviction_policy,
    ))
}

// Task-local storage for the current caller's RBAC role and identity name.
// Set by the RBAC middleware, read by tool handlers (e.g. list_hosts filtering, audit logging).
//
// `CURRENT_TOKEN` holds a [`SecretString`] so the raw bearer token is never
// printed via `Debug` (it formats as `"[REDACTED alloc::string::String]"`)
// and is zeroized on drop by the `secrecy` crate.
tokio::task_local! {
    static CURRENT_ROLE: String;
    static CURRENT_IDENTITY: String;
    static CURRENT_TOKEN: SecretString;
    static CURRENT_SUB: String;
}

/// Get the current caller's RBAC role (set by RBAC middleware).
/// Returns `None` outside an RBAC-scoped request context.
///
/// # One role per identity
///
/// Authorization evaluates exactly one role string per identity; it never
/// unions several matched roles. The string comes from
/// [`ApiKeyEntry::role`](crate::auth::ApiKeyEntry), `MtlsConfig::default_role`,
/// or -- for OAuth -- the **first matching entry in configuration order**
/// (`role_mappings` when `role_claim` is set, otherwise `scopes`). A token
/// bearing several role-granting claims therefore yields only the first
/// mapped role. See the RBAC section of `docs/GUIDE.md` for the operator
/// workarounds.
///
/// The resolved string must name a role configured in `[[rbac.roles]]`;
/// an unknown name fails closed.
///
/// # This is not an authorization decision
///
/// Tool authorization is enforced by the RBAC middleware *before* this
/// task-local is installed, and admin gating reads the request's
/// `AuthIdentity` directly rather than this accessor. Use `current_role`
/// for handler context, audit, and filtering -- never as the sole basis
/// for granting access.
///
/// # Empty roles
///
/// An empty role is treated as absent and yields `None`, matching
/// [`current_identity`], [`current_token`] and [`current_sub`]. The built-in
/// middleware additionally installs no task-local scope at all when the
/// resolved role is empty (as happens when authentication is disabled), so
/// both paths agree.
#[must_use]
#[inline]
pub fn current_role() -> Option<String> {
    CURRENT_ROLE
        .try_with(Clone::clone)
        .ok()
        .filter(|role| !role.is_empty())
}

/// Get the current caller's identity name (set by RBAC middleware).
/// Returns `None` outside an RBAC-scoped request context.
///
/// An empty identity is treated as absent and yields `None`, matching
/// [`current_role`], [`current_token`] and [`current_sub`]. This matters
/// because `current_sub().or_else(current_identity)` is a natural way to
/// resolve a stable per-user key, and an empty string returned here would
/// defeat the caller's `None` check while looking correct.
///
/// This normalises the accessor only. A configured
/// [`AuthIdentity`] may still carry an empty
/// `name`, which remains significant elsewhere (session-binding fingerprints,
/// admin summaries, audit logs).
#[must_use]
#[inline]
pub fn current_identity() -> Option<String> {
    CURRENT_IDENTITY
        .try_with(Clone::clone)
        .ok()
        .filter(|identity| !identity.is_empty())
}

/// Get the raw bearer token for the current request as a [`SecretString`].
///
/// Returns `None` outside a request context or when auth used mTLS/API-key.
/// Tool handlers use this for downstream token passthrough.
///
/// The returned value is wrapped in [`SecretString`] so it does not leak
/// via `Debug`/`Display`/serde. Call `.expose_secret()` only when the
/// raw value is actually needed (e.g. as the `Authorization` header on
/// an outbound HTTP request).
///
/// An empty token is treated as absent (returns `None`); this preserves
/// backward compatibility with the prior `Option<String>` API where the
/// empty default sentinel meant "no token".
#[must_use]
#[inline]
pub fn current_token() -> Option<SecretString> {
    CURRENT_TOKEN
        .try_with(|token| {
            if token.expose_secret().is_empty() {
                None
            } else {
                Some(token.clone())
            }
        })
        .ok()
        .flatten()
}

/// Get the JWT `sub` claim (stable user ID, e.g. Keycloak UUID).
/// Returns `None` outside a request context or for non-JWT auth.
/// Use for stable per-user keying (token store, etc.).
#[must_use]
#[inline]
pub fn current_sub() -> Option<String> {
    CURRENT_SUB
        .try_with(Clone::clone)
        .ok()
        .filter(|subject| !subject.is_empty())
}

/// Run a future with `CURRENT_TOKEN` set so that [`current_token()`] returns
/// the given value inside the future.
///
/// Useful when MCP tool handlers need the raw bearer token but run in a
/// spawned task where the RBAC middleware's task-local scope is no longer
/// active.
///
/// # Cancel safety
///
/// Cancel-safe: the whole future runs inside `scope`, so dropping it drops
/// `future` with no state left installed.
#[inline]
pub async fn with_token_scope<F>(token: SecretString, future: F) -> F::Output
where
    F: Future,
{
    CURRENT_TOKEN.scope(token, future).await
}

/// Run a future with all task-locals (`CURRENT_ROLE`, `CURRENT_IDENTITY`,
/// `CURRENT_TOKEN`, `CURRENT_SUB`) set.
///
/// Use this when re-establishing the full RBAC context in spawned tasks
/// (e.g. rmcp session tasks) where the middleware's scope is no longer
/// active.
///
/// # Cancel safety
///
/// Cancel-safe: the whole future runs inside the nested scopes, so dropping
/// it drops `future` with no task-locals left installed.
#[inline]
pub async fn with_rbac_scope<F>(
    role: String,
    identity: String,
    token: SecretString,
    sub: String,
    future: F,
) -> F::Output
where
    F: Future,
{
    with_rbac_scope_lazy(role, identity, token, sub, || future).await
}

/// Run `make()` inside all four RBAC task-local scopes.
///
/// The lazy form lets callers construct the future only once the scopes are
/// installed (e.g. so `current_role()` is observable during construction).
///
/// # Cancel safety
///
/// Cancel-safe: the future is polled inside the nested scopes, so dropping
/// the returned future drops it with no task-locals left installed.
pub(crate) async fn with_rbac_scope_lazy<T, F, Fut>(
    role: String,
    identity: String,
    token: SecretString,
    sub: String,
    make: F,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    CURRENT_ROLE
        .scope(role, async move {
            CURRENT_IDENTITY
                .scope(identity, async move {
                    CURRENT_TOKEN
                        .scope(token, async move {
                            CURRENT_SUB.scope(sub, async move { make().await }).await
                        })
                        .await
                })
                .await
        })
        .await
}

/// A single role definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleConfig {
    /// Role identifier referenced from identities (API keys, mTLS, JWT claims).
    pub name: String,
    /// Human-readable description, surfaced in diagnostics only.
    #[serde(default)]
    pub description: Option<String>,
    /// Allowed operations.  `["*"]` means all operations.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly denied operations (overrides allow).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Host name glob patterns this role can access. `["*"]` means all hosts.
    #[serde(default = "default_hosts")]
    pub hosts: Vec<String>,
    /// Per-tool argument constraints. When a tool call matches, the
    /// specified argument's first whitespace-delimited token (or its
    /// `/`-basename) must appear in the allowlist.
    #[serde(default)]
    pub argument_allowlists: Vec<ArgumentAllowlist>,
}

impl RoleConfig {
    /// Create a role with the given name, allowed operations, and host patterns.
    #[must_use]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn new(name: impl Into<String>, allow: Vec<String>, hosts: Vec<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            allow,
            deny: vec![],
            hosts,
            argument_allowlists: vec![],
        }
    }

    /// Attach denied operations to this role. Deny entries are glob-matched.
    #[must_use]
    #[inline]
    pub fn with_deny(mut self, deny: Vec<String>) -> Self {
        self.deny = deny;
        self
    }

    /// Attach argument allowlists to this role.
    #[must_use]
    #[inline]
    pub fn with_argument_allowlists(mut self, allowlists: Vec<ArgumentAllowlist>) -> Self {
        self.argument_allowlists = allowlists;
        self
    }
}

/// Per-tool argument allowlist entry.
///
/// When the middleware sees a `tools/call` for `tool`, it extracts the
/// string value at `argument` from the call's arguments object and checks
/// its first token against `allowed`. If the token is not in the list
/// the call is rejected with 403.
///
/// # Scope: this is not the argument-validation layer
///
/// Argument validation belongs **downstream, in the tool itself** -- its input
/// schema and its handler. Only the tool knows its parameter types, value
/// ranges, mutually exclusive options, and which combinations are meaningful.
/// This crate deliberately does not attempt that, and cannot: it sees an
/// untyped JSON object at an authorization boundary.
///
/// What an allowlist provides is a coarse, role-scoped gate answering "may
/// this role invoke this tool in roughly this shape". It is defence in depth
/// layered *on top of* the tool's own validation, never a replacement for it.
/// Its deliberate limits follow from that:
///
/// - Only the **first `shlex::split` word** of the value is checked. An
///   allowlist of `["ls"]` accepts `"ls -la; id"`, because the first parsed
///   word is `ls`; everything after it is unconstrained. The check therefore
///   constrains only the first parsed word, not every program a shell might
///   go on to execute.
/// - Object- and array-valued arguments are denied rather than inspected
///   wherever an allowlist or `deny_unknown_arguments` actually applies;
///   there is no nested-path matching.
/// - Basename matching is POSIX-only, so `C:\bin\ls.exe` will not match `ls`.
///
/// This division is also why presence enforcement is opt-in rather than
/// imposed: whether omitting an argument is safe depends entirely on the
/// tool's schema and defaults, which are the consumer's to declare.
///
/// By default this constrains the value only **when the argument is
/// present** -- omitting it entirely skips the check. Set
/// [`required`](Self::required) to also demand the argument be supplied.
/// This default is **permanent and deliberate**: presence enforcement is
/// opt-in, because an allowlist that constrains a supplied value is a
/// legitimate configuration and the crate does not impose the stricter
/// policy on existing deployments. Use
/// [`ArgumentAllowlist::new_required`] whenever omitting the argument must
/// fail closed -- in particular when the tool substitutes its own default
/// for a missing value, since that default is never checked.
//
// NOTE(future-pr): typed pre-tokenized argument matcher (CHANGELOG.md
// "future release" promise).
// Scope (Oracle-approved, internal-only, patch-safe):
//   - Keep `ArgumentAllowlist` public shape UNCHANGED (wire/config stability).
//     (The later addition of `required` is additive and serde-defaulted, so
//     it preserves that property; the compiled IR must carry it through.)
//   - In `RbacPolicy::new`, compile each allowlist once into a private
//     `CompiledArgumentAllowlist` IR:
//       * pre-resolve the `tool` selector: exact vs glob.
//       * pre-tokenize first-token allowlists.
//       * pre-tokenize basename allowlists.
//       * carry the `required` flag so presence enforcement survives.
//   - At request time (`has_argument_allowlist` / `argument_allowed`),
//     `shlex::split` each constrained argument once, then lookup in the
//     compiled IR.
//   - Required equivalence test matrix: exact tool names, globbed tool
//     names, basename matches, quoted paths, fail-closed parse errors,
//     required-present / required-absent.
//   - Profile before merge; justify by maintainability if perf delta <5%.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ArgumentAllowlist {
    /// Tool name to match (exact or glob, e.g. `"run_query"`).
    pub tool: String,
    /// Argument key whose value is checked (e.g. `"cmd"`, `"query"`).
    pub argument: String,
    /// Permitted first-token values. Empty means unrestricted.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Require the argument to be present and string-valued.
    ///
    /// Defaults to `false`, preserving the historical semantics: an
    /// allowlist constrains the value when the argument is supplied, and a
    /// caller omitting it passes unchecked. That is safe when the tool's
    /// input schema already marks the argument required, but fails open
    /// when the handler substitutes a default for a missing value.
    ///
    /// When `true`, a call that omits the argument -- or supplies a
    /// non-string -- is denied with 403, independently of `allowed`. Setting
    /// `required` with an empty `allowed` therefore means "must be supplied
    /// as a string, any value accepted".
    #[serde(default)]
    pub required: bool,
    /// Reject any top-level argument that no allowlist for this `(role, tool)`
    /// names.
    ///
    /// Defaults to `false`, preserving the historical semantics: allowlists
    /// constrain only the arguments they name, so `{"cmd":"ls","danger":true}`
    /// passes when only `cmd` is allowlisted. That is safe when the tool's
    /// input schema rejects unknown keys, and fails open when it does not.
    ///
    /// When `true` on ANY allowlist matching a `(role, tool)` pair, the
    /// permitted argument names become the union of every matching allowlist's
    /// [`argument`](Self::argument), and any other top-level key is denied
    /// with 403. Object- and array-valued arguments are also denied, because
    /// this crate has no nested-path allowlist to constrain their contents.
    #[serde(default)]
    pub deny_unknown_arguments: bool,
}

impl ArgumentAllowlist {
    /// Create an argument allowlist for a tool.
    ///
    /// The argument is optional: the allowed-value list is enforced only when
    /// the caller supplies it. Use [`new_required`](Self::new_required) when
    /// omitting the argument must fail closed.
    #[must_use]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn new(tool: impl Into<String>, argument: impl Into<String>, allowed: Vec<String>) -> Self {
        Self {
            tool: tool.into(),
            argument: argument.into(),
            allowed,
            required: false,
            deny_unknown_arguments: false,
        }
    }

    /// Create an argument allowlist that requires the argument to be present.
    ///
    /// This is the recommended constructor for new policies because it fails
    /// closed when the caller omits the constrained argument.
    #[must_use]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn new_required(
        tool: impl Into<String>,
        argument: impl Into<String>,
        allowed: Vec<String>,
    ) -> Self {
        Self::new(tool, argument, allowed).with_required(true)
    }

    /// Require the argument to be present and string-valued.
    #[must_use]
    #[inline]
    pub const fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Confine the tool to only the arguments its allowlists name.
    ///
    /// Applies to the whole `(role, tool)` pair, not just this entry: see
    /// [`deny_unknown_arguments`](Self::deny_unknown_arguments).
    #[must_use]
    #[inline]
    pub const fn with_deny_unknown_arguments(mut self, deny: bool) -> Self {
        self.deny_unknown_arguments = deny;
        self
    }
}

/// Default host patterns: allow every host.
fn default_hosts() -> Vec<String> {
    vec!["*".into()]
}

/// How [`RoleConfig::allow`] entries are matched against operation names.
///
/// [`RoleConfig::deny`] is **always** glob-matched and is deliberately not
/// covered by this switch: widening a deny can only ever remove capability,
/// so it is safe to enable unconditionally. Widening an *allow*, by contrast,
/// grants access, so it stays opt-in.
///
/// TOML wire values are kebab-case: `"legacy"` (default) and `"glob"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AllowOperationMatching {
    /// Exact string equality, plus the literal `"*"` meaning "all operations".
    ///
    /// A `*` inside any other entry is treated as an ordinary character, so
    /// `"jira_get_*"` grants only an operation named exactly `jira_get_*` and
    /// never acts as a pattern. [`RbacPolicy::new`] warns about such entries.
    #[default]
    Legacy,
    /// Full glob matching via the same matcher used for hosts and
    /// `argument_allowlists.tool` selectors. `*` is the only metacharacter and
    /// matching stays case-sensitive, so glob-free entries still behave as
    /// exact matches.
    Glob,
}

/// Top-level RBAC configuration (deserializable from TOML).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct RbacConfig {
    /// Master switch -- when false, the RBAC middleware is not installed.
    #[serde(default)]
    pub enabled: bool,
    /// Role definitions available to identities.
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    /// How [`RoleConfig::allow`] entries are matched. Defaults to
    /// [`AllowOperationMatching::Legacy`] (exact match) so that enabling glob
    /// support is always a deliberate operator decision.
    #[serde(default)]
    pub allow_operation_matching: AllowOperationMatching,
    /// Server-wide operation kill switch, evaluated **before** any role is
    /// consulted and applied regardless of what a role's `allow` grants --
    /// including `allow = ["*"]`.
    ///
    /// Entries are **always** glob-matched, independent of
    /// [`RbacConfig::allow_operation_matching`]. This list can only ever
    /// remove capability, never add it.
    ///
    /// Two scope limits apply. It is gated on [`RbacConfig::enabled`]: when
    /// RBAC is disabled every check short-circuits to
    /// [`RbacDecision::Allow`] before the kill switch is consulted. And it
    /// governs *invocation* only -- like the rest of this engine it is
    /// enforced on `tools/call`, so a denied tool may still appear in a
    /// `tools/list` response unless the handler filters it.
    #[serde(default)]
    pub global_deny: Vec<String>,
    /// Optional stable HMAC key (any length) used to redact argument
    /// values in deny logs. When set, redacted hashes are stable across
    /// process restarts (useful for log correlation across deploys).
    /// When `None`, a random 32-byte key is generated per process at
    /// first use; redacted hashes change every restart.
    ///
    /// The key is wrapped in [`SecretString`] so it never leaks via
    /// `Debug`/`Display`/serde and is zeroized on drop.
    #[serde(default)]
    pub redaction_salt: Option<SecretString>,
}

impl RbacConfig {
    /// Create an enabled RBAC config with the given roles.
    #[must_use]
    #[inline]
    pub fn with_roles(roles: Vec<RoleConfig>) -> Self {
        Self {
            enabled: true,
            roles,
            allow_operation_matching: AllowOperationMatching::default(),
            global_deny: Vec::new(),
            redaction_salt: None,
        }
    }

    /// Set the server-wide operation kill switch. Entries are glob-matched.
    #[must_use]
    #[inline]
    pub fn with_global_deny(mut self, global_deny: Vec<String>) -> Self {
        self.global_deny = global_deny;
        self
    }

    /// Opt into glob matching for [`RoleConfig::allow`] entries.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn with_allow_operation_matching(mut self, mode: AllowOperationMatching) -> Self {
        self.allow_operation_matching = mode;
        self
    }
}

/// Result of an RBAC policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub enum RbacDecision {
    /// Caller is permitted to perform the requested operation.
    Allow,
    /// Caller is denied access.
    Deny,
}

/// Summary of a single role, produced by [`RbacPolicy::summary`].
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct RbacRoleSummary {
    /// Role name.
    pub name: String,
    /// Number of allow entries.
    pub allow: usize,
    /// Number of deny entries.
    pub deny: usize,
    /// Number of host patterns.
    pub hosts: usize,
    /// Number of argument allowlist entries.
    pub argument_allowlists: usize,
}

/// Summary of the whole RBAC policy, produced by [`RbacPolicy::summary`].
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct RbacPolicySummary {
    /// Whether RBAC enforcement is active.
    pub enabled: bool,
    /// Number of server-wide `global_deny` patterns.
    pub global_deny: usize,
    /// Per-role summaries.
    pub roles: Vec<RbacRoleSummary>,
}

/// Compiled RBAC policy for fast lookup.
///
/// Built from [`RbacConfig`] at startup.  All lookups are O(n) over the
/// role's allow/deny/host lists, which is fine for the expected cardinality
/// (a handful of roles with tens of entries each).
#[derive(Debug, Clone)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct RbacPolicy {
    /// Compiled role definitions.
    roles: Vec<RoleConfig>,
    /// Whether enforcement is active (mirrors [`RbacConfig::enabled`]).
    enabled: bool,
    /// How `allow` entries are matched.
    allow_operation_matching: AllowOperationMatching,
    /// Server-wide operation vetoes, always glob-matched.
    global_deny: Vec<String>,
    /// HMAC key used to redact argument values in deny logs.
    /// Either a configured stable salt or a per-process random salt.
    redaction_salt: Arc<SecretString>,
}

impl RbacPolicy {
    /// Build a policy from config.  When `config.enabled` is false, all
    /// checks return [`RbacDecision::Allow`].
    #[must_use]
    #[inline]
    pub fn new(config: &RbacConfig) -> Self {
        warn_on_optional_value_allowlists(&config.roles);
        warn_on_literal_allow_globs(&config.roles, config.allow_operation_matching);
        warn_on_inert_global_deny(config);
        let salt = config
            .redaction_salt
            .clone()
            .unwrap_or_else(|| process_redaction_salt().clone());
        Self {
            roles: config.roles.clone(),
            enabled: config.enabled,
            allow_operation_matching: config.allow_operation_matching,
            global_deny: config.global_deny.clone(),
            redaction_salt: Arc::new(salt),
        }
    }

    /// Create a policy that always allows (RBAC disabled).
    #[must_use]
    #[inline]
    pub fn disabled() -> Self {
        Self {
            roles: Vec::new(),
            enabled: false,
            allow_operation_matching: AllowOperationMatching::default(),
            global_deny: Vec::new(),
            redaction_salt: Arc::new(process_redaction_salt().clone()),
        }
    }

    /// Whether RBAC enforcement is active.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The HMAC key used to redact argument values in deny logs.
    pub(crate) fn redaction_salt(&self) -> Arc<SecretString> {
        Arc::clone(&self.redaction_salt)
    }

    /// Summarize the policy for diagnostics (admin endpoint).
    ///
    /// Returns `(enabled, role_count, per_role_stats)` where each stat is
    /// `(name, allow_count, deny_count, host_count, argument_allowlist_count)`.
    #[must_use]
    #[inline]
    pub fn summary(&self) -> RbacPolicySummary {
        let roles = self
            .roles
            .iter()
            .map(|role| RbacRoleSummary {
                name: role.name.clone(),
                allow: role.allow.len(),
                deny: role.deny.len(),
                hosts: role.hosts.len(),
                argument_allowlists: role.argument_allowlists.len(),
            })
            .collect();
        RbacPolicySummary {
            enabled: self.enabled,
            global_deny: self.global_deny.len(),
            roles,
        }
    }

    /// Whether `operation` is vetoed by the server-wide kill switch.
    ///
    /// Always glob-matched, independent of
    /// [`RbacConfig::allow_operation_matching`].
    fn global_denied(&self, operation: &str) -> bool {
        self.global_deny
            .iter()
            .any(|pattern| glob_match(pattern, operation))
    }

    /// Whether `role_cfg` explicitly denies `operation`.
    ///
    /// Deny entries are always glob-matched: a glob-free entry reduces to
    /// exact equality inside [`glob_match`], so existing exact configs are
    /// unaffected, while a pattern such as `"*_delete_*"` now denies rather
    /// than silently matching nothing.
    fn role_denies(role_cfg: &RoleConfig, operation: &str) -> bool {
        role_cfg
            .deny
            .iter()
            .any(|pattern| glob_match(pattern, operation))
    }

    /// Whether `role_cfg` allows `operation` under the configured matching mode.
    fn role_allows(&self, role_cfg: &RoleConfig, operation: &str) -> bool {
        role_cfg.allow.iter().any(|entry| {
            entry == "*"
                || match self.allow_operation_matching {
                    AllowOperationMatching::Legacy => entry == operation,
                    AllowOperationMatching::Glob => glob_match(entry, operation),
                }
        })
    }

    /// Check whether `role` may perform `operation` (ignoring host).
    ///
    /// Use this for tools that don't target a specific host (e.g. `ping`,
    /// `list_hosts`).
    #[must_use]
    #[inline]
    pub fn check_operation(&self, role: &str, operation: &str) -> RbacDecision {
        if !self.enabled {
            return RbacDecision::Allow;
        }
        if self.global_denied(operation) {
            return RbacDecision::Deny;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return RbacDecision::Deny;
        };
        if Self::role_denies(role_cfg, operation) {
            return RbacDecision::Deny;
        }
        if self.role_allows(role_cfg, operation) {
            return RbacDecision::Allow;
        }
        RbacDecision::Deny
    }

    /// Check whether `role` may perform `operation` on `host`.
    ///
    /// Evaluation order:
    /// 1. If RBAC is disabled, allow.
    /// 2. Apply [`RbacConfig::global_deny`] (glob; vetoes even `allow = ["*"]`).
    /// 3. Check operation permission (deny overrides allow; deny is always
    ///    glob-matched, allow follows [`RbacConfig::allow_operation_matching`]).
    /// 4. Check host visibility via glob matching (ASCII-case-insensitive;
    ///    operation names above remain case-sensitive).
    #[must_use]
    #[inline]
    pub fn check(&self, role: &str, operation: &str, host: &str) -> RbacDecision {
        if !self.enabled {
            return RbacDecision::Allow;
        }
        if self.global_denied(operation) {
            return RbacDecision::Deny;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return RbacDecision::Deny;
        };
        if Self::role_denies(role_cfg, operation) {
            return RbacDecision::Deny;
        }
        if !self.role_allows(role_cfg, operation) {
            return RbacDecision::Deny;
        }
        if !Self::host_matches(&role_cfg.hosts, host) {
            return RbacDecision::Deny;
        }
        RbacDecision::Allow
    }

    /// Check whether `role` can see `host` at all (for `list_hosts` filtering).
    ///
    /// Host matching is ASCII-case-insensitive.
    #[must_use]
    #[inline]
    pub fn host_visible(&self, role: &str, host: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return false;
        };
        Self::host_matches(&role_cfg.hosts, host)
    }

    /// Get the list of hosts patterns for a role.
    #[must_use]
    #[inline]
    pub fn host_patterns(&self, role: &str) -> Option<&[String]> {
        self.find_role(role)
            .map(|role_cfg| role_cfg.hosts.as_slice())
    }

    /// Check whether `value` passes the argument allowlists for `tool` under `role`.
    ///
    /// If the role has no matching `argument_allowlists` entry for the tool,
    /// all values are allowed. When a matching entry exists, `value` is
    /// tokenized using POSIX-shell-like lexical rules ([`shlex::split`])
    /// and its first argv element (or the `/`-basename of that element)
    /// must appear in the `allowed` list.
    ///
    /// **Scope of the contract.** This matcher targets consumers that
    /// interpret string arguments as POSIX-shell-like command lines on
    /// Unix-like systems (e.g. anything that subsequently feeds the value
    /// through `shlex` or an equivalent splitter before `execve`). It
    /// does **not** model real shell *execution* grammar (`FOO=1 cmd`,
    /// expansion, command substitution, redirection, operators) or
    /// Windows command-line tokenization (`CommandLineToArgvW`,
    /// `cmd.exe`, PowerShell). Consumers in those regimes remain subject
    /// to a parser differential and must validate at their own boundary.
    ///
    /// **No Unicode normalization.** Token comparison is byte-exact. A
    /// value that is canonically equivalent to an allowlist entry but
    /// encoded differently (NFC vs NFD, or a homoglyph) does **not**
    /// match, and is therefore denied -- this direction is fail-closed.
    /// The residual hazard runs the other way: on a normalizing filesystem
    /// (e.g. macOS APFS, which folds NFD) an allowlisted NFC entry can
    /// resolve to a different file than the policy author intended.
    /// Express allowlist entries in the same normalization form the
    /// consumer will use.
    ///
    /// **Fail-closed cases (all return `false` when a matching allowlist
    /// entry exists):**
    ///
    /// - `value` fails to parse as a POSIX-shell-like command line
    ///   (e.g. unbalanced quotes, dangling escape).
    /// - `value` parses to zero tokens (empty input).
    /// - The first parsed token is the empty string (e.g.
    ///   `value = r#""""#` parses to `Some(vec![""])`). An empty argv
    ///   element is never a runnable executable, so we reject even when
    ///   `""` is in the allowlist.
    #[must_use]
    #[inline]
    pub fn argument_allowed(&self, role: &str, tool: &str, argument: &str, value: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return false;
        };
        for al in &role_cfg.argument_allowlists {
            if al.tool != tool && !glob_match(&al.tool, tool) {
                continue;
            }
            if al.argument != argument {
                continue;
            }
            if al.allowed.is_empty() {
                continue;
            }
            // Tokenize per POSIX-shell-like rules so quoted paths with
            // spaces match what an equivalently-tokenizing consumer
            // would actually run, and malformed shell syntax (unbalanced
            // quotes, dangling escapes) fails closed.
            let Some(tokens) = shlex::split(value) else {
                return false;
            };
            let Some(first_token) = tokens.first() else {
                return false;
            };
            // A well-formed but empty first argv element (e.g.
            // value = r#""""#) is never a runnable executable. Fail
            // closed even if "" appears in the allowlist.
            if first_token.is_empty() {
                return false;
            }
            // Also match against the basename if it's a path. POSIX
            // separator only; Windows-style backslash paths are out of
            // scope and will not basename-match (see crate-level docs).
            let basename = first_token
                .rsplit('/')
                .next()
                .unwrap_or(first_token.as_str());
            if !al
                .allowed
                .iter()
                .any(|allowed| allowed == first_token || allowed == basename)
            {
                return false;
            }
        }
        true
    }

    /// Return `true` if `(role, tool, argument)` has any non-empty
    /// allowlist entry configured.
    ///
    /// Used by the tools/call middleware to decide whether non-string
    /// JSON values must be rejected (M2 fix). When this returns `true`,
    /// the value at `argument` must be a JSON string and pass
    /// [`Self::argument_allowed`]; otherwise the call is denied with
    /// 403. When this returns `false`, the value is unconstrained by
    /// allowlist policy.
    #[must_use]
    #[inline]
    pub fn has_argument_allowlist(&self, role: &str, tool: &str, argument: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return false;
        };
        role_cfg.argument_allowlists.iter().any(|al| {
            (al.tool == tool || glob_match(&al.tool, tool))
                && al.argument == argument
                && !al.allowed.is_empty()
        })
    }

    /// Return the top-level argument names permitted for `(role, tool)` when
    /// strict confinement is enabled, or `None` when it is not.
    ///
    /// Strict mode is enabled by ANY matching allowlist setting
    /// `deny_unknown_arguments`, and the permitted set is then the union of
    /// every matching entry's `argument`. A single strict entry therefore
    /// confines the whole tool rather than only its own argument, which is
    /// what makes the flag meaningful: confining one argument while leaving
    /// its siblings unconstrained would not close the bypass.
    fn strict_argument_names(&self, role: &str, tool: &str) -> Option<Vec<&str>> {
        if !self.enabled {
            return None;
        }
        let role_cfg = self.find_role(role)?;
        let matching = || {
            role_cfg
                .argument_allowlists
                .iter()
                .filter(|al| al.tool == tool || glob_match(&al.tool, tool))
        };
        if !matching().any(|al| al.deny_unknown_arguments) {
            return None;
        }
        Some(matching().map(|al| al.argument.as_str()).collect())
    }

    /// Return the role config for a given role name.
    fn find_role(&self, name: &str) -> Option<&RoleConfig> {
        self.roles.iter().find(|role| role.name == name)
    }

    /// Name of the first `required` argument that `args` fails to supply as a
    /// JSON string, or `None` when every requirement is met.
    ///
    /// `args` is `None` when the call carried no `arguments` object at all (or
    /// carried a non-object); that must still be evaluated, otherwise omitting
    /// the object would skip every requirement.
    ///
    /// Kept private: this is middleware-internal enforcement, unlike
    /// [`Self::has_argument_allowlist`] / [`Self::argument_allowed`], which
    /// expose value-policy evaluation to consumers.
    fn missing_required_argument(
        &self,
        role: &str,
        tool: &str,
        args: Option<&serde_json::Map<String, serde_json::Value>>,
    ) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        let role_cfg = self.find_role(role)?;
        role_cfg
            .argument_allowlists
            .iter()
            .filter(|al| al.required)
            // Same exact-or-glob selector as `argument_allowed` /
            // `has_argument_allowlist`; diverging here would make a globbed
            // tool pattern enforce values but not presence.
            .filter(|al| al.tool == tool || glob_match(&al.tool, tool))
            .find(|al| {
                !args.is_some_and(|arguments| {
                    arguments
                        .get(&al.argument)
                        .is_some_and(serde_json::Value::is_string)
                })
            })
            .map(|al| al.argument.as_str())
    }

    /// Check if a host name matches any of the given glob patterns.
    ///
    /// Matching is **ASCII-case-insensitive**: `host` is a DNS name or an
    /// IP literal, and both are case-insensitive by specification.
    ///
    /// Normalization deliberately lives here rather than in [`glob_match`],
    /// which is shared with tool-name matching where case *is* significant.
    /// Lowercasing there would silently widen every tool allowlist.
    ///
    /// Pre-compiling normalized host patterns at [`RbacPolicy::new`] was
    /// evaluated and **rejected**. It would remove the remaining per-wildcard
    /// allocation, but [`RbacPolicy::host_patterns`] is public and must keep
    /// returning the operator's original casing, and the normalized copy would
    /// have to be rebuilt on every `ArcSwap` hot reload - where getting it
    /// wrong means a reloaded policy silently stops matching
    /// case-insensitively. That risk is not worth an allocation count on a
    /// path already bounded by Argon2 verification and JSON parsing. Reopen
    /// only if profiling shows wildcard host matching dominating a real
    /// workload (e.g. `list_hosts` filtering over many wildcard patterns).
    fn host_matches(patterns: &[String], host: &str) -> bool {
        // Lowercased once per call rather than once per pattern, and only
        // when a wildcard pattern will actually consume it -- an all-exact
        // pattern list stays allocation-free via `eq_ignore_ascii_case`.
        let host_lower = patterns
            .iter()
            .any(|pattern| pattern.contains('*'))
            .then(|| host.to_ascii_lowercase());
        patterns.iter().any(|pattern| {
            if pattern.contains('*') {
                host_lower
                    .as_deref()
                    .is_some_and(|lower| glob_match(&pattern.to_ascii_lowercase(), lower))
            } else {
                pattern.eq_ignore_ascii_case(host)
            }
        })
    }

    /// HMAC-SHA256 the given argument value with this policy's redaction
    /// salt and return the first 8 hex characters (4 bytes / 32 bits).
    ///
    /// 32 bits is enough entropy for log correlation (1-in-4-billion
    /// collision per pair) while being far short of any preimage attack
    /// surface for an attacker reading logs. The HMAC construction
    /// guarantees that even short or low-entropy values cannot be
    /// recovered without the key.
    #[must_use]
    #[inline]
    pub fn redact_arg(&self, value: &str) -> String {
        redact_with_salt(self.redaction_salt.expose_secret().as_bytes(), value)
    }
}

/// Warn about `allow` entries that contain a `*` while
/// [`AllowOperationMatching::Legacy`] is in effect.
///
/// Under legacy matching the `*` is an ordinary character, so the entry grants
/// only an operation whose name contains that literal `*` -- almost never what
/// the operator meant. The literal `"*"` is exempt: that is the documented
/// allow-all form.
fn warn_on_literal_allow_globs(roles: &[RoleConfig], mode: AllowOperationMatching) {
    match mode {
        AllowOperationMatching::Glob => return,
        AllowOperationMatching::Legacy => {}
    }
    for role in roles {
        for entry in role
            .allow
            .iter()
            .filter(|allow_entry| *allow_entry != "*" && allow_entry.contains('*'))
        {
            tracing::warn!(
                role = %role.name,
                operation = %entry,
                "allow entry contains '*' but operation matching is 'legacy'; \
                 the '*' is matched literally, not as a pattern -- set \
                 rbac.allow_operation_matching = \"glob\" to enable globbing, \
                 or list the operation names exactly"
            );
        }
    }
}

/// Warn when a `global_deny` list is configured but can never take effect.
fn warn_on_inert_global_deny(config: &RbacConfig) {
    if !config.enabled && !config.global_deny.is_empty() {
        tracing::warn!(
            patterns = config.global_deny.len(),
            "rbac.global_deny is configured but rbac.enabled is false; \
             the kill switch is inert because all checks short-circuit to allow"
        );
    }
}

/// Warn once per role about optional, non-empty argument allowlists, which
/// fail open when the constrained argument is omitted.
fn warn_on_optional_value_allowlists(roles: &[RoleConfig]) {
    for role in roles {
        for allowlist in &role.argument_allowlists {
            if !allowlist.allowed.is_empty() && !allowlist.required {
                tracing::warn!(
                    role = %role.name,
                    tool = %allowlist.tool,
                    argument = %allowlist.argument,
                    "argument allowlist is optional and fails open when the \
                     argument is omitted: the allowed-value list is enforced \
                     only if the caller supplies the argument, so a tool that \
                     substitutes its own default bypasses it entirely -- set \
                     `required = true` in TOML, or construct via \
                     `ArgumentAllowlist::new_required`, to reject calls that \
                     omit it"
                );
            }
        }
    }
}

/// Process-wide random redaction salt, lazily generated on first use.
/// Used when [`RbacConfig::redaction_salt`] is `None`.
fn process_redaction_salt() -> &'static SecretString {
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    static PROCESS_SALT: LazyLock<SecretString> = LazyLock::new(|| {
        let mut bytes = [0_u8; 32];
        rand::fill(&mut bytes);
        // base64-encode so the SecretString is valid UTF-8; the HMAC
        // accepts arbitrary key bytes regardless.
        SecretString::from(STANDARD_NO_PAD.encode(bytes))
    });
    &PROCESS_SALT
}

/// HMAC-SHA256(`salt`, `value`) → first 8 hex chars.
///
/// Pulled out as a free function so it can be unit-tested and benchmarked
/// without constructing a full [`RbacPolicy`].
///
/// # Panics
///
/// The fallback HMAC key construction carries an `expect`, but it cannot
/// panic: a 32-byte SHA-256 digest is a valid HMAC-SHA256 key for any key
/// length (RFC 2104), so the expectation is always fulfilled.
#[expect(
    clippy::option_if_let_else,
    reason = "constant-time: src/rbac.rs::redact_with_salt keeps the HMAC key-construction fallback branch explicit rather than a combinator (G-8)"
)]
pub(crate) fn redact_with_salt(salt: &[u8], value: &str) -> String {
    use core::fmt::{Error as FmtError, Write as _};

    use sha2::Digest as _;

    type HmacSha256 = Hmac<Sha256>;
    // HMAC-SHA256 accepts keys of any byte length: the spec pads short
    // keys with zeros and hashes long keys, so `new_from_slice` is
    // infallible here. We still defensively re-key with a SHA-256 of
    // the salt if construction ever fails (e.g. future hmac upstream
    // tightens the contract); both branches produce a valid keyed MAC.
    let mut mac = if let Ok(constructed) = HmacSha256::new_from_slice(salt) {
        constructed
    } else {
        let digest = Sha256::digest(salt);
        #[expect(
            clippy::expect_used,
            reason = "32-byte SHA-256 digest is unconditionally valid as an HMAC-SHA256 key (RFC 2104 allows any key length); see surrounding comment"
        )]
        HmacSha256::new_from_slice(&digest).expect("32-byte SHA256 digest is valid HMAC key")
    };
    mac.update(value.as_bytes());
    let bytes = mac.finalize().into_bytes();
    // 4 bytes → 8 hex chars.
    let prefix = bytes.get(..4).unwrap_or(&[0; 4]);
    let mut out = String::with_capacity(8);
    for byte in prefix {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "write! into String cannot fail"
        )]
        let _: Result<(), FmtError> = write!(out, "{byte:02x}");
    }
    out
}

// -- RBAC middleware --

/// Which client-context fields the RBAC deny log may include.
///
/// Mirrors the operator's [`LogContextConfig`] toggles; kept separate so the
/// middleware does not need to thread the whole server config through.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DenyLogKnobs {
    /// Include the resolved client IP.
    client_ip: bool,
    /// Include the direct peer IP.
    peer_ip: bool,
    /// Include the request ID.
    request_id: bool,
}

impl DenyLogKnobs {
    /// Build the knobs from the operator's log-context configuration.
    pub(crate) const fn from_config(cfg: &LogContextConfig) -> Self {
        Self {
            client_ip: cfg.client_ip,
            peer_ip: cfg.peer_ip,
            request_id: cfg.request_id,
        }
    }
}

/// Client-context values attached to RBAC deny log lines.
///
/// Each field is populated only when the matching [`DenyLogKnobs`] toggle is
/// on and the request actually carries the value; absent fields are omitted
/// from the log line.
#[derive(Clone, Debug, Default)]
pub(crate) struct DenyLogFields {
    /// Resolved client IP, when enabled and present.
    client_ip: Option<IpAddr>,
    /// Direct peer IP, when enabled and present.
    peer_ip: Option<IpAddr>,
    /// Request ID, when enabled and present.
    request_id: Option<Arc<str>>,
}

impl DenyLogFields {
    /// Collect the enabled client-context fields from request extensions.
    fn from_extensions(knobs: DenyLogKnobs, ext: &Extensions) -> Self {
        Self {
            client_ip: knobs.client_ip.then(|| limiter_client_ip(ext)).flatten(),
            peer_ip: knobs.peer_ip.then(|| peer_ip_for_log(ext)).flatten(),
            request_id: knobs.request_id.then(|| request_id_for_log(ext)).flatten(),
        }
    }
}

/// Axum middleware that enforces RBAC and per-IP tool rate limiting on
/// MCP tool calls.
///
/// Inspects POST request bodies for `tools/call` JSON-RPC messages,
/// extracts the tool name and `host` argument, and checks the
/// [`RbacPolicy`] against the [`AuthIdentity`] set by the auth middleware.
///
/// When a `tool_limiter` is provided, tool invocations are rate-limited
/// per source IP regardless of whether RBAC is enabled (MCP spec: servers
/// MUST rate limit tool invocations).
///
/// Non-POST requests and non-tool-call messages pass through unchanged.
/// The caller's role is stored in task-local storage for use by tool
/// handlers (e.g. `list_hosts` host filtering via [`current_role()`]).
// NOTE: cognitive complexity reduced from 43/25 by extracting
// `enforce_tool_policy` and `enforce_rate_limit`. Remaining flow is a
// linear body-collect + JSON-RPC parse + dispatch, intentionally left
// inline to keep the request lifecycle visible at a glance.
// cancel-safe: `TimeoutLayer` may drop during `body.collect` or `next.run`;
// buffered body/task-local scopes are request-local, and tool limiter checks
// deliberately price attempted tool calls even if the handler times out.
pub(crate) async fn rbac_middleware(
    policy: Arc<RbacPolicy>,
    tool_limiter: Option<Arc<ToolRateLimiter>>,
    knobs: DenyLogKnobs,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Only inspect POST requests - tool calls are POSTs.
    if req.method() != Method::POST {
        return next.run(req).await;
    }

    // Extract the rate-limit key (resolved client IP when trusted-forwarder
    // mode is active, else the direct peer).
    // Resolved only when the tool limiter will actually consult it, so
    // servers without tool rate limiting never trip the
    // unattributed-fallback warning.
    let peer_key = tool_limiter
        .is_some()
        .then(|| limiter_client_key(req.extensions()));

    // Extract caller identity and role (may be absent when auth is off).
    let identity = req.extensions().get::<AuthIdentity>();
    let identity_name = identity.map(|id| id.name.clone()).unwrap_or_default();
    let role = identity.map(|id| id.role.clone()).unwrap_or_default();
    // Clone the SecretString end-to-end; an absent token becomes an empty
    // SecretString sentinel (current_token() filters this out as None).
    let raw_token: SecretString = identity
        .and_then(|id| id.raw_token.clone())
        .unwrap_or_else(|| SecretString::from(String::new()));
    let sub = identity.and_then(|id| id.sub.clone()).unwrap_or_default();

    let deny_fields = DenyLogFields::from_extensions(knobs, req.extensions());

    // RBAC requires an authenticated identity.
    if policy.is_enabled() && identity.is_none() {
        return RmcpServerKitError::Rbac("no authenticated identity".into()).into_response();
    }

    // Read the body for JSON-RPC inspection.
    let (parts, body) = req.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::error!(error = %error, "failed to read request body");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to read request body",
            )
                .into_response();
        }
    };

    // Try to parse as JSON and inspect JSON-RPC tool calls, including batch arrays.
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let tool_calls = extract_tool_calls(&json);
        if !tool_calls.is_empty() {
            for params in tool_calls {
                if let Some(resp) = enforce_rate_limit(tool_limiter.as_deref(), peer_key.as_ref()) {
                    #[cfg(feature = "metrics")]
                    record_rate_limit_deny(&parts.extensions, "tool");
                    return resp;
                }
                if policy.is_enabled()
                    && let Some(resp) =
                        enforce_tool_policy(&policy, &identity_name, &role, params, &deny_fields)
                {
                    return resp;
                }
            }
        }
    }
    // Non-parseable or non-tool-call requests pass through.

    // Reconstruct the request with the consumed body.
    let rebuilt_req = Request::from_parts(parts, Body::from(bytes));

    // Set the caller's role and identity in task-local storage for the handler.
    if role.is_empty() {
        next.run(rebuilt_req).await
    } else {
        CURRENT_ROLE
            .scope(
                role,
                CURRENT_IDENTITY.scope(
                    identity_name,
                    CURRENT_TOKEN.scope(raw_token, CURRENT_SUB.scope(sub, next.run(rebuilt_req))),
                ),
            )
            .await
    }
}

/// Extract the `params` object for every top-level `tools/call` message.
///
/// Supports either a single JSON-RPC object or a JSON-RPC batch array. Any
/// malformed elements are ignored so non-RPC payloads continue to pass through
/// unchanged.
fn extract_tool_calls(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => map
            .get("method")
            .and_then(serde_json::Value::as_str)
            .filter(|method| *method == "tools/call")
            .and_then(|_| map.get("params"))
            .into_iter()
            .collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                serde_json::Value::Object(map) => map
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .filter(|method| *method == "tools/call")
                    .and_then(|_| map.get("params")),
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_)
                | serde_json::Value::String(_)
                | serde_json::Value::Array(_) => None,
            })
            .collect(),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => Vec::new(),
    }
}

/// Per-IP rate limit check for tool invocations. Returns `Some(response)`
/// if the caller should be rejected.
fn enforce_rate_limit(
    tool_limiter: Option<&ToolRateLimiter>,
    peer_key: Option<&RateLimitKey>,
) -> Option<Response> {
    let limiter = tool_limiter?;
    let key = peer_key?;
    match limiter.check_key_detailed(key) {
        Ok(()) => None,
        Err(BoundedLimiterDeny::RateLimited(wait)) => {
            tracing::warn!(rate_limit_key = %key, "tool invocation rate limited");
            Some(
                RmcpServerKitError::RateLimitedFor {
                    message: "too many tool invocations".into(),
                    retry_after: wait,
                }
                .into_response(),
            )
        }
        Err(BoundedLimiterDeny::CapacityFull) => {
            tracing::warn!(
                rate_limit_key = %key,
                "tool invocation limiter rejected unseen key because tracked-key capacity is full"
            );
            Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "rate limiter capacity exhausted",
                )
                    .into_response(),
            )
        }
    }
}

/// Apply RBAC tool/host + argument-allowlist checks. Returns `Some(response)`
/// when the caller must be rejected. Assumes `policy.is_enabled()`.
///
/// `identity_name` is passed explicitly (rather than read from
/// [`current_identity()`]) because this function runs *before* the
/// task-local context is installed by the middleware. Reading the
/// task-local here would always yield `None`, producing deny logs with
/// an empty `user` field.
fn enforce_tool_policy(
    policy: &RbacPolicy,
    identity_name: &str,
    role: &str,
    params: &serde_json::Value,
    fields: &DenyLogFields,
) -> Option<Response> {
    let tool_name = params
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let host_value = params
        .get("arguments")
        .and_then(|arguments| arguments.get("host"));

    // M2 precedent (see `check_argument`): a caller-supplied `host` of the
    // wrong JSON type must not silently downgrade the host-glob check to an
    // operation-only check. `as_str()` on an array/object/number/bool/null
    // yields `None`, which would route to `check_operation` and skip
    // `RoleConfig.hosts` entirely -- letting a caller opt out of host
    // restrictions by changing the argument's shape. Fail closed, and log
    // the type rather than the value so no caller input is leaked.
    if let Some(value) = host_value
        && !value.is_string()
    {
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            value_type = json_value_type(value),
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "non-string host argument rejected"
        );
        return Some(
            RmcpServerKitError::Rbac(format!(
                "argument 'host' must be a string for tool '{tool_name}'"
            ))
            .into_response(),
        );
    }
    // Absent `host` still routes to `check_operation` by design: hostless
    // tools (`ping`, `list_hosts`) legitimately carry no host argument.
    let host = host_value.and_then(|host_str| host_str.as_str());

    let decision = host.map_or_else(
        || policy.check_operation(role, tool_name),
        |host_name| policy.check(role, tool_name, host_name),
    );
    if decision == RbacDecision::Deny {
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            host = host.unwrap_or("-"),
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "RBAC denied"
        );
        return Some(
            RmcpServerKitError::Rbac(format!("{tool_name} denied for role '{role}'"))
                .into_response(),
        );
    }

    let args = params
        .get("arguments")
        .and_then(|arguments| arguments.as_object());
    let strict = policy.strict_argument_names(role, tool_name);
    if let Some(arguments) = args {
        for (arg_key, arg_val) in arguments {
            if let Some(permitted) = &strict
                && let Some(resp) = check_strict_argument(
                    identity_name,
                    role,
                    tool_name,
                    permitted,
                    arg_key,
                    arg_val,
                    fields,
                )
            {
                return Some(resp);
            }
            if let Some(resp) = check_argument(
                policy,
                identity_name,
                role,
                tool_name,
                arg_key,
                arg_val,
                fields,
            ) {
                return Some(resp);
            }
        }
    }
    check_required_arguments(policy, identity_name, role, tool_name, args, fields)
}

/// Deny arguments outside the allowlisted set when strict confinement is on.
///
/// Object and array values are denied outright: their contents cannot be
/// constrained, so admitting them would reopen the bypass one level down.
fn check_strict_argument(
    identity_name: &str,
    role: &str,
    tool_name: &str,
    permitted: &[&str],
    arg_key: &str,
    arg_val: &serde_json::Value,
    fields: &DenyLogFields,
) -> Option<Response> {
    if !permitted.contains(&arg_key) {
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            argument = arg_key,
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "unknown argument rejected by strict allowlist"
        );
        return Some(
            RmcpServerKitError::Rbac(format!(
                "argument '{arg_key}' is not permitted for tool '{tool_name}'"
            ))
            .into_response(),
        );
    }
    if arg_val.is_object() || arg_val.is_array() {
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            argument = arg_key,
            value_type = json_value_type(arg_val),
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "structured argument rejected by strict allowlist"
        );
        return Some(
            RmcpServerKitError::Rbac(format!(
                "argument '{arg_key}' must not be an object or array for tool '{tool_name}'"
            ))
            .into_response(),
        );
    }
    None
}

/// Deny when a `required` argument is missing or not string-valued.
///
/// Absence can only be judged here: [`check_argument`] is keyed by a present
/// argument and structurally cannot observe a missing one. This runs even when
/// `args` is `None` -- i.e. the call carried no `arguments` object, or a
/// non-object -- because returning early on that would let a caller skip every
/// `required` constraint by omitting the object entirely.
fn check_required_arguments(
    policy: &RbacPolicy,
    identity_name: &str,
    role: &str,
    tool_name: &str,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
    fields: &DenyLogFields,
) -> Option<Response> {
    let missing = policy.missing_required_argument(role, tool_name, args)?;
    tracing::warn!(
        user = %identity_name,
        role = %role,
        tool = tool_name,
        argument = missing,
        client_ip = fields.client_ip.map(field::display),
        peer_ip = fields.peer_ip.map(field::display),
        request_id = fields.request_id.as_deref(),
        "required argument missing"
    );
    Some(
        RmcpServerKitError::Rbac(format!(
            "argument '{missing}' is required for tool '{tool_name}'"
        ))
        .into_response(),
    )
}

/// Deny a present argument whose value is not permitted by its allowlist.
///
/// Non-string values for an allowlisted argument are denied (fail closed);
/// the log records the value's type, never the value itself.
fn check_argument(
    policy: &RbacPolicy,
    identity_name: &str,
    role: &str,
    tool_name: &str,
    arg_key: &str,
    arg_val: &serde_json::Value,
    fields: &DenyLogFields,
) -> Option<Response> {
    if !policy.has_argument_allowlist(role, tool_name, arg_key) {
        return None;
    }
    let Some(val_str) = arg_val.as_str() else {
        // M2: an allowlist is configured for this argument but the
        // caller sent a non-string JSON value (array/object/number/
        // bool/null), which can never satisfy a `Vec<String>`
        // allowlist. Fail closed; log the type (not the value) so
        // operators see the rejected shape without leaking inputs.
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            argument = arg_key,
            value_type = json_value_type(arg_val),
            client_ip = fields.client_ip.map(field::display),
            peer_ip = fields.peer_ip.map(field::display),
            request_id = fields.request_id.as_deref(),
            "non-string argument rejected by allowlist"
        );
        return Some(
            RmcpServerKitError::Rbac(format!(
                "argument '{arg_key}' must be a string for tool '{tool_name}'"
            ))
            .into_response(),
        );
    };
    if policy.argument_allowed(role, tool_name, arg_key, val_str) {
        return None;
    }
    // Redact the raw value: log an HMAC-SHA256 prefix instead of
    // the literal string. Operators correlate hashes across log
    // lines without ever exposing potentially sensitive inputs
    // (paths, IDs, tokens accidentally passed as args, etc.).
    tracing::warn!(
        user = %identity_name,
        role = %role,
        tool = tool_name,
        argument = arg_key,
        arg_hmac = %policy.redact_arg(val_str),
        client_ip = fields.client_ip.map(field::display),
        peer_ip = fields.peer_ip.map(field::display),
        request_id = fields.request_id.as_deref(),
        "argument not in allowlist"
    );
    Some(
        RmcpServerKitError::Rbac(format!(
            "argument '{arg_key}' value not in allowlist for tool '{tool_name}'"
        ))
        .into_response(),
    )
}

/// Name of the JSON value's type, for shape-only deny log fields.
const fn json_value_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Simple glob matching: `*` matches any sequence of characters.
///
/// Supports multiple `*` wildcards anywhere in the pattern.
/// No `?`, `[...]`, or other advanced glob features.
///
/// All slice offsets are derived from `starts_with`/`ends_with`/`find`,
/// which guarantee char-boundary alignment; the `get(..)` accessors keep
/// that machine-checked (a violated invariant degrades to a non-match
/// instead of a panic).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcards - exact match.
        return pattern == text;
    }

    // First part must match at the start (unless pattern starts with *).
    let pos = if let Some(&first) = parts.first()
        && !first.is_empty()
    {
        if !text.starts_with(first) {
            return false;
        }
        first.len()
    } else {
        0
    };

    // Last part must match at the end (unless pattern ends with *).
    if let Some(&last) = parts.last()
        && !last.is_empty()
    {
        if !text.get(pos..).unwrap_or_default().ends_with(last) {
            return false;
        }
        // Shrink the search area so middle parts don't overlap with the suffix.
        let end = text.len().saturating_sub(last.len());
        if pos > end {
            return false;
        }
        // Check middle parts in the remaining region.
        let middle = text.get(pos..end).unwrap_or_default();
        let middle_parts = parts
            .get(1..parts.len().saturating_sub(1))
            .unwrap_or_default();
        return match_middle(middle, middle_parts);
    }

    // Pattern ends with * - just check middle parts.
    let middle = text.get(pos..).unwrap_or_default();
    let middle_parts = parts
        .get(1..parts.len().saturating_sub(1))
        .unwrap_or_default();
    match_middle(middle, middle_parts)
}

/// Match middle glob segments sequentially in `text`.
fn match_middle(mut text: &str, parts: &[&str]) -> bool {
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Some(idx) = text.find(part) {
            text = text
                .get(idx.saturating_add(part.len())..)
                .unwrap_or_default();
        } else {
            return false;
        }
    }
    true
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "deliberate: src/rbac.rs::RbacConfig — the second block groups the environment-override application; merging relocates ~90 lines for no behavior gain"
)]
impl RbacConfig {
    /// Applies `RMCP_SERVER_KIT__RBAC__*` environment overrides.
    ///
    /// Supports direct `redaction_salt` and `_FILE` secret indirection. Report
    /// entries for the secret target always redact the value. File-based
    /// secrets are treated as text: exactly one terminal line ending is removed
    /// (`\r\n`, `\n`, or `\r`) while other whitespace is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when both direct and file-based salt
    /// variables are set or when the `_FILE` target cannot be read.
    ///
    /// # Examples
    ///
    /// The full config-file pipeline lives in
    /// [`examples/config_file_server.rs`](https://github.com/andrico21/rmcp-server-kit/blob/main/examples/config_file_server.rs).
    ///
    /// ```no_run
    /// use rmcp_server_kit::rbac::RbacConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut rbac = RbacConfig::default();
    /// // Do not set process env in doctests: rustdoc examples share a process.
    /// let report = rbac.apply_env_overrides()?;
    /// let _secret_targets: Vec<&str> = report
    ///     .iter()
    ///     .filter(|entry| entry.value.is_none())
    ///     .map(|entry| entry.target_field.as_str())
    ///     .collect();
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn apply_env_overrides(&mut self) -> Result<Vec<EnvOverride>, RmcpServerKitError> {
        let direct = read_env(RBAC_REDACTION_SALT_ENV)?;
        let file = read_env(RBAC_REDACTION_SALT_FILE_ENV)?;
        match (direct, file) {
            (None, None) => Ok(Vec::new()),
            (Some(_), Some(_)) => Err(RmcpServerKitError::Config(format!(
                "{RBAC_REDACTION_SALT_ENV} and {RBAC_REDACTION_SALT_FILE_ENV} must not both be set"
            ))),
            (Some(value), None) => {
                reject_blank_redaction_salt(RBAC_REDACTION_SALT_ENV, &value)?;
                self.redaction_salt = Some(SecretString::from(value));
                Ok(vec![secret_env_report(
                    RBAC_REDACTION_SALT_ENV,
                    "rbac.redaction_salt",
                    EnvOverrideSource::Env,
                )])
            }
            (None, Some(path)) => {
                let secret = fs::read_to_string(PathBuf::from(&path)).map_err(|error| {
                    RmcpServerKitError::Config(format!(
                        "failed to read {RBAC_REDACTION_SALT_FILE_ENV} file {path:?}: {error}"
                    ))
                })?;
                let normalized = normalize_text_secret_file(secret);
                reject_blank_redaction_salt(RBAC_REDACTION_SALT_FILE_ENV, &normalized)?;
                self.redaction_salt = Some(SecretString::from(normalized));
                Ok(vec![secret_env_report(
                    RBAC_REDACTION_SALT_FILE_ENV,
                    "rbac.redaction_salt",
                    EnvOverrideSource::File,
                )])
            }
        }
    }
}

/// Reject a redaction salt that is empty or whitespace-only.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `value` trims to an empty string.
fn reject_blank_redaction_salt(env_var: &str, value: &str) -> Result<(), RmcpServerKitError> {
    if value.trim().is_empty() {
        return Err(RmcpServerKitError::Config(format!(
            "{env_var} must not be empty or whitespace-only"
        )));
    }
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    use core::net::SocketAddr;
    use std::{
        env,
        io::{self, Write},
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context as _;
    use axum::{Router, http::header::RETRY_AFTER, middleware, routing};
    #[cfg(feature = "metrics")]
    use axum::extract::ConnectInfo;
    use proptest::{collection, prelude::*};
    use serde_json::{Map, Number, Value as JsonValue};
    use tower::ServiceExt as _;
    use tracing::subscriber;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    #[cfg(feature = "metrics")]
    use crate::metrics::McpMetrics;
    use crate::{
        auth::AuthMethod,
        transport::{ClientIp, PeerAddr, RequestId},
    };

    fn with_rbac_env<R>(vars: &[(&str, Option<&str>)], run: impl FnOnce() -> R) -> R {
        temp_env::with_vars(
            [
                (RBAC_REDACTION_SALT_ENV, None::<&str>),
                (RBAC_REDACTION_SALT_FILE_ENV, None::<&str>),
            ]
            .into_iter()
            .chain(vars.iter().copied())
            .collect::<Vec<_>>(),
            run,
        )
    }

    /// Pins the redaction-salt env override and that its report redacts the value.
    ///
    /// # Panics
    ///
    /// The assertions panic on failure; tests fail by panicking.
    #[test]
    fn e6_redaction_salt_env_applies_and_report_redacts_value() -> anyhow::Result<()> {
        with_rbac_env(
            &[(RBAC_REDACTION_SALT_ENV, Some("s3cret"))],
            || -> anyhow::Result<()> {
                let mut cfg = RbacConfig::default();
                let report = cfg.apply_env_overrides()?;
                assert!(cfg.redaction_salt.is_some());
                assert_eq!(report.len(), 1);
                let entry = report.first().context("override report has one entry")?;
                assert_eq!(entry.env_var, RBAC_REDACTION_SALT_ENV);
                assert_eq!(entry.target_field, "rbac.redaction_salt");
                assert_eq!(entry.source, EnvOverrideSource::Env);
                assert!(entry.value.is_none());
                assert!(!format!("{report:?}").contains("s3cret"));
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Pins that setting both the direct and file redaction salts is rejected.
    #[test]
    fn e7_redaction_salt_value_and_file_conflict_fails() -> anyhow::Result<()> {
        with_rbac_env(
            &[
                (RBAC_REDACTION_SALT_ENV, Some("direct")),
                (RBAC_REDACTION_SALT_FILE_ENV, Some("/tmp/secret-file")),
            ],
            || -> anyhow::Result<()> {
                let mut cfg = RbacConfig::default();
                let Err(err) = cfg.apply_env_overrides() else {
                    anyhow::bail!("direct and file redaction salts must conflict");
                };
                let msg = err.to_string();
                assert!(msg.contains(RBAC_REDACTION_SALT_ENV));
                assert!(msg.contains(RBAC_REDACTION_SALT_FILE_ENV));
                Ok(())
            },
        )?;
        Ok(())
    }

    /// E8 redaction salt file env reads secret and reports file source.
    #[test]
    fn e8_redaction_salt_file_env_reads_secret_and_reports_file_source() -> anyhow::Result<()> {
        let (file_redaction, report) = redaction_from_file("same-salt\n").context("file salt")?;
        let direct_redaction = redaction_from_direct_salt("same-salt");

        assert_eq!(file_redaction, direct_redaction);
        assert_eq!(report.len(), 1);
        let entry = report.first().context("override report has one entry")?;
        assert_eq!(entry.env_var, RBAC_REDACTION_SALT_FILE_ENV);
        assert_eq!(entry.target_field, "rbac.redaction_salt");
        assert_eq!(entry.source, EnvOverrideSource::File);
        assert!(entry.value.is_none());
        Ok(())
    }

    /// Redaction salt file normalizes crlf and preserves spaces.
    #[test]
    fn redaction_salt_file_normalizes_crlf_and_preserves_spaces() -> anyhow::Result<()> {
        let (crlf_redaction, _) = redaction_from_file("same-salt\r\n").context("crlf salt")?;
        assert_eq!(crlf_redaction, redaction_from_direct_salt("same-salt"));

        let (spaced_redaction, _) =
            redaction_from_file("  same-salt  \n").context("spaced salt")?;
        assert_eq!(
            spaced_redaction,
            redaction_from_direct_salt("  same-salt  ")
        );
        assert_ne!(spaced_redaction, redaction_from_direct_salt("same-salt"));
        Ok(())
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }
    }

    struct CapturedLogsWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    fn allowlist_warning_policy(allowlist: ArgumentAllowlist) -> RbacConfig {
        RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
                .with_argument_allowlists(vec![allowlist]),
        ])
    }

    fn capture_policy_construction_logs(config: &RbacConfig) -> String {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let _policy = RbacPolicy::new(config);
        logs.contents()
    }

    fn capture_rbac_deny_logs(fields: &DenyLogFields) -> String {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        trigger_all_rbac_deny_lines(fields);
        logs.contents()
    }

    fn enabled_policy(role: RoleConfig) -> RbacPolicy {
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    fn run_policy(allowlists: Vec<ArgumentAllowlist>) -> RbacPolicy {
        enabled_policy(
            RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
                .with_argument_allowlists(allowlists),
        )
    }

    fn trigger_all_rbac_deny_lines(fields: &DenyLogFields) {
        let denied_policy = enabled_policy(RoleConfig::new(
            "viewer",
            vec!["echo".into()],
            vec!["*".into()],
        ));
        let denied = serde_json::json!({ "name": "forbidden", "arguments": {} });
        let _denied_response =
            enforce_tool_policy(&denied_policy, "alice", "viewer", &denied, fields);

        let host_shape = serde_json::json!({ "name": "echo", "arguments": { "host": ["bad"] } });
        let _host_shape_response =
            enforce_tool_policy(&denied_policy, "alice", "viewer", &host_shape, fields);

        let strict_policy = run_policy(vec![
            ArgumentAllowlist::new_required("run", "cmd", vec!["ls".into()])
                .with_deny_unknown_arguments(true),
        ]);
        let unknown =
            serde_json::json!({ "name": "run", "arguments": { "cmd": "ls", "danger": true } });
        let _unknown_response =
            enforce_tool_policy(&strict_policy, "alice", "viewer", &unknown, fields);
        let structured =
            serde_json::json!({ "name": "run", "arguments": { "cmd": { "nested": true } } });
        let _structured_response =
            enforce_tool_policy(&strict_policy, "alice", "viewer", &structured, fields);

        let required_policy = run_policy(vec![ArgumentAllowlist::new_required(
            "run",
            "cmd",
            vec!["ls".into()],
        )]);
        let missing = serde_json::json!({ "name": "run", "arguments": {} });
        let _missing_response =
            enforce_tool_policy(&required_policy, "alice", "viewer", &missing, fields);

        let allow_policy = run_policy(vec![ArgumentAllowlist::new_required(
            "run",
            "cmd",
            vec!["ls".into()],
        )]);
        let non_string = serde_json::json!({ "name": "run", "arguments": { "cmd": true } });
        let _non_string_response =
            enforce_tool_policy(&allow_policy, "alice", "viewer", &non_string, fields);
        let not_allowed = serde_json::json!({ "name": "run", "arguments": { "cmd": "rm" } });
        let _not_allowed_response =
            enforce_tool_policy(&allow_policy, "alice", "viewer", &not_allowed, fields);
    }

    fn assert_all_rbac_deny_messages_present(logs: &str) {
        for message in [
            "RBAC denied",
            "non-string host argument rejected",
            "unknown argument rejected by strict allowlist",
            "structured argument rejected by strict allowlist",
            "required argument missing",
            "non-string argument rejected by allowlist",
            "argument not in allowlist",
        ] {
            assert!(logs.contains(message), "missing {message:?}: {logs}");
        }
    }

    /// Rbac deny lines carry client fields when enabled.
    #[test]
    fn rbac_deny_lines_carry_client_fields_when_enabled() -> anyhow::Result<()> {
        let fields = DenyLogFields {
            client_ip: Some("198.51.100.4".parse().context("ip parses")?),
            peer_ip: Some("10.0.0.1".parse().context("ip parses")?),
            request_id: Some(Arc::from("qa-3")),
        };

        let logs = capture_rbac_deny_logs(&fields);

        assert_all_rbac_deny_messages_present(&logs);
        for line in logs.lines().filter(|line| {
            line.contains("rejected")
                || line.contains("denied")
                || line.contains("missing")
                || line.contains("allowlist")
        }) {
            assert!(line.contains("client_ip=198.51.100.4"), "{line}");
            assert!(line.contains("peer_ip=10.0.0.1"), "{line}");
            assert!(line.contains("request_id=\"qa-3\""), "{line}");
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::rbac_deny_lines_omit_client_fields_by_default keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Rbac deny lines omit client fields by default.
    fn rbac_deny_lines_omit_client_fields_by_default() -> anyhow::Result<()> {
        let logs = capture_rbac_deny_logs(&DenyLogFields::default());

        assert_all_rbac_deny_messages_present(&logs);
        assert!(!logs.contains("client_ip"), "{logs}");
        assert!(!logs.contains("peer_ip"), "{logs}");
        assert!(!logs.contains("request_id"), "{logs}");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::optional_non_empty_argument_allowlist_warns_once_at_policy_construction keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Optional non empty argument allowlist warns once at policy construction.
    fn optional_non_empty_argument_allowlist_warns_once_at_policy_construction()
    -> anyhow::Result<()> {
        let config =
            allowlist_warning_policy(ArgumentAllowlist::new("run", "cmd", vec!["ls".into()]));

        let logs = capture_policy_construction_logs(&config);

        assert_eq!(
            logs.matches("argument allowlist is optional and fails open")
                .count(),
            1,
            "exactly one warning expected for one optional non-empty allowlist: {logs}"
        );
        assert!(logs.contains("run"), "warning must name the tool: {logs}");
        assert!(
            logs.contains("cmd"),
            "warning must name the argument: {logs}"
        );
        assert!(
            logs.contains("required = true") && logs.contains("new_required"),
            "warning must name the remedy so an operator can act on it: {logs}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::required_argument_allowlist_does_not_warn_at_policy_construction keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Required argument allowlist does not warn at policy construction.
    fn required_argument_allowlist_does_not_warn_at_policy_construction() -> anyhow::Result<()> {
        let config = allowlist_warning_policy(
            ArgumentAllowlist::new("run", "cmd", vec!["ls".into()]).with_required(true),
        );

        let logs = capture_policy_construction_logs(&config);

        assert!(
            !logs.contains("argument allowlist is optional and fails open"),
            "required allowlist must not warn: {logs}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::new_required_sets_required_and_preserves_value_allowlist_behavior keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// New required sets required and preserves value allowlist behavior.
    fn new_required_sets_required_and_preserves_value_allowlist_behavior() -> anyhow::Result<()> {
        let optional = ArgumentAllowlist::new("run", "cmd", vec!["ls".into()]);
        let required = ArgumentAllowlist::new_required("run", "cmd", vec!["ls".into()]);

        assert_eq!(required.tool, optional.tool);
        assert_eq!(required.argument, optional.argument);
        assert_eq!(required.allowed, optional.allowed);
        assert!(required.required);
        assert!(!optional.required);

        let optional_policy = RbacPolicy::new(&allowlist_warning_policy(optional));
        let required_policy = RbacPolicy::new(&allowlist_warning_policy(required));
        assert_eq!(
            optional_policy.argument_allowed("viewer", "run", "cmd", "ls -la"),
            required_policy.argument_allowed("viewer", "run", "cmd", "ls -la")
        );
        assert_eq!(
            optional_policy.argument_allowed("viewer", "run", "cmd", "rm -rf /"),
            required_policy.argument_allowed("viewer", "run", "cmd", "rm -rf /")
        );
        Ok(())
    }

    /// Pins that blank direct redaction-salt env values fail closed.
    #[test]
    fn blank_redaction_salt_env_values_fail_closed() -> anyhow::Result<()> {
        for value in ["", "\n", "   "] {
            with_rbac_env(
                &[(RBAC_REDACTION_SALT_ENV, Some(value))],
                || -> anyhow::Result<()> {
                    let mut cfg = RbacConfig::default();
                    let Err(err) = cfg.apply_env_overrides() else {
                        anyhow::bail!("blank redaction salt must be rejected");
                    };
                    assert!(err.to_string().contains(RBAC_REDACTION_SALT_ENV));
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    /// Pins that blank redaction-salt file values fail closed.
    #[test]
    fn blank_redaction_salt_file_values_fail_closed() -> anyhow::Result<()> {
        for value in ["", "\n", "\r\n", "   \n"] {
            let Err(err) = redaction_from_file(value) else {
                anyhow::bail!("blank redaction salt file must be rejected");
            };
            assert!(err.to_string().contains(RBAC_REDACTION_SALT_FILE_ENV));
        }
        Ok(())
    }

    fn redaction_from_direct_salt(salt: &str) -> String {
        RbacPolicy::new(&RbacConfig {
            redaction_salt: Some(SecretString::from(salt.to_owned())),
            ..RbacConfig::default()
        })
        .redact_arg("same-argument")
    }

    fn redaction_from_file(content: &str) -> anyhow::Result<(String, Vec<EnvOverride>)> {
        let path = env::temp_dir().join(format!(
            "rmcp-server-kit-redaction-salt-{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("clock after epoch")?
                .as_nanos()
        ));
        fs::write(&path, content).context("write salt file")?;
        let path_string = path.to_string_lossy().to_string();
        let result = with_rbac_env(
            &[(RBAC_REDACTION_SALT_FILE_ENV, Some(path_string.as_str()))],
            || -> anyhow::Result<(String, Vec<EnvOverride>)> {
                let mut cfg = RbacConfig::default();
                let report = cfg.apply_env_overrides()?;
                let redaction = RbacPolicy::new(&cfg).redact_arg("same-argument");
                Ok((redaction, report))
            },
        );
        fs::remove_file(path).context("remove salt file")?;
        result
    }

    // -- tool rate limiter: burst + Retry-After --

    /// Burst capacity admits an initial spike larger than the sustained
    /// rate; the next request within the window is denied.
    #[test]
    fn tool_limiter_burst_allows_initial_spike() -> anyhow::Result<()> {
        let limiter = build_tool_rate_limiter_with_policy(2, Some(4), KeyEvictionPolicy::default());
        let ip = RateLimitKey::Ip("10.9.9.9".parse::<IpAddr>().context("unexpected value")?);
        for attempt in 0_usize..4 {
            assert!(
                limiter.check_key(&ip).is_ok(),
                "burst request {attempt} should pass"
            );
        }
        assert!(
            limiter.check_key(&ip).is_err(),
            "request 5 must exceed the burst bucket"
        );
        Ok(())
    }

    /// The tool-limiter deny response carries a Retry-After header.
    #[test]
    fn tool_limiter_deny_sets_retry_after() -> anyhow::Result<()> {
        let limiter = build_tool_rate_limiter_with_policy(1, None, KeyEvictionPolicy::default());
        let ip = RateLimitKey::Ip("10.8.8.8".parse::<IpAddr>().context("unexpected value")?);
        assert!(enforce_rate_limit(Some(&limiter), Some(&ip)).is_none());
        let resp = enforce_rate_limit(Some(&limiter), Some(&ip))
            .context("second call within the window must deny")?;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .context("Retry-After present")?
            .to_str()
            .context("unexpected value")?
            .parse::<u64>()
            .context("unexpected value")?;
        assert!(retry_after >= 1, "delta-seconds must be >= 1");
        Ok(())
    }

    /// Tool limiter capacity full returns 503 without retry after.
    #[test]
    fn tool_limiter_capacity_full_returns_503_without_retry_after() -> anyhow::Result<()> {
        let limiter = build_tool_rate_limiter_with_bounds(
            10,
            None,
            1,
            Duration::from_hours(1),
            KeyEvictionPolicy::RejectNew,
        );
        let established =
            RateLimitKey::Ip("10.8.8.8".parse::<IpAddr>().context("unexpected value")?);
        let unseen = RateLimitKey::Ip("10.8.8.9".parse::<IpAddr>().context("unexpected value")?);
        assert!(enforce_rate_limit(Some(&limiter), Some(&established)).is_none());

        let resp = enforce_rate_limit(Some(&limiter), Some(&unseen))
            .context("unseen key must be rejected at capacity")?;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get(RETRY_AFTER).is_none());
        Ok(())
    }

    fn test_policy() -> RbacPolicy {
        RbacPolicy::new(&RbacConfig {
            enabled: true,
            roles: vec![
                RoleConfig {
                    name: "viewer".into(),
                    description: Some("Read-only".into()),
                    allow: vec![
                        "list_hosts".into(),
                        "resource_list".into(),
                        "resource_inspect".into(),
                        "resource_logs".into(),
                        "system_info".into(),
                    ],
                    deny: vec![],
                    hosts: vec!["*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "deploy".into(),
                    description: Some("Lifecycle management".into()),
                    allow: vec![
                        "list_hosts".into(),
                        "resource_list".into(),
                        "resource_run".into(),
                        "resource_start".into(),
                        "resource_stop".into(),
                        "resource_restart".into(),
                        "resource_logs".into(),
                        "image_pull".into(),
                    ],
                    deny: vec!["resource_delete".into(), "resource_exec".into()],
                    hosts: vec!["web-*".into(), "api-*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "ops".into(),
                    description: Some("Full access".into()),
                    allow: vec!["*".into()],
                    deny: vec![],
                    hosts: vec!["*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "restricted-exec".into(),
                    description: Some("Exec with argument allowlist".into()),
                    allow: vec!["resource_exec".into()],
                    deny: vec![],
                    hosts: vec!["dev-*".into()],
                    argument_allowlists: vec![ArgumentAllowlist {
                        tool: "resource_exec".into(),
                        argument: "cmd".into(),
                        allowed: vec![
                            "sh".into(),
                            "bash".into(),
                            "cat".into(),
                            "ls".into(),
                            "ps".into(),
                        ],
                        required: false,
                        deny_unknown_arguments: false,
                    }],
                },
            ],
            redaction_salt: None,
            ..RbacConfig::default()
        })
    }

    // -- glob_match tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_exact_match keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob exact match.
    fn glob_exact_match() -> anyhow::Result<()> {
        assert!(glob_match("web-prod-1", "web-prod-1"));
        assert!(!glob_match("web-prod-1", "web-prod-2"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_star_suffix keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob star suffix.
    fn glob_star_suffix() -> anyhow::Result<()> {
        assert!(glob_match("web-*", "web-prod-1"));
        assert!(glob_match("web-*", "web-staging"));
        assert!(!glob_match("web-*", "api-prod"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_star_prefix keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob star prefix.
    fn glob_star_prefix() -> anyhow::Result<()> {
        assert!(glob_match("*-prod", "web-prod"));
        assert!(glob_match("*-prod", "api-prod"));
        assert!(!glob_match("*-prod", "web-staging"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_star_middle keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob star middle.
    fn glob_star_middle() -> anyhow::Result<()> {
        assert!(glob_match("web-*-prod", "web-us-prod"));
        assert!(glob_match("web-*-prod", "web-eu-east-prod"));
        assert!(!glob_match("web-*-prod", "web-staging"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_star_only keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob star only.
    fn glob_star_only() -> anyhow::Result<()> {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_multiple_stars keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Glob multiple stars.
    fn glob_multiple_stars() -> anyhow::Result<()> {
        assert!(glob_match("*web*prod*", "my-web-us-prod-1"));
        assert!(!glob_match("*web*prod*", "my-api-us-staging"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_match_multibyte_utf8 keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pin char-boundary behavior of the `get(..)`-based slicing across
    /// multi-byte UTF-8 text: offsets derived from `starts_with` /
    /// `ends_with` / `find` are always boundary-aligned, and matching
    /// must behave identically to the ASCII cases.
    fn glob_match_multibyte_utf8() -> anyhow::Result<()> {
        assert!(glob_match("h\u{e9}*llo", "h\u{e9}llo"));
        assert!(glob_match("*\u{f6}*", "w\u{f6}rld"));
        assert!(glob_match("\u{fc}ber*", "\u{fc}bermensch"));
        assert!(glob_match("*\u{754c}", "\u{4e16}\u{754c}"));
        assert!(!glob_match("h\u{e9}*llo", "hello"));
        assert!(!glob_match("\u{754c}*", "\u{4e16}\u{754c}"));
        assert!(glob_match("\u{4e16}*\u{754c}", "\u{4e16}\u{754c}"));
        Ok(())
    }

    // -- glob_match boundary / mutation-coverage tests --
    //
    // The cases below exist to kill specific mutants surfaced by
    // `cargo mutants` against `glob_match` / `match_middle` (see
    // CI run #84, May 2026). Each test is annotated with the mutation
    // it kills so the intent survives future refactors.

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_prefix_and_suffix_meet_exactly keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Kill: `if pos > end` mutated to `pos == end` and `pos >= end`
    /// at `glob_match` line 863. The prefix and suffix exactly meet
    /// (no characters between them); the original code accepts this,
    /// both mutants reject it.
    fn glob_prefix_and_suffix_meet_exactly() -> anyhow::Result<()> {
        // parts = ["ab", "cd"]; first.len()=2, end=text.len()-last.len()=2.
        // pos == end → original passes the `pos > end` check, mutants fail.
        assert!(glob_match("ab*cd", "abcd"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_middle_segment_required_with_suffix keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Kill: `parts.len() - 1` mutated to `parts.len() + 1` at line 868
    /// (middle-parts slice when pattern has a non-empty suffix). The
    /// mutant collapses the middle-parts slice to empty, which would
    /// incorrectly accept patterns whose middle segment isn't present.
    fn glob_middle_segment_required_with_suffix() -> anyhow::Result<()> {
        // Pattern requires "b" between "a" and "c"; text omits it.
        // Original: middle_parts=["b"], match_middle("xy", ["b"])=false → reject.
        // Mutant `+`: middle_parts=[] (slice out of bounds → unwrap_or_default),
        //             match_middle("xy", [])=true → wrongly accept.
        assert!(!glob_match("a*b*c", "axyc"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_match_middle_advances_past_matched_part keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Kill: `idx + part.len()` mutated to `idx - part.len()` at
    /// `match_middle` line 885. The mutant either underflows
    /// (panic in test) or fails to advance past the matched part,
    /// causing it to re-find the same prefix and accept patterns
    /// that should be rejected.
    fn glob_match_middle_advances_past_matched_part() -> anyhow::Result<()> {
        // Original: after finding "ab" at idx 2, advance to text[4..]="_yz",
        //           which contains no second "ab" → reject.
        // Mutant `-`: text[2-2..]="xxab_yz" → re-finds "ab" → wrongly accept
        //             (or panics for the smaller-idx variants).
        assert!(!glob_match("*ab*ab*", "xxab_yz"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::glob_match_middle_uses_addition_not_multiplication keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Kill: `idx + part.len()` mutated to `idx * part.len()` at
    /// `match_middle` line 885. The mutant computes a different
    /// (usually larger) advance offset that produces an out-of-bounds
    /// slice and panics, or skips over content that should match.
    fn glob_match_middle_uses_addition_not_multiplication() -> anyhow::Result<()> {
        // Original: find "abcde" at idx 8 in "yyyyyyyyabcde_X", advance
        //           to text[13..]="_X", find "X" → accept.
        // Mutant `*`: text[8*5..]=text[40..] → out-of-bounds → panic.
        assert!(glob_match("*abcde*X*", "yyyyyyyyabcde_X"));
        Ok(())
    }

    // -- RbacPolicy::argument_allowed mutation-coverage tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_glob_pattern_with_literal_mismatch_still_enforced keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Kill: `&&` mutated to `||` at `argument_allowed` line 494.
    /// The original short-circuits the allowlist lookup only when both
    /// the literal name AND the glob fail to match. The mutant
    /// short-circuits when EITHER fails, which means a glob-matched
    /// allowlist (literal mismatch, glob match) is silently skipped
    /// and the call is wrongly allowed.
    fn argument_allowed_glob_pattern_with_literal_mismatch_still_enforced() -> anyhow::Result<()> {
        // Allowlist registered against pattern "run-*" with allowed=["ls"].
        // Calling tool="run-foo" - literal "run-*" != "run-foo" (true),
        // but glob_match("run-*", "run-foo") = true.
        //   Original `&&`: skip-condition = true && false = false → enforce
        //                  allowlist → "rm" not in ["ls"] → deny.
        //   Mutant `||`:   skip-condition = true || false = true → skip
        //                  allowlist → wrongly allow.
        let role = RoleConfig::new("viewer", vec!["run-foo".into()], vec!["*".into()])
            .with_argument_allowlists(vec![ArgumentAllowlist::new(
                "run-*",
                "cmd",
                vec!["ls".into()],
            )]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        let policy = RbacPolicy::new(&config);
        assert!(!policy.argument_allowed("viewer", "run-foo", "cmd", "rm"));
        Ok(())
    }

    // -- RbacPolicy::check tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::disabled_policy_allows_everything keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Disabled policy allows everything.
    fn disabled_policy_allows_everything() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            roles: vec![],
            redaction_salt: None,
            ..RbacConfig::default()
        });
        assert_eq!(
            policy.check("nonexistent", "resource_delete", "any-host"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::unknown_role_denied keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Unknown role denied.
    fn unknown_role_denied() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("unknown", "resource_list", "web-prod-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::viewer_allowed_read_ops keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Viewer allowed read ops.
    fn viewer_allowed_read_ops() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("viewer", "resource_list", "web-prod-1"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("viewer", "system_info", "db-host"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::viewer_denied_write_ops keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Viewer denied write ops.
    fn viewer_denied_write_ops() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("viewer", "resource_run", "web-prod-1"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("viewer", "resource_delete", "web-prod-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deploy_allowed_on_matching_hosts keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deploy allowed on matching hosts.
    fn deploy_allowed_on_matching_hosts() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_run", "web-prod-1"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("deploy", "resource_start", "api-staging"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deploy_denied_on_non_matching_host keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deploy denied on non matching host.
    fn deploy_denied_on_non_matching_host() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_run", "db-prod-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deny_overrides_allow keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deny overrides allow.
    fn deny_overrides_allow() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_delete", "web-prod-1"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("deploy", "resource_exec", "web-prod-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::ops_wildcard_allows_everything keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Ops wildcard allows everything.
    fn ops_wildcard_allows_everything() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("ops", "resource_delete", "any-host"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("ops", "secret_create", "db-host"),
            RbacDecision::Allow
        );
        Ok(())
    }

    // -- host_visible tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::host_visible_respects_globs keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Host visible respects globs.
    fn host_visible_respects_globs() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(policy.host_visible("deploy", "web-prod-1"));
        assert!(policy.host_visible("deploy", "api-staging"));
        assert!(!policy.host_visible("deploy", "db-prod-1"));
        assert!(policy.host_visible("ops", "anything"));
        assert!(policy.host_visible("viewer", "anything"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::host_visible_unknown_role keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Host visible unknown role.
    fn host_visible_unknown_role() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(!policy.host_visible("unknown", "web-prod-1"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::host_matching_is_ascii_case_insensitive keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Host matching is ascii case insensitive.
    fn host_matching_is_ascii_case_insensitive() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(policy.host_visible("deploy", "WEB-PROD-1"));
        assert!(policy.host_visible("deploy", "Web-Prod-1"));
        assert!(policy.host_visible("deploy", "API-Staging"));
        assert!(!policy.host_visible("deploy", "DB-PROD-1"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_host_matching_is_ascii_case_insensitive keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check host matching is ascii case insensitive.
    fn check_host_matching_is_ascii_case_insensitive() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_run", "WEB-PROD-1"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("deploy", "resource_run", "DB-PROD-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_operation_names_remain_case_sensitive keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check operation names remain case sensitive.
    fn check_operation_names_remain_case_sensitive() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "RESOURCE_RUN", "web-prod-1"),
            RbacDecision::Deny,
            "host normalization must not leak into operation matching"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::tool_glob_matching_remains_case_sensitive keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Tool glob matching remains case sensitive.
    fn tool_glob_matching_remains_case_sensitive() -> anyhow::Result<()> {
        // Regression guard for the host-normalization change: lowercasing
        // inside `glob_match` would silently widen every tool allowlist.
        let role = RoleConfig::new("viewer", vec!["*".into()], vec!["*".into()])
            .with_argument_allowlists(vec![ArgumentAllowlist::new(
                "resource_*",
                "cmd",
                vec!["ls".into()],
            )]);
        let policy = RbacPolicy::new(&RbacConfig::with_roles(vec![role]));

        assert!(policy.has_argument_allowlist("viewer", "resource_exec", "cmd"));
        assert!(
            !policy.has_argument_allowlist("viewer", "RESOURCE_EXEC", "cmd"),
            "tool patterns must not match case-insensitively"
        );
        assert!(!policy.argument_allowed("viewer", "resource_exec", "cmd", "rm"));
        Ok(())
    }

    // -- argument_allowed tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_no_allowlist keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed no allowlist.
    fn argument_allowed_no_allowlist() -> anyhow::Result<()> {
        let policy = test_policy();
        // ops has no argument_allowlists -- all values allowed
        assert!(policy.argument_allowed("ops", "resource_exec", "cmd", "rm -rf /"));
        assert!(policy.argument_allowed("ops", "resource_exec", "cmd", "bash"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_with_allowlist keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed with allowlist.
    fn argument_allowed_with_allowlist() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(policy.argument_allowed("restricted-exec", "resource_exec", "cmd", "sh"));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "bash -c 'echo hi'"
        ));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "cat /etc/hosts"
        ));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "/usr/bin/ls -la"
        ));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_denied_not_in_allowlist keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument denied not in allowlist.
    fn argument_denied_not_in_allowlist() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(!policy.argument_allowed("restricted-exec", "resource_exec", "cmd", "rm -rf /"));
        assert!(!policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "python3 exploit.py"
        ));
        assert!(!policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "/usr/bin/curl evil.com"
        ));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_denied_unknown_role keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument denied unknown role.
    fn argument_denied_unknown_role() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(!policy.argument_allowed("unknown", "resource_exec", "cmd", "sh"));
        Ok(())
    }

    // -- M7: strict argument confinement (`deny_unknown_arguments`) --

    fn strict_test_policy(allowlists: Vec<ArgumentAllowlist>) -> RbacPolicy {
        let role = RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
            .with_argument_allowlists(allowlists);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    fn tool_call(args: serde_json::Value) -> serde_json::Value {
        let mut params = Map::new();
        let _previous_name = params.insert(
            "name".to_owned(),
            serde_json::Value::String("run".to_owned()),
        );
        let _previous_arguments = params.insert("arguments".to_owned(), args);
        serde_json::Value::Object(params)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::unknown_arguments_are_admitted_when_strict_mode_is_off keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Unknown arguments are admitted when strict mode is off.
    fn unknown_arguments_are_admitted_when_strict_mode_is_off() -> anyhow::Result<()> {
        let policy = strict_test_policy(vec![ArgumentAllowlist::new(
            "run",
            "cmd",
            vec!["ls".into()],
        )]);
        let params = tool_call(serde_json::json!({ "cmd": "ls", "danger": true }));
        assert!(
            enforce_tool_policy(&policy, "u", "viewer", &params, &DenyLogFields::default())
                .is_none(),
            "default behaviour must be unchanged: unnamed arguments pass"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::strict_mode_rejects_unknown_arguments keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Strict mode rejects unknown arguments.
    fn strict_mode_rejects_unknown_arguments() -> anyhow::Result<()> {
        let policy = strict_test_policy(vec![
            ArgumentAllowlist::new("run", "cmd", vec!["ls".into()])
                .with_deny_unknown_arguments(true),
        ]);
        let params = tool_call(serde_json::json!({ "cmd": "ls", "danger": true }));
        assert!(
            enforce_tool_policy(&policy, "u", "viewer", &params, &DenyLogFields::default())
                .is_some(),
            "an argument no allowlist names must be denied under strict mode"
        );

        let permitted = tool_call(serde_json::json!({ "cmd": "ls" }));
        assert!(
            enforce_tool_policy(
                &policy,
                "u",
                "viewer",
                &permitted,
                &DenyLogFields::default()
            )
            .is_none(),
            "an allowlisted argument must still pass"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::strict_mode_rejects_structured_argument_values keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Strict mode rejects structured argument values.
    fn strict_mode_rejects_structured_argument_values() -> anyhow::Result<()> {
        let policy = strict_test_policy(vec![
            ArgumentAllowlist::new("run", "cmd", vec![]).with_deny_unknown_arguments(true),
        ]);
        for shape in [
            serde_json::json!({ "nested": "x" }),
            serde_json::json!(["x"]),
        ] {
            let params = tool_call(serde_json::json!({ "cmd": shape }));
            assert!(
                enforce_tool_policy(&policy, "u", "viewer", &params, &DenyLogFields::default())
                    .is_some(),
                "object/array values cannot be constrained and must be denied"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::strict_mode_permits_the_union_of_matching_allowlists keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Strict mode permits the union of matching allowlists.
    fn strict_mode_permits_the_union_of_matching_allowlists() -> anyhow::Result<()> {
        // Only the first entry sets the flag, yet both arguments stay usable:
        // strict mode confines the whole `(role, tool)` pair, not one entry.
        let policy = strict_test_policy(vec![
            ArgumentAllowlist::new("run", "cmd", vec!["ls".into()])
                .with_deny_unknown_arguments(true),
            ArgumentAllowlist::new("run", "host", vec![]),
        ]);
        let params = tool_call(serde_json::json!({ "cmd": "ls", "host": "dev-1" }));
        assert!(
            enforce_tool_policy(&policy, "u", "viewer", &params, &DenyLogFields::default())
                .is_none(),
            "every matching allowlist's argument must remain permitted"
        );
        Ok(())
    }

    // -- shlex-tokenization regression tests (1.4.1) --
    //
    // These tests pin the POSIX-shell-like tokenization contract added
    // in 1.4.1. See `RbacPolicy::argument_allowed` doc comment for the
    // full contract; see CHANGELOG.md `[1.4.1]` for the behavior matrix.

    /// Helper: build a minimal enabled policy with a single argument
    /// allowlist on tool `run`, argument `cmd`.
    fn shlex_policy(allowed: Vec<String>) -> RbacPolicy {
        let role = RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
            .with_argument_allowlists(vec![ArgumentAllowlist::new("run", "cmd", allowed)]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_matches_quoted_path_with_spaces keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed matches quoted path with spaces.
    fn argument_allowed_matches_quoted_path_with_spaces() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["/usr/bin/my tool".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", r#""/usr/bin/my tool" --flag"#));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_matches_basename_of_quoted_path keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed matches basename of quoted path.
    fn argument_allowed_matches_basename_of_quoted_path() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["my tool".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", r#""/usr/bin/my tool" --flag"#));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_fails_closed_on_unbalanced_quote keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed fails closed on unbalanced quote.
    fn argument_allowed_fails_closed_on_unbalanced_quote() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["unbalanced".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", "unbalanced 'quote"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_fails_closed_on_empty_string keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed fails closed on empty string.
    fn argument_allowed_fails_closed_on_empty_string() -> anyhow::Result<()> {
        let policy = shlex_policy(vec![String::new()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", ""));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_handles_single_quoted_executable keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed handles single quoted executable.
    fn argument_allowed_handles_single_quoted_executable() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["/bin/sh".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", "'/bin/sh' -c 'echo hi'"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_handles_tab_separator keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed handles tab separator.
    fn argument_allowed_handles_tab_separator() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["ls".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", "ls\t/etc/passwd"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_plain_token_unchanged keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed plain token unchanged.
    fn argument_allowed_plain_token_unchanged() -> anyhow::Result<()> {
        let policy = shlex_policy(vec!["ls".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", "ls"));
        Ok(())
    }

    // Per Oracle review: the next four tests pin the cases the original
    // handoff missed. Each confirms the *new* (1.4.1) deny behavior so a
    // future regression to the old `split_whitespace` semantics would
    // surface as a test failure.

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_fails_closed_on_quoted_empty_first_token keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed fails closed on quoted empty first token.
    fn argument_allowed_fails_closed_on_quoted_empty_first_token() -> anyhow::Result<()> {
        // value r#""""# parses to Some(vec![""]). An empty argv element
        // is never a runnable executable; deny even when "" is
        // explicitly allowlisted.
        let policy = shlex_policy(vec![String::new()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", r#""""#));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_quoted_literal_token_no_longer_matches keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed quoted literal token no longer matches.
    fn argument_allowed_quoted_literal_token_no_longer_matches() -> anyhow::Result<()> {
        // 1.4.0 behavior: split_whitespace first token = "'bash'" --
        //                 matched literal allowlist entry "'bash'".
        // 1.4.1 behavior: shlex strips the surrounding quotes -> first
        //                 token = "bash" -- no match against allowlist
        //                 entry "'bash'". Deny.
        let policy = shlex_policy(vec!["'bash'".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", "'bash' -c true"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_backslash_literal_token_no_longer_matches keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed backslash literal token no longer matches.
    fn argument_allowed_backslash_literal_token_no_longer_matches() -> anyhow::Result<()> {
        // 1.4.0 behavior: literal first token "foo\\bar" matched.
        // 1.4.1 behavior: POSIX shlex treats backslash as escape ->
        //                 first token = "foobar". Allowlist entry with
        //                 a literal backslash no longer matches. Deny.
        let policy = shlex_policy(vec![r"foo\bar".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", r"foo\bar --x"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::argument_allowed_windows_path_no_longer_matches keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Argument allowed windows path no longer matches.
    fn argument_allowed_windows_path_no_longer_matches() -> anyhow::Result<()> {
        // 1.4.0 behavior: literal Windows path matched.
        // 1.4.1 behavior: POSIX shlex eats backslashes -> path identity
        //                 changes; allowlist entry no longer matches.
        //                 Deny. Documented in CHANGELOG operator notes.
        let policy = shlex_policy(vec![r"C:\Windows\System32\cmd.exe".into()]);
        assert!(!policy.argument_allowed(
            "viewer",
            "run",
            "cmd",
            r"C:\Windows\System32\cmd.exe /c dir"
        ));
        Ok(())
    }

    // -- host_patterns tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::host_patterns_returns_globs keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Host patterns returns globs.
    fn host_patterns_returns_globs() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.host_patterns("deploy"),
            Some(vec!["web-*".to_owned(), "api-*".to_owned()].as_slice())
        );
        assert_eq!(
            policy.host_patterns("ops"),
            Some(vec!["*".to_owned()].as_slice())
        );
        assert!(policy.host_patterns("nonexistent").is_none());
        Ok(())
    }

    // -- check_operation tests (no host check) --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_operation_allows_without_host keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check operation allows without host.
    fn check_operation_allows_without_host() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("deploy", "resource_run"),
            RbacDecision::Allow
        );
        // but check() with a non-matching host denies
        assert_eq!(
            policy.check("deploy", "resource_run", "db-prod-1"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_operation_deny_overrides keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check operation deny overrides.
    fn check_operation_deny_overrides() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("deploy", "resource_delete"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_operation_unknown_role keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check operation unknown role.
    fn check_operation_unknown_role() -> anyhow::Result<()> {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("unknown", "resource_list"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::check_operation_disabled keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Check operation disabled.
    fn check_operation_disabled() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            roles: vec![],
            redaction_salt: None,
            ..RbacConfig::default()
        });
        assert_eq!(
            policy.check_operation("nonexistent", "anything"),
            RbacDecision::Allow
        );
        Ok(())
    }

    // -- operation glob matching / global_deny tests --

    fn op_policy(role: RoleConfig) -> RbacPolicy {
        RbacPolicy::new(&RbacConfig::with_roles(vec![role]))
    }

    fn glob_op_policy(role: RoleConfig) -> RbacPolicy {
        RbacPolicy::new(
            &RbacConfig::with_roles(vec![role])
                .with_allow_operation_matching(AllowOperationMatching::Glob),
        )
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deny_glob_blocks_under_allow_all keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deny glob blocks under allow all.
    fn deny_glob_blocks_under_allow_all() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec!["*_delete_*".into()]),
        );
        assert_eq!(
            policy.check_operation("editor", "jira_delete_issue"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("editor", "confluence_delete_page"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("editor", "jira_get_issue"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deny_glob_blocks_in_host_scoped_check keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deny glob blocks in host scoped check.
    fn deny_glob_blocks_in_host_scoped_check() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec!["jira_delete_*".into()]),
        );
        assert_eq!(
            policy.check("editor", "jira_delete_issue", "web-prod"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("editor", "jira_get_issue", "web-prod"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deny_without_glob_still_matches_exactly keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deny without glob still matches exactly.
    fn deny_without_glob_still_matches_exactly() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec!["delete".into()]),
        );
        assert_eq!(
            policy.check_operation("editor", "delete"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("editor", "delete_thing"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check_operation("editor", "soft_delete"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::allow_glob_is_inert_in_legacy_mode keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Allow glob is inert in legacy mode.
    fn allow_glob_is_inert_in_legacy_mode() -> anyhow::Result<()> {
        let policy = op_policy(RoleConfig::new(
            "reader",
            vec!["jira_get_*".into()],
            vec!["*".into()],
        ));
        assert_eq!(
            policy.check_operation("reader", "jira_get_issue"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("reader", "jira_get_*"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::allow_glob_is_honored_in_glob_mode keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Allow glob is honored in glob mode.
    fn allow_glob_is_honored_in_glob_mode() -> anyhow::Result<()> {
        let policy = glob_op_policy(RoleConfig::new(
            "reader",
            vec!["jira_get_*".into()],
            vec!["*".into()],
        ));
        assert_eq!(
            policy.check_operation("reader", "jira_get_issue"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check_operation("reader", "confluence_get_page"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::allow_glob_mode_preserves_case_sensitivity keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Allow glob mode preserves case sensitivity.
    fn allow_glob_mode_preserves_case_sensitivity() -> anyhow::Result<()> {
        let policy = glob_op_policy(RoleConfig::new(
            "reader",
            vec!["Jira_*".into()],
            vec!["*".into()],
        ));
        assert_eq!(
            policy.check_operation("reader", "jira_get_issue"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("reader", "Jira_get_issue"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::allow_exact_entries_behave_identically_in_both_modes keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Allow exact entries behave identically in both modes.
    fn allow_exact_entries_behave_identically_in_both_modes() -> anyhow::Result<()> {
        let role = RoleConfig::new(
            "reader",
            vec!["ping".into(), "list_hosts".into()],
            vec!["*".into()],
        );
        let legacy = op_policy(role.clone());
        let glob = glob_op_policy(role);
        for op in ["ping", "list_hosts", "delete", "pin", "pingg"] {
            assert_eq!(
                legacy.check_operation("reader", op),
                glob.check_operation("reader", op),
                "mode divergence on glob-free allow entry for {op}"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::allow_star_means_all_operations_in_both_modes keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Allow star means all operations in both modes.
    fn allow_star_means_all_operations_in_both_modes() -> anyhow::Result<()> {
        let role = RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]);
        for policy in [op_policy(role.clone()), glob_op_policy(role)] {
            assert_eq!(
                policy.check_operation("admin", "anything_at_all"),
                RbacDecision::Allow
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::global_deny_vetoes_allow_all keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Global deny vetoes allow all.
    fn global_deny_vetoes_allow_all() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(
            &RbacConfig::with_roles(vec![RoleConfig::new(
                "admin",
                vec!["*".into()],
                vec!["*".into()],
            )])
            .with_global_deny(vec!["*_delete_*".into()]),
        );
        assert_eq!(
            policy.check_operation("admin", "jira_delete_issue"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("admin", "jira_delete_issue", "web-prod"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("admin", "jira_get_issue"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::global_deny_globs_even_in_legacy_allow_mode keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Global deny globs even in legacy allow mode.
    fn global_deny_globs_even_in_legacy_allow_mode() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(
            &RbacConfig::with_roles(vec![RoleConfig::new(
                "admin",
                vec!["*".into()],
                vec!["*".into()],
            )])
            .with_allow_operation_matching(AllowOperationMatching::Legacy)
            .with_global_deny(vec!["danger_*".into()]),
        );
        assert_eq!(
            policy.check_operation("admin", "danger_wipe"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::global_deny_is_inert_when_rbac_disabled keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Global deny is inert when rbac disabled.
    fn global_deny_is_inert_when_rbac_disabled() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            global_deny: vec!["*".into()],
            ..RbacConfig::default()
        });
        assert_eq!(
            policy.check_operation("anyone", "anything"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::global_deny_defaults_to_empty_and_changes_nothing keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Global deny defaults to empty and changes nothing.
    fn global_deny_defaults_to_empty_and_changes_nothing() -> anyhow::Result<()> {
        let policy = op_policy(RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]));
        assert_eq!(
            policy.check_operation("admin", "jira_delete_issue"),
            RbacDecision::Allow
        );
        assert_eq!(policy.summary().global_deny, 0);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::empty_deny_entry_denies_only_the_empty_operation keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Empty deny entry denies only the empty operation.
    fn empty_deny_entry_denies_only_the_empty_operation() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec![String::new()]),
        );
        assert_eq!(policy.check_operation("editor", ""), RbacDecision::Deny);
        assert_eq!(
            policy.check_operation("editor", "anything"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::empty_global_deny_entry_denies_only_the_empty_operation keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Empty global deny entry denies only the empty operation.
    fn empty_global_deny_entry_denies_only_the_empty_operation() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(
            &RbacConfig::with_roles(vec![RoleConfig::new(
                "admin",
                vec!["*".into()],
                vec!["*".into()],
            )])
            .with_global_deny(vec![String::new()]),
        );
        assert_eq!(policy.check_operation("admin", ""), RbacDecision::Deny);
        assert_eq!(
            policy.check_operation("admin", "anything"),
            RbacDecision::Allow
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::star_deny_entry_denies_every_operation keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Star deny entry denies every operation.
    fn star_deny_entry_denies_every_operation() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec!["*".into()]),
        );
        for op in ["", "ping", "jira_delete_issue"] {
            assert_eq!(policy.check_operation("editor", op), RbacDecision::Deny);
            assert_eq!(policy.check("editor", op, "web-prod"), RbacDecision::Deny);
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::star_global_deny_entry_denies_every_operation keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Star global deny entry denies every operation.
    fn star_global_deny_entry_denies_every_operation() -> anyhow::Result<()> {
        let policy = RbacPolicy::new(
            &RbacConfig::with_roles(vec![RoleConfig::new(
                "admin",
                vec!["*".into()],
                vec!["*".into()],
            )])
            .with_global_deny(vec!["*".into()]),
        );
        for op in ["", "ping", "jira_delete_issue"] {
            assert_eq!(policy.check_operation("admin", op), RbacDecision::Deny);
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::legacy_allow_matches_a_literal_star_in_an_operation_name keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Legacy allow matches a literal star in an operation name.
    fn legacy_allow_matches_a_literal_star_in_an_operation_name() -> anyhow::Result<()> {
        let policy = op_policy(RoleConfig::new(
            "odd",
            vec!["weird_*_name".into()],
            vec!["*".into()],
        ));
        assert_eq!(
            policy.check_operation("odd", "weird_*_name"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check_operation("odd", "weird_thing_name"),
            RbacDecision::Deny
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::deny_glob_matches_multibyte_operation_names keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Deny glob matches multibyte operation names.
    fn deny_glob_matches_multibyte_operation_names() -> anyhow::Result<()> {
        let policy = op_policy(
            RoleConfig::new("editor", vec!["*".into()], vec!["*".into()])
                .with_deny(vec!["\u{524a}\u{9664}_*".into()]),
        );
        assert_eq!(
            policy.check_operation("editor", "\u{524a}\u{9664}_\u{30da}\u{30fc}\u{30b8}"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check_operation("editor", "\u{53d6}\u{5f97}_\u{30da}\u{30fc}\u{30b8}"),
            RbacDecision::Allow
        );
        Ok(())
    }

    /// Operation matching fields deserialize from toml.
    #[test]
    fn operation_matching_fields_deserialize_from_toml() -> anyhow::Result<()> {
        let cfg: RbacConfig = toml::from_str(
            r#"
            enabled = true
            allow_operation_matching = "glob"
            global_deny = ["*_purge_*"]

            [[roles]]
            name = "ops"
            allow = ["jira_*"]
            hosts = ["*"]
            "#,
        )
        .context("config parses")?;
        assert_eq!(
            cfg.allow_operation_matching,
            AllowOperationMatching::Glob,
            "kebab-case wire value must map to the Glob variant"
        );
        assert_eq!(cfg.global_deny, vec!["*_purge_*".to_owned()]);

        let policy = RbacPolicy::new(&cfg);
        assert_eq!(
            policy.check_operation("ops", "jira_get_issue"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check_operation("ops", "jira_purge_project"),
            RbacDecision::Deny
        );
        Ok(())
    }

    /// Operation matching defaults to legacy when absent from toml.
    #[test]
    fn operation_matching_defaults_to_legacy_when_absent_from_toml() -> anyhow::Result<()> {
        let cfg: RbacConfig = toml::from_str("enabled = true").context("config parses")?;
        assert_eq!(cfg.allow_operation_matching, AllowOperationMatching::Legacy);
        assert_eq!(cfg.global_deny, Vec::<String>::new());
        Ok(())
    }

    // -- current_role / current_identity tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::current_role_returns_none_outside_scope keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Current role returns none outside scope.
    fn current_role_returns_none_outside_scope() -> anyhow::Result<()> {
        assert!(current_role().is_none());
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::current_identity_returns_none_outside_scope keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Current identity returns none outside scope.
    fn current_identity_returns_none_outside_scope() -> anyhow::Result<()> {
        assert!(current_identity().is_none());
        Ok(())
    }

    /// Empty task locals are all absent.
    #[tokio::test]
    async fn empty_task_locals_are_all_absent() -> anyhow::Result<()> {
        with_rbac_scope(
            String::new(),
            String::new(),
            SecretString::from(String::new()),
            String::new(),
            async {
                assert!(current_role().is_none(), "empty role must be absent");
                assert!(
                    current_identity().is_none(),
                    "empty identity must be absent"
                );
                assert!(current_token().is_none(), "empty token must be absent");
                assert!(current_sub().is_none(), "empty sub must be absent");
            },
        )
        .await;
        Ok(())
    }

    /// Non empty task locals are all present.
    #[tokio::test]
    async fn non_empty_task_locals_are_all_present() -> anyhow::Result<()> {
        with_rbac_scope(
            "viewer".to_owned(),
            "alice".to_owned(),
            SecretString::from("tok".to_owned()),
            "sub-1".to_owned(),
            async {
                assert_eq!(current_role().as_deref(), Some("viewer"));
                assert_eq!(current_identity().as_deref(), Some("alice"));
                assert!(current_token().is_some());
                assert_eq!(current_sub().as_deref(), Some("sub-1"));
            },
        )
        .await;
        Ok(())
    }

    /// The reachable shape from the downstream report: a real role with an
    /// empty identity and no sub. `current_sub().or_else(current_identity)`
    /// must resolve to `None` so a caller's `ok_or_else` guard fires, rather
    /// than yielding `Some("")` and being used as a per-user key.
    #[tokio::test]
    async fn sub_or_identity_fallback_is_absent_for_empty_identity() -> anyhow::Result<()> {
        with_rbac_scope(
            "viewer".to_owned(),
            String::new(),
            SecretString::from(String::new()),
            String::new(),
            async {
                assert_eq!(current_role().as_deref(), Some("viewer"));
                assert!(
                    current_sub().or_else(current_identity).is_none(),
                    "empty identity must not satisfy a sub-or-identity fallback"
                );
            },
        )
        .await;
        Ok(())
    }

    // -- rbac_middleware integration tests --

    fn tool_call_body(tool: &str, args: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_u32,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args
            }
        })
        .to_string()
    }

    #[expect(
        closure_returning_async_block,
        reason = "deliberate: src/rbac.rs::rbac_router — the per-request clone must run before the future; an async closure move-captures and does not implement FnMut"
    )]
    fn rbac_router(policy: Arc<RbacPolicy>) -> Router {
        Router::new()
            .route("/mcp", routing::post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let policy_clone = Arc::clone(&policy);
                rbac_middleware(policy_clone, None, DenyLogKnobs::default(), req, next)
            }))
    }

    #[expect(
        closure_returning_async_block,
        reason = "deliberate: src/rbac.rs::rbac_router_with_identity — the per-request clones must run before the future; an async closure move-captures and does not implement FnMut"
    )]
    fn rbac_router_with_identity(policy: Arc<RbacPolicy>, identity: AuthIdentity) -> Router {
        Router::new()
            .route("/mcp", routing::post(|| async { "ok" }))
            .layer(middleware::from_fn(
                move |mut req: Request<Body>, next: Next| {
                    let policy_clone = Arc::clone(&policy);
                    let identity_clone = identity.clone();
                    async move {
                        let _previous_identity = req.extensions_mut().insert(identity_clone);
                        rbac_middleware(policy_clone, None, DenyLogKnobs::default(), req, next)
                            .await
                    }
                },
            ))
    }

    #[expect(
        closure_returning_async_block,
        reason = "deliberate: src/rbac.rs::rbac_middleware_logs_client_fields_from_extensions — the per-request clones must run before the future; an async closure move-captures and does not implement FnMut"
    )]
    #[tokio::test]
    /// Rbac middleware logs client fields from extensions.
    async fn rbac_middleware_logs_client_fields_from_extensions() -> anyhow::Result<()> {
        let policy = Arc::new(enabled_policy(RoleConfig::new(
            "viewer",
            vec!["echo".into()],
            vec!["*".into()],
        )));
        let identity = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let client_ip: IpAddr = "198.51.100.4".parse().context("ip parses")?;
        let peer_addr: SocketAddr = "10.0.0.1:5555".parse().context("socket parses")?;
        let app = Router::new()
            .route("/mcp", routing::post(|| async { "ok" }))
            .layer(middleware::from_fn(move |mut req: Request<Body>, next| {
                let policy_clone = Arc::clone(&policy);
                let identity_clone = identity.clone();
                async move {
                    let _previous_identity = req.extensions_mut().insert(identity_clone);
                    let _previous_client_ip = req.extensions_mut().insert(ClientIp::new(client_ip));
                    let _previous_peer_addr = req.extensions_mut().insert(PeerAddr::new(peer_addr));
                    let _previous_request_id = req.extensions_mut().insert(RequestId::new("qa-4"));
                    rbac_middleware(
                        policy_clone,
                        None,
                        DenyLogKnobs {
                            client_ip: true,
                            peer_ip: true,
                            request_id: true,
                        },
                        req,
                        next,
                    )
                    .await
                }
            }));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(tool_call_body(
                "forbidden",
                &serde_json::json!({}),
            )))
            .context("unexpected value")?;

        let _guard = subscriber::set_default(subscriber);
        let status = app
            .oneshot(req)
            .await
            .context("request completes")?
            .status();

        assert_eq!(status, StatusCode::FORBIDDEN);
        let contents = logs.contents();
        let Some(line) = contents.lines().find(|line| line.contains("RBAC denied")) else {
            anyhow::bail!("missing RBAC denied line: {contents}");
        };
        assert!(line.contains("client_ip=198.51.100.4"), "{line}");
        assert!(line.contains("peer_ip=10.0.0.1"), "{line}");
        assert!(line.contains("request_id=\"qa-4\""), "{line}");
        Ok(())
    }

    #[cfg(feature = "metrics")]
    #[expect(
        closure_returning_async_block,
        reason = "deliberate: src/rbac.rs::tool_limiter_deny_increments_counter — the per-request clones must run before the future; an async closure move-captures and does not implement FnMut"
    )]
    #[tokio::test]
    /// Tool-limiter deny path must increment the `tool` deny counter via
    /// the metrics handle in the request extensions - and the increment
    /// must survive the middleware's body-buffer/`from_parts` rebuild.
    async fn tool_limiter_deny_increments_counter() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let limiter = build_tool_rate_limiter_with_policy(1, None, KeyEvictionPolicy::default());
        let metrics = Arc::new(McpMetrics::new().context("metrics build")?);
        let identity = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let peer: SocketAddr = "10.9.9.1:40000"
            .parse()
            .context("static socket addr parses")?;
        let app = {
            let metrics_for_app = Arc::clone(&metrics);
            Router::new()
                .route("/mcp", routing::post(|| async { "ok" }))
                .layer(middleware::from_fn(
                    move |mut req: Request<Body>, next: Next| {
                        let policy_clone = Arc::clone(&policy);
                        let limiter_clone = Arc::clone(&limiter);
                        let identity_clone = identity.clone();
                        let metrics_clone = Arc::clone(&metrics_for_app);
                        async move {
                            let _previous_identity = req.extensions_mut().insert(identity_clone);
                            let _previous_metrics = req.extensions_mut().insert(metrics_clone);
                            let _previous_connect_info =
                                req.extensions_mut().insert(ConnectInfo(peer));
                            rbac_middleware(
                                policy_clone,
                                Some(limiter_clone),
                                DenyLogKnobs::default(),
                                req,
                                next,
                            )
                            .await
                        }
                    },
                ))
        };
        let mk = || -> anyhow::Result<Request<Body>> {
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(tool_call_body(
                    "resource_list",
                    &serde_json::json!({}),
                )))
                .context("request builds")
        };
        let counter = || {
            metrics
                .rate_limited_total
                .with_label_values(&["tool"])
                .get()
        };

        let first = app
            .clone()
            .oneshot(mk()?)
            .await
            .context("request completes")?;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(counter(), 0, "successful call must not count");

        let denied = app
            .clone()
            .oneshot(mk()?)
            .await
            .context("request completes")?;
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(counter(), 1, "deny must increment the tool label");
        Ok(())
    }

    /// Middleware passes non post.
    #[tokio::test]
    async fn middleware_passes_non_post() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router(policy);
        // GET passes through even without identity.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/mcp")
            .body(Body::empty())
            .context("unexpected value")?;
        // GET on a POST-only route returns 405, but the middleware itself
        // doesn't block it -- it returns next.run(req).
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }

    /// Middleware denies without identity.
    #[tokio::test]
    async fn middleware_denies_without_identity() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router(policy);
        let body = tool_call_body("resource_list", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    fn global_deny_identity() -> AuthIdentity {
        AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "admin".into(),
            raw_token: None,
            sub: None,
        }
    }

    fn global_deny_policy() -> Arc<RbacPolicy> {
        Arc::new(RbacPolicy::new(
            &RbacConfig::with_roles(vec![RoleConfig::new(
                "admin",
                vec!["*".into()],
                vec!["*".into()],
            )])
            .with_global_deny(vec!["*_delete_*".into()]),
        ))
    }

    async fn global_deny_call(args: serde_json::Value, tool: &str) -> anyhow::Result<StatusCode> {
        let app = rbac_router_with_identity(global_deny_policy(), global_deny_identity());
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(tool_call_body(tool, &args)))
            .context("request builds")?;
        Ok(app.oneshot(req).await?.status())
    }

    /// Middleware global deny blocks hostless tool call.
    #[tokio::test]
    async fn middleware_global_deny_blocks_hostless_tool_call() -> anyhow::Result<()> {
        assert_eq!(
            global_deny_call(serde_json::json!({}), "jira_delete_issue").await?,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            global_deny_call(serde_json::json!({}), "jira_get_issue").await?,
            StatusCode::OK
        );
        Ok(())
    }

    /// Middleware global deny blocks host scoped tool call.
    #[tokio::test]
    async fn middleware_global_deny_blocks_host_scoped_tool_call() -> anyhow::Result<()> {
        assert_eq!(
            global_deny_call(serde_json::json!({"host": "web-prod"}), "jira_delete_issue").await?,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            global_deny_call(serde_json::json!({"host": "web-prod"}), "jira_get_issue").await?,
            StatusCode::OK
        );
        Ok(())
    }

    /// Middleware allows permitted tool.
    #[tokio::test]
    async fn middleware_allows_permitted_tool() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body("resource_list", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    /// Middleware denies unpermitted tool.
    #[tokio::test]
    async fn middleware_denies_unpermitted_tool() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body("resource_delete", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Middleware passes non tool call post.
    #[tokio::test]
    async fn middleware_passes_non_tool_call_post() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        // A non-tools/call JSON-RPC (e.g. resources/list) passes through.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_u32,
            "method": "resources/list"
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    /// Middleware enforces argument allowlist.
    #[tokio::test]
    async fn middleware_enforces_argument_allowlist() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "dev".into(),
            role: "restricted-exec".into(),
            raw_token: None,
            sub: None,
        };
        // Allowed command
        let app = rbac_router_with_identity(Arc::clone(&policy), id.clone());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({"cmd": "ls -la", "host": "dev-1"}),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Denied command
        let app_denied = rbac_router_with_identity(policy, id);
        let body_denied = tool_call_body(
            "resource_exec",
            &serde_json::json!({"cmd": "rm -rf /", "host": "dev-1"}),
        );
        let req_denied = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body_denied))
            .context("unexpected value")?;
        let resp_denied = app_denied
            .oneshot(req_denied)
            .await
            .context("unexpected value")?;
        assert_eq!(resp_denied.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Middleware disabled policy passes everything.
    #[tokio::test]
    async fn middleware_disabled_policy_passes_everything() -> anyhow::Result<()> {
        let policy = Arc::new(RbacPolicy::disabled());
        let app = rbac_router(policy);
        // No identity, disabled policy -- should pass.
        let body = tool_call_body("anything", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    /// Middleware batch all allowed passes.
    #[tokio::test]
    async fn middleware_batch_all_allowed_passes() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1_u32,
                "method": "tools/call",
                "params": { "name": "resource_list", "arguments": {} }
            },
            {
                "jsonrpc": "2.0",
                "id": 2_u32,
                "method": "tools/call",
                "params": { "name": "system_info", "arguments": {} }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    /// Middleware batch with denied call rejects entire batch.
    #[tokio::test]
    async fn middleware_batch_with_denied_call_rejects_entire_batch() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1_u32,
                "method": "tools/call",
                "params": { "name": "resource_list", "arguments": {} }
            },
            {
                "jsonrpc": "2.0",
                "id": 2_u32,
                "method": "tools/call",
                "params": { "name": "resource_delete", "arguments": {} }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Middleware batch mixed allowed and denied rejects.
    #[tokio::test]
    async fn middleware_batch_mixed_allowed_and_denied_rejects() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "dev".into(),
            role: "restricted-exec".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1_u32,
                "method": "tools/call",
                "params": {
                    "name": "resource_exec",
                    "arguments": { "cmd": "ls -la", "host": "dev-1" }
                }
            },
            {
                "jsonrpc": "2.0",
                "id": 2_u32,
                "method": "tools/call",
                "params": {
                    "name": "resource_exec",
                    "arguments": { "cmd": "rm -rf /", "host": "dev-1" }
                }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    // -- redact_arg / redaction_salt tests --

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::redact_with_salt_is_deterministic_per_salt keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Redact with salt is deterministic per salt.
    fn redact_with_salt_is_deterministic_per_salt() -> anyhow::Result<()> {
        let salt = b"unit-test-salt";
        let first = redact_with_salt(salt, "rm -rf /");
        let second = redact_with_salt(salt, "rm -rf /");
        assert_eq!(first, second, "same input + salt must yield identical hash");
        assert_eq!(first.len(), 8, "redacted hash is 8 hex chars (4 bytes)");
        assert!(
            first.chars().all(|ch| ch.is_ascii_hexdigit()),
            "redacted hash must be lowercase hex: {first}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::redact_with_salt_differs_across_salts keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Redact with salt differs across salts.
    fn redact_with_salt_differs_across_salts() -> anyhow::Result<()> {
        let value = "the-same-value";
        let h1 = redact_with_salt(b"salt-one", value);
        let h2 = redact_with_salt(b"salt-two", value);
        assert_ne!(
            h1, h2,
            "different salts must produce different hashes for the same value"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::redact_with_salt_distinguishes_values keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Redact with salt distinguishes values.
    fn redact_with_salt_distinguishes_values() -> anyhow::Result<()> {
        let salt = b"k";
        let h1 = redact_with_salt(salt, "alpha");
        let h2 = redact_with_salt(salt, "beta");
        // Hash collisions on 32 bits are 1-in-4-billion; safe to assert.
        assert_ne!(h1, h2, "different values must produce different hashes");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::policy_with_configured_salt_redacts_consistently keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Policy with configured salt redacts consistently.
    fn policy_with_configured_salt_redacts_consistently() -> anyhow::Result<()> {
        let cfg = RbacConfig {
            enabled: true,
            roles: vec![],
            redaction_salt: Some(SecretString::from("my-stable-salt")),
            ..RbacConfig::default()
        };
        let p1 = RbacPolicy::new(&cfg);
        let p2 = RbacPolicy::new(&cfg);
        assert_eq!(
            p1.redact_arg("payload"),
            p2.redact_arg("payload"),
            "policies built from the same configured salt must agree"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::policy_without_configured_salt_uses_process_salt keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Policy without configured salt uses process salt.
    fn policy_without_configured_salt_uses_process_salt() -> anyhow::Result<()> {
        let cfg = RbacConfig {
            enabled: true,
            roles: vec![],
            redaction_salt: None,
            ..RbacConfig::default()
        };
        let p1 = RbacPolicy::new(&cfg);
        let p2 = RbacPolicy::new(&cfg);
        // Within one process, the lazy OnceLock salt is shared.
        assert_eq!(
            p1.redact_arg("payload"),
            p2.redact_arg("payload"),
            "process-wide salt must be consistent within one process"
        );
        Ok(())
    }

    // -- enforce_tool_policy identity propagation regression test (BUG H-S3) --

    /// Regression: when `enforce_tool_policy` denied a request, the deny
    /// log used to read `current_identity()`, which was always `None` at
    /// that point because the task-local context is installed *after*
    /// policy enforcement. The fix passes `identity_name` explicitly.
    ///
    /// We assert the deny path returns 403 (the visible behaviour).
    /// The log-content assertion lives behind tracing-test which we have
    /// not yet added as a dev-dep; the explicit-parameter signature alone
    /// makes the previous bug structurally impossible.
    #[tokio::test]
    async fn deny_path_uses_explicit_identity_not_task_local() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "alice-the-auditor".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        // viewer is not allowed to call resource_delete -> 403.
        let body = tool_call_body("resource_delete", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    // -- M2 regression: non-string argument values bypass allowlist --

    fn restricted_exec_identity() -> AuthIdentity {
        AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "carol".into(),
            role: "restricted-exec".into(),
            raw_token: None,
            sub: None,
        }
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac.rs::has_argument_allowlist_matches_configured_tool_argument keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Has argument allowlist matches configured tool argument.
    fn has_argument_allowlist_matches_configured_tool_argument() -> anyhow::Result<()> {
        let policy = test_policy();
        assert!(policy.has_argument_allowlist("restricted-exec", "resource_exec", "cmd"));
        assert!(!policy.has_argument_allowlist("restricted-exec", "resource_exec", "host"));
        assert!(!policy.has_argument_allowlist("restricted-exec", "other_tool", "cmd"));
        assert!(!policy.has_argument_allowlist("ops", "resource_exec", "cmd"));
        Ok(())
    }

    /// Array arg with matching allowlist is denied.
    #[tokio::test]
    async fn array_arg_with_matching_allowlist_is_denied() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": ["bash", "-c", "evil"] }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Object arg with matching allowlist is denied.
    #[tokio::test]
    async fn object_arg_with_matching_allowlist_is_denied() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": { "raw": "sh" } }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Number arg with matching allowlist is denied.
    #[tokio::test]
    async fn number_arg_with_matching_allowlist_is_denied() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": 42_u32 }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Bool arg with matching allowlist is denied.
    #[tokio::test]
    async fn bool_arg_with_matching_allowlist_is_denied() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": true }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Null arg with matching allowlist is denied.
    #[tokio::test]
    async fn null_arg_with_matching_allowlist_is_denied() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": null }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Non string arg without allowlist is passthrough.
    #[tokio::test]
    async fn non_string_arg_without_allowlist_is_passthrough() -> anyhow::Result<()> {
        // ops has no argument_allowlist for any (tool, arg) tuple, so
        // non-string values must reach the handler. resource_exec is in
        // ops's allow list so the call should not be rejected by RBAC.
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "olivia".into(),
            role: "ops".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": ["bash"] }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// String arg in allowlist still passes.
    #[tokio::test]
    async fn string_arg_in_allowlist_still_passes() -> anyhow::Result<()> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({ "host": "dev-1", "cmd": "bash" }),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("unexpected value")?;
        let resp = app.oneshot(req).await.context("unexpected value")?;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    // -- F4 regression: non-string `host` downgraded the host-glob check --
    //
    // `restricted-exec` is scoped to `hosts: ["dev-*"]`. Before the fix,
    // `arguments.host` was read with `as_str()`, so any non-string shape
    // yielded `None` and routed to `check_operation`, skipping the host
    // globs entirely -- letting a caller reach `prod-1` by sending the
    // host as an array. Each case below returned 200 before the fix.

    async fn exec_status(args: &serde_json::Value) -> anyhow::Result<StatusCode> {
        let policy = Arc::new(test_policy());
        let app = rbac_router_with_identity(policy, restricted_exec_identity());
        let body = tool_call_body("resource_exec", args);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("request builds")?;
        Ok(app.oneshot(req).await?.status())
    }

    /// Non string host is denied for every json type.
    #[tokio::test]
    async fn non_string_host_is_denied_for_every_json_type() -> anyhow::Result<()> {
        for host in [
            serde_json::json!(["prod-1"]),
            serde_json::json!({ "name": "prod-1" }),
            serde_json::json!(42_u32),
            serde_json::json!(true),
            serde_json::json!(null),
        ] {
            let args = serde_json::json!({ "host": host, "cmd": "sh" });
            assert_eq!(
                exec_status(&args).await?,
                StatusCode::FORBIDDEN,
                "non-string host must not bypass host globs: {host:?}"
            );
        }
        Ok(())
    }

    /// String host outside globs still denied.
    #[tokio::test]
    async fn string_host_outside_globs_still_denied() -> anyhow::Result<()> {
        let args = serde_json::json!({ "host": "prod-1", "cmd": "sh" });
        assert_eq!(exec_status(&args).await?, StatusCode::FORBIDDEN);
        Ok(())
    }

    /// String host inside globs still allowed.
    #[tokio::test]
    async fn string_host_inside_globs_still_allowed() -> anyhow::Result<()> {
        let args = serde_json::json!({ "host": "dev-1", "cmd": "sh" });
        assert_ne!(exec_status(&args).await?, StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Asserts the deliberate scope boundary: an absent `host` still routes
    /// to `check_operation` so hostless tools keep working. Requiring a host
    /// unconditionally would break `ping` / `list_hosts`.
    #[tokio::test]
    async fn absent_host_still_routes_to_check_operation() -> anyhow::Result<()> {
        let args = serde_json::json!({ "cmd": "sh" });
        assert_ne!(exec_status(&args).await?, StatusCode::FORBIDDEN);
        Ok(())
    }

    // -- F5: opt-in `required` on ArgumentAllowlist --
    //
    // An allowlist constrains a value only when the argument is present, so a
    // caller could skip it entirely by omitting the key. That is safe when the
    // tool's input schema marks the argument required, but fails open when the
    // handler substitutes a default. `required` is opt-in so existing configs
    // are untouched.

    fn required_policy(allowed: Vec<String>, required: bool) -> RbacPolicy {
        let role = RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
            .with_argument_allowlists(vec![
                ArgumentAllowlist::new("run", "cmd", allowed).with_required(required),
            ]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    fn viewer_identity() -> AuthIdentity {
        AuthIdentity {
            method: AuthMethod::BearerToken,
            name: "viewer-1".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        }
    }

    async fn run_status(
        policy: RbacPolicy,
        params: &serde_json::Value,
    ) -> anyhow::Result<StatusCode> {
        let app = rbac_router_with_identity(Arc::new(policy), viewer_identity());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_u32,
            "method": "tools/call",
            "params": params
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .context("request builds")?;
        Ok(app.oneshot(req).await?.status())
    }

    /// Required false still allows omitting the argument.
    #[tokio::test]
    async fn required_false_still_allows_omitting_the_argument() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": {} });
        assert_ne!(
            run_status(required_policy(vec!["ls".into()], false), &params).await?,
            StatusCode::FORBIDDEN,
            "default behaviour must be unchanged"
        );
        Ok(())
    }

    /// Required true denies omitted argument.
    #[tokio::test]
    async fn required_true_denies_omitted_argument() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": {} });
        assert_eq!(
            run_status(required_policy(vec!["ls".into()], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true allows permitted value.
    #[tokio::test]
    async fn required_true_allows_permitted_value() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": { "cmd": "ls -la" } });
        assert_ne!(
            run_status(required_policy(vec!["ls".into()], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true still denies disallowed value.
    #[tokio::test]
    async fn required_true_still_denies_disallowed_value() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": { "cmd": "rm -rf /" } });
        assert_eq!(
            run_status(required_policy(vec!["ls".into()], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true denies non string value.
    #[tokio::test]
    async fn required_true_denies_non_string_value() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": { "cmd": ["ls"] } });
        assert_eq!(
            run_status(required_policy(vec!["ls".into()], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true denies absent or non object arguments.
    #[tokio::test]
    async fn required_true_denies_absent_or_non_object_arguments() -> anyhow::Result<()> {
        for params in [
            serde_json::json!({ "name": "run" }),
            serde_json::json!({ "name": "run", "arguments": "not-an-object" }),
            serde_json::json!({ "name": "run", "arguments": null }),
        ] {
            assert_eq!(
                run_status(required_policy(vec!["ls".into()], true), &params).await?,
                StatusCode::FORBIDDEN,
                "omitting the arguments object must not skip `required`: {params:?}"
            );
        }
        Ok(())
    }

    // Empty `allowed` means "unrestricted value". Combined with `required`
    // that is "must be supplied as a string, any value accepted".
    /// Required true with empty allowed accepts any string.
    #[tokio::test]
    async fn required_true_with_empty_allowed_accepts_any_string() -> anyhow::Result<()> {
        let params =
            serde_json::json!({ "name": "run", "arguments": { "cmd": "anything at all" } });
        assert_ne!(
            run_status(required_policy(vec![], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true with empty allowed denies omitted argument.
    #[tokio::test]
    async fn required_true_with_empty_allowed_denies_omitted_argument() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": {} });
        assert_eq!(
            run_status(required_policy(vec![], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required true with empty allowed denies non string.
    #[tokio::test]
    async fn required_true_with_empty_allowed_denies_non_string() -> anyhow::Result<()> {
        let params = serde_json::json!({ "name": "run", "arguments": { "cmd": 42_u32 } });
        assert_eq!(
            run_status(required_policy(vec![], true), &params).await?,
            StatusCode::FORBIDDEN
        );
        Ok(())
    }

    /// Required honours globbed tool patterns.
    #[tokio::test]
    async fn required_honours_globbed_tool_patterns() -> anyhow::Result<()> {
        let role = RoleConfig::new("viewer", vec!["*".into()], vec!["*".into()])
            .with_argument_allowlists(vec![
                ArgumentAllowlist::new("run-*", "cmd", vec!["ls".into()]).with_required(true),
            ]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        let params = serde_json::json!({ "name": "run-foo", "arguments": {} });
        assert_eq!(
            run_status(RbacPolicy::new(&config), &params).await?,
            StatusCode::FORBIDDEN,
            "a globbed tool pattern must enforce presence, not just value"
        );
        Ok(())
    }

    /// Required defaults to false when absent from toml.
    #[test]
    fn required_defaults_to_false_when_absent_from_toml() -> anyhow::Result<()> {
        let cfg: RbacConfig = toml::from_str(
            r#"
            enabled = true
            [[roles]]
            name = "viewer"
            allow = ["run"]
            [[roles.argument_allowlists]]
            tool = "run"
            argument = "cmd"
            allowed = ["ls"]
            "#,
        )
        .context("config without `required` must still deserialize")?;
        let role = cfg.roles.first().context("one role configured")?;
        let allowlist = role.argument_allowlists.first().context("one allowlist")?;
        assert!(
            !allowlist.required,
            "omitted `required` must default to false so existing configs are unchanged"
        );
        Ok(())
    }

    /// Pins that an unknown top-level RBAC config key is rejected.
    #[test]
    fn unknown_rbac_config_key_is_rejected() -> anyhow::Result<()> {
        let Err(err) = toml::from_str::<RbacConfig>(
            "
            enabled = true
            typo_roles = []
            ",
        ) else {
            anyhow::bail!("an unknown config key must be rejected");
        };

        let msg = err.to_string();
        assert!(
            msg.contains("typo_roles"),
            "error must name the offending key: {msg}"
        );
        Ok(())
    }

    /// Strategy for an arbitrary JSON value, bounded in depth and size.
    fn prop_json_value_strategy() -> impl Strategy<Value = JsonValue> {
        let leaf = prop_oneof![
            Just(JsonValue::Null),
            any::<bool>().prop_map(JsonValue::Bool),
            any::<i64>().prop_map(|number| JsonValue::Number(Number::from(number))),
            ".*".prop_map(JsonValue::String),
        ];
        leaf.prop_recursive(3, 32, 4, |inner| {
            prop_oneof![
                collection::vec(inner.clone(), 0..4).prop_map(JsonValue::Array),
                collection::btree_map("[a-z]{1,8}", inner, 0..4)
                    .prop_map(|entries| JsonValue::Object(entries.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// A role with no allowed tools denies every JSON-RPC `tools/call`
        /// params object, whatever its shape, without panicking.
        #[test]
        fn prop_empty_allowlist_denies_arbitrary_json(
            params in prop_json_value_strategy(),
        ) {
            let policy = enabled_policy(RoleConfig::new(
                "viewer",
                Vec::new(),
                vec!["*".to_owned()],
            ));
            let response = enforce_tool_policy(
                &policy,
                "alice",
                "viewer",
                &params,
                &DenyLogFields::default(),
            );
            prop_assert!(
                response.is_some(),
                "a role with no allowed tools must deny {:?}",
                params
            );
        }

        /// A tool with an explicit deny entry stays denied for arbitrary
        /// argument JSON and for any string host.
        #[test]
        fn prop_denied_tool_stays_denied(
            tool in "[a-z_]{1,16}",
            host in "[a-zA-Z0-9._-]{0,24}",
            extra in prop_json_value_strategy(),
        ) {
            let policy = enabled_policy(
                RoleConfig::new("viewer", vec!["*".to_owned()], vec!["*".to_owned()])
                    .with_deny(vec![tool.clone()]),
            );
            let mut arguments = Map::new();
            let _previous_host = arguments.insert("host".to_owned(), JsonValue::String(host));
            let _previous_extra = arguments.insert("extra".to_owned(), extra);
            let mut call_params = Map::new();
            let _previous_name = call_params.insert("name".to_owned(), JsonValue::String(tool.clone()));
            let _previous_arguments =
                call_params.insert("arguments".to_owned(), JsonValue::Object(arguments));
            let params_value = JsonValue::Object(call_params);
            let response = enforce_tool_policy(
                &policy,
                "alice",
                "viewer",
                &params_value,
                &DenyLogFields::default(),
            );
            prop_assert!(
                response.is_some(),
                "denied tool {:?} must stay denied",
                tool
            );
        }
    }
}
