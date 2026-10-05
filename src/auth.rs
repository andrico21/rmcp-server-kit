//! Authentication middleware for MCP servers.
//!
//! Supports multiple authentication methods tried in priority order:
//! 1. mTLS client certificate (if configured and peer cert present)
//! 2. Bearer token (API key) with Argon2id hash verification
//!
//! Includes per-source-IP rate limiting on authentication attempts.

extern crate alloc;

use alloc::{collections::VecDeque, sync::Arc};
use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    net::{IpAddr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{LazyLock, Mutex, PoisonError},
};

use arc_swap::ArcSwap;
use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Extensions, HeaderMap, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
#[cfg(not(feature = "oauth"))]
use serde::de::IgnoredAny;
use serde::{Deserialize, de::Error as SerdeDeError};
use tokio::task::spawn_blocking;
use tracing::field;
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate};

#[cfg(feature = "metrics")]
use crate::metrics::record_rate_limit_deny;
#[cfg(feature = "oauth")]
use crate::oauth::{JwksCache, JwtValidationFailure, OAuthConfig, looks_like_jwt};
use crate::{
    bounded_limiter::{BoundedKeyedLimiter, BoundedLimiterDeny, KeyEvictionPolicy},
    error::RmcpServerKitError,
    rbac::{RbacPolicy, redact_with_salt},
    transport::{
        LogContextConfig, MAX_LOGGED_HEADER_CHARS, RateLimitKey, limiter_client_ip,
        limiter_client_key, mcp_hints_for_log, peer_ip_for_log, request_id_for_log,
        sanitize_for_log,
    },
};

/// Identity of an authenticated caller.
///
/// The [`Debug`] impl is **manually written** to redact the raw bearer token
/// and the JWT `sub` claim. This prevents accidental disclosure if an
/// `AuthIdentity` is ever logged via `tracing::debug!(?identity, …)` or
/// `format!("{identity:?}")`. Only `name`, `role`, and `method` are printed
/// in the clear; `raw_token` and `sub` are rendered as `<redacted>` /
/// `<present>` / `<none>` markers.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[derive(Clone)]
#[non_exhaustive]
pub struct AuthIdentity {
    /// Human-readable identity name (e.g. API key label or cert CN).
    pub name: String,
    /// RBAC role associated with this identity.
    pub role: String,
    /// Which authentication mechanism produced this identity.
    pub method: AuthMethod,
    /// Raw bearer token from the `Authorization` header, wrapped in
    /// [`SecretString`] so it is never accidentally logged or serialized.
    /// Present for OAuth JWT; `None` for mTLS and API-key auth.
    /// Tool handlers use this for downstream token passthrough via
    /// [`crate::rbac::current_token`].
    pub raw_token: Option<SecretString>,
    /// JWT `sub` claim (stable user identifier, e.g. Keycloak UUID).
    /// Used for token store keying. `None` for non-JWT auth.
    pub sub: Option<String>,
}

impl Debug for AuthIdentity {
    /// Redacts `raw_token` and `sub` to prevent secret leakage via
    /// `format!("{:?}")` or `tracing::debug!(?identity)`.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AuthIdentity")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("method", &self.method)
            .field(
                "raw_token",
                &if self.raw_token.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .field(
                "sub",
                &if self.sub.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

/// How the caller authenticated.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// Bearer API key (Argon2id-hashed, configured statically).
    BearerToken,
    /// Mutual TLS client certificate.
    MtlsCertificate,
    /// OAuth 2.1 JWT bearer token (validated via JWKS).
    OAuthJwt,
}

/// Classification of an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailureClass {
    /// No credential was presented.
    MissingCredential,
    /// A credential was presented but was malformed or wrong.
    InvalidCredential,
    /// A credential was presented but had expired.
    ExpiredCredential,
    /// Source IP exceeded the post-failure backoff limit.
    RateLimited,
    /// Source IP exceeded the pre-auth abuse gate (rejected before any
    /// password-hash work - see [`AuthState::pre_auth_limiter`]).
    PreAuthGate,
}

/// Reason an authentic credential was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectionReason {
    /// The credential was past its expiry.
    Expired,
    /// The JWT audience claim did not match configuration.
    #[cfg_attr(
        not(feature = "oauth"),
        expect(dead_code, reason = "constructed only by OAuth JWT validation")
    )]
    Audience,
    /// The JWT role claim was missing or rejected.
    #[cfg_attr(
        not(feature = "oauth"),
        expect(dead_code, reason = "constructed only by OAuth JWT validation")
    )]
    Role,
    /// The JWT subject claim was missing or rejected.
    #[cfg_attr(
        not(feature = "oauth"),
        expect(dead_code, reason = "constructed only by OAuth JWT validation")
    )]
    Subject,
}

impl RejectionReason {
    /// Return the `snake_case` wire string for this rejection reason.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Audience => "audience",
            Self::Role => "role",
            Self::Subject => "subject",
        }
    }
}

/// Authenticated credential owner and rejection reason for opt-in failure logs.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/auth.rs::CredentialOwner fields are constructed by src/oauth.rs"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialOwner {
    /// The API-key or JWT owner name (a principal identity).
    pub(crate) name: String,
    /// Why the owner's credential was rejected.
    pub(crate) reason: RejectionReason,
}

/// Internal outcome of an authentication attempt: failure class plus owner.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthRejection {
    /// How the attempt failed.
    failure_class: AuthFailureClass,
    /// The credential owner, when known and owner logging is enabled.
    owner: Option<CredentialOwner>,
}

/// API-key verification result from the fixed-work slot scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApiKeyVerdict {
    /// A slot matched and the key is active.
    Active {
        /// Principal identity of the matched key.
        name: String,
        /// RBAC role of the matched key.
        role: String,
    },
    /// A slot matched but the key has expired.
    Expired {
        /// Principal identity of the matched key.
        name: String,
    },
    /// No slot matched.
    NoMatch,
}

impl AuthFailureClass {
    /// Return the `snake_case` wire string for this failure class.
    const fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::ExpiredCredential => "expired_credential",
            Self::RateLimited => "rate_limited",
            Self::PreAuthGate => "pre_auth_gate",
        }
    }

    /// Return the RFC 6750 `(error, error_description)` pair for this class.
    const fn bearer_error(self) -> (&'static str, &'static str) {
        match self {
            Self::MissingCredential => (
                "invalid_request",
                "missing bearer token or mTLS client certificate",
            ),
            Self::InvalidCredential => ("invalid_token", "token is invalid"),
            Self::ExpiredCredential => ("invalid_token", "token is expired"),
            Self::RateLimited => ("invalid_request", "too many failed authentication attempts"),
            Self::PreAuthGate => (
                "invalid_request",
                "too many unauthenticated requests from this source",
            ),
        }
    }

    /// Return the plain-text HTTP response body for this class.
    const fn response_body(self) -> &'static str {
        match self {
            Self::MissingCredential => "unauthorized: missing credential",
            Self::InvalidCredential => "unauthorized: invalid credential",
            Self::ExpiredCredential => "unauthorized: expired credential",
            Self::RateLimited => "rate limited",
            Self::PreAuthGate => "rate limited (pre-auth)",
        }
    }
}

/// Snapshot of authentication success/failure counters.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct AuthCountersSnapshot {
    /// Successful mTLS authentications.
    pub success_mtls: u64,
    /// Successful bearer-token authentications.
    pub success_bearer: u64,
    /// Successful OAuth JWT authentications.
    pub success_oauth_jwt: u64,
    /// Failures because no credential was presented.
    pub failure_missing_credential: u64,
    /// Failures because the credential was malformed or wrong.
    pub failure_invalid_credential: u64,
    /// Failures because the OAuth JWT or API key had expired.
    pub failure_expired_credential: u64,
    /// Failures because the source IP was rate-limited (post-failure backoff).
    pub failure_rate_limited: u64,
    /// Failures because the source IP exceeded the pre-auth abuse gate.
    /// These never reach the password-hash verification path.
    pub failure_pre_auth_gate: u64,
}

/// Internal atomic counters backing [`AuthCountersSnapshot`].
#[derive(Debug, Default)]
pub(crate) struct AuthCounters {
    /// Count of successful mTLS authentications.
    success_mtls: AtomicU64,
    /// Count of successful bearer-token authentications.
    success_bearer: AtomicU64,
    /// Count of successful OAuth JWT authentications.
    success_oauth_jwt: AtomicU64,
    /// Count of failures where no credential was presented.
    failure_missing_credential: AtomicU64,
    /// Count of failures from a malformed or wrong credential.
    failure_invalid_credential: AtomicU64,
    /// Count of failures from an expired credential.
    failure_expired_credential: AtomicU64,
    /// Count of failures rejected by the post-failure rate limiter.
    failure_rate_limited: AtomicU64,
    /// Count of failures rejected by the pre-auth abuse gate.
    failure_pre_auth_gate: AtomicU64,
}

impl AuthCounters {
    /// Record one successful authentication for the given method.
    fn record_success(&self, method: AuthMethod) {
        match method {
            AuthMethod::MtlsCertificate => {
                let _previous = self.success_mtls.fetch_add(1, Ordering::Relaxed);
            }
            AuthMethod::BearerToken => {
                let _previous = self.success_bearer.fetch_add(1, Ordering::Relaxed);
            }
            AuthMethod::OAuthJwt => {
                let _previous = self.success_oauth_jwt.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record one failed authentication for the given failure class.
    fn record_failure(&self, class: AuthFailureClass) {
        match class {
            AuthFailureClass::MissingCredential => {
                let _previous = self
                    .failure_missing_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::InvalidCredential => {
                let _previous = self
                    .failure_invalid_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::ExpiredCredential => {
                let _previous = self
                    .failure_expired_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::RateLimited => {
                let _previous = self.failure_rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::PreAuthGate => {
                let _previous = self.failure_pre_auth_gate.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot the current counter values.
    fn snapshot(&self) -> AuthCountersSnapshot {
        AuthCountersSnapshot {
            success_mtls: self.success_mtls.load(Ordering::Relaxed),
            success_bearer: self.success_bearer.load(Ordering::Relaxed),
            success_oauth_jwt: self.success_oauth_jwt.load(Ordering::Relaxed),
            failure_missing_credential: self.failure_missing_credential.load(Ordering::Relaxed),
            failure_invalid_credential: self.failure_invalid_credential.load(Ordering::Relaxed),
            failure_expired_credential: self.failure_expired_credential.load(Ordering::Relaxed),
            failure_rate_limited: self.failure_rate_limited.load(Ordering::Relaxed),
            failure_pre_auth_gate: self.failure_pre_auth_gate.load(Ordering::Relaxed),
        }
    }
}

/// RFC 3339 timestamp, parsed at deserialization time.
///
/// Use this for any public field that needs to carry an RFC 3339 timestamp from
/// TOML/JSON config or builder APIs. Construction is fallible (`parse`); once
/// constructed the value is guaranteed to be a real RFC 3339 timestamp with a
/// known offset, so downstream code does not need to handle parse errors.
///
/// Wraps [`chrono::DateTime<chrono::FixedOffset>`]; the underlying value is
/// available via [`Self::as_datetime`] or [`Self::into_inner`]. `Serialize`
/// emits the canonical RFC 3339 form via [`chrono::DateTime::to_rfc3339`], so
/// the on-the-wire format for `ApiKeySummary` (admin endpoints) is unchanged.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct RfcTimestamp(chrono::DateTime<chrono::FixedOffset>);

impl RfcTimestamp {
    /// Parse an RFC 3339 timestamp.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`chrono::ParseError`] when `value` is not a valid
    /// RFC 3339 timestamp (e.g. missing the `T` separator, missing the offset
    /// suffix, or out-of-range fields).
    #[inline]
    pub fn parse(value: &str) -> Result<Self, chrono::ParseError> {
        chrono::DateTime::parse_from_rfc3339(value).map(Self)
    }

    /// Borrow the underlying [`chrono::DateTime`].
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn as_datetime(&self) -> &chrono::DateTime<chrono::FixedOffset> {
        &self.0
    }

    /// Consume the wrapper and return the underlying [`chrono::DateTime`].
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> chrono::DateTime<chrono::FixedOffset> {
        self.0
    }
}

impl Display for RfcTimestamp {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Canonical RFC 3339 form; matches the deserialization input contract.
        write!(f, "{}", self.0.to_rfc3339())
    }
}

impl Debug for RfcTimestamp {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Render as the canonical RFC 3339 string (not chrono's internal
        // debug form) so existing `ApiKeyEntry` Debug-redaction tests --
        // which look for the literal `"2030-01-01T00:00:00Z"` form in the
        // formatted output -- continue to hold without bespoke handling.
        write!(f, "{}", self.0.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for RfcTimestamp {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Validate at deserialization time: a malformed `expires_at` in
        // TOML or JSON aborts config load with a clear serde error rather
        // than silently producing a key that fails open at runtime.
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(SerdeDeError::custom)
    }
}

impl serde::Serialize for RfcTimestamp {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_rfc3339())
    }
}

impl From<chrono::DateTime<chrono::FixedOffset>> for RfcTimestamp {
    #[inline]
    fn from(value: chrono::DateTime<chrono::FixedOffset>) -> Self {
        Self(value)
    }
}

/// A single API key entry (stored as Argon2id hash in config).
///
/// The [`Debug`] impl is **manually written** to redact the Argon2id hash.
/// Although the hash is not directly reversible, treating it as a secret
/// prevents offline brute-force attempts from leaked logs and matches the
/// defense-in-depth posture used for [`AuthIdentity`].
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ApiKeyEntry {
    /// Session/task-binding **principal identity** for this key (and the
    /// label shown in logs and audit records).
    ///
    /// Not a mere display string: the MCP session-binding and task-binding
    /// fingerprints derive their per-principal namespace from this name
    /// alone, so two entries sharing a `name` are one principal. Config
    /// validation therefore rejects same-named entries that declare
    /// different [`role`](Self::role)s, while permitting same-named,
    /// same-role entries (credential rotation).
    pub name: String,
    /// Argon2id hash of the token (PHC string format).
    pub hash: String,
    /// RBAC role granted when this key authenticates successfully.
    pub role: String,
    /// Optional expiry, parsed from an RFC 3339 string at deserialization
    /// time. Construction from a raw string is fallible (see
    /// [`RfcTimestamp::parse`] and [`ApiKeyEntry::try_with_expiry`]),
    /// which guarantees `verify_bearer_token` never sees a malformed value.
    pub expires_at: Option<RfcTimestamp>,
}

impl Debug for ApiKeyEntry {
    /// Redacts the Argon2id `hash` to keep it out of logs, panic backtraces,
    /// and admin-endpoint responses that might `format!("{:?}", …)` an entry.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ApiKeyEntry")
            .field("name", &self.name)
            .field("hash", &"<redacted>")
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl ApiKeyEntry {
    /// Create a new API key entry (no expiry).
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn new(name: impl Into<String>, hash: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hash: hash.into(),
            role: role.into(),
            expires_at: None,
        }
    }

    /// Set an RFC 3339 expiry on this key.
    ///
    /// Takes an already-parsed [`RfcTimestamp`]; for ergonomic construction
    /// from a raw string see [`Self::try_with_expiry`].
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_expiry(mut self, expires_at: RfcTimestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set an RFC 3339 expiry on this key from a raw string.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`chrono::ParseError`] when `expires_at` is
    /// not a valid RFC 3339 timestamp. This is the fallible counterpart to
    /// [`Self::with_expiry`].
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn try_with_expiry(
        mut self,
        expires_at: impl AsRef<str>,
    ) -> Result<Self, chrono::ParseError> {
        self.expires_at = Some(RfcTimestamp::parse(expires_at.as_ref())?);
        Ok(self)
    }
}

/// mTLS client certificate authentication configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mTLS CRL behavior is intentionally configured as independent booleans"
)]
#[non_exhaustive]
pub struct MtlsConfig {
    /// Path to CA certificate(s) for verifying client certs (PEM format).
    pub ca_cert_path: PathBuf,
    /// If true, clients MUST present a valid certificate.
    /// If false, client certs are optional (verified if presented).
    #[serde(default)]
    pub required: bool,
    /// Default RBAC role for mTLS-authenticated clients.
    /// The client cert CN becomes the identity name.
    #[serde(default = "default_mtls_role")]
    pub default_role: String,
    /// Enable CRL-based certificate revocation checks using CDP URLs from the
    /// configured CA chain and connecting client certificates.
    #[serde(default = "default_true")]
    pub crl_enabled: bool,
    /// Optional fixed refresh interval for known CRLs. When omitted, refresh
    /// cadence is derived from `nextUpdate` and clamped internally.
    #[serde(default, with = "humantime_serde::option")]
    pub crl_refresh_interval: Option<Duration>,
    /// Timeout for individual CRL fetches.
    #[serde(default = "default_crl_fetch_timeout", with = "humantime_serde")]
    pub crl_fetch_timeout: Duration,
    /// Retry-retention window: how long a CRL whose refresh keeps failing is
    /// retained in the cache so the background refresher can keep retrying it,
    /// measured past the CRL's `nextUpdate`.
    ///
    /// This does **not** permit use of an expired CRL. When
    /// `crl_enforce_expiration` is set (the default), webpki rejects any CRL
    /// past its `nextUpdate` during validation; this window only bounds how
    /// long a persistently-failing entry is kept for retry before the verifier
    /// gives up and evicts it (at which point `crl_deny_on_unavailable` governs
    /// the handshake outcome).
    ///
    /// The preferred config key is `crl_retry_retention`; `crl_stale_grace` is
    /// accepted as a deprecated alias for backward compatibility.
    #[serde(
        default = "default_crl_stale_grace",
        alias = "crl_retry_retention",
        with = "humantime_serde"
    )]
    pub crl_stale_grace: Duration,
    /// When true, missing or unavailable CRLs cause revocation checks to fail
    /// closed.
    ///
    /// Defaults to `true`. RFC 5280 §6.3 treats a certificate whose
    /// revocation status cannot be determined as unverified, so a client
    /// certificate advertising CRL distribution points is rejected when
    /// *every* relevant CDP is uncached and unfetchable. Denial requires all
    /// relevant CDPs to be unavailable, not merely one -- otherwise an
    /// attacker who blocks a single mirror could deny service.
    ///
    /// Set to `false` to restore the pre-3.8 fail-open behaviour, in which an
    /// unreachable CRL lets the handshake proceed. That is strongly
    /// discouraged: a revoked certificate is then accepted whenever its CRL
    /// is unreachable, which is precisely the condition an attacker holding a
    /// revoked certificate can induce.
    #[serde(default = "default_true")]
    pub crl_deny_on_unavailable: bool,
    /// When true, apply revocation checks only to the end-entity certificate.
    #[serde(default)]
    pub crl_end_entity_only: bool,
    /// Allow HTTP CRL distribution-point URLs in addition to HTTPS.
    ///
    /// Defaults to `true` because RFC 5280 §4.2.1.13 designates HTTP (and
    /// LDAP) as the canonical transport for CRL distribution points.
    /// SSRF defense for HTTP CDPs is provided by the IP-allowlist guard
    /// (private/loopback/link-local/multicast/cloud-metadata addresses are
    /// always rejected), redirect=none, body-size cap, and per-host
    /// concurrency limit -- not by forcing HTTPS.
    #[serde(default = "default_true")]
    pub crl_allow_http: bool,
    /// Enforce CRL expiration during certificate validation.
    #[serde(default = "default_true")]
    pub crl_enforce_expiration: bool,
    /// Maximum concurrent CRL fetches across all hosts. Defense in depth
    /// against SSRF amplification: even if many CDPs are discovered, no
    /// more than this many fetches run in parallel. Per-host concurrency
    /// is independently capped at 1 regardless of this value.
    /// Default: `4`.
    #[serde(default = "default_crl_max_concurrent_fetches")]
    pub crl_max_concurrent_fetches: usize,
    /// Hard cap on each CRL response body in bytes. Fetches exceeding this
    /// are aborted mid-stream to bound memory and prevent gzip-bomb-style
    /// amplification. Default: 5 MiB (`5 * 1024 * 1024`).
    #[serde(default = "default_crl_max_response_bytes")]
    pub crl_max_response_bytes: u64,
    /// CDP discovery rate limit, in URLs per minute. Throttles how many
    /// *new* CDP URLs the verifier may admit into the fetch pipeline,
    /// bounding asymmetric `DoS` amplification when attacker-controlled
    /// certificates carry large CDP lists.
    ///
    /// Applied **per source peer IP** for attributed TLS handshakes: the
    /// value is each peer's own per-minute quota, so one peer draining its
    /// budget can no longer fail-closed deny a concurrent legitimate peer
    /// presenting a not-yet-cached CDP URL. Submissions with no attributed
    /// handshake peer (e.g. a `DynamicClientCertVerifier` built outside this
    /// crate's transport) fall back to a single process-global bucket of the
    /// same rate. The key is the direct peer IP, so behind a TCP load
    /// balancer this keys on the balancer, and per-IP keying does not by
    /// itself defeat a distributed attacker (each sprayed IP still pays a
    /// full TLS handshake). Note: the **bearer pre-auth limiter** that gates
    /// API-key / OAuth `Authorization` headers is separately per-IP - see
    /// [`RateLimitConfig::pre_auth_max_per_minute`] and the keyed
    /// governor built by `build_pre_auth_limiter`. URLs that lose the
    /// rate-limiter race are *not* marked as seen, so subsequent
    /// handshakes observing the same URL can retry admission.
    /// Default: `60`.
    #[serde(default = "default_crl_discovery_rate_per_min")]
    pub crl_discovery_rate_per_min: u32,
    /// Maximum number of distinct hosts that may hold a CRL fetch
    /// semaphore at any time. At the cap, idle entries (no in-flight
    /// fetch) are evicted on demand so new hosts keep working; only when
    /// every entry has a concurrent in-flight fetch does the request
    /// return [`RmcpServerKitError::Config`] containing the literal substring
    /// `"crl_host_semaphore_cap_exceeded"`. Bounds memory growth from
    /// attacker-controlled CDP URLs pointing at unique hostnames.
    /// Default: 1024.
    #[serde(default = "default_crl_max_host_semaphores")]
    pub crl_max_host_semaphores: usize,
    /// Maximum number of distinct URLs tracked in the "seen" set.
    /// Beyond this, additional discovered URLs are silently dropped
    /// with a rate-limited warn! log; no error surfaces. Default: 4096.
    #[serde(default = "default_crl_max_seen_urls")]
    pub crl_max_seen_urls: usize,
    /// Maximum number of cached CRL entries. Beyond this, new
    /// successful fetches are silently dropped with a rate-limited
    /// warn! log (newest-rejected, not LRU-evicted). Default: 1024.
    #[serde(default = "default_crl_max_cache_entries")]
    pub crl_max_cache_entries: usize,
}

/// Serde default for [`MtlsConfig::default_role`].
fn default_mtls_role() -> String {
    "viewer".into()
}

/// Serde default for the `true` boolean flags on [`MtlsConfig`].
const fn default_true() -> bool {
    true
}

/// Serde default for [`MtlsConfig::crl_fetch_timeout`].
const fn default_crl_fetch_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Serde default for [`MtlsConfig::crl_stale_grace`].
const fn default_crl_stale_grace() -> Duration {
    Duration::from_hours(24)
}

/// Serde default for [`MtlsConfig::crl_max_concurrent_fetches`].
const fn default_crl_max_concurrent_fetches() -> usize {
    4
}

/// Serde default for [`MtlsConfig::crl_max_response_bytes`].
const fn default_crl_max_response_bytes() -> u64 {
    5 * 1024 * 1024
}

/// Serde default for [`MtlsConfig::crl_discovery_rate_per_min`].
const fn default_crl_discovery_rate_per_min() -> u32 {
    60
}

/// Serde default for [`MtlsConfig::crl_max_host_semaphores`].
const fn default_crl_max_host_semaphores() -> usize {
    1024
}

/// Serde default for [`MtlsConfig::crl_max_seen_urls`].
const fn default_crl_max_seen_urls() -> usize {
    4096
}

/// Serde default for [`MtlsConfig::crl_max_cache_entries`].
const fn default_crl_max_cache_entries() -> usize {
    1024
}

/// Rate limiting configuration for authentication attempts.
///
/// rmcp-server-kit uses two independent per-IP token-bucket limiters for auth:
///
/// 1. **Pre-auth abuse gate** ([`Self::pre_auth_max_per_minute`]): consulted
///    *before* any password-hash work. Throttles unauthenticated traffic from
///    a single source IP so an attacker cannot pin the CPU on Argon2id by
///    spraying invalid bearer tokens. Sized generously (default = 10× the
///    post-failure quota) so legitimate clients are unaffected. mTLS-
///    authenticated connections bypass this gate entirely (the TLS handshake
///    already performed expensive crypto with a verified peer).
/// 2. **Post-failure backoff** ([`Self::max_attempts_per_minute`]): consulted
///    *after* an authentication attempt fails. Provides explicit backpressure
///    on bad credentials.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RateLimitConfig {
    /// Maximum failed authentication attempts per source IP per minute.
    /// Successful authentications do not consume this budget.
    #[serde(default = "default_max_attempts")]
    pub max_attempts_per_minute: u32,
    /// Maximum *unauthenticated* requests per source IP per minute admitted
    /// to the password-hash verification path. When `None`, defaults to
    /// `max_attempts_per_minute * 10` at limiter-construction time.
    ///
    /// Set higher than [`Self::max_attempts_per_minute`] so honest clients
    /// retrying with the wrong key never trip this gate; its purpose is only
    /// to bound CPU usage under spray attacks.
    #[serde(default)]
    pub pre_auth_max_per_minute: Option<u32>,
    /// Hard cap on the number of distinct source IPs tracked per limiter.
    /// When reached, idle entries are pruned first; if still full, the
    /// oldest (LRU) entry is evicted to make room for the new one. This
    /// bounds memory under IP-spray attacks. Default: `10_000`.
    #[serde(default = "default_max_tracked_keys")]
    pub max_tracked_keys: usize,
    /// Per-IP entries idle for longer than this are eligible for
    /// opportunistic pruning. Default: 15 minutes.
    #[serde(default = "default_idle_eviction", with = "humantime_serde")]
    pub idle_eviction: Duration,
    /// Burst capacity for the post-failure limiter: the maximum number
    /// of failed attempts admitted back-to-back before the sustained
    /// `max_attempts_per_minute` rate applies. `None` (default) keeps
    /// governor's default of burst = rate. Must be greater than zero
    /// when set. May be smaller than the rate (smoothing) or larger
    /// (spike tolerance).
    #[serde(default)]
    pub burst: Option<u32>,
    /// Burst capacity for the pre-auth abuse gate. `None` (default)
    /// keeps burst = the gate's resolved rate. Legal regardless of
    /// whether [`Self::pre_auth_max_per_minute`] is set - the gate's
    /// base rate always resolves (`max_attempts_per_minute * 10` when
    /// unset). Must be greater than zero when set.
    #[serde(default)]
    pub pre_auth_burst: Option<u32>,
    /// Full-table policy when a rate limiter sees a new source IP after
    /// reaching [`Self::max_tracked_keys`]. Default: [`KeyEvictionPolicy::EvictLru`].
    #[serde(default)]
    pub key_eviction_policy: KeyEvictionPolicy,
}

impl Default for RateLimitConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_attempts_per_minute: default_max_attempts(),
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        }
    }
}

impl RateLimitConfig {
    /// Create a rate limit config with the given max failed attempts per minute.
    /// Pre-auth gate defaults to `10x` this value at limiter-construction time.
    /// Memory-bound defaults are `10_000` tracked keys with 15-minute idle eviction.
    #[must_use]
    #[inline]
    pub fn new(max_attempts_per_minute: u32) -> Self {
        Self {
            max_attempts_per_minute,
            ..Self::default()
        }
    }

    /// Override the pre-auth abuse-gate quota (per source IP per minute).
    /// When unset, defaults to `max_attempts_per_minute * 10`.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_pre_auth_max_per_minute(mut self, quota: u32) -> Self {
        self.pre_auth_max_per_minute = Some(quota);
        self
    }

    /// Override the per-limiter cap on tracked source-IP keys (default `10_000`).
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_max_tracked_keys(mut self, max: usize) -> Self {
        self.max_tracked_keys = max;
        self
    }

    /// Override the idle-eviction window (default 15 minutes).
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_idle_eviction(mut self, idle: Duration) -> Self {
        self.idle_eviction = idle;
        self
    }

    /// Set the burst capacity for the post-failure limiter. Must be
    /// greater than zero (validated at server-config validation time).
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set the burst capacity for the pre-auth abuse gate. Must be
    /// greater than zero (validated at server-config validation time).
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_pre_auth_burst(mut self, burst: u32) -> Self {
        self.pre_auth_burst = Some(burst);
        self
    }

    /// Set the tracked-key full-table policy for auth limiters.
    #[must_use]
    #[inline]
    pub const fn with_key_eviction_policy(mut self, policy: KeyEvictionPolicy) -> Self {
        self.key_eviction_policy = policy;
        self
    }
}

/// Serde default for [`RateLimitConfig::max_attempts_per_minute`].
const fn default_max_attempts() -> u32 {
    30
}

/// Serde default for [`RateLimitConfig::max_tracked_keys`].
const fn default_max_tracked_keys() -> usize {
    10_000
}

/// Serde default for [`RateLimitConfig::idle_eviction`].
const fn default_idle_eviction() -> Duration {
    Duration::from_mins(15)
}

/// Authentication configuration.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[cfg_attr(
    not(feature = "oauth"),
    expect(
        clippy::partial_pub_fields,
        reason = "public API frozen until the next major release"
    ),
    expect(
        clippy::field_scoped_visibility_modifiers,
        reason = "deliberate: src/auth.rs::AuthConfig oauth placeholder stays crate-private"
    )
)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AuthConfig {
    /// Master switch - when false, all requests are allowed through.
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token API keys.
    #[serde(default)]
    pub api_keys: Vec<ApiKeyEntry>,
    /// mTLS client certificate authentication.
    pub mtls: Option<MtlsConfig>,
    /// Rate limiting for auth attempts.
    pub rate_limit: Option<RateLimitConfig>,
    /// OAuth 2.1 JWT bearer token authentication.
    #[cfg(feature = "oauth")]
    pub oauth: Option<OAuthConfig>,
    /// Presence-only placeholder for `auth.oauth` in builds without the
    /// `oauth` cargo feature.
    ///
    /// `deny_unknown_fields` (above) would otherwise reject an `[auth.oauth]`
    /// table with an `unknown field` error naming `oauth`, which never mentions
    /// the feature flag and sends operators hunting for a typo that does not
    /// exist. Accepting the key here and rejecting it in
    /// [`AuthConfig::check_oauth_feature`] turns that into an actionable
    /// message. `IgnoredAny` records presence without retaining the value, so
    /// no OAuth secret is held in memory by a build that cannot use it.
    #[cfg(not(feature = "oauth"))]
    #[serde(default)]
    pub(crate) oauth: Option<IgnoredAny>,
}

/// Validate API-key `name`s as session/task-binding principal identities,
/// naming the first offending index.
///
/// Two rules, because the name alone is the session-binding fingerprint's
/// stable id (CWE-384):
///
/// 1. A blank name (empty or whitespace-only) is rejected: two blank names
///    collide to one fingerprint.
/// 2. A name reused with a *different* `role` is rejected: same-named keys
///    are one principal sharing one identity namespace, so two roles under
///    one name is a contradiction. Same name with the *same* role is
///    permitted -- that is credential rotation (one principal, two secrets).
///
/// Shared by [`AuthConfig::validate_api_key_names`] (startup validation) and
/// [`AuthState::try_reload_keys`] (hot-reload validation) so both surfaces
/// enforce the same rule.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] naming the first offending index:
/// either its `name` is blank, or it reuses an earlier entry's `name` with a
/// different `role`.
pub(crate) fn check_api_key_names(keys: &[ApiKeyEntry]) -> Result<(), RmcpServerKitError> {
    let mut seen: HashMap<&str, &str> = HashMap::new();
    for (index, key) in keys.iter().enumerate() {
        if key.name.trim().is_empty() {
            return Err(RmcpServerKitError::Config(format!(
                "auth.api_keys[{index}] has a blank name; each API-key name must be \
                 non-empty and not whitespace-only (it is the session-binding identity)"
            )));
        }
        // Same name + same role is credential rotation: one principal, two secrets. Allowed.
        // Same name + different role is contradictory: session/task binding keys on the name
        // alone, so the two would silently share one identity namespace.
        if let Some(prior_role) = seen.insert(key.name.as_str(), key.role.as_str())
            && prior_role != key.role.as_str()
        {
            return Err(RmcpServerKitError::Config(format!(
                "auth.api_keys[{index}] reuses the name '{}' with role '{}' while an earlier \
                 entry uses role '{prior_role}'. API-key names are the session/task-binding principal \
                 identity, so same-named keys are one principal and must share one role. \
                 Use distinct names for distinct principals.",
                key.name, key.role
            )));
        }
    }
    Ok(())
}

impl AuthConfig {
    /// Create an enabled auth config with the given API keys.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_keys(keys: Vec<ApiKeyEntry>) -> Self {
        Self {
            enabled: true,
            api_keys: keys,
            mtls: None,
            rate_limit: None,
            #[cfg(feature = "oauth")]
            oauth: None,
            #[cfg(not(feature = "oauth"))]
            oauth: None,
        }
    }

    /// Set rate limiting on this auth config.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[must_use]
    #[inline]
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    /// Reject an `[auth.oauth]` table in a build compiled without the `oauth`
    /// cargo feature.
    ///
    /// Fails closed on purpose. Ignoring the table would start the server with
    /// OAuth silently disabled while the operator's configuration says it is
    /// on -- for a bearer-token deployment that is an unauthenticated server.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when `auth.oauth` is present and
    /// the `oauth` feature is disabled. Always `Ok` when the feature is
    /// enabled, where the table is parsed into
    /// [`oauth::OAuthConfig`](crate::oauth::OAuthConfig) instead.
    #[cfg_attr(
        feature = "oauth",
        expect(
            clippy::missing_const_for_fn,
            reason = "public API frozen until the next major release"
        )
    )]
    #[cfg_attr(
        feature = "oauth",
        expect(
            clippy::unnecessary_wraps,
            reason = "public API frozen until the next major release"
        )
    )]
    #[cfg_attr(
        feature = "oauth",
        expect(
            clippy::unused_self,
            reason = "public API frozen until the next major release"
        )
    )]
    #[inline]
    pub fn check_oauth_feature(&self) -> Result<(), RmcpServerKitError> {
        #[cfg(not(feature = "oauth"))]
        {
            (self.oauth.is_none()).ok_or_else(|| {
                RmcpServerKitError::Config(
                    "auth.oauth is configured but this build of rmcp-server-kit was compiled \
                     without the `oauth` cargo feature; rebuild with `--features oauth` or \
                     remove the [auth.oauth] table"
                        .into(),
                )
            })?;
        }
        Ok(())
    }

    /// Validate configured API-key `name`s as session/task-binding principal
    /// identities.
    ///
    /// The key name is the session-binding fingerprint's stable id for bearer
    /// auth (CWE-384): two keys that share a fingerprint share a session
    /// namespace. This rejects a blank (empty or whitespace-only) name, and a
    /// name reused across entries with different [`role`](ApiKeyEntry::role)s
    /// (same name = one principal, so it must map to one role); same name with
    /// the same role is permitted as credential rotation. The first offending
    /// index is named so an operator can locate the entry.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] naming the first offending
    /// API-key index: either its `name` is blank, or it reuses an earlier
    /// entry's `name` with a different `role`.
    #[inline]
    pub fn validate_api_key_names(&self) -> Result<(), RmcpServerKitError> {
        check_api_key_names(&self.api_keys)
    }

    /// Produce a hash-free summary of the auth config for admin endpoints.
    #[must_use]
    #[inline]
    pub fn summary(&self) -> AuthConfigSummary {
        AuthConfigSummary {
            enabled: self.enabled,
            bearer: !self.api_keys.is_empty(),
            mtls: self.mtls.is_some(),
            #[cfg(feature = "oauth")]
            oauth: self.oauth.is_some(),
            #[cfg(not(feature = "oauth"))]
            oauth: false,
            api_keys: self
                .api_keys
                .iter()
                .map(|key| ApiKeySummary {
                    name: key.name.clone(),
                    role: key.role.clone(),
                    expires_at: key.expires_at,
                })
                .collect(),
        }
    }
}

/// Summary of a single API key suitable for admin endpoints.
///
/// Intentionally omits the Argon2id hash - only metadata is exposed.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct ApiKeySummary {
    /// Human-readable key label.
    pub name: String,
    /// RBAC role granted when this key authenticates.
    pub role: String,
    /// Optional RFC 3339 expiry timestamp. Serialized as a canonical
    /// RFC 3339 string so the admin-endpoint wire format is preserved.
    pub expires_at: Option<RfcTimestamp>,
}

/// Snapshot of the enabled authentication methods for admin endpoints.
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[derive(Debug, Clone, serde::Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "this is a flat summary of independent auth-method booleans"
)]
#[non_exhaustive]
pub struct AuthConfigSummary {
    /// Master enabled flag from config.
    pub enabled: bool,
    /// Whether API-key bearer auth is configured.
    pub bearer: bool,
    /// Whether mTLS client auth is configured.
    pub mtls: bool,
    /// Whether OAuth JWT validation is configured.
    pub oauth: bool,
    /// Current API-key list (no hashes).
    pub api_keys: Vec<ApiKeySummary>,
}

/// Keyed rate limiter type (per source IP). Memory-bounded by
/// [`RateLimitConfig::max_tracked_keys`] to defend against IP-spray `DoS`.
pub(crate) type KeyedLimiter = BoundedKeyedLimiter<RateLimitKey>;

/// Connection info for TLS connections, carrying the peer socket address
/// and (when mTLS is configured) the verified client identity extracted
/// from the peer certificate during the TLS handshake.
///
/// Defined as a local type so we can implement axum's `Connected` trait
/// for our custom `TlsListener` without orphan rule issues. The `identity`
/// field travels with the connection itself (via the wrapping IO type),
/// so there is no shared map to race against, no port-reuse aliasing, and
/// no eviction policy to maintain.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) struct TlsConnInfo {
    /// Remote peer socket address.
    pub addr: SocketAddr,
    /// Verified mTLS client identity, if a client certificate was presented
    /// and successfully extracted during the TLS handshake.
    pub identity: Option<AuthIdentity>,
}

impl TlsConnInfo {
    /// Construct a new [`TlsConnInfo`].
    #[must_use]
    pub(crate) const fn new(addr: SocketAddr, identity: Option<AuthIdentity>) -> Self {
        Self { addr, identity }
    }
}

/// Default hard cap on the number of distinct authenticated identities
/// remembered by [`SeenIdentitySet`].
///
/// Sized to comfortably exceed realistic identity churn for an MCP server
/// while bounding worst-case memory at roughly `4096 * avg_name_len`
/// (~256 KiB at 64-byte names). Honest clients will never trigger eviction;
/// hostile churn (rotating mTLS subjects or OAuth `sub` values) is bounded.
const DEFAULT_SEEN_IDENTITY_CAP: usize = 4096;

/// Bounded set tracking which authenticated identities have already been
/// logged at INFO level (subsequent auths fall back to DEBUG).
///
/// # Why bounded?
///
/// `id.name` is attacker-influenced under mTLS (SAN/CN) and OAuth (`sub`).
/// An unbounded [`std::collections::HashSet`] would grow with churn,
/// producing both a slow memory leak and unbounded log-cardinality
/// downstream (Loki/ES). The cap follows the same trade-off documented in
/// [`crate::bounded_limiter`]: when an evicted identity reappears it
/// re-fires INFO once. This is acceptable for diagnostic logging.
///
/// # Concurrency
///
/// Uses [`std::sync::Mutex`] because [`Self::insert_is_first`] is purely
/// synchronous and the critical section never `.await`s. The mutex is
/// poison-tolerant: a poisoned set is still logically consistent
/// (only writer is `insert_is_first`, which performs an atomic insert
/// + bounded eviction; no torn invariants are possible).
pub(crate) struct SeenIdentitySet {
    /// Mutex-guarded set plus eviction queue.
    inner: Mutex<SeenInner>,
}

/// Mutex-guarded state of a [`SeenIdentitySet`].
struct SeenInner {
    /// Identities currently remembered.
    set: HashSet<String>,
    /// Insertion-order FIFO used for bounded eviction. Tracking strict LRU
    /// would require touching the queue on every hit (under the mutex);
    /// FIFO is sufficient because the contract only promises "bounded
    /// memory", not "remember the most recently seen identities".
    order: VecDeque<String>,
    /// Maximum number of identities retained.
    cap: usize,
}

impl SeenIdentitySet {
    /// Construct with the default cap of [`DEFAULT_SEEN_IDENTITY_CAP`].
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_cap(DEFAULT_SEEN_IDENTITY_CAP)
    }

    /// Construct with an explicit cap. A `cap` of `0` is silently raised
    /// to `1` to keep the invariant `set.len() <= cap` non-vacuous.
    #[must_use]
    pub(crate) fn with_cap(cap: usize) -> Self {
        let resolved_cap = cap.max(1);
        Self {
            inner: Mutex::new(SeenInner {
                set: HashSet::with_capacity(resolved_cap.min(64)),
                order: VecDeque::with_capacity(resolved_cap.min(64)),
                cap: resolved_cap,
            }),
        }
    }

    /// Insert `name`. Returns `true` if this is the first time `name` was
    /// inserted (or it was previously evicted and reinserted), `false`
    /// if it was already present.
    ///
    /// When the cap is reached, the oldest inserted entry is evicted to
    /// make room. Eviction never blocks the caller.
    pub(crate) fn insert_is_first(&self, name: &str) -> bool {
        // The only writer is this method; a poisoned set remains
        // logically consistent (atomic insert + bounded eviction preserve
        // the `set.len() <= cap` invariant). Continuing past poison only
        // affects diagnostic logging granularity, not correctness or
        // security.
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        if guard.set.contains(name) {
            return false;
        }
        // Cap enforcement: evict-then-insert keeps the invariant
        // `set.len() <= cap` even when the cap is `1`.
        if guard.set.len() >= guard.cap
            && let Some(evicted) = guard.order.pop_front()
        {
            let _removed = guard.set.remove(&evicted);
        }
        let owned = name.to_owned();
        let _inserted = guard.set.insert(owned.clone());
        guard.order.push_back(owned);
        true
    }

    /// Test-only snapshot of the current size.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set
            .len()
    }
}

impl Default for SeenIdentitySet {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-item client context captured for `auth failed` logs.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/auth.rs::AuthLogContext fields are constructed by src/transport.rs"
)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AuthLogContext {
    /// Which request-context fields to include in failure logs.
    pub(crate) fields: LogContextConfig,
    /// Optional salt for credential-token fingerprints.
    pub(crate) fingerprint_salt: Option<Arc<SecretString>>,
}

impl AuthLogContext {
    /// Build a log context, deriving the fingerprint salt from `rbac` when
    /// credential fingerprinting is enabled.
    pub(crate) fn new(fields: &LogContextConfig, rbac: &RbacPolicy) -> Self {
        Self {
            fields: fields.clone(),
            fingerprint_salt: fields.credential_fingerprint.then(|| rbac.redaction_salt()),
        }
    }
}

/// Shared state for the auth middleware.
///
/// `api_keys` uses [`ArcSwap`] so the SIGHUP handler can atomically
/// swap in a new key list without blocking in-flight requests.
#[non_exhaustive]
pub(crate) struct AuthState {
    /// Active set of API keys (hot-swappable).
    pub api_keys: ArcSwap<Vec<ApiKeyEntry>>,
    /// Optional per-IP post-failure rate limiter (consulted *after* auth fails).
    pub rate_limiter: Option<Arc<KeyedLimiter>>,
    /// Optional per-IP pre-auth abuse gate (consulted *before* password-hash work).
    /// mTLS-authenticated connections bypass this gate.
    pub pre_auth_limiter: Option<Arc<KeyedLimiter>>,
    #[cfg(feature = "oauth")]
    /// Optional JWKS cache for OAuth JWT validation.
    pub jwks_cache: Option<Arc<JwksCache>>,
    /// Tracks identity names that have already been logged at INFO level.
    /// Subsequent auths for the same identity are logged at DEBUG.
    /// Bounded to prevent attacker-driven memory growth via churned
    /// mTLS subjects or OAuth `sub` claims (see [`SeenIdentitySet`]).
    pub seen_identities: SeenIdentitySet,
    /// Lightweight in-memory auth success/failure counters for diagnostics.
    pub counters: AuthCounters,
    /// Absolute URL of this server's RFC 9728 Protected Resource Metadata,
    /// advertised in the `WWW-Authenticate` challenge.
    ///
    /// RFC 9728 5.1 defines `resource_metadata` as a URL; emitting an
    /// absolute one lets a client resolve it without knowing the origin it
    /// was challenged from. `None` falls back to the well-known path, which
    /// stays correct for same-origin clients.
    pub resource_metadata_url: Option<String>,
    /// Per-item client context for `auth failed` logs; startup-only.
    pub log_context: AuthLogContext,
}

impl AuthState {
    /// Validate and atomically replace the API key list.
    ///
    /// Rejects an invalid key list before installing anything (a blank name,
    /// or a name reused with a different role -- see
    /// [`AuthConfig::validate_api_key_names`]); on error the previous key list
    /// stays in place, so a failed hot reload never leaves the server serving
    /// session-binding-colliding keys.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] naming the first offending
    /// index -- either a blank `name`, or a `name` reused with a different
    /// `role` -- and leaves the current key list untouched.
    pub(crate) fn try_reload_keys(&self, keys: Vec<ApiKeyEntry>) -> Result<(), RmcpServerKitError> {
        check_api_key_names(&keys)?;
        self.reload_keys_unchecked(keys);
        Ok(())
    }

    /// Atomically replace the API key list **without validation** (lock-free,
    /// wait-free).
    ///
    /// New requests immediately see the updated keys.
    /// In-flight requests that already loaded the old list finish
    /// using it -- no torn reads.
    ///
    /// Private and unchecked on purpose: it does not reject a blank-named key
    /// (session-binding-colliding, CWE-384). The only caller is
    /// [`Self::try_reload_keys`], which validates first; all reload entry
    /// points must go through that.
    fn reload_keys_unchecked(&self, keys: Vec<ApiKeyEntry>) {
        let count = keys.len();
        self.api_keys.store(Arc::new(keys));
        tracing::info!(keys = count, "API keys reloaded");
    }

    /// Snapshot auth counters for diagnostics and tests.
    #[must_use]
    pub(crate) fn counters_snapshot(&self) -> AuthCountersSnapshot {
        self.counters.snapshot()
    }

    /// Produce the admin-endpoint list of API keys (metadata only, no hashes).
    #[must_use]
    pub(crate) fn api_key_summaries(&self) -> Vec<ApiKeySummary> {
        self.api_keys
            .load()
            .iter()
            .map(|key| ApiKeySummary {
                name: key.name.clone(),
                role: key.role.clone(),
                expires_at: key.expires_at,
            })
            .collect()
    }

    /// Log auth success: INFO on first occurrence per identity, DEBUG after.
    ///
    /// Backed by [`SeenIdentitySet`], a bounded FIFO set that caps
    /// retained identities to prevent attacker-driven memory growth.
    /// FIFO (not LRU) is intentional: this cache de-duplicates INFO logs,
    /// not security state, so per-hit eviction-order mutation is not
    /// justified. See [`SeenIdentitySet`] for the full trade-off rationale.
    fn log_auth(&self, id: &AuthIdentity, method: &str) {
        self.counters.record_success(id.method);
        let first = self.seen_identities.insert_is_first(&id.name);
        if first {
            tracing::info!(name = %id.name, role = %id.role, "{method} authenticated");
        } else {
            tracing::debug!(name = %id.name, role = %id.role, "{method} authenticated");
        }
    }
}

/// Default auth rate limit: 30 attempts per minute per source IP.
// The literal 30 is provably non-zero (const-evaluated).
const DEFAULT_AUTH_RATE: NonZeroU32 = NonZeroU32::new(30).unwrap();

/// Apply an optional burst capacity to a quota. `None` keeps governor's
/// default (burst = rate). Zero values are rejected at config-validation
/// time; the `NonZeroU32` filter here is defensive only.
fn apply_burst(quota: governor::Quota, burst: Option<u32>) -> governor::Quota {
    burst
        .and_then(NonZeroU32::new)
        .map_or(quota, |resolved_burst| quota.allow_burst(resolved_burst))
}

/// Create a post-failure rate limiter from config.
#[must_use]
pub(crate) fn build_rate_limiter(config: &RateLimitConfig) -> Arc<KeyedLimiter> {
    // Defense in depth: `serve()` and `serve_with_listener()` require a
    // `Validated<McpServerConfig>` and reject zero before startup, but
    // `auth::tests` construct limiters directly from raw `RateLimitConfig`
    // values to exercise limiter behavior without building a full server.
    let quota = governor::Quota::per_minute(
        NonZeroU32::new(config.max_attempts_per_minute).unwrap_or(DEFAULT_AUTH_RATE),
    );
    let burst_quota = apply_burst(quota, config.burst);
    // Defense in depth: Phase-1 config validation rejects `0` upstream, but
    // tests can still exercise this helper directly with raw config values.
    let max_tracked_keys = NonZeroUsize::new(config.max_tracked_keys).unwrap_or(NonZeroUsize::MIN);
    Arc::new(BoundedKeyedLimiter::new_with_policy(
        burst_quota,
        max_tracked_keys,
        config.idle_eviction,
        config.key_eviction_policy,
    ))
}

/// Create a pre-auth abuse-gate rate limiter from config.
///
/// Quota: `pre_auth_max_per_minute` if set, otherwise
/// `max_attempts_per_minute * 10` (capped at `u32::MAX`). The 10× factor
/// keeps the gate generous enough for honest retries while still bounding
/// attacker CPU on Argon2 verification.
#[must_use]
pub(crate) fn build_pre_auth_limiter(config: &RateLimitConfig) -> Arc<KeyedLimiter> {
    let resolved = config.pre_auth_max_per_minute.unwrap_or_else(|| {
        config
            .max_attempts_per_minute
            .saturating_mul(PRE_AUTH_DEFAULT_MULTIPLIER)
    });
    let quota =
        governor::Quota::per_minute(NonZeroU32::new(resolved).unwrap_or(DEFAULT_PRE_AUTH_RATE));
    let burst_quota = apply_burst(quota, config.pre_auth_burst);
    // Defense in depth: Phase-1 config validation rejects `0` upstream, but
    // tests can still exercise this helper directly with raw config values.
    let max_tracked_keys = NonZeroUsize::new(config.max_tracked_keys).unwrap_or(NonZeroUsize::MIN);
    Arc::new(BoundedKeyedLimiter::new_with_policy(
        burst_quota,
        max_tracked_keys,
        config.idle_eviction,
        config.key_eviction_policy,
    ))
}

/// Default multiplier applied to `max_attempts_per_minute` when the operator
/// does not set `pre_auth_max_per_minute` explicitly.
const PRE_AUTH_DEFAULT_MULTIPLIER: u32 = 10;

/// Default pre-auth abuse-gate rate (used only if both the configured value
/// and the multiplied fallback are zero, which `NonZeroU32::new` rejects).
// The literal 300 is provably non-zero (const-evaluated).
const DEFAULT_PRE_AUTH_RATE: NonZeroU32 = NonZeroU32::new(300).unwrap();

/// Parse an mTLS client certificate and extract an `AuthIdentity`.
///
/// Uses the first non-blank Subject CN as the identity name, else the first
/// non-blank DNS SAN. A blank (empty or whitespace-only) CN is treated as
/// absent rather than shadowing a usable SAN. Returns `None` if neither
/// yields a non-blank name that also passes the character guard. The role is
/// taken from the `MtlsConfig`.
#[must_use]
#[inline]
pub fn extract_mtls_identity(cert_der: &[u8], default_role: &str) -> Option<AuthIdentity> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    // First non-blank CN, else first non-blank DNS SAN: a blank stable id
    // collapses distinct principals to one session-binding fingerprint (CWE-384),
    // and a present-but-blank CN must not shadow a usable SAN.
    let cn = cert
        .subject()
        .iter_common_name()
        .filter_map(|attr| attr.as_str().ok())
        .find(|value| !value.trim().is_empty())
        .map(String::from);

    let name = cn.or_else(|| {
        let san = cert.subject_alternative_name().ok().flatten()?;
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "x509-parser GeneralName is a large external enum; only DNSName is meaningful here"
        )]
        let found = san.value.general_names.iter().find_map(|gn| match gn {
            GeneralName::DNSName(dns) if !dns.trim().is_empty() => Some((*dns).to_owned()),
            _ => None,
        });
        found
    });

    let Some(resolved_name) = name else {
        tracing::warn!("mTLS identity rejected: no non-blank CN or DNS SAN present");
        return None;
    };

    // Reject identities with characters unsafe for logging and RBAC matching.
    if !resolved_name
        .chars()
        .all(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '.' | '_' | '@'))
    {
        tracing::warn!(cn = %resolved_name, "mTLS identity rejected: invalid characters in CN/SAN");
        return None;
    }

    Some(AuthIdentity {
        name: resolved_name,
        role: default_role.to_owned(),
        method: AuthMethod::MtlsCertificate,
        raw_token: None,
        sub: None,
    })
}

/// Extract the bearer token from an `Authorization` header value.
///
/// Implements RFC 7235 §2.1: the auth-scheme token is **case-insensitive**.
/// `Bearer`, `bearer`, `BEARER`, and `BeArEr` all parse equivalently. Any
/// leading whitespace between the scheme and the token is trimmed (per
/// RFC 7235 the separator is one or more SP characters; we accept the
/// common single-space form plus tolerate extras).
///
/// Returns `None` if the header value:
/// - does not contain a space (no scheme/credentials boundary), or
/// - uses a scheme other than `Bearer` (case-insensitively), or
/// - carries a credential containing embedded whitespace.
///
/// # Why whitespace only, and not full `token68`
///
/// RFC 7235 §2.1 defines the credential as `token68`, which excludes
/// whitespace. Accepting an embedded SP/HTAB creates a parser differential
/// against a fronting proxy that splits on any whitespace.
///
/// Enforcing the whole `token68` character class would be a breaking
/// change: [`ApiKeyEntry::new`] accepts an arbitrary caller-supplied hash
/// and [`verify_bearer_token`] verifies the raw presented string, so
/// consumers may have hashed opaque tokens containing punctuation outside
/// `token68`. Those must keep authenticating -- do not "complete" this
/// check without a major-version note.
///
/// ASCII semantics suffice because [`http::HeaderValue::to_str`] rejects
/// every non-visible byte before this helper runs.
fn extract_bearer(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = rest.trim_start_matches(' ');
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

/// Verify a bearer token against configured API keys.
///
/// Argon2id verification is CPU-intensive, so this should be called via
/// `spawn_blocking`. Returns the matching identity if the token is valid.
///
/// # Timing-side-channel resistance
///
/// Always performs **exactly one Argon2id verification per configured key**,
/// regardless of which slot (if any) matches the presented token.
///
/// **Expired slots** with parseable hashes verify against their own real hash.
/// **Unparseable or malformed hashes** and slots encountered **after the active
/// match has already been found** verify against an internal dummy PHC hash
/// (`DUMMY_PHC_HASH`), a fixed Argon2id PHC string with the same cost
/// parameters as real hashes. This bounds the timing observable to "one Argon2
/// per configured key" regardless of which (if any) slot held the matching
/// credential, closing the first-match latency oracle (CWE-208).
///
/// Uniform timing assumes every configured key uses the same PHC (Argon2) cost
/// parameters (`m`, `t`, `p`) as the dummy hash. Those are the crate defaults
/// produced by [`generate_api_key`]; arbitrary operator-supplied hashes are not
/// rewritten or cost-normalized at load time.
///
/// `subtle::ConstantTimeEq` folds each slot's match bit into the running
/// result without comparing the token bytes in short-circuiting fashion.
///
/// The guarantee this function provides is the Argon2 count, not full
/// branchlessness: selecting `verify_against` and recording `matched_index`
/// are both ordinary data-dependent branches. They are cheap, predictable,
/// and operate on locals, so they are dwarfed by the Argon2id verification
/// that dominates every iteration -- but the timing claim stops at
/// "one verification per configured key". Do not read this as a
/// constant-time selection routine.
///
/// # Panics
///
/// Panics if the internal dummy PHC hash cannot be parsed as an Argon2id PHC string.
/// This is impossible by construction: the static is generated by
/// [`argon2::Argon2::hash_password`] which always emits a valid PHC string.
#[must_use]
#[inline]
pub fn verify_bearer_token(token: &str, keys: &[ApiKeyEntry]) -> Option<AuthIdentity> {
    match verify_bearer_token_verdict(token, keys) {
        ApiKeyVerdict::Active { name, role } => Some(AuthIdentity {
            name,
            role,
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        }),
        ApiKeyVerdict::Expired { name: _ } | ApiKeyVerdict::NoMatch => None,
    }
}

/// Fixed-work slot scan shared by [`verify_bearer_token`] and
/// [`verify_bearer_token_verdict`].
///
/// # Panics
///
/// Panics if the internal dummy PHC hash cannot be parsed as an Argon2id PHC
/// string. This is impossible by construction: [`DUMMY_PHC_HASH`] is generated
/// by [`argon2::Argon2::hash_password`], which always emits a valid PHC string.
fn verify_slots<F>(
    token: &str,
    keys: &[ApiKeyEntry],
    now: chrono::DateTime<chrono::Utc>,
    mut verify: F,
) -> ApiKeyVerdict
where
    F: FnMut(&[u8], &PasswordHash) -> bool,
{
    use subtle::ConstantTimeEq as _;

    #[expect(
        clippy::expect_used,
        reason = "DUMMY_PHC_HASH is a static LazyLock built from a fixed Argon2id PHC string by construction; PasswordHash::new on it is infallible. See DUMMY_PHC_HASH definition."
    )]
    let dummy_hash = PasswordHash::new(&DUMMY_PHC_HASH)
        .expect("DUMMY_PHC_HASH is a valid Argon2id PHC string by construction");

    let mut matched_index: usize = usize::MAX;
    let mut any_match: u8 = 0;
    let mut expired_index: usize = usize::MAX;
    let mut any_expired: u8 = 0;

    for (idx, key) in keys.iter().enumerate() {
        let expired = key.expires_at.is_some_and(|exp| exp.as_datetime() < &now);

        let real_hash = PasswordHash::new(&key.hash);
        let verify_against = match (&real_hash, expired, any_match) {
            (Ok(hash), true, _) | (Ok(hash), false, 0) => hash,
            _ => &dummy_hash,
        };

        let slot_ok = u8::from(verify(token.as_bytes(), verify_against));

        let real_match = slot_ok & u8::from(!expired) & u8::from(real_hash.is_ok());
        let first_real_match = real_match & 1_u8.wrapping_sub(any_match);
        if first_real_match.ct_eq(&1).into() {
            matched_index = idx;
        }
        any_match |= real_match;

        let expired_hit = slot_ok & u8::from(expired) & u8::from(real_hash.is_ok());
        let first_expired = expired_hit & 1_u8.wrapping_sub(any_expired);
        if first_expired.ct_eq(&1).into() {
            expired_index = idx;
        }
        any_expired |= expired_hit;
    }

    if any_match != 0
        && let Some(key) = keys.get(matched_index)
    {
        if key.name.trim().is_empty() {
            tracing::warn!("bearer token rejected: matched API key has a blank name");
            return ApiKeyVerdict::NoMatch;
        }
        return ApiKeyVerdict::Active {
            name: key.name.clone(),
            role: key.role.clone(),
        };
    }

    if any_expired != 0
        && let Some(key) = keys.get(expired_index)
    {
        if key.name.trim().is_empty() {
            tracing::warn!("bearer token rejected: matched expired API key has a blank name");
            return ApiKeyVerdict::NoMatch;
        }
        return ApiKeyVerdict::Expired {
            name: key.name.clone(),
        };
    }

    ApiKeyVerdict::NoMatch
}

/// Verify an API-key bearer token and preserve active/expired/no-match detail.
pub(crate) fn verify_bearer_token_verdict(token: &str, keys: &[ApiKeyEntry]) -> ApiKeyVerdict {
    verify_slots(token, keys, chrono::Utc::now(), |token_arg, hash| {
        Argon2::default().verify_password(token_arg, hash).is_ok()
    })
}

/// Fixed Argon2id PHC hash used as a constant-time placeholder for
/// unparseable/malformed hashes and for slots encountered after the active
/// match has already been found.
///
/// Generated once on first access using the same default Argon2 cost
/// parameters produced by [`generate_api_key`]. Uniform timing assumes
/// configured keys keep those defaults; operator-supplied hashes with different
/// PHC costs are not normalized by this crate. The plaintext
/// (`"rmcp-server-kit-dummy"`) and the fixed salt are unrelated to any
/// real credential - randomness is unnecessary because this hash is
/// only ever compared against attacker-supplied input on slots that
/// will be discarded regardless of match result. Argon2's work factor is
/// set by the PHC `m`/`t`/`p` parameters, not by the salt value, so a
/// fixed salt costs exactly what a random one would.
static DUMMY_PHC_HASH: LazyLock<String> = LazyLock::new(|| {
    #[expect(
        clippy::expect_used,
        reason = "Argon2::default() over a fixed plaintext and a fixed 16-byte salt is infallible; it fails only on invalid params or salt length, both constants here"
    )]
    Argon2::default()
        .hash_password_with_salt(b"rmcp-server-kit-dummy", &[0_u8; 16])
        .expect("Argon2 default params hash a fixed plaintext")
        .to_string()
});

/// Generate a new API key: 256-bit random token + Argon2id hash.
///
/// Returns `(plaintext_token, argon2id_hash_phc_string)`.
/// The plaintext is shown once to the user and never stored.
///
/// # Errors
///
/// Returns an error if Argon2id hashing fails (should not happen with valid
/// inputs, but we avoid panicking).
#[inline]
pub fn generate_api_key() -> Result<(String, String), RmcpServerKitError> {
    let mut token_bytes = [0_u8; 32];
    rand::fill(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    let mut salt_bytes = [0_u8; 16];
    rand::fill(&mut salt_bytes);
    let hash = Argon2::default()
        .hash_password_with_salt(token.as_bytes(), &salt_bytes)
        .map_err(|error| RmcpServerKitError::Internal(format!("argon2id hashing failed: {error}")))?
        .to_string();

    Ok((token, hash))
}

/// Build the `WWW-Authenticate: Bearer ...` challenge value, including the
/// `resource_metadata` parameter when a metadata URL is available.
fn build_www_authenticate_value(
    resource_metadata: Option<&str>,
    failure: AuthFailureClass,
) -> String {
    let (error, error_description) = failure.bearer_error();
    if let Some(url) = resource_metadata {
        return format!(
            "Bearer resource_metadata=\"{url}\", error=\"{error}\", error_description=\"{error_description}\""
        );
    }
    format!("Bearer error=\"{error}\", error_description=\"{error_description}\"")
}

/// Human-readable label for an authentication method.
const fn auth_method_label(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::MtlsCertificate => "mTLS",
        AuthMethod::BearerToken => "bearer token",
        AuthMethod::OAuthJwt => "OAuth JWT",
    }
}

/// Request-context fields captured for an `auth failed` log line.
#[derive(Debug, Default)]
struct AuthFailureFields {
    /// Resolved client IP (when enabled and available).
    client_ip: Option<IpAddr>,
    /// Direct peer IP (when enabled and available).
    peer_ip: Option<IpAddr>,
    /// Request id header value, if present.
    request_id: Option<Arc<str>>,
    /// HTTP method.
    method: Option<Method>,
    /// Request path (no query string).
    path: Option<String>,
    /// Sanitized `User-Agent` header value.
    user_agent: Option<String>,
    /// Lowercased auth scheme label (`bearer`/`basic`/`other`).
    auth_scheme: Option<&'static str>,
    /// Bearer token shape (`jwt`/`opaque`).
    token_kind: Option<&'static str>,
    /// Whether MCP session hints were present.
    mcp_session: Option<bool>,
    /// MCP protocol version header value, if any.
    mcp_protocol_version: Option<String>,
    /// Redacted credential fingerprint.
    credential_fp: Option<String>,
    /// Credential owner name (only when owner logging is enabled).
    credential_owner: Option<String>,
    /// Rejection reason for the credential owner.
    credential_rejection: Option<&'static str>,
}

/// Build the `User-Agent` value for failure logs, sanitized and truncated.
fn user_agent_for_log(headers: &HeaderMap) -> String {
    headers.get(header::USER_AGENT).map_or_else(
        || "-".to_owned(),
        |value| {
            value.to_str().map_or_else(
                |_| "<non-utf8>".to_owned(),
                |raw| sanitize_for_log(raw, MAX_LOGGED_HEADER_CHARS),
            )
        },
    )
}

/// Classify the request's `Authorization` scheme for logging.
fn auth_scheme_for_log(headers: &HeaderMap) -> &'static str {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return "none";
    };
    let Ok(raw) = value.to_str() else {
        return "other";
    };
    let scheme = raw.split_ascii_whitespace().next().unwrap_or_default();
    if scheme.eq_ignore_ascii_case("bearer") {
        "bearer"
    } else if scheme.eq_ignore_ascii_case("basic") {
        "basic"
    } else {
        "other"
    }
}

/// Classify a bearer token as `jwt` (three non-empty base64url segments) or
/// `opaque`.
fn token_kind(token: &str) -> &'static str {
    let mut parts = token.split('.');
    let Some(first) = parts.next() else {
        return "opaque";
    };
    let Some(second) = parts.next() else {
        return "opaque";
    };
    let Some(third) = parts.next() else {
        return "opaque";
    };
    if parts.next().is_some() {
        return "opaque";
    }
    let valid = [first, second, third].into_iter().all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if valid { "jwt" } else { "opaque" }
}

/// Collect the request-context fields for an `auth failed` log line.
fn auth_failure_fields(
    ctx: &AuthLogContext,
    req: &Request<Body>,
    owner: Option<&CredentialOwner>,
) -> AuthFailureFields {
    let fields = &ctx.fields;
    let headers = req.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer);
    let (mcp_session, mcp_protocol_version) = if fields.mcp_hints {
        mcp_hints_for_log(headers)
    } else {
        (false, None)
    };
    AuthFailureFields {
        client_ip: fields
            .client_ip
            .then(|| limiter_client_ip(req.extensions()))
            .flatten(),
        peer_ip: fields
            .peer_ip
            .then(|| peer_ip_for_log(req.extensions()))
            .flatten(),
        request_id: fields
            .request_id
            .then(|| request_id_for_log(req.extensions()))
            .flatten(),
        method: fields.request_line.then(|| req.method().clone()),
        path: fields.request_line.then(|| req.uri().path().to_owned()),
        user_agent: fields.user_agent.then(|| user_agent_for_log(headers)),
        auth_scheme: fields.auth_scheme.then(|| auth_scheme_for_log(headers)),
        token_kind: fields.auth_scheme.then(|| bearer.map(token_kind)).flatten(),
        mcp_session: fields.mcp_hints.then_some(mcp_session),
        mcp_protocol_version,
        credential_fp: ctx.fingerprint_salt.as_ref().and_then(|salt| {
            bearer.map(|token| redact_with_salt(salt.expose_secret().as_bytes(), token))
        }),
        credential_owner: fields
            .credential_owner
            .then_some(owner)
            .flatten()
            .map(|cred_owner| sanitize_for_log(&cred_owner.name, MAX_LOGGED_HEADER_CHARS)),
        credential_rejection: fields
            .credential_owner
            .then_some(owner.map(|rejected| rejected.reason.as_str()))
            .flatten(),
    }
}

/// Emit the `auth failed` warn log with the configured context fields.
fn log_auth_failure(
    failure_class: AuthFailureClass,
    owner: Option<&CredentialOwner>,
    ctx: &AuthLogContext,
    req: &Request<Body>,
) {
    let fields = auth_failure_fields(ctx, req, owner);
    tracing::warn!(
        failure_class = %failure_class.as_str(),
        client_ip = fields.client_ip.map(field::display),
        peer_ip = fields.peer_ip.map(field::display),
        request_id = fields.request_id.as_deref(),
        method = fields.method.as_ref().map(field::display),
        path = fields.path.as_deref().map(field::display),
        user_agent = fields.user_agent.as_deref(),
        auth_scheme = fields.auth_scheme.map(field::display),
        token_kind = fields.token_kind.map(field::display),
        mcp_session = fields.mcp_session,
        mcp_protocol_version = fields.mcp_protocol_version.as_deref(),
        credential_fp = fields.credential_fp.as_deref().map(field::display),
        credential_owner = fields.credential_owner.as_deref(),
        credential_rejection = fields.credential_rejection.map(field::display),
        "auth failed"
    );
}

/// Build the 401 response for a failed authentication, including the
/// `WWW-Authenticate` challenge and failure-class body.
fn unauthorized_response(state: &AuthState, failure_class: AuthFailureClass) -> Response {
    #[cfg(feature = "oauth")]
    let advertise_resource_metadata = state.jwks_cache.is_some();
    #[cfg(not(feature = "oauth"))]
    let advertise_resource_metadata = false;

    let resource_metadata = advertise_resource_metadata.then(|| {
        state
            .resource_metadata_url
            .as_deref()
            .unwrap_or("/.well-known/oauth-protected-resource")
    });
    let challenge = build_www_authenticate_value(resource_metadata, failure_class);
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        failure_class.response_body(),
    )
        .into_response()
}

/// Authenticate a bearer token via OAuth (when configured) then API keys.
///
/// # Errors
///
/// Returns [`AuthRejection`] describing the failure class and, when owner
/// logging is enabled, the matched credential owner, when the token is not a
/// valid active credential.
///
/// # Cancel safety
///
/// No shared-state mutation. The Argon2 verification is offloaded to
/// `spawn_blocking`; dropping its `JoinHandle` on cancellation detaches the
/// task (the hash completes off-task, harmlessly) rather than tearing partial
/// state. The OAuth branch delegates to `validate_token_detailed`, which is
/// itself cancel-safe (read-only JWKS lookup + pure claim checks).
async fn authenticate_bearer_identity(
    state: &AuthState,
    token: &str,
) -> Result<AuthIdentity, AuthRejection> {
    let mut failure_class = AuthFailureClass::MissingCredential;
    let mut owner = None;

    #[cfg(feature = "oauth")]
    if let Some(cache) = &state.jwks_cache
        && looks_like_jwt(token)
    {
        match cache
            .validate_token_detailed(token, state.log_context.fields.credential_owner)
            .await
        {
            Ok(mut id) => {
                id.raw_token = Some(SecretString::from(token.to_owned()));
                return Ok(id);
            }
            Err(rejection) => {
                failure_class = match rejection.failure {
                    JwtValidationFailure::Expired => AuthFailureClass::ExpiredCredential,
                    JwtValidationFailure::Invalid => AuthFailureClass::InvalidCredential,
                };
                owner = rejection.owner;
            }
        }
    }

    let owned_token = token.to_owned();
    let keys = state.api_keys.load_full(); // Arc clone, lock-free
    let keys_for_verify = Arc::clone(&keys);

    // Argon2id is CPU-bound - offload to blocking thread pool.
    let verdict =
        spawn_blocking(move || verify_bearer_token_verdict(&owned_token, &keys_for_verify))
            .await
            .ok();

    match verdict {
        Some(ApiKeyVerdict::Active { name, role }) => {
            return Ok(AuthIdentity {
                name,
                role,
                method: AuthMethod::BearerToken,
                raw_token: None,
                sub: None,
            });
        }
        Some(ApiKeyVerdict::Expired { name }) => {
            failure_class = AuthFailureClass::ExpiredCredential;
            owner = Some(CredentialOwner {
                name,
                reason: RejectionReason::Expired,
            });
        }
        Some(ApiKeyVerdict::NoMatch) | None => {}
    }

    if failure_class == AuthFailureClass::MissingCredential {
        failure_class = AuthFailureClass::InvalidCredential;
    }

    Err(AuthRejection {
        failure_class,
        owner,
    })
}

/// Consult the pre-auth abuse gate for the given peer.
///
/// Returns `Some(response)` if the request should be rejected (limiter
/// configured AND quota exhausted for this source IP). Returns `None`
/// otherwise (limiter absent, peer address unknown, or quota available),
/// in which case the caller should proceed with credential verification.
///
/// Side effects on rejection: increments the `pre_auth_gate` failure
/// counter and emits a warn-level log. mTLS-authenticated requests must
/// be admitted by the caller *before* invoking this helper.
fn pre_auth_gate(state: &AuthState, client_key: Option<&RateLimitKey>) -> Option<Response> {
    let limiter = state.pre_auth_limiter.as_ref()?;
    let key = client_key?;
    match limiter.check_key_detailed(key) {
        Ok(()) => None,
        Err(BoundedLimiterDeny::RateLimited(wait)) => {
            state.counters.record_failure(AuthFailureClass::PreAuthGate);
            tracing::warn!(
                rate_limit_key = %key,
                "auth rate limited by pre-auth gate (request rejected before credential verification)"
            );
            Some(
                RmcpServerKitError::RateLimitedFor {
                    message: "too many unauthenticated requests from this source".into(),
                    retry_after: wait,
                }
                .into_response(),
            )
        }
        Err(BoundedLimiterDeny::CapacityFull) => {
            tracing::warn!(
                rate_limit_key = %key,
                "auth pre-auth gate rejected unseen key because tracked-key capacity is full"
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

/// Consult the post-failure limiter and build its rejection response.
#[cfg_attr(
    not(feature = "metrics"),
    expect(
        unused_variables,
        reason = "`extensions` is read only to record the \
                  `rmcp_server_kit_rate_limited_total` metric; without the \
                  `metrics` feature there is no recording site"
    )
)]
fn post_failure_rate_limit_response(
    limiter: &KeyedLimiter,
    key: &RateLimitKey,
    extensions: &Extensions,
) -> Option<Response> {
    match limiter.check_key_detailed(key) {
        Ok(()) => None,
        Err(BoundedLimiterDeny::RateLimited(wait)) => {
            #[cfg(feature = "metrics")]
            record_rate_limit_deny(extensions, "auth_post");
            tracing::warn!(rate_limit_key = %key, "auth rate limited after repeated failures");
            Some(
                RmcpServerKitError::RateLimitedFor {
                    message: "too many failed authentication attempts".into(),
                    retry_after: wait,
                }
                .into_response(),
            )
        }
        Err(BoundedLimiterDeny::CapacityFull) => {
            tracing::warn!(
                rate_limit_key = %key,
                "auth post-failure limiter rejected unseen key because tracked-key capacity is full"
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

/// Axum middleware that enforces authentication.
///
/// Tries authentication methods in priority order:
/// 1. mTLS client certificate identity (populated by TLS acceptor)
/// 2. Bearer token from `Authorization` header
///
/// Failed authentication attempts are rate-limited per source IP.
/// Successful authentications do not consume rate limit budget.
// cancel-safe: `TimeoutLayer` may drop this future, but limiter mutations are
// deliberate attempt accounting: pre-auth prices bearer/JWT verification,
// post-failure prices failed auth, and identity extensions die with the request.
pub(crate) async fn auth_middleware(
    state: Arc<AuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // Extract the mTLS identity from ConnectInfo (TLS / mTLS:
    // ConnectInfo<TlsConnInfo> carries the verified identity directly on
    // the connection - no shared map, no port-reuse aliasing) and the
    // rate-limit key (resolved client IP when trusted-forwarder mode is
    // active, else the direct peer; see transport::limiter_client_ip).
    let tls_info = req.extensions().get::<ConnectInfo<TlsConnInfo>>().cloned();
    // Resolved only when a limiter will actually consult it, so servers
    // with no rate limiting never trip the unattributed-fallback warning.
    let client_key = (state.pre_auth_limiter.is_some() || state.rate_limiter.is_some())
        .then(|| limiter_client_key(req.extensions()));

    // 1. Try mTLS identity (extracted by the TLS acceptor during handshake
    //    and attached to the connection itself).
    //
    //    mTLS connections bypass the pre-auth abuse gate below: the TLS
    //    handshake already performed expensive crypto with a verified peer,
    //    so we trust them not to be a CPU-spray attacker.
    if let Some(id) = tls_info.and_then(|ci| ci.0.identity) {
        state.log_auth(&id, "mTLS");
        let _previous = req.extensions_mut().insert(id);
        return next.run(req).await;
    }

    // 2. Pre-auth abuse gate: rejects CPU-spray attacks BEFORE the Argon2id
    //    verification path runs. Keyed by source IP. mTLS connections (above)
    //    are exempt; this gate only protects the bearer/JWT verification path.
    if let Some(blocked) = pre_auth_gate(&state, client_key.as_ref()) {
        #[cfg(feature = "metrics")]
        record_rate_limit_deny(req.extensions(), "auth_pre");
        return blocked;
    }

    let failure_class = if let Some(value) = req.headers().get(header::AUTHORIZATION) {
        match value.to_str().ok().and_then(extract_bearer) {
            Some(token) => match authenticate_bearer_identity(&state, token).await {
                Ok(id) => {
                    state.log_auth(&id, auth_method_label(id.method));
                    let _previous = req.extensions_mut().insert(id);
                    return next.run(req).await;
                }
                Err(rejection) => (rejection.failure_class, rejection.owner),
            },
            None => (AuthFailureClass::InvalidCredential, None),
        }
    } else {
        (AuthFailureClass::MissingCredential, None)
    };

    log_auth_failure(
        failure_class.0,
        failure_class.1.as_ref(),
        &state.log_context,
        &req,
    );

    // Rate limit check (applied after auth failure only).
    // Successful authentications do not consume rate limit budget.
    if let (Some(limiter), Some(key)) = (&state.rate_limiter, client_key.as_ref())
        && let Some(resp) = post_failure_rate_limit_response(limiter, key, req.extensions())
    {
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            state.counters.record_failure(AuthFailureClass::RateLimited);
        }
        return resp;
    }

    state.counters.record_failure(failure_class.0);
    unauthorized_response(&state, failure_class.0)
}

#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
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
    use core::slice::from_ref;
    use std::io::{Result as IoResult, Write};

    use anyhow::Context as _;
    use axum::{http::HeaderValue, middleware::from_fn, routing::post};
    use tracing::subscriber::set_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    #[cfg(feature = "metrics")]
    use crate::metrics::McpMetrics;
    use crate::transport::{ClientIp, PeerAddr, RequestId};

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
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl<'log> MakeWriter<'log> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'log self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    /// A PHC string produced by **argon2 0.5.3** through the same code path as
    /// [`generate_api_key`] (16 salt bytes, `Argon2::default()`).
    ///
    /// Pinned so the argon2 0.6 upgrade cannot silently invalidate credentials
    /// that are already deployed: if this stops verifying, every stored API key
    /// stops working. Captured before the upgrade and asserted after it.
    const ARGON2_0_5_TOKEN: &str = "golden-vector-token-0p5p3";
    const ARGON2_0_5_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$BwcHBwcHBwcHBwcHBwcHBw$spS8B9AhHG1LikfhGlssVMfP8mq37+8/mXnl98ps0NU";

    /// Argon2 0 5 produced hash still verifies.
    #[test]
    fn argon2_0_5_produced_hash_still_verifies() -> anyhow::Result<()> {
        let parsed =
            PasswordHash::new(ARGON2_0_5_HASH).context("a 0.5-era PHC string must still parse")?;
        Argon2::default()
            .verify_password(ARGON2_0_5_TOKEN.as_bytes(), &parsed)
            .context("already-deployed API keys must keep verifying across the argon2 upgrade")?;
        Ok(())
    }

    /// The dummy hash burned on a miss must cost the same as a real one.
    ///
    /// Argon2 work is set by the PHC parameters, not the salt, so asserting the
    /// dummy and a freshly generated key share `argon2id`, `v=19` and identical
    /// `m`/`t`/`p` pins the constant-time property without a flaky wall-clock
    /// measurement. Forcing `DUMMY_PHC_HASH` here also surfaces a `LazyLock`
    /// panic in CI rather than at the first production auth.
    #[test]
    fn dummy_and_real_hashes_share_cost_parameters() -> anyhow::Result<()> {
        let (_token, real_hash) = generate_api_key().context("key generation must succeed")?;
        let real = PasswordHash::new(&real_hash).context("generated hash must parse")?;
        let dummy = PasswordHash::new(&DUMMY_PHC_HASH).context("dummy hash must parse")?;

        assert_eq!(dummy.algorithm, real.algorithm, "algorithm must match");
        assert_eq!(dummy.version, real.version, "PHC version must match");
        assert_eq!(
            dummy.params, real.params,
            "m/t/p must match or the dummy no longer costs what a real verification costs"
        );
        Ok(())
    }

    /// Generate and verify api key.
    #[test]
    fn generate_and_verify_api_key() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;

        // Token is 43 chars (256-bit base64url, no padding)
        assert_eq!(token.len(), 43);

        // Hash is a valid PHC string
        assert!(hash.starts_with("$argon2id$"));

        // Verification succeeds with correct token
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: None,
        }];
        let id = verify_bearer_token(&token, &keys);
        assert!(id.is_some());
        let identity = id.context("valid token must yield an identity")?;
        assert_eq!(identity.name, "test");
        assert_eq!(identity.role, "viewer");
        assert_eq!(identity.method, AuthMethod::BearerToken);
        Ok(())
    }

    /// Verify bearer token uses the matched slot role.
    #[test]
    fn verify_bearer_token_uses_the_matched_slot_role() -> anyhow::Result<()> {
        let (admin_token, admin_hash) = generate_api_key()?;
        let (viewer_token, viewer_hash) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry::new("svc", admin_hash, "admin"),
            ApiKeyEntry::new("svc", viewer_hash, "viewer"),
        ];

        let viewer = verify_bearer_token(&viewer_token, &keys)
            .context("viewer token must authenticate from its own slot")?;
        let admin = verify_bearer_token(&admin_token, &keys)
            .context("admin token must authenticate from its own slot")?;

        assert_eq!(viewer.role, "viewer");
        assert_eq!(admin.role, "admin");
        Ok(())
    }

    /// Wrong token rejected.
    #[test]
    fn wrong_token_rejected() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: None,
        }];
        assert!(verify_bearer_token("wrong-token", &keys).is_none());
        Ok(())
    }

    /// Expired key rejected.
    #[test]
    fn expired_key_rejected() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: Some(RfcTimestamp::parse("2020-01-01T00:00:00Z")?),
        }];
        assert!(verify_bearer_token(&token, &keys).is_none());
        Ok(())
    }

    /// Match in last slot still authenticates.
    #[test]
    fn match_in_last_slot_still_authenticates() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let (_other_token, other_hash) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry {
                name: "first".into(),
                hash: other_hash.clone(),
                role: "viewer".into(),
                expires_at: None,
            },
            ApiKeyEntry {
                name: "second".into(),
                hash: other_hash,
                role: "viewer".into(),
                expires_at: None,
            },
            ApiKeyEntry {
                name: "match".into(),
                hash,
                role: "ops".into(),
                expires_at: None,
            },
        ];
        let id = verify_bearer_token(&token, &keys).context("last-slot match must authenticate")?;
        assert_eq!(id.name, "match");
        assert_eq!(id.role, "ops");
        Ok(())
    }

    /// Expired slot before valid match does not short circuit.
    #[test]
    fn expired_slot_before_valid_match_does_not_short_circuit() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let (_, other_hash) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry {
                name: "expired".into(),
                hash: other_hash,
                role: "viewer".into(),
                expires_at: Some(RfcTimestamp::parse("2020-01-01T00:00:00Z")?),
            },
            ApiKeyEntry {
                name: "valid".into(),
                hash,
                role: "ops".into(),
                expires_at: None,
            },
        ];
        let id = verify_bearer_token(&token, &keys)
            .context("valid slot following an expired slot must authenticate")?;
        assert_eq!(id.name, "valid");
        Ok(())
    }

    /// Malformed hash slot does not short circuit.
    #[test]
    fn malformed_hash_slot_does_not_short_circuit() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry {
                name: "broken".into(),
                hash: "this-is-not-a-phc-string".into(),
                role: "viewer".into(),
                expires_at: None,
            },
            ApiKeyEntry {
                name: "valid".into(),
                hash,
                role: "ops".into(),
                expires_at: None,
            },
        ];
        let id = verify_bearer_token(&token, &keys)
            .context("valid slot following a malformed-hash slot must authenticate")?;
        assert_eq!(id.name, "valid");
        Ok(())
    }

    fn fixed_now() -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
        Ok(
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?
                .with_timezone(&chrono::Utc),
        )
    }

    fn slot_key(name: &str, hash: &str, expires_at: Option<&str>) -> anyhow::Result<ApiKeyEntry> {
        let mut key = ApiKeyEntry::new(name, hash, "viewer");
        if let Some(expiry) = expires_at {
            key.expires_at = Some(RfcTimestamp::parse(expiry)?);
        }
        Ok(key)
    }

    /// Slots no match verifies every slot.
    #[test]
    fn slots_no_match_verifies_every_slot() -> anyhow::Result<()> {
        let keys = vec![
            slot_key("a", ARGON2_0_5_HASH, None)?,
            slot_key("b", ARGON2_0_5_HASH, None)?,
            slot_key("old", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
        ];
        let mut calls = Vec::new();

        let verdict = verify_slots("unknown", &keys, fixed_now()?, |_, hash| {
            calls.push(hash.to_string());
            false
        });

        assert_eq!(verdict, ApiKeyVerdict::NoMatch);
        assert_eq!(calls.len(), keys.len());
        assert_eq!(calls.get(2).map(String::as_str), Some(ARGON2_0_5_HASH));
        Ok(())
    }

    /// Slots active then expired same secret.
    #[test]
    fn slots_active_then_expired_same_secret() -> anyhow::Result<()> {
        let keys = vec![
            slot_key("new", ARGON2_0_5_HASH, None)?,
            slot_key("old", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
        ];
        let mut calls = Vec::new();

        let verdict = verify_slots(ARGON2_0_5_TOKEN, &keys, fixed_now()?, |token, hash| {
            calls.push(hash.to_string());
            hash.to_string() == ARGON2_0_5_HASH && token == ARGON2_0_5_TOKEN.as_bytes()
        });

        assert_eq!(
            verdict,
            ApiKeyVerdict::Active {
                name: "new".into(),
                role: "viewer".into()
            }
        );
        assert_eq!(calls.len(), keys.len());
        assert_eq!(calls.get(1).map(String::as_str), Some(ARGON2_0_5_HASH));
        Ok(())
    }

    /// Slots expired then active same secret.
    #[test]
    fn slots_expired_then_active_same_secret() -> anyhow::Result<()> {
        let keys = vec![
            slot_key("old", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
            slot_key("new", ARGON2_0_5_HASH, None)?,
        ];

        let verdict = verify_slots(ARGON2_0_5_TOKEN, &keys, fixed_now()?, |token, hash| {
            hash.to_string() == ARGON2_0_5_HASH && token == ARGON2_0_5_TOKEN.as_bytes()
        });

        assert_eq!(
            verdict,
            ApiKeyVerdict::Active {
                name: "new".into(),
                role: "viewer".into()
            }
        );
        Ok(())
    }

    /// Slots malformed hash uses dummy.
    #[test]
    fn slots_malformed_hash_uses_dummy() -> anyhow::Result<()> {
        let keys = vec![
            slot_key("broken", "not-a-phc", None)?,
            slot_key("old", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
        ];
        let mut calls = Vec::new();

        let verdict = verify_slots("unknown", &keys, fixed_now()?, |_, hash| {
            calls.push(hash.to_string());
            false
        });

        assert_eq!(verdict, ApiKeyVerdict::NoMatch);
        assert_eq!(calls.len(), keys.len());
        assert_eq!(
            calls.first().map(String::as_str),
            Some(DUMMY_PHC_HASH.as_str())
        );
        assert_eq!(calls.get(1).map(String::as_str), Some(ARGON2_0_5_HASH));
        Ok(())
    }

    /// Slots all expired reports first expired match.
    #[test]
    fn slots_all_expired_reports_first_expired_match() -> anyhow::Result<()> {
        let keys = vec![
            slot_key("first", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
            slot_key("second", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?,
        ];

        let verdict = verify_slots(ARGON2_0_5_TOKEN, &keys, fixed_now()?, |token, hash| {
            hash.to_string() == ARGON2_0_5_HASH && token == ARGON2_0_5_TOKEN.as_bytes()
        });

        assert_eq!(
            verdict,
            ApiKeyVerdict::Expired {
                name: "first".into()
            }
        );
        Ok(())
    }

    /// Slots blank name expired is no match.
    #[test]
    fn slots_blank_name_expired_is_no_match() -> anyhow::Result<()> {
        let keys = vec![slot_key(
            "  ",
            ARGON2_0_5_HASH,
            Some("2020-01-01T00:00:00Z"),
        )?];

        let verdict = verify_slots(ARGON2_0_5_TOKEN, &keys, fixed_now()?, |token, hash| {
            hash.to_string() == ARGON2_0_5_HASH && token == ARGON2_0_5_TOKEN.as_bytes()
        });

        assert_eq!(verdict, ApiKeyVerdict::NoMatch);
        Ok(())
    }

    /// Verdict reports expired match by name.
    #[test]
    fn verdict_reports_expired_match_by_name() -> anyhow::Result<()> {
        let keys = vec![slot_key(
            "old-key",
            ARGON2_0_5_HASH,
            Some("2020-01-01T00:00:00Z"),
        )?];

        assert_eq!(
            verify_bearer_token_verdict(ARGON2_0_5_TOKEN, &keys),
            ApiKeyVerdict::Expired {
                name: "old-key".into()
            }
        );
        assert!(verify_bearer_token(ARGON2_0_5_TOKEN, &keys).is_none());
        Ok(())
    }

    // Regression tests for H3 (api_key_expires_at_fail_open).
    //
    // Prior to 1.6.0 the runtime expiry check used a chained
    // `if let Some(_) && let Ok(exp) = parse(_) && exp < now` which
    // silently fell through on parse error, letting a key with
    // `expires_at = "not-a-date"` authenticate forever. These tests
    // pin the type-system fix: malformed RFC 3339 is rejected at
    // deserialization time (no `RfcTimestamp` can ever be malformed),
    // and the runtime check is a pure comparison with no parse path.

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::rfc_timestamp_parse_rejects_malformed keeps the uniform test signature while it only asserts"
    )]
    /// Rfc timestamp parse rejects malformed.
    #[test]
    fn rfc_timestamp_parse_rejects_malformed() -> anyhow::Result<()> {
        for bad in [
            "not-a-date",
            "",
            "2025-13-01T00:00:00Z", // month 13
            "2025-01-32T00:00:00Z", // day 32
            "2025-01-01T00:00:00",  // missing offset
            "01/01/2025",           // wrong format
            "2025-01-01T25:00:00Z", // hour 25
        ] {
            assert!(
                RfcTimestamp::parse(bad).is_err(),
                "RfcTimestamp::parse must reject {bad:?}"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::rfc_timestamp_parse_accepts_valid keeps the uniform test signature while it only asserts"
    )]
    /// Rfc timestamp parse accepts valid.
    #[test]
    fn rfc_timestamp_parse_accepts_valid() -> anyhow::Result<()> {
        for good in [
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00+00:00",
            "2025-12-31T23:59:59-08:00",
            "2099-01-01T00:00:00.123456789Z",
        ] {
            assert!(
                RfcTimestamp::parse(good).is_ok(),
                "RfcTimestamp::parse must accept {good:?}"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::api_key_entry_deserialize_rejects_malformed_expires_at keeps the uniform test signature while it only asserts"
    )]
    /// Api key entry deserialize rejects malformed expires at.
    #[test]
    fn api_key_entry_deserialize_rejects_malformed_expires_at() -> anyhow::Result<()> {
        // TOML with a malformed expires_at must fail to deserialize.
        // This is the load-time defense: a typo in auth.toml aborts
        // config load with a clear serde error, instead of producing
        // a key that authenticates forever (the H3 fail-open).
        let toml = r#"
            name = "bad-key"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$h4sh"
            role = "viewer"
            expires_at = "not-a-date"
        "#;
        let result: Result<ApiKeyEntry, _> = toml::from_str(toml);
        assert!(
            result.is_err(),
            "deserialization must reject malformed expires_at"
        );
        Ok(())
    }

    /// Api key entry deserialize accepts valid expires at.
    #[test]
    fn api_key_entry_deserialize_accepts_valid_expires_at() -> anyhow::Result<()> {
        let toml = r#"
            name = "good-key"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$h4sh"
            role = "viewer"
            expires_at = "2099-01-01T00:00:00Z"
        "#;
        let entry: ApiKeyEntry = toml::from_str(toml).context("valid RFC 3339 must deserialize")?;
        assert!(entry.expires_at.is_some());
        Ok(())
    }

    /// Api key entry deserialize accepts missing expires at.
    #[test]
    fn api_key_entry_deserialize_accepts_missing_expires_at() -> anyhow::Result<()> {
        // Omitting expires_at must continue to mean "no expiry"; this
        // is the documented contract and must survive the H3 fix.
        let toml = r#"
            name = "eternal-key"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$h4sh"
            role = "viewer"
        "#;
        let entry: ApiKeyEntry =
            toml::from_str(toml).context("missing expires_at must deserialize")?;
        assert!(entry.expires_at.is_none());
        Ok(())
    }

    /// Mtls crl deny on unavailable defaults to fail closed.
    #[test]
    fn mtls_crl_deny_on_unavailable_defaults_to_fail_closed() -> anyhow::Result<()> {
        // Every in-crate test helper builds MtlsConfig via a struct literal,
        // which bypasses serde defaults entirely. Only a deserialization from
        // TOML that omits the key exercises the shipped default.
        let toml = r#"
            ca_cert_path = "/etc/certs/clients-ca.pem"
        "#;
        let cfg: MtlsConfig =
            toml::from_str(toml).context("minimal mtls config must deserialize")?;
        assert!(
            cfg.crl_deny_on_unavailable,
            "omitting crl_deny_on_unavailable must fail closed (RFC 5280 6.3)"
        );
        Ok(())
    }

    /// Mtls crl deny on unavailable opt out is honoured.
    #[test]
    fn mtls_crl_deny_on_unavailable_opt_out_is_honoured() -> anyhow::Result<()> {
        let toml = r#"
            ca_cert_path = "/etc/certs/clients-ca.pem"
            crl_deny_on_unavailable = false
        "#;
        let cfg: MtlsConfig = toml::from_str(toml).context("opt-out config must deserialize")?;
        assert!(
            !cfg.crl_deny_on_unavailable,
            "an explicit false must still select fail-open"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::try_with_expiry_rejects_malformed keeps the uniform test signature while it only asserts"
    )]
    /// Try with expiry rejects malformed.
    #[test]
    fn try_with_expiry_rejects_malformed() -> anyhow::Result<()> {
        let entry = ApiKeyEntry::new("k", "hash", "viewer");
        assert!(entry.try_with_expiry("not-a-date").err().is_some());
        Ok(())
    }

    /// Try with expiry accepts valid.
    #[test]
    fn try_with_expiry_accepts_valid() -> anyhow::Result<()> {
        let entry = ApiKeyEntry::new("k", "hash", "viewer")
            .try_with_expiry("2099-01-01T00:00:00Z")
            .context("valid RFC 3339 must be accepted")?;
        assert!(entry.expires_at.is_some());
        Ok(())
    }

    /// Api key summary serializes expires at as rfc3339.
    #[test]
    fn api_key_summary_serializes_expires_at_as_rfc3339() -> anyhow::Result<()> {
        // The admin endpoint wire format is `{"expires_at": "RFC 3339 str"}`.
        // Pinning this prevents an accidental serialization-format change
        // (e.g. chrono's debug form, a Unix timestamp) that would silently
        // break operator tooling that parses these payloads.
        let summary = ApiKeySummary {
            name: "k".into(),
            role: "viewer".into(),
            expires_at: Some(RfcTimestamp::parse("2030-01-01T00:00:00Z")?),
        };
        let json = serde_json::to_string(&summary)?;
        assert!(
            json.contains(r#""expires_at":"2030-01-01T00:00:00+00:00""#),
            "wire format regressed: {json}"
        );
        Ok(())
    }

    /// Future expiry accepted.
    #[test]
    fn future_expiry_accepted() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: Some(RfcTimestamp::parse("2099-01-01T00:00:00Z")?),
        }];
        assert!(verify_bearer_token(&token, &keys).is_some());
        Ok(())
    }

    /// Multiple keys first match wins.
    #[test]
    fn multiple_keys_first_match_wins() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry {
                name: "wrong".into(),
                hash: "$argon2id$v=19$m=19456,t=2,p=1$invalid$invalid".into(),
                role: "ops".into(),
                expires_at: None,
            },
            ApiKeyEntry {
                name: "correct".into(),
                hash,
                role: "deploy".into(),
                expires_at: None,
            },
        ];
        let id = verify_bearer_token(&token, &keys).context("correct token must authenticate")?;
        assert_eq!(id.name, "correct");
        assert_eq!(id.role, "deploy");
        Ok(())
    }

    /// Rate limiter allows within quota.
    #[test]
    fn rate_limiter_allows_within_quota() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 5,
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let limiter = build_rate_limiter(&config);
        let ip = RateLimitKey::Ip("10.0.0.1".parse::<IpAddr>()?);

        // First 5 should succeed.
        for _ in 0..5_u32 {
            assert!(limiter.check_key(&ip).ok().is_some());
        }
        // 6th should fail.
        assert!(limiter.check_key(&ip).is_err());
        Ok(())
    }

    /// Rate limiter separate ips.
    #[test]
    fn rate_limiter_separate_ips() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 2,
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let limiter = build_rate_limiter(&config);
        let ip1 = RateLimitKey::Ip("10.0.0.1".parse::<IpAddr>()?);
        let ip2 = RateLimitKey::Ip("10.0.0.2".parse::<IpAddr>()?);

        // Exhaust ip1's quota.
        assert!(limiter.check_key(&ip1).ok().is_some());
        assert!(limiter.check_key(&ip1).ok().is_some());
        assert!(limiter.check_key(&ip1).is_err());

        // ip2 should still have quota.
        assert!(limiter.check_key(&ip2).ok().is_some());
        Ok(())
    }

    /// Extract mtls identity from cn.
    #[test]
    fn extract_mtls_identity_from_cn() -> anyhow::Result<()> {
        // Generate a cert with explicit CN.
        let mut params = rcgen::CertificateParams::new(vec!["test-client.local".into()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-client");
        let cert = params.self_signed(&rcgen::KeyPair::generate()?)?;
        let der = cert.der();

        let id = extract_mtls_identity(der, "ops").context("certificate must yield an identity")?;
        assert_eq!(id.name, "test-client");
        assert_eq!(id.role, "ops");
        assert_eq!(id.method, AuthMethod::MtlsCertificate);
        Ok(())
    }

    /// Extract mtls identity falls back to san.
    #[test]
    fn extract_mtls_identity_falls_back_to_san() -> anyhow::Result<()> {
        // Cert with no CN but has a DNS SAN.
        let mut params = rcgen::CertificateParams::new(vec!["san-only.example.com".into()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        // No CN set - should fall back to DNS SAN.
        let cert = params.self_signed(&rcgen::KeyPair::generate()?)?;
        let der = cert.der();

        let id =
            extract_mtls_identity(der, "viewer").context("certificate must yield an identity")?;
        assert_eq!(id.name, "san-only.example.com");
        assert_eq!(id.role, "viewer");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_mtls_identity_invalid_der keeps the uniform test signature while it only asserts"
    )]
    /// Extract mtls identity invalid der.
    #[test]
    fn extract_mtls_identity_invalid_der() -> anyhow::Result<()> {
        assert!(extract_mtls_identity(b"not-a-cert", "viewer").is_none());
        Ok(())
    }

    /// Extract mtls identity blank cn falls back to san.
    #[test]
    fn extract_mtls_identity_blank_cn_falls_back_to_san() -> anyhow::Result<()> {
        // A present-but-blank CN must not shadow a usable DNS SAN. The pre-fix
        // `or_else` never reached the SAN here because `Some("")` short-circuited it.
        let mut params = rcgen::CertificateParams::new(vec!["san-fallback.example.com".into()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "");
        let cert = params.self_signed(&rcgen::KeyPair::generate()?)?;

        let id = extract_mtls_identity(cert.der(), "viewer")
            .context("certificate must yield an identity")?;
        assert_eq!(id.name, "san-fallback.example.com");
        assert_eq!(id.role, "viewer");
        Ok(())
    }

    /// Extract mtls identity blank cn without san yields none.
    #[test]
    fn extract_mtls_identity_blank_cn_without_san_yields_none() -> anyhow::Result<()> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "");
        let cert = params.self_signed(&rcgen::KeyPair::generate()?)?;

        assert!(extract_mtls_identity(cert.der(), "viewer").is_none());
        Ok(())
    }

    /// Extract mtls identity whitespace cn behaves as blank.
    #[test]
    fn extract_mtls_identity_whitespace_cn_behaves_as_blank() -> anyhow::Result<()> {
        let mut params = rcgen::CertificateParams::new(vec!["san-fallback.example.com".into()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "   ");
        let cert = params.self_signed(&rcgen::KeyPair::generate()?)?;

        let id = extract_mtls_identity(cert.der(), "viewer")
            .context("certificate must yield an identity")?;
        assert_eq!(id.name, "san-fallback.example.com");
        Ok(())
    }

    /// Validate api key names rejects blank and whitespace.
    #[test]
    fn validate_api_key_names_rejects_blank_and_whitespace() -> anyhow::Result<()> {
        let blank = AuthConfig::with_keys(vec![
            ApiKeyEntry::new("ok", "hash", "viewer"),
            ApiKeyEntry::new("", "hash", "viewer"),
        ]);
        let err = blank
            .validate_api_key_names()
            .err()
            .context("blank name must be rejected")?
            .to_string();
        assert!(
            err.contains("api_keys[1]"),
            "must name offending index: {err}"
        );

        let whitespace = AuthConfig::with_keys(vec![ApiKeyEntry::new("   ", "hash", "viewer")]);
        assert!(whitespace.validate_api_key_names().is_err());

        let ok = AuthConfig::with_keys(vec![ApiKeyEntry::new("viewer-key", "hash", "viewer")]);
        assert!(ok.validate_api_key_names().ok().is_some());
        Ok(())
    }

    /// Check api key names rejects same name different role.
    #[test]
    fn check_api_key_names_rejects_same_name_different_role() -> anyhow::Result<()> {
        // Two entries share a name but declare different roles. The name alone
        // is the session/task-binding principal identity, so this is one label
        // for two authorization profiles -- rejected.
        let keys = vec![
            ApiKeyEntry::new("ops", "hash-a", "admin"),
            ApiKeyEntry::new("ops", "hash-b", "viewer"),
        ];
        let err = check_api_key_names(&keys)
            .err()
            .context("same-name different-role keys must be rejected")?
            .to_string();
        assert!(
            err.contains("api_keys[1]"),
            "must name the offending index: {err}"
        );
        assert!(
            err.contains("reuses the name 'ops'"),
            "must explain the name/role conflict: {err}"
        );
        // The public startup entry point enforces the identical rule.
        assert!(
            AuthConfig::with_keys(keys)
                .validate_api_key_names()
                .is_err(),
            "validate_api_key_names must reject the same contradiction"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::check_api_key_names_permits_same_name_same_role_rotation keeps the uniform test signature while it only asserts"
    )]
    /// Check api key names permits same name same role rotation.
    #[test]
    fn check_api_key_names_permits_same_name_same_role_rotation() -> anyhow::Result<()> {
        // Same name + same role is credential rotation (one principal, two
        // secrets): explicitly allowed so key rollover keeps working.
        let keys = vec![
            ApiKeyEntry::new("ops", "old-hash", "admin"),
            ApiKeyEntry::new("ops", "new-hash", "admin"),
        ];
        assert!(
            check_api_key_names(&keys).is_ok(),
            "same-name same-role rotation must be permitted"
        );
        assert!(
            AuthConfig::with_keys(keys)
                .validate_api_key_names()
                .ok()
                .is_some()
        );
        Ok(())
    }

    /// Check api key names rejects blank name.
    #[test]
    fn check_api_key_names_rejects_blank_name() -> anyhow::Result<()> {
        // Regression guard: the blank-name rule still fires now that the
        // same-name/different-role rule is enforced alongside it.
        let keys = vec![
            ApiKeyEntry::new("ok", "hash", "viewer"),
            ApiKeyEntry::new("   ", "hash", "viewer"),
        ];
        let err = check_api_key_names(&keys)
            .err()
            .context("blank name must be rejected")?
            .to_string();
        assert!(
            err.contains("api_keys[1]"),
            "must name the blank index: {err}"
        );
        assert!(
            err.contains("blank name"),
            "must cite the blank-name rule: {err}"
        );
        Ok(())
    }

    /// Try reload keys rejects blank name and keeps previous.
    #[test]
    fn try_reload_keys_rejects_blank_name_and_keeps_previous() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let state = test_auth_state(vec![ApiKeyEntry::new("prev-key", hash, "ops")]);

        let err = state
            .try_reload_keys(vec![ApiKeyEntry::new("  ", "unused-hash", "ops")])
            .err()
            .context("blank name must be rejected")?
            .to_string();
        assert!(
            err.contains("api_keys[0]"),
            "must name offending index: {err}"
        );

        let installed = state.api_keys.load();
        assert!(
            verify_bearer_token(&token, &installed).is_some(),
            "the previous key must remain installed after a rejected reload"
        );
        Ok(())
    }

    /// Verify bearer token rejects blank named key.
    #[test]
    fn verify_bearer_token_rejects_blank_named_key() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let blank = ApiKeyEntry {
            name: String::new(),
            hash: hash.clone(),
            role: "ops".into(),
            expires_at: None,
        };
        assert!(
            verify_bearer_token(&token, from_ref(&blank)).is_none(),
            "a valid token for a blank-named key must yield no identity"
        );

        let whitespace = ApiKeyEntry {
            name: "   ".into(),
            hash: hash.clone(),
            role: "ops".into(),
            expires_at: None,
        };
        assert!(
            verify_bearer_token(&token, from_ref(&whitespace)).is_none(),
            "a whitespace-only key name must be treated as blank"
        );

        let named = ApiKeyEntry::new("real-key", hash, "ops");
        assert!(
            verify_bearer_token(&token, from_ref(&named)).is_some(),
            "a non-blank key name must still authenticate"
        );
        Ok(())
    }

    // -- auth_middleware integration tests --

    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    /// Static `ok` handler for the test router.
    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn auth_router(state: Arc<AuthState>) -> axum::Router {
        axum::Router::new()
            .route("/mcp", post(ok_handler))
            .layer(from_fn(move |req, next| {
                let state_clone = Arc::clone(&state);
                auth_middleware(state_clone, req, next)
            }))
    }

    fn test_auth_state(keys: Vec<ApiKeyEntry>) -> Arc<AuthState> {
        test_auth_state_with_log_context(keys, LogContextConfig::default())
    }

    fn test_auth_state_with_log_context(
        keys: Vec<ApiKeyEntry>,
        fields: LogContextConfig,
    ) -> Arc<AuthState> {
        let credential_fingerprint = fields.credential_fingerprint;
        Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(keys)),
            rate_limiter: None,
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext {
                fields,
                fingerprint_salt: credential_fingerprint
                    .then(|| Arc::new(SecretString::from("test-salt"))),
            },
        })
    }

    async fn capture_auth_failure_log(
        state: Arc<AuthState>,
        req: Request<Body>,
    ) -> anyhow::Result<(StatusCode, String)> {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let app = auth_router(state);
        let _guard = set_default(subscriber);
        let status = app
            .oneshot(req)
            .await
            .context("auth request must complete")?
            .status();
        Ok((status, logs.contents()))
    }

    fn auth_request(uri: &str) -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())?)
    }

    fn auth_request_with_all_context() -> anyhow::Result<Request<Body>> {
        let mut req = auth_request("/mcp?probe=1")?;
        let _previous_1 = req
            .headers_mut()
            .insert(header::USER_AGENT, HeaderValue::from_static("probe/1.0"));
        let _previous_2 = req
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("ignored"));
        let _previous_17 = req
            .extensions_mut()
            .insert(ClientIp::new("203.0.113.7".parse().context("ip parses")?));
        let _previous_18 = req.extensions_mut().insert(PeerAddr::new(
            "127.0.0.1:5555".parse().context("socket parses")?,
        ));
        let _previous_19 = req.extensions_mut().insert(RequestId::new("qa-1"));
        let _previous_6 = req.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:5555"
                .parse::<SocketAddr>()
                .context("socket parses")?,
        ));
        Ok(req)
    }

    fn assert_auth_failed_line<'log>(logs: &'log str, needle: &str) -> anyhow::Result<&'log str> {
        let Some(line) = logs.lines().find(|line| line.contains(needle)) else {
            anyhow::bail!("missing {needle:?} in logs: {logs}");
        };
        Ok(line)
    }

    fn knobs(mut configure: impl FnMut(&mut LogContextConfig)) -> LogContextConfig {
        let mut fields = LogContextConfig::default();
        configure(&mut fields);
        fields
    }

    /// Auth failure log omits client context by default.
    #[tokio::test]
    async fn auth_failure_log_omits_client_context_by_default() -> anyhow::Result<()> {
        let state = test_auth_state(vec![]);
        let req = auth_request_with_all_context()?;

        let (status, logs) = capture_auth_failure_log(state, req).await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let line = assert_auth_failed_line(&logs, "auth failed")?;
        assert!(
            line.ends_with("auth failed failure_class=missing_credential"),
            "default log must preserve golden suffix: {line}"
        );
        Ok(())
    }

    /// Auth failure log carries client context.
    #[tokio::test]
    async fn auth_failure_log_carries_client_context() -> anyhow::Result<()> {
        let mut fields = LogContextConfig::recommended();
        fields.request_id = true;
        let state = test_auth_state_with_log_context(vec![], fields);

        let (status, logs) =
            capture_auth_failure_log(Arc::clone(&state), auth_request_with_all_context()?).await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let line = assert_auth_failed_line(&logs, "failure_class=missing_credential")?;
        assert!(line.contains("client_ip=203.0.113.7"), "{line}");
        assert!(line.contains("peer_ip=127.0.0.1"), "{line}");
        assert!(line.contains("request_id=\"qa-1\""), "{line}");
        assert!(line.contains("method=POST"), "{line}");
        assert!(line.contains("path=/mcp"), "{line}");
        assert!(line.contains("user_agent=\"probe/1.0\""), "{line}");
        assert!(line.contains("auth_scheme=none"), "{line}");
        assert!(line.contains("mcp_session=false"), "{line}");
        assert!(
            !line.contains("probe=1"),
            "query string must not be logged: {line}"
        );

        let mut bearer = auth_request_with_all_context()?;
        let _previous_7 = bearer.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-a-key"),
        );
        let (_, bearer_logs) = capture_auth_failure_log(Arc::clone(&state), bearer).await?;
        let bearer_line =
            assert_auth_failed_line(&bearer_logs, "failure_class=invalid_credential")?;
        assert!(bearer_line.contains("auth_scheme=bearer"), "{bearer_line}");
        assert!(bearer_line.contains("token_kind=opaque"), "{bearer_line}");
        assert!(
            !bearer_line.contains("not-a-key"),
            "credential must not leak: {bearer_line}"
        );

        let mut basic = auth_request_with_all_context()?;
        let _previous_8 = basic
            .headers_mut()
            .insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        let (_, basic_logs) = capture_auth_failure_log(state, basic).await?;
        let basic_line = assert_auth_failed_line(&basic_logs, "failure_class=invalid_credential")?;
        assert!(basic_line.contains("auth_scheme=basic"), "{basic_line}");
        assert!(
            !basic_line.contains("token_kind"),
            "non-bearer token kind omitted: {basic_line}"
        );
        assert!(
            !basic_line.contains("abc"),
            "credential must not leak: {basic_line}"
        );
        Ok(())
    }

    /// Auth failure client ip falls back to connect info.
    #[tokio::test]
    async fn auth_failure_client_ip_falls_back_to_connect_info() -> anyhow::Result<()> {
        let fields = knobs(|ctx| ctx.client_ip = true);
        let state = test_auth_state_with_log_context(vec![], fields);
        let mut req = auth_request("/mcp")?;
        let _previous_9 = req.extensions_mut().insert(ConnectInfo(
            "10.9.8.7:1234"
                .parse::<SocketAddr>()
                .context("socket parses")?,
        ));

        let (_, logs) = capture_auth_failure_log(state, req).await?;
        let line = assert_auth_failed_line(&logs, "auth failed")?;

        assert!(line.contains("client_ip=10.9.8.7"), "{line}");
        Ok(())
    }

    /// Auth failure auth shape fields.
    #[tokio::test]
    async fn auth_failure_auth_shape_fields() -> anyhow::Result<()> {
        let fields = knobs(|ctx| ctx.auth_scheme = true);
        let state = test_auth_state_with_log_context(vec![], fields);
        let cases = [
            (None, "auth_scheme=none", None),
            (
                Some("Bearer not-a-key"),
                "auth_scheme=bearer",
                Some("token_kind=opaque"),
            ),
            (
                Some("Bearer aaa.bbb.ccc"),
                "auth_scheme=bearer",
                Some("token_kind=jwt"),
            ),
            (Some("Basic abc"), "auth_scheme=basic", None),
            (Some("Digest x"), "auth_scheme=other", None),
        ];
        for (header_value, scheme, kind) in cases {
            let mut req = auth_request("/mcp")?;
            if let Some(value) = header_value {
                let _previous_10 = req
                    .headers_mut()
                    .insert(header::AUTHORIZATION, HeaderValue::from_static(value));
            }
            let (_, logs) = capture_auth_failure_log(Arc::clone(&state), req).await?;
            let line = assert_auth_failed_line(&logs, "auth failed")?;
            assert!(line.contains(scheme), "{line}");
            if let Some(expected_kind) = kind {
                assert!(line.contains(expected_kind), "{line}");
            } else {
                assert!(!line.contains("token_kind"), "{line}");
            }
        }

        let mut req = auth_request("/mcp")?;
        let _previous_11 = req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"\xff").context("non-utf8 header builds")?,
        );
        let (_, logs) = capture_auth_failure_log(state, req).await?;
        let line = assert_auth_failed_line(&logs, "auth failed")?;
        assert!(line.contains("auth_scheme=other"), "{line}");
        Ok(())
    }

    /// Auth failure mcp hints.
    #[tokio::test]
    async fn auth_failure_mcp_hints() -> anyhow::Result<()> {
        let fields = knobs(|ctx| ctx.mcp_hints = true);
        let state = test_auth_state_with_log_context(vec![], fields);
        let mut req = auth_request("/mcp")?;
        let _previous_12 = req.headers_mut().insert(
            "mcp-session-id",
            HeaderValue::from_static("secret-session-value"),
        );
        let _previous_13 = req.headers_mut().insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-06-18"),
        );

        let (_, logs) = capture_auth_failure_log(state, req).await?;
        let line = assert_auth_failed_line(&logs, "auth failed")?;

        assert!(line.contains("mcp_session=true"), "{line}");
        assert!(
            line.contains("mcp_protocol_version=\"2025-06-18\""),
            "{line}"
        );
        assert!(!line.contains("secret-session-value"), "{line}");
        Ok(())
    }

    fn credential_fp_from_line(line: &str) -> anyhow::Result<&str> {
        let Some(found) = line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("credential_fp="))
        else {
            anyhow::bail!("credential_fp missing from line: {line}");
        };
        Ok(found)
    }

    /// Capture the failure log for a bearer request in the given state.
    async fn run(state: Arc<AuthState>, header_value: &'static str) -> anyhow::Result<String> {
        let mut req = auth_request("/mcp")?;
        let _previous_14 = req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static(header_value),
        );
        Ok(capture_auth_failure_log(state, req).await?.1)
    }

    /// Auth failure credential fingerprint is stable and bearer only.
    #[tokio::test]
    async fn auth_failure_credential_fingerprint_is_stable_and_bearer_only() -> anyhow::Result<()> {
        let fields = knobs(|ctx| ctx.credential_fingerprint = true);
        let state = test_auth_state_with_log_context(vec![], fields);

        let logs_a1 = run(Arc::clone(&state), "Bearer tok-A").await?;
        let line_a1 = assert_auth_failed_line(&logs_a1, "auth failed")?;
        let fp_a1 = credential_fp_from_line(line_a1)?;
        assert_eq!(fp_a1.len(), 8, "{line_a1}");
        assert!(fp_a1.chars().all(|ch| ch.is_ascii_hexdigit()), "{line_a1}");

        let logs_a2 = run(Arc::clone(&state), "Bearer tok-A").await?;
        let fp_a2 = credential_fp_from_line(assert_auth_failed_line(&logs_a2, "auth failed")?)?;
        assert_eq!(fp_a1, fp_a2);

        let logs_b = run(Arc::clone(&state), "Bearer tok-B").await?;
        let fp_b = credential_fp_from_line(assert_auth_failed_line(&logs_b, "auth failed")?)?;
        assert_ne!(fp_a1, fp_b);

        let logs_basic = run(Arc::clone(&state), "Basic tok-A").await?;
        let line_basic = assert_auth_failed_line(&logs_basic, "auth failed")?;
        assert!(!line_basic.contains("credential_fp"), "{line_basic}");

        let all_logs = format!("{logs_a1}{logs_a2}{logs_b}{logs_basic}");
        assert!(!all_logs.contains("tok-A"), "{all_logs}");
        assert!(!all_logs.contains("tok-B"), "{all_logs}");

        let default_state = test_auth_state_with_log_context(vec![], LogContextConfig::default());
        let default_logs = run(default_state, "Bearer tok-A").await?;
        let default_line = assert_auth_failed_line(&default_logs, "auth failed")?;
        assert!(!default_line.contains("credential_fp"), "{default_line}");
        Ok(())
    }

    /// User agent for log reads the header.
    #[test]
    fn user_agent_for_log_reads_the_header() -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        assert_eq!(user_agent_for_log(&headers), "-");

        let _user_agent_default =
            headers.insert(header::USER_AGENT, HeaderValue::from_static("probe/1.0"));
        assert_eq!(user_agent_for_log(&headers), "probe/1.0");

        let _user_agent_non_utf8 = headers.insert(
            header::USER_AGENT,
            HeaderValue::from_bytes(b"caf\xe9").context("non-utf8 header builds")?,
        );
        assert_eq!(user_agent_for_log(&headers), "<non-utf8>");

        let long = "a".repeat(200);
        let _user_agent_long = headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&long).context("header builds")?,
        );
        assert_eq!(
            user_agent_for_log(&headers),
            format!("{}...(truncated)", "a".repeat(128))
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::token_kind_classifies_jwt_shape keeps the uniform test signature while it only asserts"
    )]
    /// Token kind classifies jwt shape.
    #[test]
    fn token_kind_classifies_jwt_shape() -> anyhow::Result<()> {
        assert_eq!(token_kind("aaa.bbb.ccc"), "jwt");
        for opaque in ["a.b", "a..c", "a+b.c.d", "opaque-key"] {
            assert_eq!(token_kind(opaque), "opaque", "{opaque}");
        }
        Ok(())
    }

    /// Middleware rejects no credentials.
    #[tokio::test]
    async fn middleware_rejects_no_credentials() -> anyhow::Result<()> {
        let state = test_auth_state(vec![]);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .context("WWW-Authenticate header must be present")?
            .to_str()
            .context("WWW-Authenticate must be valid UTF-8")?;
        assert!(challenge.contains("error=\"invalid_request\""));

        let counters = state.counters_snapshot();
        assert_eq!(counters.failure_missing_credential, 1);
        Ok(())
    }

    /// Middleware accepts valid bearer.
    #[tokio::test]
    async fn middleware_accepts_valid_bearer() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let state = test_auth_state(keys);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let counters = state.counters_snapshot();
        assert_eq!(counters.success_bearer, 1);
        Ok(())
    }

    /// Middleware rejects wrong bearer.
    #[tokio::test]
    async fn middleware_rejects_wrong_bearer() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let state = test_auth_state(keys);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer wrong-token-here")
            .body(Body::empty())?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .context("WWW-Authenticate header must be present")?
            .to_str()
            .context("WWW-Authenticate must be valid UTF-8")?;
        assert!(challenge.contains("error=\"invalid_token\""));

        let counters = state.counters_snapshot();
        assert_eq!(counters.failure_invalid_credential, 1);
        Ok(())
    }

    /// Expired api key gets expired credential challenge.
    #[tokio::test]
    async fn expired_api_key_gets_expired_credential_challenge() -> anyhow::Result<()> {
        let key = slot_key("old-key", ARGON2_0_5_HASH, Some("2020-01-01T00:00:00Z"))?;
        let state = test_auth_state(vec![key]);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::AUTHORIZATION, format!("Bearer {ARGON2_0_5_TOKEN}"))
            .body(Body::empty())?;

        let resp = app.clone().oneshot(req).await?;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .context("WWW-Authenticate header must be present")?
            .to_str()
            .context("WWW-Authenticate must be valid UTF-8")?;
        assert!(challenge.contains("error_description=\"token is expired\""));
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.to_vec(), b"unauthorized: expired credential");
        let counters = state.counters_snapshot();
        assert_eq!(counters.failure_expired_credential, 1);
        assert_eq!(counters.failure_invalid_credential, 0);

        let req2 = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::AUTHORIZATION, "Bearer garbage-token")
            .body(Body::empty())?;
        let resp2 = app.oneshot(req2).await?;
        let challenge2 = resp2
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .context("WWW-Authenticate header must be present")?
            .to_str()
            .context("WWW-Authenticate must be valid UTF-8")?;
        assert!(challenge2.contains("error_description=\"token is invalid\""));
        let counters2 = state.counters_snapshot();
        assert_eq!(counters2.failure_invalid_credential, 1);
        Ok(())
    }

    /// Credential owner logged for expired api key only when enabled.
    #[tokio::test]
    async fn credential_owner_logged_for_expired_api_key_only_when_enabled() -> anyhow::Result<()> {
        for (enabled, expected_owner) in [(true, true), (false, false)] {
            let fields = LogContextConfig {
                credential_owner: enabled,
                ..LogContextConfig::default()
            };
            let state = test_auth_state_with_log_context(
                vec![slot_key(
                    "old-key",
                    ARGON2_0_5_HASH,
                    Some("2020-01-01T00:00:00Z"),
                )?],
                fields,
            );
            let mut req = auth_request("/mcp")?;
            let _previous_15 = req.headers_mut().insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer golden-vector-token-0p5p3"),
            );

            let (status, logs) = capture_auth_failure_log(state, req).await?;

            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let line = assert_auth_failed_line(&logs, "failure_class=expired_credential")?;
            if expected_owner {
                assert!(line.contains("credential_owner=\"old-key\""), "{line}");
                assert!(line.contains("credential_rejection=expired"), "{line}");
            } else {
                assert!(
                    line.ends_with("auth failed failure_class=expired_credential"),
                    "{line}"
                );
            }
            assert!(!logs.contains(ARGON2_0_5_TOKEN), "{logs}");
        }
        Ok(())
    }

    /// No owner for unknown bearer.
    #[tokio::test]
    async fn no_owner_for_unknown_bearer() -> anyhow::Result<()> {
        let fields = knobs(|ctx| ctx.credential_owner = true);
        let state = test_auth_state_with_log_context(
            vec![slot_key(
                "old-key",
                ARGON2_0_5_HASH,
                Some("2020-01-01T00:00:00Z"),
            )?],
            fields,
        );
        let mut req = auth_request("/mcp")?;
        let _previous_16 = req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-a-key"),
        );

        let (_, logs) = capture_auth_failure_log(Arc::clone(&state), req).await?;

        let line = assert_auth_failed_line(&logs, "failure_class=invalid_credential")?;
        assert!(!line.contains("credential_owner"), "{line}");

        let mut req2 = auth_request("/mcp")?;
        let _previous_17 = req2.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer golden-vector-token-0p5p3"),
        );
        let (_, logs2) = capture_auth_failure_log(state, req2).await?;
        let line2 = assert_auth_failed_line(&logs2, "failure_class=expired_credential")?;
        assert!(line2.contains("credential_owner=\"old-key\""), "{line2}");
        Ok(())
    }

    /// Middleware rate limits.
    #[tokio::test]
    async fn middleware_rate_limits() -> anyhow::Result<()> {
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: Some(build_rate_limiter(&RateLimitConfig {
                max_attempts_per_minute: 1,
                pre_auth_max_per_minute: None,
                max_tracked_keys: default_max_tracked_keys(),
                idle_eviction: default_idle_eviction(),
                burst: None,
                pre_auth_burst: None,
                key_eviction_policy: KeyEvictionPolicy::default(),
            })),
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        let app = auth_router(state);

        // First request: UNAUTHORIZED (no credentials, but not rate limited)
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Second request from same "IP" (no ConnectInfo in test, so peer_addr is None
        // and rate limiter won't fire). That's expected -- rate limiting requires
        // ConnectInfo which isn't available in unit tests without a real server.
        // This test verifies the middleware wiring doesn't panic.
        Ok(())
    }

    /// Verify that rate limit semantics: only failed auth attempts consume budget.
    ///
    /// This is a unit test of the limiter behavior. The middleware integration
    /// is that on auth failure, `check_key` is called; on auth success, it is NOT.
    /// Full e2e tests verify the middleware routing but require `ConnectInfo`.
    #[test]
    fn rate_limit_semantics_failed_only() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 3,
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let limiter = build_rate_limiter(&config);
        let ip = RateLimitKey::Ip("192.168.1.100".parse::<IpAddr>()?);

        // Simulate: 3 failed attempts should exhaust quota.
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 1 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 2 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 3 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_err(),
            "failure 4 should be blocked"
        );

        // In the actual middleware flow:
        // - Successful auth: verify_bearer_token returns Some, we return early
        //   WITHOUT calling check_key, so no budget consumed.
        // - Failed auth: verify_bearer_token returns None, we call check_key
        //   THEN return 401, so budget is consumed.
        //
        // This means N successful requests followed by M failed requests
        // will only count M toward the rate limit, not N+M.
        Ok(())
    }

    // -- pre-auth abuse gate (H-S1) --

    /// The pre-auth gate must default to ~10x the post-failure quota so honest
    /// retry storms never trip it but a Argon2-spray attacker is throttled.
    #[test]
    fn pre_auth_default_multiplier_is_10x() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 5,
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let limiter = build_pre_auth_limiter(&config);
        let ip = RateLimitKey::Ip("10.0.0.1".parse::<IpAddr>()?);

        // Quota should be 50 (5 * 10), not 5. We expect the first 50 to pass.
        for i in 0..50_u32 {
            assert!(
                limiter.check_key(&ip).is_ok(),
                "pre-auth attempt {i} (of expected 50) should be allowed under default 10x multiplier"
            );
        }
        // The 51st attempt must be blocked: confirms quota is bounded, not infinite.
        assert!(
            limiter.check_key(&ip).is_err(),
            "pre-auth attempt 51 should be blocked (quota is 50, not unbounded)"
        );
        Ok(())
    }

    /// An explicit `pre_auth_max_per_minute` override must win over the
    /// 10x-multiplier default.
    #[test]
    fn pre_auth_explicit_override_wins() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,     // would default to 1000 pre-auth quota
            pre_auth_max_per_minute: Some(2), // but operator caps at 2
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let limiter = build_pre_auth_limiter(&config);
        let ip = RateLimitKey::Ip("10.0.0.2".parse::<IpAddr>()?);

        assert!(limiter.check_key(&ip).is_ok(), "attempt 1 allowed");
        assert!(limiter.check_key(&ip).is_ok(), "attempt 2 allowed");
        assert!(
            limiter.check_key(&ip).is_err(),
            "attempt 3 must be blocked (explicit override of 2 wins over 10x default of 1000)"
        );
        Ok(())
    }

    /// The pre-auth gate's 429 must carry a Retry-After header.
    #[test]
    fn pre_auth_gate_deny_sets_retry_after() -> anyhow::Result<()> {
        let config = RateLimitConfig::new(100).with_pre_auth_max_per_minute(1);
        let state = AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        };
        let ip = RateLimitKey::Ip("10.7.7.7".parse::<IpAddr>()?);
        assert!(
            pre_auth_gate(&state, Some(&ip)).is_none(),
            "first request within quota"
        );
        let resp = pre_auth_gate(&state, Some(&ip)).context("second request must be gated")?;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .context("Retry-After present")?
            .to_str()
            .context("Retry-After must be valid UTF-8")?
            .parse::<u64>()
            .context("Retry-After must be delta-seconds")?;
        assert!(retry_after >= 1, "delta-seconds must be >= 1");
        Ok(())
    }

    /// Pre auth gate capacity full returns 503 without retry after.
    #[test]
    fn pre_auth_gate_capacity_full_returns_503_without_retry_after() -> anyhow::Result<()> {
        let config = RateLimitConfig::new(100)
            .with_pre_auth_max_per_minute(10)
            .with_max_tracked_keys(1)
            .with_key_eviction_policy(KeyEvictionPolicy::RejectNew);
        let state = AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        };
        let established = RateLimitKey::Ip("10.7.7.7".parse::<IpAddr>()?);
        let unseen = RateLimitKey::Ip("10.7.7.8".parse::<IpAddr>()?);
        assert!(pre_auth_gate(&state, Some(&established)).is_none());

        let resp = pre_auth_gate(&state, Some(&unseen)).context("unseen key must be rejected")?;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
        Ok(())
    }

    /// Post-failure limiter honors an explicit burst capacity.
    #[test]
    fn post_failure_limiter_burst_allows_initial_spike() -> anyhow::Result<()> {
        let config = RateLimitConfig::new(1).with_burst(3);
        let limiter = build_rate_limiter(&config);
        let ip = RateLimitKey::Ip("10.6.6.6".parse::<IpAddr>()?);
        for i in 0..3_u32 {
            assert!(limiter.check_key(&ip).is_ok(), "burst attempt {i}");
        }
        assert!(
            limiter.check_key(&ip).is_err(),
            "attempt 4 must exceed the burst bucket"
        );
        Ok(())
    }

    /// End-to-end: the pre-auth gate must reject before the bearer-verification
    /// path runs. We exhaust the gate's quota (Some(1)) with one bad-bearer
    /// request, then the second request must be rejected with 429 + the
    /// `pre_auth_gate` failure counter incremented (NOT
    /// `failure_invalid_credential`, which would prove Argon2 ran).
    #[tokio::test]
    async fn pre_auth_gate_blocks_before_argon2_verification() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,
            pre_auth_max_per_minute: Some(1),
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(keys)),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let peer: SocketAddr = "10.0.0.10:54321".parse()?;

        // First bad-bearer request: gate has quota, bearer verification runs,
        // returns 401 (invalid credential).
        let mut req1 = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer obviously-not-a-real-token")
            .body(Body::empty())?;
        let _previous_18 = req1.extensions_mut().insert(ConnectInfo(peer));
        let resp1 = app.clone().oneshot(req1).await?;
        assert_eq!(
            resp1.status(),
            StatusCode::UNAUTHORIZED,
            "first attempt: gate has quota, falls through to bearer auth which fails with 401"
        );

        // Second bad-bearer request from same IP: gate quota exhausted, must
        // reject with 429 BEFORE the Argon2 verification path runs.
        let mut req2 = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer also-not-a-real-token")
            .body(Body::empty())?;
        let _previous_19 = req2.extensions_mut().insert(ConnectInfo(peer));
        let resp2 = app.oneshot(req2).await?;
        assert_eq!(
            resp2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second attempt from same IP: pre-auth gate must reject with 429"
        );

        let counters = state.counters_snapshot();
        assert_eq!(
            counters.failure_pre_auth_gate, 1,
            "exactly one request must have been rejected by the pre-auth gate"
        );
        // Critical: Argon2 verification must NOT have run on the gated request.
        // The first request's 401 increments `failure_invalid_credential` to 1;
        // the second (gated) request must NOT increment it further.
        assert_eq!(
            counters.failure_invalid_credential, 1,
            "bearer verification must run exactly once (only the un-gated first request)"
        );
        Ok(())
    }

    /// mTLS-authenticated requests must bypass the pre-auth gate entirely.
    /// The TLS handshake already performed expensive crypto with a verified
    /// peer, so mTLS callers should never be throttled by this gate.
    ///
    /// Setup: a pre-auth gate with quota 1 (very tight). Submit two mTLS
    /// requests in quick succession from the same IP. Both must succeed.
    #[tokio::test]
    async fn pre_auth_gate_does_not_throttle_mtls() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,
            pre_auth_max_per_minute: Some(1), // tight: would block 2nd plain request
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let peer: SocketAddr = "10.0.0.20:54321".parse()?;
        let identity = AuthIdentity {
            name: "cn=test-client".into(),
            role: "viewer".into(),
            method: AuthMethod::MtlsCertificate,
            raw_token: None,
            sub: None,
        };
        let tls_info = TlsConnInfo::new(peer, Some(identity));

        for i in 0..3_u32 {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .body(Body::empty())?;
            let _previous_20 = req.extensions_mut().insert(ConnectInfo(tls_info.clone()));
            let resp = app.clone().oneshot(req).await?;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "mTLS request {i} must succeed: pre-auth gate must not apply to mTLS callers"
            );
        }

        let counters = state.counters_snapshot();
        assert_eq!(
            counters.failure_pre_auth_gate, 0,
            "pre-auth gate counter must remain at zero: mTLS bypasses the gate"
        );
        assert_eq!(
            counters.success_mtls, 3,
            "all three mTLS requests must have been counted as successful"
        );
        Ok(())
    }

    /// Pre-auth-gate denial must increment the `auth_pre` deny counter
    /// via the metrics handle in the request extensions.
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn pre_auth_gate_deny_increments_counter() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,
            pre_auth_max_per_minute: Some(1),
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let metrics = Arc::new(McpMetrics::new().context("metrics registry")?);
        let peer: SocketAddr = "10.0.0.30:54321".parse().context("addr parses")?;
        let mk = || -> anyhow::Result<Request<Body>> {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header("authorization", "Bearer not-a-real-token")
                .body(Body::empty())
                .context("request builds")?;
            let _connect_info = req.extensions_mut().insert(ConnectInfo(peer));
            let _metrics_handle = req.extensions_mut().insert(Arc::clone(&metrics));
            Ok(req)
        };
        let counter = |label: &str| metrics.rate_limited_total.with_label_values(&[label]).get();

        let first = app.clone().oneshot(mk()?).await.context("first request")?;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(counter("auth_pre"), 0, "un-gated request must not count");

        let gated = app.oneshot(mk()?).await.context("second request")?;
        assert_eq!(gated.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(counter("auth_pre"), 1, "gated request must count once");
        assert_eq!(counter("auth_post"), 0, "post limiter never fired");
        Ok(())
    }

    /// Post-failure limiter denial must increment the `auth_post` deny
    /// counter via the metrics handle in the request extensions.
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn post_failure_limiter_deny_increments_counter() -> anyhow::Result<()> {
        let config = RateLimitConfig {
            max_attempts_per_minute: 1, // tight: 2nd failure trips the limiter
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
            burst: None,
            pre_auth_burst: None,
            key_eviction_policy: KeyEvictionPolicy::default(),
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: Some(build_rate_limiter(&config)),
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: AuthLogContext::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let metrics = Arc::new(McpMetrics::new().context("metrics registry")?);
        let peer: SocketAddr = "10.0.0.31:54321".parse().context("addr parses")?;
        let mk = || -> anyhow::Result<Request<Body>> {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header("authorization", "Bearer not-a-real-token")
                .body(Body::empty())
                .context("request builds")?;
            let _connect_info = req.extensions_mut().insert(ConnectInfo(peer));
            let _metrics_handle = req.extensions_mut().insert(Arc::clone(&metrics));
            Ok(req)
        };
        let counter = |label: &str| metrics.rate_limited_total.with_label_values(&[label]).get();

        // First failure consumes the budget but is NOT itself limited.
        let first = app.clone().oneshot(mk()?).await.context("first request")?;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(counter("auth_post"), 0);

        // Second failure trips the post-failure limiter.
        let limited = app.oneshot(mk()?).await.context("second request")?;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(counter("auth_post"), 1, "deny must count once");
        assert_eq!(counter("auth_pre"), 0, "pre-auth gate disabled here");
        Ok(())
    }

    // -------------------------------------------------------------------
    // RFC 7235 §2.1 case-insensitive scheme parsing for `extract_bearer`.
    // -------------------------------------------------------------------

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_accepts_canonical_case keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer accepts canonical case.
    #[test]
    fn extract_bearer_accepts_canonical_case() -> anyhow::Result<()> {
        assert_eq!(extract_bearer("Bearer abc123"), Some("abc123"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_is_case_insensitive_per_rfc7235 keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer is case insensitive per rfc7235.
    #[test]
    fn extract_bearer_is_case_insensitive_per_rfc7235() -> anyhow::Result<()> {
        // RFC 7235 §2.1: "auth-scheme is case-insensitive".
        // Real-world clients (curl, browsers, custom HTTP libs) emit varied
        // casings; rejecting any of them is a spec violation.
        for header in &[
            "bearer abc123",
            "BEARER abc123",
            "BeArEr abc123",
            "bEaReR abc123",
        ] {
            assert_eq!(
                extract_bearer(header),
                Some("abc123"),
                "header {header:?} must parse as a Bearer token (RFC 7235 §2.1)"
            );
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_rejects_other_schemes keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer rejects other schemes.
    #[test]
    fn extract_bearer_rejects_other_schemes() -> anyhow::Result<()> {
        assert_eq!(extract_bearer("Basic dXNlcjpwYXNz"), None);
        assert_eq!(extract_bearer("Digest username=\"x\""), None);
        assert_eq!(extract_bearer("Token abc123"), None);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_rejects_malformed keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer rejects malformed.
    #[test]
    fn extract_bearer_rejects_malformed() -> anyhow::Result<()> {
        // Empty string, no separator, scheme-only, scheme + only whitespace.
        assert_eq!(extract_bearer(""), None);
        assert_eq!(extract_bearer("Bearer"), None);
        assert_eq!(extract_bearer("Bearer "), None);
        assert_eq!(extract_bearer("Bearer    "), None);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_tolerates_extra_separator_whitespace keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer tolerates extra separator whitespace.
    #[test]
    fn extract_bearer_tolerates_extra_separator_whitespace() -> anyhow::Result<()> {
        // Some non-conformant clients emit two spaces; we should still parse.
        assert_eq!(extract_bearer("Bearer  abc123"), Some("abc123"));
        assert_eq!(extract_bearer("Bearer   abc123"), Some("abc123"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_rejects_embedded_whitespace keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer rejects embedded whitespace.
    #[test]
    fn extract_bearer_rejects_embedded_whitespace() -> anyhow::Result<()> {
        assert_eq!(extract_bearer("Bearer abc 123"), None);
        assert_eq!(extract_bearer("Bearer abc\t123"), None);
        assert_eq!(extract_bearer("Bearer abc123 "), None);
        assert_eq!(extract_bearer("Bearer abc123\r\n"), None);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::extract_bearer_still_accepts_opaque_non_token68_credentials keeps the uniform test signature while it only asserts"
    )]
    /// Extract bearer still accepts opaque non token68 credentials.
    #[test]
    fn extract_bearer_still_accepts_opaque_non_token68_credentials() -> anyhow::Result<()> {
        // Compatibility guard. `ApiKeyEntry::new` accepts an arbitrary
        // caller-supplied hash, so consumers may have hashed opaque tokens
        // using punctuation outside RFC 7235 `token68`. Narrowing this to a
        // strict token68 charset would silently 401 them on upgrade.
        assert_eq!(
            extract_bearer("Bearer aBc!@#$%^&*()"),
            Some("aBc!@#$%^&*()")
        );
        assert_eq!(extract_bearer("Bearer tok{en}|v1"), Some("tok{en}|v1"));
        Ok(())
    }

    /// Extract bearer accepts generated key and jwt shapes.
    #[test]
    fn extract_bearer_accepts_generated_key_and_jwt_shapes() -> anyhow::Result<()> {
        let (token, _hash) = generate_api_key()?;
        let header = format!("Bearer {token}");
        assert_eq!(extract_bearer(&header), Some(token.as_str()));

        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln-_bmF0dXJl";
        let jwt_header = format!("Bearer {jwt}");
        assert_eq!(extract_bearer(&jwt_header), Some(jwt));
        Ok(())
    }

    // -------------------------------------------------------------------
    // Debug redaction: ensure `AuthIdentity` and `ApiKeyEntry` never leak
    // secret material via `format!("{:?}", …)` or `tracing::debug!(?…)`.
    // -------------------------------------------------------------------

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_identity_debug_redacts_raw_token keeps the uniform test signature while it only asserts"
    )]
    /// Auth identity debug redacts raw token.
    #[test]
    fn auth_identity_debug_redacts_raw_token() -> anyhow::Result<()> {
        let id = AuthIdentity {
            name: "alice".into(),
            role: "admin".into(),
            method: AuthMethod::OAuthJwt,
            raw_token: Some(SecretString::from("super-secret-jwt-payload-xyz")),
            sub: Some("keycloak-uuid-2f3c8b".into()),
        };
        let dbg = format!("{id:?}");

        // Plaintext fields must be visible (they are not secrets).
        assert!(dbg.contains("alice"), "name should be visible: {dbg}");
        assert!(dbg.contains("admin"), "role should be visible: {dbg}");
        assert!(dbg.contains("OAuthJwt"), "method should be visible: {dbg}");

        // Secret fields must NOT leak.
        assert!(
            !dbg.contains("super-secret-jwt-payload-xyz"),
            "raw_token must be redacted in Debug output: {dbg}"
        );
        assert!(
            !dbg.contains("keycloak-uuid-2f3c8b"),
            "sub must be redacted in Debug output: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker missing: {dbg}"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_identity_debug_marks_absent_secrets keeps the uniform test signature while it only asserts"
    )]
    /// Auth identity debug marks absent secrets.
    #[test]
    fn auth_identity_debug_marks_absent_secrets() -> anyhow::Result<()> {
        // For non-OAuth identities (mTLS / API key) the secret fields are
        // None; redacted Debug output should distinguish that from "present".
        let id = AuthIdentity {
            name: "viewer-key".into(),
            role: "viewer".into(),
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        };
        let dbg = format!("{id:?}");
        assert!(
            dbg.contains("<none>"),
            "absent secrets should be marked: {dbg}"
        );
        assert!(
            !dbg.contains("<redacted>"),
            "no <redacted> marker when secrets are absent: {dbg}"
        );
        Ok(())
    }

    /// Api key entry debug redacts hash.
    #[test]
    fn api_key_entry_debug_redacts_hash() -> anyhow::Result<()> {
        let entry = ApiKeyEntry {
            name: "viewer-key".into(),
            // Realistic Argon2id PHC string (must NOT leak).
            hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$h4sh3dPa55w0rd".into(),
            role: "viewer".into(),
            expires_at: Some(RfcTimestamp::parse("2030-01-01T00:00:00Z")?),
        };
        let dbg = format!("{entry:?}");

        // Non-secret fields visible.
        assert!(dbg.contains("viewer-key"));
        assert!(dbg.contains("viewer"));
        assert!(dbg.contains("2030-01-01T00:00:00+00:00"));

        // Hash material must NOT leak.
        assert!(
            !dbg.contains("$argon2id$"),
            "argon2 hash leaked into Debug output: {dbg}"
        );
        assert!(
            !dbg.contains("h4sh3dPa55w0rd"),
            "hash digest leaked into Debug output: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker missing: {dbg}"
        );
        Ok(())
    }

    // -- AuthFailureClass exact-string contract tests --
    //
    // These tests pin the exact wire strings emitted for each failure
    // class. They exist to kill mutation-test mutants that replace the
    // match-arm string literals (e.g. with `""` or with the value from
    // another arm). Operators and dashboards rely on these literals
    // for metric labels and audit-log filters; any change is a
    // breaking observability change and must be reflected in
    // CHANGELOG.md.

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_failure_class_as_str_exact_strings keeps the uniform test signature while it only asserts"
    )]
    /// Auth failure class as str exact strings.
    #[test]
    fn auth_failure_class_as_str_exact_strings() -> anyhow::Result<()> {
        assert_eq!(
            AuthFailureClass::MissingCredential.as_str(),
            "missing_credential"
        );
        assert_eq!(
            AuthFailureClass::InvalidCredential.as_str(),
            "invalid_credential"
        );
        assert_eq!(
            AuthFailureClass::ExpiredCredential.as_str(),
            "expired_credential"
        );
        assert_eq!(AuthFailureClass::RateLimited.as_str(), "rate_limited");
        assert_eq!(AuthFailureClass::PreAuthGate.as_str(), "pre_auth_gate");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_failure_class_response_body_exact_strings keeps the uniform test signature while it only asserts"
    )]
    /// Auth failure class response body exact strings.
    #[test]
    fn auth_failure_class_response_body_exact_strings() -> anyhow::Result<()> {
        assert_eq!(
            AuthFailureClass::MissingCredential.response_body(),
            "unauthorized: missing credential"
        );
        assert_eq!(
            AuthFailureClass::InvalidCredential.response_body(),
            "unauthorized: invalid credential"
        );
        assert_eq!(
            AuthFailureClass::ExpiredCredential.response_body(),
            "unauthorized: expired credential"
        );
        assert_eq!(
            AuthFailureClass::RateLimited.response_body(),
            "rate limited"
        );
        assert_eq!(
            AuthFailureClass::PreAuthGate.response_body(),
            "rate limited (pre-auth)"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_failure_class_bearer_error_exact_strings keeps the uniform test signature while it only asserts"
    )]
    /// Auth failure class bearer error exact strings.
    #[test]
    fn auth_failure_class_bearer_error_exact_strings() -> anyhow::Result<()> {
        assert_eq!(
            AuthFailureClass::MissingCredential.bearer_error(),
            (
                "invalid_request",
                "missing bearer token or mTLS client certificate"
            )
        );
        assert_eq!(
            AuthFailureClass::InvalidCredential.bearer_error(),
            ("invalid_token", "token is invalid")
        );
        assert_eq!(
            AuthFailureClass::ExpiredCredential.bearer_error(),
            ("invalid_token", "token is expired")
        );
        assert_eq!(
            AuthFailureClass::RateLimited.bearer_error(),
            ("invalid_request", "too many failed authentication attempts")
        );
        assert_eq!(
            AuthFailureClass::PreAuthGate.bearer_error(),
            (
                "invalid_request",
                "too many unauthenticated requests from this source"
            )
        );
        Ok(())
    }

    // -- AuthConfig::summary boolean-flag contract tests --
    //
    // These tests pin the boolean flags emitted by `AuthConfig::summary`
    // so that mutations like deleting `!` (which would invert the
    // semantics of `bearer`) or replacing `is_some()` with `is_none()`
    // are caught immediately. The summary is consumed by `/admin/*`
    // diagnostics so any inversion is an operator-visible regression.

    /// Auth config summary bearer true when keys present.
    #[test]
    fn auth_config_summary_bearer_true_when_keys_present() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let cfg = AuthConfig::with_keys(vec![ApiKeyEntry::new("k", hash, "viewer")]);
        let summary = cfg.summary();
        assert!(
            summary.enabled,
            "summary.enabled must reflect AuthConfig.enabled"
        );
        assert!(
            summary.bearer,
            "summary.bearer must be true when api_keys is non-empty (kills `!` deletion at L615)"
        );
        assert!(
            !summary.mtls,
            "summary.mtls must be false when mtls is None"
        );
        assert!(
            !summary.oauth,
            "summary.oauth must be false when oauth is None"
        );
        assert_eq!(summary.api_keys.len(), 1);
        let first = summary
            .api_keys
            .first()
            .context("first API key must exist")?;
        assert_eq!(first.name, "k");
        assert_eq!(first.role, "viewer");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::auth_config_summary_bearer_false_when_no_keys keeps the uniform test signature while it only asserts"
    )]
    /// Auth config summary bearer false when no keys.
    #[test]
    fn auth_config_summary_bearer_false_when_no_keys() -> anyhow::Result<()> {
        let cfg = AuthConfig::with_keys(vec![]);
        let summary = cfg.summary();
        assert!(
            !summary.bearer,
            "summary.bearer must be false when api_keys is empty (kills `!` deletion at L615)"
        );
        assert!(summary.api_keys.is_empty());
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::seen_identity_set_first_then_repeat keeps the uniform test signature while it only asserts"
    )]
    /// Seen identity set first then repeat.
    #[test]
    fn seen_identity_set_first_then_repeat() -> anyhow::Result<()> {
        let set = SeenIdentitySet::new();
        assert!(set.insert_is_first("alice"), "first sighting is first");
        assert!(
            !set.insert_is_first("alice"),
            "second sighting is not first"
        );
        assert!(set.insert_is_first("bob"));
        assert_eq!(set.len(), 2);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::seen_identity_set_evicts_oldest_at_cap keeps the uniform test signature while it only asserts"
    )]
    /// Seen identity set evicts oldest at cap.
    #[test]
    fn seen_identity_set_evicts_oldest_at_cap() -> anyhow::Result<()> {
        let set = SeenIdentitySet::with_cap(2);
        assert!(set.insert_is_first("a"));
        assert!(set.insert_is_first("b"));
        // Cap reached; inserting "c" evicts "a".
        assert!(set.insert_is_first("c"));
        assert_eq!(set.len(), 2);
        // "a" was evicted, so it re-fires as "first" (matches the documented
        // bounded trade-off: re-INFO once on reappearance). Inserting "a"
        // here evicts "b" (next oldest), leaving {c, a}.
        assert!(set.insert_is_first("a"));
        assert_eq!(set.len(), 2);
        // "b" has now been evicted in turn, so it re-fires as "first" too.
        assert!(set.insert_is_first("b"));
        // Sanity: cap is never exceeded regardless of churn pattern.
        for i in 0..32_u32 {
            let _churn_seen = set.insert_is_first(&format!("churn-{i}"));
            assert!(set.len() <= 2, "cap invariant must hold");
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::seen_identity_set_cap_zero_is_raised_to_one keeps the uniform test signature while it only asserts"
    )]
    /// Seen identity set cap zero is raised to one.
    #[test]
    fn seen_identity_set_cap_zero_is_raised_to_one() -> anyhow::Result<()> {
        let set = SeenIdentitySet::with_cap(0);
        assert!(set.insert_is_first("only"));
        assert_eq!(set.len(), 1);
        // Next insert evicts "only".
        assert!(set.insert_is_first("next"));
        assert_eq!(set.len(), 1);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/auth.rs::seen_identity_set_fifo_does_not_refresh_on_repeat_hit keeps the uniform test signature while it only asserts"
    )]
    /// Seen identity set fifo does not refresh on repeat hit.
    #[test]
    fn seen_identity_set_fifo_does_not_refresh_on_repeat_hit() -> anyhow::Result<()> {
        // Locks in the FIFO contract: repeat hits MUST NOT bump an entry
        // to the back of the eviction queue (that would be LRU).
        let set = SeenIdentitySet::with_cap(2);
        assert!(set.insert_is_first("a")); // order=[a]
        assert!(set.insert_is_first("b")); // order=[a,b]
        // Repeat hit on "a" - if this were LRU, "a" would move to the back
        // and "b" would be the next eviction victim. Under FIFO, "a" stays
        // at the front (oldest by insertion).
        assert!(!set.insert_is_first("a"));
        // Insert "c" forces eviction. Under FIFO, "a" (oldest by insertion)
        // is evicted; "b" survives. Under LRU, "b" would have been evicted.
        assert!(set.insert_is_first("c"));
        // Prove "a" was evicted: re-inserting fires as first again.
        assert!(set.insert_is_first("a"));
        // Prove "b" was NOT evicted: re-inserting does NOT fire as first.
        // (If LRU semantics had snuck in, this assertion would fail.)
        // After the previous step, "a" eviction pushed out "b" as the new
        // oldest, so we must re-add "b" via a fresh insert path. To keep
        // the test deterministic we rebuild a small scenario:
        let rebuilt = SeenIdentitySet::with_cap(2);
        assert!(rebuilt.insert_is_first("x")); // order=[x]
        assert!(rebuilt.insert_is_first("y")); // order=[x,y]
        assert!(!rebuilt.insert_is_first("x")); // repeat hit (under FIFO: order unchanged)
        assert!(rebuilt.insert_is_first("z")); // evicts "x" under FIFO
        assert!(
            !rebuilt.insert_is_first("y"),
            "y must still be present (FIFO did not evict it)"
        );
        assert!(
            rebuilt.insert_is_first("x"),
            "x must have been evicted by FIFO (would NOT have been evicted under LRU)"
        );
        Ok(())
    }
}
