//! OAuth 2.1 JWT bearer token validation with JWKS caching.
//!
//! When enabled, Bearer tokens that look like JWTs (three base64-separated
//! segments with a valid JSON header containing `"alg"`) are validated
//! against a JWKS fetched from the configured Authorization Server.
//! Token scopes are mapped to RBAC roles via explicit configuration.
//!
//! ## OAuth 2.1 Proxy
//!
//! When `OAuthConfig::proxy` is set, the MCP server acts as an OAuth 2.1
//! authorization server facade, proxying `/authorize` and `/token` to an
//! upstream identity provider (e.g. Keycloak).  MCP clients discover this server as the
//! authorization server via Protected Resource Metadata (RFC 9728) and
//! perform the standard Authorization Code + PKCE flow transparently.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    fmt,
    hint::cold_path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{collections::HashMap, fs, path::PathBuf, time::Instant};

use axum::{http::StatusCode, response::Response};
use base64::engine::general_purpose;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    crypto::rust_crypto::DEFAULT_PROVIDER,
    decode, decode_header,
    errors::ErrorKind,
    jwk::{Jwk, JwkSet, KeyAlgorithm},
};
use reqwest::{
    dns::Resolve,
    redirect::{Attempt, Policy},
    tls::Certificate,
};
use rustls::crypto::ring::default_provider;
use serde::Deserialize;
use tokio::{
    net::lookup_host,
    sync::{Mutex, RwLock, oneshot, oneshot::error::RecvError},
    task::spawn_blocking,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, dispatcher};
use url::form_urlencoded;

use crate::{
    auth::{AuthIdentity, AuthMethod, CredentialOwner, RejectionReason},
    cancel::DetachOutcome,
    diagnostics::{oauth_claim_values, plaintext_oauth_tokens, upstream_error_bodies},
    error::RmcpServerKitError,
    ssrf::{
        CidrEntry, CompiledSsrfAllowlist, check_url_literal_ip, ip_block_reason,
        redirect_target_reason_with_allowlist, sanitized_url_for_log,
    },
    ssrf_resolver::{SsrfScreeningResolver, TestLoopbackBypass},
};

// ---------------------------------------------------------------------------
// Shared OAuth redirect-policy helper
// ---------------------------------------------------------------------------

/// Outcome of evaluating a single OAuth redirect hop against the
/// shared policy used by both [`OauthHttpClient::build`] and
/// [`JwksCache::new`].
///
/// `Ok(())` means the redirect should be followed; `Err(reason)` means
/// the closure should reject it. Callers are responsible for emitting
/// the `tracing::warn!` rejection log so the policy stays a pure
/// function (no I/O, no logging) and so the closures keep their
/// cognitive complexity below the crate-wide clippy threshold.
///
/// The policy mirrors the documented behaviour exactly:
///   1. `https -> http` redirect downgrades are *always* rejected.
///   2. Non-`https` targets are accepted only when `allow_http` is true
///      *and* the destination scheme is `http`.
///   3. Targets resolving to disallowed IP ranges (private / loopback /
///      link-local / multicast / broadcast / unspecified /
///      cloud-metadata) are rejected via
///      [`crate::ssrf::redirect_target_reason_with_allowlist`], which
///      consults the operator-supplied allowlist while keeping
///      cloud-metadata addresses unbypassable.
///   4. The hop count is capped at 2 (i.e. at most 2 prior redirects).
///
/// # Errors
///
/// Returns the rejection reason when the redirect must not be followed.
fn evaluate_oauth_redirect(
    attempt: &Attempt<'_>,
    allow_http: bool,
    allowlist: &CompiledSsrfAllowlist,
) -> Result<(), String> {
    let prev_https = attempt
        .previous()
        .last()
        .is_some_and(|prev| prev.scheme() == "https");
    let target_url = attempt.url();
    let dest_scheme = target_url.scheme();
    if dest_scheme != "https" {
        if prev_https {
            return Err("redirect downgrades https -> http".to_owned());
        }
        if !allow_http || dest_scheme != "http" {
            return Err("redirect to non-HTTP(S) URL refused".to_owned());
        }
    }
    if let Some(reason) = redirect_target_reason_with_allowlist(target_url, allowlist) {
        return Err(format!("redirect target forbidden: {reason}"));
    }
    if attempt.previous().len() >= 2 {
        return Err("too many redirects (max 2)".to_owned());
    }
    Ok(())
}

/// True when `host` ends in a well-known internal suffix and is not allow-listed.
///
/// The suffixes are `.localhost`, `.local` and `.internal`. A trailing FQDN-root
/// dot is canonicalized first so `idp.internal.` cannot bypass the check. OAuth
/// targets only -- CRL fetches build an empty allowlist and are out of scope.
///
/// Exact `localhost` is deliberately NOT matched here: it resolves to
/// loopback and is already blocked by the post-DNS IP screen, and an
/// operator may legitimately reach a local IdP via an explicit loopback
/// CIDR allowlist.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "these are DNS-name suffixes on an already-lowercased host, not file extensions"
)]
fn oauth_internal_suffix_blocked(host: &str, allowlist: &CompiledSsrfAllowlist) -> bool {
    let host_canon = host.strip_suffix('.').unwrap_or(host);
    let host_lower = host_canon.to_ascii_lowercase();
    let is_internal = host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal");
    // Blocked when internal, unless the exact host is in a non-empty allowlist.
    is_internal && (allowlist.is_empty() || !allowlist.host_allowed(host_canon))
}

/// Screen an OAuth/JWKS target before the initial outbound connect.
///
/// This complements the per-redirect-hop guard in
/// [`evaluate_oauth_redirect`]: redirects are screened synchronously via
/// [`crate::ssrf::redirect_target_reason_with_allowlist`], while the
/// initial request target is screened here after DNS resolution so
/// hostnames resolving to loopback/private/link-local/metadata space
/// are rejected before any TCP dial occurs.
///
/// **Cloud-metadata addresses (IPv4 `169.254.169.254`, Alibaba/Tencent
/// `100.100.100.200`, AWS IPv6 `fd00:ec2::254`, GCP IPv6
/// `fd20:ce::254`) are blocked unconditionally** -- the operator
/// allowlist cannot re-allow them.
///
/// This single core is compiled identically under ALL cfgs, so the test
/// suite always exercises the exact code production runs. Production
/// callers go through [`screen_oauth_target`], which hardcodes
/// `test_allow_loopback_ssrf = false`; the test-only bypass wrapper is
/// [`screen_oauth_target_with_test_override`].
// cancel-safe: performs DNS resolution and pure screening, publishing no
// shared state; cancellation just discards the verdict.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the target URL is malformed or resolves to a
/// blocked address.
async fn screen_oauth_target_core(
    url: &str,
    allow_http: bool,
    allowlist: &CompiledSsrfAllowlist,
    test_allow_loopback_ssrf: bool,
) -> Result<(), RmcpServerKitError> {
    let target = oauth_request_target_for_log(url);
    let parsed = check_oauth_url("oauth target", url, allow_http)?;
    if test_allow_loopback_ssrf {
        return Ok(());
    }
    if let Some(reason) = check_url_literal_ip(&parsed) {
        return Err(RmcpServerKitError::Config(format!(
            "OAuth target forbidden ({reason}): {target}"
        )));
    }

    let host = parsed.host_str().ok_or_else(|| {
        RmcpServerKitError::Config(format!("OAuth target URL has no host: {target}"))
    })?;
    if oauth_internal_suffix_blocked(host, allowlist) {
        return Err(RmcpServerKitError::Config(format!(
            "OAuth target forbidden (internal hostname suffix): {target}"
        )));
    }
    let port = parsed.port_or_known_default().ok_or_else(|| {
        RmcpServerKitError::Config(format!("OAuth target URL has no known port: {target}"))
    })?;

    let addrs = lookup_host((host, port)).await.map_err(|error| {
        RmcpServerKitError::Config(format!("OAuth target DNS resolution {target}: {error}"))
    })?;

    let host_allowed = !allowlist.is_empty() && allowlist.host_allowed(host);
    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        let ip = addr.ip();
        if let Some(reason) = ip_block_reason(ip) {
            // Cloud-metadata is unbypassable. Use the strict message
            // that does NOT advertise the allowlist knob.
            if reason == "cloud_metadata" {
                return Err(RmcpServerKitError::Config(format!(
                    "OAuth target resolved to blocked IP ({reason}): {target}"
                )));
            }
            // Default-empty-allowlist path: preserve the historical
            // message verbatim so existing tests continue to pass and
            // operators get the same diagnostic they had before.
            if allowlist.is_empty() {
                return Err(RmcpServerKitError::Config(format!(
                    "OAuth target resolved to blocked IP ({reason}): {target}"
                )));
            }
            // Allowlist-configured path: consult host + per-IP allowlist.
            if host_allowed || allowlist.ip_allowed(ip) {
                continue;
            }
            return Err(RmcpServerKitError::Config(format!(
                "OAuth target blocked: hostname {host} resolved to {ip} ({reason}). \
                 To allow, add the hostname to oauth.ssrf_allowlist.hosts or the CIDR \
                 to oauth.ssrf_allowlist.cidrs (operators only -- see SECURITY.md). \
                 URL: {target}"
            )));
        }
    }
    if !any_addr {
        return Err(RmcpServerKitError::Config(format!(
            "OAuth target DNS resolution returned no addresses: {target}"
        )));
    }

    Ok(())
}

/// Production entry point for OAuth/JWKS target screening. Delegates to
/// [`screen_oauth_target_core`] with the loopback bypass hardcoded off.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the target URL is malformed or resolves to a
/// blocked address.
async fn screen_oauth_target(
    url: &str,
    allow_http: bool,
    allowlist: &CompiledSsrfAllowlist,
) -> Result<(), RmcpServerKitError> {
    screen_oauth_target_core(url, allow_http, allowlist, false).await
}

/// Test-only wrapper exposing the loopback-SSRF bypass flag of
/// [`screen_oauth_target_core`] so higher-level OAuth flows can run
/// against loopback-backed mock fixtures.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the target URL is malformed or resolves to a
/// blocked address.
#[cfg(any(test, feature = "test-helpers"))]
async fn screen_oauth_target_with_test_override(
    url: &str,
    allow_http: bool,
    allowlist: &CompiledSsrfAllowlist,
    test_allow_loopback_ssrf: bool,
) -> Result<(), RmcpServerKitError> {
    screen_oauth_target_core(url, allow_http, allowlist, test_allow_loopback_ssrf).await
}

// ---------------------------------------------------------------------------
// HTTP client wrapper
// ---------------------------------------------------------------------------

/// HTTP client used by [`exchange_token`] and the OAuth 2.1 proxy
/// handlers ([`handle_token`], [`handle_introspect`], [`handle_revoke`]).
///
/// Wraps an internal HTTP backend so callers do not depend on the
/// concrete crate. Construct one per process and reuse across requests
/// (the underlying connection pool is shared internally via
/// [`Clone`] - cheap, refcounted).
///
/// **Hardening (since 1.2.1).** When constructed via [`with_config`]
/// (preferred), the internal client refuses any redirect that downgrades
/// the scheme from `https` to `http`, even when the original request URL
/// was HTTPS. This closes a class of metadata-poisoning attacks where a
/// hostile or compromised upstream `IdP` returns `302 Location: http://...`
/// and the resulting plaintext hop is intercepted by a network-positioned
/// attacker to siphon bearer tokens, refresh tokens, or introspection
/// traffic. When the caller has set [`OAuthConfig::allow_http_oauth_urls`]
/// to `true` (development only), HTTP-to-HTTP redirects are still permitted
/// but HTTPS-to-HTTP downgrades are *always* rejected.
///
/// [`with_config`] also honours [`OAuthConfig::ca_cert_path`] (if set) and
/// adds the supplied PEM CA bundle to the system roots so that
/// every OAuth-bound HTTP request -- not just the JWKS fetch -- can
/// trust enterprise/internal certificate authorities. This restores
/// the behaviour that existed pre-`0.10.0` before the `OauthHttpClient`
/// wrapper landed.
///
/// The legacy [`new`](Self::new) constructor (no-arg) is preserved for
/// source compatibility but is `#[deprecated]`: it returns a client with
/// system-roots-only TLS trust and the strictest redirect policy
/// (HTTPS-only, never permits plain HTTP). Migrate to
/// [`with_config`](Self::with_config) at the earliest opportunity so
/// that token / introspection / revocation / exchange traffic inherits
/// the same CA trust and `allow_http_oauth_urls` toggle as the JWKS
/// fetch client.
///
/// [`with_config`]: Self::with_config
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
#[derive(Clone)]
pub struct OauthHttpClient {
    /// Screened-redirect JWKS/discovery client: follows redirects, but every
    /// hop passes `evaluate_oauth_redirect`. Post-M7 production credential
    /// traffic uses `credential_client` and JWKS fetching uses `JwksCache`,
    /// so nothing in a production build reads this field; it exists only to
    /// back the redirect-policy regression tests (`__test_get`,
    /// `__test_inner_client`, `jwks_get_still_follows_screened_redirect`),
    /// which are themselves `cfg`-gated to the same predicate.
    #[cfg(any(test, feature = "test-helpers"))]
    inner: reqwest::Client,
    /// M7: dedicated client for credential-bearing POSTs (token /
    /// introspection / revocation / RFC 8693 exchange). Built with
    /// `redirect::Policy::none()` so a 307/308 from a compromised or
    /// open-redirecting endpoint cannot re-send the `client_secret`
    /// body to another host. Shares `inner`'s `no_proxy`,
    /// `SsrfScreeningResolver`, and CA trust.
    credential_client: reqwest::Client,
    /// Whether plain-HTTP OAuth URLs are permitted ([`OAuthConfig::allow_http_oauth_urls`]).
    allow_http: bool,
    /// Compiled SSRF allowlist applied to the initial-target screen and
    /// to literal-IP redirect-hop screening. Wrapped in `Arc` so cloning
    /// the client (which is cheap and refcounted) does not deep-copy
    /// the parsed CIDR / host vectors.
    allowlist: Arc<CompiledSsrfAllowlist>,
    /// M-H4: per-`(cert_path, key_path)` cache of cert-bearing
    /// `reqwest::Client`s. Built eagerly with `redirect::Policy::none()`
    /// so an attacker-controlled 3xx cannot re-present the client cert
    /// to a different host (RFC 8705 §2 attack surface).
    #[cfg(feature = "oauth-mtls-client")]
    mtls_clients: Arc<HashMap<MtlsClientKey, reqwest::Client>>,
    /// M-H2: shared loopback bypass observed by both `send_screened`'s
    /// pre-flight check AND the `SsrfScreeningResolver` installed on
    /// `inner`. Flipping the bit via `__test_allow_loopback_ssrf` must
    /// reach the already-built `reqwest::Client`, so a per-snapshot
    /// `bool` (Oracle review B1) is forbidden.
    #[cfg(any(test, feature = "test-helpers"))]
    test_allow_loopback_ssrf: TestLoopbackBypass,
}

/// M-H4: cache key for cert-bearing `reqwest::Client`s. Path-based
/// (not contents-based) -- in-place cert rotation is not picked up
/// without restart (documented limitation in `CHANGELOG.md` 1.6.0).
#[cfg(feature = "oauth-mtls-client")]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct MtlsClientKey {
    /// Path to the PEM client certificate presented at the TLS handshake.
    cert_path: PathBuf,
    /// Path to the PEM private key for `cert_path`.
    key_path: PathBuf,
}

impl OauthHttpClient {
    /// Build a client from the OAuth configuration (preferred since 1.2.1).
    ///
    /// Defaults: `connect_timeout = 10s`, total `timeout = 30s`,
    /// scheme-downgrade-rejecting redirect policy (max 2 hops),
    /// optional custom CA trust via [`OAuthConfig::ca_cert_path`],
    /// and HTTP-to-HTTP redirects gated by
    /// [`OAuthConfig::allow_http_oauth_urls`] (dev-only).
    ///
    /// Pass the same `&OAuthConfig` you supplied to
    /// [`JwksCache::new`] / `serve()` so the OAuth-bound HTTP traffic
    /// inherits identical CA trust and HTTPS-only redirect policy.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::RmcpServerKitError::Startup`] if the configured
    /// `ca_cert_path` cannot be read or parsed, or if the underlying
    /// HTTP client cannot be constructed (e.g. TLS backend init failure).
    #[inline]
    pub fn with_config(config: &OAuthConfig) -> Result<Self, RmcpServerKitError> {
        Self::build(Some(config))
    }

    /// Build a client with default settings (system CA roots only,
    /// strict HTTPS-only redirect policy).
    ///
    /// **Deprecated since 1.2.1.** This constructor cannot honour
    /// [`OAuthConfig::ca_cert_path`] (so token / introspection /
    /// revocation / exchange traffic falls back to the system trust
    /// store, breaking enterprise PKI deployments) and ignores the
    /// [`OAuthConfig::allow_http_oauth_urls`] dev-mode toggle (so
    /// HTTP-to-HTTP redirects are unconditionally refused). Both of
    /// these are bugs that the new [`with_config`](Self::with_config)
    /// constructor fixes.
    ///
    /// The redirect policy still rejects `https -> http` downgrades,
    /// matching the security posture of [`with_config`](Self::with_config).
    ///
    /// Migrate to [`with_config`](Self::with_config) and pass the same
    /// `&OAuthConfig` your `serve()` call uses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::RmcpServerKitError::Startup`] if the underlying
    /// HTTP client cannot be constructed (e.g. TLS backend init failure).
    #[deprecated(
        since = "1.2.1",
        note = "use OauthHttpClient::with_config(&OAuthConfig) so token/introspect/revoke/exchange traffic inherits ca_cert_path and the allow_http_oauth_urls toggle"
    )]
    #[inline]
    pub fn new() -> Result<Self, RmcpServerKitError> {
        Self::build(None)
    }

    /// Internal builder shared by [`new`](Self::new) (config = `None`)
    /// and [`with_config`](Self::with_config) (config = `Some`).
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: src/oauth.rs::OauthHttpClient::build keeps shared client construction in one reviewable block"
    )]
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Startup`] when the CA bundle cannot be read or parsed or a
    /// client cannot be constructed.
    fn build(config: Option<&OAuthConfig>) -> Result<Self, RmcpServerKitError> {
        // Install the rustls crypto provider before constructing any reqwest
        // client (idempotent -- `ok()` ignores the error when a provider was
        // already installed elsewhere in the process). Without this a
        // standalone `OauthHttpClient::new`/`with_config` built before
        // `JwksCache::new` or TLS setup would panic inside reqwest with
        // "no rustls crypto provider is configured".
        drop(default_provider().install_default());

        let allow_http = config.is_some_and(|cfg| cfg.allow_http_oauth_urls);

        // Compile the operator SSRF allowlist (if any) up front. Surface
        // CIDR / host parse errors as Startup so misconfiguration fails
        // fast at server boot, mirroring how OAuthConfig::validate
        // surfaces them as Config errors.
        let allowlist = match config.and_then(|cfg| cfg.ssrf_allowlist.as_ref()) {
            Some(raw) => Arc::new(compile_oauth_ssrf_allowlist(raw).map_err(|error| {
                RmcpServerKitError::Startup(format!("oauth http client: {error}"))
            })?),
            None => Arc::new(CompiledSsrfAllowlist::default()),
        };

        // Clone an Arc into the redirect closure so the policy can
        // consult the operator allowlist without re-parsing. Only the
        // screened-redirect `inner` client needs it, so it shares that
        // client's cfg gate.
        #[cfg(any(test, feature = "test-helpers"))]
        let redirect_allowlist = Arc::clone(&allowlist);

        // M-H2: shared bypass holder created BEFORE the resolver so
        // the resolver, send_screened, and the cached `inner` client
        // all observe the same atomic.
        #[cfg(any(test, feature = "test-helpers"))]
        let test_bypass: TestLoopbackBypass = Arc::new(AtomicBool::new(false));
        #[cfg(not(any(test, feature = "test-helpers")))]
        #[expect(
            clippy::cfg_not_test,
            reason = "deliberate: src/oauth.rs::build keeps the test-helpers alias arm cfg-gated"
        )]
        let test_bypass: TestLoopbackBypass = ();

        // M-H2/B1: TestLoopbackBypass aliases to Arc<AtomicBool> in test
        // builds and to `()` in production. The `.clone()` is required in
        // test builds; in production the alias is a unit, which is why the
        // unit-value lints are allowed alongside the Arc one.
        #[cfg_attr(
            any(
                not(feature = "oauth"),
                all(not(test), not(feature = "oauth-mtls-client"))
            ),
            expect(
                clippy::clone_on_copy,
                clippy::unit_arg,
                reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
            )
        )]
        #[cfg_attr(
            any(not(feature = "oauth"), test, feature = "metrics"),
            expect(
                clippy::clone_on_ref_ptr,
                reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
            )
        )]
        let resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
            Arc::clone(&allowlist),
            test_bypass.clone(),
        ));

        // Read the optional CA bundle once; reused by both clients below.
        // Pre-startup blocking I/O is intentional -- the constructor is sync
        // by contract and runs from `serve()`'s pre-startup phase.
        let ca_pem: Option<Vec<u8>> = if let Some(cfg) = config
            && let Some(ca_path) = &cfg.ca_cert_path
        {
            Some(fs::read(ca_path).map_err(|error| {
                RmcpServerKitError::Startup(format!(
                    "oauth http client: read ca_cert_path {}: {error}",
                    ca_path.display()
                ))
            })?)
        } else {
            None
        };

        // Base builder shared by both clients: `no_proxy` (so HTTP(S)_PROXY
        // env vars cannot bypass the SsrfScreeningResolver), the SSRF
        // resolver, timeouts, and CA trust. Only the redirect policy differs.
        let make_base = || -> Result<reqwest::ClientBuilder, RmcpServerKitError> {
            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::clone(&resolver))
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30));
            if let Some(pem) = &ca_pem {
                let cert = Certificate::from_pem(pem).map_err(|error| {
                    RmcpServerKitError::Startup(format!(
                        "oauth http client: parse ca_cert_path: {error}"
                    ))
                })?;
                builder = builder.add_root_certificate(cert);
            }
            Ok(builder)
        };

        // JWKS / discovery client: follows redirects, but every hop is screened
        // by `evaluate_oauth_redirect` (https->http downgrade, literal-IP
        // target, and userinfo are all rejected). Production reads JWKS via
        // `JwksCache` and credentials via `credential_client`, so this client
        // backs only the redirect-policy regression tests and is not built in
        // a minimal `oauth` build.
        #[cfg(any(test, feature = "test-helpers"))]
        let inner = make_base()?
            .redirect(Policy::custom(
                move |attempt| match evaluate_oauth_redirect(
                    &attempt,
                    allow_http,
                    &redirect_allowlist,
                ) {
                    Ok(()) => attempt.follow(),
                    Err(reason) => {
                        tracing::warn!(
                            reason = %reason,
                            target = %sanitized_url_for_log(attempt.url()),
                            "oauth redirect rejected"
                        );
                        attempt.error(reason)
                    }
                },
            ))
            .build()
            .map_err(|error| {
                RmcpServerKitError::Startup(format!("oauth http client init: {error}"))
            })?;

        // M7: credential-POST client -- NEVER follows redirects. A 307/308 from
        // a compromised or open-redirecting token/introspection/revocation
        // endpoint must not re-send the `client_secret`-bearing body to another
        // host (RFC 8705 §2). Mirrors the `Policy::none()` mTLS cert clients.
        //
        // Shares the "oauth http client init" error label with the gated
        // `inner` build above: both consume the same `make_base()` config, so
        // a `ClientBuilder::build()` failure is a shared TLS-backend fault
        // rather than a property of either client. Using one label keeps the
        // operator-visible startup error identical whether or not `inner` is
        // compiled in. Genuine misconfiguration (allowlist, ca_cert_path read
        // and parse) is already reported by `make_base()` itself.
        let credential_client = make_base()?
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                RmcpServerKitError::Startup(format!("oauth http client init: {error}"))
            })?;

        #[cfg(feature = "oauth-mtls-client")]
        let mtls_clients = build_mtls_clients(config, &allowlist, &test_bypass)?;

        Ok(Self {
            #[cfg(any(test, feature = "test-helpers"))]
            inner,
            credential_client,
            allow_http,
            allowlist,
            #[cfg(feature = "oauth-mtls-client")]
            mtls_clients,
            #[cfg(any(test, feature = "test-helpers"))]
            test_allow_loopback_ssrf: test_bypass,
        })
    }

    /// Screen `url` against the SSRF policy, then send the prepared request.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] when screening rejects the target or the send fails.
    // cancel-safe: SSRF screening only reads allowlist/config; `reqwest` owns
    // the request during `send`, so cancellation abandons upstream I/O without
    // mutating OAuth client or JWKS cache state.
    async fn send_screened(
        &self,
        url: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, RmcpServerKitError> {
        #[cfg(any(test, feature = "test-helpers"))]
        if self.test_allow_loopback_ssrf.load(Ordering::Relaxed) {
            screen_oauth_target_with_test_override(url, self.allow_http, &self.allowlist, true)
                .await?;
        } else {
            screen_oauth_target(url, self.allow_http, &self.allowlist).await?;
        }
        #[cfg(not(any(test, feature = "test-helpers")))]
        #[expect(
            clippy::cfg_not_test,
            reason = "deliberate: src/oauth.rs::send_screened keeps the test-helpers alias arm cfg-gated"
        )]
        screen_oauth_target(url, self.allow_http, &self.allowlist).await?;
        request.send().await.map_err(|error| {
            let target = oauth_request_target_for_log(url);
            let scrubbed = error.without_url();
            RmcpServerKitError::Config(format!("oauth request {target}: {scrubbed}"))
        })
    }

    /// Test-only: disable initial-target SSRF screening for loopback-backed
    /// fixtures. This is unreachable from normal production builds and exists
    /// only so tests can exercise higher-level OAuth flows against local mock
    /// servers.
    ///
    /// # ⚠️ Security
    ///
    /// Disables the OAuth SSRF guard's loopback rejection, allowing requests to
    /// loopback-backed targets that production OAuth screening would reject.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn __test_allow_loopback_ssrf(self) -> Self {
        // M-H2/B1: flip the SHARED atomic so the resolver inside
        // `inner` and the pre-flight check both observe the bypass.
        self.test_allow_loopback_ssrf.store(true, Ordering::Relaxed);
        self
    }

    /// Test-only: issue a `GET` against an arbitrary URL using the
    /// configured client (redirect policy, CA trust, timeouts all
    /// applied). Used by integration tests to exercise the redirect-
    /// downgrade and CA-trust regressions without going through
    /// `exchange_token`. Not part of the public API.
    ///
    /// # ⚠️ Security
    ///
    /// Calls `self.inner.get(url).send()` directly, bypassing `send_screened`
    /// and its initial-target SSRF and scheme checks for caller-supplied URLs.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub async fn __test_get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        self.inner.get(url).send().await
    }

    /// Test-only: borrow the inner `reqwest::Client` so the M-H2
    /// env-proxy matrix test (`tests/integration/e2e.rs::ssrf_no_proxy_*`) can
    /// drive `.get(...).send()` directly and observe whether the
    /// SsrfScreeningResolver fired (vs. the proxy short-circuiting
    /// the request). Not part of the public API.
    ///
    /// # ⚠️ Security
    ///
    /// Exposes the raw `reqwest::Client`, enabling callers to bypass
    /// `send_screened` and its initial-target SSRF and scheme checks.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    #[inline]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    pub fn __test_inner_client(&self) -> &reqwest::Client {
        &self.inner
    }

    /// M-H4: select the cert-bearing `reqwest::Client` cached for
    /// `cfg.client_cert`'s paths, else the shared no-redirect
    /// `credential_client`. Defence-in-depth: a missing cache entry falls
    /// through to `credential_client`; combined with the Authorization-header
    /// skip in `exchange_token`, this surfaces as an upstream auth failure
    /// rather than silent secret-bearer fallback.
    #[cfg(feature = "oauth-mtls-client")]
    fn client_for(&self, cfg: &TokenExchangeConfig) -> &reqwest::Client {
        if let Some(cc) = &cfg.client_cert {
            let key = MtlsClientKey {
                cert_path: cc.cert_path.clone(),
                key_path: cc.key_path.clone(),
            };
            if let Some(client) = self.mtls_clients.get(&key) {
                return client;
            }
        }
        &self.credential_client
    }

    /// Select the credential-bearing client; the mTLS cache is compiled out.
    #[cfg(not(feature = "oauth-mtls-client"))]
    const fn client_for(&self, _cfg: &TokenExchangeConfig) -> &reqwest::Client {
        &self.credential_client
    }
}

impl fmt::Debug for OauthHttpClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OauthHttpClient").finish_non_exhaustive()
    }
}

/// Sanitize a URL for logs: drop userinfo, query, and fragment, or return a placeholder when
/// unparseable.
fn oauth_request_target_for_log(raw: &str) -> String {
    url::Url::parse(raw).map_or_else(
        |_| "<unparseable-url>".to_owned(),
        |url| sanitized_url_for_log(&url),
    )
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Operator-trusted SSRF allowlist for OAuth/JWKS targets that resolve
/// to addresses normally blocked by the post-DNS SSRF guard.
///
/// **Default: empty.** With both fields empty (or this struct unset),
/// the existing fail-closed behavior is unchanged: any OAuth/JWKS URL
/// resolving to RFC 1918, loopback, link-local, CGNAT, multicast,
/// broadcast, unspecified, IPv6 unique-local / link-local / multicast,
/// documentation, benchmarking, or reserved ranges is rejected before
/// connect.
///
/// **Cloud-metadata addresses remain unbypassable** -- operators
/// cannot opt in to metadata-service exposure. This carve-out covers:
///
/// - IPv4 `169.254.169.254` (AWS / GCP / Azure).
/// - IPv4 `100.100.100.200` (Alibaba Cloud / Tencent Cloud).
/// - IPv6 `fd00:ec2::254` (AWS IMDSv2 over IPv6).
/// - IPv6 `fd20:ce::254` (GCP).
///
/// See `SECURITY.md` § "Operator allowlist".
///
/// Both lists are evaluated additively: a target is allowed if its
/// hostname is in [`hosts`](Self::hosts) **or** every resolved IP for
/// the target falls within at least one CIDR in [`cidrs`](Self::cidrs).
///
/// The allowlist applies to all six configured OAuth URL fields
/// ([`OAuthConfig::issuer`], [`OAuthConfig::jwks_uri`],
/// [`OAuthProxyConfig::authorize_url`], [`OAuthProxyConfig::token_url`],
/// [`OAuthProxyConfig::introspection_url`],
/// [`OAuthProxyConfig::revocation_url`],
/// [`TokenExchangeConfig::token_url`]) and to the per-redirect-hop
/// SSRF guard when a redirect target is a literal IP in a configured
/// CIDR.
///
/// Entries are validated at startup: literal IPs in `hosts`, non-zero
/// host bits in `cidrs`, malformed CIDRs, and entries containing
/// ports / userinfo / paths are all rejected by
/// [`OAuthConfig::validate`].
///
/// # Example
///
/// ```no_run
/// use rmcp_server_kit::oauth::{OAuthConfig, OAuthSsrfAllowlist};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut allowlist = OAuthSsrfAllowlist::default();
/// allowlist.hosts.push("rhbk.ops.example.com".into());
/// allowlist.cidrs.push("10.0.0.0/8".into());
/// let cfg = OAuthConfig::builder(
///     "https://rhbk.ops.example.com/realms/ops",
///     "mcp",
///     "https://rhbk.ops.example.com/realms/ops/protocol/openid-connect/certs",
/// )
/// .ssrf_allowlist(allowlist)
/// .build();
/// cfg.validate()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OAuthSsrfAllowlist {
    /// Hostnames allowed to resolve into otherwise-blocked address
    /// ranges. Exact match, case-insensitive, no wildcards. Each entry
    /// must be a bare DNS hostname: no scheme, no port, no userinfo,
    /// not a literal IP.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// CIDR blocks whose addresses are considered trusted even when
    /// the address would otherwise be blocked. Accepts both IPv4
    /// (e.g. `10.0.0.0/8`) and IPv6 (e.g. `fd00::/8`).
    ///
    /// Cloud-metadata addresses inside any listed range remain blocked.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// Compile and validate an operator allowlist into the runtime form.
///
/// Lowercases hostnames, rejects literal-IP and ill-formed host
/// entries, parses + validates each CIDR (see [`crate::ssrf::CidrEntry::parse`]).
/// Returns a `String` error suitable for embedding in
/// [`crate::error::RmcpServerKitError::Config`] / [`crate::error::RmcpServerKitError::Startup`].
///
/// # Errors
///
/// Returns the first invalid host or CIDR entry as a message.
fn compile_oauth_ssrf_allowlist(raw: &OAuthSsrfAllowlist) -> Result<CompiledSsrfAllowlist, String> {
    let mut hosts: Vec<String> = Vec::with_capacity(raw.hosts.len());
    for (idx, entry) in raw.hosts.iter().enumerate() {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(format!("oauth.ssrf_allowlist.hosts[{idx}]: empty entry"));
        }
        // Reject embedded port / path / userinfo / query / fragment
        // before reaching the URL parser, so the error is clearer than
        // a generic "invalid host" diagnostic.
        if trimmed.contains([':', '/', '@', '?', '#']) {
            return Err(format!(
                "oauth.ssrf_allowlist.hosts[{idx}] = {trimmed:?}: must be a bare DNS hostname \
                 (no scheme, port, path, userinfo, query, or fragment)"
            ));
        }
        match url::Host::parse(trimmed) {
            Ok(url::Host::Domain(_)) => {}
            Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => {
                return Err(format!(
                    "oauth.ssrf_allowlist.hosts[{idx}] = {trimmed:?}: literal IPs are forbidden \
                     here -- list them via oauth.ssrf_allowlist.cidrs instead"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "oauth.ssrf_allowlist.hosts[{idx}] = {trimmed:?}: invalid hostname: {error}"
                ));
            }
        }
        hosts.push(trimmed.to_ascii_lowercase());
    }
    hosts.sort();
    hosts.dedup();

    let mut cidrs = Vec::with_capacity(raw.cidrs.len());
    for (idx, entry) in raw.cidrs.iter().enumerate() {
        let parsed = CidrEntry::parse(entry)
            .map_err(|error| format!("oauth.ssrf_allowlist.cidrs[{idx}]: {error}"))?;
        cidrs.push(parsed);
    }

    Ok(CompiledSsrfAllowlist::new(hosts, cidrs))
}

/// OAuth 2.1 JWT configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OAuthConfig {
    /// Token issuer (`iss` claim). Must match exactly.
    ///
    /// `#[serde(default)]` so a partially-specified `[oauth]` table - one that
    /// carries only `role_claim`/`role_mappings`, with the URL and audience
    /// fields supplied by a downstream env-override layer applied after TOML
    /// parsing - still deserializes. An empty value is rejected at
    /// [`OAuthConfig::validate`] time (parse-don't-validate): the HTTPS URL
    /// check fails on an empty string.
    #[serde(default)]
    pub issuer: String,
    /// Expected audience (`aud` claim). Must match exactly.
    ///
    /// Defaulted like [`OAuthConfig::issuer`]. Unlike the URL fields it is not
    /// a URL, so [`OAuthConfig::validate`] guards it with an explicit
    /// non-empty check.
    #[serde(default)]
    pub audience: String,
    /// JWKS endpoint URL (e.g. `https://auth.example.com/.well-known/jwks.json`).
    ///
    /// Defaulted like [`OAuthConfig::issuer`]; an empty value is rejected by
    /// the HTTPS URL check in [`OAuthConfig::validate`].
    #[serde(default)]
    pub jwks_uri: String,
    /// Scope-to-role mappings. First matching scope wins.
    /// Used when `role_claim` is absent (default behavior).
    #[serde(default)]
    pub scopes: Vec<ScopeMapping>,
    /// JWT claim path to extract roles from (dot-notation for nested claims).
    ///
    /// Examples: `"scope"` (default), `"roles"`, `"realm_access.roles"`.
    /// When set, the claim value is matched against `role_mappings` instead
    /// of `scopes`. Supports both space-separated strings and JSON arrays.
    pub role_claim: Option<String>,
    /// Claim-value-to-role mappings. Used when `role_claim` is set.
    /// First matching value wins.
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    /// How long to cache JWKS keys before re-fetching.
    /// Parsed as a humantime duration (e.g. "10m", "1h"). Default: "10m".
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: String,
    /// OAuth proxy configuration.  When set, the server exposes
    /// `/authorize`, `/token`, and `/register` endpoints that proxy
    /// to the upstream identity provider (e.g. Keycloak).
    pub proxy: Option<OAuthProxyConfig>,
    /// Token exchange configuration (RFC 8693).  When set, the server
    /// can exchange an inbound MCP-scoped access token for a downstream
    /// API-scoped access token via the authorization server's token
    /// endpoint.
    pub token_exchange: Option<TokenExchangeConfig>,
    /// Optional path to a PEM CA bundle for OAuth-bound HTTP traffic.
    /// Added to the system/built-in roots, not a replacement.
    ///
    /// **Scope (since 1.2.1).** When the [`OauthHttpClient`] is
    /// constructed via [`OauthHttpClient::with_config`] (preferred),
    /// this CA bundle is honoured by *every* OAuth-bound HTTP
    /// request: the JWKS key fetch, token exchange, introspection,
    /// revocation, and the OAuth proxy handlers. Application crates
    /// may auto-populate this from their own configuration (e.g. an
    /// upstream-API CA path); any application-owned HTTP clients
    /// outside the kit must still configure their own CA trust
    /// separately. The deprecated [`OauthHttpClient::new`] no-arg
    /// constructor cannot honour this field -- migrate to
    /// [`OauthHttpClient::with_config`] for full coverage.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Allow plain-HTTP (non-TLS) URLs for OAuth endpoints (`jwks_uri`,
    /// `proxy.authorize_url`, `proxy.token_url`, `proxy.introspection_url`,
    /// `proxy.revocation_url`, `token_exchange.token_url`).
    ///
    /// **Default: `false`.** Strongly discouraged in production: a
    /// network-positioned attacker can MITM JWKS responses and substitute
    /// signing keys (forging arbitrary tokens), or MITM the token / proxy
    /// endpoints to steal credentials and codes. Enable only for
    /// development against a local `IdP` without TLS, ideally bound to
    /// `127.0.0.1`.
    ///
    /// Redirect handling when this flag is `true`: an HTTPS → HTTP
    /// *downgrade* is always rejected, but an HTTP → HTTP redirect is
    /// permitted (the target must still pass SSRF screening). When the flag
    /// is `false`, every non-HTTPS redirect target is rejected.
    #[serde(default)]
    pub allow_http_oauth_urls: bool,
    /// Operator-trusted SSRF allowlist for OAuth/JWKS targets.
    ///
    /// **Default: `None`** (fail-closed; current behavior preserved).
    /// When set, the listed hostnames and CIDR blocks may resolve into
    /// otherwise-blocked address ranges (RFC 1918, loopback, link-local,
    /// CGNAT, IPv6 unique-local, ...). **Cloud-metadata addresses
    /// remain unbypassable regardless of this setting** -- see
    /// [`OAuthSsrfAllowlist`] and `SECURITY.md` § "Operator allowlist".
    #[serde(default)]
    pub ssrf_allowlist: Option<OAuthSsrfAllowlist>,
    /// Maximum number of keys accepted from a JWKS refresh response.
    /// Requests returning more keys than this are rejected fail-closed
    /// (cache remains empty / unchanged). Default: 256.
    #[serde(default = "default_max_jwks_keys")]
    pub max_jwks_keys: usize,
    /// Optional allowlist of accepted JWT signing algorithms.
    ///
    /// **Default `None`**, which accepts the crate's built-in set:
    /// `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256`, `PS384`,
    /// `PS512`, `EdDSA`.
    ///
    /// When set, it must be a non-empty **subset** of that built-in set;
    /// anything else fails [`OAuthConfig::validate`]. Names are matched
    /// case-insensitively. This knob can only ever NARROW the accepted
    /// algorithms -- it cannot re-enable `HS*` or `none`, so an operator
    /// cannot use it to open an algorithm-confusion hole.
    ///
    /// Use it to pin a deployment to exactly what its identity provider
    /// signs with, e.g. `["RS256"]` for Microsoft Entra v2.0.
    #[serde(default)]
    pub allowed_algorithms: Option<Vec<String>>,
    /// Authorization servers advertised in RFC 9728 Protected Resource
    /// Metadata.
    ///
    /// **Default `None` = resolved from topology**, which is the RFC-correct
    /// answer in both directions:
    ///
    /// - [`OAuthConfig::proxy`] configured -> this server's public URL. The
    ///   proxy really does mount `/authorize`, `/token`, `/register`, and
    ///   `/.well-known/oauth-authorization-server`.
    /// - no proxy -> the upstream [`OAuthConfig::issuer`]. This process mounts
    ///   no authorization-server endpoints, so advertising itself would send
    ///   RFC 9728 discovery to a URL that returns 404.
    ///
    /// **Set this explicitly if your application mounts its own `/authorize`
    /// and `/token` through `McpServerConfig::with_extra_router` without
    /// configuring [`OAuthConfig::proxy`]** - that server *is* the
    /// authorization server, and the crate cannot detect it. Set it to the
    /// server's public URL.
    ///
    /// `Some(vec![])` omits `authorization_servers` from the document
    /// entirely, per RFC 9728 3.2 (zero-valued claims must be omitted).
    #[serde(default)]
    pub authorization_servers: Option<Vec<String>>,
    /// `issuer` published in the RFC 8414 Authorization Server Metadata
    /// document served by the built-in proxy.
    ///
    /// **Default `None` = this server's own public URL**, which is what
    /// RFC 8414 3.3 requires: the published `issuer` MUST be identical to the
    /// identifier the metadata URL was built from, and this document is served
    /// from the local origin. RFC 8414 6.2 additionally requires *clients* to
    /// reject a mismatch, so the previous behaviour (publishing the upstream
    /// issuer) was rejected outright by conformant clients.
    ///
    /// **Legacy opt-out.** Set this to your upstream
    /// [`OAuthConfig::issuer`] to restore the pre-3.8 value. The one case that
    /// needs it: an upstream `IdP` that emits RFC 9207 `iss` in the
    /// authorization response *and* clients that validate it. The proxy does
    /// not own the front channel - `/authorize` redirects to the upstream,
    /// which redirects straight back to the client's `redirect_uri` without
    /// passing through this process - so it cannot reconcile a local `issuer`
    /// with an upstream-stamped `iss`.
    ///
    /// Token validation is unaffected either way: inbound JWT `iss` claims are
    /// always checked against [`OAuthConfig::issuer`].
    #[serde(default)]
    pub authorization_server_metadata_issuer: Option<String>,
    /// Require the JWT `sub` (subject) claim. **Default: `false`** (current
    /// behavior). When `true`, a token without `sub` is rejected. Leave
    /// `false` for OAuth client-credentials / machine-to-machine tokens,
    /// which legitimately carry no subject.
    #[serde(default)]
    pub require_subject: bool,
    /// Enforce strict audience validation using only the JWT `aud` claim.
    ///
    /// **Deprecated since 1.7.0.** Use [`OAuthConfig::audience_validation_mode`]
    /// instead. Consulted only when [`OAuthConfig::audience_validation_mode`]
    /// is `None`: `Some(true)` resolves to [`AudienceValidationMode::Strict`],
    /// `Some(false)` resolves to [`AudienceValidationMode::Warn`], and `None`
    /// (the default) resolves to [`AudienceValidationMode::Strict`] - the
    /// secure default that rejects `azp`-only audience matches.
    #[serde(default)]
    #[deprecated(
        since = "1.7.0",
        note = "use `audience_validation_mode` instead; this field is consulted only when `audience_validation_mode` is None"
    )]
    pub strict_audience_validation: Option<bool>,
    /// How the resource server treats `azp` when validating JWT audience.
    ///
    /// When `None` (default), resolution falls back to the deprecated
    /// [`OAuthConfig::strict_audience_validation`] flag: `Some(true)` ⇒
    /// [`AudienceValidationMode::Strict`], `Some(false)` ⇒
    /// [`AudienceValidationMode::Warn`], and `None` ⇒
    /// [`AudienceValidationMode::Strict`] (the secure default).
    /// Set this field explicitly to make the policy unambiguous.
    #[serde(default)]
    pub audience_validation_mode: Option<AudienceValidationMode>,
    /// Maximum size of a JWKS HTTP response body in bytes.
    /// Responses exceeding this cap are refused and logged; the cache
    /// remains empty / unchanged. Default: 1 MiB.
    #[serde(default = "default_jwks_max_bytes")]
    pub jwks_max_response_bytes: u64,
}

/// Serde default for `jwks_cache_ttl` (`"10m"`).
fn default_jwks_cache_ttl() -> String {
    "10m".into()
}

/// Serde default for `max_jwks_keys` (256 keys).
const fn default_max_jwks_keys() -> usize {
    256
}

/// Serde default for `jwks_max_response_bytes` (1 MiB).
const fn default_jwks_max_bytes() -> u64 {
    1024 * 1024
}

/// How the resource server treats `azp` when validating JWT audience.
///
/// **Background.** RFC 9068 §4 + OIDC Core §2 establish `aud` as the
/// authoritative resource-server claim and `azp` as the authorized-party
/// (client) claim. Some OAuth deployments - typically when the MCP server
/// acts as both OAuth client *and* resource server (the documented
/// [`OAuthProxyConfig`] topology) - issue tokens where the configured
/// audience appears only in `azp`. This enum lets operators decide
/// whether that historic compatibility fallback is honored, surfaced via
/// a one-shot warning, or refused.
///
/// **Default**: [`AudienceValidationMode::Strict`] - rejects `azp`-only
/// matches so a token whose configured audience appears only in `azp`
/// is refused. To keep the previous `azp`-accepting behavior, set
/// `audience_validation_mode = "warn"` (one-shot warning per process) or
/// `"permissive"` (silent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AudienceValidationMode {
    /// Accept `aud` matches and `azp`-only matches silently. Pre-1.7
    /// behavior. Use only when the IdP cannot be reconfigured to
    /// populate `aud`.
    Permissive,
    /// Accept `aud` matches silently. Accept `azp`-only matches with a
    /// one-shot `tracing::warn!` per process. Reject neither.
    Warn,
    /// Accept only `aud` matches. Reject `azp`-only matches as audience
    /// mismatch. **Default** - recommended for new deployments and any
    /// IdP that can be configured to populate `aud` reliably.
    #[default]
    Strict,
}

impl AudienceValidationMode {
    /// Stable lower-case label for logs and diagnostics.
    ///
    /// Used so structured log fields render as a plain token
    /// (e.g. `mode="warn"`) rather than the `Debug` form.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Warn => "warn",
            Self::Strict => "strict",
        }
    }
}

impl Default for OAuthConfig {
    #[inline]
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_uri: String::new(),
            scopes: Vec::new(),
            role_claim: None,
            role_mappings: Vec::new(),
            jwks_cache_ttl: default_jwks_cache_ttl(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: false,
            max_jwks_keys: default_max_jwks_keys(),
            allowed_algorithms: None,
            authorization_servers: None,
            authorization_server_metadata_issuer: None,
            require_subject: false,
            #[expect(
                deprecated,
                reason = "default-construct deprecated field for backward compat"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        }
    }
}

impl OAuthConfig {
    /// Resolve the effective audience-validation policy.
    ///
    /// Precedence: explicit `audience_validation_mode` overrides the
    /// legacy `strict_audience_validation` flag. When neither is set,
    /// the default is [`AudienceValidationMode::Strict`] (secure default;
    /// `azp`-only matches are rejected).
    #[must_use]
    #[inline]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    pub fn effective_audience_validation_mode(&self) -> AudienceValidationMode {
        if let Some(mode) = self.audience_validation_mode {
            return mode;
        }
        #[expect(deprecated, reason = "intentional: legacy flag resolution path")]
        match self.strict_audience_validation {
            Some(true) | None => AudienceValidationMode::Strict,
            Some(false) => AudienceValidationMode::Warn,
        }
    }

    /// Start building an [`OAuthConfig`] with the three required fields.
    ///
    /// All other fields default to the same values as
    /// [`OAuthConfig::default`] (empty scopes/role mappings, no proxy or
    /// token exchange, a JWKS cache TTL of `10m`).
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn builder(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_uri: impl Into<String>,
    ) -> OAuthConfigBuilder {
        OAuthConfigBuilder {
            inner: Self {
                issuer: issuer.into(),
                audience: audience.into(),
                jwks_uri: jwks_uri.into(),
                ..Self::default()
            },
        }
    }

    /// Validate the URL fields against the HTTPS-only policy.
    ///
    /// Each of `jwks_uri`, `proxy.authorize_url`, `proxy.token_url`,
    /// `proxy.introspection_url`, `proxy.revocation_url`, and
    /// `token_exchange.token_url` is parsed and its scheme checked.
    ///
    /// Schemes other than `https` are rejected unless
    /// [`OAuthConfig::allow_http_oauth_urls`] is `true`, in which case
    /// `http` is also permitted (parse failures and other schemes are
    /// always rejected).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::RmcpServerKitError::Config`] when any field fails
    /// to parse or violates the scheme policy.
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: src/oauth.rs::OAuthConfig::validate is a flat field-by-field walk-through"
    )]
    #[inline]
    pub fn validate(&self) -> Result<(), RmcpServerKitError> {
        validate_oauth_capacity_knobs(self)?;
        let _validated = resolve_allowed_algorithms(self.allowed_algorithms.as_deref())?;

        let allow_http = self.allow_http_oauth_urls;
        let issuer_url = check_oauth_url("oauth.issuer", &self.issuer, allow_http)?;
        if let Some(reason) = check_url_literal_ip(&issuer_url) {
            return Err(RmcpServerKitError::Config(format!(
                "oauth.issuer forbidden ({reason})"
            )));
        }
        let jwks_url = check_oauth_url("oauth.jwks_uri", &self.jwks_uri, allow_http)?;
        if let Some(reason) = check_url_literal_ip(&jwks_url) {
            return Err(RmcpServerKitError::Config(format!(
                "oauth.jwks_uri forbidden ({reason})"
            )));
        }
        self.validate_discovery_metadata_urls(allow_http)?;
        // `audience` is not a URL, so the `check_oauth_url` calls above do not
        // cover it. Guard it explicitly: with `#[serde(default)]` an omitted
        // audience is an empty string that would otherwise pass validation and
        // then fail-closed silently at runtime (Strict mode matches nothing).
        if self.audience.is_empty() {
            return Err(RmcpServerKitError::Config(
                "oauth.audience must not be empty".into(),
            ));
        }
        if let Some(proxy) = &self.proxy {
            let authorize_url = check_oauth_url(
                "oauth.proxy.authorize_url",
                &proxy.authorize_url,
                allow_http,
            )?;
            if let Some(reason) = check_url_literal_ip(&authorize_url) {
                return Err(RmcpServerKitError::Config(format!(
                    "oauth.proxy.authorize_url forbidden ({reason})"
                )));
            }
            let token_url = check_oauth_url("oauth.proxy.token_url", &proxy.token_url, allow_http)?;
            if let Some(reason) = check_url_literal_ip(&token_url) {
                return Err(RmcpServerKitError::Config(format!(
                    "oauth.proxy.token_url forbidden ({reason})"
                )));
            }
            if let Some(introspection_url) = &proxy.introspection_url {
                let parsed = check_oauth_url(
                    "oauth.proxy.introspection_url",
                    introspection_url,
                    allow_http,
                )?;
                if let Some(reason) = check_url_literal_ip(&parsed) {
                    return Err(RmcpServerKitError::Config(format!(
                        "oauth.proxy.introspection_url forbidden ({reason})"
                    )));
                }
            }
            if let Some(revocation_url) = &proxy.revocation_url {
                let parsed =
                    check_oauth_url("oauth.proxy.revocation_url", revocation_url, allow_http)?;
                if let Some(reason) = check_url_literal_ip(&parsed) {
                    return Err(RmcpServerKitError::Config(format!(
                        "oauth.proxy.revocation_url forbidden ({reason})"
                    )));
                }
            }
            // M3: refuse to start with admin endpoints exposed but no
            // auth in front of them, unless the operator has explicitly
            // opted out via `allow_unauthenticated_admin_endpoints`. The
            // unauthenticated combination proxies arbitrary tokens to
            // the upstream IdP and is only safe behind an authenticated
            // reverse proxy / ingress.
            if proxy.expose_admin_endpoints
                && !proxy.require_auth_on_admin_endpoints
                && !proxy.allow_unauthenticated_admin_endpoints
            {
                return Err(RmcpServerKitError::Config(
                    "oauth.proxy: expose_admin_endpoints = true requires \
                     require_auth_on_admin_endpoints = true (recommended) \
                     or allow_unauthenticated_admin_endpoints = true \
                     (explicit opt-out, only safe behind an authenticated \
                     reverse proxy)"
                        .into(),
                ));
            }
        }
        if let Some(tx) = &self.token_exchange {
            let exchange_url =
                check_oauth_url("oauth.token_exchange.token_url", &tx.token_url, allow_http)?;
            if let Some(reason) = check_url_literal_ip(&exchange_url) {
                return Err(RmcpServerKitError::Config(format!(
                    "oauth.token_exchange.token_url forbidden ({reason})"
                )));
            }
            // M-H4: enforce RFC 8705 §2 mutual exclusion + feature gate
            // for token-exchange client authentication. See helper.
            validate_token_exchange_client_auth(tx)?;
            validate_token_exchange_optional_params(tx)?;
        }
        // Compile the operator allowlist (if any) at config-validate
        // time so misconfiguration is rejected up-front, before any
        // outbound HTTP client is ever built.
        if let Some(raw) = &self.ssrf_allowlist {
            let compiled = compile_oauth_ssrf_allowlist(raw).map_err(|error| {
                RmcpServerKitError::Config(format!("oauth.ssrf_allowlist: {error}"))
            })?;
            if !compiled.is_empty() {
                tracing::warn!(
                    host_count = compiled.host_count(),
                    cidr_count = compiled.cidr_count(),
                    "oauth.ssrf_allowlist is configured: private/loopback OAuth/JWKS targets \
                     are now reachable. Cloud-metadata addresses remain blocked. \
                     See SECURITY.md \"Operator allowlist\"."
                );
            }
        }
        // Validate jwks_cache_ttl parses as a humantime duration so the
        // limiter constructor can rely on a non-fallback value (M5).
        let _parsed_ttl = humantime::parse_duration(&self.jwks_cache_ttl).map_err(|error| {
            RmcpServerKitError::Config(format!(
                "oauth.jwks_cache_ttl {:?} is not a valid humantime duration (e.g. \"10m\", \"1h30m\"): {error}",
                self.jwks_cache_ttl
            ))
        })?;
        Ok(())
    }

    /// Validate the URLs published by the discovery endpoints.
    ///
    /// SECURITY: `authorization_server_metadata_issuer` and
    /// `authorization_servers[]` are reflected verbatim by the unauthenticated
    /// `/.well-known/oauth-*` endpoints, so an unvalidated value is disclosed
    /// to any caller. They are held to the same policy as every other OAuth
    /// URL: parseable, no userinfo, scheme honouring `allow_http_oauth_urls`,
    /// and no literal-IP target.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpServerKitError::Config`] for the first URL that fails the checks.
    fn validate_discovery_metadata_urls(&self, allow_http: bool) -> Result<(), RmcpServerKitError> {
        if let Some(issuer) = &self.authorization_server_metadata_issuer {
            let url = check_oauth_url(
                "oauth.authorization_server_metadata_issuer",
                issuer,
                allow_http,
            )?;
            if let Some(reason) = check_url_literal_ip(&url) {
                return Err(RmcpServerKitError::Config(format!(
                    "oauth.authorization_server_metadata_issuer forbidden ({reason})"
                )));
            }
        }
        // An empty vec is meaningful (it omits the claim entirely) and is
        // preserved here by iterating zero times.
        if let Some(servers) = &self.authorization_servers {
            for (index, server) in servers.iter().enumerate() {
                let field = format!("oauth.authorization_servers[{index}]");
                let url = check_oauth_url(&field, server, allow_http)?;
                if let Some(reason) = check_url_literal_ip(&url) {
                    return Err(RmcpServerKitError::Config(format!(
                        "{field} forbidden ({reason})"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// M-H4: enforce RFC 8705 §2 mutual exclusion for token-exchange client auth.
///
/// `client_secret` xor `client_cert`, plus cargo-feature gating. Without this a
/// `client_cert`-only config silently disables client auth at the token endpoint
/// (the runtime path simply omits the Authorization header).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when both or neither client-auth method is set, or
/// the mTLS feature is missing.
fn validate_token_exchange_client_auth(tx: &TokenExchangeConfig) -> Result<(), RmcpServerKitError> {
    match (&tx.client_cert, tx.client_secret.is_some()) {
        (Some(_), true) => Err(RmcpServerKitError::Config(
            "oauth.token_exchange: client_cert and client_secret are mutually \
             exclusive (RFC 8705 \u{a7}2). Set exactly one."
                .into(),
        )),
        (None, false) => Err(RmcpServerKitError::Config(
            "oauth.token_exchange: token exchange requires client authentication. \
             Set either client_secret (RFC 6749 \u{a7}2.3.1) or client_cert (RFC 8705 \u{a7}2)."
                .into(),
        )),
        (Some(cc), false) => validate_client_cert_config(cc),
        (None, true) => Ok(()),
    }
}

/// Whether `c` is legal anywhere in an RFC 3986 URI.
///
/// A character-class gate, not a positional grammar check. It exists because
/// [`url::Url::parse`] implements the WHATWG URL Standard, not RFC 3986: it
/// silently trims surrounding spaces and C0 controls and percent-encodes
/// characters RFC 3986 forbids outright. Since `resource` is forwarded to the
/// authorization server verbatim, a value the RFC rejects must fail at startup
/// rather than be laundered into a different string.
const fn is_rfc3986_uri_char(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '-' | '.' | '_' | '~'
            | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
            | ':' | '/' | '?' | '#' | '[' | ']' | '@'
            | '%'
    )
}

/// Whether every `%` in `raw` begins a complete `%XX` triplet (RFC 3986 §2.1).
fn has_valid_pct_encoding(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut idx = 0;
    while let Some(byte) = bytes.get(idx) {
        if *byte == b'%' {
            let (Some(hi), Some(lo)) = (
                bytes.get(idx.saturating_add(1)),
                bytes.get(idx.saturating_add(2)),
            ) else {
                return false;
            };
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return false;
            }
            idx = idx.saturating_add(3);
        } else {
            idx = idx.saturating_add(1);
        }
    }
    true
}

/// Validate the RFC 8693 §2.1 OPTIONAL token-exchange parameters.
///
/// An empty value is rejected because it is a malformed request parameter,
/// semantically distinct from omission - omission is expressed by `None` (or
/// [`RequestedTokenType::Omit`]) and is what RFC 8693 §2.1 actually permits.
/// Sending `audience=` would otherwise reach the authorization server.
///
/// `resource` is additionally held to RFC 8707 §2, which requires an absolute
/// URI with no fragment; both are uppercase MUSTs.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when `requested_token_type` or `resource` violates
/// RFC 8693 / RFC 8707.
fn validate_token_exchange_optional_params(
    tx: &TokenExchangeConfig,
) -> Result<(), RmcpServerKitError> {
    fn empty_field(field: &str) -> RmcpServerKitError {
        RmcpServerKitError::Config(format!(
            "oauth.token_exchange.{field} must not be empty; omit the key entirely \
             to leave the RFC 8693 §2.1 parameter out of the request"
        ))
    }

    if tx.audience.as_deref().is_some_and(str::is_empty) {
        return Err(empty_field("audience"));
    }
    if tx.scope.as_deref().is_some_and(str::is_empty) {
        return Err(empty_field("scope"));
    }
    if let RequestedTokenType::Custom(uri) = &tx.requested_token_type {
        if uri.is_empty() {
            return Err(empty_field("requested_token_type"));
        }
        // A custom token type must be a URI (RFC 8693 §3), which is what makes
        // a typo such as "acess_token" a config error rather than a bare word
        // silently forwarded to the authorization server. Unlike `resource`
        // below, a fragment is NOT rejected: the no-fragment rule is
        // RFC 8707 §2's constraint on resource indicators, not a property of
        // RFC 8693 token-type identifiers.
        if !uri.chars().all(is_rfc3986_uri_char) || !has_valid_pct_encoding(uri) {
            return Err(RmcpServerKitError::Config(
                "oauth.token_exchange.requested_token_type custom value must be an RFC 3986 \
                 absolute URI using valid URI characters and percent-encoding (RFC 8693 \u{a7}3)"
                    .into(),
            ));
        }
        let _parsed_uri = url::Url::parse(uri).map_err(|error| {
            RmcpServerKitError::Config(format!(
                "oauth.token_exchange.requested_token_type custom value must be an absolute \
                 URI (RFC 8693 \u{a7}3): {error}"
            ))
        })?;
    }
    if let Some(resource) = tx.resource.as_deref() {
        if resource.is_empty() {
            return Err(empty_field("resource"));
        }
        if !resource.chars().all(is_rfc3986_uri_char) || !has_valid_pct_encoding(resource) {
            return Err(RmcpServerKitError::Config(
                "oauth.token_exchange.resource must be an RFC 3986 absolute URI using valid \
                 URI characters and percent-encoding (RFC 8707 \u{a7}2)"
                    .into(),
            ));
        }
        let parsed = url::Url::parse(resource).map_err(|error| {
            RmcpServerKitError::Config(format!(
                "oauth.token_exchange.resource must be an absolute URI (RFC 8707 \u{a7}2): {error}"
            ))
        })?;
        if parsed.fragment().is_some() {
            return Err(RmcpServerKitError::Config(
                "oauth.token_exchange.resource must not include a fragment component \
                 (RFC 8707 \u{a7}2)"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Validate a [`ClientCertConfig`] for RFC 8705 §2 mTLS client auth.
///
/// Without the `oauth-mtls-client` cargo feature this fails closed with
/// a [`crate::error::RmcpServerKitError::Config`] (M-H4: a `client_cert`-only
/// config previously silently disabled client authentication). With the
/// feature on, this performs the same PEM read + parse the runtime path
/// would do, so missing files / malformed PEM / mismatched key&cert /
/// encrypted (passphrase-protected) keys all surface at validate time
/// rather than at first token-exchange request.
///
/// The returned error message includes the file path; the underlying
/// IO / parse error stays in a `tracing::warn!` log line.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the feature is disabled or the cert/key cannot
/// be read or parsed.
fn validate_client_cert_config(cc: &ClientCertConfig) -> Result<(), RmcpServerKitError> {
    #[cfg(not(feature = "oauth-mtls-client"))]
    {
        let _: &ClientCertConfig = cc;
        Err(RmcpServerKitError::Config(
            "oauth.token_exchange.client_cert requires the `oauth-mtls-client` cargo feature; \
             rebuild rmcp-server-kit with --features oauth-mtls-client (or have your \
             application crate enable it via `rmcp-server-kit/oauth-mtls-client`), or remove \
             the field"
                .into(),
        ))
    }
    #[cfg(feature = "oauth-mtls-client")]
    {
        let cert_bytes = fs::read(&cc.cert_path).map_err(|error| {
            tracing::warn!(error = %error, path = %cc.cert_path.display(), "client cert read failed");
            RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert.cert_path unreadable: {}",
                cc.cert_path.display()
            ))
        })?;
        let key_bytes = fs::read(&cc.key_path).map_err(|error| {
            tracing::warn!(error = %error, path = %cc.key_path.display(), "client cert key read failed");
            RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert.key_path unreadable: {}",
                cc.key_path.display()
            ))
        })?;
        let mut combined = Vec::with_capacity(
            cert_bytes
                .len()
                .saturating_add(1)
                .saturating_add(key_bytes.len()),
        );
        combined.extend_from_slice(&cert_bytes);
        if !cert_bytes.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&key_bytes);
        let _identity = reqwest::Identity::from_pem(&combined).map_err(|error| {
            tracing::warn!(
                error = %error,
                cert_path = %cc.cert_path.display(),
                key_path = %cc.key_path.display(),
                "client cert PEM parse failed"
            );
            RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert: PEM parse failed (cert={}, key={})",
                cc.cert_path.display(),
                cc.key_path.display()
            ))
        })?;
        Ok(())
    }
}

/// M-H4: build the `(cert_path, key_path) -> reqwest::Client` cache.
///
/// Consulted by [`OauthHttpClient::client_for`]. Each cert-bearing client uses
/// `redirect::Policy::none()` (RFC 8705 §2: never present the client cert to a
/// redirect target the operator did not approve) and inherits the same
/// `ca_cert_path`, connect/total timeouts as the shared `inner` client. Returns
/// an empty map when no `token_exchange.client_cert` is configured.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] when a configured client certificate cannot be
/// loaded or built.
#[cfg(feature = "oauth-mtls-client")]
fn build_mtls_clients(
    config: Option<&OAuthConfig>,
    allowlist: &Arc<CompiledSsrfAllowlist>,
    test_bypass: &TestLoopbackBypass,
) -> Result<Arc<HashMap<MtlsClientKey, reqwest::Client>>, RmcpServerKitError> {
    let mut map: HashMap<MtlsClientKey, reqwest::Client> = HashMap::new();
    let Some(cfg) = config else {
        return Ok(Arc::new(map));
    };
    let Some(tx) = &cfg.token_exchange else {
        return Ok(Arc::new(map));
    };
    let Some(cc) = &tx.client_cert else {
        return Ok(Arc::new(map));
    };

    let cert_bytes = fs::read(&cc.cert_path).map_err(|error| {
        RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: read cert_path {}: {error}",
            cc.cert_path.display()
        ))
    })?;
    let key_bytes = fs::read(&cc.key_path).map_err(|error| {
        RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: read key_path {}: {error}",
            cc.key_path.display()
        ))
    })?;
    let mut combined = Vec::with_capacity(
        cert_bytes
            .len()
            .saturating_add(1)
            .saturating_add(key_bytes.len()),
    );
    combined.extend_from_slice(&cert_bytes);
    if !cert_bytes.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&key_bytes);
    let identity = reqwest::Identity::from_pem(&combined).map_err(|error| {
        RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: PEM parse (cert={}, key={}): {error}",
            cc.cert_path.display(),
            cc.key_path.display()
        ))
    })?;

    let resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
        Arc::clone(allowlist),
        // M-H2/B1: TestLoopbackBypass aliases to Arc<AtomicBool> in test
        // builds and to `()` in production. We need a value clone here
        // (not Arc::clone) because the type vanishes outside test cfg;
        // the allow is justified by the feature-gated type alias.
        #[expect(clippy::clone_on_ref_ptr, reason = "type alias varies per feature")]
        test_bypass.clone(),
    ));

    let mut builder = reqwest::Client::builder()
        // M-H2/N1: same proxy + DNS hardening as the shared client.
        .no_proxy()
        .dns_resolver(Arc::clone(&resolver))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .identity(identity);

    if let Some(ca_path) = &cfg.ca_cert_path {
        let pem = fs::read(ca_path).map_err(|error| {
            RmcpServerKitError::Startup(format!(
                "oauth http client mTLS: read ca_cert_path {}: {error}",
                ca_path.display()
            ))
        })?;
        let cert = Certificate::from_pem(&pem).map_err(|error| {
            RmcpServerKitError::Startup(format!(
                "oauth http client mTLS: parse ca_cert_path {}: {error}",
                ca_path.display()
            ))
        })?;
        builder = builder.add_root_certificate(cert);
    }

    let client = builder.build().map_err(|error| {
        RmcpServerKitError::Startup(format!("oauth http client mTLS init: {error}"))
    })?;
    let _replaced = map.insert(
        MtlsClientKey {
            cert_path: cc.cert_path.clone(),
            key_path: cc.key_path.clone(),
        },
        client,
    );
    Ok(Arc::new(map))
}

/// Parse `raw` as a URL and enforce the HTTPS-only policy.
///
/// Returns `Ok(())` for `https://...`, and also for `http://...` when
/// `allow_http` is `true`. All other schemes (and parse failures) are
/// rejected with a [`crate::error::RmcpServerKitError::Config`] referencing the
/// caller-supplied `field` name for diagnostics.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the URL does not parse or its scheme is not
/// permitted.
fn check_oauth_url(
    field: &str,
    raw: &str,
    allow_http: bool,
) -> Result<url::Url, RmcpServerKitError> {
    let parsed = url::Url::parse(raw).map_err(|error| {
        RmcpServerKitError::Config(format!("{field}: invalid URL <unparseable-url>: {error}"))
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RmcpServerKitError::Config(format!(
            "{field} rejected: URL contains userinfo (credentials in URL are forbidden)"
        )));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_http => Ok(parsed),
        "http" => Err(RmcpServerKitError::Config(format!(
            "{field}: must use https scheme (got http; set allow_http_oauth_urls=true \
             to override - strongly discouraged in production)"
        ))),
        other => Err(RmcpServerKitError::Config(format!(
            "{field}: must use https scheme (got {other:?})"
        ))),
    }
}

/// Reject zero-valued capacity knobs ([`OAuthConfig::max_jwks_keys`],
/// [`OAuthConfig::jwks_max_response_bytes`]).
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when either knob is zero.
fn validate_oauth_capacity_knobs(config: &OAuthConfig) -> Result<(), RmcpServerKitError> {
    (config.max_jwks_keys != 0)
        .ok_or_else(|| RmcpServerKitError::Config("oauth.max_jwks_keys must be nonzero".into()))?;
    (config.jwks_max_response_bytes != 0).ok_or_else(|| {
        RmcpServerKitError::Config("oauth.jwks_max_response_bytes must be nonzero".into())
    })?;
    Ok(())
}

/// Builder for [`OAuthConfig`].
///
/// Obtain via [`OAuthConfig::builder`]. All setters consume `self` and
/// return a new builder, so they compose fluently. Call
/// [`OAuthConfigBuilder::build`] to produce the final [`OAuthConfig`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing until `.build()` is called"]
pub struct OAuthConfigBuilder {
    /// Configuration under construction.
    inner: OAuthConfig,
}

impl OAuthConfigBuilder {
    /// Restrict the accepted JWT signing algorithms.
    ///
    /// Must be a non-empty subset of the built-in set; validated by
    /// [`OAuthConfig::validate`]. See
    /// [`OAuthConfig::allowed_algorithms`].
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn allowed_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inner.allowed_algorithms =
            Some(algorithms.into_iter().map(Into::into).collect::<Vec<_>>());
        self
    }

    /// Publish a specific `issuer` in the proxy's RFC 8414 Authorization
    /// Server Metadata document.
    ///
    /// The default is already RFC 8414 3.3 conformant (this server's public
    /// URL). Use this only to restore the pre-3.8 upstream value - see the
    /// RFC 9207 caveat on
    /// [`OAuthConfig::authorization_server_metadata_issuer`].
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn authorization_server_metadata_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.inner.authorization_server_metadata_issuer = Some(issuer.into());
        self
    }

    /// Override the authorization servers advertised in Protected Resource
    /// Metadata.
    ///
    /// Needed when the application mounts its own OAuth endpoints via
    /// `with_extra_router` instead of using [`OAuthConfig::proxy`]. Pass an
    /// empty iterator to omit the field. See
    /// [`OAuthConfig::authorization_servers`].
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn authorization_servers(
        mut self,
        servers: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inner.authorization_servers =
            Some(servers.into_iter().map(Into::into).collect::<Vec<_>>());
        self
    }

    /// Replace the scope-to-role mappings.
    #[inline]
    pub fn scopes(mut self, scopes: Vec<ScopeMapping>) -> Self {
        self.inner.scopes = scopes;
        self
    }

    /// Append a single scope-to-role mapping.
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn scope(mut self, scope: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.scopes.push(ScopeMapping {
            scope: scope.into(),
            role: role.into(),
        });
        self
    }

    /// Set the JWT claim path used to extract roles directly (without
    /// going through `scope` mappings).
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn role_claim(mut self, claim: impl Into<String>) -> Self {
        self.inner.role_claim = Some(claim.into());
        self
    }

    /// Replace the claim-value-to-role mappings.
    #[inline]
    pub fn role_mappings(mut self, mappings: Vec<RoleMapping>) -> Self {
        self.inner.role_mappings = mappings;
        self
    }

    /// Append a single claim-value-to-role mapping (used with
    /// [`Self::role_claim`]).
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn role_mapping(mut self, claim_value: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.role_mappings.push(RoleMapping {
            claim_value: claim_value.into(),
            role: role.into(),
        });
        self
    }

    /// Override the JWKS cache TTL (humantime string, e.g. `"5m"`).
    /// Defaults to `"10m"`.
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn jwks_cache_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.inner.jwks_cache_ttl = ttl.into();
        self
    }

    /// Attach an OAuth proxy configuration. When set, the server
    /// exposes `/authorize`, `/token`, and `/register` endpoints.
    #[inline]
    pub fn proxy(mut self, proxy: OAuthProxyConfig) -> Self {
        self.inner.proxy = Some(proxy);
        self
    }

    /// Attach an RFC 8693 token exchange configuration.
    #[inline]
    pub fn token_exchange(mut self, token_exchange: TokenExchangeConfig) -> Self {
        self.inner.token_exchange = Some(token_exchange);
        self
    }

    /// Provide a PEM CA bundle path used for all OAuth-bound HTTPS traffic
    /// originated by this crate (JWKS fetches and the optional OAuth proxy
    /// `/authorize`, `/token`, `/register`, `/introspect`, `/revoke`,
    /// `/.well-known/oauth-authorization-server` upstream calls).
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.ca_cert_path = Some(path.into());
        self
    }

    /// Allow plain-HTTP (non-TLS) URLs for OAuth endpoints.
    ///
    /// **Default: `false`.** See the field-level documentation on
    /// [`OAuthConfig::allow_http_oauth_urls`] for the security caveats
    /// before enabling this.
    #[inline]
    pub const fn allow_http_oauth_urls(mut self, allow: bool) -> Self {
        self.inner.allow_http_oauth_urls = allow;
        self
    }

    /// Toggle strict audience validation so only the JWT `aud` claim is
    /// considered and the compatibility fallback to `azp` is disabled.
    ///
    /// **Deprecated since 1.7.0.** Prefer
    /// [`OAuthConfigBuilder::audience_validation_mode`] for explicit
    /// three-state policy. This method clears
    /// `audience_validation_mode` so the legacy bool resolution path
    /// applies.
    #[deprecated(since = "1.7.0", note = "use `audience_validation_mode` instead")]
    #[inline]
    pub const fn strict_audience_validation(mut self, strict: bool) -> Self {
        #[expect(
            deprecated,
            reason = "intentional: deprecated builder forwards to deprecated field"
        )]
        {
            self.inner.strict_audience_validation = Some(strict);
        }
        self.inner.audience_validation_mode = None;
        self
    }

    /// Set the audience-validation policy explicitly.
    ///
    /// Takes precedence over the deprecated
    /// [`OAuthConfigBuilder::strict_audience_validation`] flag. See
    /// [`AudienceValidationMode`] for variant semantics. Defaults to
    /// [`AudienceValidationMode::Strict`] when neither this method nor the
    /// legacy flag is set.
    #[inline]
    pub const fn audience_validation_mode(mut self, mode: AudienceValidationMode) -> Self {
        self.inner.audience_validation_mode = Some(mode);
        self
    }

    /// Require the JWT `sub` (subject) claim (opt-in; default `false`).
    ///
    /// When `true`, a token without `sub` is rejected. Leave `false` for
    /// OAuth client-credentials / machine-to-machine tokens, which
    /// legitimately carry no subject.
    #[inline]
    pub const fn require_subject(mut self, require: bool) -> Self {
        self.inner.require_subject = require;
        self
    }

    /// Override the maximum JWKS response body size in bytes.
    #[inline]
    pub const fn jwks_max_response_bytes(mut self, bytes: u64) -> Self {
        self.inner.jwks_max_response_bytes = bytes;
        self
    }

    /// Set the operator SSRF allowlist for OAuth/JWKS targets.
    ///
    /// **Operator-only.** Use only when an in-cluster IdP (e.g. Keycloak)
    /// resolves to private/loopback address space and must be reached.
    /// Cloud-metadata addresses (AWS/GCP/Alibaba IPv4 + IPv6) remain
    /// blocked regardless of allowlist contents -- see
    /// [`OAuthSsrfAllowlist`] and `SECURITY.md`  "Operator allowlist".
    #[inline]
    pub fn ssrf_allowlist(mut self, allowlist: OAuthSsrfAllowlist) -> Self {
        self.inner.ssrf_allowlist = Some(allowlist);
        self
    }

    /// Finalise the builder and return the [`OAuthConfig`].
    #[must_use]
    #[inline]
    pub fn build(self) -> OAuthConfig {
        self.inner
    }
}

/// Maps an OAuth scope string to an RBAC role name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ScopeMapping {
    /// OAuth scope string to match against the token's `scope` claim.
    pub scope: String,
    /// RBAC role granted when the scope is present.
    pub role: String,
}

/// Maps a JWT claim value to an RBAC role name.
/// Used with `OAuthConfig::role_claim` for non-scope-based role extraction
/// (e.g. Keycloak `realm_access.roles`, Azure AD `roles`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleMapping {
    /// Expected value of the configured role claim (e.g. `admin`).
    pub claim_value: String,
    /// RBAC role granted when `claim_value` is present in the claim.
    pub role: String,
}

/// RFC 8693 URN for access tokens; the default `requested_token_type`.
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §2.1 `requested_token_type` - an OPTIONAL request parameter.
///
/// The RFC states that when the requested type is unspecified, "the issued
/// token type is at the discretion of the authorization server". [`Self::Omit`]
/// expresses that, which is otherwise unreachable.
///
/// Deserialised from a plain TOML string: `"access_token"` and `"omit"` map to
/// the corresponding variants, and any other string becomes [`Self::Custom`].
/// A misspelling such as `"acess_token"` is therefore accepted as a custom
/// token-type URI and sent verbatim rather than rejected - unavoidable, since
/// RFC 8693 §3 permits arbitrary URIs here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "String")]
#[non_exhaustive]
pub enum RequestedTokenType {
    /// Send `urn:ietf:params:oauth:token-type:access_token`.
    ///
    /// Default, preserving the behaviour of every release before 3.8.0, which
    /// always sent this value.
    #[default]
    AccessToken,
    /// Omit `requested_token_type`, letting the authorization server choose.
    Omit,
    /// Send a specific token-type URI (RFC 8693 §3).
    Custom(String),
}

impl From<String> for RequestedTokenType {
    #[inline]
    fn from(value: String) -> Self {
        match value.as_str() {
            "access_token" => Self::AccessToken,
            "omit" => Self::Omit,
            _ => Self::Custom(value),
        }
    }
}

impl RequestedTokenType {
    /// The wire value, or `None` when the parameter must be omitted.
    const fn wire_value(&self) -> Option<&str> {
        match self {
            Self::AccessToken => Some(TOKEN_TYPE_ACCESS_TOKEN),
            Self::Omit => None,
            Self::Custom(uri) => Some(uri.as_str()),
        }
    }
}

/// Configuration for RFC 8693 token exchange.
///
/// The MCP server uses this to exchange an inbound user access token
/// (audience = MCP server) for a downstream access token (audience =
/// the upstream API the application calls) via the authorization
/// server's token endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TokenExchangeConfig {
    /// Authorization server token endpoint used for the exchange
    /// (e.g. `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`).
    pub token_url: String,
    /// OAuth `client_id` of the MCP server (the requester).
    pub client_id: String,
    /// OAuth `client_secret` for confidential-client authentication
    /// (RFC 6749 §2.3.1 HTTP Basic). Mutually exclusive with
    /// `client_cert` -- [`OAuthConfig::validate`] rejects configs
    /// that set both, or neither.
    pub client_secret: Option<secrecy::SecretString>,
    /// Client certificate for RFC 8705 §2 mTLS client authentication.
    /// When set, the exchange request authenticates by presenting the
    /// configured cert at TLS handshake (no Authorization header is
    /// sent). Requires the `oauth-mtls-client` cargo feature; without
    /// it, [`OAuthConfig::validate`] fails closed.
    ///
    /// **Scope**: implements RFC 8705 §2 only (PKI-bound client
    /// auth). RFC 8705 §3 self-signed client auth and the
    /// `cnf.x5t#S256` certificate-bound access-token confirmation
    /// claim are NOT enforced; the issued access token behaves like a
    /// bearer token once minted. In-place certificate rotation is
    /// not picked up without restart.
    pub client_cert: Option<ClientCertConfig>,
    /// RFC 8693 §2.1 `audience` - OPTIONAL. The logical name of the
    /// downstream API (e.g. `upstream-api`); the exchanged token carries
    /// it in the `aud` claim. `None` omits the parameter.
    ///
    /// Distinct from [`OAuthConfig::audience`], which is the `aud` claim
    /// this server *expects* on inbound tokens.
    #[serde(default)]
    pub audience: Option<String>,
    /// RFC 8693 §2.1 `resource` - OPTIONAL. An RFC 8707 resource
    /// indicator: an absolute URI, without a fragment, naming the target
    /// service. `None` omits the parameter.
    ///
    /// Unrelated to `oauth.proxy.strip_resource_param`, which governs the
    /// OAuth *proxy* endpoints, not token exchange.
    #[serde(default)]
    pub resource: Option<String>,
    /// RFC 8693 §2.1 `scope` - OPTIONAL. Space-delimited scopes requested
    /// for the exchanged token. `None` omits the parameter.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8693 §2.1 `requested_token_type` - OPTIONAL.
    ///
    /// `#[serde(default)]` is load-bearing: without it, every existing
    /// `[server.auth.oauth.token_exchange]` table - none of which contain
    /// this key - would fail to parse.
    #[serde(default)]
    pub requested_token_type: RequestedTokenType,
}

impl TokenExchangeConfig {
    /// Create a new token exchange configuration.
    ///
    /// The RFC 8693 OPTIONAL parameters (`audience`, `resource`, `scope`,
    /// `requested_token_type`) default to omitted and are set with the
    /// `with_*` methods.
    #[must_use]
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn new(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<secrecy::SecretString>,
        client_cert: Option<ClientCertConfig>,
    ) -> Self {
        Self {
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret,
            client_cert,
            audience: None,
            resource: None,
            scope: None,
            requested_token_type: RequestedTokenType::default(),
        }
    }

    /// Set the RFC 8693 `audience` parameter.
    #[must_use]
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the RFC 8693 / RFC 8707 `resource` parameter.
    #[must_use]
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set the RFC 8693 `scope` parameter.
    #[must_use]
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the RFC 8693 `requested_token_type` parameter.
    #[must_use]
    #[inline]
    pub fn with_requested_token_type(mut self, requested_token_type: RequestedTokenType) -> Self {
        self.requested_token_type = requested_token_type;
        self
    }
}

/// Client certificate paths for RFC 8705 §2 mTLS client
/// authentication at the token exchange endpoint. Requires the
/// `oauth-mtls-client` cargo feature.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientCertConfig {
    /// Path to the PEM-encoded client certificate (X.509, single
    /// leaf or full chain). Read once at server startup.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key (PKCS#8 or RSA / EC).
    /// Encrypted (passphrase-protected) keys are NOT supported and
    /// fail closed at config validation.
    pub key_path: PathBuf,
}

impl ClientCertConfig {
    /// Construct a `ClientCertConfig`. Required because the struct is
    /// `#[non_exhaustive]` and so cannot be built with a struct literal
    /// from outside the crate.
    #[must_use]
    #[inline]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }
}

/// Successful response from an RFC 8693 token exchange.
#[derive(Deserialize)]
#[non_exhaustive]
pub struct ExchangedToken {
    /// The newly issued access token.
    pub access_token: String,
    /// Token lifetime in seconds (if provided by the authorization server).
    pub expires_in: Option<u64>,
    /// Token type identifier (e.g.
    /// `urn:ietf:params:oauth:token-type:access_token`).
    pub issued_token_type: Option<String>,
}

impl fmt::Debug for ExchangedToken {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            access_token,
            expires_in,
            issued_token_type,
        } = self;
        let access_token_display = if plaintext_oauth_tokens() {
            access_token.as_str()
        } else {
            "[REDACTED]"
        };
        f.debug_struct("ExchangedToken")
            .field("access_token", &access_token_display)
            .field("expires_in", expires_in)
            .field("issued_token_type", issued_token_type)
            .finish()
    }
}

/// Configuration for proxying OAuth 2.1 flows to an upstream identity provider.
///
/// When present, the MCP server exposes `/authorize`, `/token`, and
/// `/register` endpoints that proxy to the upstream identity provider
/// (e.g. Keycloak). MCP clients see this server as the authorization
/// server and perform a standard Authorization Code + PKCE flow.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "flat TOML sub-table of independent operator toggles; collapsing them into an enum would break both the public API and the deserialized schema"
)]
#[non_exhaustive]
pub struct OAuthProxyConfig {
    /// Upstream authorization endpoint (e.g.
    /// `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth`).
    pub authorize_url: String,
    /// Upstream token endpoint (e.g.
    /// `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`).
    pub token_url: String,
    /// OAuth `client_id` registered at the upstream identity provider.
    pub client_id: String,
    /// OAuth `client_secret` (for confidential clients). Omit for public clients.
    pub client_secret: Option<secrecy::SecretString>,
    /// Optional upstream RFC 7662 introspection endpoint. When set
    /// **and** [`Self::expose_admin_endpoints`] is `true`, the server
    /// exposes a local `/introspect` endpoint that proxies to it.
    #[serde(default)]
    pub introspection_url: Option<String>,
    /// Optional upstream RFC 7009 revocation endpoint. When set
    /// **and** [`Self::expose_admin_endpoints`] is `true`, the server
    /// exposes a local `/revoke` endpoint that proxies to it.
    #[serde(default)]
    pub revocation_url: Option<String>,
    /// Whether to expose the OAuth admin endpoints (`/introspect`,
    /// `/revoke`) and advertise them in the authorization-server
    /// metadata document.
    ///
    /// **Default: `false`.** These endpoints are unauthenticated at the
    /// transport layer (the OAuth proxy router is mounted outside the
    /// MCP auth middleware) and proxy directly to the upstream `IdP`. If
    /// enabled, you are responsible for restricting access at the
    /// network boundary (firewall, reverse proxy, mTLS) or by routing
    /// the entire rmcp-server-kit process behind an authenticated ingress. Leaving
    /// this `false` (the default) makes the endpoints return 404.
    #[serde(default)]
    pub expose_admin_endpoints: bool,
    /// Require the normal authentication middleware before the local
    /// `/introspect` and `/revoke` proxy endpoints are reached.
    ///
    /// **Default: `false` for backward compatibility.** New deployments
    /// should set this to `true` when exposing admin endpoints.
    #[serde(default)]
    pub require_auth_on_admin_endpoints: bool,
    /// Explicit operator opt-out for the M3 startup check that rejects
    /// `expose_admin_endpoints = true` combined with
    /// `require_auth_on_admin_endpoints = false`.
    ///
    /// **Default: `false`.** Setting this to `true` allows the unauth
    /// admin-endpoint combination to start, which is only safe when the
    /// rmcp-server-kit process sits behind an authenticated reverse
    /// proxy / ingress that screens `/introspect` and `/revoke` itself.
    /// Production deployments should leave this `false` and instead set
    /// `require_auth_on_admin_endpoints = true`.
    #[serde(default)]
    pub allow_unauthenticated_admin_endpoints: bool,
    /// Drop the RFC 8707 `resource` parameter from proxied `/authorize`
    /// and `/token` requests before forwarding them upstream.
    ///
    /// **Default: `false`**, which forwards the parameter unchanged and is
    /// the spec-preserving behaviour.
    ///
    /// Set this to `true` for Microsoft Entra ID (Azure AD) v2.0, which
    /// rejects a `resource` parameter carried alongside a differing
    /// `api://` scope with error `AADSTS9010010`. MCP clients send
    /// `resource` because the MCP specification requires it, so without
    /// this opt-out an Entra-backed proxy cannot complete an
    /// authorization-code flow.
    ///
    /// Only `resource` is ever dropped. Parameters that carry security
    /// meaning -- `state`, `code_challenge`, `code_challenge_method`,
    /// `code_verifier`, `redirect_uri`, `nonce`, `scope` -- are always
    /// forwarded, so enabling this cannot silently disable PKCE or CSRF
    /// protection. The upstream `/introspect` and `/revoke` proxy path is
    /// unaffected: `resource` is not a parameter of RFC 7662 or RFC 7009
    /// requests.
    #[serde(default)]
    pub strip_resource_param: bool,
}

impl OAuthProxyConfig {
    /// Start building an [`OAuthProxyConfig`] with the three required
    /// upstream fields.
    ///
    /// Optional settings (`client_secret`, `introspection_url`,
    /// `revocation_url`, `expose_admin_endpoints`) default to their
    /// [`Default`] values and can be set via the corresponding builder
    /// methods.
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn builder(
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
    ) -> OAuthProxyConfigBuilder {
        OAuthProxyConfigBuilder {
            inner: Self {
                authorize_url: authorize_url.into(),
                token_url: token_url.into(),
                client_id: client_id.into(),
                ..Self::default()
            },
        }
    }
}

/// Builder for [`OAuthProxyConfig`].
///
/// Obtain via [`OAuthProxyConfig::builder`]. See the type-level docs on
/// [`OAuthProxyConfig`] and in particular the security caveats on
/// [`OAuthProxyConfig::expose_admin_endpoints`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing until `.build()` is called"]
pub struct OAuthProxyConfigBuilder {
    /// Proxy configuration under construction.
    inner: OAuthProxyConfig,
}

impl OAuthProxyConfigBuilder {
    /// Set the upstream OAuth client secret. Omit for public clients.
    #[inline]
    pub fn client_secret(mut self, secret: secrecy::SecretString) -> Self {
        self.inner.client_secret = Some(secret);
        self
    }

    /// Configure the upstream RFC 7662 introspection endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn introspection_url(mut self, url: impl Into<String>) -> Self {
        self.inner.introspection_url = Some(url.into());
        self
    }

    /// Configure the upstream RFC 7009 revocation endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
    #[inline]
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    pub fn revocation_url(mut self, url: impl Into<String>) -> Self {
        self.inner.revocation_url = Some(url.into());
        self
    }

    /// Opt in to exposing the `/introspect` and `/revoke` admin
    /// endpoints and advertising them in the authorization-server
    /// metadata document.
    ///
    /// **Security:** see the field-level documentation on
    /// [`OAuthProxyConfig::expose_admin_endpoints`] for the caveats
    /// before enabling this.
    #[inline]
    pub const fn expose_admin_endpoints(mut self, expose: bool) -> Self {
        self.inner.expose_admin_endpoints = expose;
        self
    }

    /// Require the normal authentication middleware on `/introspect` and
    /// `/revoke`.
    #[inline]
    pub const fn require_auth_on_admin_endpoints(mut self, require: bool) -> Self {
        self.inner.require_auth_on_admin_endpoints = require;
        self
    }

    /// Explicit opt-out for the M3 startup check that rejects exposing
    /// `/introspect`/`/revoke` without authentication. See
    /// [`OAuthProxyConfig::allow_unauthenticated_admin_endpoints`].
    #[inline]
    pub const fn allow_unauthenticated_admin_endpoints(mut self, allow: bool) -> Self {
        self.inner.allow_unauthenticated_admin_endpoints = allow;
        self
    }

    /// Drop the RFC 8707 `resource` parameter when proxying `/authorize`
    /// and `/token` upstream. Required for Microsoft Entra v2.0
    /// (`AADSTS9010010`). See
    /// [`OAuthProxyConfig::strip_resource_param`].
    #[inline]
    pub const fn strip_resource_param(mut self, strip: bool) -> Self {
        self.inner.strip_resource_param = strip;
        self
    }

    /// Finalise the builder and return the [`OAuthProxyConfig`].
    #[must_use]
    #[inline]
    pub fn build(self) -> OAuthProxyConfig {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

/// Key-type family used to decide which JWS algorithms an `alg`-less JWK may
/// verify.
///
/// RFC 7517 4.4 makes the JWK `alg` member OPTIONAL, and real issuers omit it
/// (Microsoft Entra v2.0 publishes every signing key without `alg`). When it is
/// absent the algorithm is inferred from the key material instead, so the key
/// stays usable without ever consulting the untrusted token header.
///
/// **`P-521`/`ES512` is deliberately absent.** `jsonwebtoken` 11's
/// `Algorithm` enum has no `ES512` variant at all -- it defines only `ES256`
/// and `ES384` for ECDSA -- so a `P-521` family could not name an algorithm to
/// map to. It is likewise absent from [`ACCEPTED_ALGS`]. Supporting P-521 would
/// require upstream `jsonwebtoken` support first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwkKeyFamily {
    /// RSA key: any RSASSA-PKCS1-v1_5 or RSASSA-PSS algorithm.
    Rsa,
    /// NIST P-256 EC key: `ES256` only.
    EcP256,
    /// NIST P-384 EC key: `ES384` only.
    EcP384,
    /// Ed25519 octet key pair: `EdDSA` only.
    Ed25519,
}

/// How a cached JWK constrains the JWS algorithm it may verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwkAlg {
    /// The JWK declared `alg`; exactly that algorithm is accepted.
    Explicit(Algorithm),
    /// The JWK omitted `alg`; the algorithms implied by its key type are
    /// accepted (see [`family_accepts`]).
    Family(JwkKeyFamily),
}

impl JwkAlg {
    /// Whether this cached key may verify a token whose header declares `alg`.
    ///
    /// SECURITY: the candidate `alg` has already been screened against
    /// [`ACCEPTED_ALGS`] before key lookup, so `HS*` and `none` can never reach
    /// here. This is the second, key-bound half of that check: it prevents a
    /// token from selecting a key whose material cannot produce its algorithm.
    fn accepts(self, alg: Algorithm) -> bool {
        match self {
            Self::Explicit(declared) => declared == alg,
            Self::Family(family) => family_accepts(family, alg),
        }
    }
}

/// Algorithms an `alg`-less JWK of the given family may verify.
///
/// INVARIANT: every algorithm returned here is a member of [`ACCEPTED_ALGS`];
/// `family_accepts_is_subset_of_accepted_algs` locks that down. Widening this
/// beyond [`ACCEPTED_ALGS`] would let an inferred key bypass the pre-lookup
/// algorithm screen.
const fn family_accepts(family: JwkKeyFamily, alg: Algorithm) -> bool {
    match family {
        JwkKeyFamily::Rsa => matches!(
            alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ),
        JwkKeyFamily::EcP256 => matches!(alg, Algorithm::ES256),
        JwkKeyFamily::EcP384 => matches!(alg, Algorithm::ES384),
        JwkKeyFamily::Ed25519 => matches!(alg, Algorithm::EdDSA),
    }
}

/// `kid`-indexed map of (algorithm, decoding key) pairs plus a list of
/// unnamed keys. Produced by [`build_key_cache`] and consumed by
/// [`JwksCache::refresh_inner`].
type JwksKeyCache = (
    HashMap<String, (JwkAlg, DecodingKey)>,
    Vec<(JwkAlg, DecodingKey)>,
);

/// One fetched JWKS snapshot: kid-indexed keys, unnamed keys, and freshness metadata.
struct CachedKeys {
    /// `kid` -> (`JwkAlg`, `DecodingKey`).
    keys: HashMap<String, (JwkAlg, DecodingKey)>,
    /// Keys without a kid, indexed by algorithm family.
    unnamed_keys: Vec<(JwkAlg, DecodingKey)>,
    /// When this snapshot was stored.
    fetched_at: Instant,
    /// How long this snapshot stays fresh.
    ttl: Duration,
}

/// Anchor keeping [`JWKS_REFRESH_COOLDOWN`] linkable from module docs.
const _JWKS_REFRESH_COOLDOWN_DOC_ANCHOR: &str = "JWKS_REFRESH_COOLDOWN";

impl CachedKeys {
    /// Whether the snapshot has outlived its TTL.
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// Thread-safe JWKS key cache with automatic refresh.
///
/// Includes protections against denial-of-service via invalid JWTs:
/// - **Refresh cooldown**: At most one refresh per 10 seconds, regardless of
///   cache misses. This prevents attackers from flooding the upstream JWKS
///   endpoint by sending JWTs with fabricated `kid` values.
/// - **Concurrent deduplication**: Only one refresh in flight at a time;
///   concurrent waiters share the same fetch result.
#[expect(
    missing_debug_implementations,
    reason = "contains reqwest::Client and DecodingKey cache with no Debug impl"
)]
#[non_exhaustive]
pub struct JwksCache {
    /// The upstream JWKS endpoint.
    jwks_uri: String,
    /// Configured cache TTL for fetched keys.
    ttl: Duration,
    /// Upper bound on keys accepted from one JWKS document.
    max_jwks_keys: usize,
    /// Algorithms this cache will verify with. Defaults to [`ACCEPTED_ALGS`];
    /// [`OAuthConfig::allowed_algorithms`] may narrow it but never widen it.
    allowed_algorithms: Vec<Algorithm>,
    /// Upper bound on the JWKS response body size in bytes.
    max_response_bytes: u64,
    /// Whether plain-HTTP JWKS URLs are permitted (`allow_http_oauth_urls`).
    allow_http: bool,
    /// Current key snapshot; `None` until the first successful fetch.
    inner: RwLock<Option<CachedKeys>>,
    /// Fetch client (SSRF-screened, redirect-policy applied).
    http: reqwest::Client,
    /// Base `Validation` template; per-token validation clones and narrows it.
    validation_template: Validation,
    /// Expected audience value from config; checked against `aud` and,
    /// per `audience_mode`, optionally `azp`.
    expected_audience: String,
    /// How `aud`/`azp` are validated.
    audience_mode: AudienceValidationMode,
    /// Whether tokens without `sub` are rejected.
    require_subject: bool,
    /// Set to `true` after the first `azp`-only audience match while in
    /// [`AudienceValidationMode::Warn`], so the deprecation warning logs
    /// at most once per process lifetime.
    azp_fallback_warned: AtomicBool,
    /// Separate from [`Self::azp_fallback_warned`] on purpose: sharing one
    /// flag would let whichever mode logged first suppress the other.
    azp_permissive_logged: AtomicBool,
    /// Scope-to-role mappings.
    scopes: Vec<ScopeMapping>,
    /// Claim path that carries roles directly, when set.
    role_claim: Option<String>,
    /// Claim-value-to-role mappings.
    role_mappings: Vec<RoleMapping>,
    /// Tracks the last refresh attempt timestamp. Enforces a 10-second cooldown
    /// between refresh attempts to prevent abuse via fabricated JWTs with invalid kids.
    last_refresh_attempt: RwLock<Option<Instant>>,
    /// Serializes concurrent refresh attempts so only one fetch is in flight.
    refresh_lock: Mutex<()>,
    /// Compiled operator SSRF allowlist (empty by default = original
    /// fail-closed behaviour). Wrapped in `Arc` so the redirect-policy
    /// closure can capture a cheap clone without inflating the cache size.
    allowlist: Arc<CompiledSsrfAllowlist>,
    /// M-H2/B1: shared loopback bypass; same Arc is captured by the
    /// SSRF resolver inside the cached `reqwest::Client`. See the
    /// matching field on `OauthHttpClient`.
    #[cfg(any(test, feature = "test-helpers"))]
    test_allow_loopback_ssrf: TestLoopbackBypass,
}

/// Minimum interval between refresh attempts triggered by an unknown `kid`.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// Upper bound on an upstream OAuth proxy response body (`/token`,
/// `/introspect`, `/revoke`, and RFC 8693 token exchange).
///
/// The upstream is the operator-configured, SSRF-screened authorization
/// server, so this is defense-in-depth rather than an attacker-facing
/// control - but it keeps the proxy paths symmetric with the bounded JWKS
/// fetch (`jwks_max_response_bytes`) so a misbehaving or compromised IdP
/// cannot make the server buffer an unbounded response. 1 MiB comfortably
/// covers token, introspection, and revocation JSON payloads.
const OAUTH_PROXY_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Algorithms we accept from JWKS-served keys.
///
/// This is the crate-wide ceiling. `HS*` and `none` are deliberately absent:
/// a JWKS publishes public keys, so a symmetric secret must never become a
/// verification key, and RFC 9068 2.1 forbids `none` for access tokens.
/// [`OAuthConfig::allowed_algorithms`] may only NARROW this set, never widen
/// it.
const ACCEPTED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

/// The JWA name of an accepted algorithm, or `None` if it is not accepted.
///
/// Single source of truth for the strings operators write in
/// [`OAuthConfig::allowed_algorithms`], so config parsing and error messages
/// can never drift from [`ACCEPTED_ALGS`]. `accepted_algorithm_names_cover_accepted_algs`
/// asserts the two stay in lockstep.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "jsonwebtoken Algorithm is #[non_exhaustive], so an exhaustive match is impossible; HS*, `none`, and any future variant must fail closed to None"
)]
const fn accepted_algorithm_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::RS256 => Some("RS256"),
        Algorithm::RS384 => Some("RS384"),
        Algorithm::RS512 => Some("RS512"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::ES384 => Some("ES384"),
        Algorithm::PS256 => Some("PS256"),
        Algorithm::PS384 => Some("PS384"),
        Algorithm::PS512 => Some("PS512"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

/// Parse an operator-supplied algorithm name.
///
/// Case-insensitive so `rs256` and `RS256` both work. Returns `None` for any
/// name outside [`ACCEPTED_ALGS`] -- including `HS256` and `none` -- which is
/// what enforces the narrow-only rule at config-validation time.
fn accepted_algorithm_from_name(name: &str) -> Option<Algorithm> {
    ACCEPTED_ALGS
        .iter()
        .copied()
        .find(|alg| accepted_algorithm_name(*alg).is_some_and(|n| n.eq_ignore_ascii_case(name)))
}

/// Comma-separated list of every accepted algorithm name, for error messages.
fn accepted_algorithm_names() -> String {
    ACCEPTED_ALGS
        .iter()
        .filter_map(|alg| accepted_algorithm_name(*alg))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve the configured algorithm allowlist into concrete algorithms.
///
/// SECURITY (narrow-only): every name must resolve inside [`ACCEPTED_ALGS`].
/// `accepted_algorithm_from_name` returns `None` for `HS*` and `none`, so an
/// operator can never re-enable a symmetric or unsigned algorithm through
/// config. An empty list is rejected because it would silently reject every
/// token -- almost certainly an operator mistake rather than an intent to
/// disable OAuth.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Config`] when the list is empty or names an unsupported
/// algorithm.
pub(crate) fn resolve_allowed_algorithms(
    configured: Option<&[String]>,
) -> Result<Vec<Algorithm>, RmcpServerKitError> {
    let Some(names) = configured else {
        return Ok(ACCEPTED_ALGS.to_vec());
    };
    if names.is_empty() {
        return Err(RmcpServerKitError::Config(
            "oauth.allowed_algorithms must not be empty; omit the field to accept the default set"
                .into(),
        ));
    }
    let mut resolved = Vec::with_capacity(names.len());
    for name in names {
        let Some(alg) = accepted_algorithm_from_name(name) else {
            return Err(RmcpServerKitError::Config(format!(
                "oauth.allowed_algorithms contains unsupported algorithm {name:?}; \
                 permitted values are: {}",
                accepted_algorithm_names()
            )));
        };
        if !resolved.contains(&alg) {
            resolved.push(alg);
        }
    }
    Ok(resolved)
}

/// Coarse JWT validation failure classification for auth diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtValidationFailure {
    /// JWT was well-formed but expired per `exp` validation.
    Expired,
    /// JWT failed validation for all other reasons.
    Invalid,
}

/// JWT validation rejection plus optional verified credential owner details.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/oauth.rs::JwtRejection fields are read by src/auth.rs; accessors would churn the crate-internal API"
)]
pub(crate) struct JwtRejection {
    /// Why validation failed.
    pub(crate) failure: JwtValidationFailure,
    /// Verified credential owner details, when the endpoint wants them.
    pub(crate) owner: Option<CredentialOwner>,
}

/// A failed decode plus any expired-claim data recovered from it.
struct DecodeFailure {
    /// Classification of the decode failure.
    failure: JwtValidationFailure,
    /// Claims recovered from an expired token, for owner attribution.
    expired_claims: Option<Box<Claims>>,
}

impl JwksCache {
    /// Build a new cache from OAuth configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the CA bundle cannot be read, the HTTP client
    /// cannot be built, or `config.jwks_cache_ttl` is not a valid
    /// humantime duration. [`OAuthConfig::validate`] (run automatically by
    /// the typed
    /// [`McpServerConfig::validate`](crate::transport::McpServerConfig::validate)
    /// pipeline) rejects invalid TTLs up front, so the TTL branch is
    /// unreachable for validated configs.
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: src/oauth.rs::JwksCache::new keeps the screening, TLS and redirect setup in one reviewable block"
    )]
    #[inline]
    pub fn new(config: &OAuthConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Ensure crypto providers are installed (idempotent -- ok() ignores
        // the error if already installed by another call in the same process).
        drop(default_provider().install_default());
        if let Err(_already_installed) = DEFAULT_PROVIDER.install_default() {
            tracing::debug!("jsonwebtoken crypto provider already installed");
        }

        let ttl = humantime::parse_duration(&config.jwks_cache_ttl).map_err(|error| {
            format!(
                "invalid jwks_cache_ttl {:?}: {error}",
                config.jwks_cache_ttl
            )
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        // Note: validation.algorithms is overridden per-decode to [header.alg]
        // because jsonwebtoken requires all listed algorithms to share
        // the same key family. The ACCEPTED_ALGS whitelist is checked
        // separately before looking up the key.
        //
        // Audience validation is done manually after decode: we accept the
        // token if `aud` contains `config.audience` OR `azp == config.audience`.
        // This is correct per RFC 9068 Sec.4 + OIDC Core Sec.2: `aud` lists
        // resource servers, `azp` identifies the authorized client. When the
        // MCP server is both the OAuth client and the resource server (as in
        // our proxy setup), the configured audience may appear in either claim.
        validation.validate_aud = false;
        validation.set_issuer(&[&config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let allow_http = config.allow_http_oauth_urls;

        // Compile operator allowlist up-front so misconfiguration is
        // surfaced at startup rather than on first JWKS fetch.
        let allowlist = match config.ssrf_allowlist.as_ref() {
            Some(raw) => Arc::new(compile_oauth_ssrf_allowlist(raw).map_err(|error| {
                Box::<dyn Error + Send + Sync>::from(format!("oauth.ssrf_allowlist: {error}"))
            })?),
            None => Arc::new(CompiledSsrfAllowlist::default()),
        };
        let redirect_allowlist = Arc::clone(&allowlist);

        // M-H2: see OauthHttpClient::build for rationale; same pattern.
        #[cfg(any(test, feature = "test-helpers"))]
        let test_bypass: TestLoopbackBypass = Arc::new(AtomicBool::new(false));
        #[cfg(not(any(test, feature = "test-helpers")))]
        #[expect(
            clippy::cfg_not_test,
            reason = "deliberate: src/oauth.rs::new keeps the test-helpers alias arm cfg-gated"
        )]
        let test_bypass: TestLoopbackBypass = ();

        #[cfg_attr(
            any(
                not(feature = "oauth"),
                all(not(test), not(feature = "oauth-mtls-client"))
            ),
            expect(
                clippy::clone_on_copy,
                clippy::unit_arg,
                reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
            )
        )]
        #[cfg_attr(
            any(not(feature = "oauth"), test, feature = "metrics"),
            expect(
                clippy::clone_on_ref_ptr,
                reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
            )
        )]
        let resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
            Arc::clone(&allowlist),
            test_bypass.clone(),
        ));

        let mut http_builder = reqwest::Client::builder()
            // M-H2/N1: see OauthHttpClient::build.
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .redirect(Policy::custom(move |attempt| {
                // SECURITY: a redirect from `https` to `http` is *always*
                // rejected, even when `allow_http_oauth_urls` is true.
                // The flag controls whether the *original* request URL
                // may be plain HTTP; it never authorises a downgrade
                // mid-flight. An `http -> http` redirect is permitted
                // only when the flag is true (dev-only). The full
                // policy lives in `evaluate_oauth_redirect` so the
                // OauthHttpClient and JwksCache closures stay
                // byte-for-byte identical.
                match evaluate_oauth_redirect(&attempt, allow_http, &redirect_allowlist) {
                    Ok(()) => attempt.follow(),
                    Err(reason) => {
                        // Sanitized target: the rejected URL may carry
                        // userinfo credentials (the rejection reason
                        // itself is URL-free).
                        tracing::warn!(
                            reason = %reason,
                            target = %sanitized_url_for_log(attempt.url()),
                            "oauth redirect rejected"
                        );
                        attempt.error(reason)
                    }
                }
            }));

        if let Some(ca_path) = &config.ca_cert_path {
            // Pre-startup blocking I/O - runs before the runtime begins
            // serving requests, so blocking the current thread here is
            // intentional. Do not wrap in `spawn_blocking`: the constructor
            // is synchronous by contract and is called from `serve()`'s
            // pre-startup phase.
            let pem = fs::read(ca_path)?;
            let cert = Certificate::from_pem(&pem)?;
            http_builder = http_builder.add_root_certificate(cert);
        }

        let http = http_builder.build()?;

        Ok(Self {
            jwks_uri: config.jwks_uri.clone(),
            ttl,
            max_jwks_keys: config.max_jwks_keys,
            allowed_algorithms: resolve_allowed_algorithms(config.allowed_algorithms.as_deref())?,
            max_response_bytes: config.jwks_max_response_bytes,
            allow_http,
            inner: RwLock::new(None),
            http,
            validation_template: validation,
            expected_audience: config.audience.clone(),
            audience_mode: config.effective_audience_validation_mode(),
            require_subject: config.require_subject,
            azp_fallback_warned: AtomicBool::new(false),
            azp_permissive_logged: AtomicBool::new(false),
            scopes: config.scopes.clone(),
            role_claim: config.role_claim.clone(),
            role_mappings: config.role_mappings.clone(),
            last_refresh_attempt: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            allowlist,
            #[cfg(any(test, feature = "test-helpers"))]
            test_allow_loopback_ssrf: test_bypass,
        })
    }

    /// Test-only: disable initial-target SSRF screening for loopback-backed
    /// fixtures. This is unreachable from normal production builds and exists
    /// only so tests can fetch JWKS from local mock servers.
    ///
    /// # ⚠️ Security
    ///
    /// Disables the JWKS fetcher's SSRF guard loopback rejection, allowing
    /// loopback JWKS targets that production OAuth screening would reject.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn __test_allow_loopback_ssrf(self) -> Self {
        // M-H2/B1: flip the SHARED atomic so the resolver inside the
        // cached client and the pre-flight check both observe the bypass.
        self.test_allow_loopback_ssrf.store(true, Ordering::Relaxed);
        self
    }

    /// Validate a JWT Bearer token. Returns `Some(AuthIdentity)` on success.
    #[inline]
    pub async fn validate_token(&self, token: &str) -> Option<AuthIdentity> {
        self.validate_token_with_reason(token).await.ok()
    }

    /// Validate a JWT Bearer token with failure classification.
    ///
    /// # Errors
    ///
    /// Returns [`JwtValidationFailure::Expired`] when the JWT is expired,
    /// or [`JwtValidationFailure::Invalid`] for all other validation failures.
    // cancel-safe: composed of cancel-safe `decode_claims` (spawn_blocking
    // decode, no shared state) plus pure, side-effect-free claim checks
    // (`check_audience`, `resolve_role`). No partial state on cancellation.
    #[inline]
    pub async fn validate_token_with_reason(
        &self,
        token: &str,
    ) -> Result<AuthIdentity, JwtValidationFailure> {
        self.validate_token_detailed(token, false)
            .await
            .map_err(|rejection| rejection.failure)
    }

    /// Validate a JWT Bearer token with internal rejection owner attribution.
    // cancel-safe: composed of cancel-safe `decode_claims` (spawn_blocking
    // decode, no shared state) plus pure claim checks. Owner attribution uses
    // already-verified claims or expired claims from the same blocking decode.
    // No partial state is committed on cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`JwtRejection`] carrying the failure classification and optional owner.
    pub(crate) async fn validate_token_detailed(
        &self,
        token: &str,
        want_owner: bool,
    ) -> Result<AuthIdentity, JwtRejection> {
        let claims = match self.decode_claims(token, want_owner).await {
            Ok(claims) => claims,
            Err(failure) => {
                let owner = match (want_owner, failure.expired_claims.as_ref()) {
                    (true, Some(claims)) => Some(CredentialOwner {
                        name: identity_label(claims, claims.sub.as_deref()),
                        reason: RejectionReason::Expired,
                    }),
                    (true | false, None) | (false, Some(_)) => None,
                };
                return Err(JwtRejection {
                    failure: failure.failure,
                    owner,
                });
            }
        };

        // `require_subject` must also reject a *blank* sub: it is the OAuth
        // session-binding stable id, so a blank one collapses distinct
        // principals to one fingerprint (CWE-384).
        if self.require_subject
            && claims
                .sub
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
        {
            cold_path();
            tracing::debug!(
                "JWT rejected: require_subject is set but the token has no non-blank `sub`"
            );
            return Err(JwtRejection {
                failure: JwtValidationFailure::Invalid,
                owner: want_owner.then(|| CredentialOwner {
                    name: identity_label(&claims, claims.sub.as_deref()),
                    reason: RejectionReason::Subject,
                }),
            });
        }
        if let Err(failure) = self.check_audience(&claims) {
            return Err(JwtRejection {
                failure,
                owner: want_owner.then(|| CredentialOwner {
                    name: identity_label(&claims, claims.sub.as_deref()),
                    reason: RejectionReason::Audience,
                }),
            });
        }
        let role = match self.resolve_role(&claims) {
            Ok(role) => role,
            Err(failure) => {
                return Err(JwtRejection {
                    failure,
                    owner: want_owner.then(|| CredentialOwner {
                        name: identity_label(&claims, claims.sub.as_deref()),
                        reason: RejectionReason::Role,
                    }),
                });
            }
        };

        // Store a blank `sub` as `None` so `fingerprint` never keys on a blank
        // stable id.
        let sub = claims
            .sub
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(String::from);

        let name = identity_label(&claims, sub.as_deref());

        Ok(AuthIdentity {
            name,
            role,
            method: AuthMethod::OAuthJwt,
            raw_token: None,
            sub,
        })
    }

    /// Decode and fully verify a JWT, returning its claims.
    ///
    /// Performs header decode, algorithm allow-list check, JWKS key lookup
    /// (with on-demand refresh), signature verification, and standard
    /// claim validation (exp/nbf/iss) against the template.
    ///
    /// The CPU-bound `jsonwebtoken::decode` call (RSA / ECDSA signature
    /// verification) is offloaded to [`tokio::task::spawn_blocking`] so a
    /// burst of concurrent JWT validations never starves other tasks on
    /// the multi-threaded runtime's worker pool. The blocking pool absorbs
    /// the verification cost; the async path stays responsive.
    // cancel-safe: `select_jwks_key` (cancel-safe: read-only lookup + idempotent
    // refresh) then a `spawn_blocking` decode whose `JoinHandle`, if dropped on
    // cancellation, detaches the verification (it completes off-task). No shared
    // state is mutated on this path.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeFailure`] carrying the failure classification and any expired claims.
    async fn decode_claims(
        &self,
        token: &str,
        want_expired_claims: bool,
    ) -> Result<Claims, DecodeFailure> {
        let (key, alg) = self
            .select_jwks_key(token)
            .await
            .map_err(|failure| DecodeFailure {
                failure,
                expired_claims: None,
            })?;

        // Build a per-decode validation scoped to the header's algorithm.
        // jsonwebtoken requires ALL algorithms in the list to share the
        // same family as the key, so we restrict to [alg] only.
        let mut validation = self.validation_template.clone();
        validation.algorithms = vec![alg];

        // Move the (cheap) clones into the blocking task so the verifier
        // does not hold a reference into the request's async scope.
        let token_owned = token.to_owned();
        let dispatch = dispatcher::get_default(Clone::clone);
        let join = spawn_blocking(move || {
            dispatcher::with_default(&dispatch, || {
                let first = decode::<Claims>(&token_owned, &key, &validation);
                if want_expired_claims
                    && let Err(error) = &first
                    && matches!(error.kind(), ErrorKind::ExpiredSignature)
                {
                    tracing::debug!("JWT expired; re-decoding without exp for owner attribution");
                    let mut expired_validation = validation.clone();
                    expired_validation.validate_exp = false;
                    let expired_claims = decode::<Claims>(&token_owned, &key, &expired_validation)
                        .ok()
                        .map(|data| Box::new(data.claims));
                    return (first, expired_claims);
                }
                (first, None)
            })
        })
        .await;

        let decode_result = match join {
            Ok(decoded) => decoded,
            Err(join_err) => {
                cold_path();
                tracing::error!(
                    error = %join_err,
                    "JWT decode task panicked or was cancelled"
                );
                return Err(DecodeFailure {
                    failure: JwtValidationFailure::Invalid,
                    expired_claims: None,
                });
            }
        };

        decode_result.0.map(|td| td.claims).map_err(|error| {
            cold_path();
            let failure = if matches!(error.kind(), ErrorKind::ExpiredSignature) {
                JwtValidationFailure::Expired
            } else {
                JwtValidationFailure::Invalid
            };
            tracing::debug!(error = %error, ?alg, ?failure, "JWT decode failed");
            DecodeFailure {
                failure,
                expired_claims: decode_result.1,
            }
        })
    }

    /// Decode the JWT header, check the algorithm against the allow-list,
    /// and look up the matching JWKS key (refreshing on miss).
    //
    // Complexity: 28/25. Three structured early-returns each pair a
    // `cold_path()` hint with a distinct `tracing::debug!` site so the
    // failure is observable. Collapsing them into a combinator chain
    // would lose those structured-field log sites without reducing
    // real cognitive load.
    // NOT cancel-safe: on a cache miss this delegates to `find_key`, which can
    // enter `refresh_with_cooldown`. That commits `last_refresh_attempt` before
    // fetching, so a cancellation mid-refresh still consumes the cooldown slot
    // and the next caller may be refused a refresh for the cooldown window.
    #[expect(
        clippy::cognitive_complexity,
        reason = "each failure arm pairs `cold_path()` with a distinct `tracing::debug!` site for observability; collapsing into combinators would lose structured-field log sites without reducing real complexity"
    )]
    ///
    /// # Errors
    ///
    /// Returns a message when no key in the refreshed JWKS can verify the token.
    async fn select_jwks_key(
        &self,
        token: &str,
    ) -> Result<(DecodingKey, Algorithm), JwtValidationFailure> {
        let Ok(header) = decode_header(token) else {
            cold_path();
            tracing::debug!("JWT header decode failed");
            return Err(JwtValidationFailure::Invalid);
        };
        let kid = header.kid.as_deref();
        tracing::debug!(alg = ?header.alg, kid = kid.unwrap_or("-"), "JWT header decoded");

        if !self.allowed_algorithms.contains(&header.alg) {
            cold_path();
            tracing::debug!(alg = ?header.alg, "JWT algorithm not accepted");
            return Err(JwtValidationFailure::Invalid);
        }

        let Some(key) = self.find_key(kid, header.alg).await else {
            cold_path();
            tracing::debug!(kid = kid.unwrap_or("-"), alg = ?header.alg, "no matching JWKS key found");
            return Err(JwtValidationFailure::Invalid);
        };

        Ok((key, header.alg))
    }

    /// Manual audience check.
    ///
    /// Resolves per [`AudienceValidationMode`]: `aud` matches always
    /// accept silently. `azp`-only matches accept silently in
    /// [`AudienceValidationMode::Permissive`], accept with a one-shot
    /// `tracing::warn!` per process in [`AudienceValidationMode::Warn`],
    /// and reject in [`AudienceValidationMode::Strict`]. No-claim-match
    /// always rejects.
    ///
    /// # Errors
    ///
    /// Returns the [`JwtValidationFailure`] classification for the mismatch.
    fn check_audience(&self, claims: &Claims) -> Result<(), JwtValidationFailure> {
        if claims.aud.contains(&self.expected_audience) {
            return Ok(());
        }
        let azp_match = claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp == self.expected_audience);
        if azp_match {
            match self.audience_mode {
                AudienceValidationMode::Permissive => {
                    if !self.azp_permissive_logged.swap(true, Ordering::Relaxed) {
                        tracing::info!(
                            expected = %self.expected_audience,
                            "JWT accepted via azp-only audience fallback because \
                             audience_validation_mode = \"permissive\". Acceptance is \
                             intentionally wider than the spec; set \"warn\" or \"strict\" \
                             to tighten it. This message logs once per process."
                        );
                    }
                    return Ok(());
                }
                AudienceValidationMode::Warn => {
                    if !self.azp_fallback_warned.swap(true, Ordering::Relaxed) {
                        tracing::warn!(
                            expected = %self.expected_audience,
                            azp = claims.azp.as_deref().unwrap_or("-"),
                            "JWT accepted via deprecated azp-only audience fallback. \
                             Configure your IdP to populate aud, or set \
                             audience_validation_mode = \"strict\" once tokens carry aud correctly. \
                             To silence this warning without changing acceptance, \
                             set audience_validation_mode = \"permissive\". \
                             This warning logs once per process."
                        );
                    }
                    return Ok(());
                }
                AudienceValidationMode::Strict => {}
            }
        }
        cold_path();
        self.log_audience_mismatch(claims);
        Err(JwtValidationFailure::Invalid)
    }

    /// Log an audience-mismatch rejection.
    ///
    /// The token's own claim values (`aud`, `azp`) are gated behind the
    /// operator diagnostic switch, matching `log_exchanged_token`.
    /// `expected` and `mode` are local configuration rather than token
    /// material, so they stay visible for debuggability.
    fn log_audience_mismatch(&self, claims: &Claims) {
        let expose = oauth_claim_values();
        let aud = if expose {
            claims.aud.log_display()
        } else {
            "[REDACTED]".to_owned()
        };
        let azp = if expose {
            claims.azp.as_deref().unwrap_or("-")
        } else {
            "[REDACTED]"
        };
        tracing::debug!(
            aud = %aud,
            azp = azp,
            expected = %self.expected_audience,
            mode = self.audience_mode.as_str(),
            "JWT rejected: audience mismatch"
        );
    }

    /// Resolve the role for this token.
    ///
    /// When `role_claim` is set, extract values from the given claim path
    /// and match against `role_mappings`. Otherwise, match space-separated
    /// tokens in the `scope` claim against configured scope mappings.
    ///
    /// # Errors
    ///
    /// Returns [`JwtValidationFailure::Invalid`] when no mapping matches.
    fn resolve_role(&self, claims: &Claims) -> Result<String, JwtValidationFailure> {
        if let Some(claim_path) = &self.role_claim {
            let owned_first_class: Vec<String> = first_class_claim_values(claims, claim_path);
            let mut values: Vec<&str> = owned_first_class.iter().map(String::as_str).collect();
            values.extend(resolve_claim_path(&claims.extra, claim_path));
            return self
                .role_mappings
                .iter()
                .find(|mapping| values.contains(&mapping.claim_value.as_str()))
                .map(|mapping| mapping.role.clone())
                .ok_or(JwtValidationFailure::Invalid);
        }

        let token_scopes: Vec<&str> = claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();

        self.scopes
            .iter()
            .find(|mapping| token_scopes.contains(&mapping.scope.as_str()))
            .map(|mapping| mapping.role.clone())
            .ok_or(JwtValidationFailure::Invalid)
    }

    /// Look up a decoding key by kid + algorithm. Refreshes JWKS on miss,
    /// subject to cooldown and deduplication constraints.
    // cancel-safe: reads the key cache under a `tokio::sync::RwLock` and, on a
    // miss, delegates to the idempotent `refresh_with_cooldown`. Cancellation at
    // any await leaves the cache in its prior consistent state.
    async fn find_key(&self, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
        // Try cached keys first.
        {
            let guard = self.inner.read().await;
            if let Some(cached) = guard.as_ref()
                && !cached.is_expired()
                && let Some(key) = lookup_key(cached, kid, alg)
            {
                return Some(key);
            }
        }

        // Cache miss or expired -- refresh (with cooldown/deduplication).
        self.refresh_with_cooldown().await;

        // Fail closed (H2): a failed or cooled-down refresh leaves the previous
        // (now-expired) cache in place. Re-apply the freshness gate the first
        // lookup enforces so a rotated-out key is never served from a stale
        // cache -- otherwise an attacker who can stall the JWKS endpoint could
        // keep a revoked signing key valid past its TTL.
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .filter(|cached| !cached.is_expired())
            .and_then(|cached| lookup_key(cached, kid, alg))
    }

    /// Refresh JWKS with cooldown and concurrent deduplication.
    ///
    /// - Only one refresh in flight at a time (concurrent waiters share result).
    /// - At most one refresh per [`JWKS_REFRESH_COOLDOWN`] (10 seconds).
    ///
    /// # Cancellation
    ///
    /// **NOT cancel-safe by design.** `last_refresh_attempt` is committed
    /// *before* the fetch so that a burst of failing or cancelled refreshes
    /// cannot hammer the JWKS endpoint (the invalid-JWT → JWKS-refresh DoS
    /// class; see `AGENTS.md` pitfall #2). The consequence is a deliberate
    /// trade-off: if this future is cancelled between the timestamp write and
    /// cache publication, a genuinely-new `kid` may be rejected for up to
    /// [`JWKS_REFRESH_COOLDOWN`] (10s). Endpoint DoS protection is preferred
    /// over immediate post-cancellation retriability. Do **not** "fix" this by
    /// bypassing the cooldown on unknown-`kid` requests - that reopens the
    /// DoS-amplification vector the cooldown exists to close.
    // NOT cancel-safe: see the `# Cancellation` section above - cooldown is
    // committed before the fetch to throttle JWKS-endpoint abuse.
    async fn refresh_with_cooldown(&self) {
        // Acquire the mutex to serialize refresh attempts.
        let _guard = self.refresh_lock.lock().await;

        // Check cooldown: skip if we refreshed recently.
        {
            let last = self.last_refresh_attempt.read().await;
            if let Some(ts) = *last
                && ts.elapsed() < JWKS_REFRESH_COOLDOWN
            {
                tracing::info!(
                    elapsed_ms = ts.elapsed().as_millis(),
                    cooldown_ms = JWKS_REFRESH_COOLDOWN.as_millis(),
                    "JWKS refresh skipped (cooldown active)"
                );
                return;
            }
        }

        // Update last refresh timestamp BEFORE the fetch attempt.
        // This ensures the cooldown applies even if the fetch fails.
        {
            let mut last = self.last_refresh_attempt.write().await;
            *last = Some(Instant::now());
        }

        // Perform the actual fetch.
        // The error is already logged inside `refresh_inner`; the cooldown
        // stamp above must stand regardless so a failing upstream cannot be
        // hammered by fabricated-kid floods.
        if let Err(error) = self.refresh_inner().await {
            tracing::debug!(%error, "JWKS refresh failed; 10s cooldown preserved");
        }
    }

    /// Fetch JWKS from the configured URI and update the cache.
    ///
    /// Internal implementation - callers should use [`Self::refresh_with_cooldown`]
    /// to respect rate limiting.
    // cancel-safe (cache integrity): the cache is published via a single
    // `*guard = Some(..)` assignment under the `tokio::sync::RwLock` write lock
    // at the end. Cancellation before that point leaves the prior cache intact;
    // it never observes a half-built cache.
    ///
    /// # Errors
    ///
    /// Returns the `build_key_cache` message when the JWKS exceeds the key cap.
    async fn refresh_inner(&self) -> Result<(), String> {
        let Some(jwks) = self.fetch_jwks().await else {
            return Ok(());
        };
        let (keys, unnamed_keys) = match build_key_cache(&jwks, self.max_jwks_keys) {
            Ok(cache) => cache,
            Err(msg) => {
                tracing::warn!(reason = %msg, "JWKS key cap exceeded; refusing to populate cache");
                return Err(msg);
            }
        };

        tracing::debug!(
            named = keys.len(),
            unnamed = unnamed_keys.len(),
            "JWKS refreshed"
        );

        let mut guard = self.inner.write().await;
        *guard = Some(CachedKeys {
            keys,
            unnamed_keys,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        drop(guard);
        Ok(())
    }

    /// Fetch and parse the JWKS document. Returns `None` and logs on failure.
    #[expect(
        clippy::cognitive_complexity,
        reason = "screening, bounded streaming, and parse logging are intentionally kept in one fetch path"
    )]
    // cancel-safe (cache integrity): screening, `send`, chunk reads, and JSON
    // parse build only a local body/JWK set; cache publication happens later
    // via one `refresh_inner` write-lock assignment, so old cache stays intact.
    async fn fetch_jwks(&self) -> Option<JwkSet> {
        #[cfg(any(test, feature = "test-helpers"))]
        let screening = if self.test_allow_loopback_ssrf.load(Ordering::Relaxed) {
            screen_oauth_target_with_test_override(
                &self.jwks_uri,
                self.allow_http,
                &self.allowlist,
                true,
            )
            .await
        } else {
            screen_oauth_target(&self.jwks_uri, self.allow_http, &self.allowlist).await
        };
        #[cfg(not(any(test, feature = "test-helpers")))]
        #[expect(
            clippy::cfg_not_test,
            reason = "deliberate: src/oauth.rs::fetch_jwks keeps the test-helpers alias arm cfg-gated"
        )]
        let screening = screen_oauth_target(&self.jwks_uri, self.allow_http, &self.allowlist).await;

        if let Err(error) = screening {
            tracing::warn!(
                error = %error,
                uri = %oauth_request_target_for_log(&self.jwks_uri),
                "failed to screen JWKS target"
            );
            return None;
        }

        let mut resp = match self.http.get(&self.jwks_uri).send().await {
            Ok(resp) => resp,
            Err(error) => {
                tracing::warn!(
                    error = %error.without_url(),
                    uri = %oauth_request_target_for_log(&self.jwks_uri),
                    "failed to fetch JWKS"
                );
                return None;
            }
        };

        let initial_capacity =
            usize::try_from(self.max_response_bytes.min(64 * 1024)).unwrap_or(64 * 1024);
        let mut body = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = match resp.chunk().await {
            Ok(chunk) => chunk,
            Err(error) => {
                tracing::warn!(
                    error = %error.without_url(),
                    uri = %oauth_request_target_for_log(&self.jwks_uri),
                    "failed to read JWKS response"
                );
                return None;
            }
        } {
            let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
            if body_len.saturating_add(chunk_len) > self.max_response_bytes {
                tracing::warn!(
                    uri = %oauth_request_target_for_log(&self.jwks_uri),
                    max_bytes = self.max_response_bytes,
                    "JWKS response exceeded configured size cap"
                );
                return None;
            }
            body.extend_from_slice(&chunk);
        }

        match serde_json::from_slice::<JwkSet>(&body) {
            Ok(jwks) => Some(jwks),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    uri = %oauth_request_target_for_log(&self.jwks_uri),
                    "failed to parse JWKS"
                );
                None
            }
        }
    }

    /// Test-only: drive `refresh_inner` now, surfacing the
    /// `build_key_cache` error string. Used by `tests/integration/jwks_key_cap.rs`.
    ///
    /// # ⚠️ Security
    ///
    /// Bypasses `refresh_with_cooldown` and therefore `JWKS_REFRESH_COOLDOWN`,
    /// the DoS protection that prevents invalid-JWT floods from hammering the
    /// identity provider's JWKS endpoint.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub async fn __test_refresh_now(&self) -> Result<(), String> {
        let jwks = self
            .fetch_jwks()
            .await
            .ok_or_else(|| "failed to fetch or parse JWKS".to_owned())?;
        let (keys, unnamed_keys) = build_key_cache(&jwks, self.max_jwks_keys)?;
        let mut guard = self.inner.write().await;
        *guard = Some(CachedKeys {
            keys,
            unnamed_keys,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        drop(guard);
        Ok(())
    }

    /// Test-only: returns whether the cache currently contains the
    /// supplied kid. Read-only; takes the cache lock briefly.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub async fn __test_has_kid(&self, kid: &str) -> bool {
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .is_some_and(|cache| cache.keys.contains_key(kid))
    }
}

/// Human-readable identity label: `preferred_username`, else `sub`/`azp`/`client_id`, else
/// `oauth-client`.
fn identity_label(claims: &Claims, sub: Option<&str>) -> String {
    claims
        .extra
        .get("preferred_username")
        .and_then(|value| value.as_str())
        .filter(|text| !text.trim().is_empty())
        .map(String::from)
        .or_else(|| sub.filter(|text| !text.trim().is_empty()).map(String::from))
        .or_else(|| claims.azp.clone().filter(|text| !text.trim().is_empty()))
        .or_else(|| {
            claims
                .client_id
                .clone()
                .filter(|text| !text.trim().is_empty())
        })
        .unwrap_or_else(|| "oauth-client".into())
}

/// Partition a JWKS into a kid-indexed map plus a list of unnamed keys.
/// Longest `kid` prefix emitted to logs.
const MAX_LOGGED_KID_CHARS: usize = 64;

/// Truncate an issuer-supplied `kid` to [`MAX_LOGGED_KID_CHARS`] before it
/// reaches a log line.
///
/// `kid` is remote-controlled text of unbounded length, so logging it raw
/// lets a hostile or misconfigured issuer inflate log volume. Truncation is
/// on a char boundary to keep the output valid UTF-8.
fn truncate_kid_for_log(kid: &str) -> (String, bool) {
    if kid.chars().count() <= MAX_LOGGED_KID_CHARS {
        return (kid.to_owned(), false);
    }
    let head: String = kid.chars().take(MAX_LOGGED_KID_CHARS).collect();
    (format!("{head}...(truncated)"), true)
}

/// Render a JWK's `kid` for logging, bounded, with a placeholder when absent.
fn jwk_kid_for_log(jwk: &Jwk) -> (String, bool) {
    jwk.common
        .key_id
        .as_deref()
        .map_or_else(|| ("<no-kid>".to_owned(), false), truncate_kid_for_log)
}

/// Classify a single JWK into a cacheable (algorithm-constraint, key) pair.
///
/// Returns `None` for every fail-closed case: a key whose declared `use`/
/// `key_ops` forbid signature verification, a key `jsonwebtoken` cannot decode,
/// and a key whose algorithm can be neither read nor inferred.
fn classify_jwk(jwk: &Jwk) -> Option<(JwkAlg, DecodingKey)> {
    if !jwk_permits_signature_verification(jwk) {
        let (kid_log, kid_truncated) = jwk_kid_for_log(jwk);
        tracing::debug!(
            kid = %kid_log,
            kid_truncated,
            "skipping JWKS key not permitted for signature verification (use/key_ops)"
        );
        return None;
    }
    let decoding_key = DecodingKey::from_jwk(jwk).ok()?;
    let alg = jwk_algorithm(jwk)?;
    if let JwkAlg::Family(family) = alg {
        let (kid_log, kid_truncated) = jwk_kid_for_log(jwk);
        tracing::debug!(
            kid = %kid_log,
            kid_truncated,
            family = ?family,
            "JWKS key omits `alg`; inferring permitted algorithms from key type (RFC 7517 4.4)"
        );
    }
    Some((alg, decoding_key))
}

/// Partition a JWKS into a kid-indexed map plus a list of unnamed keys.
///
/// # Errors
///
/// Returns a message when the JWKS carries more than `max_keys` keys.
fn build_key_cache(jwks: &JwkSet, max_keys: usize) -> Result<JwksKeyCache, String> {
    if jwks.keys.len() > max_keys {
        return Err(format!(
            "jwks_key_count_exceeds_cap: got {} keys, max is {max_keys}",
            jwks.keys.len()
        ));
    }
    let mut keys = HashMap::new();
    let mut unnamed_keys = Vec::new();
    for jwk in &jwks.keys {
        let Some((alg, decoding_key)) = classify_jwk(jwk) else {
            continue;
        };
        if let Some(kid) = &jwk.common.key_id {
            if keys.insert(kid.clone(), (alg, decoding_key)).is_some() {
                let (kid_log, kid_truncated) = truncate_kid_for_log(kid);
                tracing::warn!(
                    kid = %kid_log,
                    kid_truncated,
                    "duplicate kid in JWKS; later entry wins"
                );
            }
        } else {
            unnamed_keys.push((alg, decoding_key));
        }
    }
    Ok((keys, unnamed_keys))
}

/// Look up a key from the cache by kid (if present) or by algorithm.
fn lookup_key(cached: &CachedKeys, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
    if let Some(key_id) = kid {
        // A token carrying a `kid` must match a NAMED JWKS key exactly; it
        // must NOT fall back to an unnamed key. Otherwise an attacker could
        // present an unknown `kid` and be validated against an unrelated
        // unnamed key of the same algorithm (L4, fail-closed key selection).
        if let Some((cached_alg, key)) = cached.keys.get(key_id)
            && cached_alg.accepts(alg)
        {
            return Some(key.clone());
        }
        return None;
    }
    // No `kid`: fall back to any unnamed key that permits this algorithm.
    cached
        .unnamed_keys
        .iter()
        .find(|(cached_alg, _)| cached_alg.accepts(alg))
        .map(|(_, key)| key.clone())
}

/// Whether a JWK is permitted to act as a JWT **signature verification**
/// key, per its declared intent.
///
/// SECURITY (key-use separation, RFC 7517 4.2/4.3): `DecodingKey::from_jwk`
/// does NOT enforce `use` or `key_ops`, so without this gate an issuer that
/// publishes signing and encryption keys in one JWKS would have its
/// encryption keys silently accepted as verification keys. Anyone holding
/// such a key's private half could then mint tokens this server trusts.
///
/// Both parameters are optional; absent means unconstrained and is accepted
/// (RFC 7517 says `use` is optional unless the application requires it).
/// When present they are enforced fail-closed.
fn jwk_permits_signature_verification(jwk: &Jwk) -> bool {
    use jsonwebtoken::jwk::{KeyOperations, PublicKeyUse};

    let use_ok = match jwk.common.public_key_use {
        None | Some(PublicKeyUse::Signature) => true,
        Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_)) => false,
    };
    // RFC 7517 4.3: when key_ops is present it enumerates the permitted
    // operations exhaustively, so a key without "verify" must be refused.
    let ops_ok = jwk
        .common
        .key_operations
        .as_ref()
        .is_none_or(|ops| ops.contains(&KeyOperations::Verify));

    use_ok && ops_ok
}

/// Determine how a JWK constrains the algorithms it may verify.
///
/// An explicit `alg` pins exactly one algorithm (unchanged behaviour). When
/// `alg` is absent -- which RFC 7517 4.4 explicitly permits, and which Entra
/// v2.0 always does -- the key type implies the family instead. Returning
/// `None` drops the key, so unknown or symmetric key types stay fail-closed.
fn jwk_algorithm(jwk: &Jwk) -> Option<JwkAlg> {
    jwk.common.key_algorithm.map_or_else(
        || infer_jwk_family(jwk).map(JwkAlg::Family),
        |declared| explicit_jwk_algorithm(declared).map(JwkAlg::Explicit),
    )
}

/// Map a declared JWK `alg` onto a supported JWS algorithm.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "jsonwebtoken KeyAlgorithm is a large external enum; only the JWT-signing variants are mappable to `Algorithm`"
)]
const fn explicit_jwk_algorithm(declared: KeyAlgorithm) -> Option<Algorithm> {
    match declared {
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

/// Infer the algorithm family of a JWK that omitted `alg`, from its key type.
///
/// SECURITY: inference reads only the JWK's own key material, never the token
/// header, so it cannot be steered by an attacker. `OctetKey` (symmetric) is
/// deliberately never inferred -- an `HS*` secret must not become a
/// verification key -- and `P-521` yields `None` because `jsonwebtoken` 11
/// defines no `ES512` variant (its own `EllipticCurve::P521` doc notes the
/// curve is unsupported by `ring`).
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "jsonwebtoken AlgorithmParameters and EllipticCurve are both #[non_exhaustive] external enums, so an exhaustive match is impossible; unmatched variants must fail closed to None"
)]
const fn infer_jwk_family(jwk: &Jwk) -> Option<JwkKeyFamily> {
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};

    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(JwkKeyFamily::Rsa),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(JwkKeyFamily::EcP256),
            EllipticCurve::P384 => Some(JwkKeyFamily::EcP384),
            _ => None,
        },
        AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            EllipticCurve::Ed25519 => Some(JwkKeyFamily::Ed25519),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Claim path resolution
// ---------------------------------------------------------------------------

/// Resolve a `role_claim` path against the explicit [`Claims`] fields
/// (`sub`, `aud`, `azp`, `client_id`, `scope`).
///
/// Operators commonly configure `role_claim = "scope"` or `"sub"` /
/// `"client_id"` to map first-class JWT claims to roles. These claims are
/// captured by [`Claims`] as named fields, so they never appear in the
/// `extra` map that [`resolve_claim_path`] inspects. This helper bridges
/// that gap by returning owned `String`s for those first-class fields
/// when the claim path matches one of them; the caller layers the result
/// over [`resolve_claim_path`] so dot-paths into custom claims continue
/// to work.
///
/// `scope` is split on whitespace per the OAuth 2.0 convention so a token
/// like `scope = "read write"` matches `claim_value = "read"` or
/// `"write"`. `aud` returns every audience entry. Other fields return
/// their value as a single element when present.
fn first_class_claim_values(claims: &Claims, path: &str) -> Vec<String> {
    match path {
        "sub" => claims.sub.iter().cloned().collect(),
        "azp" => claims.azp.iter().cloned().collect(),
        "client_id" => claims.client_id.iter().cloned().collect(),
        "aud" => claims.aud.0.clone(),
        "scope" => claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Resolve a dot-separated claim path to a list of string values.
///
/// Handles three shapes:
/// - **String**: split on whitespace (OAuth `scope` convention).
/// - **Array of strings**: each element becomes a value (Keycloak `realm_access.roles`).
/// - **Nested object**: traversed by dot-separated segments (e.g. `realm_access.roles`).
///
/// Returns an empty vec if the path does not exist or the leaf is not a
/// string/array.
fn resolve_claim_path<'path>(
    extra: &'path HashMap<String, serde_json::Value>,
    path: &str,
) -> Vec<&'path str> {
    let mut segments = path.split('.');
    let Some(first) = segments.next() else {
        return Vec::new();
    };

    let mut current: Option<&serde_json::Value> = extra.get(first);

    for segment in segments {
        current = current.and_then(|node| node.get(segment));
    }

    match current {
        Some(serde_json::Value::String(text)) => text.split_whitespace().collect(),
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().filter_map(|element| element.as_str()).collect()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/// Standard + common JWT claims we care about.
#[derive(Debug, Deserialize)]
struct Claims {
    /// Subject (user or service account).
    sub: Option<String>,
    /// Audience - resource servers the token is intended for.
    /// Can be a single string or an array of strings per RFC 7519 Sec.4.1.3.
    #[serde(default)]
    aud: OneOrMany,
    /// Authorized party (OIDC Core Sec.2) - the OAuth client that was issued the token.
    azp: Option<String>,
    /// Client ID (some providers use this instead of azp).
    client_id: Option<String>,
    /// Space-separated scope string (OAuth 2.0 convention).
    scope: Option<String>,
    /// All remaining claims, captured for `role_claim` dot-path resolution.
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Deserializes a JWT claim that can be either a single string or an array of strings.
#[derive(Debug, Default)]
struct OneOrMany(Vec<String>);

impl OneOrMany {
    /// Whether any element matches `value` exactly.
    fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|candidate| candidate == value)
    }

    /// Render the audience list as a single comma-separated string for
    /// structured logging (e.g. `aud="a, b"`), preserving every entry so
    /// no debugging signal is lost. An empty list renders as `"-"`.
    fn log_display(&self) -> String {
        if self.0.is_empty() {
            "-".to_owned()
        } else {
            self.0.join(", ")
        }
    }
}

/// Format a JSON `aud` claim (string OR array of strings) for structured
/// logging without losing shape.
///
/// The `aud` claim is legitimately either a single string or an array
/// (RFC 7519 §4.1.3). Rendering via `serde_json::Value::as_str()` alone
/// would drop array audiences (returns `None` → `"-"`), hiding real
/// values in the log. This joins arrays with `", "`, passes strings
/// through, and falls back to `"-"` only when the claim is truly absent
/// or an unexpected JSON type.
fn fmt_json_aud(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Array(items)) => {
            let joined = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if joined.is_empty() {
                "-".to_owned()
            } else {
                joined
            }
        }
        Some(
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::Object(_),
        )
        | None => "-".to_owned(),
    }
}

/// Render an optional JSON claim as a plain string for logging, without the
/// `Debug` wrapper/escaping (e.g. `sub="alice"` not `sub=Some(String("alice"))`).
/// Non-string or absent claims render as `"-"`.
fn fmt_json_str(value: Option<&serde_json::Value>) -> &str {
    value.and_then(serde_json::Value::as_str).unwrap_or("-")
}

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = OneOrMany;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or array of strings")
            }
            fn visit_str<E>(self, v: &str) -> Result<OneOrMany, E>
            where
                E: de::Error,
            {
                Ok(OneOrMany(vec![v.to_owned()]))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<OneOrMany, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<String>()? {
                    items.push(item);
                }
                Ok(OneOrMany(items))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

// ---------------------------------------------------------------------------
// JWT detection heuristic
// ---------------------------------------------------------------------------

/// Returns true if the token looks like a JWT (3 dot-separated segments
/// where the first segment decodes to JSON containing `"alg"`).
#[must_use]
#[inline]
pub fn looks_like_jwt(token: &str) -> bool {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut parts = token.splitn(4, '.');
    let Some(header_b64) = parts.next() else {
        return false;
    };
    // Must have exactly 3 segments.
    if parts.next().is_none() || parts.next().is_none() || parts.next().is_some() {
        return false;
    }
    // Try to decode the header segment.
    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
        return false;
    };
    // Check for "alg" key in the JSON.
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return false;
    };
    header.get("alg").is_some()
}

// ---------------------------------------------------------------------------
// Protected Resource Metadata (RFC 9728)
// ---------------------------------------------------------------------------

/// Resolve the `authorization_servers` list for Protected Resource Metadata.
///
/// RFC 9728 3.2: a zero-valued claim MUST be omitted, so an empty result means
/// "leave the field out" rather than "emit `[]`".
fn resolve_authorization_servers<'server>(
    server_url: &'server str,
    config: &'server OAuthConfig,
) -> Vec<&'server str> {
    if let Some(explicit) = &config.authorization_servers {
        return explicit.iter().map(String::as_str).collect();
    }
    // Advertise this server only when it actually mounts the OAuth endpoints.
    // `install_oauth_proxy_routes` mounts `/authorize`, `/token`, and
    // `/.well-known/oauth-authorization-server` ONLY when `proxy` is set, while
    // Protected Resource Metadata is served unconditionally -- so without a
    // proxy the local URL resolves to a 404 and the upstream issuer is the only
    // truthful answer. An application that mounts its own facade through
    // `with_extra_router` must say so via `authorization_servers`.
    if config.proxy.is_some() {
        vec![server_url]
    } else {
        vec![config.issuer.as_str()]
    }
}

/// Build the Protected Resource Metadata JSON response.
///
/// `authorization_servers` follows [`OAuthConfig::authorization_servers`]:
/// the upstream issuer for a plain resource server, this server's own URL
/// when the built-in proxy is mounted, or an explicit operator override.
#[must_use]
#[inline]
pub fn protected_resource_metadata(
    resource_url: &str,
    server_url: &str,
    config: &OAuthConfig,
) -> serde_json::Value {
    let mut meta = serde_json::json!({
        "resource": resource_url,
        "bearer_methods_supported": ["header"],
    });
    let Some(obj) = meta.as_object_mut() else {
        return meta;
    };
    // RFC 9728 3.2: omit zero-valued claims rather than emitting empty arrays.
    let auth_servers = resolve_authorization_servers(server_url, config);
    if !auth_servers.is_empty() {
        let _inserted_auth_servers = obj.insert(
            "authorization_servers".into(),
            serde_json::json!(auth_servers),
        );
    }
    let scopes: Vec<&str> = config
        .scopes
        .iter()
        .map(|scope| scope.scope.as_str())
        .collect();
    if !scopes.is_empty() {
        let _inserted_scopes = obj.insert("scopes_supported".into(), serde_json::json!(scopes));
    }
    meta
}

/// Build the Authorization Server Metadata JSON response (RFC 8414).
///
/// Returned at `GET /.well-known/oauth-authorization-server` so MCP
/// clients can discover the authorization and token endpoints.
///
/// `issuer` defaults to `server_url`, the origin this document is served from,
/// as RFC 8414 3.3 requires. The upstream [`OAuthConfig::issuer`] remains the
/// *token* issuer and is still what inbound JWT `iss` claims are validated
/// against - the two are deliberately different. See
/// [`OAuthConfig::authorization_server_metadata_issuer`] for the legacy
/// opt-out.
#[must_use]
#[inline]
pub fn authorization_server_metadata(server_url: &str, config: &OAuthConfig) -> serde_json::Value {
    let issuer = config
        .authorization_server_metadata_issuer
        .as_deref()
        .unwrap_or(server_url);
    let mut meta = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{server_url}/authorize"),
        "token_endpoint": format!("{server_url}/token"),
        "registration_endpoint": format!("{server_url}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    });
    // RFC 8414 3.2: omit zero-valued claims rather than emitting `[]`.
    let scopes: Vec<&str> = config
        .scopes
        .iter()
        .map(|scope| scope.scope.as_str())
        .collect();
    if !scopes.is_empty()
        && let Some(obj) = meta.as_object_mut()
    {
        let _inserted_scopes = obj.insert("scopes_supported".into(), serde_json::json!(scopes));
    }
    if let Some(proxy) = &config.proxy
        && proxy.expose_admin_endpoints
        && let Some(obj) = meta.as_object_mut()
    {
        if proxy.introspection_url.is_some() {
            let _inserted_introspection = obj.insert(
                "introspection_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/introspect")),
            );
        }
        if proxy.revocation_url.is_some() {
            let _inserted_revocation = obj.insert(
                "revocation_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/revoke")),
            );
        }
        if proxy.require_auth_on_admin_endpoints {
            let _inserted_introspection_auth = obj.insert(
                "introspection_endpoint_auth_methods_supported".into(),
                serde_json::json!(["bearer"]),
            );
            let _inserted_revocation_auth = obj.insert(
                "revocation_endpoint_auth_methods_supported".into(),
                serde_json::json!(["bearer"]),
            );
        }
    }
    meta
}

// ---------------------------------------------------------------------------
// OAuth 2.1 Proxy Handlers
// ---------------------------------------------------------------------------

/// Handle `GET /authorize` - redirect to the upstream authorize URL.
///
/// Forwards all OAuth query parameters (`response_type`, `client_id`,
/// `redirect_uri`, `scope`, `state`, `code_challenge`,
/// `code_challenge_method`) to the upstream identity provider.
/// The upstream provider (e.g. Keycloak) presents the login UI and
/// redirects the user back to the MCP client's `redirect_uri` with an
/// authorization code.
#[must_use]
#[inline]
pub fn handle_authorize(proxy: &OAuthProxyConfig, query: &str) -> Response {
    use axum::{http::header, response::IntoResponse as _};

    // Replace the client_id in the query with the upstream client_id.
    let upstream_query =
        rewrite_client_auth_params(query, &proxy.client_id, proxy.strip_resource_param);
    let redirect_url = format!("{}?{upstream_query}", proxy.authorize_url);

    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

/// Handle `POST /token` - proxy the token request to the upstream provider.
///
/// Forwards the request body (authorization code exchange or refresh token
/// grant) to the upstream token endpoint, injecting client credentials
/// when configured (confidential client). Returns the upstream response as-is.
// NOT cancel-safe: once the upstream POST is in flight the authorization
// code may be consumed or a token minted upstream. Cancelling between send
// and response-forwarding loses the token while the grant is spent, so the
// client must retry with a fresh code rather than replay this one.
#[inline]
pub async fn handle_token(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> Response {
    use axum::{http::header, response::IntoResponse as _};

    // Replace client_id in the form body with the upstream client_id.
    let mut upstream_body =
        rewrite_client_auth_params(body, &proxy.client_id, proxy.strip_resource_param);

    // For confidential clients, inject the client_secret.
    if let Some(secret) = &proxy.client_secret {
        use core::fmt::Write as _;

        use secrecy::ExposeSecret as _;
        #[expect(
            clippy::let_underscore_must_use,
            reason = "write! into String cannot fail"
        )]
        let _: Result<(), fmt::Error> = write!(
            upstream_body,
            "&client_secret={}",
            urlencoding::encode(secret.expose_secret())
        );
    }

    let result = http
        .send_screened(
            &proxy.token_url,
            http.credential_client
                .post(&proxy.token_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(upstream_body),
        )
        .await;

    match result {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let Ok(body_bytes) =
                read_response_capped(resp, OAUTH_PROXY_MAX_RESPONSE_BYTES, "oauth/token").await
            else {
                return oauth_error_response(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "upstream response too large or unreadable",
                );
            };
            (
                status,
                [(header::CONTENT_TYPE, "application/json")],
                body_bytes,
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "OAuth token proxy request failed");
            (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                "{\"error\":\"server_error\",\"error_description\":\"token endpoint unreachable\"}",
            )
                .into_response()
        }
    }
}

/// Handle `POST /register` - return the pre-configured `client_id`.
///
/// MCP clients call this to discover which `client_id` to use in the
/// authorization flow.  We return the upstream `client_id` from config
/// and echo back any `redirect_uris` from the request body (required
/// by the MCP SDK's Zod validation).
#[must_use]
#[inline]
pub fn handle_register(proxy: &OAuthProxyConfig, body: &serde_json::Value) -> serde_json::Value {
    let mut resp = serde_json::json!({
        "client_id": proxy.client_id,
        "token_endpoint_auth_method": "none",
    });
    if let Some(uris) = body.get("redirect_uris")
        && let Some(obj) = resp.as_object_mut()
    {
        let _inserted_redirect_uris = obj.insert("redirect_uris".into(), uris.clone());
    }
    if let Some(name) = body.get("client_name")
        && let Some(obj) = resp.as_object_mut()
    {
        let _inserted_client_name = obj.insert("client_name".into(), name.clone());
    }
    resp
}

/// Handle `POST /introspect` - RFC 7662 token introspection proxy.
///
/// Forwards the request body to the upstream introspection endpoint,
/// injecting client credentials when configured. Returns the upstream
/// response as-is.  Requires `proxy.introspection_url` to be `Some`.
// cancel-safe: introspection is a read-only upstream query; cancelling only
// discards the answer and leaves no upstream state change.
#[inline]
pub async fn handle_introspect(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> Response {
    let Some(url) = &proxy.introspection_url else {
        return oauth_error_response(
            StatusCode::NOT_FOUND,
            "not_supported",
            "introspection endpoint is not configured",
        );
    };
    proxy_oauth_admin_request(http, proxy, url, body).await
}

/// Handle `POST /revoke` - RFC 7009 token revocation proxy.
///
/// Forwards the request body to the upstream revocation endpoint,
/// injecting client credentials when configured. Returns the upstream
/// response as-is (per RFC 7009, typically 200 with empty body).
/// Requires `proxy.revocation_url` to be `Some`.
// cancel-safe for security purposes: cancellation cannot un-revoke a token.
// The caller may lose the confirmation response while the revocation still
// takes effect upstream, which fails in the safe direction.
#[inline]
pub async fn handle_revoke(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> Response {
    let Some(url) = &proxy.revocation_url else {
        return oauth_error_response(
            StatusCode::NOT_FOUND,
            "not_supported",
            "revocation endpoint is not configured",
        );
    };
    proxy_oauth_admin_request(http, proxy, url, body).await
}

/// Shared proxy for introspection/revocation: injects `client_id` and
/// `client_secret` (when configured) and forwards the form-encoded body
/// upstream, returning the upstream status/body verbatim.
// cancel-safe for local state: credential rewriting is local, and
// `send_screened`/`read_response_capped` publish no server state. A repeated
// revocation cannot restore a token; introspection is read-only.
async fn proxy_oauth_admin_request(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    upstream_url: &str,
    body: &str,
) -> Response {
    use axum::{http::header, response::IntoResponse as _};

    // `false`: `resource` is not a parameter of RFC 7662 introspection or
    // RFC 7009 revocation requests, so the strip flag -- which exists purely
    // to satisfy Entra's authorization-code flow -- must not reach this path.
    let mut upstream_body = rewrite_client_auth_params(body, &proxy.client_id, false);
    if let Some(secret) = &proxy.client_secret {
        use core::fmt::Write as _;

        use secrecy::ExposeSecret as _;
        #[expect(
            clippy::let_underscore_must_use,
            reason = "write! into String cannot fail"
        )]
        let _: Result<(), fmt::Error> = write!(
            upstream_body,
            "&client_secret={}",
            urlencoding::encode(secret.expose_secret())
        );
    }

    let result = http
        .send_screened(
            upstream_url,
            http.credential_client
                .post(upstream_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(upstream_body),
        )
        .await;

    match result {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/json")
                .to_owned();
            let Ok(body_bytes) =
                read_response_capped(resp, OAUTH_PROXY_MAX_RESPONSE_BYTES, "oauth/admin").await
            else {
                return oauth_error_response(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "upstream response too large or unreadable",
                );
            };
            (status, [(header::CONTENT_TYPE, content_type)], body_bytes).into_response()
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                url = %oauth_request_target_for_log(upstream_url),
                "OAuth admin proxy request failed"
            );
            oauth_error_response(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream endpoint unreachable",
            )
        }
    }
}

/// Read an upstream response body, aborting if it exceeds `max_bytes`.
///
/// Mirrors the bounded-streaming read used for JWKS
/// ([`JwksCache::fetch_jwks`]) so OAuth proxy paths never buffer an
/// unbounded upstream response. Fails **closed**: on a transport error or
/// a body that grows past the cap it returns `Err(())` (the caller maps
/// this to a generic `502`); it never returns a truncated body that a
/// caller might forward as if complete. `context` is an authority-only
/// label for logs (never a full URL with credentials).
// cancel-safe: the response body is accumulated in a local `Vec` and returned
// only after EOF; cancellation during `resp.chunk()` drops the partial buffer
// and never forwards a truncated OAuth response.
///
/// # Errors
///
/// Returns `()` after logging the transport or size-cap failure.
async fn read_response_capped(
    mut resp: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<Vec<u8>, ()> {
    let initial_capacity = usize::try_from(max_bytes.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut body = Vec::with_capacity(initial_capacity);
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
                if body_len.saturating_add(chunk_len) > max_bytes {
                    tracing::warn!(
                        context = context,
                        max_bytes = max_bytes,
                        "upstream OAuth response exceeded size cap; failing closed"
                    );
                    return Err(());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(error) => {
                tracing::warn!(context = context, error = %error, "failed to read upstream OAuth response");
                return Err(());
            }
        }
    }
}

/// Build a JSON OAuth error response with the given status code and description.
fn oauth_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    use axum::{http::header, response::IntoResponse as _};
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// RFC 8693 Token Exchange
// ---------------------------------------------------------------------------

/// OAuth error response body from the authorization server.
#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    /// RFC 6749 §5.2 error code.
    error: String,
    /// Optional human-readable error description (upstream-controlled).
    error_description: Option<String>,
}

/// Choose what to log for an upstream `error_description`.
///
/// SECURITY: `error_description` is free-form text chosen by the authorization
/// server and may echo request parameters back, so it is redacted unless an
/// operator explicitly enables `observability.log_upstream_error_bodies`. The
/// sibling `error` field is an enumerated RFC 6749 §5.2 / RFC 8693 code rather
/// than free text, and is logged unconditionally.
fn upstream_error_description_for_log(description: Option<&str>) -> &str {
    if upstream_error_bodies() {
        description.unwrap_or("")
    } else {
        "[REDACTED]"
    }
}

/// Map an upstream OAuth error code to an allowlisted short code suitable
/// for client exposure.
///
/// Returns one of the RFC 6749 §5.2 / RFC 8693 standard codes. Unknown or
/// non-standard codes collapse to `server_error` to avoid leaking
/// authorization-server implementation details to MCP clients.
fn sanitize_oauth_error_code(raw: &str) -> &'static str {
    match raw {
        "invalid_request" => "invalid_request",
        "invalid_client" => "invalid_client",
        "invalid_grant" => "invalid_grant",
        "unauthorized_client" => "unauthorized_client",
        "unsupported_grant_type" => "unsupported_grant_type",
        "invalid_scope" => "invalid_scope",
        "temporarily_unavailable" => "temporarily_unavailable",
        // RFC 8693 token-exchange specific.
        "invalid_target" => "invalid_target",
        // Anything else (including upstream-specific codes that may leak
        // implementation details) collapses to a generic short code.
        _ => "server_error",
    }
}

/// Exchange an inbound access token for a downstream access token
/// via RFC 8693 token exchange.
///
/// The MCP server calls this to swap a user's MCP-scoped JWT
/// (`subject_token`) for a new JWT scoped to a downstream API
/// identified by [`TokenExchangeConfig::audience`].
///
/// # Errors
///
/// Returns an error if the HTTP request fails, the authorization
/// server rejects the exchange, or the response cannot be parsed.
// NOT cancel-safe, and NOT fixable at this layer: once `send_screened` puts the
// RFC 8693 POST on the wire, dropping this future cannot un-send it. The
// authorization server may mint a downstream token that never reaches the
// caller and that nothing here records. No local cache is torn, but retries may
// duplicate upstream issuance.
//
// Callers that can be cancelled should use `exchange_token_with_cancel`, which
// pre-checks the token, detaches the in-flight exchange rather than dropping it,
// and audits a token minted after the caller went away. That is a mitigation,
// not a guarantee -- see its docs for what remains unattainable.
#[inline]
pub async fn exchange_token(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
) -> Result<ExchangedToken, RmcpServerKitError> {
    exchange_token_inner(http, config, subject_token, SuccessLogMode::Normal).await
}

/// Whether a successful exchange logs the exchanged-token metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuccessLogMode {
    /// Log the exchanged-token metadata.
    Normal,
    /// Stay quiet; the detached caller audits the outcome itself.
    Suppress,
}

/// Perform the RFC 8693 exchange POST, logging success per `success_log`.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Auth`] with a sanitized code for upstream failures.
async fn exchange_token_inner(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
    success_log: SuccessLogMode,
) -> Result<ExchangedToken, RmcpServerKitError> {
    use secrecy::ExposeSecret as _;

    let client = http.client_for(config);
    let mut req = client
        .post(&config.token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");

    // M-H4: client authentication strategy.
    //   * `client_secret` set -> RFC 6749 §2.3.1 HTTP Basic.
    //   * `client_cert`   set -> RFC 8705 §2 mTLS via the cert-bearing
    //     `reqwest::Client` selected by `client_for`. NO Authorization
    //     header is sent: presenting a TLS client certificate at
    //     handshake time *is* the client authentication.
    // `OAuthConfig::validate` enforces exactly-one-of so neither both
    // nor neither reach this code path.
    if config.client_cert.is_none()
        && let Some(secret) = &config.client_secret
    {
        use base64::Engine as _;
        let credentials = general_purpose::STANDARD.encode(format!(
            "{}:{}",
            urlencoding::encode(&config.client_id),
            urlencoding::encode(secret.expose_secret()),
        ));
        req = req.header("Authorization", format!("Basic {credentials}"));
    }

    let form_body = build_exchange_form(config, subject_token);

    let resp = http
        .send_screened(&config.token_url, req.body(form_body))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "token exchange request failed");
            // Do NOT leak upstream URL, reqwest internals, or DNS detail to clients.
            RmcpServerKitError::Auth("server_error".into())
        })?;

    let status = resp.status();
    let body_bytes =
        read_response_capped(resp, OAUTH_PROXY_MAX_RESPONSE_BYTES, "oauth/token-exchange")
            .await
            .map_err(|()| {
                // read_response_capped already logged the cause (oversize / transport).
                RmcpServerKitError::Auth("server_error".into())
            })?;

    if !status.is_success() {
        cold_path();
        // Parse upstream error for logging only; client-visible payload is a
        // sanitized short code from the RFC 6749 §5.2 / RFC 8693 allowlist.
        let parsed = serde_json::from_slice::<OAuthErrorResponse>(&body_bytes).ok();
        let short_code = parsed.as_ref().map_or("server_error", |error| {
            sanitize_oauth_error_code(&error.error)
        });
        if let Some(error) = &parsed {
            let description =
                upstream_error_description_for_log(error.error_description.as_deref());
            tracing::warn!(
                status = %status,
                upstream_error = %error.error,
                upstream_error_description = description,
                client_code = %short_code,
                "token exchange rejected by authorization server",
            );
        } else {
            tracing::warn!(
                status = %status,
                client_code = %short_code,
                "token exchange rejected (unparseable upstream body)",
            );
        }
        return Err(RmcpServerKitError::Auth(short_code.into()));
    }

    let exchanged = serde_json::from_slice::<ExchangedToken>(&body_bytes).map_err(|error| {
        tracing::error!(error = %error, "failed to parse token exchange response");
        // Avoid surfacing serde internals; map to sanitized short code so
        // RmcpServerKitError::into_response cannot leak parser detail to the client.
        RmcpServerKitError::Auth("server_error".into())
    })?;

    match success_log {
        SuccessLogMode::Normal => log_exchanged_token(&exchanged),
        SuccessLogMode::Suppress => {}
    }

    Ok(exchanged)
}

/// Exchange an inbound access token while preserving post-send observability
/// if the caller cancels or times out.
///
/// This wrapper does **not** make RFC 8693 token exchange strictly
/// cancel-safe. Once the POST reaches the authorization server, this process
/// cannot un-send it or prove whether the server minted a downstream token.
/// Instead it provides the three local guarantees that are achievable: work is
/// not started when `ct` is already cancelled, the in-flight exchange future is
/// not dropped while reading the response, and an abandoned successful exchange
/// emits a sanitized warning so the orphaned downstream credential is
/// observable.
///
/// On cancellation or timeout after the spawned exchange starts, the exchange
/// task is deliberately detached and allowed to finish under the existing
/// [`OauthHttpClient`] request budgets. The task is **not** aborted. If it later
/// receives a successful [`ExchangedToken`] after the caller has gone away, it
/// discards the token and logs only bounded metadata (`expires_in` and a
/// truncated `issued_token_type`); token material and endpoint details are never
/// logged.
///
/// # Resource caveat
///
/// Detaching is unbounded in *count* under a cancel storm: every detached task
/// is time-bounded by the HTTP client's connect/total timeouts, but this helper
/// does not cap how many detached exchanges can exist at once. Use it only
/// behind the crate's existing authentication, rate-limit, and concurrency
/// controls (or equivalent caller-side controls).
///
/// # Errors
///
/// The completed outcome carries the exact [`Result`] returned by
/// [`exchange_token`]. Cancellation and timeout are reported structurally via
/// [`crate::cancel::DetachOutcome`] and do not construct client-visible error
/// strings.
#[must_use = "DetachOutcome must be inspected to distinguish completion from cancel/timeout"]
#[inline]
pub async fn exchange_token_with_cancel(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
    ct: &CancellationToken,
    timeout: Option<Duration>,
) -> DetachOutcome<Result<ExchangedToken, RmcpServerKitError>> {
    // Pre-cancel check FIRST: do not clone config, client, or subject token for
    // an already-abandoned request. In particular, cloning the subject token
    // would allocate and keep credential-adjacent material alive for work that
    // the caller has already told us not to start.
    if ct.is_cancelled() {
        return DetachOutcome::Cancelled;
    }

    let (tx, rx) = oneshot::channel();
    let http_owned = http.clone();
    let config_owned = config.clone();
    let subject_token_owned = subject_token.to_owned();

    // This task is intentionally detached on caller cancel/timeout. A plain
    // `run_with_cancel_and_timeout(exchange_token(...))` would drop the
    // JoinHandle in those arms, but it would not keep a result sink. The
    // `oneshot::Sender` is the sink: if the receiver is gone, `send` returns
    // the result to this task so an abandoned success can be audited without
    // logging token material.
    let _task = tokio::spawn(
        async move {
            let result = exchange_token_inner(
                &http_owned,
                &config_owned,
                &subject_token_owned,
                SuccessLogMode::Suppress,
            )
            .await;
            if let Err(abandoned) = tx.send(result) {
                audit_abandoned_exchange_result(abandoned);
            }
        }
        .instrument(tracing::Span::current()),
    );

    receive_exchange_result_with_cancel(rx, ct, timeout).await
}

/// Await the detached exchange result under cancellation and the optional timeout.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
)]
async fn receive_exchange_result_with_cancel(
    rx: oneshot::Receiver<Result<ExchangedToken, RmcpServerKitError>>,
    ct: &CancellationToken,
    timeout: Option<Duration>,
) -> DetachOutcome<Result<ExchangedToken, RmcpServerKitError>> {
    // `biased;` is deliberate and matches `cancel::run_with_cancel_and_timeout`:
    // the receiver arm comes first so a ready completion wins over a
    // simultaneously-ready cancellation or timeout. Dropping the receiver on
    // the other arms is not a leak; it is the signal that tells the spawned task
    // to audit an eventual success via `Sender::send`'s returned value.
    if let Some(deadline) = timeout {
        tokio::select! {
            biased;
            received = rx => map_exchange_receiver(received),
            () = ct.cancelled() => DetachOutcome::Cancelled,
            () = sleep(deadline) => DetachOutcome::TimedOut,
        }
    } else {
        tokio::select! {
            biased;
            received = rx => map_exchange_receiver(received),
            () = ct.cancelled() => DetachOutcome::Cancelled,
        }
    }
}

/// Map the oneshot receive into a [`DetachOutcome`], treating a dropped sender as
/// `server_error`.
fn map_exchange_receiver(
    received: Result<Result<ExchangedToken, RmcpServerKitError>, RecvError>,
) -> DetachOutcome<Result<ExchangedToken, RmcpServerKitError>> {
    match received {
        Ok(result) => DetachOutcome::Completed(result),
        Err(error) => {
            tracing::error!(error = %error, "token exchange task ended before returning a result");
            DetachOutcome::Completed(Err(RmcpServerKitError::Internal("server_error".into())))
        }
    }
}

/// Log bounded metadata when a detached exchange mints a token (never token material).
fn audit_abandoned_exchange_result(result: Result<ExchangedToken, RmcpServerKitError>) {
    match result {
        Ok(token) => {
            let (issued_token_type, issued_token_type_truncated) = token
                .issued_token_type
                .as_deref()
                .map_or_else(|| ("-".to_owned(), false), truncate_kid_for_log);
            tracing::warn!(
                expires_in = token.expires_in,
                issued_token_type = %issued_token_type,
                issued_token_type_truncated,
                "token exchange minted downstream token after caller detached; discarded token material"
            );
        }
        Err(error) => {
            tracing::debug!(error = %error, "token exchange failed after caller detached");
        }
    }
}

/// Append `&name=value` to a form body, percent-encoding the value.
fn push_form_param(body: &mut String, name: &str, value: &str) {
    body.push('&');
    body.push_str(name);
    body.push('=');
    body.push_str(&urlencoding::encode(value));
}

/// Build the RFC 8693 token-exchange form body.
///
/// Emits the three REQUIRED parameters (RFC 8693 §2.1) unconditionally, then
/// each OPTIONAL parameter only when configured. Parameter ORDER is fixed and
/// load-bearing: `resource` and `scope` are appended after `audience` and
/// before `client_id` so that a config predating 3.8.0 - where both are
/// necessarily `None` - produces a byte-identical body to earlier releases.
fn build_exchange_form(config: &TokenExchangeConfig, subject_token: &str) -> String {
    let mut body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}",
        urlencoding::encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        urlencoding::encode(subject_token),
        urlencoding::encode(TOKEN_TYPE_ACCESS_TOKEN),
    );
    if let Some(value) = config.requested_token_type.wire_value() {
        push_form_param(&mut body, "requested_token_type", value);
    }
    if let Some(audience) = config.audience.as_deref() {
        push_form_param(&mut body, "audience", audience);
    }
    if let Some(resource) = config.resource.as_deref() {
        push_form_param(&mut body, "resource", resource);
    }
    if let Some(scope) = config.scope.as_deref() {
        push_form_param(&mut body, "scope", scope);
    }
    if config.client_secret.is_none() {
        push_form_param(&mut body, "client_id", &config.client_id);
    }
    body
}

/// Debug-log the exchanged token. For JWTs, decode and log claim summary;
/// for opaque tokens, log length + issued type.
fn log_exchanged_token(exchanged: &ExchangedToken) {
    use base64::Engine as _;

    if !looks_like_jwt(&exchanged.access_token) {
        tracing::debug!(
            token_len = exchanged.access_token.len(),
            issued_token_type = exchanged.issued_token_type.as_deref().unwrap_or("-"),
            expires_in = exchanged.expires_in,
            "exchanged token (opaque)",
        );
        return;
    }
    let Some(payload) = exchanged.access_token.split('.').nth(1) else {
        return;
    };
    let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return;
    };
    let expose_claims = oauth_claim_values();
    let sub = gated_claim_str(claims.get("sub"), expose_claims);
    let aud = gated_claim_aud(claims.get("aud"), expose_claims);
    let azp = gated_claim_str(claims.get("azp"), expose_claims);
    let iss = gated_claim_str(claims.get("iss"), expose_claims);
    tracing::debug!(
        sub = sub,
        aud = %aud,
        azp = azp,
        iss = iss,
        expires_in = exchanged.expires_in,
        "exchanged token claims (JWT)",
    );
}

/// A string claim value for logs: raw when `expose`, else `"[REDACTED]"`.
fn gated_claim_str(value: Option<&serde_json::Value>, expose: bool) -> &str {
    if expose {
        fmt_json_str(value)
    } else {
        "[REDACTED]"
    }
}

/// The `aud` claim for logs: rendered when `expose`, else `"[REDACTED]"`.
fn gated_claim_aud(value: Option<&serde_json::Value>, expose: bool) -> String {
    if expose {
        fmt_json_aud(value)
    } else {
        "[REDACTED]".to_owned()
    }
}

/// Form/query parameters that carry OAuth client authentication.
///
/// Every one of these is proxy-owned: the upstream client identity and its
/// credentials are configured server-side and must never be influenced by the
/// downstream caller.
const CLIENT_AUTH_PARAMS: [&str; 4] = [
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
];

/// Re-serialize an `application/x-www-form-urlencoded` query or body with every
/// caller-supplied client-authentication parameter removed, then inject the
/// proxy's `client_id`.
///
/// This parses and re-serializes rather than rewriting the raw string. The
/// previous implementation split on `&` and dropped segments literally starting
/// with `client_id=`, which let a caller smuggle client credentials past the
/// proxy two ways:
///
/// - percent-encoded keys (`%63lient_id=...`, `client%5Fid=...`) do not match the
///   literal prefix but decode upstream to `client_id`; and
/// - `client_secret` was never filtered at all, so a caller-supplied secret
///   survived alongside the proxy's own injected one on credential-bearing POSTs.
///
/// Either way the upstream IdP received duplicate decoded parameters, and a
/// first-wins parser would honour the caller's value over the proxy's.
///
/// Decoded values and the relative order of non-client parameters are preserved
/// (OAuth permits repeated `scope` / `resource`). The raw byte encoding is *not*
/// preserved: `form_urlencoded` normalizes `+` and percent-escapes on
/// re-serialization, which is semantically equivalent for form data.
fn rewrite_client_auth_params(
    params: &str,
    upstream_client_id: &str,
    strip_resource: bool,
) -> String {
    let mut out = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(params.as_bytes()) {
        if CLIENT_AUTH_PARAMS.contains(&key.as_ref()) {
            continue;
        }
        // SECURITY: `resource` is the ONLY caller parameter this flag drops.
        // Comparison happens post-decode, so `%72esource` cannot smuggle past
        // it -- the same property that protects CLIENT_AUTH_PARAMS above.
        if strip_resource && key.as_ref() == "resource" {
            continue;
        }
        let _appended = out.append_pair(&key, &value);
    }
    let _appended = out.append_pair("client_id", upstream_client_id);
    out.finish()
}

#[cfg_attr(
    all(test, feature = "oauth", target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {

    #[cfg(feature = "oauth-mtls-client")]
    use core::ptr;
    #[cfg(feature = "oauth-mtls-client")]
    use std::{env, process};
    use std::{io, sync::Mutex};

    use anyhow::Context as _;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::{pkcs8, rand_core};
    use tokio::time::timeout;
    use tracing::subscriber;
    use tracing_subscriber::fmt as subscriber_fmt;
    use wiremock::matchers;

    use super::*;
    use crate::{
        diagnostics::{DiagnosticExposure, ExposureTestGuard, set_diagnostic_exposure},
        session_binding,
    };

    /// `value[key]` in a test, or an error naming the missing path.
    fn json_get<'val>(
        value: &'val serde_json::Value,
        key: &str,
    ) -> anyhow::Result<&'val serde_json::Value> {
        value.get(key).with_context(|| format!("{key} must exist"))
    }

    /// `value[key][0]` in a test, or an error naming the missing path.
    fn json_first<'val>(
        value: &'val serde_json::Value,
        key: &str,
    ) -> anyhow::Result<&'val serde_json::Value> {
        value
            .get(key)
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.first())
            .with_context(|| format!("{key}[0] must exist"))
    }

    /// `value[key][0]` mutably in a test, or an error naming the missing path.
    fn json_first_mut<'val>(
        value: &'val mut serde_json::Value,
        key: &str,
    ) -> anyhow::Result<&'val mut serde_json::Value> {
        value
            .get_mut(key)
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|items| items.first_mut())
            .with_context(|| format!("{key}[0] must exist"))
    }

    /// `value[key]` as a string in a test, or an error naming the missing path.
    fn json_str<'val>(value: &'val serde_json::Value, key: &str) -> anyhow::Result<&'val str> {
        json_get(value, key)?
            .as_str()
            .with_context(|| format!("{key} must be a string"))
    }

    /// `value[key][0]` as a string in a test, or an error naming the missing path.
    fn json_first_str<'val>(
        value: &'val serde_json::Value,
        key: &str,
    ) -> anyhow::Result<&'val str> {
        json_first(value, key)?
            .as_str()
            .with_context(|| format!("{key}[0] must be a string"))
    }

    /// Set `key` on a JSON object in a test, or an error naming the value.
    fn json_set(
        value: &mut serde_json::Value,
        key: &str,
        new: serde_json::Value,
    ) -> anyhow::Result<()> {
        drop(
            value
                .as_object_mut()
                .with_context(|| format!("{key} needs an object"))?
                .insert(key.to_owned(), new),
        );
        Ok(())
    }

    // -- F2 regression: client-auth parameter smuggling in the OAuth proxy --
    //
    // The previous `replace_client_id` split on `&` and dropped segments
    // literally starting with `client_id=`. Percent-encoded keys survived that
    // filter but decode upstream to `client_id`, and `client_secret` was never
    // filtered at all, so a caller could ship duplicate client credentials to
    // the IdP alongside the proxy's own. Every case below forwarded the
    // attacker value before the fix.

    /// Decode a rewritten form back into `(key, value)` pairs.
    ///
    /// Assertions run on decoded pairs, never on raw bytes: `form_urlencoded`
    /// normalizes `+` and percent-escapes on re-serialization, so byte equality
    /// is not a meaningful contract here.
    fn decoded_pairs(form: &str) -> Vec<(String, String)> {
        form_urlencoded::parse(form.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    /// Drops a percent-encoded `client_id` key so only the proxy's value remains.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_drops_percent_encoded_client_id_key keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_drops_percent_encoded_client_id_key() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params("%63lient_id=attacker&scope=read", "proxy-id", false);
        let pairs = decoded_pairs(&out);
        let client_ids: Vec<&String> = pairs
            .iter()
            .filter(|(key, _)| key == "client_id")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(client_ids, vec!["proxy-id"], "smuggled client_id survived");

        Ok(())
    }

    /// Drops an underscore-encoded `client_id` key so the attacker value never survives.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_drops_underscore_encoded_client_id_key keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_drops_underscore_encoded_client_id_key() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params("client%5Fid=attacker&scope=read", "proxy-id", false);
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs.iter().any(|(_, value)| value == "attacker"),
            "smuggled client_id survived: {pairs:?}"
        );

        Ok(())
    }

    /// Removes any caller-supplied `client_secret` from the rewritten auth params.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_drops_caller_supplied_client_secret keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_drops_caller_supplied_client_secret() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params(
            "client_secret=attacker-secret&scope=read",
            "proxy-id",
            false,
        );
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs
                .iter()
                .any(|(entry_key, _)| entry_key == "client_secret"),
            "caller client_secret survived: {pairs:?}"
        );

        Ok(())
    }

    /// Strips caller-supplied `client_assertion` and `client_assertion_type` parameters.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_drops_caller_supplied_client_assertion keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_drops_caller_supplied_client_assertion() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params(
            "client_assertion=ey.evil&client_assertion_type=urn:evil&scope=read",
            "proxy-id",
            false,
        );
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs
                .iter()
                .any(|(entry_key, _)| entry_key == "client_assertion"
                    || entry_key == "client_assertion_type"),
            "caller client assertion survived: {pairs:?}"
        );

        Ok(())
    }

    /// Collapses duplicate `client_id` parameters to a single proxy `client_id` value.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_collapses_duplicate_client_id_to_proxy_value keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_collapses_duplicate_client_id_to_proxy_value() -> anyhow::Result<()> {
        let out =
            rewrite_client_auth_params("client_id=a&client_id=b&scope=read", "proxy-id", false);
        let pairs = decoded_pairs(&out);
        let client_ids: Vec<&String> = pairs
            .iter()
            .filter(|(key, _)| key == "client_id")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(client_ids, vec!["proxy-id"]);

        Ok(())
    }

    /// Preserves non-client parameters in order, duplicates included, unchanged.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_preserves_non_client_params_in_order_with_duplicates keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_preserves_non_client_params_in_order_with_duplicates() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params(
            "scope=read&resource=a&state=xyz&resource=b&code_verifier=v",
            "proxy-id",
            false,
        );
        let pairs = decoded_pairs(&out);
        let non_client: Vec<(String, String)> = pairs
            .into_iter()
            .filter(|(entry_key, _)| entry_key != "client_id")
            .collect();
        assert_eq!(
            non_client,
            vec![
                ("scope".to_owned(), "read".to_owned()),
                ("resource".to_owned(), "a".to_owned()),
                ("state".to_owned(), "xyz".to_owned()),
                ("resource".to_owned(), "b".to_owned()),
                ("code_verifier".to_owned(), "v".to_owned()),
            ]
        );

        Ok(())
    }

    /// Strips every resource parameter when the Entra workaround flag is enabled.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_strips_every_resource_param_when_enabled keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_strips_every_resource_param_when_enabled() -> anyhow::Result<()> {
        // Issue #17: Entra rejects `resource` alongside a differing api://
        // scope (AADSTS9010010). All occurrences must go, and everything else
        // must survive in order.
        let out = rewrite_client_auth_params(
            "scope=read&resource=a&state=xyz&resource=b&code_verifier=v",
            "proxy-id",
            true,
        );
        let non_client: Vec<(String, String)> = decoded_pairs(&out)
            .into_iter()
            .filter(|(entry_key, _)| entry_key != "client_id")
            .collect();
        assert_eq!(
            non_client,
            vec![
                ("scope".to_owned(), "read".to_owned()),
                ("state".to_owned(), "xyz".to_owned()),
                ("code_verifier".to_owned(), "v".to_owned()),
            ]
        );

        Ok(())
    }

    /// Strips a percent-encoded resource key, matched after decoding.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_strips_percent_encoded_resource_key keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_strips_percent_encoded_resource_key() -> anyhow::Result<()> {
        // The strip filter compares post-decode, so an encoded key cannot
        // smuggle `resource` upstream -- same property that protects
        // CLIENT_AUTH_PARAMS.
        let out = rewrite_client_auth_params("%72esource=sneaky&scope=read", "proxy-id", true);
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs.iter().any(|(entry_key, _)| entry_key == "resource"),
            "percent-encoded resource survived: {pairs:?}"
        );
        assert!(pairs.contains(&("scope".to_owned(), "read".to_owned())));

        Ok(())
    }

    /// Never strips PKCE/CSRF/redirect params when resource stripping is enabled.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_never_strips_security_params_when_resource_stripping_enabled keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_never_strips_security_params_when_resource_stripping_enabled() -> anyhow::Result<()>
    {
        // SECURITY: stripping must never reach PKCE, CSRF, or redirect
        // binding. If this ever fails, an operator enabling the Entra
        // workaround would silently lose those protections.
        let input = "response_type=code&redirect_uri=https%3A%2F%2Fapp%2Fcb&state=s1\
                     &code_challenge=cc&code_challenge_method=S256&nonce=n1&scope=read\
                     &code_verifier=cv&grant_type=authorization_code&code=abc\
                     &refresh_token=rt&resource=https%3A%2F%2Fapi";
        let pairs = decoded_pairs(&rewrite_client_auth_params(input, "proxy-id", true));
        for key in [
            "response_type",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "scope",
            "code_verifier",
            "grant_type",
            "code",
            "refresh_token",
        ] {
            assert!(
                pairs.iter().any(|(entry_key, _)| entry_key == key),
                "{key} must never be stripped: {pairs:?}"
            );
        }
        assert!(!pairs.iter().any(|(entry_key, _)| entry_key == "resource"));

        Ok(())
    }

    /// Round-trips percent-encoded values containing special characters unchanged.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_roundtrips_values_with_special_characters keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_roundtrips_values_with_special_characters() -> anyhow::Result<()> {
        let input = form_urlencoded::Serializer::new(String::new())
            .append_pair("state", "a&b=c+d")
            .append_pair("scope", "r\u{e9}ad \u{2713}")
            .finish();
        let out = rewrite_client_auth_params(&input, "proxy-id", false);
        let pairs = decoded_pairs(&out);
        assert!(pairs.contains(&("state".to_owned(), "a&b=c+d".to_owned())));
        assert!(pairs.contains(&("scope".to_owned(), "r\u{e9}ad \u{2713}".to_owned())));

        Ok(())
    }

    /// Injects the proxy `client_id` when the incoming form lacks one.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::rewrite_injects_client_id_when_absent keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn rewrite_injects_client_id_when_absent() -> anyhow::Result<()> {
        let out = rewrite_client_auth_params("scope=read", "proxy-id", false);
        assert!(decoded_pairs(&out).contains(&("client_id".to_owned(), "proxy-id".to_owned())));

        Ok(())
    }

    /// Accepts a three-segment token whose header decodes to alg-bearing JSON.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::looks_like_jwt_valid keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn looks_like_jwt_valid() -> anyhow::Result<()> {
        // Minimal valid JWT structure: base64({"alg":"RS256"}).base64({}).sig
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.signature");
        assert!(looks_like_jwt(&token));

        Ok(())
    }

    /// Rejects a single-segment opaque token as not JWT-shaped.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::looks_like_jwt_rejects_opaque_token keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn looks_like_jwt_rejects_opaque_token() -> anyhow::Result<()> {
        assert!(!looks_like_jwt("dGhpcyBpcyBhbiBvcGFxdWUgdG9rZW4"));

        Ok(())
    }

    /// Rejects a two-segment token as not JWT-shaped.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::looks_like_jwt_rejects_two_segments keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn looks_like_jwt_rejects_two_segments() -> anyhow::Result<()> {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}");
        let token = format!("{header}.payload");
        assert!(!looks_like_jwt(&token));

        Ok(())
    }

    /// Rejects a four-segment token as not JWT-shaped.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::looks_like_jwt_rejects_four_segments keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn looks_like_jwt_rejects_four_segments() -> anyhow::Result<()> {
        assert!(!looks_like_jwt("a.b.c.d"));

        Ok(())
    }

    /// Rejects a JWT-shaped token whose decoded header lacks an alg member.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::looks_like_jwt_rejects_no_alg keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn looks_like_jwt_rejects_no_alg() -> anyhow::Result<()> {
        let header = URL_SAFE_NO_PAD.encode(b"{\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.sig");
        assert!(!looks_like_jwt(&token));

        Ok(())
    }

    /// Populates PRM resource, upstream `authorization_servers`, scopes, and bearer method.
    #[test]
    fn protected_resource_metadata_shape() -> anyhow::Result<()> {
        let config = OAuthConfig {
            require_subject: false,
            issuer: "https://auth.example.com".into(),
            audience: "https://mcp.example.com/mcp".into(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".into(),
            scopes: vec![
                ScopeMapping {
                    scope: "mcp:read".into(),
                    role: "viewer".into(),
                },
                ScopeMapping {
                    scope: "mcp:admin".into(),
                    role: "ops".into(),
                },
            ],
            role_claim: None,
            role_mappings: vec![],
            jwks_cache_ttl: "10m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: false,
            max_jwks_keys: default_max_jwks_keys(),
            allowed_algorithms: None,
            authorization_servers: None,
            authorization_server_metadata_issuer: None,
            #[expect(
                deprecated,
                reason = "test fixture: explicit value for the deprecated field"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        };
        let meta = protected_resource_metadata(
            "https://mcp.example.com/mcp",
            "https://mcp.example.com",
            &config,
        );
        assert_eq!(json_str(&meta, "resource")?, "https://mcp.example.com/mcp");
        // No proxy: this process mounts no authorization-server endpoints, so
        // advertising itself would point RFC 9728 discovery at a 404. The
        // upstream issuer is the only truthful answer.
        assert_eq!(
            json_first_str(&meta, "authorization_servers")?,
            "https://auth.example.com"
        );
        assert_eq!(
            meta.get("scopes_supported")
                .and_then(serde_json::Value::as_array)
                .context("scopes_supported must be an array")?
                .len(),
            2
        );
        assert_eq!(json_first_str(&meta, "bearer_methods_supported")?, "header");

        Ok(())
    }

    /// Build a PRM fixture with the given proxy / override topology.
    fn prm_for(
        proxy: Option<OAuthProxyConfig>,
        authorization_servers: Option<Vec<String>>,
        scopes: Vec<ScopeMapping>,
    ) -> serde_json::Value {
        let config = OAuthConfig {
            issuer: "https://auth.example.com".into(),
            audience: "https://mcp.example.com/mcp".into(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".into(),
            scopes,
            proxy,
            authorization_servers,
            ..OAuthConfig::default()
        };
        protected_resource_metadata(
            "https://mcp.example.com/mcp",
            "https://mcp.example.com",
            &config,
        )
    }

    fn demo_proxy() -> OAuthProxyConfig {
        OAuthProxyConfig::builder(
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
            "mcp",
        )
        .build()
    }

    /// Advertises the local server as AS only when the built-in proxy is configured.
    #[test]
    fn prm_advertises_local_server_only_when_proxy_mounts_the_endpoints() -> anyhow::Result<()> {
        // With the built-in proxy the local server really does serve
        // /authorize, /token, /register and the AS metadata document.
        let meta = prm_for(Some(demo_proxy()), None, vec![]);
        assert_eq!(
            json_first_str(&meta, "authorization_servers")?,
            "https://mcp.example.com"
        );

        Ok(())
    }

    /// Lets an explicit `authorization_servers` override win over proxy topology.
    #[test]
    fn prm_explicit_override_wins_over_topology() -> anyhow::Result<()> {
        // The extra_router case: the application mounts its own OAuth facade
        // without configuring `proxy`, so it must be able to say so.
        let meta = prm_for(
            None,
            Some(vec!["https://mcp.example.com".to_owned()]),
            vec![],
        );
        assert_eq!(
            json_first_str(&meta, "authorization_servers")?,
            "https://mcp.example.com"
        );

        // An override also wins when a proxy IS configured.
        let override_meta = prm_for(
            Some(demo_proxy()),
            Some(vec!["https://elsewhere.example".to_owned()]),
            vec![],
        );
        assert_eq!(
            json_first_str(&override_meta, "authorization_servers")?,
            "https://elsewhere.example"
        );

        Ok(())
    }

    /// Omits zero-valued PRM claims instead of emitting empty arrays.
    #[test]
    fn prm_omits_zero_valued_claims() -> anyhow::Result<()> {
        // RFC 9728 3.2: claims with zero elements MUST be omitted, not
        // emitted as `[]`.
        let meta = prm_for(None, Some(vec![]), vec![]);
        assert!(
            meta.get("authorization_servers").is_none(),
            "empty override must omit the claim: {meta}"
        );
        assert!(
            meta.get("scopes_supported").is_none(),
            "no configured scopes must omit the claim: {meta}"
        );
        assert_eq!(json_str(&meta, "resource")?, "https://mcp.example.com/mcp");

        Ok(())
    }

    fn proxy_as_metadata_config() -> OAuthConfig {
        OAuthConfig {
            issuer: "https://auth.example.com".into(),
            audience: "https://mcp.example.com/mcp".into(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".into(),
            proxy: Some(demo_proxy()),
            ..OAuthConfig::default()
        }
    }

    /// Defaults the AS metadata issuer to the origin the document is served from.
    #[test]
    fn as_metadata_issuer_defaults_to_the_origin_it_is_served_from() -> anyhow::Result<()> {
        // RFC 8414 3.3: the published `issuer` MUST equal the identifier the
        // metadata URL was built from. RFC 8414 6.2 requires clients to reject
        // a mismatch, so publishing the upstream issuer here made the document
        // unusable to conformant clients.
        let config = proxy_as_metadata_config();
        let meta = authorization_server_metadata("https://mcp.example.com", &config);
        assert_eq!(json_str(&meta, "issuer")?, "https://mcp.example.com");
        assert_eq!(
            json_get(&meta, "authorization_endpoint")?,
            "https://mcp.example.com/authorize"
        );
        assert!(
            meta.get("scopes_supported").is_none(),
            "RFC 8414 3.2: omit zero-valued claims: {meta}"
        );

        Ok(())
    }

    /// Restores the upstream issuer when `authorization_server_metadata_issuer` is set.
    #[test]
    fn as_metadata_issuer_legacy_opt_out_restores_upstream_value() -> anyhow::Result<()> {
        // Escape hatch for an upstream IdP that emits RFC 9207 `iss` to
        // clients that validate it; the proxy cannot reconcile that because
        // the callback bypasses this process entirely.
        let mut config = proxy_as_metadata_config();
        config.authorization_server_metadata_issuer = Some("https://auth.example.com".into());
        let meta = authorization_server_metadata("https://mcp.example.com", &config);
        assert_eq!(json_str(&meta, "issuer")?, "https://auth.example.com");

        Ok(())
    }

    /// Keeps config.issuer untouched for token validation when the metadata issuer differs.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::as_metadata_issuer_never_affects_token_validation keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn as_metadata_issuer_never_affects_token_validation() -> anyhow::Result<()> {
        // Whichever value is published, inbound JWT `iss` is validated against
        // `config.issuer`.
        let mut config = proxy_as_metadata_config();
        config.authorization_server_metadata_issuer = Some("https://mcp.example.com".into());
        assert_eq!(config.issuer, "https://auth.example.com");

        Ok(())
    }

    // -----------------------------------------------------------------------
    // F2: OAuth URL HTTPS-only validation (CVE-class: MITM JWKS / token URL)
    // -----------------------------------------------------------------------

    fn validation_https_config() -> OAuthConfig {
        OAuthConfig::builder(
            "https://auth.example.com",
            "mcp",
            "https://auth.example.com/.well-known/jwks.json",
        )
        .build()
    }

    /// Rejects non-HTTPS, credentialed, IP-literal, or unparseable discovery metadata URLs.
    #[test]
    fn validate_rejects_non_conformant_discovery_metadata_urls() -> anyhow::Result<()> {
        for bad in [
            "https://user:pw@as.example.com",
            "http://as.example.com",
            "https://10.0.0.1",
            "not-a-url",
        ] {
            let mut cfg = validation_https_config();
            cfg.authorization_server_metadata_issuer = Some(bad.to_owned());
            assert!(cfg.validate().is_err(), "validate must reject this config");

            let mut servers_cfg = validation_https_config();
            servers_cfg.authorization_servers = Some(vec![bad.to_owned()]);
            let err = servers_cfg
                .validate()
                .err()
                .context("validate must reject this config")?
                .to_string();
            assert!(
                err.contains("authorization_servers[0]"),
                "error must identify the offending index; got {err:?}"
            );
        }

        Ok(())
    }

    /// Accepts well-formed HTTPS discovery URLs and an empty `authorization_servers` list.
    #[test]
    fn validate_accepts_discovery_metadata_urls_and_the_empty_override() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.authorization_server_metadata_issuer = Some("https://as.example.com".to_owned());
        cfg.authorization_servers = Some(vec!["https://as.example.com".to_owned()]);
        cfg.validate()
            .context("well-formed https metadata must validate")?;

        let mut empty_cfg = validation_https_config();
        empty_cfg.authorization_servers = Some(vec![]);
        empty_cfg
            .validate()
            .context("an empty list is the documented way to omit the claim entirely")?;

        Ok(())
    }

    /// Accepts a config whose URLs are all HTTPS.
    #[test]
    fn validate_accepts_all_https_urls() -> anyhow::Result<()> {
        let cfg = validation_https_config();
        cfg.validate().context("all-HTTPS config must validate")?;

        Ok(())
    }

    /// Rejects an empty audience with an error naming oauth.audience.
    #[test]
    fn validate_rejects_empty_audience() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.audience = String::new();
        let Err(err) = cfg.validate() else {
            anyhow::bail!("empty audience must be rejected");
        };
        assert!(
            err.to_string().contains("oauth.audience"),
            "error must reference oauth.audience; got {err}"
        );

        Ok(())
    }

    fn assert_config_nonzero_error(err: RmcpServerKitError, field: &str) -> anyhow::Result<()> {
        let RmcpServerKitError::Config(msg) = err else {
            anyhow::bail!("expected Config error for {field}");
        };
        assert!(
            msg.contains(field) && msg.contains("must be nonzero"),
            "error must name {field} and say must be nonzero; got {msg:?}"
        );
        Ok(())
    }

    /// Rejects `jwks_max_response_bytes = 0` with a must-be-nonzero config error.
    #[test]
    fn rejects_zero_max_jwks_keys() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.max_jwks_keys = 0;
        let Err(err) = cfg.validate() else {
            anyhow::bail!("zero max_jwks_keys must be rejected");
        };
        assert_config_nonzero_error(err, "oauth.max_jwks_keys")?;

        Ok(())
    }

    /// Rejects `jwks_max_response_bytes = 0` with a must-be-nonzero config error.
    #[test]
    fn rejects_zero_jwks_max_response_bytes() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.jwks_max_response_bytes = 0;
        let Err(err) = cfg.validate() else {
            anyhow::bail!("zero jwks_max_response_bytes must be rejected");
        };
        assert_config_nonzero_error(err, "oauth.jwks_max_response_bytes")?;

        Ok(())
    }

    /// Deserializes a partial OAuth table via defaults, then rejects empty required fields.
    #[test]
    fn oauth_config_partial_table_deserializes_then_validate_rejects_empty_fields()
    -> anyhow::Result<()> {
        let toml_src = r#"
role_claim = "realm_access.roles"

[[role_mappings]]
claim_value = "mcp-admin"
role = "admin"
"#;
        let cfg: OAuthConfig = toml::from_str(toml_src).context(
            "partial [oauth] table without issuer/audience/jwks_uri must deserialize via serde(default)",
        )?;
        assert_eq!(cfg.issuer, "", "omitted issuer must default to empty");
        assert_eq!(cfg.audience, "", "omitted audience must default to empty");
        assert_eq!(cfg.jwks_uri, "", "omitted jwks_uri must default to empty");
        assert_eq!(cfg.role_claim.as_deref(), Some("realm_access.roles"));
        assert_eq!(cfg.role_mappings.len(), 1);
        let Err(_) = cfg.validate() else {
            anyhow::bail!(
                "empty issuer/jwks_uri/audience must still fail validate() (parse-don't-validate)"
            );
        };

        Ok(())
    }

    /// Rejects a malformed `jwks_cache_ttl` naming the offending field.
    #[test]
    fn validate_rejects_unparseable_jwks_cache_ttl() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.jwks_cache_ttl = "not-a-duration".into();
        let Err(err) = cfg.validate() else {
            anyhow::bail!("malformed jwks_cache_ttl must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("jwks_cache_ttl"),
            "error must reference offending field; got {msg:?}"
        );

        Ok(())
    }

    /// Rejects an HTTP `jwks_uri` while demanding HTTPS.
    #[test]
    fn validate_rejects_http_jwks_uri() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "http://auth.example.com/.well-known/jwks.json".into();
        let Err(err) = cfg.validate() else {
            anyhow::bail!("http jwks_uri must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("oauth.jwks_uri") && msg.contains("https"),
            "error must reference offending field + scheme requirement; got {msg:?}"
        );

        Ok(())
    }

    /// Rejects an HTTP proxy `authorize_url` naming `oauth.proxy.authorize_url`.
    #[test]
    fn validate_rejects_http_proxy_authorize_url() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "http://idp.example.com/authorize", // <-- HTTP, must be rejected
                "https://idp.example.com/token",
                "client",
            )
            .build(),
        );
        let Err(err) = cfg.validate() else {
            anyhow::bail!("http authorize_url must be rejected");
        };
        assert!(
            err.to_string().contains("oauth.proxy.authorize_url"),
            "error must reference proxy.authorize_url; got {err}"
        );

        Ok(())
    }

    /// Rejects an HTTP proxy `token_url` naming `oauth.proxy.token_url`.
    #[test]
    fn validate_rejects_http_proxy_token_url() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "http://idp.example.com/token", // <-- HTTP, must be rejected
                "client",
            )
            .build(),
        );
        let Err(err) = cfg.validate() else {
            anyhow::bail!("http token_url must be rejected");
        };
        assert!(
            err.to_string().contains("oauth.proxy.token_url"),
            "error must reference proxy.token_url; got {err}"
        );

        Ok(())
    }

    /// Rejects HTTP proxy `introspection_url` and `revocation_url` fields.
    #[test]
    fn validate_rejects_http_proxy_introspection_and_revocation_urls() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("http://idp.example.com/introspect")
            .build(),
        );
        let Err(err) = cfg.validate() else {
            anyhow::bail!("http introspection_url must be rejected");
        };
        assert!(err.to_string().contains("oauth.proxy.introspection_url"));

        let mut revocation_cfg = validation_https_config();
        revocation_cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .revocation_url("http://idp.example.com/revoke")
            .build(),
        );
        let Err(revocation_err) = revocation_cfg.validate() else {
            anyhow::bail!("http revocation_url must be rejected");
        };
        assert!(
            revocation_err
                .to_string()
                .contains("oauth.proxy.revocation_url")
        );

        Ok(())
    }

    // -- M3 regression: unauthenticated /introspect and /revoke must fail validate --

    /// Rejects exposed admin endpoints lacking both auth guards.
    #[test]
    fn validate_rejects_exposed_admin_endpoints_without_auth() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("https://idp.example.com/introspect")
            .expose_admin_endpoints(true)
            .build(),
        );
        let Err(err) = cfg.validate() else {
            anyhow::bail!("expose_admin_endpoints without auth must fail");
        };
        let msg = err.to_string();
        assert!(msg.contains("require_auth_on_admin_endpoints"), "{msg}");
        assert!(
            msg.contains("allow_unauthenticated_admin_endpoints"),
            "{msg}"
        );

        Ok(())
    }

    /// Accepts exposed admin endpoints when auth is required.
    #[test]
    fn validate_accepts_exposed_admin_endpoints_with_auth() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("https://idp.example.com/introspect")
            .expose_admin_endpoints(true)
            .require_auth_on_admin_endpoints(true)
            .build(),
        );
        cfg.validate()
            .context("authed admin endpoints must validate")?;

        Ok(())
    }

    /// Accepts exposed admin endpoints with the explicit unauthenticated opt-out.
    #[test]
    fn validate_accepts_exposed_admin_endpoints_with_explicit_unauth_optout() -> anyhow::Result<()>
    {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("https://idp.example.com/introspect")
            .expose_admin_endpoints(true)
            .allow_unauthenticated_admin_endpoints(true)
            .build(),
        );
        cfg.validate()
            .context("explicit unauth opt-out must validate")?;

        Ok(())
    }

    /// Accepts the default unexposed admin endpoints without auth.
    #[test]
    fn validate_accepts_unexposed_admin_endpoints_without_auth() -> anyhow::Result<()> {
        // The default safe shape: expose_admin_endpoints = false. The
        // M3 check must not fire because the routes are not mounted.
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("https://idp.example.com/introspect")
            .build(),
        );
        cfg.validate()
            .context("unexposed admin endpoints must validate")?;

        Ok(())
    }

    /// Rejects an HTTP `token_exchange.token_url` naming the field.
    #[test]
    fn validate_rejects_http_token_exchange_url() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.token_exchange = Some(
            TokenExchangeConfig::new(
                "http://idp.example.com/token", // <-- HTTP
                "client",
                None,
                None,
            )
            .with_audience("downstream"),
        );
        let Err(err) = cfg.validate() else {
            anyhow::bail!("http token_exchange.token_url must be rejected");
        };
        assert!(
            err.to_string().contains("oauth.token_exchange.token_url"),
            "error must reference token_exchange.token_url; got {err}"
        );

        Ok(())
    }

    /// Rejects an unparseable URL with an invalid-URL error.
    #[test]
    fn validate_rejects_unparseable_url() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "not a url".into();
        let Err(err) = cfg.validate() else {
            anyhow::bail!("unparseable URL must be rejected");
        };
        assert!(err.to_string().contains("invalid URL"));

        Ok(())
    }

    /// Rejects a non-HTTP scheme such as `file://` while demanding HTTPS.
    #[test]
    fn validate_rejects_non_http_scheme() -> anyhow::Result<()> {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "file:///etc/passwd".into();
        let Err(err) = cfg.validate() else {
            anyhow::bail!("file:// scheme must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("must use https scheme") && msg.contains("file"),
            "error must reject non-http(s) schemes; got {msg:?}"
        );

        Ok(())
    }

    /// Accepts HTTP on all six URL fields when `allow_http_oauth_urls` is set.
    #[test]
    fn validate_accepts_http_with_escape_hatch() -> anyhow::Result<()> {
        // F2 escape-hatch: `allow_http_oauth_urls = true` permits HTTP for
        // dev/test against local IdPs without TLS. Document the security
        // tradeoff (see field doc) and verify all 6 URL fields are accepted
        // when the flag is set.
        let mut cfg = OAuthConfig::builder(
            "http://auth.local",
            "mcp",
            "http://auth.local/.well-known/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "http://idp.local/authorize",
                "http://idp.local/token",
                "client",
            )
            .introspection_url("http://idp.local/introspect")
            .revocation_url("http://idp.local/revoke")
            .build(),
        );
        cfg.token_exchange = Some(
            TokenExchangeConfig::new(
                "http://idp.local/token",
                "client",
                Some(secrecy::SecretString::new("dev-secret".into())),
                None,
            )
            .with_audience("downstream"),
        );
        cfg.validate()
            .context("escape hatch must permit http on all URL fields")?;

        Ok(())
    }

    /// Still rejects malformed URLs even when the HTTP escape hatch is enabled.
    #[test]
    fn validate_with_escape_hatch_still_rejects_unparseable() -> anyhow::Result<()> {
        // Even with the escape hatch, malformed URLs are rejected so
        // garbage configuration cannot silently degrade to no-op.
        let mut cfg = validation_https_config();
        cfg.allow_http_oauth_urls = true;
        cfg.jwks_uri = "::not-a-url::".into();
        let Err(_) = cfg.validate() else {
            anyhow::bail!("escape hatch must NOT bypass URL parsing");
        };

        Ok(())
    }

    /// Requires the redirect policy to refuse a JWKS redirect that downgrades to HTTP.
    #[tokio::test]
    async fn jwks_cache_rejects_redirect_downgrade_to_http() -> anyhow::Result<()> {
        // F2.4 (Oracle modification A): even when the configured `jwks_uri`
        // is HTTPS, a `302 Location: http://...` from the JWKS host must
        // be refused by the reqwest redirect policy. Without this guard,
        // a network-positioned attacker who can spoof the upstream IdP
        // could redirect the JWKS fetch to plaintext and inject signing
        // keys, forging arbitrary JWTs.
        //
        // We assert at the reqwest-client level (rather than through
        // `validate_token`) so the assertion is precise: it pins the
        // policy to "reject scheme downgrade" rather than the broader
        // "JWKS fetch failed for any reason".

        // Install the same rustls crypto provider JwksCache::new uses,
        // so the test client can build with TLS support.
        drop(default_provider().install_default());

        let policy = Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" {
                attempt.error("redirect to non-HTTPS URL refused")
            } else if attempt.previous().len() >= 2 {
                attempt.error("too many redirects (max 2)")
            } else {
                attempt.follow()
            }
        });
        // M-H2: even though this is a redirect-policy test harness
        // (not a production code path), wire the same resolver +
        // .no_proxy() so the audit-trail invariant "every reqwest
        // builder in this crate uses SsrfScreeningResolver" holds.
        // Loopback bypass is enabled so the wiremock fixture stays
        // reachable.
        let test_bypass: TestLoopbackBypass = Arc::new(AtomicBool::new(true));
        let allowlist = Arc::new(CompiledSsrfAllowlist::default());
        let resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
            Arc::clone(&allowlist),
            test_bypass,
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(policy)
            .build()
            .context("test client builds")?;

        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "http://example.invalid/jwks.json"),
            )
            .mount(&mock)
            .await;

        // Emulate an HTTPS jwks_uri that 302s to HTTP.  We can't easily
        // bring up an HTTPS wiremock, so we simulate the kernel of the
        // policy: the same client that JwksCache uses must refuse the
        // redirect target.  reqwest invokes the redirect policy
        // regardless of source scheme, so an HTTP -> HTTP redirect with
        // policy `custom(... if scheme != https then error ...)` still
        // yields the redirect-rejection error path.  That is sufficient
        // to lock in the policy semantics.
        let url = format!("{}/jwks.json", mock.uri());
        let Err(err) = client.get(&url).send().await else {
            anyhow::bail!("redirect policy must reject scheme downgrade");
        };
        let chain = format!("{err:#}");
        assert!(
            chain.contains("redirect to non-HTTPS URL refused")
                || chain.to_lowercase().contains("redirect"),
            "error must surface redirect-policy rejection; got {chain:?}"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Integration tests with in-process RSA keypair + wiremock JWKS
    // -----------------------------------------------------------------------

    use rsa::{pkcs8::EncodePrivateKey as _, traits::PublicKeyParts as _};

    /// Generate an RSA-2048 keypair and return `(private_pem, jwks_json)`.
    fn generate_test_keypair(kid: &str) -> anyhow::Result<(String, serde_json::Value)> {
        let mut rng = rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).context("keypair generation")?;
        let private_pem = private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .context("PKCS8 PEM export")?
            .to_string();

        let public_key = private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": exponent
            }]
        });

        Ok((private_pem, jwks))
    }

    /// Mint a signed JWT with the given claims.
    fn mint_token(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        subject: &str,
        scope: &str,
    ) -> anyhow::Result<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "scope": scope,
            "exp": now.saturating_add(3600),
            "iat": now,
        });

        jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
    }

    /// Mint a signed JWT WITHOUT a `sub` claim (for `require_subject` tests).
    fn mint_token_without_sub(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        scope: &str,
    ) -> anyhow::Result<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "scope": scope,
            "exp": now.saturating_add(3600),
            "iat": now,
        });
        jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
    }

    fn test_config(jwks_uri: &str) -> OAuthConfig {
        OAuthConfig {
            require_subject: false,
            issuer: "https://auth.test.local".into(),
            audience: "https://mcp.test.local/mcp".into(),
            jwks_uri: jwks_uri.into(),
            scopes: vec![
                ScopeMapping {
                    scope: "mcp:read".into(),
                    role: "viewer".into(),
                },
                ScopeMapping {
                    scope: "mcp:admin".into(),
                    role: "ops".into(),
                },
            ],
            role_claim: None,
            role_mappings: vec![],
            jwks_cache_ttl: "5m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: true,
            max_jwks_keys: default_max_jwks_keys(),
            allowed_algorithms: None,
            authorization_servers: None,
            authorization_server_metadata_issuer: None,
            #[expect(
                deprecated,
                reason = "test fixture: explicit value for the deprecated field"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        }
    }

    fn test_cache(config: &OAuthConfig) -> anyhow::Result<JwksCache> {
        Ok(JwksCache::new(config)
            .map_err(anyhow::Error::msg)?
            .__test_allow_loopback_ssrf())
    }

    // -- H2: expired JWKS cache must fail closed when refresh cannot succeed --

    /// Prime a cache from a valid JWKS, then repoint the endpoint at a 503.
    ///
    /// Confirms the kid landed before the endpoint is broken; returns the cache,
    /// a matching-`aud` token for the primed kid, and the live mock server (kept
    /// alive by the caller).
    async fn h2_prime_then_break(
        ttl: &str,
    ) -> anyhow::Result<(JwksCache, String, wiremock::MockServer)> {
        let kid = "test-h2-stale";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.jwks_cache_ttl = ttl.into();
        let cache = test_cache(&config)?;
        cache
            .__test_refresh_now()
            .await
            .map_err(anyhow::Error::msg)
            .context("prime JWKS cache")?;
        assert!(cache.__test_has_kid(kid).await, "kid must be primed");

        mock_server.reset().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "h2-client",
            "mcp:read",
        )?;
        Ok((cache, token, mock_server))
    }

    /// Collapses duplicate `kid` entries in the JWKS to a single cached key.
    #[test]
    fn build_key_cache_last_duplicate_kid_wins() -> anyhow::Result<()> {
        let (_pem, jwks_json) = generate_test_keypair("dup-kid")?;
        let entry = json_first(&jwks_json, "keys")?.clone();
        let merged = serde_json::json!({ "keys": [entry.clone(), entry] });
        let jwks: JwkSet = serde_json::from_value(merged).context("merged jwks parses")?;
        assert_eq!(jwks.keys.len(), 2, "fixture must carry two colliding kids");

        let (keys, unnamed) = build_key_cache(&jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert_eq!(keys.len(), 1, "colliding kids collapse to one entry");
        assert!(keys.contains_key("dup-kid"));
        assert!(unnamed.is_empty());

        Ok(())
    }

    /// Drops keys with use=enc or `key_ops` lacking verify from the verification cache.
    #[test]
    fn build_key_cache_rejects_keys_not_marked_for_signature_verification() -> anyhow::Result<()> {
        // SECURITY (key-use separation, RFC 7517 4.2/4.3): DecodingKey::from_jwk
        // ignores `use`/`key_ops`, so an issuer publishing an encryption key in
        // the same JWKS must not have it accepted as a verification key.
        let (_pem, jwks_json) = generate_test_keypair("enc-only")?;

        let mut enc = json_first(&jwks_json, "keys")?.clone();
        json_set(&mut enc, "use", serde_json::json!("enc"))?;
        let jwks: JwkSet =
            serde_json::from_value(serde_json::json!({ "keys": [enc] })).context("jwks parses")?;
        let (keys, unnamed) = build_key_cache(&jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(
            keys.is_empty(),
            "use=enc key must not be a verification key"
        );
        assert!(unnamed.is_empty());

        let mut wrap_only = json_first(&jwks_json, "keys")?.clone();
        json_set(&mut wrap_only, "key_ops", serde_json::json!(["wrapKey"]))?;
        let wrap_jwks: JwkSet = serde_json::from_value(serde_json::json!({ "keys": [wrap_only] }))
            .context("jwks parses")?;
        let (wrap_keys, wrap_unnamed) = build_key_cache(&wrap_jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(
            wrap_keys.is_empty(),
            "key_ops without verify must be rejected"
        );
        assert!(wrap_unnamed.is_empty());

        Ok(())
    }

    /// Accepts keys with `use=sig/key_ops=verify` or with no `use/key_ops` constraint.
    #[test]
    fn build_key_cache_accepts_sig_and_unconstrained_keys() -> anyhow::Result<()> {
        let (_pem, jwks_json) = generate_test_keypair("sig-key")?;

        // Absent `use`/`key_ops` stays accepted (RFC 7517: both are optional).
        let jwks: JwkSet = serde_json::from_value(jwks_json.clone()).context("jwks parses")?;
        let (keys, _) = build_key_cache(&jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(keys.contains_key("sig-key"));

        let mut sig = json_first(&jwks_json, "keys")?.clone();
        json_set(&mut sig, "use", serde_json::json!("sig"))?;
        json_set(&mut sig, "key_ops", serde_json::json!(["verify"]))?;
        let sig_jwks: JwkSet =
            serde_json::from_value(serde_json::json!({ "keys": [sig] })).context("jwks parses")?;
        let (sig_keys, _) = build_key_cache(&sig_jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(sig_keys.contains_key("sig-key"));

        Ok(())
    }

    // -- Issue #17: JWKS keys that omit the OPTIONAL `alg` member (RFC 7517 4.4) --
    //
    // Microsoft Entra v2.0 publishes every signing key without `alg`
    // (verified against login.microsoftonline.com/common/discovery/v2.0/keys:
    // 9 keys, 0 with `alg`, all kty=RSA use=sig). Requiring `alg` dropped every
    // key and produced a silent, total authentication outage.

    /// Strip the `alg` member from a generated fixture, reproducing Entra shape.
    fn jwks_without_alg(jwks: &serde_json::Value) -> anyhow::Result<JwkSet> {
        let mut key = json_first(jwks, "keys")?.clone();
        if let Some(obj) = key.as_object_mut() {
            drop(obj.remove("alg"));
        }
        serde_json::from_value(serde_json::json!({ "keys": [key] })).context("alg-less jwks parses")
    }

    /// Caches an alg-less RSA key with family Rsa rather than dropping it.
    #[test]
    fn alg_less_rsa_key_is_cached_as_rsa_family() -> anyhow::Result<()> {
        let (_pem, jwks_json) = generate_test_keypair("entra-kid")?;
        let jwks = jwks_without_alg(&jwks_json)?;
        assert!(
            jwks.keys
                .first()
                .context("jwks must carry a key")?
                .common
                .key_algorithm
                .is_none(),
            "fixture must omit `alg`"
        );

        let (keys, unnamed) = build_key_cache(&jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(unnamed.is_empty());
        let (cached_alg, _) = keys
            .get("entra-kid")
            .context("alg-less key must be cached")?;
        assert_eq!(*cached_alg, JwkAlg::Family(JwkKeyFamily::Rsa));

        Ok(())
    }

    /// Resolves an alg-less RSA key for RS*/PS* algs but not ES256.
    #[test]
    fn alg_less_rsa_key_accepts_rsa_family_and_rejects_others() -> anyhow::Result<()> {
        let (_pem, jwks_json) = generate_test_keypair("entra-kid")?;
        let cached = CachedKeys {
            keys: build_key_cache(&jwks_without_alg(&jwks_json)?, 16)
                .map_err(anyhow::Error::msg)
                .context("under key cap")?
                .0,
            unnamed_keys: vec![],
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };

        for alg in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            assert!(
                lookup_key(&cached, Some("entra-kid"), alg).is_some(),
                "{alg:?} is producible by an RSA key and must resolve"
            );
        }
        // An RSA key cannot produce an EC signature.
        assert!(lookup_key(&cached, Some("entra-kid"), Algorithm::ES256).is_none());
        // The kid-strict rule still holds for inferred keys.
        assert!(lookup_key(&cached, Some("unknown"), Algorithm::RS256).is_none());

        Ok(())
    }

    /// Prevents family inference from accepting HMAC algs against asymmetric keys.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::alg_less_key_never_accepts_hmac_algorithm_confusion keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn alg_less_key_never_accepts_hmac_algorithm_confusion() -> anyhow::Result<()> {
        // Regression guard: the classic attack is to present alg=HS256 and use
        // the issuer's PUBLIC RSA modulus as the HMAC secret. Family inference
        // must never widen an RSA key to a symmetric algorithm. (ACCEPTED_ALGS
        // also screens HS* before lookup; this asserts the key-bound layer.)
        assert!(!family_accepts(JwkKeyFamily::Rsa, Algorithm::HS256));
        assert!(!family_accepts(JwkKeyFamily::Rsa, Algorithm::HS384));
        assert!(!family_accepts(JwkKeyFamily::Rsa, Algorithm::HS512));
        assert!(!family_accepts(JwkKeyFamily::EcP256, Algorithm::HS256));
        assert!(!family_accepts(JwkKeyFamily::Ed25519, Algorithm::HS256));

        Ok(())
    }

    /// Ensures family inference never admits an algorithm outside `ACCEPTED_ALGS`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::family_accepts_is_subset_of_accepted_algs keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn family_accepts_is_subset_of_accepted_algs() -> anyhow::Result<()> {
        // INVARIANT: family inference must never admit an algorithm that the
        // pre-lookup `ACCEPTED_ALGS` screen would reject.
        let every_alg = [
            Algorithm::HS256,
            Algorithm::HS384,
            Algorithm::HS512,
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::EdDSA,
        ];
        for family in [
            JwkKeyFamily::Rsa,
            JwkKeyFamily::EcP256,
            JwkKeyFamily::EcP384,
            JwkKeyFamily::Ed25519,
        ] {
            for alg in every_alg {
                if family_accepts(family, alg) {
                    assert!(
                        ACCEPTED_ALGS.contains(&alg),
                        "{family:?} admits {alg:?}, which is outside ACCEPTED_ALGS"
                    );
                }
            }
        }

        Ok(())
    }

    /// Pins a key declaring RS256 to exactly RS256, rejecting RS384.
    #[test]
    fn explicit_alg_still_pins_exactly_one_algorithm() -> anyhow::Result<()> {
        // The JWK declares RS256, so an RS384 token must NOT be accepted even
        // though both are producible by the same RSA key.
        let (_pem, jwks_json) = generate_test_keypair("pinned")?;
        let jwks: JwkSet = serde_json::from_value(jwks_json).context("jwks parses")?;
        let cached = CachedKeys {
            keys: build_key_cache(&jwks, 16)
                .map_err(anyhow::Error::msg)
                .context("under key cap")?
                .0,
            unnamed_keys: vec![],
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };
        assert!(lookup_key(&cached, Some("pinned"), Algorithm::RS256).is_some());
        assert!(lookup_key(&cached, Some("pinned"), Algorithm::RS384).is_none());

        Ok(())
    }

    /// Still drops alg-less keys excluded by use=enc or `key_ops` without verify.
    #[test]
    fn alg_less_key_still_subject_to_use_and_key_ops_gate() -> anyhow::Result<()> {
        // Ordering guard: `jwk_permits_signature_verification` runs BEFORE the
        // algorithm step, so inference must not resurrect a key excluded by
        // key-use separation. Covers both branches of that gate.
        let (_pem, jwks_json) = generate_test_keypair("gated")?;

        let mut enc = json_first(&jwks_json, "keys")?.clone();
        if let Some(obj) = enc.as_object_mut() {
            drop(obj.remove("alg"));
        }
        json_set(&mut enc, "use", serde_json::json!("enc"))?;
        let jwks: JwkSet =
            serde_json::from_value(serde_json::json!({ "keys": [enc] })).context("jwks parses")?;
        let (keys, unnamed) = build_key_cache(&jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(
            keys.is_empty() && unnamed.is_empty(),
            "use=enc must be dropped"
        );

        let mut wrap = json_first(&jwks_json, "keys")?.clone();
        if let Some(obj) = wrap.as_object_mut() {
            drop(obj.remove("alg"));
            drop(obj.remove("use"));
        }
        json_set(&mut wrap, "key_ops", serde_json::json!(["wrapKey"]))?;
        let wrap_jwks: JwkSet =
            serde_json::from_value(serde_json::json!({ "keys": [wrap] })).context("jwks parses")?;
        let (wrap_keys, wrap_unnamed) = build_key_cache(&wrap_jwks, 16)
            .map_err(anyhow::Error::msg)
            .context("under key cap")?;
        assert!(
            wrap_keys.is_empty() && wrap_unnamed.is_empty(),
            "key_ops without verify must be dropped"
        );

        Ok(())
    }

    // -- allowed_algorithms: operator narrowing of the accepted algorithm set --

    /// Round-trips every accepted algorithm to a configurable name and back.
    #[test]
    fn accepted_algorithm_names_cover_accepted_algs() -> anyhow::Result<()> {
        // Lockstep contract: every accepted algorithm must have a name an
        // operator can write, and every name must round-trip back.
        for alg in ACCEPTED_ALGS {
            let Some(name) = accepted_algorithm_name(*alg) else {
                anyhow::bail!("{alg:?} is accepted but has no configurable name");
            };
            assert_eq!(accepted_algorithm_from_name(name), Some(*alg));
        }
        assert_eq!(
            accepted_algorithm_names().split(", ").count(),
            ACCEPTED_ALGS.len()
        );

        Ok(())
    }

    /// Rejects configured algorithm names outside the accepted set.
    #[test]
    fn allowed_algorithms_cannot_widen_beyond_accepted_algs() -> anyhow::Result<()> {
        // SECURITY: the whole point of the narrow-only rule. An operator must
        // not be able to re-enable a symmetric or unsigned algorithm and open
        // an algorithm-confusion hole.
        for name in ["HS256", "HS384", "HS512", "none", "ES512", "RS1"] {
            assert!(
                accepted_algorithm_from_name(name).is_none(),
                "{name} must not be resolvable"
            );
            let Err(err) = resolve_allowed_algorithms(Some(&[name.to_owned()])) else {
                anyhow::bail!("must reject non-accepted algorithm");
            };
            assert!(err.to_string().contains("unsupported algorithm"));
        }

        Ok(())
    }

    /// Rejects an empty `allowed_algorithms` list.
    #[test]
    fn allowed_algorithms_rejects_empty_list() -> anyhow::Result<()> {
        let err = resolve_allowed_algorithms(Some(&[]))
            .err()
            .context("empty list would reject every token")?;
        assert!(err.to_string().contains("must not be empty"));

        Ok(())
    }

    /// Defaults `allowed_algorithms` to the full accepted algorithm set.
    #[test]
    fn allowed_algorithms_defaults_to_full_accepted_set() -> anyhow::Result<()> {
        assert_eq!(
            resolve_allowed_algorithms(None).context("default resolves")?,
            ACCEPTED_ALGS.to_vec()
        );

        Ok(())
    }

    /// Narrows and case-insensitively dedups an `allowed_algorithms` subset.
    #[test]
    fn allowed_algorithms_narrows_and_dedups_case_insensitively() -> anyhow::Result<()> {
        let resolved = resolve_allowed_algorithms(Some(&[
            "rs256".to_owned(),
            "RS256".to_owned(),
            "ES384".to_owned(),
        ]))
        .context("valid subset")?;
        assert_eq!(resolved, vec![Algorithm::RS256, Algorithm::ES384]);

        Ok(())
    }

    /// Surfaces unsupported `allowed_algorithms` through config validation.
    #[test]
    fn allowed_algorithms_surfaces_through_config_validate() -> anyhow::Result<()> {
        let mut cfg = test_config("https://idp.test.local/jwks.json");
        cfg.allowed_algorithms = Some(vec!["HS256".to_owned()]);
        let Err(err) = cfg.validate() else {
            anyhow::bail!("HS256 must fail validation");
        };
        assert!(err.to_string().contains("unsupported algorithm"));

        cfg.allowed_algorithms = Some(vec!["RS256".to_owned()]);
        cfg.validate().context("a valid subset must validate")?;

        Ok(())
    }

    /// Rejects an RS256 token when `allowed_algorithms` is narrowed to ES384.
    #[tokio::test]
    async fn narrowed_allowed_algorithms_rejects_excluded_but_otherwise_valid_token()
    -> anyhow::Result<()> {
        // The token is signed RS256 by a key the JWKS serves, so it would
        // normally authenticate; narrowing to ES384 must reject it at the
        // pre-lookup algorithm gate.
        let kid = "narrowing-kid";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "narrow-user",
            "mcp:admin",
        )?;

        let mut permissive = test_config(&jwks_uri);
        permissive.allowed_algorithms = Some(vec!["RS256".to_owned()]);
        assert!(
            test_cache(&permissive)?
                .validate_token(&token)
                .await
                .is_some(),
            "RS256 token must authenticate when RS256 is allowed"
        );

        let mut narrowed = test_config(&jwks_uri);
        narrowed.allowed_algorithms = Some(vec!["ES384".to_owned()]);
        assert!(
            test_cache(&narrowed)?
                .validate_token(&token)
                .await
                .is_none(),
            "RS256 token must be rejected when only ES384 is allowed"
        );

        Ok(())
    }

    /// Bounds a long kid to `MAX_LOGGED_KID_CHARS` plus a truncation marker.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::truncate_kid_for_log_bounds_hostile_input keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn truncate_kid_for_log_bounds_hostile_input() -> anyhow::Result<()> {
        let short = "kid-1";
        assert_eq!(truncate_kid_for_log(short), (short.to_owned(), false));

        let long = "k".repeat(4096);
        let (truncated, was_truncated) = truncate_kid_for_log(&long);
        assert!(was_truncated);
        assert!(truncated.ends_with("...(truncated)"));
        assert_eq!(
            truncated.chars().count(),
            MAX_LOGGED_KID_CHARS + "...(truncated)".chars().count()
        );

        Ok(())
    }

    /// Truncates a multibyte kid on a char boundary without panicking.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::truncate_kid_for_log_splits_on_char_boundary keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn truncate_kid_for_log_splits_on_char_boundary() -> anyhow::Result<()> {
        let multibyte = "\u{1f512}".repeat(MAX_LOGGED_KID_CHARS + 10);
        let (truncated, was_truncated) = truncate_kid_for_log(&multibyte);
        assert!(was_truncated);
        assert!(truncated.starts_with('\u{1f512}'));
        assert!(truncated.ends_with("...(truncated)"));

        Ok(())
    }

    /// Reports a kid exactly at the cap as untruncated.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::truncate_kid_for_log_flag_marks_exact_boundary_as_untruncated keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn truncate_kid_for_log_flag_marks_exact_boundary_as_untruncated() -> anyhow::Result<()> {
        let exact = "k".repeat(MAX_LOGGED_KID_CHARS);
        let (out, was_truncated) = truncate_kid_for_log(&exact);
        assert!(!was_truncated, "a kid exactly at the cap is not truncated");
        assert_eq!(out, exact);

        Ok(())
    }

    /// Rejects tokens when the JWKS cache expired and refresh fails.
    #[tokio::test]
    async fn expired_jwks_fails_closed_when_refresh_fails() -> anyhow::Result<()> {
        let (cache, token, _mock) = h2_prime_then_break("80ms").await?;
        sleep(Duration::from_millis(200)).await;
        let Err(failure) = cache.validate_token_with_reason(&token).await else {
            anyhow::bail!("an expired cache whose refresh fails must not serve the stale key");
        };
        assert_eq!(failure, JwtValidationFailure::Invalid);

        Ok(())
    }

    /// Validates a matching token while the JWKS cache is fresh and reachable.
    #[tokio::test]
    async fn fresh_jwks_still_validates() -> anyhow::Result<()> {
        let kid = "test-h2-fresh";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // 5m TTL, reachable JWKS
        let cache = test_cache(&config)?;
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "h2-fresh-client",
            "mcp:read",
        )?;
        drop(
            cache
                .validate_token_with_reason(&token)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context("a reachable JWKS must still validate a matching token")?,
        );

        Ok(())
    }

    /// Fails closed when the expired cache cannot refresh because the cooldown is active.
    #[tokio::test]
    async fn cooldown_active_plus_expired_fails_closed() -> anyhow::Result<()> {
        let (cache, token, _mock) = h2_prime_then_break("80ms").await?;
        sleep(Duration::from_millis(200)).await;
        // First attempt: no cooldown yet, so this triggers a (503) refresh that
        // records `last_refresh_attempt` and still fails closed.
        let Err(first_failure) = cache.validate_token_with_reason(&token).await else {
            anyhow::bail!("first attempt must fail closed");
        };
        assert_eq!(first_failure, JwtValidationFailure::Invalid);
        // Second attempt: the refresh cooldown is now active, so no refresh is
        // attempted -- the still-expired cache must not serve the stale key.
        let Err(failure) = cache.validate_token_with_reason(&token).await else {
            anyhow::bail!("cooldown-active + expired cache must still fail closed");
        };
        assert_eq!(failure, JwtValidationFailure::Invalid);

        Ok(())
    }

    /// Returns identity name, first mapped role, method, and sub from a valid JWT.
    #[tokio::test]
    async fn valid_jwt_returns_identity() -> anyhow::Result<()> {
        let kid = "test-key-1";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "ci-bot",
            "mcp:read mcp:other",
        )?;

        let identity = cache.validate_token(&token).await;
        assert!(identity.is_some(), "valid JWT should authenticate");
        let id = identity.context("valid JWT should authenticate")?;
        assert_eq!(id.name, "ci-bot");
        assert_eq!(id.role, "viewer"); // first matching scope
        assert_eq!(id.method, AuthMethod::OAuthJwt);
        // Session binding fingerprints prefer `sub` over `name` precisely
        // because `name` falls back through preferred_username -> sub -> azp
        // -> client_id and is unstable across token refresh. If `sub` stopped
        // being carried onto the identity, that fallback would engage silently
        // and OAuth sessions would break across replicas on refresh, with
        // every other assertion here still passing.
        assert_eq!(id.sub.as_deref(), Some("ci-bot"));

        Ok(())
    }

    // -- L4: kid-strict key lookup + require_subject --

    /// Rejects an unknown kid instead of falling back to an unnamed key.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::unknown_kid_with_named_keys_rejected keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn unknown_kid_with_named_keys_rejected() -> anyhow::Result<()> {
        let mut keys = HashMap::new();
        drop(keys.insert(
            "kid-1".to_owned(),
            (
                JwkAlg::Explicit(Algorithm::RS256),
                DecodingKey::from_secret(b"named"),
            ),
        ));
        let cached = CachedKeys {
            keys,
            unnamed_keys: vec![(
                JwkAlg::Explicit(Algorithm::RS256),
                DecodingKey::from_secret(b"unnamed"),
            )],
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };
        // A matching kid + algorithm resolves to the named key.
        assert!(lookup_key(&cached, Some("kid-1"), Algorithm::RS256).is_some());
        // An unknown kid must NOT fall back to the unnamed key (L4 fail-closed):
        // a token naming an absent key is rejected rather than silently verified
        // against a keyless JWKS entry.
        assert!(lookup_key(&cached, Some("unknown"), Algorithm::RS256).is_none());
        // A known kid paired with the wrong algorithm is rejected too.
        assert!(lookup_key(&cached, Some("kid-1"), Algorithm::ES256).is_none());

        Ok(())
    }

    /// Matches a kid-less token against an unnamed JWKS key.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::no_kid_token_matches_unnamed_key keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn no_kid_token_matches_unnamed_key() -> anyhow::Result<()> {
        let mut keys = HashMap::new();
        drop(keys.insert(
            "kid-1".to_owned(),
            (
                JwkAlg::Explicit(Algorithm::RS256),
                DecodingKey::from_secret(b"named"),
            ),
        ));
        let cached = CachedKeys {
            keys,
            unnamed_keys: vec![(
                JwkAlg::Explicit(Algorithm::RS256),
                DecodingKey::from_secret(b"unnamed"),
            )],
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };
        // A token with no kid falls back to an unnamed key, supporting JWKS
        // entries that legitimately omit `kid`.
        assert!(lookup_key(&cached, None, Algorithm::RS256).is_some());

        Ok(())
    }

    /// Rejects a sub-less token when `require_subject` is on, accepting one with sub.
    #[tokio::test]
    async fn require_subject_rejects_subject_less() -> anyhow::Result<()> {
        let kid = "test-key-reqsub";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.require_subject = true;
        let cache = test_cache(&config)?;

        let no_sub = mint_token_without_sub(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "mcp:read",
        )?;
        assert!(
            cache.validate_token(&no_sub).await.is_none(),
            "require_subject must reject a token with no sub"
        );

        let with_sub = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "svc",
            "mcp:read",
        )?;
        assert!(
            cache.validate_token(&with_sub).await.is_some(),
            "a token carrying sub must still be accepted"
        );

        Ok(())
    }

    /// Accepts a sub-less token by default and stores no subject.
    #[tokio::test]
    async fn subject_less_token_accepted_by_default() -> anyhow::Result<()> {
        let kid = "test-key-nosub-default";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // require_subject defaults to false
        let cache = test_cache(&config)?;
        let no_sub = mint_token_without_sub(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "mcp:read",
        )?;
        let identity = cache.validate_token(&no_sub).await;
        assert!(
            identity.is_some(),
            "the default policy must accept a sub-less (client-credentials) token"
        );
        // Documents, rather than guards, the subjectless case: with no `sub`
        // the session-binding fingerprint falls back to `name`, which is why
        // `require_subject = true` is recommended for OAuth deployments using
        // an external session store.
        assert!(
            identity.and_then(|id| id.sub).is_none(),
            "a sub-less token must not synthesise a subject"
        );

        Ok(())
    }

    fn mint_token_with_extra(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        extra: &serde_json::Value,
    ) -> anyhow::Result<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let mut claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "scope": "mcp:read",
            "exp": now.saturating_add(3600),
            "iat": now,
        });
        if let (Some(base), Some(extra_map)) = (claims.as_object_mut(), extra.as_object()) {
            for (key, value) in extra_map {
                drop(base.insert(key.clone(), value.clone()));
            }
        }
        jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
    }

    async fn blank_claim_cache(
        require_subject: bool,
    ) -> anyhow::Result<(JwksCache, String, wiremock::MockServer)> {
        let kid = "blank-claim-kid";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.require_subject = require_subject;
        let cache = test_cache(&config)?;
        Ok((cache, pem, mock_server))
    }

    /// Skips a blank `preferred_username` and falls through to sub for name.
    #[tokio::test]
    async fn oauth_blank_preferred_username_falls_through_to_sub() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(false).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({ "sub": "real-sub", "preferred_username": "" }),
        )?;
        let id = cache
            .validate_token(&token)
            .await
            .context("a token with a usable sub must authenticate")?;
        assert_eq!(
            id.name, "real-sub",
            "blank preferred_username must be skipped"
        );
        assert_eq!(id.sub.as_deref(), Some("real-sub"));

        Ok(())
    }

    /// Falls all-blank claims to the oauth-client sentinel and fingerprints without panic.
    #[tokio::test]
    async fn oauth_all_blank_claims_yield_non_blank_name_and_fingerprint() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(false).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({
                "sub": "",
                "preferred_username": "  ",
                "azp": "",
                "client_id": "   ",
            }),
        )?;
        let id = cache
            .validate_token(&token)
            .await
            .context("all-blank identity claims still authenticate on a valid token")?;
        assert_eq!(
            id.name, "oauth-client",
            "all-blank claims must fall to the sentinel"
        );
        assert!(id.sub.is_none(), "a blank sub must be stored as None");
        // Exercises the fingerprint debug_assert: a blank stable id would panic.
        let _fingerprint = session_binding::fingerprint(&id);

        Ok(())
    }

    /// Rejects a whitespace-only sub when `require_subject` is on.
    #[tokio::test]
    async fn oauth_blank_sub_rejected_when_require_subject() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(true).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({ "sub": "   " }),
        )?;
        assert!(
            cache.validate_token(&token).await.is_none(),
            "require_subject must reject a blank sub"
        );

        Ok(())
    }

    /// Accepts a blank sub by default and stores it as None.
    #[tokio::test]
    async fn oauth_blank_sub_stored_as_none() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(false).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({ "sub": "" }),
        )?;
        let id = cache
            .validate_token(&token)
            .await
            .context("a blank sub is accepted by default (require_subject off)")?;
        assert!(id.sub.is_none(), "a blank sub must be stored as None");
        assert_eq!(id.name, "oauth-client");

        Ok(())
    }

    /// Falls through blank` sub and ``preferred_username` to a non-blank azp.
    #[tokio::test]
    async fn oauth_blank_preferred_and_sub_fall_through_to_azp() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(false).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({ "sub": "", "preferred_username": "  ", "azp": "svc-account" }),
        )?;
        let id = cache
            .validate_token(&token)
            .await
            .context("a usable azp must authenticate")?;
        assert_eq!(
            id.name, "svc-account",
            "must fall through to a non-blank azp"
        );
        assert!(id.sub.is_none(), "a blank sub must be stored as None");

        Ok(())
    }

    /// Falls through a blank azp to a non-blank `client_id`.
    #[tokio::test]
    async fn oauth_blank_azp_falls_through_to_client_id() -> anyhow::Result<()> {
        let (cache, pem, _server) = blank_claim_cache(false).await?;
        let token = mint_token_with_extra(
            &pem,
            "blank-claim-kid",
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            &serde_json::json!({
                "sub": "",
                "preferred_username": "",
                "azp": "  ",
                "client_id": "svc-client",
            }),
        )?;
        let id = cache
            .validate_token(&token)
            .await
            .context("a usable client_id must authenticate")?;
        assert_eq!(
            id.name, "svc-client",
            "must fall through past a blank azp to a non-blank client_id"
        );

        Ok(())
    }

    /// Surfaces a 307 from the token endpoint instead of following it with credentials.
    #[tokio::test]
    async fn credential_post_does_not_follow_redirect() -> anyhow::Result<()> {
        // M7: a 307 from the token endpoint must NOT be followed, or the
        // client_secret-bearing body would be re-sent to the redirect host.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/followed"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0) // verified on MockServer drop: must never be hit
            .mount(&mock)
            .await;
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/followed", mock.uri()).as_str()),
            )
            .mount(&mock)
            .await;

        let client = OauthHttpClient::build(None).context("build oauth http client")?;
        let resp = client
            .credential_client
            .post(format!("{}/token", mock.uri()))
            .body("grant_type=client_credentials")
            .send()
            .await
            .context("request sent")?;
        assert_eq!(
            resp.status().as_u16(),
            307,
            "credential client must surface the 307 rather than follow it"
        );

        Ok(())
    }

    fn test_token_exchange_config(token_url: String) -> TokenExchangeConfig {
        TokenExchangeConfig::new(
            token_url,
            "mcp-client",
            Some(secrecy::SecretString::new("test-client-secret".into())),
            None,
        )
        .with_audience("downstream-api")
    }

    const ENC_GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange";
    const ENC_ACCESS: &str = "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token";

    /// Keeps the pre-3.8.0 exchange form byte-identical for legacy configs.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::build_exchange_form_is_byte_identical_to_pre_3_8_0_output keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn build_exchange_form_is_byte_identical_to_pre_3_8_0_output() -> anyhow::Result<()> {
        let config = test_token_exchange_config("https://idp.example.com/token".into());
        let body = build_exchange_form(&config, "subj-token");
        assert_eq!(
            body,
            format!(
                "grant_type={ENC_GRANT}&subject_token=subj-token\
                 &subject_token_type={ENC_ACCESS}&requested_token_type={ENC_ACCESS}\
                 &audience=downstream-api"
            ),
            "a config predating 3.8.0 must produce an unchanged request body"
        );

        Ok(())
    }

    /// Emits only the required RFC 8693 params plus `client_id` when optionals are omitted.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::build_exchange_form_emits_only_required_params_when_all_optional_omitted keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn build_exchange_form_emits_only_required_params_when_all_optional_omitted()
    -> anyhow::Result<()> {
        let config =
            TokenExchangeConfig::new("https://idp.example.com/token", "public-client", None, None)
                .with_requested_token_type(RequestedTokenType::Omit);
        let body = build_exchange_form(&config, "subj");
        assert_eq!(
            body,
            format!(
                "grant_type={ENC_GRANT}&subject_token=subj\
                 &subject_token_type={ENC_ACCESS}&client_id=public-client"
            ),
            "only the three RFC 8693 \u{a7}2.1 REQUIRED params plus the public-client id"
        );

        Ok(())
    }

    /// Keeps RFC 8693 parameter order and sends a custom token type verbatim.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::build_exchange_form_keeps_rfc_parameter_order keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn build_exchange_form_keeps_rfc_parameter_order() -> anyhow::Result<()> {
        let config = test_token_exchange_config("https://idp.example.com/token".into())
            .with_resource("https://api.example.com/v1")
            .with_scope("read write")
            .with_requested_token_type(RequestedTokenType::Custom("urn:example:token".into()));
        let body = build_exchange_form(&config, "subj");
        let keys: Vec<&str> = body
            .split('&')
            .filter_map(|kv| kv.split('=').next())
            .collect();
        assert_eq!(
            keys,
            vec![
                "grant_type",
                "subject_token",
                "subject_token_type",
                "requested_token_type",
                "audience",
                "resource",
                "scope",
            ]
        );
        assert!(
            body.contains("&requested_token_type=urn%3Aexample%3Atoken"),
            "custom token type must be sent verbatim: {body}"
        );

        Ok(())
    }

    /// Deserializes a pre-3.8.0 `token_exchange` table with defaults for new keys.
    #[test]
    fn token_exchange_toml_omitting_new_keys_still_deserializes() -> anyhow::Result<()> {
        let cfg: TokenExchangeConfig = toml::from_str(
            "token_url = \"https://idp.example.com/token\"\n\
             client_id = \"client\"\n\
             audience = \"downstream\"\n",
        )
        .context("a token_exchange table predating 3.8.0 must still parse")?;
        assert_eq!(cfg.audience.as_deref(), Some("downstream"));
        assert_eq!(cfg.resource, None);
        assert_eq!(cfg.scope, None);
        assert_eq!(cfg.requested_token_type, RequestedTokenType::AccessToken);

        Ok(())
    }

    /// Redacts the upstream error description unless diagnostics opt in.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::upstream_error_description_is_redacted_by_default keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn upstream_error_description_is_redacted_by_default() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure::default());

        assert_eq!(
            upstream_error_description_for_log(Some("subject_token=eyJhbGciOi...")),
            "[REDACTED]",
            "upstream free-form text must not reach logs unless opted in"
        );
        assert_eq!(upstream_error_description_for_log(None), "[REDACTED]");

        Ok(())
    }

    /// Shows the upstream error description verbatim when opted in, empty for `None`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::upstream_error_description_is_shown_when_opted_in keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn upstream_error_description_is_shown_when_opted_in() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure {
            upstream_error_bodies: true,
            ..DiagnosticExposure::default()
        });

        assert_eq!(
            upstream_error_description_for_log(Some("audience not permitted")),
            "audience not permitted",
            "the debug switch must surface the upstream description verbatim"
        );
        assert_eq!(
            upstream_error_description_for_log(None),
            "",
            "an absent description renders empty, not the redaction marker"
        );

        Ok(())
    }

    /// Deserializes `requested_token_type` from `access_token`, omit, or a custom URN.
    #[test]
    fn requested_token_type_deserializes_from_plain_strings() -> anyhow::Result<()> {
        for (raw, expected) in [
            ("access_token", RequestedTokenType::AccessToken),
            ("omit", RequestedTokenType::Omit),
            (
                "urn:example:token",
                RequestedTokenType::Custom("urn:example:token".into()),
            ),
        ] {
            let cfg: TokenExchangeConfig = toml::from_str(&format!(
                "token_url = \"https://idp.example.com/token\"\n\
                 client_id = \"client\"\n\
                 requested_token_type = \"{raw}\"\n"
            ))
            .context("requested_token_type must accept any string")?;
            assert_eq!(cfg.requested_token_type, expected, "input {raw}");
        }

        Ok(())
    }

    fn exchange_response(access_token: &str, issued_token_type: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": access_token,
            "expires_in": 3600_u64,
            "issued_token_type": issued_token_type,
        })
    }

    fn unsigned_jwt_with_claims(claims: &serde_json::Value) -> anyhow::Result<String> {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).context("claims json")?);
        Ok(format!("{header}.{payload}.signature"))
    }

    fn test_exchange_client() -> anyhow::Result<OauthHttpClient> {
        let config = OAuthConfig::builder(
            "http://auth.test.local",
            "mcp",
            "http://auth.test.local/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        Ok(OauthHttpClient::build(Some(&config))
            .context("build oauth http client")?
            .__test_allow_loopback_ssrf())
    }

    fn unavailable_loopback_token_url() -> String {
        "http://127.0.0.1:1/token?client_secret=super-secret".to_owned()
    }

    async fn recorded_request_count(mock: &wiremock::MockServer) -> anyhow::Result<usize> {
        Ok(mock
            .received_requests()
            .await
            .context("wiremock request recording is enabled")?
            .len())
    }

    async fn wait_for_recorded_request(mock: &wiremock::MockServer) -> anyhow::Result<()> {
        // Liveness wait, not a latency bound: it returns as soon as the mock
        // records the request, so a generous ceiling costs nothing on success
        // and only makes a genuine hang fail slower.
        timeout(Duration::from_secs(15), async {
            loop {
                if recorded_request_count(mock)
                    .await
                    .is_ok_and(|count| count > 0)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("token endpoint must record the in-flight request before cancellation")?;
        Ok(())
    }

    async fn wait_for_log_contains(logs: &CapturedLogs, needle: &str) -> anyhow::Result<()> {
        // Must comfortably exceed the mock response delay: the detached task
        // cannot emit its audit line until the upstream exchange completes, so
        // this bound is `mock delay + slack`, not a latency expectation. It is
        // a bounded wait -- on success it returns as soon as the line appears.
        timeout(Duration::from_secs(15), async {
            loop {
                if logs.contents().contains(needle) {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("detached token exchange must eventually emit its audit log")?;
        Ok(())
    }

    /// Sanitizes the request URL and reqwest error, leaking no path or credentials.
    #[tokio::test]
    async fn send_screened_request_failure_sanitizes_url_and_reqwest_error() -> anyhow::Result<()> {
        let client = test_exchange_client()?;
        let screened_url = unavailable_loopback_token_url();
        let request_url = screened_url.replacen("//", "//u:p@", 1);

        let Err(error) = client
            .send_screened(
                &screened_url,
                client
                    .credential_client
                    .post(&request_url)
                    .body("grant_type=test"),
            )
            .await
        else {
            anyhow::bail!("closed loopback port must fail the request");
        };

        let rendered = error.to_string();
        let sanitized = oauth_request_target_for_log(&screened_url);
        assert!(
            rendered.contains(&format!("oauth request {sanitized}")),
            "request failure must identify only the sanitized origin: {rendered}"
        );
        for leaked in ["u:p", "/token", "client_secret", "super-secret"] {
            assert!(
                !rendered.contains(leaked),
                "request failure must not echo raw URL component {leaked}: {rendered}"
            );
        }

        Ok(())
    }

    /// Logs only the sanitized origin and keeps the client error sanitized on failure.
    #[tokio::test]
    async fn exchange_token_request_failure_log_sanitizes_token_url() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let client = test_exchange_client()?;
        let token_url = unavailable_loopback_token_url();
        let config = test_token_exchange_config(token_url);
        let Err(error) = exchange_token(&client, &config, "subject-token").await else {
            anyhow::bail!("closed loopback port must fail exchange");
        };

        assert!(
            error.to_string().contains("server_error"),
            "client-visible exchange error must remain sanitized: {error}"
        );
        let contents = logs.contents();
        assert!(
            contents.contains("token exchange request failed"),
            "exchange failure must still be logged: {contents}"
        );
        assert!(
            contents.contains("oauth request http://127.0.0.1:1"),
            "exchange failure log must include only sanitized origin: {contents}"
        );
        for leaked in ["/token", "client_secret", "super-secret", "subject-token"] {
            assert!(
                !contents.contains(leaked),
                "exchange failure log must not echo raw URL/token component {leaked}: {contents}"
            );
        }

        Ok(())
    }

    /// Skips sending entirely when the cancellation token is pre-cancelled.
    #[tokio::test]
    async fn exchange_token_with_cancel_precancel_does_not_send() -> anyhow::Result<()> {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(exchange_response(
                    "downstream-token",
                    "urn:ietf:params:oauth:token-type:access_token",
                )),
            )
            .mount(&mock)
            .await;

        let client = test_exchange_client()?;
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = CancellationToken::new();
        ct.cancel();

        let outcome =
            exchange_token_with_cancel(&client, &config, "subject-token", &ct, None).await;

        assert!(
            matches!(outcome, DetachOutcome::Cancelled),
            "pre-cancelled exchanges must not start work"
        );
        assert_eq!(
            recorded_request_count(&mock).await?,
            0,
            "pre-cancel check must happen before cloning/spawning/sending"
        );

        Ok(())
    }

    /// Completes a normal exchange and returns the downstream token when uncancelled.
    #[tokio::test]
    async fn exchange_token_with_cancel_completes_normally() -> anyhow::Result<()> {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(exchange_response(
                    "downstream-token",
                    "urn:ietf:params:oauth:token-type:access_token",
                )),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let client = test_exchange_client()?;
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = CancellationToken::new();

        let outcome =
            exchange_token_with_cancel(&client, &config, "subject-token", &ct, None).await;

        let DetachOutcome::Completed(Ok(token)) = outcome else {
            anyhow::bail!("uncancelled exchange must complete successfully")
        };
        assert_eq!(token.access_token, "downstream-token");
        mock.verify().await;

        Ok(())
    }

    /// Detaches on cancel, then audits an abandoned token without leaking secrets or claims.
    #[tokio::test]
    async fn exchange_token_with_cancel_detaches_and_audits_abandoned_token() -> anyhow::Result<()>
    {
        let mock = wiremock::MockServer::start().await;
        let long_issued_token_type = format!(
            "urn:ietf:params:oauth:token-type:{}",
            "x".repeat(MAX_LOGGED_KID_CHARS + 32)
        );
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    // Long enough that the completion arm cannot plausibly win
                    // the `biased;` race before the caller cancels. A tight
                    // delay would make the outcome assertion depend on machine
                    // load rather than on the detach behaviour it proves. The
                    // test never waits this out -- returning without waiting is
                    // precisely the point.
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(exchange_response(
                        "abandoned-downstream-token",
                        &long_issued_token_type,
                    )),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let token_url = format!("{}/token", mock.uri());
        let token_url_host = url::Url::parse(&token_url)
            .context("mock token URL parses")?
            .host_str()
            .context("mock token URL has host")?
            .to_owned();
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("rmcp_server_kit=debug"))
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let client = test_exchange_client()?;
        let config = test_token_exchange_config(token_url);
        let ct = CancellationToken::new();
        let task_ct = ct.clone();
        let handle = tokio::spawn(async move {
            exchange_token_with_cancel(&client, &config, "subject-token", &task_ct, None).await
        });

        wait_for_recorded_request(&mock).await?;
        let cancelled_at = Instant::now();
        ct.cancel();
        let outcome = handle.await.context("wrapper task must not panic")?;

        assert!(
            matches!(outcome, DetachOutcome::Cancelled),
            "caller must get an immediate cancellation outcome"
        );
        assert!(
            cancelled_at.elapsed() < Duration::from_millis(100),
            "wrapper must detach instead of waiting for the delayed upstream response"
        );

        wait_for_log_contains(
            &logs,
            "token exchange minted downstream token after caller detached",
        )
        .await?;
        mock.verify().await;
        let contents = logs.contents();
        assert!(
            contents.contains("issued_token_type_truncated=true"),
            "audit log must mark issuer-controlled token type truncation: {contents}"
        );
        assert!(
            !contents.contains("abandoned-downstream-token"),
            "audit log must not include downstream token material: {contents}"
        );
        assert!(
            !contents.contains("token_len="),
            "DEBUG success log must be suppressed on abandoned exchanges: {contents}"
        );
        assert!(
            !contents.contains(&long_issued_token_type),
            "detached logs must not include unbounded issued token type: {contents}"
        );
        for field in ["sub=", "aud=", "azp=", "iss="] {
            assert!(
                !contents.contains(field),
                "detached logs must not include JWT claim field {field}: {contents}"
            );
        }
        assert!(
            !contents.contains(&token_url_host),
            "detached success logs must not include token endpoint host: {contents}"
        );
        assert!(
            !contents.contains("subject-token"),
            "audit log must not include subject token material: {contents}"
        );
        assert!(
            !contents.contains("test-client-secret"),
            "audit log must not include client secret material: {contents}"
        );

        Ok(())
    }

    /// Suppresses JWT claim material in logs when a detached exchange later succeeds.
    #[tokio::test]
    async fn exchange_token_with_cancel_detached_jwt_success_does_not_log_claims()
    -> anyhow::Result<()> {
        let mock = wiremock::MockServer::start().await;
        let jwt = unsigned_jwt_with_claims(&serde_json::json!({
            "sub": "detached-subject",
            "aud": "detached-audience",
            "azp": "detached-client",
            "iss": "https://issuer.example.test/realm",
        }))?;
        wiremock::Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    // See the opaque-token variant of this test: the delay is a
                    // race margin, not a wait. It keeps the completion arm from
                    // winning the `biased;` race under load.
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(exchange_response(
                        &jwt,
                        "urn:ietf:params:oauth:token-type:access_token",
                    )),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("rmcp_server_kit=debug"))
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let client = test_exchange_client()?;
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = CancellationToken::new();
        let task_ct = ct.clone();
        let handle = tokio::spawn(async move {
            exchange_token_with_cancel(&client, &config, "subject-token", &task_ct, None).await
        });

        wait_for_recorded_request(&mock).await?;
        ct.cancel();
        let outcome = handle.await.context("wrapper task must not panic")?;
        assert!(
            matches!(outcome, DetachOutcome::Cancelled),
            "caller must get cancellation while spawned JWT exchange continues"
        );

        wait_for_log_contains(
            &logs,
            "token exchange minted downstream token after caller detached",
        )
        .await?;
        mock.verify().await;
        let contents = logs.contents();
        assert!(
            !contents.contains(&jwt),
            "detached JWT success must not log token material: {contents}"
        );
        for leaked in [
            "sub=",
            "aud=",
            "azp=",
            "iss=",
            "detached-subject",
            "detached-audience",
            "detached-client",
            "issuer.example.test",
        ] {
            assert!(
                !contents.contains(leaked),
                "detached JWT success must not log claim material {leaked}: {contents}"
            );
        }

        Ok(())
    }

    /// Lets a ready completion beat a ready cancellation under biased select.
    #[tokio::test]
    async fn exchange_token_with_cancel_completion_wins_tie() -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        tx.send(Ok(ExchangedToken {
            access_token: "tie-winner".into(),
            expires_in: Some(3600),
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".into()),
        }))
        .map_err(|_rejected| anyhow::anyhow!("test receiver is alive"))?;
        let ct = CancellationToken::new();
        ct.cancel();

        let outcome = receive_exchange_result_with_cancel(rx, &ct, None).await;

        let DetachOutcome::Completed(Ok(token)) = outcome else {
            anyhow::bail!("ready completion must win over ready cancellation under biased select")
        };
        assert_eq!(token.access_token, "tie-winner");

        Ok(())
    }

    /// Keeps the JWKS client following a redirect that passes the SSRF screen.
    #[tokio::test]
    async fn jwks_get_still_follows_screened_redirect() -> anyhow::Result<()> {
        // M7 regression: adding the no-redirect credential client must NOT
        // change the JWKS/discovery client, which still follows a redirect
        // whose every hop passes the SSRF screen. `allow_http` plus a loopback
        // allowlist entry let the http->http hop to the wiremock literal IP
        // clear `evaluate_oauth_redirect`'s scheme and per-hop SSRF checks.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(302).insert_header(
                "location",
                format!("{}/jwks-final.json", mock.uri()).as_str(),
            ))
            .mount(&mock)
            .await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks-final.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("reached"))
            .expect(1)
            .mount(&mock)
            .await;

        let mut allowlist = OAuthSsrfAllowlist::default();
        allowlist.cidrs.push("127.0.0.0/8".into());
        allowlist.cidrs.push("::1/128".into());
        let mut config = test_config(&format!("{}/jwks.json", mock.uri()));
        config.allow_http_oauth_urls = true;
        config.ssrf_allowlist = Some(allowlist);

        let client = OauthHttpClient::build(Some(&config)).context("build oauth http client")?;
        let resp = client
            .inner
            .get(format!("{}/jwks.json", mock.uri()))
            .send()
            .await
            .context("request sent")?;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "JWKS client must follow the screened redirect to the final endpoint"
        );
        assert_eq!(resp.text().await.context("response body")?, "reached");

        Ok(())
    }

    /// Rejects a token whose issuer differs from the configured issuer.
    #[tokio::test]
    async fn wrong_issuer_rejected() -> anyhow::Result<()> {
        let kid = "test-key-2";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://wrong-issuer.example.com", // wrong
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Rejects a token whose audience differs from the configured audience.
    #[tokio::test]
    async fn wrong_audience_rejected() -> anyhow::Result<()> {
        let kid = "test-key-3";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://wrong-audience.example.com", // wrong
            "attacker",
            "mcp:admin",
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Rejects a token expired beyond the leeway.
    #[tokio::test]
    async fn expired_jwt_rejected() -> anyhow::Result<()> {
        let kid = "test-key-4";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        // Create a token that expired 2 minutes ago (past the 60s leeway).
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).context("encoding key")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://mcp.test.local/mcp",
            "sub": "expired-bot",
            "scope": "mcp:read",
            "exp": now - 120,
            "iat": now - 3720,
        });
        let token =
            jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Classifies an expired token as `JwtValidationFailure::Expired`.
    #[tokio::test]
    async fn characterize_expired_jwt_is_classified_expired() -> anyhow::Result<()> {
        let kid = "test-key-characterize-expired";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "expired-bot",
                "scope": "mcp:read",
                "exp": now - 120,
                "iat": now - 3720,
            }),
        )?;

        assert!(matches!(
            cache.validate_token_with_reason(&token).await,
            Err(JwtValidationFailure::Expired)
        ));

        Ok(())
    }

    /// Classifies wrong-audience, no-role, and sub-less rejections as Invalid.
    #[tokio::test]
    async fn characterize_rejections_are_invalid_publicly() -> anyhow::Result<()> {
        let kid = "test-key-characterize-invalid";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let cache = test_cache(&test_config(&jwks_uri))?;
        let wrong_aud = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://wrong-audience.example.com",
            "attacker",
            "mcp:read",
        )?;
        assert!(matches!(
            cache.validate_token_with_reason(&wrong_aud).await,
            Err(JwtValidationFailure::Invalid)
        ));

        let no_role = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "limited",
            "no:mapping",
        )?;
        assert!(matches!(
            cache.validate_token_with_reason(&no_role).await,
            Err(JwtValidationFailure::Invalid)
        ));

        let mut require_sub = test_config(&jwks_uri);
        require_sub.require_subject = true;
        let require_sub_cache = test_cache(&require_sub)?;
        let no_sub = mint_token_without_sub(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "mcp:read",
        )?;
        assert!(matches!(
            require_sub_cache.validate_token_with_reason(&no_sub).await,
            Err(JwtValidationFailure::Invalid)
        ));

        Ok(())
    }

    /// Rejects a token whose scopes map to no configured role.
    #[tokio::test]
    async fn no_matching_scope_rejected() -> anyhow::Result<()> {
        let kid = "test-key-5";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "limited-bot",
            "some:other:scope", // no matching scope
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Rejects a token signed by a key different from the JWKS public key.
    #[tokio::test]
    async fn wrong_signing_key_rejected() -> anyhow::Result<()> {
        let kid = "test-key-6";
        let (_pem, jwks) = generate_test_keypair(kid)?;

        // Generate a DIFFERENT keypair for signing (attacker key).
        let (attacker_pem, _) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        // Sign with attacker key but JWKS has legitimate public key.
        let token = mint_token(
            &attacker_pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Maps the mcp:admin scope to the ops role.
    #[tokio::test]
    async fn admin_scope_maps_to_ops_role() -> anyhow::Result<()> {
        let kid = "test-key-7";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "admin-bot",
            "mcp:admin",
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("should authenticate")?;
        assert_eq!(id.role, "ops");
        assert_eq!(id.name, "admin-bot");

        Ok(())
    }

    /// Authenticates end-to-end against an Entra-shaped JWKS whose keys omit alg.
    #[tokio::test]
    async fn entra_shaped_alg_less_jwks_authenticates_end_to_end() -> anyhow::Result<()> {
        // Issue #17: the reported Entra failure, reproduced end-to-end. The
        // JWKS omits `alg` exactly as login.microsoftonline.com does; before
        // family inference the key was dropped and this returned None.
        let kid = "entra-e2e";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mut alg_less = jwks;
        if let Some(key) = json_first_mut(&mut alg_less, "keys")?.as_object_mut() {
            drop(key.remove("alg"));
        }
        assert!(
            json_first(&alg_less, "keys")?.get("alg").is_none(),
            "fixture must reproduce Entra's alg-less shape"
        );

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&alg_less))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "entra-user",
            "mcp:admin",
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("an alg-less JWKS key must still authenticate (issue #17)")?;
        assert_eq!(id.name, "entra-user");

        Ok(())
    }

    /// Returns None when the JWKS endpoint is unreachable.
    #[tokio::test]
    async fn jwks_server_down_returns_none() -> anyhow::Result<()> {
        // Point to a non-existent server.
        let config = test_config("http://127.0.0.1:1/jwks.json");
        let cache = test_cache(&config)?;

        let kid = "orphan-key";
        let (pem, _) = generate_test_keypair(kid)?;
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "bot",
            "mcp:read",
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // resolve_claim_path tests
    // -----------------------------------------------------------------------

    /// Splits a flat whitespace-delimited string claim into values.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::resolve_claim_path_flat_string keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn resolve_claim_path_flat_string() -> anyhow::Result<()> {
        let mut extra = HashMap::new();
        drop(extra.insert(
            "scope".into(),
            serde_json::Value::String("mcp:read mcp:admin".into()),
        ));
        let values = resolve_claim_path(&extra, "scope");
        assert_eq!(values, vec!["mcp:read", "mcp:admin"]);

        Ok(())
    }

    /// Returns the elements of a flat JSON array claim.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::resolve_claim_path_flat_array keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn resolve_claim_path_flat_array() -> anyhow::Result<()> {
        let mut extra = HashMap::new();
        drop(extra.insert(
            "roles".into(),
            serde_json::json!(["mcp-admin", "mcp-viewer"]),
        ));
        let values = resolve_claim_path(&extra, "roles");
        assert_eq!(values, vec!["mcp-admin", "mcp-viewer"]);

        Ok(())
    }

    /// Resolves a dotted nested path into a Keycloak roles array.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::resolve_claim_path_nested_keycloak keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn resolve_claim_path_nested_keycloak() -> anyhow::Result<()> {
        let mut extra = HashMap::new();
        drop(extra.insert(
            "realm_access".into(),
            serde_json::json!({"roles": ["uma_authorization", "mcp-admin"]}),
        ));
        let values = resolve_claim_path(&extra, "realm_access.roles");
        assert_eq!(values, vec!["uma_authorization", "mcp-admin"]);

        Ok(())
    }

    /// Returns empty for a claim path that does not exist.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::resolve_claim_path_missing_returns_empty keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn resolve_claim_path_missing_returns_empty() -> anyhow::Result<()> {
        let extra = HashMap::new();
        assert_eq!(
            resolve_claim_path(&extra, "nonexistent.path"),
            Vec::<&str>::new()
        );

        Ok(())
    }

    /// Returns empty for a numeric leaf that is not a string or array.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::resolve_claim_path_numeric_leaf_returns_empty keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn resolve_claim_path_numeric_leaf_returns_empty() -> anyhow::Result<()> {
        let mut extra = HashMap::new();
        drop(extra.insert("count".into(), serde_json::json!(42_i32)));
        assert_eq!(resolve_claim_path(&extra, "count"), Vec::<&str>::new());

        Ok(())
    }

    fn make_claims(json: serde_json::Value) -> anyhow::Result<Claims> {
        serde_json::from_value(json).context("test claims must deserialize")
    }

    /// Splits the first-class scope claim on whitespace.
    #[test]
    fn first_class_scope_claim_splits_on_whitespace() -> anyhow::Result<()> {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "scope": "read write admin",
        }))?;
        let values = first_class_claim_values(&claims, "scope");
        assert_eq!(values, vec!["read", "write", "admin"]);

        Ok(())
    }

    /// Returns the sub claim as a single value.
    #[test]
    fn first_class_sub_claim_returns_single_value() -> anyhow::Result<()> {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "sub": "service-account-orders",
        }))?;
        let values = first_class_claim_values(&claims, "sub");
        assert_eq!(values, vec!["service-account-orders"]);

        Ok(())
    }

    /// Returns every entry of a multi-valued aud claim.
    #[test]
    fn first_class_aud_claim_returns_every_audience() -> anyhow::Result<()> {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "aud": ["api-a", "api-b"],
        }))?;
        let values = first_class_claim_values(&claims, "aud");
        assert_eq!(values, vec!["api-a", "api-b"]);

        Ok(())
    }

    /// Returns empty for an unknown first-class claim path.
    #[test]
    fn first_class_unknown_path_returns_empty() -> anyhow::Result<()> {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
        }))?;
        assert_eq!(
            first_class_claim_values(&claims, "realm_access.roles"),
            Vec::<String>::new()
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // role_claim integration tests (wiremock)
    // -----------------------------------------------------------------------

    /// Mint a JWT with arbitrary custom claims (for `role_claim` testing).
    fn mint_token_with_claims(
        private_pem: &str,
        kid: &str,
        claims: &serde_json::Value,
    ) -> anyhow::Result<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
    }

    async fn cache_for_jwks(
        jwks: &serde_json::Value,
    ) -> anyhow::Result<(JwksCache, wiremock::MockServer)> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        Ok((test_cache(&test_config(&jwks_uri))?, mock_server))
    }

    fn assert_jwt_owner(
        rejection: &JwtRejection,
        failure: JwtValidationFailure,
        owner: Option<(&str, RejectionReason)>,
    ) -> anyhow::Result<()> {
        assert_eq!(rejection.failure, failure);
        match (rejection.owner.as_ref(), owner) {
            (Some(actual), Some((name, reason))) => {
                assert_eq!(actual.name, name);
                assert_eq!(actual.reason, reason);
            }
            (None, None) => {}
            (actual, expected) => {
                anyhow::bail!("owner mismatch: actual={actual:?} expected={expected:?}");
            }
        }
        Ok(())
    }

    /// Names the owner for an expired correct-issuer token, logging the re-decode.
    #[tokio::test]
    async fn detailed_expired_correct_issuer_names_owner() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let kid = "detailed-expired-owner";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "sub-alice",
                "preferred_username": "alice",
                "scope": "mcp:read",
                "exp": now - 120,
                "iat": now - 3720,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("expired token must reject");
        };

        assert_jwt_owner(
            &rejection,
            JwtValidationFailure::Expired,
            Some(("alice", RejectionReason::Expired)),
        )?;
        assert!(
            logs.contents()
                .contains("JWT expired; re-decoding without exp for owner attribution")
        );

        Ok(())
    }

    /// Skips owner re-decode and leaves no owner when owner attribution is disabled.
    #[tokio::test]
    async fn detailed_expired_without_owner_does_not_redecode() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let kid = "detailed-expired-no-owner";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "sub-alice",
                "preferred_username": "alice",
                "scope": "mcp:read",
                "exp": now - 120,
                "iat": now - 3720,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, false).await else {
            anyhow::bail!("expired token must reject");
        };

        assert_jwt_owner(&rejection, JwtValidationFailure::Expired, None)?;
        assert!(
            !logs
                .contents()
                .contains("JWT expired; re-decoding without exp for owner attribution")
        );

        Ok(())
    }

    /// Leaves no owner for an expired token with a wrong issuer.
    #[tokio::test]
    async fn detailed_expired_wrong_issuer_has_no_owner() -> anyhow::Result<()> {
        let kid = "detailed-expired-wrong-issuer";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://evil.example",
                "aud": "https://mcp.test.local/mcp",
                "preferred_username": "alice",
                "scope": "mcp:read",
                "exp": now - 120,
                "iat": now - 3720,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(&rejection, JwtValidationFailure::Expired, None)?;

        Ok(())
    }

    /// Leaves no owner for an expired token whose nbf is in the future.
    #[tokio::test]
    async fn detailed_expired_future_nbf_has_no_owner() -> anyhow::Result<()> {
        let kid = "detailed-expired-future-nbf";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "preferred_username": "alice",
                "scope": "mcp:read",
                "exp": now - 120,
                "nbf": now + 3600,
                "iat": now - 3720,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(&rejection, JwtValidationFailure::Expired, None)?;

        Ok(())
    }

    /// Leaves no owner for a token with a bad signature.
    #[tokio::test]
    async fn detailed_bad_signature_has_no_owner() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let _guard = capture_debug_logs(logs.clone());
        let kid = "detailed-bad-signature";
        let (_pem, jwks) = generate_test_keypair(kid)?;
        let (attacker_pem, _) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let token = mint_token(
            &attacker_pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:read",
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(&rejection, JwtValidationFailure::Invalid, None)?;
        assert!(
            !logs
                .contents()
                .contains("JWT expired; re-decoding without exp for owner attribution")
        );

        Ok(())
    }

    /// Names the owner with reason Audience for a wrong-audience token.
    #[tokio::test]
    async fn detailed_wrong_audience_names_owner() -> anyhow::Result<()> {
        let kid = "detailed-wrong-audience";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://wrong.example",
            "bob",
            "mcp:read",
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(
            &rejection,
            JwtValidationFailure::Invalid,
            Some(("bob", RejectionReason::Audience)),
        )?;

        Ok(())
    }

    /// Names the owner with reason Role when no role mapping matches.
    #[tokio::test]
    async fn detailed_no_role_names_owner() -> anyhow::Result<()> {
        let kid = "detailed-no-role";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "carol",
            "no:mapping",
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(
            &rejection,
            JwtValidationFailure::Invalid,
            Some(("carol", RejectionReason::Role)),
        )?;

        Ok(())
    }

    /// Names the owner with reason Subject when `require_subject` rejects a sub-less token.
    #[tokio::test]
    async fn detailed_require_subject_names_owner() -> anyhow::Result<()> {
        let kid = "detailed-require-subject";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let mut config = test_config(&format!("{}/jwks.json", mock_server.uri()));
        config.require_subject = true;
        let cache = test_cache(&config)?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "preferred_username": "svc",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(
            &rejection,
            JwtValidationFailure::Invalid,
            Some(("svc", RejectionReason::Subject)),
        )?;

        Ok(())
    }

    /// Falls back to the oauth-client owner name when no name claims exist.
    #[tokio::test]
    async fn detailed_no_name_claims_uses_oauth_client_fallback() -> anyhow::Result<()> {
        let kid = "detailed-no-name-fallback";
        let (pem, jwks) = generate_test_keypair(kid)?;
        let (cache, _server) = cache_for_jwks(&jwks).await?;
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://wrong.example",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        let Err(rejection) = cache.validate_token_detailed(&token, true).await else {
            anyhow::bail!("validate_token_detailed must reject the token");
        };

        assert_jwt_owner(
            &rejection,
            JwtValidationFailure::Invalid,
            Some(("oauth-client", RejectionReason::Audience)),
        )?;

        Ok(())
    }

    fn test_config_with_role_claim(
        jwks_uri: &str,
        role_claim: &str,
        role_mappings: Vec<RoleMapping>,
    ) -> OAuthConfig {
        OAuthConfig {
            require_subject: false,
            issuer: "https://auth.test.local".into(),
            audience: "https://mcp.test.local/mcp".into(),
            jwks_uri: jwks_uri.into(),
            scopes: vec![],
            role_claim: Some(role_claim.into()),
            role_mappings,
            jwks_cache_ttl: "5m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: true,
            max_jwks_keys: default_max_jwks_keys(),
            allowed_algorithms: None,
            authorization_servers: None,
            authorization_server_metadata_issuer: None,
            #[expect(
                deprecated,
                reason = "test fixture: explicit value for the deprecated field"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        }
    }

    /// Rejects a literal IPv4 URL target as forbidden.
    #[tokio::test]
    async fn screen_oauth_target_rejects_literal_ip() -> anyhow::Result<()> {
        let Err(err) = screen_oauth_target(
            "https://127.0.0.1/jwks.json",
            false,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        else {
            anyhow::bail!("literal IPs must be rejected");
        };
        let msg = err.to_string();
        assert!(msg.contains("literal IPv4 addresses are forbidden"));

        Ok(())
    }

    /// Rejects a hostname resolving to loopback.
    #[tokio::test]
    async fn screen_oauth_target_rejects_private_dns_resolution() -> anyhow::Result<()> {
        let Err(err) = screen_oauth_target(
            "https://localhost/jwks.json",
            false,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        else {
            anyhow::bail!("localhost resolution must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("blocked IP") && msg.contains("loopback"),
            "got {msg:?}"
        );

        Ok(())
    }

    /// Rejects a literal IPv4 even when `allow_http` is set.
    #[tokio::test]
    async fn screen_oauth_target_rejects_literal_ip_even_with_allow_http() -> anyhow::Result<()> {
        let Err(err) = screen_oauth_target(
            "http://127.0.0.1/jwks.json",
            true,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        else {
            anyhow::bail!("literal IPs must still be rejected when http is allowed");
        };
        let msg = err.to_string();
        assert!(msg.contains("literal IPv4 addresses are forbidden"));

        Ok(())
    }

    /// Rejects a loopback-resolving hostname even when `allow_http` is set.
    #[tokio::test]
    async fn screen_oauth_target_rejects_private_dns_even_with_allow_http() -> anyhow::Result<()> {
        let Err(err) = screen_oauth_target(
            "http://localhost/jwks.json",
            true,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        else {
            anyhow::bail!("private DNS resolution must still be rejected when http is allowed");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("blocked IP") && msg.contains("loopback"),
            "got {msg:?}"
        );

        Ok(())
    }

    /// Allows a public hostname through SSRF screening.
    #[tokio::test]
    async fn screen_oauth_target_allows_public_hostname() -> anyhow::Result<()> {
        screen_oauth_target(
            "https://example.com/.well-known/jwks.json",
            false,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        .context("public hostname should pass screening")?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Operator SSRF allowlist (1.4.0)
    // -----------------------------------------------------------------------

    /// Helper: compile an allowlist from string literals.
    fn make_allowlist(hosts: &[&str], cidrs: &[&str]) -> anyhow::Result<CompiledSsrfAllowlist> {
        let raw = OAuthSsrfAllowlist {
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            cidrs: cidrs.iter().map(|cidr| (*cidr).to_owned()).collect(),
        };
        compile_oauth_ssrf_allowlist(&raw)
            .map_err(anyhow::Error::msg)
            .context("test allowlist compiles")
    }

    /// Lowercases and dedupes host allowlist entries, matching case-insensitively.
    #[test]
    fn compile_oauth_ssrf_allowlist_lowercases_and_dedupes_hosts() -> anyhow::Result<()> {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["RHBK.ops.example.com".into(), "rhbk.ops.example.com".into()],
            cidrs: vec![],
        };
        let compiled = compile_oauth_ssrf_allowlist(&raw)
            .map_err(anyhow::Error::msg)
            .context("compiles")?;
        assert_eq!(compiled.host_count(), 1);
        assert!(compiled.host_allowed("rhbk.ops.example.com"));
        assert!(compiled.host_allowed("RHBK.OPS.EXAMPLE.COM"));

        Ok(())
    }

    /// Rejects a literal IP in the host allowlist.
    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_literal_ip_in_hosts() -> anyhow::Result<()> {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["10.0.0.1".into()],
            cidrs: vec![],
        };
        let Err(err) = compile_oauth_ssrf_allowlist(&raw) else {
            anyhow::bail!("literal IP in hosts");
        };
        assert!(err.contains("literal IPs are forbidden"), "got {err:?}");

        Ok(())
    }

    /// Rejects a host allowlist entry containing a port.
    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_host_with_port() -> anyhow::Result<()> {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["rhbk.ops.example.com:8443".into()],
            cidrs: vec![],
        };
        let Err(err) = compile_oauth_ssrf_allowlist(&raw) else {
            anyhow::bail!("host:port");
        };
        assert!(err.contains("must be a bare DNS hostname"), "got {err:?}");

        Ok(())
    }

    // -- L3: internal-hostname-suffix pre-DNS denylist --

    /// Blocks internal/local/.localhost suffixes when no allowlist entry matches.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::internal_suffix_rejected_by_default keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn internal_suffix_rejected_by_default() -> anyhow::Result<()> {
        let allow = CompiledSsrfAllowlist::default();
        for host in ["idp.internal", "svc.local", "x.localhost", "idp.internal."] {
            assert!(oauth_internal_suffix_blocked(host, &allow), "{host}");
        }

        Ok(())
    }

    /// Permits an exact allowlisted internal host, with or without trailing dot.
    #[test]
    fn exact_allowlisted_internal_permitted() -> anyhow::Result<()> {
        let allow = make_allowlist(&["idp.internal"], &[])?;
        assert!(!oauth_internal_suffix_blocked("idp.internal", &allow));
        assert!(!oauth_internal_suffix_blocked("idp.internal.", &allow));

        Ok(())
    }

    /// Still rejects a subdomain of an allowlisted internal host.
    #[test]
    fn subdomain_of_allowlisted_internal_still_rejected() -> anyhow::Result<()> {
        let allow = make_allowlist(&["idp.internal"], &[])?;
        assert!(oauth_internal_suffix_blocked("sub.idp.internal", &allow));

        Ok(())
    }

    /// Does not let a CIDR allowlist bypass the internal suffix denylist.
    #[test]
    fn cidr_allowlist_does_not_bypass_suffix_denylist() -> anyhow::Result<()> {
        let allow = make_allowlist(&[], &["10.0.0.0/8"])?;
        assert!(oauth_internal_suffix_blocked("idp.internal", &allow));

        Ok(())
    }

    /// Leaves a public hostname unblocked by the internal suffix rule.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::public_hostname_not_blocked_by_suffix keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn public_hostname_not_blocked_by_suffix() -> anyhow::Result<()> {
        let allow = CompiledSsrfAllowlist::default();
        assert!(!oauth_internal_suffix_blocked("idp.example.com", &allow));

        Ok(())
    }

    /// Rejects an invalid CIDR naming the `oauth.ssrf_allowlist.cidrs` index.
    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_invalid_cidr() -> anyhow::Result<()> {
        let raw = OAuthSsrfAllowlist {
            hosts: vec![],
            cidrs: vec!["not-a-cidr".into()],
        };
        let Err(err) = compile_oauth_ssrf_allowlist(&raw) else {
            anyhow::bail!("invalid CIDR");
        };
        assert!(err.contains("oauth.ssrf_allowlist.cidrs[0]"), "got {err:?}");

        Ok(())
    }

    /// Rejects a misconfigured `ssrf_allowlist` through config validation.
    #[test]
    fn validate_rejects_misconfigured_allowlist() -> anyhow::Result<()> {
        let mut cfg = OAuthConfig::builder(
            "https://auth.example.com/",
            "mcp",
            "https://auth.example.com/jwks.json",
        )
        .build();
        cfg.ssrf_allowlist = Some(OAuthSsrfAllowlist {
            hosts: vec!["10.0.0.1".into()],
            cidrs: vec![],
        });
        let Err(err) = cfg.validate() else {
            anyhow::bail!("literal IP host must be rejected");
        };
        assert!(
            err.to_string().contains("oauth.ssrf_allowlist"),
            "got {err}"
        );

        Ok(())
    }

    /// Emits a verbose blocked-target error referencing the allowlist and SECURITY.md.
    #[tokio::test]
    async fn screen_oauth_target_with_allowlist_emits_helpful_error() -> anyhow::Result<()> {
        // localhost resolves to loopback; with a *non-empty* allowlist that
        // doesn't cover loopback, we expect the new verbose error referencing
        // the config field.
        let allow = make_allowlist(&["other.example.com"], &["10.0.0.0/8"])?;
        let Err(err) = screen_oauth_target("https://localhost/jwks.json", false, &allow).await
        else {
            anyhow::bail!("loopback must still be blocked when not in allowlist");
        };
        let msg = err.to_string();
        assert!(msg.contains("OAuth target blocked"), "got {msg:?}");
        assert!(msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");
        assert!(msg.contains("SECURITY.md"), "got {msg:?}");

        Ok(())
    }

    /// Keeps the pre-1.4.0 blocked-target wording when the allowlist is empty.
    #[tokio::test]
    async fn screen_oauth_target_empty_allowlist_uses_legacy_message() -> anyhow::Result<()> {
        // The default (empty) allowlist must continue to emit the
        // pre-1.4.0 wording so existing operator runbooks keep working.
        let Err(err) = screen_oauth_target(
            "https://localhost/jwks.json",
            false,
            &CompiledSsrfAllowlist::default(),
        )
        .await
        else {
            anyhow::bail!("loopback rejection");
        };
        let msg = err.to_string();
        assert!(msg.contains("blocked IP"), "got {msg:?}");
        assert!(msg.contains("loopback"), "got {msg:?}");
        // The legacy message must NOT advertise the new knob.
        assert!(!msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");

        Ok(())
    }

    /// Allows loopback when localhost is host-allowlisted.
    #[tokio::test]
    async fn screen_oauth_target_allows_loopback_when_host_allowlisted() -> anyhow::Result<()> {
        // localhost -> 127.0.0.1; allowlisting the hostname must let it through.
        let allow = make_allowlist(&["localhost"], &[])?;
        screen_oauth_target("https://localhost/jwks.json", false, &allow)
            .await
            .context("allowlisted host must pass")?;

        Ok(())
    }

    /// Allows loopback when both loopback CIDRs are allowlisted.
    #[tokio::test]
    async fn screen_oauth_target_allows_loopback_when_cidr_allowlisted() -> anyhow::Result<()> {
        // localhost may resolve to 127.0.0.1 and/or ::1 depending on the OS;
        // allowlist both loopback ranges to make the test stable cross-platform.
        let allow = make_allowlist(&[], &["127.0.0.0/8", "::1/128"])?;
        screen_oauth_target("https://localhost/jwks.json", false, &allow)
            .await
            .context("allowlisted CIDR must pass")?;

        Ok(())
    }

    /// Fails `JwksCache::new` for an invalid `ssrf_allowlist` CIDR.
    #[tokio::test]
    async fn jwks_cache_rejects_misconfigured_allowlist_at_startup() -> anyhow::Result<()> {
        let mut cfg = OAuthConfig::builder(
            "https://auth.example.com/",
            "mcp",
            "https://auth.example.com/jwks.json",
        )
        .build();
        cfg.ssrf_allowlist = Some(OAuthSsrfAllowlist {
            hosts: vec![],
            cidrs: vec!["bad-cidr".into()],
        });
        let Err(err) = JwksCache::new(&cfg) else {
            anyhow::bail!("invalid CIDR must fail JwksCache::new")
        };
        let msg = err.to_string();
        assert!(msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");

        Ok(())
    }

    /// Returns Err rather than panicking for an invalid `jwks_cache_ttl`.
    #[tokio::test]
    async fn jwks_cache_new_invalid_ttl_is_err() -> anyhow::Result<()> {
        // An unvalidated config with a bogus TTL must surface as Err, not
        // as the formerly-documented panic.
        let cfg = OAuthConfig::builder(
            "https://auth.example.com/",
            "mcp",
            "https://auth.example.com/jwks.json",
        )
        .jwks_cache_ttl("not-a-duration")
        .build();
        let Err(err) = JwksCache::new(&cfg) else {
            anyhow::bail!("invalid jwks_cache_ttl must fail JwksCache::new")
        };
        let msg = err.to_string();
        assert!(msg.contains("jwks_cache_ttl"), "got {msg:?}");

        Ok(())
    }

    /// Rejects an azp-only audience match under the default Strict policy.
    #[tokio::test]
    async fn audience_default_is_strict() -> anyhow::Result<()> {
        let kid = "test-audience-azp-default";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://some-other-resource.example.com",
                "azp": "https://mcp.test.local/mcp",
                "sub": "compat-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        let Err(failure) = cache.validate_token_with_reason(&token).await else {
            anyhow::bail!("the default policy is Strict and must reject an azp-only match");
        };
        assert_eq!(failure, JwtValidationFailure::Invalid);

        Ok(())
    }

    /// Accepts an azp-only audience match when `audience_validation_mode` is Warn.
    #[tokio::test]
    async fn audience_warn_still_accepts_azp() -> anyhow::Result<()> {
        let kid = "test-audience-warn-optin";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Warn);
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://some-other-resource.example.com",
                "azp": "https://mcp.test.local/mcp",
                "sub": "warn-optin-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        drop(
            cache
                .validate_token_with_reason(&token)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context(
                    "the audience_validation_mode=warn opt-out must still accept an azp-only match",
                )?,
        );

        Ok(())
    }

    /// Maps the legacy `strict_audience_validation=false` to Warn, accepting azp.
    #[tokio::test]
    async fn legacy_strict_false_maps_to_warn() -> anyhow::Result<()> {
        let kid = "test-audience-legacy-false";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        // Legacy opt-out: the deprecated bool set to Some(false) with the enum
        // unset must resolve to Warn, preserving the pre-3.2 azp-accepting path.
        #[expect(deprecated, reason = "covers the legacy bool compat mapping")]
        {
            config.strict_audience_validation = Some(false);
        }
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://some-other-resource.example.com",
                "azp": "https://mcp.test.local/mcp",
                "sub": "legacy-false-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        drop(
            cache
                .validate_token_with_reason(&token)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context(
                    "strict_audience_validation=Some(false) must map to Warn and accept azp",
                )?,
        );

        Ok(())
    }

    /// Accepts a matching aud even under the Strict default.
    #[tokio::test]
    async fn aud_match_always_accepts() -> anyhow::Result<()> {
        let kid = "test-audience-aud-match";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // Strict by default
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "aud-match-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        drop(
            cache
                .validate_token_with_reason(&token)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context("a matching aud must be accepted even under the Strict default")?,
        );

        Ok(())
    }

    /// Rejects an azp-only match when strict validation is enabled.
    #[tokio::test]
    async fn strict_audience_validation_rejects_azp_only_match() -> anyhow::Result<()> {
        let kid = "test-audience-azp-strict";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        #[expect(deprecated, reason = "covers the legacy bool resolution path")]
        {
            config.strict_audience_validation = Some(true);
        }
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://some-other-resource.example.com",
                "azp": "https://mcp.test.local/mcp",
                "sub": "strict-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        let Err(failure) = cache.validate_token_with_reason(&token).await else {
            anyhow::bail!("strict audience validation must ignore azp fallback");
        };
        assert_eq!(failure, JwtValidationFailure::Invalid);

        Ok(())
    }

    /// Accepts azp-only matches in Warn mode and sets the warn-once flag once.
    #[tokio::test]
    async fn warn_mode_accepts_azp_only_match_and_warns_once() -> anyhow::Result<()> {
        let kid = "test-audience-warn-mode";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Warn);
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://some-other-resource.example.com",
            "azp": "https://mcp.test.local/mcp",
            "sub": "warn-client",
            "scope": "mcp:read",
            "exp": now.saturating_add(3600),
            "iat": now,
        });
        let token = mint_token_with_claims(&pem, kid, &claims)?;

        let identity = cache
            .validate_token_with_reason(&token)
            .await
            .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
            .context("warn mode must accept azp-only match")?;
        assert_eq!(identity.role, "viewer");
        assert!(
            cache.azp_fallback_warned.load(Ordering::Relaxed),
            "warn-once flag should be set after first azp-only match"
        );

        let token2 = mint_token_with_claims(&pem, kid, &claims)?;
        drop(
            cache
                .validate_token_with_reason(&token2)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context("warn mode must continue accepting subsequent matches")?,
        );
        assert!(
            cache.azp_fallback_warned.load(Ordering::Relaxed),
            "warn-once flag must remain set; the assertion guards against accidental clearing"
        );

        Ok(())
    }

    /// Accepts azp-only matches silently in Permissive mode without the warn flag.
    #[tokio::test]
    async fn permissive_mode_accepts_azp_only_match_silently() -> anyhow::Result<()> {
        let kid = "test-audience-permissive-mode";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Permissive);
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://some-other-resource.example.com",
                "azp": "https://mcp.test.local/mcp",
                "sub": "permissive-client",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now,
            }),
        )?;

        drop(
            cache
                .validate_token_with_reason(&token)
                .await
                .map_err(|failure| anyhow::anyhow!("token rejected: {failure:?}"))
                .context("permissive mode must accept azp-only match")?,
        );
        assert!(
            !cache.azp_fallback_warned.load(Ordering::Relaxed),
            "permissive mode must not flip the warn-once flag"
        );
        assert!(
            cache.azp_permissive_logged.load(Ordering::Relaxed),
            "permissive mode must record its own once-per-process log flag"
        );

        Ok(())
    }

    // Lets an explicit audience_validation_mode override the legacy bool either way.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::audience_validation_mode_overrides_legacy_bool keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn audience_validation_mode_overrides_legacy_bool() -> anyhow::Result<()> {
        let mut config = OAuthConfig::default();
        #[expect(deprecated, reason = "covers the precedence rule for the legacy bool")]
        {
            config.strict_audience_validation = Some(false);
        }
        config.audience_validation_mode = Some(AudienceValidationMode::Strict);
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "explicit mode must override legacy false"
        );

        let mut legacy_config = OAuthConfig::default();
        #[expect(deprecated, reason = "covers the precedence rule for the legacy bool")]
        {
            legacy_config.strict_audience_validation = Some(true);
        }
        legacy_config.audience_validation_mode = Some(AudienceValidationMode::Permissive);
        assert_eq!(
            legacy_config.effective_audience_validation_mode(),
            AudienceValidationMode::Permissive,
            "explicit mode must override legacy true"
        );

        Ok(())
    }

    /// Resolves unset mode and bool to Strict.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::audience_validation_mode_default_is_strict_when_unset keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn audience_validation_mode_default_is_strict_when_unset() -> anyhow::Result<()> {
        let config = OAuthConfig::default();
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "unset mode + unset bool must resolve to Strict (the secure default)"
        );

        Ok(())
    }

    /// Resolves the legacy `strict_audience_validation=true` to Strict.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::audience_validation_legacy_bool_true_resolves_to_strict keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn audience_validation_legacy_bool_true_resolves_to_strict() -> anyhow::Result<()> {
        let mut config = OAuthConfig::default();
        #[expect(deprecated, reason = "covers the legacy bool resolution path")]
        {
            config.strict_audience_validation = Some(true);
        }
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "legacy bool=true must resolve to Strict for backward compat"
        );

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

    impl io::Write for CapturedLogsWriter {
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

    impl<'writer> subscriber_fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    fn capture_debug_logs(logs: CapturedLogs) -> dispatcher::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs)
            .with_ansi(false)
            .without_time()
            .finish();
        subscriber::set_default(subscriber)
    }

    fn exchanged_token_for_debug(secret: &str) -> ExchangedToken {
        ExchangedToken {
            access_token: secret.to_owned(),
            expires_in: Some(3600),
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_owned()),
        }
    }

    fn exchanged_jwt_with_sensitive_claims() -> ExchangedToken {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"sub":"subject-secret","aud":["aud-secret"],"azp":"azp-secret","iss":"issuer-secret"}"#,
        );
        exchanged_token_for_debug(&format!("{header}.{payload}.signature"))
    }

    /// Redacts the access token in Debug output by default while showing other fields.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::exchanged_token_debug_redacts_access_token_by_default keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn exchanged_token_debug_redacts_access_token_by_default() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure::default());
        let secret = "oauth-access-token-secret";

        let rendered = format!("{:?}", exchanged_token_for_debug(secret));

        assert!(rendered.contains("[REDACTED]"));
        assert!(
            !rendered.contains(secret),
            "Debug output must not contain plaintext access token: {rendered}"
        );
        assert!(rendered.contains("expires_in"));
        assert!(rendered.contains("issued_token_type"));

        Ok(())
    }

    /// Shows the plaintext access token in Debug output when opted in.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::exchanged_token_debug_can_show_access_token_when_enabled keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn exchanged_token_debug_can_show_access_token_when_enabled() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure {
            plaintext_oauth_tokens: true,
            ..DiagnosticExposure::default()
        });
        let secret = "oauth-access-token-secret";

        let rendered = format!("{:?}", exchanged_token_for_debug(secret));

        assert!(rendered.contains(secret));

        Ok(())
    }

    /// Redacts JWT claim values in the exchanged-token log by default.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::exchanged_token_claim_log_redacts_claim_values_by_default keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn exchanged_token_claim_log_redacts_claim_values_by_default() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure::default());
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _subscriber_guard = subscriber::set_default(subscriber);

        log_exchanged_token(&exchanged_jwt_with_sensitive_claims());

        let contents = logs.contents();
        assert!(contents.contains("[REDACTED]"));
        for secret in [
            "subject-secret",
            "aud-secret",
            "azp-secret",
            "issuer-secret",
        ] {
            assert!(
                !contents.contains(secret),
                "claim log must not contain {secret}: {contents}"
            );
        }
        assert!(contents.contains("expires_in"));

        Ok(())
    }

    /// Logs JWT claim values verbatim when `oauth_claim_values` is enabled.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/oauth.rs::exchanged_token_claim_log_can_show_claim_values_when_enabled keeps the uniform test signature while it only asserts"
    )]
    #[test]
    fn exchanged_token_claim_log_can_show_claim_values_when_enabled() -> anyhow::Result<()> {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure {
            oauth_claim_values: true,
            ..DiagnosticExposure::default()
        });
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _subscriber_guard = subscriber::set_default(subscriber);

        log_exchanged_token(&exchanged_jwt_with_sensitive_claims());

        let contents = logs.contents();
        for secret in [
            "subject-secret",
            "aud-secret",
            "azp-secret",
            "issuer-secret",
        ] {
            assert!(
                contents.contains(secret),
                "claim log must contain {secret} when enabled: {contents}"
            );
        }

        Ok(())
    }

    /// Drops an oversized JWKS response and logs a cap-exceeded warning.
    #[tokio::test]
    async fn jwks_response_size_cap_returns_none_and_logs_warning() -> anyhow::Result<()> {
        let kid = "oversized-jwks";
        let (_pem, jwks) = generate_test_keypair(kid)?;
        let mut oversized_body = serde_json::to_string(&jwks).context("jwks json")?;
        oversized_body.push_str(&" ".repeat(4096));

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(oversized_body),
            )
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.jwks_max_response_bytes = 256;
        let cache = test_cache(&config)?;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let result = cache.fetch_jwks().await;
        assert!(result.is_none(), "oversized JWKS must be dropped");
        assert!(
            logs.contents()
                .contains("JWKS response exceeded configured size cap"),
            "expected cap-exceeded warning in logs"
        );

        Ok(())
    }

    /// A redirect to a userinfo-bearing target is rejected, and the
    /// rejection warn log must not echo the embedded credentials
    /// (sanitized to scheme+host+port only).
    #[tokio::test]
    async fn redirect_rejection_log_does_not_echo_credentials() -> anyhow::Result<()> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "https://u:p@redirect-target.example/next"),
            )
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let result = cache.fetch_jwks().await;
        assert!(result.is_none(), "rejected redirect must fail the fetch");
        let contents = logs.contents();
        assert!(
            contents.contains("oauth redirect rejected"),
            "expected redirect-rejection warning in logs: {contents}"
        );
        assert!(
            !contents.contains("u:p"),
            "rejection log must not echo userinfo credentials: {contents}"
        );

        Ok(())
    }

    /// Logs only the sanitized JWKS origin on fetch failure, leaking no path or secret.
    #[tokio::test]
    async fn jwks_fetch_failure_log_sanitizes_url_and_reqwest_error() -> anyhow::Result<()> {
        let config = test_config("http://127.0.0.1:1/jwks.json?client_secret=super-secret");
        let cache = test_cache(&config)?;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

        let result = cache.fetch_jwks().await;
        assert!(
            result.is_none(),
            "closed loopback port must fail JWKS fetch"
        );
        let contents = logs.contents();
        assert!(
            contents.contains("failed to fetch JWKS"),
            "JWKS failure must still be logged: {contents}"
        );
        assert!(
            contents.contains("uri=http://127.0.0.1:1"),
            "JWKS failure log must include only sanitized origin: {contents}"
        );
        for leaked in ["/jwks.json", "client_secret", "super-secret"] {
            assert!(
                !contents.contains(leaked),
                "JWKS failure log must not echo raw URL component {leaked}: {contents}"
            );
        }

        Ok(())
    }

    /// Maps a nested Keycloak `realm_access.roles` claim to a role.
    #[tokio::test]
    async fn role_claim_keycloak_nested_array() -> anyhow::Result<()> {
        let kid = "test-role-1";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "realm_access.roles",
            vec![
                RoleMapping {
                    claim_value: "mcp-admin".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "mcp-viewer".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "keycloak-user",
                "exp": now.saturating_add(3600),
                "iat": now,
                "realm_access": { "roles": ["uma_authorization", "mcp-admin"] }
            }),
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("should authenticate")?;
        assert_eq!(id.name, "keycloak-user");
        assert_eq!(id.role, "ops");

        Ok(())
    }

    /// Maps a flat roles array claim value to a role.
    #[tokio::test]
    async fn role_claim_flat_roles_array() -> anyhow::Result<()> {
        let kid = "test-role-2";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "roles",
            vec![
                RoleMapping {
                    claim_value: "MCP.Admin".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "MCP.Reader".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "azure-ad-user",
                "exp": now.saturating_add(3600),
                "iat": now,
                "roles": ["MCP.Reader", "OtherApp.Admin"]
            }),
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("should authenticate")?;
        assert_eq!(id.name, "azure-ad-user");
        assert_eq!(id.role, "viewer");

        Ok(())
    }

    /// Rejects a token whose role claim value matches no mapping.
    #[tokio::test]
    async fn role_claim_no_matching_value_rejected() -> anyhow::Result<()> {
        let kid = "test-role-3";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "roles",
            vec![RoleMapping {
                claim_value: "mcp-admin".into(),
                role: "ops".into(),
            }],
        );
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "limited-user",
                "exp": now.saturating_add(3600),
                "iat": now,
                "roles": ["some-other-role"]
            }),
        )?;

        assert!(cache.validate_token(&token).await.is_none());

        Ok(())
    }

    /// Maps a whitespace-separated string role claim value to a role.
    #[tokio::test]
    async fn role_claim_space_separated_string() -> anyhow::Result<()> {
        let kid = "test-role-4";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "custom_scope",
            vec![
                RoleMapping {
                    claim_value: "write".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "read".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = test_cache(&config)?;

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "custom-client",
                "exp": now.saturating_add(3600),
                "iat": now,
                "custom_scope": "read audit"
            }),
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("should authenticate")?;
        assert_eq!(id.name, "custom-client");
        assert_eq!(id.role, "viewer");

        Ok(())
    }

    /// Keeps the scope-based mapping working when `role_claim` is None.
    #[tokio::test]
    async fn scope_backward_compat_without_role_claim() -> anyhow::Result<()> {
        // Verify existing `scopes` behavior still works when role_claim is None.
        let kid = "test-compat-1";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // role_claim: None, uses scopes
        let cache = test_cache(&config)?;

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "legacy-bot",
            "mcp:admin other:scope",
        )?;

        let id = cache
            .validate_token(&token)
            .await
            .context("should authenticate")?;
        assert_eq!(id.name, "legacy-bot");
        assert_eq!(id.role, "ops"); // mcp:admin -> ops via scopes

        Ok(())
    }

    // -----------------------------------------------------------------------
    // JWKS refresh cooldown tests
    // -----------------------------------------------------------------------

    /// Deduplicates concurrent cache misses into exactly one JWKS fetch.
    #[tokio::test]
    async fn jwks_refresh_deduplication() -> anyhow::Result<()> {
        // Verify that concurrent requests with unknown kids result in exactly
        // one JWKS fetch, not one per request (deduplication via mutex).
        let kid = "test-dedup";
        let (pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = Arc::new(test_cache(&config)?);

        // Create 5 concurrent validation requests with the same valid token.
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "concurrent-bot",
            "mcp:read",
        )?;

        let mut handles = Vec::new();
        for _ in 0_i32..5_i32 {
            let cache_ref = Arc::clone(&cache);
            let token_ref = token.clone();
            handles.push(tokio::spawn(async move {
                cache_ref.validate_token(&token_ref).await
            }));
        }

        for handle in handles {
            let result = handle.await?;
            assert!(result.is_some(), "all concurrent requests should succeed");
        }

        // The expect(1) assertion on the mock verifies only one fetch occurred.

        Ok(())
    }

    /// Limits rapid unknown-kid misses to one JWKS fetch within the cooldown.
    #[tokio::test]
    async fn jwks_refresh_cooldown_blocks_rapid_requests() -> anyhow::Result<()> {
        // Verify that rapid sequential requests with unknown kids (cache misses)
        // only trigger one JWKS fetch due to cooldown.
        let kid = "test-cooldown";
        let (_pem, jwks) = generate_test_keypair(kid)?;

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once despite multiple misses
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config)?;

        // First request with unknown kid triggers a refresh.
        let fake_token1 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTEifQ.e30.sig";
        let _unused = cache.validate_token(fake_token1).await;

        // Second request with a different unknown kid should NOT trigger refresh
        // because we're within the 10-second cooldown.
        let fake_token2 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTIifQ.e30.sig";
        let _second_call = cache.validate_token(fake_token2).await;

        // Third request with yet another unknown kid - still within cooldown.
        let fake_token3 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTMifQ.e30.sig";
        let _third_call = cache.validate_token(fake_token3).await;

        // The expect(1) assertion verifies only one fetch occurred.

        Ok(())
    }

    // -- introspection / revocation proxy --

    fn proxy_cfg(token_url: &str) -> OAuthProxyConfig {
        OAuthProxyConfig {
            authorize_url: "https://example.invalid/auth".into(),
            token_url: token_url.into(),
            client_id: "mcp-client".into(),
            client_secret: Some(secrecy::SecretString::from("shh".to_owned())),
            introspection_url: None,
            revocation_url: None,
            expose_admin_endpoints: false,
            require_auth_on_admin_endpoints: false,
            allow_unauthenticated_admin_endpoints: false,
            strip_resource_param: false,
        }
    }

    /// Build an HTTP client for tests. Ensures a rustls crypto provider
    /// is installed (normally done inside `JwksCache::new`).
    fn test_http_client() -> anyhow::Result<OauthHttpClient> {
        drop(default_provider().install_default());
        let config = OAuthConfig::builder(
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "https://auth.test.local/.well-known/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        Ok(OauthHttpClient::with_config(&config)
            .context("build test http client")?
            .__test_allow_loopback_ssrf())
    }

    /// Proxies introspection upstream, injecting the proxy client credentials.
    #[tokio::test]
    async fn introspect_proxies_and_injects_client_credentials() -> anyhow::Result<()> {
        use wiremock::matchers::{body_string_contains, method, path};

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(body_string_contains("client_id=mcp-client"))
            .and(body_string_contains("client_secret=shh"))
            .and(body_string_contains("token=abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "active": true,
                    "scope": "read"
                })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        proxy.introspection_url = Some(format!("{}/introspect", mock_server.uri()));

        let http = test_http_client()?;
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);

        Ok(())
    }

    /// Fails closed with 502 and does not forward an oversized upstream token response.
    #[tokio::test]
    async fn token_proxy_fails_closed_on_oversized_upstream_response() -> anyhow::Result<()> {
        use http_body_util::BodyExt as _;
        use wiremock::matchers::{method, path};

        // Upstream returns a body far larger than OAUTH_PROXY_MAX_RESPONSE_BYTES.
        let oversized = "x"
            .repeat(usize::try_from(OAUTH_PROXY_MAX_RESPONSE_BYTES).unwrap_or(usize::MAX) + 4096);
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(oversized.clone()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        let http = test_http_client()?;
        let resp = handle_token(&http, &proxy, "grant_type=authorization_code&code=abc").await;

        // Must fail closed with 502, and MUST NOT forward the oversized body.
        assert_eq!(
            resp.status(),
            502,
            "oversized upstream response must fail closed as 502"
        );
        let body = resp
            .into_body()
            .collect()
            .await
            .context("collect body")?
            .to_bytes();
        assert!(
            body.len() < 1024,
            "must return the small generic error body, not the oversized upstream body (got {} bytes)",
            body.len()
        );
        assert!(
            !body.windows(8).any(|w| w == b"xxxxxxxx"),
            "the oversized upstream payload must not be forwarded to the client"
        );

        Ok(())
    }

    /// Passes a normal-sized upstream token response through with status and body intact.
    #[tokio::test]
    async fn token_proxy_passes_through_normal_response() -> anyhow::Result<()> {
        use http_body_util::BodyExt as _;
        use wiremock::matchers::{method, path};

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "at-123",
                    "token_type": "Bearer"
                })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        let http = test_http_client()?;
        let resp = handle_token(&http, &proxy, "grant_type=authorization_code&code=abc").await;

        assert_eq!(
            resp.status(),
            200,
            "a normal-sized response must pass through"
        );
        let body = resp
            .into_body()
            .collect()
            .await
            .context("collect body")?
            .to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&body).context("upstream JSON preserved")?;
        assert_eq!(json_str(&json, "access_token")?, "at-123");

        Ok(())
    }

    /// Returns 404 for introspection when no `introspection_url` is configured.
    #[tokio::test]
    async fn introspect_returns_404_when_not_configured() -> anyhow::Result<()> {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client()?;
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);

        Ok(())
    }

    /// Proxies revocation upstream and returns the upstream status.
    #[tokio::test]
    async fn revoke_proxies_and_returns_upstream_status() -> anyhow::Result<()> {
        use wiremock::matchers::{method, path};

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        proxy.revocation_url = Some(format!("{}/revoke", mock_server.uri()));

        let http = test_http_client()?;
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);

        Ok(())
    }

    /// Returns 404 for revocation when no `revocation_url` is configured.
    #[tokio::test]
    async fn revoke_returns_404_when_not_configured() -> anyhow::Result<()> {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client()?;
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);

        Ok(())
    }

    /// Advertises introspection/revocation endpoints only when configured and exposed.
    #[test]
    fn metadata_advertises_endpoints_only_when_configured() -> anyhow::Result<()> {
        let mut cfg = test_config("https://auth.test.local/jwks.json");
        // Without proxy configured, no introspection/revocation advertised.
        let no_proxy_meta = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(no_proxy_meta.get("introspection_endpoint").is_none());
        assert!(no_proxy_meta.get("revocation_endpoint").is_none());

        // With proxy + introspection_url but expose_admin_endpoints = false
        // (the secure default): endpoints MUST NOT be advertised.
        let mut proxy = proxy_cfg("https://upstream.local/token");
        proxy.introspection_url = Some("https://upstream.local/introspect".into());
        proxy.revocation_url = Some("https://upstream.local/revoke".into());
        cfg.proxy = Some(proxy);
        let hidden_meta = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(
            hidden_meta.get("introspection_endpoint").is_none(),
            "introspection must not be advertised when expose_admin_endpoints=false"
        );
        assert!(
            hidden_meta.get("revocation_endpoint").is_none(),
            "revocation must not be advertised when expose_admin_endpoints=false"
        );

        // Opt in: expose_admin_endpoints = true + introspection_url only.
        if let Some(exposed_proxy) = cfg.proxy.as_mut() {
            exposed_proxy.expose_admin_endpoints = true;
            exposed_proxy.revocation_url = None;
        }
        let opt_in_meta = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            json_get(&opt_in_meta, "introspection_endpoint")?.clone(),
            serde_json::Value::String("https://mcp.local/introspect".into())
        );
        assert!(opt_in_meta.get("revocation_endpoint").is_none());

        // Add revocation_url.
        if let Some(proxy_revocation) = cfg.proxy.as_mut() {
            proxy_revocation.revocation_url = Some("https://upstream.local/revoke".into());
        }
        let revocation_meta = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            json_get(&revocation_meta, "revocation_endpoint")?.clone(),
            serde_json::Value::String("https://mcp.local/revoke".into())
        );

        Ok(())
    }

    // ---------- M-H4: token-exchange client authentication ----------

    fn https_cfg_with_tx(tx: TokenExchangeConfig) -> OAuthConfig {
        let mut cfg = validation_https_config();
        cfg.token_exchange = Some(tx);
        cfg
    }

    fn tx_with(
        client_secret: Option<&str>,
        client_cert: Option<ClientCertConfig>,
    ) -> TokenExchangeConfig {
        TokenExchangeConfig::new(
            "https://idp.example.com/token",
            "client",
            client_secret.map(|secret| secrecy::SecretString::new(secret.into())),
            client_cert,
        )
        .with_audience("downstream")
    }

    /// Rejects a custom `requested_token_type` that is not a URI.
    #[test]
    fn validate_rejects_non_uri_custom_requested_token_type() -> anyhow::Result<()> {
        for bad in ["acess_token", "not a uri", "urn:bad%zz:token"] {
            let tx = tx_with(Some("s"), None)
                .with_requested_token_type(RequestedTokenType::Custom(bad.to_owned()));
            let Err(err) = https_cfg_with_tx(tx).validate() else {
                anyhow::bail!("a custom token type that is not a URI must be rejected");
            };
            let err_text = err.to_string();
            assert!(
                err_text.contains("requested_token_type"),
                "error must name the offending field for {bad:?}; got {err_text:?}"
            );
        }

        Ok(())
    }

    /// Accepts URI custom `requested_token_type` values, including fragments.
    #[test]
    fn validate_accepts_uri_custom_requested_token_type_including_fragments() -> anyhow::Result<()>
    {
        for good in [
            "urn:ietf:params:oauth:token-type:saml2",
            "https://vendor.example/token-type",
            "urn:example:token#v2",
        ] {
            let tx = tx_with(Some("s"), None)
                .with_requested_token_type(RequestedTokenType::Custom(good.to_owned()));
            if let Err(error) = https_cfg_with_tx(tx).validate() {
                anyhow::bail!(
                    "RFC 8693 §3 only requires a URI; {good:?} must be accepted \
                     (the no-fragment rule is RFC 8707's, for `resource` only): {error}"
                );
            }
        }

        Ok(())
    }

    /// Rejects empty audience, resource, scope, or custom `requested_token_type` values.
    #[test]
    fn validate_rejects_empty_optional_token_exchange_params() -> anyhow::Result<()> {
        let base = || tx_with(Some("s"), None);
        let cases = [
            (base().with_audience(""), "audience"),
            (base().with_resource(""), "resource"),
            (base().with_scope(""), "scope"),
            (
                base().with_requested_token_type(RequestedTokenType::Custom(String::new())),
                "requested_token_type",
            ),
        ];
        for (tx, field) in cases {
            let cfg = https_cfg_with_tx(tx);
            let Err(err) = cfg.validate() else {
                anyhow::bail!("an empty optional parameter must be rejected");
            };
            let msg = err.to_string();
            assert!(
                msg.contains(field) && msg.contains("must not be empty"),
                "error must name {field} and explain emptiness; got {msg:?}"
            );
        }

        Ok(())
    }

    /// Rejects resource values violating RFC 8707 URI rules.
    #[test]
    fn validate_rejects_non_conformant_resource_uri() -> anyhow::Result<()> {
        for (value, expected) in [
            ("not-an-absolute-uri", "absolute URI"),
            ("https://api.example.com/v1#frag", "fragment"),
            ("https://api.example.com/a b", "valid URI characters"),
            ("https://api.example.com/%zz", "valid URI characters"),
            ("https://api.example.com/\u{e9}", "valid URI characters"),
        ] {
            let cfg = https_cfg_with_tx(tx_with(Some("s"), None).with_resource(value));
            let Err(err) = cfg.validate() else {
                anyhow::bail!("resource must satisfy RFC 8707 \u{a7}2");
            };
            let msg = err.to_string();
            assert!(
                msg.contains(expected),
                "error for {value:?} must mention {expected:?}; got {msg:?}"
            );
        }

        Ok(())
    }

    /// Accepts token exchange with every optional RFC 8693 parameter omitted.
    #[test]
    fn validate_accepts_token_exchange_with_all_optional_params_omitted() -> anyhow::Result<()> {
        let mut tx = tx_with(Some("s"), None);
        tx.audience = None;
        tx.requested_token_type = RequestedTokenType::Omit;
        https_cfg_with_tx(tx)
            .validate()
            .context("omitting every RFC 8693 \u{a7}2.1 OPTIONAL parameter must be valid")?;

        Ok(())
    }

    /// Rejects token exchange configured with neither client secret nor cert.
    #[test]
    fn validate_rejects_token_exchange_without_client_auth() -> anyhow::Result<()> {
        let cfg = https_cfg_with_tx(tx_with(None, None));
        let Err(err) = cfg.validate() else {
            anyhow::bail!("token_exchange without client auth must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("requires client authentication"),
            "error must explain missing client auth; got {msg:?}"
        );

        Ok(())
    }

    /// Rejects token exchange configured with both client secret and client cert.
    #[test]
    fn validate_rejects_token_exchange_with_both_secret_and_cert() -> anyhow::Result<()> {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(Some("s"), Some(cc)));
        let Err(err) = cfg.validate() else {
            anyhow::bail!("client_secret + client_cert must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("mutually") && msg.contains("exclusive"),
            "error must explain mutual exclusion; got {msg:?}"
        );

        Ok(())
    }

    /// Rejects a client cert config when the oauth-mtls-client feature is disabled.
    #[cfg(not(feature = "oauth-mtls-client"))]
    #[test]
    fn validate_rejects_client_cert_without_feature() -> anyhow::Result<()> {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let Err(err) = cfg.validate() else {
            anyhow::bail!("client_cert without feature must be rejected");
        };
        assert!(
            err.to_string().contains("oauth-mtls-client"),
            "error must reference the cargo feature; got {err}"
        );

        Ok(())
    }

    /// Rejects a client cert config whose files are unreadable.
    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_rejects_missing_client_cert_files() -> anyhow::Result<()> {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let Err(err) = cfg.validate() else {
            anyhow::bail!("missing cert file must be rejected");
        };
        assert!(
            err.to_string().contains("unreadable"),
            "error must call out unreadable file; got {err}"
        );

        Ok(())
    }

    /// Rejects a client cert whose PEM fails to parse.
    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_rejects_malformed_client_cert_pem() -> anyhow::Result<()> {
        let dir = env::temp_dir();
        let cert = dir.join(format!("rmcp-mtls-bad-cert-{}.pem", process::id()));
        let key = dir.join(format!("rmcp-mtls-bad-key-{}.pem", process::id()));
        fs::write(&cert, b"not a real PEM").context("write tmp cert")?;
        fs::write(&key, b"not a real PEM either").context("write tmp key")?;
        let cc = ClientCertConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let Err(err) = cfg.validate() else {
            anyhow::bail!("malformed PEM must be rejected");
        };
        let _removed_cert = fs::remove_file(&cert);
        let _removed_key = fs::remove_file(&key);
        assert!(
            err.to_string().contains("PEM parse failed"),
            "error must call out PEM parse failure; got {err}"
        );

        Ok(())
    }

    #[cfg(feature = "oauth-mtls-client")]
    fn write_self_signed_pem() -> anyhow::Result<(PathBuf, PathBuf)> {
        let cert =
            rcgen::generate_simple_self_signed(vec!["client.test".into()]).context("rcgen")?;
        let dir = env::temp_dir();
        let pid = process::id();
        let nonce: u64 = rand::random();
        let cert_path = dir.join(format!("rmcp-mtls-cert-{pid}-{nonce}.pem"));
        let key_path = dir.join(format!("rmcp-mtls-key-{pid}-{nonce}.pem"));
        fs::write(&cert_path, cert.cert.pem()).context("write cert")?;
        fs::write(&key_path, cert.signing_key.serialize_pem()).context("write key")?;
        Ok((cert_path, key_path))
    }

    #[cfg(feature = "oauth-mtls-client")]
    fn install_test_crypto_provider() {
        let _unused = default_provider().install_default();
    }

    /// Accepts a well-formed self-signed client cert and key.
    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_accepts_well_formed_client_cert() -> anyhow::Result<()> {
        install_test_crypto_provider();
        let (cert_path, key_path) = write_self_signed_pem()?;
        let cc = ClientCertConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let res = cfg.validate();
        let _removed_cert_path = fs::remove_file(&cert_path);
        let _removed_key_path = fs::remove_file(&key_path);
        res.context("well-formed cert+key must validate")?;

        Ok(())
    }

    /// Returns a distinct mTLS client for cert configs versus no-cert configs.
    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn client_for_returns_cached_mtls_client() -> anyhow::Result<()> {
        install_test_crypto_provider();
        let (cert_path, key_path) = write_self_signed_pem()?;
        let cc = ClientCertConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let http = OauthHttpClient::with_config(&cfg).context("build mtls client")?;
        let tx_ref = cfg.token_exchange.as_ref().context("tx set")?;
        let cert_client = http.client_for(tx_ref);
        let inner_client = http.client_for(&tx_with(Some("s"), None));
        let _removed_cert_path = fs::remove_file(&cert_path);
        let _removed_key_path = fs::remove_file(&key_path);
        assert!(
            !ptr::eq(cert_client, inner_client),
            "client_for must return distinct clients for cert vs no-cert configs"
        );

        Ok(())
    }

    /// Falls back to the inner client when no cached mTLS client matches.
    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn client_for_falls_back_to_inner_when_cache_miss() -> anyhow::Result<()> {
        install_test_crypto_provider();
        let cfg = validation_https_config();
        let http = OauthHttpClient::with_config(&cfg).context("build client")?;
        let unrelated_cc = ClientCertConfig {
            cert_path: PathBuf::from("/cache/miss/cert.pem"),
            key_path: PathBuf::from("/cache/miss/key.pem"),
        };
        let tx_unknown = tx_with(None, Some(unrelated_cc));
        let fallback = http.client_for(&tx_unknown);
        let inner = http.client_for(&tx_with(Some("s"), None));
        assert!(
            ptr::eq(fallback, inner),
            "cache miss must fall back to inner client"
        );

        Ok(())
    }
}
