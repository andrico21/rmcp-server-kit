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

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::{net::lookup_host, sync::RwLock};
use tracing::Instrument;

use crate::auth::{AuthIdentity, AuthMethod};

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
fn evaluate_oauth_redirect(
    attempt: &reqwest::redirect::Attempt<'_>,
    allow_http: bool,
    allowlist: &crate::ssrf::CompiledSsrfAllowlist,
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
    if let Some(reason) = crate::ssrf::redirect_target_reason_with_allowlist(target_url, allowlist)
    {
        return Err(format!("redirect target forbidden: {reason}"));
    }
    if attempt.previous().len() >= 2 {
        return Err("too many redirects (max 2)".to_owned());
    }
    Ok(())
}

/// True when `host` ends in a well-known internal suffix (`.localhost`,
/// `.local`, `.internal`) and is not exactly allow-listed. A trailing
/// FQDN-root dot is canonicalized first so `idp.internal.` cannot bypass
/// the check. OAuth targets only -- CRL fetches build an empty allowlist
/// and are out of scope.
///
/// Exact `localhost` is deliberately NOT matched here: it resolves to
/// loopback and is already blocked by the post-DNS IP screen, and an
/// operator may legitimately reach a local IdP via an explicit loopback
/// CIDR allowlist.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "these are DNS-name suffixes on an already-lowercased host, not file extensions"
)]
fn oauth_internal_suffix_blocked(
    host: &str,
    allowlist: &crate::ssrf::CompiledSsrfAllowlist,
) -> bool {
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
async fn screen_oauth_target_core(
    url: &str,
    allow_http: bool,
    allowlist: &crate::ssrf::CompiledSsrfAllowlist,
    test_allow_loopback_ssrf: bool,
) -> Result<(), crate::error::RmcpServerKitError> {
    let target = oauth_request_target_for_log(url);
    let parsed = check_oauth_url("oauth target", url, allow_http)?;
    if test_allow_loopback_ssrf {
        return Ok(());
    }
    if let Some(reason) = crate::ssrf::check_url_literal_ip(&parsed) {
        return Err(crate::error::RmcpServerKitError::Config(format!(
            "OAuth target forbidden ({reason}): {target}"
        )));
    }

    let host = parsed.host_str().ok_or_else(|| {
        crate::error::RmcpServerKitError::Config(format!("OAuth target URL has no host: {target}"))
    })?;
    if oauth_internal_suffix_blocked(host, allowlist) {
        return Err(crate::error::RmcpServerKitError::Config(format!(
            "OAuth target forbidden (internal hostname suffix): {target}"
        )));
    }
    let port = parsed.port_or_known_default().ok_or_else(|| {
        crate::error::RmcpServerKitError::Config(format!(
            "OAuth target URL has no known port: {target}"
        ))
    })?;

    let addrs = lookup_host((host, port)).await.map_err(|error| {
        crate::error::RmcpServerKitError::Config(format!(
            "OAuth target DNS resolution {target}: {error}"
        ))
    })?;

    let host_allowed = !allowlist.is_empty() && allowlist.host_allowed(host);
    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        let ip = addr.ip();
        if let Some(reason) = crate::ssrf::ip_block_reason(ip) {
            // Cloud-metadata is unbypassable. Use the strict message
            // that does NOT advertise the allowlist knob.
            if reason == "cloud_metadata" {
                return Err(crate::error::RmcpServerKitError::Config(format!(
                    "OAuth target resolved to blocked IP ({reason}): {target}"
                )));
            }
            // Default-empty-allowlist path: preserve the historical
            // message verbatim so existing tests continue to pass and
            // operators get the same diagnostic they had before.
            if allowlist.is_empty() {
                return Err(crate::error::RmcpServerKitError::Config(format!(
                    "OAuth target resolved to blocked IP ({reason}): {target}"
                )));
            }
            // Allowlist-configured path: consult host + per-IP allowlist.
            if host_allowed || allowlist.ip_allowed(ip) {
                continue;
            }
            return Err(crate::error::RmcpServerKitError::Config(format!(
                "OAuth target blocked: hostname {host} resolved to {ip} ({reason}). \
                 To allow, add the hostname to oauth.ssrf_allowlist.hosts or the CIDR \
                 to oauth.ssrf_allowlist.cidrs (operators only -- see SECURITY.md). \
                 URL: {target}"
            )));
        }
    }
    if !any_addr {
        return Err(crate::error::RmcpServerKitError::Config(format!(
            "OAuth target DNS resolution returned no addresses: {target}"
        )));
    }

    Ok(())
}

/// Production entry point for OAuth/JWKS target screening. Delegates to
/// [`screen_oauth_target_core`] with the loopback bypass hardcoded off.
async fn screen_oauth_target(
    url: &str,
    allow_http: bool,
    allowlist: &crate::ssrf::CompiledSsrfAllowlist,
) -> Result<(), crate::error::RmcpServerKitError> {
    screen_oauth_target_core(url, allow_http, allowlist, false).await
}

/// Test-only wrapper exposing the loopback-SSRF bypass flag of
/// [`screen_oauth_target_core`] so higher-level OAuth flows can run
/// against loopback-backed mock fixtures.
#[cfg(any(test, feature = "test-helpers"))]
async fn screen_oauth_target_with_test_override(
    url: &str,
    allow_http: bool,
    allowlist: &crate::ssrf::CompiledSsrfAllowlist,
    test_allow_loopback_ssrf: bool,
) -> Result<(), crate::error::RmcpServerKitError> {
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
    allow_http: bool,
    /// Compiled SSRF allowlist applied to the initial-target screen and
    /// to literal-IP redirect-hop screening. Wrapped in `Arc` so cloning
    /// the client (which is cheap and refcounted) does not deep-copy
    /// the parsed CIDR / host vectors.
    allowlist: Arc<crate::ssrf::CompiledSsrfAllowlist>,
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
    test_allow_loopback_ssrf: crate::ssrf_resolver::TestLoopbackBypass,
}

/// M-H4: cache key for cert-bearing `reqwest::Client`s. Path-based
/// (not contents-based) -- in-place cert rotation is not picked up
/// without restart (documented limitation in `CHANGELOG.md` 1.6.0).
#[cfg(feature = "oauth-mtls-client")]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct MtlsClientKey {
    cert_path: PathBuf,
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
    pub fn with_config(config: &OAuthConfig) -> Result<Self, crate::error::RmcpServerKitError> {
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
    pub fn new() -> Result<Self, crate::error::RmcpServerKitError> {
        Self::build(None)
    }

    /// Internal builder shared by [`new`](Self::new) (config = `None`)
    /// and [`with_config`](Self::with_config) (config = `Some`).
    fn build(config: Option<&OAuthConfig>) -> Result<Self, crate::error::RmcpServerKitError> {
        // Install the rustls crypto provider before constructing any reqwest
        // client (idempotent -- `ok()` ignores the error when a provider was
        // already installed elsewhere in the process). Without this a
        // standalone `OauthHttpClient::new`/`with_config` built before
        // `JwksCache::new` or TLS setup would panic inside reqwest with
        // "no rustls crypto provider is configured".
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let allow_http = config.is_some_and(|c| c.allow_http_oauth_urls);

        // Compile the operator SSRF allowlist (if any) up front. Surface
        // CIDR / host parse errors as Startup so misconfiguration fails
        // fast at server boot, mirroring how OAuthConfig::validate
        // surfaces them as Config errors.
        let allowlist = match config.and_then(|c| c.ssrf_allowlist.as_ref()) {
            Some(raw) => Arc::new(compile_oauth_ssrf_allowlist(raw).map_err(|e| {
                crate::error::RmcpServerKitError::Startup(format!("oauth http client: {e}"))
            })?),
            None => Arc::new(crate::ssrf::CompiledSsrfAllowlist::default()),
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
        let test_bypass: crate::ssrf_resolver::TestLoopbackBypass =
            Arc::new(AtomicBool::new(false));
        #[cfg(not(any(test, feature = "test-helpers")))]
        let test_bypass: crate::ssrf_resolver::TestLoopbackBypass = ();

        // M-H2/B1: TestLoopbackBypass aliases to Arc<AtomicBool> in test
        // builds and to `()` in production. The `.clone()` is required in
        // test builds; in production the alias is a unit, which is why the
        // unit-value lints are allowed alongside the Arc one.
        #[allow(
            clippy::clone_on_ref_ptr,
            clippy::clone_on_copy,
            clippy::unit_arg,
            reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
        )]
        let resolver: Arc<dyn reqwest::dns::Resolve> =
            Arc::new(crate::ssrf_resolver::SsrfScreeningResolver::new(
                Arc::clone(&allowlist),
                test_bypass.clone(),
            ));

        // Read the optional CA bundle once; reused by both clients below.
        // Pre-startup blocking I/O is intentional -- the constructor is sync
        // by contract and runs from `serve()`'s pre-startup phase.
        let ca_pem: Option<Vec<u8>> = if let Some(cfg) = config
            && let Some(ref ca_path) = cfg.ca_cert_path
        {
            Some(std::fs::read(ca_path).map_err(|e| {
                crate::error::RmcpServerKitError::Startup(format!(
                    "oauth http client: read ca_cert_path {}: {e}",
                    ca_path.display()
                ))
            })?)
        } else {
            None
        };

        // Base builder shared by both clients: `no_proxy` (so HTTP(S)_PROXY
        // env vars cannot bypass the SsrfScreeningResolver), the SSRF
        // resolver, timeouts, and CA trust. Only the redirect policy differs.
        let make_base = || -> Result<reqwest::ClientBuilder, crate::error::RmcpServerKitError> {
            let mut b = reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::clone(&resolver))
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30));
            if let Some(ref pem) = ca_pem {
                let cert = reqwest::tls::Certificate::from_pem(pem).map_err(|e| {
                    crate::error::RmcpServerKitError::Startup(format!(
                        "oauth http client: parse ca_cert_path: {e}"
                    ))
                })?;
                b = b.add_root_certificate(cert);
            }
            Ok(b)
        };

        // JWKS / discovery client: follows redirects, but every hop is screened
        // by `evaluate_oauth_redirect` (https->http downgrade, literal-IP
        // target, and userinfo are all rejected). Production reads JWKS via
        // `JwksCache` and credentials via `credential_client`, so this client
        // backs only the redirect-policy regression tests and is not built in
        // a minimal `oauth` build.
        #[cfg(any(test, feature = "test-helpers"))]
        let inner =
            make_base()?
                .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                    match evaluate_oauth_redirect(&attempt, allow_http, &redirect_allowlist) {
                        Ok(()) => attempt.follow(),
                        Err(reason) => {
                            tracing::warn!(
                                reason = %reason,
                                target = %crate::ssrf::sanitized_url_for_log(attempt.url()),
                                "oauth redirect rejected"
                            );
                            attempt.error(reason)
                        }
                    }
                }))
                .build()
                .map_err(|e| {
                    crate::error::RmcpServerKitError::Startup(format!(
                        "oauth http client init: {e}"
                    ))
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
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                crate::error::RmcpServerKitError::Startup(format!("oauth http client init: {e}"))
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

    // cancel-safe: SSRF screening only reads allowlist/config; `reqwest` owns
    // the request during `send`, so cancellation abandons upstream I/O without
    // mutating OAuth client or JWKS cache state.
    async fn send_screened(
        &self,
        url: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, crate::error::RmcpServerKitError> {
        #[cfg(any(test, feature = "test-helpers"))]
        if self.test_allow_loopback_ssrf.load(Ordering::Relaxed) {
            screen_oauth_target_with_test_override(url, self.allow_http, &self.allowlist, true)
                .await?;
        } else {
            screen_oauth_target(url, self.allow_http, &self.allowlist).await?;
        }
        #[cfg(not(any(test, feature = "test-helpers")))]
        screen_oauth_target(url, self.allow_http, &self.allowlist).await?;
        request.send().await.map_err(|error| {
            let target = oauth_request_target_for_log(url);
            let error = error.without_url();
            crate::error::RmcpServerKitError::Config(format!("oauth request {target}: {error}"))
        })
    }

    /// Test-only: disable initial-target SSRF screening for loopback-backed
    /// fixtures. This is unreachable from normal production builds and exists
    /// only so tests can exercise higher-level OAuth flows against local mock
    /// servers.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
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
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        self.inner.get(url).send().await
    }

    /// Test-only: borrow the inner `reqwest::Client` so the M-H2
    /// env-proxy matrix test (`tests/e2e.rs::ssrf_no_proxy_*`) can
    /// drive `.get(...).send()` directly and observe whether the
    /// SsrfScreeningResolver fired (vs. the proxy short-circuiting
    /// the request). Not part of the public API.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
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

    #[cfg(not(feature = "oauth-mtls-client"))]
    fn client_for(&self, _cfg: &TokenExchangeConfig) -> &reqwest::Client {
        &self.credential_client
    }
}

impl std::fmt::Debug for OauthHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthHttpClient").finish_non_exhaustive()
    }
}

fn oauth_request_target_for_log(raw: &str) -> String {
    url::Url::parse(raw).map_or_else(
        |_| "<unparseable-url>".to_owned(),
        |url| crate::ssrf::sanitized_url_for_log(&url),
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
fn compile_oauth_ssrf_allowlist(
    raw: &OAuthSsrfAllowlist,
) -> Result<crate::ssrf::CompiledSsrfAllowlist, String> {
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
            Err(e) => {
                return Err(format!(
                    "oauth.ssrf_allowlist.hosts[{idx}] = {trimmed:?}: invalid hostname: {e}"
                ));
            }
        }
        hosts.push(trimmed.to_ascii_lowercase());
    }
    hosts.sort();
    hosts.dedup();

    let mut cidrs = Vec::with_capacity(raw.cidrs.len());
    for (idx, entry) in raw.cidrs.iter().enumerate() {
        let parsed = crate::ssrf::CidrEntry::parse(entry)
            .map_err(|e| format!("oauth.ssrf_allowlist.cidrs[{idx}]: {e}"))?;
        cidrs.push(parsed);
    }

    Ok(crate::ssrf::CompiledSsrfAllowlist::new(hosts, cidrs))
}

/// OAuth 2.1 JWT configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OAuthConfig {
    /// Token issuer (`iss` claim). Must match exactly.
    ///
    /// `#[serde(default)]` so a partially-specified `[oauth]` table — one that
    /// carries only `role_claim`/`role_mappings`, with the URL and audience
    /// fields supplied by a downstream env-override layer applied after TOML
    /// parsing — still deserializes. An empty value is rejected at
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
    /// `127.0.0.1`. JWKS-cache redirects to non-HTTPS targets are still
    /// rejected even when this flag is `true`.
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
    /// (the default) resolves to [`AudienceValidationMode::Strict`] — the
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

fn default_jwks_cache_ttl() -> String {
    "10m".into()
}

const fn default_max_jwks_keys() -> usize {
    256
}

const fn default_jwks_max_bytes() -> u64 {
    1024 * 1024
}

/// How the resource server treats `azp` when validating JWT audience.
///
/// **Background.** RFC 9068 §4 + OIDC Core §2 establish `aud` as the
/// authoritative resource-server claim and `azp` as the authorized-party
/// (client) claim. Some OAuth deployments — typically when the MCP server
/// acts as both OAuth client *and* resource server (the documented
/// [`OAuthProxyConfig`] topology) — issue tokens where the configured
/// audience appears only in `azp`. This enum lets operators decide
/// whether that historic compatibility fallback is honored, surfaced via
/// a one-shot warning, or refused.
///
/// **Default**: [`AudienceValidationMode::Strict`] — rejects `azp`-only
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
    /// mismatch. **Default** — recommended for new deployments and any
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
            require_subject: false,
            #[allow(
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
    pub fn effective_audience_validation_mode(&self) -> AudienceValidationMode {
        if let Some(mode) = self.audience_validation_mode {
            return mode;
        }
        #[allow(deprecated, reason = "intentional: legacy flag resolution path")]
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
    pub fn validate(&self) -> Result<(), crate::error::RmcpServerKitError> {
        validate_oauth_capacity_knobs(self)?;

        let allow_http = self.allow_http_oauth_urls;
        let url = check_oauth_url("oauth.issuer", &self.issuer, allow_http)?;
        if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
            return Err(crate::error::RmcpServerKitError::Config(format!(
                "oauth.issuer forbidden ({reason})"
            )));
        }
        let url = check_oauth_url("oauth.jwks_uri", &self.jwks_uri, allow_http)?;
        if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
            return Err(crate::error::RmcpServerKitError::Config(format!(
                "oauth.jwks_uri forbidden ({reason})"
            )));
        }
        // `audience` is not a URL, so the `check_oauth_url` calls above do not
        // cover it. Guard it explicitly: with `#[serde(default)]` an omitted
        // audience is an empty string that would otherwise pass validation and
        // then fail-closed silently at runtime (Strict mode matches nothing).
        if self.audience.is_empty() {
            return Err(crate::error::RmcpServerKitError::Config(
                "oauth.audience must not be empty".into(),
            ));
        }
        if let Some(proxy) = &self.proxy {
            let url = check_oauth_url(
                "oauth.proxy.authorize_url",
                &proxy.authorize_url,
                allow_http,
            )?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::RmcpServerKitError::Config(format!(
                    "oauth.proxy.authorize_url forbidden ({reason})"
                )));
            }
            let url = check_oauth_url("oauth.proxy.token_url", &proxy.token_url, allow_http)?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::RmcpServerKitError::Config(format!(
                    "oauth.proxy.token_url forbidden ({reason})"
                )));
            }
            if let Some(url) = &proxy.introspection_url {
                let parsed = check_oauth_url("oauth.proxy.introspection_url", url, allow_http)?;
                if let Some(reason) = crate::ssrf::check_url_literal_ip(&parsed) {
                    return Err(crate::error::RmcpServerKitError::Config(format!(
                        "oauth.proxy.introspection_url forbidden ({reason})"
                    )));
                }
            }
            if let Some(url) = &proxy.revocation_url {
                let parsed = check_oauth_url("oauth.proxy.revocation_url", url, allow_http)?;
                if let Some(reason) = crate::ssrf::check_url_literal_ip(&parsed) {
                    return Err(crate::error::RmcpServerKitError::Config(format!(
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
                return Err(crate::error::RmcpServerKitError::Config(
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
            let url = check_oauth_url("oauth.token_exchange.token_url", &tx.token_url, allow_http)?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::RmcpServerKitError::Config(format!(
                    "oauth.token_exchange.token_url forbidden ({reason})"
                )));
            }
            // M-H4: enforce RFC 8705 §2 mutual exclusion + feature gate
            // for token-exchange client authentication. See helper.
            validate_token_exchange_client_auth(tx)?;
        }
        // Compile the operator allowlist (if any) at config-validate
        // time so misconfiguration is rejected up-front, before any
        // outbound HTTP client is ever built.
        if let Some(raw) = &self.ssrf_allowlist {
            let compiled = compile_oauth_ssrf_allowlist(raw).map_err(|e| {
                crate::error::RmcpServerKitError::Config(format!("oauth.ssrf_allowlist: {e}"))
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
        humantime::parse_duration(&self.jwks_cache_ttl).map_err(|e| {
            crate::error::RmcpServerKitError::Config(format!(
                "oauth.jwks_cache_ttl {:?} is not a valid humantime duration (e.g. \"10m\", \"1h30m\"): {e}",
                self.jwks_cache_ttl
            ))
        })?;
        Ok(())
    }
}

/// M-H4: enforce RFC 8705 §2 mutual exclusion (`client_secret` xor
/// `client_cert`) + cargo-feature gating for token-exchange client
/// authentication. Without this a `client_cert`-only config silently
/// disables client auth at the token endpoint (the runtime path
/// simply omits the Authorization header).
fn validate_token_exchange_client_auth(
    tx: &TokenExchangeConfig,
) -> Result<(), crate::error::RmcpServerKitError> {
    match (&tx.client_cert, tx.client_secret.is_some()) {
        (Some(_), true) => Err(crate::error::RmcpServerKitError::Config(
            "oauth.token_exchange: client_cert and client_secret are mutually \
             exclusive (RFC 8705 §2). Set exactly one."
                .into(),
        )),
        (None, false) => Err(crate::error::RmcpServerKitError::Config(
            "oauth.token_exchange: token exchange requires client authentication. \
             Set either client_secret (RFC 6749 §2.3.1) or client_cert (RFC 8705 §2)."
                .into(),
        )),
        (Some(cc), false) => validate_client_cert_config(cc),
        (None, true) => Ok(()),
    }
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
fn validate_client_cert_config(
    cc: &ClientCertConfig,
) -> Result<(), crate::error::RmcpServerKitError> {
    #[cfg(not(feature = "oauth-mtls-client"))]
    {
        let _ = cc;
        Err(crate::error::RmcpServerKitError::Config(
            "oauth.token_exchange.client_cert requires the `oauth-mtls-client` cargo feature; \
             rebuild rmcp-server-kit with --features oauth-mtls-client (or have your \
             application crate enable it via `rmcp-server-kit/oauth-mtls-client`), or remove \
             the field"
                .into(),
        ))
    }
    #[cfg(feature = "oauth-mtls-client")]
    {
        let cert_bytes = std::fs::read(&cc.cert_path).map_err(|e| {
            tracing::warn!(error = %e, path = %cc.cert_path.display(), "client cert read failed");
            crate::error::RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert.cert_path unreadable: {}",
                cc.cert_path.display()
            ))
        })?;
        let key_bytes = std::fs::read(&cc.key_path).map_err(|e| {
            tracing::warn!(error = %e, path = %cc.key_path.display(), "client cert key read failed");
            crate::error::RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert.key_path unreadable: {}",
                cc.key_path.display()
            ))
        })?;
        let mut combined = Vec::with_capacity(cert_bytes.len() + 1 + key_bytes.len());
        combined.extend_from_slice(&cert_bytes);
        if !cert_bytes.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&key_bytes);
        let _identity = reqwest::Identity::from_pem(&combined).map_err(|e| {
            tracing::warn!(
                error = %e,
                cert_path = %cc.cert_path.display(),
                key_path = %cc.key_path.display(),
                "client cert PEM parse failed"
            );
            crate::error::RmcpServerKitError::Config(format!(
                "oauth.token_exchange.client_cert: PEM parse failed (cert={}, key={})",
                cc.cert_path.display(),
                cc.key_path.display()
            ))
        })?;
        Ok(())
    }
}

/// M-H4: build the `(cert_path, key_path) -> reqwest::Client` cache
/// consulted by [`OauthHttpClient::client_for`]. Each cert-bearing
/// client uses `redirect::Policy::none()` (RFC 8705 §2: never present
/// the client cert to a redirect target the operator did not approve)
/// and inherits the same `ca_cert_path`, connect/total timeouts as
/// the shared `inner` client. Returns an empty map when no
/// `token_exchange.client_cert` is configured.
#[cfg(feature = "oauth-mtls-client")]
fn build_mtls_clients(
    config: Option<&OAuthConfig>,
    allowlist: &Arc<crate::ssrf::CompiledSsrfAllowlist>,
    test_bypass: &crate::ssrf_resolver::TestLoopbackBypass,
) -> Result<Arc<HashMap<MtlsClientKey, reqwest::Client>>, crate::error::RmcpServerKitError> {
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

    let cert_bytes = std::fs::read(&cc.cert_path).map_err(|e| {
        crate::error::RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: read cert_path {}: {e}",
            cc.cert_path.display()
        ))
    })?;
    let key_bytes = std::fs::read(&cc.key_path).map_err(|e| {
        crate::error::RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: read key_path {}: {e}",
            cc.key_path.display()
        ))
    })?;
    let mut combined = Vec::with_capacity(cert_bytes.len() + 1 + key_bytes.len());
    combined.extend_from_slice(&cert_bytes);
    if !cert_bytes.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&key_bytes);
    let identity = reqwest::Identity::from_pem(&combined).map_err(|e| {
        crate::error::RmcpServerKitError::Startup(format!(
            "oauth http client mTLS: PEM parse (cert={}, key={}): {e}",
            cc.cert_path.display(),
            cc.key_path.display()
        ))
    })?;

    let resolver: Arc<dyn reqwest::dns::Resolve> =
        Arc::new(crate::ssrf_resolver::SsrfScreeningResolver::new(
            Arc::clone(allowlist),
            // M-H2/B1: TestLoopbackBypass aliases to Arc<AtomicBool> in test
            // builds and to `()` in production. We need a value clone here
            // (not Arc::clone) because the type vanishes outside test cfg;
            // the allow is justified by the feature-gated type alias.
            #[allow(clippy::clone_on_ref_ptr, reason = "type alias varies per feature")]
            test_bypass.clone(),
        ));

    let mut builder = reqwest::Client::builder()
        // M-H2/N1: same proxy + DNS hardening as the shared client.
        .no_proxy()
        .dns_resolver(Arc::clone(&resolver))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .identity(identity);

    if let Some(ref ca_path) = cfg.ca_cert_path {
        let pem = std::fs::read(ca_path).map_err(|e| {
            crate::error::RmcpServerKitError::Startup(format!(
                "oauth http client mTLS: read ca_cert_path {}: {e}",
                ca_path.display()
            ))
        })?;
        let cert = reqwest::tls::Certificate::from_pem(&pem).map_err(|e| {
            crate::error::RmcpServerKitError::Startup(format!(
                "oauth http client mTLS: parse ca_cert_path {}: {e}",
                ca_path.display()
            ))
        })?;
        builder = builder.add_root_certificate(cert);
    }

    let client = builder.build().map_err(|e| {
        crate::error::RmcpServerKitError::Startup(format!("oauth http client mTLS init: {e}"))
    })?;
    map.insert(
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
fn check_oauth_url(
    field: &str,
    raw: &str,
    allow_http: bool,
) -> Result<url::Url, crate::error::RmcpServerKitError> {
    let parsed = url::Url::parse(raw).map_err(|e| {
        crate::error::RmcpServerKitError::Config(format!(
            "{field}: invalid URL <unparseable-url>: {e}"
        ))
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(crate::error::RmcpServerKitError::Config(format!(
            "{field} rejected: URL contains userinfo (credentials in URL are forbidden)"
        )));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_http => Ok(parsed),
        "http" => Err(crate::error::RmcpServerKitError::Config(format!(
            "{field}: must use https scheme (got http; set allow_http_oauth_urls=true \
             to override - strongly discouraged in production)"
        ))),
        other => Err(crate::error::RmcpServerKitError::Config(format!(
            "{field}: must use https scheme (got {other:?})"
        ))),
    }
}

fn validate_oauth_capacity_knobs(
    config: &OAuthConfig,
) -> Result<(), crate::error::RmcpServerKitError> {
    (config.max_jwks_keys != 0).ok_or_else(|| {
        crate::error::RmcpServerKitError::Config("oauth.max_jwks_keys must be nonzero".into())
    })?;
    (config.jwks_max_response_bytes != 0).ok_or_else(|| {
        crate::error::RmcpServerKitError::Config(
            "oauth.jwks_max_response_bytes must be nonzero".into(),
        )
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
    inner: OAuthConfig,
}

impl OAuthConfigBuilder {
    /// Replace the scope-to-role mappings.
    pub fn scopes(mut self, scopes: Vec<ScopeMapping>) -> Self {
        self.inner.scopes = scopes;
        self
    }

    /// Append a single scope-to-role mapping.
    pub fn scope(mut self, scope: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.scopes.push(ScopeMapping {
            scope: scope.into(),
            role: role.into(),
        });
        self
    }

    /// Set the JWT claim path used to extract roles directly (without
    /// going through `scope` mappings).
    pub fn role_claim(mut self, claim: impl Into<String>) -> Self {
        self.inner.role_claim = Some(claim.into());
        self
    }

    /// Replace the claim-value-to-role mappings.
    pub fn role_mappings(mut self, mappings: Vec<RoleMapping>) -> Self {
        self.inner.role_mappings = mappings;
        self
    }

    /// Append a single claim-value-to-role mapping (used with
    /// [`Self::role_claim`]).
    pub fn role_mapping(mut self, claim_value: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.role_mappings.push(RoleMapping {
            claim_value: claim_value.into(),
            role: role.into(),
        });
        self
    }

    /// Override the JWKS cache TTL (humantime string, e.g. `"5m"`).
    /// Defaults to `"10m"`.
    pub fn jwks_cache_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.inner.jwks_cache_ttl = ttl.into();
        self
    }

    /// Attach an OAuth proxy configuration. When set, the server
    /// exposes `/authorize`, `/token`, and `/register` endpoints.
    pub fn proxy(mut self, proxy: OAuthProxyConfig) -> Self {
        self.inner.proxy = Some(proxy);
        self
    }

    /// Attach an RFC 8693 token exchange configuration.
    pub fn token_exchange(mut self, token_exchange: TokenExchangeConfig) -> Self {
        self.inner.token_exchange = Some(token_exchange);
        self
    }

    /// Provide a PEM CA bundle path used for all OAuth-bound HTTPS traffic
    /// originated by this crate (JWKS fetches and the optional OAuth proxy
    /// `/authorize`, `/token`, `/register`, `/introspect`, `/revoke`,
    /// `/.well-known/oauth-authorization-server` upstream calls).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.ca_cert_path = Some(path.into());
        self
    }

    /// Allow plain-HTTP (non-TLS) URLs for OAuth endpoints.
    ///
    /// **Default: `false`.** See the field-level documentation on
    /// [`OAuthConfig::allow_http_oauth_urls`] for the security caveats
    /// before enabling this.
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
    pub const fn strict_audience_validation(mut self, strict: bool) -> Self {
        #[allow(
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
    pub const fn audience_validation_mode(mut self, mode: AudienceValidationMode) -> Self {
        self.inner.audience_validation_mode = Some(mode);
        self
    }

    /// Require the JWT `sub` (subject) claim (opt-in; default `false`).
    ///
    /// When `true`, a token without `sub` is rejected. Leave `false` for
    /// OAuth client-credentials / machine-to-machine tokens, which
    /// legitimately carry no subject.
    pub const fn require_subject(mut self, require: bool) -> Self {
        self.inner.require_subject = require;
        self
    }

    /// Override the maximum JWKS response body size in bytes.
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
    pub fn ssrf_allowlist(mut self, allowlist: OAuthSsrfAllowlist) -> Self {
        self.inner.ssrf_allowlist = Some(allowlist);
        self
    }

    /// Finalise the builder and return the [`OAuthConfig`].
    #[must_use]
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
    /// Target audience - the `client_id` of the downstream API
    /// (e.g. `upstream-api`).  The exchanged token will have this
    /// value in its `aud` claim.
    pub audience: String,
}

impl TokenExchangeConfig {
    /// Create a new token exchange configuration.
    #[must_use]
    pub fn new(
        token_url: String,
        client_id: String,
        client_secret: Option<secrecy::SecretString>,
        client_cert: Option<ClientCertConfig>,
        audience: String,
    ) -> Self {
        Self {
            token_url,
            client_id,
            client_secret,
            client_cert,
            audience,
        }
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
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }
}

/// Successful response from an RFC 8693 token exchange.
#[derive(Debug, Deserialize)]
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

/// Configuration for proxying OAuth 2.1 flows to an upstream identity provider.
///
/// When present, the MCP server exposes `/authorize`, `/token`, and
/// `/register` endpoints that proxy to the upstream identity provider
/// (e.g. Keycloak). MCP clients see this server as the authorization
/// server and perform a standard Authorization Code + PKCE flow.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
}

impl OAuthProxyConfig {
    /// Start building an [`OAuthProxyConfig`] with the three required
    /// upstream fields.
    ///
    /// Optional settings (`client_secret`, `introspection_url`,
    /// `revocation_url`, `expose_admin_endpoints`) default to their
    /// [`Default`] values and can be set via the corresponding builder
    /// methods.
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
    inner: OAuthProxyConfig,
}

impl OAuthProxyConfigBuilder {
    /// Set the upstream OAuth client secret. Omit for public clients.
    pub fn client_secret(mut self, secret: secrecy::SecretString) -> Self {
        self.inner.client_secret = Some(secret);
        self
    }

    /// Configure the upstream RFC 7662 introspection endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
    pub fn introspection_url(mut self, url: impl Into<String>) -> Self {
        self.inner.introspection_url = Some(url.into());
        self
    }

    /// Configure the upstream RFC 7009 revocation endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
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
    pub const fn expose_admin_endpoints(mut self, expose: bool) -> Self {
        self.inner.expose_admin_endpoints = expose;
        self
    }

    /// Require the normal authentication middleware on `/introspect` and
    /// `/revoke`.
    pub const fn require_auth_on_admin_endpoints(mut self, require: bool) -> Self {
        self.inner.require_auth_on_admin_endpoints = require;
        self
    }

    /// Explicit opt-out for the M3 startup check that rejects exposing
    /// `/introspect`/`/revoke` without authentication. See
    /// [`OAuthProxyConfig::allow_unauthenticated_admin_endpoints`].
    pub const fn allow_unauthenticated_admin_endpoints(mut self, allow: bool) -> Self {
        self.inner.allow_unauthenticated_admin_endpoints = allow;
        self
    }

    /// Finalise the builder and return the [`OAuthProxyConfig`].
    #[must_use]
    pub fn build(self) -> OAuthProxyConfig {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

/// `kid`-indexed map of (algorithm, decoding key) pairs plus a list of
/// unnamed keys. Produced by [`build_key_cache`] and consumed by
/// [`JwksCache::refresh_inner`].
type JwksKeyCache = (
    HashMap<String, (Algorithm, DecodingKey)>,
    Vec<(Algorithm, DecodingKey)>,
);

struct CachedKeys {
    /// `kid` -> (Algorithm, `DecodingKey`)
    keys: HashMap<String, (Algorithm, DecodingKey)>,
    /// Keys without a kid, indexed by algorithm family.
    unnamed_keys: Vec<(Algorithm, DecodingKey)>,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedKeys {
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
#[allow(
    missing_debug_implementations,
    reason = "contains reqwest::Client and DecodingKey cache with no Debug impl"
)]
#[non_exhaustive]
pub struct JwksCache {
    jwks_uri: String,
    ttl: Duration,
    max_jwks_keys: usize,
    max_response_bytes: u64,
    allow_http: bool,
    inner: RwLock<Option<CachedKeys>>,
    http: reqwest::Client,
    validation_template: Validation,
    /// Expected audience value from config; checked against `aud` and,
    /// per `audience_mode`, optionally `azp`.
    expected_audience: String,
    audience_mode: AudienceValidationMode,
    require_subject: bool,
    /// Set to `true` after the first `azp`-only audience match while in
    /// [`AudienceValidationMode::Warn`], so the deprecation warning logs
    /// at most once per process lifetime.
    azp_fallback_warned: AtomicBool,
    /// Separate from [Self::azp_fallback_warned] on purpose: sharing one
    /// flag would let whichever mode logged first suppress the other.
    azp_permissive_logged: AtomicBool,
    scopes: Vec<ScopeMapping>,
    role_claim: Option<String>,
    role_mappings: Vec<RoleMapping>,
    /// Tracks the last refresh attempt timestamp. Enforces a 10-second cooldown
    /// between refresh attempts to prevent abuse via fabricated JWTs with invalid kids.
    last_refresh_attempt: RwLock<Option<Instant>>,
    /// Serializes concurrent refresh attempts so only one fetch is in flight.
    refresh_lock: tokio::sync::Mutex<()>,
    /// Compiled operator SSRF allowlist (empty by default = original
    /// fail-closed behaviour). Wrapped in `Arc` so the redirect-policy
    /// closure can capture a cheap clone without inflating the cache size.
    allowlist: Arc<crate::ssrf::CompiledSsrfAllowlist>,
    /// M-H2/B1: shared loopback bypass; same Arc is captured by the
    /// SSRF resolver inside the cached `reqwest::Client`. See the
    /// matching field on `OauthHttpClient`.
    #[cfg(any(test, feature = "test-helpers"))]
    test_allow_loopback_ssrf: crate::ssrf_resolver::TestLoopbackBypass,
}

/// Minimum cooldown between JWKS refresh attempts (prevents abuse).
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// Upper bound on an upstream OAuth proxy response body (`/token`,
/// `/introspect`, `/revoke`, and RFC 8693 token exchange).
///
/// The upstream is the operator-configured, SSRF-screened authorization
/// server, so this is defense-in-depth rather than an attacker-facing
/// control — but it keeps the proxy paths symmetric with the bounded JWKS
/// fetch (`jwks_max_response_bytes`) so a misbehaving or compromised IdP
/// cannot make the server buffer an unbounded response. 1 MiB comfortably
/// covers token, introspection, and revocation JSON payloads.
const OAUTH_PROXY_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Algorithms we accept from JWKS-served keys.
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

/// Coarse JWT validation failure classification for auth diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtValidationFailure {
    /// JWT was well-formed but expired per `exp` validation.
    Expired,
    /// JWT failed validation for all other reasons.
    Invalid,
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
    pub fn new(config: &OAuthConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure crypto providers are installed (idempotent -- ok() ignores
        // the error if already installed by another call in the same process).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
            .install_default()
            .ok();

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
            Some(raw) => Arc::new(compile_oauth_ssrf_allowlist(raw).map_err(|e| {
                Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "oauth.ssrf_allowlist: {e}"
                ))
            })?),
            None => Arc::new(crate::ssrf::CompiledSsrfAllowlist::default()),
        };
        let redirect_allowlist = Arc::clone(&allowlist);

        // M-H2: see OauthHttpClient::build for rationale; same pattern.
        #[cfg(any(test, feature = "test-helpers"))]
        let test_bypass: crate::ssrf_resolver::TestLoopbackBypass =
            Arc::new(AtomicBool::new(false));
        #[cfg(not(any(test, feature = "test-helpers")))]
        let test_bypass: crate::ssrf_resolver::TestLoopbackBypass = ();

        #[allow(
            clippy::clone_on_ref_ptr,
            clippy::clone_on_copy,
            clippy::unit_arg,
            reason = "TestLoopbackBypass aliases to Arc<AtomicBool> under cfg(test)/test-helpers and to `()` otherwise; each cfg trips a different clone/arg lint"
        )]
        let resolver: Arc<dyn reqwest::dns::Resolve> =
            Arc::new(crate::ssrf_resolver::SsrfScreeningResolver::new(
                Arc::clone(&allowlist),
                test_bypass.clone(),
            ));

        let mut http_builder = reqwest::Client::builder()
            // M-H2/N1: see OauthHttpClient::build.
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
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
                            target = %crate::ssrf::sanitized_url_for_log(attempt.url()),
                            "oauth redirect rejected"
                        );
                        attempt.error(reason)
                    }
                }
            }));

        if let Some(ref ca_path) = config.ca_cert_path {
            // Pre-startup blocking I/O — runs before the runtime begins
            // serving requests, so blocking the current thread here is
            // intentional. Do not wrap in `spawn_blocking`: the constructor
            // is synchronous by contract and is called from `serve()`'s
            // pre-startup phase.
            let pem = std::fs::read(ca_path)?;
            let cert = reqwest::tls::Certificate::from_pem(&pem)?;
            http_builder = http_builder.add_root_certificate(cert);
        }

        let http = http_builder.build()?;

        Ok(Self {
            jwks_uri: config.jwks_uri.clone(),
            ttl,
            max_jwks_keys: config.max_jwks_keys,
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
            refresh_lock: tokio::sync::Mutex::new(()),
            allowlist,
            #[cfg(any(test, feature = "test-helpers"))]
            test_allow_loopback_ssrf: test_bypass,
        })
    }

    /// Test-only: disable initial-target SSRF screening for loopback-backed
    /// fixtures. This is unreachable from normal production builds and exists
    /// only so tests can fetch JWKS from local mock servers.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_allow_loopback_ssrf(self) -> Self {
        // M-H2/B1: flip the SHARED atomic so the resolver inside the
        // cached client and the pre-flight check both observe the bypass.
        self.test_allow_loopback_ssrf.store(true, Ordering::Relaxed);
        self
    }

    /// Validate a JWT Bearer token. Returns `Some(AuthIdentity)` on success.
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
    pub async fn validate_token_with_reason(
        &self,
        token: &str,
    ) -> Result<AuthIdentity, JwtValidationFailure> {
        let claims = self.decode_claims(token).await?;

        if self.require_subject && claims.sub.is_none() {
            core::hint::cold_path();
            tracing::debug!("JWT rejected: require_subject is set but the token has no `sub`");
            return Err(JwtValidationFailure::Invalid);
        }
        self.check_audience(&claims)?;
        let role = self.resolve_role(&claims)?;

        // Identity: prefer human-readable `preferred_username` (Keycloak/OIDC),
        // then `sub`, then `azp` (authorized party), then `client_id`.
        let sub = claims.sub;
        let name = claims
            .extra
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| sub.clone())
            .or(claims.azp)
            .or(claims.client_id)
            .unwrap_or_else(|| "oauth-client".into());

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
    async fn decode_claims(&self, token: &str) -> Result<Claims, JwtValidationFailure> {
        let (key, alg) = self.select_jwks_key(token).await?;

        // Build a per-decode validation scoped to the header's algorithm.
        // jsonwebtoken requires ALL algorithms in the list to share the
        // same family as the key, so we restrict to [alg] only.
        let mut validation = self.validation_template.clone();
        validation.algorithms = vec![alg];

        // Move the (cheap) clones into the blocking task so the verifier
        // does not hold a reference into the request's async scope.
        let token_owned = token.to_owned();
        let join =
            tokio::task::spawn_blocking(move || decode::<Claims>(&token_owned, &key, &validation))
                .await;

        let decode_result = match join {
            Ok(r) => r,
            Err(join_err) => {
                core::hint::cold_path();
                tracing::error!(
                    error = %join_err,
                    "JWT decode task panicked or was cancelled"
                );
                return Err(JwtValidationFailure::Invalid);
            }
        };

        decode_result.map(|td| td.claims).map_err(|e| {
            core::hint::cold_path();
            let failure = if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                JwtValidationFailure::Expired
            } else {
                JwtValidationFailure::Invalid
            };
            tracing::debug!(error = %e, ?alg, ?failure, "JWT decode failed");
            failure
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
    #[allow(
        clippy::cognitive_complexity,
        reason = "each failure arm pairs `cold_path()` with a distinct `tracing::debug!` site for observability; collapsing into combinators would lose structured-field log sites without reducing real complexity"
    )]
    async fn select_jwks_key(
        &self,
        token: &str,
    ) -> Result<(DecodingKey, Algorithm), JwtValidationFailure> {
        let Ok(header) = decode_header(token) else {
            core::hint::cold_path();
            tracing::debug!("JWT header decode failed");
            return Err(JwtValidationFailure::Invalid);
        };
        let kid = header.kid.as_deref();
        tracing::debug!(alg = ?header.alg, kid = kid.unwrap_or("-"), "JWT header decoded");

        if !ACCEPTED_ALGS.contains(&header.alg) {
            core::hint::cold_path();
            tracing::debug!(alg = ?header.alg, "JWT algorithm not accepted");
            return Err(JwtValidationFailure::Invalid);
        }

        let Some(key) = self.find_key(kid, header.alg).await else {
            core::hint::cold_path();
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
        core::hint::cold_path();
        tracing::debug!(
            aud = %claims.aud.log_display(),
            azp = claims.azp.as_deref().unwrap_or("-"),
            expected = %self.expected_audience,
            mode = self.audience_mode.as_str(),
            "JWT rejected: audience mismatch"
        );
        Err(JwtValidationFailure::Invalid)
    }

    /// Resolve the role for this token.
    ///
    /// When `role_claim` is set, extract values from the given claim path
    /// and match against `role_mappings`. Otherwise, match space-separated
    /// tokens in the `scope` claim against configured scope mappings.
    fn resolve_role(&self, claims: &Claims) -> Result<String, JwtValidationFailure> {
        if let Some(ref claim_path) = self.role_claim {
            let owned_first_class: Vec<String> = first_class_claim_values(claims, claim_path);
            let mut values: Vec<&str> = owned_first_class.iter().map(String::as_str).collect();
            values.extend(resolve_claim_path(&claims.extra, claim_path));
            return self
                .role_mappings
                .iter()
                .find(|m| values.contains(&m.claim_value.as_str()))
                .map(|m| m.role.clone())
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
            .find(|m| token_scopes.contains(&m.scope.as_str()))
            .map(|m| m.role.clone())
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
    /// bypassing the cooldown on unknown-`kid` requests — that reopens the
    /// DoS-amplification vector the cooldown exists to close.
    // NOT cancel-safe: see the `# Cancellation` section above — cooldown is
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
        let _ = self.refresh_inner().await;
    }

    /// Fetch JWKS from the configured URI and update the cache.
    ///
    /// Internal implementation - callers should use [`Self::refresh_with_cooldown`]
    /// to respect rate limiting.
    // cancel-safe (cache integrity): the cache is published via a single
    // `*guard = Some(..)` assignment under the `tokio::sync::RwLock` write lock
    // at the end. Cancellation before that point leaves the prior cache intact;
    // it never observes a half-built cache.
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
    #[allow(
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
            Err(e) => {
                tracing::warn!(
                    error = %e.without_url(),
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
    /// `build_key_cache` error string. Used by `tests/jwks_key_cap.rs`.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
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
    pub async fn __test_has_kid(&self, kid: &str) -> bool {
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .is_some_and(|cache| cache.keys.contains_key(kid))
    }
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

fn build_key_cache(jwks: &JwkSet, max_keys: usize) -> Result<JwksKeyCache, String> {
    if jwks.keys.len() > max_keys {
        return Err(format!(
            "jwks_key_count_exceeds_cap: got {} keys, max is {}",
            jwks.keys.len(),
            max_keys
        ));
    }
    let mut keys = HashMap::new();
    let mut unnamed_keys = Vec::new();
    for jwk in &jwks.keys {
        let Ok(decoding_key) = DecodingKey::from_jwk(jwk) else {
            continue;
        };
        let Some(alg) = jwk_algorithm(jwk) else {
            continue;
        };
        if let Some(ref kid) = jwk.common.key_id {
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
    if let Some(kid) = kid {
        // A token carrying a `kid` must match a NAMED JWKS key exactly; it
        // must NOT fall back to an unnamed key. Otherwise an attacker could
        // present an unknown `kid` and be validated against an unrelated
        // unnamed key of the same algorithm (L4, fail-closed key selection).
        if let Some((cached_alg, key)) = cached.keys.get(kid)
            && *cached_alg == alg
        {
            return Some(key.clone());
        }
        return None;
    }
    // No `kid`: fall back to any unnamed key matching the algorithm.
    cached
        .unnamed_keys
        .iter()
        .find(|(a, _)| *a == alg)
        .map(|(_, k)| k.clone())
}

/// Extract the algorithm from a JWK's common parameters.
#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "jsonwebtoken KeyAlgorithm is a large external enum; only the JWT-signing variants are mappable to `Algorithm`"
)]
fn jwk_algorithm(jwk: &jsonwebtoken::jwk::Jwk) -> Option<Algorithm> {
    jwk.common.key_algorithm.and_then(|ka| match ka {
        jsonwebtoken::jwk::KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        jsonwebtoken::jwk::KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        jsonwebtoken::jwk::KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        jsonwebtoken::jwk::KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        jsonwebtoken::jwk::KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        jsonwebtoken::jwk::KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        jsonwebtoken::jwk::KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        jsonwebtoken::jwk::KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        jsonwebtoken::jwk::KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    })
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
fn resolve_claim_path<'a>(
    extra: &'a HashMap<String, serde_json::Value>,
    path: &str,
) -> Vec<&'a str> {
    let mut segments = path.split('.');
    let Some(first) = segments.next() else {
        return Vec::new();
    };

    let mut current: Option<&serde_json::Value> = extra.get(first);

    for segment in segments {
        current = current.and_then(|v| v.get(segment));
    }

    match current {
        Some(serde_json::Value::String(s)) => s.split_whitespace().collect(),
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
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
    fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|v| v == value)
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
        Some(serde_json::Value::String(s)) => s.clone(),
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
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = OneOrMany;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string or array of strings")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<OneOrMany, E> {
                Ok(OneOrMany(vec![v.to_owned()]))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<OneOrMany, A::Error> {
                let mut v = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    v.push(s);
                }
                Ok(OneOrMany(v))
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
pub fn looks_like_jwt(token: &str) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

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

/// Build the Protected Resource Metadata JSON response.
///
/// When an OAuth proxy is configured, `authorization_servers` points to
/// the MCP server itself (the proxy facade).  Otherwise it points directly
/// to the upstream issuer.
#[must_use]
pub fn protected_resource_metadata(
    resource_url: &str,
    server_url: &str,
    config: &OAuthConfig,
) -> serde_json::Value {
    // Always point to the local server -- when a proxy is configured the
    // server exposes /authorize, /token, /register locally.  When an
    // application provides its own chained OAuth flow (via extra_router)
    // without a proxy, the auth server is still the local server.
    let scopes: Vec<&str> = config.scopes.iter().map(|s| s.scope.as_str()).collect();
    let auth_server = server_url;
    serde_json::json!({
        "resource": resource_url,
        "authorization_servers": [auth_server],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"]
    })
}

/// Build the Authorization Server Metadata JSON response (RFC 8414).
///
/// Returned at `GET /.well-known/oauth-authorization-server` so MCP
/// clients can discover the authorization and token endpoints.
#[must_use]
pub fn authorization_server_metadata(server_url: &str, config: &OAuthConfig) -> serde_json::Value {
    let scopes: Vec<&str> = config.scopes.iter().map(|s| s.scope.as_str()).collect();
    let mut meta = serde_json::json!({
        "issuer": &config.issuer,
        "authorization_endpoint": format!("{server_url}/authorize"),
        "token_endpoint": format!("{server_url}/token"),
        "registration_endpoint": format!("{server_url}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": scopes,
        "token_endpoint_auth_methods_supported": ["none"],
    });
    if let Some(proxy) = &config.proxy
        && proxy.expose_admin_endpoints
        && let Some(obj) = meta.as_object_mut()
    {
        if proxy.introspection_url.is_some() {
            obj.insert(
                "introspection_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/introspect")),
            );
        }
        if proxy.revocation_url.is_some() {
            obj.insert(
                "revocation_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/revoke")),
            );
        }
        if proxy.require_auth_on_admin_endpoints {
            obj.insert(
                "introspection_endpoint_auth_methods_supported".into(),
                serde_json::json!(["bearer"]),
            );
            obj.insert(
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
pub fn handle_authorize(proxy: &OAuthProxyConfig, query: &str) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    // Replace the client_id in the query with the upstream client_id.
    let upstream_query = rewrite_client_auth_params(query, &proxy.client_id);
    let redirect_url = format!("{}?{upstream_query}", proxy.authorize_url);

    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

/// Handle `POST /token` - proxy the token request to the upstream provider.
///
/// Forwards the request body (authorization code exchange or refresh token
/// grant) to the upstream token endpoint, injecting client credentials
/// when configured (confidential client). Returns the upstream response as-is.
pub async fn handle_token(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    // Replace client_id in the form body with the upstream client_id.
    let mut upstream_body = rewrite_client_auth_params(body, &proxy.client_id);

    // For confidential clients, inject the client_secret.
    if let Some(ref secret) = proxy.client_secret {
        use std::fmt::Write;

        use secrecy::ExposeSecret;
        let _ = write!(
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
        Err(e) => {
            tracing::error!(error = %e, "OAuth token proxy request failed");
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
pub fn handle_register(proxy: &OAuthProxyConfig, body: &serde_json::Value) -> serde_json::Value {
    let mut resp = serde_json::json!({
        "client_id": proxy.client_id,
        "token_endpoint_auth_method": "none",
    });
    if let Some(uris) = body.get("redirect_uris")
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert("redirect_uris".into(), uris.clone());
    }
    if let Some(name) = body.get("client_name")
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert("client_name".into(), name.clone());
    }
    resp
}

/// Handle `POST /introspect` - RFC 7662 token introspection proxy.
///
/// Forwards the request body to the upstream introspection endpoint,
/// injecting client credentials when configured. Returns the upstream
/// response as-is.  Requires `proxy.introspection_url` to be `Some`.
pub async fn handle_introspect(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    let Some(ref url) = proxy.introspection_url else {
        return oauth_error_response(
            axum::http::StatusCode::NOT_FOUND,
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
pub async fn handle_revoke(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    let Some(ref url) = proxy.revocation_url else {
        return oauth_error_response(
            axum::http::StatusCode::NOT_FOUND,
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
) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    let mut upstream_body = rewrite_client_auth_params(body, &proxy.client_id);
    if let Some(ref secret) = proxy.client_secret {
        use std::fmt::Write;

        use secrecy::ExposeSecret;
        let _ = write!(
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
                .and_then(|v| v.to_str().ok())
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
        Err(e) => {
            tracing::error!(
                error = %e,
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

fn oauth_error_response(
    status: axum::http::StatusCode,
    error: &str,
    description: &str,
) -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};
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
    error: String,
    error_description: Option<String>,
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
pub async fn exchange_token(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
) -> Result<ExchangedToken, crate::error::RmcpServerKitError> {
    exchange_token_inner(http, config, subject_token, SuccessLogMode::Normal).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuccessLogMode {
    Normal,
    Suppress,
}

async fn exchange_token_inner(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
    success_log: SuccessLogMode,
) -> Result<ExchangedToken, crate::error::RmcpServerKitError> {
    use secrecy::ExposeSecret;

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
        && let Some(ref secret) = config.client_secret
    {
        use base64::Engine;
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
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
        .map_err(|e| {
            tracing::error!(error = %e, "token exchange request failed");
            // Do NOT leak upstream URL, reqwest internals, or DNS detail to clients.
            crate::error::RmcpServerKitError::Auth("server_error".into())
        })?;

    let status = resp.status();
    let body_bytes =
        read_response_capped(resp, OAUTH_PROXY_MAX_RESPONSE_BYTES, "oauth/token-exchange")
            .await
            .map_err(|()| {
                // read_response_capped already logged the cause (oversize / transport).
                crate::error::RmcpServerKitError::Auth("server_error".into())
            })?;

    if !status.is_success() {
        core::hint::cold_path();
        // Parse upstream error for logging only; client-visible payload is a
        // sanitized short code from the RFC 6749 §5.2 / RFC 8693 allowlist.
        let parsed = serde_json::from_slice::<OAuthErrorResponse>(&body_bytes).ok();
        let short_code = parsed
            .as_ref()
            .map_or("server_error", |e| sanitize_oauth_error_code(&e.error));
        if let Some(ref e) = parsed {
            tracing::warn!(
                status = %status,
                upstream_error = %e.error,
                upstream_error_description = e.error_description.as_deref().unwrap_or(""),
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
        return Err(crate::error::RmcpServerKitError::Auth(short_code.into()));
    }

    let exchanged = serde_json::from_slice::<ExchangedToken>(&body_bytes).map_err(|e| {
        tracing::error!(error = %e, "failed to parse token exchange response");
        // Avoid surfacing serde internals; map to sanitized short code so
        // RmcpServerKitError::into_response cannot leak parser detail to the client.
        crate::error::RmcpServerKitError::Auth("server_error".into())
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
pub async fn exchange_token_with_cancel(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
    ct: &tokio_util::sync::CancellationToken,
    timeout: Option<Duration>,
) -> crate::cancel::DetachOutcome<Result<ExchangedToken, crate::error::RmcpServerKitError>> {
    // Pre-cancel check FIRST: do not clone config, client, or subject token for
    // an already-abandoned request. In particular, cloning the subject token
    // would allocate and keep credential-adjacent material alive for work that
    // the caller has already told us not to start.
    if ct.is_cancelled() {
        return crate::cancel::DetachOutcome::Cancelled;
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    let http = http.clone();
    let config = config.clone();
    let subject_token = subject_token.to_owned();

    // This task is intentionally detached on caller cancel/timeout. A plain
    // `run_with_cancel_and_timeout(exchange_token(...))` would drop the
    // JoinHandle in those arms, but it would not keep a result sink. The
    // `oneshot::Sender` is the sink: if the receiver is gone, `send` returns
    // the result to this task so an abandoned success can be audited without
    // logging token material.
    tokio::spawn(
        async move {
            let result =
                exchange_token_inner(&http, &config, &subject_token, SuccessLogMode::Suppress)
                    .await;
            if let Err(result) = tx.send(result) {
                audit_abandoned_exchange_result(result);
            }
        }
        .instrument(tracing::Span::current()),
    );

    receive_exchange_result_with_cancel(rx, ct, timeout).await
}

async fn receive_exchange_result_with_cancel(
    rx: tokio::sync::oneshot::Receiver<Result<ExchangedToken, crate::error::RmcpServerKitError>>,
    ct: &tokio_util::sync::CancellationToken,
    timeout: Option<Duration>,
) -> crate::cancel::DetachOutcome<Result<ExchangedToken, crate::error::RmcpServerKitError>> {
    // `biased;` is deliberate and matches `cancel::run_with_cancel_and_timeout`:
    // the receiver arm comes first so a ready completion wins over a
    // simultaneously-ready cancellation or timeout. Dropping the receiver on
    // the other arms is not a leak; it is the signal that tells the spawned task
    // to audit an eventual success via `Sender::send`'s returned value.
    if let Some(t) = timeout {
        tokio::select! {
            biased;
            received = rx => map_exchange_receiver(received),
            () = ct.cancelled() => crate::cancel::DetachOutcome::Cancelled,
            () = tokio::time::sleep(t) => crate::cancel::DetachOutcome::TimedOut,
        }
    } else {
        tokio::select! {
            biased;
            received = rx => map_exchange_receiver(received),
            () = ct.cancelled() => crate::cancel::DetachOutcome::Cancelled,
        }
    }
}

fn map_exchange_receiver(
    received: Result<
        Result<ExchangedToken, crate::error::RmcpServerKitError>,
        tokio::sync::oneshot::error::RecvError,
    >,
) -> crate::cancel::DetachOutcome<Result<ExchangedToken, crate::error::RmcpServerKitError>> {
    match received {
        Ok(result) => crate::cancel::DetachOutcome::Completed(result),
        Err(error) => {
            tracing::error!(error = %error, "token exchange task ended before returning a result");
            crate::cancel::DetachOutcome::Completed(Err(
                crate::error::RmcpServerKitError::Internal("server_error".into()),
            ))
        }
    }
}

fn audit_abandoned_exchange_result(
    result: Result<ExchangedToken, crate::error::RmcpServerKitError>,
) {
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

/// Build the RFC 8693 token-exchange form body. Adds `client_id` when the
/// client is public (no `client_secret`).
fn build_exchange_form(config: &TokenExchangeConfig, subject_token: &str) -> String {
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}&requested_token_type={}&audience={}",
        urlencoding::encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        urlencoding::encode(subject_token),
        urlencoding::encode("urn:ietf:params:oauth:token-type:access_token"),
        urlencoding::encode("urn:ietf:params:oauth:token-type:access_token"),
        urlencoding::encode(&config.audience),
    );
    if config.client_secret.is_none() {
        format!(
            "{body}&client_id={}",
            urlencoding::encode(&config.client_id)
        )
    } else {
        body
    }
}

/// Debug-log the exchanged token. For JWTs, decode and log claim summary;
/// for opaque tokens, log length + issued type.
fn log_exchanged_token(exchanged: &ExchangedToken) {
    use base64::Engine;

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
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return;
    };
    tracing::debug!(
        sub = fmt_json_str(claims.get("sub")),
        aud = %fmt_json_aud(claims.get("aud")),
        azp = fmt_json_str(claims.get("azp")),
        iss = fmt_json_str(claims.get("iss")),
        expires_in = exchanged.expires_in,
        "exchanged token claims (JWT)",
    );
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
fn rewrite_client_auth_params(params: &str, upstream_client_id: &str) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(params.as_bytes()) {
        if CLIENT_AUTH_PARAMS.contains(&key.as_ref()) {
            continue;
        }
        out.append_pair(&key, &value);
    }
    out.append_pair("client_id", upstream_client_id);
    out.finish()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Instant};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    // -- F2 regression: client-auth parameter smuggling in the OAuth proxy --
    //
    // The previous `replace_client_id` split on `&` and dropped segments
    // literally starting with `client_id=`. Percent-encoded keys survived that
    // filter but decode upstream to `client_id`, and `client_secret` was never
    // filtered at all, so a caller could ship duplicate client credentials to
    // the IdP alongside the proxy's own. Every case below forwarded the
    // attacker value before the fix.

    /// Decode a rewritten form back into `(key, value)` pairs. Assertions run
    /// on decoded pairs, never on raw bytes: `form_urlencoded` normalizes `+`
    /// and percent-escapes on re-serialization, so byte equality is not a
    /// meaningful contract here.
    fn decoded_pairs(form: &str) -> Vec<(String, String)> {
        url::form_urlencoded::parse(form.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn rewrite_drops_percent_encoded_client_id_key() {
        let out = rewrite_client_auth_params("%63lient_id=attacker&scope=read", "proxy-id");
        let pairs = decoded_pairs(&out);
        let client_ids: Vec<&String> = pairs
            .iter()
            .filter(|(k, _)| k == "client_id")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(client_ids, vec!["proxy-id"], "smuggled client_id survived");
    }

    #[test]
    fn rewrite_drops_underscore_encoded_client_id_key() {
        let out = rewrite_client_auth_params("client%5Fid=attacker&scope=read", "proxy-id");
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs.iter().any(|(_, v)| v == "attacker"),
            "smuggled client_id survived: {pairs:?}"
        );
    }

    #[test]
    fn rewrite_drops_caller_supplied_client_secret() {
        let out =
            rewrite_client_auth_params("client_secret=attacker-secret&scope=read", "proxy-id");
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs.iter().any(|(k, _)| k == "client_secret"),
            "caller client_secret survived: {pairs:?}"
        );
    }

    #[test]
    fn rewrite_drops_caller_supplied_client_assertion() {
        let out = rewrite_client_auth_params(
            "client_assertion=ey.evil&client_assertion_type=urn:evil&scope=read",
            "proxy-id",
        );
        let pairs = decoded_pairs(&out);
        assert!(
            !pairs
                .iter()
                .any(|(k, _)| k == "client_assertion" || k == "client_assertion_type"),
            "caller client assertion survived: {pairs:?}"
        );
    }

    #[test]
    fn rewrite_collapses_duplicate_client_id_to_proxy_value() {
        let out = rewrite_client_auth_params("client_id=a&client_id=b&scope=read", "proxy-id");
        let pairs = decoded_pairs(&out);
        let client_ids: Vec<&String> = pairs
            .iter()
            .filter(|(k, _)| k == "client_id")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(client_ids, vec!["proxy-id"]);
    }

    #[test]
    fn rewrite_preserves_non_client_params_in_order_with_duplicates() {
        let out = rewrite_client_auth_params(
            "scope=read&resource=a&state=xyz&resource=b&code_verifier=v",
            "proxy-id",
        );
        let pairs = decoded_pairs(&out);
        let non_client: Vec<(String, String)> = pairs
            .into_iter()
            .filter(|(k, _)| k != "client_id")
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
    }

    #[test]
    fn rewrite_roundtrips_values_with_special_characters() {
        let input = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", "a&b=c+d")
            .append_pair("scope", "réad ✓")
            .finish();
        let out = rewrite_client_auth_params(&input, "proxy-id");
        let pairs = decoded_pairs(&out);
        assert!(pairs.contains(&("state".to_owned(), "a&b=c+d".to_owned())));
        assert!(pairs.contains(&("scope".to_owned(), "réad ✓".to_owned())));
    }

    #[test]
    fn rewrite_injects_client_id_when_absent() {
        let out = rewrite_client_auth_params("scope=read", "proxy-id");
        assert!(decoded_pairs(&out).contains(&("client_id".to_owned(), "proxy-id".to_owned())));
    }

    #[test]
    fn looks_like_jwt_valid() {
        // Minimal valid JWT structure: base64({"alg":"RS256"}).base64({}).sig
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.signature");
        assert!(looks_like_jwt(&token));
    }

    #[test]
    fn looks_like_jwt_rejects_opaque_token() {
        assert!(!looks_like_jwt("dGhpcyBpcyBhbiBvcGFxdWUgdG9rZW4"));
    }

    #[test]
    fn looks_like_jwt_rejects_two_segments() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}");
        let token = format!("{header}.payload");
        assert!(!looks_like_jwt(&token));
    }

    #[test]
    fn looks_like_jwt_rejects_four_segments() {
        assert!(!looks_like_jwt("a.b.c.d"));
    }

    #[test]
    fn looks_like_jwt_rejects_no_alg() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.sig");
        assert!(!looks_like_jwt(&token));
    }

    #[test]
    fn protected_resource_metadata_shape() {
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
            #[allow(
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
        assert_eq!(meta["resource"], "https://mcp.example.com/mcp");
        assert_eq!(meta["authorization_servers"][0], "https://mcp.example.com");
        assert_eq!(meta["scopes_supported"].as_array().unwrap().len(), 2);
        assert_eq!(meta["bearer_methods_supported"][0], "header");
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

    #[test]
    fn validate_accepts_all_https_urls() {
        let cfg = validation_https_config();
        cfg.validate().expect("all-HTTPS config must validate");
    }

    #[test]
    fn validate_rejects_empty_audience() {
        let mut cfg = validation_https_config();
        cfg.audience = String::new();
        let err = cfg.validate().expect_err("empty audience must be rejected");
        assert!(
            err.to_string().contains("oauth.audience"),
            "error must reference oauth.audience; got {err}"
        );
    }

    fn assert_config_nonzero_error(err: crate::error::RmcpServerKitError, field: &str) {
        let crate::error::RmcpServerKitError::Config(msg) = err else {
            panic!("expected Config error for {field}");
        };
        assert!(
            msg.contains(field) && msg.contains("must be nonzero"),
            "error must name {field} and say must be nonzero; got {msg:?}"
        );
    }

    #[test]
    fn rejects_zero_max_jwks_keys() {
        let mut cfg = validation_https_config();
        cfg.max_jwks_keys = 0;
        let err = cfg
            .validate()
            .expect_err("zero max_jwks_keys must be rejected");
        assert_config_nonzero_error(err, "oauth.max_jwks_keys");
    }

    #[test]
    fn rejects_zero_jwks_max_response_bytes() {
        let mut cfg = validation_https_config();
        cfg.jwks_max_response_bytes = 0;
        let err = cfg
            .validate()
            .expect_err("zero jwks_max_response_bytes must be rejected");
        assert_config_nonzero_error(err, "oauth.jwks_max_response_bytes");
    }

    #[test]
    fn oauth_config_partial_table_deserializes_then_validate_rejects_empty_fields() {
        let toml_src = r#"
role_claim = "realm_access.roles"

[[role_mappings]]
claim_value = "mcp-admin"
role = "admin"
"#;
        let cfg: OAuthConfig = toml::from_str(toml_src).expect(
            "partial [oauth] table without issuer/audience/jwks_uri must deserialize via serde(default)",
        );
        assert_eq!(cfg.issuer, "", "omitted issuer must default to empty");
        assert_eq!(cfg.audience, "", "omitted audience must default to empty");
        assert_eq!(cfg.jwks_uri, "", "omitted jwks_uri must default to empty");
        assert_eq!(cfg.role_claim.as_deref(), Some("realm_access.roles"));
        assert_eq!(cfg.role_mappings.len(), 1);
        cfg.validate().expect_err(
            "empty issuer/jwks_uri/audience must still fail validate() (parse-don't-validate)",
        );
    }

    #[test]
    fn validate_rejects_unparseable_jwks_cache_ttl() {
        let mut cfg = validation_https_config();
        cfg.jwks_cache_ttl = "not-a-duration".into();
        let err = cfg
            .validate()
            .expect_err("malformed jwks_cache_ttl must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("jwks_cache_ttl"),
            "error must reference offending field; got {msg:?}"
        );
    }

    #[test]
    fn validate_rejects_http_jwks_uri() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "http://auth.example.com/.well-known/jwks.json".into();
        let err = cfg.validate().expect_err("http jwks_uri must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("oauth.jwks_uri") && msg.contains("https"),
            "error must reference offending field + scheme requirement; got {msg:?}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_authorize_url() {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "http://idp.example.com/authorize", // <-- HTTP, must be rejected
                "https://idp.example.com/token",
                "client",
            )
            .build(),
        );
        let err = cfg
            .validate()
            .expect_err("http authorize_url must be rejected");
        assert!(
            err.to_string().contains("oauth.proxy.authorize_url"),
            "error must reference proxy.authorize_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_token_url() {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "http://idp.example.com/token", // <-- HTTP, must be rejected
                "client",
            )
            .build(),
        );
        let err = cfg.validate().expect_err("http token_url must be rejected");
        assert!(
            err.to_string().contains("oauth.proxy.token_url"),
            "error must reference proxy.token_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_introspection_and_revocation_urls() {
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
        let err = cfg
            .validate()
            .expect_err("http introspection_url must be rejected");
        assert!(err.to_string().contains("oauth.proxy.introspection_url"));

        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .revocation_url("http://idp.example.com/revoke")
            .build(),
        );
        let err = cfg
            .validate()
            .expect_err("http revocation_url must be rejected");
        assert!(err.to_string().contains("oauth.proxy.revocation_url"));
    }

    // -- M3 regression: unauthenticated /introspect and /revoke must fail validate --

    #[test]
    fn validate_rejects_exposed_admin_endpoints_without_auth() {
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
        let err = cfg
            .validate()
            .expect_err("expose_admin_endpoints without auth must fail");
        let msg = err.to_string();
        assert!(msg.contains("require_auth_on_admin_endpoints"), "{msg}");
        assert!(
            msg.contains("allow_unauthenticated_admin_endpoints"),
            "{msg}"
        );
    }

    #[test]
    fn validate_accepts_exposed_admin_endpoints_with_auth() {
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
            .expect("authed admin endpoints must validate");
    }

    #[test]
    fn validate_accepts_exposed_admin_endpoints_with_explicit_unauth_optout() {
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
            .expect("explicit unauth opt-out must validate");
    }

    #[test]
    fn validate_accepts_unexposed_admin_endpoints_without_auth() {
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
            .expect("unexposed admin endpoints must validate");
    }

    #[test]
    fn validate_rejects_http_token_exchange_url() {
        let mut cfg = validation_https_config();
        cfg.token_exchange = Some(TokenExchangeConfig::new(
            "http://idp.example.com/token".into(), // <-- HTTP
            "client".into(),
            None,
            None,
            "downstream".into(),
        ));
        let err = cfg
            .validate()
            .expect_err("http token_exchange.token_url must be rejected");
        assert!(
            err.to_string().contains("oauth.token_exchange.token_url"),
            "error must reference token_exchange.token_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_unparseable_url() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "not a url".into();
        let err = cfg
            .validate()
            .expect_err("unparseable URL must be rejected");
        assert!(err.to_string().contains("invalid URL"));
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "file:///etc/passwd".into();
        let err = cfg.validate().expect_err("file:// scheme must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("must use https scheme") && msg.contains("file"),
            "error must reject non-http(s) schemes; got {msg:?}"
        );
    }

    #[test]
    fn validate_accepts_http_with_escape_hatch() {
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
        cfg.token_exchange = Some(TokenExchangeConfig::new(
            "http://idp.local/token".into(),
            "client".into(),
            Some(secrecy::SecretString::new("dev-secret".into())),
            None,
            "downstream".into(),
        ));
        cfg.validate()
            .expect("escape hatch must permit http on all URL fields");
    }

    #[test]
    fn validate_with_escape_hatch_still_rejects_unparseable() {
        // Even with the escape hatch, malformed URLs are rejected so
        // garbage configuration cannot silently degrade to no-op.
        let mut cfg = validation_https_config();
        cfg.allow_http_oauth_urls = true;
        cfg.jwks_uri = "::not-a-url::".into();
        cfg.validate()
            .expect_err("escape hatch must NOT bypass URL parsing");
    }

    #[tokio::test]
    async fn jwks_cache_rejects_redirect_downgrade_to_http() {
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
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let policy = reqwest::redirect::Policy::custom(|attempt| {
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
        let test_bypass: crate::ssrf_resolver::TestLoopbackBypass = Arc::new(AtomicBool::new(true));
        let allowlist = Arc::new(crate::ssrf::CompiledSsrfAllowlist::default());
        let resolver: Arc<dyn reqwest::dns::Resolve> = Arc::new(
            crate::ssrf_resolver::SsrfScreeningResolver::new(Arc::clone(&allowlist), test_bypass),
        );
        let client = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(policy)
            .build()
            .expect("test client builds");

        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("redirect policy must reject scheme downgrade");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("redirect to non-HTTPS URL refused")
                || chain.to_lowercase().contains("redirect"),
            "error must surface redirect-policy rejection; got {chain:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests with in-process RSA keypair + wiremock JWKS
    // -----------------------------------------------------------------------

    use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};

    /// Generate an RSA-2048 keypair and return `(private_pem, jwks_json)`.
    fn generate_test_keypair(kid: &str) -> (String, serde_json::Value) {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keypair generation");
        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PKCS8 PEM export")
            .to_string();

        let public_key = private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e
            }]
        });

        (private_pem, jwks)
    }

    /// Mint a signed JWT with the given claims.
    fn mint_token(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        subject: &str,
        scope: &str,
    ) -> String {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .expect("encoding key from PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "scope": scope,
            "exp": now + 3600,
            "iat": now,
        });

        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding")
    }

    /// Mint a signed JWT WITHOUT a `sub` claim (for `require_subject` tests).
    fn mint_token_without_sub(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        scope: &str,
    ) -> String {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .expect("encoding key from PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "scope": scope,
            "exp": now + 3600,
            "iat": now,
        });
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding")
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
            #[allow(
                deprecated,
                reason = "test fixture: explicit value for the deprecated field"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        }
    }

    fn test_cache(config: &OAuthConfig) -> JwksCache {
        JwksCache::new(config).unwrap().__test_allow_loopback_ssrf()
    }

    // -- H2: expired JWKS cache must fail closed when refresh cannot succeed --

    /// Prime a cache (with `ttl`) from a valid JWKS, confirm the kid landed,
    /// then repoint the endpoint at a 503 so any later refresh fails. Returns
    /// the cache, a matching-`aud` token for the primed kid, and the live mock
    /// server (kept alive by the caller).
    async fn h2_prime_then_break(ttl: &str) -> (JwksCache, String, wiremock::MockServer) {
        let kid = "test-h2-stale";
        let (pem, jwks) = generate_test_keypair(kid);
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.jwks_cache_ttl = ttl.into();
        let cache = test_cache(&config);
        cache.__test_refresh_now().await.expect("prime JWKS cache");
        assert!(cache.__test_has_kid(kid).await, "kid must be primed");

        mock_server.reset().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        );
        (cache, token, mock_server)
    }

    #[test]
    fn build_key_cache_last_duplicate_kid_wins() {
        let (_pem, jwks_json) = generate_test_keypair("dup-kid");
        let entry = jwks_json["keys"][0].clone();
        let merged = serde_json::json!({ "keys": [entry.clone(), entry] });
        let jwks: JwkSet = serde_json::from_value(merged).expect("merged jwks parses");
        assert_eq!(jwks.keys.len(), 2, "fixture must carry two colliding kids");

        let (keys, unnamed) = build_key_cache(&jwks, 16).expect("under key cap");
        assert_eq!(keys.len(), 1, "colliding kids collapse to one entry");
        assert!(keys.contains_key("dup-kid"));
        assert!(unnamed.is_empty());
    }

    #[test]
    fn truncate_kid_for_log_bounds_hostile_input() {
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
    }

    #[test]
    fn truncate_kid_for_log_splits_on_char_boundary() {
        let multibyte = "\u{1f512}".repeat(MAX_LOGGED_KID_CHARS + 10);
        let (truncated, was_truncated) = truncate_kid_for_log(&multibyte);
        assert!(was_truncated);
        assert!(truncated.starts_with('\u{1f512}'));
        assert!(truncated.ends_with("...(truncated)"));
    }

    #[test]
    fn truncate_kid_for_log_flag_marks_exact_boundary_as_untruncated() {
        let exact = "k".repeat(MAX_LOGGED_KID_CHARS);
        let (out, was_truncated) = truncate_kid_for_log(&exact);
        assert!(!was_truncated, "a kid exactly at the cap is not truncated");
        assert_eq!(out, exact);
    }

    #[tokio::test]
    async fn expired_jwks_fails_closed_when_refresh_fails() {
        let (cache, token, _mock) = h2_prime_then_break("80ms").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let failure = cache
            .validate_token_with_reason(&token)
            .await
            .expect_err("an expired cache whose refresh fails must not serve the stale key");
        assert_eq!(failure, JwtValidationFailure::Invalid);
    }

    #[tokio::test]
    async fn fresh_jwks_still_validates() {
        let kid = "test-h2-fresh";
        let (pem, jwks) = generate_test_keypair(kid);
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // 5m TTL, reachable JWKS
        let cache = test_cache(&config);
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "h2-fresh-client",
            "mcp:read",
        );
        cache
            .validate_token_with_reason(&token)
            .await
            .expect("a reachable JWKS must still validate a matching token");
    }

    #[tokio::test]
    async fn cooldown_active_plus_expired_fails_closed() {
        let (cache, token, _mock) = h2_prime_then_break("80ms").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        // First attempt: no cooldown yet, so this triggers a (503) refresh that
        // records `last_refresh_attempt` and still fails closed.
        assert_eq!(
            cache
                .validate_token_with_reason(&token)
                .await
                .expect_err("first attempt must fail closed"),
            JwtValidationFailure::Invalid,
        );
        // Second attempt: the refresh cooldown is now active, so no refresh is
        // attempted -- the still-expired cache must not serve the stale key.
        let failure = cache
            .validate_token_with_reason(&token)
            .await
            .expect_err("cooldown-active + expired cache must still fail closed");
        assert_eq!(failure, JwtValidationFailure::Invalid);
    }

    #[tokio::test]
    async fn valid_jwt_returns_identity() {
        let kid = "test-key-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "ci-bot",
            "mcp:read mcp:other",
        );

        let identity = cache.validate_token(&token).await;
        assert!(identity.is_some(), "valid JWT should authenticate");
        let id = identity.unwrap();
        assert_eq!(id.name, "ci-bot");
        assert_eq!(id.role, "viewer"); // first matching scope
        assert_eq!(id.method, AuthMethod::OAuthJwt);
    }

    // -- L4: kid-strict key lookup + require_subject --

    #[test]
    fn unknown_kid_with_named_keys_rejected() {
        let mut keys = HashMap::new();
        keys.insert(
            "kid-1".to_owned(),
            (Algorithm::RS256, DecodingKey::from_secret(b"named")),
        );
        let cached = CachedKeys {
            keys,
            unnamed_keys: vec![(Algorithm::RS256, DecodingKey::from_secret(b"unnamed"))],
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
    }

    #[test]
    fn no_kid_token_matches_unnamed_key() {
        let mut keys = HashMap::new();
        keys.insert(
            "kid-1".to_owned(),
            (Algorithm::RS256, DecodingKey::from_secret(b"named")),
        );
        let cached = CachedKeys {
            keys,
            unnamed_keys: vec![(Algorithm::RS256, DecodingKey::from_secret(b"unnamed"))],
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };
        // A token with no kid falls back to an unnamed key, supporting JWKS
        // entries that legitimately omit `kid`.
        assert!(lookup_key(&cached, None, Algorithm::RS256).is_some());
    }

    #[tokio::test]
    async fn require_subject_rejects_subject_less() {
        let kid = "test-key-reqsub";
        let (pem, jwks) = generate_test_keypair(kid);
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.require_subject = true;
        let cache = test_cache(&config);

        let no_sub = mint_token_without_sub(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "mcp:read",
        );
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
        );
        assert!(
            cache.validate_token(&with_sub).await.is_some(),
            "a token carrying sub must still be accepted"
        );
    }

    #[tokio::test]
    async fn subject_less_token_accepted_by_default() {
        let kid = "test-key-nosub-default";
        let (pem, jwks) = generate_test_keypair(kid);
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // require_subject defaults to false
        let cache = test_cache(&config);
        let no_sub = mint_token_without_sub(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "mcp:read",
        );
        assert!(
            cache.validate_token(&no_sub).await.is_some(),
            "the default policy must accept a sub-less (client-credentials) token"
        );
    }

    #[tokio::test]
    async fn credential_post_does_not_follow_redirect() {
        // M7: a 307 from the token endpoint must NOT be followed, or the
        // client_secret-bearing body would be re-sent to the redirect host.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/followed"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0) // verified on MockServer drop: must never be hit
            .mount(&mock)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/followed", mock.uri()).as_str()),
            )
            .mount(&mock)
            .await;

        let client = OauthHttpClient::build(None).expect("build oauth http client");
        let resp = client
            .credential_client
            .post(format!("{}/token", mock.uri()))
            .body("grant_type=client_credentials")
            .send()
            .await
            .expect("request sent");
        assert_eq!(
            resp.status().as_u16(),
            307,
            "credential client must surface the 307 rather than follow it"
        );
    }

    fn test_token_exchange_config(token_url: String) -> TokenExchangeConfig {
        TokenExchangeConfig::new(
            token_url,
            "mcp-client".into(),
            Some(secrecy::SecretString::new("test-client-secret".into())),
            None,
            "downstream-api".into(),
        )
    }

    fn exchange_response(access_token: &str, issued_token_type: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": access_token,
            "expires_in": 3600_u64,
            "issued_token_type": issued_token_type,
        })
    }

    fn unsigned_jwt_with_claims(claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims json"));
        format!("{header}.{payload}.signature")
    }

    fn test_exchange_client() -> OauthHttpClient {
        let config = OAuthConfig::builder(
            "http://auth.test.local",
            "mcp",
            "http://auth.test.local/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        OauthHttpClient::build(Some(&config))
            .expect("build oauth http client")
            .__test_allow_loopback_ssrf()
    }

    fn unavailable_loopback_token_url() -> String {
        "http://127.0.0.1:1/token?client_secret=super-secret".to_owned()
    }

    async fn recorded_request_count(mock: &wiremock::MockServer) -> usize {
        mock.received_requests()
            .await
            .expect("wiremock request recording is enabled")
            .len()
    }

    async fn wait_for_recorded_request(mock: &wiremock::MockServer) {
        // Liveness wait, not a latency bound: it returns as soon as the mock
        // records the request, so a generous ceiling costs nothing on success
        // and only makes a genuine hang fail slower.
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if recorded_request_count(mock).await > 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("token endpoint must record the in-flight request before cancellation");
    }

    async fn wait_for_log_contains(logs: &CapturedLogs, needle: &str) {
        // Must comfortably exceed the mock response delay: the detached task
        // cannot emit its audit line until the upstream exchange completes, so
        // this bound is `mock delay + slack`, not a latency expectation. It is
        // a bounded wait -- on success it returns as soon as the line appears.
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if logs.contents().contains(needle) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached token exchange must eventually emit its audit log");
    }

    #[tokio::test]
    async fn send_screened_request_failure_sanitizes_url_and_reqwest_error() {
        let client = test_exchange_client();
        let screened_url = unavailable_loopback_token_url();
        let request_url = screened_url.replacen("//", "//u:p@", 1);

        let error = client
            .send_screened(
                &screened_url,
                client
                    .credential_client
                    .post(&request_url)
                    .body("grant_type=test"),
            )
            .await
            .expect_err("closed loopback port must fail the request");

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
    }

    #[tokio::test]
    async fn exchange_token_request_failure_log_sanitizes_token_url() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = test_exchange_client();
        let token_url = unavailable_loopback_token_url();
        let config = test_token_exchange_config(token_url);
        let error = exchange_token(&client, &config, "subject-token")
            .await
            .expect_err("closed loopback port must fail exchange");

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
    }

    #[tokio::test]
    async fn exchange_token_with_cancel_precancel_does_not_send() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(exchange_response(
                    "downstream-token",
                    "urn:ietf:params:oauth:token-type:access_token",
                )),
            )
            .mount(&mock)
            .await;

        let client = test_exchange_client();
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = tokio_util::sync::CancellationToken::new();
        ct.cancel();

        let outcome =
            exchange_token_with_cancel(&client, &config, "subject-token", &ct, None).await;

        assert!(
            matches!(outcome, crate::cancel::DetachOutcome::Cancelled),
            "pre-cancelled exchanges must not start work"
        );
        assert_eq!(
            recorded_request_count(&mock).await,
            0,
            "pre-cancel check must happen before cloning/spawning/sending"
        );
    }

    #[tokio::test]
    async fn exchange_token_with_cancel_completes_normally() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(exchange_response(
                    "downstream-token",
                    "urn:ietf:params:oauth:token-type:access_token",
                )),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let client = test_exchange_client();
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = tokio_util::sync::CancellationToken::new();

        let outcome =
            exchange_token_with_cancel(&client, &config, "subject-token", &ct, None).await;

        let crate::cancel::DetachOutcome::Completed(Ok(token)) = outcome else {
            panic!("uncancelled exchange must complete successfully")
        };
        assert_eq!(token.access_token, "downstream-token");
        mock.verify().await;
    }

    #[tokio::test]
    async fn exchange_token_with_cancel_detaches_and_audits_abandoned_token() {
        let mock = wiremock::MockServer::start().await;
        let long_issued_token_type = format!(
            "urn:ietf:params:oauth:token-type:{}",
            "x".repeat(MAX_LOGGED_KID_CHARS + 32)
        );
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
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
            .expect("mock token URL parses")
            .host_str()
            .expect("mock token URL has host")
            .to_owned();
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("rmcp_server_kit=debug"))
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = test_exchange_client();
        let config = test_token_exchange_config(token_url);
        let ct = tokio_util::sync::CancellationToken::new();
        let task_ct = ct.clone();
        let handle = tokio::spawn(async move {
            exchange_token_with_cancel(&client, &config, "subject-token", &task_ct, None).await
        });

        wait_for_recorded_request(&mock).await;
        let cancelled_at = Instant::now();
        ct.cancel();
        let outcome = handle.await.expect("wrapper task must not panic");

        assert!(
            matches!(outcome, crate::cancel::DetachOutcome::Cancelled),
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
        .await;
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
    }

    #[tokio::test]
    async fn exchange_token_with_cancel_detached_jwt_success_does_not_log_claims() {
        let mock = wiremock::MockServer::start().await;
        let jwt = unsigned_jwt_with_claims(&serde_json::json!({
            "sub": "detached-subject",
            "aud": "detached-audience",
            "azp": "detached-client",
            "iss": "https://issuer.example.test/realm",
        }));
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
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
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = test_exchange_client();
        let config = test_token_exchange_config(format!("{}/token", mock.uri()));
        let ct = tokio_util::sync::CancellationToken::new();
        let task_ct = ct.clone();
        let handle = tokio::spawn(async move {
            exchange_token_with_cancel(&client, &config, "subject-token", &task_ct, None).await
        });

        wait_for_recorded_request(&mock).await;
        ct.cancel();
        let outcome = handle.await.expect("wrapper task must not panic");
        assert!(
            matches!(outcome, crate::cancel::DetachOutcome::Cancelled),
            "caller must get cancellation while spawned JWT exchange continues"
        );

        wait_for_log_contains(
            &logs,
            "token exchange minted downstream token after caller detached",
        )
        .await;
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
    }

    #[tokio::test]
    async fn exchange_token_with_cancel_completion_wins_tie() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Ok(ExchangedToken {
            access_token: "tie-winner".into(),
            expires_in: Some(3600),
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".into()),
        }))
        .expect("test receiver is alive");
        let ct = tokio_util::sync::CancellationToken::new();
        ct.cancel();

        let outcome = receive_exchange_result_with_cancel(rx, &ct, None).await;

        let crate::cancel::DetachOutcome::Completed(Ok(token)) = outcome else {
            panic!("ready completion must win over ready cancellation under biased select")
        };
        assert_eq!(token.access_token, "tie-winner");
    }

    #[tokio::test]
    async fn jwks_get_still_follows_screened_redirect() {
        // M7 regression: adding the no-redirect credential client must NOT
        // change the JWKS/discovery client, which still follows a redirect
        // whose every hop passes the SSRF screen. `allow_http` plus a loopback
        // allowlist entry let the http->http hop to the wiremock literal IP
        // clear `evaluate_oauth_redirect`'s scheme and per-hop SSRF checks.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(302).insert_header(
                "location",
                format!("{}/jwks-final.json", mock.uri()).as_str(),
            ))
            .mount(&mock)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks-final.json"))
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

        let client = OauthHttpClient::build(Some(&config)).expect("build oauth http client");
        let resp = client
            .inner
            .get(format!("{}/jwks.json", mock.uri()))
            .send()
            .await
            .expect("request sent");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "JWKS client must follow the screened redirect to the final endpoint"
        );
        assert_eq!(resp.text().await.expect("response body"), "reached");
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let kid = "test-key-2";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://wrong-issuer.example.com", // wrong
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let kid = "test-key-3";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://wrong-audience.example.com", // wrong
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn expired_jwt_rejected() {
        let kid = "test-key-4";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        // Create a token that expired 2 minutes ago (past the 60s leeway).
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
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
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding");

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn no_matching_scope_rejected() {
        let kid = "test-key-5";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "limited-bot",
            "some:other:scope", // no matching scope
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn wrong_signing_key_rejected() {
        let kid = "test-key-6";
        let (_pem, jwks) = generate_test_keypair(kid);

        // Generate a DIFFERENT keypair for signing (attacker key).
        let (attacker_pem, _) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        // Sign with attacker key but JWKS has legitimate public key.
        let token = mint_token(
            &attacker_pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn admin_scope_maps_to_ops_role() {
        let kid = "test-key-7";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "admin-bot",
            "mcp:admin",
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.role, "ops");
        assert_eq!(id.name, "admin-bot");
    }

    #[tokio::test]
    async fn jwks_server_down_returns_none() {
        // Point to a non-existent server.
        let config = test_config("http://127.0.0.1:1/jwks.json");
        let cache = test_cache(&config);

        let kid = "orphan-key";
        let (pem, _) = generate_test_keypair(kid);
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "bot",
            "mcp:read",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    // -----------------------------------------------------------------------
    // resolve_claim_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_claim_path_flat_string() {
        let mut extra = HashMap::new();
        extra.insert(
            "scope".into(),
            serde_json::Value::String("mcp:read mcp:admin".into()),
        );
        let values = resolve_claim_path(&extra, "scope");
        assert_eq!(values, vec!["mcp:read", "mcp:admin"]);
    }

    #[test]
    fn resolve_claim_path_flat_array() {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".into(),
            serde_json::json!(["mcp-admin", "mcp-viewer"]),
        );
        let values = resolve_claim_path(&extra, "roles");
        assert_eq!(values, vec!["mcp-admin", "mcp-viewer"]);
    }

    #[test]
    fn resolve_claim_path_nested_keycloak() {
        let mut extra = HashMap::new();
        extra.insert(
            "realm_access".into(),
            serde_json::json!({"roles": ["uma_authorization", "mcp-admin"]}),
        );
        let values = resolve_claim_path(&extra, "realm_access.roles");
        assert_eq!(values, vec!["uma_authorization", "mcp-admin"]);
    }

    #[test]
    fn resolve_claim_path_missing_returns_empty() {
        let extra = HashMap::new();
        assert!(resolve_claim_path(&extra, "nonexistent.path").is_empty());
    }

    #[test]
    fn resolve_claim_path_numeric_leaf_returns_empty() {
        let mut extra = HashMap::new();
        extra.insert("count".into(), serde_json::json!(42));
        assert!(resolve_claim_path(&extra, "count").is_empty());
    }

    fn make_claims(json: serde_json::Value) -> Claims {
        serde_json::from_value(json).expect("test claims must deserialize")
    }

    #[test]
    fn first_class_scope_claim_splits_on_whitespace() {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "scope": "read write admin",
        }));
        let values = first_class_claim_values(&claims, "scope");
        assert_eq!(values, vec!["read", "write", "admin"]);
    }

    #[test]
    fn first_class_sub_claim_returns_single_value() {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "sub": "service-account-orders",
        }));
        let values = first_class_claim_values(&claims, "sub");
        assert_eq!(values, vec!["service-account-orders"]);
    }

    #[test]
    fn first_class_aud_claim_returns_every_audience() {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
            "aud": ["api-a", "api-b"],
        }));
        let values = first_class_claim_values(&claims, "aud");
        assert_eq!(values, vec!["api-a", "api-b"]);
    }

    #[test]
    fn first_class_unknown_path_returns_empty() {
        let claims = make_claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 9_999_999_999_u64,
        }));
        assert!(first_class_claim_values(&claims, "realm_access.roles").is_empty());
    }

    // -----------------------------------------------------------------------
    // role_claim integration tests (wiremock)
    // -----------------------------------------------------------------------

    /// Mint a JWT with arbitrary custom claims (for `role_claim` testing).
    fn mint_token_with_claims(private_pem: &str, kid: &str, claims: &serde_json::Value) -> String {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .expect("encoding key from PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding")
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
            #[allow(
                deprecated,
                reason = "test fixture: explicit value for the deprecated field"
            )]
            strict_audience_validation: None,
            audience_validation_mode: None,
            jwks_max_response_bytes: default_jwks_max_bytes(),
            ssrf_allowlist: None,
        }
    }

    #[tokio::test]
    async fn screen_oauth_target_rejects_literal_ip() {
        let err = screen_oauth_target(
            "https://127.0.0.1/jwks.json",
            false,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect_err("literal IPs must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("literal IPv4 addresses are forbidden"));
    }

    #[tokio::test]
    async fn screen_oauth_target_rejects_private_dns_resolution() {
        let err = screen_oauth_target(
            "https://localhost/jwks.json",
            false,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect_err("localhost resolution must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("blocked IP") && msg.contains("loopback"),
            "got {msg:?}"
        );
    }

    #[tokio::test]
    async fn screen_oauth_target_rejects_literal_ip_even_with_allow_http() {
        let err = screen_oauth_target(
            "http://127.0.0.1/jwks.json",
            true,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect_err("literal IPs must still be rejected when http is allowed");
        let msg = err.to_string();
        assert!(msg.contains("literal IPv4 addresses are forbidden"));
    }

    #[tokio::test]
    async fn screen_oauth_target_rejects_private_dns_even_with_allow_http() {
        let err = screen_oauth_target(
            "http://localhost/jwks.json",
            true,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect_err("private DNS resolution must still be rejected when http is allowed");
        let msg = err.to_string();
        assert!(
            msg.contains("blocked IP") && msg.contains("loopback"),
            "got {msg:?}"
        );
    }

    #[tokio::test]
    async fn screen_oauth_target_allows_public_hostname() {
        screen_oauth_target(
            "https://example.com/.well-known/jwks.json",
            false,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect("public hostname should pass screening");
    }

    // -----------------------------------------------------------------------
    // Operator SSRF allowlist (1.4.0)
    // -----------------------------------------------------------------------

    /// Helper: compile an allowlist from string literals.
    fn make_allowlist(hosts: &[&str], cidrs: &[&str]) -> crate::ssrf::CompiledSsrfAllowlist {
        let raw = OAuthSsrfAllowlist {
            hosts: hosts.iter().map(|s| (*s).to_owned()).collect(),
            cidrs: cidrs.iter().map(|s| (*s).to_owned()).collect(),
        };
        compile_oauth_ssrf_allowlist(&raw).expect("test allowlist compiles")
    }

    #[test]
    fn compile_oauth_ssrf_allowlist_lowercases_and_dedupes_hosts() {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["RHBK.ops.example.com".into(), "rhbk.ops.example.com".into()],
            cidrs: vec![],
        };
        let compiled = compile_oauth_ssrf_allowlist(&raw).expect("compiles");
        assert_eq!(compiled.host_count(), 1);
        assert!(compiled.host_allowed("rhbk.ops.example.com"));
        assert!(compiled.host_allowed("RHBK.OPS.EXAMPLE.COM"));
    }

    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_literal_ip_in_hosts() {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["10.0.0.1".into()],
            cidrs: vec![],
        };
        let err = compile_oauth_ssrf_allowlist(&raw).expect_err("literal IP in hosts");
        assert!(err.contains("literal IPs are forbidden"), "got {err:?}");
    }

    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_host_with_port() {
        let raw = OAuthSsrfAllowlist {
            hosts: vec!["rhbk.ops.example.com:8443".into()],
            cidrs: vec![],
        };
        let err = compile_oauth_ssrf_allowlist(&raw).expect_err("host:port");
        assert!(err.contains("must be a bare DNS hostname"), "got {err:?}");
    }

    // -- L3: internal-hostname-suffix pre-DNS denylist --

    #[test]
    fn internal_suffix_rejected_by_default() {
        let allow = crate::ssrf::CompiledSsrfAllowlist::default();
        for h in ["idp.internal", "svc.local", "x.localhost", "idp.internal."] {
            assert!(oauth_internal_suffix_blocked(h, &allow), "{h}");
        }
    }

    #[test]
    fn exact_allowlisted_internal_permitted() {
        let allow = make_allowlist(&["idp.internal"], &[]);
        assert!(!oauth_internal_suffix_blocked("idp.internal", &allow));
        assert!(!oauth_internal_suffix_blocked("idp.internal.", &allow));
    }

    #[test]
    fn subdomain_of_allowlisted_internal_still_rejected() {
        let allow = make_allowlist(&["idp.internal"], &[]);
        assert!(oauth_internal_suffix_blocked("sub.idp.internal", &allow));
    }

    #[test]
    fn cidr_allowlist_does_not_bypass_suffix_denylist() {
        let allow = make_allowlist(&[], &["10.0.0.0/8"]);
        assert!(oauth_internal_suffix_blocked("idp.internal", &allow));
    }

    #[test]
    fn public_hostname_not_blocked_by_suffix() {
        let allow = crate::ssrf::CompiledSsrfAllowlist::default();
        assert!(!oauth_internal_suffix_blocked("idp.example.com", &allow));
    }

    #[test]
    fn compile_oauth_ssrf_allowlist_rejects_invalid_cidr() {
        let raw = OAuthSsrfAllowlist {
            hosts: vec![],
            cidrs: vec!["not-a-cidr".into()],
        };
        let err = compile_oauth_ssrf_allowlist(&raw).expect_err("invalid CIDR");
        assert!(err.contains("oauth.ssrf_allowlist.cidrs[0]"), "got {err:?}");
    }

    #[test]
    fn validate_rejects_misconfigured_allowlist() {
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
        let err = cfg
            .validate()
            .expect_err("literal IP host must be rejected");
        assert!(
            err.to_string().contains("oauth.ssrf_allowlist"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn screen_oauth_target_with_allowlist_emits_helpful_error() {
        // localhost resolves to loopback; with a *non-empty* allowlist that
        // doesn't cover loopback, we expect the new verbose error referencing
        // the config field.
        let allow = make_allowlist(&["other.example.com"], &["10.0.0.0/8"]);
        let err = screen_oauth_target("https://localhost/jwks.json", false, &allow)
            .await
            .expect_err("loopback must still be blocked when not in allowlist");
        let msg = err.to_string();
        assert!(msg.contains("OAuth target blocked"), "got {msg:?}");
        assert!(msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");
        assert!(msg.contains("SECURITY.md"), "got {msg:?}");
    }

    #[tokio::test]
    async fn screen_oauth_target_empty_allowlist_uses_legacy_message() {
        // The default (empty) allowlist must continue to emit the
        // pre-1.4.0 wording so existing operator runbooks keep working.
        let err = screen_oauth_target(
            "https://localhost/jwks.json",
            false,
            &crate::ssrf::CompiledSsrfAllowlist::default(),
        )
        .await
        .expect_err("loopback rejection");
        let msg = err.to_string();
        assert!(msg.contains("blocked IP"), "got {msg:?}");
        assert!(msg.contains("loopback"), "got {msg:?}");
        // The legacy message must NOT advertise the new knob.
        assert!(!msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");
    }

    #[tokio::test]
    async fn screen_oauth_target_allows_loopback_when_host_allowlisted() {
        // localhost -> 127.0.0.1; allowlisting the hostname must let it through.
        let allow = make_allowlist(&["localhost"], &[]);
        screen_oauth_target("https://localhost/jwks.json", false, &allow)
            .await
            .expect("allowlisted host must pass");
    }

    #[tokio::test]
    async fn screen_oauth_target_allows_loopback_when_cidr_allowlisted() {
        // localhost may resolve to 127.0.0.1 and/or ::1 depending on the OS;
        // allowlist both loopback ranges to make the test stable cross-platform.
        let allow = make_allowlist(&[], &["127.0.0.0/8", "::1/128"]);
        screen_oauth_target("https://localhost/jwks.json", false, &allow)
            .await
            .expect("allowlisted CIDR must pass");
    }

    #[tokio::test]
    async fn jwks_cache_rejects_misconfigured_allowlist_at_startup() {
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
            panic!("invalid CIDR must fail JwksCache::new")
        };
        let msg = err.to_string();
        assert!(msg.contains("oauth.ssrf_allowlist"), "got {msg:?}");
    }

    #[tokio::test]
    async fn jwks_cache_new_invalid_ttl_is_err() {
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
            panic!("invalid jwks_cache_ttl must fail JwksCache::new")
        };
        let msg = err.to_string();
        assert!(msg.contains("jwks_cache_ttl"), "got {msg:?}");
    }

    #[tokio::test]
    async fn audience_default_is_strict() {
        let kid = "test-audience-azp-default";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

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
                "exp": now + 3600,
                "iat": now,
            }),
        );

        let failure = cache
            .validate_token_with_reason(&token)
            .await
            .expect_err("the default policy is Strict and must reject an azp-only match");
        assert_eq!(failure, JwtValidationFailure::Invalid);
    }

    #[tokio::test]
    async fn audience_warn_still_accepts_azp() {
        let kid = "test-audience-warn-optin";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Warn);
        let cache = test_cache(&config);

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
                "exp": now + 3600,
                "iat": now,
            }),
        );

        cache.validate_token_with_reason(&token).await.expect(
            "the audience_validation_mode=warn opt-out must still accept an azp-only match",
        );
    }

    #[tokio::test]
    async fn legacy_strict_false_maps_to_warn() {
        let kid = "test-audience-legacy-false";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        // Legacy opt-out: the deprecated bool set to Some(false) with the enum
        // unset must resolve to Warn, preserving the pre-3.2 azp-accepting path.
        #[allow(deprecated, reason = "covers the legacy bool compat mapping")]
        {
            config.strict_audience_validation = Some(false);
        }
        let cache = test_cache(&config);

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
                "exp": now + 3600,
                "iat": now,
            }),
        );

        cache
            .validate_token_with_reason(&token)
            .await
            .expect("strict_audience_validation=Some(false) must map to Warn and accept azp");
    }

    #[tokio::test]
    async fn aud_match_always_accepts() {
        let kid = "test-audience-aud-match";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // Strict by default
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "aud-match-client",
                "scope": "mcp:read",
                "exp": now + 3600,
                "iat": now,
            }),
        );

        cache
            .validate_token_with_reason(&token)
            .await
            .expect("a matching aud must be accepted even under the Strict default");
    }

    #[tokio::test]
    async fn strict_audience_validation_rejects_azp_only_match() {
        let kid = "test-audience-azp-strict";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        #[allow(deprecated, reason = "covers the legacy bool resolution path")]
        {
            config.strict_audience_validation = Some(true);
        }
        let cache = test_cache(&config);

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
                "exp": now + 3600,
                "iat": now,
            }),
        );

        let failure = cache
            .validate_token_with_reason(&token)
            .await
            .expect_err("strict audience validation must ignore azp fallback");
        assert_eq!(failure, JwtValidationFailure::Invalid);
    }

    #[tokio::test]
    async fn warn_mode_accepts_azp_only_match_and_warns_once() {
        let kid = "test-audience-warn-mode";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Warn);
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://some-other-resource.example.com",
            "azp": "https://mcp.test.local/mcp",
            "sub": "warn-client",
            "scope": "mcp:read",
            "exp": now + 3600,
            "iat": now,
        });
        let token = mint_token_with_claims(&pem, kid, &claims);

        let identity = cache
            .validate_token_with_reason(&token)
            .await
            .expect("warn mode must accept azp-only match");
        assert_eq!(identity.role, "viewer");
        assert!(
            cache.azp_fallback_warned.load(Ordering::Relaxed),
            "warn-once flag should be set after first azp-only match"
        );

        let token2 = mint_token_with_claims(&pem, kid, &claims);
        cache
            .validate_token_with_reason(&token2)
            .await
            .expect("warn mode must continue accepting subsequent matches");
        assert!(
            cache.azp_fallback_warned.load(Ordering::Relaxed),
            "warn-once flag must remain set; the assertion guards against accidental clearing"
        );
    }

    #[tokio::test]
    async fn permissive_mode_accepts_azp_only_match_silently() {
        let kid = "test-audience-permissive-mode";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let mut config = test_config(&jwks_uri);
        config.audience_validation_mode = Some(AudienceValidationMode::Permissive);
        let cache = test_cache(&config);

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
                "exp": now + 3600,
                "iat": now,
            }),
        );

        cache
            .validate_token_with_reason(&token)
            .await
            .expect("permissive mode must accept azp-only match");
        assert!(
            !cache.azp_fallback_warned.load(Ordering::Relaxed),
            "permissive mode must not flip the warn-once flag"
        );
        assert!(
            cache.azp_permissive_logged.load(Ordering::Relaxed),
            "permissive mode must record its own once-per-process log flag"
        );
    }

    #[test]
    fn audience_validation_mode_overrides_legacy_bool() {
        let mut config = OAuthConfig::default();
        #[allow(deprecated, reason = "covers the precedence rule for the legacy bool")]
        {
            config.strict_audience_validation = Some(false);
        }
        config.audience_validation_mode = Some(AudienceValidationMode::Strict);
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "explicit mode must override legacy false"
        );

        let mut config = OAuthConfig::default();
        #[allow(deprecated, reason = "covers the precedence rule for the legacy bool")]
        {
            config.strict_audience_validation = Some(true);
        }
        config.audience_validation_mode = Some(AudienceValidationMode::Permissive);
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Permissive,
            "explicit mode must override legacy true"
        );
    }

    #[test]
    fn audience_validation_mode_default_is_strict_when_unset() {
        let config = OAuthConfig::default();
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "unset mode + unset bool must resolve to Strict (the secure default)"
        );
    }

    #[test]
    fn audience_validation_legacy_bool_true_resolves_to_strict() {
        let mut config = OAuthConfig::default();
        #[allow(deprecated, reason = "covers the legacy bool resolution path")]
        {
            config.strict_audience_validation = Some(true);
        }
        assert_eq!(
            config.effective_audience_validation_mode(),
            AudienceValidationMode::Strict,
            "legacy bool=true must resolve to Strict for backward compat"
        );
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }
    }

    struct CapturedLogsWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    #[tokio::test]
    async fn jwks_response_size_cap_returns_none_and_logs_warning() {
        let kid = "oversized-jwks";
        let (_pem, jwks) = generate_test_keypair(kid);
        let mut oversized_body = serde_json::to_string(&jwks).expect("jwks json");
        oversized_body.push_str(&" ".repeat(4096));

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let cache = test_cache(&config);

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let result = cache.fetch_jwks().await;
        assert!(result.is_none(), "oversized JWKS must be dropped");
        assert!(
            logs.contents()
                .contains("JWKS response exceeded configured size cap"),
            "expected cap-exceeded warning in logs"
        );
    }

    /// A redirect to a userinfo-bearing target is rejected, and the
    /// rejection warn log must not echo the embedded credentials
    /// (sanitized to scheme+host+port only).
    #[tokio::test]
    async fn redirect_rejection_log_does_not_echo_credentials() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "https://u:p@redirect-target.example/next"),
            )
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

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
    }

    #[tokio::test]
    async fn jwks_fetch_failure_log_sanitizes_url_and_reqwest_error() {
        let config = test_config("http://127.0.0.1:1/jwks.json?client_secret=super-secret");
        let cache = test_cache(&config);

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

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
    }

    #[tokio::test]
    async fn role_claim_keycloak_nested_array() {
        let kid = "test-role-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "keycloak-user",
                "exp": now + 3600,
                "iat": now,
                "realm_access": { "roles": ["uma_authorization", "mcp-admin"] }
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "keycloak-user");
        assert_eq!(id.role, "ops");
    }

    #[tokio::test]
    async fn role_claim_flat_roles_array() {
        let kid = "test-role-2";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "azure-ad-user",
                "exp": now + 3600,
                "iat": now,
                "roles": ["MCP.Reader", "OtherApp.Admin"]
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "azure-ad-user");
        assert_eq!(id.role, "viewer");
    }

    #[tokio::test]
    async fn role_claim_no_matching_value_rejected() {
        let kid = "test-role-3";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "limited-user",
                "exp": now + 3600,
                "iat": now,
                "roles": ["some-other-role"]
            }),
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn role_claim_space_separated_string() {
        let kid = "test-role-4";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
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
        let cache = test_cache(&config);

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "custom-client",
                "exp": now + 3600,
                "iat": now,
                "custom_scope": "read audit"
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "custom-client");
        assert_eq!(id.role, "viewer");
    }

    #[tokio::test]
    async fn scope_backward_compat_without_role_claim() {
        // Verify existing `scopes` behavior still works when role_claim is None.
        let kid = "test-compat-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // role_claim: None, uses scopes
        let cache = test_cache(&config);

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "legacy-bot",
            "mcp:admin other:scope",
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "legacy-bot");
        assert_eq!(id.role, "ops"); // mcp:admin -> ops via scopes
    }

    // -----------------------------------------------------------------------
    // JWKS refresh cooldown tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn jwks_refresh_deduplication() {
        // Verify that concurrent requests with unknown kids result in exactly
        // one JWKS fetch, not one per request (deduplication via mutex).
        let kid = "test-dedup";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        let _mock = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = Arc::new(test_cache(&config));

        // Create 5 concurrent validation requests with the same valid token.
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "concurrent-bot",
            "mcp:read",
        );

        let mut handles = Vec::new();
        for _ in 0..5 {
            let c = Arc::clone(&cache);
            let t = token.clone();
            handles.push(tokio::spawn(async move { c.validate_token(&t).await }));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_some(), "all concurrent requests should succeed");
        }

        // The expect(1) assertion on the mock verifies only one fetch occurred.
    }

    #[tokio::test]
    async fn jwks_refresh_cooldown_blocks_rapid_requests() {
        // Verify that rapid sequential requests with unknown kids (cache misses)
        // only trigger one JWKS fetch due to cooldown.
        let kid = "test-cooldown";
        let (_pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        let _mock = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once despite multiple misses
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = test_cache(&config);

        // First request with unknown kid triggers a refresh.
        let fake_token1 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTEifQ.e30.sig";
        let _ = cache.validate_token(fake_token1).await;

        // Second request with a different unknown kid should NOT trigger refresh
        // because we're within the 10-second cooldown.
        let fake_token2 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTIifQ.e30.sig";
        let _ = cache.validate_token(fake_token2).await;

        // Third request with yet another unknown kid - still within cooldown.
        let fake_token3 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTMifQ.e30.sig";
        let _ = cache.validate_token(fake_token3).await;

        // The expect(1) assertion verifies only one fetch occurred.
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
        }
    }

    /// Build an HTTP client for tests. Ensures a rustls crypto provider
    /// is installed (normally done inside `JwksCache::new`).
    fn test_http_client() -> OauthHttpClient {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let config = OAuthConfig::builder(
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "https://auth.test.local/.well-known/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        OauthHttpClient::with_config(&config)
            .expect("build test http client")
            .__test_allow_loopback_ssrf()
    }

    #[tokio::test]
    async fn introspect_proxies_and_injects_client_credentials() {
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

        let http = test_http_client();
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn token_proxy_fails_closed_on_oversized_upstream_response() {
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
        let http = test_http_client();
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
            .expect("collect body")
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
    }

    #[tokio::test]
    async fn token_proxy_passes_through_normal_response() {
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
        let http = test_http_client();
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
            .expect("collect body")
            .to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("upstream JSON preserved");
        assert_eq!(json["access_token"], "at-123");
    }

    #[tokio::test]
    async fn introspect_returns_404_when_not_configured() {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client();
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn revoke_proxies_and_returns_upstream_status() {
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

        let http = test_http_client();
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn revoke_returns_404_when_not_configured() {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client();
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn metadata_advertises_endpoints_only_when_configured() {
        let mut cfg = test_config("https://auth.test.local/jwks.json");
        // Without proxy configured, no introspection/revocation advertised.
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(m.get("introspection_endpoint").is_none());
        assert!(m.get("revocation_endpoint").is_none());

        // With proxy + introspection_url but expose_admin_endpoints = false
        // (the secure default): endpoints MUST NOT be advertised.
        let mut proxy = proxy_cfg("https://upstream.local/token");
        proxy.introspection_url = Some("https://upstream.local/introspect".into());
        proxy.revocation_url = Some("https://upstream.local/revoke".into());
        cfg.proxy = Some(proxy);
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(
            m.get("introspection_endpoint").is_none(),
            "introspection must not be advertised when expose_admin_endpoints=false"
        );
        assert!(
            m.get("revocation_endpoint").is_none(),
            "revocation must not be advertised when expose_admin_endpoints=false"
        );

        // Opt in: expose_admin_endpoints = true + introspection_url only.
        if let Some(p) = cfg.proxy.as_mut() {
            p.expose_admin_endpoints = true;
            p.revocation_url = None;
        }
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            m["introspection_endpoint"],
            serde_json::Value::String("https://mcp.local/introspect".into())
        );
        assert!(m.get("revocation_endpoint").is_none());

        // Add revocation_url.
        if let Some(p) = cfg.proxy.as_mut() {
            p.revocation_url = Some("https://upstream.local/revoke".into());
        }
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            m["revocation_endpoint"],
            serde_json::Value::String("https://mcp.local/revoke".into())
        );
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
            "https://idp.example.com/token".into(),
            "client".into(),
            client_secret.map(|s| secrecy::SecretString::new(s.into())),
            client_cert,
            "downstream".into(),
        )
    }

    #[test]
    fn validate_rejects_token_exchange_without_client_auth() {
        let cfg = https_cfg_with_tx(tx_with(None, None));
        let err = cfg
            .validate()
            .expect_err("token_exchange without client auth must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("requires client authentication"),
            "error must explain missing client auth; got {msg:?}"
        );
    }

    #[test]
    fn validate_rejects_token_exchange_with_both_secret_and_cert() {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(Some("s"), Some(cc)));
        let err = cfg
            .validate()
            .expect_err("client_secret + client_cert must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("mutually") && msg.contains("exclusive"),
            "error must explain mutual exclusion; got {msg:?}"
        );
    }

    #[cfg(not(feature = "oauth-mtls-client"))]
    #[test]
    fn validate_rejects_client_cert_without_feature() {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let err = cfg
            .validate()
            .expect_err("client_cert without feature must be rejected");
        assert!(
            err.to_string().contains("oauth-mtls-client"),
            "error must reference the cargo feature; got {err}"
        );
    }

    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_rejects_missing_client_cert_files() {
        let cc = ClientCertConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let err = cfg
            .validate()
            .expect_err("missing cert file must be rejected");
        assert!(
            err.to_string().contains("unreadable"),
            "error must call out unreadable file; got {err}"
        );
    }

    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_rejects_malformed_client_cert_pem() {
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("rmcp-mtls-bad-cert-{}.pem", std::process::id()));
        let key = dir.join(format!("rmcp-mtls-bad-key-{}.pem", std::process::id()));
        std::fs::write(&cert, b"not a real PEM").expect("write tmp cert");
        std::fs::write(&key, b"not a real PEM either").expect("write tmp key");
        let cc = ClientCertConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let err = cfg.validate().expect_err("malformed PEM must be rejected");
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        assert!(
            err.to_string().contains("PEM parse failed"),
            "error must call out PEM parse failure; got {err}"
        );
    }

    #[cfg(feature = "oauth-mtls-client")]
    fn write_self_signed_pem() -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["client.test".into()]).expect("rcgen");
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let nonce: u64 = rand::random();
        let cert_path = dir.join(format!("rmcp-mtls-cert-{pid}-{nonce}.pem"));
        let key_path = dir.join(format!("rmcp-mtls-key-{pid}-{nonce}.pem"));
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");
        (cert_path, key_path)
    }

    #[cfg(feature = "oauth-mtls-client")]
    fn install_test_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn validate_accepts_well_formed_client_cert() {
        install_test_crypto_provider();
        let (cert_path, key_path) = write_self_signed_pem();
        let cc = ClientCertConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let res = cfg.validate();
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        res.expect("well-formed cert+key must validate");
    }

    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn client_for_returns_cached_mtls_client() {
        install_test_crypto_provider();
        let (cert_path, key_path) = write_self_signed_pem();
        let cc = ClientCertConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let cfg = https_cfg_with_tx(tx_with(None, Some(cc)));
        let http = OauthHttpClient::with_config(&cfg).expect("build mtls client");
        let tx_ref = cfg.token_exchange.as_ref().expect("tx set");
        let cert_client = http.client_for(tx_ref);
        let inner_client = http.client_for(&tx_with(Some("s"), None));
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        assert!(
            !std::ptr::eq(cert_client, inner_client),
            "client_for must return distinct clients for cert vs no-cert configs"
        );
    }

    #[cfg(feature = "oauth-mtls-client")]
    #[test]
    fn client_for_falls_back_to_inner_when_cache_miss() {
        install_test_crypto_provider();
        let cfg = validation_https_config();
        let http = OauthHttpClient::with_config(&cfg).expect("build client");
        let unrelated_cc = ClientCertConfig {
            cert_path: PathBuf::from("/cache/miss/cert.pem"),
            key_path: PathBuf::from("/cache/miss/key.pem"),
        };
        let tx_unknown = tx_with(None, Some(unrelated_cc));
        let fallback = http.client_for(&tx_unknown);
        let inner = http.client_for(&tx_with(Some("s"), None));
        assert!(
            std::ptr::eq(fallback, inner),
            "cache miss must fall back to inner client"
        );
    }
}
