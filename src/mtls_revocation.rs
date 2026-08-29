//! CDP-driven CRL revocation support for mTLS.
//!
//! When mTLS is configured with CRL checks enabled, startup performs a bounded
//! bootstrap pass over the configured CA bundle, extracts CRL Distribution
//! Point (CDP) URLs, fetches reachable CRLs, and builds the initial inner
//! `rustls` verifier from that cache.
//!
//! During handshakes, the outer verifier remains stable for the lifetime of the
//! TLS acceptor while its inner `WebPkiClientVerifier` is swapped atomically via
//! `ArcSwap` as CRLs are discovered or refreshed. Discovery from connecting
//! client certificates is fire-and-forget and never blocks the synchronous
//! handshake path.
//!
//! Security note: CDP URLs are extracted from attacker-controllable client
//! certs *before* chain validation. This is safe by design; see the
//! `// SECURITY:` comment on `DynamicClientCertVerifier::verify_client_cert`
//! for the full rationale before changing the discovery ordering.
//!
//! Semantics:
//! - `crl_deny_on_unavailable = true` (default) => fail closed when a
//!   certificate advertises CDP URLs whose revocation status is not yet
//!   available. Denial requires *every* relevant CDP to be uncached, per
//!   RFC 5280 6.3; denying on a single unavailable mirror would let an
//!   attacker who blocks one CDP deny service.
//! - `crl_deny_on_unavailable = false` => fail open with warn logs. Restores
//!   the pre-3.9 behaviour and is strongly discouraged: a revoked
//!   certificate is accepted whenever its CRL is unreachable.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use tokio::{
    net::lookup_host,
    sync::{RwLock, Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use x509_parser::{
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::{FromDer, X509Certificate},
    revocation_list::CertificateRevocationList,
};

use crate::{
    auth::MtlsConfig,
    error::RmcpServerKitError,
    ssrf::{check_scheme, ip_block_reason, sanitized_url_for_log},
};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_AUTO_REFRESH: Duration = Duration::from_mins(10);
const MAX_AUTO_REFRESH: Duration = Duration::from_hours(24);
/// Connection timeout for CRL HTTP fetches. Independent of overall fetch
/// timeout to bound time spent on unreachable hosts.
const CRL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Most distinct CDP URLs a single handshake will consider.
///
/// RFC 5280 4.2.1.13 treats multiple URIs inside one `DistributionPoint` as
/// mirrors of the same CRL, so a conforming certificate needs only a handful.
/// 64 sits far above any plausible legitimate certificate while bounding the
/// work a peer can demand on the unauthenticated handshake path. Deliberately
/// a private constant rather than a config field: no operator should need to
/// tune it, and widening the public config surface for it would be worse.
const MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE: usize = 64;

/// Parsed CRL cached in memory and keyed by its source URL.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CachedCrl {
    /// DER bytes for the CRL.
    pub der: CertificateRevocationListDer<'static>,
    /// `thisUpdate` field from the CRL.
    pub this_update: SystemTime,
    /// `nextUpdate` field from the CRL, if present.
    pub next_update: Option<SystemTime>,
    /// Time the server fetched this CRL.
    pub fetched_at: SystemTime,
    /// Source URL used for retrieval.
    pub source_url: String,
}

/// One atomically-published verifier generation.
///
/// SECURITY: `verifier`, `cached_urls`, and `committed_identities` are
/// published together as a single immutable snapshot behind one [`ArcSwap`].
/// Publishing them separately would let a handshake observe the coverage hint
/// from one commit against the verifier of another — a mixed-generation read
/// the fail-closed precheck cannot distinguish from out-of-band mutation.
/// Readers load this state exactly once per handshake and both pre-check and
/// enforce against it.
pub(crate) struct VerifierState {
    /// What rustls actually enforces for this generation.
    verifier: Arc<dyn ClientCertVerifier>,
    /// URLs whose CRL this generation's `verifier` genuinely enforces.
    cached_urls: HashSet<String>,
    /// Constant-cost identity of every committed [`CachedCrl`], keyed by URL.
    ///
    /// The precheck compares the live public `cache` against this index, so an
    /// out-of-band write through the `pub` cache field is detected and denied
    /// instead of silently claiming coverage the verifier does not provide.
    committed_identities: HashMap<String, EntryIdentity>,
}

impl std::fmt::Debug for VerifierState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierState")
            .field("cached_urls_len", &self.cached_urls.len())
            .field("committed_identities_len", &self.committed_identities.len())
            .finish_non_exhaustive()
    }
}

/// Constant-cost fingerprint of a cached CRL entry, recorded at commit time.
///
/// # What this does and does not guarantee
///
/// This detects **out-of-band mutation of the public [`CrlSet::cache`] field by
/// non-adversarial code** — the API-misuse hazard that field creates. It is
/// deliberately **not** a cryptographic integrity check and must never be
/// described as one.
///
/// Hashing the DER instead would be a stronger check, but it was measured
/// (`benches/crl_precheck.rs`) at 56 ms p95 per relevant cached CRL at the
/// 5 MiB `crl_max_response_bytes` default, scaling linearly with an
/// attacker-chosen CDP-URL count on the *unauthenticated* handshake path. That
/// trades a local misuse tripwire for a remote CPU-amplification vulnerability,
/// so identity comparison is used instead and the DER is never rescanned.
///
/// Known limit: a same-process caller that deliberately drops an entry and
/// reallocates a replacement at the same address, with the same length and the
/// same 32-byte head and tail, would not be detected. Such a caller already
/// holds the cache write lock and is inside the trust boundary. The real fix is
/// making `cache` private, which is a 4.0 change.
#[derive(Clone, PartialEq, Eq)]
struct EntryIdentity {
    der_ptr: usize,
    der_len: usize,
    head: [u8; 32],
    tail: [u8; 32],
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    fetched_at: SystemTime,
    source_url: String,
}

/// Fingerprint one cache entry. Reads at most 64 bytes of DER regardless of
/// CRL size, so handshake cost does not scale with `crl_max_response_bytes`.
fn entry_identity(entry: &CachedCrl) -> EntryIdentity {
    // Exhaustive destructuring is load-bearing: adding a field to `CachedCrl`
    // must fail compilation here so someone decides whether it belongs in the
    // identity, rather than silently falling outside mutation detection.
    let CachedCrl {
        der,
        this_update,
        next_update,
        fetched_at,
        source_url,
    } = entry;

    let bytes = der.as_ref();
    let mut head = [0u8; 32];
    let mut tail = [0u8; 32];
    let sample = bytes.len().min(32);
    if let Some(source) = bytes.get(..sample)
        && let Some(target) = head.get_mut(..sample)
    {
        target.copy_from_slice(source);
    }
    if let Some(source) = bytes.get(bytes.len().saturating_sub(sample)..)
        && let Some(target) = tail.get_mut(..sample)
    {
        target.copy_from_slice(source);
    }

    EntryIdentity {
        der_ptr: bytes.as_ptr().addr(),
        der_len: bytes.len(),
        head,
        tail,
        this_update: *this_update,
        next_update: *next_update,
        fetched_at: *fetched_at,
        source_url: source_url.clone(),
    }
}

/// Fingerprint every entry of a cache map.
fn crl_cache_identities<S: std::hash::BuildHasher>(
    cache: &HashMap<String, CachedCrl, S>,
) -> HashMap<String, EntryIdentity> {
    cache
        .iter()
        .map(|(url, entry)| (url.clone(), entry_identity(entry)))
        .collect()
}

/// Confirm the live cache still matches what `state` committed, for the CDP
/// URLs this handshake would rely on.
///
/// SECURITY: the scope is `relevant_urls ∩ state.cached_urls` — the only URLs
/// whose coverage claim can admit the handshake. A relevant URL missing from
/// the live cache, missing an identity, or whose identity differs has had its
/// entry mutated out of band: coverage is claimed but unproven.
fn cache_matches_committed_identities(
    cache: &HashMap<String, CachedCrl>,
    state: &VerifierState,
    relevant_urls: &[String],
) -> bool {
    relevant_urls
        .iter()
        .filter(|url| state.cached_urls.contains(*url))
        .all(
            |url| match (cache.get(url), state.committed_identities.get(url)) {
                (Some(entry), Some(expected)) => entry_identity(entry) == *expected,
                _ => false,
            },
        )
}

/// Shared CRL state backing the dynamic mTLS verifier.
#[allow(
    missing_debug_implementations,
    reason = "contains ArcSwap and dyn verifier internals"
)]
#[non_exhaustive]
pub struct CrlSet {
    /// Single atomically-published generation of verifier + coverage hint +
    /// digest index. See [`VerifierState`].
    verifier_state: ArcSwap<VerifierState>,
    /// Serializes commits end to end.
    ///
    /// SECURITY: the cache write lock is deliberately NOT the commit
    /// transaction lock — holding it across `rebuild_verifier` would make the
    /// verifier path's non-blocking `try_read` fail under ordinary refresh
    /// load, turning a legitimate refresh into a spurious handshake denial.
    /// Without this mutex, two commits could each snapshot the same old cache
    /// and publish states whose `cached_urls` omit the other's URL, which is
    /// exactly the desynchronisation the digest index exists to prevent.
    commit_lock: tokio::sync::Mutex<()>,
    /// Cached CRLs keyed by URL.
    ///
    /// # ⚠️ Deprecated
    ///
    /// Writing through this field bypasses the atomic commit path and
    /// desynchronises the published coverage hint from the live verifier.
    /// Since 3.9 such a write is **detected and fails the handshake closed**
    /// rather than silently admitting a certificate whose revocation status
    /// cannot be enforced. Reads remain safe but are not part of the supported
    /// surface. The field becomes private in 4.0.
    #[deprecated(
        since = "3.9.0",
        note = "mutating the CRL cache out of band is detected and denies handshakes; this field becomes private in 4.0"
    )]
    pub cache: RwLock<HashMap<String, CachedCrl>>,
    /// Immutable client-auth root store.
    pub roots: Arc<RootCertStore>,
    /// mTLS CRL configuration.
    pub config: MtlsConfig,
    /// Fire-and-forget discovery channel for newly-seen CDP URLs.
    pub discover_tx: mpsc::UnboundedSender<String>,
    client: reqwest::Client,
    /// URLs whose CRL is confirmed present in `cache`. Permanent dedup: a URL
    /// here is never re-enqueued for discovery.
    seen_urls: Mutex<HashSet<String>>,
    /// URLs admitted to the discovery channel but not yet confirmed cached.
    ///
    /// This exists so a queued URL is not re-enqueued while its fetch is in
    /// flight, WITHOUT permanently suppressing it. Promotion to `seen_urls`
    /// happens only once the CRL is actually in the cache; a fetch error or a
    /// cache-cap rejection clears the entry so a later handshake can retry.
    /// Merging the two states is exactly the bug this separation fixes: a
    /// first-fetch failure would otherwise suppress the URL for the process
    /// lifetime, silently disabling revocation for that CDP.
    pending_urls: Mutex<HashSet<String>>,
    /// Global cap on simultaneous CRL HTTP fetches (SSRF amplification guard).
    global_fetch_sem: Arc<Semaphore>,
    /// Per-host serializer (one in-flight fetch per origin host). Bounded
    /// by `crl_max_host_semaphores`; at the cap, idle entries are evicted
    /// on demand (see [`acquire_host_semaphore`]), so the cap only rejects
    /// genuinely concurrent fetch floods and is never a permanent lockout.
    host_semaphores: Arc<tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// Global rate-limiter on discovery URL submissions; protects against
    /// cert-driven URL flooding by a malicious mTLS peer.
    ///
    /// Note: this ships as a process-global limiter; per-source-IP scoping
    /// is deferred to a future release because the rustls
    /// `verify_client_cert` callback does not carry a `SocketAddr` for the
    /// peer. This is a CRL-discovery limiter in the TLS verifier path —
    /// distinct from the bearer pre-auth limiter (`AuthState`), which is
    /// already keyed per-IP via a bounded keyed governor and lives in the
    /// ordinary request middleware path.
    discovery_limiter: Arc<DefaultDirectRateLimiter>,
    /// Cached cap on per-fetch response body size; copied from `config` so the
    /// hot path doesn't re-read the (rarely changing) config struct.
    max_response_bytes: u64,
    last_cap_warn: Mutex<HashMap<&'static str, Instant>>,
    /// Test-only hook fired immediately before a discovered URL becomes
    /// observable on `discover_tx`.
    ///
    /// Exists because the "pending marker is inserted before the URL is
    /// published" invariant cannot otherwise be observed deterministically:
    /// the previous test raced a spinning thread against the scheduler and
    /// could pass without ever exercising the interleaving.
    #[cfg(any(test, feature = "test-helpers"))]
    discovery_send_probe: Mutex<Option<DiscoverySendProbe>>,
}

/// Callback fired immediately before a discovered URL is published.
#[cfg(any(test, feature = "test-helpers"))]
type DiscoverySendProbe = Arc<dyn Fn(&CrlSet, &str) + Send + Sync>;

impl CrlSet {
    fn new(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        discover_tx: mpsc::UnboundedSender<String>,
        initial_cache: HashMap<String, CachedCrl>,
    ) -> Result<Arc<Self>, RmcpServerKitError> {
        // M-H2: install the SSRF screening resolver on the CRL fetcher.
        // CRL CDP URLs come from attacker-controllable client certs and
        // their hosts are re-resolved per fetch -- exactly the TOCTOU
        // class M-H2 closes. The allowlist is empty (default-strict),
        // matching the existing CRL pre-flight posture; operators who
        // need internal CDPs would extend this with the same
        // CompiledSsrfAllowlist plumbing used by oauth.
        let allowlist = Arc::new(crate::ssrf::CompiledSsrfAllowlist::default());
        let resolver: Arc<dyn reqwest::dns::Resolve> =
            Arc::new(crate::ssrf_resolver::SsrfScreeningResolver::new(
                Arc::clone(&allowlist),
                #[cfg(any(test, feature = "test-helpers"))]
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                #[cfg(not(any(test, feature = "test-helpers")))]
                (),
            ));

        let client = reqwest::Client::builder()
            // M-H2/N1: see oauth.rs::OauthHttpClient::build for rationale.
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(config.crl_fetch_timeout)
            .connect_timeout(CRL_CONNECT_TIMEOUT)
            .tcp_keepalive(None)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                RmcpServerKitError::Startup(format!("CRL HTTP client init: {error}"))
            })?;

        let initial_verifier = rebuild_verifier(&roots, &config, &initial_cache)?;
        let seen_urls = initial_cache.keys().cloned().collect::<HashSet<_>>();
        // SECURITY: identities MUST be seeded here, not only on commit. `new`
        // receives the bootstrap-fetched cache, so an index populated only by
        // `commit_cache_update_atomically` would read every bootstrapped CRL
        // as mutated out of band and fail mTLS closed at startup.
        let initial_state = VerifierState {
            verifier: initial_verifier,
            cached_urls: seen_urls.clone(),
            committed_identities: crl_cache_identities(&initial_cache),
        };

        // Defense in depth: normal server startup reaches this only through
        // `Validated<McpServerConfig>`, but the public `bootstrap_fetch` helper
        // and test-helper constructors accept a raw `MtlsConfig` directly.
        let concurrency = config.crl_max_concurrent_fetches.max(1);
        let global_fetch_sem = Arc::new(Semaphore::new(concurrency));
        let host_semaphores = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        // Same raw-`MtlsConfig` bypass as above; keep a one-token minimum even
        // when callers skip the startup validator.
        let rate =
            NonZeroU32::new(config.crl_discovery_rate_per_min.max(1)).unwrap_or(NonZeroU32::MIN);
        let discovery_limiter = Arc::new(RateLimiter::direct(Quota::per_minute(rate)));

        let max_response_bytes = config.crl_max_response_bytes;

        #[allow(
            deprecated,
            reason = "constructing the struct necessarily names the deprecated field; the deprecation targets downstream mutation, not construction"
        )]
        Ok(Arc::new(Self {
            verifier_state: ArcSwap::from_pointee(initial_state),
            commit_lock: tokio::sync::Mutex::new(()),
            cache: RwLock::new(initial_cache),
            roots,
            config,
            discover_tx,
            client,
            seen_urls: Mutex::new(seen_urls),
            pending_urls: Mutex::new(HashSet::new()),
            global_fetch_sem,
            host_semaphores,
            discovery_limiter,
            max_response_bytes,
            last_cap_warn: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-helpers"))]
            discovery_send_probe: Mutex::new(None),
        }))
    }

    /// Fire the test-only pre-publication probe, if one is installed.
    ///
    /// The `Arc` is cloned out and the lock released before the callback runs,
    /// so a probe may re-enter `CrlSet` state (`pending_urls`, `seen_urls`)
    /// without deadlocking against this non-reentrant `std::sync::Mutex`.
    #[cfg(any(test, feature = "test-helpers"))]
    fn fire_discovery_send_probe(&self, url: &str) {
        let probe = self
            .discovery_send_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(probe) = probe {
            probe(self, url);
        }
    }

    #[cfg(not(any(test, feature = "test-helpers")))]
    #[inline]
    #[allow(
        clippy::unused_self,
        reason = "the receiver keeps the call site identical across cfgs; production builds compile this to nothing"
    )]
    fn fire_discovery_send_probe(&self, _url: &str) {}

    /// Test-only: observe every URL at the instant before it is published to
    /// the discovery channel.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_set_discovery_send_probe(&self, probe: DiscoverySendProbe) {
        *self
            .discovery_send_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(probe);
    }

    fn should_warn_throttled(&self, which: &'static str) -> bool {
        let now = Instant::now();
        let cooldown = Duration::from_mins(1);
        let mut guard = self
            .last_cap_warn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let should_emit = guard
            .get(which)
            .is_none_or(|last| now.saturating_duration_since(*last) >= cooldown);
        if should_emit {
            guard.insert(which, now);
        }
        should_emit
    }

    fn warn_cap_exceeded_throttled(&self, which: &'static str) {
        if self.should_warn_throttled(which) {
            tracing::warn!(which = which, "CRL map cap exceeded; dropping newest entry");
        }
    }

    /// Report a rejected certificate that advertised more distinct CDP URLs
    /// than [`MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE`]. Distinct from both the
    /// unavailable-CRL and the out-of-band-mutation denials, because this one
    /// applies in fail-open mode too and has no opt-out.
    /// Single in-crate entry point to the deprecated public `cache` field.
    ///
    /// Routing every internal use through here keeps the deprecation honest for
    /// downstream callers while confining the `allow` to one site instead of
    /// scattering it across every read.
    #[allow(
        deprecated,
        reason = "the deprecation targets downstream out-of-band mutation; in-crate reads and the atomic commit path are the supported users of this field"
    )]
    fn cache_lock(&self) -> &RwLock<HashMap<String, CachedCrl>> {
        &self.cache
    }

    fn warn_cdp_cap_exceeded_throttled(&self, observed: usize) {
        if self.should_warn_throttled("cdp_url_cap") {
            tracing::warn!(
                observed = observed,
                cap = MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE,
                "crl_cdp_url_cap_exceeded: client certificate advertises more distinct CDP URLs than the per-handshake cap; rejecting as malformed"
            );
        }
    }

    /// Report a fail-closed denial caused by out-of-band mutation of the public
    /// `cache` field, distinct from the ordinary unavailable-CRL denial so
    /// operators can tell a mutated entry from a missing mirror.
    fn warn_cache_tamper_throttled(&self) {
        if self.should_warn_throttled("cache_entry_mismatch") {
            tracing::warn!(
                "crl_cache_out_of_band_mutation: live CRL cache does not match the committed identity index; denying handshake"
            );
        }
    }

    // cancel-safe: `commit_lock` is held across awaits, but every mutation
    // before publication builds a local candidate. The cache swap and the
    // `verifier_state.store` publication are adjacent with NO await between
    // them, so a cancelled commit leaves either the old or the new generation
    // -- never a half-applied mix.
    async fn commit_cache_update_atomically(
        &self,
        inserts: Vec<(String, CachedCrl)>,
        removals: &[String],
    ) -> Result<bool, RmcpServerKitError> {
        // SECURITY (lock order, load-bearing): hold `commit_lock` across the
        // whole transaction — snapshot, rebuild, publish. The cache write lock
        // is taken only for the paired `*cache = candidate` +
        // `verifier_state.store(..)` publication, so readers synchronising on
        // that same `RwLock` can never observe a commit half-applied, while
        // `rebuild_verifier` and digesting stay off-lock and out of the
        // verifier path's way.
        let _commit = self.commit_lock.lock().await;

        let mut candidate = self.cache_lock().read().await.clone();
        let mut admitted_urls = Vec::new();

        // POLICY: at cap the NEWEST entry is rejected, never an existing
        // one (no LRU). Under adversarial unique-CDP churn an LRU would
        // let an attacker evict the legitimate warm set by spamming
        // throwaway CDP URLs; rejecting newcomers instead preserves
        // revocation coverage for the established CA estate. Confirmed
        // by Oracle review of the 1.13.0 rust-review fix plan.
        for (url, cached) in inserts {
            if candidate.len() >= self.config.crl_max_cache_entries && !candidate.contains_key(&url)
            {
                self.warn_cap_exceeded_throttled("cache");
                continue;
            }
            candidate.insert(url.clone(), cached);
            admitted_urls.push(url);
        }

        for url in removals {
            candidate.remove(url);
        }

        let verifier = rebuild_verifier(&self.roots, &self.config, &candidate)?;

        // SECURITY: identities are recomputed for EVERY entry, not only for
        // what this commit wrote. `candidate` is a clone of the live cache and
        // cloning a `CachedCrl` reallocates its DER, so every carried-forward
        // entry has a new address. Carrying identities forward would make an
        // unrelated commit invalidate every other URL and deny every later
        // handshake. Recomputation is O(entries) pointer and scalar reads with
        // no hashing, so there is nothing to gain by being incremental.
        let new_state = Arc::new(VerifierState {
            verifier,
            cached_urls: candidate.keys().cloned().collect(),
            committed_identities: crl_cache_identities(&candidate),
        });
        let changed = !admitted_urls.is_empty() || !removals.is_empty();

        {
            let mut cache = self.cache_lock().write().await;
            let superseded = std::mem::replace(&mut *cache, candidate);
            self.verifier_state.store(new_state);
            drop(cache);
            // Free the superseded map only AFTER releasing the write lock.
            // Dropping it in place would deallocate one `String` and one DER
            // buffer per cached CRL inside the publication window, which is
            // precisely the window the verifier path's non-blocking `try_read`
            // has to get through. Measured at 256 entries: ~15% of reader
            // attempts blocked with the in-place drop, under 1% without it.
            drop(superseded);
        }

        // A removed CRL must become fully re-discoverable, so clear the URL
        // from BOTH dedup states. Clearing only `seen_urls` would leave a
        // stale `pending_urls` entry suppressing re-enqueue forever.
        {
            let mut seen = self
                .seen_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for url in removals {
                seen.remove(url);
            }
        }
        {
            let mut pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for url in removals {
                pending.remove(url);
            }
        }

        Ok(changed)
    }

    /// Force an immediate refresh of all currently known CRL URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if rebuilding the inner verifier fails.
    pub async fn force_refresh(&self) -> Result<(), RmcpServerKitError> {
        let urls = {
            let cache = self.cache_lock().read().await;
            cache.keys().cloned().collect::<Vec<_>>()
        };
        self.refresh_urls(urls).await
    }

    // cancel-safe: selects due URLs and delegates to efresh_urls, which
    // stages results locally before a single atomic commit.
    async fn refresh_due_urls(&self) -> Result<(), RmcpServerKitError> {
        let now = SystemTime::now();
        let urls = {
            let cache = self.cache_lock().read().await;
            cache
                .iter()
                .filter(|(_, cached)| {
                    should_refresh_cached(cached, now, self.config.crl_refresh_interval)
                })
                .map(|(url, _)| url.clone())
                .collect::<Vec<_>>()
        };

        if urls.is_empty() {
            return Ok(());
        }

        self.refresh_urls(urls).await
    }

    // cancel-safe: fetch results accumulate in local insert/remove vectors and
    // are applied only by commit_cache_update_atomically. Cancelling before
    // that commit discards the batch and leaves the cache untouched.
    async fn refresh_urls(&self, urls: Vec<String>) -> Result<(), RmcpServerKitError> {
        let results = self.fetch_url_results(urls).await;
        let now = SystemTime::now();
        let cache = self.cache_lock().read().await;
        let mut inserts = Vec::new();
        let mut removals = Vec::new();

        for (url, result) in results {
            match result {
                Ok(cached) => {
                    inserts.push((url, cached));
                }
                Err(error) => {
                    let remove_entry = cache.get(&url).is_some_and(|existing| {
                        existing
                            .next_update
                            .and_then(|next| next.checked_add(self.config.crl_stale_grace))
                            .is_some_and(|deadline| now > deadline)
                    });
                    tracing::warn!(url = %url, error = %error, "CRL refresh failed");
                    if remove_entry {
                        removals.push(url);
                    }
                }
            }
        }
        drop(cache);

        if !inserts.is_empty() || !removals.is_empty() {
            let _ = self
                .commit_cache_update_atomically(inserts, &removals)
                .await?;
        }

        Ok(())
    }

    /// Fetch a CRL and commit it to the cache.
    ///
    /// Returns whether the CRL is actually present in the cache afterwards.
    /// A successful HTTP fetch is NOT sufficient:
    /// [`Self::commit_cache_update_atomically`] rejects new entries once
    /// `crl_max_cache_entries` is reached. Only a URL that genuinely landed in
    /// the cache may be promoted to the permanent `seen_urls` dedup set —
    /// promoting on fetch success alone would suppress a URL that was never
    /// cached, which is the same revocation-bypass this state split fixes.
    // cancel-safe: commits only after gated_fetch returns, so cancellation
    // during the fetch cannot promote a URL into the seen_urls dedup set.
    async fn fetch_and_store_url(&self, url: String) -> Result<bool, RmcpServerKitError> {
        let cached = gated_fetch(
            &self.client,
            &self.global_fetch_sem,
            &self.host_semaphores,
            &url,
            self.config.crl_allow_http,
            self.max_response_bytes,
            self.config.crl_max_host_semaphores,
        )
        .await?;
        let _ = self
            .commit_cache_update_atomically(vec![(url.clone(), cached)], &[])
            .await?;
        Ok(self.cache_lock().read().await.contains_key(&url))
    }

    /// Promote a URL from the in-flight set to the permanent dedup set.
    /// Called only once its CRL is confirmed present in the cache.
    fn promote_pending_to_seen(&self, url: &str) {
        {
            let mut pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.remove(url);
        }
        let mut seen = self
            .seen_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() >= self.config.crl_max_seen_urls && !seen.contains(url) {
            self.warn_cap_exceeded_throttled("seen_urls");
            return;
        }
        seen.insert(url.to_owned());
    }

    /// Clear a URL's in-flight marker without promoting it, so a later
    /// handshake can re-enqueue it. Used when the fetch failed or the cache
    /// refused the entry.
    fn clear_pending(&self, url: &str) {
        let mut pending = self
            .pending_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.remove(url);
    }

    /// Enqueue newly-seen CDP URLs and run the synchronous fail-closed
    /// precheck.
    ///
    /// Returns `(deny, state)`. The caller MUST enforce with the returned
    /// `state.verifier` rather than re-loading: pre-check and enforcement have
    /// to observe the same verifier generation.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the cache read guard is deliberately acquired BEFORE loading VerifierState and is released by the match that consumes it; tightening as the lint suggests would invert the lock order this precheck's generation-coherence depends on"
    )]
    fn note_discovered_urls(
        &self,
        end_entity_urls: &[String],
        intermediate_urls: &[String],
    ) -> (bool, Arc<VerifierState>) {
        // INVARIANT: only called post-handshake from
        // `DynamicClientCertVerifier::verify_client_cert`. The peer has
        // already presented a chain that parses; this method must not panic
        // under attacker-controlled URL contents.
        //
        // SECURITY: see `DynamicClientCertVerifier::verify_client_cert` for
        // the rationale on why accepting URLs from an unverified cert is
        // safe (no HTTP on this path; fetch is off-path and SSRF-gated).
        let mut all_urls = Vec::with_capacity(end_entity_urls.len() + intermediate_urls.len());
        all_urls.extend_from_slice(end_entity_urls);
        all_urls.extend_from_slice(intermediate_urls);
        all_urls.sort();
        all_urls.dedup();

        let relevant_urls = if self.config.crl_end_entity_only {
            end_entity_urls
        } else {
            all_urls.as_slice()
        };

        // SECURITY: reject a certificate advertising an implausible number of
        // distinct CDP URLs, BEFORE the discovery loop and BEFORE the
        // fail-open branch. Every later step is linear in this peer-chosen
        // count, so leaving it unbounded is the amplification primitive this
        // cap exists to remove; and the sort/dedup/rate-limiter work is paid
        // identically under `crl_deny_on_unavailable = false`, so capping only
        // the fail-closed path would leave the amplifier fully intact.
        //
        // This is a MALFORMED-CERTIFICATE rejection, not a revocation-status
        // denial: an operator who set `crl_deny_on_unavailable = false` opted
        // out of unavailability denials, not out of this. It therefore has no
        // opt-out and carries its own distinct log message.
        if relevant_urls.len() > MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE {
            self.warn_cdp_cap_exceeded_throttled(relevant_urls.len());
            return (true, self.verifier_state.load_full());
        }

        // Snapshot both dedup sets under their locks; do NOT mutate yet.
        // A URL is skipped if it is already cached (`seen_urls`) or already
        // queued and awaiting its fetch (`pending_urls`). Promotion to
        // `seen_urls` happens only after the CRL is confirmed in the cache,
        // so a URL that loses the limiter race, hits a closed channel, fails
        // to fetch, or is rejected by the cache cap stays retriable. Marking
        // "seen" any earlier permanently black-holes the URL: every later
        // handshake would treat it as known and skip discovery, while no CRL
        // was ever cached. With `crl_deny_on_unavailable = true` that is a
        // persistent handshake failure; with fail-open it silently disables
        // revocation checking for that CDP for the process lifetime.
        // SECURITY: discover only from `relevant_urls`, the same set the cap
        // above governs. Reading `all_urls` here instead would let a peer with
        // `crl_end_entity_only = true` drive discovery, pending-set growth, and
        // limiter consumption from uncapped intermediate CDPs -- the exact
        // amplification the cap exists to remove.
        let candidates: Vec<String> = {
            let seen = self
                .seen_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            relevant_urls
                .iter()
                .filter(|url| !seen.contains(*url) && !pending.contains(*url))
                .cloned()
                .collect()
        };

        // Rate-limit gate: drop excess submissions on the floor with a WARN.
        // The mTLS verifier must remain non-blocking, so we use the
        // synchronous `check()` API and never await here.
        for url in candidates {
            if self.discovery_limiter.check().is_err() {
                tracing::warn!(
                    url = %url,
                    "discovery_rate_limited: dropped CDP URL beyond per-minute cap (will be retried on next handshake observing this URL)"
                );
                continue;
            }
            let inserted = {
                // Invariant: while a URL is observable by the refresher, its
                // transient in-flight marker already exists, so every fetch
                // settlement path can remove or promote the same marker.
                let mut guard = self
                    .pending_urls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if guard.contains(&url) {
                    false
                } else {
                    if guard.len() >= self.config.crl_max_seen_urls {
                        self.warn_cap_exceeded_throttled("pending_urls");
                        break;
                    }
                    guard.insert(url.clone())
                }
            };
            if !inserted {
                continue;
            }
            self.fire_discovery_send_probe(&url);
            if self.discover_tx.send(url.clone()).is_err() {
                // Receiver gone (shutdown). Do NOT mark pending so the
                // URL can be retried after a reload / restart.
                self.clear_pending(&url);
                tracing::debug!(
                    url = %url,
                    "discover channel closed; dropping CDP URL without marking pending"
                );
            }
        }

        if !self.config.crl_deny_on_unavailable {
            return (false, self.verifier_state.load_full());
        }

        if relevant_urls.is_empty() {
            return (false, self.verifier_state.load_full());
        }

        // SECURITY (lock order — must match `commit_cache_update_atomically`):
        // take the cache read guard FIRST, then load the verifier state while
        // still holding it. Commits publish `cache` and `verifier_state` under
        // the same write lock, so this ordering makes a legitimate commit
        // atomic to this reader; loading the state first could pair a new
        // identity index with a pre-commit cache view and report a routine
        // refresh as out-of-band mutation.
        //
        // `try_read` is mandatory: this runs inside the synchronous rustls
        // verifier callback, where blocking and awaiting are forbidden.
        let cache_guard = self.cache_lock().try_read();
        let state = self.verifier_state.load_full();

        // SECURITY: a failed `try_read` is NOT evidence of tampering, and must
        // not deny on its own. `tokio::sync::RwLock` is write-preferring, so an
        // ordinary refresh commit makes `try_read` fail — denying here would
        // turn every legitimate CRL refresh into a self-inflicted handshake
        // outage. It also buys no security: the handshake is enforced by the
        // immutable `state.verifier` that was committed with `cached_urls`, not
        // by the live map, so an unreadable cache simply means the public
        // mirror could not be audited this time. Out-of-band mutation is still
        // caught on every handshake that does get the lock.
        if let Ok(cache) = cache_guard
            && !cache_matches_committed_identities(&cache, &state, relevant_urls)
        {
            drop(cache);
            self.warn_cache_tamper_throttled();
            return (true, state);
        }

        // `all(..not cached..)` -- deny only when EVERY relevant CDP URL is
        // uncached, not when any single one is. RFC 5280 4.2.1.13: "If the
        // DistributionPointName contains multiple values, each name
        // describes a different mechanism to obtain the same CRL." The
        // URLs are therefore mirrors, and one successful fetch is
        // sufficient revocation coverage; failing on a single unreachable
        // mirror would let an attacker who can DoS one CDP host deny
        // service to every client.
        //
        // Known limitation: multiple `DistributionPoint` *entries* (as
        // opposed to multiple URIs inside one entry) may in principle be
        // reason-partitioned scopes rather than mirrors, and this flattens
        // them into a single URL set. That is safe against RFC-conforming
        // issuers, because the same section requires "a conforming CA ...
        // MUST include at least one DistributionPoint that points to a CRL
        // that covers the certificate for all reasons", and the profile
        // "RECOMMENDS against segmenting CRLs by reason code". Reason-code
        // partitioning is not otherwise modelled here.
        let deny = relevant_urls
            .iter()
            .all(|url| !state.cached_urls.contains(url));
        (deny, state)
    }

    /// Test helper for constructing a CRL set from in-memory CRLs. Benign but
    /// ungated public leak; test-only despite not requiring `test-helpers`.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier cannot be built from the provided CRLs.
    #[doc(hidden)]
    #[deprecated(
        since = "3.9.0",
        note = "test-only constructor that is ungated in 3.x by accident; it becomes feature-gated in 4.0"
    )]
    pub fn __test_with_prepopulated_crls(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        prefilled_crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Arc<Self>, RmcpServerKitError> {
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);

        let mut initial_cache = HashMap::new();
        for (index, der) in prefilled_crls.into_iter().enumerate() {
            let source_url = format!("memory://crl/{index}");
            let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;
            initial_cache.insert(
                source_url.clone(),
                CachedCrl {
                    der,
                    this_update,
                    next_update,
                    fetched_at: SystemTime::now(),
                    source_url,
                },
            );
        }

        Self::new(roots, config, discover_tx, initial_cache)
    }

    /// Test-only: same as [`Self::__test_with_prepopulated_crls`] but keeps and
    /// returns the discover receiver. Benign but ungated public leak; test-only
    /// despite not requiring `test-helpers`.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier cannot be built from the provided CRLs.
    #[doc(hidden)]
    #[deprecated(
        since = "3.9.0",
        note = "test-only constructor that is ungated in 3.x by accident; it becomes feature-gated in 4.0"
    )]
    pub fn __test_with_kept_receiver(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        prefilled_crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<String>), RmcpServerKitError> {
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();

        let mut initial_cache = HashMap::new();
        for (index, der) in prefilled_crls.into_iter().enumerate() {
            let source_url = format!("memory://crl/{index}");
            let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;
            initial_cache.insert(
                source_url.clone(),
                CachedCrl {
                    der,
                    this_update,
                    next_update,
                    fetched_at: SystemTime::now(),
                    source_url,
                },
            );
        }

        let crl_set = Self::new(roots, config, discover_tx, initial_cache)?;
        Ok((crl_set, discover_rx))
    }

    /// # ⚠️ Security
    ///
    /// Availability hazard: bypasses discovery deduplication, consumes CDP
    /// discovery quota, and enqueues arbitrary URLs. Fetch-side SSRF, scheme,
    /// and concurrency caps still apply. Ungated public leak.
    #[doc(hidden)]
    pub fn __test_check_discovery_rate(&self, urls: &[String]) -> (usize, usize) {
        let mut accepted = 0usize;
        let mut dropped = 0usize;
        for url in urls {
            if self.discovery_limiter.check().is_ok() {
                let _ = self.discover_tx.send(url.clone());
                accepted += 1;
            } else {
                dropped += 1;
            }
        }
        (accepted, dropped)
    }

    /// # ⚠️ Security
    ///
    /// State hazard: mutates discovery state; its closed-channel pending shim
    /// differs from production behaviour and can create state a real closed
    /// discovery channel would not record. Ungated public leak.
    #[doc(hidden)]
    pub fn __test_note_discovered_urls(&self, urls: &[String]) -> bool {
        let (missing_cached, _state) = self.note_discovered_urls(urls, &[]);
        if self.discover_tx.is_closed() {
            let already_seen: HashSet<String> = {
                let seen = self
                    .seen_urls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                urls.iter()
                    .filter(|url| seen.contains(*url))
                    .cloned()
                    .collect()
            };
            let mut pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for url in urls {
                if already_seen.contains(url) || pending.contains(url) {
                    continue;
                }
                if pending.len() >= self.config.crl_max_seen_urls {
                    self.warn_cap_exceeded_throttled("pending_urls");
                    break;
                }
                pending.insert(url.clone());
            }
        }
        missing_cached
    }

    /// Test-only: invoke the real precheck with separate end-entity and
    /// intermediate CDP sets.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_note_discovered_urls_by_cert(
        &self,
        end_entity_urls: &[String],
        intermediate_urls: &[String],
    ) -> bool {
        self.note_discovered_urls(end_entity_urls, intermediate_urls)
            .0
    }

    /// Test-only: report whether a URL is suppressed from re-discovery. Benign
    /// inspection helper, but an ungated public leak available without
    /// `test-helpers`; use only in tests.
    #[doc(hidden)]
    pub fn __test_is_seen(&self, url: &str) -> bool {
        let in_seen = {
            let seen = self
                .seen_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            seen.contains(url)
        };
        if in_seen {
            return true;
        }
        let pending = self
            .pending_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.contains(url)
    }

    /// Test-only: report whether a URL reached the PERMANENT dedup set,
    /// which happens only after its CRL is confirmed present in the cache.
    /// A URL that was merely queued, or whose fetch failed, is not counted.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_is_permanently_seen(&self, url: &str) -> bool {
        let seen = self
            .seen_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.contains(url)
    }

    /// # ⚠️ Security
    ///
    /// Caller-supplied `admitted = true` promotes to `seen_urls` without
    /// verifying the CRL is cached; a wrongly promoted URL is never re-enqueued
    /// for the process lifetime.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_settle_pending(&self, url: &str, admitted: bool) {
        if admitted {
            self.promote_pending_to_seen(url);
        } else {
            self.clear_pending(url);
        }
    }

    /// Test-only: current count of host semaphores. Used by
    /// `tests/crl_map_bounds.rs` to assert the cap is enforced.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_host_semaphore_count(&self) -> usize {
        self.host_semaphores
            .try_lock()
            .map_or(0, |guard| guard.len())
    }

    /// Test-only: current number of entries in the CRL cache.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_cache_len(&self) -> usize {
        self.cache_lock().try_read().map_or(0, |guard| guard.len())
    }

    /// Test-only: whether a specific URL is currently cached.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_cache_contains(&self, url: &str) -> bool {
        self.cache_lock()
            .try_read()
            .is_ok_and(|guard| guard.contains_key(url))
    }

    /// Test-only: whether a URL is advertised to the fail-closed precheck as
    /// present in the live verifier.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_cached_url_contains(&self, url: &str) -> bool {
        self.verifier_state.load().cached_urls.contains(url)
    }

    /// # ⚠️ Security
    ///
    /// Calls `gated_fetch` directly, bypassing `note_discovered_urls` and
    /// therefore `discovery_limiter.check()`, the per-minute CDP discovery cap.
    /// SSRF, scheme, and concurrency caps still apply.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_trigger_fetch(&self, url: &str) -> Result<(), RmcpServerKitError> {
        if let Err(error) = gated_fetch(
            &self.client,
            &self.global_fetch_sem,
            &self.host_semaphores,
            url,
            self.config.crl_allow_http,
            self.max_response_bytes,
            self.config.crl_max_host_semaphores,
        )
        .await
        {
            if error
                .to_string()
                .contains("crl_host_semaphore_cap_exceeded")
            {
                Err(error)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Test-only: insert through `commit_cache_update_atomically`, preserving
    /// normal cache/verifier publication. Best-effort: discards verifier
    /// rebuild errors, so an invalid CRL is a silent no-op.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_insert_cache(&self, url: &str, cached: CachedCrl) {
        let _ = self
            .commit_cache_update_atomically(vec![(url.to_owned(), cached)], &[])
            .await;
    }

    /// Test-only: direct cache insertion that returns verifier rebuild errors.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_try_insert_cache(
        &self,
        url: &str,
        cached: CachedCrl,
    ) -> Result<bool, RmcpServerKitError> {
        self.commit_cache_update_atomically(vec![(url.to_owned(), cached)], &[])
            .await
    }

    /// # ⚠️ Security
    ///
    /// Writes into `cache` directly, bypassing `commit_cache_update_atomically`
    /// and publication ordering at lines 283-291. This can desynchronise
    /// `cached_urls` from `inner_verifier`; with default
    /// `crl_deny_on_unavailable = true`, the lines 547-579 precheck trusts
    /// `cached_urls` and can admit a certificate whose revocation status is
    /// unenforceable.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_replace_cache_entry_unverified(&self, url: &str, cached: CachedCrl) {
        let mut cache = self.cache_lock().write().await;
        cache.insert(url.to_owned(), cached);
    }

    /// # ⚠️ Security
    ///
    /// Lets a caller-supplied URL reach `refresh_urls` and then `gated_fetch`,
    /// bypassing normal CDP discovery admission, deduplication, and rate-limit
    /// checks.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_trigger_refresh_url(&self, url: &str) -> Result<(), RmcpServerKitError> {
        self.refresh_urls(vec![url.to_owned()]).await
    }

    // cancel-safe (cache integrity): `join_next` fills a local `Vec`; dropping
    // the `JoinSet` aborts unfinished `gated_fetch` before any cache commit.
    // A cancelled fetch leaves at most an idle bounded host semaphore.
    async fn fetch_url_results(
        &self,
        urls: Vec<String>,
    ) -> Vec<(String, Result<CachedCrl, RmcpServerKitError>)> {
        let mut tasks = JoinSet::new();
        for url in urls {
            let client = self.client.clone();
            let global_sem = Arc::clone(&self.global_fetch_sem);
            let host_map = Arc::clone(&self.host_semaphores);
            let allow_http = self.config.crl_allow_http;
            let max_bytes = self.max_response_bytes;
            let max_host_semaphores = self.config.crl_max_host_semaphores;
            tasks.spawn(async move {
                let result = gated_fetch(
                    &client,
                    &global_sem,
                    &host_map,
                    &url,
                    allow_http,
                    max_bytes,
                    max_host_semaphores,
                )
                .await;
                (url, result)
            });
        }

        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(result) => results.push(result),
                Err(error) => {
                    tracing::warn!(error = %error, "CRL refresh task join failed");
                }
            }
        }

        results
    }
}

#[cfg(any(test, feature = "test-helpers"))]
const SYNTHETIC_TEST_CRL_DER: &[u8] = &[
    48, 129, 199, 48, 110, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 14, 49, 12,
    48, 10, 6, 3, 85, 4, 3, 12, 3, 99, 114, 108, 23, 13, 50, 54, 48, 49, 48, 49, 48, 48, 48, 48,
    48, 48, 90, 23, 13, 50, 55, 48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90, 160, 47, 48, 45, 48,
    31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 14, 62, 48, 146, 7, 182, 179, 215, 90, 226, 214,
    90, 201, 83, 149, 116, 34, 31, 26, 255, 48, 10, 6, 3, 85, 29, 20, 4, 3, 2, 1, 1, 48, 10, 6, 8,
    42, 134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70, 2, 33, 0, 250, 240, 103, 87, 60, 78, 208, 171,
    184, 206, 117, 134, 236, 234, 53, 115, 122, 90, 64, 217, 146, 27, 32, 103, 170, 222, 240, 159,
    137, 187, 116, 6, 2, 33, 0, 188, 23, 204, 232, 130, 84, 135, 249, 43, 208, 224, 220, 202, 57,
    98, 140, 4, 251, 148, 189, 105, 68, 105, 40, 53, 180, 208, 38, 193, 120, 118, 100,
];

impl CachedCrl {
    /// Test-only: synthesize a cache entry that looks valid, `next_update`
    /// = now + 24h. Fields used only to populate the HashMap — the bytes
    /// are a minimal CRL-shape that won't be parsed by tests.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_synthetic(now: SystemTime) -> Self {
        Self {
            der: CertificateRevocationListDer::from(SYNTHETIC_TEST_CRL_DER.to_vec()),
            this_update: now,
            next_update: now.checked_add(Duration::from_hours(24)),
            fetched_at: now,
            source_url: "test://synthetic".to_owned(),
        }
    }

    /// Test-only: synthesize a STALE cache entry (`next_update` in the
    /// deep past so `is_stale_beyond_grace` fires with any sensible
    /// `crl_stale_grace`).
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_stale(reference_past: SystemTime) -> Self {
        Self {
            der: CertificateRevocationListDer::from(vec![0x30, 0x00]),
            this_update: reference_past,
            next_update: Some(reference_past),
            fetched_at: reference_past,
            source_url: "test://stale".to_owned(),
        }
    }
}

/// Stable outer verifier that delegates all TLS verification behavior to the
/// atomically swappable inner verifier.
pub struct DynamicClientCertVerifier {
    inner: Arc<CrlSet>,
    dn_subjects: Vec<DistinguishedName>,
}

impl DynamicClientCertVerifier {
    /// Construct a new dynamic verifier from a shared [`CrlSet`].
    #[must_use]
    pub fn new(inner: Arc<CrlSet>) -> Self {
        Self {
            dn_subjects: inner.roots.subjects(),
            inner,
        }
    }
}

impl std::fmt::Debug for DynamicClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicClientCertVerifier")
            .field("dn_subjects_len", &self.dn_subjects.len())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for DynamicClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        let state = self.inner.verifier_state.load();
        state.verifier.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        let state = self.inner.verifier_state.load();
        state.verifier.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.dn_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // SECURITY: extracting CDP URLs from an unverified client cert
        // here is intentional. No HTTP happens on this path -- the call
        // to `note_discovered_urls` only enqueues onto a bounded,
        // rate-limited channel. The actual fetch runs off-path in
        // `run_crl_refresher` and is gated by SSRF screening
        // (`src/ssrf.rs`), body-size cap, deadline, and the
        // `crl_allow_http` policy. CRLs are CA-signed (RFC 5280 §5), so
        // http(s) CDP URLs are protocol design, not an SSRF sink. The
        // discovery must happen BEFORE delegating to the inner verifier
        // so `crl_deny_on_unavailable = true` can fail-closed on a
        // never-fetched CDP. Do NOT reorder.
        let mut end_entity_urls =
            extract_cdp_urls(end_entity.as_ref(), self.inner.config.crl_allow_http);
        end_entity_urls.sort();
        end_entity_urls.dedup();

        let mut intermediate_urls = Vec::new();
        for intermediate in intermediates {
            intermediate_urls.extend(extract_cdp_urls(
                intermediate.as_ref(),
                self.inner.config.crl_allow_http,
            ));
        }
        intermediate_urls.sort();
        intermediate_urls.dedup();

        let (revocation_unavailable, state) = self
            .inner
            .note_discovered_urls(&end_entity_urls, &intermediate_urls);
        if revocation_unavailable {
            return Err(TlsError::General(
                "client certificate revocation status unavailable".to_owned(),
            ));
        }

        state
            .verifier
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let state = self.inner.verifier_state.load();
        state.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let state = self.inner.verifier_state.load();
        state.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let state = self.inner.verifier_state.load();
        state.verifier.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        let state = self.inner.verifier_state.load();
        state.verifier.requires_raw_public_keys()
    }
}

/// Extract CRL Distribution Point URLs from a DER-encoded certificate.
///
/// URLs are validated with `url::Url::parse` (case-insensitive scheme handling)
/// and filtered through an internal scheme guard. Malformed URLs, URLs
/// using disallowed schemes, and URLs carrying embedded credentials
/// (userinfo) are silently dropped. SSRF defenses against private
/// IP literals and metadata endpoints are applied later, at fetch time, after
/// DNS resolution.
#[must_use]
pub fn extract_cdp_urls(cert_der: &[u8], allow_http: bool) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return Vec::new();
    };

    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(cdps) = ext.parsed_extension() {
            for point in cdps.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            let raw = *uri;
                            let Ok(parsed) = Url::parse(raw) else {
                                // `?raw` (Debug) escapes control characters the
                                // failed parse may have left in this
                                // attacker-supplied string.
                                tracing::debug!(url = ?raw, "CDP URL parse failed; dropped");
                                continue;
                            };
                            if let Err(reason) = check_scheme(&parsed, allow_http) {
                                tracing::debug!(
                                    url = %sanitized_url_for_log(&parsed),
                                    reason,
                                    "CDP URL rejected by scheme guard; dropped"
                                );
                                continue;
                            }
                            urls.push(parsed.into());
                        }
                    }
                }
            }
        }
    }

    urls
}

/// Bound the startup CDP fan-out to the same limit the steady-state cache obeys.
///
/// SECURITY: `bootstrap_fetch` is a public helper taking a raw [`MtlsConfig`]
/// and raw CA certificates, so it is reachable without
/// `McpServerConfig::validate`. A broad CA bundle would otherwise spawn one
/// fetch task and one cache entry per distinct CDP URL, unbounded by the cap
/// that governs every other cache write.
///
/// Extracted from `bootstrap_fetch` so the bound is testable at all: that
/// function cannot be driven from a test without weakening production SSRF
/// screening, which `bootstrap_cache_cap_is_applied_before_crl_set_publication`
/// documents at length and explicitly forbids.
fn cap_bootstrap_urls(urls: &mut Vec<String>, cap: usize) {
    if urls.len() > cap {
        tracing::warn!(
            discovered = urls.len(),
            cap,
            "CRL bootstrap: CA chain advertises more distinct CDP URLs than \
             crl_max_cache_entries; fetching only the first {cap} after dedup"
        );
        urls.truncate(cap);
    }
}

/// Bootstrap the CRL cache by extracting CDP URLs from the CA chain and
/// fetching any reachable CRLs with a 10-second total deadline.
///
/// # Errors
///
/// Returns an error if the initial verifier cannot be built.
#[allow(
    clippy::cognitive_complexity,
    reason = "bootstrap coordinates timeout, parallel fetches, and partial-cache recovery"
)]
// cancel-safe: CRL cache state is local until final `CrlSet::new`; timeout or
// cancellation drops the `JoinSet`, aborting in-flight `gated_fetch` before
// publication. Bootstrap host semaphores are local and drop with this future.
pub async fn bootstrap_fetch(
    roots: Arc<RootCertStore>,
    ca_certs: &[CertificateDer<'static>],
    config: MtlsConfig,
) -> Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>), RmcpServerKitError> {
    let (discover_tx, discover_rx) = mpsc::unbounded_channel();

    let mut urls = ca_certs
        .iter()
        .flat_map(|cert| extract_cdp_urls(cert.as_ref(), config.crl_allow_http))
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    cap_bootstrap_urls(&mut urls, config.crl_max_cache_entries);

    // M-H2: same SSRF resolver hardening as CrlSet::new -- bootstrap
    // fetches the same attacker-controlled CDP URLs, just earlier in
    // the lifecycle.
    let bootstrap_allowlist = Arc::new(crate::ssrf::CompiledSsrfAllowlist::default());
    let bootstrap_resolver: Arc<dyn reqwest::dns::Resolve> =
        Arc::new(crate::ssrf_resolver::SsrfScreeningResolver::new(
            Arc::clone(&bootstrap_allowlist),
            #[cfg(any(test, feature = "test-helpers"))]
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(not(any(test, feature = "test-helpers")))]
            (),
        ));

    let client = reqwest::Client::builder()
        // M-H2/N1: see oauth.rs::OauthHttpClient::build for rationale.
        .no_proxy()
        .dns_resolver(Arc::clone(&bootstrap_resolver))
        .timeout(config.crl_fetch_timeout)
        .connect_timeout(CRL_CONNECT_TIMEOUT)
        .tcp_keepalive(None)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| RmcpServerKitError::Startup(format!("CRL HTTP client init: {error}")))?;

    // Bootstrap shares the same global concurrency + per-host cap as the
    // hot-path verifier so a maliciously broad CA chain cannot overwhelm
    // the network at startup.
    // Defense in depth: this public helper accepts raw `MtlsConfig` directly,
    // so callers can bypass `McpServerConfig::validate`.
    let bootstrap_concurrency = config.crl_max_concurrent_fetches.max(1);
    let global_sem = Arc::new(Semaphore::new(bootstrap_concurrency));
    let host_semaphores = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let allow_http = config.crl_allow_http;
    let max_bytes = config.crl_max_response_bytes;
    let max_host_semaphores = config.crl_max_host_semaphores;

    let mut initial_cache = HashMap::new();
    let mut tasks = JoinSet::new();
    for url in &urls {
        let client = client.clone();
        let url = url.clone();
        let global_sem = Arc::clone(&global_sem);
        let host_semaphores = Arc::clone(&host_semaphores);
        tasks.spawn(async move {
            let result = gated_fetch(
                &client,
                &global_sem,
                &host_semaphores,
                &url,
                allow_http,
                max_bytes,
                max_host_semaphores,
            )
            .await;
            (url, result)
        });
    }

    let timeout: Sleep = tokio::time::sleep(BOOTSTRAP_TIMEOUT);
    tokio::pin!(timeout);

    while !tasks.is_empty() {
        // cancel-safe: pinned Sleep and JoinSet::join_next are cancel-safe
        // (tokio docs); on timeout the loop breaks and dropping the JoinSet
        // aborts remaining fetches — the intended deadline behavior.
        tokio::select! {
            () = &mut timeout => {
                tracing::warn!("CRL bootstrap timed out after {:?}", BOOTSTRAP_TIMEOUT);
                break;
            }
            maybe_joined = tasks.join_next() => {
                let Some(joined) = maybe_joined else {
                    break;
                };
                match joined {
                    Ok((url, Ok(cached))) => {
                        initial_cache.insert(url, cached);
                    }
                    Ok((url, Err(error))) => {
                        tracing::warn!(url = %url, error = %error, "CRL bootstrap fetch failed");
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "CRL bootstrap task join failed");
                    }
                }
            }
        }
    }

    let set = new_crl_set_from_bootstrap_cache(roots, config, discover_tx, initial_cache)?;
    Ok((set, discover_rx))
}

fn new_crl_set_from_bootstrap_cache(
    roots: Arc<RootCertStore>,
    config: MtlsConfig,
    discover_tx: mpsc::UnboundedSender<String>,
    mut initial_cache: HashMap<String, CachedCrl>,
) -> Result<Arc<CrlSet>, RmcpServerKitError> {
    apply_bootstrap_cache_cap(&mut initial_cache, config.crl_max_cache_entries);
    CrlSet::new(roots, config, discover_tx, initial_cache)
}

fn apply_bootstrap_cache_cap(
    initial_cache: &mut HashMap<String, CachedCrl>,
    max_cache_entries: usize,
) {
    if initial_cache.len() <= max_cache_entries {
        return;
    }

    let mut urls = initial_cache.keys().cloned().collect::<Vec<_>>();
    urls.sort();
    for url in urls.into_iter().skip(max_cache_entries) {
        initial_cache.remove(&url);
    }
}

/// Run the CRL refresher loop until shutdown.
#[allow(
    clippy::cognitive_complexity,
    reason = "refresher loop intentionally handles shutdown, timer, and discovery in one select"
)]
// cancel-safe, including under abort: cooperative `shutdown` breaks the loop at
// a settlement point, and the discovery arm holds a `PendingUrlGuard` across
// `fetch_and_store_url`, so a `JoinHandle::abort` that drops the future mid-await
// still clears the transient `pending_urls` marker via `Drop`. Without that
// guard a stale marker would suppress re-enqueue forever (see the note above
// `seen_urls`/`pending_urls` clearing) and silently narrow revocation coverage.
pub async fn run_crl_refresher(
    set: Arc<CrlSet>,
    mut discover_rx: mpsc::UnboundedReceiver<String>,
    shutdown: CancellationToken,
) {
    let mut refresh_sleep = schedule_next_refresh(&set).await;

    loop {
        // cancel-safe: CancellationToken::cancelled, pinned &mut Sleep, and
        // mpsc::UnboundedReceiver::recv are all cancel-safe (tokio docs);
        // refresh work happens inside arm bodies, never in the raced futures.
        tokio::select! {
            () = shutdown.cancelled() => {
                break;
            }
            () = &mut refresh_sleep => {
                if let Err(error) = set.refresh_due_urls().await {
                    tracing::warn!(error = %error, "CRL periodic refresh failed");
                }
                refresh_sleep = schedule_next_refresh(&set).await;
            }
            maybe_url = discover_rx.recv() => {
                let Some(url) = maybe_url else {
                    break;
                };
                let pending_guard = PendingUrlGuard::armed(Arc::clone(&set), url.clone());
                let result = set.fetch_and_store_url(url).await;
                settle_discovered_url(pending_guard, result);
                refresh_sleep = schedule_next_refresh(&set).await;
            }
        }
    }
}

// Abort-safety guard for the discovery arm in `run_crl_refresher`. Cooperative
// shutdown already leaves `pending_urls` consistent because the arm body runs to
// a normal `Ok`/`Err` settlement point, but `JoinHandle::abort` drops the future
// at whatever `.await` it is currently suspended on. Holding this owned guard
// across `fetch_and_store_url` makes that hard-abort path deterministic too: if
// the fetch future is dropped before a CRL is confirmed cached, `Drop` removes
// the transient in-flight marker so the CDP can be retried by a later handshake.
struct PendingUrlGuard {
    set: Arc<CrlSet>,
    url: String,
    armed: bool,
}

impl PendingUrlGuard {
    fn armed(set: Arc<CrlSet>, url: String) -> Self {
        Self {
            set,
            url,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingUrlGuard {
    fn drop(&mut self) {
        if self.armed {
            self.set.clear_pending(&self.url);
        }
    }
}

fn settle_discovered_url(
    mut pending_guard: PendingUrlGuard,
    result: Result<bool, RmcpServerKitError>,
) {
    match result {
        // Cached: safe to suppress this URL permanently.
        Ok(true) => {
            pending_guard.disarm();
            pending_guard
                .set
                .promote_pending_to_seen(&pending_guard.url);
        }
        // Fetched but refused by the cache cap. Keep the guard armed so scope
        // exit clears the in-flight marker before refresh rescheduling, and a
        // later handshake can retry; suppressing it here would disable
        // revocation for this CDP even though no CRL was ever cached.
        Ok(false) => {
            tracing::warn!(
                url = %pending_guard.url,
                "CRL fetched but not admitted to cache (cap reached); will retry on a later handshake"
            );
        }
        Err(error) => {
            tracing::warn!(
                url = %pending_guard.url,
                error = %error,
                "CRL discovery fetch failed; will retry on a later handshake"
            );
        }
    }
}

/// Rebuild the inner rustls verifier from the current CRL cache.
///
/// # Errors
///
/// Returns an error if rustls rejects the verifier configuration.
pub fn rebuild_verifier<S: std::hash::BuildHasher>(
    roots: &Arc<RootCertStore>,
    config: &MtlsConfig,
    cache: &HashMap<String, CachedCrl, S>,
) -> Result<Arc<dyn ClientCertVerifier>, RmcpServerKitError> {
    let mut builder = WebPkiClientVerifier::builder(Arc::clone(roots));

    if !cache.is_empty() {
        let crls = cache
            .values()
            .map(|cached| cached.der.clone())
            .collect::<Vec<_>>();
        builder = builder.with_crls(crls);
    }
    if config.crl_end_entity_only {
        builder = builder.only_check_end_entity_revocation();
    }
    if !config.crl_deny_on_unavailable {
        builder = builder.allow_unknown_revocation_status();
    }
    if config.crl_enforce_expiration {
        builder = builder.enforce_revocation_expiration();
    }
    if !config.required {
        builder = builder.allow_unauthenticated();
    }

    builder
        .build()
        .map_err(|error| RmcpServerKitError::Tls(format!("mTLS verifier error: {error}")))
}

/// Parse `thisUpdate` and `nextUpdate` metadata from a DER-encoded CRL.
///
/// # Errors
///
/// Returns an error if the CRL cannot be parsed.
pub fn parse_crl_metadata(
    der: &[u8],
) -> Result<(SystemTime, Option<SystemTime>), RmcpServerKitError> {
    let (_, crl) = CertificateRevocationList::from_der(der)
        .map_err(|error| RmcpServerKitError::Tls(format!("invalid CRL DER: {error:?}")))?;

    Ok((
        asn1_time_to_system_time(crl.last_update()),
        crl.next_update().map(asn1_time_to_system_time),
    ))
}

async fn schedule_next_refresh(set: &CrlSet) -> Pin<Box<Sleep>> {
    let duration = next_refresh_delay(set).await;
    boxed_sleep(duration)
}

fn boxed_sleep(duration: Duration) -> Pin<Box<Sleep>> {
    Box::pin(tokio::time::sleep_until(Instant::now() + duration))
}

async fn next_refresh_delay(set: &CrlSet) -> Duration {
    if let Some(interval) = set.config.crl_refresh_interval {
        return clamp_refresh(interval);
    }

    let now = SystemTime::now();
    let cache = set.cache_lock().read().await;
    let mut next = MAX_AUTO_REFRESH;

    for cached in cache.values() {
        if let Some(next_update) = cached.next_update {
            let duration = next_update.duration_since(now).unwrap_or(Duration::ZERO);
            next = next.min(clamp_refresh(duration));
        }
    }
    drop(cache);

    next
}

/// Get-or-insert the per-host fetch semaphore for `host_key`.
///
/// When the map is at `max_host_semaphores`, idle entries (no in-flight
/// fetch) are evicted before rejecting, so the cap only fails when `max`
/// distinct hosts are *concurrently* fetching — it is never a permanent
/// lockout. Every clone of a host semaphore is created while holding the
/// map lock, and a clone outlives the critical section only while a fetch
/// is in flight, so an entry with `Arc::strong_count == 1` is provably
/// idle and safe to drop.
fn acquire_host_semaphore(
    map: &mut HashMap<String, Arc<Semaphore>>,
    host_key: &str,
    max_host_semaphores: usize,
) -> Result<Arc<Semaphore>, RmcpServerKitError> {
    if !map.contains_key(host_key) {
        if map.len() >= max_host_semaphores {
            // Self-heal: drop semaphores with no in-flight fetch.
            map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
        }
        if map.len() >= max_host_semaphores {
            return Err(RmcpServerKitError::Config(
                "crl_host_semaphore_cap_exceeded: too many distinct CRL hosts in flight".to_owned(),
            ));
        }
        map.insert(host_key.to_owned(), Arc::new(Semaphore::new(1)));
    }
    match map.get(host_key) {
        Some(semaphore) => Ok(Arc::clone(semaphore)),
        None => Err(RmcpServerKitError::Tls(
            "CRL host semaphore missing after insertion".to_owned(),
        )),
    }
}

/// Fetch a single CRL URL through the global + per-host concurrency caps.
///
/// `global_sem` caps total simultaneous CRL fetches process-wide.
/// `host_semaphores` ensures at most one in-flight fetch per origin host
/// (an SSRF amplification defense); at the host cap, idle entries are
/// evicted on demand. Both permits are dropped when the returned future
/// completes (whether `Ok` or `Err`).
// cancel-safe for permits: cancelling queued `acquire_owned` loses only queue
// position, acquired global/host permits RAII-drop, and host-map insertion can
// leave only an idle bounded semaphore entry that later self-heals.
async fn gated_fetch(
    client: &reqwest::Client,
    global_sem: &Arc<Semaphore>,
    host_semaphores: &Arc<tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>>,
    url: &str,
    allow_http: bool,
    max_bytes: u64,
    max_host_semaphores: usize,
) -> Result<CachedCrl, RmcpServerKitError> {
    let host_key = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned());

    let host_sem = {
        let mut map = host_semaphores.lock().await;
        acquire_host_semaphore(&mut map, &host_key, max_host_semaphores)?
    };

    let _global_permit = Arc::clone(global_sem)
        .acquire_owned()
        .await
        .map_err(|error| {
            RmcpServerKitError::Tls(format!("CRL global semaphore closed: {error}"))
        })?;
    let _host_permit = host_sem
        .acquire_owned()
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL host semaphore closed: {error}")))?;

    fetch_crl(client, url, allow_http, max_bytes).await
}

// cancel-safe: DNS lookup, request send, chunk reads, DER parse, and metadata
// extraction build only a local `CachedCrl`; CRL cache/verifier state changes
// happen later, when callers commit the returned value.
async fn fetch_crl(
    client: &reqwest::Client,
    url: &str,
    allow_http: bool,
    max_bytes: u64,
) -> Result<CachedCrl, RmcpServerKitError> {
    let parsed = Url::parse(url)
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL URL parse {url}: {error}")))?;

    if let Err(reason) = check_scheme(&parsed, allow_http) {
        // Sanitized: the gate must not echo what it rejects (the URL may
        // carry userinfo credentials — the very thing being refused).
        let sanitized = sanitized_url_for_log(&parsed);
        tracing::warn!(url = %sanitized, reason, "CRL fetch denied: scheme");
        return Err(RmcpServerKitError::Tls(format!(
            "CRL scheme rejected ({reason}): {sanitized}"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| RmcpServerKitError::Tls(format!("CRL URL has no host: {url}")))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| RmcpServerKitError::Tls(format!("CRL URL has no known port: {url}")))?;

    let addrs = lookup_host((host, port))
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL DNS resolution {url}: {error}")))?;

    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        if let Some(reason) = ip_block_reason(addr.ip()) {
            tracing::warn!(
                url = %url,
                resolved_ip = %addr.ip(),
                reason,
                "CRL fetch denied: blocked IP"
            );
            return Err(RmcpServerKitError::Tls(format!(
                "CRL host resolved to blocked IP ({reason}): {url}"
            )));
        }
    }
    if !any_addr {
        return Err(RmcpServerKitError::Tls(format!(
            "CRL DNS resolution returned no addresses: {url}"
        )));
    }

    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL fetch {url}: {error}")))?
        .error_for_status()
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL fetch {url}: {error}")))?;

    // Enforce body cap by streaming chunk-by-chunk; a malicious or
    // misconfigured server cannot allocate more than `max_bytes` of memory.
    let initial_capacity = usize::try_from(max_bytes.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut body: Vec<u8> = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL read {url}: {error}")))?
    {
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if body_len.saturating_add(chunk_len) > max_bytes {
            return Err(RmcpServerKitError::Tls(format!(
                "CRL body exceeded cap of {max_bytes} bytes: {url}"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let der = CertificateRevocationListDer::from(body);
    let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;

    Ok(CachedCrl {
        der,
        this_update,
        next_update,
        fetched_at: SystemTime::now(),
        source_url: url.to_owned(),
    })
}

fn should_refresh_cached(
    cached: &CachedCrl,
    now: SystemTime,
    fixed_interval: Option<Duration>,
) -> bool {
    if let Some(interval) = fixed_interval {
        return cached
            .fetched_at
            .checked_add(clamp_refresh(interval))
            .is_none_or(|deadline| now >= deadline);
    }

    cached
        .next_update
        .is_none_or(|next_update| now >= next_update)
}

fn clamp_refresh(duration: Duration) -> Duration {
    duration.clamp(MIN_AUTO_REFRESH, MAX_AUTO_REFRESH)
}

/// 9999-12-31T23:59:59Z — the maximum instant expressible as an ASN.1
/// GeneralizedTime (four-digit year). Used to clamp absurd positive
/// timestamps before converting to [`SystemTime`].
const MAX_ASN1_TIMESTAMP_SECS: u64 = 253_402_300_799;

/// Convert an ASN.1 time to [`SystemTime`] without ever panicking.
///
/// CRL metadata is parsed from raw fetched bytes *before* signature
/// validation, so timestamps are attacker-controlled. Platform
/// `SystemTime` ranges differ (Windows cannot represent pre-1601);
/// unrepresentable values are clamped toward [`UNIX_EPOCH`], which is the
/// safe direction: it can only make a CRL look *older* (forcing an
/// eager refresh), never fresher.
fn asn1_time_to_system_time(time: x509_parser::time::ASN1Time) -> SystemTime {
    let timestamp = time.timestamp();
    if timestamp >= 0 {
        let seconds = u64::try_from(timestamp)
            .unwrap_or(0)
            .min(MAX_ASN1_TIMESTAMP_SECS);
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(timestamp.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        deprecated,
        reason = "these tests deliberately exercise the deprecated out-of-band cache surface and the ungated test constructors; that is precisely the behaviour under test"
    )]

    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<StdMutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    struct CapturedLogsWriter(Arc<StdMutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            {
                let mut guard = self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    fn asn1(timestamp: i64) -> x509_parser::time::ASN1Time {
        x509_parser::time::ASN1Time::from_timestamp(timestamp).expect("valid ASN.1 timestamp")
    }

    fn install_ring_provider() {
        // `CrlSet::new` builds a reqwest client whose rustls backend is compiled
        // with `rustls-no-provider`; installing the provider is idempotent and
        // keeps these unit tests independent from whichever integration test
        // happens to initialize crypto first.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn test_ca_root() -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "mtls-revocation-unit-test-ca");
        let key = KeyPair::generate().expect("ca key");
        let issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(params, key).expect("ca self-signed");
        issuer.der().clone()
    }

    fn test_mtls_config() -> MtlsConfig {
        serde_json::from_value(serde_json::json!({
            "ca_cert_path": "memory://ca.pem",
            "required": true,
            "default_role": "viewer",
            "crl_enabled": true,
            "crl_deny_on_unavailable": false,
            "crl_allow_http": true,
            "crl_enforce_expiration": true,
            "crl_end_entity_only": false,
            "crl_fetch_timeout": "30s",
            "crl_stale_grace": "24h",
            "crl_max_concurrent_fetches": 1,
            "crl_max_response_bytes": 5_242_880,
            "crl_discovery_rate_per_min": 60,
            "crl_max_host_semaphores": 16,
            "crl_max_seen_urls": 16,
            "crl_max_cache_entries": 16,
        }))
        .expect("verifier mtls config")
    }

    fn test_crl_set_with_receiver() -> (Arc<CrlSet>, mpsc::UnboundedReceiver<String>) {
        test_crl_set_with_receiver_config(test_mtls_config())
    }

    fn test_crl_set_with_receiver_config(
        config: MtlsConfig,
    ) -> (Arc<CrlSet>, mpsc::UnboundedReceiver<String>) {
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()).expect("add ca root");
        CrlSet::__test_with_kept_receiver(Arc::new(roots), config, vec![])
            .expect("empty CRL set with kept receiver")
    }

    fn pending_contains(set: &CrlSet, url: &str) -> bool {
        set.pending_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(url)
    }

    fn seen_contains(set: &CrlSet, url: &str) -> bool {
        set.seen_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(url)
    }

    fn mark_pending(set: &CrlSet, url: &str) {
        let mut pending = set
            .pending_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.insert(url.to_owned());
    }

    /// The pending marker must exist before a URL becomes observable on the
    /// discovery channel; otherwise a settlement racing the send strands the
    /// URL as permanently pending.
    ///
    /// Asserted at the exact instant it can be violated, via the pre-send
    /// probe. The previous form spun a contending thread across 200 attempts
    /// and could pass without ever producing the bad interleaving.
    #[test]
    fn discovery_does_not_send_before_pending_marker_exists() {
        let mut config = test_mtls_config();
        config.crl_discovery_rate_per_min = 10_000;
        config.crl_max_seen_urls = 512;
        let (set, mut discover_rx) = test_crl_set_with_receiver_config(config);

        let url = "http://pending-order.example.test/crl".to_owned();
        let observed = Arc::new(AtomicUsize::new(0));
        let probe_observed = Arc::clone(&observed);
        let probe_url = url.clone();

        set.__test_set_discovery_send_probe(Arc::new(move |set: &CrlSet, sent: &str| {
            assert_eq!(sent, probe_url, "probe must observe the discovered URL");
            assert!(
                pending_contains(set, sent),
                "URL {sent} became observable before its pending marker existed"
            );
            probe_observed.fetch_add(1, Ordering::Relaxed);
        }));

        let _ = set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]);

        assert_eq!(
            discover_rx.try_recv().ok().as_deref(),
            Some(url.as_str()),
            "the discovered URL must be published exactly once"
        );
        assert_eq!(
            observed.load(Ordering::Relaxed),
            1,
            "the pre-send probe must have fired for this URL"
        );

        set.__test_settle_pending(&url, false);
        assert!(
            !pending_contains(&set, &url),
            "settling a fetch must not strand pending URL {url}"
        );
        assert!(
            !set.__test_is_seen(&url),
            "settling a failed fetch must leave URL {url} discoverable again"
        );
    }

    /// Covers the cap-before-publication invariant directly rather than by
    /// driving `bootstrap_fetch`, because `bootstrap_fetch` cannot be reached
    /// from a test without weakening production SSRF screening.
    ///
    /// `fetch_crl` performs its own DNS precheck -- `tokio::net::lookup_host`
    /// followed by `ip_block_reason` -- *before* handing the request to
    /// `reqwest`. That precheck is independent of the `dns_resolver` injected
    /// into the client, so a custom resolver cannot redirect a fetch to a
    /// local mock: a `wiremock` server on loopback is rejected as a blocked IP
    /// before `reqwest` is ever invoked.
    ///
    /// Reaching `bootstrap_fetch` end to end would therefore require either a
    /// test-only bypass of that precheck, or a CRL served from a public
    /// non-private address. The first is deliberately not done -- a bypass
    /// seam next to CRL fetching is a worse security liability than the
    /// coverage it would buy -- and the second is not available offline.
    ///
    /// This test asserts the property that actually matters: the cap is
    /// applied *before* `CrlSet::new`, so `cache`, `cached_urls`, and
    /// `inner_verifier` are all derived from one already-bounded map. Post-hoc
    /// mutation would violate the publication ordering documented above.
    ///
    /// If you are here to "improve" this by making it drive `bootstrap_fetch`:
    /// do not add a precheck bypass to `fetch_crl` to do it.
    #[tokio::test]
    async fn bootstrap_cache_cap_is_applied_before_crl_set_publication() {
        let cap = 4usize;
        let mut config = test_mtls_config();
        config.crl_max_cache_entries = cap;
        let (discover_tx, _discover_rx) = mpsc::unbounded_channel();
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()).expect("add ca root");
        let roots = Arc::new(roots);
        let now = SystemTime::now();
        let initial_cache: HashMap<String, CachedCrl> = (0..cap + 3)
            .rev()
            .map(|index| format!("https://bootstrap-{index:02}.example.test/crl"))
            .map(|url| {
                let mut cached = CachedCrl::__test_synthetic(now);
                cached.source_url = url.clone();
                (url, cached)
            })
            .collect();

        let set = new_crl_set_from_bootstrap_cache(roots, config, discover_tx, initial_cache)
            .expect("bootstrap cache should build CRL set");
        let cache_keys = {
            let cache = set.cache_lock().read().await;
            assert_eq!(cache.len(), cap, "bootstrap cache len must be capped");
            cache.keys().cloned().collect::<HashSet<_>>()
        };
        let cached_url_keys = {
            let cached_urls = &set.verifier_state.load().cached_urls;
            assert_eq!(
                cached_urls.len(),
                cap,
                "cached_urls len must match capped bootstrap cache"
            );
            cached_urls.iter().cloned().collect::<HashSet<_>>()
        };
        let expected: HashSet<String> = (0..cap)
            .map(|index| format!("https://bootstrap-{index:02}.example.test/crl"))
            .collect();

        assert_eq!(
            cache_keys, cached_url_keys,
            "bootstrap cache and cached_urls must publish the same key set"
        );
        assert_eq!(
            cache_keys, expected,
            "bootstrap admission must keep the first cap URLs in sort order"
        );
    }

    async fn wait_for_host_fetch_to_block_on_global_permit(set: &CrlSet, host: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if set.host_semaphores.lock().await.contains_key(host) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("refresher must reach the CRL fetch path before abort");
    }

    #[tokio::test]
    async fn aborted_refresher_does_not_strand_pending_url() {
        let (set, discover_rx) = test_crl_set_with_receiver();
        let url = "http://abort.example.test/crl";
        let host = "abort.example.test";
        let held_global_permit = Arc::clone(&set.global_fetch_sem)
            .acquire_owned()
            .await
            .expect("test semaphore is open");

        assert!(!pending_contains(&set, url));
        assert!(!seen_contains(&set, url));

        let _ = set.__test_note_discovered_urls_by_cert(&[url.to_owned()], &[]);
        assert!(
            pending_contains(&set, url),
            "queued URL must be marked in-flight before the fetch starts"
        );
        assert!(
            !seen_contains(&set, url),
            "queueing alone must not promote to the permanent dedup set"
        );

        let handle = tokio::spawn(run_crl_refresher(
            Arc::clone(&set),
            discover_rx,
            CancellationToken::new(),
        ));

        wait_for_host_fetch_to_block_on_global_permit(&set, host).await;
        handle.abort();
        let join_error = handle
            .await
            .expect_err("aborted refresher must not complete normally");
        assert!(join_error.is_cancelled());
        drop(held_global_permit);

        assert!(
            !pending_contains(&set, url),
            "aborting while fetch_and_store_url awaits must clear the in-flight marker"
        );
        assert!(
            !seen_contains(&set, url),
            "an aborted fetch must not promote the URL to the permanent dedup set"
        );

        let _ = set.__test_note_discovered_urls(&[url.to_owned()]);
        assert!(
            pending_contains(&set, url),
            "once the stale marker is gone, the same URL can be queued again"
        );
        assert!(
            !seen_contains(&set, url),
            "retry admission must still be pending-only, not permanent suppression"
        );
    }

    #[test]
    fn discovered_url_settlement_promotes_only_confirmed_cache_admission() {
        let (set, _discover_rx) = test_crl_set_with_receiver();
        let url = "http://settle-ok.example.test/crl";
        mark_pending(&set, url);

        let pending_guard = PendingUrlGuard::armed(Arc::clone(&set), url.to_owned());
        settle_discovered_url(pending_guard, Ok(true));

        assert!(
            seen_contains(&set, url),
            "Ok(true) means the CRL is cached and must permanently dedup the URL"
        );
        assert!(
            !pending_contains(&set, url),
            "promotion must remove the transient in-flight marker"
        );
    }

    #[test]
    fn discovered_url_settlement_clears_cache_cap_rejection_and_warns() {
        let (set, _discover_rx) = test_crl_set_with_receiver();
        let url = "http://settle-cap.example.test/crl";
        mark_pending(&set, url);
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let pending_guard = PendingUrlGuard::armed(Arc::clone(&set), url.to_owned());
        settle_discovered_url(pending_guard, Ok(false));

        assert!(
            !pending_contains(&set, url),
            "cache-cap rejection must leave the URL retriable"
        );
        assert!(
            !seen_contains(&set, url),
            "cache-cap rejection must not promote permanent suppression"
        );
        let contents = logs.contents();
        assert!(
            contents.contains(
                "CRL fetched but not admitted to cache (cap reached); will retry on a later handshake"
            ),
            "existing cache-cap warning must still be emitted: {contents}"
        );
    }

    #[test]
    fn discovered_url_settlement_clears_fetch_failure_and_warns() {
        let (set, _discover_rx) = test_crl_set_with_receiver();
        let url = "http://settle-error.example.test/crl";
        mark_pending(&set, url);
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let pending_guard = PendingUrlGuard::armed(Arc::clone(&set), url.to_owned());
        settle_discovered_url(
            pending_guard,
            Err(RmcpServerKitError::Tls("test-fetch-failed".to_owned())),
        );

        assert!(
            !pending_contains(&set, url),
            "fetch failure must leave the URL retriable"
        );
        assert!(
            !seen_contains(&set, url),
            "fetch failure must not promote permanent suppression"
        );
        let contents = logs.contents();
        assert!(
            contents.contains("CRL discovery fetch failed; will retry on a later handshake"),
            "existing fetch-failure warning must still be emitted: {contents}"
        );
        assert!(
            contents.contains("test-fetch-failed"),
            "existing warning must still include the fetch error: {contents}"
        );
    }

    /// The userinfo gate fires before DNS resolution (no network needed)
    /// and the surfaced error must not echo the rejected credentials.
    #[tokio::test]
    async fn fetch_crl_rejects_userinfo_without_echoing_credentials() {
        // reqwest with `rustls-no-provider` requires a process-wide crypto
        // provider before any Client is built (same pattern as the
        // transport/oauth test suites).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::new();
        let err = fetch_crl(&client, "https://u:p@crl.example/ca.crl", false, 1024)
            .await
            .expect_err("userinfo-bearing CRL URL must be rejected");
        let rendered = err.to_string();
        assert!(
            rendered.contains("userinfo_forbidden"),
            "error must carry the rejection reason: {rendered}"
        );
        assert!(
            !rendered.contains("u:p"),
            "error must not echo the rejected credentials: {rendered}"
        );
    }

    /// `extract_cdp_urls`'s scheme/userinfo guard reuses the same gate;
    /// the sanitizer keeps credentials out of its debug logging too.
    #[test]
    fn sanitizer_used_by_rejection_sites_strips_credentials() {
        let parsed = Url::parse("https://u:p@crl.example/ca.crl").expect("parse");
        let sanitized = sanitized_url_for_log(&parsed);
        assert_eq!(sanitized, "https://crl.example");
        assert!(!sanitized.contains("u:p"));
    }

    #[test]
    fn asn1_time_clamps_unrepresentable_timestamps() {
        // Year 1500 — pre-1601, NOT representable by Windows `SystemTime`.
        // Pre-fix this panicked on Windows; now it must return a value no
        // later than the epoch on every platform (clamped to UNIX_EPOCH on
        // Windows, the real instant on platforms that can represent it).
        let year_1500 = asn1_time_to_system_time(asn1(-14_831_769_600));
        assert!(year_1500 <= UNIX_EPOCH);
        #[cfg(windows)]
        assert_eq!(year_1500, UNIX_EPOCH);

        // 1601-01-01T00:00:00Z — the exact Windows epoch boundary, which IS
        // representable everywhere. No clamp, no panic.
        let year_1601 = asn1_time_to_system_time(asn1(-11_644_473_600));
        assert!(year_1601 <= UNIX_EPOCH);

        // Mildly negative (pre-1970) stays at-or-before the epoch.
        assert!(asn1_time_to_system_time(asn1(-2)) <= UNIX_EPOCH);

        // Normal positive timestamps round-trip exactly.
        assert_eq!(
            asn1_time_to_system_time(asn1(1_700_000_000)),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );

        // The ASN.1 maximum (9999-12-31) is representable and preserved.
        let max = i64::try_from(MAX_ASN1_TIMESTAMP_SECS).expect("fits in i64");
        assert_eq!(
            asn1_time_to_system_time(asn1(max)),
            UNIX_EPOCH + Duration::from_secs(MAX_ASN1_TIMESTAMP_SECS)
        );
    }

    #[test]
    fn host_semaphore_evicts_idle_at_cap() {
        let mut map = HashMap::new();
        for i in 0..4 {
            // Dropped immediately: only the map holds each semaphore (idle).
            drop(
                acquire_host_semaphore(&mut map, &format!("idle-{i}.example"), 4)
                    .expect("under cap"),
            );
        }
        assert_eq!(map.len(), 4);

        // At the cap, a NEW host must succeed by evicting idle entries —
        // the cap error is not sticky.
        let sem = acquire_host_semaphore(&mut map, "new-host.example", 4)
            .expect("idle eviction frees space for a new host");
        assert!(map.contains_key("new-host.example"));
        drop(sem);
    }

    #[test]
    fn host_semaphore_keeps_inflight_at_cap() {
        let mut map = HashMap::new();
        // Held across the cap check: simulates an in-flight fetch.
        let inflight = acquire_host_semaphore(&mut map, "busy.example", 3).expect("under cap");
        for i in 0..2 {
            drop(
                acquire_host_semaphore(&mut map, &format!("idle-{i}.example"), 3)
                    .expect("under cap"),
            );
        }
        assert_eq!(map.len(), 3);

        drop(
            acquire_host_semaphore(&mut map, "new-host.example", 3)
                .expect("idle entries evicted while in-flight survives"),
        );
        assert!(
            map.contains_key("busy.example"),
            "in-flight host must survive eviction"
        );
        assert!(map.contains_key("new-host.example"));
        drop(inflight);
    }

    #[test]
    fn host_semaphore_cap_error_when_all_inflight() {
        let mut map = HashMap::new();
        let held: Vec<_> = (0..2)
            .map(|i| {
                acquire_host_semaphore(&mut map, &format!("busy-{i}.example"), 2)
                    .expect("under cap")
            })
            .collect();

        let result = acquire_host_semaphore(&mut map, "new-host.example", 2);
        assert!(
            result.is_err(),
            "cap must still reject when every entry has an in-flight fetch"
        );
        drop(held);
    }

    // ---- CrlSet cache invariant (A1/A2/A3) --------------------------------

    fn tamper_test_config() -> MtlsConfig {
        let mut config = test_mtls_config();
        config.crl_deny_on_unavailable = true;
        config.crl_end_entity_only = false;
        config.crl_discovery_rate_per_min = 10_000;
        config.crl_max_seen_urls = 4096;
        config.crl_max_cache_entries = 4096;
        config
    }

    fn synthetic_entry(now: SystemTime) -> CachedCrl {
        CachedCrl::__test_synthetic(now)
    }

    fn identity_of(set: &CrlSet, url: &str) -> Option<EntryIdentity> {
        set.verifier_state
            .load()
            .committed_identities
            .get(url)
            .cloned()
    }

    fn warned(set: &CrlSet, which: &str) -> bool {
        set.last_cap_warn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(which)
    }

    /// A replacement that is indistinguishable from `entry` on every cheap
    /// field: same DER length, same 32-byte head and tail, same scalars, same
    /// `source_url`. Only a middle byte differs, so only the reallocation can
    /// betray it. An implementation comparing anything less than the full
    /// identity tuple fails the tests that use this.
    fn same_shape_replacement(entry: &CachedCrl) -> CachedCrl {
        let mut bytes = entry.der.as_ref().to_vec();
        let middle = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(middle) {
            *byte ^= 0xFF;
        }
        CachedCrl {
            der: CertificateRevocationListDer::from(bytes),
            this_update: entry.this_update,
            next_update: entry.next_update,
            fetched_at: entry.fetched_at,
            source_url: entry.source_url.clone(),
        }
    }

    fn crl_set_with_cached_urls(config: MtlsConfig, count: usize) -> (Arc<CrlSet>, Vec<String>) {
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()).expect("add ca root");
        let now = SystemTime::now();
        let mut initial_cache = HashMap::new();
        let mut urls = Vec::with_capacity(count);
        for index in 0..count {
            let url = format!("https://cdp-{index:03}.example.test/crl");
            initial_cache.insert(url.clone(), synthetic_entry(now));
            urls.push(url);
        }
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);
        let set = CrlSet::new(Arc::new(roots), config, discover_tx, initial_cache)
            .expect("crl set with prepopulated cache");
        urls.sort();
        (set, urls)
    }

    #[tokio::test]
    async fn identity_index_is_seeded_by_new_and_maintained_by_commit() {
        let boot = "https://cdp-000.example.test/crl";
        let (set, _urls) = crl_set_with_cached_urls(tamper_test_config(), 1);

        // Blocker 1 regression: identities seeded only on commit would read
        // every bootstrap-fetched CRL as mutated and fail mTLS closed at
        // startup.
        assert!(
            identity_of(&set, boot).is_some(),
            "CrlSet::new must record identities for the bootstrap cache"
        );

        let added = "https://added.example.test/crl";
        let now = SystemTime::now();
        set.__test_insert_cache(added, synthetic_entry(now)).await;
        let added_identity = identity_of(&set, added).expect("commit must record an identity");

        set.__test_insert_cache(added, synthetic_entry(now + Duration::from_secs(3_600)))
            .await;
        assert!(
            identity_of(&set, added).as_ref() != Some(&added_identity),
            "legitimate replacement must change the recorded identity"
        );

        set.commit_cache_update_atomically(Vec::new(), &[added.to_owned()])
            .await
            .expect("removal commit");
        assert!(
            identity_of(&set, added).is_none(),
            "removal must drop the identity in the same publication"
        );
    }

    #[test]
    fn identity_covers_der_bytes_beyond_the_sampled_head_and_tail() {
        let entry = synthetic_entry(SystemTime::now());
        assert!(
            entry.der.as_ref().len() > 64,
            "fixture must be longer than head+tail so the middle is unsampled"
        );
        assert!(
            entry_identity(&entry) != entry_identity(&same_shape_replacement(&entry)),
            "a same-length middle-byte edit must still change the identity"
        );
    }

    #[test]
    fn identity_covers_every_scalar_field() {
        let now = SystemTime::now();
        let base = synthetic_entry(now);
        let baseline = entry_identity(&base);

        let mut this_update = base.clone();
        this_update.this_update = now + Duration::from_secs(1);
        let mut next_update = base.clone();
        next_update.next_update = None;
        let mut fetched_at = base.clone();
        fetched_at.fetched_at = now + Duration::from_secs(1);
        let mut source_url = base;
        source_url.source_url = "test://other".to_owned();

        for (label, mutated) in [
            ("this_update", this_update),
            ("next_update", next_update),
            ("fetched_at", fetched_at),
            ("source_url", source_url),
        ] {
            assert!(
                entry_identity(&mutated) != baseline,
                "mutating {label} alone must change the identity"
            );
        }
    }

    #[tokio::test]
    async fn precheck_denies_after_same_key_replace_through_public_cache() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let url = "https://replace.example.test/crl".to_owned();
        let now = SystemTime::now();

        let committed = synthetic_entry(now);
        set.__test_insert_cache(&url, committed.clone()).await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "a legitimately committed CRL must admit the handshake"
        );

        // The replacement matches on DER length, head, tail, every scalar and
        // `source_url`. An implementation that compares anything less than the
        // full identity tuple admits here and fails this test.
        set.__test_replace_cache_entry_unverified(&url, same_shape_replacement(&committed))
            .await;

        assert!(
            set.verifier_state.load().cached_urls.contains(&url),
            "precondition: cached_urls must still claim coverage, or the denial proves nothing"
        );
        assert!(
            set.cache_lock().read().await.contains_key(&url),
            "precondition: the entry must still be present, so this is a REPLACE and not a removal"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "REPLACE through the public cache leaves cached_urls claiming coverage the verifier does not enforce; it must deny"
        );
    }

    #[tokio::test]
    async fn precheck_denies_after_direct_removal_through_public_cache() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let url = "https://remove.example.test/crl".to_owned();

        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;
        assert!(!set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]));

        set.cache_lock().write().await.remove(&url);

        assert!(
            set.verifier_state.load().cached_urls.contains(&url),
            "precondition: cached_urls must still claim the removed URL"
        );
        assert!(
            !set.cache_lock().read().await.contains_key(&url),
            "precondition: the live entry must actually be gone"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "cached_urls still claims a URL whose entry was removed out of band; it must deny"
        );
    }

    #[tokio::test]
    async fn precheck_uses_committed_state_when_cache_lock_is_temporarily_unavailable() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let cached = "https://locked.example.test/crl".to_owned();
        let uncached = "https://locked-uncached.example.test/crl".to_owned();

        set.__test_insert_cache(&cached, synthetic_entry(SystemTime::now()))
            .await;
        assert!(!set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&cached), &[]));

        // Contention is not tamper. `tokio::sync::RwLock` is write-preferring,
        // so denying here would make every legitimate refresh commit deny
        // concurrent handshakes; enforcement still runs against the immutable
        // committed state, which is what makes falling through sound.
        let guard = set.cache_lock().write().await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&cached), &[]),
            "temporary lock contention must not create a spurious denial"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&uncached), &[]),
            "lock contention must not invent coverage absent from the committed cached_urls"
        );
        drop(guard);
    }

    #[tokio::test]
    async fn precheck_clean_path_is_unchanged() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let cached = "https://cached.example.test/crl".to_owned();
        let uncached = "https://uncached.example.test/crl".to_owned();

        set.__test_insert_cache(&cached, synthetic_entry(SystemTime::now()))
            .await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&cached), &[]),
            "an untampered cached CDP must still admit"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&uncached), &[]),
            "an uncached CDP must still follow the all(not cached) predicate"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(&[cached, uncached], &[]),
            "one cached mirror is sufficient coverage (RFC 5280 4.2.1.13)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_commits_lose_no_url_and_publish_a_matching_coverage_hint() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let now = SystemTime::now();
        let total = 64usize;

        // Without `commit_lock` these commits each snapshot the same old cache
        // and clobber one another, so URLs are silently lost.
        let mut tasks = JoinSet::new();
        for index in 0..total {
            let set = Arc::clone(&set);
            tasks.spawn(async move {
                set.__test_insert_cache(
                    &format!("https://concurrent-{index:03}.example.test/crl"),
                    synthetic_entry(now),
                )
                .await;
            });
        }
        while tasks.join_next().await.is_some() {}

        let cache_keys = set
            .cache_lock()
            .read()
            .await
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            cache_keys.len(),
            total,
            "concurrent commits must not lose entries"
        );
        assert_eq!(
            cache_keys,
            set.verifier_state.load().cached_urls.clone(),
            "the published coverage hint must exactly match the committed cache"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn legitimate_refresh_is_never_observed_as_tampering() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let url = "https://coherent.example.test/crl".to_owned();
        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;

        let stop = Arc::new(AtomicBool::new(false));
        let writer_set = Arc::clone(&set);
        let writer_url = url.clone();
        let writer_stop = Arc::clone(&stop);
        let writer = tokio::spawn(async move {
            for round in 0..400u64 {
                if writer_stop.load(Ordering::Relaxed) {
                    break;
                }
                writer_set
                    .__test_insert_cache(
                        &writer_url,
                        synthetic_entry(SystemTime::now() + Duration::from_secs(round)),
                    )
                    .await;
                tokio::task::yield_now().await;
            }
            writer_stop.store(true, Ordering::Relaxed);
        });

        let reader_set = Arc::clone(&set);
        let reader_url = url.clone();
        let reader_stop = Arc::clone(&stop);
        let (denials, checks) = tokio::task::spawn_blocking(move || {
            let mut denials = 0usize;
            let mut checks = 0usize;
            while !reader_stop.load(Ordering::Relaxed) || checks < 1_000 {
                if reader_set
                    .__test_note_discovered_urls_by_cert(std::slice::from_ref(&reader_url), &[])
                {
                    denials += 1;
                }
                checks += 1;
                if checks > 200_000 {
                    break;
                }
            }
            (denials, checks)
        })
        .await
        .expect("reader task");

        writer.await.expect("writer task");
        assert_eq!(
            denials, 0,
            "a legitimate refresh must never be reported as tampering, and must never be observed half-applied"
        );
        assert!(
            checks >= 1_000,
            "the reader must actually exercise the precheck: only {checks} checks ran"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "the URL must still admit once churn stops"
        );
        assert_eq!(
            set.cache_lock()
                .read()
                .await
                .keys()
                .cloned()
                .collect::<HashSet<_>>(),
            set.verifier_state.load().cached_urls.clone(),
            "cache and published coverage hint must agree after churn"
        );
    }

    /// The commit path must reach `rebuild_verifier` BEFORE taking the cache
    /// write lock.
    ///
    /// Asserted by ordering, not by timing: a held read guard excludes writers,
    /// so a commit that surfaces a rebuild error *while that guard is still
    /// held* provably performed the rebuild off-lock. Moving the rebuild back
    /// inside the write-lock block makes this block until the timeout fires.
    /// The previous form of this test compared `try_read` hit ratios, which
    /// measured scheduler fairness under CPU oversubscription and failed
    /// intermittently on shared CI runners.
    ///
    /// A multi-threaded runtime is REQUIRED: the commit must be able to make
    /// progress on another worker while this task holds the read guard. Under
    /// `current_thread` the spawned commit cannot advance and the timeout fires
    /// spuriously. Two workers suffice; more only reintroduces oversubscription.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commit_does_not_hold_the_cache_write_lock_across_the_verifier_rebuild() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let url = "https://invalid-rebuild.example.test/crl";
        let now = SystemTime::now();

        let invalid = CachedCrl {
            der: CertificateRevocationListDer::from(vec![0_u8]),
            this_update: now,
            next_update: now.checked_add(Duration::from_secs(24 * 60 * 60)),
            fetched_at: now,
            source_url: url.to_owned(),
        };

        let invalid_cache = HashMap::from([(url.to_owned(), invalid.clone())]);
        assert!(
            rebuild_verifier(&set.roots, &set.config, &invalid_cache).is_err(),
            "precondition: the synthetic CRL must make rebuild_verifier fail"
        );

        let read_guard = set.cache_lock().read().await;

        let commit = {
            let set = Arc::clone(&set);
            tokio::spawn(async move { set.__test_try_insert_cache(url, invalid).await })
        };

        let finished_while_reader_held = tokio::time::timeout(Duration::from_secs(5), commit).await;

        drop(read_guard);

        let commit_result = finished_while_reader_held
            .expect("commit must reach rebuild_verifier before waiting for the cache write lock")
            .expect("commit task must not panic");

        assert!(
            commit_result.is_err(),
            "invalid CRL must fail during verifier rebuild"
        );
        assert!(
            !set.__test_cache_contains(url),
            "failed commit must not publish the invalid CRL into the live cache"
        );
        assert!(
            !set.__test_cached_url_contains(url),
            "failed commit must not publish invalid CRL coverage into verifier_state"
        );
    }

    // ---- B3: per-handshake CDP URL cap ------------------------------------

    fn fail_open_config() -> MtlsConfig {
        let mut config = tamper_test_config();
        config.crl_deny_on_unavailable = false;
        config
    }

    #[test]
    fn bootstrap_urls_are_capped_to_the_cache_limit() {
        let cap = 4usize;
        let mut urls: Vec<String> = (0..cap + 9)
            .map(|index| format!("https://ca-{index:02}.example.test/crl"))
            .collect();

        cap_bootstrap_urls(&mut urls, cap);

        assert_eq!(
            urls.len(),
            cap,
            "a broad CA bundle must not spawn one fetch task per advertised CDP"
        );
    }

    #[test]
    fn bootstrap_urls_below_the_cap_are_untouched() {
        let mut urls: Vec<String> = (0..3)
            .map(|index| format!("https://ca-{index:02}.example.test/crl"))
            .collect();
        let before = urls.clone();

        cap_bootstrap_urls(&mut urls, 16);

        assert_eq!(urls, before, "capping must not perturb an in-bounds chain");
    }

    #[tokio::test]
    async fn end_entity_only_mode_does_not_discover_uncapped_intermediate_cdps() {
        let mut config = tamper_test_config();
        config.crl_end_entity_only = true;
        let (set, mut rx) = test_crl_set_with_receiver_config(config);

        let end_entity = vec!["https://ee.example.test/crl".to_owned()];
        let intermediate: Vec<String> = (0..MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 10)
            .map(|index| format!("https://int-{index:03}.example.test/crl"))
            .collect();

        let _ = set.__test_note_discovered_urls_by_cert(&end_entity, &intermediate);

        let mut enqueued = Vec::new();
        while let Ok(url) = rx.try_recv() {
            enqueued.push(url);
        }

        assert_eq!(
            enqueued, end_entity,
            "under crl_end_entity_only the capped end-entity set is the only \
             discovery source; intermediate CDPs bypass MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE \
             and must never be enqueued"
        );
    }

    #[test]
    fn cdp_cap_admits_at_the_cap_and_denies_above_it_fail_closed() {
        let (at_cap, urls) =
            crl_set_with_cached_urls(tamper_test_config(), MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE);
        assert!(
            !at_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "exactly the cap must admit; all URLs are cached so nothing else can deny"
        );

        let (over_cap, urls) = crl_set_with_cached_urls(
            tamper_test_config(),
            MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1,
        );
        assert!(
            over_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "one URL past the cap must deny even though every URL is cached"
        );
        assert!(
            warned(&over_cap, "cdp_url_cap"),
            "the cap denial must be attributable to the cap, not to some other condition"
        );
    }

    #[test]
    fn cdp_cap_applies_in_fail_open_mode_too() {
        // The decision recorded in the rev-7 plan: this is a malformed-cert
        // rejection, not a revocation-unavailability denial, so opting out of
        // fail-closed does NOT opt out of the cap. An implementation that puts
        // the cap check inside the fail-closed branch admits here.
        let (over_cap, urls) =
            crl_set_with_cached_urls(fail_open_config(), MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1);
        assert!(
            over_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "the cap must deny in fail-open mode, where the same amplification is paid"
        );

        let (at_cap, urls) =
            crl_set_with_cached_urls(fail_open_config(), MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE);
        assert!(
            !at_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "the cap must not become a blanket fail-open denial"
        );
    }

    #[test]
    fn cdp_cap_is_evaluated_before_out_of_band_mutation_detection() {
        let (set, urls) = crl_set_with_cached_urls(
            tamper_test_config(),
            MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1,
        );
        let target = urls.first().expect("at least one url").clone();
        let committed = set
            .cache_lock()
            .try_read()
            .expect("uncontended")
            .get(&target)
            .cloned()
            .expect("entry present");
        set.cache_lock()
            .try_write()
            .expect("uncontended")
            .insert(target, same_shape_replacement(&committed));

        assert!(set.__test_note_discovered_urls_by_cert(&urls, &[]));
        assert!(
            warned(&set, "cdp_url_cap"),
            "over-cap must be reported as the cap, so operators are not misdirected"
        );
        assert!(
            !warned(&set, "cache_entry_mismatch"),
            "the cap must short-circuit before any per-entry auditing runs"
        );
    }

    // ---- B4-4 / B2: remaining precheck semantics --------------------------

    #[tokio::test]
    async fn unrelated_commit_does_not_invalidate_other_urls() {
        // RELEASE-CRITICAL. `commit_cache_update_atomically` clones the live
        // cache, and cloning a `CachedCrl` reallocates its DER, so every
        // carried-forward entry gets a new address. An implementation that
        // carries identities forward instead of recomputing them denies every
        // handshake after any unrelated refresh.
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let first = "https://first.example.test/crl".to_owned();
        let second = "https://second.example.test/crl".to_owned();
        let now = SystemTime::now();

        set.__test_insert_cache(&first, synthetic_entry(now)).await;
        assert!(!set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&first), &[]));

        set.__test_insert_cache(&second, synthetic_entry(now)).await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&first), &[]),
            "committing an unrelated URL must not invalidate an existing URL's identity"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&second), &[]),
            "the newly committed URL must admit too"
        );
    }

    #[tokio::test]
    async fn lock_contention_is_not_reported_as_out_of_band_mutation() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let url = "https://contended.example.test/crl".to_owned();
        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;

        let guard = set.cache_lock().write().await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "contention must fall through to the committed state, not deny"
        );
        assert!(
            !warned(&set, "cache_entry_mismatch"),
            "contention must not be logged as out-of-band mutation, or operators chase a phantom"
        );
        drop(guard);
    }

    #[tokio::test]
    async fn mutation_detection_only_ever_adds_a_denial() {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config());
        let cached = "https://audited.example.test/crl".to_owned();
        let uncached = "https://never-cached.example.test/crl".to_owned();
        let now = SystemTime::now();

        let committed = synthetic_entry(now);
        set.__test_insert_cache(&cached, committed.clone()).await;
        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&uncached), &[]),
            "an all-uncached certificate denies under all(not cached) before any mutation"
        );

        set.__test_replace_cache_entry_unverified(&cached, same_shape_replacement(&committed))
            .await;

        assert!(
            set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&uncached), &[]),
            "mutating an unrelated cached URL must not flip an all-uncached deny into an admit"
        );
    }

    #[tokio::test]
    async fn fail_open_mode_still_admits_a_mutated_entry() {
        // Operators who set `crl_deny_on_unavailable = false` accepted that a
        // revoked cert is admitted when its CRL cannot be trusted. Silently
        // re-enabling denial for them would be a behaviour change they did not
        // opt into; only the malformed-cert cap applies in this mode.
        let (set, _rx) = test_crl_set_with_receiver_config(fail_open_config());
        let url = "https://fail-open.example.test/crl".to_owned();
        let committed = synthetic_entry(SystemTime::now());

        set.__test_insert_cache(&url, committed.clone()).await;
        set.__test_replace_cache_entry_unverified(&url, same_shape_replacement(&committed))
            .await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(std::slice::from_ref(&url), &[]),
            "fail-open must stay fail-open for out-of-band mutation"
        );
    }
}
