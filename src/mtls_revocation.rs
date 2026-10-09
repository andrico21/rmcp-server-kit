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
//! Security note: CDP URLs are read from the certificates a client presents
//! before the chain is verified, so that `crl_deny_on_unavailable` can reject a
//! client whose CRL was never fetched. A client with a self-made, unsigned
//! certificate therefore chooses the URL.
//!
//! The CA signature guarantees a CRL's contents and origin, so where a genuine
//! CRL is downloaded from does not matter for trust. It does not stop the
//! server from sending the request: without screening, any client that can
//! start a TLS handshake could make the server send `GET` requests to internal
//! addresses, such as cloud metadata, loopback admin ports, or internal APIs.
//! That is blind SSRF: the bogus CRL is rejected afterwards, but the request
//! has already reached the internal service, which is enough to trigger a
//! state-changing `GET` endpoint or to map the internal network.
//!
//! The defences are the scheme and userinfo check in `check_scheme`,
//! resolved-address screening before connecting through `ip_block_reason`
//! applied by `reject_blocked_crl_ip` in `fetch_crl`, re-screening at connect
//! time through `SsrfScreeningResolver` to catch DNS rebinding, no redirects,
//! and the discovery-rate, concurrency, and body-size caps.
//!
//! Plain HTTP is allowed by default (`crl_allow_http = true`): the signature
//! makes HTTP safe for the CRL itself, but it also puts plain-HTTP internal
//! services, such as cloud metadata and loopback admin ports, in reach.
//! Requiring HTTPS would narrow this exposure, not remove it, so it is no
//! substitute for the address screening.
//!
//! There is no configurable CRL allowlist. Instead, the origins (scheme, host,
//! port) of the CDP and AIA URLs named in the operator's configured
//! certificates (the mTLS CA bundle and the server certificate chain) pass the
//! address screening automatically, because the operator chose them;
//! cloud-metadata addresses stay blocked. Any other CDP that resolves to a
//! blocked address is never fetched, and with `crl_deny_on_unavailable = true`
//! (the default) a client whose certificate names only such CDPs is rejected.
//!
//! Semantics:
//! - `crl_deny_on_unavailable = true` (default) => fail closed when a
//!   certificate advertises CDP URLs whose revocation status is not yet
//!   available. Denial requires *every* relevant CDP to be uncached, per
//!   RFC 5280 6.3; denying on a single unavailable mirror would let an
//!   attacker who blocks one CDP deny service.
//! - `crl_deny_on_unavailable = false` => fail open with warn logs. Restores
//!   the pre-3.8 behaviour and is strongly discouraged: a revoked
//!   certificate is accepted whenever its CRL is unreachable.

extern crate alloc;

use alloc::sync::Arc;
#[cfg(any(test, feature = "test-helpers"))]
use core::sync::atomic::AtomicBool;
use core::{fmt, hash::BuildHasher, mem, net::IpAddr, num::NonZeroU32, pin::Pin, time::Duration};
use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use reqwest::{Client, dns::Resolve, redirect::Policy};
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
    sync::{Mutex as TokioMutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc},
    task::{JoinSet, spawn_blocking},
    time::{Instant, Sleep, sleep},
};
use tokio_util::sync::CancellationToken;
use url::{Host, Origin, Url};
use x509_parser::{
    der_parser::oid,
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::{FromDer as _, X509Certificate},
    revocation_list::CertificateRevocationList,
    time::ASN1Time,
};

use crate::{
    auth::MtlsConfig,
    bounded_limiter::BoundedKeyedLimiter,
    error::RmcpServerKitError,
    ssrf::{CompiledSsrfAllowlist, check_scheme, ip_block_reason, sanitized_url_for_log},
    ssrf_resolver::SsrfScreeningResolver,
};

/// Total deadline for the startup bootstrap CRL pass.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Floor for the automatic CRL refresh interval.
const MIN_AUTO_REFRESH: Duration = Duration::from_mins(10);

/// Ceiling for the automatic CRL refresh interval.
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

/// Peer-key cap for CRL discovery admission. Matches the house pair used by
/// the tool and extra-route limiters.
const CRL_DISCOVERY_MAX_TRACKED_PEERS: usize = 10_000;
/// Idle-eviction window for CRL discovery peer keys. Matches the house pair.
const CRL_DISCOVERY_PEER_IDLE_EVICTION: Duration = Duration::from_mins(15);

/// Max concurrent CPU-bound CRL parse and verifier-rebuild jobs.
///
/// Shared across every handshake, refresh and discovery commit on one
/// `CrlSet` (bootstrap uses its own, separate semaphore of the same size;
/// see `bootstrap_fetch`). Deliberately independent of
/// `crl_max_concurrent_fetches`, which bounds network fetch concurrency, not
/// CPU parallelism. Deliberately a private constant rather than a config
/// field: no operator should need to tune it.
const CRL_CPU_PERMITS: usize = 2;

tokio::task_local! {
    /// Peer IP of the TLS handshake being verified on this task. Set by the
    /// accept path; read by discovery admission. Absent outside a handshake.
    pub(crate) static CURRENT_HANDSHAKE_PEER: IpAddr;
}

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
/// from one commit against the verifier of another - a mixed-generation read
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

impl fmt::Debug for VerifierState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
/// non-adversarial code** - the API-misuse hazard that field creates. It is
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
#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryIdentity {
    /// Pointer address of the DER allocation at commit time.
    der_ptr: usize,
    /// DER length at commit time.
    der_len: usize,
    /// First 32 DER bytes (or fewer) at commit time.
    head: [u8; 32],
    /// Last 32 DER bytes (or fewer) at commit time.
    tail: [u8; 32],
    /// `thisUpdate` at commit time.
    this_update: SystemTime,
    /// `nextUpdate` at commit time.
    next_update: Option<SystemTime>,
    /// Fetch time at commit time.
    fetched_at: SystemTime,
    /// Source URL at commit time.
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
    let mut head = [0_u8; 32];
    let mut tail = [0_u8; 32];
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
fn crl_cache_identities<S>(cache: &HashMap<String, CachedCrl, S>) -> HashMap<String, EntryIdentity>
where
    S: BuildHasher,
{
    cache
        .iter()
        .map(|(url, entry)| (url.clone(), entry_identity(entry)))
        .collect()
}

/// Confirm the live cache still matches what `state` committed, for the CDP
/// URLs this handshake would rely on.
///
/// SECURITY: the scope is `relevant_urls ∩ state.cached_urls` - the only URLs
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
#[expect(
    clippy::partial_pub_fields,
    reason = "public API frozen until the next major release"
)]
#[expect(
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
    /// transaction lock - holding it across `rebuild_verifier` would make the
    /// verifier path's non-blocking `try_read` fail under ordinary refresh
    /// load, turning a legitimate refresh into a spurious handshake denial.
    /// Without this mutex, two commits could each snapshot the same old cache
    /// and publish states whose `cached_urls` omit the other's URL, which is
    /// exactly the desynchronisation the digest index exists to prevent.
    commit_lock: TokioMutex<()>,
    /// Cached CRLs keyed by URL.
    ///
    /// # ⚠️ Deprecated
    ///
    /// Writing through this field bypasses the atomic commit path and
    /// desynchronises the published coverage hint from the live verifier.
    /// Since 3.8 such a write is **detected and fails the handshake closed**
    /// rather than silently admitting a certificate whose revocation status
    /// cannot be enforced. Reads remain safe but are not part of the supported
    /// surface. The field becomes private in 4.0.
    #[deprecated(
        since = "3.8.0",
        note = "mutating the CRL cache out of band is detected and denies handshakes; this field becomes private in 4.0"
    )]
    pub cache: RwLock<HashMap<String, CachedCrl>>,
    /// Immutable client-auth root store.
    pub roots: Arc<RootCertStore>,
    /// mTLS CRL configuration.
    pub config: MtlsConfig,
    /// Fire-and-forget discovery channel for newly-seen CDP URLs.
    pub discover_tx: mpsc::UnboundedSender<String>,
    /// CRL fetcher with the SSRF-screening resolver installed.
    client: Client,
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
    host_semaphores: Arc<TokioMutex<HashMap<String, Arc<Semaphore>>>>,
    /// Process-global rate-limiter on discovery URL submissions; the
    /// **fallback** admission path, consulted only when a submission arrives
    /// with no attributed handshake peer (see `discovery_limiter_per_peer`).
    ///
    /// Attributed handshakes -- the sole production path, via the
    /// `CURRENT_HANDSHAKE_PEER` scope installed by the TLS accept worker in
    /// `crate::transport` -- consult the per-peer limiter instead, so one peer
    /// can no longer drain another peer's discovery budget. This global bucket
    /// still guards the unattributed path: a downstream verifier built outside
    /// this crate's transport, or any future caller of `note_discovered_urls`
    /// without a handshake scope. Distinct from the bearer pre-auth limiter
    /// (`AuthState`), which is already keyed per-IP via a bounded keyed
    /// governor and lives in the ordinary request middleware path.
    discovery_limiter: Arc<DefaultDirectRateLimiter>,
    /// Per-peer discovery admission for attributed handshakes. Quota mirrors
    /// `crl_discovery_rate_per_min`, so a single peer sees today's rate; what
    /// changes is that one peer can no longer consume another peer's budget.
    discovery_limiter_per_peer: Arc<BoundedKeyedLimiter<IpAddr>>,
    /// Cached cap on per-fetch response body size; copied from `config` so the
    /// hot path doesn't re-read the (rarely changing) config struct.
    max_response_bytes: u64,
    /// Last time each throttle key emitted a warning, for cooldown accounting.
    last_cap_warn: Mutex<HashMap<&'static str, Instant>>,
    /// Bounds concurrent CPU-bound CRL parse and verifier-rebuild jobs on the
    /// blocking pool. See [`CRL_CPU_PERMITS`].
    crl_cpu: Arc<Semaphore>,
    /// Deduplicated http(s) origins named in the CRL Distribution Points and
    /// Authority Information Access extensions of the operator's configured
    /// certificates (the mTLS CA bundle and the server certificate chain). A
    /// CRL fetch whose URL origin is in this set skips the private-address
    /// block (cloud metadata excepted). Computed once at startup; there is
    /// no configurable CRL allowlist.
    trusted_origins: Arc<HashSet<Origin>>,
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
    /// Build a `CrlSet` and its initial verifier generation from prefetched CRLs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client or the initial verifier cannot be built.
    fn new(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        discover_tx: mpsc::UnboundedSender<String>,
        initial_cache: HashMap<String, CachedCrl>,
        trusted_origins: Arc<HashSet<Origin>>,
    ) -> Result<Arc<Self>, RmcpServerKitError> {
        // M-H2: install the SSRF screening resolver on the CRL fetcher.
        // CRL CDP URLs come from attacker-controllable client certs and
        // their hosts are re-resolved per fetch -- exactly the TOCTOU
        // class M-H2 closes. The allowlist holds the lowercased hostnames
        // of the operator-trusted origins (the CDP and AIA URIs named in
        // the configured certificates); there is no configurable CRL
        // allowlist.
        let allowlist = Arc::new(build_trusted_origin_allowlist(&trusted_origins));
        let resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
            Arc::clone(&allowlist),
            #[cfg(any(test, feature = "test-helpers"))]
            Arc::new(AtomicBool::new(false)),
            #[expect(
                clippy::cfg_not_test,
                reason = "deliberate: src/mtls_revocation.rs::SsrfScreeningResolver::new takes a no-op bypass argument when the test-helpers feature is absent; the inverted cfg is intentional"
            )]
            #[cfg(not(any(test, feature = "test-helpers")))]
            (),
        ));

        let client = Client::builder()
            // M-H2/N1: see oauth.rs::OauthHttpClient::build for rationale.
            .no_proxy()
            .dns_resolver(Arc::clone(&resolver))
            .timeout(config.crl_fetch_timeout)
            .connect_timeout(CRL_CONNECT_TIMEOUT)
            .tcp_keepalive(None)
            .redirect(Policy::none())
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
        let host_semaphores = Arc::new(TokioMutex::new(HashMap::new()));

        // Same raw-`MtlsConfig` bypass as above; keep a one-token minimum even
        // when callers skip the startup validator.
        let rate =
            NonZeroU32::new(config.crl_discovery_rate_per_min.max(1)).unwrap_or(NonZeroU32::MIN);
        let discovery_limiter = Arc::new(RateLimiter::direct(Quota::per_minute(rate)));
        let discovery_limiter_per_peer = Arc::new(BoundedKeyedLimiter::with_per_minute(
            config.crl_discovery_rate_per_min,
            CRL_DISCOVERY_MAX_TRACKED_PEERS,
            CRL_DISCOVERY_PEER_IDLE_EVICTION,
        ));

        let max_response_bytes = config.crl_max_response_bytes;

        #[expect(
            deprecated,
            reason = "constructing the struct necessarily names the deprecated field; the deprecation targets downstream mutation, not construction"
        )]
        Ok(Arc::new(Self {
            verifier_state: ArcSwap::from_pointee(initial_state),
            commit_lock: TokioMutex::new(()),
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
            discovery_limiter_per_peer,
            max_response_bytes,
            last_cap_warn: Mutex::new(HashMap::new()),
            crl_cpu: Arc::new(Semaphore::new(CRL_CPU_PERMITS)),
            trusted_origins,
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
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(callback) = probe {
            callback(self, url);
        }
    }

    #[expect(
        clippy::cfg_not_test,
        reason = "deliberate: src/mtls_revocation.rs::fire_discovery_send_probe the production stub is compiled out when the test-helpers bypass is present; the inverted cfg is intentional"
    )]
    #[cfg(not(any(test, feature = "test-helpers")))]
    #[inline]
    #[expect(
        clippy::unused_self,
        reason = "the receiver keeps the call site identical across cfgs; production builds compile this to nothing"
    )]
    /// Production no-op predecessor of the test-only pre-publication probe.
    const fn fire_discovery_send_probe(&self, _url: &str) {}

    /// Test-only: observe every URL at the instant before it is published to
    /// the discovery channel.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_set_discovery_send_probe(&self, probe: DiscoverySendProbe) {
        *self
            .discovery_send_probe
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(probe);
    }

    /// Whether `which` is outside its one-minute cooldown, recording the
    /// emission when so.
    fn should_warn_throttled(&self, which: &'static str) -> bool {
        let now = Instant::now();
        let cooldown = Duration::from_mins(1);
        let mut guard = self
            .last_cap_warn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let should_emit = guard
            .get(which)
            .is_none_or(|last| now.saturating_duration_since(*last) >= cooldown);
        if should_emit {
            let _previous = guard.insert(which, now);
        }
        should_emit
    }

    /// Emit the cache-cap warning for `which`, throttled to one line per minute.
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
    #[expect(
        deprecated,
        reason = "the deprecation targets downstream out-of-band mutation; in-crate reads and the atomic commit path are the supported users of this field"
    )]
    const fn cache_lock(&self) -> &RwLock<HashMap<String, CachedCrl>> {
        &self.cache
    }

    /// Emit the per-handshake CDP-URL cap rejection warning, throttled.
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

    /// Report a CDP discovery submission dropped by the per-minute limiter --
    /// per-peer when the handshake peer is attributed, process-global
    /// otherwise. Throttled through `should_warn_throttled` exactly like the
    /// cap warnings: the drain happens on the unauthenticated handshake path,
    /// so an unthrottled `warn!` here would itself be a log-flood amplifier of
    /// the same class this limiter defends against. Throttling trades away a
    /// line per dropped URL for flood resistance: at most one line survives per
    /// cooldown window, naming whichever `url` tripped it rather than every one.
    fn warn_discovery_rate_limited_throttled(&self, url: &str) {
        if self.should_warn_throttled("discovery_rate_limited") {
            tracing::warn!(
                url = %url,
                "discovery_rate_limited: dropped CDP URL beyond the per-minute cap (per-peer when the handshake peer is attributed, process-global otherwise; will be retried on the next handshake observing this URL)"
            );
        }
    }

    /// Report that discovery ran with no attributed handshake peer, so per-peer
    /// admission was unavailable and the process-global limiter was consulted
    /// as a fallback. The happy path -- attributed TLS handshakes driven by the
    /// scoped accept worker in `crate::transport` -- never triggers this; it is
    /// a regression canary. If a future edit drops the `CURRENT_HANDSHAKE_PEER`
    /// scope, per-peer isolation silently reverts to global-only admission and
    /// this WARN is what makes that observable. Downstream users constructing
    /// `DynamicClientCertVerifier` outside this crate's transport also land
    /// here. Throttled like the cap warnings for the same flood-resistance
    /// reason.
    fn warn_unattributed_discovery_throttled(&self) {
        if self.should_warn_throttled("discovery_unattributed_fallback") {
            tracing::warn!(
                "discovery_unattributed_fallback: CDP discovery ran without a handshake peer scope; per-peer admission unavailable, using the process-global discovery limiter"
            );
        }
    }

    /// Commit a batch of CRL inserts and removals as one atomic generation.
    ///
    /// The verifier rebuild and identity recomputation for the candidate
    /// cache run on the blocking pool (see
    /// [`build_verifier_state_blocking`]), bounded by [`CRL_CPU_PERMITS`]. If
    /// this future is dropped while that blocking work is running (caller
    /// cancellation, a timeout), the bounded build still runs to completion
    /// in the background and its result is simply discarded: the committed
    /// cache and the published verifier stay at the previous generation,
    /// never a late, out-of-order publication.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier cannot be rebuilt for the new cache,
    /// or if the blocking rebuild task cannot be joined (including a panic
    /// inside it).
    // cancel-safe: `commit_lock` is held across awaits, but every mutation before publication
    // builds a local candidate; the cache swap and `verifier_state.store` publication are
    // adjacent with NO await between them, so a cancelled commit leaves the old or the new
    // generation, never a half-applied mix. Dropping this future while the blocking rebuild runs
    // does not cancel it (spawn_blocking cannot be aborted); the bounded build finishes and its
    // result is discarded.
    async fn commit_cache_update_atomically(
        &self,
        inserts: Vec<(String, CachedCrl)>,
        removals: &[String],
    ) -> Result<bool, RmcpServerKitError> {
        // SECURITY (lock order, load-bearing): hold `commit_lock` across the
        // whole transaction - snapshot, rebuild, publish. The cache write lock
        // is taken only for the paired `*cache = candidate` +
        // `verifier_state.store(..)` publication, so readers synchronising on
        // that same `RwLock` can never observe a commit half-applied, while
        // `rebuild_verifier` and digesting stay off-lock and out of the
        // verifier path's way. Lock order is `commit_lock` then the
        // `crl_cpu` permit acquired below; the fetch path (`fetch_crl`)
        // acquires only the permit, never `commit_lock`, so there is no
        // cycle.
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
            let _previous = candidate.insert(url.clone(), cached);
            admitted_urls.push(url);
        }

        for url in removals {
            let _removed = candidate.remove(url);
        }

        // SECURITY: identities are recomputed for EVERY entry, not only for
        // what this commit wrote. `candidate` is a clone of the live cache and
        // cloning a `CachedCrl` reallocates its DER, so every carried-forward
        // entry has a new address. Carrying identities forward would make an
        // unrelated commit invalidate every other URL and deny every later
        // handshake. Recomputation is O(entries) pointer and scalar reads with
        // no hashing, so there is nothing to gain by being incremental.
        let (rebuilt_cache, verifier, identities) = {
            let permit = Arc::clone(&self.crl_cpu)
                .acquire_owned()
                .await
                .map_err(|error| {
                    RmcpServerKitError::Tls(format!("CRL CPU semaphore closed: {error}"))
                })?;
            build_verifier_state_blocking(
                Arc::clone(&self.roots),
                self.config.clone(),
                candidate,
                permit,
            )
            .await?
        };
        let new_state = Arc::new(VerifierState {
            verifier,
            cached_urls: rebuilt_cache.keys().cloned().collect(),
            committed_identities: identities,
        });
        let changed = !admitted_urls.is_empty() || !removals.is_empty();

        {
            let mut cache = self.cache_lock().write().await;
            let superseded = mem::replace(&mut *cache, rebuilt_cache);
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
                .unwrap_or_else(PoisonError::into_inner);
            for url in removals {
                let _removed = seen.remove(url);
            }
        }
        {
            let mut pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for url in removals {
                let _removed = pending.remove(url);
            }
        }

        Ok(changed)
    }

    /// Force an immediate refresh of all currently known CRL URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if rebuilding the inner verifier fails.
    // cancel-safe: only snapshots URLs then delegates to `refresh_urls`, whose
    // commits are whole-cache atomic; dropping this future leaves the previous
    // fully-published generation in place.
    #[inline]
    pub async fn force_refresh(&self) -> Result<(), RmcpServerKitError> {
        let urls = {
            let cache = self.cache_lock().read().await;
            cache.keys().cloned().collect::<Vec<_>>()
        };
        self.refresh_urls(urls).await
    }

    /// Refresh every cached URL whose refresh deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns an error if the atomic commit fails.
    // cancel-safe: selects due URLs and delegates to refresh_urls, which
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

    /// Fetch each URL and commit the successful results atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if the atomic commit fails.
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
            let _changed = self
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
    /// the cache may be promoted to the permanent `seen_urls` dedup set -
    /// promoting on fetch success alone would suppress a URL that was never
    /// cached, which is the same revocation-bypass this state split fixes.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch or the atomic commit fails.
    // cancel-safe: commits only after gated_fetch returns, so cancellation
    // during the fetch cannot promote a URL into the seen_urls dedup set.
    async fn fetch_and_store_url(&self, url: String) -> Result<bool, RmcpServerKitError> {
        let ctx = CrlFetchContext {
            client: &self.client,
            global_sem: &self.global_fetch_sem,
            host_semaphores: &self.host_semaphores,
            allow_http: self.config.crl_allow_http,
            max_bytes: self.max_response_bytes,
            max_host_semaphores: self.config.crl_max_host_semaphores,
            crl_cpu: &self.crl_cpu,
            trusted_origins: &self.trusted_origins,
        };
        let cached = gated_fetch(&ctx, &url).await?;
        let _committed = self
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
                .unwrap_or_else(PoisonError::into_inner);
            let _removed = pending.remove(url);
        }
        let mut seen = self
            .seen_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if seen.len() >= self.config.crl_max_seen_urls && !seen.contains(url) {
            self.warn_cap_exceeded_throttled("seen_urls");
            return;
        }
        let _inserted = seen.insert(url.to_owned());
    }

    /// Clear a URL's in-flight marker without promoting it, so a later
    /// handshake can re-enqueue it. Used when the fetch failed or the cache
    /// refused the entry.
    fn clear_pending(&self, url: &str) {
        let mut pending = self
            .pending_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _removed = pending.remove(url);
    }

    /// Enqueue newly-seen CDP URLs and run the synchronous fail-closed
    /// precheck.
    ///
    /// Returns `(deny, state)`. The caller MUST enforce with the returned
    /// `state.verifier` rather than re-loading: pre-check and enforcement have
    /// to observe the same verifier generation.
    #[expect(
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
        let mut all_urls = Vec::with_capacity(
            end_entity_urls
                .len()
                .saturating_add(intermediate_urls.len()),
        );
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
                .unwrap_or_else(PoisonError::into_inner);
            let pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            relevant_urls
                .iter()
                .filter(|url| !seen.contains(*url) && !pending.contains(*url))
                .cloned()
                .collect()
        };

        // Rate-limit gate: drop excess submissions on the floor with a WARN.
        // The mTLS verifier must remain non-blocking, so we use the
        // synchronous `check()`/`check_key()` APIs and never await here.
        //
        // Admission is per-peer when the handshake peer is attributed via the
        // `CURRENT_HANDSHAKE_PEER` task-local (set by the TLS accept worker),
        // and falls back to the process-global limiter only when no handshake
        // scope is present. SECURITY (order is load-bearing): the
        // `governor`-backed `check()`/`check_key()` APIs CONSUME a token rather
        // than peek, so an attributed peer must consult ONLY its own bucket --
        // also consulting the global bucket would let a rejected attacker still
        // drain the shared budget, the exact cross-peer starvation this fixes.
        for url in candidates {
            let admitted = CURRENT_HANDSHAKE_PEER.try_with(|ip| *ip).map_or_else(
                |_| {
                    // No handshake scope: preserve the pre-change process-global
                    // behaviour exactly. Emitted (throttled) so a future
                    // regression dropping the task-local scope is observable
                    // rather than silently reverting to global-only admission.
                    self.warn_unattributed_discovery_throttled();
                    self.discovery_limiter.check().is_ok()
                },
                |peer| self.discovery_limiter_per_peer.check_key(&peer).is_ok(),
            );
            if !admitted {
                self.warn_discovery_rate_limited_throttled(&url);
                continue;
            }
            let inserted = {
                // Invariant: while a URL is observable by the refresher, its
                // transient in-flight marker already exists, so every fetch
                // settlement path can remove or promote the same marker.
                let mut guard = self
                    .pending_urls
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
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

        // SECURITY (lock order - must match `commit_cache_update_atomically`):
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
        // ordinary refresh commit makes `try_read` fail - denying here would
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
        since = "3.8.0",
        note = "test-only constructor that is ungated in 3.x by accident; it becomes feature-gated in 4.0"
    )]
    #[inline]
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
            let _previous = initial_cache.insert(
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

        Self::new(
            roots,
            config,
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )
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
        since = "3.8.0",
        note = "test-only constructor that is ungated in 3.x by accident; it becomes feature-gated in 4.0"
    )]
    #[inline]
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
            let _previous = initial_cache.insert(
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

        let crl_set = Self::new(
            roots,
            config,
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )?;
        Ok((crl_set, discover_rx))
    }

    /// # ⚠️ Security
    ///
    /// Availability hazard: bypasses discovery deduplication, consumes CDP
    /// discovery quota, and enqueues arbitrary URLs. Fetch-side SSRF, scheme,
    /// and concurrency caps still apply. Ungated public leak.
    #[doc(hidden)]
    #[inline]
    pub fn __test_check_discovery_rate(&self, urls: &[String]) -> (usize, usize) {
        let mut accepted = 0_usize;
        let mut dropped = 0_usize;
        for url in urls {
            if self.discovery_limiter.check().is_ok() {
                let _sent = self.discover_tx.send(url.clone());
                accepted = accepted.saturating_add(1);
            } else {
                dropped = dropped.saturating_add(1);
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
    #[inline]
    pub fn __test_note_discovered_urls(&self, urls: &[String]) -> bool {
        let (missing_cached, _state) = self.note_discovered_urls(urls, &[]);
        if self.discover_tx.is_closed() {
            let already_seen: HashSet<String> = {
                let seen = self
                    .seen_urls
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                urls.iter()
                    .filter(|url| seen.contains(*url))
                    .cloned()
                    .collect()
            };
            let mut pending = self
                .pending_urls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for url in urls {
                if already_seen.contains(url) || pending.contains(url) {
                    continue;
                }
                if pending.len() >= self.config.crl_max_seen_urls {
                    self.warn_cap_exceeded_throttled("pending_urls");
                    break;
                }
                let _inserted = pending.insert(url.clone());
            }
        }
        missing_cached
    }

    /// Test-only: invoke the real precheck with separate end-entity and
    /// intermediate CDP sets.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
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
    #[inline]
    pub fn __test_is_seen(&self, url: &str) -> bool {
        let in_seen = {
            let seen = self
                .seen_urls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            seen.contains(url)
        };
        if in_seen {
            return true;
        }
        let pending = self
            .pending_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.contains(url)
    }

    /// Test-only: report whether a URL reached the PERMANENT dedup set,
    /// which happens only after its CRL is confirmed present in the cache.
    /// A URL that was merely queued, or whose fetch failed, is not counted.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_is_permanently_seen(&self, url: &str) -> bool {
        let seen = self
            .seen_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        seen.contains(url)
    }

    /// # ⚠️ Security
    ///
    /// Caller-supplied `admitted = true` promotes to `seen_urls` without
    /// verifying the CRL is cached; a wrongly promoted URL is never re-enqueued
    /// for the process lifetime.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_settle_pending(&self, url: &str, admitted: bool) {
        if admitted {
            self.promote_pending_to_seen(url);
        } else {
            self.clear_pending(url);
        }
    }

    /// Test-only: current count of host semaphores. Used by
    /// `tests/unit/crl_map_bounds.rs` to assert the cap is enforced.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_host_semaphore_count(&self) -> usize {
        self.host_semaphores
            .try_lock()
            .map_or(0, |guard| guard.len())
    }

    /// Test-only: current number of entries in the CRL cache.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_cache_len(&self) -> usize {
        self.cache_lock().try_read().map_or(0, |guard| guard.len())
    }

    /// Test-only: whether a specific URL is currently cached.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    pub fn __test_cache_contains(&self, url: &str) -> bool {
        self.cache_lock()
            .try_read()
            .is_ok_and(|guard| guard.contains_key(url))
    }

    /// Test-only: whether a URL is advertised to the fail-closed precheck as
    /// present in the live verifier.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
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
    #[inline]
    // cancel-safe: no local CRL state is published; dropping the future aborts
    // `gated_fetch` and leaves only bounded semaphore/map state behind.
    pub async fn __test_trigger_fetch(&self, url: &str) -> Result<(), RmcpServerKitError> {
        let ctx = CrlFetchContext {
            client: &self.client,
            global_sem: &self.global_fetch_sem,
            host_semaphores: &self.host_semaphores,
            allow_http: self.config.crl_allow_http,
            max_bytes: self.max_response_bytes,
            max_host_semaphores: self.config.crl_max_host_semaphores,
            crl_cpu: &self.crl_cpu,
            trusted_origins: &self.trusted_origins,
        };
        if let Err(error) = gated_fetch(&ctx, url).await {
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
    #[inline]
    // cancel-safe: delegates to the atomic cache commit; cancellation before the
    // commit leaves no update, and cancellation after it leaves a consistent
    // cache/verifier publication.
    pub async fn __test_insert_cache(&self, url: &str, cached: CachedCrl) {
        let _result = self
            .commit_cache_update_atomically(vec![(url.to_owned(), cached)], &[])
            .await;
    }

    /// Test-only: direct cache insertion that returns verifier rebuild errors.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    // cancel-safe: same atomic cache commit as `__test_insert_cache`, with the
    // commit result returned instead of discarded.
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
    /// and the publication step in `commit_cache_update_atomically`. This can
    /// desynchronise `cached_urls` from `verifier_state`; with default
    /// `crl_deny_on_unavailable = true`, the precheck trusts `cached_urls` and
    /// can admit a certificate whose revocation status is unenforceable.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    // cancel-safe: the only awaited operation is acquiring the cache write
    // lock; once held, the direct insertion is synchronous.
    pub async fn __test_replace_cache_entry_unverified(&self, url: &str, cached: CachedCrl) {
        let mut cache = self.cache_lock().write().await;
        let _previous = cache.insert(url.to_owned(), cached);
    }

    /// # ⚠️ Security
    ///
    /// Lets a caller-supplied URL reach `refresh_urls` and then `gated_fetch`,
    /// bypassing normal CDP discovery admission, deduplication, and rate-limit
    /// checks.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[inline]
    // cancel-safe: delegates to `refresh_urls`, which fetches into locals and
    // publishes only through the atomic cache commit.
    pub async fn __test_trigger_refresh_url(&self, url: &str) -> Result<(), RmcpServerKitError> {
        self.refresh_urls(vec![url.to_owned()]).await
    }

    /// Fetch every URL concurrently, returning each result.
    // cancel-safe: cache integrity - `join_next` fills a local `Vec`; dropping
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
            let crl_cpu = Arc::clone(&self.crl_cpu);
            let trusted_origins = Arc::clone(&self.trusted_origins);
            let _task = tasks.spawn(async move {
                let ctx = CrlFetchContext {
                    client: &client,
                    global_sem: &global_sem,
                    host_semaphores: &host_map,
                    allow_http,
                    max_bytes,
                    max_host_semaphores,
                    crl_cpu: &crl_cpu,
                    trusted_origins: &trusted_origins,
                };
                let result = gated_fetch(&ctx, &url).await;
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

/// Minimal CRL-shaped DER used by the test-only synthetic cache entries.
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
    /// = now + 24h. Fields used only to populate the HashMap - the bytes
    /// are a minimal CRL-shape that won't be parsed by tests.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    #[inline]
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
    #[inline]
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
    /// Shared CRL state; the verifier delegates every decision to it.
    inner: Arc<CrlSet>,
    /// Root subject names advertised as hints, snapshotted at construction.
    dn_subjects: Vec<DistinguishedName>,
}

impl DynamicClientCertVerifier {
    /// Construct a new dynamic verifier from a shared [`CrlSet`].
    #[must_use]
    #[inline]
    pub fn new(inner: Arc<CrlSet>) -> Self {
        Self {
            dn_subjects: inner.roots.subjects(),
            inner,
        }
    }
}

impl fmt::Debug for DynamicClientCertVerifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicClientCertVerifier")
            .field("dn_subjects_len", &self.dn_subjects.len())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for DynamicClientCertVerifier {
    #[inline]
    fn offer_client_auth(&self) -> bool {
        let state = self.inner.verifier_state.load();
        state.verifier.offer_client_auth()
    }

    #[inline]
    fn client_auth_mandatory(&self) -> bool {
        let state = self.inner.verifier_state.load();
        state.verifier.client_auth_mandatory()
    }

    #[inline]
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.dn_subjects
    }

    #[inline]
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
        // `crl_allow_http` policy. The signature protects the CRL, not the
        // request; fetching a URL from an unverified certificate off-path is
        // acceptable only because the fetch is screened. See the module docs.
        // The discovery must happen BEFORE delegating to the inner verifier
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

    #[inline]
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let state = self.inner.verifier_state.load();
        state.verifier.verify_tls12_signature(message, cert, dss)
    }

    #[inline]
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let state = self.inner.verifier_state.load();
        state.verifier.verify_tls13_signature(message, cert, dss)
    }

    #[inline]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let state = self.inner.verifier_state.load();
        state.verifier.supported_verify_schemes()
    }

    #[inline]
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
#[inline]
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

/// Push `name`'s origin onto `origins` when it is an accepted http(s) URI.
///
/// Drops non-URI names, parse failures, and rejected schemes (userinfo,
/// non-http(s)) silently (debug log), matching `extract_cdp_urls`.
fn collect_uri_origin(name: &GeneralName<'_>, allow_http: bool, origins: &mut Vec<Origin>) {
    let GeneralName::URI(uri) = name else {
        return;
    };
    let raw = *uri;
    let Ok(parsed) = Url::parse(raw) else {
        tracing::debug!(url = ?raw, "trusted CRL origin URI parse failed; dropped");
        return;
    };
    if let Err(reason) = check_scheme(&parsed, allow_http) {
        tracing::debug!(
            url = %sanitized_url_for_log(&parsed),
            reason,
            "trusted CRL origin URI rejected by scheme guard; dropped"
        );
        return;
    }
    origins.push(parsed.origin());
}

/// Collect the http(s) origins named in a certificate's CRL Distribution
/// Points and Authority Information Access extensions.
///
/// Covers `id-ad-caIssuers` and `id-ad-ocsp` (RFC 5280 §4.2.2.1). Mirrors
/// `extract_cdp_urls`'s scheme and userinfo filtering via `check_scheme`,
/// but reduces each accepted URL to its origin (scheme, lowercased host,
/// effective port) instead of keeping the full URL. A certificate that
/// fails to parse yields no origins (debug log), never an error: this runs
/// over operator-configured certificates at startup, and a malformed entry
/// should narrow the trusted set, not abort the server.
fn extract_trusted_origins(cert_der: &[u8], allow_http: bool) -> Vec<Origin> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        tracing::debug!("trusted CRL origin: certificate parse failed; skipped");
        return Vec::new();
    };

    let mut origins = Vec::new();
    for ext in cert.extensions() {
        let parsed = ext.parsed_extension();
        if let ParsedExtension::CRLDistributionPoints(cdps) = parsed {
            for point in cdps.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        collect_uri_origin(name, allow_http, &mut origins);
                    }
                }
            }
        }
        if let ParsedExtension::AuthorityInfoAccess(aia) = parsed {
            for desc in aia.iter() {
                let is_relevant = desc.access_method == oid!(1.3.6.1.5.5.7.48.2)
                    || desc.access_method == oid!(1.3.6.1.5.5.7.48.1);
                if is_relevant {
                    collect_uri_origin(&desc.access_location, allow_http, &mut origins);
                }
            }
        }
    }
    origins
}

/// Collect the deduplicated trusted CRL/AIA origins named across `ca_certs`
/// and `server_chain`.
///
/// `ca_certs` is the operator's configured mTLS CA bundle; `server_chain` is
/// the server's own TLS certificate chain. A CRL fetch whose URL origin is
/// in the returned set skips the private-address block (cloud metadata
/// excepted); there is no configurable CRL allowlist.
fn collect_trusted_crl_origins(
    ca_certs: &[CertificateDer<'_>],
    server_chain: &[CertificateDer<'_>],
    allow_http: bool,
) -> HashSet<Origin> {
    ca_certs
        .iter()
        .chain(server_chain.iter())
        .flat_map(|cert| extract_trusted_origins(cert.as_ref(), allow_http))
        .collect()
}

/// Lowercased hostnames of the hostname-form (non-IP-literal) origins in
/// `origins`, for the connect-time resolver allowlist.
///
/// IP-literal origins are intentionally excluded: `screen_addrs` applies
/// CIDR entries to every hostname's resolved addresses, so adding an
/// IP-literal origin as a CIDR would let a rebinding hostname reach that
/// same address on any port. IP-literal trusted origins are enforced
/// solely by the pre-flight origin match in `fetch_crl`, which is final:
/// reqwest never re-resolves a literal.
fn trusted_hostnames(origins: &HashSet<Origin>) -> Vec<String> {
    origins
        .iter()
        .filter_map(|origin| match origin {
            Origin::Tuple(_, Host::Domain(domain), _) => Some(domain.clone()),
            Origin::Tuple(_, Host::Ipv4(_) | Host::Ipv6(_), _) | Origin::Opaque(_) => None,
        })
        .collect()
}

/// Build the CRL fetcher's connect-time resolver allowlist from the trusted
/// origins.
///
/// Hostnames only, never CIDR entries: see [`trusted_hostnames`] for why
/// IP-literal origins are excluded rather than turned into a CIDR. Shared by
/// [`CrlSet::new`] and [`bootstrap_fetch_with_server_chain`] so both
/// entry points build the identical allowlist from the same trusted set.
fn build_trusted_origin_allowlist(trusted_origins: &HashSet<Origin>) -> CompiledSsrfAllowlist {
    CompiledSsrfAllowlist::new(trusted_hostnames(trusted_origins), Vec::new())
}

/// Log the trusted CRL/AIA origins once at startup, so an operator can audit
/// what bypasses the private-address screening (cloud metadata excepted).
fn log_trusted_crl_origins(origins: &HashSet<Origin>) {
    let mut rendered: Vec<String> = origins.iter().map(Origin::ascii_serialization).collect();
    rendered.sort();
    tracing::info!(
        count = rendered.len(),
        origins = %rendered.join(", "),
        "CRL fetch: trusted origins named in the configured certificates"
    );
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
/// The CRL/AIA origins named in `ca_certs` are trusted automatically (no
/// configurable CRL allowlist): a CRL fetch whose URL origin is in that set
/// skips the private-address block, cloud metadata excepted. Callers that
/// also have the server's own TLS certificate chain available (the mTLS CRL
/// wiring in `crate::transport::run_server`) extend that trusted set with it.
///
/// # Errors
///
/// Returns an error if the initial verifier cannot be built.
#[inline]
// cancel-safe: CRL cache state is local until final `CrlSet::new`; timeout or cancellation drops
// the `JoinSet`, aborting in-flight `gated_fetch` before publication. Bootstrap host semaphores
// are local and drop with this future.
pub async fn bootstrap_fetch(
    roots: Arc<RootCertStore>,
    ca_certs: &[CertificateDer<'static>],
    config: MtlsConfig,
) -> Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>), RmcpServerKitError> {
    // Bootstrap URLs come from the configured CA certificates, not clients.
    // Their origins are operator-trusted for CRL address screening;
    // cloud-metadata addresses stay blocked.
    bootstrap_fetch_with_server_chain(roots, ca_certs, &[], config).await
}

/// Same as [`bootstrap_fetch`], but also derives the trusted origin set
/// from `server_chain`.
///
/// `server_chain` is the server's own TLS certificate chain.
/// `crate::transport::run_server` has both chains available and uses this
/// variant directly; `bootstrap_fetch` delegates here with an empty
/// `server_chain`.
///
/// # Errors
///
/// Returns an error if the initial verifier cannot be built.
// cancel-safe: identical to `bootstrap_fetch` (see its comment); the extra
// `server_chain` slice is read synchronously before any await.
pub(crate) async fn bootstrap_fetch_with_server_chain(
    roots: Arc<RootCertStore>,
    ca_certs: &[CertificateDer<'static>],
    server_chain: &[CertificateDer<'static>],
    config: MtlsConfig,
) -> Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>), RmcpServerKitError> {
    let (discover_tx, discover_rx) = mpsc::unbounded_channel();

    // Bootstrap URLs come from configured certificates: the public helper uses
    // the CA bundle, while this crate-internal path also trusts origins named
    // in the server certificate chain. Cloud-metadata addresses stay blocked.
    let mut urls = ca_certs
        .iter()
        .flat_map(|cert| extract_cdp_urls(cert.as_ref(), config.crl_allow_http))
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    cap_bootstrap_urls(&mut urls, config.crl_max_cache_entries);

    let trusted_origins = Arc::new(collect_trusted_crl_origins(
        ca_certs,
        server_chain,
        config.crl_allow_http,
    ));
    log_trusted_crl_origins(&trusted_origins);

    // M-H2: same SSRF resolver hardening as CrlSet::new. The resolver
    // allowlist is seeded with the hostnames of the operator-trusted
    // origins computed above, instead of staying empty.
    let bootstrap_allowlist = Arc::new(build_trusted_origin_allowlist(&trusted_origins));
    let bootstrap_resolver: Arc<dyn Resolve> = Arc::new(SsrfScreeningResolver::new(
        Arc::clone(&bootstrap_allowlist),
        #[cfg(any(test, feature = "test-helpers"))]
        Arc::new(AtomicBool::new(false)),
        #[expect(
            clippy::cfg_not_test,
            reason = "deliberate: src/mtls_revocation.rs::SsrfScreeningResolver::new takes a no-op bypass argument when the test-helpers feature is absent; the inverted cfg is intentional"
        )]
        #[cfg(not(any(test, feature = "test-helpers")))]
        (),
    ));

    let client = Client::builder()
        // M-H2/N1: see oauth.rs::OauthHttpClient::build for rationale.
        .no_proxy()
        .dns_resolver(Arc::clone(&bootstrap_resolver))
        .timeout(config.crl_fetch_timeout)
        .connect_timeout(CRL_CONNECT_TIMEOUT)
        .tcp_keepalive(None)
        .redirect(Policy::none())
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
    let host_semaphores = Arc::new(TokioMutex::new(HashMap::new()));
    let allow_http = config.crl_allow_http;
    let max_bytes = config.crl_max_response_bytes;
    let max_host_semaphores = config.crl_max_host_semaphores;
    // Bounds CPU-bound CRL parse jobs during bootstrap. Separate from the
    // `crl_cpu` field the resulting `CrlSet` gets in `CrlSet::new`: bootstrap
    // runs before that `CrlSet` exists, so its fetch tasks and its one-shot
    // initial verifier build below share this bootstrap-local semaphore.
    let bootstrap_crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));

    let fetch_ctx = CrlFetchContext {
        client: &client,
        global_sem: &global_sem,
        host_semaphores: &host_semaphores,
        allow_http,
        max_bytes,
        max_host_semaphores,
        crl_cpu: &bootstrap_crl_cpu,
        trusted_origins: &trusted_origins,
    };
    let initial_cache = bootstrap_fetch_urls(&fetch_ctx, &urls).await;

    let set = {
        let permit = Arc::clone(&bootstrap_crl_cpu)
            .acquire_owned()
            .await
            .map_err(|error| {
                RmcpServerKitError::Tls(format!("CRL CPU semaphore closed: {error}"))
            })?;
        new_crl_set_from_bootstrap_cache_blocking(
            roots,
            config,
            discover_tx,
            initial_cache,
            trusted_origins,
            permit,
        )
        .await?
    };
    Ok((set, discover_rx))
}

/// Fetch every bootstrap CDP URL concurrently under [`BOOTSTRAP_TIMEOUT`],
/// returning whatever was fetched successfully before the deadline.
#[expect(
    clippy::cognitive_complexity,
    reason = "bootstrap coordinates timeout, parallel fetches, and partial-cache recovery"
)]
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
)]
// cancel-safe: results accumulate in a local map; the deadline elapsing, or
// this future being dropped, only stops collecting further results - nothing
// is published here, the caller commits the returned map itself.
async fn bootstrap_fetch_urls(
    ctx: &CrlFetchContext<'_>,
    urls: &[String],
) -> HashMap<String, CachedCrl> {
    let mut initial_cache = HashMap::new();
    let mut tasks = JoinSet::new();
    for url in urls {
        let task_url = url.clone();
        let task_client = ctx.client.clone();
        let task_global_sem = Arc::clone(ctx.global_sem);
        let task_host_semaphores = Arc::clone(ctx.host_semaphores);
        let task_crl_cpu = Arc::clone(ctx.crl_cpu);
        let task_trusted_origins = Arc::clone(ctx.trusted_origins);
        let allow_http = ctx.allow_http;
        let max_bytes = ctx.max_bytes;
        let max_host_semaphores = ctx.max_host_semaphores;
        let _task = tasks.spawn(async move {
            let task_ctx = CrlFetchContext {
                client: &task_client,
                global_sem: &task_global_sem,
                host_semaphores: &task_host_semaphores,
                allow_http,
                max_bytes,
                max_host_semaphores,
                crl_cpu: &task_crl_cpu,
                trusted_origins: &task_trusted_origins,
            };
            let result = gated_fetch(&task_ctx, &task_url).await;
            (task_url, result)
        });
    }

    let timeout: Sleep = sleep(BOOTSTRAP_TIMEOUT);
    tokio::pin!(timeout);

    while !tasks.is_empty() {
        // cancel-safe: pinned Sleep and JoinSet::join_next are cancel-safe
        // (tokio docs); on timeout the loop breaks and dropping the JoinSet
        // aborts remaining fetches - the intended deadline behavior.
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
                        let _previous = initial_cache.insert(url, cached);
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

    initial_cache
}

/// Apply the cache cap, then build the `CrlSet` from the bootstrap cache.
///
/// # Errors
///
/// Returns an error if the initial verifier cannot be built.
fn new_crl_set_from_bootstrap_cache(
    roots: Arc<RootCertStore>,
    config: MtlsConfig,
    discover_tx: mpsc::UnboundedSender<String>,
    mut initial_cache: HashMap<String, CachedCrl>,
    trusted_origins: Arc<HashSet<Origin>>,
) -> Result<Arc<CrlSet>, RmcpServerKitError> {
    apply_bootstrap_cache_cap(&mut initial_cache, config.crl_max_cache_entries);
    CrlSet::new(roots, config, discover_tx, initial_cache, trusted_origins)
}

/// Build the bootstrap `CrlSet` on the blocking thread pool, bounded by the
/// bootstrap-local CRL CPU semaphore (see `bootstrap_fetch`).
///
/// # Errors
///
/// Returns an error if [`new_crl_set_from_bootstrap_cache`] fails, or if the
/// blocking task cannot be joined (including a panic inside it).
// cancel-safe: every input, including the semaphore permit, is moved into the
// blocking closure, so a dropped future lets the bounded build finish and
// discards its result; bootstrap has published nothing yet in that case.
async fn new_crl_set_from_bootstrap_cache_blocking(
    roots: Arc<RootCertStore>,
    config: MtlsConfig,
    discover_tx: mpsc::UnboundedSender<String>,
    initial_cache: HashMap<String, CachedCrl>,
    trusted_origins: Arc<HashSet<Origin>>,
    permit: OwnedSemaphorePermit,
) -> Result<Arc<CrlSet>, RmcpServerKitError> {
    spawn_blocking(move || {
        let _permit = permit;
        new_crl_set_from_bootstrap_cache(roots, config, discover_tx, initial_cache, trusted_origins)
    })
    .await
    .map_err(|error| {
        RmcpServerKitError::Tls(format!("CRL bootstrap verifier build task failed: {error}"))
    })?
}

/// Drop the excess cache entries beyond `max_cache_entries`, in sorted order.
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
        let _removed = initial_cache.remove(&url);
    }
}

/// Run the CRL refresher loop until shutdown.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "external macro: tokio::select"
)]
// Without the discovery arm's `PendingUrlGuard`, an abort would leave a stale
// `pending_urls` marker that suppresses re-enqueue forever (see the note above
// `seen_urls`/`pending_urls` clearing) and silently narrows revocation coverage.
#[inline]
// cancel-safe: including under abort - cooperative `shutdown` breaks the loop
// at a settlement point; the discovery arm holds a `PendingUrlGuard` across
// `fetch_and_store_url`, so `JoinHandle::abort` dropping the future mid-await
// still clears the transient marker via `Drop`.
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

/// Owned abort-safety guard for the discovery arm in `run_crl_refresher`.
// Abort-safety guard for the discovery arm in `run_crl_refresher`. Cooperative
// shutdown already leaves `pending_urls` consistent because the arm body runs to
// a normal `Ok`/`Err` settlement point, but `JoinHandle::abort` drops the future
// at whatever `.await` it is currently suspended on. Holding this owned guard
// across `fetch_and_store_url` makes that hard-abort path deterministic too: if
// the fetch future is dropped before a CRL is confirmed cached, `Drop` removes
// the transient in-flight marker so the CDP can be retried by a later handshake.
struct PendingUrlGuard {
    /// The CRL set whose `pending_urls` marker this guard owns.
    set: Arc<CrlSet>,
    /// The URL whose in-flight marker this guard owns.
    url: String,
    /// Whether the guard still owns the marker (disarmed once promoted).
    armed: bool,
}

impl PendingUrlGuard {
    /// Arm a guard that clears `url`'s in-flight marker on drop.
    const fn armed(set: Arc<CrlSet>, url: String) -> Self {
        Self {
            set,
            url,
            armed: true,
        }
    }

    /// Relinquish ownership after the URL is promoted, so drop only clears.
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

// Removes the in-flight URL marker from `pending_urls` with a sync std-Mutex
// lock (poison recovered). Ordering is explicit, not implicit in Drop: callers
// `disarm()` before promoting to `seen_urls`, so an armed drop only clears.
// Drop audit (2026-10-04): no blocking/async work, no panic path.
impl Drop for PendingUrlGuard {
    fn drop(&mut self) {
        if self.armed {
            self.set.clear_pending(&self.url);
        }
    }
}

/// Apply a discovery fetch's settlement to the pending/seen dedup state.
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
#[inline]
pub fn rebuild_verifier<S>(
    roots: &Arc<RootCertStore>,
    config: &MtlsConfig,
    cache: &HashMap<String, CachedCrl, S>,
) -> Result<Arc<dyn ClientCertVerifier>, RmcpServerKitError>
where
    S: BuildHasher,
{
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

/// Rebuild the verifier and recompute every entry's identity for a candidate
/// cache on the blocking thread pool, bounded by the shared CRL CPU
/// semaphore.
///
/// Takes the candidate cache by value and returns it unchanged alongside the
/// rebuilt verifier and identity index, so the caller can publish all three
/// together without re-reading the candidate after the blocking call.
///
/// # Errors
///
/// Returns an error if [`rebuild_verifier`] fails for the candidate cache, or
/// if the blocking task cannot be joined (including a panic inside it).
// cancel-safe: the semaphore permit and the candidate cache are both moved
// into the blocking closure, so a dropped future lets the bounded rebuild
// finish and discards its result; nothing is published in that case because
// the caller never reaches its own publication step.
async fn build_verifier_state_blocking(
    roots: Arc<RootCertStore>,
    config: MtlsConfig,
    candidate: HashMap<String, CachedCrl>,
    permit: OwnedSemaphorePermit,
) -> Result<
    (
        HashMap<String, CachedCrl>,
        Arc<dyn ClientCertVerifier>,
        HashMap<String, EntryIdentity>,
    ),
    RmcpServerKitError,
> {
    spawn_blocking(move || {
        let _permit = permit;
        let verifier = rebuild_verifier(&roots, &config, &candidate)?;
        let identities = crl_cache_identities(&candidate);
        Ok((candidate, verifier, identities))
    })
    .await
    .map_err(|error| {
        RmcpServerKitError::Tls(format!("CRL verifier rebuild task failed: {error}"))
    })?
}

/// Parse `thisUpdate` and `nextUpdate` metadata from a DER-encoded CRL.
///
/// # Errors
///
/// Returns an error if the CRL cannot be parsed.
#[inline]
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

/// Parse CRL metadata on the blocking thread pool, bounded by the shared CRL
/// CPU semaphore.
///
/// Takes the DER bytes by value and returns them unchanged alongside the
/// parsed metadata, so the caller can build a [`CachedCrl`] without
/// re-reading the bytes after the blocking call.
///
/// # Errors
///
/// Returns an error if [`parse_crl_metadata`] fails for the DER bytes, or if
/// the blocking task cannot be joined (including a panic inside it).
// cancel-safe: the semaphore permit and the DER bytes are both moved into the
// blocking closure, so a dropped future lets the bounded parse finish and
// discards its result; no caller ever observes a partially-parsed `CachedCrl`.
async fn parse_crl_metadata_blocking(
    der: Vec<u8>,
    permit: OwnedSemaphorePermit,
) -> Result<(Vec<u8>, SystemTime, Option<SystemTime>), RmcpServerKitError> {
    spawn_blocking(move || {
        let _permit = permit;
        let (this_update, next_update) = parse_crl_metadata(&der)?;
        Ok((der, this_update, next_update))
    })
    .await
    .map_err(|error| RmcpServerKitError::Tls(format!("CRL parse task failed: {error}")))?
}

/// Compute and box the next refresh sleep deadline.
// cancel-safe: builds the next sleep deadline from a read lock that is released
// before this future resolves; no state is mutated, so a cancelled call only
// delays rescheduling until the next loop iteration.
async fn schedule_next_refresh(set: &CrlSet) -> Pin<Box<Sleep>> {
    let duration = next_refresh_delay(set).await;
    boxed_sleep(duration)
}

/// Box a sleep for `duration` from now into a pin-ready `Sleep`.
fn boxed_sleep(duration: Duration) -> Pin<Box<Sleep>> {
    Box::pin(sleep(duration))
}

/// Compute the delay until the next due refresh, clamped to the house bounds.
// cancel-safe: takes a read lock, folds cache metadata into a local deadline,
// and drops the guard before returning; cancellation leaves no partial state.
#[expect(
    clippy::iter_over_hash_type,
    reason = "deliberate: src/mtls_revocation.rs::next_refresh_delay folds every cached deadline with `min`, so iteration order cannot affect the result"
)]
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
/// distinct hosts are *concurrently* fetching - it is never a permanent
/// lockout. Every clone of a host semaphore is created while holding the
/// map lock, and a clone outlives the critical section only while a fetch
/// is in flight, so an entry with `Arc::strong_count == 1` is provably
/// idle and safe to drop.
///
/// # Errors
///
/// Returns an error when the host cap is reached with no idle entry to evict.
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
        let _previous = map.insert(host_key.to_owned(), Arc::new(Semaphore::new(1)));
    }
    map.get(host_key).map_or_else(
        || {
            Err(RmcpServerKitError::Tls(
                "CRL host semaphore missing after insertion".to_owned(),
            ))
        },
        |semaphore| Ok(Arc::clone(semaphore)),
    )
}

/// Network and CPU concurrency caps shared by one `gated_fetch` call.
///
/// Groups `gated_fetch`'s parameters so the function itself stays within the
/// house argument-count limit; every field is a borrow or a cheap `Copy`
/// value already owned by the caller.
struct CrlFetchContext<'ctx> {
    /// CRL fetcher with the SSRF-screening resolver installed.
    client: &'ctx Client,
    /// Global cap on simultaneous CRL HTTP fetches (SSRF amplification guard).
    global_sem: &'ctx Arc<Semaphore>,
    /// Per-host serializer, at most one in-flight fetch per origin host.
    host_semaphores: &'ctx Arc<TokioMutex<HashMap<String, Arc<Semaphore>>>>,
    /// Whether plain `http://` CDP URLs are fetched.
    allow_http: bool,
    /// Cap on a single CRL response body.
    max_bytes: u64,
    /// Cap on distinct CDP hosts tracked by `host_semaphores`.
    max_host_semaphores: usize,
    /// Bounds concurrent CPU-bound CRL parse jobs. See [`CRL_CPU_PERMITS`].
    crl_cpu: &'ctx Arc<Semaphore>,
    /// Operator-trusted origins; see `CrlSet::trusted_origins`.
    trusted_origins: &'ctx Arc<HashSet<Origin>>,
}

/// Fetch a single CRL URL through the global + per-host concurrency caps.
///
/// `global_sem` caps total simultaneous CRL fetches process-wide.
/// `host_semaphores` ensures at most one in-flight fetch per origin host
/// (an SSRF amplification defense); at the host cap, idle entries are
/// evicted on demand. Both permits are dropped when the returned future
/// completes (whether `Ok` or `Err`).
///
/// # Errors
///
/// Returns an error if a permit is unavailable or the underlying fetch fails.
// cancel-safe: permits - cancelling queued `acquire_owned` loses only queue
// position, acquired global/host permits RAII-drop, and host-map insertion can
// leave only an idle bounded semaphore entry that later self-heals.
async fn gated_fetch(
    ctx: &CrlFetchContext<'_>,
    url: &str,
) -> Result<CachedCrl, RmcpServerKitError> {
    let host_key = Url::parse(url)
        .ok()
        .and_then(|parsed_url| parsed_url.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned());

    let host_sem = {
        let mut map = ctx.host_semaphores.lock().await;
        acquire_host_semaphore(&mut map, &host_key, ctx.max_host_semaphores)?
    };

    let _global_permit = Arc::clone(ctx.global_sem)
        .acquire_owned()
        .await
        .map_err(|error| {
            RmcpServerKitError::Tls(format!("CRL global semaphore closed: {error}"))
        })?;
    let _host_permit = host_sem
        .acquire_owned()
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL host semaphore closed: {error}")))?;

    fetch_crl(
        ctx.client,
        url,
        ctx.allow_http,
        ctx.max_bytes,
        ctx.crl_cpu,
        ctx.trusted_origins,
    )
    .await
}

/// Fetch and parse a single CRL into a cache entry.
///
/// The DER parse runs on the blocking pool (see
/// [`parse_crl_metadata_blocking`]), bounded by [`CRL_CPU_PERMITS`].
///
/// # Errors
///
/// Returns an error if the scheme is rejected, DNS screening fails (unless
/// the URL's origin is in the operator-trusted set, cloud metadata
/// excepted), the HTTP fetch fails, the body exceeds the cap, or the DER
/// cannot be parsed.
// cancel-safe: DNS lookup, request send, and chunk reads build only a local buffer; CRL
// cache/verifier state changes happen later, when callers commit the returned value. Dropping
// this future while the blocking parse is in flight does not cancel it (spawn_blocking cannot be
// aborted); the bounded parse finishes and its result is simply discarded.
async fn fetch_crl(
    client: &Client,
    url: &str,
    allow_http: bool,
    max_bytes: u64,
    crl_cpu: &Arc<Semaphore>,
    trusted_origins: &Arc<HashSet<Origin>>,
) -> Result<CachedCrl, RmcpServerKitError> {
    let parsed = Url::parse(url)
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL URL parse {url}: {error}")))?;

    // SECURITY: this URL can come from an unverified client certificate; see
    // the module docs for why the fetch must be screened before any request.
    if let Err(reason) = check_scheme(&parsed, allow_http) {
        // Sanitized: the gate must not echo what it rejects (the URL may
        // carry userinfo credentials - the very thing being refused).
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

    // The origin (scheme, host, port) is trusted when it is named in a CRL
    // Distribution Point or Authority Information Access extension of the
    // operator's configured certificates; see `CrlSet::trusted_origins`.
    let trusted_origin = trusted_origins.contains(&parsed.origin());

    // An IPv6-literal host fails closed here because `host_str()` retains
    // brackets, and `lookup_host` expects an unbracketed IPv6 address.
    let addrs = lookup_host((host, port))
        .await
        .map_err(|error| RmcpServerKitError::Tls(format!("CRL DNS resolution {url}: {error}")))?;

    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        // SECURITY: a client-chosen CDP host is resolved before connecting and
        // each address is screened; see the module docs for the threat model.
        reject_blocked_crl_ip(url, addr.ip(), trusted_origin)?;
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

    let (parsed_der, this_update, next_update) = {
        let permit = Arc::clone(crl_cpu).acquire_owned().await.map_err(|error| {
            RmcpServerKitError::Tls(format!("CRL CPU semaphore closed: {error}"))
        })?;
        parse_crl_metadata_blocking(body, permit).await?
    };
    let der = CertificateRevocationListDer::from(parsed_der);

    Ok(CachedCrl {
        der,
        this_update,
        next_update,
        fetched_at: SystemTime::now(),
        source_url: url.to_owned(),
    })
}

/// Reject a CRL resolved IP when the shared SSRF classifier blocks it.
///
/// Skipped when `trusted_origin` is true - the fetch's URL origin is named
/// in the operator's configured certificates. Cloud metadata is rejected
/// either way.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Tls`] when `ip` is in a blocked SSRF class
/// and either `trusted_origin` is false or the class is cloud metadata.
fn reject_blocked_crl_ip(
    url: &str,
    ip: IpAddr,
    trusted_origin: bool,
) -> Result<(), RmcpServerKitError> {
    let Some(reason) = ip_block_reason(ip) else {
        return Ok(());
    };
    if trusted_origin && reason != "cloud_metadata" {
        return Ok(());
    }
    tracing::warn!(
        url = %url,
        resolved_ip = %ip,
        reason,
        "CRL fetch denied: blocked IP"
    );
    Err(RmcpServerKitError::Tls(format!(
        "CRL host resolved to blocked IP ({reason}): {url}"
    )))
}

/// Whether a cached CRL is due for refresh at `now`.
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

/// Clamp a refresh interval into [`MIN_AUTO_REFRESH`]..=[`MAX_AUTO_REFRESH`].
fn clamp_refresh(duration: Duration) -> Duration {
    duration.clamp(MIN_AUTO_REFRESH, MAX_AUTO_REFRESH)
}

/// 9999-12-31T23:59:59Z - the maximum instant expressible as an ASN.1
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
fn asn1_time_to_system_time(time: ASN1Time) -> SystemTime {
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

#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {

    use core::{
        iter::once,
        net::{Ipv4Addr, Ipv6Addr},
        slice,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use std::{
        io,
        sync::{Mutex as StdMutex, OnceLock},
        time::Instant as StdInstant,
    };

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        CrlDistributionPoint, CustomExtension, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevocationReason, RevokedCertParams, SerialNumber, date_time_ymd,
    };
    use rustls::crypto::ring;
    use serde_json::{from_value, json};
    use tokio::{
        runtime::Handle,
        task::yield_now,
        time::{MissedTickBehavior, interval, timeout},
    };
    use tracing::{Level, subscriber};
    use tracing_subscriber::fmt as subscriber_fmt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<StdMutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    struct CapturedLogsWriter(Arc<StdMutex<Vec<u8>>>);

    impl io::Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            {
                let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
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

    /// Parse an ASN.1 timestamp, failing the test with the offending value.
    fn asn1(timestamp: i64) -> anyhow::Result<ASN1Time> {
        ASN1Time::from_timestamp(timestamp).with_context(|| format!("ASN.1 timestamp {timestamp}"))
    }

    fn install_ring_provider() {
        // `CrlSet::new` builds a reqwest client whose rustls backend is compiled
        // with `rustls-no-provider`; installing the provider is idempotent and
        // keeps these unit tests independent from whichever integration test
        // happens to initialize crypto first.
        drop(ring::default_provider().install_default());
    }

    /// Generate the self-signed CA certificate shared by these tests.
    fn test_ca_root() -> anyhow::Result<CertificateDer<'static>> {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).context("CA certificate params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "mtls-revocation-unit-test-ca");
        let key = KeyPair::generate().context("CA key")?;
        let issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(params, key).context("self-signed CA")?;
        Ok(issuer.der().clone())
    }

    /// Build the mTLS configuration most unit tests start from.
    fn test_mtls_config() -> anyhow::Result<MtlsConfig> {
        from_value(json!({
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
        .context("verifier mtls config")
    }

    // trusted-origin derivation (operator-trusted CRL/AIA origins)

    /// Minimal DER length encoding (definite form, short or long).
    fn der_len(len: usize) -> anyhow::Result<Vec<u8>> {
        if len < 0x80 {
            return Ok(vec![
                u8::try_from(len).context("short DER length fits in a byte")?,
            ]);
        }
        let mut bytes = Vec::new();
        let mut remaining = len;
        while remaining > 0 {
            bytes.push(u8::try_from(remaining & 0xff).context("DER length byte")?);
            remaining >>= 8_u32;
        }
        bytes.reverse();
        let mut out =
            vec![0x80 | u8::try_from(bytes.len()).context("DER length-of-length fits in 7 bits")?];
        out.extend(bytes);
        Ok(out)
    }

    /// Wrap `content` in a DER TLV with the given tag byte.
    fn der_tlv(tag: u8, content: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![tag];
        out.extend(der_len(content.len())?);
        out.extend_from_slice(content);
        Ok(out)
    }

    /// DER encoding of the `id-ad-caIssuers` OID (1.3.6.1.5.5.7.48.2).
    const OID_AD_CA_ISSUERS_DER: [u8; 10] =
        [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    /// DER encoding of the `id-ad-ocsp` OID (1.3.6.1.5.5.7.48.1).
    const OID_AD_OCSP_DER: [u8; 10] = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

    /// Hand-encode an `AuthorityInfoAccessSyntax` extension value (RFC 5280
    /// §4.2.2.1) naming one or more (method OID DER, URI) access
    /// descriptions. `rcgen` has no native AIA field.
    fn aia_extension_der(entries: &[(&[u8], &str)]) -> anyhow::Result<Vec<u8>> {
        let mut access_descriptions = Vec::new();
        for (oid_der, uri) in entries {
            // GeneralName's uniformResourceIdentifier is context tag [6]
            // IMPLICIT IA5String (RFC 5280 appendix A).
            let general_name = der_tlv(0x86, uri.as_bytes())?;
            let mut access_description = Vec::new();
            access_description.extend_from_slice(oid_der);
            access_description.extend(general_name);
            access_descriptions.extend(der_tlv(0x30, &access_description)?);
        }
        der_tlv(0x30, &access_descriptions)
    }

    /// Build a self-signed CA certificate carrying a CDP extension with
    /// `cdp_uris` and an Authority Information Access extension with
    /// `aia_entries` (method OID DER, URI).
    fn build_ca_with_cdp_and_aia(
        common_name: &str,
        cdp_uris: Vec<String>,
        aia_entries: &[(&[u8], &str)],
    ) -> anyhow::Result<CertificateDer<'static>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        if !cdp_uris.is_empty() {
            params.crl_distribution_points = vec![CrlDistributionPoint { uris: cdp_uris }];
        }
        if !aia_entries.is_empty() {
            let aia_der = aia_extension_der(aia_entries)?;
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    aia_der,
                ));
        }
        let key = KeyPair::generate().context("ca key")?;
        let issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(params, key).context("ca self-signed")?;
        Ok(issuer.der().clone())
    }

    /// Pins that trusted-origin derivation reads CDP and AIA (caIssuers,
    /// OCSP) URIs from BOTH the CA-bundle and server-chain inputs, keeps
    /// only http(s), lowercases hosts, normalizes default ports, keeps
    /// IP-literal hosts (including a bracketed IPv6 literal), and drops
    /// userinfo-bearing and non-http(s) URIs.
    #[test]
    fn trusted_origins_derived_from_ca_bundle_and_server_chain() -> anyhow::Result<()> {
        let ca_cert = build_ca_with_cdp_and_aia(
            "trusted-origin-ca-bundle-cert",
            vec![
                "https://ca-cdp.example:443/crl".to_owned(),
                "https://user:pass@ca-cdp.example/userinfo-crl".to_owned(),
                "ldap://ca-cdp.example/crl".to_owned(),
            ],
            &[
                (&OID_AD_CA_ISSUERS_DER, "http://ca-issuer.example:80/ca.crt"),
                (&OID_AD_OCSP_DER, "http://192.0.2.1:8080/ocsp"),
            ],
        )?;
        let server_cert = build_ca_with_cdp_and_aia(
            "trusted-origin-server-chain-cert",
            vec![
                "HTTPS://CRL.Example.COM/x".to_owned(),
                "https://[2001:db8::1]:8443/crl".to_owned(),
            ],
            &[],
        )?;

        let origins = collect_trusted_crl_origins(
            slice::from_ref(&ca_cert),
            slice::from_ref(&server_cert),
            true,
        );
        let mut rendered: Vec<String> = origins.iter().map(Origin::ascii_serialization).collect();
        rendered.sort();

        assert_eq!(
            rendered,
            vec![
                "http://192.0.2.1:8080".to_owned(),
                "http://ca-issuer.example".to_owned(),
                "https://[2001:db8::1]:8443".to_owned(),
                "https://ca-cdp.example".to_owned(),
                "https://crl.example.com".to_owned(),
            ],
            "exactly the five http(s) origins must survive, with userinfo and ldap:// \
             dropped, hosts lowercased, and default ports normalized: {rendered:?}"
        );
        Ok(())
    }

    /// Pins that the connect-time resolver allowlist built from an
    /// IP-literal trusted origin carries no CIDR entries: `screen_addrs`
    /// applies CIDR entries to every hostname's resolved addresses, so an
    /// IP-literal origin added as a CIDR would let a rebinding hostname
    /// reach that same address on any port.
    #[test]
    fn ip_literal_trusted_origin_yields_no_resolver_cidr_entries() -> anyhow::Result<()> {
        let origin = Url::parse("http://127.0.0.1:4242/crl")
            .context("parse IP-literal origin URL")?
            .origin();
        let origins: HashSet<Origin> = once(origin).collect();

        assert!(
            trusted_hostnames(&origins).is_empty(),
            "an IP-literal origin must not contribute a resolver hostname"
        );
        let allowlist = build_trusted_origin_allowlist(&origins);
        assert!(
            !allowlist.ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "the resolver allowlist must hold no CIDR entry for an IP-literal trusted origin"
        );
        Ok(())
    }

    /// Pins that the trusted-origin match considers the full origin (scheme,
    /// host, port), not just host and port.
    ///
    /// A loopback address trusted only under `https` must stay blocked when
    /// the same host and port are requested under `http`.
    #[tokio::test]
    async fn fetch_crl_trusted_origin_match_is_scheme_sensitive() -> anyhow::Result<()> {
        install_ring_provider();
        let client = Client::new();
        let crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));
        let trusted_origin = Url::parse("https://127.0.0.1:65535/crl")
            .context("parse https trusted origin")?
            .origin();
        let trusted_origins: Arc<HashSet<Origin>> = Arc::new(once(trusted_origin).collect());

        let Err(err) = fetch_crl(
            &client,
            "http://127.0.0.1:65535/crl",
            true,
            1024,
            &crl_cpu,
            &trusted_origins,
        )
        .await
        else {
            anyhow::bail!(
                "a loopback origin trusted only under https must stay blocked under http"
            );
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("loopback"),
            "error must carry the loopback block reason: {rendered}"
        );
        Ok(())
    }

    /// Pins that a cloud-metadata address stays blocked even when its
    /// origin is in the trusted set: the exception in
    /// `reject_blocked_crl_ip` is unconditional on the block reason, not
    /// just on `trusted_origin`.
    ///
    /// Both the client's own timeout and the outer `tokio::time::timeout`
    /// bound this test's worst case: if the cloud-metadata exception were
    /// ever dropped, the pre-flight would stop rejecting before any network
    /// attempt, and the fetch would instead try to reach a real (unreachable
    /// from a test sandbox) `169.254.169.254` for as long as the client's
    /// timeout allows. Both bounds are generous for the passing case (the
    /// pre-flight returns in microseconds, no network attempted) and make a
    /// regression fail by assertion in bounded time instead of hanging until
    /// an external test-runner kill.
    #[tokio::test]
    async fn fetch_crl_cloud_metadata_blocked_even_for_trusted_origin() -> anyhow::Result<()> {
        install_ring_provider();
        let client = Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_millis(500))
            .build()
            .context("build bounded test client")?;
        let crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));
        let metadata_url = "http://169.254.169.254/latest/meta-data/";
        let trusted_origin = Url::parse(metadata_url)
            .context("parse cloud-metadata origin")?
            .origin();
        let trusted_origins: Arc<HashSet<Origin>> = Arc::new(once(trusted_origin).collect());

        let outcome = timeout(
            Duration::from_secs(2),
            fetch_crl(
                &client,
                metadata_url,
                true,
                1024,
                &crl_cpu,
                &trusted_origins,
            ),
        )
        .await
        .context(
            "cloud metadata must be rejected at the pre-flight stage, well within 2s; a \
             mutant that drops the cloud-metadata exception would instead attempt a real \
             network connection and hang here",
        )?;

        let Err(err) = outcome else {
            anyhow::bail!("cloud metadata must stay blocked even for a trusted origin");
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("cloud_metadata"),
            "error must carry the cloud_metadata block reason, proving the pre-flight check \
             ran before any network attempt: {rendered}"
        );
        Ok(())
    }

    /// Pins the server-chain source of trusted CRL origins end to end
    /// through the crate-internal `bootstrap_fetch_with_server_chain`: a CDP
    /// named ONLY in the server certificate chain (never in the CA bundle)
    /// is trusted and fetched.
    ///
    /// The production call site (`run_server` in `transport.rs`) that passes
    /// the real server chain is not unit-testable here: it also loads TLS
    /// listener state this module's tests do not construct. This test is the
    /// nearest in-crate seam: it calls the exact crate-internal function
    /// `run_server` calls, with the one parameter it is the only caller to
    /// populate.
    #[tokio::test]
    async fn bootstrap_fetch_with_server_chain_trusts_server_chain_only_origin()
    -> anyhow::Result<()> {
        install_ring_provider();
        let mock = MockServer::start().await;
        let port = mock.address().port();
        let cdp_url = format!("http://127.0.0.1:{port}/server-chain-only-crl");
        Mock::given(method("GET"))
            .and(path("/server-chain-only-crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::<u8>::new()))
            .mount(&mock)
            .await;

        // The CA bundle names NO CDP at all: if the trusted set were ever
        // derived from `ca_certs` alone, this origin would be absent from it
        // and the fetch below would stay blocked.
        let ca_cert = build_ca_with_cdp_and_aia("server-chain-only-ca", vec![], &[])?;
        let server_chain_cert =
            build_ca_with_cdp_and_aia("server-chain-only-leaf", vec![cdp_url.clone()], &[])?;

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.clone()).context("add ca root")?;

        let (set, discover_rx) = bootstrap_fetch_with_server_chain(
            Arc::new(roots),
            slice::from_ref(&ca_cert),
            slice::from_ref(&server_chain_cert),
            test_mtls_config()?,
        )
        .await
        .context("bootstrap with server chain")?;
        drop(discover_rx);

        // `__test_trigger_fetch` swallows fetch errors and never commits a
        // non-CRL body to the cache, so the trust decision is asserted by
        // the mock's received-request count, not by `__test_cache_contains`.
        set.__test_trigger_fetch(&cdp_url)
            .await
            .context("trigger fetch of the server-chain-only trusted origin")?;
        let received = mock
            .received_requests()
            .await
            .context("request recording must be enabled")?;
        assert!(
            received
                .iter()
                .any(|request| request.url.path() == "/server-chain-only-crl"),
            "a CDP named only in the server certificate chain must be trusted and reach \
             the mock"
        );
        Ok(())
    }

    fn test_crl_set_with_receiver() -> anyhow::Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>)>
    {
        test_crl_set_with_receiver_config(test_mtls_config()?)
    }

    #[expect(
        deprecated,
        reason = "deliberate: src/mtls_revocation.rs::test_crl_set_with_receiver_config exercises the deprecated test-only constructor, which is the behavior under test"
    )]
    fn test_crl_set_with_receiver_config(
        config: MtlsConfig,
    ) -> anyhow::Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>)> {
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        CrlSet::__test_with_kept_receiver(Arc::new(roots), config, vec![])
            .context("empty CRL set with kept receiver")
    }

    fn pending_contains(set: &CrlSet, url: &str) -> bool {
        set.pending_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(url)
    }

    fn seen_contains(set: &CrlSet, url: &str) -> bool {
        set.seen_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(url)
    }

    fn mark_pending(set: &CrlSet, url: &str) {
        let mut pending = set
            .pending_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _inserted = pending.insert(url.to_owned());
    }

    /// The pending marker must exist before a URL becomes observable on the
    /// discovery channel; otherwise a settlement racing the send strands the
    /// URL as permanently pending.
    ///
    /// Asserted at the exact instant it can be violated, via the pre-send
    /// probe. The previous form spun a contending thread across 200 attempts
    /// and could pass without ever producing the bad interleaving.
    #[test]
    fn discovery_does_not_send_before_pending_marker_exists() -> anyhow::Result<()> {
        let mut config = test_mtls_config()?;
        config.crl_discovery_rate_per_min = 10_000;
        config.crl_max_seen_urls = 512;
        let (set, mut discover_rx) = test_crl_set_with_receiver_config(config)?;

        let url = "http://pending-order.example.test/crl".to_owned();
        let observed = Arc::new(AtomicUsize::new(0));
        let probe_observed = Arc::clone(&observed);
        let probe_url = url.clone();

        set.__test_set_discovery_send_probe(Arc::new(move |probe_set: &CrlSet, sent: &str| {
            assert_eq!(sent, probe_url, "probe must observe the discovered URL");
            assert!(
                pending_contains(probe_set, sent),
                "URL {sent} became observable before its pending marker existed"
            );
            let _count = probe_observed.fetch_add(1, Ordering::Relaxed);
        }));

        let _accepted = set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]);

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
        Ok(())
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
    /// `verifier_state` are all derived from one already-bounded map. Post-hoc
    /// mutation would violate the publication ordering documented above.
    ///
    /// If you are here to "improve" this by making it drive `bootstrap_fetch`:
    /// do not add a precheck bypass to `fetch_crl` to do it.
    #[tokio::test]
    async fn bootstrap_cache_cap_is_applied_before_crl_set_publication() -> anyhow::Result<()> {
        let cap = 4_usize;
        let mut config = test_mtls_config()?;
        config.crl_max_cache_entries = cap;
        let (discover_tx, _discover_rx) = mpsc::unbounded_channel();
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        let arc_roots = Arc::new(roots);
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

        let set = new_crl_set_from_bootstrap_cache(
            arc_roots,
            config,
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )
        .context("bootstrap cache should build CRL set")?;
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
        Ok(())
    }

    /// Wait until `set` has an in-flight fetch for `host`, or fail the test.
    async fn wait_for_host_fetch_to_block_on_global_permit(
        set: &CrlSet,
        host: &str,
    ) -> anyhow::Result<()> {
        timeout(Duration::from_secs(2), async {
            loop {
                if set.host_semaphores.lock().await.contains_key(host) {
                    return;
                }
                yield_now().await;
            }
        })
        .await
        .context("refresher must reach the CRL fetch path before abort")
    }

    /// Aborting the refresher mid-fetch must clear the in-flight pending marker
    /// so the same URL can be retried by a later handshake.
    #[tokio::test]
    async fn aborted_refresher_does_not_strand_pending_url() -> anyhow::Result<()> {
        let (set, discover_rx) = test_crl_set_with_receiver()?;
        let url = "http://abort.example.test/crl";
        let host = "abort.example.test";
        let held_global_permit = Arc::clone(&set.global_fetch_sem)
            .acquire_owned()
            .await
            .context("test semaphore is open")?;

        assert!(!pending_contains(&set, url));
        assert!(!seen_contains(&set, url));

        let _queued = set.__test_note_discovered_urls_by_cert(&[url.to_owned()], &[]);
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

        wait_for_host_fetch_to_block_on_global_permit(&set, host).await?;
        handle.abort();
        let Err(join_error) = handle.await else {
            anyhow::bail!("aborted refresher must not complete normally");
        };
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

        let _requeued = set.__test_note_discovered_urls(&[url.to_owned()]);
        assert!(
            pending_contains(&set, url),
            "once the stale marker is gone, the same URL can be queued again"
        );
        assert!(
            !seen_contains(&set, url),
            "retry admission must still be pending-only, not permanent suppression"
        );
        Ok(())
    }

    /// `Ok(true)` from the settlement must permanently dedup the URL.
    #[test]
    fn discovered_url_settlement_promotes_only_confirmed_cache_admission() -> anyhow::Result<()> {
        let (set, _discover_rx) = test_crl_set_with_receiver()?;
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
        Ok(())
    }

    /// A cache-cap rejection must clear the marker, keep the URL retriable,
    /// and still emit the existing warning.
    #[test]
    fn discovered_url_settlement_clears_cache_cap_rejection_and_warns() -> anyhow::Result<()> {
        let (set, _discover_rx) = test_crl_set_with_receiver()?;
        let url = "http://settle-cap.example.test/crl";
        mark_pending(&set, url);
        let logs = CapturedLogs::default();
        let subscriber = subscriber_fmt()
            .with_max_level(Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

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
        Ok(())
    }

    /// A fetch failure must clear the marker, keep the URL retriable, and
    /// still emit the existing warning including the fetch error.
    #[test]
    fn discovered_url_settlement_clears_fetch_failure_and_warns() -> anyhow::Result<()> {
        let (set, _discover_rx) = test_crl_set_with_receiver()?;
        let url = "http://settle-error.example.test/crl";
        mark_pending(&set, url);
        let logs = CapturedLogs::default();
        let subscriber = subscriber_fmt()
            .with_max_level(Level::WARN)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = subscriber::set_default(subscriber);

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
        Ok(())
    }

    /// The userinfo gate fires before DNS resolution (no network needed)
    /// and the surfaced error must not echo the rejected credentials.
    #[tokio::test]
    async fn fetch_crl_rejects_userinfo_without_echoing_credentials() -> anyhow::Result<()> {
        // reqwest with `rustls-no-provider` requires a process-wide crypto
        // provider before any Client is built (same pattern as the
        // transport/oauth test suites).
        drop(ring::default_provider().install_default());
        let client = Client::new();
        let crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));
        let trusted_origins = Arc::new(HashSet::new());
        let Err(err) = fetch_crl(
            &client,
            "https://u:p@crl.example/ca.crl",
            false,
            1024,
            &crl_cpu,
            &trusted_origins,
        )
        .await
        else {
            anyhow::bail!("userinfo-bearing CRL URL must be rejected");
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("userinfo_forbidden"),
            "error must carry the rejection reason: {rendered}"
        );
        assert!(
            !rendered.contains("u:p"),
            "error must not echo the rejected credentials: {rendered}"
        );
        Ok(())
    }

    /// Pins that CRL fetch preflight rejects RFC 8215 local-use NAT64 targets.
    #[tokio::test]
    async fn crl_preflight_rejects_nat64_local_use_target() -> anyhow::Result<()> {
        let url = "https://crl.example/ca.crl";
        let ip = IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0x0808, 0x0808));
        let Err(err) = reject_blocked_crl_ip(url, ip, false) else {
            anyhow::bail!("local-use NAT64 CRL target must be rejected");
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("nat64_local_use"),
            "error must carry the local-use NAT64 reason: {rendered}"
        );
        Ok(())
    }

    /// `extract_cdp_urls`'s scheme/userinfo guard reuses the same gate;
    /// the sanitizer keeps credentials out of its debug logging too.
    #[test]
    fn sanitizer_used_by_rejection_sites_strips_credentials() -> anyhow::Result<()> {
        let parsed = Url::parse("https://u:p@crl.example/ca.crl").context("parse")?;
        let sanitized = sanitized_url_for_log(&parsed);
        assert_eq!(sanitized, "https://crl.example");
        assert!(!sanitized.contains("u:p"));
        Ok(())
    }

    /// Unrepresentable or out-of-range ASN.1 timestamps must clamp toward the
    /// epoch instead of panicking, and ordinary timestamps must round-trip.
    #[test]
    fn asn1_time_clamps_unrepresentable_timestamps() -> anyhow::Result<()> {
        // Year 1500 - pre-1601, NOT representable by Windows `SystemTime`.
        // Pre-fix this panicked on Windows; now it must return a value no
        // later than the epoch on every platform (clamped to UNIX_EPOCH on
        // Windows, the real instant on platforms that can represent it).
        let year_1500 = asn1_time_to_system_time(asn1(-14_831_769_600)?);
        assert!(year_1500 <= UNIX_EPOCH);
        #[cfg(windows)]
        assert_eq!(year_1500, UNIX_EPOCH);

        // 1601-01-01T00:00:00Z - the exact Windows epoch boundary, which IS
        // representable everywhere. No clamp, no panic.
        let year_1601 = asn1_time_to_system_time(asn1(-11_644_473_600)?);
        assert!(year_1601 <= UNIX_EPOCH);

        // Mildly negative (pre-1970) stays at-or-before the epoch.
        assert!(asn1_time_to_system_time(asn1(-2)?) <= UNIX_EPOCH);

        // Normal positive timestamps round-trip exactly.
        assert_eq!(
            asn1_time_to_system_time(asn1(1_700_000_000)?),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );

        // The ASN.1 maximum (9999-12-31) is representable and preserved.
        let max = i64::try_from(MAX_ASN1_TIMESTAMP_SECS).context("fits in i64")?;
        assert_eq!(
            asn1_time_to_system_time(asn1(max)?),
            UNIX_EPOCH + Duration::from_secs(MAX_ASN1_TIMESTAMP_SECS)
        );
        Ok(())
    }

    /// At the cap, a new host evicts idle semaphores rather than failing.
    #[test]
    fn host_semaphore_evicts_idle_at_cap() -> anyhow::Result<()> {
        let mut map = HashMap::new();
        for i in 0..4_usize {
            // Dropped immediately: only the map holds each semaphore (idle).
            drop(
                acquire_host_semaphore(&mut map, &format!("idle-{i}.example"), 4)
                    .context("under cap")?,
            );
        }
        assert_eq!(map.len(), 4);

        // At the cap, a NEW host must succeed by evicting idle entries -
        // the cap error is not sticky.
        let sem = acquire_host_semaphore(&mut map, "new-host.example", 4)
            .context("idle eviction frees space for a new host")?;
        assert!(map.contains_key("new-host.example"));
        drop(sem);
        Ok(())
    }

    /// In-flight semaphores survive eviction while idle ones are reclaimed.
    #[test]
    fn host_semaphore_keeps_inflight_at_cap() -> anyhow::Result<()> {
        let mut map = HashMap::new();
        // Held across the cap check: simulates an in-flight fetch.
        let inflight = acquire_host_semaphore(&mut map, "busy.example", 3).context("under cap")?;
        for i in 0..2_usize {
            drop(
                acquire_host_semaphore(&mut map, &format!("idle-{i}.example"), 3)
                    .context("under cap")?,
            );
        }
        assert_eq!(map.len(), 3);

        drop(
            acquire_host_semaphore(&mut map, "new-host.example", 3)
                .context("idle entries evicted while in-flight survives")?,
        );
        assert!(
            map.contains_key("busy.example"),
            "in-flight host must survive eviction"
        );
        assert!(map.contains_key("new-host.example"));
        drop(inflight);
        Ok(())
    }

    /// The cap error is returned only when every entry has an in-flight fetch.
    #[test]
    fn host_semaphore_cap_error_when_all_inflight() -> anyhow::Result<()> {
        let mut map = HashMap::new();
        let mut held = Vec::new();
        for i in 0..2_usize {
            held.push(
                acquire_host_semaphore(&mut map, &format!("busy-{i}.example"), 2)
                    .context("under cap")?,
            );
        }

        let result = acquire_host_semaphore(&mut map, "new-host.example", 2);
        assert!(
            result.is_err(),
            "cap must still reject when every entry has an in-flight fetch"
        );
        drop(held);
        Ok(())
    }

    // ---- CrlSet cache invariant (A1/A2/A3) --------------------------------

    /// Strict fail-closed config with generous caps, for tamper tests.
    fn tamper_test_config() -> anyhow::Result<MtlsConfig> {
        let mut config = test_mtls_config()?;
        config.crl_deny_on_unavailable = true;
        config.crl_end_entity_only = false;
        config.crl_discovery_rate_per_min = 10_000;
        config.crl_max_seen_urls = 4096;
        config.crl_max_cache_entries = 4096;
        Ok(config)
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
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(which)
    }

    /// A replacement that is indistinguishable from `entry` on every cheap
    /// field: same DER length, same 32-byte head and tail, same scalars, same
    /// `source_url`. Only a middle byte differs, so only the reallocation can
    /// betray it. An implementation comparing anything less than the full
    /// identity tuple fails the tests that use this.
    fn same_shape_replacement(entry: &CachedCrl) -> CachedCrl {
        let mut bytes = entry.der.as_ref().to_vec();
        let middle = bytes.len().div_euclid(2);
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

    fn crl_set_with_cached_urls(
        config: MtlsConfig,
        count: usize,
    ) -> anyhow::Result<(Arc<CrlSet>, Vec<String>)> {
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        let now = SystemTime::now();
        let mut initial_cache = HashMap::new();
        let mut urls = Vec::with_capacity(count);
        for index in 0..count {
            let url = format!("https://cdp-{index:03}.example.test/crl");
            let _previous = initial_cache.insert(url.clone(), synthetic_entry(now));
            urls.push(url);
        }
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);
        let set = CrlSet::new(
            Arc::new(roots),
            config,
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )
        .context("crl set with prepopulated cache")?;
        urls.sort();
        Ok((set, urls))
    }

    /// Identities are seeded by `CrlSet::new` and maintained by each commit.
    #[tokio::test]
    async fn identity_index_is_seeded_by_new_and_maintained_by_commit() -> anyhow::Result<()> {
        let boot = "https://cdp-000.example.test/crl";
        let (set, _urls) = crl_set_with_cached_urls(tamper_test_config()?, 1)?;

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
        let added_identity = identity_of(&set, added).context("commit must record an identity")?;

        set.__test_insert_cache(added, synthetic_entry(now + Duration::from_secs(3_600)))
            .await;
        assert!(
            identity_of(&set, added).as_ref() != Some(&added_identity),
            "legitimate replacement must change the recorded identity"
        );

        let _removed = set
            .commit_cache_update_atomically(Vec::new(), &[added.to_owned()])
            .await
            .context("removal commit")?;
        assert!(
            identity_of(&set, added).is_none(),
            "removal must drop the identity in the same publication"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/mtls_revocation.rs::identity_covers_der_bytes_beyond_the_sampled_head_and_tail keeps the uniform test signature while it cannot fail"
    )]
    /// The identity covers DER bytes beyond the sampled head and tail.
    #[test]
    fn identity_covers_der_bytes_beyond_the_sampled_head_and_tail() -> anyhow::Result<()> {
        let entry = synthetic_entry(SystemTime::now());
        assert!(
            entry.der.as_ref().len() > 64,
            "fixture must be longer than head+tail so the middle is unsampled"
        );
        assert!(
            entry_identity(&entry) != entry_identity(&same_shape_replacement(&entry)),
            "a same-length middle-byte edit must still change the identity"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/mtls_revocation.rs::identity_covers_every_scalar_field keeps the uniform test signature while it cannot fail"
    )]
    /// Every scalar field contributes to the entry identity.
    #[test]
    fn identity_covers_every_scalar_field() -> anyhow::Result<()> {
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
        Ok(())
    }

    /// Replacing a committed entry through the public cache must deny.
    #[tokio::test]
    async fn precheck_denies_after_same_key_replace_through_public_cache() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let url = "https://replace.example.test/crl".to_owned();
        let now = SystemTime::now();

        let committed = synthetic_entry(now);
        set.__test_insert_cache(&url, committed.clone()).await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
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
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
            "REPLACE through the public cache leaves cached_urls claiming coverage the verifier does not enforce; it must deny"
        );
        Ok(())
    }

    /// Removing a committed entry through the public cache must deny.
    #[tokio::test]
    async fn precheck_denies_after_direct_removal_through_public_cache() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let url = "https://remove.example.test/crl".to_owned();

        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;
        assert!(!set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]));

        let _removed = set.cache_lock().write().await.remove(&url);

        assert!(
            set.verifier_state.load().cached_urls.contains(&url),
            "precondition: cached_urls must still claim the removed URL"
        );
        assert!(
            !set.cache_lock().read().await.contains_key(&url),
            "precondition: the live entry must actually be gone"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
            "cached_urls still claims a URL whose entry was removed out of band; it must deny"
        );
        Ok(())
    }

    /// Contention on the cache lock is not tamper and must not deny.
    #[tokio::test]
    async fn precheck_uses_committed_state_when_cache_lock_is_temporarily_unavailable()
    -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let cached = "https://locked.example.test/crl".to_owned();
        let uncached = "https://locked-uncached.example.test/crl".to_owned();

        set.__test_insert_cache(&cached, synthetic_entry(SystemTime::now()))
            .await;
        assert!(!set.__test_note_discovered_urls_by_cert(slice::from_ref(&cached), &[]));

        // Contention is not tamper. `tokio::sync::RwLock` is write-preferring,
        // so denying here would make every legitimate refresh commit deny
        // concurrent handshakes; enforcement still runs against the immutable
        // committed state, which is what makes falling through sound.
        let guard = set.cache_lock().write().await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&cached), &[]),
            "temporary lock contention must not create a spurious denial"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&uncached), &[]),
            "lock contention must not invent coverage absent from the committed cached_urls"
        );
        drop(guard);
        Ok(())
    }

    /// The untampered precheck path is unchanged.
    #[tokio::test]
    async fn precheck_clean_path_is_unchanged() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let cached = "https://cached.example.test/crl".to_owned();
        let uncached = "https://uncached.example.test/crl".to_owned();

        set.__test_insert_cache(&cached, synthetic_entry(SystemTime::now()))
            .await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&cached), &[]),
            "an untampered cached CDP must still admit"
        );
        assert!(
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&uncached), &[]),
            "an uncached CDP must still follow the all(not cached) predicate"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(&[cached, uncached], &[]),
            "one cached mirror is sufficient coverage (RFC 5280 4.2.1.13)"
        );
        Ok(())
    }

    /// Concurrent commits lose no URL and publish a matching coverage hint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_commits_lose_no_url_and_publish_a_matching_coverage_hint()
    -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let now = SystemTime::now();
        let total = 64_usize;

        // Without `commit_lock` these commits each snapshot the same old cache
        // and clobber one another, so URLs are silently lost.
        let mut tasks = JoinSet::new();
        for index in 0..total {
            let task_set = Arc::clone(&set);
            let _task = tasks.spawn(async move {
                task_set
                    .__test_insert_cache(
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
        Ok(())
    }

    /// A legitimate refresh is never observed as tampering or half-applied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn legitimate_refresh_is_never_observed_as_tampering() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let url = "https://coherent.example.test/crl".to_owned();
        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;

        let stop = Arc::new(AtomicBool::new(false));
        let writer_set = Arc::clone(&set);
        let writer_url = url.clone();
        let writer_stop = Arc::clone(&stop);
        let writer = tokio::spawn(async move {
            for round in 0..400_u64 {
                if writer_stop.load(Ordering::Relaxed) {
                    break;
                }
                writer_set
                    .__test_insert_cache(
                        &writer_url,
                        synthetic_entry(SystemTime::now() + Duration::from_secs(round)),
                    )
                    .await;
                yield_now().await;
            }
            writer_stop.store(true, Ordering::Relaxed);
        });

        let reader_set = Arc::clone(&set);
        let reader_url = url.clone();
        let reader_stop = Arc::clone(&stop);
        let (denials, checks) = spawn_blocking(move || {
            let mut denials = 0_usize;
            let mut checks = 0_usize;
            while !reader_stop.load(Ordering::Relaxed) || checks < 1_000 {
                if reader_set.__test_note_discovered_urls_by_cert(slice::from_ref(&reader_url), &[])
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
        .context("reader task")?;

        writer.await.context("writer task")?;
        assert_eq!(
            denials, 0,
            "a legitimate refresh must never be reported as tampering, and must never be observed half-applied"
        );
        assert!(
            checks >= 1_000,
            "the reader must actually exercise the precheck: only {checks} checks ran"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
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
        Ok(())
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
    async fn commit_does_not_hold_the_cache_write_lock_across_the_verifier_rebuild()
    -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let url = "https://invalid-rebuild.example.test/crl";
        let now = SystemTime::now();

        let invalid = CachedCrl {
            der: CertificateRevocationListDer::from(vec![0_u8]),
            this_update: now,
            next_update: now.checked_add(Duration::from_hours(24)),
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
            let task_set = Arc::clone(&set);
            tokio::spawn(async move { task_set.__test_try_insert_cache(url, invalid).await })
        };

        let finished_while_reader_held = timeout(Duration::from_secs(5), commit).await;

        drop(read_guard);

        let commit_result = finished_while_reader_held
            .context("commit must reach rebuild_verifier before waiting for the cache write lock")?
            .context("commit task must not panic")?;

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
        Ok(())
    }

    // ---- B3: per-handshake CDP URL cap ------------------------------------

    /// Tamper config with fail-open revocation (cap still applies).
    fn fail_open_config() -> anyhow::Result<MtlsConfig> {
        let mut config = tamper_test_config()?;
        config.crl_deny_on_unavailable = false;
        Ok(config)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/mtls_revocation.rs::bootstrap_urls_are_capped_to_the_cache_limit keeps the uniform test signature while it cannot fail"
    )]
    /// A broad CA bundle is capped to the cache limit.
    #[test]
    fn bootstrap_urls_are_capped_to_the_cache_limit() -> anyhow::Result<()> {
        let cap = 4_usize;
        let mut urls: Vec<String> = (0..cap + 9)
            .map(|index| format!("https://ca-{index:02}.example.test/crl"))
            .collect();

        cap_bootstrap_urls(&mut urls, cap);

        assert_eq!(
            urls.len(),
            cap,
            "a broad CA bundle must not spawn one fetch task per advertised CDP"
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/mtls_revocation.rs::bootstrap_urls_below_the_cap_are_untouched keeps the uniform test signature while it cannot fail"
    )]
    /// An in-bounds CA chain is left untouched by the cap.
    #[test]
    fn bootstrap_urls_below_the_cap_are_untouched() -> anyhow::Result<()> {
        let mut urls: Vec<String> = (0..3_usize)
            .map(|index| format!("https://ca-{index:02}.example.test/crl"))
            .collect();
        let before = urls.clone();

        cap_bootstrap_urls(&mut urls, 16);

        assert_eq!(urls, before, "capping must not perturb an in-bounds chain");
        Ok(())
    }

    /// Under `crl_end_entity_only`, uncapped intermediate CDPs are never
    /// enqueued for discovery.
    #[tokio::test]
    async fn end_entity_only_mode_does_not_discover_uncapped_intermediate_cdps()
    -> anyhow::Result<()> {
        let mut config = tamper_test_config()?;
        config.crl_end_entity_only = true;
        let (set, mut rx) = test_crl_set_with_receiver_config(config)?;

        let end_entity = vec!["https://ee.example.test/crl".to_owned()];
        let intermediate: Vec<String> = (0..MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 10)
            .map(|index| format!("https://int-{index:03}.example.test/crl"))
            .collect();

        let _discovered = set.__test_note_discovered_urls_by_cert(&end_entity, &intermediate);

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
        Ok(())
    }

    /// Exactly the cap admits; one URL past it denies fail-closed.
    #[test]
    fn cdp_cap_admits_at_the_cap_and_denies_above_it_fail_closed() -> anyhow::Result<()> {
        let (at_cap, urls) =
            crl_set_with_cached_urls(tamper_test_config()?, MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE)?;
        assert!(
            !at_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "exactly the cap must admit; all URLs are cached so nothing else can deny"
        );

        let (over_cap, urls_over) = crl_set_with_cached_urls(
            tamper_test_config()?,
            MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1,
        )?;
        assert!(
            over_cap.__test_note_discovered_urls_by_cert(&urls_over, &[]),
            "one URL past the cap must deny even though every URL is cached"
        );
        assert!(
            warned(&over_cap, "cdp_url_cap"),
            "the cap denial must be attributable to the cap, not to some other condition"
        );
        Ok(())
    }

    /// The malformed-cert cap applies in fail-open mode too.
    #[test]
    fn cdp_cap_applies_in_fail_open_mode_too() -> anyhow::Result<()> {
        // The decision recorded in the rev-7 plan: this is a malformed-cert
        // rejection, not a revocation-unavailability denial, so opting out of
        // fail-closed does NOT opt out of the cap. An implementation that puts
        // the cap check inside the fail-closed branch admits here.
        let (over_cap, urls) =
            crl_set_with_cached_urls(fail_open_config()?, MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1)?;
        assert!(
            over_cap.__test_note_discovered_urls_by_cert(&urls, &[]),
            "the cap must deny in fail-open mode, where the same amplification is paid"
        );

        let (at_cap, urls_at) =
            crl_set_with_cached_urls(fail_open_config()?, MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE)?;
        assert!(
            !at_cap.__test_note_discovered_urls_by_cert(&urls_at, &[]),
            "the cap must not become a blanket fail-open denial"
        );
        Ok(())
    }

    /// The cap short-circuits before any per-entry mutation auditing.
    #[test]
    fn cdp_cap_is_evaluated_before_out_of_band_mutation_detection() -> anyhow::Result<()> {
        let (set, urls) = crl_set_with_cached_urls(
            tamper_test_config()?,
            MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE + 1,
        )?;
        let target = urls.first().context("at least one url")?.clone();
        let committed = set
            .cache_lock()
            .try_read()
            .context("uncontended")?
            .get(&target)
            .cloned()
            .context("entry present")?;
        drop(
            set.cache_lock()
                .try_write()
                .context("uncontended")?
                .insert(target, same_shape_replacement(&committed)),
        );

        assert!(set.__test_note_discovered_urls_by_cert(&urls, &[]));
        assert!(
            warned(&set, "cdp_url_cap"),
            "over-cap must be reported as the cap, so operators are not misdirected"
        );
        assert!(
            !warned(&set, "cache_entry_mismatch"),
            "the cap must short-circuit before any per-entry auditing runs"
        );
        Ok(())
    }

    // ---- B4-4 / B2: remaining precheck semantics --------------------------

    /// Committing an unrelated URL must not invalidate another URL's identity.
    #[tokio::test]
    async fn unrelated_commit_does_not_invalidate_other_urls() -> anyhow::Result<()> {
        // RELEASE-CRITICAL. `commit_cache_update_atomically` clones the live
        // cache, and cloning a `CachedCrl` reallocates its DER, so every
        // carried-forward entry gets a new address. An implementation that
        // carries identities forward instead of recomputing them denies every
        // handshake after any unrelated refresh.
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let first = "https://first.example.test/crl".to_owned();
        let second = "https://second.example.test/crl".to_owned();
        let now = SystemTime::now();

        set.__test_insert_cache(&first, synthetic_entry(now)).await;
        assert!(!set.__test_note_discovered_urls_by_cert(slice::from_ref(&first), &[]));

        set.__test_insert_cache(&second, synthetic_entry(now)).await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&first), &[]),
            "committing an unrelated URL must not invalidate an existing URL's identity"
        );
        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&second), &[]),
            "the newly committed URL must admit too"
        );
        Ok(())
    }

    /// Cache-lock contention is not logged as out-of-band mutation.
    #[tokio::test]
    async fn lock_contention_is_not_reported_as_out_of_band_mutation() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let url = "https://contended.example.test/crl".to_owned();
        set.__test_insert_cache(&url, synthetic_entry(SystemTime::now()))
            .await;

        let guard = set.cache_lock().write().await;
        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
            "contention must fall through to the committed state, not deny"
        );
        assert!(
            !warned(&set, "cache_entry_mismatch"),
            "contention must not be logged as out-of-band mutation, or operators chase a phantom"
        );
        drop(guard);
        Ok(())
    }

    /// Mutation detection only ever adds a denial, never flips one to admit.
    #[tokio::test]
    async fn mutation_detection_only_ever_adds_a_denial() -> anyhow::Result<()> {
        let (set, _rx) = test_crl_set_with_receiver_config(tamper_test_config()?)?;
        let cached = "https://audited.example.test/crl".to_owned();
        let uncached = "https://never-cached.example.test/crl".to_owned();
        let now = SystemTime::now();

        let committed = synthetic_entry(now);
        set.__test_insert_cache(&cached, committed.clone()).await;
        assert!(
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&uncached), &[]),
            "an all-uncached certificate denies under all(not cached) before any mutation"
        );

        set.__test_replace_cache_entry_unverified(&cached, same_shape_replacement(&committed))
            .await;

        assert!(
            set.__test_note_discovered_urls_by_cert(slice::from_ref(&uncached), &[]),
            "mutating an unrelated cached URL must not flip an all-uncached deny into an admit"
        );
        Ok(())
    }

    /// Fail-open mode stays fail-open for out-of-band mutation.
    #[tokio::test]
    async fn fail_open_mode_still_admits_a_mutated_entry() -> anyhow::Result<()> {
        // Operators who set `crl_deny_on_unavailable = false` accepted that a
        // revoked cert is admitted when its CRL cannot be trusted. Silently
        // re-enabling denial for them would be a behaviour change they did not
        // opt into; only the malformed-cert cap applies in this mode.
        let (set, _rx) = test_crl_set_with_receiver_config(fail_open_config()?)?;
        let url = "https://fail-open.example.test/crl".to_owned();
        let committed = synthetic_entry(SystemTime::now());

        set.__test_insert_cache(&url, committed.clone()).await;
        set.__test_replace_cache_entry_unverified(&url, same_shape_replacement(&committed))
            .await;

        assert!(
            !set.__test_note_discovered_urls_by_cert(slice::from_ref(&url), &[]),
            "fail-open must stay fail-open for out-of-band mutation"
        );
        Ok(())
    }

    // ---- WO-R6: per-peer CRL discovery admission ---------------------------

    /// A single peer draining its own per-peer discovery quota must not deny a
    /// concurrent legitimate peer presenting a not-yet-cached CDP URL -- the
    /// cross-peer starvation the process-global limiter allowed and per-peer
    /// keying removes. Also asserts the attributed path never fires the
    /// unattributed-fallback canary, proving the task-local scope was honoured.
    #[tokio::test]
    async fn per_peer_discovery_quota_does_not_starve_other_peers() -> anyhow::Result<()> {
        let mut config = test_mtls_config()?;
        config.crl_discovery_rate_per_min = 4;
        config.crl_deny_on_unavailable = false;
        let (set, _rx) = test_crl_set_with_receiver_config(config)?;

        let peer_a = IpAddr::from([203, 0, 113, 7]);
        let peer_b = IpAddr::from([203, 0, 113, 8]);

        let attacker_urls: Vec<String> = (0..8_usize)
            .map(|i| format!("http://attacker-{i:02}.example.test/crl"))
            .collect();
        CURRENT_HANDSHAKE_PEER
            .scope(peer_a, async {
                let _drained = set.__test_note_discovered_urls_by_cert(&attacker_urls, &[]);
            })
            .await;

        let attacker_dropped = attacker_urls
            .iter()
            .filter(|url| !set.__test_is_seen(url.as_str()))
            .count();
        assert!(
            attacker_dropped > 0,
            "peer_a must exhaust its own per-peer quota so later URLs are dropped"
        );
        assert!(
            warned(&set, "discovery_rate_limited"),
            "a per-peer denial must fire the throttled discovery_rate_limited WARN"
        );
        assert!(
            !warned(&set, "discovery_unattributed_fallback"),
            "an attributed handshake must NOT fall back to the global limiter"
        );

        let victim_url = "http://victim.example.test/crl".to_owned();
        CURRENT_HANDSHAKE_PEER
            .scope(peer_b, async {
                let _victim =
                    set.__test_note_discovered_urls_by_cert(slice::from_ref(&victim_url), &[]);
            })
            .await;

        assert!(
            set.__test_is_seen(&victim_url),
            "peer_b's not-yet-cached URL must still be admitted after peer_a drained its own quota"
        );
        Ok(())
    }

    /// With no handshake peer scope, admission must fall back to the
    /// process-global limiter and behave exactly as before per-peer keying:
    /// the global per-minute quota gates admission and the unattributed canary
    /// fires so a lost scope is observable rather than silent.
    #[tokio::test]
    async fn unattributed_discovery_falls_back_to_global_limiter() -> anyhow::Result<()> {
        let mut config = test_mtls_config()?;
        config.crl_discovery_rate_per_min = 4;
        config.crl_deny_on_unavailable = false;
        let (set, _rx) = test_crl_set_with_receiver_config(config)?;

        let urls: Vec<String> = (0..8_usize)
            .map(|i| format!("http://unattributed-{i:02}.example.test/crl"))
            .collect();
        let _admitted = set.__test_note_discovered_urls_by_cert(&urls, &[]);

        let admitted = urls
            .iter()
            .filter(|url| set.__test_is_seen(url.as_str()))
            .count();
        assert_eq!(
            admitted, 4,
            "the global fallback limiter must admit exactly the per-minute quota and drop the rest"
        );
        assert!(
            warned(&set, "discovery_unattributed_fallback"),
            "the unattributed path must fire the fallback canary so a lost scope is observable"
        );
        assert!(
            warned(&set, "discovery_rate_limited"),
            "the global fallback must still fire the rate-limited WARN on drops"
        );
        Ok(())
    }

    /// Per-peer keying widens the aggregate discovery RATE but must never let
    /// many distinct peers push the shared `pending_urls` set past
    /// `crl_max_seen_urls`: memory stays bounded regardless of peer count.
    #[tokio::test]
    async fn many_peers_cannot_exceed_pending_urls_cap() -> anyhow::Result<()> {
        let mut config = test_mtls_config()?;
        config.crl_discovery_rate_per_min = 64;
        config.crl_deny_on_unavailable = false;
        let cap = config.crl_max_seen_urls;
        let (set, _rx) = test_crl_set_with_receiver_config(config)?;

        for peer_index in 0..32_u8 {
            let peer = IpAddr::from([198, 51, 100, peer_index]);
            let urls: Vec<String> = (0..4_usize)
                .map(|unit| format!("http://p{peer_index:03}-u{unit}.example.test/crl"))
                .collect();
            CURRENT_HANDSHAKE_PEER
                .scope(peer, async {
                    let _peer_admitted = set.__test_note_discovered_urls_by_cert(&urls, &[]);
                })
                .await;
        }

        let pending = set
            .pending_urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert!(
            pending <= cap,
            "pending_urls ({pending}) must never exceed crl_max_seen_urls ({cap}) regardless of peer count"
        );
        Ok(())
    }

    // ---- CRL parsing and verifier rebuilds run on the blocking pool

    /// Revoked-certificate count the shared large CRL fixture below starts
    /// from; `adaptive_large_crl_der` grows it (doubling, bounded by
    /// `LARGE_FIXTURE_ENTRIES_MAX`) until a single synchronous parse takes at
    /// least the caller's target duration, so the fixture stays heavy enough
    /// on a fast machine instead of a fixed count needing per-host tuning.
    const LARGE_FIXTURE_ENTRIES: u64 = 16_000;

    /// Upper bound on adaptive CRL fixture growth. The helpers stop as soon
    /// as their target duration is met, so wall time and memory scale with
    /// the runner's own speed: faster machines need more entries for the
    /// same duration, but each entry costs them less. This cap is 8x the old
    /// bound, so only a runner several times faster than the development box
    /// should approach it; reaching it below target is a loud test-fixture
    /// error, not a weak pass.
    const LARGE_FIXTURE_ENTRIES_MAX: u64 = 1_024_000;

    /// How many copies of the shared large fixture CRL the commit-path
    /// progress and cancellation tests pre-populate the cache with, to
    /// approximate a multi-CRL verifier rebuild at a scale a debug test
    /// build can afford.
    const COMMIT_FIXTURE_COUNT: usize = 3;

    /// Floor for `yield_progress_count_until`'s counter. A mutant that runs
    /// the measured CPU-bound work inline (no `.await` point at all) leaves
    /// the counter at 0 or 1, since the executor never gets a chance to poll
    /// it before the race ends; genuine offload lets the scheduler dispatch
    /// the progress task repeatedly for the whole duration of the blocking
    /// work, reaching into the hundreds even on a loaded CI box. 50 is a
    /// large margin above the mutant's ceiling and a large margin below a
    /// realistic genuine-offload count - with no wall-clock dependence at
    /// all, since it counts scheduler dispatches, not elapsed time.
    const PROGRESS_COUNT_FLOOR: u64 = 50;

    /// Revoked-certificate entries for a large CRL fixture: `entry_count`
    /// synthetic serials, all revoked for key compromise.
    fn large_crl_revoked_certs(entry_count: u64) -> Vec<RevokedCertParams> {
        (0..entry_count)
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from(serial),
                revocation_time: date_time_ymd(2026, 1, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect()
    }

    /// Sign a CRL with `entry_count` revoked entries, issued by `ca`.
    fn sign_large_crl(
        ca: &CertifiedIssuer<'static, KeyPair>,
        entry_count: u64,
    ) -> anyhow::Result<CertificateRevocationListDer<'static>> {
        let der: CertificateRevocationListDer<'static> = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2027, 1, 1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: large_crl_revoked_certs(entry_count),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(ca)
        .context("sign large CRL")?
        .into();
        Ok(der)
    }

    /// Build a self-signed CA with no CDP: the helper-level CPU-offload
    /// tests below parse and rebuild the fixture directly and never fetch it
    /// over the network.
    fn build_large_crl_fixture_ca(
        common_name: &str,
    ) -> anyhow::Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("CRL CA params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().context("CRL CA key")?;
        CertifiedIssuer::self_signed(params, key).context("CRL CA self-signed")
    }

    /// Build a self-signed CA and a CRL DER revoking `entry_count`
    /// certificates, for the large-fixture CPU-offload tests.
    fn generate_large_crl_der(
        entry_count: u64,
    ) -> anyhow::Result<CertificateRevocationListDer<'static>> {
        let ca = build_large_crl_fixture_ca("large-crl-fixture-ca")?;
        sign_large_crl(&ca, entry_count)
    }

    /// Build a `CachedCrl` from a DER buffer, parsing its real metadata
    /// (unlike `synthetic_entry`'s minimal placeholder DER).
    fn cached_crl_from_der(
        der: CertificateRevocationListDer<'static>,
        source_url: &str,
    ) -> anyhow::Result<CachedCrl> {
        let (this_update, next_update) =
            parse_crl_metadata(der.as_ref()).context("parse fixture CRL metadata")?;
        Ok(CachedCrl {
            der,
            this_update,
            next_update,
            fetched_at: SystemTime::now(),
            source_url: source_url.to_owned(),
        })
    }

    /// Grow `entry_count` by doubling (bounded by `LARGE_FIXTURE_ENTRIES_MAX`)
    /// until a synchronous parse of the generated CRL takes at least
    /// `target`, returning the DER that met it. Keeps the "fixture is heavy
    /// enough" precondition the CPU-offload tests rely on adaptive to host
    /// speed, instead of a fixed entry count a fast machine could outrun.
    fn adaptive_large_crl_der(
        target: Duration,
    ) -> anyhow::Result<(CertificateRevocationListDer<'static>, Duration)> {
        let mut entries = LARGE_FIXTURE_ENTRIES;
        loop {
            let der = generate_large_crl_der(entries)?;
            let start = StdInstant::now();
            let _parsed = parse_crl_metadata(der.as_ref()).context("adaptive fixture parse")?;
            let parse_elapsed = start.elapsed();
            if parse_elapsed >= target {
                return Ok((der, parse_elapsed));
            }
            if entries >= LARGE_FIXTURE_ENTRIES_MAX {
                anyhow::bail!(
                    "large CRL fixture capped below target: parse_elapsed={parse_elapsed:?}, \
                     target={target:?}, cap_entries={LARGE_FIXTURE_ENTRIES_MAX}; \
                     this machine is faster than the fixture can compensate for, so enlarge \
                     LARGE_FIXTURE_ENTRIES_MAX"
                );
            }
            entries = entries.saturating_mul(2).min(LARGE_FIXTURE_ENTRIES_MAX);
        }
    }

    /// One large CRL DER, generated once and shared by every helper-level
    /// CPU-offload test in this module: fixture generation (signing every
    /// revoked-certificate entry) is the slow part, and the DER is read-only
    /// once built, so every test reuses this one instance instead of
    /// regenerating it. Its parse baseline is at least 300 ms, which keeps the
    /// cancellation permit race margin well above coarse CI scheduling stalls.
    fn shared_large_crl_der() -> anyhow::Result<&'static CertificateRevocationListDer<'static>> {
        Ok(&shared_large_crl_fixture()?.0)
    }

    fn shared_large_crl_parse_baseline() -> anyhow::Result<Duration> {
        Ok(shared_large_crl_fixture()?.1)
    }

    fn shared_large_crl_fixture()
    -> anyhow::Result<&'static (CertificateRevocationListDer<'static>, Duration)> {
        static FIXTURE: OnceLock<(CertificateRevocationListDer<'static>, Duration)> =
            OnceLock::new();
        if let Some(fixture) = FIXTURE.get() {
            return Ok(fixture);
        }
        let fixture = adaptive_large_crl_der(Duration::from_millis(300))?;
        Ok(FIXTURE.get_or_init(move || fixture))
    }

    /// Run `fut` to completion while a task that does nothing but repeatedly
    /// `tokio::task::yield_now().await` runs concurrently on this (possibly
    /// single-threaded) runtime, returning how many times that loop body ran
    /// alongside `fut`'s result.
    ///
    /// A pure scheduling-progress count, with no wall-clock dependence at
    /// all: see `PROGRESS_COUNT_FLOOR` for why a mutant and genuine offload
    /// are separated by orders of magnitude, not a ratio.
    async fn yield_progress_count_until<F>(fut: F) -> (u64, anyhow::Result<()>)
    where
        F: Future<Output = anyhow::Result<()>>,
    {
        let counter = Arc::new(AtomicU64::new(0));
        let task_counter = Arc::clone(&counter);
        let progress = tokio::spawn(async move {
            loop {
                let _previous = task_counter.fetch_add(1, Ordering::Relaxed);
                yield_now().await;
            }
        });

        let result = fut.await;
        progress.abort();
        let _joined = progress.await;

        (counter.load(Ordering::Relaxed), result)
    }

    /// Run `fut` to completion while a real-clock 5 ms ticker runs
    /// concurrently on this (possibly single-threaded) runtime, returning the
    /// largest gap observed between consecutive ticks alongside `fut`'s
    /// result.
    ///
    /// A stalled executor thread (synchronous CPU work with no yield point)
    /// shows up as one gap close to the stall's whole duration; an executor
    /// that keeps yielding to work offloaded elsewhere (`spawn_blocking`)
    /// shows only small, timer-jitter gaps. Used only by the end-to-end
    /// bootstrap test below: that test's measured work interleaves with real
    /// socket I/O, during which a plain scheduling-progress count keeps
    /// advancing regardless of whether the CPU-bound parts are offloaded, so
    /// a gap measurement is the only one of the two methods that can still
    /// detect a stall there.
    async fn max_ticker_gap_until<F>(fut: F) -> (Duration, anyhow::Result<()>)
    where
        F: Future<Output = anyhow::Result<()>>,
    {
        let max_gap_cell = Arc::new(StdMutex::new(Duration::ZERO));
        // Seeded to the race's start, not left at a zero/placeholder value:
        // a ticker that never gets polled even once (the executor is fully
        // starved end to end) must still read back as one large gap, not a
        // vacuous `Duration::ZERO` the inter-tick loop below never observed.
        let last_tick = Arc::new(StdMutex::new(StdInstant::now()));
        let ticker_max_gap = Arc::clone(&max_gap_cell);
        let ticker_last_tick = Arc::clone(&last_tick);
        let ticker = tokio::spawn(async move {
            let mut ticks = interval(Duration::from_millis(5));
            ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                let _tick = ticks.tick().await;
                let now = StdInstant::now();
                let gap = {
                    let mut last_guard = ticker_last_tick
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let gap = now.duration_since(*last_guard);
                    *last_guard = now;
                    gap
                };
                let mut max_guard = ticker_max_gap
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if gap > *max_guard {
                    *max_guard = gap;
                }
            }
        });

        let result = fut.await;
        // Close out any trailing gap since the last successful tick: the
        // inter-tick loop above can only record a gap once a NEXT tick
        // arrives to measure against, so a ticker that fell behind (or never
        // ran at all) right up to `fut`'s completion would otherwise go
        // unmeasured.
        let now = StdInstant::now();
        {
            let last = *last_tick.lock().unwrap_or_else(PoisonError::into_inner);
            let trailing_gap = now.duration_since(last);
            let mut max_guard = max_gap_cell.lock().unwrap_or_else(PoisonError::into_inner);
            if trailing_gap > *max_guard {
                *max_guard = trailing_gap;
            }
        }
        ticker.abort();
        let _joined = ticker.await;

        let max_gap = *max_gap_cell.lock().unwrap_or_else(PoisonError::into_inner);
        (max_gap, result)
    }

    /// Pins that `fetch_crl`'s DER parse runs on the blocking pool: on a
    /// current-thread runtime, a `yield_now`-looping progress counter keeps
    /// advancing while a large CRL is parsed through
    /// [`parse_crl_metadata_blocking`] (the same offload helper `fetch_crl`
    /// calls), instead of being starved for the whole parse duration. A pure
    /// scheduling-progress count: no wall-clock ratio, no `sleep`.
    ///
    /// Calls `parse_crl_metadata_blocking` directly rather than the full
    /// `fetch_crl`: `fetch_crl` also screens the resolved address before
    /// connecting, and a `wiremock` server only ever resolves to loopback,
    /// which that unrelated, pre-existing screening always rejects. This is
    /// the "nearest in-crate seam" that still exercises the real offloaded
    /// parse path;
    /// `bootstrap_fetch_offload_keeps_the_runtime_responsive_end_to_end`
    /// below exercises the real network path, now that a trusted loopback
    /// origin can be fetched.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_crl_offload_keeps_the_runtime_responsive() -> anyhow::Result<()> {
        install_ring_provider();
        let der = shared_large_crl_der()?;
        let der_bytes = der.as_ref().to_vec();

        let baseline_start = StdInstant::now();
        let _metadata =
            parse_crl_metadata(&der_bytes).context("baseline parse must succeed on the fixture")?;
        let baseline = baseline_start.elapsed();
        assert!(
            baseline >= Duration::from_millis(20),
            "fixture must take at least 20 ms to parse synchronously (was {baseline:?}); \
             adaptive_large_crl_der should have grown it further"
        );

        let crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));
        let (progress, parse_result) = yield_progress_count_until(async {
            let _parsed = {
                let permit = Arc::clone(&crl_cpu)
                    .acquire_owned()
                    .await
                    .context("acquire CRL CPU permit")?;
                parse_crl_metadata_blocking(der_bytes.clone(), permit)
                    .await
                    .map_err(anyhow::Error::from)?
            };
            Ok(())
        })
        .await;
        parse_result
            .context("offloaded parse_crl_metadata_blocking must succeed on the fixture")?;

        assert!(
            progress >= PROGRESS_COUNT_FLOOR,
            "offloaded parse must not stall the runtime: the scheduler only dispatched the \
             progress counter {progress} times while the parse ran (floor {PROGRESS_COUNT_FLOOR})"
        );
        Ok(())
    }

    /// Pins that `commit_cache_update_atomically`'s verifier rebuild and
    /// identity recomputation run on the blocking pool: the same
    /// scheduling-progress-count property as the parse test above, applied
    /// to a commit that rebuilds a verifier over several large cached CRLs.
    #[tokio::test(flavor = "current_thread")]
    async fn commit_rebuild_offload_keeps_the_runtime_responsive() -> anyhow::Result<()> {
        install_ring_provider();
        let der = shared_large_crl_der()?;

        let mut config = test_mtls_config()?;
        config.crl_max_cache_entries = 64;
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        let arc_roots = Arc::new(roots);

        let mut initial_cache = HashMap::new();
        for index in 0..COMMIT_FIXTURE_COUNT {
            let url = format!("memory://large-crl-{index}");
            let entry = cached_crl_from_der(der.clone(), &url)?;
            let _previous = initial_cache.insert(url, entry);
        }

        let extra_url = "memory://large-crl-extra".to_owned();
        let extra_entry = cached_crl_from_der(der.clone(), &extra_url)?;

        let mut baseline_candidate = initial_cache.clone();
        let _displaced = baseline_candidate.insert(extra_url.clone(), extra_entry.clone());
        let _baseline = shared_large_crl_parse_baseline()?;

        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);
        let set = CrlSet::new(
            Arc::clone(&arc_roots),
            config,
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )?;

        let (progress, commit_result) = yield_progress_count_until(async {
            set.__test_try_insert_cache(&extra_url, extra_entry)
                .await
                .map(|_changed| ())
                .map_err(anyhow::Error::from)
        })
        .await;
        commit_result.context("offloaded commit must succeed")?;

        assert!(
            progress >= PROGRESS_COUNT_FLOOR,
            "offloaded commit rebuild must not stall the runtime: the scheduler only \
             dispatched the progress counter {progress} times while the rebuild ran \
             (floor {PROGRESS_COUNT_FLOOR})"
        );
        Ok(())
    }

    /// Pins that the CRL CPU permit is held by the BLOCKING CLOSURE, not by
    /// the awaiting future: aborting the task that awaits the offloaded
    /// parse must not release the permit before the bounded parse actually
    /// finishes.
    ///
    /// No fixed `sleep` anywhere in this test. The "permit still held right
    /// after abort" assertion is safe from its one possible race - the
    /// detached parse finishing before the assertion runs - by construction,
    /// not by probability: the permit is only observed taken by POLLING
    /// (`yield_now`, no sleep), so the very next statement runs within a
    /// handful of scheduler ticks of that observation, well below the
    /// fixture's generation-time parse baseline, which is grown to at least
    /// 300 ms. A warm re-parse can legitimately be lower, so this test relies
    /// on the helper's own cold measurement instead of gating on a fresh
    /// wall-clock measurement. The eventual release is then proven by a
    /// notification barrier
    /// (`Semaphore::acquire_many_owned` under a generous `timeout`), not a
    /// fixed `sleep`.
    #[tokio::test]
    async fn crl_cpu_permit_stays_held_until_blocking_parse_completes_after_cancellation()
    -> anyhow::Result<()> {
        install_ring_provider();
        let der = shared_large_crl_der()?;
        let der_bytes = der.as_ref().to_vec();

        let baseline = shared_large_crl_parse_baseline()?;
        assert!(
            baseline >= Duration::from_millis(300),
            "fixture must take at least 300 ms to parse synchronously (was {baseline:?})"
        );

        let crl_cpu = Arc::new(Semaphore::new(CRL_CPU_PERMITS));
        let task_cpu = Arc::clone(&crl_cpu);
        let handle = tokio::spawn(async move {
            let permit = Arc::clone(&task_cpu)
                .acquire_owned()
                .await
                .context("acquire CRL CPU permit")?;
            parse_crl_metadata_blocking(der_bytes, permit)
                .await
                .map_err(anyhow::Error::from)
        });

        // Poll (no sleep) until the spawned task's `acquire_owned` has
        // actually completed: the permit count only drops once that
        // happens, so this cannot observe a false "taken" before it is true.
        let observed = timeout(Duration::from_secs(5), async {
            loop {
                if crl_cpu.available_permits() < CRL_CPU_PERMITS {
                    return;
                }
                yield_now().await;
            }
        })
        .await;
        observed.context("the permit must be observed taken within 5s")?;

        handle.abort();
        let _joined = handle.await;

        assert_eq!(
            crl_cpu.available_permits(),
            CRL_CPU_PERMITS - 1,
            "the permit must still be held immediately after the awaiting task is aborted: \
             it is owned by the detached blocking closure, not by the aborted future"
        );

        // Notification barrier: both permits become acquirable again only
        // once the detached parse actually finishes and drops its permit.
        let permit_count =
            u32::try_from(CRL_CPU_PERMITS).context("CRL_CPU_PERMITS must fit in a u32")?;
        let _barrier = timeout(
            Duration::from_secs(30),
            Arc::clone(&crl_cpu).acquire_many_owned(permit_count),
        )
        .await
        .context("the detached parse must release the permit within 30s")?
        .context("acquire_many_owned must succeed")?;
        Ok(())
    }

    /// Pins that a cancelled commit lets the bounded verifier rebuild finish
    /// in the background and discards its result: the committed cache and
    /// the published verifier stay at the previous generation, even once the
    /// detached blocking work later completes.
    ///
    /// No fixed `sleep` anywhere in this test: both waits are
    /// notification-driven (poll-until-permit-taken before aborting;
    /// `acquire_many_owned` under a generous `timeout`; then a state-driven
    /// drain that waits for the commit mutex and spawned-task count before the
    /// final re-check), for the same reason given on the permit test above.
    #[tokio::test]
    async fn cancelled_commit_leaves_the_previous_generation_published() -> anyhow::Result<()> {
        install_ring_provider();
        let der = shared_large_crl_der()?;

        let mut config = test_mtls_config()?;
        config.crl_max_cache_entries = 64;
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        let arc_roots = Arc::new(roots);

        let small_url = "memory://small-baseline".to_owned();
        let small_entry = synthetic_entry(SystemTime::now());
        let mut initial_cache = HashMap::new();
        let _previous = initial_cache.insert(small_url, small_entry);

        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);
        let set = CrlSet::new(
            Arc::clone(&arc_roots),
            config.clone(),
            discover_tx,
            initial_cache,
            Arc::new(HashSet::new()),
        )?;

        let large_url = "memory://large-new-entry".to_owned();
        let large_entry = cached_crl_from_der(der.clone(), &large_url)?;

        // Read directly from the LIVE cache both times, with nothing in
        // between: a `CachedCrl`'s DER reallocates on every `.clone()`, so
        // comparing two independently-cloned snapshots would always differ
        // in `der_ptr` even when nothing changed.
        let pre_cache_identities = {
            let cache = set.cache_lock().read().await;
            crl_cache_identities(&cache)
        };
        let pre_committed_identities = set.verifier_state.load().committed_identities.clone();
        let pre_cached_urls = set.verifier_state.load().cached_urls.clone();

        let alive_tasks_before_commit = Handle::current().metrics().num_alive_tasks();
        let task_set = Arc::clone(&set);
        let handle = tokio::spawn(async move {
            task_set
                .__test_try_insert_cache(&large_url, large_entry)
                .await
        });

        // Poll (no sleep) until the commit holds the CRL CPU permit:
        // `commit_cache_update_atomically` acquires the permit and spawns
        // the blocking rebuild in the same expression, with no `.await`
        // point between them, so observing the permit taken also proves the
        // detached rebuild has already been dispatched.
        let permit_taken = timeout(Duration::from_secs(5), async {
            loop {
                if set.crl_cpu.available_permits() < CRL_CPU_PERMITS {
                    return;
                }
                yield_now().await;
            }
        })
        .await;
        permit_taken.context("the commit must take the CRL CPU permit within 5s")?;

        handle.abort();
        let _joined = handle.await;

        {
            let cache_now = set.cache_lock().read().await;
            assert_eq!(
                crl_cache_identities(&cache_now),
                pre_cache_identities,
                "a cancelled commit must not publish a partial cache write"
            );
        }
        let state_now = set.verifier_state.load();
        assert_eq!(
            state_now.committed_identities, pre_committed_identities,
            "a cancelled commit must not publish new identities"
        );
        assert_eq!(
            state_now.cached_urls, pre_cached_urls,
            "a cancelled commit must not publish new coverage"
        );
        drop(state_now);

        // Notification barrier: let the detached blocking rebuild actually
        // finish (both permits become acquirable again only once it does),
        // then prove again that its discarded result was never published
        // late.
        let permit_count =
            u32::try_from(CRL_CPU_PERMITS).context("CRL_CPU_PERMITS must fit in a u32")?;
        let _barrier = timeout(
            Duration::from_secs(30),
            Arc::clone(&set.crl_cpu).acquire_many_owned(permit_count),
        )
        .await
        .context("the detached rebuild must release the permit within 30s")?
        .context("acquire_many_owned must succeed")?;

        // State-driven drain: a detached whole-commit mutant keeps
        // `commit_lock` until its publication tail finishes. Tokio's runtime
        // metric counts spawned async tasks; sampling before the commit task is
        // spawned means a detached tail task of any shape must finish before
        // the count returns to this baseline. Blocking-pool jobs are covered by
        // the permit barrier above, so no fixed yield count or sleep is needed.
        drain_cancelled_commit_tail(&set, alive_tasks_before_commit).await?;

        assert_cancelled_commit_still_unpublished(
            &set,
            &pre_cache_identities,
            &pre_committed_identities,
        )
        .await;
        Ok(())
    }

    async fn drain_cancelled_commit_tail(
        set: &CrlSet,
        alive_tasks_before_commit: usize,
    ) -> anyhow::Result<()> {
        let drain_start = StdInstant::now();
        timeout(Duration::from_secs(30), async {
            loop {
                {
                    let _commit = set.commit_lock.lock().await;
                }
                if Handle::current().metrics().num_alive_tasks() <= alive_tasks_before_commit {
                    return;
                }
                yield_now().await;
            }
        })
        .await
        .context("the cancelled commit tail must drain within 30s")?;
        let _drain_elapsed = drain_start.elapsed();
        Ok(())
    }

    async fn assert_cancelled_commit_still_unpublished(
        set: &CrlSet,
        pre_cache_identities: &HashMap<String, EntryIdentity>,
        pre_committed_identities: &HashMap<String, EntryIdentity>,
    ) {
        {
            let cache_now = set.cache_lock().read().await;
            assert_eq!(
                &crl_cache_identities(&cache_now),
                pre_cache_identities,
                "the discarded blocking result must never be published late"
            );
        }
        let state_after = set.verifier_state.load();
        assert_eq!(
            &state_after.committed_identities, pre_committed_identities,
            "the discarded blocking result must never publish identities late"
        );
    }

    /// Pins that a closed `crl_cpu` semaphore surfaces as an error instead of
    /// a hang.
    ///
    /// Covers only the closed-semaphore sub-case of `JoinError` handling: a
    /// genuine panic inside `rebuild_verifier` or `parse_crl_metadata` is not
    /// cheaply testable without a new test-only fault-injection hook, which
    /// this unit does not add (no new public or `test-helpers` item).
    #[tokio::test]
    async fn closed_crl_cpu_semaphore_surfaces_as_an_error_not_a_hang() -> anyhow::Result<()> {
        install_ring_provider();
        let mut config = test_mtls_config()?;
        config.crl_max_cache_entries = 64;
        let mut roots = RootCertStore::empty();
        roots.add(test_ca_root()?).context("add ca root")?;
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);
        let set = CrlSet::new(
            Arc::new(roots),
            config,
            discover_tx,
            HashMap::new(),
            Arc::new(HashSet::new()),
        )?;
        set.crl_cpu.close();

        let url = "memory://closed-semaphore".to_owned();
        let entry = synthetic_entry(SystemTime::now());
        let result = timeout(
            Duration::from_secs(5),
            set.__test_try_insert_cache(&url, entry),
        )
        .await
        .context("commit must not hang when the CRL CPU semaphore is closed")?;

        let Err(error) = result else {
            anyhow::bail!("commit over a closed CRL CPU semaphore must fail, not succeed");
        };
        assert!(
            error.to_string().contains("CRL CPU semaphore closed"),
            "error must name the closed semaphore: {error}"
        );
        Ok(())
    }

    /// Build a self-signed CA carrying a CDP extension with one entry per
    /// `cdp_urls` element, so the same CA can sign a large CRL served at
    /// each of them (unlike `build_ca_with_cdp_and_aia`, this returns the
    /// signer, not just the DER, because the end-to-end responsiveness test
    /// below needs to sign a large CRL with it). Each URL gets its OWN
    /// `CrlDistributionPoint` rather than sharing one with multiple URIs, so
    /// every URL is fetched and cached as its own entry instead of being
    /// treated as an RFC 5280 4.2.1.13 mirror of the others.
    fn build_large_crl_ca_with_cdp(
        common_name: &str,
        cdp_urls: &[String],
    ) -> anyhow::Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("CRL CA params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.crl_distribution_points = cdp_urls
            .iter()
            .map(|url| CrlDistributionPoint {
                uris: vec![url.clone()],
            })
            .collect();
        let key = KeyPair::generate().context("CRL CA key")?;
        CertifiedIssuer::self_signed(params, key).context("CRL CA self-signed")
    }

    /// Grow `entry_count` by doubling (bounded by `LARGE_FIXTURE_ENTRIES_MAX`)
    /// until BOTH a single synchronous parse AND a `rebuild_verifier` over
    /// `copies` copies of the signed CRL take at least `target`, returning
    /// the DER together with the two measurements that decided it. The
    /// end-to-end responsiveness test below has two independently mutable
    /// offload points (the per-fetch parse, and the final verifier build
    /// over every fetched entry); each needs its own baseline heavy enough
    /// to make that point's stall observable. Returning these measurements,
    /// instead of having the caller re-measure the same operations
    /// afterward, avoids a second source of timing noise: a cold-cache
    /// first parse and a warm-cache re-parse of the same bytes can
    /// legitimately differ, so a separate re-check could read below
    /// `target` even though this loop's own measurement cleared it.
    fn adaptive_e2e_crl_der(
        ca: &CertifiedIssuer<'static, KeyPair>,
        roots: &Arc<RootCertStore>,
        config: &MtlsConfig,
        copies: usize,
        target: Duration,
    ) -> anyhow::Result<(CertificateRevocationListDer<'static>, Duration, Duration)> {
        let mut entries = LARGE_FIXTURE_ENTRIES;
        loop {
            let der = sign_large_crl(ca, entries)?;

            let parse_start = StdInstant::now();
            let _parsed = parse_crl_metadata(der.as_ref()).context("adaptive e2e fixture parse")?;
            let parse_elapsed = parse_start.elapsed();

            let mut candidate = HashMap::new();
            for index in 0..copies {
                let url = format!("memory://e2e-rebuild-probe-{index}");
                let entry = cached_crl_from_der(der.clone(), &url)?;
                let _previous = candidate.insert(url, entry);
            }
            let rebuild_start = StdInstant::now();
            let _verifier = rebuild_verifier(roots, config, &candidate)
                .context("adaptive e2e fixture rebuild")?;
            let rebuild_elapsed = rebuild_start.elapsed();

            if parse_elapsed >= target && rebuild_elapsed >= target {
                return Ok((der, parse_elapsed, rebuild_elapsed));
            }
            if entries >= LARGE_FIXTURE_ENTRIES_MAX {
                anyhow::bail!(
                    "e2e CRL fixture capped below target: parse_elapsed={parse_elapsed:?}, \
                     rebuild_elapsed={rebuild_elapsed:?}, target={target:?}, \
                     cap_entries={LARGE_FIXTURE_ENTRIES_MAX}; this machine is faster than the \
                     fixture can compensate for, so enlarge LARGE_FIXTURE_ENTRIES_MAX"
                );
            }
            entries = entries.saturating_mul(2).min(LARGE_FIXTURE_ENTRIES_MAX);
        }
    }

    /// Pins that `bootstrap_fetch`'s offloaded CRL parses and initial
    /// verifier build keep a `current_thread` runtime responsive end to end,
    /// through the real network path: trusted loopback origins (the CDPs
    /// named in the configured CA certificate) can now be fetched through
    /// `wiremock`, where before they would have been blocked at the
    /// pre-flight stage.
    ///
    /// Unlike the helper-level progress-count tests above, a plain
    /// scheduling-progress count cannot tell offload from a stall here: the
    /// fetch itself also awaits real socket I/O, during which the counter
    /// keeps advancing regardless of whether the CPU-bound parse and
    /// verifier build are offloaded. This measures the LARGEST GAP between a
    /// 5 ms ticker's ticks instead (`max_ticker_gap_until`): a stall shows up
    /// as one outsized gap even with real I/O happening around it. Both
    /// fixture baselines (a single fetch's parse, and the final rebuild over
    /// every fetched entry) are grown inside the adaptive helper until both
    /// clear 300 ms, and the assertion allows up to half of the smaller one as
    /// observed gap - a margin of at least 150 ms above ordinary scheduler
    /// jitter (observed in the tens of ms on this machine), so routine
    /// jitter cannot trip it, while a real stall at either offload point
    /// (which shows up as a gap close to that point's own baseline) still
    /// fails it.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_fetch_offload_keeps_the_runtime_responsive_end_to_end() -> anyhow::Result<()>
    {
        install_ring_provider();
        let mock = MockServer::start().await;
        let port = mock.address().port();
        let cdp_urls: Vec<String> = (0..=COMMIT_FIXTURE_COUNT)
            .map(|index| format!("http://127.0.0.1:{port}/e2e-large-crl-{index}"))
            .collect();

        let ca = build_large_crl_ca_with_cdp("e2e-large-crl-ca", &cdp_urls)?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).context("add ca root")?;
        let arc_roots = Arc::new(roots);
        let mut config = test_mtls_config()?;

        let (der, fetch_baseline, rebuild_baseline) = adaptive_e2e_crl_der(
            &ca,
            &arc_roots,
            &config,
            cdp_urls.len(),
            Duration::from_millis(300),
        )?;
        let der_bytes = der.as_ref().to_vec();
        config.crl_max_response_bytes = u64::try_from(der_bytes.len())
            .context("large fixture DER length must fit the CRL byte cap type")?
            .saturating_add(1024);
        for url in &cdp_urls {
            let request_path = Url::parse(url).context("parse cdp url")?.path().to_owned();
            Mock::given(method("GET"))
                .and(path(request_path))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(der_bytes.clone()))
                .mount(&mock)
                .await;
        }

        let baseline = fetch_baseline.min(rebuild_baseline);

        let ca_certs = vec![ca.der().clone()];
        let (max_gap, bootstrap_result) = max_ticker_gap_until(async {
            let (set, discover_rx) = bootstrap_fetch(arc_roots, &ca_certs, config)
                .await
                .map_err(anyhow::Error::from)?;
            drop(discover_rx);
            for url in &cdp_urls {
                if !set.__test_cache_contains(url) {
                    anyhow::bail!(
                        "every large CRL must be fetched and cached at bootstrap: missing {url}"
                    );
                }
            }
            Ok(())
        })
        .await;
        bootstrap_result.context("bootstrap_fetch over the large CRLs must succeed")?;

        assert!(
            max_gap.saturating_mul(2) <= baseline,
            "bootstrap's offloaded parse and verifier rebuild must not stall the runtime: \
             max_gap={max_gap:?}, baseline={baseline:?}"
        );
        Ok(())
    }
}
