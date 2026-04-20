//! F3 — CDP discovery rate-limit gate.
//!
//! These tests exercise the `discovery_limiter` field on `CrlSet`, which
//! caps how many newly-discovered CDP URLs the mTLS verifier may forward
//! to the background fetcher per minute. The limiter is **global** in
//! 1.2.1 (per-IP scoping requires a public-API change on the verifier
//! hook to plumb the peer `SocketAddr` through, deferred to a future
//! release) and is used in the synchronous `note_discovered_urls` path
//! so the verifier never blocks the rustls handshake.
//!
//! ## Coverage
//!
//! | # | Scenario                                                                  | Verifies                                                                  |
//! |---|---------------------------------------------------------------------------|---------------------------------------------------------------------------|
//! | 1 | Excess submissions are dropped, not queued                                | `__test_check_discovery_rate` returns N accepted + remainder dropped       |
//! | 2 | First N URLs in a burst all pass (limiter starts full)                    | First-batch acceptance count equals configured per-minute quota            |
//! | 3 | `note_discovered_urls` deduplicates URLs marked seen in a previous batch  | Re-submitting the same URLs does not consume additional limiter capacity   |
//! | 4 | A URL dropped by the limiter is NOT marked seen (B2 regression test)      | Rate-limited URLs remain retriable on the next handshake (no black-hole)   |
//!
//! Tests 3 and 4 use [`CrlSet::__test_with_kept_receiver`] (instead of
//! `__test_with_prepopulated_crls` which drops the discover-channel
//! receiver) so the production commit-to-`seen_urls` path -- which only
//! marks a URL seen after BOTH the limiter admits it AND the channel
//! send succeeds -- actually executes. With the receiver dropped, the
//! send side would always fail and `seen_urls` would never be
//! populated, masking both real bugs and real fixes.
//!
//! Component-level testing only: end-to-end exercise via the verifier
//! requires a full mTLS handshake, which is already covered in `e2e.rs`.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rmcp_server_kit::{auth::MtlsConfig, mtls_revocation::CrlSet};
use rustls::RootCertStore;
use tokio::sync::mpsc::UnboundedReceiver;

fn build_ca_root() -> rustls::pki_types::CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "ratelimit-ca");
    let key = KeyPair::generate().expect("ca key");
    let issuer: CertifiedIssuer<'static, KeyPair> =
        CertifiedIssuer::self_signed(params, key).expect("ca self-signed");
    issuer.der().clone()
}

fn build_mtls_config(rate_per_min: u32) -> MtlsConfig {
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
        "crl_max_concurrent_fetches": 4,
        "crl_max_response_bytes": 5_242_880,
        "crl_discovery_rate_per_min": rate_per_min,
    }))
    .expect("verifier mtls config")
}

fn install_ring_provider() {
    // CrlSet::new builds a reqwest client whose rustls is built with
    // rustls-no-provider; install ring once for tests.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn empty_crl_set(rate_per_min: u32) -> Arc<CrlSet> {
    install_ring_provider();
    let mut roots = RootCertStore::empty();
    roots.add(build_ca_root()).expect("add ca root");
    let roots = Arc::new(roots);
    CrlSet::__test_with_prepopulated_crls(roots, build_mtls_config(rate_per_min), vec![])
        .expect("crl set with empty CRLs")
}

/// Variant that returns the discover-channel receiver alongside the
/// `CrlSet` so that channel sends actually succeed (and therefore the
/// production commit-to-`seen_urls` path executes). The receiver must
/// stay alive in the test scope; drain or just hold it.
fn empty_crl_set_with_receiver(rate_per_min: u32) -> (Arc<CrlSet>, UnboundedReceiver<String>) {
    install_ring_provider();
    let mut roots = RootCertStore::empty();
    roots.add(build_ca_root()).expect("add ca root");
    let roots = Arc::new(roots);
    CrlSet::__test_with_kept_receiver(roots, build_mtls_config(rate_per_min), vec![])
        .expect("crl set with empty CRLs and kept receiver")
}

fn urls(prefix: &str, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("http://crl-{prefix}.example.test/{i}.crl"))
        .collect()
}

// -- Q1: rate limiter accepts N then drops remainder -------------------------

#[test]
fn discovery_rate_limit_drops_excess() {
    // Configure a rate of 5/minute. Submit 12 distinct URLs in one burst.
    // governor's leaky-bucket starts at full capacity = 5, so the first 5
    // pass and the remaining 7 are dropped.
    let crl_set = empty_crl_set(5);
    let urls = urls("excess", 12);
    let (accepted, dropped) = crl_set.__test_check_discovery_rate(&urls);
    assert_eq!(accepted, 5, "first 5 must pass at rate=5/min");
    assert_eq!(dropped, 7, "remaining 7 must be rejected by limiter");
}

// -- Q2: first burst within quota all pass -----------------------------------

#[test]
fn discovery_rate_limit_allows_first_burst_within_quota() {
    // At rate=10/min, the first 10 URLs in a single burst all pass.
    let crl_set = empty_crl_set(10);
    let urls = urls("burst", 10);
    let (accepted, dropped) = crl_set.__test_check_discovery_rate(&urls);
    assert_eq!(accepted, 10);
    assert_eq!(dropped, 0);
}

// -- Q3: note_discovered_urls dedup runs before the limiter ----------------
//
// In the B2-fixed implementation, `note_discovered_urls` snapshots
// `seen_urls` read-only first to filter out already-known URLs (cheap
// dedup that never consumes limiter capacity), then admits the
// remaining URLs through the limiter. A URL is committed to `seen_urls`
// ONLY after the limiter accepts it AND the discovery channel send
// succeeds. To observe the commit (so the second batch can actually be
// dedup'd) we must keep the receiver alive -- otherwise channel sends
// fail, no URL is ever marked seen, and re-submitting the same batch
// would consume limiter capacity a second time, masking the bug.

#[test]
fn note_discovered_urls_dedup_does_not_consume_limiter_quota() {
    // Rate = 10/min. First batch consumes 3 of 10, leaving 7 available.
    // Second batch (same 3 URLs) must consume 0 if dedup works; if dedup
    // is broken it would consume 3 more, leaving only 4. We then probe
    // remaining quota with 7 fresh URLs: dedup-correct => all 7
    // accepted; dedup-broken => only 4 accepted, 3 dropped. This
    // distinguishes the two outcomes (unlike a saturated-limiter setup
    // where both outcomes drop everything).
    let (crl_set, mut rx) = empty_crl_set_with_receiver(10);
    let batch = urls("dedup", 3);

    // First call: 3 distinct URLs admitted and committed to `seen_urls`.
    let _ = crl_set.__test_note_discovered_urls(&batch);
    while rx.try_recv().is_ok() {}

    // Sanity check: the first batch is now in `seen_urls`. If this
    // fails, the test infrastructure (not the dedup logic under test)
    // is broken and the rest of the assertions below would be
    // meaningless.
    for url in &batch {
        assert!(
            crl_set.__test_is_seen(url),
            "first-batch URL {url} must be marked seen after successful limiter+send"
        );
    }

    // Second call: SAME 3 URLs. Dedup must drop them all *before*
    // hitting the limiter, so no quota is consumed.
    let _ = crl_set.__test_note_discovered_urls(&batch);
    while rx.try_recv().is_ok() {}

    // Probe remaining quota with 7 fresh URLs. With dedup working:
    // limiter still has 10 - 3 = 7 capacity, so all 7 fresh URLs are
    // accepted. With dedup broken: the second `note_discovered_urls`
    // call would have consumed 3 more, leaving only 4, so 3 of the
    // fresh URLs would be dropped.
    let probe = urls("dedup-probe", 7);
    let (accepted, dropped) = crl_set.__test_check_discovery_rate(&probe);
    assert_eq!(
        accepted, 7,
        "dedup must leave 7 quota free; got accepted={accepted} dropped={dropped} \
         -- non-7 acceptance means second-batch dedup wrongly consumed limiter quota"
    );
    assert_eq!(
        dropped, 0,
        "all 7 fresh probe URLs must fit in remaining quota"
    );
}

// -- Q4: B2 regression -- rate-limited URLs are NOT marked seen --------------

#[test]
fn rate_limited_url_remains_retriable_on_next_handshake() {
    // B2 regression: prior to the fix, `note_discovered_urls` promoted
    // every input URL to `seen_urls` BEFORE the rate-limiter check. A
    // URL that lost the limiter race was therefore black-holed forever:
    // every subsequent handshake observed it as "already known" and
    // skipped the limiter, while the background fetcher had never
    // received it. Combined with `crl_deny_on_unavailable=true` this
    // produced permanent handshake failure for that distribution point.
    //
    // The fix snapshots `seen_urls` read-only, then commits a URL to
    // `seen_urls` only after BOTH (a) the limiter admits it AND (b)
    // the discovery channel send succeeds. URLs dropped by the limiter
    // remain absent from `seen_urls` and are reconsidered on the next
    // handshake.
    //
    // We keep the receiver alive so the saturating URL is committed
    // (proving the success path works), then verify the rate-limited
    // target URL is *not* committed (proving the B2 fix).
    let (crl_set, mut rx) = empty_crl_set_with_receiver(1); // 1/min capacity
    let saturate = urls("saturate-b2", 1);
    let target = urls("target-b2", 1);
    let saturate_url = saturate.first().expect("saturate batch has 1 url");
    let target_url = target.first().expect("target batch has 1 url");

    // Saturate the limiter (this URL must be admitted and committed).
    let _ = crl_set.__test_note_discovered_urls(&saturate);
    while rx.try_recv().is_ok() {}
    assert!(
        crl_set.__test_is_seen(saturate_url),
        "first-batch URL must be marked seen after successful limiter+send (test infra check)"
    );

    // Target URL: limiter exhausted -- governor must drop it. Under
    // B2 the URL must NOT be marked seen so the next handshake gets
    // a fresh chance once the limiter refills.
    let _ = crl_set.__test_note_discovered_urls(&target);
    while rx.try_recv().is_ok() {}
    assert!(
        !crl_set.__test_is_seen(target_url),
        "B2 regression: rate-limited URL must NOT be marked seen \
         (otherwise it would be permanently black-holed by dedup)"
    );
}
