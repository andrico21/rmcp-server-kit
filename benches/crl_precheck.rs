//! Cost of the synchronous fail-closed CRL precheck on the mTLS handshake path.
//!
//! # Why this bench exists
//!
//! Sealing the `CrlSet` cache invariant means every handshake re-checks that
//! the cached CRLs its certificate points at still match what was committed,
//! so revocation coverage can be *proved* rather than trusted. That check runs
//! on the **unauthenticated** TLS path, which makes its cost a DoS surface: a
//! peer presenting a certificate that lists many already-cached CDP URLs
//! amplifies one handshake into however much work each URL costs.
//!
//! An earlier revision proved this concretely. Comparing a SHA-256 digest of
//! the DER measured **56.3 ms p95 per relevant cached CRL** at the 5 MiB
//! `crl_max_response_bytes` default (900.9 ms for a single handshake at 16
//! cached URLs), scaling linearly in both CRL bytes and the attacker-chosen
//! URL count. That failed its abort criterion and was replaced by a
//! constant-cost identity comparison that never rescans the DER.
//!
//! # What this bench now guards
//!
//! The threshold gate is retired: at O(1) it is trivially met and therefore
//! meaningless. The gate is now **scale invariance**, which is what actually
//! detects a full-DER scan being reintroduced:
//!
//! - **Primary — CRL-size invariance.** At a fixed 16 relevant URLs, p95 for
//!   5 MiB CRLs must be within 1 ms of p95 for 64 KiB CRLs. Any per-byte work
//!   on the handshake path blows this by orders of magnitude: the digest
//!   implementation measured 6.607 ms vs 900.9 ms for exactly this pair.
//! - **Secondary — URL-count slope.** Cost may scale with the relevant-URL
//!   count, which is bounded by `MAX_RELEVANT_CDP_URLS_PER_HANDSHAKE`, but
//!   must not scale with CRL bytes.
//!
//! `hook_latency` and `rbac_redaction` do not execute a single line of this
//! path and must never be cited as coverage for it.
//!
//! Run with `cargo bench --bench crl_precheck --features test-helpers`.

#![allow(
    deprecated,
    reason = "benchmarks the deprecated ungated test constructors and the out-of-band cache write path on purpose"
)]
#![allow(
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    missing_docs
)]

use std::{
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use criterion::{Criterion, criterion_group, criterion_main};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    date_time_ymd,
};
use rmcp_server_kit::{
    auth::MtlsConfig,
    mtls_revocation::{CachedCrl, CrlSet},
};
use rustls::{RootCertStore, pki_types::CertificateRevocationListDer};

/// CRL sizes swept, in bytes.
const SIZES: [(&str, usize); 3] = [
    ("64KiB", 64 * 1024),
    ("1MiB", 1024 * 1024),
    ("5MiB", 5 * 1024 * 1024),
];

/// Relevant-cached-URL counts swept. The worst case is an attacker-controlled
/// certificate listing many CDP URLs that are all already cached.
const URL_COUNTS: [usize; 4] = [1, 4, 16, 64];

/// A 5 MiB CRL replicated 64 times would allocate ~320 MiB twice over (cache
/// plus the verifier's own copies) and spend minutes in webpki parsing during
/// setup, which measures fixture construction rather than the precheck. The
/// invariance gate only needs `INVARIANCE_URL_COUNT`.
const MAX_URLS_AT_5MIB: usize = 16;

/// Most the 5 MiB p95 may exceed the 64 KiB p95 at the same URL count before
/// the precheck is considered to be scanning the DER again.
const MAX_SIZE_SCALING_DELTA: Duration = Duration::from_millis(1);

/// URL count at which the size-invariance comparison is made.
const INVARIANCE_URL_COUNT: usize = 16;

fn build_ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "crl-precheck-bench-ca");
    let key = KeyPair::generate().expect("ca key");
    CertifiedIssuer::self_signed(params, key).expect("ca self-signed")
}

/// Build a signed CRL of roughly `target_bytes`, by revoking enough serials.
fn build_crl(ca: &CertifiedIssuer<'static, KeyPair>, target_bytes: usize) -> Vec<u8> {
    // Each `RevokedCertParams` costs on the order of 40 DER bytes once encoded
    // with its revocation time and reason; converge by measuring one small CRL
    // and scaling, then trimming, so the sweep sizes are honest rather than
    // nominal.
    let mut count = (target_bytes / 40).max(1);
    let mut der = sign_crl(ca, count);
    for _ in 0..8 {
        if der.len() >= target_bytes {
            break;
        }
        let grown = count
            .saturating_mul(target_bytes)
            .checked_div(der.len().max(1))
            .unwrap_or(count)
            .max(count + 1);
        count = grown;
        der = sign_crl(ca, count);
    }
    der
}

fn sign_crl(ca: &CertifiedIssuer<'static, KeyPair>, revoked: usize) -> Vec<u8> {
    let revoked_certs = (0..revoked)
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(u64::try_from(serial).unwrap_or(u64::MAX)),
            revocation_time: date_time_ymd(2026, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect::<Vec<_>>();

    let der: CertificateRevocationListDer<'static> = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2027, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(ca)
    .expect("signed crl")
    .into();
    der.as_ref().to_vec()
}

fn bench_config(deny_on_unavailable: bool) -> MtlsConfig {
    let mut config: MtlsConfig = serde_json::from_value(serde_json::json!({
        "ca_cert_path": "memory://ca.pem",
        "required": true,
        "default_role": "viewer",
        "crl_enabled": true,
        "crl_allow_http": true,
        "crl_enforce_expiration": false,
        "crl_end_entity_only": false,
        "crl_fetch_timeout": "30s",
        "crl_stale_grace": "24h",
        "crl_max_concurrent_fetches": 1,
        "crl_max_response_bytes": 5_242_880,
        "crl_discovery_rate_per_min": 1_000_000,
        "crl_max_host_semaphores": 16,
        "crl_max_seen_urls": 4096,
        "crl_max_cache_entries": 4096,
    }))
    .expect("bench mtls config");
    config.crl_deny_on_unavailable = deny_on_unavailable;
    config
}

struct Scenario {
    set: Arc<CrlSet>,
    urls: Vec<String>,
}

fn scenario(
    ca: &CertifiedIssuer<'static, KeyPair>,
    crl_der: &[u8],
    url_count: usize,
    deny_on_unavailable: bool,
) -> Scenario {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add ca root");

    let crls = (0..url_count)
        .map(|_| CertificateRevocationListDer::from(crl_der.to_vec()))
        .collect::<Vec<_>>();
    let set = CrlSet::__test_with_prepopulated_crls(
        Arc::new(roots),
        bench_config(deny_on_unavailable),
        crls,
    )
    .expect("prepopulated crl set");

    let urls = (0..url_count)
        .map(|index| format!("memory://crl/{index}"))
        .collect::<Vec<_>>();

    // Settle discovery dedup so the measured calls exercise only the precheck.
    let _ = set.__test_note_discovered_urls_by_cert(&urls, &[]);
    Scenario { set, urls }
}

fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    let index = samples.len().saturating_mul(95).saturating_div(100);
    samples
        .get(index.min(samples.len().saturating_sub(1)))
        .copied()
        .unwrap_or_default()
}

fn measure<F: FnMut()>(iterations: usize, mut body: F) -> Duration {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        body();
        samples.push(start.elapsed());
    }
    p95(samples)
}

/// Print the p95 table the plan requires recorded, and evaluate the
/// scale-invariance gate explicitly.
fn report_p95(ca: &CertifiedIssuer<'static, KeyPair>) {
    println!("\n=== crl_precheck p95 (per handshake) ===");
    println!(
        "{:<8} {:>6} {:>16} {:>16} {:>16}",
        "size", "urls", "precheck p95", "fail-open p95", "audit cost p95"
    );

    let mut invariance: Vec<(usize, Duration)> = Vec::new();

    for (size_label, target) in SIZES {
        let crl = build_crl(ca, target);

        for url_count in URL_COUNTS {
            if target >= 5 * 1024 * 1024 && url_count > MAX_URLS_AT_5MIB {
                continue;
            }
            let audited = scenario(ca, &crl, url_count, true);
            let fail_open = scenario(ca, &crl, url_count, false);

            let audited_p95 = measure(200, || {
                black_box(
                    audited
                        .set
                        .__test_note_discovered_urls_by_cert(black_box(&audited.urls), &[]),
                );
            });
            let fail_open_p95 = measure(200, || {
                black_box(
                    fail_open
                        .set
                        .__test_note_discovered_urls_by_cert(black_box(&fail_open.urls), &[]),
                );
            });
            let audit_cost = audited_p95.saturating_sub(fail_open_p95);

            println!(
                "{size_label:<8} {url_count:>6} {audited_p95:>16?} {fail_open_p95:>16?} {audit_cost:>16?}"
            );

            if url_count == INVARIANCE_URL_COUNT {
                invariance.push((target, audited_p95));
            }
        }
    }

    let smallest = invariance.iter().min_by_key(|(target, _)| *target).copied();
    let largest = invariance.iter().max_by_key(|(target, _)| *target).copied();

    match (smallest, largest) {
        (Some((small_bytes, small_p95)), Some((large_bytes, large_p95))) => {
            let delta = large_p95.saturating_sub(small_p95);
            println!(
                "\nsize-invariance gate at {INVARIANCE_URL_COUNT} relevant cached URLs: \
                 {small_bytes} B -> {small_p95:?}, {large_bytes} B -> {large_p95:?}, \
                 delta {delta:?} (budget {MAX_SIZE_SCALING_DELTA:?})"
            );
            if delta > MAX_SIZE_SCALING_DELTA {
                println!(
                    "FAIL: handshake cost scales with CRL size. Something on the precheck path \
                     is scanning the DER again; that is the 56 ms/CRL amplifier this design \
                     removed. Do not ship."
                );
            } else {
                println!("PASS: handshake cost is independent of CRL size.");
            }
        }
        _ => println!("\nFAIL: invariance gate collected no samples; the sweep is misconfigured."),
    }
    println!();
}

fn bench_precheck(c: &mut Criterion) {
    let ca = build_ca();
    report_p95(&ca);

    let mut group = c.benchmark_group("crl_precheck");
    for (size_label, target) in SIZES {
        let crl = build_crl(&ca, target);
        for url_count in URL_COUNTS {
            if target >= 5 * 1024 * 1024 && url_count > MAX_URLS_AT_5MIB {
                continue;
            }
            let hot = scenario(&ca, &crl, url_count, true);
            group.bench_function(format!("{size_label}/{url_count}urls/clean"), |b| {
                b.iter(|| {
                    black_box(
                        hot.set
                            .__test_note_discovered_urls_by_cert(black_box(&hot.urls), &[]),
                    );
                });
            });
        }
    }
    group.finish();
}

/// The out-of-band-mutation paths short-circuit on the first mismatched URL,
/// so they are measured separately to confirm denial is not *more* expensive
/// than admission, which would make denial itself the amplifier.
fn bench_tampered(c: &mut Criterion) {
    let ca = build_ca();
    let crl = build_crl(&ca, 1024 * 1024);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");

    let replaced = scenario(&ca, &crl, 16, true);
    runtime.block_on(async {
        let mut cache = replaced.set.cache.write().await;
        if let Some(entry) = cache.get_mut("memory://crl/0") {
            entry.der = CertificateRevocationListDer::from(vec![0x30, 0x00]);
        }
        drop(cache);
    });

    let removed = scenario(&ca, &crl, 16, true);
    runtime.block_on(async {
        let mut cache = removed.set.cache.write().await;
        cache.remove("memory://crl/0");
        drop(cache);
    });

    let mut group = c.benchmark_group("crl_precheck_mutated");
    group.bench_function("1MiB/16urls/replaced", |b| {
        b.iter(|| {
            black_box(
                replaced
                    .set
                    .__test_note_discovered_urls_by_cert(black_box(&replaced.urls), &[]),
            );
        });
    });
    group.bench_function("1MiB/16urls/removed", |b| {
        b.iter(|| {
            black_box(
                removed
                    .set
                    .__test_note_discovered_urls_by_cert(black_box(&removed.urls), &[]),
            );
        });
    });
    group.finish();
}

/// Under a concurrent refresh loop the precheck's non-blocking `try_read` can
/// miss the cache lock. This variant exists so that cost — and any denial
/// behaviour it triggers — is visible rather than assumed.
fn bench_writer_contention(c: &mut Criterion) {
    let ca = build_ca();
    let crl = build_crl(&ca, 64 * 1024);
    let hot = scenario(&ca, &crl, 16, true);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_set = Arc::clone(&hot.set);
    let writer_stop = Arc::clone(&stop);
    let writer = runtime.spawn(async move {
        let mut round = 0u64;
        while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
            // A real commit, so the precheck's `try_read` genuinely contends
            // with the publication write lock. `force_refresh` would only
            // attempt (and fail) HTTP fetches for these `memory://` URLs and
            // commit nothing, measuring no contention at all.
            writer_set
                .__test_insert_cache(
                    &format!("memory://churn/{round}"),
                    CachedCrl::__test_synthetic(SystemTime::now()),
                )
                .await;
            round = round.wrapping_add(1);
            tokio::task::yield_now().await;
        }
    });

    c.bench_function("crl_precheck/64KiB/16urls/writer_contention", |b| {
        b.iter(|| {
            black_box(
                hot.set
                    .__test_note_discovered_urls_by_cert(black_box(&hot.urls), &[]),
            );
        });
    });

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = runtime.block_on(writer);
}

criterion_group!(
    benches,
    bench_precheck,
    bench_tampered,
    bench_writer_contention
);
criterion_main!(benches);
