//! H3 regression coverage for mTLS CRL cache/verifier atomicity and precheck semantics.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![cfg(feature = "test-helpers")]

use std::{sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rmcp_server_kit::{
    auth::MtlsConfig,
    mtls_revocation::{CachedCrl, CrlSet},
};
use rustls::{RootCertStore, pki_types::CertificateRevocationListDer};

fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_ca_root() -> rustls::pki_types::CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, "h3-ca");
    let key = KeyPair::generate().expect("ca key");
    let issuer: CertifiedIssuer<'static, KeyPair> =
        CertifiedIssuer::self_signed(params, key).expect("ca self-signed");
    issuer.der().clone()
}

fn h3_config(deny_on_unavailable: bool, end_entity_only: bool) -> MtlsConfig {
    h3_config_with_retention(deny_on_unavailable, end_entity_only, "24h")
}

fn h3_config_with_retention(
    deny_on_unavailable: bool,
    end_entity_only: bool,
    retry_retention: &str,
) -> MtlsConfig {
    serde_json::from_value(serde_json::json!({
        "ca_cert_path": "memory://ca.pem",
        "required": true,
        "default_role": "viewer",
        "crl_enabled": true,
        "crl_deny_on_unavailable": deny_on_unavailable,
        "crl_allow_http": true,
        "crl_enforce_expiration": true,
        "crl_end_entity_only": end_entity_only,
        "crl_fetch_timeout": "1s",
        "crl_retry_retention": retry_retention,
        "crl_max_concurrent_fetches": 4,
        "crl_max_response_bytes": 5_242_880u64,
        "crl_discovery_rate_per_min": 10_000u32,
        "crl_max_host_semaphores": 1024usize,
        "crl_max_seen_urls": 4096usize,
        "crl_max_cache_entries": 1024usize,
    }))
    .expect("h3 mtls config")
}

fn empty_crl_set(deny_on_unavailable: bool, end_entity_only: bool) -> Arc<CrlSet> {
    empty_crl_set_with_config(h3_config(deny_on_unavailable, end_entity_only))
}

fn empty_crl_set_with_config(config: MtlsConfig) -> Arc<CrlSet> {
    install_ring_provider();
    let mut roots = RootCertStore::empty();
    roots.add(build_ca_root()).expect("add ca root");
    CrlSet::__test_with_prepopulated_crls(Arc::new(roots), config, Vec::new())
        .expect("empty CRL set")
}

#[tokio::test]
async fn cached_urls_not_advertised_when_verifier_rebuild_fails() {
    let set = empty_crl_set(true, false);
    let url = "https://bad-crl.example.test/crl";
    let mut invalid_crl = CachedCrl::__test_synthetic(std::time::SystemTime::now());
    invalid_crl.der = CertificateRevocationListDer::from(vec![0x30, 0x00]);
    invalid_crl.source_url = url.to_owned();

    let result = set.__test_try_insert_cache(url, invalid_crl).await;

    assert!(result.is_err(), "invalid CRL must fail verifier rebuild");
    assert!(
        !set.__test_cache_contains(url),
        "failed rebuild must not commit cache entry"
    );
    assert!(
        !set.__test_cached_url_contains(url),
        "failed rebuild must not advertise cached URL"
    );
    assert!(
        set.__test_note_discovered_urls(&[url.to_owned()]),
        "deny-on-unavailable precheck must still fail closed"
    );
}

#[tokio::test]
async fn end_entity_only_ignores_intermediate_cdp() {
    let set = empty_crl_set(true, true);
    let end_entity_url = "https://ee.example.test/crl";
    let intermediate_url = "https://intermediate.example.test/crl";

    set.__test_insert_cache(
        end_entity_url,
        CachedCrl::__test_synthetic(std::time::SystemTime::now()),
    )
    .await;

    let missing = set.__test_note_discovered_urls_by_cert(
        &[end_entity_url.to_owned()],
        &[intermediate_url.to_owned()],
    );

    assert!(
        !missing,
        "end-entity-only precheck must ignore uncached intermediate CDPs"
    );
}

#[tokio::test]
async fn any_of_n_cdp_sufficient() {
    let set = empty_crl_set(true, false);
    let cached_url = "https://cached.example.test/crl";
    let missing_url = "https://missing.example.test/crl";

    set.__test_insert_cache(
        cached_url,
        CachedCrl::__test_synthetic(std::time::SystemTime::now()),
    )
    .await;

    let missing = set.__test_note_discovered_urls(&[cached_url.to_owned(), missing_url.to_owned()]);

    assert!(
        !missing,
        "one cached CDP must be enough for webpki to make the authoritative decision"
    );
}

#[tokio::test]
async fn retry_retention_alias() {
    let retry_config: MtlsConfig = serde_json::from_value(serde_json::json!({
        "ca_cert_path": "memory://ca.pem",
        "crl_retry_retention": "1h"
    }))
    .expect("preferred retry-retention key must deserialize");
    let legacy_config: MtlsConfig = serde_json::from_value(serde_json::json!({
        "ca_cert_path": "memory://ca.pem",
        "crl_stale_grace": "1h"
    }))
    .expect("legacy stale-grace alias must deserialize");
    assert_eq!(retry_config.crl_stale_grace, Duration::from_secs(3600));
    assert_eq!(legacy_config.crl_stale_grace, Duration::from_secs(3600));

    let set = empty_crl_set_with_config(h3_config_with_retention(false, false, "1h"));
    let url = "https://retention.example.test/crl";
    let now = std::time::SystemTime::now();
    set.__test_insert_cache(url, CachedCrl::__test_synthetic(now))
        .await;
    set.__test_replace_cache_entry_unverified(
        url,
        CachedCrl::__test_stale(now - Duration::from_secs(1800)),
    )
    .await;

    let _ = set.__test_trigger_refresh_url(url).await;
    assert!(
        set.__test_cache_contains(url),
        "failed refresh inside retry-retention window must remain cached for retry"
    );

    set.__test_insert_cache(url, CachedCrl::__test_synthetic(now))
        .await;
    set.__test_replace_cache_entry_unverified(
        url,
        CachedCrl::__test_stale(now - Duration::from_secs(7200)),
    )
    .await;

    let _ = set.__test_trigger_refresh_url(url).await;
    assert!(
        !set.__test_cache_contains(url),
        "failed refresh past retry-retention window must evict the CRL"
    );
}
