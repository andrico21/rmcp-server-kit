//! H3 regression coverage for mTLS CRL cache/verifier atomicity and precheck semantics.
#![cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#![cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::time::Duration;
    use std::time::SystemTime;

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rmcp_server_kit::{
        auth::MtlsConfig,
        mtls_revocation::{CachedCrl, CrlSet},
    };
    use rustls::{
        RootCertStore,
        crypto::ring,
        pki_types::{CertificateDer, CertificateRevocationListDer},
    };

    /// Install the ring crypto provider once per test process.
    fn install_ring_provider() {
        drop(ring::default_provider().install_default());
    }

    /// Build a self-signed CA root certificate for the test `CrlSet`s.
    fn build_ca_root() -> anyhow::Result<CertificateDer<'static>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(DnType::CommonName, "h3-ca");
        let key = KeyPair::generate().context("ca key")?;
        let issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(params, key).context("ca self-signed")?;
        Ok(issuer.der().clone())
    }

    /// Build an `MtlsConfig` with the given precheck knobs.
    fn h3_config(deny_on_unavailable: bool, end_entity_only: bool) -> anyhow::Result<MtlsConfig> {
        h3_config_with_retention(deny_on_unavailable, end_entity_only, "24h")
    }

    /// Build an `MtlsConfig` with an explicit retry-retention window.
    fn h3_config_with_retention(
        deny_on_unavailable: bool,
        end_entity_only: bool,
        retry_retention: &str,
    ) -> anyhow::Result<MtlsConfig> {
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
            "crl_max_response_bytes": 5_242_880_u64,
            "crl_discovery_rate_per_min": 10_000_u32,
            "crl_max_host_semaphores": 1024_usize,
            "crl_max_seen_urls": 4096_usize,
            "crl_max_cache_entries": 1024_usize,
        }))
        .context("h3 mtls config")
    }

    /// Build an empty `CrlSet` with the given precheck flags.
    fn empty_crl_set(
        deny_on_unavailable: bool,
        end_entity_only: bool,
    ) -> anyhow::Result<Arc<CrlSet>> {
        empty_crl_set_with_config(h3_config(deny_on_unavailable, end_entity_only)?)
    }

    /// Build an empty `CrlSet` from an explicit config.
    fn empty_crl_set_with_config(config: MtlsConfig) -> anyhow::Result<Arc<CrlSet>> {
        install_ring_provider();
        let mut roots = RootCertStore::empty();
        roots.add(build_ca_root()?).context("add ca root")?;
        #[expect(
            deprecated,
            reason = "deliberate: mtls_revocation::CrlSet::__test_with_prepopulated_crls — the deprecated test-only constructor is the only prepopulated-CrlSet entry point until 4.0"
        )]
        let set = CrlSet::__test_with_prepopulated_crls(Arc::new(roots), config, Vec::new())
            .context("empty CRL set")?;
        Ok(set)
    }

    /// Pins that a CRL failing the verifier rebuild is neither cached nor advertised.
    #[tokio::test]
    async fn cached_urls_not_advertised_when_verifier_rebuild_fails() -> anyhow::Result<()> {
        let set = empty_crl_set(true, false)?;
        let url = "https://bad-crl.example.test/crl";
        let mut invalid_crl = CachedCrl::__test_synthetic(SystemTime::now());
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
        Ok(())
    }

    /// Pins that end-entity-only mode ignores uncached intermediate CDPs.
    #[tokio::test]
    async fn end_entity_only_ignores_intermediate_cdp() -> anyhow::Result<()> {
        let set = empty_crl_set(true, true)?;
        let end_entity_url = "https://ee.example.test/crl";
        let intermediate_url = "https://intermediate.example.test/crl";

        set.__test_insert_cache(
            end_entity_url,
            CachedCrl::__test_synthetic(SystemTime::now()),
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
        Ok(())
    }

    /// Pins that one cached CDP is enough for the precheck to pass.
    #[tokio::test]
    async fn any_of_n_cdp_sufficient() -> anyhow::Result<()> {
        let set = empty_crl_set(true, false)?;
        let cached_url = "https://cached.example.test/crl";
        let missing_url = "https://missing.example.test/crl";

        set.__test_insert_cache(cached_url, CachedCrl::__test_synthetic(SystemTime::now()))
            .await;

        let missing =
            set.__test_note_discovered_urls(&[cached_url.to_owned(), missing_url.to_owned()]);

        assert!(
            !missing,
            "one cached CDP must be enough for webpki to make the authoritative decision"
        );
        Ok(())
    }

    /// Pins that `crl_retry_retention` and its legacy alias both set the grace window.
    #[tokio::test]
    async fn retry_retention_alias() -> anyhow::Result<()> {
        let retry_config: MtlsConfig = serde_json::from_value(serde_json::json!({
            "ca_cert_path": "memory://ca.pem",
            "crl_retry_retention": "1h"
        }))
        .context("preferred retry-retention key must deserialize")?;
        let legacy_config: MtlsConfig = serde_json::from_value(serde_json::json!({
            "ca_cert_path": "memory://ca.pem",
            "crl_stale_grace": "1h"
        }))
        .context("legacy stale-grace alias must deserialize")?;
        assert_eq!(retry_config.crl_stale_grace, Duration::from_hours(1));
        assert_eq!(legacy_config.crl_stale_grace, Duration::from_hours(1));

        let set = empty_crl_set_with_config(h3_config_with_retention(false, false, "1h")?)?;
        let url = "https://retention.example.test/crl";
        let now = SystemTime::now();
        set.__test_insert_cache(url, CachedCrl::__test_synthetic(now))
            .await;
        set.__test_replace_cache_entry_unverified(
            url,
            CachedCrl::__test_stale(now - Duration::from_mins(30)),
        )
        .await;

        drop(set.__test_trigger_refresh_url(url).await);
        assert!(
            set.__test_cache_contains(url),
            "failed refresh inside retry-retention window must remain cached for retry"
        );

        set.__test_insert_cache(url, CachedCrl::__test_synthetic(now))
            .await;
        set.__test_replace_cache_entry_unverified(
            url,
            CachedCrl::__test_stale(now - Duration::from_hours(2)),
        )
        .await;

        drop(set.__test_trigger_refresh_url(url).await);
        assert!(
            !set.__test_cache_contains(url),
            "failed refresh past retry-retention window must evict the CRL"
        );
        Ok(())
    }
}
