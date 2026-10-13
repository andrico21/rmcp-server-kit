//! Regression coverage for building a CRL set directly, without bootstrap, when no rustls crypto provider is installed.
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rmcp_server_kit::{auth::MtlsConfig, mtls_revocation::CrlSet};
    use rustls::{RootCertStore, crypto::CryptoProvider, pki_types::CertificateDer};

    /// Build a self-signed CA root certificate without CRL distribution points.
    fn build_ca_root() -> anyhow::Result<CertificateDer<'static>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "crypto-provider-ca");
        let key = KeyPair::generate().context("ca key")?;
        let issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(params, key).context("ca self-signed")?;
        Ok(issuer.der().clone())
    }

    /// Build an `MtlsConfig` for CRL bootstrap without network fetches.
    fn build_mtls_config() -> anyhow::Result<MtlsConfig> {
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
            "crl_discovery_rate_per_min": 60,
        }))
        .context("verifier mtls config")
    }

    /// Pins that the direct `CrlSet` constructor installs rustls ring before building its HTTP client.
    #[test]
    fn crl_set_constructor_installs_crypto_provider_before_client_build() -> anyhow::Result<()> {
        let ca_root = build_ca_root()?;
        let mut roots = RootCertStore::empty();
        roots.add(ca_root).context("add ca root")?;

        assert!(
            CryptoProvider::get_default().is_none(),
            "test binary must start without a process-default rustls provider"
        );

        #[expect(
            deprecated,
            reason = "deliberate: tests/unit/crl_crypto_provider_crl_set.rs::crl_set_constructor_installs_crypto_provider_before_client_build exercises the deprecated test-only constructor, the only public path to CrlSet::new without bootstrap"
        )]
        let result = CrlSet::__test_with_prepopulated_crls(
            Arc::new(roots),
            build_mtls_config()?,
            Vec::new(),
        );

        assert!(result.is_ok(), "CrlSet::new should not panic or fail");
        assert!(
            CryptoProvider::get_default().is_some(),
            "CrlSet::new must leave a process-default provider installed"
        );
        Ok(())
    }
}
