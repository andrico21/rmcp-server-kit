//! Regression coverage for CRL bootstrap without a preinstalled crypto provider.
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
    use rmcp_server_kit::{auth::MtlsConfig, mtls_revocation::bootstrap_fetch};
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

    /// Pins that CRL bootstrap installs rustls ring before building its client.
    #[tokio::test]
    async fn bootstrap_fetch_installs_crypto_provider_before_client_build() -> anyhow::Result<()> {
        assert!(
            CryptoProvider::get_default().is_none(),
            "test binary must start without a process-default rustls provider"
        );

        let ca_root = build_ca_root()?;
        let mut roots = RootCertStore::empty();
        roots.add(ca_root.clone()).context("add ca root")?;
        let ca_certs = vec![ca_root];

        let result = bootstrap_fetch(Arc::new(roots), &ca_certs, build_mtls_config()?).await;

        assert!(result.is_ok(), "CRL bootstrap should not panic or fail");
        Ok(())
    }
}
