//! Integration tests for CRL-fetch trusted-origin behaviour: a CRL
//! Distribution Point URL whose origin (scheme, lowercased host, effective
//! port) is named in the operator's configured certificates (the mTLS CA
//! bundle or the server certificate chain) skips the private-address
//! block, cloud metadata excepted.
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
    use core::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };
    use std::{io::ErrorKind, net::TcpListener};

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        CrlDistributionPoint, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
        date_time_ymd,
    };
    use rmcp_server_kit::{
        auth::MtlsConfig,
        mtls_revocation::{CrlSet, bootstrap_fetch},
    };
    use rustls::{
        RootCertStore,
        crypto::ring,
        pki_types::{CertificateDer, CertificateRevocationListDer},
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    // helpers

    /// reqwest with `rustls-no-provider` requires a process-wide crypto
    /// provider before any `Client` is built.
    fn install_ring_provider() {
        drop(ring::default_provider().install_default());
    }

    /// Build a self-signed CA carrying a CDP extension naming `cdp_uris`.
    fn build_ca_with_cdp(
        cdp_uris: Vec<String>,
        common_name: &str,
    ) -> anyhow::Result<CertifiedIssuer<'static, KeyPair>> {
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
        params.crl_distribution_points = vec![CrlDistributionPoint { uris: cdp_uris }];
        let key = KeyPair::generate().context("ca key")?;
        CertifiedIssuer::self_signed(params, key).context("ca self-signed")
    }

    /// Build a real (empty) CRL signed by `ca`, as bytes.
    fn build_crl_bytes(
        ca: &CertifiedIssuer<'static, KeyPair>,
        crl_number: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let der: CertificateRevocationListDer<'static> = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2027, 1, 1),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(ca)
        .context("signed crl")?
        .into();
        Ok(der.as_ref().to_vec())
    }

    /// Build the `MtlsConfig` every test in this file starts from.
    fn trusted_origin_test_config(allow_http: bool) -> anyhow::Result<MtlsConfig> {
        serde_json::from_value(serde_json::json!({
            "ca_cert_path": "memory://ca.pem",
            "required": true,
            "default_role": "viewer",
            "crl_enabled": true,
            "crl_deny_on_unavailable": false,
            "crl_allow_http": allow_http,
            "crl_enforce_expiration": true,
            "crl_end_entity_only": false,
            "crl_fetch_timeout": "5s",
            "crl_stale_grace": "24h",
            "crl_max_concurrent_fetches": 4,
            "crl_max_response_bytes": 5_242_880_u64,
            "crl_discovery_rate_per_min": 10_000_u32,
            "crl_max_host_semaphores": 64,
            "crl_max_seen_urls": 64,
            "crl_max_cache_entries": 64,
        }))
        .context("trusted-origin test mtls config")
    }

    /// Bootstrap a `CrlSet` from a single CA certificate.
    async fn bootstrap_with_ca(
        ca: &CertifiedIssuer<'static, KeyPair>,
        config: MtlsConfig,
    ) -> anyhow::Result<Arc<CrlSet>> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).context("add ca root")?;
        let ca_certs: Vec<CertificateDer<'static>> = vec![ca.der().clone()];
        let (set, discover_rx) = bootstrap_fetch(Arc::new(roots), &ca_certs, config)
            .await
            .context("bootstrap fetch")?;
        drop(discover_rx);
        Ok(set)
    }

    /// `localhost` resolves to `::1`, `127.0.0.1` or both, in a
    /// host-specific order, and a fetch tries them in that order.
    ///
    /// Listening on both loopback addresses on one shared port lets a
    /// fetch connect on its first attempt instead of depending on an
    /// IPv6-to-IPv4 connect fallback, and lets a must-not-reach check
    /// observe either family.
    struct LoopbackMock {
        v4: MockServer,
        v6: Option<MockServer>,
    }

    impl LoopbackMock {
        async fn start() -> anyhow::Result<Self> {
            const MAX_ATTEMPTS: u32 = 16;
            for _ in 0..MAX_ATTEMPTS {
                let listener_v4 =
                    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("bind v4 loopback")?;
                let port = listener_v4.local_addr().context("v4 local addr")?.port();
                let v4 = MockServer::builder().listener(listener_v4).start().await;
                match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                    Ok(listener_v6) => {
                        let v6 = MockServer::builder().listener(listener_v6).start().await;
                        return Ok(Self { v4, v6: Some(v6) });
                    }
                    Err(err) if err.kind() == ErrorKind::AddrInUse => {}
                    Err(_) => return Ok(Self { v4, v6: None }),
                }
            }
            anyhow::bail!(
                "failed to bind a shared v4/v6 loopback port after {MAX_ATTEMPTS} attempts"
            )
        }

        fn port(&self) -> u16 {
            self.v4.address().port()
        }

        async fn mount<B>(&self, build: B)
        where
            B: Fn() -> Mock,
        {
            build().mount(&self.v4).await;
            if let Some(v6) = &self.v6 {
                build().mount(v6).await;
            }
        }

        async fn received_paths(&self) -> anyhow::Result<Vec<String>> {
            let mut paths: Vec<String> = self
                .v4
                .received_requests()
                .await
                .context("request recording must be enabled")?
                .iter()
                .map(|request| request.url.path().to_owned())
                .collect();
            if let Some(v6) = &self.v6 {
                paths.extend(
                    v6.received_requests()
                        .await
                        .context("request recording must be enabled")?
                        .iter()
                        .map(|request| request.url.path().to_owned()),
                );
            }
            Ok(paths)
        }
    }

    // (a) trusted IP-literal origin: pre-flight-only path

    /// Pins that a CDP on a trusted IP-literal origin is fetched at
    /// bootstrap. Blocked without the trusted-origin bypass: a bare
    /// `127.0.0.1` CDP is loopback and would otherwise never be fetched.
    #[tokio::test]
    async fn trusted_ip_literal_origin_is_fetched_at_bootstrap() -> anyhow::Result<()> {
        install_ring_provider();
        let mock = MockServer::start().await;
        let port = mock.address().port();
        let cdp_url = format!("http://127.0.0.1:{port}/crl-ip-literal");
        let ca = build_ca_with_cdp(vec![cdp_url.clone()], "trusted-ip-literal-ca")?;
        let crl_bytes = build_crl_bytes(&ca, 1)?;
        Mock::given(method("GET"))
            .and(path("/crl-ip-literal"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes))
            .mount(&mock)
            .await;

        let set = bootstrap_with_ca(&ca, trusted_origin_test_config(true)?).await?;

        assert!(
            set.__test_cache_contains(&cdp_url),
            "a CDP on a trusted IP-literal origin must be fetched and cached at bootstrap"
        );
        Ok(())
    }

    // (b)+(c)+(d) trusted hostname origin: both checks, another path, other port blocked

    /// Pins three things about a trusted hostname origin.
    ///
    /// It passes both the pre-flight check and connect-time resolver
    /// screening at bootstrap; a different path discovered later at the
    /// same origin is also fetched (`__test_trigger_fetch`); and the same
    /// host on a different port - not named in the trusted set - stays
    /// blocked.
    ///
    /// Uses `LoopbackMock` so the fetch connects on its first attempt on
    /// either loopback family, independent of the host's `localhost`
    /// resolver order.
    #[tokio::test]
    async fn trusted_hostname_origin_passes_both_checks_and_other_port_stays_blocked()
    -> anyhow::Result<()> {
        install_ring_provider();
        let mock_trusted = LoopbackMock::start().await?;
        let trusted_port = mock_trusted.port();
        let cdp_url = format!("http://localhost:{trusted_port}/crl-hostname");
        let ca = build_ca_with_cdp(vec![cdp_url.clone()], "trusted-hostname-ca")?;
        let crl_bytes = build_crl_bytes(&ca, 2)?;
        mock_trusted
            .mount(|| {
                Mock::given(method("GET"))
                    .and(path("/crl-hostname"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes.clone()))
            })
            .await;
        // A different path at the SAME trusted origin.
        mock_trusted
            .mount(|| {
                Mock::given(method("GET"))
                    .and(path("/discovered-elsewhere"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes.clone()))
            })
            .await;

        let set = bootstrap_with_ca(&ca, trusted_origin_test_config(true)?).await?;
        assert!(
            set.__test_cache_contains(&cdp_url),
            "a trusted hostname origin must pass both pre-flight and connect-time screening"
        );

        // `__test_trigger_fetch` swallows fetch errors and never commits to
        // the cache, so the trusted path is asserted by the mock's
        // received-request count, not by `__test_cache_contains`.
        let discovered_url = format!("http://localhost:{trusted_port}/discovered-elsewhere");
        set.__test_trigger_fetch(&discovered_url)
            .await
            .context("trigger fetch of a second path at the trusted origin")?;
        let received_discovered = mock_trusted.received_paths().await?;
        assert!(
            received_discovered
                .iter()
                .any(|received_path| received_path == "/discovered-elsewhere"),
            "a different path at the same trusted origin must reach the mock server"
        );

        // A second mock server on its OWN port: same hostname, a port not
        // named in the trusted set, must stay blocked.
        let mock_other_port = LoopbackMock::start().await?;
        let other_port = mock_other_port.port();
        mock_other_port
            .mount(|| {
                Mock::given(method("GET"))
                    .and(path("/crl-other-port"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::<u8>::new()))
            })
            .await;
        let blocked_url = format!("http://localhost:{other_port}/crl-other-port");
        set.__test_trigger_fetch(&blocked_url)
            .await
            .context("trigger fetch of an untrusted port")?;
        let received = mock_other_port.received_paths().await?;
        assert!(
            received.is_empty(),
            "the untrusted port must never receive a request: blocked at the pre-flight stage"
        );
        Ok(())
    }

    // (e) trust does not follow the resolved address

    /// Pins that trust is bound to the exact origin form, not the address.
    ///
    /// A loopback origin named in no configured certificate stays blocked
    /// even when the same port is trusted under the OTHER form
    /// (IP-literal vs hostname).
    ///
    /// Uses `LoopbackMock` so each check is independent of the host's
    /// `localhost` resolver order.
    #[tokio::test]
    async fn loopback_origin_in_untrusted_form_stays_blocked() -> anyhow::Result<()> {
        install_ring_provider();

        // `127.0.0.1` is trusted; `localhost` on the SAME port is not.
        let mock_ip_trusted = LoopbackMock::start().await?;
        let ip_trusted_port = mock_ip_trusted.port();
        mock_ip_trusted
            .mount(|| {
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::<u8>::new()))
            })
            .await;
        let ca_ip = build_ca_with_cdp(
            vec![format!("http://127.0.0.1:{ip_trusted_port}/crl")],
            "ip-trusted-ca",
        )?;
        let set_ip = bootstrap_with_ca(&ca_ip, trusted_origin_test_config(true)?).await?;
        let before_ip_trusted = mock_ip_trusted.received_paths().await?.len();
        let hostname_form_url = format!("http://localhost:{ip_trusted_port}/crl");
        set_ip
            .__test_trigger_fetch(&hostname_form_url)
            .await
            .context("trigger fetch of the hostname form on the ip-trusted port")?;
        let after_ip_trusted = mock_ip_trusted.received_paths().await?.len();
        assert_eq!(
            after_ip_trusted, before_ip_trusted,
            "localhost on the ip-trusted port must never reach the mock (the bootstrap fetch \
             of the trusted 127.0.0.1 origin is the only request expected): trust does not \
             follow the resolved address, it is blocked at the pre-flight stage"
        );

        // The reverse: `localhost` is trusted; `127.0.0.1` on the SAME port
        // is not.
        let mock_host_trusted = LoopbackMock::start().await?;
        let host_trusted_port = mock_host_trusted.port();
        mock_host_trusted
            .mount(|| {
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::<u8>::new()))
            })
            .await;
        let ca_host = build_ca_with_cdp(
            vec![format!("http://localhost:{host_trusted_port}/crl")],
            "host-trusted-ca",
        )?;
        let set_host = bootstrap_with_ca(&ca_host, trusted_origin_test_config(true)?).await?;
        let before_host_trusted = mock_host_trusted.received_paths().await?.len();
        let ip_form_url = format!("http://127.0.0.1:{host_trusted_port}/crl");
        set_host
            .__test_trigger_fetch(&ip_form_url)
            .await
            .context("trigger fetch of the IP-literal form on the host-trusted port")?;
        let after_host_trusted = mock_host_trusted.received_paths().await?.len();
        assert_eq!(
            after_host_trusted, before_host_trusted,
            "127.0.0.1 on the host-trusted port must never reach the mock (the bootstrap \
             fetch of the trusted localhost origin is the only request expected): trust does \
             not follow the resolved address, it is blocked at the pre-flight stage"
        );
        Ok(())
    }

    // (f) cloud metadata stays unbypassable

    /// Pins that a cloud-metadata address named in a configured certificate
    /// stays blocked: cloud metadata is never bypassed, trusted origin or
    /// not.
    #[tokio::test]
    async fn cloud_metadata_origin_named_in_configured_cert_stays_blocked() -> anyhow::Result<()> {
        install_ring_provider();
        let metadata_url = "http://169.254.169.254/latest/meta-data/".to_owned();
        let ca = build_ca_with_cdp(vec![metadata_url.clone()], "metadata-ca")?;
        let mut config = trusted_origin_test_config(true)?;
        config.crl_fetch_timeout = Duration::from_secs(2);

        let set = bootstrap_with_ca(&ca, config).await?;

        assert!(
            !set.__test_cache_contains(&metadata_url),
            "cloud metadata must stay blocked even though its origin is named in the \
             configured CA certificate"
        );
        Ok(())
    }
}
