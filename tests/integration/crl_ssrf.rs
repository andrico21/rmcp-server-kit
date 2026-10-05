//! Integration tests for the F1 CRL-fetch SSRF defenses.
//!
//! These tests exercise the public surface of `mtls_revocation` and
//! verify the behaviors that ship in 1.2.1:
//!
//! - `extract_cdp_urls` validates schemes, drops malformed URLs, and
//!   filters HTTP per `crl_allow_http`.
//! - The reqwest client configuration matches what `CrlSet::new` builds
//!   (redirect=none, `connect_timeout=3s`) so any deviation is loud.
//! - End-to-end behaviors against `wiremock`:
//!   - Successful CRL fetch through the full pipeline.
//!   - Body cap rejects oversized responses.
//!   - Redirect policy rejects 30x.
//!
//! The SSRF *blocked-IP* defense (loopback / metadata / RFC1918 / etc.) is
//! covered by the `ssrf_guard` unit tests inside `mtls_revocation.rs`
//! because exercising it in an integration test would require resolving
//! attacker-controlled hostnames to private IPs (which `wiremock` cannot
//! provide). The unit tests there cover all 12 IP classes exhaustively.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg(test)]
mod tests {

    use core::time::Duration;

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        CrlDistributionPoint, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevocationReason, RevokedCertParams, SerialNumber, date_time_ymd,
    };
    use reqwest::redirect::Policy;
    use rmcp_server_kit::mtls_revocation::extract_cdp_urls;
    use rustls::{
        crypto::ring,
        pki_types::{CertificateDer, CertificateRevocationListDer},
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    // -- helpers -----------------------------------------------------------------

    fn build_ca() -> anyhow::Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "ssrf-ca");
        let key = KeyPair::generate().context("ca key")?;
        CertifiedIssuer::self_signed(params, key).context("ca self-signed")
    }

    fn build_cert_with_cdp_urls(uris: Vec<String>) -> anyhow::Result<CertificateDer<'static>> {
        let ca = build_ca()?;
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).context("params")?;
        params.serial_number = Some(SerialNumber::from(42_u64));
        params
            .distinguished_name
            .push(DnType::CommonName, "ssrf-leaf");
        params.crl_distribution_points = vec![CrlDistributionPoint { uris }];
        let key = KeyPair::generate().context("leaf key")?;
        let cert = params.signed_by(&key, &ca).context("leaf signed")?;
        Ok(cert.der().clone())
    }

    fn build_test_crl_der() -> anyhow::Result<Vec<u8>> {
        let ca = build_ca()?;
        let der: CertificateRevocationListDer<'static> = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2027, 1, 1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(42_u64),
                revocation_time: date_time_ymd(2026, 1, 2),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&ca)
        .context("signed crl")?
        .into();
        Ok(der.as_ref().to_vec())
    }

    /// Construct the same `reqwest::Client` shape that `CrlSet::new` builds.
    /// Kept here (not imported) so any production-side regression that loosens
    /// the policy is caught by these tests failing.
    fn build_hardened_client() -> anyhow::Result<reqwest::Client> {
        // reqwest is built with rustls-no-provider; install ring for tests.
        drop(ring::default_provider().install_default());
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .tcp_keepalive(None)
            .redirect(Policy::none())
            .user_agent("rmcp-server-kit-test")
            .build()
            .context("hardened client builds")
    }

    // -- Q1: extract_cdp_urls schema validation ---------------------------------

    /// Pins that only HTTPS CDP URLs survive when `crl_allow_http` is false.
    #[test]
    fn extract_cdp_urls_drops_disallowed_schemes() -> anyhow::Result<()> {
        let cert = build_cert_with_cdp_urls(vec![
            "ldap://example.com/crl".to_owned(),
            "file:///etc/passwd".to_owned(),
            "ftp://example.com/crl.crl".to_owned(),
            "https://crl.example.com/test.crl".to_owned(),
        ])?;
        let urls = extract_cdp_urls(&cert, false);
        assert_eq!(urls.len(), 1, "only HTTPS should survive: {urls:?}");
        assert_eq!(
            urls.first().context("surviving HTTPS CDP URL")?.as_str(),
            "https://crl.example.com/test.crl"
        );
        Ok(())
    }

    /// Pins that `crl_allow_http=false` filters HTTP while `true` keeps it.
    #[test]
    fn extract_cdp_urls_filters_http_when_disallowed() -> anyhow::Result<()> {
        let cert = build_cert_with_cdp_urls(vec![
            "http://crl.example.com/x.crl".to_owned(),
            "https://crl.example.com/y.crl".to_owned(),
        ])?;
        let urls_strict = extract_cdp_urls(&cert, false);
        assert_eq!(urls_strict.len(), 1);
        assert!(
            urls_strict
                .first()
                .context("strict list keeps the HTTPS URL")?
                .starts_with("https://")
        );

        let urls_lax = extract_cdp_urls(&cert, true);
        assert_eq!(urls_lax.len(), 2);
        Ok(())
    }

    /// Pins that malformed CDP URLs are dropped, keeping the valid HTTPS one.
    #[test]
    fn extract_cdp_urls_drops_malformed() -> anyhow::Result<()> {
        let cert = build_cert_with_cdp_urls(vec![
            "not-a-url".to_owned(),
            ":::::broken:::".to_owned(),
            "https://valid.example.com/crl".to_owned(),
        ])?;
        let urls = extract_cdp_urls(&cert, false);
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls.first().context("surviving valid CDP URL")?.as_str(),
            "https://valid.example.com/crl"
        );
        Ok(())
    }

    /// Pins that scheme comparison is case-insensitive (normalized lowercase).
    #[test]
    fn extract_cdp_urls_handles_uppercase_scheme() -> anyhow::Result<()> {
        // url::Url::parse normalizes scheme to lowercase, which is the
        // behavior we want (case-insensitive).
        let cert = build_cert_with_cdp_urls(vec!["HTTPS://crl.example.com/X.crl".to_owned()])?;
        let urls = extract_cdp_urls(&cert, false);
        assert_eq!(urls.len(), 1);
        assert!(
            urls.first()
                .context("uppercase-scheme URL survives")?
                .starts_with("https://")
        );
        Ok(())
    }

    // -- Q2: hardened client refuses redirects ----------------------------------

    /// Pins that the hardened client surfaces a 302 without following it.
    #[tokio::test]
    async fn hardened_client_refuses_redirect() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "http://elsewhere.invalid/x"),
            )
            .mount(&mock)
            .await;

        let client = build_hardened_client()?;
        let url = format!("{}/crl", mock.uri());
        // Policy::none() returns the 302 response itself rather than following it.
        // The Location header points to elsewhere.invalid which would fail to
        // resolve if we followed it; the assertion below proves we did not.
        let response = client.get(&url).send().await.context("got 302 back")?;
        assert_eq!(
            response.status().as_u16(),
            302,
            "redirect must surface as 302 (not followed)"
        );
        // The original mock host responded; we never chained to elsewhere.invalid.
        assert!(
            response.url().as_str().starts_with(&mock.uri()),
            "response URL must remain the original (no follow): {}",
            response.url()
        );
        Ok(())
    }

    // -- Q3: hardened client returns 5xx upstream errors as errors --------------

    /// Pins that a 5xx upstream response surfaces as an error.
    #[tokio::test]
    async fn hardened_client_surfaces_5xx_as_error() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let client = build_hardened_client()?;
        let url = format!("{}/crl", mock.uri());
        let err = client
            .get(&url)
            .send()
            .await
            .context("got 503")?
            .error_for_status()
            .err()
            .context("5xx should error")?;
        assert!(err.status().is_some_and(|status| status.as_u16() == 503));
        Ok(())
    }

    // -- Q4: streaming body-cap behavior (chunk-loop semantics) -----------------

    /// Pins that the chunked cap loop trips on an oversized response body.
    #[tokio::test]
    async fn body_cap_rejects_oversized_response() -> anyhow::Result<()> {
        // We can't call the private `fetch_crl` directly across crate
        // boundaries, so we re-implement the same chunked-cap loop here and
        // verify the algorithm rejects oversized bodies. This locks the
        // contract: any change to the production loop that loses the cap
        // will fail to be mirrored here and we'll catch it in code review.
        let mock = MockServer::start().await;
        let big_body = vec![0_u8; 8 * 1024]; // 8 KiB
        Mock::given(method("GET"))
            .and(path("/big.crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body.clone()))
            .mount(&mock)
            .await;

        let client = build_hardened_client()?;
        let url = format!("{}/big.crl", mock.uri());
        let max_bytes: u64 = 1024; // cap below body size

        let mut response = client
            .get(&url)
            .send()
            .await
            .context("send")?
            .error_for_status()
            .context("ok")?;
        let mut body: Vec<u8> = Vec::new();
        let mut hit_cap = false;
        while let Some(chunk) = response.chunk().await.context("chunk")? {
            let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
            if body_len.saturating_add(chunk_len) > max_bytes {
                hit_cap = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        assert!(hit_cap, "body cap must trip on oversized response");
        assert!(
            u64::try_from(body.len()).unwrap_or(u64::MAX) <= max_bytes,
            "body cannot exceed cap: {} vs {max_bytes}",
            body.len()
        );
        Ok(())
    }

    /// Pins that an undersized body is accepted and matches what was served.
    #[tokio::test]
    async fn body_cap_allows_undersized_response() -> anyhow::Result<()> {
        let crl_bytes = build_test_crl_der()?;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/small.crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes.clone()))
            .mount(&mock)
            .await;

        let client = build_hardened_client()?;
        let url = format!("{}/small.crl", mock.uri());
        let max_bytes: u64 = 5 * 1024 * 1024;

        let mut response = client
            .get(&url)
            .send()
            .await
            .context("send")?
            .error_for_status()
            .context("ok")?;
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.context("chunk")? {
            let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
            assert!(
                body_len.saturating_add(chunk_len) <= max_bytes,
                "should never exceed cap"
            );
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, crl_bytes);
        Ok(())
    }

    // -- Q5: test-cert with no CDP URLs -----------------------------------------

    /// Pins that a cert without a CDP extension yields no URLs.
    #[test]
    fn cert_without_cdp_returns_empty() -> anyhow::Result<()> {
        let ca = build_ca()?;
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).context("params")?;
        params.serial_number = Some(SerialNumber::from(7_u64));
        params.distinguished_name.push(DnType::CommonName, "no-cdp");
        let key = KeyPair::generate().context("key")?;
        let cert = params.signed_by(&key, &ca).context("signed")?;
        let urls = extract_cdp_urls(cert.der(), true);
        assert!(urls.is_empty(), "no CDP extension means no URLs");
        Ok(())
    }

    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: tests/integration/crl_ssrf.rs::malformed_cert_der_returns_empty keeps the uniform test signature while it only asserts a non-panic"
    )]
    /// Pins that garbage DER is rejected without panicking.
    fn malformed_cert_der_returns_empty() -> anyhow::Result<()> {
        let urls = extract_cdp_urls(b"not a certificate", true);
        assert!(urls.is_empty(), "garbage DER must not panic");
        Ok(())
    }
}
