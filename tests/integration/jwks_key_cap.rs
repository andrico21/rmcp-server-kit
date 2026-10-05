//! 1.3.0 hardening: JWKS key-count soft cap (Deliverable 6).
//!
//! `JwksCache::refresh_inner` MUST refuse to populate the in-memory
//! key cache when the upstream JWKS document carries more keys than
//! [`OAuthConfig::max_jwks_keys`] (default 256). The failure mode is
//! **fail-closed** - no keys are installed, so subsequent
//! `validate_token` calls still reject the JWT. Silent truncation
//! would cause sporadic auth failures and hide the misconfiguration.
//!
//! Failing-first TDD surface - requires these NEW helpers:
//!
//! * `OAuthConfig::max_jwks_keys: usize` (`#[serde(default)]`, default 256)
//! * `fn build_key_cache(&JwkSet, usize) -> Result<JwksKeyCache, String>`
//!   returning `Err(msg)` containing the literal substring
//!   `"jwks_key_count_exceeds_cap"` on breach.
//! * `impl JwksCache { pub async fn __test_refresh_now(&self) -> Result<(), String> }`
//! * `impl JwksCache { pub async fn __test_has_kid(&self, kid: &str) -> bool }`
#[cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg_attr(
    all(feature = "oauth-mtls-client", target_os = "linux"),
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {

    use anyhow::Context as _;
    use rmcp_server_kit::oauth::{JwksCache, OAuthConfig};
    use rustls::crypto::ring;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    /// Build a synthetic JWKS document with `n` RSA keys. The key material
    /// is bogus (short base64url `"AQAB"` / `"dummy"`) because the test
    /// exercises the cap path - `build_key_cache` rejects on length BEFORE
    /// it would attempt key decoding, so invalid key bytes are fine.
    fn synthetic_jwks(n: usize) -> Value {
        let keys: Vec<Value> = (0..n)
            .map(|i| {
                json!({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": format!("kid-{i}"),
                    "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS-uo-0Rwm9uYCKu_yvfZm9LDJ7zXYf8DrK9tYmoPSt4K3fhfB9m9k9MhE7_tR5sQkOA0OiYuVLxbBR-g3nL5yGgGSsj5lmNS_4F9zMzJgJWK5A7K6sH8zDjpwcTWfTUqB2c9yw0yDkBYMHRDHeozs9ybyoUNt4fT7aVRMVAjEhCEPJmSmnyfH_5w",
                    "e": "AQAB"
                })
            })
            .collect();
        json!({ "keys": keys })
    }

    fn install_crypto_provider() {
        drop(ring::default_provider().install_default());
    }

    /// Pins that a JWKS document with more keys than `max_jwks_keys` is
    /// rejected fail-closed, installing no keys at all.
    #[tokio::test]
    async fn jwks_rejects_excess_keys_fail_closed() -> anyhow::Result<()> {
        install_crypto_provider();

        // Wiremock serves a JWKS document with 300 RSA keys.
        let mock = MockServer::start().await;
        let jwks_doc = synthetic_jwks(300);
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
            .mount(&mock)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
        let mut config =
            OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
        // Permit plain-HTTP wiremock origin for this test (validate() does
        // not otherwise allow http:// jwks URIs). The allow_http flag is
        // orthogonal to the key-cap hardening under test.
        config.allow_http_oauth_urls = true;
        // Cap = 256; document has 300 → must reject fail-closed.
        config.max_jwks_keys = 256;

        // `JwksCache::new` does NOT fetch - only builds the reqwest client.
        let cache = JwksCache::new(&config)
            .map_err(anyhow::Error::msg)
            .context("construct cache")?
            .__test_allow_loopback_ssrf();

        // Drive the refresh path that would normally happen on first
        // validate_token() call. The new __test_refresh_now helper surfaces
        // the `build_key_cache` error string verbatim.
        let result = cache.__test_refresh_now().await;

        let err = result.err().context("300 keys must exceed cap=256")?;
        assert!(
            err.contains("jwks_key_count_exceeds_cap"),
            "refresh error must contain literal `jwks_key_count_exceeds_cap`; got: {err}"
        );

        // Fail-closed: cache MUST be empty afterwards. No keys were installed.
        assert!(
            !cache.__test_has_kid("kid-0").await,
            "cache must remain empty on cap breach (fail-closed, no silent truncation)"
        );
        assert!(
            !cache.__test_has_kid("kid-255").await,
            "cache must remain empty on cap breach (fail-closed, not first-N truncation)"
        );
        assert!(
            !cache.__test_has_kid("kid-299").await,
            "cache must remain empty on cap breach (fail-closed, not last-N)"
        );
        Ok(())
    }

    /// Pins that a JWKS document exactly at `max_jwks_keys` populates the
    /// cache normally.
    #[tokio::test]
    async fn jwks_at_cap_populates_successfully() -> anyhow::Result<()> {
        install_crypto_provider();

        // Exactly at the cap → populate as normal.
        let mock = MockServer::start().await;
        let jwks_doc = synthetic_jwks(8);
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
            .mount(&mock)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
        let mut config =
            OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
        config.allow_http_oauth_urls = true;
        config.max_jwks_keys = 8;

        let cache = JwksCache::new(&config)
            .map_err(anyhow::Error::msg)
            .context("construct cache")?
            .__test_allow_loopback_ssrf();
        cache
            .__test_refresh_now()
            .await
            .map_err(anyhow::Error::msg)
            .context("refresh at cap must succeed")?;

        assert!(
            cache.__test_has_kid("kid-0").await,
            "cache must contain first kid after successful refresh"
        );
        assert!(
            cache.__test_has_kid("kid-7").await,
            "cache must contain last kid after successful refresh"
        );
        Ok(())
    }
}
