//! 1.3.0 Oracle B3: exercise JWKS redirect SSRF protection through the
//! real `JwksCache::new()` client and refresh path.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![cfg(all(feature = "oauth", feature = "test-helpers"))]

use rmcp_server_kit::oauth::{JwksCache, OAuthConfig};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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

#[tokio::test]
async fn jwks_cache_redirect_to_private_ip_rejected() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://127.0.0.1:1/jwks"),
        )
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("redirect to loopback/private IP must be rejected");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after redirect rejection"
    );
}

#[tokio::test]
async fn jwks_cache_redirect_to_userinfo_rejected() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "https://user:pass@example.com/jwks"),
        )
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("redirect with userinfo must be rejected");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after redirect rejection"
    );
}

#[tokio::test]
async fn jwks_cache_http_to_http_redirect_followed_when_http_allowed() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");
    let jwks_doc = synthetic_jwks(1);
    let redirect_target = format!("{base}/jwks-followed.json");

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", redirect_target.as_str()),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks-followed.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    cache
        .__test_refresh_now()
        .await
        .expect("http-to-http redirect should be followed when allow_http=true");
    assert!(
        cache.__test_has_kid("kid-0").await,
        "cache must populate after allowed http-to-http redirect"
    );
}

#[tokio::test]
async fn jwks_cache_http_to_http_redirect_rejected_when_http_disallowed() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");
    let redirect_target = format!("{base}/jwks-followed.json");

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", redirect_target.as_str()),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks-followed.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(synthetic_jwks(1)))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("http-to-http redirect must be rejected when allow_http=false");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after disallowed http-to-http redirect"
    );
}

// ---------------------------------------------------------------------------
// 1.4.0 -- Operator SSRF allowlist (no `__test_allow_loopback_ssrf`)
// ---------------------------------------------------------------------------
//
// These tests exercise the *real* post-DNS screening path against a
// loopback-backed wiremock server, demonstrating that:
//   * an operator allowlist covering the loopback CIDR(s) lets the
//     fetch through (happy path);
//   * the same configuration WITHOUT the allowlist still fails closed
//     (regression guard for the default behaviour);
//   * even with a permissive allowlist (`fd00::/8` etc.), a redirect
//     into the cloud-metadata range is unconditionally rejected.

#[tokio::test]
async fn jwks_cache_loopback_fetched_when_operator_allowlist_permits() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    // Resolve via DNS so the post-DNS screening path -- not the
    // literal-IP rejector -- is what gates the request.
    let base = mock.uri().replace("127.0.0.1", "localhost");
    let jwks_doc = synthetic_jwks(1);

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    // Configure an operator allowlist covering the loopback ranges that
    // `localhost` may resolve to on the test host (Linux: 127.0.0.1;
    // Windows: ::1; macOS: both).
    let mut allowlist = rmcp_server_kit::oauth::OAuthSsrfAllowlist::default();
    allowlist.cidrs.push("127.0.0.0/8".into());
    allowlist.cidrs.push("::1/128".into());
    config.ssrf_allowlist = Some(allowlist);

    // NOTE: we deliberately do NOT call `__test_allow_loopback_ssrf()`.
    // The fetch must succeed via the operator allowlist alone.
    let cache = JwksCache::new(&config).expect("construct cache");
    cache
        .__test_refresh_now()
        .await
        .expect("operator allowlist must permit the in-cluster JWKS fetch");
    assert!(
        cache.__test_has_kid("kid-0").await,
        "cache must populate after allowlisted loopback fetch"
    );
}

#[tokio::test]
async fn jwks_cache_loopback_blocked_when_no_operator_allowlist() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(synthetic_jwks(1)))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;
    // No `ssrf_allowlist` -> default fail-closed behaviour.

    let cache = JwksCache::new(&config).expect("construct cache");
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("default config must still block loopback fetches");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when default screening blocks target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched when default screening blocks fetch"
    );
}

#[tokio::test]
async fn jwks_cache_redirect_to_cloud_metadata_blocked_even_with_permissive_allowlist() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            // Redirect into the AWS/GCP IPv4 cloud-metadata address.
            // Listing `169.254.0.0/16` in the allowlist must NOT
            // re-allow this address; the cloud-metadata classifier
            // runs before the allowlist consult.
            ResponseTemplate::new(302).insert_header("location", "https://169.254.169.254/jwks"),
        )
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    // Deliberately permissive allowlist. The metadata IP MUST still be
    // rejected on the redirect hop -- this pins the cloud-metadata
    // carve-out invariant.
    let mut allowlist = rmcp_server_kit::oauth::OAuthSsrfAllowlist::default();
    allowlist.cidrs.push("169.254.0.0/16".into());
    allowlist.cidrs.push("127.0.0.0/8".into());
    allowlist.cidrs.push("::1/128".into());
    config.ssrf_allowlist = Some(allowlist);

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("redirect to cloud-metadata must be rejected even with permissive allowlist");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly on cloud-metadata redirect; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after cloud-metadata rejection"
    );
}
