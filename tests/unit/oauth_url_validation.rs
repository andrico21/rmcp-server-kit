//! 1.3.0 hardening: `check_oauth_url` userinfo rejection + `check_url_literal_ip`
//! applied at `OAuthConfig::validate` time.
//!
//! These tests are **failing-first** per the 1.3.0 TDD plan. They become
//! passing once the following is implemented:
//!
//! * `check_oauth_url` rejects any URL whose `username()` is non-empty or
//!   whose `password()` is `Some(_)`, returning [`RmcpServerKitError::Config`].
//! * `OAuthConfig::validate` additionally runs a new
//!   `crate::ssrf::check_url_literal_ip` guard that rejects any literal
//!   IPv4 or IPv6 host in the URL string (any canonical form parsed by
//!   [`url::Url`]).
#![cfg_attr(
    all(feature = "oauth", target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#![cfg_attr(
    all(feature = "oauth", target_os = "linux"),
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use rmcp_server_kit::oauth::OAuthConfig;

    /// Build a minimal `OAuthConfig` with a given `jwks_uri` and `allow_http` flag.
    fn cfg_with_jwks(jwks_uri: &str, allow_http: bool) -> OAuthConfig {
        let mut cfg = OAuthConfig::builder("https://issuer.example.com/", "aud", jwks_uri).build();
        cfg.allow_http_oauth_urls = allow_http;
        cfg
    }

    /// Pins that a JWKS URL carrying only a username is rejected by validation.
    #[test]
    fn rejects_userinfo_username_only() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://attacker@idp.example.com/jwks", false);
        let err = cfg.validate().err().context("userinfo must be rejected")?;
        let msg = err.to_string();
        assert!(
            msg.contains("userinfo") || msg.contains("credentials"),
            "error must mention userinfo rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a JWKS URL carrying `user:password@` userinfo is rejected.
    #[test]
    fn rejects_userinfo_username_password() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://victim:secret@attacker.com/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("userinfo (user:pass) must be rejected")?;
        let msg = err.to_string();
        assert!(
            msg.contains("userinfo") || msg.contains("credentials"),
            "error must mention userinfo rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that an issuer URL carrying userinfo is rejected by validation.
    #[test]
    fn issuer_with_userinfo_rejected() -> anyhow::Result<()> {
        let cfg = OAuthConfig::builder(
            "https://user:pass@auth.example.com/",
            "aud",
            "https://auth.example.com/jwks",
        )
        .build();
        let err = cfg
            .validate()
            .err()
            .context("issuer userinfo must be rejected")?;
        let msg = err.to_string();
        assert!(
            msg.contains("userinfo") || msg.contains("credentials"),
            "error must mention userinfo rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a literal IPv4 issuer is rejected by validation.
    #[test]
    fn issuer_with_literal_ipv4_rejected() -> anyhow::Result<()> {
        let cfg =
            OAuthConfig::builder("https://192.0.2.1/", "aud", "https://auth.example.com/jwks")
                .build();
        let err = cfg
            .validate()
            .err()
            .context("literal IPv4 issuer must be rejected")?;
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden") || msg.contains("literal") || msg.contains("ip"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a literal IPv6 issuer is rejected by validation.
    #[test]
    fn issuer_with_literal_ipv6_rejected() -> anyhow::Result<()> {
        let cfg = OAuthConfig::builder(
            "https://[2001:db8::1]/",
            "aud",
            "https://auth.example.com/jwks",
        )
        .build();
        let err = cfg
            .validate()
            .err()
            .context("literal IPv6 issuer must be rejected")?;
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden") || msg.contains("literal") || msg.contains("ip"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a literal loopback JWKS host is rejected by validation.
    #[test]
    fn rejects_literal_loopback_jwks() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://127.0.0.1/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("literal loopback IP must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("loopback") || msg.contains("forbidden"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a literal RFC1918 JWKS host is rejected by validation.
    #[test]
    fn rejects_literal_private_jwks() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://10.0.0.1/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("literal private (RFC1918) IP must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("private") || msg.contains("forbidden") || msg.contains("rfc1918"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that the cloud-metadata JWKS host is rejected by validation.
    #[test]
    fn rejects_literal_metadata_jwks() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://169.254.169.254/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("cloud-metadata IP must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("metadata")
                || msg.contains("link-local")
                || msg.contains("link local")
                || msg.contains("forbidden"),
            "error must mention cloud-metadata/link-local rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a hex-canonicalised loopback JWKS host is rejected by validation.
    #[test]
    fn rejects_hex_loopback_jwks() -> anyhow::Result<()> {
        // `url::Url` canonicalises `0x7f000001` -> `127.0.0.1`, so the
        // literal-IP guard must also reject this form.
        let cfg = cfg_with_jwks("https://0x7f000001/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("hex-encoded loopback IP must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("loopback") || msg.contains("forbidden"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a public literal IPv4 JWKS host is rejected by validation.
    #[test]
    fn validate_rejects_public_literal_ipv4() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://8.8.8.8/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("public literal IPv4 must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden") || msg.contains("literal") || msg.contains("ip"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a public literal IPv6 JWKS host is rejected by validation.
    #[test]
    fn validate_rejects_public_literal_ipv6() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://[2001:4860:4860::8888]/jwks", false);
        let err = cfg
            .validate()
            .err()
            .context("public literal IPv6 must be rejected at validation")?;
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden") || msg.contains("literal") || msg.contains("ip"),
            "error must mention literal-IP rejection; got: {msg}"
        );
        Ok(())
    }

    /// Pins that a `localhost` JWKS name passes validation when plain HTTP is allowed.
    #[test]
    fn allows_localhost_with_allow_http_true() -> anyhow::Result<()> {
        // DNS names (like `localhost`) are NOT blocked by the sync pre-DNS
        // literal-IP guard. The post-DNS block remains the runtime/network
        // layer's responsibility (outside the scope of `check_url_literal_ip`).
        let cfg = cfg_with_jwks("http://localhost/jwks", true);
        cfg.validate()
            .context("DNS name `localhost` must pass the sync validation guard")?;
        Ok(())
    }

    /// Pins that a public HTTPS JWKS URL with a DNS name validates cleanly.
    #[test]
    fn allows_legitimate_https() -> anyhow::Result<()> {
        let cfg = cfg_with_jwks("https://auth.example.com/.well-known/jwks.json", false);
        cfg.validate()
            .context("public HTTPS URL with DNS name must validate cleanly")?;
        Ok(())
    }
}
