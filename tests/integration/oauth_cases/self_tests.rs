//! Inline contracts for the documentation runner's input boundaries.

use alloc::collections::BTreeSet;

use anyhow::{Context as _, ensure};
use tokio::task::spawn_blocking;

use super::compare::Message;

fn parse_cases(markdown: &str) -> anyhow::Result<Vec<super::grammar::Case>> {
    super::grammar::parse_cases(&super::fence_tables::complete_document(markdown))
}

/// Response mismatches return errors rather than panicking.
#[test]
fn responses_reject_when_status_headers_or_body_differ() -> anyhow::Result<()> {
    // Given: multiple headers and a literal response body.
    let expected = Message::parse(
        "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer <any>\nX-Test: yes\n\nbody",
    )?;
    for (actual, passes) in [
        (
            "HTTP/1.1 401 Unauthorized\nwww-authenticate: Bearer abc\nx-test: yes\nextra: ignored\n\nbody",
            true,
        ),
        (
            "HTTP/1.1 200 OK\nWWW-Authenticate: Bearer abc\nX-Test: yes\n\nbody",
            false,
        ),
        ("HTTP/1.1 401 Unauthorized\nX-Test: yes\n\nbody", false),
        (
            "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic abc\nX-Test: yes\n\nbody",
            false,
        ),
        (
            "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer abc\nX-Test: no\n\nbody",
            false,
        ),
        (
            "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer abc\nX-Test: yes\n\nother",
            false,
        ),
    ] {
        // When: compare the wire representation.
        let result = expected.compare_response(&Message::parse(actual)?);
        // Then: every named mismatch is observable as an error.
        ensure!(result.is_ok() == passes, "response comparison differs");
    }
    Ok(())
}

/// Requests retain optional bodies without interpreting their contents.
#[test]
fn requests_parse_when_body_is_present_or_absent() -> anyhow::Result<()> {
    for (input, body) in [
        ("POST /mcp HTTP/1.1\nHost: mcp.example", None),
        ("POST /mcp HTTP/1.1\n\na=b=c", Some("a=b=c")),
    ] {
        // Given/When: parse a raw documented request.
        let request = Message::parse(input)?;
        // Then: body presence and literal content survive.
        ensure!(request.body.as_deref() == body, "request body differs");
        ensure!(
            request.request_target()? == ("POST", "/mcp"),
            "request target differs"
        );
    }
    Ok(())
}

/// Case fences are paired in order and unrelated examples are ignored.
#[test]
fn cases_reject_when_fences_are_duplicate_or_out_of_order() -> anyhow::Result<()> {
    // Given: an inline section, never the live documentation prose.
    let prefix =
        "## 7. Configuration examples\n```toml,case=X\n[server]\n```\n```sh,case=X\nA=b\n```\n";
    for (tail, passes) in [
        (
            "```http,case=X,request\nPOST /mcp HTTP/1.1\n```\nprose\n```http,case=X,response\nHTTP/1.1 401 Unauthorized\n```",
            true,
        ),
        (
            "```http,case=X,response\nHTTP/1.1 401 Unauthorized\n```",
            false,
        ),
        ("```toml,case=X\n[server]\n```", false),
        ("```http,case=X,request\nPOST /mcp HTTP/1.1\n```", false),
        ("```http,case=X,unknown\nanything\n```", false),
    ] {
        // When: assemble fences into cases.
        let result = parse_cases(&format!("{prefix}{tail}\n## 8. End\n"));
        // Then: malformed case data names the case and returns an error.
        ensure!(result.is_ok() == passes, "case grammar acceptance differs");
        if let Err(error) = result {
            ensure!(error.to_string().contains('X'), "missing case context");
        }
    }
    let cases = parse_cases(&format!(
        "{prefix}```text\nunrelated\n```\n```http,case=X,request\nGET / HTTP/1.1\n```\n```http,case=X,response\nHTTP/1.1 200 OK\n```\n## 8. End\n```toml,fragment\nbad\n```"
    ))?;
    ensure!(cases.len() == 1, "outside-section fences were executed");
    ensure!(
        parse_cases("## 7. Empty\n## 8. End")
            .err()
            .context("zero cases must fail")?
            .to_string()
            .contains("cases"),
        "zero-case error"
    );
    Ok(())
}

/// JWT overrides survive signature verification and malformed JSON returns an error.
#[test]
fn jwt_claims_override_when_explicit_values_are_provided() -> anyhow::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::Value;

    use super::identity::{Identity, RULES};
    let identity = Identity::generate()?;
    let mut covered = BTreeSet::new();
    for (placeholder, expected_issuer, expected_exp) in [
        ("<jwt>", "https://default.example", None),
        (
            "<jwt {\"iss\":\"https://override.example\",\"exp\":4000000000}>",
            "https://override.example",
            Some(4_000_000_000_u64),
        ),
    ] {
        let token = identity.substitute(placeholder, "https://default.example")?;
        let key = identity.jwks.pointer("/keys/0").context("JWK")?;
        let decoding = DecodingKey::from_rsa_components(
            key.get("n")
                .and_then(Value::as_str)
                .context("RSA modulus")?,
            key.get("e")
                .and_then(Value::as_str)
                .context("RSA exponent")?,
        )?;
        let verified =
            jsonwebtoken::decode::<Value>(&token, &decoding, &Validation::new(Algorithm::RS256))?;
        ensure!(
            verified.header.kid.as_deref() == Some("case-key"),
            "wrong kid"
        );
        ensure!(
            verified.claims.get("iss").and_then(Value::as_str) == Some(expected_issuer),
            "issuer override lost"
        );
        let exp = verified
            .claims
            .get("exp")
            .and_then(Value::as_u64)
            .context("exp")?;
        ensure!(exp > jsonwebtoken::get_current_timestamp(), "JWT expired");
        if let Some(expected) = expected_exp {
            ensure!(exp == expected, "exp override lost");
        } else {
            let issued = verified
                .claims
                .get("iat")
                .and_then(Value::as_u64)
                .context("iat")?;
            ensure!(
                issued.abs_diff(jsonwebtoken::get_current_timestamp()) <= 5,
                "default issue time differs"
            );
            ensure!(
                exp.checked_sub(issued) == Some(300),
                "default lifetime differs"
            );
            let _new = covered.insert("jwt-iat");
            ensure!(
                exp <= jsonwebtoken::get_current_timestamp().saturating_add(300),
                "default expiry exceeds five minutes"
            );
        }
        let payload = token.split('.').nth(1).context("JWT payload")?;
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        ensure!(
            claims.get("sub").and_then(Value::as_str) == Some("user-1"),
            "default subject"
        );
    }
    ensure!(
        RULES.iter().all(|rule| covered.contains(rule)) && covered.len() == RULES.len(),
        "JWT rule lacks a table row"
    );
    for input in ["<jwt {bad}>", "<jwt []>", "<jwt {\"iss\":1}"] {
        let error = identity
            .substitute(input, "issuer")
            .err()
            .context("malformed JWT must fail")?;
        ensure!(!error.to_string().is_empty(), "JWT error needs context");
    }
    Ok(())
}

/// Upstream assertions distinguish method, path, headers and decoded form fields.
// cancel-safe: fixture-owned requests and mock listeners drop with the test.
#[tokio::test]
async fn upstream_matches_when_all_listed_fields_agree() -> anyhow::Result<()> {
    use super::{compare::compare_upstream, mock::DualStackMock};
    let mock = DualStackMock::start().await?;
    let client = super::network::client()?;
    let _response = client
        .post(format!("{}/token", mock.base()))
        .header("Authorization", "Basic abc")
        .body("scope=mcp%3Aread&token=a%3Db&empty=")
        .send()
        .await?;
    let requests = mock.requests().await?;
    let actual = requests.first().context("recorded request")?;
    for (expected, passes) in [
        (
            "POST /token\nauthorization: Basic <any>\n\nscope=mcp:read\ntoken=a=b\nempty=<any>",
            true,
        ),
        ("GET /token", false),
        ("POST /other", false),
        ("POST /token\nAuthorization: Bearer <any>", false),
        ("POST /token\nMissing: yes", false),
        ("POST /token\n\nscope=wrong", false),
        ("POST /token\n\nmissing=<any>", false),
    ] {
        ensure!(
            compare_upstream(expected, actual).is_ok() == passes,
            "upstream comparison acceptance differs"
        );
    }
    Ok(())
}

/// Alternate env and library-call fences retain their case association.
#[test]
fn library_exchanges_parse_when_upstream_follows_rust_snippet() -> anyhow::Result<()> {
    use super::grammar::Exchange;
    let markdown = "## 7. Cases\n```toml,case=R7\n[server]\n```\n```sh,case=R7\nA=x\n```\n```sh,case=R7,alt\nA='x'\n```\n```rust,ignore\nexchange_token().await?;\n```\n```http,case=R7,upstream\nPOST /token\n\nsubject_token=<any>\n```\n## 8. End";
    let cases = parse_cases(markdown)?;
    let case = cases.first().context("library case")?;
    ensure!(case.env.len() == 2, "alternate env missing");
    match case.exchanges.first().context("library exchange")? {
        Exchange::Library { snippet, upstream } => ensure!(
            snippet.contains("exchange_token") && upstream.starts_with("POST /token"),
            "library payload lost"
        ),
        Exchange::Http {
            request: _,
            response: _,
            upstream: _,
        } => anyhow::bail!("library exchange parsed as HTTP"),
    }
    Ok(())
}

/// A mismatched upstream fence fails the real exchange rather than being silently skipped.
// cancel-safe: case-owned listeners and request futures are dropped on failure.
#[tokio::test]
async fn upstream_rejects_when_recorded_request_is_absent() -> anyhow::Result<()> {
    use super::{identity::Identity, runtime::run_case};
    let markdown = "## 7. Cases\n```toml,case=ABSENT\n[server]\npublic_url='https://mcp.example'\n[server.auth]\nenabled=true\n[server.auth.oauth]\nissuer='https://idp.example/realms/example'\naudience='mcp-example'\njwks_uri='https://idp.example/custom/certs'\n[[server.auth.oauth.scopes]]\nscope='mcp:read'\nrole='viewer'\n```\n```sh,case=ABSENT\n# no overrides\n```\n```http,case=ABSENT,request\nPOST /mcp HTTP/1.1\nHost: mcp.example\n```\n```http,case=ABSENT,response\nHTTP/1.1 401 Unauthorized\n```\n```http,case=ABSENT,upstream\nPOST /never-called\n```\n## 8. End";
    let cases = parse_cases(markdown)?;
    let identity = spawn_blocking(Identity::generate).await??;
    let error = run_case(cases.first().context("absent case")?, &identity)
        .await
        .err()
        .context("missing upstream accepted")?;
    ensure!(
        error.to_string().contains("upstream"),
        "upstream error context missing"
    );
    Ok(())
}
