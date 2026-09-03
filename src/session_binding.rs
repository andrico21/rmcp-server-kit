//! Stateless binding between rmcp session IDs and authenticated identities.

use std::sync::OnceLock;

use axum::{
    body::Body,
    http::{HeaderValue, Request, StatusCode, header::HeaderName},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    auth::{AuthIdentity, AuthMethod},
    error::RmcpServerKitError,
};

const VERSION: &str = "v1";
const DOMAIN_SEPARATOR: u8 = 0;
const RAW_SESSION_ID_LEN: usize = 36;
const RAW_SESSION_ID_B64_LEN: usize = 48;
const MAC_LEN: usize = 32;
pub(crate) const MIN_CONFIGURED_SECRET_BYTES: usize = 32;
const MAC_B64_LEN: usize = 43;
const MAX_WRAPPED_SESSION_TOKEN_LEN: usize =
    VERSION.len() + 1 + RAW_SESSION_ID_B64_LEN + 1 + MAC_B64_LEN;

/// Process-random HMAC secret used for stateless session binding.
#[derive(Clone)]
pub(crate) enum SessionBindingSecret {
    /// Process-random fallback for single-instance deployments.
    Process([u8; MAC_LEN]),
    /// Operator-supplied shared secret for multi-instance deployments.
    Configured(SecretString),
}

impl std::fmt::Debug for SessionBindingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionBindingSecret(<redacted>)")
    }
}

/// Canonical authenticated-identity fingerprint bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityFingerprint(Vec<u8>);

/// Raw rmcp session ID after wrapper verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSessionId(String);

impl RawSessionId {
    fn parse(raw: &str) -> Result<Self, Reason> {
        if is_uuid_shaped(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(Reason::Malformed)
        }
    }
}

/// Reason a session token failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The header is not a syntactically valid wrapped session token.
    Malformed,
    /// The header is a raw rmcp UUID rather than a wrapper.
    Unwrapped,
    /// The wrapper shape is valid, but the MAC is not valid for this identity.
    MacFailed,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unwrapped => "unwrapped",
            Self::MacFailed => "mac_failed",
        }
    }
}

/// Process-wide random session-binding secret, generated once per process.
pub(crate) fn process_session_binding_secret() -> &'static SessionBindingSecret {
    static PROCESS_SECRET: OnceLock<SessionBindingSecret> = OnceLock::new();
    PROCESS_SECRET.get_or_init(|| {
        let mut bytes = [0u8; MAC_LEN];
        rand::fill(&mut bytes);
        SessionBindingSecret::Process(bytes)
    })
}

/// Build a session-binding HMAC secret from operator configuration.
pub(crate) fn configured_session_binding_secret(
    secret: &SecretString,
) -> Result<SessionBindingSecret, RmcpServerKitError> {
    validate_configured_secret("session_binding_secret", secret.expose_secret())?;
    Ok(SessionBindingSecret::Configured(secret.clone()))
}

/// Validate the configured session-binding secret's strength.
pub(crate) fn validate_configured_secret(
    field: &str,
    value: &str,
) -> Result<(), RmcpServerKitError> {
    if value.trim().is_empty() {
        return Err(RmcpServerKitError::Config(format!(
            "{field} must not be empty or whitespace-only"
        )));
    }
    let len = value.len();
    if len < MIN_CONFIGURED_SECRET_BYTES {
        return Err(RmcpServerKitError::Config(format!(
            "{field} must be at least {MIN_CONFIGURED_SECRET_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Build the stable authenticated-identity fingerprint bytes.
pub(crate) fn fingerprint(identity: &AuthIdentity) -> IdentityFingerprint {
    let (method, stable_id) = match identity.method {
        AuthMethod::BearerToken => (b"api-key".as_slice(), identity.name.as_str()),
        AuthMethod::MtlsCertificate => (b"mtls".as_slice(), identity.name.as_str()),
        AuthMethod::OAuthJwt => (
            b"oauth-jwt".as_slice(),
            identity.sub.as_deref().unwrap_or(identity.name.as_str()),
        ),
    };
    let mut bytes = Vec::with_capacity(method.len() + 1 + stable_id.len());
    bytes.extend_from_slice(method);
    bytes.push(DOMAIN_SEPARATOR);
    bytes.extend_from_slice(stable_id.as_bytes());
    IdentityFingerprint(bytes)
}

/// Wrap a raw rmcp session ID in a stateless identity-bound token.
pub(crate) fn wrap(
    secret: &SessionBindingSecret,
    raw_id: &RawSessionId,
    fp: &IdentityFingerprint,
) -> String {
    let mac = compute_mac(secret, raw_id, fp);
    format!(
        "{VERSION}.{}.{}",
        URL_SAFE_NO_PAD.encode(&raw_id.0),
        URL_SAFE_NO_PAD.encode(mac)
    )
}

/// Verify an identity-bound token and recover the raw rmcp session ID.
pub(crate) fn unwrap_and_verify(
    secret: &SessionBindingSecret,
    token: &str,
    fp: &IdentityFingerprint,
) -> Result<RawSessionId, Reason> {
    if token.len() > MAX_WRAPPED_SESSION_TOKEN_LEN {
        return Err(Reason::Malformed);
    }
    if is_uuid_shaped(token) {
        return Err(Reason::Unwrapped);
    }

    let (raw_part, mac_part) = split_token(token)?;
    if mac_part.len() != MAC_B64_LEN
        || raw_part.is_empty()
        || raw_part.len() > RAW_SESSION_ID_B64_LEN
    {
        return Err(Reason::Malformed);
    }

    let mut mac = [0u8; MAC_LEN];
    let mac_len = URL_SAFE_NO_PAD
        .decode_slice(mac_part, &mut mac)
        .map_err(|_| Reason::Malformed)?;
    if mac_len != MAC_LEN {
        return Err(Reason::Malformed);
    }

    let mut raw = [0u8; RAW_SESSION_ID_LEN];
    let raw_len = URL_SAFE_NO_PAD
        .decode_slice(raw_part, &mut raw)
        .map_err(|_| Reason::Malformed)?;
    if raw_len != RAW_SESSION_ID_LEN {
        return Err(Reason::Malformed);
    }
    let raw_str = std::str::from_utf8(&raw).map_err(|_| Reason::Malformed)?;
    let raw_id = RawSessionId::parse(raw_str)?;
    let expected = compute_mac(secret, &raw_id, fp);
    if expected.ct_eq(&mac).into() {
        Ok(raw_id)
    } else {
        Err(Reason::MacFailed)
    }
}

/// Bind incoming/outgoing `Mcp-Session-Id` headers to `AuthIdentity`.
// cancel-safe: this middleware only rewrites request/response headers and
// performs deterministic hashing. Cancellation leaves no shared state because
// the design is deliberately stateless.
pub(crate) async fn session_binding_middleware(
    secret: SessionBindingSecret,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let identity = req.extensions().get::<AuthIdentity>().cloned();
    let Some(identity) = identity else {
        return next.run(req).await;
    };

    let request_had_session = req.headers().contains_key(session_header_name());
    if request_had_session {
        let header = req
            .headers()
            .get(session_header_name())
            .and_then(|h| h.to_str().ok());
        let Some(token) = header else {
            return reject(Reason::Malformed);
        };
        let fp = fingerprint(&identity);
        match unwrap_and_verify(&secret, token, &fp) {
            Ok(raw_id) => match HeaderValue::from_str(&raw_id.0) {
                Ok(value) => {
                    req.headers_mut().insert(session_header_name(), value);
                }
                Err(_) => return reject(Reason::Malformed),
            },
            Err(reason) => return reject(reason),
        }
    }

    let mut response = next.run(req).await;
    if !request_had_session {
        wrap_response_session(&secret, &identity, &mut response);
    }
    response
}

fn split_token(token: &str) -> Result<(&str, &str), Reason> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(VERSION), Some(raw), Some(mac), None) => Ok((raw, mac)),
        _ => Err(Reason::Malformed),
    }
}

fn compute_mac(
    secret: &SessionBindingSecret,
    raw_id: &RawSessionId,
    fp: &IdentityFingerprint,
) -> [u8; MAC_LEN] {
    type HmacSha256 = Hmac<Sha256>;

    // HMAC-SHA256 accepts keys of any length (RFC 2104), so construction
    // cannot fail for either the process-random default or configured secret.
    // Mirror the defensive re-key used by `rbac::redact_with_salt` rather
    // than unwrapping, so a future upstream contract change degrades to a
    // still-valid keyed MAC instead of a panic.
    let configured_key;
    let key = match secret {
        SessionBindingSecret::Process(bytes) => bytes.as_slice(),
        SessionBindingSecret::Configured(secret) => {
            configured_key = secret.expose_secret();
            configured_key.as_bytes()
        }
    };
    let mut mac = if let Ok(m) = HmacSha256::new_from_slice(key) {
        m
    } else {
        let digest = Sha256::digest(key);
        #[allow(
            clippy::expect_used,
            reason = "32-byte SHA-256 digest is unconditionally valid as an HMAC-SHA256 key (RFC 2104 allows any key length); see surrounding comment"
        )]
        HmacSha256::new_from_slice(&digest).expect("32-byte SHA256 digest is valid HMAC key")
    };
    mac.update(VERSION.as_bytes());
    mac.update(&[DOMAIN_SEPARATOR]);
    mac.update(raw_id.0.as_bytes());
    mac.update(&[DOMAIN_SEPARATOR]);
    mac.update(&fp.0);
    mac.finalize().into_bytes().into()
}

fn wrap_response_session(
    secret: &SessionBindingSecret,
    identity: &AuthIdentity,
    response: &mut Response,
) {
    let raw = response
        .headers()
        .get(session_header_name())
        .and_then(|h| h.to_str().ok());
    let Some(raw) = raw else {
        return;
    };
    let Ok(raw_id) = RawSessionId::parse(raw) else {
        tracing::warn!(reason = %Reason::Malformed.as_str(), "mcp session binding skipped invalid response session id");
        response.headers_mut().remove(session_header_name());
        return;
    };
    let token = wrap(secret, &raw_id, &fingerprint(identity));
    if let Ok(value) = HeaderValue::from_str(&token) {
        response.headers_mut().insert(session_header_name(), value);
    } else {
        tracing::warn!(reason = %Reason::Malformed.as_str(), "mcp session binding failed to encode response session id");
        response.headers_mut().remove(session_header_name());
    }
}

fn reject(reason: Reason) -> Response {
    tracing::warn!(reason = %reason.as_str(), "mcp session binding rejected request");
    match reason {
        Reason::Malformed | Reason::Unwrapped => {
            (StatusCode::FORBIDDEN, "invalid MCP session").into_response()
        }
        Reason::MacFailed => (StatusCode::NOT_FOUND, "unknown MCP session").into_response(),
    }
}

fn session_header_name() -> HeaderName {
    HeaderName::from_static("mcp-session-id")
}

fn is_uuid_shaped(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == RAW_SESSION_ID_LEN
        && bytes.iter().enumerate().all(|(idx, byte)| match idx {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::post,
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    const RAW_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_RAW_ID: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn test_secret(byte: u8) -> SessionBindingSecret {
        SessionBindingSecret::Process([byte; MAC_LEN])
    }

    fn test_identity(name: &str, method: AuthMethod, sub: Option<&str>) -> AuthIdentity {
        AuthIdentity {
            name: name.to_owned(),
            role: "ops".to_owned(),
            method,
            raw_token: None,
            sub: sub.map(ToOwned::to_owned),
        }
    }

    fn raw_id(value: &str) -> RawSessionId {
        RawSessionId::parse(value).expect("test raw session id must be UUID-shaped")
    }

    fn bound_token(secret: &SessionBindingSecret, identity: &AuthIdentity, raw: &str) -> String {
        wrap(secret, &raw_id(raw), &fingerprint(identity))
    }

    #[test]
    fn session_binding_secret_from_config_is_used() {
        let left = configured_session_binding_secret(&SecretString::from("x".repeat(32)))
            .expect("configured secret valid");
        let right = configured_session_binding_secret(&SecretString::from("x".repeat(32)))
            .expect("configured secret valid");
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&left, &identity, RAW_ID);

        let verified = unwrap_and_verify(&right, &token, &fingerprint(&identity))
            .expect("same configured secret verifies");

        assert_eq!(verified, raw_id(RAW_ID));
    }

    #[test]
    fn session_binding_secret_differs_from_process_secret() {
        let configured = configured_session_binding_secret(&SecretString::from("x".repeat(32)))
            .expect("configured secret valid");
        let process = process_session_binding_secret();
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let configured_token = bound_token(&configured, &identity, RAW_ID);
        let process_token = bound_token(process, &identity, RAW_ID);

        let configured_against_process =
            unwrap_and_verify(process, &configured_token, &fingerprint(&identity));
        let process_against_configured =
            unwrap_and_verify(&configured, &process_token, &fingerprint(&identity));

        assert_eq!(configured_against_process, Err(Reason::MacFailed));
        assert_eq!(process_against_configured, Err(Reason::MacFailed));
    }

    #[test]
    fn wrap_then_verify_roundtrips() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let fp = fingerprint(&identity);
        let raw = raw_id(RAW_ID);

        let token = wrap(&secret, &raw, &fp);
        let verified = unwrap_and_verify(&secret, &token, &fp).expect("token verifies");

        assert_eq!(verified, raw);
    }

    #[test]
    fn verify_rejects_other_identity() {
        let secret = test_secret(7);
        let alice = test_identity("alice", AuthMethod::BearerToken, None);
        let bob = test_identity("bob", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &alice, RAW_ID);

        let result = unwrap_and_verify(&secret, &token, &fingerprint(&bob));

        assert_eq!(result, Err(Reason::MacFailed));
    }

    #[test]
    fn verify_rejects_tampered_mac() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &identity, RAW_ID);
        let mut parts = token.split('.');
        let version = parts.next().expect("version segment");
        let raw = parts.next().expect("raw segment");
        let mac = parts.next().expect("mac segment");
        let replacement = if mac.starts_with('A') { 'B' } else { 'A' };
        let suffix = mac.get(1..).expect("base64url MAC segment is ASCII");
        let tampered = format!("{version}.{raw}.{replacement}{suffix}");

        let result = unwrap_and_verify(&secret, &tampered, &fingerprint(&identity));

        assert_eq!(result, Err(Reason::MacFailed));
    }

    #[test]
    fn verify_rejects_tampered_session_id() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &identity, RAW_ID);
        let mut parts = token.split('.');
        let version = parts.next().expect("version segment");
        let _raw = parts.next().expect("raw segment");
        let mac = parts.next().expect("mac segment");
        let tampered = format!("{version}.{}.{mac}", URL_SAFE_NO_PAD.encode(OTHER_RAW_ID));

        let result = unwrap_and_verify(&secret, &tampered, &fingerprint(&identity));

        assert_eq!(result, Err(Reason::MacFailed));
    }

    #[test]
    fn verify_rejects_unwrapped_raw_uuid() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);

        let result = unwrap_and_verify(&secret, RAW_ID, &fingerprint(&identity));

        assert_eq!(result, Err(Reason::Unwrapped));
    }

    #[test]
    fn verify_reports_mac_failure_distinctly() {
        let old_secret = test_secret(7);
        let new_secret = test_secret(9);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&old_secret, &identity, RAW_ID);

        let result = unwrap_and_verify(&new_secret, &token, &fingerprint(&identity));

        assert_eq!(result, Err(Reason::MacFailed));
    }

    #[test]
    fn decoder_rejects_oversized_and_wrong_segment_counts() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let oversized = format!("v1.{}.{}", "A".repeat(200), "A".repeat(MAC_B64_LEN));

        let oversized_result = unwrap_and_verify(&secret, &oversized, &fingerprint(&identity));
        let too_few = unwrap_and_verify(&secret, "v1.only-two", &fingerprint(&identity));
        let too_many = unwrap_and_verify(&secret, "v1.a.b.c", &fingerprint(&identity));

        assert_eq!(oversized_result, Err(Reason::Malformed));
        assert_eq!(too_few, Err(Reason::Malformed));
        assert_eq!(too_many, Err(Reason::Malformed));
    }

    #[test]
    fn verify_rejects_malformed_and_truncated_tokens() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        for token in ["", "v1.", "v1..", "v2.raw.mac", "v1.bad_base64.@@@@"] {
            let result = unwrap_and_verify(&secret, token, &fingerprint(&identity));
            assert_eq!(result, Err(Reason::Malformed), "token: {token:?}");
        }
    }

    #[test]
    fn fingerprint_distinguishes_auth_methods() {
        let api = test_identity("alice", AuthMethod::BearerToken, None);
        let mtls = test_identity("alice", AuthMethod::MtlsCertificate, None);

        assert_ne!(fingerprint(&api), fingerprint(&mtls));
    }

    #[test]
    fn fingerprint_oauth_prefers_sub_over_name() {
        let first = test_identity("preferred-a", AuthMethod::OAuthJwt, Some("stable-sub"));
        let second = test_identity("preferred-b", AuthMethod::OAuthJwt, Some("stable-sub"));

        assert_eq!(fingerprint(&first), fingerprint(&second));
    }

    #[test]
    fn fingerprint_oauth_falls_back_to_name_without_sub() {
        let first = test_identity("client-a", AuthMethod::OAuthJwt, None);
        let second = test_identity("client-b", AuthMethod::OAuthJwt, None);

        assert_ne!(fingerprint(&first), fingerprint(&second));
    }

    #[test]
    fn mac_is_full_length() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &identity, RAW_ID);
        let mac_segment = token
            .split('.')
            .nth(2)
            .expect("wrapped token carries a MAC segment");
        let mut mac = [0u8; MAC_LEN];

        let len = URL_SAFE_NO_PAD
            .decode_slice(mac_segment, &mut mac)
            .expect("MAC segment decodes");

        assert_eq!(len, MAC_LEN);
    }

    fn router_with_identity(
        secret: SessionBindingSecret,
        identity: Option<AuthIdentity>,
    ) -> Router {
        async fn echo_session(headers: axum::http::HeaderMap) -> String {
            headers
                .get(session_header_name())
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing")
                .to_owned()
        }

        async fn mint_session() -> Response {
            let mut response = StatusCode::OK.into_response();
            response
                .headers_mut()
                .insert(session_header_name(), HeaderValue::from_static(RAW_ID));
            response
        }

        let router = Router::new()
            .route("/echo", post(echo_session))
            .route("/mint", post(mint_session))
            .layer(middleware::from_fn(move |req, next| {
                let secret = secret.clone();
                session_binding_middleware(secret, req, next)
            }));
        match identity {
            Some(id) => router.layer(middleware::from_fn(
                move |mut req: Request<Body>, next: Next| {
                    let id = id.clone();
                    async move {
                        req.extensions_mut().insert(id);
                        next.run(req).await
                    }
                },
            )),
            None => router,
        }
    }

    async fn post_with_session(router: Router, uri: &str, session: Option<&str>) -> Response {
        let mut builder = Request::builder().method("POST").uri(uri);
        if let Some(session) = session {
            builder = builder.header(session_header_name(), session);
        }
        let request = builder.body(Body::empty()).expect("test request builds");
        router.oneshot(request).await.expect("router responds")
    }

    #[tokio::test]
    async fn session_binding_middleware_request_without_header_passes_through() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let router = router_with_identity(secret, Some(identity));

        let response = post_with_session(router, "/echo", None).await;
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();

        assert_eq!(body, "missing");
    }

    #[tokio::test]
    async fn session_binding_middleware_response_minting_session_gets_wrapped_header() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let router = router_with_identity(secret, Some(identity));

        let response = post_with_session(router, "/mint", None).await;
        let header = response
            .headers()
            .get(session_header_name())
            .expect("session response header")
            .to_str()
            .expect("wrapped session is ascii");

        assert_ne!(header, RAW_ID);
        assert!(header.starts_with("v1."));
    }

    #[tokio::test]
    async fn session_binding_middleware_same_identity_rewrites_header_to_raw() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &identity, RAW_ID);
        let router = router_with_identity(secret, Some(identity));

        let response = post_with_session(router, "/echo", Some(&token)).await;
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();

        assert_eq!(body, RAW_ID);
    }

    #[tokio::test]
    async fn session_binding_middleware_different_identity_returns_404() {
        let secret = test_secret(7);
        let alice = test_identity("alice", AuthMethod::BearerToken, None);
        let bob = test_identity("bob", AuthMethod::BearerToken, None);
        let token = bound_token(&secret, &alice, RAW_ID);
        let router = router_with_identity(secret, Some(bob));

        let response = post_with_session(router, "/echo", Some(&token)).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn session_binding_middleware_stale_secret_returns_404() {
        let old_secret = test_secret(7);
        let new_secret = test_secret(9);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let token = bound_token(&old_secret, &identity, RAW_ID);
        let router = router_with_identity(new_secret, Some(identity));

        let response = post_with_session(router, "/echo", Some(&token)).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn session_binding_middleware_raw_unwrapped_uuid_returns_403() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let router = router_with_identity(secret, Some(identity));

        let response = post_with_session(router, "/echo", Some(RAW_ID)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn session_binding_middleware_malformed_token_returns_403() {
        let secret = test_secret(7);
        let identity = test_identity("alice", AuthMethod::BearerToken, None);
        let router = router_with_identity(secret, Some(identity));

        let response = post_with_session(router, "/echo", Some("malformed")).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn session_binding_middleware_no_auth_identity_passes_through_unmodified() {
        let secret = test_secret(7);
        let router = router_with_identity(secret, None);

        let response = post_with_session(router, "/echo", Some(RAW_ID)).await;
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();

        assert_eq!(body, RAW_ID);
    }
}
