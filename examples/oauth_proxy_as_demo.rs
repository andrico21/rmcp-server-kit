//! Authorization-server proxy demo with an in-process fake identity provider.
//!
//! Starts two loopback listeners in one process:
//!
//! - a fake upstream identity provider on an ephemeral port that issues
//!   RS256 access tokens after an S256 PKCE check, and
//! - an MCP server (one `echo` tool) whose OAuth proxy runs in
//!   `authorization_server` mode in front of that provider: dynamic client
//!   registration, a consent page, `/oauth/callback` and `/token`.
//!
//! Requires the `oauth` Cargo feature. Run with:
//!
//! ```bash
//! RMCP_DEMO_PORT=8080 cargo run --example oauth_proxy_as_demo --features oauth
//! ```
//!
//! The startup log prints copy-paste `curl` commands for every step of the
//! flow. `consent_ttl` is `0s`, so the consent page is shown on every
//! `/authorize` and no remembered-consent cookie is ever issued; approve it
//! in a browser, or with `curl` by posting the hidden `request` value back
//! to `/oauth/consent` together with the `rmcp_csrf_*` cookie of the page.
//!
//! Everything here is demo-only: the sealing secret is a fixed public
//! string, the provider signs a token for anyone who completes PKCE, and
//! both listeners bind to `127.0.0.1` only.
extern crate alloc;

use alloc::sync::Arc;
use core::{future::ready, num::NonZeroU16};
use std::{
    collections::HashMap,
    env::{self, VarError},
    io,
    sync::{Mutex, PoisonError},
};

use anyhow::Context as _;
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rmcp::{
    ErrorData,
    handler::server::ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    service::{MaybeSendFuture, RequestContext, RoleServer},
};
use rmcp_server_kit::{
    auth::AuthConfig,
    config::ObservabilityConfig,
    oauth::{OAuthConfig, OAuthProxyConfig, OAuthSsrfAllowlist, ProxyMode},
    observability::init_tracing_from_config_strict,
    rbac::{RbacConfig, RbacPolicy, RoleConfig},
    secret::SecretString,
    transport::{McpServerConfig, serve},
};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey as _, LineEnding},
    rand_core::OsRng,
    traits::PublicKeyParts as _,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::{
    net::TcpListener,
    task::{JoinHandle, spawn_blocking},
};

/// Audience the fake provider stamps into every access token.
const AUDIENCE: &str = "mcp-demo";
/// Static client id the proxy presents to the fake provider.
const UPSTREAM_CLIENT_ID: &str = "demo-upstream-client";
/// Key id published in the fake provider's JWKS.
const KEY_ID: &str = "demo-idp-key";
/// Fixed, public, demo-only sealing secret (at least 32 bytes).
const DEMO_SEALING_SECRET: &str = "demo-only-sealing-secret-never-use-in-production";
/// Upper bound on unredeemed authorization codes held by the fake provider.
const MAX_PENDING_CODES: usize = 256;
/// Redirect URI a demo client registers; nothing needs to listen on it.
const CLIENT_REDIRECT: &str = "http://127.0.0.1:18999/cb";
/// RFC 7636 Appendix B verifier, a public test vector.
const DEMO_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// RFC 7636 Appendix B S256 challenge of [`DEMO_VERIFIER`].
const DEMO_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// MCP handler exposing a single `echo` tool.
#[derive(Clone)]
struct DemoHandler;

impl ServerHandler for DemoHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + MaybeSendFuture + '_ {
        let mut schema = JsonObject::new();
        drop(schema.insert("type".into(), json!("object")));
        drop(schema.insert("properties".into(), json!({"message": {"type": "string"}})));
        let echo = Tool::new("echo", "Return the message argument.", Arc::new(schema));
        ready(Ok(ListToolsResult::with_all_items(vec![echo])))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + MaybeSendFuture + '_ {
        let message = request
            .arguments
            .as_ref()
            .and_then(|arguments| arguments.get("message"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        ready(if request.name == "echo" {
            Ok(CallToolResult::success(vec![ContentBlock::text(message.to_owned())]).into())
        } else {
            Err(ErrorData::invalid_params("unknown tool", None))
        })
    }
}

/// An issued authorization code awaiting redemption.
struct PendingCode {
    /// S256 `code_challenge` received on `/authorize`.
    challenge: String,
    /// `redirect_uri` the code was delivered to.
    redirect_uri: String,
}

/// Shared state of the fake upstream identity provider.
struct FakeIdp {
    /// Issuer URL, using the `localhost` hostname the kit requires.
    issuer: String,
    /// The only `redirect_uri` accepted: the proxy's `/oauth/callback`.
    callback: String,
    /// Unredeemed codes; the lock is never held across an `.await`.
    pending: Mutex<HashMap<String, PendingCode>>,
    /// RS256 key generated at startup.
    signing_key: EncodingKey,
    /// Public half of `signing_key` as a JWKS document.
    jwks: Value,
}

/// Query parameters the fake provider reads on `/authorize`.
#[derive(Deserialize)]
struct AuthorizeQuery {
    /// Upstream client id; must be [`UPSTREAM_CLIENT_ID`].
    client_id: String,
    /// Must equal the proxy callback.
    redirect_uri: String,
    /// Opaque state echoed back unchanged.
    state: String,
    /// PKCE challenge stored with the issued code.
    code_challenge: String,
    /// Must be `S256`.
    code_challenge_method: String,
}

/// Form fields the fake provider reads on `/token`.
#[derive(Deserialize)]
struct TokenForm {
    /// Only `authorization_code` is supported.
    grant_type: String,
    /// Code issued by `/authorize`.
    code: String,
    /// Must match the `redirect_uri` the code was issued for.
    redirect_uri: String,
    /// PKCE verifier checked against the stored challenge.
    code_verifier: String,
}

/// A running fake provider and the task serving it.
struct RunningIdp {
    /// Issuer URL handed to the kit.
    issuer: String,
    /// Serving task, aborted when the MCP server stops.
    task: JoinHandle<io::Result<()>>,
}

/// Build an RFC 6749 JSON error body.
fn idp_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

/// Generate 256 random bits in the URL-safe base64 alphabet.
fn random_code() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Store the challenge under a fresh code and redirect back with `code`, `state` and `iss`.
// cancel-safe: synchronous body; the code map lock is released before the response is built.
async fn idp_authorize(
    State(idp): State<Arc<FakeIdp>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    if query.client_id != UPSTREAM_CLIENT_ID
        || query.redirect_uri != idp.callback
        || query.code_challenge_method != "S256"
        || query.code_challenge.is_empty()
    {
        return idp_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let code = random_code();
    let stored = {
        let mut pending = idp.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let room = pending.len() < MAX_PENDING_CODES;
        if room {
            let entry = PendingCode {
                challenge: query.code_challenge,
                redirect_uri: query.redirect_uri.clone(),
            };
            drop(pending.insert(code.clone(), entry));
        }
        room
    };
    if !stored {
        return idp_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let Ok(mut target) = url::Url::parse(&query.redirect_uri) else {
        return idp_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    {
        let mut pairs = target.query_pairs_mut();
        let _pairs = pairs
            .append_pair("code", &code)
            .append_pair("state", &query.state)
            .append_pair("iss", &idp.issuer);
    }
    (StatusCode::FOUND, [(header::LOCATION, target.to_string())]).into_response()
}

/// Redeem a code once after verifying the PKCE verifier and the redirect URI.
// cancel-safe: synchronous body; the code is removed under a lock released before signing.
async fn idp_token(State(idp): State<Arc<FakeIdp>>, Form(form): Form<TokenForm>) -> Response {
    if form.grant_type != "authorization_code" {
        return idp_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let removed = idp
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&form.code);
    let Some(pending) = removed else {
        return idp_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(form.code_verifier.as_bytes()));
    if !bool::from(computed.as_bytes().ct_eq(pending.challenge.as_bytes()))
        || form.redirect_uri != pending.redirect_uri
    {
        return idp_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    match mint_access_token(&idp) {
        Ok(token) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"access_token": token, "token_type": "Bearer", "expires_in": 300_u64})),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "fake identity provider could not sign a token");
            idp_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// Serve the public signing key.
// cancel-safe: returns a clone of immutable state.
async fn idp_jwks(State(idp): State<Arc<FakeIdp>>) -> Json<Value> {
    Json(idp.jwks.clone())
}

/// Sign the demo access token the kit validates against the JWKS.
///
/// # Errors
/// Returns an error if JWT encoding fails.
fn mint_access_token(idp: &FakeIdp) -> anyhow::Result<String> {
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(KEY_ID.to_owned());
    let now = jsonwebtoken::get_current_timestamp();
    let claims = json!({
        "iss": idp.issuer, "aud": AUDIENCE, "sub": "demo-user", "scope": "mcp:read",
        "iat": now, "exp": now.saturating_add(300),
    });
    jsonwebtoken::encode(&jwt_header, &claims, &idp.signing_key).context("JWT signing")
}

/// Generate the provider's RS256 key pair and its public JWKS document.
///
/// # Errors
/// Returns an error if key generation or PEM export fails.
fn generate_signing_key() -> anyhow::Result<(EncodingKey, Value)> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).context("RSA key generation")?;
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("PKCS#8 export")?;
    let signing_key = EncodingKey::from_rsa_pem(pem.as_bytes()).context("signing key")?;
    let public_key = private_key.to_public_key();
    let jwks = json!({"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KEY_ID,
        "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    }]});
    Ok((signing_key, jwks))
}

/// Bind the fake provider to an ephemeral loopback port and start serving it.
///
/// # Errors
/// Returns an error if key generation or the loopback bind fails.
// cancel-safe: dropping the future before the spawn releases the listener; nothing else is shared.
async fn start_fake_idp(callback: String) -> anyhow::Result<RunningIdp> {
    let (signing_key, jwks) = spawn_blocking(generate_signing_key)
        .await
        .context("key generation task")??;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind fake identity provider")?;
    let issuer = format!("http://localhost:{}", listener.local_addr()?.port());
    let idp = Arc::new(FakeIdp {
        issuer: issuer.clone(),
        callback,
        pending: Mutex::default(),
        signing_key,
        jwks,
    });
    let router = Router::new()
        .route("/authorize", get(idp_authorize))
        .route("/token", post(idp_token))
        .route("/jwks.json", get(idp_jwks))
        .with_state(idp);
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(RunningIdp { issuer, task })
}

/// Point the kit's OAuth proxy at the fake provider in `authorization_server` mode.
fn oauth_config(issuer: &str) -> OAuthConfig {
    let mut allowlist = OAuthSsrfAllowlist::default();
    allowlist.hosts.push("localhost".into());
    allowlist.cidrs.push("127.0.0.0/8".into());
    let proxy = OAuthProxyConfig::builder(
        format!("{issuer}/authorize"),
        format!("{issuer}/token"),
        UPSTREAM_CLIENT_ID,
    )
    .mode(ProxyMode::AuthorizationServer)
    .sealing_secret(SecretString::from(DEMO_SEALING_SECRET.to_owned()))
    .consent_ttl("0s".to_owned())
    .build();
    OAuthConfig::builder(issuer, AUDIENCE, format!("{issuer}/jwks.json"))
        .scope("mcp:read", "viewer")
        .allow_http_oauth_urls(true)
        .ssrf_allowlist(allowlist)
        .proxy(proxy)
        .build()
}

/// Read `RMCP_DEMO_PORT`, defaulting to 8080.
///
/// # Errors
/// Returns an error if the variable is set but is not a nonzero port number.
fn demo_port() -> anyhow::Result<u16> {
    match env::var("RMCP_DEMO_PORT") {
        Ok(raw) => raw
            .parse::<NonZeroU16>()
            .map(NonZeroU16::get)
            .with_context(|| format!("RMCP_DEMO_PORT {raw:?} is not a port number")),
        Err(VarError::NotPresent) => Ok(8080),
        Err(VarError::NotUnicode(_)) => anyhow::bail!("RMCP_DEMO_PORT is not valid UTF-8"),
    }
}

/// Log the endpoints and a copy-paste walkthrough of the whole flow.
fn log_walkthrough(public_url: &str, issuer: &str) {
    tracing::info!(issuer = %issuer, jwks_uri = %format!("{issuer}/jwks.json"), "fake identity provider listening on loopback");
    tracing::warn!(
        "oauth.proxy.sealing_secret is a fixed, public, demo-only value; never reuse it outside this example"
    );
    let ru = "http%3A%2F%2F127.0.0.1%3A18999%2Fcb";
    let authorize = format!(
        "{public_url}/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri={ru}&scope=mcp%3Aread&state=demo-state&code_challenge={DEMO_CHALLENGE}&code_challenge_method=S256"
    );
    let steps = [
        format!(
            "curl -s -X POST {public_url}/register -H 'content-type: application/json' -d '{{\"redirect_uris\":[\"{CLIENT_REDIRECT}\"],\"client_name\":\"demo\"}}'"
        ),
        format!("open in a browser, or: curl -si '{authorize}'"),
        format!(
            "curl -si -X POST {public_url}/oauth/consent -H 'cookie: <RMCP_CSRF_COOKIE>' -H 'content-type: application/x-www-form-urlencoded' -d 'request=<HIDDEN_REQUEST>&decision=approve'"
        ),
        "curl -si '<LOCATION_OF_THE_APPROVAL>'".to_owned(),
        "curl -si '<LOCATION_FROM_THE_IDENTITY_PROVIDER>' -H 'cookie: <RMCP_STATE_COOKIE>'"
            .to_owned(),
        format!(
            "curl -s -X POST {public_url}/token -d grant_type=authorization_code -d client_id=<CLIENT_ID> -d code=<CODE> -d redirect_uri={CLIENT_REDIRECT} -d code_verifier={DEMO_VERIFIER}"
        ),
        format!(
            "curl -si -X POST {public_url}/mcp -H 'authorization: Bearer <ACCESS_TOKEN>' -H 'accept: application/json, text/event-stream' -H 'content-type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"demo\",\"version\":\"1\"}}}}}}'"
        ),
    ];
    for (step, command) in (1_u8..).zip(steps) {
        tracing::info!(step, command = %command, "walkthrough");
    }
}

// cancel-safe: process entry point; dropping this future tears down both listeners and the runtime.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let mut observability = ObservabilityConfig::default();
    observability.log_level = "info,rmcp_server_kit=debug".into();
    let _tracing_guard = init_tracing_from_config_strict(&observability)?;

    let port = demo_port()?;
    let public_url = format!("http://127.0.0.1:{port}");
    let idp = start_fake_idp(format!("{public_url}/oauth/callback")).await?;
    log_walkthrough(&public_url, &idp.issuer);

    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth_config(&idp.issuer));
    let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()]),
    ])));
    let config = McpServerConfig::new(
        format!("127.0.0.1:{port}"),
        "rmcp-server-kit-oauth-proxy-as-demo",
        env!("CARGO_PKG_VERSION"),
    )
    .with_auth(auth)
    .with_rbac(rbac)
    .with_public_url(public_url);

    let served = serve(config.validate()?, || DemoHandler).await;
    idp.task.abort();
    served.context("MCP server")
}
