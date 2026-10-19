//! Stateless authorization-server registration and browser consent boundary.
// allow: SIZE_OK - the sealed payload types and the handlers form one security boundary, so they stay in one module.

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};
use core::time::Duration;

use axum::{
    Json, Router,
    body::{Bytes, to_bytes},
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::from_fn,
    response::{Html, IntoResponse as _, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use url::{Url, form_urlencoded};

use crate::{
    RmcpServerKitError,
    oauth::{
        OAuthConfig, OAuthProxyConfig, OauthHttpClient, authorization_server_metadata,
        is_rfc6750_scope_token, relay_token_request,
    },
    oauth_seal::{SealKind, Sealer, now_unix, sha256_b64},
    transport::{PageSecurityHeaders, oauth_token_cache_headers_middleware},
};

/// Script-free consent page policy, allowing upstream form redirect chains.
const CONSENT_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
/// Error pages cannot initiate form submissions.
const ERROR_CSP: &str =
    "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
/// Aggregate encoded parameter cap before allocation and sealing.
const PARAM_LIMIT: usize = 0x8000;

/// Immutable configuration and cryptographic context for browser authorization.
struct AsState {
    /// Purpose-separated signing and verification keys.
    sealer: Sealer,
    /// Configured static upstream client.
    proxy: OAuthProxyConfig,
    /// Parsed, serialized facade issuer without its trailing slash.
    issuer_url: String,
    /// Operator-supplied display name, escaped only at HTML rendering.
    server_name: String,
    /// Require secure host-only cookies for HTTPS issuers.
    cookie_secure: bool,
    /// First eight hexadecimal digest characters isolating issuers on one host.
    cookie_suffix: String,
    /// Browser approval lifetime, with zero disabling remembered approval.
    consent_ttl: Duration,
    /// Exact upstream issuer accepted on authorization responses.
    upstream_issuer: String,
    /// Shared screened upstream connection pool.
    http: OauthHttpClient,
}

/// Integrity-protected downstream registration with compact wire member names.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientReg {
    /// Exact registered return addresses.
    ru: Vec<String>,
    /// Unverified application display name.
    #[serde(rename = "n")]
    name: Option<String>,
    /// Issuance time in Unix seconds.
    iat: u64,
}

/// Pending approval bound to the browser's unpredictable CSRF nonce.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentRequest {
    /// Digest of the sealed downstream client identifier.
    cid: String,
    /// Exact validated return address.
    ru: String,
    /// Downstream state echoed only to its registered return address.
    st: Option<String>,
    /// Approved S256 challenge.
    cc: String,
    /// Sorted unique requested scope tokens.
    sc: Vec<String>,
    /// Validated resource indicators.
    rs: Vec<String>,
    /// Explicitly allowlisted upstream authorization hints.
    ex: Vec<(String, String)>,
    /// Digest of the browser's CSRF cookie value.
    csrf: String,
    /// Expiration time in Unix seconds.
    exp: u64,
}

/// Approved downstream transaction stored only in its per-flow browser cookie.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowState {
    /// Downstream client identifier digest.
    cid: String,
    /// Exact approved return address.
    ru: String,
    /// Downstream state to echo after the callback.
    st: Option<String>,
    /// Approved PKCE challenge.
    cc: String,
    /// Digest of the upstream state nonce.
    nh: String,
    /// Expiration time in Unix seconds.
    exp: u64,
}

/// Short-lived upstream authorization code with approved downstream bindings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeWrap {
    /// Upstream authorization code.
    kc: String,
    /// Digest of the redeeming downstream registration.
    cid: String,
    /// Exact approved redirect URI.
    ru: String,
    /// Approved S256 challenge.
    cc: String,
    /// Exclusive redemption deadline in Unix seconds.
    exp: u64,
}

/// Upstream refresh credential bound to its downstream client.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshWrap {
    /// Upstream refresh credential, bounded to 4096 bytes.
    rt: String,
    /// Downstream registration digest retained across rotations.
    cid: String,
}

/// Browser approvals in most-recently-used order.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentSet {
    /// At most twenty unexpired approvals, further limited by sealed size.
    #[serde(rename = "e")]
    entries: Vec<ConsentEntry>,
}

/// Client-scoped approval recorded in a browser profile, not an IdP account.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentEntry {
    /// First twenty-two characters of the client identifier digest.
    #[serde(rename = "c")]
    client: String,
    /// Sorted unique previously approved scopes.
    #[serde(rename = "s")]
    scopes: Vec<String>,
    /// Expiration time in Unix seconds.
    #[serde(rename = "x")]
    expires: u64,
}

/// Registration input; unsupported metadata is intentionally ignored and replaced.
#[derive(Deserialize)]
struct Registration {
    /// Requested exact return addresses.
    redirect_uris: Vec<String>,
    /// Optional unverified display name.
    client_name: Option<String>,
}

/// Install the stateless authorization-server facade without changing passthrough helpers.
///
/// # Errors
/// Returns a configuration error for missing secrets or an unusable issuer URL.
pub(crate) fn install_routes(
    oauth: &OAuthConfig,
    issuer_url: &str,
    server_name: &str,
) -> Result<Router, RmcpServerKitError> {
    let proxy = oauth
        .proxy
        .as_ref()
        .ok_or_else(|| RmcpServerKitError::Config("oauth.proxy is required".into()))?;
    let secret = proxy.sealing_secret.as_ref().ok_or_else(|| {
        RmcpServerKitError::Config("oauth.proxy.sealing_secret is required".into())
    })?;
    let issuer = Url::parse(issuer_url)
        .map_err(|_error| RmcpServerKitError::Config("oauth proxy issuer URL is invalid".into()))?;
    let canonical_issuer = issuer.as_str().trim_end_matches('/').to_owned();
    let digest = Sha256::digest(canonical_issuer.as_bytes());
    let suffix = digest
        .iter()
        .take(4)
        .fold(String::new(), |mut output, byte| {
            output.push(char::from(
                b"0123456789abcdef"
                    .get(usize::from(byte >> 4_u8))
                    .copied()
                    .unwrap_or(b'0'),
            ));
            output.push(char::from(
                b"0123456789abcdef"
                    .get(usize::from(byte & 15))
                    .copied()
                    .unwrap_or(b'0'),
            ));
            output
        });
    let state = Arc::new(AsState {
        sealer: Sealer::new(secret, proxy.sealing_secret_previous.as_ref()),
        proxy: proxy.clone(),
        issuer_url: canonical_issuer,
        server_name: server_name.to_owned(),
        cookie_secure: issuer.scheme() == "https",
        cookie_suffix: suffix,
        consent_ttl: proxy.effective_consent_ttl(),
        upstream_issuer: oauth.issuer.clone(),
        http: OauthHttpClient::with_config(oauth)?,
    });
    let mut metadata = authorization_server_metadata(&state.issuer_url, oauth);
    if let Some(object) = metadata.as_object_mut() {
        drop(object.insert(
            "authorization_response_iss_parameter_supported".into(),
            serde_json::Value::Bool(true),
        ));
    }
    Ok(Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let document = metadata.clone();
                async move { Json(document) }
            }),
        )
        .route(
            "/register",
            post(register).layer(from_fn(oauth_token_cache_headers_middleware)),
        )
        .route("/authorize", get(authorize))
        .route("/oauth/consent", post(consent))
        .route("/oauth/callback", get(callback))
        .route(
            "/token",
            post(token).layer(from_fn(oauth_token_cache_headers_middleware)),
        )
        .with_state(state))
}

/// Construct the admin adapter's purpose-separated current and rotation keys.
///
/// # Errors
/// Returns a configuration error if the required AS secret is absent.
pub(crate) fn admin_sealer(proxy: &OAuthProxyConfig) -> Result<Sealer, RmcpServerKitError> {
    let secret = proxy.sealing_secret.as_ref().ok_or_else(|| {
        RmcpServerKitError::Config("oauth.proxy.sealing_secret is required".into())
    })?;
    Ok(Sealer::new(secret, proxy.sealing_secret_previous.as_ref()))
}

/// Encode every HTML metacharacter before interpolation into text or attributes.
fn html_escape(value: &str) -> String {
    value.chars().fold(String::new(), |mut output, ch| {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            other => output.push(other),
        }
        output
    })
}

/// Wrap already escaped markup and request mandatory page-only security headers.
fn page(status: StatusCode, content: &str, csp: &'static str) -> Response {
    let mut response = (status, Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"same-origin\"><title>Authorization</title></head><body>{content}</body></html>"
    ))).into_response();
    let _previous = response
        .extensions_mut()
        .insert(PageSecurityHeaders::new(csp));
    response
}

/// Log a content-free rejection reason and return a nonredirecting error page.
fn rejected(reason: &'static str, integrity: bool) -> Response {
    if integrity {
        tracing::warn!(reason, "oauth authorization-server request rejected");
    } else {
        tracing::debug!(reason, "oauth authorization-server request rejected");
    }
    page(
        StatusCode::BAD_REQUEST,
        "<h1>Authorization request rejected</h1>",
        ERROR_CSP,
    )
}

/// Return an RFC 7591 metadata error without reflecting the rejected input.
fn registration_error(code: &'static str) -> Response {
    tracing::debug!(reason = code, "oauth authorization-server request rejected");
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error":code,"error_description":"Invalid client registration metadata"
        })),
    )
        .into_response()
}

/// Parse a bounded web callback without userinfo, fragments or parser control bytes.
fn redirect_uri(value: &str) -> Option<Url> {
    if value.len() > 512
        || value
            .chars()
            .any(|ch| ch.is_control() || is_spoofing_char(ch))
        || value.contains('\\')
    {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let permitted = match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => loopback(&url),
        _ => false,
    };
    permitted.then_some(url)
}

/// Recognize the three explicitly permitted local callback hosts.
fn loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// Report whether a character can hide, reorder or visually fake neighbouring text.
///
/// The set is the Unicode `Default_Ignorable_Code_Point` property minus the variation
/// selector blocks U+FE00 to U+FE0F and U+E0100 to U+E01EF, plus the invisible characters
/// that are not default ignorable: U+2028, U+2029, U+2800 and U+FFF9 to U+FFFB. It includes
/// the bidirectional controls, the zero-width and invisible formatting characters, the
/// Hangul and Khmer fillers and the tag characters. Letters of right-to-left scripts are
/// not in this set.
///
/// Trade-offs: the variation selectors stay accepted so that emoji such as a heart with
/// U+FE0F remain valid. The zero-width joiner is rejected, so joined emoji sequences are
/// not accepted; tag-sequence flags such as the flag of England are rejected with the tag
/// characters; and the Mongolian free variation selectors U+180B to U+180D and U+180F are
/// rejected.
const fn is_spoofing_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E00FF}'
            | '\u{E01F0}'..='\u{E0FFF}'
    )
}

/// Register a public downstream client without retaining server-side state.
// cancel-safe: body extraction completes before this synchronous, stateless response construction.
async fn register(State(state): State<Arc<AsState>>, body: Bytes) -> Response {
    let Ok(input) = serde_json::from_slice::<Registration>(&body) else {
        return registration_error("invalid_client_metadata");
    };
    if !(1..=5).contains(&input.redirect_uris.len())
        || input.redirect_uris.iter().map(String::len).sum::<usize>() > 2048
        || input
            .redirect_uris
            .iter()
            .any(|value| redirect_uri(value).is_none())
    {
        return registration_error("invalid_redirect_uri");
    }
    if input.client_name.as_ref().is_some_and(|name| {
        name.chars().count() > 128
            || name
                .chars()
                .any(|ch| ch.is_control() || is_spoofing_char(ch))
    }) {
        return registration_error("invalid_client_metadata");
    }
    let client = ClientReg {
        ru: input.redirect_uris,
        name: input.client_name,
        iat: now_unix(),
    };
    let Ok(cid) = state.sealer.seal(SealKind::Client, &client) else {
        return rejected("registration_seal", true);
    };
    let mut output = serde_json::json!({
        "client_id":cid,"client_id_issued_at":client.iat,"redirect_uris":client.ru,
        "token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],
        "response_types":["code"]
    });
    if let Some(name) = client.name
        && let Some(object) = output.as_object_mut()
    {
        drop(object.insert("client_name".into(), serde_json::Value::String(name)));
    }
    (StatusCode::CREATED, Json(output)).into_response()
}

/// Parse bounded form pairs and reject repeated singleton names.
///
/// # Errors
/// Returns a stable reason code for oversized or ambiguous input.
fn parameters(raw: &str, resources: bool) -> Result<Vec<(String, String)>, &'static str> {
    if raw.len() > PARAM_LIMIT {
        return Err("parameters_too_long");
    }
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();
    for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
        if !(seen.insert(name.clone().into_owned()) || resources && name == "resource") {
            return Err("repeated_parameter");
        }
        pairs.push((name.into_owned(), value.into_owned()));
    }
    Ok(pairs)
}

/// Borrow the sole value of a name after duplicate rejection.
fn param<'pairs>(pairs: &'pairs [(String, String)], key: &str) -> Option<&'pairs str> {
    pairs
        .iter()
        .find(|(name, _value)| name == key)
        .map(|(_name, value)| value.as_str())
}

/// Redirect protocol errors only after client and exact return-address validation.
fn client_error(state: &AsState, request: &ConsentRequest, code: &str) -> Response {
    tracing::debug!(reason = code, "oauth authorization-server request rejected");
    let Ok(mut url) = Url::parse(&request.ru) else {
        return rejected("redirect_uri", false);
    };
    {
        let mut query = url.query_pairs_mut();
        let _pairs = query
            .append_pair("error", code)
            .append_pair("iss", &state.issuer_url);
        if let Some(value) = &request.st {
            let _pair = query.append_pair("state", value);
        }
    }
    redirect(&url)
}

/// Serialize a parsed URL into a header without permitting header injection.
fn redirect(url: &Url) -> Response {
    match HeaderValue::from_str(url.as_str()) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_error) => rejected("location", false),
    }
}

/// Validate the downstream transaction before rendering or bypassing consent.
// cancel-safe: no suspension or shared mutable state; cookies are returned atomically with the response.
async fn authorize(
    State(state): State<Arc<AsState>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let pairs = match parameters(query.as_deref().unwrap_or_default(), true) {
        Ok(pairs) => pairs,
        Err(reason) => return rejected(reason, false),
    };
    let Some(cid) = param(&pairs, "client_id") else {
        return rejected("client_id", false);
    };
    let Ok(client) = state.sealer.open::<ClientReg>(SealKind::Client, cid) else {
        return rejected("client_seal", true);
    };
    let Some(ru) =
        param(&pairs, "redirect_uri").filter(|ru| client.ru.iter().any(|entry| entry == ru))
    else {
        return rejected("redirect_uri", false);
    };
    if redirect_uri(ru).is_none() {
        return rejected("redirect_uri", false);
    }
    let mut request = ConsentRequest {
        cid: sha256_b64(cid),
        ru: ru.to_owned(),
        st: param(&pairs, "state").map(str::to_owned),
        cc: param(&pairs, "code_challenge")
            .unwrap_or_default()
            .to_owned(),
        sc: Vec::new(),
        rs: Vec::new(),
        ex: Vec::new(),
        csrf: String::new(),
        exp: now_unix().saturating_add(600),
    };
    if param(&pairs, "response_type") != Some("code") {
        return client_error(&state, &request, "unsupported_response_type");
    }
    if param(&pairs, "code_challenge_method") != Some("S256") || !valid_challenge(&request.cc) {
        return client_error(&state, &request, "invalid_request");
    }
    if fill_request(&mut request, &pairs).is_err() {
        return client_error(&state, &request, "invalid_request");
    }
    let mut consent = state.consent_set(&headers);
    if !state.consent_ttl.is_zero()
        && consent.entries.iter().any(|entry| {
            entry.client == short(&request.cid, 22)
                && request.sc.iter().all(|scope| entry.scopes.contains(scope))
        })
    {
        state.remember(&mut consent, &request);
        return state.approved(&request, Some(&mut consent));
    }
    let nonce = nonce();
    request.csrf = sha256_b64(&nonce);
    let Ok(token) = state.sealer.seal(SealKind::ConsentRequest, &request) else {
        return rejected("consent_seal", true);
    };
    let mut response = consent_page(&state, &client, &request, &token);
    state.set_cookie(
        &mut response,
        &state.cookie_name("csrf", Some(&request.csrf)),
        &nonce,
        600,
    );
    response
}

/// Check the RFC 7636 unreserved challenge alphabet and length.
fn valid_challenge(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
}

/// Populate bounded scopes, resources and allowlisted upstream hints.
///
/// # Errors
/// Returns unit when any protocol field exceeds its boundary contract.
fn fill_request(request: &mut ConsentRequest, pairs: &[(String, String)]) -> Result<(), ()> {
    (request.st.as_ref().is_none_or(|state| state.len() <= 512)).ok_or(())?;
    let scope = param(pairs, "scope").unwrap_or_default();
    (scope.len() <= 512).ok_or(())?;
    request.sc = scope
        .split(' ')
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect();
    request
        .sc
        .iter()
        .all(|token| is_rfc6750_scope_token(token))
        .ok_or(())?;
    request.sc.sort();
    request.sc.dedup();
    for (name, value) in pairs {
        match name.as_str() {
            "resource" => {
                (request.rs.len() < 2
                    && value.len() <= 256
                    && Url::parse(value).is_ok_and(|url| url.fragment().is_none()))
                .ok_or(())?;
                request.rs.push(value.clone());
            }
            "prompt" | "login_hint" | "ui_locales" => {
                (value.len() <= 128).ok_or(())?;
                request.ex.push((name.clone(), value.clone()));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Render every untrusted display value as escaped text without active content.
fn consent_page(
    state: &AsState,
    client: &ClientReg,
    request: &ConsentRequest,
    token: &str,
) -> Response {
    let name = client.name.as_ref().map_or_else(
        || "An unnamed application".to_owned(),
        |value| {
            format!(
                "<bdi>{}</bdi> (name supplied by the application, not verified)",
                html_escape(value)
            )
        },
    );
    let url = redirect_uri(&request.ru);
    let host = url.as_ref().and_then(Url::host_str).unwrap_or_default();
    let local = if url.as_ref().is_some_and(loopback) {
        "<p>This application runs on your computer. Approve only if you just started this sign-in yourself.</p>"
    } else {
        ""
    };
    let scopes = if request.sc.is_empty() {
        "<p>default access</p>".to_owned()
    } else {
        format!(
            "<ul>{}</ul>",
            request.sc.iter().fold(String::new(), |mut output, scope| {
                output.push_str("<li>");
                output.push_str(&html_escape(scope));
                output.push_str("</li>");
                output
            })
        )
    };
    page(
        StatusCode::OK,
        &format!(
            "<h1>Authorize access</h1><p>Authorize access to {}.</p><p>{name}</p><p>After approval you will be sent to: <bdi>{}</bdi> <bdi><strong>{}</strong></bdi></p>{local}{scopes}<form method=\"post\" action=\"/oauth/consent\"><input type=\"hidden\" name=\"request\" value=\"{}\"><button name=\"decision\" value=\"approve\">Approve</button><button name=\"decision\" value=\"deny\">Deny</button></form>",
            html_escape(&state.server_name),
            html_escape(&request.ru),
            html_escape(host),
            html_escape(token)
        ),
        CONSENT_CSP,
    )
}

/// Authenticate the sealed transaction and its browser nonce before any decision.
// cancel-safe: all processing is local; no flow state is persisted before response delivery.
async fn consent(State(state): State<Arc<AsState>>, headers: HeaderMap, body: String) -> Response {
    let pairs = match parameters(&body, false) {
        Ok(pairs) => pairs,
        Err(reason) => return rejected(reason, false),
    };
    let Some(token) = param(&pairs, "request") else {
        return rejected("consent_request", true);
    };
    let Ok(request) = state
        .sealer
        .open::<ConsentRequest>(SealKind::ConsentRequest, token)
    else {
        return rejected("consent_seal", true);
    };
    if request.exp <= now_unix() {
        return rejected("consent_expired", true);
    }
    let name = state.cookie_name("csrf", Some(&request.csrf));
    let Some(csrf) = cookie(&headers, &name) else {
        return rejected("csrf_missing", true);
    };
    if !bool::from(sha256_b64(csrf).as_bytes().ct_eq(request.csrf.as_bytes())) {
        return rejected("csrf_mismatch", true);
    }
    let mut response = match param(&pairs, "decision") {
        Some("deny") => client_error(&state, &request, "access_denied"),
        Some("approve") => {
            let mut set = state.consent_set(&headers);
            if state.consent_ttl.is_zero() {
                state.approved(&request, None)
            } else {
                state.remember(&mut set, &request);
                state.approved(&request, Some(&mut set))
            }
        }
        Some(_) | None => rejected("decision", false),
    };
    state.set_cookie(&mut response, &name, "", 0);
    response
}

/// Generate 256 unpredictable bits in the URL-safe cookie alphabet.
fn nonce() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Take a bounded ASCII digest prefix without indexing or byte-boundary panics.
fn short(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

/// Read the first bounded exact-name match across all Cookie header fields.
fn cookie<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, value)| *key == name && value.len() <= 4096)
        .map(|(_key, value)| value)
}

impl AsState {
    /// Isolate a cookie by issuer and optionally by flow nonce digest.
    fn cookie_name(&self, kind: &str, hash: Option<&str>) -> String {
        let prefix = if self.cookie_secure { "__Host-" } else { "" };
        let flow = hash.map_or_else(String::new, |value| format!("_{}", short(value, 16)));
        format!("{prefix}rmcp_{kind}_{}{flow}", self.cookie_suffix)
    }

    /// Serialize only internally generated names and safe sealed or random values.
    fn set_cookie(&self, response: &mut Response, name: &str, value: &str, age: u64) {
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        if let Ok(header) = HeaderValue::from_str(&format!(
            "{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}{secure}"
        )) {
            let _inserted = response.headers_mut().append(header::SET_COOKIE, header);
        }
    }

    /// Load authenticated browser approvals and discard expired entries.
    fn consent_set(&self, headers: &HeaderMap) -> ConsentSet {
        let mut set = cookie(headers, &self.cookie_name("consent", None))
            .and_then(|token| {
                self.sealer
                    .open::<ConsentSet>(SealKind::Consent, token)
                    .ok()
            })
            .unwrap_or_default();
        set.entries.retain(|entry| entry.expires > now_unix());
        set
    }

    /// Merge approved scopes and move the refreshed entry to the MRU position.
    fn remember(&self, set: &mut ConsentSet, request: &ConsentRequest) {
        let cid = short(&request.cid, 22);
        let mut scopes = request.sc.clone();
        if let Some(entry) = set.entries.iter().find(|entry| entry.client == cid) {
            scopes.extend(entry.scopes.iter().cloned());
        }
        scopes.sort();
        scopes.dedup();
        set.entries
            .retain(|entry| entry.client != cid && entry.expires > now_unix());
        set.entries.insert(
            0,
            ConsentEntry {
                client: cid,
                scopes,
                expires: now_unix().saturating_add(self.consent_ttl.as_secs()),
            },
        );
        set.entries.truncate(20);
    }

    /// Drop LRU entries until the cookie fits the browser-safe sealed-size cap.
    fn seal_consent(&self, set: &mut ConsentSet) -> Option<String> {
        loop {
            if let Ok(token) = self.sealer.seal(SealKind::Consent, set)
                && token.len() <= 3800
            {
                return Some(token);
            }
            let _dropped = set.entries.pop()?;
        }
    }

    /// Set state only for an approved transaction and build the upstream allowlist.
    fn approved(&self, request: &ConsentRequest, consent: Option<&mut ConsentSet>) -> Response {
        let state_nonce = nonce();
        let flow = FlowState {
            cid: request.cid.clone(),
            ru: request.ru.clone(),
            st: request.st.clone(),
            cc: request.cc.clone(),
            nh: sha256_b64(&state_nonce),
            exp: now_unix().saturating_add(600),
        };
        let Ok(token) = self.sealer.seal(SealKind::State, &flow) else {
            return rejected("state_seal", true);
        };
        let Ok(mut url) = Url::parse(&self.proxy.authorize_url) else {
            return rejected("upstream_url", false);
        };
        let Ok(callback) =
            Url::parse(&self.issuer_url).and_then(|issuer| issuer.join("/oauth/callback"))
        else {
            return rejected("callback_url", false);
        };
        {
            let mut query = url.query_pairs_mut();
            let _pairs = query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.proxy.client_id)
                .append_pair("redirect_uri", callback.as_str())
                .append_pair("state", &state_nonce)
                .append_pair("code_challenge", &request.cc)
                .append_pair("code_challenge_method", "S256");
            if !request.sc.is_empty() {
                let _pair = query.append_pair("scope", &request.sc.join(" "));
            }
            if !self.proxy.strip_resource_param {
                for value in &request.rs {
                    let _pair = query.append_pair("resource", value);
                }
            }
            for (name, value) in &request.ex {
                let _pair = query.append_pair(name, value);
            }
        }
        let mut response = redirect(&url);
        self.set_cookie(
            &mut response,
            &self.cookie_name("state", Some(&flow.nh)),
            &token,
            600,
        );
        if let Some(set) = consent
            && let Some(value) = self.seal_consent(set)
        {
            self.set_cookie(
                &mut response,
                &self.cookie_name("consent", None),
                &value,
                self.consent_ttl.as_secs(),
            );
        }
        response
    }
}

/// Complete a browser transaction and clear its presented state credentials.
// cancel-safe: callback processing is synchronous and publishes only response cookies.
async fn callback(
    State(state): State<Arc<AsState>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let raw = query.as_deref().unwrap_or_default();
    let mut response = callback_response(&state, &headers, raw);
    let selected: BTreeSet<String> = form_urlencoded::parse(raw.as_bytes())
        .filter(|(name, value)| name == "state" && valid_state(value))
        .map(|(_name, value)| state.cookie_name("state", Some(&sha256_b64(&value))))
        .collect();
    for cookie_name in selected {
        state.set_cookie(&mut response, &cookie_name, "", 0);
    }
    response
}

/// Require the exact encoding shape of a generated 256-bit state nonce.
fn valid_state(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// Authenticate browser state before trusting the upstream outcome or redirecting.
fn callback_response(state: &AsState, headers: &HeaderMap, raw: &str) -> Response {
    let pairs = match parameters(raw, false) {
        Ok(pairs) => pairs,
        Err(reason) => return rejected(reason, false),
    };
    let Some(nonce) = param(&pairs, "state").filter(|value| valid_state(value)) else {
        return rejected("callback_state", true);
    };
    let hash = sha256_b64(nonce);
    let Some(sealed) = cookie(headers, &state.cookie_name("state", Some(&hash))) else {
        return rejected("state_missing", true);
    };
    let Ok(flow) = state.sealer.open::<FlowState>(SealKind::State, sealed) else {
        return rejected("state_seal", true);
    };
    if flow.exp <= now_unix() || !bool::from(flow.nh.as_bytes().ct_eq(hash.as_bytes())) {
        return rejected("state_binding", true);
    }
    if param(&pairs, "iss").is_some_and(|issuer| issuer != state.upstream_issuer) {
        return rejected("issuer_mismatch", true);
    }
    let Ok(mut target) = Url::parse(&flow.ru) else {
        return rejected("callback_redirect", true);
    };
    {
        let mut query = target.query_pairs_mut();
        if let Some(error) = param(&pairs, "error") {
            let filtered: String = error
                .bytes()
                .filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .take(64)
                .map(char::from)
                .collect();
            let _pair = query.append_pair(
                "error",
                if filtered.is_empty() {
                    "server_error"
                } else {
                    &filtered
                },
            );
            if let Some(description) = param(&pairs, "error_description") {
                let safe_description: String = description
                    .bytes()
                    .filter(|byte| (0x20..=0x7e).contains(byte) && !b"\"\\".contains(byte))
                    .take(256)
                    .map(char::from)
                    .collect();
                let _description = query.append_pair("error_description", &safe_description);
            }
        } else {
            let Some(code) = param(&pairs, "code").filter(|value| value.len() <= 2048) else {
                return rejected("callback_code", false);
            };
            let wrapped = CodeWrap {
                kc: code.to_owned(),
                cid: flow.cid,
                ru: flow.ru,
                cc: flow.cc,
                exp: now_unix().saturating_add(120),
            };
            let Ok(sealed_code) = state.sealer.seal(SealKind::Code, &wrapped) else {
                return rejected("code_seal", true);
            };
            let _pair = query.append_pair("code", &sealed_code);
        }
        if let Some(client_state) = flow.st {
            let _pair = query.append_pair("state", &client_state);
        }
        let _pair = query.append_pair("iss", &state.issuer_url);
    }
    redirect(&target)
}

/// Emit a content-free RFC 6749 section 5.2 error with the required status.
fn token_error(code: &'static str) -> Response {
    let status = if code == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    tracing::debug!(reason = code, "oauth authorization-server request rejected");
    (status, Json(serde_json::json!({"error":code}))).into_response()
}

/// Authenticate downstream bindings and serialize only the grant-specific allowlist.
///
/// # Errors
/// Returns an RFC 6749 error code before any upstream operation on invalid inputs.
fn token_form(
    state: &AsState,
    pairs: &[(String, String)],
) -> Result<(String, String), &'static str> {
    use secrecy::ExposeSecret as _;
    let grant = param(pairs, "grant_type").ok_or("invalid_request")?;
    let mut form = form_urlencoded::Serializer::new(String::new());
    let cid = match grant {
        "authorization_code" => {
            let client = param(pairs, "client_id").ok_or("invalid_request")?;
            let code = param(pairs, "code").ok_or("invalid_request")?;
            let verifier = param(pairs, "code_verifier")
                .filter(|value| valid_challenge(value))
                .ok_or("invalid_request")?;
            let ru = param(pairs, "redirect_uri").ok_or("invalid_request")?;
            let _registration = state
                .sealer
                .open::<ClientReg>(SealKind::Client, client)
                .map_err(|_error| "invalid_client")?;
            let wrapped = state
                .sealer
                .open::<CodeWrap>(SealKind::Code, code)
                .map_err(|_error| "invalid_grant")?;
            if wrapped.exp <= now_unix()
                || sha256_b64(client) != wrapped.cid
                || ru != wrapped.ru
                || !bool::from(sha256_b64(verifier).as_bytes().ct_eq(wrapped.cc.as_bytes()))
            {
                return Err("invalid_grant");
            }
            let _pairs = form
                .append_pair("grant_type", grant)
                .append_pair("code", &wrapped.kc)
                .append_pair(
                    "redirect_uri",
                    &format!("{}/oauth/callback", state.issuer_url),
                )
                .append_pair("code_verifier", verifier);
            wrapped.cid
        }
        "refresh_token" => {
            let refresh = param(pairs, "refresh_token").ok_or("invalid_request")?;
            let wrapped = state
                .sealer
                .open::<RefreshWrap>(SealKind::Refresh, refresh)
                .map_err(|_error| "invalid_grant")?;
            if wrapped.rt.len() > 4096 {
                return Err("invalid_grant");
            }
            if let Some(client) = param(pairs, "client_id") {
                let _registration = state
                    .sealer
                    .open::<ClientReg>(SealKind::Client, client)
                    .map_err(|_error| "invalid_client")?;
                if sha256_b64(client) != wrapped.cid {
                    return Err("invalid_grant");
                }
            }
            let _pairs = form
                .append_pair("grant_type", grant)
                .append_pair("refresh_token", &wrapped.rt);
            if let Some(scope) = param(pairs, "scope") {
                if !scope.split(' ').all(is_rfc6750_scope_token) {
                    return Err("invalid_request");
                }
                let _pair = form.append_pair("scope", scope);
            }
            wrapped.cid
        }
        _ => return Err("unsupported_grant_type"),
    };
    let mut resources = 0_u8;
    for (name, value) in pairs {
        if name == "resource" {
            resources = resources.saturating_add(1);
            if resources > 2
                || value.len() > 256
                || !Url::parse(value).is_ok_and(|url| url.fragment().is_none())
            {
                return Err("invalid_request");
            }
            if !state.proxy.strip_resource_param {
                let _pair = form.append_pair("resource", value);
            }
        }
    }
    let _pair = form.append_pair("client_id", &state.proxy.client_id);
    if let Some(secret) = &state.proxy.client_secret {
        let _secret = form.append_pair("client_secret", secret.expose_secret());
    }
    Ok((form.finish(), cid))
}

/// Exchange a locally authenticated grant and bind any rotated refresh credential.
// cancel-safe: no local flow state is persisted; cancellation after upstream exchange may consume the grant.
async fn token(State(state): State<Arc<AsState>>, body: String) -> Response {
    let pairs = match parameters(&body, true) {
        Ok(pairs) => pairs,
        Err(_reason) => return token_error("invalid_request"),
    };
    let (form, cid) = match token_form(&state, &pairs) {
        Ok(form) => form,
        Err(code) => return token_error(code),
    };
    let response = relay_token_request(&state.http, &state.proxy, form).await;
    if !response.status().is_success() {
        return response;
    }
    let (parts, upstream_body) = response.into_parts();
    let Ok(bytes) = to_bytes(upstream_body, 1024 * 1024).await else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error":"server_error"})),
        )
            .into_response();
    };
    let Ok(mut object) =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&bytes)
    else {
        return Response::from_parts(parts, bytes.into());
    };
    if let Some(refresh) = object
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
    {
        if refresh.len() > 4096 {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error":"server_error"})),
            )
                .into_response();
        }
        let Ok(wrapped) = state.sealer.seal(
            SealKind::Refresh,
            &RefreshWrap {
                rt: refresh.to_owned(),
                cid,
            },
        ) else {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error":"server_error"})),
            )
                .into_response();
        };
        drop(object.insert("refresh_token".into(), serde_json::Value::String(wrapped)));
    }
    match serde_json::to_vec(&object) {
        Ok(encoded) => Response::from_parts(parts, encoded.into()),
        Err(_error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error":"server_error"})),
        )
            .into_response(),
    }
}

/// Unwrap only authenticated facade refresh tokens, preserving access-token bodies verbatim.
///
/// # Errors
/// Returns an RFC 6749 error for duplicate token parameters or oversized forms.
#[expect(
    clippy::result_large_err,
    reason = "deliberate: oauth_as::unwrap_refresh_token_param preserves the specified Response error boundary"
)]
pub(crate) fn unwrap_refresh_token_param(sealer: &Sealer, body: &str) -> Result<String, Response> {
    if body.len() > PARAM_LIMIT {
        return Err(token_error("invalid_request"));
    }
    let pairs: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    if pairs
        .iter()
        .filter(|(name, _value)| name == "token")
        .count()
        > 1
    {
        return Err(token_error("invalid_request"));
    }
    let Some(refresh) = param(&pairs, "token")
        .and_then(|value| sealer.open::<RefreshWrap>(SealKind::Refresh, value).ok())
    else {
        return Ok(body.to_owned());
    };
    let mut form = form_urlencoded::Serializer::new(String::new());
    for (name, value) in &pairs {
        let _pair = form.append_pair(name, if name == "token" { &refresh.rt } else { value });
    }
    Ok(form.finish())
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use anyhow::{Context as _, ensure};
    use secrecy::SecretString;

    use super::*;
    use crate::transport::McpServerConfig;

    mod binding_near_misses;
    mod client_name_chars;

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "deliberate: oauth_as::tests::unusual_public_url_is_serialized_without_injection - exercises deprecated config fields directly"
    )]
    /// Exercises the issuer boundary without the pending config-hardening rules.
    async fn unusual_public_url_is_serialized_without_injection() -> anyhow::Result<()> {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt as _;

        // Given: deliberately bypass McpServerConfig::validate, including its pending hardening.
        let mut config = McpServerConfig::new("127.0.0.1:0", "Issuer", "1");
        config.public_url =
            Some("https://facade.example\\<script>?x=\"; HttpOnly\r\nX-Injected: yes".into());
        let mut context = state(true)?;
        context.proxy.sealing_secret = Some(SecretString::from(
            "unit-test-secret-with-at-least-32-bytes",
        ));
        let mut oauth =
            OAuthConfig::builder("https://idp.example", "unit", "https://idp.example/jwks").build();
        oauth.proxy = Some(context.proxy.clone());
        let router = install_routes(
            &oauth,
            config.public_url.as_deref().context("public URL")?,
            &config.name,
        )?;
        let client = ClientReg {
            ru: vec!["https://client.example/cb".into()],
            name: None,
            iat: 0,
        };
        let cid = context.sealer.seal(SealKind::Client, &client)?;
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", cid.as_str()),
                ("redirect_uri", "https://client.example/cb"),
                ("response_type", "code"),
                (
                    "code_challenge",
                    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                ),
                ("code_challenge_method", "S256"),
            ])
            .finish();
        // When
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?{query}"))
                    .body(Body::empty())?,
            )
            .await?;
        // Then
        ensure!(
            response.status() == 200 && !response.headers().contains_key("x-injected"),
            "issuer cannot inject header"
        );
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .context("CSRF")?
            .to_str()?;
        let name = cookie.split_once('=').context("cookie name")?.0;
        ensure!(
            name.starts_with("__Host-rmcp_csrf_")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
            "issuer only enters cookie name through digest"
        );
        let body = String::from_utf8(to_bytes(response.into_body(), 0x8000).await?.to_vec())?;
        ensure!(
            !body.contains("<script>") && !body.contains("X-Injected"),
            "issuer never interpolated into page"
        );
        Ok(())
    }

    /// A remembered consent entry that expired is not eligible for the fast path.
    #[test]
    fn expired_remembered_consent_is_discarded() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let set = ConsentSet {
            entries: vec![ConsentEntry {
                client: "client".into(),
                scopes: vec!["read".into()],
                expires: 0,
            }],
        };
        let token = context.sealer.seal(SealKind::Consent, &set)?;
        let mut headers = HeaderMap::new();
        let _previous = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{}={token}", context.cookie_name("consent", None)))?,
        );
        // When
        let actual = context.consent_set(&headers);
        // Then
        ensure!(actual.entries.is_empty(), "expired approval removed");
        Ok(())
    }

    /// Every truncated sealed form fails even with the genuine browser credential.
    #[tokio::test]
    async fn consent_request_truncation_sweep_fails_closed() -> anyhow::Result<()> {
        // Given
        let context = Arc::new(state(false)?);
        let pending = request("client");
        let token = context.sealer.seal(SealKind::ConsentRequest, &pending)?;
        let mut headers = HeaderMap::new();
        let _previous = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}=browser-nonce",
                context.cookie_name("csrf", Some(&pending.csrf))
            ))?,
        );
        for prefix in [
            "",
            "v1",
            "v1.",
            token
                .get(..token.len().saturating_sub(1))
                .context("prefix")?,
        ] {
            let body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("request", prefix), ("decision", "approve")])
                .finish();
            // When
            let response = consent(State(Arc::clone(&context)), headers.clone(), body).await;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key(header::LOCATION),
                "truncated form rejected"
            );
        }
        Ok(())
    }

    /// Two approvals produce distinct state nonces and browser-cookie bindings.
    #[test]
    fn concurrent_approved_flows_have_distinct_state_bindings() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let approved = request("client");
        let first = context.approved(&approved, None);
        // When
        let second = context.approved(&approved, None);
        // Then
        let first_cookie = first
            .headers()
            .get(header::SET_COOKIE)
            .context("first")?
            .to_str()?
            .split_once('=')
            .context("pair")?;
        let second_cookie = second
            .headers()
            .get(header::SET_COOKIE)
            .context("second")?
            .to_str()?
            .split_once('=')
            .context("pair")?;
        ensure!(
            first_cookie.0 != second_cookie.0 && first_cookie.1 != second_cookie.1,
            "independent state credentials"
        );
        Ok(())
    }

    /// Editing a client binding without recomputing the MAC cannot reuse a consent request.
    #[tokio::test]
    async fn modified_consent_payload_client_binding_is_rejected() -> anyhow::Result<()> {
        // Given
        let context = Arc::new(state(false)?);
        let original = request("client-a");
        let token = context.sealer.seal(SealKind::ConsentRequest, &original)?;
        let mut modified = request("client-b");
        modified.exp = original.exp;
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified)?);
        let tag = token.rsplit('.').next().context("tag")?;
        let forged = format!("v1.{payload}.{tag}");
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("request", forged.as_str()), ("decision", "approve")])
            .finish();
        let mut headers = HeaderMap::new();
        let _previous = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}=browser-nonce",
                context.cookie_name("csrf", Some(&original.csrf))
            ))?,
        );
        // When
        let response = consent(State(context), headers, body).await;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key(header::LOCATION),
            "client substitution rejected"
        );
        Ok(())
    }

    /// Construct immutable signing context without listeners or shared fixtures.
    fn state(secure: bool) -> anyhow::Result<AsState> {
        let proxy: OAuthProxyConfig = serde_json::from_value(serde_json::json!({
            "authorize_url":"https://idp.example/authorize", "token_url":"https://idp.example/token",
            "client_id":"upstream", "mode":"authorization_server"
        }))?;
        Ok(AsState {
            sealer: Sealer::new(
                &SecretString::from("unit-test-secret-with-at-least-32-bytes"),
                None,
            ),
            proxy,
            issuer_url: "https://facade.example".into(),
            server_name: "Facade".into(),
            cookie_secure: secure,
            cookie_suffix: "aabbccdd".into(),
            consent_ttl: Duration::from_hours(720),
            upstream_issuer: "https://idp.example".into(),
            http: OauthHttpClient::with_config(
                &OAuthConfig::builder("https://idp.example", "unit", "https://idp.example/jwks")
                    .build(),
            )?,
        })
    }

    /// Build a valid transaction with a chosen downstream identity digest.
    fn request(client: &str) -> ConsentRequest {
        ConsentRequest {
            cid: client.into(),
            ru: "http://localhost:9/cb".into(),
            st: Some("state".into()),
            cc: "a".repeat(43),
            sc: vec!["read".into()],
            rs: vec![],
            ex: vec![],
            csrf: sha256_b64("browser-nonce"),
            exp: now_unix().saturating_add(600),
        }
    }

    /// All five HTML metacharacters become inert text, including quoted attributes.
    #[test]
    fn html_escape_encodes_metacharacters() -> anyhow::Result<()> {
        // Given / When
        let escaped = html_escape("<&\"'>safe");
        // Then
        ensure!(
            escaped == "&lt;&amp;&quot;&#39;&gt;safe",
            "complete HTML escaping"
        );
        Ok(())
    }

    /// Cookie parsing traverses every header and chooses the first bounded exact name.
    #[test]
    fn cookie_parsing_uses_first_exact_match() -> anyhow::Result<()> {
        // Given
        let mut headers = HeaderMap::new();
        let _first = headers.append(
            header::COOKIE,
            HeaderValue::from_static("target_extra=wrong; junk"),
        );
        let _second = headers.append(
            header::COOKIE,
            HeaderValue::from_static(" target=first; target=second"),
        );
        // When / Then
        ensure!(
            cookie(&headers, "target") == Some("first"),
            "first exact name wins across headers"
        );
        Ok(())
    }

    /// Oversized cookie values are ignored rather than decoded or selected.
    #[test]
    fn cookie_parsing_ignores_oversized_values() -> anyhow::Result<()> {
        // Given
        let mut headers = HeaderMap::new();
        let _header = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("target={}; target=bounded", "x".repeat(4097)))?,
        );
        // When / Then
        ensure!(
            cookie(&headers, "target") == Some("bounded"),
            "oversized match ignored"
        );
        Ok(())
    }

    /// HTTPS cookie serialization includes host-prefix and every mandated attribute.
    #[test]
    fn secure_cookie_attributes_and_flow_names() -> anyhow::Result<()> {
        // Given
        let context = state(true)?;
        let name = context.cookie_name("csrf", Some("abcdefghijklmnop-more"));
        let mut response = StatusCode::OK.into_response();
        // When
        context.set_cookie(&mut response, &name, "safe-nonce", 600);
        // Then
        ensure!(
            name == "__Host-rmcp_csrf_aabbccdd_abcdefghijklmnop",
            "per-flow host name"
        );
        ensure!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .context("cookie")?
                .to_str()?
                == "__Host-rmcp_csrf_aabbccdd_abcdefghijklmnop=safe-nonce; HttpOnly; SameSite=Lax; Path=/; Max-Age=600; Secure",
            "secure attributes"
        );
        Ok(())
    }

    /// Development HTTP cookies omit only Secure and the host prefix.
    #[test]
    fn development_cookie_attributes() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let mut response = StatusCode::OK.into_response();
        // When
        context.set_cookie(
            &mut response,
            &context.cookie_name("consent", None),
            "sealed",
            0,
        );
        // Then
        ensure!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .context("cookie")?
                .to_str()?
                == "rmcp_consent_aabbccdd=sealed; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            "development attributes"
        );
        Ok(())
    }

    /// Browser approvals union scopes, drop expired entries and maintain bounded MRU order.
    #[test]
    fn consent_set_merges_and_evicts_lru() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let mut set = ConsentSet::default();
        for index in 0_u8..25 {
            context.remember(&mut set, &request(&format!("client-{index}")));
        }
        let mut approved = request("client-10");
        approved.sc = vec!["admin".into()];
        set.entries.push(ConsentEntry {
            client: "expired".into(),
            scopes: vec![],
            expires: 0,
        });
        // When
        context.remember(&mut set, &approved);
        // Then
        ensure!(set.entries.len() == 20, "twenty-entry cap");
        let first = set.entries.first().context("MRU entry")?;
        ensure!(
            first.client == "client-10" && first.scopes == ["admin", "read"],
            "merged approval at front"
        );
        ensure!(
            !set.entries
                .iter()
                .any(|entry| entry.client == "expired" || entry.client == "client-0"),
            "expiry and LRU eviction"
        );
        Ok(())
    }

    /// Large scope sets are evicted from the tail until the actual sealed cookie fits.
    #[test]
    fn consent_set_sealed_size_is_bounded() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let mut set = ConsentSet::default();
        for index in 0_u8..20 {
            let mut approved = request(&format!("client-{index}"));
            approved.sc = vec!["s".repeat(512)];
            context.remember(&mut set, &approved);
        }
        // When
        let token = context.seal_consent(&mut set).context("bounded seal")?;
        // Then
        ensure!(
            token.len() <= 3800 && set.entries.len() < 20,
            "sealed size drives eviction"
        );
        ensure!(
            set.entries.first().context("newest")?.client == "client-19",
            "newest retained"
        );
        Ok(())
    }

    /// Only HTTPS and the explicitly enumerated HTTP loopback callbacks are accepted.
    #[test]
    fn redirect_uri_scheme_and_host_rules() -> anyhow::Result<()> {
        // Given
        let accepted = [
            "https://example.test/cb",
            "http://localhost:9/cb",
            "http://127.0.0.1/cb",
            "http://[::1]:9/cb",
        ];
        let rejected = [
            "cursor://callback",
            "http://example.test/cb",
            "https://u@example.test",
            "https://example.test/#f",
            "//example.test/cb",
            "https://example.test\\@evil.test",
            "https://example.test/\r\nx:y",
        ];
        // When / Then
        ensure!(
            accepted.iter().all(|value| redirect_uri(value).is_some()),
            "allowed callback classes"
        );
        ensure!(
            rejected.iter().all(|value| redirect_uri(value).is_none()),
            "unsafe callback classes"
        );
        Ok(())
    }

    /// A correctly signed but expired consent request cannot be replayed with its cookie.
    #[tokio::test]
    async fn expired_consent_request_is_rejected() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let mut expired = request("client");
        expired.exp = 0;
        let token = context.sealer.seal(SealKind::ConsentRequest, &expired)?;
        let mut headers = HeaderMap::new();
        let _header = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}=browser-nonce",
                context.cookie_name("csrf", Some(&expired.csrf))
            ))?,
        );
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("request", token.as_str()), ("decision", "approve")])
            .finish();
        // When
        let response = consent(State(Arc::new(context)), headers, body).await;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key(header::LOCATION),
            "expired transaction fails closed"
        );
        Ok(())
    }

    /// Approval cookies cannot authenticate a pending request or be fixed by a browser.
    #[test]
    fn consent_cookie_wrong_kind_and_tamper_are_ignored() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let token = context
            .sealer
            .seal(SealKind::ConsentRequest, &request("client"))?;
        for value in [token, "attacker-fixed-value".into()] {
            let mut headers = HeaderMap::new();
            let _header = headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!(
                    "{}={value}",
                    context.cookie_name("consent", None)
                ))?,
            );
            // When
            let loaded = context.consent_set(&headers);
            // Then
            ensure!(
                loaded.entries.is_empty(),
                "wrong-purpose or forged cookie ignored"
            );
        }
        Ok(())
    }

    /// Approved flow cookies bind the client, return address, PKCE and nonce digest.
    #[test]
    fn state_cookie_is_bound_to_approved_transaction() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let approved = request("client-a");
        // When
        let response = context.approved(&approved, None);
        // Then
        ensure!(response.status() == 302, "upstream redirect");
        let location = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .context("location")?
                .to_str()?,
        )?;
        let state_nonce = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .context("state")?
            .1
            .into_owned();
        let pair = response
            .headers()
            .get(header::SET_COOKIE)
            .context("flow cookie")?
            .to_str()?
            .split(';')
            .next()
            .context("cookie pair")?;
        let (name, token) = pair.split_once('=').context("cookie value")?;
        let flow: FlowState = context.sealer.open(SealKind::State, token)?;
        ensure!(
            name == context.cookie_name("state", Some(&sha256_b64(&state_nonce))),
            "nonce-specific cookie"
        );
        ensure!(
            flow.cid == approved.cid
                && flow.ru == approved.ru
                && flow.cc == approved.cc
                && flow.st == approved.st,
            "approved transaction binding"
        );
        ensure!(flow.nh == sha256_b64(&state_nonce), "nonce digest binding");
        Ok(())
    }

    // Authenticated wrapper and callback contracts.

    /// Build distinct signed grant inputs without depending on callback serialization.
    fn grant_fixture(context: &AsState) -> anyhow::Result<Vec<(String, String)>> {
        let client = context.sealer.seal(
            SealKind::Client,
            &ClientReg {
                ru: vec!["https://consumer.example/return-distinct".into()],
                name: Some("Grant fixture independent client".into()),
                iat: 1973,
            },
        )?;
        let verifier = "unit-verifier-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._~-";
        let code = context.sealer.seal(
            SealKind::Code,
            &CodeWrap {
                kc: "unit-upstream-code-Z9".into(),
                cid: sha256_b64(&client),
                ru: "https://consumer.example/return-distinct".into(),
                cc: sha256_b64(verifier),
                exp: now_unix().saturating_add(119),
            },
        )?;
        Ok(vec![
            ("grant_type".into(), "authorization_code".into()),
            ("client_id".into(), client),
            ("code".into(), code),
            (
                "redirect_uri".into(),
                "https://consumer.example/return-distinct".into(),
            ),
            ("code_verifier".into(), verifier.into()),
        ])
    }

    /// Each code binding is authenticated independently before an upstream form can exist.
    #[test]
    fn code_grant_rejects_each_binding_mismatch_and_expiry() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let original = grant_fixture(&context)?;
        for field in ["cid", "ru", "cc", "exp", "tamper", "foreign_key"] {
            let mut pairs = original.clone();
            let encoded = param(&pairs, "code").context("code")?;
            let mut payload: CodeWrap = context.sealer.open(SealKind::Code, encoded)?;
            match field {
                "cid" => payload.cid = sha256_b64("unrelated-client"),
                "ru" => payload.ru = "https://foreign.example/different".into(),
                "cc" => {
                    payload.cc = sha256_b64("other-verifier-abcdefghijklmnopqrstuvwxyz0123456789");
                }
                "exp" => payload.exp = now_unix().saturating_sub(1),
                "tamper" | "foreign_key" => {}
                _ => anyhow::bail!("unknown binding fixture"),
            }
            let code = match field {
                "tamper" => format!("{encoded}x"),
                "foreign_key" => Sealer::new(
                    &SecretString::from("unknown-key-with-more-than-thirty-two-bytes"),
                    None,
                )
                .seal(SealKind::Code, &payload)?,
                _ => context.sealer.seal(SealKind::Code, &payload)?,
            };
            for (name, value) in &mut pairs {
                if name == "code" {
                    *value = code.clone();
                }
            }
            // When / Then
            ensure!(
                token_form(&context, &pairs) == Err("invalid_grant"),
                "independent code binding {field}"
            );
        }
        Ok(())
    }

    /// Both upstream grant forms contain exactly their allowed key/value pairs despite client junk.
    #[test]
    fn upstream_grant_forms_carry_only_allowlisted_pairs() -> anyhow::Result<()> {
        // Given
        let mut context = state(false)?;
        context.proxy.client_id = "operator-static-client-unique".into();
        context.proxy.client_secret =
            Some(SecretString::from("operator-secret-allowlist-distinct"));
        for stripped in [false, true] {
            context.proxy.strip_resource_param = stripped;
            for refresh in [false, true] {
                let mut pairs = grant_fixture(&context)?;
                let client = param(&pairs, "client_id").context("client")?.to_owned();
                let bound = sha256_b64(&client);
                let wrapped = context.sealer.seal(
                    SealKind::Refresh,
                    &RefreshWrap {
                        rt: "refresh-upstream-unique-42".into(),
                        cid: bound.clone(),
                    },
                )?;
                if refresh {
                    pairs = vec![
                        ("grant_type".into(), "refresh_token".into()),
                        ("refresh_token".into(), wrapped),
                        ("scope".into(), "scope:refresh_unique".into()),
                    ];
                }
                pairs.extend([
                    ("resource".into(), "https://resource-one.example/mcp".into()),
                    (
                        "resource".into(),
                        "https://resource-two.example/service".into(),
                    ),
                    (
                        "client_secret".into(),
                        "attacker-secret-never-forward".into(),
                    ),
                    ("unknown".into(), "discard-this-parameter".into()),
                ]);
                if !refresh {
                    pairs.push(("scope".into(), "scope:code_must_disappear".into()));
                }
                // When
                let (encoded, cid) = token_form(&context, &pairs).map_err(anyhow::Error::msg)?;
                let actual: Vec<(String, String)> = form_urlencoded::parse(encoded.as_bytes())
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                let mut expected = if refresh {
                    vec![
                        ("grant_type".into(), "refresh_token".into()),
                        ("refresh_token".into(), "refresh-upstream-unique-42".into()),
                        ("scope".into(), "scope:refresh_unique".into()),
                    ]
                } else {
                    vec![
                        ("grant_type".into(), "authorization_code".into()),
                        ("code".into(), "unit-upstream-code-Z9".into()),
                        (
                            "redirect_uri".into(),
                            "https://facade.example/oauth/callback".into(),
                        ),
                        (
                            "code_verifier".into(),
                            "unit-verifier-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._~-".into(),
                        ),
                    ]
                };
                if !stripped {
                    expected.extend([
                        ("resource".into(), "https://resource-one.example/mcp".into()),
                        (
                            "resource".into(),
                            "https://resource-two.example/service".into(),
                        ),
                    ]);
                }
                expected.extend([
                    ("client_id".into(), "operator-static-client-unique".into()),
                    (
                        "client_secret".into(),
                        "operator-secret-allowlist-distinct".into(),
                    ),
                ]);
                // Then
                ensure!(
                    actual == expected && cid == bound,
                    "complete allowlist refresh={refresh} stripped={stripped}"
                );
            }
        }
        Ok(())
    }

    /// Callback payloads preserve distinct approved fields and the exact 120-second code lifetime.
    #[tokio::test]
    async fn callback_code_preserves_approved_fields_and_120_second_lifetime() -> anyhow::Result<()>
    {
        // Given
        let context = Arc::new(state(false)?);
        let nonce = "nonce-Q0123456789abcdefghijklmnopqrstuvwxyz";
        for outcome in [
            "code",
            "error",
            "issuer",
            "missing_code",
            "expired",
            "nonce",
            "tamper",
            "duplicate",
        ] {
            let flow = FlowState {
                cid: sha256_b64("approved-client-distinct"),
                ru: "https://callback.example/approved?prior=unique".into(),
                st: Some("approved-client-state-unique".into()),
                cc: sha256_b64("approved-verifier-distinct-0123456789abcdefghijklmnopqrstuvwxyz"),
                nh: if outcome == "nonce" {
                    sha256_b64("foreign-nonce")
                } else {
                    sha256_b64(nonce)
                },
                exp: if outcome == "expired" {
                    now_unix().saturating_sub(1)
                } else {
                    now_unix().saturating_add(587)
                },
            };
            let sealed = context.sealer.seal(SealKind::State, &flow)?;
            let cookie_name = context.cookie_name("state", Some(&sha256_b64(nonce)));
            let mut headers = HeaderMap::new();
            let _header = headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!(
                    "{cookie_name}={}",
                    if outcome == "tamper" {
                        format!("{sealed}x")
                    } else {
                        sealed
                    }
                ))?,
            );
            let mut pairs = vec![("state", nonce)];
            match outcome {
                "error" => pairs.extend([
                    ("error", "access_denied"),
                    ("error_description", "Permission denied uniquely"),
                ]),
                "issuer" => pairs.extend([
                    ("code", "callback-code-unique"),
                    ("iss", "https://foreign.example"),
                ]),
                "missing_code" => {}
                "duplicate" => {
                    pairs.extend([("code", "callback-code-unique"), ("code", "other-code")]);
                }
                _ => pairs.push(("code", "callback-code-unique")),
            }
            let raw = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            let before = now_unix();
            // When
            let response =
                callback(State(Arc::clone(&context)), headers, RawQuery(Some(raw))).await;
            // Then
            ensure!(
                response
                    .headers()
                    .get(header::SET_COOKIE)
                    .context("clear")?
                    .to_str()?
                    == format!("{cookie_name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"),
                "always clear {outcome}"
            );
            if matches!(outcome, "code" | "error") {
                ensure!(response.status() == 302, "callback redirect");
                let url = Url::parse(
                    response
                        .headers()
                        .get(header::LOCATION)
                        .context("location")?
                        .to_str()?,
                )?;
                ensure!(
                    url.query_pairs()
                        .any(|(key, value)| key == "iss" && value == "https://facade.example")
                        && url.query_pairs().any(|(key, value)| key == "state"
                            && value == "approved-client-state-unique"),
                    "redirect bindings"
                );
                if outcome == "code" {
                    assert_callback_code(&context, &url, &flow, before)?;
                }
            } else {
                ensure!(
                    response.status() == 400 && !response.headers().contains_key(header::LOCATION),
                    "integrity error no redirect {outcome}"
                );
            }
        }
        Ok(())
    }

    /// Open the observed browser code and compare all fields to the approved input fixture.
    fn assert_callback_code(
        context: &AsState,
        url: &Url,
        flow: &FlowState,
        before: u64,
    ) -> anyhow::Result<()> {
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("code")?
            .1
            .into_owned();
        let opened: CodeWrap = context.sealer.open(SealKind::Code, &code)?;
        ensure!(
            opened.kc == "callback-code-unique"
                && opened.cid == flow.cid
                && opened.ru == flow.ru
                && opened.cc == flow.cc
                && (before.saturating_add(120)..=now_unix().saturating_add(120))
                    .contains(&opened.exp),
            "exact approved envelope"
        );
        Ok(())
    }

    /// Current and retired keys unwrap admin credentials while access token bytes stay untouched.
    #[test]
    fn admin_unwrap_accepts_current_and_retired_refresh_keys() -> anyhow::Result<()> {
        // Given
        let current = SecretString::from("current-key-0123456789-abcdefghijklmnopqrstuvwxyz");
        let previous = SecretString::from("previous-key-9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBA");
        let rotating = Sealer::new(&current, Some(&previous));
        for signer in [Sealer::new(&current, None), Sealer::new(&previous, None)] {
            let token = signer.seal(
                SealKind::Refresh,
                &RefreshWrap {
                    rt: "admin-raw-refresh-distinct".into(),
                    cid: "client-digest-admin-distinct".into(),
                },
            )?;
            let form = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("token", token.as_str()),
                    ("token_type_hint", "refresh_token"),
                ])
                .finish();
            // When
            let decoded = unwrap_refresh_token_param(&rotating, &form)
                .map_err(|_response| anyhow::anyhow!("adapter error"))?;
            // Then
            ensure!(
                decoded == "token=admin-raw-refresh-distinct&token_type_hint=refresh_token",
                "rotation raw credential"
            );
            let opened: RefreshWrap = rotating.open(SealKind::Refresh, &token)?;
            ensure!(
                opened.rt == "admin-raw-refresh-distinct"
                    && opened.cid == "client-digest-admin-distinct",
                "refresh fields"
            );
        }
        let access = "token=access%2fraw+verbatim&custom=%41";
        ensure!(
            unwrap_refresh_token_param(&rotating, access).is_ok_and(|body| body == access),
            "access bytes untouched"
        );
        let repeated_hint = "token=unwrapped-access&hint=a&hint=b";
        ensure!(
            unwrap_refresh_token_param(&rotating, repeated_hint)
                .is_ok_and(|body| body == repeated_hint),
            "only repeated token is rejected by admin adapter"
        );
        ensure!(
            unwrap_refresh_token_param(&rotating, "token=a&token=b").is_err(),
            "duplicate token rejected"
        );
        Ok(())
    }

    /// Token numeric boundaries and unreserved verifier alphabet are enforced before upstream I/O.
    #[test]
    fn token_enforces_numeric_and_pkce_charset_bounds_before_upstream() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        for length in [42_usize, 43, 44, 127, 128, 129] {
            let mut pairs = grant_fixture(&context)?;
            let verifier: String = (0..length)
                .map(|index| {
                    char::from(
                        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._~-"
                            .get(index.checked_rem(66).unwrap_or_default())
                            .copied()
                            .unwrap_or(b'Z'),
                    )
                })
                .collect();
            let encoded = param(&pairs, "code").context("code")?;
            let mut code: CodeWrap = context.sealer.open(SealKind::Code, encoded)?;
            code.cc = sha256_b64(&verifier);
            let sealed = context.sealer.seal(SealKind::Code, &code)?;
            for (name, value) in &mut pairs {
                match name.as_str() {
                    "code" => *value = sealed.clone(),
                    "code_verifier" => *value = verifier.clone(),
                    _ => {}
                }
            }
            // When / Then
            ensure!(
                token_form(&context, &pairs).is_ok() == (43..=128).contains(&length),
                "verifier length {length}"
            );
        }
        for bad in ["/", "+", "=", " ", "\t", "%", "\u{e9}"] {
            let mut pairs = grant_fixture(&context)?;
            for (name, value) in &mut pairs {
                if name == "code_verifier" {
                    *value = format!("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG{bad}");
                }
            }
            ensure!(
                token_form(&context, &pairs) == Err("invalid_request"),
                "verifier alphabet"
            );
        }
        for count in [1_usize, 2, 3] {
            for size in [255_usize, 256, 257] {
                let mut pairs = grant_fixture(&context)?;
                let prefix = "https://resource.example/";
                let resource = format!("{prefix}{}", "r".repeat(size.saturating_sub(prefix.len())));
                for _ in 0..count {
                    pairs.push(("resource".into(), resource.clone()));
                }
                ensure!(
                    token_form(&context, &pairs).is_ok() == (count <= 2 && size <= 256),
                    "resource count/length"
                );
            }
        }
        Ok(())
    }

    /// Callback bounds accept the exact cap and filter upstream error text without active delimiters.
    #[test]
    fn callback_accepts_exact_caps_and_filters_upstream_error_text() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let nonce = "state-X0123456789abcdefghijklmnopqrstuvwxyz";
        ensure!(nonce.len() == 43, "state fixture");
        let flow = FlowState {
            cid: "callback-bound-client".into(),
            ru: "https://bounds.example/return".into(),
            st: None,
            cc: "approved-challenge-distinct-boundary".into(),
            nh: sha256_b64(nonce),
            exp: now_unix().saturating_add(593),
        };
        let sealed = context.sealer.seal(SealKind::State, &flow)?;
        let mut headers = HeaderMap::new();
        let _header = headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}={sealed}",
                context.cookie_name("state", Some(&flow.nh))
            ))?,
        );
        for size in [2047_usize, 2048, 2049] {
            let code: String = (0..size)
                .map(|index| {
                    char::from(
                        b"0123456789abcdefghijklmnopqrstuvwxyz"
                            .get(index.checked_rem(36).unwrap_or_default())
                            .copied()
                            .unwrap_or(b'Z'),
                    )
                })
                .collect();
            let raw = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("state", nonce), ("code", code.as_str())])
                .finish();
            // When
            let response = callback_response(&context, &headers, &raw);
            // Then
            ensure!(
                response.status() == if size <= 2048 { 302 } else { 400 },
                "upstream code cap {size}"
            );
        }
        for size in [63, 64, 65, 255, 256, 257] {
            let error = format!("{}-!", "E".repeat(size));
            let description = format!("{}\"\\\n", "D".repeat(size));
            let raw = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("state", nonce),
                    ("error", error.as_str()),
                    ("error_description", description.as_str()),
                ])
                .finish();
            let response = callback_response(&context, &headers, &raw);
            let target = Url::parse(
                response
                    .headers()
                    .get(header::LOCATION)
                    .context("location")?
                    .to_str()?,
            )?;
            let pairs: Vec<_> = target.query_pairs().collect();
            ensure!(
                pairs
                    .iter()
                    .any(|(key, value)| key == "error" && value == &"E".repeat(size.min(64)))
                    && pairs.iter().any(|(key, value)| key == "error_description"
                        && value == &"D".repeat(size.min(256))),
                "upstream error filtering"
            );
            ensure!(
                !pairs.iter().any(|(key, _)| key == "state"),
                "absent client state not invented"
            );
        }
        for size in [42, 43, 44] {
            ensure!(
                valid_state(&"S".repeat(size)) == (size == 43),
                "state length"
            );
        }
        Ok(())
    }

    // Expiry, cookie and renderer contract tables using the real signing boundary.

    /// A genuine request at its deadline or one second beyond it is refused with its real cookie.
    #[tokio::test]
    async fn consent_request_is_refused_at_and_after_its_deadline() -> anyhow::Result<()> {
        // Given
        let context = Arc::new(state(false)?);
        for seconds_ago in [0, 1] {
            let mut observed_same_second = false;
            for _attempt in 0_u8..3 {
                let now = now_unix();
                let mut pending = request("client");
                pending.exp = now.saturating_sub(seconds_ago);
                let token = context.sealer.seal(SealKind::ConsentRequest, &pending)?;
                let mut headers = HeaderMap::new();
                let _previous = headers.insert(
                    header::COOKIE,
                    HeaderValue::from_str(&format!(
                        "{}=browser-nonce",
                        context.cookie_name("csrf", Some(&pending.csrf))
                    ))?,
                );
                let form = form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("request", token.as_str()), ("decision", "approve")])
                    .finish();
                // When
                let response = consent(State(Arc::clone(&context)), headers, form).await;
                if now_unix() != now {
                    continue;
                }
                // Then
                ensure!(
                    response.status() == 400 && !response.headers().contains_key(header::LOCATION),
                    "ten-minute request is expired at its deadline and at simulated +601 seconds"
                );
                observed_same_second = true;
                break;
            }
            ensure!(
                observed_same_second,
                "expiry evaluated within captured Unix second"
            );
        }
        Ok(())
    }

    /// All three cookie families have exact secure/development names and complete set/clear attributes.
    #[test]
    fn cookie_families_serialize_exact_names_and_attributes() -> anyhow::Result<()> {
        // Given
        for secure in [false, true] {
            let context = state(secure)?;
            for (kind, hash) in [
                ("csrf", Some("abcdefghijklmnop-more")),
                ("state", Some("abcdefghijklmnop-more")),
                ("consent", None),
            ] {
                for (value, age) in [("credential", 1234), ("", 0)] {
                    let prefix = if secure { "__Host-" } else { "" };
                    let flow = if hash.is_some() {
                        "_abcdefghijklmnop"
                    } else {
                        ""
                    };
                    let expected_name = format!("{prefix}rmcp_{kind}_aabbccdd{flow}");
                    let name = context.cookie_name(kind, hash);
                    let mut response = StatusCode::OK.into_response();
                    // When
                    context.set_cookie(&mut response, &name, value, age);
                    // Then
                    let suffix = if secure { "; Secure" } else { "" };
                    ensure!(
                        response
                            .headers()
                            .get_all(header::SET_COOKIE)
                            .iter()
                            .count()
                            == 1,
                        "single cookie serialization"
                    );
                    ensure!(
                        response
                            .headers()
                            .get(header::SET_COOKIE)
                            .context("cookie")?
                            .to_str()?
                            == format!(
                                "{expected_name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}{suffix}"
                            ),
                        "exact {kind} cookie for secure={secure}, age={age}"
                    );
                }
            }
        }
        Ok(())
    }

    /// Cookie parser limits select the first accepted value at both sides of the cap.
    #[test]
    fn cookie_parser_selects_first_value_within_size_cap() -> anyhow::Result<()> {
        // Given
        for size in [4095, 4096, 4097] {
            let value = "a".repeat(size);
            let mut headers = HeaderMap::new();
            let _previous = headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("target={value}; target=fallback"))?,
            );
            // When
            let parsed = cookie(&headers, "target");
            // Then
            ensure!(
                parsed
                    == Some(if size <= 4096 {
                        value.as_str()
                    } else {
                        "fallback"
                    }),
                "cookie size {size}"
            );
        }
        Ok(())
    }

    /// Renderer interpolation escapes every metacharacter even in a synthetic hidden field.
    #[tokio::test]
    async fn renderer_escapes_every_metacharacter_in_each_field() -> anyhow::Result<()> {
        use axum::body::to_bytes;
        // Given
        let hostile = "<img/src=x>&'\"";
        let escaped = "&lt;img/src=x&gt;&amp;&#39;&quot;";
        let mut context = state(false)?;
        context.server_name = hostile.into();
        let client = ClientReg {
            ru: vec![],
            name: Some(hostile.into()),
            iat: 0,
        };
        let mut pending = request("client");
        pending.ru = format!("https://example.test/cb?{hostile}");
        pending.sc = vec![hostile.into(), "<img/src=x>&'".into()];
        // When: direct renderer exercises escaping independently of the sealed alphabet.
        let response = consent_page(&context, &client, &pending, hostile);
        // Then
        let html = String::from_utf8(to_bytes(response.into_body(), 0x8000).await?.to_vec())?;
        for expected in [
            format!("Authorize access to {escaped}."),
            format!("<bdi>{escaped}</bdi> (name supplied"),
            format!("https://example.test/cb?{escaped}"),
            format!("<li>{escaped}</li>"),
            format!("name=\"request\" value=\"{escaped}\""),
            "<strong>example.test</strong>".into(),
        ] {
            ensure!(html.contains(&expected), "escaped renderer site");
        }
        ensure!(
            !html.contains(hostile),
            "hostile markup never reaches HTML unchanged"
        );
        Ok(())
    }

    // Authenticated-state distinct-values tables.

    /// A nondefault approved challenge remains bound inside the authenticated flow cookie.
    #[test]
    fn nondefault_pkce_challenge_stays_bound_in_flow_cookie() -> anyhow::Result<()> {
        // Given
        let context = state(false)?;
        let mut pending = request("client-a");
        pending.cc = "B".repeat(43);
        // When
        let response = context.approved(&pending, None);
        // Then
        let pair = response
            .headers()
            .get(header::SET_COOKIE)
            .context("cookie")?
            .to_str()?
            .split(';')
            .next()
            .context("pair")?;
        let token = pair.split_once('=').context("token")?.1;
        let flow: FlowState = context.sealer.open(SealKind::State, token)?;
        ensure!(
            flow.cc == pending.cc,
            "approved challenge remains authenticated"
        );
        Ok(())
    }

    /// Read generated response cookies without accepting their attributes as credential data.
    fn cookie_request_headers(response: &Response) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for value in response.headers().get_all(header::SET_COOKIE) {
            let pair = value.to_str()?.split(';').next().context("cookie pair")?;
            let _inserted = headers.append(header::COOKIE, HeaderValue::from_str(pair)?);
        }
        Ok(headers)
    }

    /// Open both approval outputs and compare every carried field with independent source data.
    fn assert_approved_flow_fields(
        context: &AsState,
        pending: &ConsentRequest,
        response: &Response,
    ) -> anyhow::Result<()> {
        ensure!(response.status() == 302, "approval redirects");
        let location = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .context("location")?
                .to_str()?,
        )?;
        let pairs: Vec<_> = location
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let upstream_nonce = param(&pairs, "state").context("upstream nonce")?;
        let headers = cookie_request_headers(response)?;
        let hash = sha256_b64(upstream_nonce);
        let token =
            cookie(&headers, &context.cookie_name("state", Some(&hash))).context("state cookie")?;
        let flow: FlowState = context.sealer.open(SealKind::State, token)?;
        for (field, actual, source) in [
            ("cid", flow.cid.as_str(), pending.cid.as_str()),
            ("ru", flow.ru.as_str(), pending.ru.as_str()),
            ("cc", flow.cc.as_str(), pending.cc.as_str()),
            ("nh", flow.nh.as_str(), hash.as_str()),
        ] {
            ensure!(actual == source, "authenticated flow field {field}");
        }
        ensure!(flow.st == pending.st, "authenticated downstream state");
        ensure!(
            flow.exp == pending.exp.saturating_sub(337).saturating_add(600),
            "flow deadline from captured second"
        );
        ensure!(
            param(&pairs, "code_challenge") == Some(pending.cc.as_str()),
            "upstream challenge"
        );
        ensure!(
            param(&pairs, "scope") == Some(pending.sc.join(" ").as_str()),
            "upstream scopes"
        );
        let resources: Vec<_> = pairs
            .iter()
            .filter(|(key, _)| key == "resource")
            .map(|(_, value)| value)
            .collect();
        ensure!(
            resources == pending.rs.iter().collect::<Vec<_>>(),
            "upstream resources"
        );
        for (key, value) in &pending.ex {
            ensure!(
                param(&pairs, key) == Some(value.as_str()),
                "upstream hint {key}"
            );
        }
        ensure!(
            param(&pairs, "redirect_uri")
                == Some(format!("{}/oauth/callback", context.issuer_url).as_str()),
            "facade callback"
        );
        let consent_token =
            cookie(&headers, &context.cookie_name("consent", None)).context("consent cookie")?;
        let remembered: ConsentSet = context.sealer.open(SealKind::Consent, consent_token)?;
        ensure!(
            remembered.entries.len() == 2,
            "both distinct clients retained"
        );
        let current = remembered.entries.first().context("current entry")?;
        ensure!(
            current.client == short(&pending.cid, 22),
            "remembered client"
        );
        ensure!(current.scopes == pending.sc, "remembered scopes");
        ensure!(
            current.expires
                == pending
                    .exp
                    .saturating_sub(337)
                    .saturating_add(context.consent_ttl.as_secs()),
            "remembered deadline"
        );
        let previous = remembered.entries.get(1).context("previous entry")?;
        ensure!(
            previous.client == "prior-distinct-client-Z",
            "previous client preserved"
        );
        ensure!(
            previous.scopes == ["previous:retain"],
            "previous scope preserved"
        );
        ensure!(
            previous.expires == pending.exp.saturating_sub(337).saturating_add(2111),
            "previous deadline preserved"
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: oauth_as::tests::authenticated_state_preserves_distinct_values_per_transaction keeps source/output fields in one reviewable security transaction"
    )]
    /// Authorization, approval and denial preserve distinct fields through real authenticated envelopes.
    async fn authenticated_state_preserves_distinct_values_per_transaction() -> anyhow::Result<()> {
        use axum::body::to_bytes;
        // Given: each row uses a different client, callback, state, challenge and hint set.
        for (row, challenge) in [
            ("alpha", "BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"),
            ("beta", "76543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq"),
        ] {
            let mut configured = state(false)?;
            configured.consent_ttl = Duration::from_secs(1234);
            let context = Arc::new(configured);
            let redirect = format!("https://{row}.client.test/return?binding={row}");
            let client = ClientReg {
                ru: vec![redirect.clone()],
                name: Some(format!("app-{row}")),
                iat: 17,
            };
            let cid = context.sealer.seal(SealKind::Client, &client)?;
            let downstream_state = format!("downstream-state-{row}-distinct");
            let scope = format!("{row}:write {row}:read");
            let resources = [
                format!("https://resource-{row}.test/mcp"),
                format!("urn:{row}:archive"),
            ];
            let hints = [
                ("prompt", format!("select-{row}")),
                ("login_hint", format!("person-{row}@example.test")),
                ("ui_locales", format!("en-{row}")),
            ];
            let mut pairs = vec![
                ("client_id", cid.as_str()),
                ("redirect_uri", redirect.as_str()),
                ("state", downstream_state.as_str()),
                ("response_type", "code"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("scope", scope.as_str()),
            ];
            pairs.extend(resources.iter().map(|value| ("resource", value.as_str())));
            pairs.extend(hints.iter().map(|(key, value)| (*key, value.as_str())));
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            let before = now_unix();
            // When
            let page = authorize(
                State(Arc::clone(&context)),
                HeaderMap::new(),
                RawQuery(Some(query)),
            )
            .await;
            // Then: authenticate the generated request, not just its visible JSON payload.
            ensure!(page.status() == 200, "distinct fixture renders consent");
            let cookies = cookie_request_headers(&page)?;
            let html = String::from_utf8(to_bytes(page.into_body(), 0x8000).await?.to_vec())?;
            let token = html
                .split("name=\"request\" value=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .context("request")?;
            let mut pending: ConsentRequest =
                context.sealer.open(SealKind::ConsentRequest, token)?;
            ensure!(pending.cid == sha256_b64(&cid), "request client digest");
            ensure!(pending.ru == redirect, "request redirect");
            ensure!(
                pending.st.as_deref() == Some(downstream_state.as_str()),
                "request state"
            );
            ensure!(pending.cc == challenge, "request PKCE");
            ensure!(
                pending.sc == [format!("{row}:read"), format!("{row}:write")],
                "request scopes sorted"
            );
            ensure!(pending.rs == resources, "request resources");
            ensure!(
                pending.ex
                    == hints
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), value.clone()))
                        .collect::<Vec<_>>(),
                "request hints"
            );
            ensure!(
                (before.saturating_add(600)..=now_unix().saturating_add(600))
                    .contains(&pending.exp),
                "request expiry"
            );
            let csrf_name = context.cookie_name("csrf", Some(&pending.csrf));
            let csrf_nonce = cookie(&cookies, &csrf_name).context("CSRF cookie")?;
            ensure!(
                pending.csrf == sha256_b64(csrf_nonce),
                "request CSRF digest binds cookie value"
            );
            ensure!(
                csrf_nonce.len() == 43 && csrf_nonce != challenge && csrf_nonce != downstream_state,
                "distinct generated nonce"
            );
            for decision in ["approve", "deny"] {
                let mut same_second = false;
                for _attempt in 0_u8..3 {
                    let now = now_unix();
                    pending.exp = now.saturating_add(337);
                    let decision_token = context.sealer.seal(SealKind::ConsentRequest, &pending)?;
                    let previous = ConsentSet {
                        entries: vec![ConsentEntry {
                            client: "prior-distinct-client-Z".into(),
                            scopes: vec!["previous:retain".into()],
                            expires: now.saturating_add(2111),
                        }],
                    };
                    let previous_token = context.sealer.seal(SealKind::Consent, &previous)?;
                    let mut headers = cookies.clone();
                    let _inserted = headers.append(
                        header::COOKIE,
                        HeaderValue::from_str(&format!(
                            "{}={previous_token}",
                            context.cookie_name("consent", None)
                        ))?,
                    );
                    let form = form_urlencoded::Serializer::new(String::new())
                        .extend_pairs([
                            ("request", decision_token.as_str()),
                            ("decision", decision),
                        ])
                        .finish();
                    // When
                    let response = consent(State(Arc::clone(&context)), headers, form).await;
                    if now_unix() != now {
                        continue;
                    }
                    // Then
                    let cleared = cookie_request_headers(&response)?;
                    ensure!(
                        cookie(&cleared, &csrf_name) == Some(""),
                        "original CSRF cookie cleared"
                    );
                    match decision {
                        "approve" => assert_approved_flow_fields(&context, &pending, &response)?,
                        "deny" => {
                            let mut expected = Url::parse(&redirect)?;
                            let _query = expected
                                .query_pairs_mut()
                                .append_pair("error", "access_denied")
                                .append_pair("iss", &context.issuer_url)
                                .append_pair("state", &downstream_state);
                            ensure!(
                                response
                                    .headers()
                                    .get(header::LOCATION)
                                    .context("denial location")?
                                    .to_str()?
                                    == expected.as_str(),
                                "denial preserves source redirect and state"
                            );
                            ensure!(
                                cleared.get_all(header::COOKIE).iter().count() == 1,
                                "deny issues no authenticated approval outputs"
                            );
                        }
                        other => anyhow::bail!("unexpected decision {other}"),
                    }
                    same_second = true;
                    break;
                }
                ensure!(
                    same_second,
                    "deadline checks share one captured Unix second"
                );
            }
        }
        Ok(())
    }
}
