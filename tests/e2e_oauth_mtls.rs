//! M-H4 end-to-end test: RFC 8705 §2 mTLS client authentication for
//! OAuth token exchange.
//!
//! Asserts three security-critical properties of the
//! `oauth-mtls-client` feature:
//!
//! 1. When `TokenExchangeConfig::client_cert` is set, the runtime
//!    `OauthHttpClient` presents the configured TLS client
//!    certificate at the handshake (`peer_certificates()` is
//!    populated on the server side).
//! 2. The exchange request carries NO `Authorization` header
//!    (presenting the cert IS the client authentication; sending an
//!    Authorization header alongside would defeat RFC 8705 by
//!    confusing layered auth).
//! 3. The cert-bearing client uses `redirect::Policy::none()` so that
//!    an attacker-controlled 3xx from the token endpoint cannot
//!    cause the cert to be re-presented to a different host.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![allow(clippy::print_stderr, reason = "tests")]
#![allow(clippy::indexing_slicing, reason = "tests")]
#![cfg(all(
    feature = "oauth",
    feature = "oauth-mtls-client",
    feature = "test-helpers"
))]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rmcp_server_kit::oauth::{
    ClientCertConfig, OAuthConfig, OauthHttpClient, TokenExchangeConfig, exchange_token,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Test PKI: one CA, one server cert (SAN=localhost), one client cert.
// ---------------------------------------------------------------------------

struct MtlsPki {
    ca_pem: String,
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
    client_cert_pem: String,
    client_key_pem: String,
    ca_cert_der: Vec<u8>,
}

fn build_mtls_pki() -> MtlsPki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mtls-test-ca");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_issuer: CertifiedIssuer<'static, KeyPair> =
        CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca self-signed");

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, "mtls-test-server");
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("server signed");

    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "mtls-test-client");
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("client signed");

    MtlsPki {
        ca_pem: ca_issuer.as_ref().pem(),
        server_cert_der: server_cert.der().to_vec(),
        server_key_der: server_key.serialize_der(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        ca_cert_der: ca_issuer.as_ref().der().to_vec(),
    }
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_mtls_server_config(pki: &MtlsPki) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_cert_der.clone()))
        .expect("add ca to roots");
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let cert = CertificateDer::from(pki.server_cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key_der.clone()));
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .expect("server config");
    Arc::new(config)
}

#[derive(Debug)]
struct CapturedRequest {
    headers: String,
    peer_cert_count: usize,
}

async fn spawn_one_shot_mtls_server(
    pki: &MtlsPki,
    response_bytes: Vec<u8>,
) -> (String, oneshot::Receiver<CapturedRequest>) {
    install_crypto_provider();
    let server_config = build_mtls_server_config(pki);
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    let (tx, rx) = oneshot::channel::<CapturedRequest>();

    tokio::spawn(async move {
        let accept_fut = listener.accept();
        let (tcp, _peer) = match tokio::time::timeout(Duration::from_secs(5), accept_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                eprintln!("mtls accept error: {e}");
                return;
            }
            Err(_) => {
                eprintln!("mtls accept timeout");
                return;
            }
        };
        let mut tls_stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mtls handshake error: {e}");
                return;
            }
        };

        let peer_cert_count = {
            let (_io, conn) = tls_stream.get_ref();
            conn.peer_certificates().map_or(0, <[_]>::len)
        };

        let mut buf = vec![0u8; 16 * 1024];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = match tokio::time::timeout(
                Duration::from_secs(5),
                tls_stream.read(&mut buf[filled..]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    eprintln!("mtls read error: {e}");
                    return;
                }
                Err(_) => {
                    eprintln!("mtls read timeout");
                    return;
                }
            };
            filled += n;
            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8_lossy(&buf[..filled]).into_owned();

        if let Err(e) = tls_stream.write_all(&response_bytes).await {
            eprintln!("mtls write error: {e}");
        }
        let _ = tls_stream.shutdown().await;

        let _ = tx.send(CapturedRequest {
            headers,
            peer_cert_count,
        });
    });

    (format!("https://localhost:{port}/token"), rx)
}

fn write_pem(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let path = dir.join(format!("rmcp-mtls-e2e-{name}-{pid}.pem"));
    std::fs::write(&path, body).expect("write pem");
    path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exchange_token_presents_client_cert_and_omits_authorization() {
    let pki = build_mtls_pki();
    let body =
        b"{\"access_token\":\"AAA\",\"token_type\":\"Bearer\",\"issued_token_type\":\"x\",\"expires_in\":60}";
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    let (token_url, captured_rx) = spawn_one_shot_mtls_server(&pki, response).await;

    let ca_path = write_pem("ca", &pki.ca_pem);
    let cert_path = write_pem("client-cert", &pki.client_cert_pem);
    let key_path = write_pem("client-key", &pki.client_key_pem);

    let cc = ClientCertConfig::new(cert_path.clone(), key_path.clone());
    let tx_cfg = TokenExchangeConfig::new(
        token_url,
        "client".into(),
        None,
        Some(cc),
        "downstream".into(),
    );

    let mut oauth_cfg = OAuthConfig::builder(
        "https://issuer.invalid",
        "mcp",
        "https://issuer.invalid/jwks.json",
    )
    .build();
    oauth_cfg.token_exchange = Some(tx_cfg.clone());
    oauth_cfg.ca_cert_path = Some(ca_path.clone());

    oauth_cfg.validate().expect("config validates");

    let http = OauthHttpClient::with_config(&oauth_cfg)
        .expect("build oauth http client")
        .__test_allow_loopback_ssrf();

    let exchanged = exchange_token(&http, &tx_cfg, "subject-token-xxx")
        .await
        .expect("token exchange must succeed");
    assert_eq!(exchanged.access_token, "AAA");

    let captured = tokio::time::timeout(Duration::from_secs(5), captured_rx)
        .await
        .expect("captured channel timeout")
        .expect("captured channel closed");

    let _ = std::fs::remove_file(&ca_path);
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(
        captured.peer_cert_count >= 1,
        "server must have received a client certificate at handshake; got {} certs",
        captured.peer_cert_count
    );

    let lower = captured.headers.to_lowercase();
    assert!(
        !lower.contains("\nauthorization:") && !lower.starts_with("authorization:"),
        "exchange request must NOT carry an Authorization header in mTLS mode; \
         captured headers:\n{}",
        captured.headers
    );
    assert!(
        captured.headers.contains("grant_type=") || captured.headers.contains("POST "),
        "captured request must look like an RFC 8693 token exchange POST; got:\n{}",
        captured.headers
    );
}

#[tokio::test]
async fn mtls_client_does_not_follow_redirects() {
    let pki = build_mtls_pki();

    let redirect = b"HTTP/1.1 302 Found\r\n\
        Location: https://attacker.invalid/exfil\r\n\
        Content-Length: 0\r\n\
        \r\n";
    let (token_url, _captured_rx) = spawn_one_shot_mtls_server(&pki, redirect.to_vec()).await;

    let ca_path = write_pem("ca-redir", &pki.ca_pem);
    let cert_path = write_pem("client-cert-redir", &pki.client_cert_pem);
    let key_path = write_pem("client-key-redir", &pki.client_key_pem);

    let cc = ClientCertConfig::new(cert_path.clone(), key_path.clone());
    let tx_cfg = TokenExchangeConfig::new(
        token_url,
        "client".into(),
        None,
        Some(cc),
        "downstream".into(),
    );

    let mut oauth_cfg = OAuthConfig::builder(
        "https://issuer.invalid",
        "mcp",
        "https://issuer.invalid/jwks.json",
    )
    .build();
    oauth_cfg.token_exchange = Some(tx_cfg.clone());
    oauth_cfg.ca_cert_path = Some(ca_path.clone());

    oauth_cfg.validate().expect("config validates");

    let http = OauthHttpClient::with_config(&oauth_cfg)
        .expect("build oauth http client")
        .__test_allow_loopback_ssrf();

    let result = exchange_token(&http, &tx_cfg, "subject-token-xxx").await;

    let _ = std::fs::remove_file(&ca_path);
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let err = result.expect_err(
        "302 with Policy::none() must surface as an upstream error, NOT silently follow",
    );
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("server_error")
            || err_msg.contains("invalid_request")
            || err_msg.contains("invalid_grant"),
        "302 must map to a sanitized OAuth error short code, NOT a follow-through; got {err_msg}"
    );
}
