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
#[cfg(test)]
mod tests {

    extern crate alloc;

    use alloc::sync::Arc;
    use core::{net::SocketAddr, time::Duration};
    use std::{
        env, fs,
        io::{Write as _, stderr},
        path::PathBuf,
        process,
    };

    use anyhow::Context as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rmcp_server_kit::oauth::{
        ClientCertConfig, OAuthConfig, OauthHttpClient, TokenExchangeConfig, exchange_token,
    };
    use rustls::{
        RootCertStore, ServerConfig,
        crypto::ring,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        server::WebPkiClientVerifier,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::oneshot,
        time::timeout,
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

    fn build_mtls_pki() -> anyhow::Result<MtlsPki> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "mtls-test-ca");
        let ca_key = KeyPair::generate().context("ca key")?;
        let ca_issuer: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(ca_params, ca_key).context("ca self-signed")?;

        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).context("server params")?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "mtls-test-server");
        let server_key = KeyPair::generate().context("server key")?;
        let server_cert = server_params
            .signed_by(&server_key, &ca_issuer)
            .context("server signed")?;

        let mut client_params =
            CertificateParams::new(Vec::<String>::new()).context("client params")?;
        client_params
            .distinguished_name
            .push(DnType::CommonName, "mtls-test-client");
        let client_key = KeyPair::generate().context("client key")?;
        let client_cert = client_params
            .signed_by(&client_key, &ca_issuer)
            .context("client signed")?;

        Ok(MtlsPki {
            ca_pem: ca_issuer.as_ref().pem(),
            server_cert_der: server_cert.der().to_vec(),
            server_key_der: server_key.serialize_der(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            ca_cert_der: ca_issuer.as_ref().der().to_vec(),
        })
    }

    fn install_crypto_provider() {
        drop(ring::default_provider().install_default());
    }

    fn build_mtls_server_config(pki: &MtlsPki) -> anyhow::Result<Arc<ServerConfig>> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(pki.ca_cert_der.clone()))
            .context("add ca to roots")?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("client verifier")?;
        let cert = CertificateDer::from(pki.server_cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key_der.clone()));
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .context("server config")?;
        Ok(Arc::new(config))
    }

    #[derive(Debug)]
    struct CapturedRequest {
        headers: String,
        peer_cert_count: usize,
    }

    async fn spawn_one_shot_mtls_server(
        pki: &MtlsPki,
        response_bytes: Vec<u8>,
    ) -> anyhow::Result<(String, oneshot::Receiver<CapturedRequest>)> {
        install_crypto_provider();
        let server_config = build_mtls_server_config(pki)?;
        let acceptor = TlsAcceptor::from(server_config);

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("bind 127.0.0.1:0")?;
        let port = listener.local_addr().context("local_addr")?.port();

        let (tx, rx) = oneshot::channel::<CapturedRequest>();

        drop(tokio::spawn(serve_one_shot_mtls_connection(
            acceptor,
            listener,
            tx,
            response_bytes,
        )));

        Ok((format!("https://localhost:{port}/token"), rx))
    }

    async fn serve_one_shot_mtls_connection(
        acceptor: TlsAcceptor,
        listener: TcpListener,
        tx: oneshot::Sender<CapturedRequest>,
        response_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let accept_fut = listener.accept();
        let (tcp, _peer) = match timeout(Duration::from_secs(30), accept_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) => {
                writeln!(stderr(), "mtls accept error: {error}")
                    .context("report mtls accept error")?;
                return Ok(());
            }
            Err(_) => {
                writeln!(stderr(), "mtls accept timeout").context("report mtls accept timeout")?;
                return Ok(());
            }
        };
        let mut tls_stream = match acceptor.accept(tcp).await {
            Ok(stream) => stream,
            Err(error) => {
                writeln!(stderr(), "mtls handshake error: {error}")
                    .context("report mtls handshake error")?;
                return Ok(());
            }
        };

        let peer_cert_count = {
            let (_io, conn) = tls_stream.get_ref();
            conn.peer_certificates().map_or(0, <[_]>::len)
        };

        let mut buf = vec![0_u8; 16 * 1024];
        let mut filled = 0_usize;
        while filled < buf.len() {
            let Some(read_slice) = buf.get_mut(filled..) else {
                return Ok(());
            };
            let bytes_read = match timeout(Duration::from_secs(5), tls_stream.read(read_slice))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(bytes_read)) => bytes_read,
                Ok(Err(error)) => {
                    writeln!(stderr(), "mtls read error: {error}")
                        .context("report mtls read error")?;
                    return Ok(());
                }
                Err(_) => {
                    writeln!(stderr(), "mtls read timeout").context("report mtls read timeout")?;
                    return Ok(());
                }
            };
            let Some(next) = filled.checked_add(bytes_read) else {
                return Ok(());
            };
            filled = next;
            let Some(head) = buf.get(..filled) else {
                return Ok(());
            };
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let Some(head) = buf.get(..filled) else {
            return Ok(());
        };
        let headers = String::from_utf8_lossy(head).into_owned();

        if let Err(error) = tls_stream.write_all(&response_bytes).await {
            writeln!(stderr(), "mtls write error: {error}").context("report mtls write error")?;
        }
        drop(tls_stream.shutdown().await);

        drop(tx.send(CapturedRequest {
            headers,
            peer_cert_count,
        }));
        Ok(())
    }

    fn write_pem(name: &str, body: &str) -> anyhow::Result<PathBuf> {
        let dir = env::temp_dir();
        let pid = process::id();
        let path = dir.join(format!("rmcp-mtls-e2e-{name}-{pid}.pem"));
        fs::write(&path, body).context("write pem")?;
        Ok(path)
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /// Pins that the mTLS client presents its client certificate at the TLS
    /// handshake and sends no `Authorization` header on the token exchange.
    #[tokio::test]
    async fn exchange_token_presents_client_cert_and_omits_authorization() -> anyhow::Result<()> {
        let pki = build_mtls_pki()?;
        let body =
            b"{\"access_token\":\"AAA\",\"token_type\":\"Bearer\",\"issued_token_type\":\"x\",\"expires_in\":60}";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let (token_url, captured_rx) = spawn_one_shot_mtls_server(&pki, response).await?;

        let ca_path = write_pem("ca", &pki.ca_pem)?;
        let cert_path = write_pem("client-cert", &pki.client_cert_pem)?;
        let key_path = write_pem("client-key", &pki.client_key_pem)?;

        let cc = ClientCertConfig::new(cert_path.clone(), key_path.clone());
        let tx_cfg = TokenExchangeConfig::new(token_url, "client", None, Some(cc))
            .with_audience("downstream");

        let mut oauth_cfg = OAuthConfig::builder(
            "https://issuer.invalid",
            "mcp",
            "https://issuer.invalid/jwks.json",
        )
        .build();
        oauth_cfg.token_exchange = Some(tx_cfg.clone());
        oauth_cfg.ca_cert_path = Some(ca_path.clone());

        oauth_cfg.validate().context("config validates")?;

        let http = OauthHttpClient::with_config(&oauth_cfg)
            .context("build oauth http client")?
            .__test_allow_loopback_ssrf();

        let exchanged = exchange_token(&http, &tx_cfg, "subject-token-xxx")
            .await
            .context("token exchange must succeed")?;
        assert_eq!(exchanged.access_token, "AAA");

        let captured = timeout(Duration::from_secs(30), captured_rx)
            .await
            .context("captured channel timeout")?
            .context("captured channel closed")?;

        drop(fs::remove_file(&ca_path));
        drop(fs::remove_file(&cert_path));
        drop(fs::remove_file(&key_path));

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
        Ok(())
    }

    /// Pins that the cert-bearing mTLS client does not follow a 3xx from the
    /// token endpoint, surfacing it as a sanitized OAuth error instead.
    #[tokio::test]
    async fn mtls_client_does_not_follow_redirects() -> anyhow::Result<()> {
        let pki = build_mtls_pki()?;

        let redirect = b"HTTP/1.1 302 Found\r\n\
            Location: https://attacker.invalid/exfil\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let (token_url, _captured_rx) = spawn_one_shot_mtls_server(&pki, redirect.to_vec()).await?;

        let ca_path = write_pem("ca-redir", &pki.ca_pem)?;
        let cert_path = write_pem("client-cert-redir", &pki.client_cert_pem)?;
        let key_path = write_pem("client-key-redir", &pki.client_key_pem)?;

        let cc = ClientCertConfig::new(cert_path.clone(), key_path.clone());
        let tx_cfg = TokenExchangeConfig::new(token_url, "client", None, Some(cc))
            .with_audience("downstream");

        let mut oauth_cfg = OAuthConfig::builder(
            "https://issuer.invalid",
            "mcp",
            "https://issuer.invalid/jwks.json",
        )
        .build();
        oauth_cfg.token_exchange = Some(tx_cfg.clone());
        oauth_cfg.ca_cert_path = Some(ca_path.clone());

        oauth_cfg.validate().context("config validates")?;

        let http = OauthHttpClient::with_config(&oauth_cfg)
            .context("build oauth http client")?
            .__test_allow_loopback_ssrf();

        let result = exchange_token(&http, &tx_cfg, "subject-token-xxx").await;

        drop(fs::remove_file(&ca_path));
        drop(fs::remove_file(&cert_path));
        drop(fs::remove_file(&key_path));

        let err = result.err().context(
            "302 with Policy::none() must surface as an upstream error, NOT silently follow",
        )?;
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("server_error")
                || err_msg.contains("invalid_request")
                || err_msg.contains("invalid_grant"),
            "302 must map to a sanitized OAuth error short code, NOT a follow-through; got {err_msg}"
        );
        Ok(())
    }
}
