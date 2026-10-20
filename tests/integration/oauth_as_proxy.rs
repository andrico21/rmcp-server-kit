//! Authorization-server facade exercised through real loopback HTTP.

#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[cfg(test)]
// On an inline module `path` names the directory of its file submodules.
#[path = "oauth_as_proxy"]
mod tests {
    use core::{net::SocketAddr, time::Duration};
    use std::{env, fs, process::Command};

    use anyhow::{Context as _, ensure};
    use reqwest::{Client, Response, redirect::Policy};
    use rmcp::{
        ServerHandler,
        model::{ServerCapabilities, ServerConfig},
    };
    use rmcp_server_kit::{
        auth::AuthConfig,
        oauth::OAuthConfig,
        transport::{McpServerConfig, SecurityHeadersConfig, serve_with_listener},
    };
    use rustls::crypto::ring;
    use serde_json::{Value, json};
    use tokio::{
        net::TcpListener,
        sync::oneshot,
        task::{JoinSet, spawn_blocking},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    mod client_name_spoofing;
    mod phone_layout;
    mod refresh_and_replicas;
    mod wire_rejections;

    const CALLBACK: &str = "http://127.0.0.1:18999/cb?original=1";
    const CHALLENGE: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    #[derive(Clone)]
    struct Handler;
    impl ServerHandler for Handler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }
    }

    struct Harness {
        base: String,
        client: Client,
        stop: CancellationToken,
        tasks: JoinSet<rmcp_server_kit::Result<()>>,
        upstream: wiremock::MockServer,
    }

    // Drop audit: cancellation is synchronous; JoinSet aborts remaining tasks, without I/O or panic.
    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.cancel();
        }
    }

    impl Harness {
        /// Start a real server with a deterministic readiness signal.
        async fn start(ttl: &str) -> anyhow::Result<Self> {
            Self::start_mode(ttl, "authorization_server").await
        }

        /// Start either routing mode through the same real listener.
        async fn start_mode(ttl: &str, mode: &str) -> anyhow::Result<Self> {
            Self::start_options(ttl, mode, false).await
        }

        /// Optionally configure deliberately incompatible API header overrides.
        async fn start_options(ttl: &str, mode: &str, overrides: bool) -> anyhow::Result<Self> {
            Self::start_extended(ttl, mode, overrides, false).await
        }

        /// Enable admin adapters and trailing-slash metadata for the part-B wire tables.
        async fn start_extended(
            ttl: &str,
            mode: &str,
            overrides: bool,
            extended: bool,
        ) -> anyhow::Result<Self> {
            Self::start_public(ttl, mode, (overrides, extended), None).await
        }

        /// Start a replica with an optional shared public origin independent of its listener.
        async fn start_public(
            ttl: &str,
            mode: &str,
            options: (bool, bool),
            public: Option<&str>,
        ) -> anyhow::Result<Self> {
            let (overrides, extended) = options;
            drop(ring::default_provider().install_default());
            let upstream = wiremock::MockServer::start().await;
            let origin = format!("http://localhost:{}", upstream.address().port());
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let base = format!("http://{addr}");
            let oauth: OAuthConfig = serde_json::from_value(json!({
                "issuer": origin, "audience": "as-test", "jwks_uri": format!("{origin}/jwks"),
                "allow_http_oauth_urls": true,
                "scopes":[{"scope":"task12:read","role":"viewer"}],
                "ssrf_allowlist": {"hosts":["localhost"],"cidrs":["127.0.0.0/8"]},
                "proxy": {"mode":mode, "authorize_url":format!("{origin}/authorize"),
                    "token_url":format!("{origin}/token"),"client_id":"static-upstream",
                    "expose_admin_endpoints":extended,"require_auth_on_admin_endpoints":!extended,"allow_unauthenticated_admin_endpoints":extended,
                    "introspection_url":format!("{origin}/introspect"),"revocation_url":format!("{origin}/revoke"),
                    "sealing_secret_previous":"previous-lane12-key-with-more-than-32-bytes",
                    "sealing_secret":"fixture-secret-with-at-least-32-bytes", "consent_ttl":ttl}
            }))?;
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.oauth = Some(oauth);
            let configured = McpServerConfig::new(addr.to_string(), "Test server", "1")
                .with_public_url(public.map_or_else(
                    || {
                        if extended {
                            format!("{base}/")
                        } else {
                            base.clone()
                        }
                    },
                    str::to_owned,
                ))
                .with_auth(auth);
            let config = if overrides {
                let mut headers = SecurityHeadersConfig::default();
                headers.content_security_policy = Some("default-src 'self'".into());
                headers.referrer_policy = Some("no-referrer".into());
                headers.cache_control = Some("public, max-age=3600".into());
                configured.with_security_headers(headers).validate()?
            } else {
                configured.validate()?
            };
            let (tx, rx) = oneshot::channel::<SocketAddr>();
            let stop = CancellationToken::new();
            let shutdown = stop.clone();
            let mut tasks = JoinSet::new();
            let _abort = tasks.spawn(async move {
                serve_with_listener(listener, config, || Handler, Some(tx), Some(shutdown)).await
            });
            ensure!(
                timeout(Duration::from_secs(30), rx).await?? == addr,
                "ready address"
            );
            Ok(Self {
                base,
                client: Client::builder()
                    .redirect(Policy::none())
                    .timeout(Duration::from_secs(10))
                    .build()?,
                stop,
                tasks,
                upstream,
            })
        }

        /// Join the listener rather than leaving background work behind.
        async fn close(mut self) -> anyhow::Result<()> {
            self.stop.cancel();
            while let Some(result) =
                timeout(Duration::from_secs(30), self.tasks.join_next()).await?
            {
                result??;
            }
            Ok(())
        }

        /// Register a fixture client using the public endpoint.
        async fn register(&self, name: &str) -> anyhow::Result<String> {
            let response = self
                .client
                .post(format!("{}/register", self.base))
                .json(&json!({"redirect_uris":[CALLBACK],"client_name":name}))
                .send()
                .await?;
            ensure!(
                response.status() == 201,
                "registration status: {}",
                response.status()
            );
            let body: Value = response.json().await?;
            Ok(body
                .get("client_id")
                .and_then(Value::as_str)
                .context("client id")?
                .to_owned())
        }

        /// Valid authorization parameters; mutations in tests change one boundary input.
        fn params(cid: &str) -> Vec<(&str, &str)> {
            vec![
                ("client_id", cid),
                ("redirect_uri", CALLBACK),
                ("response_type", "code"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("scope", "mcp:read"),
                ("state", "client-state"),
            ]
        }

        /// Open the consent page for a registered client.
        async fn page(&self, cid: &str) -> anyhow::Result<Response> {
            self.authorize(&Self::params(cid), None).await
        }

        /// Submit explicitly selected query pairs with optional manual cookies.
        async fn authorize(
            &self,
            pairs: &[(&str, &str)],
            cookie: Option<&str>,
        ) -> anyhow::Result<Response> {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().copied())
                .finish();
            let request = self.client.get(format!("{}/authorize?{query}", self.base));
            let with_cookie = match cookie {
                Some(value) => request.header("cookie", value),
                None => request,
            };
            Ok(with_cookie.send().await?)
        }

        /// Submit a consent decision with explicit browser-bound credentials.
        async fn decide(
            &self,
            token: &str,
            cookie: &str,
            decision: &str,
        ) -> anyhow::Result<Response> {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("request", token), ("decision", decision)])
                .finish();
            Ok(self
                .client
                .post(format!("{}/oauth/consent", self.base))
                .header("cookie", cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await?)
        }
    }

    /// Extract the form token and the single CSRF cookie without browser cookie magic.
    async fn consent_form(response: Response) -> anyhow::Result<(String, String)> {
        ensure!(response.status() == 200, "consent page status");
        let cookie = response
            .headers()
            .get("set-cookie")
            .context("CSRF cookie")?
            .to_str()?
            .split(';')
            .next()
            .context("cookie pair")?
            .to_owned();
        ensure!(
            cookie.starts_with("rmcp_csrf_"),
            "only a CSRF cookie before approval"
        );
        let html = response.text().await?;
        let token = html
            .split("name=\"request\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .context("hidden request")?
            .to_owned();
        Ok((token, cookie))
    }

    /// Approval forwards only the approved parameter allowlist and sets flow cookies.
    #[tokio::test]
    async fn consent_approve_redirects_upstream() -> anyhow::Result<()> {
        let server = Harness::start("30days").await?; // Given
        let cid = server.register("Example app").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        let response = server
            .client
            .post(format!("{}/oauth/consent", server.base)) // When
            .header("cookie", cookie)
            .header("origin", &server.base)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("request", request.as_str()), ("decision", "approve")])
                    .finish(),
            )
            .send()
            .await?;
        ensure!(
            response.status() == 302,
            "approval status {}",
            response.status()
        ); // Then
        let location = url::Url::parse(
            response
                .headers()
                .get("location")
                .context("upstream redirect")?
                .to_str()?,
        )?;
        let pairs: Vec<_> = location.query_pairs().collect();
        ensure!(
            pairs.len() == 7,
            "exact upstream parameter count: {}",
            pairs.len()
        );
        ensure!(
            pairs
                .iter()
                .any(|(key, value)| key == "client_id" && value == "static-upstream"),
            "static id"
        );
        ensure!(
            pairs.iter().any(|(key, value)| key == "redirect_uri"
                && value == &format!("{}/oauth/callback", server.base)),
            "callback"
        );
        ensure!(
            pairs
                .iter()
                .any(|(key, value)| key == "state" && value.len() == 43 && value != "client-state"),
            "fresh state"
        );
        for (key, expected) in [
            ("response_type", "code"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("scope", "mcp:read"),
        ] {
            ensure!(
                pairs
                    .iter()
                    .any(|(name, value)| name == key && value == expected),
                "approved upstream field {key}"
            );
        }
        let cookies: Vec<_> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str())
            .collect::<Result<_, _>>()?;
        ensure!(
            cookies
                .iter()
                .any(|value| value.starts_with("rmcp_state_") && value.contains("Max-Age=600")),
            "state cookie"
        );
        ensure!(
            cookies
                .iter()
                .any(|value| value.starts_with("rmcp_consent_")),
            "consent cookie"
        );
        server.close().await
    }

    /// Consent cannot be submitted without the browser's matching CSRF cookie.
    #[tokio::test]
    async fn consent_post_without_csrf_cookie_is_rejected() -> anyhow::Result<()> {
        let server = Harness::start("30days").await?; // Given
        let cid = server.register("Example app").await?;
        let (request, _cookie) = consent_form(server.page(&cid).await?).await?;
        let response = server
            .client
            .post(format!("{}/oauth/consent", server.base)) // When
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("request", request.as_str()), ("decision", "approve")])
                    .finish(),
            )
            .send()
            .await?;
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "fail closed"
        ); // Then
        server.close().await
    }

    /// Untrusted application markup is rendered as text under mandatory page headers.
    #[tokio::test]
    async fn consent_page_is_escaped_and_uncacheable() -> anyhow::Result<()> {
        let server = Harness::start("30days").await?; // Given
        let cid = server.register("<script>\"'&</script>").await?;
        let response = server.page(&cid).await?; // When
        ensure!(
            response.status() == 200 && !response.headers().contains_key("location"),
            "page not redirect"
        ); // Then
        ensure!(
            response
                .headers()
                .get("content-security-policy")
                .context("CSP")?
                == "default-src 'none'; style-src 'sha256-duPJE+yRsr7GWUwbG4KlBrtEWYrMTMxBbEoskxCsGOA='; frame-ancestors 'none'; base-uri 'none'",
            "CSP"
        );
        ensure!(
            response
                .headers()
                .get("referrer-policy")
                .context("referrer")?
                == "same-origin",
            "referrer"
        );
        ensure!(
            response.headers().get("cache-control").context("cache")? == "no-store",
            "no store"
        );
        ensure!(
            response.headers().get_all("set-cookie").iter().count() == 1,
            "CSRF only"
        );
        let html = response.text().await?;
        ensure!(
            html.contains("&lt;script&gt;&quot;&#39;&amp;&lt;/script&gt;")
                && !html.contains("<script>"),
            "escaped name"
        );
        ensure!(
            html.contains("http://127.0.0.1:18999/cb?original=1") && html.contains("mcp:read"),
            "full destination and scope"
        );
        server.close().await
    }

    /// Invalid clients never become open redirects.
    #[tokio::test]
    async fn bad_client_is_rejected_without_location() -> anyhow::Result<()> {
        let server = Harness::start("30days").await?; // Given
        let response = server.page("not-sealed").await?; // When
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "bad client page"
        ); // Then
        server.close().await
    }

    /// Registration replaces unsupported metadata rather than trusting client claims.
    #[tokio::test]
    async fn registration_replaces_metadata_and_disables_caching() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        // When
        let response = server
            .client
            .post(format!("{}/register", server.base))
            .json(&json!({
                "redirect_uris":[CALLBACK], "client_name":"Registered",
                "token_endpoint_auth_method":"client_secret_basic", "grant_types":["password"],
                "response_types":["token"], "unknown": {"ignored":true}
            }))
            .send()
            .await?;
        // Then
        ensure!(response.status() == 201, "created");
        ensure!(
            response.headers().get("pragma").context("pragma")? == "no-cache",
            "cache layer"
        );
        let body: Value = response.json().await?;
        ensure!(
            body.get("token_endpoint_auth_method") == Some(&json!("none")),
            "public client"
        );
        ensure!(
            body.get("grant_types") == Some(&json!(["authorization_code", "refresh_token"])),
            "grants replaced"
        );
        ensure!(
            body.get("response_types") == Some(&json!(["code"])),
            "response types replaced"
        );
        ensure!(
            body.get("redirect_uris") == Some(&json!([CALLBACK])),
            "redirect retained"
        );
        ensure!(
            body.get("client_name") == Some(&json!("Registered")),
            "name retained"
        );
        ensure!(
            body.get("client_id_issued_at")
                .and_then(Value::as_u64)
                .is_some(),
            "issued time"
        );
        server.close().await
    }

    /// Every registration boundary rejects invalid metadata without injected headers.
    #[tokio::test]
    async fn registration_rejects_invalid_metadata() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let oversized_uri = format!("https://example.test/{}", "a".repeat(512));
        let total_uri = format!("https://example.test/{}", "a".repeat(400));
        let cases = [
            (json!({}), "invalid_client_metadata"),
            (json!({"redirect_uris":[]}), "invalid_redirect_uri"),
            (
                json!({"redirect_uris":vec![CALLBACK;6]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":[oversized_uri]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":vec![total_uri;5]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["relative"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["cursor://callback"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["http://example.test/cb"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["https://user:pass@example.test/cb"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["https://example.test/cb#fragment"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["https://example.test/\r\nX-Injected: yes"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":[CALLBACK],"client_name":"x".repeat(129)}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris":[CALLBACK],"client_name":"control\u{0000}"}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris":[CALLBACK],"client_name":7_u8}),
                "invalid_client_metadata",
            ),
        ];
        for (input, error) in cases {
            // When
            let response = server
                .client
                .post(format!("{}/register", server.base))
                .json(&input)
                .send()
                .await?;
            // Then
            ensure!(response.status() == 400, "reject registration {input}");
            ensure!(
                !response.headers().contains_key("location")
                    && !response.headers().contains_key("x-injected"),
                "no injection"
            );
            let body: Value = response.json().await?;
            ensure!(
                body.get("error") == Some(&json!(error)),
                "error classification"
            );
        }
        server.close().await
    }

    /// Exact string comparison rejects port, case, slash, scheme and userinfo substitutions.
    #[tokio::test]
    async fn authorize_rejects_unregistered_redirect_variants() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Redirect test").await?;
        for uri in [
            "https://evil.example/cb",
            "http://127.0.0.1:19000/cb?original=1",
            "https://127.0.0.1:18999/cb?original=1",
            "http://127.0.0.1:18999/cb/?original=1",
            "http://127.0.0.1:18999/CB?original=1",
            "http://user@127.0.0.1:18999/cb?original=1",
            "http://127.0.0.1:18999/cb?original=1#fragment",
        ] {
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(key, _)| *key != "redirect_uri");
            pairs.push(("redirect_uri", uri));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "exact redirect match"
            );
        }
        server.close().await
    }

    /// Missing PKCE is a protocol error only after the return address is trusted.
    #[tokio::test]
    async fn authorize_missing_pkce_redirects_with_state_and_issuer() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("PKCE").await?;
        let mut pairs = Harness::params(&cid);
        pairs.retain(|(key, _)| *key != "code_challenge");
        // When
        let response = server.authorize(&pairs, None).await?;
        // Then
        assert_error_redirect(&response, "invalid_request", &server.base)?;
        server.close().await
    }

    /// Duplicate singleton parameters cannot choose a different client or grant.
    #[tokio::test]
    async fn authorize_repeated_parameters_are_rejected() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Duplicates").await?;
        for key in [
            "client_id",
            "redirect_uri",
            "response_type",
            "state",
            "scope",
            "code_challenge",
            "response_mode",
        ] {
            let mut pairs = Harness::params(&cid);
            if key == "response_mode" {
                pairs.push((key, "query"));
            }
            pairs.push((key, "injected"));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "duplicate {key}"
            );
        }
        server.close().await
    }

    /// Two resource indicators survive approval; `response_mode` and nonce never do.
    #[tokio::test]
    async fn authorize_forwards_only_allowlisted_parameters() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Allowlist").await?;
        let mut pairs = Harness::params(&cid);
        pairs.extend([
            ("resource", "https://one.example/mcp"),
            ("resource", "urn:two"),
            ("prompt", "login"),
            ("login_hint", "a\r\nX-Injected: yes"),
            ("ui_locales", "en"),
            ("response_mode", "form_post"),
            ("nonce", "ignored"),
            ("unrecognized", "ignored"),
        ]);
        let (request, cookie) = consent_form(server.authorize(&pairs, None).await?).await?;
        // When
        let response = server.decide(&request, &cookie, "approve").await?;
        // Then
        let url = location(&response)?;
        let actual: Vec<_> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        ensure!(actual.len() == 12, "exact allowlist count");
        for (key, value) in pairs
            .iter()
            .filter(|(key, _)| matches!(*key, "resource" | "prompt" | "login_hint" | "ui_locales"))
        {
            ensure!(
                actual.contains(&(key.to_string(), value.to_string())),
                "forwarded pair"
            );
        }
        ensure!(
            !actual
                .iter()
                .any(|(key, _)| matches!(key.as_str(), "response_mode" | "nonce" | "unrecognized")),
            "dropped extras"
        );
        ensure!(
            !response.headers().contains_key("x-injected"),
            "encoded header control bytes"
        );
        server.close().await
    }

    /// Protocol bounds reject bad resources, scopes, PKCE and forwarded extras.
    #[tokio::test]
    async fn authorize_rejects_parameter_boundaries() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Bounds").await?;
        let long_state = "s".repeat(513);
        let long_extra = "x".repeat(129);
        let long_resource = format!("https://example.test/{}", "a".repeat(256));
        for (key, value) in [
            ("state", long_state.as_str()),
            ("scope", long_state.as_str()),
            ("scope", "mcp:read\tadmin"),
            ("scope", "bad\"scope"),
            ("resource", "relative"),
            ("resource", "https://example.test/#frag"),
            ("resource", long_resource.as_str()),
            ("prompt", long_extra.as_str()),
            ("login_hint", long_extra.as_str()),
            ("ui_locales", long_extra.as_str()),
            ("code_challenge", "short"),
            ("code_challenge_method", "plain"),
        ] {
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(name, _value)| *name != key);
            pairs.push((key, value));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            ensure!(response.status() == 302, "protocol error status");
            let target = location(&response)?;
            ensure!(
                target
                    .query_pairs()
                    .any(|(name, received)| name == "error" && received == "invalid_request"),
                "invalid request"
            );
            let expected_state = if key == "state" {
                value
            } else {
                "client-state"
            };
            ensure!(
                target
                    .query_pairs()
                    .any(|(name, received)| name == "state" && received == expected_state),
                "original state echoed"
            );
        }
        let mut pairs = Harness::params(&cid);
        pairs.extend([
            ("resource", "urn:one"),
            ("resource", "urn:two"),
            ("resource", "urn:three"),
        ]);
        let response = server.authorize(&pairs, None).await?;
        assert_error_redirect(&response, "invalid_request", &server.base)?;
        server.close().await
    }

    /// Denial returns to the validated client and clears only this flow's CSRF cookie.
    #[tokio::test]
    async fn consent_deny_redirects_with_issuer() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Deny").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        // When
        let response = server.decide(&request, &cookie, "deny").await?;
        // Then
        assert_error_redirect(&response, "access_denied", &server.base)?;
        let cookies = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .collect::<Vec<_>>();
        ensure!(
            cookies.len() == 1
                && cookies
                    .first()
                    .context("cleared cookie")?
                    .to_str()?
                    .contains("Max-Age=0"),
            "CSRF cleared without state"
        );
        server.close().await
    }

    /// Tampering, wrong-flow cookies, fixation and wrong-purpose replay fail closed.
    #[tokio::test]
    async fn consent_rejects_integrity_and_cookie_substitution() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Integrity").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        let (_, other_cookie) = consent_form(server.page(&cid).await?).await?;
        let cookie_name = cookie.split_once('=').context("cookie name")?.0;
        let fixed = format!("{cookie_name}=attacker-nonce");
        let tampered = format!("{request}x");
        let huge = "x".repeat(8193);
        for (token, supplied) in [
            (tampered.as_str(), cookie.as_str()),
            ("v1.x", cookie.as_str()),
            (huge.as_str(), cookie.as_str()),
            (cid.as_str(), cookie.as_str()),
            (request.as_str(), other_cookie.as_str()),
            (request.as_str(), fixed.as_str()),
        ] {
            // When
            let response = server.decide(token, supplied, "approve").await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "integrity failure"
            );
            ensure!(
                !response.headers().contains_key("x-injected"),
                "no header injection"
            );
        }
        server.close().await
    }

    /// Form duplicates and invalid decisions cannot approve an ambiguous transaction.
    #[tokio::test]
    async fn consent_rejects_repeated_form_parameters() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Form").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        for extra in [
            ("request", request.as_str()),
            ("decision", "deny"),
            ("resource", "urn:one"),
        ] {
            let mut pairs = vec![("request", request.as_str()), ("decision", "approve")];
            if extra.0 == "resource" {
                pairs.push(extra);
            }
            pairs.push(extra);
            // When
            let response = server
                .client
                .post(format!("{}/oauth/consent", server.base))
                .header("cookie", &cookie)
                .body(
                    url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(pairs)
                        .finish(),
                )
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "duplicate form rejected"
            );
        }
        let response = server.decide(&request, &cookie, "maybe").await?;
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "unknown decision rejected"
        );
        server.close().await
    }

    /// Remembered approval skips the page, but broader scopes and another client do not.
    #[tokio::test]
    async fn remembered_consent_is_bound_to_client_and_scope() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Remembered").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        let approved = server.decide(&request, &cookie, "approve").await?;
        let remembered = response_cookie(&approved, "rmcp_consent_")?;
        // When
        let response = server
            .authorize(&Harness::params(&cid), Some(&remembered))
            .await?;
        // Then
        ensure!(response.status() == 302, "remembered consent fast path");
        ensure!(
            response_cookie(&response, "rmcp_state_").is_ok(),
            "new state cookie"
        );
        let mut broader = Harness::params(&cid);
        broader.retain(|(key, _)| *key != "scope");
        broader.push(("scope", "mcp:read mcp:admin"));
        let broader_response = server.authorize(&broader, Some(&remembered)).await?;
        ensure!(
            broader_response.status() == 200,
            "broader scope requires approval"
        );
        let other = server.register("Another client").await?;
        let foreign_response = server
            .authorize(&Harness::params(&other), Some(&remembered))
            .await?;
        ensure!(
            foreign_response.status() == 200,
            "cross-client consent replay rejected"
        );
        server.close().await
    }

    /// Zero duration always prompts and never issues a remembered-consent cookie.
    #[tokio::test]
    async fn zero_consent_ttl_always_prompts() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("0s").await?;
        let cid = server.register("Always ask").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        // When
        let response = server.decide(&request, &cookie, "approve").await?;
        // Then
        ensure!(
            response.status() == 302 && response_cookie(&response, "rmcp_consent_").is_err(),
            "no consent cookie"
        );
        let repeated = server.page(&cid).await?;
        ensure!(repeated.status() == 200, "ask again");
        server.close().await
    }

    /// The outer Origin guard accepts the same origin and blocks a hostile origin.
    #[tokio::test]
    async fn consent_hostile_origin_is_forbidden() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Origin").await?;
        let (request, cookie) = consent_form(server.page(&cid).await?).await?;
        // When
        let response = server
            .client
            .post(format!("{}/oauth/consent", server.base))
            .header("origin", "https://evil.example")
            .header("cookie", cookie)
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("request", request.as_str()), ("decision", "approve")])
                    .finish(),
            )
            .send()
            .await?;
        // Then
        ensure!(response.status() == 403, "outer guard status");
        ensure!(
            response.text().await? == "Forbidden: Origin not allowed",
            "outer guard response"
        );
        server.close().await
    }

    /// Independent public origins and concurrent flows have distinct cookie names.
    #[tokio::test]
    async fn cookie_names_isolate_servers_and_flows() -> anyhow::Result<()> {
        // Given
        let first = Harness::start("30days").await?;
        let second = Harness::start("30days").await?;
        let first_client = first.register("First").await?;
        let second_client = second.register("Second").await?;
        // When
        let (_, ca) = consent_form(first.page(&first_client).await?).await?;
        let (_, cb) = consent_form(second.page(&second_client).await?).await?;
        let (_, cc) = consent_form(first.page(&first_client).await?).await?;
        // Then
        ensure!(
            ca.split_once('=').map(|pair| pair.0) != cb.split_once('=').map(|pair| pair.0),
            "server isolation"
        );
        ensure!(
            ca.split_once('=').map(|pair| pair.0) != cc.split_once('=').map(|pair| pair.0),
            "flow isolation"
        );
        first.close().await?;
        second.close().await
    }

    /// Explicit passthrough retains the legacy static-client redirect without cookies.
    #[tokio::test]
    async fn passthrough_authorize_remains_unchanged() -> anyhow::Result<()> {
        // Given
        let server = Harness::start_mode("30days", "passthrough").await?;
        // When
        let response = server.page("legacy-client").await?;
        // Then
        ensure!(
            response.status() == 302 && !response.headers().contains_key("set-cookie"),
            "passthrough redirect"
        );
        let url = location(&response)?;
        ensure!(
            url.query_pairs()
                .any(|(key, value)| key == "client_id" && value == "static-upstream"),
            "legacy substitution"
        );
        ensure!(
            url.query_pairs()
                .any(|(key, value)| key == "redirect_uri" && value == CALLBACK),
            "legacy callback"
        );
        server.close().await
    }

    /// Parse only a valid Location header, never follow the callback.
    fn location(response: &Response) -> anyhow::Result<url::Url> {
        Ok(url::Url::parse(
            response
                .headers()
                .get("location")
                .context("Location")?
                .to_str()?,
        )?)
    }

    /// Inspect a protocol-error redirect while preserving the registered query string.
    fn assert_error_redirect(response: &Response, error: &str, issuer: &str) -> anyhow::Result<()> {
        ensure!(response.status() == 302, "protocol redirect status");
        let url = location(response)?;
        ensure!(
            url.host_str() == Some("127.0.0.1") && url.port() == Some(18999),
            "registered destination"
        );
        for (key, value) in [
            ("error", error),
            ("state", "client-state"),
            ("iss", issuer),
            ("original", "1"),
        ] {
            ensure!(
                url.query_pairs()
                    .any(|(name, received)| name == key && received == value),
                "redirect parameter {key}"
            );
        }
        Ok(())
    }

    /// Select one exact cookie family from a response for manual browser simulation.
    fn response_cookie(response: &Response, prefix: &str) -> anyhow::Result<String> {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(prefix))
            .and_then(|value| value.split(';').next())
            .map(str::to_owned)
            .context("cookie family")
    }

    /// Mandatory page policies override operators without changing ordinary API responses.
    #[tokio::test]
    async fn page_headers_override_only_marked_responses() -> anyhow::Result<()> {
        // Given
        let server = Harness::start_options("30days", "authorization_server", true).await?;
        let cid = server.register("Header isolation").await?;
        // When
        let response = server.page(&cid).await?;
        let error = server.page("bad-seal").await?;
        let api = server
            .client
            .get(format!("{}/healthz", server.base))
            .send()
            .await?;
        // Then
        ensure!(
            response
                .headers()
                .get("content-security-policy")
                .context("CSP")?
                == "default-src 'none'; style-src 'sha256-duPJE+yRsr7GWUwbG4KlBrtEWYrMTMxBbEoskxCsGOA='; frame-ancestors 'none'; base-uri 'none'",
            "consent CSP"
        );
        ensure!(
            error
                .headers()
                .get("content-security-policy")
                .context("error CSP")?
                == "default-src 'none'; style-src 'sha256-duPJE+yRsr7GWUwbG4KlBrtEWYrMTMxBbEoskxCsGOA='; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
            "error CSP"
        );
        for page in [&response, &error] {
            ensure!(
                page.headers().get("referrer-policy").context("referrer")? == "same-origin",
                "page referrer override"
            );
            ensure!(
                page.headers().get("cache-control").context("cache")? == "no-store",
                "page cache override"
            );
            ensure!(
                page.headers().get("x-frame-options").context("frame")? == "deny",
                "frame protection retained"
            );
        }
        ensure!(
            api.headers().get("cache-control").context("API cache")? == "public, max-age=3600",
            "nonpage override retained"
        );
        ensure!(
            api.headers()
                .get("referrer-policy")
                .context("API referrer")?
                == "no-referrer",
            "nonpage referrer retained"
        );
        server.close().await
    }

    /// Invalid UTF-8, oversized forms and JSON cannot create headers or redirect.
    #[tokio::test]
    async fn malformed_and_oversized_bodies_fail_closed() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        for (path, body) in [
            ("register", vec![255_u8]),
            ("register", b"{broken".to_vec()),
            ("register", vec![b'x'; 1024 * 1024 + 1]),
            ("oauth/consent", vec![255_u8]),
            ("oauth/consent", vec![b'x'; 0x8001]),
            (
                "oauth/consent",
                b"request=%FF%0D%0AX-Injected%3Ayes&decision=approve".to_vec(),
            ),
        ] {
            // When
            let response = server
                .client
                .post(format!("{}/{path}", server.base))
                .header("connection", "close")
                .body(body)
                .send()
                .await?;
            // Then
            ensure!(
                response.status().is_client_error(),
                "malformed body rejected"
            );
            ensure!(
                !response.headers().contains_key("location")
                    && !response.headers().contains_key("x-injected"),
                "no injected response"
            );
        }
        server.close().await
    }

    /// State cookies are flow-specific and cannot substitute for browser CSRF credentials.
    #[tokio::test]
    async fn state_cookie_cannot_approve_another_flow() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("State substitution").await?;
        let (first, cookie) = consent_form(server.page(&cid).await?).await?;
        let approved = server.decide(&first, &cookie, "approve").await?;
        let state_cookie = response_cookie(&approved, "rmcp_state_")?;
        let (second, _csrf) = consent_form(server.page(&cid).await?).await?;
        // When
        let response = server.decide(&second, &state_cookie, "approve").await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "state is not a CSRF credential"
        );
        server.close().await
    }

    /// Real curl drives registration, page retrieval and approval against a live listener.
    #[tokio::test]
    async fn live_curl_browser_flow() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        // When
        let registration = curl(vec![
            "-X".into(),
            "POST".into(),
            format!("{}/register", server.base),
            "-H".into(),
            "content-type: application/json".into(),
            "-d".into(),
            json!({"redirect_uris":[CALLBACK],"client_name":"Curl fixture"}).to_string(),
        ])
        .await?;
        let (_, body) = registration
            .split_once("\r\n\r\n")
            .context("register body")?;
        let client: Value = serde_json::from_str(body)?;
        let cid = client
            .get("client_id")
            .and_then(Value::as_str)
            .context("registered client")?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(Harness::params(cid))
            .finish();
        let page = curl(vec![format!("{}/authorize?{query}", server.base)]).await?;
        let csrf = page
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .and_then(|line| line.split(';').next())
            .context("curl csrf")?;
        let token = page
            .split("name=\"request\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .context("curl hidden request")?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("request", token), ("decision", "approve")])
            .finish();
        let approved = curl(vec![
            "-X".into(),
            "POST".into(),
            format!("{}/oauth/consent", server.base),
            "-H".into(),
            format!("cookie: {csrf}"),
            "-H".into(),
            format!("origin: {}", server.base),
            "-H".into(),
            "content-type: application/x-www-form-urlencoded".into(),
            "-d".into(),
            form,
        ])
        .await?;
        // Then
        ensure!(registration.starts_with("HTTP/1.1 201"), "curl register");
        ensure!(
            page.starts_with("HTTP/1.1 200")
                && page.contains("referrer-policy: same-origin")
                && page.contains("cache-control: no-store"),
            "curl page headers"
        );
        ensure!(
            approved.starts_with("HTTP/1.1 302")
                && approved.contains("rmcp_state_")
                && approved.contains("rmcp_consent_"),
            "curl approval cookies"
        );
        if let Ok(path) = env::var("RMCP_LANE11_PROBE_OUTPUT") {
            let transcript = format!(
                "curl -si POST /register\n{registration}\ncurl -si GET /authorize\n{page}\ncurl -si POST /oauth/consent\n{approved}\nAll curl processes exited 0; no temporary files created.\n"
            );
            spawn_blocking(move || fs::write(path, transcript)).await??;
        }
        server.close().await
    }

    /// Redirect text remains inert even when the exact registered URI contains HTML syntax.
    #[tokio::test]
    async fn consent_redirect_uri_html_is_escaped() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let uri = "https://example.test/cb?x=<script>&quote=\"'";
        let registered: Value = server
            .client
            .post(format!("{}/register", server.base))
            .json(&json!({"redirect_uris":[uri],"client_name":"Markup destination"}))
            .send()
            .await?
            .json()
            .await?;
        let cid = registered
            .get("client_id")
            .and_then(Value::as_str)
            .context("client")?;
        let mut pairs = Harness::params(cid);
        pairs.retain(|(key, _)| *key != "redirect_uri");
        pairs.push(("redirect_uri", uri));
        // When
        let response = server.authorize(&pairs, None).await?;
        // Then
        ensure!(response.status() == 200, "registered destination accepted");
        let html = response.text().await?;
        ensure!(
            html.contains("https://example.test/cb?x=&lt;script&gt;&amp;quote=&quot;&#39;")
                && !html.contains("<script>"),
            "destination is escaped text"
        );
        server.close().await
    }

    /// A forged first duplicate CSRF value cannot be rescued by a later valid value.
    #[tokio::test]
    async fn duplicate_csrf_cookie_first_match_wins() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Cookie ambiguity").await?;
        let (request, valid) = consent_form(server.page(&cid).await?).await?;
        let name = valid.split_once('=').context("name")?.0;
        let duplicate = format!("{name}=fixed; {valid}");
        // When
        let response = server.decide(&request, &duplicate, "approve").await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "first cookie fails browser binding"
        );
        server.close().await
    }

    /// A huge CSRF value and cookie-parser junk never become approval credentials.
    #[tokio::test]
    async fn oversized_csrf_cookie_fails_closed() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Cookie cap").await?;
        let (request, valid) = consent_form(server.page(&cid).await?).await?;
        let name = valid.split_once('=').context("name")?.0;
        let oversized = format!("junk; other=ok; {name}={}", "x".repeat(4097));
        // When
        let response = server.decide(&request, &oversized, "approve").await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "oversized browser nonce ignored"
        );
        server.close().await
    }

    /// Invalid trust inputs are rejected before response-type and PKCE error redirects.
    #[tokio::test]
    async fn authorize_validation_order_prevents_error_open_redirects() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Ordering").await?;
        for pairs in [
            vec![("redirect_uri", CALLBACK), ("response_type", "token")],
            vec![("client_id", cid.as_str()), ("response_type", "token")],
            vec![
                ("client_id", cid.as_str()),
                ("redirect_uri", "https://evil.example"),
                ("response_type", "token"),
            ],
        ] {
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "trust boundary precedes protocol redirects"
            );
        }
        server.close().await
    }

    /// Encoded malformed input cannot inject headers at any browser endpoint.
    #[tokio::test]
    async fn authorize_malformed_parameter_sweep_is_inert() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Parameter sweep").await?;
        let oversized = "x".repeat(0x8001);
        for query in [
            "client_id=%FF",
            "client_id=%0D%0AX-Injected%3Ayes",
            oversized.as_str(),
        ] {
            // When
            let response = server
                .client
                .get(format!("{}/authorize?{query}", server.base))
                .send()
                .await?;
            // Then
            ensure!(
                response.status().is_client_error()
                    && !response.headers().contains_key("location")
                    && !response.headers().contains_key("x-injected"),
                "malformed query fails closed"
            );
        }
        for value in ["\r\nX-Injected: yes", "<script>\"'&", "\u{fffd}"] {
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(key, _)| *key != "state");
            pairs.push(("state", value));
            pairs.retain(|(key, _)| *key != "code_challenge");
            let response = server.authorize(&pairs, None).await?;
            ensure!(
                response.status() == 302 && !response.headers().contains_key("x-injected"),
                "client state is encoded in redirect"
            );
            ensure!(
                location(&response)?
                    .query_pairs()
                    .any(|(key, received)| key == "state" && received == value),
                "state round trips without header interpretation"
            );
        }
        server.close().await
    }

    /// Name bounds count characters rather than UTF-8 bytes, while controls remain forbidden.
    #[tokio::test]
    async fn registration_unicode_character_boundary_is_respected() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        for (count, status) in [(128, 201), (129, 400)] {
            let name = "\u{e9}".repeat(count);
            // When
            let response = server
                .client
                .post(format!("{}/register", server.base))
                .json(&json!({"redirect_uris":[CALLBACK],"client_name":name}))
                .send()
                .await?;
            // Then
            ensure!(response.status() == status, "character boundary {count}");
        }
        server.close().await
    }

    /// Run a bounded curl subprocess without blocking the async runtime.
    async fn curl(arguments: Vec<String>) -> anyhow::Result<String> {
        let output = spawn_blocking(move || {
            Command::new("curl")
                .args(["-si", "--max-time", "10", "--noproxy", "*"])
                .args(arguments)
                .output()
        })
        .await??;
        ensure!(output.status.success(), "curl process exit");
        Ok(String::from_utf8(output.stdout)?)
    }

    // allow: SIZE_OK - one integration target exercises the facade end to end through shared harness helpers and contract tables.
    // Callback, downstream bindings and upstream token allowlists.

    /// Approve a distinct transaction and retain only its browser state credential.
    async fn approved_flow(
        server: &Harness,
        cid: &str,
        verifier: &str,
    ) -> anyhow::Result<(String, String)> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut pairs = Harness::params(cid);
        pairs.retain(|(key, _)| *key != "code_challenge");
        pairs.push(("code_challenge", &challenge));
        let (request, csrf) = consent_form(server.authorize(&pairs, None).await?).await?;
        let approved = server.decide(&request, &csrf, "approve").await?;
        ensure!(approved.status() == 302, "approved flow");
        let nonce = location(&approved)?
            .query_pairs()
            .find(|(key, _)| key == "state")
            .context("upstream state")?
            .1
            .into_owned();
        let cookie = approved
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("rmcp_state_"))
            .context("state cookie")?
            .split(';')
            .next()
            .context("cookie pair")?
            .to_owned();
        Ok((nonce, cookie))
    }

    /// Deliver an upstream outcome using the genuine per-flow browser credential.
    async fn callback_flow(
        server: &Harness,
        flow: &(String, String),
        code: &str,
    ) -> anyhow::Result<Response> {
        Ok(server
            .client
            .get(format!(
                "{}/oauth/callback?{}",
                server.base,
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("state", flow.0.as_str()), ("code", code)])
                    .finish()
            ))
            .header("cookie", &flow.1)
            .send()
            .await?)
    }

    /// Redeem through the real token route with a complete public-client form.
    async fn redeem(
        server: &Harness,
        cid: &str,
        code: &str,
        verifier: &str,
    ) -> anyhow::Result<Response> {
        use url::form_urlencoded;
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", cid),
                ("code", code),
                ("redirect_uri", CALLBACK),
                ("code_verifier", verifier),
            ])
            .finish();
        Ok(server
            .client
            .post(format!("{}/token", server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await?)
    }

    /// The completed browser flow redeems the wrapped code and preserves upstream JSON members.
    #[tokio::test]
    async fn full_flow_end_to_end() -> anyhow::Result<()> {
        use url::form_urlencoded;
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let cid = server
            .register("Task12 full flow distinct application")
            .await?;
        let verifier = "verifier-A0123456789abcdefghijklmnopqrstuvwxyz._~-XYZ";
        let flow = approved_flow(&server, &cid, verifier).await?;
        let jwt = upstream_jwt(&server).await?;
        Mock::given(method("POST")).and(path("/token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":jwt, "refresh_token":"upstream-refresh-task12", "expires_in":1739_u64,"custom":{"preserved":true}}))).expect(1).mount(&server.upstream).await;
        // When
        let callback = callback_flow(&server, &flow, "upstream-code-task12-distinct").await?;
        ensure!(callback.status() == 302, "callback status");
        ensure!(
            callback
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|value| value.to_str().is_ok_and(|text| text
                    == format!(
                        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
                        flow.1.split_once('=').map_or("", |pair| pair.0)
                    ))),
            "callback clears state"
        );
        let target = location(&callback)?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("wrapped code")?
            .1
            .into_owned();
        let response = redeem(&server, &cid, &code, verifier).await?;
        // Then
        ensure!(response.status() == 200, "token response");
        let output: Value = response.json().await?;
        ensure!(
            output.get("access_token") == Some(&json!(jwt))
                && output.get("expires_in") == Some(&json!(1739_u64))
                && output.get("custom") == Some(&json!({"preserved":true})),
            "upstream JSON members"
        );
        let refresh = output
            .get("refresh_token")
            .and_then(Value::as_str)
            .context("refresh wrapper")?;
        ensure!(
            reference_open("refresh", refresh)?
                == json!({"rt":"upstream-refresh-task12","cid":fixture_digest(&cid)}),
            "refresh binding wrapper"
        );
        let requests = server
            .upstream
            .received_requests()
            .await
            .context("requests")?;
        let actual: Vec<_> =
            form_urlencoded::parse(&requests.first().context("token request")?.body)
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
        let expected = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), "upstream-code-task12-distinct".into()),
            (
                "redirect_uri".into(),
                format!("{}/oauth/callback", server.base),
            ),
            ("code_verifier".into(), verifier.into()),
            ("client_id".into(), "static-upstream".into()),
        ];
        ensure!(actual == expected, "complete upstream form");
        for (key, value) in [("state", "client-state"), ("iss", server.base.as_str())] {
            ensure!(
                target
                    .query_pairs()
                    .any(|(name, received)| name == key && received == value),
                "client redirect binding {key}"
            );
        }
        let metadata: Value = server
            .client
            .get(format!(
                "{}/.well-known/oauth-authorization-server",
                server.base
            ))
            .send()
            .await?
            .json()
            .await?;
        ensure!(
            metadata.get("issuer") == Some(&json!(server.base))
                && metadata.get("authorization_response_iss_parameter_supported")
                    == Some(&json!(true)),
            "AS metadata"
        );
        assert_tools_list(&server, &jwt).await?;
        server.close().await
    }

    /// Initialize MCP and list tools through the JWT-authenticated transport surface.
    async fn assert_tools_list(server: &Harness, jwt: &str) -> anyhow::Result<()> {
        let initialized = server.client.post(format!("{}/mcp",server.base)).bearer_auth(jwt).header("accept","application/json, text/event-stream").header("content-type","application/json").body(r#"{"jsonrpc":"2.0","id":940,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"task12-client","version":"1"}}}"#).send().await?;
        ensure!(initialized.status() == 200, "MCP initialized");
        let session = initialized
            .headers()
            .get("mcp-session-id")
            .context("MCP session")?
            .to_str()?
            .to_owned();
        let listing = server
            .client
            .post(format!("{}/mcp", server.base))
            .bearer_auth(jwt)
            .header("mcp-session-id", session)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":941,"method":"tools/list"}"#)
            .send()
            .await?;
        ensure!(
            listing.status() == 200,
            "upstream JWT tools/list status {}",
            listing.status()
        );
        Ok(())
    }

    /// Mint a real RS256 upstream JWT and publish its key through the upstream JWKS route.
    async fn upstream_jwt(server: &Harness) -> anyhow::Result<String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use rsa::{
            pkcs8::{EncodePrivateKey as _, LineEnding},
            rand_core,
            traits::PublicKeyParts as _,
        };
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        let (pem,jwks) = spawn_blocking(|| -> anyhow::Result<_> {
            let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng,2048)?;
            let public = key.to_public_key();
            let jwks = json!({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"task12-upstream-key","n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});
            Ok((key.to_pkcs8_pem(LineEnding::LF)?.to_string(),jwks))
        }).await??;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server.upstream)
            .await;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("task12-upstream-key".into());
        let claims = json!({"iss":format!("http://localhost:{}",server.upstream.address().port()),"aud":"as-test","sub":"task12-resource-owner-distinct","scope":"task12:read","iat":jsonwebtoken::get_current_timestamp(),"exp":jsonwebtoken::get_current_timestamp().saturating_add(1937)});
        Ok(jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?,
        )?)
    }

    /// A foreign issuer is a nonredirecting integrity error that still clears state.
    #[tokio::test]
    async fn callback_rejects_issuer_mismatch() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Issuer mismatch app").await?;
        let flow = approved_flow(
            &server,
            &cid,
            "verifier-B9876543210ZYXWVUTSRQPONMLKJIHGFEDCBA._~-",
        )
        .await?;
        // When
        let response = server
            .client
            .get(format!(
                "{}/oauth/callback?{}",
                server.base,
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("state", flow.0.as_str()),
                        ("code", "issuer-bound-code"),
                        ("iss", "https://foreign-issuer.example"),
                    ])
                    .finish()
            ))
            .header("cookie", &flow.1)
            .send()
            .await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "issuer mismatch page"
        );
        ensure!(
            response
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|value| value.to_str().is_ok_and(|text| text
                    == format!(
                        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
                        flow.1.split_once('=').map_or("", |pair| pair.0)
                    ))),
            "error clears cookie"
        );
        server.close().await
    }

    /// Another registered client cannot redeem a genuine code and no upstream call occurs.
    #[tokio::test]
    async fn token_rejects_foreign_client() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let cid = server.register("Owner client A").await?;
        let foreign = server.register("Foreign client B").await?;
        let verifier = "verifier-CabcdefghijkLMNOPQRSTUVWXYZ0123456789._~-";
        let flow = approved_flow(&server, &cid, verifier).await?;
        let callback = callback_flow(&server, &flow, "foreign-client-upstream-code").await?;
        let target = location(&callback)?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("code")?
            .1
            .into_owned();
        // When
        let response = redeem(&server, &foreign, &code, verifier).await?;
        // Then
        ensure!(
            response.status() == 400
                && response.json::<Value>().await?.get("error") == Some(&json!("invalid_grant")),
            "foreign client rejected"
        );
        ensure!(
            server
                .upstream
                .received_requests()
                .await
                .context("requests")?
                .is_empty(),
            "no upstream side effect"
        );
        server.close().await
    }

    /// Missing, repeated and unsupported token parameters return RFC 6749 JSON errors.
    #[tokio::test]
    async fn token_error_contract_table() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        for (body, status, error) in [
            ("", 400, "invalid_request"),
            ("grant_type=password", 400, "unsupported_grant_type"),
            ("grant_type=refresh_token", 400, "invalid_request"),
            ("grant_type=authorization_code", 400, "invalid_request"),
            (
                "grant_type=refresh_token&refresh_token=raw",
                400,
                "invalid_grant",
            ),
            (
                "grant_type=refresh_token&grant_type=refresh_token",
                400,
                "invalid_request",
            ),
        ] {
            // When
            let response = server
                .client
                .post(format!("{}/token", server.base))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == status && !response.headers().contains_key("location"),
                "token error status"
            );
            ensure!(
                response
                    .headers()
                    .get("cache-control")
                    .context("no store")?
                    .to_str()?
                    .split(',')
                    .any(|directive| directive.trim() == "no-store"),
                "token never cached"
            );
            ensure!(
                response.json::<Value>().await?.get("error") == Some(&json!(error)),
                "RFC error {error}"
            );
        }
        server.close().await
    }

    /// A substituted upstream code cannot bypass the downstream challenge before contacting the IdP.
    #[tokio::test]
    async fn pkce_substitution_across_flows_is_rejected_locally() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        let first = server.register("Substitution client A distinct").await?;
        let second = server.register("Substitution client B different").await?;
        let verifier_a = "PKCE-A0123456789abcdefghijklmnopqrstuvwxyzUVWXYZ._~-";
        let verifier_b = "PKCE-B9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAabcdef._~-";
        let _flow_a = approved_flow(&server, &first, verifier_a).await?;
        let flow_b = approved_flow(&server, &second, verifier_b).await?;
        let callback = callback_flow(&server, &flow_b, "upstream-code-from-client-A").await?;
        let target = location(&callback)?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("code")?
            .1
            .into_owned();
        // When
        let response = redeem(&server, &second, &code, verifier_a).await?;
        // Then
        ensure!(
            response.status() == 400
                && response.json::<Value>().await?.get("error") == Some(&json!("invalid_grant")),
            "substitution denied"
        );
        ensure!(
            server
                .upstream
                .received_requests()
                .await
                .context("requests")?
                .is_empty(),
            "PKCE checked before upstream"
        );
        server.close().await
    }

    /// Refresh credentials retain their original client binding even across upstream rotation.
    #[tokio::test]
    async fn refresh_keeps_client_binding_across_upstream_rotation() -> anyhow::Result<()> {
        use url::form_urlencoded;
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let owner = server.register("Refresh original owner A").await?;
        let verifier = "refresh-flow-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        let code = reference_seal(
            "fixture-secret-with-at-least-32-bytes",
            "code",
            &json!({"kc":"refresh-initial-code-unique","cid":fixture_digest(&owner),"ru":CALLBACK,
                "cc":fixture_digest(verifier),"exp":jsonwebtoken::get_current_timestamp().saturating_add(117)}),
        )?;
        Mock::given(method("POST")).and(path("/token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"refresh-access-initial","refresh_token":"raw-refresh-initial-A"}))).mount(&server.upstream).await;
        let initial: Value = redeem(&server, &owner, &code, verifier)
            .await?
            .json()
            .await?;
        let mut wrapped = initial
            .get("refresh_token")
            .and_then(Value::as_str)
            .context("refresh")?
            .to_owned();
        ensure!(
            reference_open("refresh", &wrapped)?
                == json!({"rt":"raw-refresh-initial-A","cid":fixture_digest(&owner)}),
            "initial independent owner and raw token"
        );
        for (client, raw, rotated) in [
            (
                Some(owner.as_str()),
                "raw-refresh-initial-A",
                "raw-refresh-rotation-B",
            ),
            (
                Some(owner.as_str()),
                "raw-refresh-rotation-B",
                "raw-refresh-rotation-C",
            ),
            (None, "raw-refresh-rotation-C", "raw-refresh-rotation-D"),
        ] {
            server.upstream.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"access_token":"refresh-access-rotated","refresh_token":rotated}),
                ))
                .expect(1)
                .mount(&server.upstream)
                .await;
            let mut pairs = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", wrapped.as_str()),
            ];
            if let Some(cid) = client {
                pairs.push(("client_id", cid));
            }
            let form = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            // When
            let response = server
                .client
                .post(format!("{}/token", server.base))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form)
                .send()
                .await?;
            // Then
            ensure!(response.status() == 200, "refresh status");
            let json: Value = response.json().await?;
            let issued = json
                .get("refresh_token")
                .and_then(Value::as_str)
                .context("rotated")?;
            ensure!(
                reference_open("refresh", issued)?
                    == json!({"rt":rotated,"cid":fixture_digest(&owner)}),
                "rotation raw token and independent owner digest"
            );
            let requests = server
                .upstream
                .received_requests()
                .await
                .context("requests")?;
            ensure!(
                requests.len() == 1
                    && requests.first().context("refresh request")?.body
                        == format!(
                            "grant_type=refresh_token&refresh_token={raw}&client_id=static-upstream"
                        )
                        .as_bytes(),
                "exact refresh form uses this generation raw token"
            );
            wrapped = issued.to_owned();
        }
        server.close().await
    }

    /// Local malformed callback inputs remain nonredirecting pages with forced security headers.
    #[tokio::test]
    async fn malformed_callbacks_render_nonredirecting_pages() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("30days").await?;
        for query in [
            "",
            "state=short",
            "state=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "state=x&state=y",
            "code=x&code=y",
        ] {
            // When
            let response = server
                .client
                .get(format!("{}/oauth/callback?{query}", server.base))
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "callback integrity page"
            );
            for (header, expected) in [
                (
                    "content-security-policy",
                    "default-src 'none'; style-src 'sha256-duPJE+yRsr7GWUwbG4KlBrtEWYrMTMxBbEoskxCsGOA='; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
                ),
                ("referrer-policy", "same-origin"),
                ("cache-control", "no-store"),
                ("x-frame-options", "DENY"),
                ("x-content-type-options", "nosniff"),
            ] {
                ensure!(
                    response
                        .headers()
                        .get(header)
                        .context("security header")?
                        .to_str()?
                        .eq_ignore_ascii_case(expected),
                    "callback header {header}"
                );
            }
            ensure!(
                response.text().await?.starts_with("<!DOCTYPE html>"),
                "HTML error page"
            );
        }
        server.close().await
    }

    /// Upstream non-JSON successes and error bytes are not rewritten in authorization-server mode.
    #[tokio::test]
    async fn upstream_token_responses_are_relayed_unrewritten() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let client = server.register("Response relay contract").await?;
        let verifier = "relay-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        for (status, body) in [
            (200, "not json upstream body"),
            (
                400,
                "{ \"error\": \"invalid_grant\", \"refresh_token\": \"raw-error-only\" }",
            ),
            (201, "[1, 2, 3]"),
        ] {
            server.upstream.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server.upstream)
                .await;
            let flow = approved_flow(&server, &client, verifier).await?;
            let callback = callback_flow(&server, &flow, "relay-distinct-upstream-code").await?;
            let target = location(&callback)?;
            let code = target
                .query_pairs()
                .find(|(key, _)| key == "code")
                .context("code")?
                .1
                .into_owned();
            // When
            let response = redeem(&server, &client, &code, verifier).await?;
            // Then
            ensure!(
                response.status() == status && response.text().await? == body,
                "upstream exact status/bytes"
            );
        }
        server.close().await
    }

    /// The issuer chain is byte-identical with either public URL spelling.
    #[tokio::test]
    async fn discovery_issuer_chain_ignores_public_url_trailing_slash() -> anyhow::Result<()> {
        // Given
        for trailing in [false, true] {
            let server =
                Harness::start_extended("30days", "authorization_server", false, trailing).await?;
            let client = server.register("Discovery chain application").await?;
            let flow = approved_flow(
                &server,
                &client,
                "discovery-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-",
            )
            .await?;
            // When
            let response = callback_flow(&server, &flow, "discovery-upstream-code").await?;
            let target = location(&response)?;
            let metadata: Value = server
                .client
                .get(format!(
                    "{}/.well-known/oauth-authorization-server",
                    server.base
                ))
                .send()
                .await?
                .json()
                .await?;
            let resource: Value = server
                .client
                .get(format!(
                    "{}/.well-known/oauth-protected-resource/mcp",
                    server.base
                ))
                .send()
                .await?
                .json()
                .await?;
            // Then
            ensure!(
                metadata.get("issuer") == Some(&json!(server.base))
                    && resource
                        .get("authorization_servers")
                        .and_then(Value::as_array)
                        .and_then(|values| values.first())
                        == metadata.get("issuer")
                    && target
                        .query_pairs()
                        .any(|(key, value)| key == "iss" && value == server.base),
                "discovery chain trailing={trailing}"
            );
            server.close().await?;
        }
        Ok(())
    }

    /// A non-canonical public URL is rejected by `validate()` before `serve`, naming the canonical form.
    #[tokio::test]
    async fn discovery_issuer_chain_rejects_non_canonical_public_url() -> anyhow::Result<()> {
        // Given
        for (spelling, canonical) in [
            ("https://MCP.Example.com", "https://mcp.example.com"),
            ("https://mcp.example.com:443", "https://mcp.example.com"),
            ("http://LOCALHOST:8080", "http://localhost:8080"),
            ("http://localhost:80", "http://localhost"),
            ("https://[0:0:0:0:0:0:0:1]:8443", "https://[::1]:8443"),
        ] {
            // When
            let result = Harness::start_public(
                "30days",
                "authorization_server",
                (false, false),
                Some(spelling),
            )
            .await;
            // Then
            let message = match result {
                Ok(server) => {
                    server.close().await?;
                    anyhow::bail!("{spelling} must be rejected before serve");
                }
                Err(err) => err.to_string(),
            };
            ensure!(
                message.contains(&format!("use {canonical:?}"))
                    && message.contains("server.public_url")
                    && message.contains("RFC 8414 section 3.3"),
                "{spelling}: {message}"
            );
        }
        Ok(())
    }

    /// Admin routes unwrap current/previous refresh wrappers and retain unwrapped access-token behavior.
    #[tokio::test]
    async fn admin_routes_unwrap_current_and_previous_refresh_wrappers() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start_extended("30days", "authorization_server", false, true).await?;
        for endpoint in ["introspect", "revoke"] {
            Mock::given(method("POST"))
                .and(path(format!("/{endpoint}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("{\"active\":true}"))
                .mount(&server.upstream)
                .await;
            for secret in [
                "fixture-secret-with-at-least-32-bytes",
                "previous-lane12-key-with-more-than-32-bytes",
            ] {
                let wrapped = reference_seal(
                    secret,
                    "refresh",
                    &json!({"rt":"admin-upstream-refresh-unique","cid":"admin-client-binding-unique"}),
                )?;
                let form = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("token", wrapped.as_str()),
                        ("token_type_hint", "refresh_token"),
                    ])
                    .finish();
                // When
                let response = server
                    .client
                    .post(format!("{}/{endpoint}", server.base))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(form)
                    .send()
                    .await?;
                // Then
                ensure!(response.status() == 200, "admin status");
                let requests = server
                    .upstream
                    .received_requests()
                    .await
                    .context("requests")?;
                ensure!(requests.last().context("admin request")?.body == b"token=admin-upstream-refresh-unique&token_type_hint=refresh_token&client_id=static-upstream","admin exact raw form");
            }
            for (body, status) in [
                ("token=access%2Funique&custom=kept", 200),
                ("token=a&token=b", 400),
            ] {
                let response = server
                    .client
                    .post(format!("{}/{endpoint}", server.base))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await?;
                ensure!(response.status() == status, "admin raw/duplicate status");
                if status == 200 {
                    let requests = server
                        .upstream
                        .received_requests()
                        .await
                        .context("requests")?;
                    ensure!(
                        requests.last().context("access request")?.body
                            == b"token=access%2Funique&custom=kept&client_id=static-upstream",
                        "admin access form unchanged"
                    );
                } else {
                    ensure!(
                        response.json::<Value>().await?.get("error")
                            == Some(&json!("invalid_request")),
                        "admin duplicate JSON"
                    );
                }
            }
        }
        server.close().await
    }

    /// Independently encode the documented purpose-separated integrity envelope for rotation fixtures.
    fn reference_seal(secret: &str, label: &str, payload: &Value) -> anyhow::Result<String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha2::Sha256;
        let mut derivation = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
        derivation.update(format!("rmcp-server-kit/oauth-as/v1/{label}").as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&derivation.finalize().into_bytes())?;
        let message = format!(
            "v1.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
        );
        mac.update(message.as_bytes());
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Hash fixture inputs independently of the server's binding implementation.
    fn fixture_digest(value: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    /// Authenticate an observed wrapper using the independent fixture sealer before opening it.
    fn reference_open(label: &str, token: &str) -> anyhow::Result<Value> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha2::Sha256;
        let (message, tag) = token.rsplit_once('.').context("envelope tag")?;
        let mut derivation =
            Hmac::<Sha256>::new_from_slice(b"fixture-secret-with-at-least-32-bytes")?;
        derivation.update(format!("rmcp-server-kit/oauth-as/v1/{label}").as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&derivation.finalize().into_bytes())?;
        mac.update(message.as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(tag)?)?;
        visible_payload(token)
    }

    /// Independently sealed previous-key codes redeem, while unknown keys and expired codes fail locally.
    #[tokio::test]
    async fn previous_key_codes_redeem_and_unknown_or_expired_codes_fail() -> anyhow::Result<()> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let client = server.register("Previous code key app").await?;
        let verifier = "previous-key-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(client.as_bytes()));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"previous-key-access-distinct"})),
            )
            .expect(1)
            .mount(&server.upstream)
            .await;
        for (key, expired, status) in [
            ("previous-lane12-key-with-more-than-32-bytes", false, 200),
            ("foreign-lane12-key-never-configured-here", false, 400),
            ("fixture-secret-with-at-least-32-bytes", true, 400),
        ] {
            let deadline = if expired {
                1_u64
            } else {
                jsonwebtoken::get_current_timestamp().saturating_add(113)
            };
            let code = reference_seal(
                key,
                "code",
                &json!({"kc":"previous-key-upstream-code","cid":digest,"ru":CALLBACK,"cc":challenge,"exp":deadline}),
            )?;
            // When
            let response = redeem(&server, &client, &code, verifier).await?;
            // Then
            ensure!(response.status() == status, "code key/expiry");
        }
        server.close().await
    }

    /// Shared signing keys allow registration/approval on one replica and callback/exchange on another.
    #[tokio::test]
    async fn two_replicas_share_one_stateless_flow() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let first = Harness::start("30days").await?;
        let second = Harness::start("30days").await?;
        let client = first.register("Cross replica client unique").await?;
        let verifier = "replica-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        let flow = approved_flow(&first, &client, verifier).await?;
        let cookie_name = flow.1.split_once('=').context("cookie")?.0;
        let other_flow = approved_flow(&second, &client, verifier).await?;
        let second_name = other_flow.1.split_once('=').context("second cookie")?.0;
        let nonce_suffix = cookie_name
            .get(cookie_name.len().saturating_sub(16)..)
            .context("nonce suffix")?;
        let issuer_prefix = second_name
            .get(..second_name.len().saturating_sub(17))
            .context("issuer prefix")?;
        let cookie_value = flow.1.split_once('=').context("cookie value")?.1;
        let cross_flow = (
            flow.0,
            format!("{issuer_prefix}_{nonce_suffix}={cookie_value}"),
        );
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"replica-upstream-access"})),
            )
            .expect(1)
            .mount(&second.upstream)
            .await;
        // When
        let callback = callback_flow(&second, &cross_flow, "replica-upstream-code").await?;
        let target = location(&callback)?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("code")?
            .1
            .into_owned();
        let response = redeem(&second, &client, &code, verifier).await?;
        // Then
        ensure!(response.status() == 200, "replica exchange");
        first.close().await?;
        second.close().await
    }

    /// Drive a full browser-to-token flow using bounded curl processes without writing credentials.
    #[tokio::test]
    async fn curl_drives_complete_browser_to_token_flow() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let client = server.register("Live curl complete app").await?;
        let verifier = "live-curl-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        let flow = approved_flow(&server, &client, verifier).await?;
        Mock::given(method("POST")).and(path("/token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"live-curl-upstream-access","refresh_token":"live-curl-upstream-refresh"}))).expect(1).mount(&server.upstream).await;
        // When
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("state", flow.0.as_str()),
                ("code", "live-curl-upstream-code"),
            ])
            .finish();
        let callback = curl(vec![
            format!("{}/oauth/callback?{query}", server.base),
            "-H".into(),
            format!("cookie: {}", flow.1),
        ])
        .await?;
        let location_header = callback
            .lines()
            .find_map(|line| line.strip_prefix("location: "))
            .context("curl redirect")?;
        let target = url::Url::parse(location_header.trim())?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .context("code")?
            .1
            .into_owned();
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", client.as_str()),
                ("code", code.as_str()),
                ("redirect_uri", CALLBACK),
                ("code_verifier", verifier),
            ])
            .finish();
        let token = curl(vec![
            format!("{}/token", server.base),
            "-H".into(),
            "content-type: application/x-www-form-urlencoded".into(),
            "-d".into(),
            form,
        ])
        .await?;
        // Then
        let clear = format!(
            "set-cookie: {}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            flow.1.split_once('=').context("cookie name")?.0
        );
        ensure!(
            callback.starts_with("HTTP/1.1 302")
                && callback.lines().any(|line| line.trim_end() == clear),
            "curl callback exact clearing cookie"
        );
        ensure!(token.starts_with("HTTP/1.1 200"), "curl token status");
        let body: Value =
            serde_json::from_str(token.split_once("\r\n\r\n").context("curl body")?.1)?;
        let refresh = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .context("curl refresh")?;
        ensure!(
            body == json!({"access_token":"live-curl-upstream-access","refresh_token":refresh}),
            "curl exact response members"
        );
        ensure!(
            reference_open("refresh", refresh)?
                == json!({"rt":"live-curl-upstream-refresh","cid":fixture_digest(&client)}),
            "curl refresh owner and raw token"
        );
        if let Ok(path) = env::var("RMCP_LANE12_LIVE_OUTPUT") {
            spawn_blocking(move || fs::write(path,"Live loopback serve_with_listener + wiremock upstream.\nRegistration 201; authorize 200; consent approval 302.\ncurl GET /oauth/callback: HTTP/1.1 302, state cookie Max-Age=0.\ncurl POST /token: HTTP/1.1 200, access token relayed, refresh token wrapped.\nBoth curl processes exited 0. Credentials intentionally omitted from artifact.\n")).await??;
        }
        server.close().await
    }

    /// The upstream response cap fails closed at cap plus one and preserves bytes at/below it.
    #[tokio::test]
    async fn upstream_token_body_cap_fails_closed_above_limit() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start("30days").await?;
        let client = server.register("Token response cap app").await?;
        let verifier = "body-cap-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
        for size in [0x000f_ffff_usize, 0x0010_0000, 0x0010_0001] {
            server.upstream.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_string("b".repeat(size)))
                .mount(&server.upstream)
                .await;
            let flow = approved_flow(&server, &client, verifier).await?;
            let callback = callback_flow(&server, &flow, "body-cap-upstream-code").await?;
            let target = location(&callback)?;
            let code = target
                .query_pairs()
                .find(|(key, _)| key == "code")
                .context("code")?
                .1
                .into_owned();
            // When
            let response = redeem(&server, &client, &code, verifier).await?;
            // Then
            ensure!(
                response.status() == if size <= 0x0010_0000 { 200 } else { 502 },
                "body cap status"
            );
            if size <= 0x0010_0000 {
                ensure!(response.bytes().await?.len() == size, "exact body length");
            } else {
                ensure!(
                    response.json::<Value>().await?.get("error") == Some(&json!("server_error")),
                    "cap RFC JSON"
                );
            }
        }
        server.close().await
    }

    /// Passthrough admin adapters preserve exact upstream request forms and response bytes.
    #[tokio::test]
    async fn passthrough_admin_preserves_exact_forms_and_bytes() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start_extended("30days", "passthrough", false, true).await?;
        for endpoint in ["introspect", "revoke"] {
            let response_bytes = "{ \"active\" : true, \"refresh_token\" : \"raw-not-wrapped\" }\n";
            Mock::given(method("POST"))
                .and(path(format!("/{endpoint}")))
                .respond_with(ResponseTemplate::new(202).set_body_string(response_bytes))
                .mount(&server.upstream)
                .await;
            // When
            let response = server
                .client
                .post(format!("{}/{endpoint}", server.base))
                .header("content-type", "application/x-www-form-urlencoded")
                .body("token=access%2Fraw&token=second&hint=%41&client_id=ignored")
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == 202 && response.text().await? == response_bytes,
                "passthrough exact response"
            );
            let requests = server
                .upstream
                .received_requests()
                .await
                .context("requests")?;
            ensure!(
                requests.last().context("request")?.body
                    == b"token=access%2Fraw&token=second&hint=A&client_id=static-upstream",
                "passthrough exact form"
            );
        }
        server.close().await
    }

    /// Passthrough token responses retain refresh strings and whitespace without JSON rewriting.
    #[tokio::test]
    async fn passthrough_token_responses_keep_refresh_bytes() -> anyhow::Result<()> {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        // Given
        let server = Harness::start_mode("30days", "passthrough").await?;
        let original = "{ \"access_token\" : \"passthrough-access-unique\", \"refresh_token\" : \"passthrough-refresh-never-wrapped\", \"expires_in\" : 1913 }\n";
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(original))
            .expect(1)
            .mount(&server.upstream)
            .await;
        // When
        let response = server.client.post(format!("{}/token",server.base)).header("content-type","application/x-www-form-urlencoded").body("grant_type=refresh_token&refresh_token=raw-input-distinct&client_id=ignored-downstream").send().await?;
        // Then
        ensure!(
            response.status() == 200 && response.text().await? == original,
            "passthrough refresh exact bytes"
        );
        let requests = server
            .upstream
            .received_requests()
            .await
            .context("requests")?;
        ensure!(requests.first().context("request")?.body == b"grant_type=refresh_token&refresh_token=raw-input-distinct&client_id=static-upstream","passthrough refresh exact form");
        server.close().await
    }

    // Boundaries, error kinds, cookies and interpolation.

    /// Decode the public integrity-only envelope without treating it as authenticated input.
    fn visible_payload(token: &str) -> anyhow::Result<Value> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = token.split('.').nth(1).context("sealed payload")?;
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
    }

    /// Require the entire registered error destination, including state presence and issuer.
    fn exact_error(
        response: &Response,
        expected: (&str, Option<&str>),
        issuer: &str,
    ) -> anyhow::Result<()> {
        ensure!(response.status() == 302, "protocol error status");
        let mut target = url::Url::parse(CALLBACK)?;
        let _query = target
            .query_pairs_mut()
            .append_pair("error", expected.0)
            .append_pair("iss", issuer);
        if let Some(state) = expected.1 {
            let _state_pair = target.query_pairs_mut().append_pair("state", state);
        }
        ensure!(
            location(response)? == target,
            "exact error destination and parameters"
        );
        Ok(())
    }

    /// Every authorize numeric boundary observes both neighbors and the exact outcome class.
    #[tokio::test]
    async fn authorize_rejects_values_at_each_size_bound() -> anyhow::Result<()> {
        use core::iter::repeat_n;
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Boundary table").await?;
        for (key, bound) in [
            ("state", 512_usize),
            ("scope", 512),
            ("prompt", 128),
            ("login_hint", 128),
            ("ui_locales", 128),
            ("resource", 256),
            ("code_challenge", 128),
        ] {
            for size in [bound.saturating_sub(1), bound, bound.saturating_add(1)] {
                let value = if key == "resource" {
                    format!("urn:{}", "x".repeat(size.saturating_sub(4)))
                } else {
                    "x".repeat(size)
                };
                let mut pairs = Harness::params(&cid);
                pairs.retain(|(name, _)| *name != key);
                pairs.push((key, &value));
                // When
                let response = server.authorize(&pairs, None).await?;
                // Then
                if size <= bound {
                    ensure!(
                        response.status() == 200 && !response.headers().contains_key("location"),
                        "accepted {key} length {size}"
                    );
                } else {
                    let state = if key == "state" {
                        value.as_str()
                    } else {
                        "client-state"
                    };
                    exact_error(&response, ("invalid_request", Some(state)), &server.base)?;
                }
            }
        }
        for (size, accepted) in [(42, false), (43, true), (44, true)] {
            let challenge = "a".repeat(size);
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(key, _)| *key != "code_challenge");
            pairs.push(("code_challenge", &challenge));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            if accepted {
                ensure!(response.status() == 200, "PKCE lower boundary {size}");
            } else {
                exact_error(
                    &response,
                    ("invalid_request", Some("client-state")),
                    &server.base,
                )?;
            }
        }
        for count in [1, 2, 3] {
            let mut pairs = Harness::params(&cid);
            pairs.extend(repeat_n(("resource", "urn:resource"), count));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then
            if count <= 2 {
                ensure!(response.status() == 200, "resource count {count}");
            } else {
                exact_error(
                    &response,
                    ("invalid_request", Some("client-state")),
                    &server.base,
                )?;
            }
        }
        server.close().await
    }

    /// Registration count, per-URI, aggregate and character bounds distinguish both neighbors.
    #[tokio::test]
    async fn registration_bounds_distinguish_both_neighbors() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let mut cases = Vec::new();
        for count in [0, 1, 2, 4, 5, 6] {
            cases.push((
                json!({"redirect_uris":vec![CALLBACK; count]}),
                (1..=5).contains(&count),
                "invalid_redirect_uri",
            ));
        }
        for size in [511_usize, 512, 513] {
            let uri = format!(
                "https://example.test/{}",
                "x".repeat(size.saturating_sub(21))
            );
            ensure!(uri.len() == size, "fixture URI byte length");
            cases.push((
                json!({"redirect_uris":[uri]}),
                size <= 512,
                "invalid_redirect_uri",
            ));
        }
        for total in [2047_usize, 2048, 2049] {
            let sizes = [512, 512, 512, total.saturating_sub(1568), 32];
            let uris: Vec<_> = sizes
                .into_iter()
                .map(|size| {
                    format!(
                        "https://example.test/{}",
                        "x".repeat(size.saturating_sub(21))
                    )
                })
                .collect();
            ensure!(
                uris.iter().map(String::len).sum::<usize>() == total,
                "fixture aggregate URI bytes"
            );
            cases.push((
                json!({"redirect_uris":uris}),
                total <= 2048,
                "invalid_redirect_uri",
            ));
        }
        for count in [127, 128, 129] {
            cases.push((
                json!({"redirect_uris":[CALLBACK],"client_name":"\u{e9}".repeat(count)}),
                count <= 128,
                "invalid_client_metadata",
            ));
        }
        for ch in ['\0', '\t', '\n', '\r', '\u{7f}', '\u{85}'] {
            cases.push((
                json!({"redirect_uris":[CALLBACK],"client_name":format!("app{ch}")}),
                false,
                "invalid_client_metadata",
            ));
        }
        for (input, accepted, error) in cases {
            // When
            let response = server
                .client
                .post(format!("{}/register", server.base))
                .json(&input)
                .send()
                .await?;
            // Then
            ensure!(
                !response.headers().contains_key("location"),
                "registration never redirects"
            );
            ensure!(
                response.status() == if accepted { 201 } else { 400 },
                "registration boundary"
            );
            let body: Value = response.json().await?;
            if accepted {
                ensure!(
                    body.get("redirect_uris") == input.get("redirect_uris"),
                    "exact registered URIs"
                );
            } else {
                ensure!(
                    body.get("error") == Some(&json!(error)),
                    "registration error kind"
                );
            }
        }
        server.close().await
    }

    /// All protocol-error causes preserve only registered destinations and the original state.
    #[tokio::test]
    async fn protocol_errors_redirect_only_to_registered_uri_with_state() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Error table").await?;
        let cases = [
            ("response_type", None, "unsupported_response_type"),
            (
                "response_type",
                Some("token<img/src=x>&'\""),
                "unsupported_response_type",
            ),
            ("code_challenge_method", None, "invalid_request"),
            ("code_challenge_method", Some("plain"), "invalid_request"),
            ("code_challenge", None, "invalid_request"),
            ("code_challenge", Some("short"), "invalid_request"),
            ("scope", Some("bad\\scope"), "invalid_request"),
            ("scope", Some("bad\"scope"), "invalid_request"),
            ("scope", Some("bad\tscope"), "invalid_request"),
            (
                "resource",
                Some("relative<img/src=x>&'\""),
                "invalid_request",
            ),
            ("resource", Some("urn:resource#fragment"), "invalid_request"),
        ];
        for supplied_state in [None, Some("client-state"), Some("<img/src=x>&'\"")] {
            for (key, value, error) in cases {
                let mut pairs = Harness::params(&cid);
                pairs.retain(|(name, _)| *name != key && *name != "state");
                if let Some(state) = supplied_state {
                    pairs.push(("state", state));
                }
                if let Some(supplied) = value {
                    pairs.push((key, supplied));
                }
                // When
                let response = server.authorize(&pairs, None).await?;
                // Then
                exact_error(&response, (error, supplied_state), &server.base)?;
            }
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(key, _)| *key != "state");
            if let Some(state) = supplied_state {
                pairs.push(("state", state));
            }
            let (token, csrf) = consent_form(server.authorize(&pairs, None).await?).await?;
            // When
            let response = server.decide(&token, &csrf, "deny").await?;
            // Then
            exact_error(&response, ("access_denied", supplied_state), &server.base)?;
        }
        server.close().await
    }

    /// Every ASCII PKCE character is classified at an otherwise valid length.
    #[tokio::test]
    async fn pkce_classifies_every_ascii_character() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Alphabet table").await?;
        for byte in 0_u8..=127 {
            let value = format!("{}{}", "a".repeat(42), char::from(byte));
            let mut pairs = Harness::params(&cid);
            pairs.retain(|(key, _)| *key != "code_challenge");
            pairs.push(("code_challenge", &value));
            // When
            let response = server.authorize(&pairs, None).await?;
            // Then: RFC 7636 unreserved alphabet, independently enumerated as ranges.
            if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
                ensure!(response.status() == 200, "PKCE accepted byte {byte}");
            } else {
                exact_error(
                    &response,
                    ("invalid_request", Some("client-state")),
                    &server.base,
                )?;
            }
        }
        server.close().await
    }

    /// A slash at the end of a query is not equivalent to the registered query.
    #[tokio::test]
    async fn redirect_query_trailing_slash_is_distinct() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Exact query").await?;
        let mut pairs = Harness::params(&cid);
        pairs.retain(|(key, _)| *key != "redirect_uri");
        pairs.push(("redirect_uri", "http://127.0.0.1:18999/cb?original=1/"));
        // When
        let response = server.authorize(&pairs, None).await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "unregistered query is a nonredirecting page"
        );
        server.close().await
    }

    /// The observable pending-request deadline is exactly ten minutes after page issuance.
    #[tokio::test]
    async fn pending_request_lifetime_is_600_seconds() -> anyhow::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Pending lifetime").await?;
        let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // When
        let (token, _) = consent_form(server.page(&cid).await?).await?;
        // Then
        let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expiry = visible_payload(&token)?
            .get("exp")
            .and_then(Value::as_u64)
            .context("expiry")?;
        ensure!(
            (before.saturating_add(600)..=after.saturating_add(600)).contains(&expiry),
            "pending request deadline lies within issuance interval plus 600"
        );
        server.close().await
    }

    /// Cookies expose the complete contract, not merely a matching family substring.
    fn cookie_contract(
        response: &Response,
        issuer: &str,
        ages: &[(&str, u64)],
    ) -> anyhow::Result<()> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        let digest: String = Sha256::digest(issuer.as_bytes())
            .iter()
            .flat_map(|byte| {
                [
                    char::from_digit(u32::from(byte >> 4_u8), 16).unwrap_or('0'),
                    char::from_digit(u32::from(byte & 15), 16).unwrap_or('0'),
                ]
            })
            .collect();
        let suffix = digest.get(..8).context("issuer suffix")?;
        let cookies: Vec<_> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str())
            .collect::<Result<_, _>>()?;
        ensure!(cookies.len() == ages.len(), "exact cookie set");
        for (kind, age) in ages {
            let prefix = format!("rmcp_{kind}_{suffix}");
            let full = cookies
                .iter()
                .find(|value| value.starts_with(&prefix))
                .context("cookie kind")?;
            let pair = full.split(';').next().context("pair")?;
            let (name, value) = pair.split_once('=').context("cookie value")?;
            ensure!(
                *full == format!("{pair}; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}"),
                "complete development cookie attributes"
            );
            if *age == 0 {
                ensure!(value.is_empty(), "cleared cookie has no credential");
                continue;
            }
            match *kind {
                "csrf" => {
                    ensure!(
                        URL_SAFE_NO_PAD.decode(value)?.len() == 32 && value.len() == 43,
                        "256-bit CSRF nonce"
                    );
                    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()));
                    ensure!(
                        name == format!("{prefix}_{}", hash.get(..16).context("CSRF suffix")?),
                        "CSRF name binds actual nonce"
                    );
                }
                "state" => {
                    let payload = visible_payload(value)?;
                    let nh = payload
                        .get("nh")
                        .and_then(Value::as_str)
                        .context("nonce hash")?;
                    ensure!(
                        name == format!("{prefix}_{}", nh.get(..16).context("state suffix")?),
                        "state name binds flow"
                    );
                    ensure!(
                        value.starts_with("v1.") && value.split('.').count() == 3,
                        "sealed state shape"
                    );
                }
                "consent" => {
                    ensure!(
                        name == prefix && visible_payload(value)?.get("e").is_some(),
                        "sealed consent shape"
                    );
                }
                other => anyhow::bail!("unexpected cookie family {other}"),
            }
        }
        Ok(())
    }

    /// Page, approve, deny, fast-path and zero-TTL transitions serialize exact cookie contracts.
    #[tokio::test]
    async fn consent_transitions_serialize_exact_cookies() -> anyhow::Result<()> {
        // Given
        for ttl in ["1234s", "0s"] {
            let server = Harness::start(ttl).await?;
            let cid = server.register("Cookie transitions").await?;
            for decision in ["approve", "deny", "invalid"] {
                let page = server.page(&cid).await?;
                cookie_contract(&page, &server.base, &[("csrf", 600)])?;
                let (token, csrf) = consent_form(page).await?;
                let original_name = csrf.split_once('=').context("original CSRF name")?.0;
                // When
                let response = server.decide(&token, &csrf, decision).await?;
                // Then
                let expected = match (decision, ttl) {
                    ("approve", "1234s") => vec![("state", 600), ("consent", 1234), ("csrf", 0)],
                    ("approve", _) => vec![("state", 600), ("csrf", 0)],
                    _ => vec![("csrf", 0)],
                };
                cookie_contract(&response, &server.base, &expected)?;
                let clear = format!("{original_name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
                ensure!(
                    response
                        .headers()
                        .get_all("set-cookie")
                        .iter()
                        .any(|value| value == clear.as_str()),
                    "clear exactly the original CSRF name and path after {decision}"
                );
                if decision == "approve" && ttl == "1234s" {
                    let remembered = response_cookie(&response, "rmcp_consent_")?;
                    let fast = server
                        .authorize(&Harness::params(&cid), Some(&remembered))
                        .await?;
                    ensure!(fast.status() == 302, "remembered approval redirects");
                    cookie_contract(&fast, &server.base, &[("state", 600), ("consent", 1234)])?;
                }
            }
            server.close().await?;
        }
        Ok(())
    }

    /// Each reachable untrusted HTML field is inert, while forbidden scope quotes fail as protocol errors.
    #[tokio::test]
    async fn untrusted_html_fields_are_inert() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let uri = "https://example.test/cb?x=<img/src=x>&quote='\"";
        let registration_response = server
            .client
            .post(format!("{}/register", server.base))
            .json(&json!({"redirect_uris":[uri],"client_name":"<img/src=x>&'\""}))
            .send()
            .await?;
        ensure!(
            registration_response.status() == 201,
            "hostile valid registration"
        );
        let registration: Value = registration_response.json().await?;
        let cid = registration
            .get("client_id")
            .and_then(Value::as_str)
            .context("client")?;
        let mut pairs = Harness::params(cid);
        pairs.retain(|(key, _)| !matches!(*key, "redirect_uri" | "scope"));
        pairs.extend([
            ("redirect_uri", uri),
            ("scope", "<img/src=x>&' second&scope"),
        ]);
        // When
        let response = server.authorize(&pairs, None).await?;
        // Then
        ensure!(
            response.status() == 200,
            "RFC 6750 permits markup punctuation except quote and backslash"
        );
        let html = response.text().await?;
        for escaped in [
            "&lt;img/src=x&gt;&amp;&#39;&quot;",
            "https://example.test/cb?x=&lt;img/src=x&gt;&amp;quote=&#39;&quot;",
            "<li>&lt;img/src=x&gt;&amp;&#39;</li>",
            "<li>second&amp;scope</li>",
            "<strong>example.test</strong>",
        ] {
            ensure!(html.contains(escaped), "escaped interpolation {escaped}");
        }
        ensure!(!html.contains("<img/src=x>"), "no active injected element");
        let token = html
            .split("name=\"request\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .context("hidden request")?;
        ensure!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "sealed hidden field has no HTML metacharacters"
        );
        for hostile in ["<img/src=x>&'\"", "bad\\scope"] {
            let mut invalid = Harness::params(cid);
            invalid.retain(|(key, _)| *key != "scope" && *key != "redirect_uri");
            invalid.extend([("scope", hostile), ("redirect_uri", uri)]);
            let invalid_response = server.authorize(&invalid, None).await?;
            ensure!(
                invalid_response.status() == 302,
                "excluded scope bytes rejected"
            );
        }
        server.close().await
    }

    /// Every reachable integrity rejection is an inert nonredirecting page rather than a protocol redirect.
    #[tokio::test]
    async fn integrity_rejections_render_nonredirecting_pages() -> anyhow::Result<()> {
        // Given
        let server = Harness::start("1234s").await?;
        let cid = server.register("Integrity table").await?;
        let (token, csrf) = consent_form(server.page(&cid).await?).await?;
        let csrf_name = csrf.split_once('=').context("CSRF name")?.0;
        let wrong_cookie = format!("{csrf_name}=<img/src=x>&'\"");
        let forged = "<img/src=x>&'\"";
        let oversized = "x".repeat(8193);
        let cases = [
            (vec![], csrf.as_str()),
            (
                vec![("request", forged), ("decision", "approve")],
                csrf.as_str(),
            ),
            (
                vec![("request", oversized.as_str()), ("decision", "approve")],
                csrf.as_str(),
            ),
            (
                vec![("request", cid.as_str()), ("decision", "approve")],
                csrf.as_str(),
            ),
            (
                vec![("request", token.as_str()), ("decision", "approve")],
                "",
            ),
            (
                vec![("request", token.as_str()), ("decision", "approve")],
                wrong_cookie.as_str(),
            ),
            (
                vec![("request", token.as_str()), ("decision", forged)],
                csrf.as_str(),
            ),
            (vec![("request", token.as_str())], csrf.as_str()),
            (
                vec![
                    ("request", token.as_str()),
                    ("decision", "approve"),
                    ("decision", "deny"),
                ],
                csrf.as_str(),
            ),
        ];
        for (pairs, cookie) in cases {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            // When
            let response = server
                .client
                .post(format!("{}/oauth/consent", server.base))
                .header("cookie", cookie)
                .body(body)
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == 400 && !response.headers().contains_key("location"),
                "integrity rejection never redirects"
            );
            let html = response.text().await?;
            ensure!(
                !html.contains(forged) && !html.contains("&lt;img/src=x&gt;"),
                "error page does not interpolate request-derived text"
            );
        }
        for size in [0x7fff_usize, 0x8000, 0x8001] {
            let mut query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(Harness::params(&cid))
                .finish();
            query.push_str("&ignored=");
            query.push_str(&"x".repeat(size.checked_sub(query.len()).context("padding")?));
            // When
            let response = server
                .client
                .get(format!("{}/authorize?{query}", server.base))
                .send()
                .await?;
            // Then
            ensure!(
                response.status() == if size <= 0x8000 { 200 } else { 400 },
                "encoded parameter cap {size}"
            );
            ensure!(
                !response.headers().contains_key("location"),
                "parameter cap page class"
            );
        }
        server.close().await
    }

    // Distinct authenticated-state fields observed through HTTP.

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: tests::distinct_browser_transactions_keep_their_fields keeps each source and observable output in one transaction"
    )]
    /// Distinct browser transactions preserve payload fields and the corresponding upstream redirect.
    async fn distinct_browser_transactions_keep_their_fields() -> anyhow::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        // Given
        let server = Harness::start("1234s").await?;
        for (row, challenge) in [
            ("gamma", "CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs"),
            ("delta", "6543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqp"),
        ] {
            let redirect = format!("https://{row}.client.test/callback?source={row}");
            let registered: Value = server
                .client
                .post(format!("{}/register", server.base))
                .json(&json!({"redirect_uris":[redirect],"client_name":format!("distinct-{row}")}))
                .send()
                .await?
                .json()
                .await?;
            let cid = registered
                .get("client_id")
                .and_then(Value::as_str)
                .context("client")?;
            let client_state = format!("http-downstream-state-{row}");
            let scopes = format!("{row}:audit {row}:write");
            let resources = [
                format!("https://resource-{row}.test/mcp"),
                format!("urn:{row}:records"),
            ];
            let hints = [
                ("prompt", format!("select-{row}")),
                ("login_hint", format!("user-{row}@example.test")),
                ("ui_locales", format!("fr-{row}")),
            ];
            let mut pairs = vec![
                ("client_id", cid),
                ("redirect_uri", redirect.as_str()),
                ("response_type", "code"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("scope", scopes.as_str()),
                ("state", client_state.as_str()),
            ];
            pairs.extend(
                resources
                    .iter()
                    .map(|resource| ("resource", resource.as_str())),
            );
            pairs.extend(hints.iter().map(|(key, value)| (*key, value.as_str())));
            for decision in ["approve", "deny"] {
                let issued_before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let (token, csrf) = consent_form(server.authorize(&pairs, None).await?).await?;
                let pending = visible_payload(&token)?;
                let issued_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let pending_expiry = pending
                    .get("exp")
                    .and_then(Value::as_u64)
                    .context("pending expiry")?;
                ensure!(
                    (issued_before.saturating_add(600)..=issued_after.saturating_add(600))
                        .contains(&pending_expiry),
                    "HTTP pending deadline"
                );
                for (field, expected) in [
                    (
                        "cid",
                        json!(URL_SAFE_NO_PAD.encode(Sha256::digest(cid.as_bytes()))),
                    ),
                    ("ru", json!(redirect)),
                    ("st", json!(client_state)),
                    ("cc", json!(challenge)),
                    (
                        "sc",
                        json!([format!("{row}:audit"), format!("{row}:write")]),
                    ),
                    ("rs", json!(resources)),
                    ("ex", json!(hints)),
                    (
                        "csrf",
                        json!(URL_SAFE_NO_PAD.encode(Sha256::digest(
                            csrf.split_once('=').context("nonce")?.1.as_bytes()
                        ))),
                    ),
                ] {
                    ensure!(
                        pending.get(field) == Some(&expected),
                        "HTTP pending field {field}"
                    );
                }
                // When
                let approved_before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let response = server.decide(&token, &csrf, decision).await?;
                let approved_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                // Then
                ensure!(response.status() == 302, "distinct decision redirects");
                let target = location(&response)?;
                match decision {
                    "approve" => {
                        let actual: Vec<_> = target
                            .query_pairs()
                            .map(|(key, value)| (key.into_owned(), value.into_owned()))
                            .collect();
                        for (key, expected) in [
                            ("code_challenge", challenge),
                            ("scope", scopes.as_str()),
                            (
                                "redirect_uri",
                                format!("{}/oauth/callback", server.base).as_str(),
                            ),
                        ] {
                            ensure!(
                                actual
                                    .iter()
                                    .any(|(name, received)| name == key && received == expected),
                                "HTTP upstream {key}"
                            );
                        }
                        for (key, value) in resources
                            .iter()
                            .map(|resource| ("resource", resource))
                            .chain(hints.iter().map(|(name, hint)| (*name, hint)))
                        {
                            ensure!(
                                actual
                                    .iter()
                                    .any(|(name, received)| name == key && received == value),
                                "HTTP upstream resource/hint"
                            );
                        }
                        let upstream_state = actual
                            .iter()
                            .find(|(name, _)| name == "state")
                            .context("upstream state")?
                            .1
                            .as_str();
                        ensure!(
                            upstream_state.len() == 43
                                && upstream_state != client_state
                                && upstream_state != challenge,
                            "fresh upstream state"
                        );
                        let state_cookie = response_cookie(&response, "rmcp_state_")?;
                        let flow =
                            visible_payload(state_cookie.split_once('=').context("flow token")?.1)?;
                        let flow_expiry = flow
                            .get("exp")
                            .and_then(Value::as_u64)
                            .context("flow expiry")?;
                        ensure!(
                            (approved_before.saturating_add(600)
                                ..=approved_after.saturating_add(600))
                                .contains(&flow_expiry),
                            "HTTP flow deadline"
                        );
                        for field in ["cid", "ru", "st", "cc"] {
                            ensure!(
                                flow.get(field) == pending.get(field),
                                "HTTP flow carries {field}"
                            );
                        }
                        ensure!(
                            flow.get("nh")
                                == Some(&json!(
                                    URL_SAFE_NO_PAD
                                        .encode(Sha256::digest(upstream_state.as_bytes()))
                                )),
                            "redirect state binds flow hash"
                        );
                        let consent = response_cookie(&response, "rmcp_consent_")?;
                        let remembered =
                            visible_payload(consent.split_once('=').context("consent token")?.1)?;
                        let entry = remembered
                            .get("e")
                            .and_then(Value::as_array)
                            .and_then(|entries| entries.first())
                            .context("remembered entry")?;
                        ensure!(
                            entry.get("c")
                                == Some(&json!(
                                    URL_SAFE_NO_PAD
                                        .encode(Sha256::digest(cid.as_bytes()))
                                        .chars()
                                        .take(22)
                                        .collect::<String>()
                                )),
                            "HTTP remembered client"
                        );
                        ensure!(
                            entry.get("s") == pending.get("sc"),
                            "HTTP remembered scopes"
                        );
                        let consent_expiry = entry
                            .get("x")
                            .and_then(Value::as_u64)
                            .context("consent expiry")?;
                        ensure!(
                            (approved_before.saturating_add(1234)
                                ..=approved_after.saturating_add(1234))
                                .contains(&consent_expiry),
                            "HTTP consent deadline"
                        );
                    }
                    "deny" => {
                        let mut expected = url::Url::parse(&redirect)?;
                        let _query = expected
                            .query_pairs_mut()
                            .append_pair("error", "access_denied")
                            .append_pair("iss", &server.base)
                            .append_pair("state", &client_state);
                        ensure!(
                            target == expected,
                            "HTTP denial preserves exact source destination"
                        );
                        ensure!(
                            response_cookie(&response, "rmcp_state_").is_err()
                                && response_cookie(&response, "rmcp_consent_").is_err(),
                            "denial sets no approval cookies"
                        );
                    }
                    other => anyhow::bail!("unexpected decision {other}"),
                }
            }
        }
        server.close().await
    }
}
