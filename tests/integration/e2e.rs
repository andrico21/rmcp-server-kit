//! End-to-end tests for the rmcp-server-kit HTTP server stack.
//!
//! Spins up a real `serve()` instance on an ephemeral port with a minimal
//! `ServerHandler` and makes HTTP requests against it.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    target_os = "linux",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{collections::VecDeque, sync::Arc};
    use core::{
        fmt,
        future::ready,
        net::SocketAddr,
        num::NonZeroUsize,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{
        collections::HashMap,
        env,
        path::PathBuf,
        sync::{Mutex as StdMutex, PoisonError},
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context as _;
    use axum::{
        Router,
        extract::ConnectInfo,
        routing::{get, post},
    };
    use futures::stream;
    use reqwest::header::HeaderMap;
    use rmcp::{
        handler::server::ServerHandler,
        model::{
            CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
            ListToolsResult, PaginatedRequestParams, ServerCapabilities,
            ServerConfig as RmcpServerConfig, Tool,
        },
        service::{MaybeSendFuture, RequestContext, RoleServer},
        transport::streamable_http_server::session::{
            EventStore, EventStoreError, EventStream, ServerSseMessage, SessionState, SessionStore,
            SessionStoreError,
        },
    };
    #[cfg(feature = "oauth")]
    use rmcp_server_kit::oauth::OAuthConfig;
    use rmcp_server_kit::{
        auth::{ApiKeyEntry, AuthConfig, RateLimitConfig, generate_api_key},
        config::ServerConfig,
        rbac::{
            ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig, current_identity, current_role,
            current_sub, current_token,
        },
        transport::{ForwardedHeaderMode, McpServerConfig, serve_with_listener},
    };
    use rustls::crypto::ring;
    use secrecy::SecretString;
    use tokio::{
        fs,
        net::{TcpListener, TcpStream},
        sync::{Mutex, Notify, oneshot},
        task::JoinHandle,
        time::{sleep, timeout},
    };
    use tokio_util::sync::CancellationToken;

    // -- Minimal test handler --

    #[derive(Clone)]
    struct TestHandler;

    impl ServerHandler for TestHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }
    }

    /// Handler whose `call_tool` blocks until the test releases it.
    ///
    /// Needed for the graceful-shutdown regression test: the shutdown session
    /// token is only wired into the `/mcp` `StreamableHttpService`, so the work
    /// held open across shutdown has to be a real MCP tool call. A route added via
    /// `with_extra_router` is merged into the outer axum router and never reaches
    /// that service, so it would be drained by axum's own graceful shutdown and
    /// prove nothing.
    #[derive(Clone)]
    struct BlockingToolHandler {
        /// Fires once, when `call_tool` begins, so the test can be sure the call
        /// is genuinely in flight before triggering shutdown.
        started: Arc<StdMutex<Option<oneshot::Sender<()>>>>,
        /// Held by the test until it wants the call to return.
        release: Arc<Notify>,
    }

    impl ServerHandler for BlockingToolHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, rmcp::ErrorData> {
            if let Ok(mut guard) = self.started.lock()
                && let Some(tx) = guard.take()
                && tx.send(()).is_err()
            {
                // The test receiver may already be gone; best-effort notify.
                tracing::debug!("oneshot receiver dropped before the send");
            }
            self.release.notified().await;
            Ok(CallToolResult::success(vec![ContentBlock::text("released")]).into())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedRbacContext {
        role: Option<String>,
        identity: Option<String>,
        sub: Option<String>,
        token_present: bool,
    }

    #[derive(Debug, Clone)]
    struct RbacContextProbeHandler {
        observed: Arc<StdMutex<Option<ObservedRbacContext>>>,
    }

    impl ServerHandler for RbacContextProbeHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
        {
            let observed = ObservedRbacContext {
                role: current_role(),
                identity: current_identity(),
                sub: current_sub(),
                token_present: current_token().is_some(),
            };
            *self.observed.lock().unwrap_or_else(PoisonError::into_inner) = Some(observed);
            ready(Ok(CallToolResult::success(vec![ContentBlock::text(
                "context captured",
            )])
            .into()))
        }
    }

    #[derive(Clone)]
    struct AdvertisedToolsHandler;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler requires async methods; this E2E fake returns immediately"
    )]
    impl ServerHandler for AdvertisedToolsHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, rmcp::ErrorData> {
            Ok(ListToolsResult::with_all_items(vec![
                Tool::new("allowed_tool", "allowed", Arc::new(JsonObject::default())),
                Tool::new("denied_tool", "denied", Arc::new(JsonObject::default())),
            ]))
        }

        async fn call_tool(
            &self,
            request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, rmcp::ErrorData> {
            Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "called {}",
                request.name
            ))])
            .into())
        }
    }

    #[derive(Clone, Default)]
    struct SharedMapSessionStore {
        sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    }

    #[async_trait::async_trait]
    impl SessionStore for SharedMapSessionStore {
        async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
            Ok(self.sessions.lock().await.get(session_id).cloned())
        }

        async fn store(
            &self,
            session_id: &str,
            state: &SessionState,
        ) -> Result<(), SessionStoreError> {
            drop(
                self.sessions
                    .lock()
                    .await
                    .insert(session_id.to_owned(), state.clone()),
            );
            Ok(())
        }

        async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
            drop(self.sessions.lock().await.remove(session_id));
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct RecordedEvent {
        stream_id: String,
        event_id: String,
        event: ServerSseMessage,
    }

    #[derive(Debug)]
    struct BoundedTestEventStore {
        next_sequence: AtomicU64,
        capacity: NonZeroUsize,
        events: Mutex<VecDeque<RecordedEvent>>,
    }

    impl BoundedTestEventStore {
        fn new(capacity: NonZeroUsize) -> Self {
            Self {
                next_sequence: AtomicU64::new(1),
                capacity,
                events: Mutex::new(VecDeque::with_capacity(capacity.get())),
            }
        }

        fn default_capacity() -> NonZeroUsize {
            NonZeroUsize::new(64).unwrap_or(NonZeroUsize::MIN)
        }

        async fn recorded_events(&self) -> Vec<RecordedEvent> {
            let events = self.events.lock().await;
            events.iter().cloned().collect()
        }

        async fn push_record(&self, record: RecordedEvent) {
            let mut events = self.events.lock().await;
            if events.len() == self.capacity.get() {
                drop(events.pop_front());
            }
            events.push_back(record);
        }

        async fn replay_after(
            &self,
            stream_id: &str,
            last_event_id: &str,
        ) -> Vec<ServerSseMessage> {
            let events = self.events.lock().await;
            let mut found_last_event = false;
            events
                .iter()
                .filter_map(|record| {
                    if record.stream_id != stream_id {
                        return None;
                    }
                    if found_last_event {
                        return Some(record.event.clone());
                    }
                    if record.event_id == last_event_id {
                        found_last_event = true;
                    }
                    None
                })
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl EventStore for BoundedTestEventStore {
        async fn store_event(
            &self,
            stream_id: &str,
            event: &ServerSseMessage,
        ) -> Result<String, EventStoreError> {
            let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
            let event_id = format!("{stream_id}:{sequence}");
            let mut stored_event = event.clone();
            stored_event.event_id = Some(event_id.clone());

            self.push_record(RecordedEvent {
                stream_id: stream_id.to_owned(),
                event_id: event_id.clone(),
                event: stored_event,
            })
            .await;
            Ok(event_id)
        }

        async fn replay_events_after(
            &self,
            last_event_id: &str,
        ) -> Result<EventStream, EventStoreError> {
            let Some((stream_id, _sequence)) = last_event_id.rsplit_once(':') else {
                return Ok(Box::pin(stream::empty()));
            };
            let replayed = self.replay_after(stream_id, last_event_id).await;
            Ok(Box::pin(stream::iter(replayed)))
        }
    }

    struct EventStoreHarness {
        server: ServerHarness,
        client: reqwest::Client,
        token: String,
        session_id: String,
        store: Arc<BoundedTestEventStore>,
    }

    impl EventStoreHarness {
        async fn send_tool_call(&self) -> anyhow::Result<String> {
            let resp = self
                .client
                .post(format!("{}/mcp", self.server.base))
                .header("authorization", format!("Bearer {}", self.token))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &self.session_id)
                .body(tool_call_body("allowed_tool", &serde_json::json!({})))
                .send()
                .await
                .context("tool call request")?;
            assert_eq!(resp.status(), 200, "tool call must produce an SSE response");
            resp.text().await.context("read tool call SSE body")
        }

        async fn resume_after(&self, last_event_id: &str) -> anyhow::Result<String> {
            let resp = self
                .client
                .get(format!("{}/mcp", self.server.base))
                .header("authorization", format!("Bearer {}", self.token))
                .header("accept", "text/event-stream")
                .header("mcp-session-id", &self.session_id)
                .header("last-event-id", last_event_id)
                .send()
                .await
                .context("resume request")?;
            assert_eq!(resp.status(), 200, "resume must return an SSE response");
            resp.text().await.context("read resumed SSE body")
        }

        async fn wait_for_recorded_events(
            &self,
            expected: usize,
        ) -> anyhow::Result<Vec<RecordedEvent>> {
            timeout(Duration::from_secs(10), async {
                loop {
                    let records = self.store.recorded_events().await;
                    if records.len() >= expected {
                        return records;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("event store did not observe expected events within 10s")
        }
    }

    async fn spawn_event_store_harness() -> anyhow::Result<EventStoreHarness> {
        let (token, hash) = generate_api_key()?;
        let store = Arc::new(BoundedTestEventStore::new(
            BoundedTestEventStore::default_capacity(),
        ));
        let event_store: Arc<dyn EventStore> = Arc::<BoundedTestEventStore>::clone(&store);
        let cfg = config_on_port(free_port().await?)
            .with_auth(test_auth_config(vec![ApiKeyEntry::new(
                "event-store-key",
                hash,
                "ops",
            )]))
            .with_event_store(event_store);
        let server = spawn_server_with(cfg, || AdvertisedToolsHandler).await?;
        let client = reqwest::Client::new();
        let session_id = mcp_initialize_with_bearer(&client, &server.base, Some(&token)).await?;

        Ok(EventStoreHarness {
            server,
            client,
            token,
            session_id,
            store,
        })
    }

    // -- Test helpers --

    /// Find a free ephemeral port. Retained for legacy call-sites that
    /// build a config from a port number; new tests should prefer
    /// [`spawn_server`] which uses port 0 + pre-bound listener.
    async fn free_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(listener.local_addr()?.port())
    }

    /// Handle to a server spawned via [`spawn_server`]. Drop the harness
    /// (or call [`ServerHarness::shutdown`]) to terminate the server
    /// deterministically.
    struct ServerHarness {
        /// Base URL (`http://127.0.0.1:<port>`). Always contains the
        /// actually-bound port -- safe to use immediately.
        base: String,
        /// Cancellation token wired into `serve_with_listener`'s shutdown
        /// path. Cancelling triggers the same graceful drain as a real
        /// `SIGTERM`.
        shutdown: CancellationToken,
        /// Join handle for the server task. `None` after [`Self::shutdown`]
        /// joins it.
        join: Option<JoinHandle<rmcp_server_kit::Result<()>>>,
    }

    impl ServerHarness {
        /// Cancel the shutdown token, await the server task, and return
        /// the server's final result. Safe to call multiple times: only
        /// the first invocation joins.
        async fn shutdown(&mut self) -> anyhow::Result<()> {
            self.shutdown.cancel();
            match self.join.take() {
                Some(handle) => match handle.await {
                    Ok(server_res) => server_res.map_err(anyhow::Error::from),
                    Err(join_err) => Err(join_err.into()),
                },
                None => Ok(()),
            }
        }
    }

    // Drop audit (2026-10-04): cancels the shutdown token only; no blocking/async work, no panic paths.
    impl Drop for ServerHarness {
        fn drop(&mut self) {
            // Ensure the server task does not outlive the test even if
            // the test forgot to call `shutdown`.
            self.shutdown.cancel();
        }
    }

    impl fmt::Display for ServerHarness {
        /// Display formats as the harness's base URL so existing test
        /// call-sites (`format!("{base}/healthz")`) keep working when
        /// `base` is a [`ServerHarness`] rather than a `String`.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.base)
        }
    }

    /// Spawn a server on an ephemeral port using
    /// [`rmcp_server_kit::transport::serve_with_listener`] and return a
    /// [`ServerHarness`] once the server has signalled readiness.
    ///
    /// Replaces the previous "spawn + poll `/healthz` for 2.5s" pattern
    /// with a deterministic readiness oneshot, eliminating start-up
    /// races and removing the need for `config_on_port` to know the port
    /// ahead of time.
    async fn spawn_server(config: McpServerConfig) -> anyhow::Result<ServerHarness> {
        spawn_server_with(config, || TestHandler).await
    }

    /// [`spawn_server`], but with a caller-supplied handler factory.
    async fn spawn_server_with<H, F>(
        config: McpServerConfig,
        handler_factory: F,
    ) -> anyhow::Result<ServerHarness>
    where
        H: ServerHandler + 'static,
        F: Fn() -> H + Send + Sync + Clone + 'static,
    {
        // Ensure ring crypto provider is available for reqwest's TLS.
        drop(ring::default_provider().install_default());

        // Bind the listener up front so the server has nothing to fail on
        // address-in-use, and we know the actual port immediately.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let bound: SocketAddr = listener.local_addr()?;
        // Keep config.bind_addr aligned with the real port for any
        // public_url derivation paths that read it.
        let bound_config = config.with_bind_addr(bound.to_string());

        let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let validated = bound_config.validate().context("test config valid")?;
        let join = tokio::spawn(async move {
            serve_with_listener(
                listener,
                validated,
                handler_factory,
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
        });

        // Deterministic readiness: wait for serve_with_listener to signal
        // *after* router build, *before* accept loop. No polling loop, no
        // sleep races.
        let signalled: SocketAddr = timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("server did not signal readiness within 5s")?
            .context("server task aborted before readiness signal")?;
        assert_eq!(
            signalled, bound,
            "ready_tx address mismatched the pre-bound listener"
        );

        Ok(ServerHarness {
            base: format!("http://{bound}"),
            shutdown,
            join: Some(join),
        })
    }

    fn config_on_port(port: u16) -> McpServerConfig {
        McpServerConfig::new(format!("127.0.0.1:{port}"), "test-rmcp-server-kit", "0.0.1")
            .with_shutdown_timeout(Duration::from_millis(100))
    }

    // ==========================================================================
    // Health endpoints
    // ==========================================================================

    /// Pins that `/healthz` returns 200 with `status: ok` and no server name or version leak.
    #[tokio::test]
    async fn healthz_returns_ok() -> anyhow::Result<()> {
        let port = free_port().await?;
        let base = spawn_server(config_on_port(port)).await?;

        let resp = reqwest::get(&format!("{base}/healthz")).await?;
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await?;
        assert_eq!(
            json.get("status").and_then(serde_json::Value::as_str),
            Some("ok")
        );
        assert!(
            json.get("name").is_none(),
            "healthz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "healthz must not expose version"
        );
        Ok(())
    }

    /// Pins that `/readyz` mirrors `/healthz`'s 200 when no readiness check is configured.
    #[tokio::test]
    async fn readyz_mirrors_healthz_when_no_check() -> anyhow::Result<()> {
        let port = free_port().await?;
        let base = spawn_server(config_on_port(port)).await?;

        let resp = reqwest::get(&format!("{base}/readyz")).await?;
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await?;
        assert_eq!(
            json.get("status").and_then(serde_json::Value::as_str),
            Some("ok")
        );
        Ok(())
    }

    /// Pins that `/readyz` returns 503 while the readiness check reports not ready.
    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_readiness_check(Arc::new(|| {
            Box::pin(async { serde_json::json!({"ready": false, "reason": "starting"}) })
        }));
        let base = spawn_server(cfg).await?;

        let resp = reqwest::get(&format!("{base}/readyz")).await?;
        assert_eq!(resp.status(), 503);
        Ok(())
    }

    #[derive(serde::Deserialize)]
    struct E2eRootConfig {
        server: ServerConfig,
    }

    fn toml_backed_config(toml: &str) -> anyhow::Result<McpServerConfig> {
        let root: E2eRootConfig = toml::from_str(toml).context("server TOML parses")?;
        root.server
            .apply_to_mcp_config(McpServerConfig::new(
                "127.0.0.1:0",
                "test-rmcp-server-kit",
                "0.0.1",
            ))
            .context("server TOML bridges to MCP config")
    }

    fn default_security_header_values() -> [(&'static str, &'static str); 11] {
        [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "deny"),
            ("cache-control", "no-store, max-age=0"),
            ("referrer-policy", "no-referrer"),
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-resource-policy", "same-origin"),
            ("cross-origin-embedder-policy", "require-corp"),
            (
                "permissions-policy",
                "accelerometer=(), camera=(), geolocation=(), microphone=()",
            ),
            ("x-permitted-cross-domain-policies", "none"),
            (
                "content-security-policy",
                "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
            ),
            ("x-dns-prefetch-control", "off"),
        ]
    }

    fn assert_security_header_defaults_except(
        headers: &HeaderMap,
        context: &str,
        omitted: &[&str],
    ) {
        for (header, value) in default_security_header_values() {
            if omitted.contains(&header) {
                assert!(headers.get(header).is_none(), "{context}: {header} present");
            } else {
                assert_eq!(
                    headers
                        .get(header)
                        .and_then(|header_value| header_value.to_str().ok()),
                    Some(value),
                    "{context}: {header} default mismatch"
                );
            }
        }
        assert!(
            headers.get("strict-transport-security").is_none(),
            "{context}: HSTS must remain absent on plaintext"
        );
    }

    fn assert_security_header_defaults(headers: &HeaderMap, context: &str) {
        assert_security_header_defaults_except(headers, context, &[]);
    }

    fn assert_security_header_defaults_with_override(
        headers: &HeaderMap,
        context: &str,
        override_header: &str,
        override_value: &str,
    ) {
        for (header, value) in default_security_header_values() {
            let expected = if header == override_header {
                override_value
            } else {
                value
            };
            assert_eq!(
                headers
                    .get(header)
                    .and_then(|header_value| header_value.to_str().ok()),
                Some(expected),
                "{context}: {header} mismatch"
            );
        }
        assert!(
            headers.get("strict-transport-security").is_none(),
            "{context}: HSTS must remain absent on plaintext"
        );
    }

    /// Pins that a TOML CSP override reaches the real `/healthz` response while every other default stays.
    #[tokio::test]
    async fn t3_toml_csp_override_applies_to_real_healthz_response() -> anyhow::Result<()> {
        let cfg = toml_backed_config(
            r#"
                [server.security_headers]
                content_security_policy = "default-src 'self'"
            "#,
        )?;
        let base = spawn_server(cfg).await?;

        let resp = reqwest::get(&format!("{base}/healthz")).await?;
        assert_eq!(resp.status(), 200);
        assert_security_header_defaults_with_override(
            resp.headers(),
            "T3 healthz",
            "content-security-policy",
            "default-src 'self'",
        );
        Ok(())
    }

    /// Pins that an empty TOML security-header value omits exactly that one header.
    #[tokio::test]
    async fn t4_toml_empty_security_header_omits_only_that_header() -> anyhow::Result<()> {
        let cfg = toml_backed_config(
            r#"
                [server.security_headers]
                cross_origin_embedder_policy = ""
            "#,
        )?;
        let base = spawn_server(cfg).await?;

        let resp = reqwest::get(&format!("{base}/healthz")).await?;
        assert_eq!(resp.status(), 200);
        assert_security_header_defaults_except(
            resp.headers(),
            "T4 healthz",
            &["cross-origin-embedder-policy"],
        );
        Ok(())
    }

    /// Pins that `expose_build_metadata` toggles the build fields in `/version`.
    #[tokio::test]
    async fn t8_toml_expose_build_metadata_controls_version_payload() -> anyhow::Result<()> {
        let exposed = spawn_server(toml_backed_config(
            "
                [server]
                expose_build_metadata = true
            ",
        )?)
        .await?;
        let hidden = spawn_server(toml_backed_config(
            "
                [server]
                expose_build_metadata = false
            ",
        )?)
        .await?;

        let exposed_body: serde_json::Value = reqwest::get(&format!("{exposed}/version"))
            .await?
            .json()
            .await?;
        assert!(exposed_body.get("build_git_sha").is_some());
        assert!(exposed_body.get("build_timestamp").is_some());
        assert!(exposed_body.get("rust_version").is_some());

        let hidden_resp = reqwest::get(&format!("{hidden}/version")).await?;
        assert_security_header_defaults(hidden_resp.headers(), "hidden /version");
        let hidden_body: serde_json::Value = hidden_resp.json().await?;
        assert!(hidden_body.get("build_git_sha").is_none());
        assert!(hidden_body.get("build_timestamp").is_none());
        assert!(hidden_body.get("rust_version").is_none());
        Ok(())
    }

    // ==========================================================================
    // Auth enforcement
    // ==========================================================================

    fn test_auth_config(keys: Vec<ApiKeyEntry>) -> AuthConfig {
        AuthConfig::with_keys(keys)
    }

    fn shared_binding_secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn session_store_auth_config() -> anyhow::Result<(String, AuthConfig)> {
        let (token, hash) = generate_api_key()?;
        Ok((
            token,
            test_auth_config(vec![ApiKeyEntry::new("replica-key", hash, "ops")]),
        ))
    }

    async fn session_store_tool_call(
        base: &str,
        token: &str,
        session_id: &str,
    ) -> anyhow::Result<(u16, String)> {
        let resp = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await
            .context("tool call request")?;
        let status = resp.status().as_u16();
        Ok((status, resp.text().await.unwrap_or_default()))
    }

    async fn session_store_tool_call_status(
        base: &str,
        token: &str,
        session_id: &str,
    ) -> anyhow::Result<u16> {
        Ok(session_store_tool_call(base, token, session_id).await?.0)
    }

    /// Pins that a shared session store lets a second replica serve a session minted by the first.
    #[tokio::test]
    async fn session_store_shares_sessions_across_replicas() -> anyhow::Result<()> {
        let (token, auth) = session_store_auth_config()?;
        let store: Arc<dyn SessionStore> = Arc::new(SharedMapSessionStore::default());
        let secret = shared_binding_secret("0123456789abcdef0123456789abcdef");
        let server_a = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth.clone())
                .with_session_store(Arc::clone(&store))
                .with_session_binding_secret(secret.clone()),
        )
        .await?;
        let server_b = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth)
                .with_session_store(store)
                .with_session_binding_secret(secret),
        )
        .await?;
        let client = reqwest::Client::new();

        let session_id = mcp_initialize_with_bearer(&client, &server_a.base, Some(&token)).await?;
        let status = session_store_tool_call_status(&server_b.base, &token, &session_id).await?;

        assert!(
            session_id.starts_with("v1."),
            "binding must wrap the session id"
        );
        assert_eq!(status, 200);
        Ok(())
    }

    /// Pins that replicas with different binding secrets reject each other's wrapped session ids.
    #[tokio::test]
    async fn session_store_rejects_mismatched_binding_secret() -> anyhow::Result<()> {
        let (token, auth) = session_store_auth_config()?;
        let store: Arc<dyn SessionStore> = Arc::new(SharedMapSessionStore::default());
        let server_a = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth.clone())
                .with_session_store(Arc::clone(&store))
                .with_session_binding_secret(shared_binding_secret(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
        )
        .await?;
        let server_b = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth)
                .with_session_store(store)
                .with_session_binding_secret(shared_binding_secret(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )),
        )
        .await?;
        let client = reqwest::Client::new();

        let session_id = mcp_initialize_with_bearer(&client, &server_a.base, Some(&token)).await?;
        let (status, body) = session_store_tool_call(&server_b.base, &token, &session_id).await?;

        assert_eq!(status, 404);
        assert!(
            body.contains("unknown MCP session"),
            "404 must come from session binding, not an unrelated path: {body}"
        );
        Ok(())
    }

    /// Pins that cross-replica tool calls fail with 404 when no shared session store is configured.
    #[tokio::test]
    async fn session_store_required_for_cross_replica() -> anyhow::Result<()> {
        let (token, auth) = session_store_auth_config()?;
        let secret = shared_binding_secret("0123456789abcdef0123456789abcdef");
        let server_a = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth.clone())
                .with_session_binding_secret(secret.clone()),
        )
        .await?;
        let server_b = spawn_server(
            config_on_port(free_port().await?)
                .with_auth(auth)
                .with_session_binding_secret(secret),
        )
        .await?;
        let client = reqwest::Client::new();

        let session_id = mcp_initialize_with_bearer(&client, &server_a.base, Some(&token)).await?;
        let (status, body) = session_store_tool_call(&server_b.base, &token, &session_id).await?;

        assert_eq!(status, 404);
        assert!(
            body.contains("Session not found"),
            "404 must come from rmcp after binding verified and unwrapped, proving the shared store is what is missing: {body}"
        );
        Ok(())
    }

    /// Pins that a tool call stores its SSE events in the configured event store.
    #[tokio::test]
    async fn event_store_receives_stored_events() -> anyhow::Result<()> {
        let harness = spawn_event_store_harness().await?;

        let body = harness.send_tool_call().await?;
        let records = harness.wait_for_recorded_events(2).await?;

        assert!(
            body.contains("called allowed_tool"),
            "tool response: {body}"
        );
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.event_id.starts_with(&record.stream_id)),
            "event IDs must carry their stream id: {records:?}"
        );
        Ok(())
    }

    /// Pins that resuming with Last-Event-ID replays only the events after it.
    #[tokio::test]
    async fn resumption_replays_from_event_store() -> anyhow::Result<()> {
        let harness = spawn_event_store_harness().await?;

        let body = harness.send_tool_call().await?;
        let records = harness.wait_for_recorded_events(2).await?;
        let before = records
            .first()
            .context("event store must record the seed events")?;
        let after = records
            .get(1)
            .context("event store must record both seed events")?;
        let before_id = &before.event_id;
        let after_id = &after.event_id;
        let replayed = harness.resume_after(before_id).await?;

        assert!(
            body.contains(before_id),
            "seed stream must include first id: {body}"
        );
        assert!(
            body.contains(after_id),
            "seed stream must include second id: {body}"
        );
        assert!(
            !replayed.contains(before_id),
            "resume must not replay the event at Last-Event-ID: {replayed}"
        );
        assert!(
            replayed.contains(after_id),
            "resume must replay events after Last-Event-ID: {replayed}"
        );
        assert!(
            replayed.contains("called allowed_tool"),
            "resume must carry the persisted tool result: {replayed}"
        );
        Ok(())
    }

    /// Pins that resumption works through an identity-bound session id.
    #[tokio::test]
    async fn resumption_works_through_session_binding() -> anyhow::Result<()> {
        let harness = spawn_event_store_harness().await?;

        drop(harness.send_tool_call().await?);
        let records = harness.wait_for_recorded_events(2).await?;
        let first = records
            .first()
            .context("event store must record the seed events")?;
        let second = records
            .get(1)
            .context("event store must record both seed events")?;
        let replayed = harness.resume_after(&first.event_id).await?;

        assert!(
            harness.session_id.starts_with("v1."),
            "default auth path must return an identity-bound session token"
        );
        assert!(
            replayed.contains(&second.event_id),
            "wrapped Mcp-Session-Id must be unwrapped before rmcp resumes: {replayed}"
        );
        Ok(())
    }

    /// Pins that `/mcp` without credentials returns 401 while `/healthz` stays open.
    #[tokio::test]
    async fn auth_rejects_unauthenticated_mcp() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_auth(test_auth_config(vec![]));
        let base = spawn_server(cfg).await?;

        // /healthz is always open.
        let resp = reqwest::get(&format!("{base}/healthz")).await?;
        assert_eq!(resp.status(), 200);

        // /mcp without credentials returns 401.
        let client = reqwest::Client::new();
        let mcp_resp = client.post(format!("{base}/mcp")).body("{}").send().await?;
        assert_eq!(mcp_resp.status(), 401);
        Ok(())
    }

    /// Pins that a valid bearer key is accepted for an MCP initialize.
    #[tokio::test]
    async fn auth_accepts_valid_bearer() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

        let port = free_port().await?;
        let cfg = config_on_port(port).with_auth(test_auth_config(keys));
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}"#)
            .send()
            .await
            ?;
        // Should get a valid MCP response (200), not 401.
        assert_eq!(resp.status(), 200);
        Ok(())
    }

    /// Pins that a wrong bearer token is rejected with 401.
    #[tokio::test]
    async fn auth_rejects_wrong_bearer() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

        let port = free_port().await?;
        let cfg = config_on_port(port).with_auth(test_auth_config(keys));
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", "Bearer wrong-token")
            .body("{}")
            .send()
            .await?;
        assert_eq!(resp.status(), 401);
        Ok(())
    }

    // ==========================================================================
    // Origin validation
    // ==========================================================================

    /// Pins that an allowed Origin passes the origin check.
    #[tokio::test]
    async fn origin_allowed_passes() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("origin", "http://localhost:3000")
            .body("{}")
            .send()
            .await?;
        // Not 403 (origin passes). Might be 4xx for other reasons (no auth, bad body),
        // but definitely not origin-rejected.
        assert_ne!(resp.status(), 403);
        Ok(())
    }

    /// Pins that a forbidden Origin is rejected with 403.
    #[tokio::test]
    async fn origin_rejected() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("origin", "http://evil.example.com")
            .body("{}")
            .send()
            .await?;
        assert_eq!(resp.status(), 403);
        Ok(())
    }

    /// Pins that requests without an Origin header pass the origin check.
    #[tokio::test]
    async fn no_origin_header_passes() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
        let base = spawn_server(cfg).await?;

        // No Origin header -- non-browser client, should pass.
        let client = reqwest::Client::new();
        let resp = client.post(format!("{base}/mcp")).body("{}").send().await?;
        assert_ne!(resp.status(), 403);
        Ok(())
    }

    // ==========================================================================
    // RBAC enforcement (auth + RBAC together)
    // ==========================================================================

    fn tool_call_body(tool: &str, args: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_u32,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args
            }
        })
        .to_string()
    }

    /// Pins that RBAC denies a tool outside the role's allow list with 403.
    #[tokio::test]
    async fn rbac_denies_unpermitted_tool() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("viewer-key", hash, "viewer")];

        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["resource_list".into()], vec!["*".into()]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();

        // Attempt a tool not in the viewer's allow list.
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(tool_call_body("resource_delete", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(resp.status(), 403);
        Ok(())
    }

    /// Pins that RBAC admits a wildcard-permitted tool call.
    #[tokio::test]
    async fn rbac_allows_permitted_tool() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];

        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();

        // Ops role with wildcard allow -- should pass RBAC.
        // The tool doesn't exist on the handler, so MCP returns an error *response*
        // (not an HTTP error), meaning HTTP 200 with a JSON-RPC error body.
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        // Should NOT be 403 (RBAC passed).
        assert_ne!(resp.status(), 403);
        Ok(())
    }

    /// Pins that the argument allowlist admits `ls` and denies `rm`.
    #[tokio::test]
    async fn rbac_argument_allowlist_enforced() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("exec-key", hash, "restricted")];

        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new(
                "restricted",
                vec!["container_exec".into()],
                vec!["*".into()],
            )
            .with_argument_allowlists(vec![ArgumentAllowlist::new(
                "container_exec",
                "cmd",
                vec!["ls".into(), "cat".into(), "ps".into()],
            )]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();

        // Allowed command: ls
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(tool_call_body(
                "container_exec",
                &serde_json::json!({"cmd": "ls -la"}),
            ))
            .send()
            .await?;
        assert_ne!(resp.status(), 403, "allowed cmd 'ls' should not be denied");

        // Denied command: rm
        let denied_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(tool_call_body(
                "container_exec",
                &serde_json::json!({"cmd": "rm -rf /"}),
            ))
            .send()
            .await?;
        assert_eq!(
            denied_resp.status(),
            403,
            "denied cmd 'rm' should be rejected"
        );
        Ok(())
    }

    /// Pins that the handler observes role, identity, no JWT sub and no OAuth passthrough token.
    #[tokio::test]
    async fn rbac_context_reaches_handler() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["context_probe".into()], vec!["*".into()]),
        ])));
        let observed = Arc::new(StdMutex::new(None));
        let handler = RbacContextProbeHandler {
            observed: Arc::clone(&observed),
        };

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server_with(cfg, move || handler.clone()).await?;
        let client = reqwest::Client::new();
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;

        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session_id)
            .body(tool_call_body("context_probe", &serde_json::json!({})))
            .send()
            .await?;

        assert_eq!(resp.status(), 200, "permitted tool call must reach handler");
        let captured = observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .context("handler must record RBAC context")?;
        assert_eq!(captured.role.as_deref(), Some("ops"));
        assert_eq!(captured.identity.as_deref(), Some("ops-key"));
        assert_eq!(captured.sub, None, "API-key auth does not carry a JWT sub");
        assert!(
            !captured.token_present,
            "API-key auth does not install an OAuth passthrough token"
        );
        Ok(())
    }

    /// Pins that `tools/list` hides denied tools and marks the listing private.
    #[tokio::test]
    async fn tools_list_hides_denied_tools() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("viewer-key", hash, "viewer")];
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["allowed_tool".into()], vec!["*".into()]),
        ])));
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server_with(cfg, || AdvertisedToolsHandler).await?;
        let client = reqwest::Client::new();
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;

        let list_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2_u32,
                    "method": "tools/list"
                })
                .to_string(),
            )
            .send()
            .await?;
        assert_eq!(list_resp.status(), 200);
        let list_body = mcp_response_json(list_resp).await?;
        let tools = list_body
            .get("result")
            .and_then(|result| result.get("tools"))
            .and_then(serde_json::Value::as_array)
            .context("tools list must be an array")?;
        assert_eq!(tools.len(), 1);
        assert_eq!(
            tools
                .first()
                .and_then(|tool| tool.get("name"))
                .and_then(serde_json::Value::as_str),
            Some("allowed_tool")
        );
        assert_eq!(
            list_body
                .get("result")
                .and_then(|result| result.get("cacheScope"))
                .and_then(serde_json::Value::as_str),
            Some("private")
        );

        let denied_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session_id)
            .body(tool_call_body("denied_tool", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(denied_resp.status(), 403);
        Ok(())
    }

    /// Pins that a session minted by one identity is a 404 for another.
    #[tokio::test]
    async fn session_bound_to_initiating_identity() -> anyhow::Result<()> {
        let (token_a, hash_a) = generate_api_key()?;
        let (token_b, hash_b) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry::new("ops-a", hash_a, "ops"),
            ApiKeyEntry::new("ops-b", hash_b, "ops"),
        ];
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server(cfg).await?;
        let client = reqwest::Client::new();
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token_a)).await?;

        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token_b}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(
            resp.status(),
            404,
            "identity B must not reach identity A's MCP session"
        );

        let own_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token_a}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(
            own_resp.status(),
            200,
            "identity A must retain its own session"
        );
        Ok(())
    }

    /// rmcp 3.2.0 (#1228) routes *every* `initialize` through the legacy/session
    /// lifecycle, regardless of the protocol version in the body. Before that, a
    /// `2026-07-28` initialize took the stateless path and minted no session.
    ///
    /// Every other e2e initialize in this file uses `2025-06-18` or `2025-11-25`,
    /// both of which rmcp classifies as legacy (`< 2026-07-28`), so none of them
    /// crosses the path #1228 changed. This test pins the transition: a
    /// post-legacy client must still receive an *identity-bound* session, and that
    /// session must remain unusable by a second identity.
    #[tokio::test]
    async fn initialize_2026_protocol_is_session_bound_to_identity() -> anyhow::Result<()> {
        let (token_a, hash_a) = generate_api_key()?;
        let (token_b, hash_b) = generate_api_key()?;
        let keys = vec![
            ApiKeyEntry::new("ops-a", hash_a, "ops"),
            ApiKeyEntry::new("ops-b", hash_b, "ops"),
        ];
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy);
        let base = spawn_server(cfg).await?;
        let client = reqwest::Client::new();

        // Issued inline rather than via `mcp_initialize_with_bearer`, which
        // hardcodes the legacy `2025-06-18` and therefore cannot exercise #1228.
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token_a}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1_u32,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {},
                        "clientInfo": { "name": "e2e-2026", "version": "0.0.1" }
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .context("initialize request")?;

        assert_eq!(resp.status(), 200, "2026-07-28 initialize must succeed");

        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .context("#1228: a post-legacy initialize must now mint a session")?
            .to_str()
            .context("session id is ascii")?
            .to_owned();
        assert!(
            session_id.starts_with("v1."),
            "session id must be wrapped by our identity binding, got {session_id}"
        );

        let body = mcp_response_json(resp).await?;
        let negotiated = body
            .get("result")
            .and_then(|result| result.get("protocolVersion"))
            .and_then(serde_json::Value::as_str)
            .context("initialize result must carry protocolVersion")?;
        // Asserted as an inequality, not equality with a specific legacy version:
        // which legacy version rmcp settles on is upstream's choice and will move.
        assert!(
            negotiated < "2026-07-28",
            "#1228 negotiates initialize down to a legacy version, got {negotiated}"
        );

        let other_identity_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token_b}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(
            other_identity_resp.status(),
            404,
            "identity B must not reach identity A's post-legacy session"
        );

        let owner_resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token_a}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        assert_eq!(
            owner_resp.status(),
            200,
            "identity A must retain its own session"
        );
        Ok(())
    }

    // ==========================================================================
    // Auth rate limiting
    // ==========================================================================

    /// Pins that the auth failure limiter returns 429 on the third attempt.
    #[tokio::test]
    async fn auth_rate_limit_triggers() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(2)));
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/mcp");

        // First 2 requests: 401 (auth fails, but not rate limited).
        for i in 0..2_u32 {
            let resp = client.post(&url).body("{}").send().await?;
            assert_eq!(resp.status(), 401, "request {i} should be 401");
        }

        // Third request: should be 429 (rate limited).
        let resp = client.post(&url).body("{}").send().await?;
        assert_eq!(resp.status(), 429, "request 3 should be rate limited");
        Ok(())
    }

    // ==========================================================================
    // Extra-route per-IP rate limiting (issue #10)
    // ==========================================================================

    /// Extra router with a GET probe and a POST token-style endpoint -
    /// the unauthenticated surfaces the limiter is designed to protect.
    fn limited_extra_router() -> Router {
        Router::new()
            .route("/ping", get(async || "pong"))
            .route("/token-like", post(async || "issued"))
    }

    /// Pins that the extra-route limiter returns 429 with its explanatory message.
    #[tokio::test]
    async fn extra_route_rate_limit_triggers() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(2);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        for i in 0..2_u32 {
            let resp = client.get(format!("{base}/ping")).send().await?;
            assert_eq!(resp.status(), 200, "request {i} should pass");
        }
        let resp = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(resp.status(), 429, "request 3 should be rate limited");
        assert!(
            resp.text()
                .await?
                .contains("too many requests to application routes")
        );
        Ok(())
    }

    /// Pins that the extra-route limiter also covers POST endpoints.
    #[tokio::test]
    async fn extra_route_rate_limit_applies_to_post() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(2);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/token-like");
        for i in 0..2_u32 {
            let resp = client.post(&url).body("grant").send().await?;
            assert_eq!(resp.status(), 200, "POST {i} should pass");
        }
        let resp = client.post(&url).body("grant").send().await?;
        assert_eq!(resp.status(), 429, "POST 3 should be rate limited");
        Ok(())
    }

    /// Pins that the extra-route budget leaves built-in routes unaffected.
    #[tokio::test]
    async fn extra_route_rate_limit_scoped_to_extra_routes() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        // Exhaust the extra-route budget from this IP.
        let first = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(first.status(), 200);
        let limited = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(limited.status(), 429, "extra route should be exhausted");

        // Built-in routes - health AND the always-present unauthenticated
        // protected-resource-metadata endpoint - must be unaffected: the
        // limiter is layered onto the extra router only, pre-merge.
        let health = client.get(format!("{base}/healthz")).send().await?;
        assert_eq!(health.status(), 200, "/healthz must not share the budget");
        let prm = client
            .get(format!("{base}/.well-known/oauth-protected-resource"))
            .send()
            .await?;
        assert_eq!(
            prm.status(),
            200,
            "built-in PRM route must not share the budget"
        );
        Ok(())
    }

    /// Pins that extra routes stay unlimited when no limiter knob is set.
    #[tokio::test]
    async fn extra_routes_unlimited_without_knob() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_extra_router(limited_extra_router());
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        for i in 0..5_u32 {
            let resp = client.get(format!("{base}/ping")).send().await?;
            assert_eq!(resp.status(), 200, "request {i}: no limiter when unset");
        }
        Ok(())
    }

    // ==========================================================================
    // Retry-After + burst (limiter evolution, 1.12.0)
    // ==========================================================================

    /// Pins that an auth 429 carries a Retry-After of at least one second.
    #[tokio::test]
    async fn auth_rate_limit_sets_retry_after() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(2)));
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/mcp");
        for _ in 0..2_u32 {
            let resp = client.post(&url).body("{}").send().await?;
            assert_eq!(resp.status(), 401);
        }
        let resp = client.post(&url).body("{}").send().await?;
        assert_eq!(resp.status(), 429);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .context("Retry-After present on auth 429")?
            .to_str()?
            .parse::<u64>()?;
        assert!(retry_after >= 1, "delta-seconds must be >= 1");
        Ok(())
    }

    /// Pins that an extra-route 429 carries a Retry-After of at least one second.
    #[tokio::test]
    async fn extra_route_rate_limit_sets_retry_after() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let ok = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(ok.status(), 200);
        let denied = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(denied.status(), 429);
        let retry_after = denied
            .headers()
            .get("retry-after")
            .context("Retry-After present on extra-route 429")?
            .to_str()?
            .parse::<u64>()?;
        assert!(retry_after >= 1, "delta-seconds must be >= 1");
        Ok(())
    }

    /// Pins that the configured burst admits the initial spike before limiting.
    #[tokio::test]
    async fn extra_route_burst_allows_initial_spike() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1)
            .with_extra_route_rate_limit_burst(3);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        for i in 0..3_u32 {
            let resp = client.get(format!("{base}/ping")).send().await?;
            assert_eq!(resp.status(), 200, "burst request {i} should pass");
        }
        let resp = client.get(format!("{base}/ping")).send().await?;
        assert_eq!(resp.status(), 429, "request 4 must exceed the burst bucket");
        Ok(())
    }

    // ==========================================================================
    // Trusted-forwarder mode (limiter evolution, 1.13.0)
    // ==========================================================================

    /// Pins that trusted `X-Forwarded-For` clients get separate limiter buckets.
    #[tokio::test]
    async fn trusted_forwarder_separates_client_buckets() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1)
            .with_trusted_proxies(["127.0.0.1/32"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/ping");
        let a1 = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await?;
        assert_eq!(a1.status(), 200, "client A first request");
        let a2 = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await?;
        assert_eq!(a2.status(), 429, "client A exhausted its own bucket");
        let b1 = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.8")
            .send()
            .await?;
        assert_eq!(b1.status(), 200, "client B has a separate bucket");
        Ok(())
    }

    /// Pins that forwarded headers are inert without trusted proxies configured.
    #[tokio::test]
    async fn forwarded_headers_ignored_without_config() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/ping");
        let first = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await?;
        assert_eq!(first.status(), 200);
        // Different spoofed client, same direct peer: must share the bucket.
        let second = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.8")
            .send()
            .await?;
        assert_eq!(
            second.status(),
            429,
            "without trusted_proxies the spoofed header must be inert"
        );
        Ok(())
    }

    /// Pins that forwarded headers from an untrusted direct peer are ignored.
    #[tokio::test]
    async fn forwarded_headers_ignored_from_untrusted_peer() -> anyhow::Result<()> {
        let port = free_port().await?;
        // Loopback (the actual direct peer) is NOT in the trusted set.
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1)
            .with_trusted_proxies(["192.0.2.0/24"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/ping");
        let first = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await?;
        assert_eq!(first.status(), 200);
        let second = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.8")
            .send()
            .await?;
        assert_eq!(
            second.status(),
            429,
            "headers from an untrusted direct peer must be ignored"
        );
        Ok(())
    }

    /// Pins that RFC 7239 `Forwarded` resolves per client in forwarded mode.
    #[tokio::test]
    async fn forwarded_rfc7239_mode_resolves() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_extra_router(limited_extra_router())
            .with_extra_route_rate_limit(1)
            .with_trusted_proxies(["127.0.0.1/32"])
            .with_forwarded_header(ForwardedHeaderMode::Forwarded);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/ping");
        let a1 = client
            .get(&url)
            .header("forwarded", "for=203.0.113.9")
            .send()
            .await?;
        assert_eq!(a1.status(), 200);
        let a2 = client
            .get(&url)
            .header("forwarded", "for=203.0.113.9")
            .send()
            .await?;
        assert_eq!(a2.status(), 429, "same RFC 7239 client shares its bucket");
        let b1 = client
            .get(&url)
            .header("forwarded", "for=203.0.113.10")
            .send()
            .await?;
        assert_eq!(b1.status(), 200, "different RFC 7239 client is isolated");
        Ok(())
    }

    /// Pins that forwarded clients key the auth limiter, not just extra routes.
    #[tokio::test]
    async fn trusted_forwarder_keys_auth_limiter() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(1)))
            .with_trusted_proxies(["127.0.0.1/32"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let url = format!("{base}/mcp");
        // Two different forwarded clients: each gets its own post-failure
        // budget (quota 1 -> first failure passes as 401).
        let a1 = client
            .post(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .body("{}")
            .send()
            .await?;
        assert_eq!(a1.status(), 401, "client A first failure");
        let b1 = client
            .post(&url)
            .header("x-forwarded-for", "203.0.113.8")
            .body("{}")
            .send()
            .await?;
        assert_eq!(b1.status(), 401, "client B is a separate bucket");
        // Client A again: budget exhausted -> 429. Proves the keying switch
        // applies to the auth limiter, not just extra routes.
        let a2 = client
            .post(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .body("{}")
            .send()
            .await?;
        assert_eq!(a2.status(), 429, "client A exhausted its auth budget");
        Ok(())
    }

    mod crl_tests {
        use core::net::IpAddr;

        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
            CrlDistributionPoint, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod,
            KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
            date_time_ymd,
        };
        use rmcp_server_kit::{
            auth::MtlsConfig,
            mtls_revocation::{CrlSet, DynamicClientCertVerifier},
        };
        use rustls::{
            RootCertStore,
            pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime},
            server::danger::ClientCertVerifier as _,
        };
        use wiremock::MockServer;
        use x509_parser::prelude::{FromDer as _, X509Certificate};

        use super::*;

        struct TestPki {
            ca_pem: String,
            server_cert_pem: String,
            server_key_pem: String,
            client_cert_pem: String,
            client_key_pem: String,
            client_der: CertificateDer<'static>,
            ca_der: CertificateDer<'static>,
            crl_der: CertificateRevocationListDer<'static>,
        }

        struct TlsMaterialPaths {
            _dir: PathBuf,
            ca_cert: PathBuf,
            server_cert: PathBuf,
            server_key: PathBuf,
        }

        fn build_certified_ca() -> anyhow::Result<CertifiedIssuer<'static, KeyPair>> {
            let mut ca_params =
                CertificateParams::new(Vec::<String>::new()).context("ca params")?;
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "test-ca");

            let ca_key = KeyPair::generate().context("ca key")?;
            CertifiedIssuer::self_signed(ca_params, ca_key).context("ca self-signed")
        }

        fn build_end_entity_params(
            common_name: &str,
            serial: u64,
            cdp_url: &str,
            usages: Vec<ExtendedKeyUsagePurpose>,
        ) -> anyhow::Result<CertificateParams> {
            let mut params =
                CertificateParams::new(vec!["localhost".to_owned()]).context("params")?;
            params.serial_number = Some(SerialNumber::from(serial));
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params
                .subject_alt_names
                .push(rcgen::SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = usages;
            params.use_authority_key_identifier_extension = true;
            params.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![cdp_url.to_owned()],
            }];
            Ok(params)
        }

        fn build_crl(
            issuer: &Issuer<'_, KeyPair>,
            revoked_serials: &[u64],
        ) -> anyhow::Result<CertificateRevocationListDer<'static>> {
            let revoked_certs = revoked_serials
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: date_time_ymd(2026, 1, 2),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect::<Vec<_>>();

            Ok(CertificateRevocationListParams {
                this_update: date_time_ymd(2026, 1, 1),
                next_update: date_time_ymd(2027, 1, 1),
                crl_number: SerialNumber::from(1_u64),
                issuing_distribution_point: None,
                revoked_certs,
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(issuer)
            .context("crl signed")?
            .into())
        }

        fn build_test_pki_with_client_params(
            cdp_url: &str,
            client_serial: u64,
            revoked_serials: &[u64],
            mut client_params: CertificateParams,
        ) -> anyhow::Result<TestPki> {
            let ca = build_certified_ca()?;

            let server_key = KeyPair::generate().context("server key")?;
            let server_cert = build_end_entity_params(
                "localhost",
                11,
                cdp_url,
                vec![ExtendedKeyUsagePurpose::ServerAuth],
            )?
            .signed_by(&server_key, &ca)
            .context("server cert")?;

            let client_key = KeyPair::generate().context("client key")?;
            client_params.serial_number = Some(SerialNumber::from(client_serial));
            if client_params.key_usages.is_empty() {
                client_params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
            }
            if client_params.extended_key_usages.is_empty() {
                client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            }
            client_params.use_authority_key_identifier_extension = true;
            let client_cert = client_params
                .signed_by(&client_key, &ca)
                .context("client cert")?;

            Ok(TestPki {
                ca_pem: ca.pem(),
                server_cert_pem: server_cert.pem(),
                server_key_pem: server_key.serialize_pem(),
                client_cert_pem: client_cert.pem(),
                client_key_pem: client_key.serialize_pem(),
                client_der: client_cert.der().clone(),
                ca_der: ca.der().clone(),
                crl_der: build_crl(&ca, revoked_serials)?,
            })
        }

        fn build_test_pki(
            cdp_url: &str,
            client_serial: u64,
            revoked_serials: &[u64],
        ) -> anyhow::Result<TestPki> {
            let client_params = build_end_entity_params(
                "mtls-client",
                client_serial,
                cdp_url,
                vec![ExtendedKeyUsagePurpose::ClientAuth],
            )?;
            build_test_pki_with_client_params(
                cdp_url,
                client_serial,
                revoked_serials,
                client_params,
            )
        }

        fn empty_cn_client_params(dns_sans: Vec<String>) -> anyhow::Result<CertificateParams> {
            let mut params = CertificateParams::new(dns_sans).context("empty-CN client params")?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, "");
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            Ok(params)
        }

        fn build_empty_cn_test_pki(dns_sans: Vec<String>) -> anyhow::Result<TestPki> {
            let pki = build_test_pki_with_client_params(
                "http://127.0.0.1:1/unused.crl",
                200,
                &[],
                empty_cn_client_params(dns_sans)?,
            )?;
            assert_client_cert_has_empty_cn(&pki)?;
            Ok(pki)
        }

        fn assert_client_cert_has_empty_cn(pki: &TestPki) -> anyhow::Result<()> {
            let (_, cert) = X509Certificate::from_der(pki.client_der.as_ref())
                .context("client certificate parses")?;
            assert!(
                cert.subject()
                    .iter_common_name()
                    .filter_map(|attr| attr.as_str().ok())
                    .any(str::is_empty),
                "rcgen must preserve the explicitly empty Subject CN; otherwise the live-handshake test no longer exercises the reported scenario"
            );
            Ok(())
        }

        async fn write_tls_materials(
            pki: &TestPki,
            suffix: &str,
        ) -> anyhow::Result<TlsMaterialPaths> {
            let dir = env::temp_dir().join(format!(
                "rmcp-server-kit-crl-{suffix}-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("clock after epoch")?
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).await.context("create temp dir")?;

            let ca_cert = dir.join("ca.pem");
            let server_cert = dir.join("server.pem");
            let server_key = dir.join("server.key");

            fs::write(&ca_cert, &pki.ca_pem)
                .await
                .context("write ca pem")?;
            fs::write(&server_cert, &pki.server_cert_pem)
                .await
                .context("write server cert pem")?;
            fs::write(&server_key, &pki.server_key_pem)
                .await
                .context("write server key pem")?;

            Ok(TlsMaterialPaths {
                _dir: dir,
                ca_cert,
                server_cert,
                server_key,
            })
        }

        fn build_mtls_auth_config(
            ca_cert_path: &PathBuf,
            deny_on_unavailable: bool,
        ) -> anyhow::Result<AuthConfig> {
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "api_keys": [],
                "mtls": {
                    "ca_cert_path": ca_cert_path,
                    "required": true,
                    "default_role": "viewer",
                    "crl_enabled": true,
                    "crl_deny_on_unavailable": deny_on_unavailable,
                    "crl_allow_http": true,
                    "crl_enforce_expiration": true,
                    "crl_end_entity_only": false,
                    "crl_fetch_timeout": "1s",
                    "crl_stale_grace": "24h"
                }
            }))
            .context("mtls auth config")
        }

        fn build_identity_mtls_auth_config(ca_cert_path: &PathBuf) -> anyhow::Result<AuthConfig> {
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "api_keys": [],
                "mtls": {
                    "ca_cert_path": ca_cert_path,
                    "required": true,
                    "default_role": "viewer",
                    "crl_enabled": false
                }
            }))
            .context("identity mtls auth config")
        }

        fn build_verifier_mtls_config(ca_cert_path: &str) -> anyhow::Result<MtlsConfig> {
            serde_json::from_value(serde_json::json!({
                "ca_cert_path": ca_cert_path,
                "required": true,
                "default_role": "viewer",
                "crl_enabled": true,
                "crl_deny_on_unavailable": false,
                "crl_allow_http": true,
                "crl_enforce_expiration": true,
                "crl_end_entity_only": false,
                "crl_fetch_timeout": "30s",
                "crl_stale_grace": "24h"
            }))
            .context("verifier mtls config")
        }

        #[expect(
            deprecated,
            reason = "deliberate: tests/integration/e2e.rs::crl_tests::build_verifier exercises the test-only prepopulated-CRL constructor until it becomes feature-gated in 4"
        )]
        fn build_verifier(pki: &TestPki) -> anyhow::Result<DynamicClientCertVerifier> {
            let mut roots = RootCertStore::empty();
            roots.add(pki.ca_der.clone()).context("root add")?;
            let crl_set = CrlSet::__test_with_prepopulated_crls(
                Arc::new(roots),
                build_verifier_mtls_config("memory://ca.pem")?,
                vec![pki.crl_der.clone()],
            )
            .context("crl set")?;
            Ok(DynamicClientCertVerifier::new(crl_set))
        }

        async fn spawn_tls_server_with<H, F>(
            config: McpServerConfig,
            handler_factory: F,
        ) -> anyhow::Result<ServerHarness>
        where
            H: ServerHandler + 'static,
            F: Fn() -> H + Send + Sync + Clone + 'static,
        {
            drop(ring::default_provider().install_default());

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let bound: SocketAddr = listener.local_addr()?;
            let bound_config = config.with_bind_addr(bound.to_string());

            let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
            let shutdown = CancellationToken::new();
            let shutdown_for_server = shutdown.clone();

            let validated = bound_config.validate().context("tls test config valid")?;
            let join = tokio::spawn(async move {
                serve_with_listener(
                    listener,
                    validated,
                    handler_factory,
                    Some(ready_tx),
                    Some(shutdown_for_server),
                )
                .await
            });

            let signalled: SocketAddr = timeout(Duration::from_secs(30), ready_rx)
                .await
                .context("tls server readiness")?
                .context("tls server task aborted")?;

            Ok(ServerHarness {
                base: format!("https://localhost:{}", signalled.port()),
                shutdown,
                join: Some(join),
            })
        }

        async fn spawn_tls_server(config: McpServerConfig) -> anyhow::Result<ServerHarness> {
            spawn_tls_server_with(config, || TestHandler).await
        }

        fn build_mtls_client(pki: &TestPki) -> anyhow::Result<reqwest::Client> {
            drop(ring::default_provider().install_default());

            let ca_cert =
                reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).context("ca cert")?;
            let identity = reqwest::Identity::from_pem(
                format!(
                    "{}{}{}",
                    pki.client_cert_pem, pki.ca_pem, pki.client_key_pem
                )
                .as_bytes(),
            )
            .context("client identity")?;

            reqwest::Client::builder()
                .add_root_certificate(ca_cert)
                .identity(identity)
                .build()
                .context("mtls reqwest client")
        }

        /// Pins that a client cert with an empty CN and a DNS SAN authenticates as that SAN.
        #[tokio::test]
        async fn mtls_empty_cn_with_dns_san_authenticates_as_san() -> anyhow::Result<()> {
            let pki = build_empty_cn_test_pki(vec!["san-fallback.example.com".to_owned()])?;
            let paths = write_tls_materials(&pki, "empty-cn-with-san").await?;
            let auth = build_identity_mtls_auth_config(&paths.ca_cert)?;
            let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                RoleConfig::new("viewer", vec!["context_probe".into()], vec!["*".into()]),
            ])));
            let observed = Arc::new(StdMutex::new(None));
            let handler = RbacContextProbeHandler {
                observed: Arc::clone(&observed),
            };

            let cfg = config_on_port(free_port().await?)
                .with_tls(&paths.server_cert, &paths.server_key)
                .with_auth(auth)
                .with_rbac(policy);
            let mut harness = spawn_tls_server_with(cfg, move || handler.clone()).await?;
            let client = build_mtls_client(&pki)?;

            let session_id = mcp_initialize(&client, &harness.base).await?;
            let resp = client
                .post(format!("{}/mcp", harness.base))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", session_id)
                .body(tool_call_body("context_probe", &serde_json::json!({})))
                .send()
                .await
                .context("empty-CN-with-SAN request should complete after TLS handshake")?;

            assert_eq!(resp.status(), 200, "SAN-backed mTLS identity must pass");
            let captured = observed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .context("handler must record RBAC context")?;
            assert_eq!(captured.role.as_deref(), Some("viewer"));
            assert_eq!(
                captured.identity.as_deref(),
                Some("san-fallback.example.com")
            );
            assert_eq!(captured.sub, None, "mTLS auth does not carry a JWT sub");
            assert!(
                !captured.token_present,
                "mTLS auth does not install an OAuth passthrough token"
            );

            harness
                .shutdown()
                .await
                .context("shutdown empty-CN-with-SAN server")?;
            Ok(())
        }

        #[tokio::test]
        /// Pins that a cert with no CN and no SAN handshakes but stays unauthenticated.
        async fn mtls_empty_cn_without_san_handshakes_but_is_unauthenticated() -> anyhow::Result<()>
        {
            let pki = build_empty_cn_test_pki(Vec::new())?;
            let paths = write_tls_materials(&pki, "empty-cn-no-san").await?;
            let auth = build_identity_mtls_auth_config(&paths.ca_cert)?;
            let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                RoleConfig::new("viewer", vec!["context_probe".into()], vec!["*".into()]),
            ])));

            let cfg = config_on_port(free_port().await?)
                .with_tls(&paths.server_cert, &paths.server_key)
                .with_auth(auth)
                .with_rbac(policy);
            let mut harness = spawn_tls_server(cfg).await?;
            let client = build_mtls_client(&pki)?;

            let response = client
                .post(format!("{}/mcp", harness.base))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1_u32,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": { "name": "empty-cn", "version": "0.0.1" }
                        }
                    })
                    .to_string(),
                )
                .send()
                .await
                .context("empty-CN-without-SAN request should complete after TLS handshake")?;

            assert_eq!(
                response.status(),
                401,
                "cert with no non-blank CN or DNS SAN must not authenticate"
            );
            harness
                .shutdown()
                .await
                .context("shutdown empty-CN-without-SAN server")?;
            Ok(())
        }

        /// Pins that an unrevoked client certificate passes CRL verification.
        #[tokio::test]
        async fn crl_allows_unrevoked_client() -> anyhow::Result<()> {
            // Each test runs in its own process under cargo-nextest, so each
            // test that touches rustls (directly or transitively, e.g. via
            // `wiremock::MockServer` -> reqwest) must install the default
            // crypto provider itself. Idempotent across tests in the same
            // process (returns Err if already installed; we ignore it).
            drop(ring::default_provider().install_default());

            let mock_server = MockServer::start().await;
            let pki = build_test_pki(&format!("{}/ca.crl", mock_server.uri()), 100, &[])?;
            let verifier = build_verifier(&pki)?;

            let result = verifier.verify_client_cert(&pki.client_der, &[], UnixTime::now());
            assert!(result.is_ok(), "unrevoked client cert should verify");
            Ok(())
        }

        /// Pins that a revoked client certificate fails CRL verification.
        #[tokio::test]
        async fn crl_rejects_revoked_client() -> anyhow::Result<()> {
            // See `crl_allows_unrevoked_client` for the rationale; same
            // requirement applies here.
            drop(ring::default_provider().install_default());

            let mock_server = MockServer::start().await;
            let pki = build_test_pki(&format!("{}/ca.crl", mock_server.uri()), 101, &[101])?;
            let verifier = build_verifier(&pki)?;

            let result = verifier.verify_client_cert(&pki.client_der, &[], UnixTime::now());
            assert!(
                result.is_err(),
                "revoked client cert should fail verification"
            );
            Ok(())
        }

        /// Pins that an unreachable CDP fails open when the config says so.
        #[tokio::test]
        async fn crl_fail_open_when_cdp_unreachable() -> anyhow::Result<()> {
            let pki = build_test_pki("http://127.0.0.1:1/unreachable.crl", 102, &[])?;
            let paths = write_tls_materials(&pki, "fail-open").await?;
            let auth = build_mtls_auth_config(&paths.ca_cert, false)?;

            let port = free_port().await?;
            let cfg = config_on_port(port)
                .with_tls(&paths.server_cert, &paths.server_key)
                .with_auth(auth);
            let mut harness = spawn_tls_server(cfg).await?;

            let client = build_mtls_client(&pki)?;
            let response = client
                .get(format!("{}/healthz", harness.base))
                .send()
                .await
                .context("fail-open request should succeed")?;

            assert_eq!(response.status(), 200);
            harness
                .shutdown()
                .await
                .context("shutdown fail-open server")?;
            Ok(())
        }

        /// Pins that an unreachable CDP fails the handshake when the config says so.
        #[tokio::test]
        async fn crl_fail_closed_when_cdp_unreachable() -> anyhow::Result<()> {
            let pki = build_test_pki("http://127.0.0.1:1/unreachable.crl", 103, &[])?;
            let paths = write_tls_materials(&pki, "fail-closed").await?;
            let auth = build_mtls_auth_config(&paths.ca_cert, true)?;

            let port = free_port().await?;
            let cfg = config_on_port(port)
                .with_tls(&paths.server_cert, &paths.server_key)
                .with_auth(auth);
            let mut harness = spawn_tls_server(cfg).await?;

            let client = build_mtls_client(&pki)?;
            let response = client.get(format!("{}/healthz", harness.base)).send().await;

            assert!(
                response.is_err(),
                "fail-closed request should fail during handshake"
            );
            harness
                .shutdown()
                .await
                .context("shutdown fail-closed server")?;
            Ok(())
        }

        /// Regression test for the serialized-accept-loop DoS: an idle TCP
        /// connection that never sends a byte must NOT block other clients
        /// from completing TLS handshakes. Pre-fix, `TlsListener::accept`
        /// performed the handshake inline, so this test hung past its
        /// deadline.
        #[tokio::test]
        async fn tls_idle_connection_does_not_block_others() -> anyhow::Result<()> {
            drop(ring::default_provider().install_default());

            // Plain TLS (no mTLS auth): the CDP URL in the cert is unused.
            let pki = build_test_pki("http://127.0.0.1:1/unused.crl", 104, &[])?;
            let paths = write_tls_materials(&pki, "idle-conn").await?;

            let port = free_port().await?;
            let cfg = config_on_port(port).with_tls(&paths.server_cert, &paths.server_key);
            let mut harness = spawn_tls_server(cfg).await?;

            // Open a raw TCP connection and send NOTHING, keeping it open.
            let tls_port: u16 = harness
                .base
                .rsplit(':')
                .next()
                .and_then(|port_text| port_text.parse().ok())
                .context("harness port")?;
            let idle = TcpStream::connect(("127.0.0.1", tls_port))
                .await
                .context("idle raw connection")?;

            // While the idle connection is open, a full TLS request on a
            // second connection must succeed within the deadline.
            let ca_cert =
                reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).context("ca certificate")?;
            let client = reqwest::Client::builder()
                .add_root_certificate(ca_cert)
                .build()
                .context("tls client")?;
            let response = timeout(
                Duration::from_secs(5),
                client.get(format!("{}/healthz", harness.base)).send(),
            )
            .await
            .context("idle connection must not block other TLS handshakes")?
            .context("healthz over TLS")?;
            assert_eq!(response.status(), 200);

            drop(idle);
            harness
                .shutdown()
                .await
                .context("shutdown idle-conn server")?;
            Ok(())
        }
    }

    // ==========================================================================
    // C1 regression: middleware ordering
    // ==========================================================================

    /// Regression test for C1: origin check MUST execute before auth so that a
    /// caller presenting a forbidden Origin header is rejected with 403 BEFORE
    /// any auth challenge (401) is surfaced. This prevents information leakage
    /// about whether auth is configured and matches the documented "outer" vs
    /// "inner" middleware semantics.
    #[tokio::test]
    async fn c1_origin_rejected_before_auth() -> anyhow::Result<()> {
        let (_token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("guard-key", hash, "ops")];

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_allowed_origins(["http://localhost:3000"]);
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        // No Authorization header + bad Origin. If auth ran first we'd get 401.
        // Origin running outermost must short-circuit to 403.
        let resp = client
            .post(format!("{base}/mcp"))
            .header("origin", "http://evil.example.com")
            .body("{}")
            .send()
            .await?;
        assert_eq!(
            resp.status(),
            403,
            "bad Origin must be rejected (403) before auth challenge (401)"
        );
        Ok(())
    }

    /// Regression test for C1: the request-body size limit MUST execute before
    /// RBAC parses the JSON-RPC body. Otherwise an oversized payload would be
    /// fully buffered by RBAC before the size gate fires. We send a payload
    /// larger than the configured cap and expect 413 Payload Too Large.
    #[tokio::test]
    async fn c1_body_limit_applies_before_rbac() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
        ])));

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(test_auth_config(keys))
            .with_rbac(policy)
            // 512 byte cap - much smaller than default 1 MiB.
            .with_max_request_body(512);
        let base = spawn_server(cfg).await?;

        // Build a 16 KiB JSON-RPC body (well over 512).
        let padding = "A".repeat(16 * 1024);
        let oversized = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"x","arguments":{{"pad":"{padding}"}}}}}}"#
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(oversized)
            .send()
            .await?;
        assert_eq!(
            resp.status(),
            413,
            "oversized body must be rejected with 413 before RBAC buffers it"
        );
        Ok(())
    }

    /// Regression test for the public `max_request_body` knob above rmcp's own
    /// default: rmcp independently caps POST bodies at 4 MiB
    /// (`DEFAULT_MAX_REQUEST_BODY_BYTES`), so a configured cap above that used to
    /// under-deliver - the outer tower layer admitted the body and rmcp answered
    /// 413 from inside the service. The fix propagates the configured value into
    /// `StreamableHttpServerConfig::with_max_request_body_bytes`.
    #[tokio::test]
    async fn max_request_body_above_rmcp_default_is_honoured() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port)
            // Above rmcp's 4 MiB default, below this crate's outer cap.
            .with_max_request_body(6 * 1024 * 1024);
        let base = spawn_server(cfg).await?;

        // ~5 MiB: accepted only if the configured cap reaches rmcp. The padding
        // rides in an ignored extra field so the request stays otherwise valid.
        let padding = "x".repeat(5 * 1024 * 1024);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"test","version":"0.1"}},"pad":"{padding}"}}}}"#
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body)
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            200,
            "a valid body under the configured cap must be accepted, not rejected as too large"
        );
        Ok(())
    }

    // ==========================================================================
    // C3 regression: OAuth admin endpoints gated by expose_admin_endpoints
    // ==========================================================================

    #[cfg(feature = "oauth")]
    fn oauth_cfg_with_proxy(expose: bool) -> anyhow::Result<OAuthConfig> {
        // OAuthConfig and OAuthProxyConfig are `#[non_exhaustive]`, so we build
        // them via serde from a TOML-equivalent JSON document. This is the same
        // path real consumers take when loading from a config file.
        //
        // `allow_unauthenticated_admin_endpoints = true` is the explicit M3
        // escape hatch: this helper preserves the historical (pre-M3) behaviour
        // of `expose=true, require_auth=false` for tests that exercise the
        // route mounting/advertisement; production deployments should instead
        // set `require_auth_on_admin_endpoints = true`.
        let json = serde_json::json!({
            "issuer": "https://upstream.example/",
            "audience": "rmcp-server-kit-test",
            "jwks_uri": "https://upstream.example/.well-known/jwks.json",
            "jwks_cache_ttl": "10m",
            "proxy": {
                "authorize_url": "https://upstream.example/authorize",
                "token_url": "https://upstream.example/token",
                "client_id": "mcp-client",
                "introspection_url": "https://upstream.example/introspect",
                "revocation_url": "https://upstream.example/revoke",
                "expose_admin_endpoints": expose,
                "require_auth_on_admin_endpoints": false,
                "allow_unauthenticated_admin_endpoints": expose,
            }
        });
        serde_json::from_value(json).context("oauth config deserialization")
    }

    /// Regression test for C3: by default (`expose_admin_endpoints = false`),
    /// `/introspect` and `/revoke` must NOT be mounted and must NOT be
    /// advertised in the authorization-server metadata document. This is the
    /// secure default - unauthenticated endpoints that proxy to the upstream
    /// `IdP` must be explicitly opted in to.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn c3_admin_endpoints_hidden_by_default() -> anyhow::Result<()> {
        let port = free_port().await?;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth_cfg_with_proxy(false)?);
        let cfg = config_on_port(port)
            .with_auth(auth)
            .with_public_url(format!("http://127.0.0.1:{port}"));
        let base = spawn_server(cfg).await?;

        // Metadata must NOT advertise the admin endpoints.
        let meta: serde_json::Value =
            reqwest::get(&format!("{base}/.well-known/oauth-authorization-server"))
                .await?
                .json()
                .await?;
        assert!(
            meta.get("introspection_endpoint").is_none(),
            "introspection must not be advertised by default"
        );
        assert!(
            meta.get("revocation_endpoint").is_none(),
            "revocation must not be advertised by default"
        );

        // Endpoints must 404 (not mounted).
        let client = reqwest::Client::new();
        let introspect_resp = client
            .post(format!("{base}/introspect"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=abc")
            .send()
            .await?;
        assert_eq!(
            introspect_resp.status(),
            404,
            "/introspect must 404 by default"
        );

        let revoke_resp = client
            .post(format!("{base}/revoke"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=abc")
            .send()
            .await?;
        assert_eq!(revoke_resp.status(), 404, "/revoke must 404 by default");
        Ok(())
    }

    /// Regression test for C3: when `expose_admin_endpoints = true`, the
    /// endpoints ARE advertised in metadata and ARE mounted (i.e. no longer
    /// 404). We don't assert a specific upstream response because no real
    /// `IdP` is reachable - we only assert non-404, proving the route is live.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn c3_admin_endpoints_exposed_when_enabled() -> anyhow::Result<()> {
        let port = free_port().await?;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth_cfg_with_proxy(true)?);
        let cfg = config_on_port(port)
            .with_auth(auth)
            .with_public_url(format!("http://127.0.0.1:{port}"));
        let base = spawn_server(cfg).await?;

        let meta: serde_json::Value =
            reqwest::get(&format!("{base}/.well-known/oauth-authorization-server"))
                .await?
                .json()
                .await?;
        assert!(
            meta.get("introspection_endpoint").is_some(),
            "introspection must be advertised when expose_admin_endpoints=true"
        );
        assert!(
            meta.get("revocation_endpoint").is_some(),
            "revocation must be advertised when expose_admin_endpoints=true"
        );

        // Endpoint is mounted: response should NOT be 404. Upstream is
        // unreachable so we expect a bad-gateway / error response, but the
        // route itself is live.
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/introspect"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=abc")
            .send()
            .await?;
        assert_ne!(
            resp.status(),
            404,
            "/introspect must be mounted when expose_admin_endpoints=true"
        );
        Ok(())
    }

    /// Pins that the OAuth admin endpoints require auth when so configured.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn c3_admin_endpoints_can_require_auth() -> anyhow::Result<()> {
        let (token, hash) = generate_api_key()?;
        // M6: `/introspect` and `/revoke` require the admin role, so the
        // authenticated caller must hold `admin` (the default `admin_role`).
        let mut auth = AuthConfig::with_keys(vec![ApiKeyEntry::new("oauth-admin", hash, "admin")]);

        let mut oauth = oauth_cfg_with_proxy(true)?;
        if let Some(proxy) = oauth.proxy.as_mut() {
            proxy.require_auth_on_admin_endpoints = true;
        }
        auth.oauth = Some(oauth);

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(auth)
            .with_public_url(format!("http://127.0.0.1:{port}"));
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();

        let unauth = client
            .post(format!("{base}/introspect"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=abc")
            .send()
            .await?;
        assert!(
            matches!(unauth.status().as_u16(), 401 | 403),
            "expected 401/403 without auth, got {}",
            unauth.status()
        );

        let authed = client
            .post(format!("{base}/introspect"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=abc")
            .send()
            .await?;
        assert_ne!(
            authed.status(),
            401,
            "authenticated caller must reach the proxy handler"
        );
        assert_ne!(
            authed.status(),
            403,
            "authenticated caller must reach the proxy handler"
        );
        Ok(())
    }

    /// rust-review MEDIUM: the OAuth proxy routes (`/token`, `/register`,
    /// `/introspect`, `/revoke`) must honor the operator-configured
    /// `max_request_body`, not fall back to axum's 2 MB `DefaultBodyLimit`.
    ///
    /// Sets a 1 KiB cap (well below the 2 MB default) and asserts an oversized
    /// (~4 KiB) POST to each route type - `/token` (String extractor),
    /// `/register` (Json extractor), and `/introspect` (admin-merge route) - is
    /// rejected with 413. The body-limit layer rejects BEFORE the handler runs,
    /// so the unreachable upstream never matters. A small body proves the cap is
    /// not over-tight.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn c3_oauth_proxy_routes_honor_max_request_body() -> anyhow::Result<()> {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth_cfg_with_proxy(true)?); // exposes /introspect + /revoke

        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(auth)
            .with_public_url(format!("http://127.0.0.1:{port}"))
            .with_max_request_body(1024); // 1 KiB, far below axum's 2 MB default
        let base = spawn_server(cfg).await?;

        let client = reqwest::Client::new();
        let oversized = "x".repeat(4096); // 4 KiB > 1 KiB cap

        // /token - String extractor.
        let token_resp = client
            .post(format!("{base}/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(oversized.clone())
            .send()
            .await?;
        assert_eq!(
            token_resp.status(),
            413,
            "/token must reject oversized body with 413 (got {})",
            token_resp.status()
        );

        // /register - Json extractor. Send an oversized JSON string value.
        let big_json = serde_json::json!({ "redirect_uris": [oversized.clone()] }).to_string();
        let register_resp = client
            .post(format!("{base}/register"))
            .header("content-type", "application/json")
            .body(big_json)
            .send()
            .await?;
        assert_eq!(
            register_resp.status(),
            413,
            "/register must reject oversized body with 413 (got {})",
            register_resp.status()
        );

        // /introspect - admin-merge route (proves the admin sub-router inherits
        // the cap after the merge).
        let introspect_resp = client
            .post(format!("{base}/introspect"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(oversized.clone())
            .send()
            .await?;
        assert_eq!(
            introspect_resp.status(),
            413,
            "/introspect must reject oversized body with 413 (got {})",
            introspect_resp.status()
        );

        // A small body must NOT be rejected by the limit (proves it isn't
        // over-tight). Upstream is unreachable so we expect a 5xx/4xx from the
        // handler - just assert it is NOT 413.
        let small_resp = client
            .post(format!("{base}/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await?;
        assert_ne!(
            small_resp.status(),
            413,
            "a small body must pass the size limit"
        );
        Ok(())
    }

    // ==========================================================================
    // BUG-NEW: shutdown timeout double-signal regression test
    // ==========================================================================

    /// Regression test for the shutdown double-signal bug fixed in 0.11.0.
    ///
    /// **Bug**: Both branches of the shutdown `tokio::select!` in
    /// `run_server` previously awaited `shutdown_signal()` independently.
    /// Because `shutdown_signal` resolves once per future and consumes one
    /// signal, the force-exit timer was tied to a *second* signal that
    /// would never come. Under a single SIGTERM with an in-flight request,
    /// graceful drain hung forever.
    ///
    /// **What this test verifies**:
    /// 1. With a long-running in-flight request and a 500ms shutdown
    ///    timeout, cancelling the harness's `CancellationToken` (the same
    ///    code path a real SIGTERM would trigger after BUG-NEW's fix)
    ///    causes the server to exit within ~500ms.
    /// 2. The server actually waits at least most of the graceful window
    ///    (~450ms) instead of insta-killing the in-flight request -- this
    ///    catches an over-correction that would skip graceful drain
    ///    entirely.
    ///
    /// **Cross-platform note**: real `SIGTERM` / Ctrl+C is intentionally
    /// NOT used here (Windows portability). Production `shutdown_signal()`
    /// still wires SIGTERM/SIGINT; this test exercises the same internal
    /// cancellation path via the unified `CancellationToken` from H-T1.
    #[tokio::test]
    async fn shutdown_timeout_honored_on_first_signal() -> anyhow::Result<()> {
        use std::{sync::Mutex, time::Instant};

        use axum::{extract::State, routing::get};
        use tokio::sync::oneshot;

        // Build a server with a *short* graceful deadline (500ms) and an
        // extra route that sleeps 10s server-side -- representing an
        // in-flight tool call that will not finish before the deadline.
        //
        // The handler signals via a oneshot channel as soon as it begins
        // executing, so the test can wait for the request to be
        // *deterministically* in-flight before triggering shutdown
        // (eliminates the prior race where slow CI scheduling could let
        // shutdown fire before the server even saw the request).
        let port = free_port().await?;
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let started_state = Arc::new(Mutex::new(Some(started_tx)));
        let cfg = config_on_port(port)
            .with_shutdown_timeout(Duration::from_millis(500))
            .with_extra_router(
                Router::new()
                    .route(
                        "/slow",
                        get(
                            async move |State(state): State<
                                Arc<Mutex<Option<oneshot::Sender<()>>>>,
                            >| {
                                // Signal exactly once that we've begun
                                // serving the request.
                                if let Ok(mut guard) = state.lock()
                                    && let Some(tx) = guard.take()
                                    && tx.send(()).is_err()
                                {
                                    // The client may already be gone; best-effort notify.
                                    tracing::debug!("oneshot receiver dropped before the send");
                                }
                                sleep(Duration::from_secs(10)).await;
                                "done"
                            },
                        ),
                    )
                    .with_state(started_state),
            );

        let mut harness = spawn_server(cfg).await?;
        let base = harness.base.clone();

        // Fire the long-running request in the background. It MUST be
        // in-flight when we trigger shutdown; otherwise graceful drain
        // would complete instantly regardless of the bug.
        let slow_url = format!("{base}/slow");
        let in_flight = tokio::spawn(async move {
            // We don't care about the response -- only that the request
            // was accepted and is occupying server resources during
            // shutdown.
            drop(reqwest::get(&slow_url).await);
        });

        // Wait deterministically until the handler has started executing
        // server-side (replaces the prior fixed 100ms sleep, which was
        // race-prone on slow CI runners). Bound the wait so a real
        // regression in request acceptance still surfaces as a test
        // failure rather than a hang.
        timeout(Duration::from_secs(30), started_rx)
            .await
            .context("/slow handler did not start within 5s -- request never reached the server")?
            .context("started_tx dropped without sending")?;

        // Trigger graceful shutdown. With BUG-NEW fixed, this is
        // semantically identical to a single SIGTERM.
        let start = Instant::now();
        let res = timeout(Duration::from_secs(2), harness.shutdown()).await;
        let elapsed = start.elapsed();

        // Outer timeout MUST NOT fire -- if it did, the server hung past
        // both its graceful window and the cushion, which is the bug.
        let server_result =
            res.context("server failed to shut down within 2s -- BUG-NEW regression")?;

        // The server should exit cleanly (an error here would indicate a
        // fault unrelated to this bug; surface it loudly).
        server_result.context("server returned an error during shutdown")?;

        // Best-effort: drain the background HTTP task. It may complete
        // with an error (connection reset by force-exit) or succeed if
        // the runtime aborted it -- either is acceptable.
        in_flight.abort();
        drop(in_flight.await);

        // Lower bound: the server actually waited (most of) the graceful
        // window. 450ms = 500ms - 50ms scheduling/cleanup slack. Catches
        // an over-correction that skips graceful drain.
        assert!(
            elapsed >= Duration::from_millis(450),
            "shutdown completed in {elapsed:?}, expected >= 450ms (server skipped graceful drain)"
        );

        // Upper bound: the server did NOT hang. 1500ms = 500ms graceful +
        // 1000ms generous slack for CI scheduling jitter (the bug used to
        // hang indefinitely; any value materially below the 2s outer
        // timeout proves the fix).
        assert!(
            elapsed < Duration::from_millis(1500),
            "shutdown took {elapsed:?}, expected < 1500ms (BUG-NEW regression)"
        );
        Ok(())
    }

    // ==========================================================================
    // H-A2: McpServerConfig builder + validate()
    // ==========================================================================

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "intentionally exercises the deprecated direct-field-write path to verify builder equivalence; this test IS the equivalence proof"
    )]
    /// Builder methods produce the same effective config as direct field
    /// assignment. Asserts a representative subset of fields touched by
    /// every common builder so future drift surfaces here first.
    async fn builder_matches_direct_field_assignment() -> anyhow::Result<()> {
        let port = free_port().await?;
        let bind = format!("127.0.0.1:{port}");

        let manual = {
            let mut cfg = McpServerConfig::new(&bind, "test", "0.0.1");
            cfg.allowed_origins = vec!["http://localhost:3000".into()];
            cfg.public_url = Some("http://example.com".into());
            cfg.max_request_body = 4096;
            cfg.request_timeout = Duration::from_secs(7);
            cfg.shutdown_timeout = Duration::from_secs(11);
            cfg.session_idle_timeout = Duration::from_mins(2);
            cfg.sse_keep_alive = Duration::from_secs(3);
            cfg.tool_rate_limit = Some(42);
            cfg.max_concurrent_requests = Some(99);
            cfg.compression_enabled = true;
            cfg.compression_min_size = 256;
            cfg.log_request_headers = true;
            cfg.admin_enabled = false;
            cfg.admin_role = "ops".to_owned();
            cfg
        };

        let built = McpServerConfig::new(&bind, "test", "0.0.1")
            .with_allowed_origins(["http://localhost:3000"])
            .with_public_url("http://example.com")
            .with_max_request_body(4096)
            .with_request_timeout(Duration::from_secs(7))
            .with_shutdown_timeout(Duration::from_secs(11))
            .with_session_idle_timeout(Duration::from_mins(2))
            .with_sse_keep_alive(Duration::from_secs(3))
            .with_tool_rate_limit(42)
            .with_max_concurrent_requests(99)
            .enable_compression(256)
            .enable_request_header_logging()
            .enable_admin("ops");
        // `enable_admin` flips admin_enabled=true; manual leaves it false.
        // Compare every other field; admin_enabled is asserted separately.
        assert_eq!(manual.bind_addr, built.bind_addr);
        assert_eq!(manual.allowed_origins, built.allowed_origins);
        assert_eq!(manual.public_url, built.public_url);
        assert_eq!(manual.max_request_body, built.max_request_body);
        assert_eq!(manual.request_timeout, built.request_timeout);
        assert_eq!(manual.shutdown_timeout, built.shutdown_timeout);
        assert_eq!(manual.session_idle_timeout, built.session_idle_timeout);
        assert_eq!(manual.sse_keep_alive, built.sse_keep_alive);
        assert_eq!(manual.tool_rate_limit, built.tool_rate_limit);
        assert_eq!(
            manual.max_concurrent_requests,
            built.max_concurrent_requests
        );
        assert_eq!(manual.compression_enabled, built.compression_enabled);
        assert_eq!(manual.compression_min_size, built.compression_min_size);
        assert_eq!(manual.log_request_headers, built.log_request_headers);
        assert_eq!(manual.admin_role, built.admin_role);
        assert!(built.admin_enabled, "enable_admin should set the flag");
        assert!(
            manual.validate().is_ok(),
            "manual config must validate cleanly"
        );
        Ok(())
    }

    /// `enable_admin` without a corresponding `with_auth(...).enabled = true`
    /// must be rejected by `validate()` as `RmcpServerKitError::Config`. With the
    /// typestate `Validated<McpServerConfig>` proof token, `serve()` cannot
    /// even be called with an invalid config -- the rejection happens at
    /// `validate()` time, statically preventing exposing `/admin/*` without
    /// authentication.
    #[tokio::test]
    async fn validate_rejects_admin_without_auth() -> anyhow::Result<()> {
        let cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1").enable_admin("admin");
        let admin_err = cfg
            .validate()
            .err()
            .context("must reject admin without auth")?;
        assert!(
            matches!(&admin_err, rmcp_server_kit::RmcpServerKitError::Config(msg) if msg.contains("admin")),
            "expected RmcpServerKitError::Config mentioning admin, got: {admin_err}"
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "intentionally exercises direct field writes to test partial-pair rejection (no builder sets only one of the pair)"
    )]
    /// Setting only the TLS cert (or only the key) must be rejected by
    /// `validate()`. Both paths must be present together or absent together.
    async fn validate_rejects_partial_tls_pair() -> anyhow::Result<()> {
        let mut cert_only_cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1");
        cert_only_cfg.tls_cert_path = Some(PathBuf::from("/tmp/cert.pem"));
        let cert_err = cert_only_cfg
            .validate()
            .err()
            .context("cert without key must be rejected")?;
        assert!(
            matches!(&cert_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("tls_key_path"))
        );

        let mut key_only_cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1");
        key_only_cfg.tls_key_path = Some(PathBuf::from("/tmp/key.pem"));
        let key_err = key_only_cfg
            .validate()
            .err()
            .context("key without cert must be rejected")?;
        assert!(
            matches!(&key_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("tls_cert_path"))
        );

        // Both set together: only the *file existence* matters at startup,
        // not validate() -- so this should pass validation.
        let paired_cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1")
            .with_tls("/tmp/cert.pem", "/tmp/key.pem");
        drop(
            paired_cfg
                .validate()
                .context("paired cert+key must validate")?,
        );
        Ok(())
    }

    /// Bad `bind_addr` / `public_url` / origin / zero body cap must each be
    /// rejected with a descriptive `RmcpServerKitError::Config`.
    #[tokio::test]
    async fn validate_rejects_other_misconfig() -> anyhow::Result<()> {
        // Unparseable bind_addr
        let bad_bind_cfg = McpServerConfig::new("not-a-socket-addr", "t", "0");
        let bind_err = bad_bind_cfg
            .validate()
            .err()
            .context("must reject bad bind_addr")?;
        assert!(
            matches!(&bind_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("bind_addr"))
        );

        // public_url without scheme
        let public_url_cfg =
            McpServerConfig::new("127.0.0.1:0", "t", "0").with_public_url("example.com/no-scheme");
        let public_url_err = public_url_cfg
            .validate()
            .err()
            .context("must reject schemeless public_url")?;
        assert!(
            matches!(&public_url_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("public_url"))
        );

        // origin without scheme
        let origin_cfg =
            McpServerConfig::new("127.0.0.1:0", "t", "0").with_allowed_origins(["localhost"]);
        let origin_err = origin_cfg
            .validate()
            .err()
            .context("must reject schemeless origin")?;
        assert!(
            matches!(&origin_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("allowed_origins"))
        );

        // zero body cap
        let body_cap_cfg = McpServerConfig::new("127.0.0.1:0", "t", "0").with_max_request_body(0);
        let body_cap_err = body_cap_cfg
            .validate()
            .err()
            .context("must reject zero body cap")?;
        assert!(
            matches!(&body_cap_err, rmcp_server_kit::RmcpServerKitError::Config(message) if message.contains("max_request_body"))
        );
        Ok(())
    }

    // ==========================================================================
    // HookedHandler integration (H-A4)
    // ==========================================================================

    /// Spin up a server whose factory wraps `TestHandler` in a
    /// [`rmcp_server_kit::tool_hooks::HookedHandler`].  This proves the new async hook
    /// types satisfy `serve_with_listener`'s `ServerHandler` bound and that
    /// hook plumbing does not break the basic transport path.
    #[tokio::test]
    async fn hooked_handler_serves_healthz() -> anyhow::Result<()> {
        use rmcp_server_kit::tool_hooks::{
            AfterHook, BeforeHook, HookOutcome, ToolHooks, with_hooks,
        };

        drop(ring::default_provider().install_default());

        let port = free_port().await?;
        let cfg = config_on_port(port);

        let before_calls = Arc::new(AtomicUsize::new(0));
        let after_calls = Arc::new(AtomicUsize::new(0));
        let before_calls_for_hook = Arc::clone(&before_calls);
        let after_calls_for_hook = Arc::clone(&after_calls);

        let before: BeforeHook = Arc::new(move |_ctx| {
            let before_counter = Arc::clone(&before_calls_for_hook);
            Box::pin(async move {
                let _: usize = before_counter.fetch_add(1, Ordering::Relaxed);
                HookOutcome::Continue
            })
        });
        let after: AfterHook = Arc::new(move |_ctx, _disp, _bytes| {
            let after_counter = Arc::clone(&after_calls_for_hook);
            Box::pin(async move {
                let _: usize = after_counter.fetch_add(1, Ordering::Relaxed);
            })
        });

        let hooks = Arc::new(
            ToolHooks::new()
                .with_max_result_bytes(64 * 1024)
                .with_before(before)
                .with_after(after),
        );

        // Custom spawn flow because the standard `spawn_server` factory
        // returns the bare TestHandler; we need it wrapped in HookedHandler.
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
        let bound: SocketAddr = listener.local_addr()?;
        let bound_cfg = cfg.with_bind_addr(bound.to_string());

        let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();
        let hooks_for_factory = Arc::clone(&hooks);

        let validated = bound_cfg.validate().context("test config valid")?;
        let join = tokio::spawn(async move {
            serve_with_listener(
                listener,
                validated,
                move || with_hooks(TestHandler, Arc::clone(&hooks_for_factory)),
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
        });

        let _signalled: SocketAddr = timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("server did not signal readiness within 5s")?
            .context("server task aborted before readiness signal")?;

        let resp = reqwest::get(&format!("http://{bound}/healthz")).await?;
        assert_eq!(resp.status(), 200);

        // Hooks haven't fired (no /mcp tools/call traffic), but the server
        // is alive and the wrapped handler is being served.
        assert_eq!(before_calls.load(Ordering::Relaxed), 0);
        assert_eq!(after_calls.load(Ordering::Relaxed), 0);

        shutdown.cancel();
        drop(timeout(Duration::from_secs(2), join).await);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: tests/integration/e2e.rs::hook_outcome_variants_are_constructible keeps the uniform test signature while it only constructs values"
    )]
    /// Constructing all three [`rmcp_server_kit::tool_hooks::HookOutcome`] variants
    /// must compile and round-trip through the public API.  This guards
    /// against accidental visibility regressions on the new enum during
    /// future refactors.
    fn hook_outcome_variants_are_constructible() -> anyhow::Result<()> {
        use rmcp::{
            ErrorData,
            model::{CallToolResult, ContentBlock},
        };
        use rmcp_server_kit::tool_hooks::HookOutcome;

        drop(HookOutcome::Continue);
        drop(HookOutcome::Deny(ErrorData::invalid_request(
            "denied", None,
        )));
        drop(HookOutcome::Replace(Box::new(CallToolResult::success(
            vec![ContentBlock::text("x".to_owned())],
        ))));
        Ok(())
    }

    // ==========================================================================
    // Peer-address exposure for extra_router (PeerAddr + ConnectInfo<SocketAddr>)
    // ==========================================================================

    mod peer_addr_tests {
        use core::net::IpAddr;

        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        use rmcp_server_kit::transport::PeerAddr;

        use super::*;

        /// Extra router exposing `/peer`, which reports both peer-address
        /// extensions as `"<ConnectInfo>|<PeerAddr>"`. Mounted via
        /// `with_extra_router`, i.e. it bypasses auth/RBAC - exactly the
        /// scenario from the downstream report.
        fn peer_router() -> Router {
            async fn peer_probe(
                ConnectInfo(ci): ConnectInfo<SocketAddr>,
                peer: PeerAddr,
            ) -> String {
                format!("{ci}|{}", peer.addr)
            }
            Router::new().route("/peer", get(peer_probe))
        }

        fn assert_loopback_peer(text: &str) -> anyhow::Result<()> {
            let (ci, pa) = text.split_once('|').context("probe format <ci>|<pa>")?;
            let connect_info: SocketAddr = ci.parse().context("ConnectInfo<SocketAddr> value")?;
            let peer_addr: SocketAddr = pa.parse().context("PeerAddr value")?;
            assert_eq!(
                connect_info, peer_addr,
                "ConnectInfo and PeerAddr must agree"
            );
            assert_eq!(connect_info.ip(), IpAddr::from([127, 0, 0, 1]));
            Ok(())
        }

        /// Pins that an extra route observes matching `ConnectInfo` and `PeerAddr` extensions.
        #[tokio::test]
        async fn plain_extra_router_sees_peer_addr() -> anyhow::Result<()> {
            let port = free_port().await?;
            let cfg = config_on_port(port).with_extra_router(peer_router());
            let base = spawn_server(cfg).await?;

            let resp = reqwest::get(&format!("{base}/peer")).await?;
            assert_eq!(resp.status(), 200);
            assert_loopback_peer(&resp.text().await?)?;
            Ok(())
        }

        // -- server-side-TLS-only PKI (no mTLS, no CRL) --

        /// PEM-encoded server-side-TLS-only materials (no mTLS, no CRL).
        struct ServerTlsPki {
            ca: String,
            server_cert: String,
            server_key: String,
        }

        fn build_server_tls_pki() -> anyhow::Result<ServerTlsPki> {
            let mut ca_params =
                CertificateParams::new(Vec::<String>::new()).context("ca params")?;
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "peer-addr-test-ca");
            let ca_key = KeyPair::generate().context("ca key")?;
            let ca = CertifiedIssuer::self_signed(ca_params, ca_key).context("ca self-signed")?;

            let mut params =
                CertificateParams::new(vec!["localhost".to_owned()]).context("params")?;
            params
                .distinguished_name
                .push(DnType::CommonName, "localhost");
            params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_key = KeyPair::generate().context("server key")?;
            let server_cert = params.signed_by(&server_key, &ca).context("server cert")?;

            Ok(ServerTlsPki {
                ca: ca.pem(),
                server_cert: server_cert.pem(),
                server_key: server_key.serialize_pem(),
            })
        }

        struct ServerTlsPaths {
            _dir: PathBuf,
            server_cert: PathBuf,
            server_key: PathBuf,
        }

        async fn write_server_tls_materials(pki: &ServerTlsPki) -> anyhow::Result<ServerTlsPaths> {
            let dir = env::temp_dir().join(format!(
                "rmcp-server-kit-peer-addr-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("clock after epoch")?
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).await.context("create temp dir")?;

            let server_cert = dir.join("server.pem");
            let server_key = dir.join("server.key");
            fs::write(&server_cert, &pki.server_cert)
                .await
                .context("write server cert pem")?;
            fs::write(&server_key, &pki.server_key)
                .await
                .context("write server key pem")?;

            Ok(ServerTlsPaths {
                _dir: dir,
                server_cert,
                server_key,
            })
        }

        async fn spawn_plain_tls_server(config: McpServerConfig) -> anyhow::Result<ServerHarness> {
            drop(ring::default_provider().install_default());

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let bound: SocketAddr = listener.local_addr()?;
            let bound_config = config.with_bind_addr(bound.to_string());

            let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
            let shutdown = CancellationToken::new();
            let shutdown_for_server = shutdown.clone();

            let validated = bound_config.validate().context("tls test config valid")?;
            let join = tokio::spawn(async move {
                serve_with_listener(
                    listener,
                    validated,
                    || TestHandler,
                    Some(ready_tx),
                    Some(shutdown_for_server),
                )
                .await
            });

            let signalled: SocketAddr = timeout(Duration::from_secs(30), ready_rx)
                .await
                .context("tls server readiness")?
                .context("tls server task aborted")?;

            Ok(ServerHarness {
                base: format!("https://localhost:{}", signalled.port()),
                shutdown,
                join: Some(join),
            })
        }

        /// Pins that the same peer-address extensions reach an extra route over TLS.
        #[tokio::test]
        async fn tls_extra_router_sees_peer_addr() -> anyhow::Result<()> {
            drop(ring::default_provider().install_default());

            let pki = build_server_tls_pki()?;
            let paths = write_server_tls_materials(&pki).await?;

            let port = free_port().await?;
            let cfg = config_on_port(port)
                .with_tls(&paths.server_cert, &paths.server_key)
                .with_extra_router(peer_router());
            let mut harness = spawn_plain_tls_server(cfg).await?;

            let ca = reqwest::Certificate::from_pem(pki.ca.as_bytes()).context("ca cert")?;
            let client = reqwest::Client::builder()
                .add_root_certificate(ca)
                .build()
                .context("tls reqwest client")?;

            let resp = client
                .get(format!("{}/peer", harness.base))
                .send()
                .await
                .context("tls /peer request")?;
            assert_eq!(resp.status(), 200);
            assert_loopback_peer(&resp.text().await?)?;

            harness.shutdown().await.context("shutdown tls server")?;
            Ok(())
        }
    }

    // ==========================================================================
    // F8 regression: graceful shutdown must not cancel in-flight MCP sessions
    // at the START of the grace window
    // ==========================================================================

    /// An in-flight MCP tool call that finishes inside `shutdown_timeout` must
    /// complete successfully when shutdown is triggered.
    ///
    /// Before the fix, the MCP service was handed `ct.child_token()`, and the
    /// graceful path cancels `ct` the moment the shutdown trigger fires -- i.e. at
    /// the *start* of the grace window. rmcp ends the SSE response stream on that
    /// cancellation, so a tool call still running was cut off even though the
    /// drain window had barely opened. The service now holds a dedicated session
    /// token cancelled only after axum finishes draining.
    ///
    /// The test is event-gated rather than duration-gated: it waits for the
    /// handler to signal that the call is genuinely in flight, triggers shutdown,
    /// and only then releases the handler. Nothing depends on elapsed time
    /// thresholds, so it does not become flaky under CI scheduling.
    ///
    /// It must exercise `/mcp` specifically -- `with_extra_router` routes never
    /// reach `StreamableHttpService`, which is the sole consumer of the session
    /// token, so a test built that way would pass against the bug.
    #[tokio::test]
    async fn in_flight_mcp_call_completes_within_grace_window() -> anyhow::Result<()> {
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let release = Arc::new(Notify::new());
        let handler = BlockingToolHandler {
            started: Arc::new(StdMutex::new(Some(started_tx))),
            release: Arc::clone(&release),
        };

        // Generous grace window: the tool returns immediately once released, so
        // the call finishes well inside it. Anything cut short is the bug.
        let cfg = McpServerConfig::new("127.0.0.1:0", "test-rmcp-server-kit", "0.0.1")
            .with_shutdown_timeout(Duration::from_secs(10));

        let mut harness = spawn_server_with(cfg, move || handler.clone()).await?;
        let base = harness.base.clone();
        let client = reqwest::Client::new();

        // A bare `tools/call` without a session is rejected by rmcp before it ever
        // reaches the handler, so the full handshake is required.
        let session_id = mcp_initialize(&client, &base).await?;

        let call = tokio::spawn({
            let call_client = client.clone();
            let call_base = base.clone();
            let call_session_id = session_id.clone();
            async move {
                call_client
                    .post(format!("{call_base}/mcp"))
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-session-id", call_session_id)
                    .body(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 2_u32,
                            "method": "tools/call",
                            "params": { "name": "slow", "arguments": {} }
                        })
                        .to_string(),
                    )
                    .send()
                    .await
            }
        });

        // The call is now genuinely in flight inside the MCP service.
        timeout(Duration::from_secs(10), started_rx)
            .await
            .context("tool handler did not start within 10s")?
            .context("started signal dropped")?;

        // Trigger shutdown while it is still blocked, then let it finish.
        // The join handle is taken so the harness `Drop` does not also try to
        // shut down, and so the server task can be awaited after the call.
        let server_task = harness.join.take().context("server join handle")?;
        harness.shutdown.cancel();
        sleep(Duration::from_millis(150)).await;
        release.notify_waiters();

        let resp = timeout(Duration::from_secs(10), call)
            .await
            .context("tool call did not return within 10s")?
            .context("tool call task panicked")?
            .context("tool call transport error -- the session was cancelled mid-flight")?;

        assert_eq!(
            resp.status(),
            200,
            "in-flight MCP call must survive the grace window"
        );
        let body = resp.text().await.context("read tool response body")?;
        assert!(
            body.contains("released"),
            "tool response must carry the handler's payload, got: {body}"
        );

        timeout(Duration::from_secs(10), server_task)
            .await
            .context("server did not shut down within 10s")?
            .context("server task panicked")?
            .context("server shutdown returned an error")?;
        Ok(())
    }

    /// Perform the MCP `initialize` handshake and return the negotiated
    /// `Mcp-Session-Id`.
    async fn mcp_initialize(client: &reqwest::Client, base: &str) -> anyhow::Result<String> {
        mcp_initialize_with_bearer(client, base, None).await
    }

    async fn mcp_response_json(resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
        let body = resp.text().await.context("read MCP response body")?;
        assert!(!body.is_empty(), "MCP response body must not be empty");
        let payload = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .find(|payload| !payload.is_empty())
            .unwrap_or(body.as_str());
        serde_json::from_str(payload).context("MCP response body is JSON")
    }

    async fn mcp_initialize_with_bearer(
        client: &reqwest::Client,
        base: &str,
        bearer: Option<&str>,
    ) -> anyhow::Result<String> {
        let init_request = client
            .post(format!("{base}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        let authed_init_request = match bearer {
            Some(token) => init_request.header("authorization", format!("Bearer {token}")),
            None => init_request,
        };
        let resp = authed_init_request
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1_u32,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "e2e", "version": "0.0.1" }
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .context("initialize request")?;
        assert_eq!(resp.status(), 200, "initialize must succeed");
        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .context("server must return Mcp-Session-Id")?
            .to_str()
            .context("session id is ascii")?
            .to_owned();

        let notify_request = client
            .post(format!("{base}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id);
        let authed_notify_request = match bearer {
            Some(token) => notify_request.header("authorization", format!("Bearer {token}")),
            None => notify_request,
        };
        drop(
            authed_notify_request
                .body(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    })
                    .to_string(),
                )
                .send()
                .await
                .context("initialized notification")?,
        );

        Ok(session_id)
    }

    /// A tool call still running when `shutdown_timeout` expires must have its
    /// response stream terminated by the force-exit path.
    ///
    /// `session_ct` is cancelled in BOTH arms of the shutdown `select!`: after
    /// axum drains, and when the force-exit timer wins. This covers the second
    /// arm, which the grace-window test above never reaches.
    ///
    /// The assertion is deliberately on the **client-side response body**, not on
    /// the server task completing. When force-exit wins the `select!` the
    /// `axum::serve` future is simply dropped, so `serve_with_listener` returns
    /// whether or not the session token was cancelled -- asserting on the join
    /// handle would produce a test that cannot fail. What the cancellation
    /// actually changes is that rmcp ends the SSE stream, so the body reaches EOF
    /// instead of hanging until some unrelated timeout.
    ///
    /// Awaiting only `send()` would also be useless: the SSE response headers are
    /// established before the tool result exists, so `send()` resolves either way.
    /// The body read is the observation point.
    #[tokio::test]
    async fn in_flight_mcp_call_terminated_when_grace_window_expires() -> anyhow::Result<()> {
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let release = Arc::new(Notify::new());
        let handler = BlockingToolHandler {
            started: Arc::new(StdMutex::new(Some(started_tx))),
            release: Arc::clone(&release),
        };

        // Short grace window; the handler is never released, so the call cannot
        // finish inside it and force-exit must be what ends the stream.
        let cfg = McpServerConfig::new("127.0.0.1:0", "test-rmcp-server-kit", "0.0.1")
            .with_shutdown_timeout(Duration::from_millis(300));

        let mut harness = spawn_server_with(cfg, move || handler.clone()).await?;
        let base = harness.base.clone();
        let client = reqwest::Client::new();
        let session_id = mcp_initialize(&client, &base).await?;

        let call = tokio::spawn({
            let call_client = client.clone();
            let call_base = base.clone();
            let call_session_id = session_id.clone();
            async move {
                call_client
                    .post(format!("{call_base}/mcp"))
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-session-id", call_session_id)
                    .body(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 2_u32,
                            "method": "tools/call",
                            "params": { "name": "slow", "arguments": {} }
                        })
                        .to_string(),
                    )
                    .send()
                    .await
            }
        });

        timeout(Duration::from_secs(10), started_rx)
            .await
            .context("tool handler did not start within 10s")?
            .context("started signal dropped")?;

        let server_task = harness.join.take().context("server join handle")?;
        harness.shutdown.cancel();

        let resp = timeout(Duration::from_secs(10), call)
            .await
            .context("response headers did not arrive within 10s")?
            .context("tool call task panicked")?
            .context("tool call transport error")?;

        // The regression manifests here as a hang, caught by the timeout, rather
        // than as an elapsed-time comparison.
        let body = timeout(Duration::from_secs(10), resp.text())
            .await
            .context(
                "response body never terminated -- force-exit did not cancel the session token",
            )?
            .context("read response body")?;

        assert!(
            !body.contains("released"),
            "the tool never completed, so its payload must not appear: {body}"
        );

        // Let the blocked handler unwind rather than leaving it parked.
        release.notify_waiters();

        timeout(Duration::from_secs(10), server_task)
            .await
            .context("server did not shut down within 10s")?
            .context("server task panicked")?
            .context("server shutdown returned an error")?;
        Ok(())
    }
}
