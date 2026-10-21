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
        future::{pending, ready},
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
    #[cfg(feature = "oauth")]
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures::stream;
    #[cfg(feature = "oauth")]
    use jsonwebtoken::Algorithm;
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
    #[cfg(feature = "oauth")]
    use rsa::{pkcs8, pkcs8::EncodePrivateKey as _, rand_core, traits::PublicKeyParts as _};
    use rustls::crypto::ring;
    use secrecy::SecretString;
    #[cfg(feature = "oauth")]
    use tokio::io::AsyncWriteExt as _;
    use tokio::{
        fs,
        net::{TcpListener, TcpStream},
        sync::{Mutex, Notify, oneshot},
        task::JoinHandle,
        time::{sleep, timeout},
    };
    use tokio_util::sync::CancellationToken;

    // - Minimal test handler -

    #[derive(Clone)]
    struct TestHandler;

    #[derive(Clone)]
    struct NestedHeaderToolHandler;

    impl ServerHandler for NestedHeaderToolHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        fn get_tool(&self, name: &str) -> Option<Tool> {
            if name != "route" {
                return None;
            }
            let schema = serde_json::json!({"type":"object","properties":{"target":{
                "type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}
            }}});
            schema
                .as_object()
                .map(|object| Tool::new("route", "route", Arc::new(object.clone())))
        }

        fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + MaybeSendFuture + '_
        {
            ready(Ok(ListToolsResult::with_all_items(
                self.get_tool("route").into_iter().collect(),
            )))
        }

        fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
        {
            ready(Ok(CallToolResult::success(vec![]).into()))
        }
    }

    /// Pins nested parameter headers through the hook and RBAC-context wrappers.
    #[tokio::test]
    async fn nested_param_header_is_enforced_through_both_wrappers() -> anyhow::Result<()> {
        use std::io::{Write as _, stdout};

        use rmcp_server_kit::tool_hooks::{ToolHooks, with_hooks};

        // Given: both kit wrappers surround a handler with a nested header schema.
        let hooks = Arc::new(ToolHooks::new());
        let base = spawn_server_with(config_on_port(0), move || {
            with_hooks(NestedHeaderToolHandler, Arc::clone(&hooks))
        })
        .await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let cases = [
            (
                Some("eu"),
                serde_json::json!({"target":{"region":"eu"}}),
                200,
                None,
            ),
            (
                None,
                serde_json::json!({"target":{"region":"eu"}}),
                400,
                Some("missing Mcp-Param-Region header"),
            ),
            (
                Some("us"),
                serde_json::json!({"target":{"region":"eu"}}),
                400,
                Some("does not match body value"),
            ),
            (None, serde_json::json!({}), 200, None),
        ];
        let mut observed = Vec::new();
        // When: matching, missing, mismatching, and absent nested arguments cross HTTP.
        for (header, arguments, expected, message) in cases {
            let request = client
                .post(format!("{}/mcp", base.base))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "route");
            let request_with_header = match header {
                Some(value) => request.header("Mcp-Param-Region", value),
                None => request,
            };
            let response = request_with_header
                .json(&serde_json::json!({
                    "jsonrpc":"2.0", "id":1_u32, "method":"tools/call",
                    "params":{"name":"route","arguments":arguments,"_meta":{
                        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities":{}
                    }}
                }))
                .send()
                .await?;
            let status = response.status();
            let body = mcp_response_json(response).await?;
            writeln!(stdout(), "nested header: {status} {body}")?;
            observed.push((status, body, expected, message));
        }
        // Then: every outcome follows the schema supplied through both wrappers.
        for (status, body, expected, message) in observed {
            assert_eq!(status, expected, "{body}");
            match message {
                Some(fragment) => assert!(
                    body.pointer("/error/message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|text| text.contains(fragment)),
                    "{body}"
                ),
                None => assert!(body.get("result").is_some(), "{body}"),
            }
        }
        Ok(())
    }

    #[derive(Clone)]
    struct RecordingToolHandler {
        called: Arc<StdMutex<Vec<String>>>,
    }

    #[derive(Clone)]
    struct CancellableToolHandler {
        events: Arc<StdMutex<Vec<&'static str>>>,
        started: Arc<Notify>,
    }

    impl ServerHandler for CancellableToolHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        #[expect(
            clippy::integer_division_remainder_used,
            reason = "tokio select expands to remainder arithmetic even in biased mode"
        )]
        async fn call_tool(
            &self,
            request: CallToolRequestParams,
            context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, rmcp::ErrorData> {
            if request.name == "wait" {
                self.events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push("started");
                self.started.notify_one();
                tokio::select! {
                    biased;
                    () = context.ct.cancelled() => {
                        self.events.lock().unwrap_or_else(PoisonError::into_inner).push("cancelled");
                        return Err(rmcp::ErrorData::internal_error("cancelled", None));
                    }
                    () = sleep(Duration::from_secs(30)) => {
                        self.events.lock().unwrap_or_else(PoisonError::into_inner).push("timeout");
                    }
                }
            }
            if request.name == "quick" {
                self.events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push("quick");
            }
            Ok(CallToolResult::success(vec![]).into())
        }
    }

    async fn wait_for_handler_cancellation(
        events: &StdMutex<Vec<&'static str>>,
    ) -> anyhow::Result<()> {
        let observed = timeout(Duration::from_secs(10), async {
            while !events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&"cancelled")
            {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let snapshot = events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        observed
            .with_context(|| format!("missing cancelled event within 10s; events={snapshot:?}"))?;
        Ok(())
    }

    /// Pins legacy notification cancellation while retaining the same usable session.
    #[tokio::test]
    async fn legacy_session_cancellation_reaches_the_handler() -> anyhow::Result<()> {
        // Given: a wait tool is in flight on an initialized legacy session.
        let events = Arc::new(StdMutex::new(Vec::new()));
        let started = Arc::new(Notify::new());
        let handler = CancellableToolHandler {
            events: Arc::clone(&events),
            started: Arc::clone(&started),
        };
        let base = spawn_server_with(config_on_port(0), move || handler.clone()).await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .build()?;
        let session = mcp_initialize_with_bearer(&client, &base.base, None).await?;
        let call = tokio::spawn({
            let call_client = client.clone();
            let url = format!("{}/mcp", base.base);
            let call_session = session.clone();
            async move {
                let response = call_client.post(url).header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream").header("mcp-session-id", call_session)
                    .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait"}}"#).send().await?;
                let body = response.text().await?;
                Ok::<_, reqwest::Error>(body)
            }
        });
        timeout(Duration::from_secs(10), started.notified())
            .await
            .context("wait tool did not start")?;
        // When: the client cancels request 2 without closing its session.
        let cancellation_response = client.post(format!("{}/mcp", base.base)).header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream").header("mcp-session-id", &session)
            .body(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"test"}}"#).send().await?;
        assert_eq!(cancellation_response.status(), 202);
        // Then: the handler sees cancellation and the session still serves quick calls.
        wait_for_handler_cancellation(&events).await?;
        let response = client
            .post(format!("{}/mcp", base.base))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session)
            .body(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"quick"}}"#)
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        let body = mcp_response_json(response).await?;
        assert!(body.get("result").is_some(), "quick call: {body}");
        call.abort();
        let snapshot = events.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(!snapshot.contains(&"timeout"), "events={snapshot:?}");
        drop(snapshot);
        Ok(())
    }

    /// Pins handler cancellation when a negotiated stateless client disconnects.
    #[tokio::test]
    async fn stateless_2026_disconnect_cancels_the_handler() -> anyhow::Result<()> {
        // Given: a metadata-bearing stateless wait call has reached the handler.
        let events = Arc::new(StdMutex::new(Vec::new()));
        let started = Arc::new(Notify::new());
        let handler = CancellableToolHandler {
            events: Arc::clone(&events),
            started: Arc::clone(&started),
        };
        let base = spawn_server_with(config_on_port(0), move || handler.clone()).await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .build()?;
        let call = tokio::spawn({
            let call_client = client.clone();
            let url = format!("{}/mcp", base.base);
            async move {
                let response = call_client.post(url).header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("MCP-Protocol-Version", "2026-07-28").header("Mcp-Method", "tools/call").header("Mcp-Name", "wait")
                    .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#).send().await?;
                pending::<()>().await;
                Ok::<_, reqwest::Error>(response)
            }
        });
        timeout(Duration::from_secs(10), started.notified())
            .await
            .context("stateless wait tool did not start")?;
        // When: dropping the pending HTTP request or unread response disconnects the client.
        call.abort();
        let joined = call.await;
        assert!(
            joined.is_err_and(|error| error.is_cancelled()),
            "client task must be aborted"
        );
        // Then: the handler observes cancellation before another stateless request succeeds.
        wait_for_handler_cancellation(&events).await?;
        let response = client.post(format!("{}/mcp", base.base)).header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28").header("Mcp-Method", "tools/call").header("Mcp-Name", "quick")
            .body(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"quick","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#).send().await?;
        assert_eq!(response.status(), 200);
        let body = mcp_response_json(response).await?;
        assert!(body.get("result").is_some(), "quick call: {body}");
        Ok(())
    }

    impl ServerHandler for RecordingToolHandler {
        fn get_info(&self) -> RmcpServerConfig {
            RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        }

        fn call_tool(
            &self,
            request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
        {
            self.called
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.name.into_owned());
            ready(Ok(CallToolResult::success(vec![]).into()))
        }
    }

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

    // - Test helpers -

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
        /// actually-bound port - safe to use immediately.
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
        assert!(
            headers.get("server").is_none(),
            "{context}: server fingerprint header must be absent"
        );
        assert!(
            headers.get("x-powered-by").is_none(),
            "{context}: x-powered-by fingerprint header must be absent"
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
        assert!(
            headers.get("server").is_none(),
            "{context}: server fingerprint header must be absent"
        );
        assert!(
            headers.get("x-powered-by").is_none(),
            "{context}: x-powered-by fingerprint header must be absent"
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
        assert_security_header_defaults(mcp_resp.headers(), "unauthenticated /mcp 401");
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
        assert_security_header_defaults(resp.headers(), "rbac deny 403");
        Ok(())
    }

    /// Pins that requests without an Origin header pass the origin check.
    #[tokio::test]
    async fn no_origin_header_passes() -> anyhow::Result<()> {
        let port = free_port().await?;
        let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
        let base = spawn_server(cfg).await?;

        // No Origin header - non-browser client, should pass.
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

    async fn assert_allowed_tool_call_response(
        resp: reqwest::Response,
        context: &str,
    ) -> anyhow::Result<()> {
        assert_eq!(resp.status(), 200, "{context}: HTTP status must be 200");
        let body = mcp_response_json(resp).await?;
        assert_eq!(
            body.get("id").and_then(serde_json::Value::as_u64),
            Some(1),
            "{context}: JSON-RPC id must match the request"
        );
        assert!(
            body.get("result").is_some() || body.get("error").is_some(),
            "{context}: JSON-RPC response must carry result or error: {body}"
        );
        Ok(())
    }

    /// Proves malformed parser inputs never dispatch a tool RBAC did not inspect.
    #[tokio::test]
    async fn rbac_parser_differential_never_dispatches_an_uninspected_tool() -> anyhow::Result<()> {
        use std::io::{Write as _, stdout};
        // Given: an authenticated session permits only the control tool.
        let (token, hash) = generate_api_key()?;
        let called = Arc::new(StdMutex::new(Vec::new()));
        let handler = RecordingToolHandler {
            called: Arc::clone(&called),
        };
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("ops", vec!["allowed_tool".into()], vec!["*".into()]),
        ])));
        let cfg = config_on_port(0)
            .with_auth(test_auth_config(vec![ApiKeyEntry::new(
                "ops-key", hash, "ops",
            )]))
            .with_rbac(policy);
        let base = spawn_server_with(cfg, move || handler.clone()).await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let session = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;
        let bodies = [
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"denied_tool"},"params":{"name":"allowed_tool"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"denied_tool","name":"allowed_tool"}}"#,
            r#"{"jsonrpc":"2.0","id":3.0,"method":"tools/call","params":{"name":"denied_tool"}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"allowed_tool"}}"#,
        ];
        // When: duplicate fields, a floating id, and the valid control reach the real router.
        for (index, body) in bodies.into_iter().enumerate() {
            let response = client
                .post(format!("{}/mcp", base.base))
                .bearer_auth(&token)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &session)
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let text = response.text().await?;
            writeln!(stdout(), "parser case {index}: {status} {text}")?;
            // Then: malformed requests cannot succeed, and only the control is dispatched.
            match index {
                0 | 1 => assert!(
                    !(status == 200 && text.contains("\"result\"")),
                    "case {index}: {status} {text}"
                ),
                2 => assert_eq!(status, 403, "float-id denied call: {text}"),
                3 => {
                    assert_eq!(status, 200, "control: {text}");
                    assert!(
                        text.contains("\"result\""),
                        "control must return result: {text}"
                    );
                }
                _ => anyhow::bail!("unexpected parser differential case"),
            }
        }
        let observed = called.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(*observed, vec!["allowed_tool"]);
        Ok(())
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
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;

        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session_id)
            .body(tool_call_body("resource_list", &serde_json::json!({})))
            .send()
            .await?;
        assert_allowed_tool_call_response(resp, "wildcard-permitted tool").await?;
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
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;

        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(tool_call_body(
                "container_exec",
                &serde_json::json!({"cmd": "ls -la"}),
            ))
            .send()
            .await?;
        assert_allowed_tool_call_response(resp, "allowlisted command").await?;

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
        assert_security_header_defaults(resp.headers(), "auth rate limit 429");
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
        assert_security_header_defaults(resp.headers(), "extra route rate limit 429");
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
        assert_security_header_defaults(resp.headers(), "auth retry-after 429");
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
        assert_security_header_defaults(resp.headers(), "mcp body limit 413");
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

    #[cfg(feature = "oauth")]
    fn generate_oauth_test_keypair(kid: &str) -> anyhow::Result<(String, serde_json::Value)> {
        let mut rng = rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).context("keypair generation")?;
        let private_pem = private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .context("PKCS8 PEM export")?
            .to_string();
        let public_key = private_key.to_public_key();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())
            }]
        });
        Ok((private_pem, jwks))
    }

    #[cfg(feature = "oauth")]
    fn mint_oauth_test_token(private_pem: &str, kid: &str) -> anyhow::Result<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://mcp.test.local/mcp",
            "sub": "asy01-http",
            "scope": "mcp:read",
            "exp": now.saturating_add(3600),
            "iat": now
        });
        jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
    }

    #[cfg(feature = "oauth")]
    fn oauth_auth_config(jwks_uri: &str, ttl: &str) -> anyhow::Result<AuthConfig> {
        let json = serde_json::json!({
            "issuer": "https://auth.test.local",
            "audience": "https://mcp.test.local/mcp",
            "jwks_uri": jwks_uri,
            "jwks_cache_ttl": ttl,
            "allow_http_oauth_urls": true,
            "ssrf_allowlist": {
                "hosts": ["localhost"],
                "cidrs": ["127.0.0.0/8"]
            },
            "scopes": [{"scope": "mcp:read", "role": "viewer"}]
        });
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(serde_json::from_value(json).context("oauth config deserialization")?);
        Ok(auth)
    }

    #[cfg(feature = "oauth")]
    async fn initialize_status(
        client: &reqwest::Client,
        base: &str,
        token: &str,
    ) -> anyhow::Result<reqwest::StatusCode> {
        let resp = client
            .post(format!("{base}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {token}"))
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
        Ok(resp.status())
    }

    /// `localhost` resolves to `::1`, `127.0.0.1` or both, in a host-specific
    /// order, and IP-literal OAuth URLs are rejected, so the JWKS mock must
    /// answer on both loopback addresses on one shared port.
    #[cfg(feature = "oauth")]
    struct DualStackMock {
        /// The server bound to `127.0.0.1`.
        v4: wiremock::MockServer,
        /// The server bound to `::1` on the same port, when this host has `::1`.
        v6: Option<wiremock::MockServer>,
    }

    #[cfg(feature = "oauth")]
    impl DualStackMock {
        /// Binds `127.0.0.1` on an ephemeral port and `::1` on the same port,
        /// retrying when that port is taken on `::1`; a host without `::1`
        /// gets an IPv4-only mock.
        async fn start() -> anyhow::Result<Self> {
            use core::net::{Ipv4Addr, Ipv6Addr};
            use std::{io::ErrorKind as IoErrorKind, net::TcpListener as StdTcpListener};

            for _ in 0..16_u8 {
                let v4_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .context("bind the IPv4 loopback mock listener")?;
                let port = v4_listener
                    .local_addr()
                    .context("read the IPv4 mock listener address")?
                    .port();
                match StdTcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                    Ok(v6_listener) => {
                        let v4 = wiremock::MockServer::builder()
                            .listener(v4_listener)
                            .start()
                            .await;
                        let v6 = wiremock::MockServer::builder()
                            .listener(v6_listener)
                            .start()
                            .await;
                        return Ok(Self { v4, v6: Some(v6) });
                    }
                    Err(err) if err.kind() == IoErrorKind::AddrInUse => {}
                    Err(_) => {
                        let v4 = wiremock::MockServer::builder()
                            .listener(v4_listener)
                            .start()
                            .await;
                        return Ok(Self { v4, v6: None });
                    }
                }
            }
            anyhow::bail!("no port was free on both 127.0.0.1 and ::1 after 16 attempts")
        }

        /// The port both loopback servers share.
        fn port(&self) -> u16 {
            self.v4.address().port()
        }

        /// Mounts a fresh mock from `build` on every running server.
        async fn mount<B>(&self, build: B)
        where
            B: Fn() -> wiremock::Mock,
        {
            build().mount(&self.v4).await;
            if let Some(v6) = &self.v6 {
                build().mount(v6).await;
            }
        }

        /// Counts the requests for `wanted` received across both servers.
        async fn path_count(&self, wanted: &str) -> anyhow::Result<usize> {
            let mut count = 0_usize;
            for server in [Some(&self.v4), self.v6.as_ref()].into_iter().flatten() {
                let requests = server
                    .received_requests()
                    .await
                    .context("request recording must be enabled")?;
                count = count.saturating_add(
                    requests
                        .iter()
                        .filter(|request| request.url.path() == wanted)
                        .count(),
                );
            }
            Ok(count)
        }
    }

    /// Writes a complete initialize request, waits until the server has
    /// started the JWKS fetch, then drops the connection.
    #[cfg(feature = "oauth")]
    async fn cancel_initialize_after_jwks_fetch_started(
        base: &str,
        token: &str,
        jwks: &DualStackMock,
    ) -> anyhow::Result<()> {
        let before = jwks.path_count("/jwks.json").await?;
        let addr = base
            .strip_prefix("http://")
            .context("test base must be plain HTTP")?;
        let mut stream = TcpStream::connect(addr)
            .await
            .context("connect raw client")?;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_u32,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "e2e", "version": "0.0.1" }
            }
        })
        .to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .context("write raw initialize")?;
        timeout(Duration::from_secs(10), async {
            loop {
                if jwks
                    .path_count("/jwks.json")
                    .await
                    .is_ok_and(|count| count > before)
                {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("the server must start the JWKS fetch within 10s")?;
        drop(stream);
        Ok(())
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

    /// Pins that a cancelled OAuth HTTP request does not abort the shared JWKS
    /// refresh: the first request is cancelled only after the upstream JWKS
    /// fetch has started. Before the shared-refresh fix the fetch ran inside
    /// the request future with the cooldown already stamped, so dropping the
    /// connection cancelled it and the immediate second request was rejected
    /// with 401. The 2 s upstream delay gives the server ample time to notice
    /// the dropped connection before the fetch could complete.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn asy01_cancelled_http_request_does_not_burn_jwks_cooldown() -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        let kid = "asy01-http";
        let (pem, jwks_body) = generate_oauth_test_keypair(kid)?;
        let token = mint_oauth_test_token(&pem, kid)?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(&jwks_body)
                        .set_delay(Duration::from_secs(2)),
                )
        })
        .await;

        let jwks_uri = format!("http://localhost:{}/jwks.json", jwks.port());
        let port = free_port().await?;
        let cfg = config_on_port(port)
            .with_auth(oauth_auth_config(&jwks_uri, "10m")?)
            .with_public_url(format!("http://127.0.0.1:{port}"));
        let base = spawn_server(cfg).await?;
        let client = reqwest::Client::new();

        cancel_initialize_after_jwks_fetch_started(&base.base, &token, &jwks).await?;
        let status = timeout(
            Duration::from_secs(15),
            initialize_status(&client, &base.base, &token),
        )
        .await
        .context("the second initialize must finish")??;
        assert_eq!(
            status, 200,
            "the second request must join the cancelled request's refresh and authenticate"
        );
        assert_eq!(
            jwks.path_count("/jwks.json").await?,
            1,
            "the second request must join the in-flight refresh, not start another"
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
        assert_security_header_defaults(token_resp.headers(), "oauth token body limit 413");

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

    /// With `challenge_scopes = ["mcp:read"]` and
    /// `omit_error_on_missing_credential = true`, a request without credentials
    /// gets the RFC 6750 3.1 bare challenge plus the scope hint, a malformed
    /// token keeps its `error` parameters after the hint, and neither status
    /// nor body changes.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn challenge_scope_and_bare_missing_credential() -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        let (_pem, jwks_body) = generate_oauth_test_keypair("challenge-kid")?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
        })
        .await;
        let oauth: OAuthConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://idp.challenge.test/realms/challenge",
            "audience": "mcp-challenge",
            "jwks_uri": format!("http://localhost:{}/jwks.json", jwks.port()),
            "allow_http_oauth_urls": true,
            "ssrf_allowlist": {
                "hosts": ["localhost"],
                "cidrs": ["127.0.0.0/8"]
            },
            "scopes": [{"scope": "mcp:read", "role": "viewer"}],
            "challenge_scopes": ["mcp:read"],
            "omit_error_on_missing_credential": true
        }))
        .context("oauth config deserialization")?;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth);
        let port = free_port().await?;
        let base = spawn_server(
            config_on_port(port)
                .with_auth(auth)
                .with_public_url(format!("http://127.0.0.1:{port}")),
        )
        .await?;
        let url = format!("http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp");
        let client = reqwest::Client::new();

        for (bearer, challenge, body) in [
            (
                None,
                format!(r#"Bearer resource_metadata="{url}", scope="mcp:read""#),
                "unauthorized: missing credential",
            ),
            (
                Some("a.b.c"),
                format!(
                    r#"Bearer resource_metadata="{url}", scope="mcp:read", error="invalid_token", error_description="token is invalid""#
                ),
                "unauthorized: invalid credential",
            ),
        ] {
            let unauthenticated = client
                .post(format!("{base}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
            let request = match bearer {
                Some(token) => unauthenticated.header("authorization", format!("Bearer {token}")),
                None => unauthenticated,
            };
            let resp = request
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0.0.1"}}}"#)
                .send()
                .await
                .context("POST /mcp")?;

            assert_eq!(resp.status(), 401, "{bearer:?}");
            let challenges: Vec<&str> = resp
                .headers()
                .get_all("www-authenticate")
                .iter()
                .map(|value| value.to_str())
                .collect::<Result<_, _>>()
                .context("challenge is visible ASCII")?;
            assert_eq!(challenges, [challenge.as_str()], "{bearer:?}");
            assert_eq!(
                resp.headers()
                    .get("content-type")
                    .and_then(|value| value.to_str().ok()),
                Some("text/plain; charset=utf-8"),
                "{bearer:?}"
            );
            assert_eq!(resp.text().await?, body, "{bearer:?}");
        }
        Ok(())
    }

    /// Step-up names a scope that unlocks the call without changing the denial body.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn insufficient_scope_challenge_names_unlocking_scope() -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        // Given a read-only token and an admin-first scope mapping.
        let kid = "step-up-kid";
        let (pem, jwks_body) = generate_oauth_test_keypair(kid)?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
        })
        .await;
        let token = mint_oauth_test_token(&pem, kid)?;
        for enabled in [true, false] {
            let oauth: OAuthConfig = serde_json::from_value(serde_json::json!({
                "issuer": "https://auth.test.local",
                "audience": "https://mcp.test.local/mcp",
                "jwks_uri": format!("http://localhost:{}/jwks.json", jwks.port()),
                "allow_http_oauth_urls": true,
                "ssrf_allowlist": {"hosts": ["localhost"], "cidrs": ["127.0.0.0/8"]},
                "scopes": [{"scope": "mcp:admin", "role": "ops"}, {"scope": "mcp:read", "role": "viewer"}],
                "insufficient_scope_challenge": enabled
            }))?;
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.oauth = Some(oauth);
            let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()]),
                RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
            ])));
            let port = free_port().await?;
            let base = spawn_server(
                config_on_port(port)
                    .with_auth(auth)
                    .with_rbac(policy)
                    .with_public_url(format!("http://127.0.0.1:{port}")),
            )
            .await?;

            // When the caller requests a tool forbidden to its current role.
            let response = reqwest::Client::new().post(format!("{base}/mcp"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1_u32, "method": "tools/call", "params": {"name": "admin_only", "arguments": {}}}))
                .send().await?;

            // Then only the opt-in header differs; access remains denied.
            assert_eq!(response.status(), 403);
            let expected = enabled.then(|| format!(r#"Bearer error="insufficient_scope", scope="mcp:admin", resource_metadata="http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp", error_description="additional scope required""#));
            assert_eq!(
                response
                    .headers()
                    .get_all("www-authenticate")
                    .iter()
                    .map(|value| value.to_str())
                    .collect::<Result<Vec<_>, _>>()?,
                expected.as_deref().into_iter().collect::<Vec<_>>()
            );
            assert_eq!(
                response.text().await?,
                "admin_only denied for role 'viewer'"
            );
        }
        Ok(())
    }

    /// OAuth settings for the step-up mapping-order scenarios.
    #[cfg(feature = "oauth")]
    fn step_up_auth(
        jwks_port: u16,
        scopes: &serde_json::Value,
        enabled: bool,
    ) -> anyhow::Result<AuthConfig> {
        let oauth: OAuthConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://auth.test.local",
            "audience": "https://mcp.test.local/mcp",
            "jwks_uri": format!("http://localhost:{jwks_port}/jwks.json"),
            "allow_http_oauth_urls": true,
            "ssrf_allowlist": {"hosts": ["localhost"], "cidrs": ["127.0.0.0/8"]},
            "scopes": scopes,
            "insufficient_scope_challenge": enabled
        }))?;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth);
        Ok(auth)
    }

    /// Roles whose names prefix each other, plus a strictly widening chain.
    #[cfg(feature = "oauth")]
    fn step_up_e2e_policy() -> Arc<RbacPolicy> {
        let star = || vec!["*".to_owned()];
        Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["echo".into()], star()),
            RoleConfig::new(
                "viewer-plus",
                vec!["echo".into(), "admin_only".into()],
                star(),
            ),
            RoleConfig::new("ops-ro", vec!["echo".into()], star()),
            RoleConfig::new("ops", vec!["echo".into(), "admin_only".into()], star()),
            RoleConfig::new(
                "root",
                vec!["echo".into(), "admin_only".into(), "root_only".into()],
                star(),
            ),
        ])))
    }

    /// Knob-on versus knob-off comparison of one mapping-order scenario.
    #[cfg(feature = "oauth")]
    struct StepUpOrderCase {
        /// `oauth.scopes` exactly as configured, in order.
        scopes: serde_json::Value,
        /// Tool the `mcp:read` token's role is denied.
        tool: &'static str,
        /// Role the real JWT resolution assigns to the `mcp:read` token.
        role: &'static str,
        /// Whether the server advertises an absolute `public_url`.
        public_url: bool,
        /// Scope the knob-on challenge must name, or `None` for a bare 403.
        hint: Option<&'static str>,
    }

    /// Mapping lists whose config order differs from sorted order, with a
    /// duplicate scope, more than two entries, and prefix-related role names.
    #[cfg(feature = "oauth")]
    fn step_up_order_cases() -> Vec<StepUpOrderCase> {
        let map = |scope: &str, role: &str| serde_json::json!({"scope": scope, "role": role});
        let case = |scopes: Vec<serde_json::Value>, tool, role, public_url, hint| StepUpOrderCase {
            scopes: serde_json::Value::Array(scopes),
            tool,
            role,
            public_url,
            hint,
        };
        vec![
            // Read first: adding mcp:admin still resolves to viewer, so no hint.
            case(
                vec![map("mcp:read", "viewer"), map("mcp:admin", "ops")],
                "admin_only",
                "viewer",
                true,
                None,
            ),
            // Duplicate scope: the first mcp:admin mapping (ops) wins, never root.
            case(
                vec![
                    map("mcp:admin", "ops"),
                    map("mcp:admin", "root"),
                    map("mcp:read", "viewer"),
                ],
                "root_only",
                "viewer",
                false,
                None,
            ),
            // Config order, not alphabetical order, picks the hint.
            case(
                vec![
                    map("mcp:zeta", "ops"),
                    map("mcp:alpha", "root"),
                    map("mcp:read", "viewer"),
                ],
                "admin_only",
                "viewer",
                true,
                Some("mcp:zeta"),
            ),
            // Only the third of four mappings unlocks the call.
            case(
                vec![
                    map("mcp:x", "ops-ro"),
                    map("mcp:y", "ops-ro"),
                    map("mcp:admin", "ops"),
                    map("mcp:read", "viewer"),
                ],
                "admin_only",
                "viewer",
                false,
                Some("mcp:admin"),
            ),
            // The current role is a longer name than the unlocking role.
            case(
                vec![map("mcp:admin", "ops"), map("mcp:read", "ops-ro")],
                "admin_only",
                "ops-ro",
                true,
                Some("mcp:admin"),
            ),
            // The unlocking role is a longer name than the current role.
            case(
                vec![map("mcp:plus", "viewer-plus"), map("mcp:read", "viewer")],
                "admin_only",
                "viewer",
                false,
                Some("mcp:plus"),
            ),
        ]
    }

    /// Status, step-up challenge, every other header except `date`, and body.
    #[cfg(feature = "oauth")]
    type StepUpOutcome = (
        reqwest::StatusCode,
        Option<String>,
        Vec<(String, String)>,
        String,
    );

    /// Calls `tool` on a fresh `config` server with `token`, after checking
    /// that its unauthenticated 401 never carries a scope hint.
    #[cfg(feature = "oauth")]
    async fn step_up_outcome(
        config: McpServerConfig,
        token: &str,
        tool: &str,
    ) -> anyhow::Result<StepUpOutcome> {
        let base = spawn_server(config).await?;
        let client = reqwest::Client::new();
        let call = serde_json::json!({"jsonrpc": "2.0", "id": 1_u32, "method": "tools/call", "params": {"name": tool, "arguments": {}}});
        let unauthenticated = client
            .post(format!("{base}/mcp"))
            .json(&call)
            .send()
            .await?;
        assert_eq!(unauthenticated.status(), 401);
        for value in unauthenticated.headers().get_all("www-authenticate") {
            assert!(!value.to_str()?.contains("insufficient_scope"), "{value:?}");
        }
        let response = client
            .post(format!("{base}/mcp"))
            .bearer_auth(token)
            .json(&call)
            .send()
            .await?;
        let status = response.status();
        let challenge = response
            .headers()
            .get("www-authenticate")
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?;
        assert_eq!(
            response
                .headers()
                .get_all("www-authenticate")
                .iter()
                .count(),
            usize::from(challenge.is_some()),
            "a hinted 403 carries exactly one challenge field"
        );
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| *name != "date" && *name != "www-authenticate")
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        Ok((status, challenge, headers, response.text().await?))
    }

    /// `serve()` resolves hints from the configured mapping list as written:
    /// order, duplicate scopes and prefix-related role names are preserved.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn insufficient_scope_challenge_follows_configured_mapping_order() -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        // Given an `mcp:read` token, real JWKS validation and every order case.
        let kid = "step-up-order-kid";
        let (pem, jwks_body) = generate_oauth_test_keypair(kid)?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
        })
        .await;
        let token = mint_oauth_test_token(&pem, kid)?;
        for case in step_up_order_cases() {
            let port = free_port().await?;
            let origin = format!("http://127.0.0.1:{port}");
            // The trailing slash must not leak into the advertised metadata URL.
            let public_url = case.public_url.then(|| format!("{origin}/"));
            let mut outcomes = Vec::new();
            for enabled in [true, false] {
                let mut config = config_on_port(0)
                    .with_auth(step_up_auth(jwks.port(), &case.scopes, enabled)?)
                    .with_rbac(step_up_e2e_policy());
                if let Some(url) = &public_url {
                    config = config.with_public_url(url.clone());
                }
                // When the token's current role is denied the tool.
                outcomes.push(step_up_outcome(config, &token, case.tool).await?);
            }
            // Then the knob only adds the configured-order hint to the same 403.
            let metadata = if case.public_url {
                format!("{origin}/.well-known/oauth-protected-resource/mcp")
            } else {
                "/.well-known/oauth-protected-resource".to_owned()
            };
            let expected = case.hint.map(|scope| format!(r#"Bearer error="insufficient_scope", scope="{scope}", resource_metadata="{metadata}", error_description="additional scope required""#));
            let [
                (on_status, on_challenge, on_headers, on_body),
                (off_status, off_challenge, off_headers, off_body),
            ] = outcomes.as_slice()
            else {
                anyhow::bail!("expected two outcomes, got {}", outcomes.len());
            };
            let label = format!("{} {}", case.scopes, case.tool);
            assert_eq!(*on_status, 403, "{label}");
            assert_eq!(*off_status, 403, "{label}");
            assert_eq!(*on_challenge, expected, "{label}");
            assert_eq!(*off_challenge, None, "{label}");
            assert_eq!(on_headers, off_headers, "{label}");
            assert_eq!(
                *on_body,
                format!("{} denied for role '{}'", case.tool, case.role),
                "{label}"
            );
            assert_eq!(off_body, on_body, "{label}");
        }
        Ok(())
    }

    /// Role table that both the matrix server policy and its oracle read:
    /// role name, allowed tools, and host globs.
    #[cfg(feature = "oauth")]
    const STEP_UP_MATRIX_ROLES: [(&str, &[&str], &[&str]); 7] = [
        ("viewer", &["echo"], &["*"]),
        ("viewer-plus", &["echo", "admin_only"], &["*"]),
        ("ops-ro", &["echo"], &["*"]),
        ("ops", &["echo", "admin_only"], &["*"]),
        ("root", &["echo", "admin_only", "root_only"], &["*"]),
        ("prod-admin", &["admin_only"], &["prod-*"]),
        ("solo-admin", &["admin_only"], &["*"]),
    ];

    /// One matrix tool call: the tool name and an optional string `host`.
    #[cfg(feature = "oauth")]
    type StepUpMatrixCall = (&'static str, Option<&'static str>);

    /// One real-server matrix configuration: tool calls sent as a batch in
    /// both orientations, with the hint pinned for each orientation.
    #[cfg(feature = "oauth")]
    struct StepUpMatrixCase {
        /// `oauth.scopes` in configuration order.
        mappings: Vec<(&'static str, &'static str)>,
        /// The token's `scope` claim.
        token_scope: &'static str,
        /// Calls of the batch in order; the other orientation is reversed.
        calls: Vec<StepUpMatrixCall>,
        /// Expected knob-on hint for the batch and for its reverse.
        pins: [Option<&'static str>; 2],
    }

    /// Orders, duplicates, prefix roles, empty-role mappings held by the token,
    /// and batches that only a later candidate (or no candidate) fully unlocks.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_cases() -> Vec<StepUpMatrixCase> {
        let case = |mappings, token_scope, calls: [&'static str; 2], pins| StepUpMatrixCase {
            mappings,
            token_scope,
            calls: calls.map(|tool| (tool, None)).to_vec(),
            pins,
        };
        let (admin, read, root) = (
            ("mcp:admin", "ops"),
            ("mcp:read", "viewer"),
            ("mcp:root", "root"),
        );
        let blank = ("mcp:blank", "");
        let (ops_ro_x, ops_ro_y) = (("mcp:x", "ops-ro"), ("mcp:y", "ops-ro"));
        let echo_admin = ["echo", "admin_only"];
        let admin_root = ["admin_only", "root_only"];
        let both = |scope| [Some(scope), Some(scope)];
        let none = [None, None];
        let mut cases = vec![
            case(vec![admin, read], "mcp:read", echo_admin, both("mcp:admin")),
            case(vec![read, admin], "mcp:read", echo_admin, none),
            case(
                vec![blank, admin, read],
                "mcp:blank mcp:read",
                echo_admin,
                none,
            ),
            case(
                vec![blank, admin, read],
                "mcp:read",
                echo_admin,
                both("mcp:admin"),
            ),
            case(
                vec![admin, blank, read],
                "mcp:blank mcp:read",
                echo_admin,
                both("mcp:admin"),
            ),
            case(
                vec![admin, root, read],
                "mcp:read",
                admin_root,
                both("mcp:root"),
            ),
            case(vec![admin, read], "mcp:read", ["admin_only", "nope"], none),
            case(
                vec![("mcp:zeta", "ops"), ("mcp:alpha", "root"), read],
                "mcp:read",
                echo_admin,
                both("mcp:zeta"),
            ),
            case(
                vec![admin, ("mcp:admin", "root"), read],
                "mcp:read",
                admin_root,
                none,
            ),
            case(
                vec![admin, ("mcp:read", "ops-ro")],
                "mcp:read",
                echo_admin,
                both("mcp:admin"),
            ),
            case(
                vec![("mcp:plus", "viewer-plus"), read],
                "mcp:read",
                ["admin_only", "echo"],
                both("mcp:plus"),
            ),
            case(
                vec![ops_ro_x, ops_ro_y, admin, read],
                "mcp:read",
                echo_admin,
                both("mcp:admin"),
            ),
            case(
                vec![root, admin, read],
                "mcp:read mcp:admin",
                admin_root,
                both("mcp:root"),
            ),
            case(vec![admin, read], "mcp:admin", ["echo", "root_only"], none),
            case(
                vec![ops_ro_x, root, read],
                "mcp:read",
                ["echo", "root_only"],
                both("mcp:root"),
            ),
            case(
                vec![("MCP:ADMIN", "root"), admin, read],
                "mcp:read",
                admin_root,
                both("MCP:ADMIN"),
            ),
        ];
        cases.extend(step_up_matrix_host_and_long_cases());
        cases
    }

    /// Three unlocking candidates, non-nested candidate roles, host-restricted
    /// roles with string hosts in both cases and absent hosts, and batches of
    /// four to eight calls.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_host_and_long_cases() -> Vec<StepUpMatrixCase> {
        let case = |mappings, token_scope, calls, pins| StepUpMatrixCase {
            mappings,
            token_scope,
            calls,
            pins,
        };
        let (admin, read, root) = (
            ("mcp:admin", "ops"),
            ("mcp:read", "viewer"),
            ("mcp:root", "root"),
        );
        let (prod, solo) = (("mcp:prod", "prod-admin"), ("mcp:solo", "solo-admin"));
        let on = |host| ("admin_only", Some(host));
        let (echo, admin_call) = (("echo", None), ("admin_only", None));
        let both = |scope| [Some(scope), Some(scope)];
        let none = [None, None];
        let prod_hosts: Vec<StepUpMatrixCall> = ["prod-1", "prod-2", "PROD-3", "prod-4"]
            .into_iter()
            .chain(["prod-5", "prod-6", "prod-7"])
            .map(on)
            .collect();
        let mut prod_then_dev = prod_hosts.clone();
        prod_then_dev.push(on("dev-1"));
        vec![
            case(
                vec![("mcp:a", "ops"), ("mcp:b", "root"), ("mcp:c", "root"), read],
                "mcp:read",
                vec![echo, admin_call],
                both("mcp:a"),
            ),
            case(vec![solo, read], "mcp:read", vec![echo, admin_call], none),
            case(
                vec![solo, admin, read],
                "mcp:read",
                vec![echo, admin_call],
                both("mcp:admin"),
            ),
            case(
                vec![prod, read],
                "mcp:read",
                vec![on("dev-1"), on("prod-1")],
                none,
            ),
            case(
                vec![prod, read],
                "mcp:read",
                vec![on("prod-1"), on("PROD-2")],
                both("mcp:prod"),
            ),
            case(
                vec![prod, read],
                "mcp:read",
                vec![on("prod-1"), admin_call],
                both("mcp:prod"),
            ),
            case(
                vec![prod, root, read],
                "mcp:read",
                vec![on("dev-1"), on("prod-1")],
                both("mcp:root"),
            ),
            case(
                vec![admin, prod],
                "mcp:prod",
                vec![on("dev-1"), on("prod-1")],
                both("mcp:admin"),
            ),
            case(
                vec![prod, admin],
                "mcp:prod",
                vec![on("dev-1"), on("prod-1")],
                none,
            ),
            case(
                vec![admin, read],
                "mcp:read",
                vec![admin_call, admin_call, admin_call, ("nope", None)],
                none,
            ),
            case(
                vec![admin, read],
                "mcp:read",
                vec![echo, admin_call, echo, admin_call, on("dev-9")],
                both("mcp:admin"),
            ),
            case(vec![prod, read], "mcp:read", prod_then_dev, none),
            case(vec![prod, read], "mcp:read", prod_hosts, both("mcp:prod")),
        ]
    }

    /// Independent host glob rule: `*` matches any host, `prefix*` matches by
    /// prefix, anything else matches exactly, all ASCII-case-insensitively.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_host_matches(glob: &str, host: &str) -> bool {
        let (pattern, name) = (glob.to_ascii_lowercase(), host.to_ascii_lowercase());
        pattern
            .strip_suffix('*')
            .map_or(pattern == name, |prefix| name.starts_with(prefix))
    }

    /// Whether `role` may make `call` per [`STEP_UP_MATRIX_ROLES`]: the tool
    /// is allowed and a string host, when present, matches a host glob.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_allows(role: &str, (tool, host): StepUpMatrixCall) -> bool {
        STEP_UP_MATRIX_ROLES.iter().any(|(name, tools, globs)| {
            *name == role
                && tools.contains(&tool)
                && host.is_none_or(|requested| {
                    globs
                        .iter()
                        .any(|glob| step_up_matrix_host_matches(glob, requested))
                })
        })
    }

    /// Real `resolve_role` semantics: the first mapping in configuration
    /// order whose scope is granted wins, whatever the token order.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_resolve(
        mappings: &[(&'static str, &'static str)],
        granted: &[&str],
    ) -> Option<&'static str> {
        mappings
            .iter()
            .find(|(scope, _)| granted.contains(scope))
            .map(|(_, role)| *role)
    }

    /// Independent oracle: the resolved role, the first denied tool, and the
    /// first configured scope whose addition changes the role to one that
    /// passes every call of the batch.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_oracle(
        case: &StepUpMatrixCase,
        batch: &[StepUpMatrixCall],
    ) -> anyhow::Result<(&'static str, Option<&'static str>, Option<&'static str>)> {
        let granted: Vec<&str> = case.token_scope.split_whitespace().collect();
        let current = step_up_matrix_resolve(&case.mappings, &granted)
            .context("the token scope must resolve to a role")?;
        let denied = batch
            .iter()
            .copied()
            .find(|call| !step_up_matrix_allows(current, *call))
            .map(|(tool, _host)| tool);
        let hint = denied.and_then(|_| {
            case.mappings.iter().map(|(scope, _)| *scope).find(|scope| {
                let mut union = granted.clone();
                union.push(*scope);
                step_up_matrix_resolve(&case.mappings, &union).is_some_and(|role| {
                    role != current && batch.iter().all(|call| step_up_matrix_allows(role, *call))
                })
            })
        });
        Ok((current, denied, hint))
    }

    /// A signed `mcp` token carrying `scope`.
    #[cfg(feature = "oauth")]
    fn mint_scoped_oauth_test_token(pem: &str, kid: &str, scope: &str) -> anyhow::Result<String> {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())
            .context("encoding key from PEM")?;
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://mcp.test.local/mcp",
            "sub": "step-up-matrix",
            "scope": scope,
            "exp": now.saturating_add(3600),
            "iat": now
        });
        jsonwebtoken::encode(&header, &claims, &key).context("JWT encoding")
    }

    /// Status, every challenge field, every other header except `date`, and body.
    #[cfg(feature = "oauth")]
    type StepUpBatchOutcome = (
        reqwest::StatusCode,
        Vec<String>,
        Vec<(String, String)>,
        String,
    );

    /// Sends `batch` as a JSON-RPC batch of `tools/call` requests.
    #[cfg(feature = "oauth")]
    async fn step_up_batch_outcome(
        base: &str,
        token: &str,
        batch: &[StepUpMatrixCall],
    ) -> anyhow::Result<StepUpBatchOutcome> {
        let body: Vec<serde_json::Value> = batch
            .iter()
            .zip(1_u32..)
            .map(|((tool, host), id)| {
                let arguments = host.map_or_else(
                    || serde_json::json!({}),
                    |name| serde_json::json!({"host": name}),
                );
                serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
            })
            .collect();
        let response = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        let challenges = response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .map(|value| value.to_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| *name != "date" && *name != "www-authenticate")
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        Ok((status, challenges, headers, response.text().await?))
    }

    /// Runs `cases` against real servers: every configuration, both batch
    /// orientations and both knob states must agree with the independent
    /// oracle, and the knob only ever adds one challenge field to an
    /// otherwise identical 403. One server per configuration and knob state.
    #[cfg(feature = "oauth")]
    async fn step_up_matrix_check(cases: &[StepUpMatrixCase]) -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        // Given real JWKS validation and a policy built from the oracle's
        // role table.
        let kid = "step-up-matrix-kid";
        let (pem, jwks_body) = generate_oauth_test_keypair(kid)?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
        })
        .await;
        let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(
            STEP_UP_MATRIX_ROLES
                .iter()
                .map(|(role, tools, hosts)| {
                    RoleConfig::new(
                        *role,
                        tools.iter().map(|tool| (*tool).to_owned()).collect(),
                        hosts.iter().map(|host| (*host).to_owned()).collect(),
                    )
                })
                .collect(),
        )));
        for case in cases {
            let token = mint_scoped_oauth_test_token(&pem, kid, case.token_scope)?;
            let scopes: Vec<serde_json::Value> = case
                .mappings
                .iter()
                .map(|(scope, role)| serde_json::json!({"scope": scope, "role": role}))
                .collect();
            let reversed: Vec<StepUpMatrixCall> = case.calls.iter().rev().copied().collect();
            let batches = [case.calls.clone(), reversed];
            let mut outcomes = Vec::new();
            for enabled in [true, false] {
                let base = spawn_server(
                    config_on_port(0)
                        .with_auth(step_up_auth(
                            jwks.port(),
                            &serde_json::Value::Array(scopes.clone()),
                            enabled,
                        )?)
                        .with_rbac(Arc::clone(&policy)),
                )
                .await?;
                // When both batch orientations reach the same server.
                for batch in &batches {
                    outcomes.push(step_up_batch_outcome(&base.to_string(), &token, batch).await?);
                }
            }
            let [on_ab, on_ba, off_ab, off_ba] = outcomes.as_slice() else {
                anyhow::bail!("expected four outcomes, got {}", outcomes.len());
            };
            // Then each outcome matches the oracle and the pinned hint, and
            // knob on and off differ only by that single challenge field.
            for ((batch, pin), (on, off)) in batches
                .iter()
                .zip(case.pins)
                .zip([(on_ab, off_ab), (on_ba, off_ba)])
            {
                let label = format!("{:?} {:?} {batch:?}", case.mappings, case.token_scope);
                let (current, first_denied, hint) = step_up_matrix_oracle(case, batch)?;
                assert_eq!(hint, pin, "oracle disagrees with the pin: {label}");
                let denied = first_denied.context("every matrix batch is denied")?;
                let expected = hint.map(|scope| format!(r#"Bearer error="insufficient_scope", scope="{scope}", resource_metadata="/.well-known/oauth-protected-resource", error_description="additional scope required""#));
                let (on_status, on_challenges, on_headers, on_body) = on;
                let (off_status, off_challenges, off_headers, off_body) = off;
                assert_eq!(*on_status, 403, "{label}");
                assert_eq!(
                    *on_body,
                    format!("{denied} denied for role '{current}'"),
                    "{label}"
                );
                assert_eq!(
                    *on_challenges,
                    expected.into_iter().collect::<Vec<_>>(),
                    "{label}"
                );
                assert!(off_challenges.is_empty(), "{label}: {off_challenges:?}");
                assert_eq!(off_status, on_status, "{label}");
                assert_eq!(off_headers, on_headers, "{label}");
                assert_eq!(off_body, on_body, "{label}");
            }
        }
        Ok(())
    }

    /// Real-server matrix: every configuration, both batch orientations and
    /// both knob states agree with an independent oracle built from the real
    /// role resolution rule and the policy table, and the knob only ever adds
    /// one challenge field to an otherwise identical 403.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn insufficient_scope_challenge_matrix_matches_independent_oracle() -> anyhow::Result<()>
    {
        // Given every `mcp:<word>`-shaped matrix configuration.
        let cases = step_up_matrix_cases();
        // When and Then: each configuration agrees with the oracle.
        step_up_matrix_check(&cases).await?;
        assert!(cases.len() >= 29, "{} configurations", cases.len());
        assert!(
            cases.iter().any(|case| case.calls.len() >= 8),
            "an eight-call batch is covered"
        );
        Ok(())
    }

    /// A 200-byte scope token (namespace prefix plus 49 `long` words).
    #[cfg(feature = "oauth")]
    const STEP_UP_LONG_SCOPE: &str = concat!(
        "mcp:",
        "longlonglonglonglonglonglonglonglonglonglonglong",
        "longlonglonglonglonglonglonglonglonglonglonglong",
        "longlonglonglonglonglonglonglonglonglonglonglong",
        "longlonglonglonglonglonglonglonglonglonglonglong",
        "long",
    );

    /// Scope spellings real authorization servers use, all valid RFC 6750
    /// scope tokens: un-namespaced, empty or leading namespace, nested
    /// namespaces, dots, slashes, URLs, dashes and underscores, upper and
    /// mixed case, digits, a 200-byte token, `~ % +` and the remaining
    /// punctuation, and a scope spelled like a role name.
    #[cfg(feature = "oauth")]
    const STEP_UP_SCOPE_ALPHABET: [&str; 20] = [
        "read",
        "admin",
        "mcp:",
        ":read",
        "a:b:c",
        "mcp.read",
        "api/read",
        "https://example.test/scope/read",
        "mcp:read-only",
        "mcp_admin",
        "READ",
        "Mcp:Admin",
        "mcp:v2",
        "scope42",
        STEP_UP_LONG_SCOPE,
        "mcp:~a%2B+b",
        "!#$&'()*,;<=>?@[]^`{|}",
        "ops",
        "viewer",
        "urn:example:mcp:tools.admin",
    ];

    /// For every alphabet scope `s` next to `mcp:read`: `s` first and
    /// unlocking is the hint; `s` first and held keeps the role, so no hint
    /// (the step-up loop shape). Then hand-pinned mixes of alphabet scopes,
    /// case variants of one word, role-name scopes and tokens separated by
    /// Unicode whitespace.
    #[cfg(feature = "oauth")]
    fn step_up_matrix_alphabet_cases() -> Vec<StepUpMatrixCase> {
        let case = |mappings, token_scope, calls: [&'static str; 2], pins| StepUpMatrixCase {
            mappings,
            token_scope,
            calls: calls.map(|tool| (tool, None)).to_vec(),
            pins,
        };
        let echo_admin = ["echo", "admin_only"];
        let admin_root = ["admin_only", "root_only"];
        let both = |scope| [Some(scope), Some(scope)];
        let none = [None, None];
        let url = "https://example.test/scope/read";
        let mut cases: Vec<StepUpMatrixCase> = STEP_UP_SCOPE_ALPHABET
            .into_iter()
            .flat_map(|scope| {
                [
                    case(
                        vec![(scope, "ops"), ("mcp:read", "viewer")],
                        "mcp:read",
                        echo_admin,
                        both(scope),
                    ),
                    case(
                        vec![(scope, "viewer"), ("mcp:read", "ops")],
                        scope,
                        echo_admin,
                        none,
                    ),
                ]
            })
            .collect();
        cases.extend([
            case(
                vec![(url, "root"), ("api/read", "viewer"), ("mcp:", "ops")],
                "read\u{3000}mcp:\u{a0}api/read",
                echo_admin,
                both(url),
            ),
            case(
                vec![("api/read", "viewer"), ("mcp:", "ops"), (url, "root")],
                "read\u{3000}mcp:\u{a0}api/read",
                echo_admin,
                none,
            ),
            case(
                vec![("READ", "root"), ("read", "viewer")],
                "read",
                admin_root,
                both("READ"),
            ),
            case(
                vec![("read", "viewer"), ("READ", "ops")],
                "READ\u{2003}Read",
                admin_root,
                none,
            ),
            case(
                vec![("viewer", "ops"), ("ops", "viewer")],
                "ops",
                echo_admin,
                both("viewer"),
            ),
            case(
                vec![("ops", "viewer"), ("viewer", "ops")],
                "ops\tmcp:read",
                echo_admin,
                none,
            ),
            case(
                vec![
                    ("a:b:c", "ops"),
                    (STEP_UP_LONG_SCOPE, "root"),
                    (":read", "viewer"),
                ],
                "\u{2003}:read\n",
                admin_root,
                both(STEP_UP_LONG_SCOPE),
            ),
            case(
                vec![
                    ("mcp.read", "ops"),
                    ("mcp:~a%2B+b", "root"),
                    ("mcp:", "viewer"),
                ],
                "mcp:\u{3000}other",
                admin_root,
                both("mcp:~a%2B+b"),
            ),
            case(
                vec![("mcp:", "viewer"), ("mcp:~a%2B+b", "root")],
                "mcp:\u{85}mcp:~a%2B+b",
                admin_root,
                none,
            ),
        ]);
        cases
    }

    /// The real-server matrix over the scope alphabet: for every alphabet
    /// scope the knob-on hint is the oracle's first unlocking scope in
    /// configuration order, and knob off is a bare 403. Fixtures built only
    /// from `mcp:<word>` scopes cannot catch a simulation that loses or
    /// rewrites mappings or granted scopes of another shape.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn insufficient_scope_challenge_scope_alphabet_matches_independent_oracle()
    -> anyhow::Result<()> {
        // Given every alphabet configuration.
        let cases = step_up_matrix_alphabet_cases();
        // When and Then: each configuration agrees with the oracle.
        step_up_matrix_check(&cases).await?;
        assert_eq!(STEP_UP_LONG_SCOPE.len(), 200, "the long scope is 200 bytes");
        assert!(
            cases.len() >= 2 * STEP_UP_SCOPE_ALPHABET.len() + 9,
            "{} configurations",
            cases.len()
        );
        Ok(())
    }

    /// The quoted `resource_metadata` parameter of every `WWW-Authenticate` field.
    #[cfg(feature = "oauth")]
    fn resource_metadata_params(response: &reqwest::Response) -> anyhow::Result<Vec<String>> {
        response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .map(|value| {
                let (_, rest) = value
                    .to_str()?
                    .split_once("resource_metadata=\"")
                    .context("challenge carries resource_metadata")?;
                let (url, _) = rest.split_once('"').context("closing quote")?;
                Ok(url.to_owned())
            })
            .collect()
    }

    /// With a mixed-case `public_url` the step-up challenge advertises the
    /// 401 challenge's `resource_metadata` byte for byte, next to the
    /// case-preserving metadata `resource`, and with the knob on an allowed
    /// `tools/list` carries no `WWW-Authenticate` field at all.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn insufficient_scope_challenge_reuses_the_401_metadata_url_verbatim()
    -> anyhow::Result<()> {
        use wiremock::{Mock, ResponseTemplate, matchers};

        // Given real JWKS validation, the knob on, and a public_url whose
        // host and path carry upper-case letters.
        let kid = "step-up-case-kid";
        let (pem, jwks_body) = generate_oauth_test_keypair(kid)?;
        let jwks = DualStackMock::start().await?;
        jwks.mount(|| {
            Mock::given(matchers::method("GET"))
                .and(matchers::path("/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
        })
        .await;
        let public_url = "http://MCP.Example.test:8443/Tenant";
        let scopes = serde_json::json!([
            {"scope": "mcp:admin", "role": "ops"},
            {"scope": "mcp:read", "role": "viewer"}
        ]);
        let base = spawn_server(
            config_on_port(0)
                .with_auth(step_up_auth(jwks.port(), &scopes, true)?)
                .with_rbac(step_up_e2e_policy())
                .with_public_url(public_url),
        )
        .await?;
        let token = mint_scoped_oauth_test_token(&pem, kid, "mcp:read")?;
        let client = reqwest::Client::new();
        let call = serde_json::json!({"jsonrpc": "2.0", "id": 1_u32, "method": "tools/call", "params": {"name": "admin_only", "arguments": {}}});

        // When the same denied call arrives without and with the token, and
        // the token then lists tools in an initialized session.
        let unauthenticated = client
            .post(format!("{base}/mcp"))
            .json(&call)
            .send()
            .await?;
        let denied = client
            .post(format!("{base}/mcp"))
            .bearer_auth(&token)
            .json(&call)
            .send()
            .await?;
        let session_id = mcp_initialize_with_bearer(&client, &base.base, Some(&token)).await?;
        let listed = client
            .post(format!("{base}/mcp"))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .send()
            .await?;
        let prm: serde_json::Value = client
            .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
            .send()
            .await?
            .json()
            .await?;

        // Then both challenges name the same case-preserving metadata URL.
        let metadata = format!("{public_url}/.well-known/oauth-protected-resource/mcp");
        assert_eq!(unauthenticated.status(), 401);
        assert_eq!(
            resource_metadata_params(&unauthenticated)?,
            [metadata.as_str()]
        );
        assert_eq!(denied.status(), 403);
        assert_eq!(resource_metadata_params(&denied)?, [metadata.as_str()]);
        assert_eq!(
            prm.get("resource").and_then(serde_json::Value::as_str),
            Some(format!("{public_url}/mcp").as_str())
        );
        // And the allowed listing is never decorated.
        assert_eq!(listed.status(), 200);
        assert_eq!(
            listed.headers().get_all("www-authenticate").iter().count(),
            0
        );
        Ok(())
    }

    /// `iss` of every audience-widening token and the configured issuer.
    #[cfg(feature = "oauth")]
    const AUDIENCE_ISSUER: &str = "https://idp.audience.test/realms/audience";

    /// Mock IdP serving a fresh signing key for the audience-widening tests.
    #[cfg(feature = "oauth")]
    struct AudienceIdp {
        /// The dual-stack JWKS mock; kept alive for the test's duration.
        jwks: DualStackMock,
        /// PKCS#8 PEM of the signing key.
        pem: String,
    }

    #[cfg(feature = "oauth")]
    impl AudienceIdp {
        /// `kid` of the signing key.
        const KID: &'static str = "audience-kid";

        /// Starts the JWKS mock.
        async fn start() -> anyhow::Result<Self> {
            use wiremock::{Mock, ResponseTemplate, matchers};

            let (pem, jwks_body) = generate_oauth_test_keypair(Self::KID)?;
            let jwks = DualStackMock::start().await?;
            jwks.mount(|| {
                Mock::given(matchers::method("GET"))
                    .and(matchers::path("/jwks.json"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_body))
            })
            .await;
            Ok(Self { jwks, pem })
        }

        /// Direct-mode OAuth config with audience `mcp-audience` plus `extra`
        /// top-level keys.
        fn oauth(&self, extra: &serde_json::Value) -> anyhow::Result<OAuthConfig> {
            let mut json = serde_json::json!({
                "issuer": AUDIENCE_ISSUER,
                "audience": "mcp-audience",
                "jwks_uri": format!("http://localhost:{}/jwks.json", self.jwks.port()),
                "allow_http_oauth_urls": true,
                "ssrf_allowlist": {
                    "hosts": ["localhost"],
                    "cidrs": ["127.0.0.0/8"]
                },
                "scopes": [{"scope": "mcp:read", "role": "viewer"}]
            });
            let object = json
                .as_object_mut()
                .context("oauth document is an object")?;
            for (key, value) in extra
                .as_object()
                .context("extra oauth keys are an object")?
            {
                drop(object.insert(key.clone(), value.clone()));
            }
            serde_json::from_value(json).context("oauth config deserialization")
        }

        /// A valid `mcp:read` token whose claims carry `aud` and, when given,
        /// `azp`.
        fn token(&self, aud: &serde_json::Value, azp: Option<&str>) -> anyhow::Result<String> {
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(self.pem.as_bytes())
                .context("encoding key from PEM")?;
            let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
            header.kid = Some(Self::KID.into());
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims = serde_json::json!({
                "iss": AUDIENCE_ISSUER,
                "aud": aud,
                "sub": "audience-user",
                "scope": "mcp:read",
                "exp": now.saturating_add(3600),
                "iat": now
            });
            if let Some(authorized_party) = azp {
                drop(
                    claims
                        .as_object_mut()
                        .context("claims are an object")?
                        .insert("azp".to_owned(), serde_json::Value::from(authorized_party)),
                );
            }
            jsonwebtoken::encode(&header, &claims, &encoding_key).context("JWT encoding")
        }
    }

    /// Spawns an OAuth-only server whose `public_url` is its own origin and
    /// returns it with that origin.
    #[cfg(feature = "oauth")]
    async fn spawn_audience_server(oauth: OAuthConfig) -> anyhow::Result<(ServerHarness, String)> {
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(oauth);
        let port = free_port().await?;
        let public_url = format!("http://127.0.0.1:{port}");
        let server = spawn_server(
            config_on_port(port)
                .with_auth(auth)
                .with_public_url(public_url.clone()),
        )
        .await?;
        Ok((server, public_url))
    }

    /// Initializes a session with `token`, then returns the `tools/list`
    /// status and the number of listed tools.
    #[cfg(feature = "oauth")]
    async fn tools_list_with_token(base: &str, token: &str) -> anyhow::Result<(u16, usize)> {
        let client = reqwest::Client::new();
        let session_id = mcp_initialize_with_bearer(&client, base, Some(token)).await?;
        let resp = client
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .send()
            .await
            .context("tools/list request")?;
        let status = resp.status().as_u16();
        let body = mcp_response_json(resp).await?;
        let tools = body
            .get("result")
            .and_then(|result| result.get("tools"))
            .and_then(serde_json::Value::as_array)
            .context("tools/list result carries a tools array")?;
        Ok((status, tools.len()))
    }

    /// With `accept_resource_audience = true` and `public_url` set, a token
    /// whose `aud` is `{public_url}/mcp` (alone or inside an array)
    /// authenticates and lists tools; near misses of that URL, another
    /// resource, and an azp-only match on it stay rejected with 401 under the
    /// default strict mode.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn resource_audience_accepted_when_opted_in() -> anyhow::Result<()> {
        let idp = AudienceIdp::start().await?;
        let (server, public_url) = spawn_audience_server(
            idp.oauth(&serde_json::json!({ "accept_resource_audience": true }))?,
        )
        .await?;
        let resource = format!("{public_url}/mcp");

        for aud in [
            serde_json::json!(resource),
            serde_json::json!(["https://other.example/mcp", resource]),
        ] {
            let token = idp.token(&aud, None)?;
            assert_eq!(
                tools_list_with_token(&server.base, &token).await?,
                (200, 0),
                "aud={aud}"
            );
        }

        let port = public_url.rsplit(':').next().context("public_url port")?;
        let client = reqwest::Client::new();
        let mut rejected = 0_usize;
        for (aud, azp) in [
            (format!("{resource}/"), None),
            (public_url.clone(), None),
            (format!("http://localhost:{port}/mcp"), None),
            (format!("https://127.0.0.1:{port}/mcp"), None),
            (format!("http://user@127.0.0.1:{port}/mcp"), None),
            (format!("HTTP://127.0.0.1:{port}/MCP"), None),
            ("https://other.example/mcp".to_owned(), None),
            (
                "https://other.example/mcp".to_owned(),
                Some(resource.as_str()),
            ),
        ] {
            let token = idp.token(&serde_json::json!(aud), azp)?;
            assert_eq!(
                initialize_status(&client, &server.base, &token).await?,
                401,
                "aud={aud} azp={azp:?}"
            );
            rejected = rejected.saturating_add(1);
        }
        assert_eq!(rejected, 8);
        Ok(())
    }

    /// With `additional_audiences = ["https://alt.example/mcp"]`, a token for
    /// that audience authenticates and lists tools, the configured
    /// `audience` still does, and the server's own resource URL is not
    /// implicitly accepted (`accept_resource_audience` is off).
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn additional_audience_accepted_when_listed() -> anyhow::Result<()> {
        let idp = AudienceIdp::start().await?;
        let (server, public_url) = spawn_audience_server(
            idp.oauth(&serde_json::json!({ "additional_audiences": ["https://alt.example/mcp"] }))?,
        )
        .await?;

        for aud in ["https://alt.example/mcp", "mcp-audience"] {
            let token = idp.token(&serde_json::json!(aud), None)?;
            assert_eq!(
                tools_list_with_token(&server.base, &token).await?,
                (200, 0),
                "aud={aud}"
            );
        }

        let client = reqwest::Client::new();
        for aud in [
            format!("{public_url}/mcp"),
            "https://alt.example/mcp/".to_owned(),
        ] {
            let token = idp.token(&serde_json::json!(aud), None)?;
            assert_eq!(
                initialize_status(&client, &server.base, &token).await?,
                401,
                "aud={aud}"
            );
        }
        Ok(())
    }

    /// The PRM `resource` and the accepted resource audience are one value.
    ///
    /// With `public_url` on a host other than the bind host and the knob on,
    /// both PRM locations advertise `{public_url}/mcp`, and a token whose
    /// `aud` is exactly that advertised string authenticates, while a token
    /// for a resource derived from the bind address is rejected.
    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn prm_resource_equals_accepted_resource_audience() -> anyhow::Result<()> {
        let idp = AudienceIdp::start().await?;
        let mut auth = AuthConfig::with_keys(vec![]);
        auth.oauth = Some(idp.oauth(&serde_json::json!({ "accept_resource_audience": true }))?);
        let port = free_port().await?;
        let public_url = "https://mcp.example.test";
        let server = spawn_server(
            config_on_port(port)
                .with_auth(auth)
                .with_public_url(public_url),
        )
        .await?;
        let client = reqwest::Client::new();

        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ] {
            let prm: serde_json::Value = client
                .get(format!("{}{path}", server.base))
                .send()
                .await
                .context("PRM request")?
                .json()
                .await
                .context("PRM body")?;
            assert_eq!(
                prm.get("resource").and_then(serde_json::Value::as_str),
                Some("https://mcp.example.test/mcp"),
                "{path}"
            );
        }

        let token = idp.token(&serde_json::json!("https://mcp.example.test/mcp"), None)?;
        assert_eq!(tools_list_with_token(&server.base, &token).await?, (200, 0));
        let bind_token = idp.token(&serde_json::json!(format!("{}/mcp", server.base)), None)?;
        assert_eq!(
            initialize_status(&client, &server.base, &bind_token).await?,
            401
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
    ///    causes the server to exit before a 10s hang detector fires.
    /// 2. The server actually waits at least most of the graceful window
    ///    (~450ms) instead of insta-killing the in-flight request - this
    ///    catches an over-correction that would skip graceful drain
    ///    entirely.
    /// 3. The server exits within the grace window plus 4s: the 1.5s
    ///    bound removed in a2eaa08 flaked on CI jitter, while 4s of slack
    ///    still catches a multi-second wait added to the shutdown path.
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
        // extra route that sleeps 60s server-side. The handler must be
        // abandoned when the grace window expires; waiting for it would trip
        // the 10s hang detector below.
        //
        // The handler signals via a oneshot channel as soon as it begins
        // executing, so the test can wait for the request to be
        // *deterministically* in-flight before triggering shutdown
        // (eliminates the prior race where slow CI scheduling could let
        // shutdown fire before the server even saw the request).
        let port = free_port().await?;
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let started_state = Arc::new(Mutex::new(Some(started_tx)));
        let shutdown_timeout = Duration::from_millis(500);
        let cfg = config_on_port(port)
            .with_shutdown_timeout(shutdown_timeout)
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
                                sleep(Duration::from_secs(60)).await;
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
            // We don't care about the response - only that the request
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
            .context("/slow handler did not start within 30s - request never reached the server")?
            .context("started_tx dropped without sending")?;

        // Trigger graceful shutdown. With BUG-NEW fixed, this is
        // semantically identical to a single SIGTERM.
        let start = Instant::now();
        let res = timeout(Duration::from_secs(10), harness.shutdown()).await;
        let elapsed = start.elapsed();

        // Outer timeout MUST NOT fire. Ten seconds is at least 20x the 500ms
        // grace window, so it is a jitter-safe hang detector rather than a
        // timing expectation.
        let server_result =
            res.context("server failed to shut down within 10s - BUG-NEW regression")?;

        // The server should exit cleanly (an error here would indicate a
        // fault unrelated to this bug; surface it loudly).
        server_result.context("server returned an error during shutdown")?;

        // Best-effort: drain the background HTTP task. It may complete
        // with an error (connection reset by force-exit) or succeed if
        // the runtime aborted it - either is acceptable.
        in_flight.abort();
        drop(in_flight.await);

        // Lower bound: the server actually waited most of the graceful
        // window. 450ms = 500ms - 50ms scheduling and cleanup slack. A lower
        // bound cannot fail because a runner is slow; it only fails if the
        // server exits too early.
        let drain_floor = shutdown_timeout.saturating_sub(Duration::from_millis(50));
        assert!(
            elapsed >= drain_floor,
            "shutdown completed in {elapsed:?}, expected >= 450ms (server skipped graceful drain)"
        );

        // Upper bound: the server must not overrun the grace window by more
        // than 4s. 4s is >=8x the 500ms grace window, which is jitter-safe:
        // the 1.5s bound removed in a2eaa08 flaked on CI jitter, while 4s of
        // slack still catches a multi-second wait added to the shutdown path.
        let overrun_limit = shutdown_timeout.saturating_add(Duration::from_secs(4));
        assert!(
            elapsed < overrun_limit,
            "shutdown took {elapsed:?}, more than 4s past the {shutdown_timeout:?} grace window: the force-exit timer fired late or the shutdown path gained a blocking wait"
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
    /// even be called with an invalid config - the rejection happens at
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
        // not validate() - so this should pass validation.
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

        // - server-side-TLS-only PKI (no mTLS, no CRL) -

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
    /// graceful path cancels `ct` the moment the shutdown trigger fires - i.e. at
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
    /// It must exercise `/mcp` specifically - `with_extra_router` routes never
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
            .context("tool call transport error - the session was cancelled mid-flight")?;

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
    /// whether or not the session token was cancelled - asserting on the join
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
                "response body never terminated - force-exit did not cancel the session token",
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

    // ==========================================================================
    // Compat oracle: the 3.20.0 wire behaviour of an unchanged config
    // ==========================================================================

    /// Byte-level oracle for the wire behaviour an operator observes with an
    /// unchanged 3.20.0 config (no post-3.20.0 knob set anywhere).
    ///
    /// Every expected value below was captured from the unmodified 3.20.0
    /// tree and pasted verbatim; only the ephemeral ports are interpolated. A
    /// failing test here means a wire change for an unchanged config: fix the
    /// change, never the snapshot.
    #[cfg(feature = "oauth")]
    mod compat_3_20 {
        use alloc::collections::BTreeMap;
        use std::sync::LazyLock;

        use reqwest::redirect::Policy;
        use rmcp_server_kit::transport::SecurityHeadersConfig;
        use wiremock::{Mock, ResponseTemplate, matchers};

        use super::*;

        /// `kid` of the mock IdP signing key.
        const KID: &str = "compat-kid";
        /// `issuer` of the OAuth config and `iss` of every minted token.
        const ISSUER: &str = "https://idp.compat.test/realms/compat";
        /// The single configured `audience`.
        const AUDIENCE: &str = "mcp-compat";
        /// Raw JSON the mock IdP `/token` endpoint answers with.
        const UPSTREAM_TOKEN_BODY: &str = r#"{"access_token":"upstream-at","token_type":"Bearer","expires_in":300,"scope":"mcp:read"}"#;
        /// MCP `initialize` request body used for every `POST /mcp` probe.
        const INITIALIZE_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"compat","version":"0.0.1"}}}"#;
        /// RFC 7636 appendix B `code_challenge` (43 characters).
        const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        /// RFC 7636 appendix B `code_verifier`.
        const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        /// `redirect_uri` every proxy probe sends, form-encoded.
        const REDIRECT_URI_ENCODED: &str = "http%3A%2F%2F127.0.0.1%3A9%2Fcb";
        /// 401 body for a request without any credential.
        const MISSING_CREDENTIAL: &str = "unauthorized: missing credential";
        /// 401 body for a credential that fails validation.
        const INVALID_CREDENTIAL: &str = "unauthorized: invalid credential";
        /// 401 body for an expired token.
        const EXPIRED_CREDENTIAL: &str = "unauthorized: expired credential";
        /// JSON body of the router fallback and of every unmounted route.
        const NOT_FOUND_BODY: &str =
            r#"{"error":"not_found","error_description":"The requested endpoint does not exist"}"#;
        /// JSON body of the passthrough `/register` stub for the probe request.
        const REGISTER_BODY: &str = r#"{"client_id":"static-client","client_name":"compat","redirect_uris":["http://127.0.0.1:9/cb"],"token_endpoint_auth_method":"none"}"#;
        /// `content-type` of every plain-text 401/403 body.
        const TEXT_PLAIN: &str = "text/plain; charset=utf-8";
        /// The 11 security headers 3.20.0 puts on every plaintext response.
        /// Kept local (not shared with [`default_security_header_values`]) so
        /// an edit to a shared helper can never silently move the oracle.
        const DEFAULT_SECURITY_HEADERS: [(&str, &str); 11] = [
            ("cache-control", "no-store, max-age=0"),
            (
                "content-security-policy",
                "default-src 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
            ),
            ("cross-origin-embedder-policy", "require-corp"),
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-resource-policy", "same-origin"),
            (
                "permissions-policy",
                "accelerometer=(), camera=(), geolocation=(), microphone=()",
            ),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("x-dns-prefetch-control", "off"),
            ("x-frame-options", "deny"),
            ("x-permitted-cross-domain-policies", "none"),
        ];
        /// C15 operator `Content-Security-Policy` override.
        const C15_CSP: &str = "default-src 'none'; sandbox";
        /// C15 operator `Referrer-Policy` override.
        const C15_REFERRER_POLICY: &str = "strict-origin";
        /// C15 operator `Cache-Control` override.
        const C15_CACHE_CONTROL: &str = "no-store";
        /// The security headers with the three C15 overrides applied.
        const C15_SECURITY_HEADERS: [(&str, &str); 11] = [
            ("cache-control", C15_CACHE_CONTROL),
            ("content-security-policy", C15_CSP),
            ("cross-origin-embedder-policy", "require-corp"),
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-resource-policy", "same-origin"),
            (
                "permissions-policy",
                "accelerometer=(), camera=(), geolocation=(), microphone=()",
            ),
            ("referrer-policy", C15_REFERRER_POLICY),
            ("x-content-type-options", "nosniff"),
            ("x-dns-prefetch-control", "off"),
            ("x-frame-options", "deny"),
            ("x-permitted-cross-domain-policies", "none"),
        ];

        /// One RSA keypair for the whole module: generating a 2048-bit key in
        /// an unoptimized build costs seconds, and no scenario needs its own.
        static KEYPAIR: LazyLock<Result<(String, serde_json::Value), String>> =
            LazyLock::new(|| generate_oauth_test_keypair(KID).map_err(|err| format!("{err:#}")));

        /// The exact response an unchanged config produces: status, every
        /// header except `date` (each name's values in `HeaderMap::get_all`
        /// order) and the raw body bytes.
        struct WireSnapshot {
            /// HTTP status code.
            status: u16,
            /// Every `(name, value)` pair except `date`; a repeated name lists
            /// its values in wire order.
            headers: Vec<(&'static str, String)>,
            /// Raw body; every captured body is ASCII.
            body: String,
        }

        impl WireSnapshot {
            /// A snapshot with `status`, `body` and no headers yet.
            fn new(status: u16, body: &str) -> Self {
                Self {
                    status,
                    headers: Vec::new(),
                    body: body.to_owned(),
                }
            }

            /// Appends literal header pairs in order.
            fn headers(mut self, pairs: &[(&'static str, &str)]) -> Self {
                self.headers
                    .extend(pairs.iter().map(|&(name, value)| (name, value.to_owned())));
                self
            }

            /// Appends one header whose value is built at run time.
            fn header(mut self, name: &'static str, value: String) -> Self {
                self.headers.push((name, value));
                self
            }

            /// Appends `content-length` computed from the expected body, for
            /// bodies that embed an ephemeral port.
            fn content_length(self) -> Self {
                let length = self.body.len().to_string();
                self.header("content-length", length)
            }
        }

        /// Groups `headers` by name, keeping each name's values in
        /// `HeaderMap::get_all` order. `date` is excluded: it carries the
        /// wall-clock time of the response, the only non-deterministic header
        /// these scenarios produce.
        fn header_multimap(headers: &HeaderMap) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
            let mut grouped = BTreeMap::new();
            for name in headers.keys() {
                if name.as_str() == "date" {
                    continue;
                }
                let mut values = Vec::new();
                for value in headers.get_all(name) {
                    values.push(
                        value
                            .to_str()
                            .with_context(|| format!("header {name} is visible ASCII"))?
                            .to_owned(),
                    );
                }
                drop(grouped.insert(name.as_str().to_owned(), values));
            }
            Ok(grouped)
        }

        /// Renders a response for the assertion messages.
        fn render(status: u16, headers: &BTreeMap<String, Vec<String>>, body: &[u8]) -> String {
            let header_lines: String = headers
                .iter()
                .flat_map(|(name, values)| {
                    values.iter().map(move |value| format!("{name}: {value}\n"))
                })
                .collect();
            format!(
                "status: {status}\n{header_lines}body: {}",
                String::from_utf8_lossy(body)
            )
        }

        /// Asserts that `resp` matches `expected` exactly: status, the complete
        /// header multimap except `date`, and the raw body bytes.
        async fn assert_wire_eq(
            resp: reqwest::Response,
            expected: &WireSnapshot,
        ) -> anyhow::Result<()> {
            let status = resp.status().as_u16();
            let headers = header_multimap(resp.headers())?;
            let body = resp.bytes().await.context("read response body")?;
            let mut expected_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (name, value) in &expected.headers {
                expected_headers
                    .entry((*name).to_owned())
                    .or_default()
                    .push(value.clone());
            }
            let actual = render(status, &headers, &body);
            let wanted = render(expected.status, &expected_headers, expected.body.as_bytes());
            assert_eq!(
                status, expected.status,
                "status drifted\nactual:\n{actual}\nexpected:\n{wanted}"
            );
            assert_eq!(
                headers, expected_headers,
                "headers drifted\nactual:\n{actual}\nexpected:\n{wanted}"
            );
            assert_eq!(
                body.as_ref(),
                expected.body.as_bytes(),
                "body drifted\nactual:\n{actual}\nexpected:\n{wanted}"
            );
            Ok(())
        }

        /// Mock upstream IdP: serves the JWKS and a fixed `/token` answer on
        /// both loopback addresses.
        struct CompatIdp {
            /// The dual-stack wiremock server.
            mock: DualStackMock,
        }

        impl CompatIdp {
            /// Starts the mock and mounts `/jwks.json` and `/token`.
            async fn start() -> anyhow::Result<Self> {
                let (_pem, jwks_body) = KEYPAIR
                    .as_ref()
                    .map_err(|err| anyhow::anyhow!("keypair generation: {err}"))?;
                let mock = DualStackMock::start().await?;
                mock.mount(|| {
                    Mock::given(matchers::method("GET"))
                        .and(matchers::path("/jwks.json"))
                        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body))
                })
                .await;
                mock.mount(|| {
                    Mock::given(matchers::method("POST"))
                        .and(matchers::path("/token"))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_body_raw(UPSTREAM_TOKEN_BODY, "application/json"),
                        )
                })
                .await;
                Ok(Self { mock })
            }

            /// `http://localhost:<port><path>` on the mock.
            fn url(&self, path: &str) -> String {
                format!("http://localhost:{}{path}", self.mock.port())
            }

            /// Mints an RS256 token signed by the mock key with `claims`.
            fn token(claims: &serde_json::Value) -> anyhow::Result<String> {
                let (pem, _jwks) = KEYPAIR
                    .as_ref()
                    .map_err(|err| anyhow::anyhow!("keypair generation: {err}"))?;
                let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())
                    .context("encoding key from PEM")?;
                let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
                header.kid = Some(KID.into());
                jsonwebtoken::encode(&header, claims, &encoding_key).context("JWT encoding")
            }

            /// Bodies of every `POST /token` the mock received, on either
            /// loopback address.
            async fn token_request_bodies(&self) -> anyhow::Result<Vec<String>> {
                let mut bodies = Vec::new();
                for server in [Some(&self.mock.v4), self.mock.v6.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    let requests = server
                        .received_requests()
                        .await
                        .context("request recording must be enabled")?;
                    for request in requests.iter().filter(|req| req.url.path() == "/token") {
                        bodies.push(
                            String::from_utf8(request.body.clone())
                                .context("upstream token body is UTF-8")?,
                        );
                    }
                }
                Ok(bodies)
            }
        }

        /// Token claims with the configured issuer, a fresh `iat`, and the
        /// given audience, scope and expiry offset in seconds from now.
        fn claims(aud: &str, scope: &str, exp_offset: i64) -> serde_json::Value {
            let now = jsonwebtoken::get_current_timestamp();
            serde_json::json!({
                "iss": ISSUER,
                "aud": aud,
                "sub": "compat-user",
                "scope": scope,
                "exp": now.saturating_add_signed(exp_offset),
                "iat": now
            })
        }

        /// The 3.20.0-shaped OAuth document: direct mode (no `proxy` table).
        fn oauth_direct_json(idp: &CompatIdp) -> serde_json::Value {
            serde_json::json!({
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "jwks_uri": idp.url("/jwks.json"),
                "allow_http_oauth_urls": true,
                "ssrf_allowlist": {
                    "hosts": ["localhost"],
                    "cidrs": ["127.0.0.0/8"]
                },
                "scopes": [
                    {"scope": "mcp:admin", "role": "ops"},
                    {"scope": "mcp:read", "role": "viewer"}
                ]
            })
        }

        /// Direct-mode OAuth config.
        fn oauth_direct(idp: &CompatIdp) -> anyhow::Result<OAuthConfig> {
            serde_json::from_value(oauth_direct_json(idp)).context("oauth config deserialization")
        }

        /// Direct-mode OAuth config plus a passthrough `proxy` table.
        fn oauth_proxy(idp: &CompatIdp) -> anyhow::Result<OAuthConfig> {
            let mut json = oauth_direct_json(idp);
            let proxy = serde_json::json!({
                "authorize_url": idp.url("/authorize"),
                "token_url": idp.url("/token"),
                "client_id": "static-client"
            });
            let previous = json
                .as_object_mut()
                .context("oauth document is an object")?
                .insert("proxy".to_owned(), proxy);
            anyhow::ensure!(previous.is_none(), "proxy key was already set");
            serde_json::from_value(json).context("oauth config deserialization")
        }

        /// `viewer` may call only `echo`; `ops` may call every tool.
        fn compat_rbac() -> Arc<RbacPolicy> {
            Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()]),
                RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
            ])))
        }

        /// The server's own origin, `http://127.0.0.1:<port>`.
        fn origin(port: u16) -> String {
            format!("http://127.0.0.1:{port}")
        }

        /// OAuth server config with `oauth` as the only auth source and
        /// [`compat_rbac`], without `public_url`.
        fn oauth_server_config(port: u16, oauth: OAuthConfig) -> McpServerConfig {
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.oauth = Some(oauth);
            config_on_port(port)
                .with_auth(auth)
                .with_rbac(compat_rbac())
        }

        /// Like [`spawn_server`], but binds the listener before building the
        /// config so `build` can name the real port (e.g. in `public_url`).
        async fn spawn_on_known_port<B>(build: B) -> anyhow::Result<(ServerHarness, u16)>
        where
            B: FnOnce(u16) -> anyhow::Result<McpServerConfig>,
        {
            drop(ring::default_provider().install_default());
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let bound: SocketAddr = listener.local_addr()?;
            let port = bound.port();
            let validated = build(port)?.validate().context("test config valid")?;
            let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
            let shutdown = CancellationToken::new();
            let shutdown_for_server = shutdown.clone();
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
            let signalled = timeout(Duration::from_secs(30), ready_rx)
                .await
                .context("server did not signal readiness within 30s")?
                .context("server task aborted before readiness signal")?;
            assert_eq!(
                signalled, bound,
                "ready_tx address mismatched the pre-bound listener"
            );
            Ok((
                ServerHarness {
                    base: format!("http://{bound}"),
                    shutdown,
                    join: Some(join),
                },
                port,
            ))
        }

        /// Spawns the OAuth + passthrough-proxy server with `public_url` set
        /// to its own origin.
        async fn spawn_proxy_server(idp: &CompatIdp) -> anyhow::Result<(ServerHarness, u16)> {
            let oauth = oauth_proxy(idp)?;
            spawn_on_known_port(|port| {
                Ok(oauth_server_config(port, oauth).with_public_url(origin(port)))
            })
            .await
        }

        /// A client that never follows redirects, so a 302 is observed as-is.
        fn client() -> anyhow::Result<reqwest::Client> {
            reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .context("build reqwest client")
        }

        /// `POST /mcp` with [`INITIALIZE_BODY`] and an optional bearer.
        async fn post_initialize(
            client: &reqwest::Client,
            base: &str,
            bearer: Option<&str>,
        ) -> anyhow::Result<reqwest::Response> {
            let request = client
                .post(format!("{base}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
            let authed = match bearer {
                Some(token) => request.header("authorization", format!("Bearer {token}")),
                None => request,
            };
            authed
                .body(INITIALIZE_BODY)
                .send()
                .await
                .context("POST /mcp")
        }

        /// `GET /authorize` with a full PKCE authorization request.
        async fn get_authorize(
            client: &reqwest::Client,
            base: &str,
            port: u16,
        ) -> anyhow::Result<reqwest::Response> {
            let url = format!(
                "{base}/authorize?response_type=code&client_id=anything&redirect_uri={REDIRECT_URI_ENCODED}&state=s1&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256&scope=mcp%3Aread&resource=http%3A%2F%2F127.0.0.1%3A{port}%2Fmcp"
            );
            client.get(url).send().await.context("GET /authorize")
        }

        /// `POST /register` with a minimal RFC 7591 registration.
        async fn post_register(
            client: &reqwest::Client,
            base: &str,
        ) -> anyhow::Result<reqwest::Response> {
            client
                .post(format!("{base}/register"))
                .header("content-type", "application/json")
                .body(r#"{"redirect_uris":["http://127.0.0.1:9/cb"],"client_name":"compat"}"#)
                .send()
                .await
                .context("POST /register")
        }

        /// `GET {base}{path}`.
        async fn get_path(
            client: &reqwest::Client,
            base: &str,
            path: &str,
        ) -> anyhow::Result<reqwest::Response> {
            client
                .get(format!("{base}{path}"))
                .send()
                .await
                .with_context(|| format!("GET {path}"))
        }

        /// The upstream `Location` the passthrough `/authorize` answers with.
        fn upstream_authorize_location(idp: &CompatIdp, port: u16) -> String {
            idp.url(&format!(
                "/authorize?response_type=code&redirect_uri={REDIRECT_URI_ENCODED}&state=s1&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256&scope=mcp%3Aread&resource=http%3A%2F%2F127.0.0.1%3A{port}%2Fmcp&client_id=static-client"
            ))
        }

        /// RFC 9728 metadata body naming `authorization_server` and the
        /// resource `http://127.0.0.1:<port>/mcp`.
        fn protected_resource_body(authorization_server: &str, port: u16) -> String {
            format!(
                r#"{{"authorization_servers":["{authorization_server}"],"bearer_methods_supported":["header"],"resource":"{}/mcp","scopes_supported":["mcp:admin","mcp:read"]}}"#,
                origin(port)
            )
        }

        /// The absolute `resource_metadata` challenge parameter for `port`.
        fn resource_metadata(port: u16) -> String {
            format!(
                r#"resource_metadata="{}/.well-known/oauth-protected-resource/mcp""#,
                origin(port)
            )
        }

        /// The default-headers 200 JSON snapshot of a metadata document.
        fn json_200(body: &str) -> WireSnapshot {
            WireSnapshot::new(200, body)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[("content-type", "application/json"), ("vary", "origin")])
                .content_length()
        }

        /// The 404 snapshot of the router fallback and of an unmounted route.
        fn not_found() -> WireSnapshot {
            WireSnapshot::new(404, NOT_FOUND_BODY)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "81"),
                    ("content-type", "application/json"),
                ])
        }

        /// The default-headers OAuth 401 snapshot with `challenge` as the
        /// `WWW-Authenticate` value.
        fn oauth_401(challenge: String, body: &str) -> WireSnapshot {
            WireSnapshot::new(401, body)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "32"),
                    ("content-type", TEXT_PLAIN),
                    ("vary", "origin"),
                ])
                .header("www-authenticate", challenge)
        }

        /// C1: both protected-resource metadata routes of the proxy config.
        #[tokio::test]
        async fn c1_protected_resource_metadata() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let client = client()?;
            let expected = json_200(&protected_resource_body(&origin(port), port));

            let suffixed = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-protected-resource/mcp",
            )
            .await?;
            assert_wire_eq(suffixed, &expected).await?;
            let root = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-protected-resource",
            )
            .await?;
            assert_wire_eq(root, &expected).await?;
            Ok(())
        }

        /// C2: authorization-server metadata of the proxy config, without the
        /// RFC 9207 `iss` parameter flag.
        #[tokio::test]
        async fn c2_authorization_server_metadata() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let client = client()?;
            let own = origin(port);
            let body = format!(
                r#"{{"authorization_endpoint":"{own}/authorize","code_challenge_methods_supported":["S256"],"grant_types_supported":["authorization_code","refresh_token"],"issuer":"{own}","registration_endpoint":"{own}/register","response_types_supported":["code"],"scopes_supported":["mcp:admin","mcp:read"],"token_endpoint":"{own}/token","token_endpoint_auth_methods_supported":["none"]}}"#
            );

            let resp = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-authorization-server",
            )
            .await?;
            assert_wire_eq(resp, &json_200(&body)).await?;
            let doc: serde_json::Value = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-authorization-server",
            )
            .await?
            .json()
            .await?;
            assert!(
                doc.get("authorization_response_iss_parameter_supported")
                    .is_none(),
                "3.20.0 never advertises authorization_response_iss_parameter_supported"
            );
            Ok(())
        }

        /// C3: `POST /mcp` without credentials.
        #[tokio::test]
        async fn c3_missing_credentials_challenge() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let expected = oauth_401(
                format!(
                    r#"Bearer {}, error="invalid_request", error_description="missing bearer token or mTLS client certificate""#,
                    resource_metadata(port)
                ),
                MISSING_CREDENTIAL,
            );

            let resp = post_initialize(&client()?, &server.base, None).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C4: `POST /mcp` with a malformed JWT.
        #[tokio::test]
        async fn c4_malformed_jwt_challenge() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let expected = oauth_401(
                format!(
                    r#"Bearer {}, error="invalid_token", error_description="token is invalid""#,
                    resource_metadata(port)
                ),
                INVALID_CREDENTIAL,
            );

            let resp = post_initialize(&client()?, &server.base, Some("a.b.c")).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C5: a valid `mcp:read` token calling a tool its role may not call
        /// gets a bare 403 without `WWW-Authenticate`.
        #[tokio::test]
        async fn c5_rbac_deny_is_bare_403() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, _port) = spawn_proxy_server(&idp).await?;
            let token = CompatIdp::token(&claims(AUDIENCE, "mcp:read", 3600))?;
            let expected = WireSnapshot::new(403, "admin_only denied for role 'viewer'")
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "35"),
                    ("content-type", TEXT_PLAIN),
                    ("vary", "origin"),
                ]);

            let resp = client()?
                .post(format!("{}/mcp", server.base))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(tool_call_body("admin_only", &serde_json::json!({})))
                .send()
                .await?;
            assert!(
                resp.headers().get("www-authenticate").is_none(),
                "3.20.0 RBAC deny carries no WWW-Authenticate"
            );
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C6: a token whose `aud` is the server's own resource URL instead of
        /// the configured audience is rejected (no implicit audience widening).
        #[tokio::test]
        async fn c6_resource_url_audience_rejected() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let resource = format!("{}/mcp", origin(port));
            let token = CompatIdp::token(&claims(&resource, "mcp:read", 3600))?;
            let expected = oauth_401(
                format!(
                    r#"Bearer {}, error="invalid_token", error_description="token is invalid""#,
                    resource_metadata(port)
                ),
                INVALID_CREDENTIAL,
            );

            let resp = post_initialize(&client()?, &server.base, Some(&token)).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C7: passthrough `/authorize` redirects to the upstream with the
        /// client id swapped.
        #[tokio::test]
        async fn c7_authorize_redirect() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let expected = WireSnapshot::new(302, "")
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[("content-length", "0"), ("vary", "origin")])
                .header("location", upstream_authorize_location(&idp, port));

            let resp = get_authorize(&client()?, &server.base, port).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C8: passthrough `/register` stub response.
        #[tokio::test]
        async fn c8_register_stub() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, _port) = spawn_proxy_server(&idp).await?;
            let expected = WireSnapshot::new(200, REGISTER_BODY)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "130"),
                    ("content-type", "application/json"),
                    ("pragma", "no-cache"),
                    ("vary", "Authorization"),
                    ("vary", "origin"),
                ]);

            let resp = post_register(&client()?, &server.base).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C9: passthrough `/token` forwards an exact form body upstream and
        /// relays the upstream JSON verbatim.
        #[tokio::test]
        async fn c9_token_passthrough() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, _port) = spawn_proxy_server(&idp).await?;
            let expected = WireSnapshot::new(200, UPSTREAM_TOKEN_BODY)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "88"),
                    ("content-type", "application/json"),
                    ("pragma", "no-cache"),
                    ("vary", "Authorization"),
                    ("vary", "origin"),
                ]);

            let resp = client()?
                .post(format!("{}/token", server.base))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(format!(
                    "grant_type=authorization_code&code=c1&redirect_uri={REDIRECT_URI_ENCODED}&code_verifier={CODE_VERIFIER}&client_id=anything"
                ))
                .send()
                .await?;
            assert_wire_eq(resp, &expected).await?;
            assert_eq!(
                idp.token_request_bodies().await?,
                vec![format!(
                    "grant_type=authorization_code&code=c1&redirect_uri={REDIRECT_URI_ENCODED}&code_verifier={CODE_VERIFIER}&client_id=static-client"
                )],
                "the upstream must receive exactly one request with this exact form body"
            );
            Ok(())
        }

        /// C10: API-key-only server (no OAuth), `POST /mcp` without
        /// credentials.
        #[tokio::test]
        async fn c10_api_key_missing_credentials_challenge() -> anyhow::Result<()> {
            let (_token, hash) = generate_api_key()?;
            let (server, _port) =
                spawn_on_known_port(|port| {
                    Ok(config_on_port(port).with_auth(AuthConfig::with_keys(vec![
                        ApiKeyEntry::new("compat-key", hash, "ops"),
                    ])))
                })
                .await?;
            let expected = WireSnapshot::new(401, MISSING_CREDENTIAL)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "32"),
                    ("content-type", TEXT_PLAIN),
                    (
                        "www-authenticate",
                        r#"Bearer error="invalid_request", error_description="missing bearer token or mTLS client certificate""#,
                    ),
                ]);

            let resp = post_initialize(&client()?, &server.base, None).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C11: OAuth direct mode (no `proxy` table, `public_url` set): both
        /// metadata routes, and the proxy routes stay unmounted.
        #[tokio::test]
        async fn c11_direct_mode_routes() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let oauth = oauth_direct(&idp)?;
            let (server, port) = spawn_on_known_port(|port| {
                Ok(oauth_server_config(port, oauth).with_public_url(origin(port)))
            })
            .await?;
            let client = client()?;
            let metadata = json_200(&protected_resource_body(ISSUER, port));

            let suffixed = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-protected-resource/mcp",
            )
            .await?;
            assert_wire_eq(suffixed, &metadata).await?;
            let root = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-protected-resource",
            )
            .await?;
            assert_wire_eq(root, &metadata).await?;
            let as_meta = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-authorization-server",
            )
            .await?;
            assert_wire_eq(as_meta, &not_found()).await?;
            let authorize = get_path(&client, &server.base, "/authorize").await?;
            assert_wire_eq(authorize, &not_found()).await?;
            Ok(())
        }

        /// C12: OAuth direct mode without `public_url`: the challenge carries
        /// a relative `resource_metadata` and the metadata derives `resource`
        /// from the bind address.
        #[tokio::test]
        async fn c12_direct_mode_without_public_url() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let oauth = oauth_direct(&idp)?;
            let (server, port) =
                spawn_on_known_port(|port| Ok(oauth_server_config(port, oauth))).await?;
            let client = client()?;
            let challenge_expected = WireSnapshot::new(401, MISSING_CREDENTIAL)
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "32"),
                    ("content-type", TEXT_PLAIN),
                    (
                        "www-authenticate",
                        r#"Bearer resource_metadata="/.well-known/oauth-protected-resource", error="invalid_request", error_description="missing bearer token or mTLS client certificate""#,
                    ),
                ]);
            let metadata_expected = WireSnapshot::new(200, &protected_resource_body(ISSUER, port))
                .headers(&DEFAULT_SECURITY_HEADERS)
                .headers(&[("content-type", "application/json")])
                .content_length();

            let challenge = post_initialize(&client, &server.base, None).await?;
            assert_wire_eq(challenge, &challenge_expected).await?;
            let metadata = get_path(
                &client,
                &server.base,
                "/.well-known/oauth-protected-resource",
            )
            .await?;
            assert_wire_eq(metadata, &metadata_expected).await?;
            Ok(())
        }

        /// C13: an expired token.
        #[tokio::test]
        async fn c13_expired_jwt_challenge() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, port) = spawn_proxy_server(&idp).await?;
            let token = CompatIdp::token(&claims(AUDIENCE, "mcp:read", -3600))?;
            let expected = oauth_401(
                format!(
                    r#"Bearer {}, error="invalid_token", error_description="token is expired""#,
                    resource_metadata(port)
                ),
                EXPIRED_CREDENTIAL,
            );

            let resp = post_initialize(&client()?, &server.base, Some(&token)).await?;
            assert_wire_eq(resp, &expected).await?;
            Ok(())
        }

        /// C14: an unknown path hits the router fallback.
        #[tokio::test]
        async fn c14_unknown_path_fallback() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let (server, _port) = spawn_proxy_server(&idp).await?;

            let resp = get_path(&client()?, &server.base, "/does-not-exist").await?;
            assert_wire_eq(resp, &not_found()).await?;
            Ok(())
        }

        /// C15: operator `security_headers` overrides apply unchanged to the
        /// 401 challenge, the `/authorize` redirect and the `/register` stub.
        #[tokio::test]
        async fn c15_security_header_overrides() -> anyhow::Result<()> {
            let idp = CompatIdp::start().await?;
            let oauth = oauth_proxy(&idp)?;
            let mut overrides = SecurityHeadersConfig::default();
            overrides.content_security_policy = Some(C15_CSP.to_owned());
            overrides.referrer_policy = Some(C15_REFERRER_POLICY.to_owned());
            overrides.cache_control = Some(C15_CACHE_CONTROL.to_owned());
            let (server, port) = spawn_on_known_port(|port| {
                Ok(oauth_server_config(port, oauth)
                    .with_public_url(origin(port))
                    .with_security_headers(overrides))
            })
            .await?;
            let client = client()?;
            let challenge_expected = WireSnapshot::new(401, MISSING_CREDENTIAL)
                .headers(&C15_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "32"),
                    ("content-type", TEXT_PLAIN),
                    ("vary", "origin"),
                ])
                .header(
                    "www-authenticate",
                    format!(
                        r#"Bearer {}, error="invalid_request", error_description="missing bearer token or mTLS client certificate""#,
                        resource_metadata(port)
                    ),
                );
            let authorize_expected = WireSnapshot::new(302, "")
                .headers(&C15_SECURITY_HEADERS)
                .headers(&[("content-length", "0"), ("vary", "origin")])
                .header("location", upstream_authorize_location(&idp, port));
            let register_expected = WireSnapshot::new(200, REGISTER_BODY)
                .headers(&C15_SECURITY_HEADERS)
                .headers(&[
                    ("content-length", "130"),
                    ("content-type", "application/json"),
                    ("pragma", "no-cache"),
                    ("vary", "Authorization"),
                    ("vary", "origin"),
                ]);

            let challenge = post_initialize(&client, &server.base, None).await?;
            assert_wire_eq(challenge, &challenge_expected).await?;
            let authorize = get_authorize(&client, &server.base, port).await?;
            assert_wire_eq(authorize, &authorize_expected).await?;
            let register = post_register(&client, &server.base).await?;
            assert_wire_eq(register, &register_expected).await?;
            Ok(())
        }
    }

    // ==========================================================================
    // Keycloak 26.6 token shape: ES384, `at+jwt`, array `aud`, role claims
    // ==========================================================================

    /// Pins acceptance of access tokens shaped like the ones a Keycloak 26.6
    /// realm issues: an ES384 signature, the RFC 9068 header `typ: at+jwt`,
    /// an array `aud` plus `azp`, and roles under `realm_access.roles`,
    /// `resource_access.<client>.roles` and `groups`.
    ///
    /// Every value is a generic placeholder. Each accepted token is paired
    /// with a tampered-signature twin and an expired twin that the same
    /// server rejects, so no 200 below is vacuous; each rejection is paired
    /// with an acceptance that differs only in the property under test.
    #[cfg(feature = "oauth")]
    mod keycloak_26_token_shape {
        use std::sync::LazyLock;

        use wiremock::{Mock, ResponseTemplate, matchers};

        use super::*;

        /// `kid` of the ES384 realm key.
        const EC_KID: &str = "kc-es384";
        /// `kid` of the RS256 realm key served next to it in K8.
        const RSA_KID: &str = "kc-rs256";
        /// Client id of the MCP client: the configured `audience` and `azp`.
        const CLIENT_ID: &str = "mcp-example";
        /// Path of the realm JWKS on the mock IdP.
        const CERTS_PATH: &str = "/realms/example/protocol/openid-connect/certs";
        /// The role claim K1 and K4-K8 map.
        const REALM_ROLES: &str = "realm_access.roles";
        /// The realm role K1 and K4-K8 map to `viewer`.
        const REALM_ROLE: &str = "mcp-users";
        /// An audience alias configured through `additional_audiences`.
        const ALIAS: &str = "mcp-example-alias";
        /// Bytes per P-384 affine coordinate.
        const P384_COORDINATE_LEN: usize = 48;
        /// Seconds an expired twin lies in the past, beyond the 60 s leeway.
        const EXPIRED_BY: u64 = 600;
        /// MCP `initialize` request body.
        const INITIALIZE_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"keycloak-shape","version":"0.0.1"}}}"#;
        /// MCP `tools/list` request body.
        const TOOLS_LIST_BODY: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        /// Accepted: `initialize` 200, then `tools/list` 200 in that session.
        const ACCEPTED: (u16, Option<u16>) = (200, Some(200));
        /// Rejected: `initialize` 401 and no session to list tools in.
        const REJECTED: (u16, Option<u16>) = (401, None);
        /// `error_description` of every rejection except expiry.
        const DESC_INVALID: &str = "token is invalid";
        /// `error_description` of an expired token.
        const DESC_EXPIRED: &str = "token is expired";

        /// The exact challenge for a server at `base`: Bearer, the
        /// protected-resource metadata URL, `error="invalid_token"` and
        /// `description`.
        fn invalid_token_challenge(base: &str, description: &str) -> String {
            format!(
                r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp", error="invalid_token", error_description="{description}""#
            )
        }

        /// The module's ES384 realm key.
        struct EcKey {
            /// PKCS#8 PEM of the P-384 private key.
            pem: String,
            /// Public JWK (`kty = EC`, `crv = P-384`) as Keycloak publishes it.
            jwk: serde_json::Value,
        }

        /// One P-384 key for the whole module.
        static EC_KEY: LazyLock<Result<EcKey, String>> =
            LazyLock::new(|| generate_es384_key().map_err(|err| format!("{err:#}")));

        /// One RSA key for K8: 2048-bit generation in an unoptimized build
        /// costs seconds.
        static RSA_KEY: LazyLock<Result<(String, serde_json::Value), String>> =
            LazyLock::new(|| {
                generate_oauth_test_keypair(RSA_KID).map_err(|err| format!("{err:#}"))
            });

        /// Generates a P-384 key and its JWK from the uncompressed public
        /// point `0x04 || X(48) || Y(48)`.
        fn generate_es384_key() -> anyhow::Result<EcKey> {
            let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
                .context("P-384 key generation")?;
            let Some((&0x04, coordinates)) = key_pair.public_key_raw().split_first() else {
                anyhow::bail!("P-384 public key is not an uncompressed point");
            };
            let (x, y) = coordinates
                .split_at_checked(P384_COORDINATE_LEN)
                .context("P-384 point carries a 48-byte X")?;
            anyhow::ensure!(
                y.len() == P384_COORDINATE_LEN,
                "P-384 point carries a 48-byte Y"
            );
            Ok(EcKey {
                pem: key_pair.serialize_pem(),
                jwk: serde_json::json!({
                    "kty": "EC",
                    "crv": "P-384",
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                    "kid": EC_KID,
                    "alg": "ES384",
                    "use": "sig"
                }),
            })
        }

        /// The shared ES384 key.
        fn ec_key() -> anyhow::Result<&'static EcKey> {
            EC_KEY
                .as_ref()
                .map_err(|err| anyhow::anyhow!("P-384 key generation: {err}"))
        }

        /// The shared RSA key: PKCS#8 PEM and its JWKS document.
        fn rsa_key() -> anyhow::Result<&'static (String, serde_json::Value)> {
            RSA_KEY
                .as_ref()
                .map_err(|err| anyhow::anyhow!("RSA key generation: {err}"))
        }

        /// Which realm key signs a token, with which header shape.
        #[derive(Clone, Copy, Debug)]
        enum Signer {
            /// ES384 with the RFC 9068 header `typ: at+jwt`, as Keycloak
            /// 26.6 issues for a client with RFC 9068 tokens enabled.
            Es384AtJwt,
            /// RS256 with the classic header `typ: JWT`.
            Rs256Jwt,
        }

        impl Signer {
            /// Signs `claims` with `kid` set to this signer's realm key.
            fn sign(self, claims: &serde_json::Value) -> anyhow::Result<String> {
                let (header, key) = match self {
                    Self::Es384AtJwt => {
                        let mut header = jsonwebtoken::Header::new(Algorithm::ES384);
                        header.kid = Some(EC_KID.into());
                        header.typ = Some("at+jwt".into());
                        let key = jsonwebtoken::EncodingKey::from_ec_pem(ec_key()?.pem.as_bytes())
                            .context("EC encoding key from PEM")?;
                        (header, key)
                    }
                    Self::Rs256Jwt => {
                        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
                        header.kid = Some(RSA_KID.into());
                        header.typ = Some("JWT".into());
                        let key = jsonwebtoken::EncodingKey::from_rsa_pem(rsa_key()?.0.as_bytes())
                            .context("RSA encoding key from PEM")?;
                        (header, key)
                    }
                };
                jsonwebtoken::encode(&header, claims, &key).context("JWT encoding")
            }
        }

        /// Mock Keycloak realm serving its JWKS on both loopback addresses.
        struct KeycloakIdp {
            /// The dual-stack wiremock server.
            mock: DualStackMock,
        }

        impl KeycloakIdp {
            /// Starts a realm whose JWKS holds exactly `keys`.
            async fn start(keys: Vec<serde_json::Value>) -> anyhow::Result<Self> {
                let body = serde_json::json!({ "keys": keys });
                let mock = DualStackMock::start().await?;
                mock.mount(|| {
                    Mock::given(matchers::method("GET"))
                        .and(matchers::path(CERTS_PATH))
                        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
                })
                .await;
                Ok(Self { mock })
            }

            /// Starts a realm whose JWKS holds only the ES384 key.
            async fn es384() -> anyhow::Result<Self> {
                Self::start(vec![ec_key()?.jwk.clone()]).await
            }

            /// `iss` of every token and the configured `issuer`.
            fn issuer(&self) -> String {
                format!("http://localhost:{}/realms/example", self.mock.port())
            }

            /// OAuth config: audience [`CLIENT_ID`], default (`strict`)
            /// audience mode, default `allowed_algorithms`, `role_claim =`
            /// [`REALM_ROLES`] mapping [`REALM_ROLE`] to `viewer`; each
            /// top-level key of `overrides` replaces the default.
            fn oauth(&self, overrides: &serde_json::Value) -> anyhow::Result<OAuthConfig> {
                let mut json = serde_json::json!({
                    "issuer": self.issuer(),
                    "audience": CLIENT_ID,
                    "jwks_uri": format!("http://localhost:{}{CERTS_PATH}", self.mock.port()),
                    "allow_http_oauth_urls": true,
                    "ssrf_allowlist": {
                        "hosts": ["localhost"],
                        "cidrs": ["127.0.0.0/8"]
                    },
                    "role_claim": REALM_ROLES,
                    "role_mappings": [{"claim_value": REALM_ROLE, "role": "viewer"}]
                });
                let object = json
                    .as_object_mut()
                    .context("oauth document is an object")?;
                for (key, value) in overrides
                    .as_object()
                    .context("oauth overrides are an object")?
                {
                    drop(object.insert(key.clone(), value.clone()));
                }
                serde_json::from_value(json).context("oauth config deserialization")
            }

            /// Claims modelled on a Keycloak 26.6 access token for
            /// [`CLIENT_ID`], expiring 180 s from now.
            fn claims(&self) -> serde_json::Value {
                let now = jsonwebtoken::get_current_timestamp();
                serde_json::json!({
                    "exp": now.saturating_add(180),
                    "iat": now,
                    "auth_time": now,
                    "jti": "00000000-0000-4000-8000-000000000001",
                    "iss": self.issuer(),
                    "aud": [CLIENT_ID, "other-service", "account"],
                    "sub": "00000000-0000-4000-8000-000000000002",
                    "typ": "Bearer",
                    "azp": CLIENT_ID,
                    "sid": "00000000-0000-4000-8000-000000000003",
                    "scope": "openid profile email",
                    "realm_access": {"roles": [REALM_ROLE]},
                    "resource_access": {"mcp-example": {"roles": ["tool-admin"]}},
                    "groups": ["mcp-operators"]
                })
            }
        }

        /// `claims` with the top-level `key` set to `value`.
        fn with_claim(
            mut claims: serde_json::Value,
            key: &str,
            value: serde_json::Value,
        ) -> anyhow::Result<serde_json::Value> {
            drop(
                claims
                    .as_object_mut()
                    .context("claims are an object")?
                    .insert(key.to_owned(), value),
            );
            Ok(claims)
        }

        /// `viewer` may call only `echo`.
        fn viewer_rbac() -> Arc<RbacPolicy> {
            Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
                RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()]),
            ])))
        }

        /// Spawns an OAuth-only server through `serve_with_listener` on an
        /// ephemeral port with `public_url = http://127.0.0.1:<port>` (equal
        /// to the harness `base`) and [`viewer_rbac`].
        async fn spawn_keycloak_server(oauth: OAuthConfig) -> anyhow::Result<ServerHarness> {
            drop(ring::default_provider().install_default());
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let bound: SocketAddr = listener.local_addr()?;
            let public_url = format!("http://{bound}");
            let mut auth = AuthConfig::with_keys(vec![]);
            auth.oauth = Some(oauth);
            let validated = config_on_port(bound.port())
                .with_auth(auth)
                .with_rbac(viewer_rbac())
                .with_public_url(public_url.clone())
                .validate()
                .context("test config valid")?;
            let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
            let shutdown = CancellationToken::new();
            let shutdown_for_server = shutdown.clone();
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
            let signalled = timeout(Duration::from_secs(30), ready_rx)
                .await
                .context("server did not signal readiness within 30s")?
                .context("server task aborted before readiness signal")?;
            assert_eq!(
                signalled, bound,
                "ready_tx address mismatched the pre-bound listener"
            );
            Ok(ServerHarness {
                base: public_url,
                shutdown,
                join: Some(join),
            })
        }

        /// A `POST /mcp` carrying `token` as the bearer.
        fn mcp_request(
            client: &reqwest::Client,
            base: &str,
            token: &str,
        ) -> reqwest::RequestBuilder {
            client
                .post(format!("{base}/mcp"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
        }

        /// MCP `initialize` with `token`, then `tools/list` in the returned
        /// session: the two statuses (`None` when no session was issued). A
        /// 200 listing must carry a `result.tools` array.
        async fn outcome(base: &str, token: &str) -> anyhow::Result<(u16, Option<u16>)> {
            let client = reqwest::Client::new();
            let init = mcp_request(&client, base, token)
                .body(INITIALIZE_BODY)
                .send()
                .await
                .context("initialize request")?;
            let init_status = init.status().as_u16();
            let Some(session_header) = init.headers().get("mcp-session-id") else {
                return Ok((init_status, None));
            };
            let session = session_header
                .to_str()
                .context("session id is ASCII")?
                .to_owned();
            let list = mcp_request(&client, base, token)
                .header("mcp-session-id", session)
                .body(TOOLS_LIST_BODY)
                .send()
                .await
                .context("tools/list request")?;
            let list_status = list.status().as_u16();
            if list_status == 200 {
                let body = mcp_response_json(list).await?;
                anyhow::ensure!(
                    body.get("result")
                        .and_then(|result| result.get("tools"))
                        .is_some_and(serde_json::Value::is_array),
                    "tools/list result carries a tools array: {body}"
                );
            }
            Ok((init_status, Some(list_status)))
        }

        /// `token` with one bit of its signature flipped; header and payload
        /// stay byte-identical.
        fn tamper_signature(token: &str) -> anyhow::Result<String> {
            let (signed, signature) = token.rsplit_once('.').context("JWT has a signature")?;
            let mut bytes = URL_SAFE_NO_PAD
                .decode(signature)
                .context("JWT signature is base64url")?;
            let first = bytes.first_mut().context("JWT signature is not empty")?;
            *first ^= 0x01;
            Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(bytes)))
        }

        /// Asserts that `signer` over `claims` is accepted by `base`, and that
        /// its tampered-signature twin and its expired twin (same header,
        /// `exp` in the past) are rejected by the same server.
        async fn assert_accepted(
            base: &str,
            signer: Signer,
            claims: &serde_json::Value,
        ) -> anyhow::Result<()> {
            let token = signer.sign(claims)?;
            assert_eq!(
                outcome(base, &token).await?,
                ACCEPTED,
                "{signer:?} token must be accepted: {claims}"
            );
            assert_token_rejected(
                base,
                &tamper_signature(&token)?,
                DESC_INVALID,
                &format!("{signer:?} token with a tampered signature"),
            )
            .await?;
            let now = jsonwebtoken::get_current_timestamp();
            let expired_exp =
                with_claim(claims.clone(), "exp", now.saturating_sub(EXPIRED_BY).into())?;
            let expired = with_claim(
                expired_exp,
                "iat",
                now.saturating_sub(EXPIRED_BY.saturating_mul(2)).into(),
            )?;
            assert_token_rejected(
                base,
                &signer.sign(&expired)?,
                DESC_EXPIRED,
                &format!("{signer:?} token with exp in the past"),
            )
            .await?;
            Ok(())
        }

        /// The `WWW-Authenticate` challenge of the `initialize` response to
        /// `token` (`None` when the header is absent).
        async fn challenge_of(base: &str, token: &str) -> anyhow::Result<Option<String>> {
            let client = reqwest::Client::new();
            let init = mcp_request(&client, base, token)
                .body(INITIALIZE_BODY)
                .send()
                .await
                .context("initialize request")?;
            init.headers()
                .get("www-authenticate")
                .map(|value| value.to_str().map(str::to_owned))
                .transpose()
                .context("challenge is ASCII")
        }

        /// Asserts that `token` is rejected with the status pair
        /// [`REJECTED`] and the exact Bearer `invalid_token` challenge
        /// carrying `description`.
        async fn assert_token_rejected(
            base: &str,
            token: &str,
            description: &str,
            what: &str,
        ) -> anyhow::Result<()> {
            assert_eq!(
                outcome(base, token).await?,
                REJECTED,
                "{what}: must be rejected"
            );
            assert_eq!(
                challenge_of(base, token).await?,
                Some(invalid_token_challenge(base, description)),
                "{what}: 401 must carry the Bearer invalid_token challenge"
            );
            Ok(())
        }

        /// Asserts that the ES384 `at+jwt` token over `claims` is rejected.
        async fn assert_rejected(base: &str, claims: &serde_json::Value) -> anyhow::Result<()> {
            let token = Signer::Es384AtJwt.sign(claims)?;
            assert_token_rejected(base, &token, DESC_INVALID, &format!("token over {claims}")).await
        }

        /// A role-bearing claim of the Keycloak token, with the dot path a
        /// deployment configures as `role_claim` and the realm mapping.
        #[derive(Clone, Copy, Debug)]
        enum RoleShape {
            /// `realm_access.roles`, mapped value `mcp-users`.
            Realm,
            /// `resource_access.mcp-example.roles`, mapped value `tool-admin`.
            Resource,
            /// `groups`, mapped value `mcp-operators`.
            Groups,
        }

        impl RoleShape {
            /// Every role-bearing claim shape.
            const ALL: [Self; 3] = [Self::Realm, Self::Resource, Self::Groups];

            /// The configured `role_claim` dot path.
            const fn role_claim(self) -> &'static str {
                match self {
                    Self::Realm => REALM_ROLES,
                    Self::Resource => "resource_access.mcp-example.roles",
                    Self::Groups => "groups",
                }
            }

            /// The claim value mapped to `viewer` when this is the
            /// configured `role_claim`.
            const fn mapped(self) -> &'static str {
                match self {
                    Self::Realm => REALM_ROLE,
                    Self::Resource => "tool-admin",
                    Self::Groups => "mcp-operators",
                }
            }

            /// The top-level claim holding this shape.
            const fn top_level(self) -> &'static str {
                match self {
                    Self::Realm => "realm_access",
                    Self::Resource => "resource_access",
                    Self::Groups => "groups",
                }
            }

            /// This claim holding exactly `values`, in Keycloak's nesting.
            fn value(self, values: &[&str]) -> serde_json::Value {
                match self {
                    Self::Realm => serde_json::json!({"roles": values}),
                    Self::Resource => serde_json::json!({
                        "mcp-example": {"roles": values}
                    }),
                    Self::Groups => serde_json::json!(values),
                }
            }

            /// `claims` with this claim holding `values`, or removed when
            /// `values` is `None`.
            fn set(
                self,
                mut claims: serde_json::Value,
                values: Option<&[&str]>,
            ) -> anyhow::Result<serde_json::Value> {
                let Some(held) = values else {
                    drop(
                        claims
                            .as_object_mut()
                            .context("claims are an object")?
                            .remove(self.top_level()),
                    );
                    return Ok(claims);
                };
                with_claim(claims, self.top_level(), self.value(held))
            }
        }

        /// A role value no mapping names.
        const UNMAPPED_ROLE: &str = "unmapped-role";

        /// Spawns a server whose `role_claim` is `configured` and whose only
        /// mapping sends `configured.mapped()` to `viewer`.
        async fn spawn_role_server(
            idp: &KeycloakIdp,
            configured: RoleShape,
        ) -> anyhow::Result<ServerHarness> {
            spawn_keycloak_server(idp.oauth(&serde_json::json!({
                "role_claim": configured.role_claim(),
                "role_mappings": [{"claim_value": configured.mapped(), "role": "viewer"}]
            }))?)
            .await
        }

        /// One `role_claim` scenario (K1-K3).
        struct RoleClaimCase {
            /// The configured role claim.
            shape: RoleShape,
            /// A multi-valued claim with the mapped value last, as Keycloak
            /// emits when the user holds several roles or groups.
            mapped_last: &'static [&'static str],
            /// Values of the configured claim without the mapped value.
            unmapped: &'static [&'static str],
        }

        /// Runs a [`RoleClaimCase`]: the base token, then the mapped-last
        /// variant, are accepted; the unmapped variant gets the existing
        /// outcome for "no role mapping matches": 401 at authentication
        /// (`resolve_role` fails, so RBAC never runs). In the unmapped
        /// variant every OTHER role-bearing claim carries the mapped value,
        /// so a resolver that reads any claim but the configured one accepts.
        async fn run_role_claim_case(case: RoleClaimCase) -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let server = spawn_role_server(&idp, case.shape).await?;
            let claims = idp.claims();

            assert_accepted(&server.base, Signer::Es384AtJwt, &claims).await?;
            let mapped_last = case.shape.set(claims.clone(), Some(case.mapped_last))?;
            assert_eq!(
                outcome(&server.base, &Signer::Es384AtJwt.sign(&mapped_last)?).await?,
                ACCEPTED,
                "{}: mapped value after other values must be accepted",
                case.shape.role_claim()
            );
            let mut unmapped = case.shape.set(claims, Some(case.unmapped))?;
            for other in RoleShape::ALL
                .into_iter()
                .filter(|other| other.top_level() != case.shape.top_level())
            {
                unmapped = other.set(unmapped, Some(&[case.shape.mapped()]))?;
            }
            assert_rejected(&server.base, &unmapped).await
        }

        /// Cross-claim isolation over every (configured `role_claim`) x
        /// (other claim carrying the mapped role) combination: the role is
        /// read only from the configured claim. Per configured claim: the
        /// positive row (only it carries the mapped role, the others hold
        /// unrelated values) is accepted; each other claim alone carrying the
        /// mapped role, over a configured claim that holds an unmapped value
        /// or is absent, and all other claims carrying it together, are
        /// rejected with the "no mapping matches" outcome.
        #[tokio::test]
        async fn role_read_only_from_configured_claim() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            for configured in RoleShape::ALL {
                let server = spawn_role_server(&idp, configured).await?;
                let mapped = [configured.mapped()];
                let unrelated = [UNMAPPED_ROLE];
                let others: Vec<RoleShape> = RoleShape::ALL
                    .into_iter()
                    .filter(|other| other.top_level() != configured.top_level())
                    .collect();

                let configured_only = configured.set(idp.claims(), Some(&mapped))?;
                let positive = others.iter().try_fold(configured_only, |claims, other| {
                    other.set(claims, Some(&unrelated))
                })?;
                assert_eq!(
                    outcome(&server.base, &Signer::Es384AtJwt.sign(&positive)?).await?,
                    ACCEPTED,
                    "{configured:?}: configured claim carrying the mapped role is accepted"
                );

                for configured_claim in [Some(&unrelated[..]), None] {
                    let base_claims = configured.set(idp.claims(), configured_claim)?;
                    for carrier in &others {
                        let only_carrier =
                            others
                                .iter()
                                .try_fold(base_claims.clone(), |claims, other| {
                                    let values: &[&str] =
                                        if other.top_level() == carrier.top_level() {
                                            &mapped
                                        } else {
                                            &unrelated
                                        };
                                    other.set(claims, Some(values))
                                })?;
                        assert_rejected(&server.base, &only_carrier).await?;
                    }
                    let all_others = others.iter().try_fold(base_claims, |claims, other| {
                        other.set(claims, Some(&mapped))
                    })?;
                    assert_rejected(&server.base, &all_others).await?;
                }
            }
            Ok(())
        }

        /// K1: `role_claim = "realm_access.roles"` mapping `mcp-users` to
        /// `viewer` accepts the Keycloak-shaped ES384 `at+jwt` token.
        #[tokio::test]
        async fn k1_realm_access_roles_accepted() -> anyhow::Result<()> {
            run_role_claim_case(RoleClaimCase {
                shape: RoleShape::Realm,
                mapped_last: &[
                    "default-roles-example",
                    "offline_access",
                    "uma_authorization",
                    REALM_ROLE,
                ],
                unmapped: &["default-roles-example", UNMAPPED_ROLE],
            })
            .await
        }

        /// K2: `role_claim = "groups"` mapping `mcp-operators` to `viewer`
        /// accepts the token.
        #[tokio::test]
        async fn k2_groups_accepted() -> anyhow::Result<()> {
            run_role_claim_case(RoleClaimCase {
                shape: RoleShape::Groups,
                mapped_last: &["other-group", "mcp-operators"],
                unmapped: &["other-group"],
            })
            .await
        }

        /// K3: `role_claim = "resource_access.mcp-example.roles"` mapping
        /// `tool-admin` to `viewer` accepts the token; the same role under
        /// another client does not count.
        #[tokio::test]
        async fn k3_resource_access_client_roles_accepted() -> anyhow::Result<()> {
            run_role_claim_case(RoleClaimCase {
                shape: RoleShape::Resource,
                mapped_last: &["tool-reader", "tool-admin"],
                unmapped: &["tool-reader"],
            })
            .await?;
            let idp = KeycloakIdp::es384().await?;
            let server = spawn_role_server(&idp, RoleShape::Resource).await?;
            let other_client = with_claim(
                idp.claims(),
                "resource_access",
                serde_json::json!({
                    "mcp-example": {"roles": ["tool-reader"]},
                    "other-service": {"roles": ["tool-admin"]}
                }),
            )?;
            assert_rejected(&server.base, &other_client).await
        }

        /// K4: `audience = "mcp-other"` in strict mode rejects the token
        /// whose array `aud` lacks it, though `azp` and other `aud` entries
        /// are set (no `azp` or multi-`aud` widening); the same server
        /// accepts a token whose `aud` names it.
        #[tokio::test]
        async fn k4_audience_not_in_aud_rejected() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let server =
                spawn_keycloak_server(idp.oauth(&serde_json::json!({"audience": "mcp-other"}))?)
                    .await?;
            let claims = idp.claims();

            assert_rejected(&server.base, &claims).await?;
            let named = with_claim(claims, "aud", serde_json::json!(["mcp-other", "account"]))?;
            assert_accepted(&server.base, Signer::Es384AtJwt, &named).await
        }

        /// K5: a token whose `aud` holds only other services while `azp`
        /// names the client is rejected in strict mode and accepted only
        /// through the deprecated `azp` fallback of `warn` mode.
        #[tokio::test]
        async fn k5_azp_only_audience_strict_rejected_warn_accepted() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let claims = idp.claims();
            let azp_only = with_claim(
                claims.clone(),
                "aud",
                serde_json::json!(["other-service", "account"]),
            )?;

            let strict = spawn_keycloak_server(idp.oauth(&serde_json::json!({}))?).await?;
            assert_rejected(&strict.base, &azp_only).await?;
            assert_accepted(&strict.base, Signer::Es384AtJwt, &claims).await?;

            let warn = spawn_keycloak_server(
                idp.oauth(&serde_json::json!({"audience_validation_mode": "warn"}))?,
            )
            .await?;
            assert_accepted(&warn.base, Signer::Es384AtJwt, &azp_only).await
        }

        /// K6 (resource URL): `accept_resource_audience = true` accepts a
        /// token whose only `aud` is `<public_url>/mcp` (an "Included Custom
        /// Audience" mapper set to the resource URL); an unconfigured alias
        /// stays rejected.
        #[tokio::test]
        async fn k6_resource_url_audience_accepted() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let server = spawn_keycloak_server(
                idp.oauth(&serde_json::json!({"accept_resource_audience": true}))?,
            )
            .await?;
            let claims = idp.claims();
            let resource = format!("{}/mcp", server.base);

            let resource_aud = with_claim(claims.clone(), "aud", serde_json::json!([resource]))?;
            assert_accepted(&server.base, Signer::Es384AtJwt, &resource_aud).await?;
            let alias_aud = with_claim(claims, "aud", serde_json::json!([ALIAS]))?;
            assert_rejected(&server.base, &alias_aud).await
        }

        /// K6 (alias): `additional_audiences = ["mcp-example-alias"]` accepts
        /// a token whose only `aud` is the alias; with the resource-URL knob
        /// off, `<public_url>/mcp` stays rejected.
        #[tokio::test]
        async fn k6_additional_audience_accepted() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let server = spawn_keycloak_server(
                idp.oauth(&serde_json::json!({"additional_audiences": [ALIAS]}))?,
            )
            .await?;
            let claims = idp.claims();
            let resource = format!("{}/mcp", server.base);

            let alias_aud = with_claim(claims.clone(), "aud", serde_json::json!([ALIAS]))?;
            assert_accepted(&server.base, Signer::Es384AtJwt, &alias_aud).await?;
            let resource_aud = with_claim(claims, "aud", serde_json::json!([resource]))?;
            assert_rejected(&server.base, &resource_aud).await
        }

        /// K7: `allowed_algorithms = ["ES256"]` rejects the ES384 token that
        /// a server allowing `ES384` accepts.
        #[tokio::test]
        async fn k7_es384_outside_allowed_algorithms_rejected() -> anyhow::Result<()> {
            let idp = KeycloakIdp::es384().await?;
            let claims = idp.claims();

            let narrowed = spawn_keycloak_server(
                idp.oauth(&serde_json::json!({"allowed_algorithms": ["ES256"]}))?,
            )
            .await?;
            assert_rejected(&narrowed.base, &claims).await?;

            let allowed = spawn_keycloak_server(
                idp.oauth(&serde_json::json!({"allowed_algorithms": ["ES384"]}))?,
            )
            .await?;
            assert_accepted(&allowed.base, Signer::Es384AtJwt, &claims).await
        }

        /// K8: against a realm JWKS holding both an RSA and the ES384 key,
        /// the same claims signed RS256 with `typ: JWT` and signed ES384 with
        /// `typ: at+jwt` are both accepted: the RFC 9068 `typ` is not
        /// required (MCP does not mandate it) and not refused.
        #[tokio::test]
        async fn k8_rs256_jwt_and_es384_at_jwt_both_accepted() -> anyhow::Result<()> {
            let rsa_jwk = rsa_key()?
                .1
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .and_then(|keys| keys.first())
                .context("RSA JWKS holds one key")?
                .clone();
            let idp = KeycloakIdp::start(vec![rsa_jwk, ec_key()?.jwk.clone()]).await?;
            let server = spawn_keycloak_server(idp.oauth(&serde_json::json!({}))?).await?;
            let claims = idp.claims();

            assert_accepted(&server.base, Signer::Rs256Jwt, &claims).await?;
            assert_accepted(&server.base, Signer::Es384AtJwt, &claims).await
        }
    }
}
