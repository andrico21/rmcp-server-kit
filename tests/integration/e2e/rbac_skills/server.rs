//! The running B4 server with its credentials and reload handle.

use super::*;

/// A running server plus the credentials and reload handle of one case.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: tests/integration/e2e/rbac_skills/server.rs::RbacSkillsServer fields are read by the sibling case modules"
)]
pub(super) struct RbacSkillsServer {
    base: ServerHarness,
    pub(super) handler: RbacSkillsHandler,
    pub(super) reload: ReloadHandle,
    client: reqwest::Client,
    pub(super) analyst: String,
    pub(super) legacy: String,
}

impl RbacSkillsServer {
    pub(super) async fn start(policy: RbacPolicy) -> anyhow::Result<Self> {
        let (analyst, analyst_hash) = generate_api_key()?;
        let (legacy, legacy_hash) = generate_api_key()?;
        let auth = test_auth_config(vec![
            ApiKeyEntry::new("analyst-key", analyst_hash, "analyst"),
            ApiKeyEntry::new("legacy-key", legacy_hash, "legacy"),
        ]);
        let handler = RbacSkillsHandler::default();
        let factory_handler = handler.clone();
        let (reload_tx, reload_rx) = oneshot::channel();
        let config = config_on_port(0)
            .with_auth(auth)
            .with_rbac(Arc::new(policy))
            .with_tool_list_filtering(true)
            .with_reload_callback(move |reload| drop(reload_tx.send(reload)));
        let base = spawn_server_with(config, move || factory_handler.clone()).await?;
        let reload = timeout(Duration::from_secs(10), reload_rx)
            .await
            .context("reload handle within the bound")?
            .context("reload callback ran")?;
        Ok(Self {
            base,
            handler,
            reload,
            client: sse_client()?,
            analyst,
            legacy,
        })
    }

    /// A legacy (2025-06-18) session for `token`.
    pub(super) async fn session(&self, token: &str) -> anyhow::Result<String> {
        mcp_initialize_with_bearer(&self.client, &self.base.base, Some(token)).await
    }

    /// One JSON-RPC request on a legacy session; returns the raw JSON text
    /// of the single response frame.
    pub(super) async fn call_text(
        &self,
        auth: (&str, &str),
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<String> {
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 9_u32, "method": method, "params": params });
        let response = skills_post(
            &self.client,
            &self.base.base,
            (Some(auth.0), Some(auth.1)),
            &body,
        )
        .await?;
        assert_eq!(response.status(), 200, "{method} {params}");
        let text = response.text().await.context("read MCP response body")?;
        Ok(frame_payload(&text).to_owned())
    }

    /// One stateless 2026-07-28 JSON-RPC request for `token`, parsed. rmcp
    /// strips the cache hints from results for older peers, so assertions on
    /// `cacheScope` need this version.
    pub(super) async fn call_current(
        &self,
        token: &str,
        method: &str,
        mut params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let meta = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        let object = params
            .as_object_mut()
            .context("request params must be a JSON object")?;
        let _previous_meta = object.insert("_meta".to_owned(), meta);
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 9_u32, "method": method, "params": params });
        let response = self
            .client
            .post(format!("{}/mcp", self.base.base))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", method)
            .body(body.to_string())
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{method} {params}");
        let text = response.text().await.context("read MCP response body")?;
        Ok(serde_json::from_str(frame_payload(&text))?)
    }

    /// [`Self::call_text`], parsed.
    pub(super) async fn call(
        &self,
        auth: (&str, &str),
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_str(
            &self.call_text(auth, method, params).await?,
        )?)
    }

    /// A stateless 2026-07-28 `subscriptions/listen` for `uris`; returns the
    /// HTTP status and every JSON-RPC frame of the response, in order.
    pub(super) async fn listen(
        &self,
        token: &str,
        uris: &[&str],
    ) -> anyhow::Result<(u16, Vec<serde_json::Value>)> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1_u32, "method": "subscriptions/listen",
            "params": {
                "notifications": { "resourceSubscriptions": uris },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let response = self
            .client
            .post(format!("{}/mcp", self.base.base))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "subscriptions/listen")
            .body(body.to_string())
            .send()
            .await?;
        let status = response.status().as_u16();
        let lines = sse_lines(response).await?;
        let frames = if lines.iter().any(|line| line.starts_with("data:")) {
            lines
                .iter()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .filter(|payload| !payload.is_empty())
                .map(serde_json::from_str)
                .collect::<Result<Vec<serde_json::Value>, _>>()?
        } else {
            vec![serde_json::from_str(&lines.concat())?]
        };
        Ok((status, frames))
    }
}

/// The JSON of the first non-empty SSE `data:` line, or the whole body when it
/// is plain JSON.
fn frame_payload(text: &str) -> &str {
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .find(|payload| !payload.is_empty())
        .unwrap_or(text)
}
