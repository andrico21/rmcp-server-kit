//! Plan B4: per-role skills and resources RBAC through `serve()`.
//!
//! One handler serves four skills (three under `skill://`, one under the
//! extra root `file:///srv/skills/`), each with a `SKILL.md` and one extra
//! file, plus two ordinary resources. It resolves the received URI string
//! literally and records every request it answers, so a log that lacks a
//! URI proves the request never reached it. Every server runs with both
//! wrappers, API-key auth, RBAC and tool-list filtering on.

use rmcp::{
    model::{CacheScope, SkillResource, SubscribeRequestParams, SubscriptionFilter},
    service::SubscriptionContext,
};
use rmcp_server_kit::{error::RmcpServerKitError, transport::ReloadHandle};

use super::*;

mod assertions;
mod policy_cases;

/// The four skill directories and their skill names.
const SKILL_DIRS: [(&str, &str); 4] = [
    ("skill://acme/billing/", "billing"),
    ("skill://acme/hr/", "hr"),
    ("skill://other/x/", "x"),
    ("file:///srv/skills/hr2/", "hr2"),
];
const BILLING_MD: &str = "skill://acme/billing/SKILL.md";
const BILLING_NOTES: &str = "skill://acme/billing/notes.md";
const HR_MD: &str = "skill://acme/hr/SKILL.md";
const HR2_MD: &str = "file:///srv/skills/hr2/SKILL.md";
const PUB: &str = "file:///pub/a.txt";
const PRIV: &str = "file:///priv/b.txt";

/// A skill with a manifest listing its `SKILL.md` and `notes.md`.
fn skill_in(dir: &str, name: &str) -> Skill {
    let digest = format!("sha256:{}", "a".repeat(64));
    let entry = format!("{dir}SKILL.md");
    Skill::new(
        entry.clone(),
        SkillFrontmatter::new(name, "rbac skills e2e"),
        SkillResources::Files(vec![
            SkillResource::new(entry, digest.clone(), 1),
            SkillResource::new(format!("{dir}notes.md"), digest, 1),
        ]),
    )
}

fn all_skills() -> Vec<Skill> {
    SKILL_DIRS
        .iter()
        .map(|(dir, name)| skill_in(dir, name))
        .collect()
}

/// Every URI the handler can resolve, in its listing order.
fn all_files() -> Vec<String> {
    let mut files: Vec<String> = SKILL_DIRS
        .iter()
        .flat_map(|(dir, _)| [format!("{dir}SKILL.md"), format!("{dir}notes.md")])
        .collect();
    files.extend([PUB.to_owned(), PRIV.to_owned()]);
    files
}

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|uri| (*uri).to_owned()).collect()
}

/// Serves the fixtures, resolving each URI literally and recording every
/// call as `"<method> <uri>"` (or the bare method for listings).
#[derive(Clone, Default)]
struct RbacSkillsHandler {
    calls: Arc<StdMutex<Vec<String>>>,
}

impl RbacSkillsHandler {
    fn record(&self, call: String) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ServerHandler for RbacSkillsHandler {
    fn get_info(&self) -> RmcpServerConfig {
        RmcpServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_skills_with_directory_read()
                .build(),
        )
    }

    fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListSkillsResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record("list_skills".to_owned());
        ready(Ok(ListSkillsResult::with_all_items(all_skills())))
    }

    fn get_skill(
        &self,
        request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetSkillResult, rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record(format!("get_skill {}", request.uri));
        ready(
            all_skills()
                .into_iter()
                .find(|skill| skill.uri == request.uri)
                .map(GetSkillResult::new)
                .ok_or_else(|| rmcp::ErrorData::invalid_params("no such skill", None)),
        )
    }

    fn read_resource_directory(
        &self,
        request: ReadResourceDirectoryRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceDirectoryResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record(format!("read_resource_directory {}", request.uri));
        let entries = all_files()
            .into_iter()
            .filter(|uri| uri.starts_with(&request.uri))
            .map(|uri| Resource::new(uri, "file"))
            .collect();
        ready(Ok(ListResourcesResult::with_all_items(entries)))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record("list_resources".to_owned());
        ready(Ok(ListResourcesResult::with_all_items(
            all_files()
                .into_iter()
                .map(|uri| Resource::new(uri, "file"))
                .collect(),
        )))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record(format!("read_resource {}", request.uri));
        ready(if all_files().contains(&request.uri) {
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                format!("body of {}", request.uri),
                request.uri,
            )])
            .into())
        } else {
            Err(rmcp::ErrorData::resource_not_found(
                "no such resource",
                None,
            ))
        })
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record(format!("subscribe {}", request.uri));
        ready(Ok(()))
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.record(format!(
            "accepted_subscription_filter {:?}",
            requested.resource_subscriptions
        ));
        let known = all_files();
        let existing: Vec<String> = requested
            .resource_subscriptions
            .iter()
            .flatten()
            .filter(|uri| known.contains(uri))
            .cloned()
            .collect();
        if existing.is_empty() {
            return None;
        }
        let mut accepted = requested.clone();
        accepted.resource_subscriptions = Some(existing);
        Some(accepted)
    }

    fn listen(
        &self,
        _context: SubscriptionContext,
    ) -> impl Future<Output = Result<(), rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record("listen".to_owned());
        ready(Ok(()))
    }
}

/// The main `[rbac]`: extra root `file:///srv/skills/`, restrict mode on,
/// `analyst` with `analyst_skills` and `resources = ["file:///pub/*"]`, and
/// `legacy` with neither setting.
fn main_rbac(analyst_skills: &[&str]) -> RbacConfig {
    RbacConfig::with_roles(vec![
        RoleConfig::new("analyst", vec![], vec!["*".into()])
            .with_skills(owned(analyst_skills))
            .with_resources(owned(&["file:///pub/*"])),
        RoleConfig::new("legacy", vec![], vec!["*".into()]),
    ])
    .with_skill_roots(owned(&["file:///srv/skills/"]))
    .with_restrict_resources(true)
}

/// `config` after `RbacConfig::validate`, as a policy.
fn validated(config: &RbacConfig) -> anyhow::Result<RbacPolicy> {
    config.validate().context("rbac config validates")?;
    Ok(RbacPolicy::new(config))
}

/// A running server plus the credentials and reload handle of one case.
struct RbacSkillsServer {
    base: ServerHarness,
    handler: RbacSkillsHandler,
    reload: ReloadHandle,
    client: reqwest::Client,
    analyst: String,
    legacy: String,
}

impl RbacSkillsServer {
    async fn start(policy: RbacPolicy) -> anyhow::Result<Self> {
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
    async fn session(&self, token: &str) -> anyhow::Result<String> {
        mcp_initialize_with_bearer(&self.client, &self.base.base, Some(token)).await
    }

    /// One JSON-RPC request on a legacy session; returns the raw JSON text
    /// of the single response frame.
    async fn call_text(
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
        let payload = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .find(|payload| !payload.is_empty())
            .unwrap_or(text.as_str());
        Ok(payload.to_owned())
    }

    /// [`Self::call_text`], parsed.
    async fn call(
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
    async fn listen(
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

/// The exact legacy-protocol error frame for JSON-RPC id 9.
fn error_frame(code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 9_u32, "error": { "code": code, "message": message }
    })
}

/// Legacy peers receive resource-not-found as `-32002` (plan G7).
fn not_found() -> serde_json::Value {
    error_frame(-32_002, "resource not found")
}

fn unknown_skill() -> serde_json::Value {
    error_frame(-32_602, "unknown skill")
}

/// The URIs of a listing frame, in order.
fn listed_uris(frame: &serde_json::Value) -> anyhow::Result<Vec<String>> {
    let listed: ListResourcesResult = frame_result(frame)?;
    Ok(listed
        .resources
        .into_iter()
        .map(|entry| entry.uri)
        .collect())
}

/// The cache scope of a result frame.
fn cache_scope(frame: &serde_json::Value) -> anyhow::Result<Option<CacheScope>> {
    Ok(frame
        .pointer("/result/cacheScope")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?)
}

fn uri_params(uri: &str) -> serde_json::Value {
    serde_json::json!({ "uri": uri })
}

/// The `Config` variant of a failed `validate`, or an error naming the result.
fn expect_config_error(config: &RbacConfig) -> anyhow::Result<()> {
    match config.validate() {
        Err(RmcpServerKitError::Config(_)) => Ok(()),
        other => anyhow::bail!("validate must return Config, got {other:?}"),
    }
}
