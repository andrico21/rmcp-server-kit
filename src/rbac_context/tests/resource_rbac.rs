//! Probe, fixtures and harness for the per-role skills and resources rules
//! (plan B-D4) enforced by [`RbacContextHandler`].
//!
//! The cases live in the two child modules; this module owns what they share:
//! a probe whose answers are scripted per case and whose every method records
//! the identity and role it observes, and a one-handler session that drives
//! full rmcp dispatch request by request.

#[expect(
    deprecated,
    reason = "deliberate: src/rbac_context/tests/resource_rbac.rs::subscribe_request drives the legacy resources/subscribe gate"
)]
use rmcp::{
    model::{
        ListResourcesRequest, ReadResourceRequest, ReadResourceResult, SkillResource,
        SubscribeRequest,
    },
    service::RunningService,
};

use super::*;

mod listing_cases;
mod subscription_cases;

/// A skill the `analyst` role is granted.
const BILLING_SKILL: &str = "skill://acme/billing/SKILL.md";
/// A skill outside every grant.
const HR_SKILL: &str = "skill://acme/hr/SKILL.md";
/// A skill URI that is lexically unsafe.
const UNSAFE_SKILL: &str = "skill://a%2Fb/SKILL.md";
/// A `SKILL.md` manifest outside every registered root.
const UNREGISTERED_MANIFEST: &str = "file:///x/y/SKILL.md";
/// An ordinary resource the `analyst` role may read in restrict mode.
const PUB_FILE: &str = "file:///pub/a.txt";
/// An ordinary resource the `analyst` role may not read in restrict mode.
const PRIV_FILE: &str = "file:///priv/b.txt";
/// The cursor every scripted list carries.
const CURSOR: &str = "c1";

/// A skill named after the last directory of `uri`, with dynamic resources.
fn skill(uri: &str, name: &str) -> Skill {
    Skill::new(
        uri,
        SkillFrontmatter::new(name, "probe skill"),
        SkillResources::Dynamic,
    )
}

/// A granted skill whose manifest lists a file the `analyst` may not read.
fn manifest_with_denied_file() -> Skill {
    let digest = format!("sha256:{}", "0".repeat(64));
    Skill::new(
        "skill://acme/billing/x/SKILL.md",
        SkillFrontmatter::new("x", "probe skill"),
        SkillResources::Files(vec![
            SkillResource::new("skill://acme/billing/x/SKILL.md", digest.clone(), 1),
            SkillResource::new(PRIV_FILE, digest, 1),
        ]),
    )
}

fn resource(uri: &str) -> Resource {
    Resource::new(uri, "probe-resource")
}

/// The scripted mix of granted, denied, unsafe, unregistered and ordinary
/// entries, in a fixed order.
fn mixed_listing() -> Vec<Resource> {
    [
        BILLING_SKILL,
        HR_SKILL,
        UNSAFE_SKILL,
        UNREGISTERED_MANIFEST,
        PUB_FILE,
        PRIV_FILE,
    ]
    .map(resource)
    .to_vec()
}

fn text_contents(uri: &str) -> ResourceContents {
    ResourceContents::text(format!("body of {uri}"), uri)
}

/// How the probe answers `accepted_subscription_filter`.
#[derive(Clone, Copy)]
enum Accept {
    /// Accept exactly the requested filter.
    Echo,
    /// Return `None` unless a requested resource URI is in the list; else
    /// accept only the existing ones.
    ExistingOnly(&'static [&'static str]),
    /// Accept the requested filter plus one URI that was not requested.
    EchoPlus(&'static str),
}

/// Everything a probe answers, fixed per case. The probe sets `cache_scope`
/// only when `public_ttl` is `Some`.
#[derive(Clone)]
struct Script {
    listing: Vec<Resource>,
    skills: Vec<Skill>,
    skill: Skill,
    read: ReadResourceResponse,
    public_ttl: Option<u64>,
    accept: Accept,
    /// Installed into the shared policy when a subscription is accepted.
    reload_on_accept: Option<(Arc<ArcSwap<RbacPolicy>>, Arc<RbacPolicy>)>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            listing: mixed_listing(),
            skills: vec![skill(BILLING_SKILL, "billing"), skill(HR_SKILL, "hr")],
            skill: skill(BILLING_SKILL, "billing"),
            read: ReadResourceResponse::Complete(ReadResourceResult::new(vec![text_contents(
                PUB_FILE,
            )])),
            public_ttl: None,
            accept: Accept::Echo,
            reload_on_accept: None,
        }
    }
}

/// Scripted inner handler. Every request method records
/// `(method, current_identity(), current_role())`; `get_info` is silent
/// because rmcp calls it on every gated request.
#[derive(Clone)]
struct ResourceProbe {
    script: Arc<Script>,
    seen: Arc<Mutex<Vec<SkillCall>>>,
    filters: Arc<Mutex<Vec<SubscriptionFilter>>>,
}

impl ResourceProbe {
    fn new(script: Script) -> Self {
        Self {
            script: Arc::new(script),
            seen: Arc::new(Mutex::new(Vec::new())),
            filters: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record(&self, method: &str) {
        let call = (
            method.to_owned(),
            rbac::current_identity(),
            rbac::current_role(),
        );
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    fn seen(&self) -> Vec<SkillCall> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every filter `accepted_subscription_filter` received, in order.
    fn filters(&self) -> Vec<SubscriptionFilter> {
        self.filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn listing(&self) -> ListResourcesResult {
        let mut listed = ListResourcesResult::with_all_items(self.script.listing.clone());
        listed.next_cursor = Some(CURSOR.to_owned());
        listed
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "deliberate: src/rbac_context/tests/resource_rbac.rs::ResourceProbe implements rmcp's async ServerHandler; the in-memory probe returns immediately"
)]
impl ServerHandler for ResourceProbe {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_skills_with_directory_read()
                .build(),
        )
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.record("list_resources");
        Ok(self.listing())
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn read_resource_directory(
        &self,
        _request: ReadResourceDirectoryRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceDirectoryResult, ErrorData> {
        self.record("read_resource_directory");
        Ok(self.listing())
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListSkillsResult, ErrorData> {
        self.record("list_skills");
        let mut listed = ListSkillsResult::with_all_items(self.script.skills.clone());
        listed.next_cursor = Some(CURSOR.to_owned());
        Ok(listed)
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn get_skill(
        &self,
        _request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetSkillResult, ErrorData> {
        self.record("get_skill");
        let fetched = GetSkillResult::new(self.script.skill.clone());
        Ok(match self.script.public_ttl {
            Some(ttl) => fetched
                .with_cache_scope(CacheScope::Public)
                .with_ttl_ms(ttl),
            None => fetched,
        })
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn read_resource(
        &self,
        _request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.record("read_resource");
        Ok(match (self.script.read.clone(), self.script.public_ttl) {
            (ReadResourceResponse::Complete(result), Some(ttl)) => ReadResourceResponse::Complete(
                result.with_cache_scope(CacheScope::Public).with_ttl_ms(ttl),
            ),
            (scripted, _) => scripted,
        })
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn subscribe(
        &self,
        _request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.record("subscribe");
        Ok(())
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(requested.clone());
        if let Some((shared, reloaded)) = self.script.reload_on_accept.as_ref() {
            shared.store(Arc::clone(reloaded));
        }
        match self.script.accept {
            Accept::Echo => Some(requested.clone()),
            Accept::ExistingOnly(existing) => {
                let present: Vec<String> = requested
                    .resource_subscriptions
                    .iter()
                    .flatten()
                    .filter(|uri| existing.contains(&uri.as_str()))
                    .cloned()
                    .collect();
                if present.is_empty() {
                    return None;
                }
                let mut accepted = requested.clone();
                accepted.resource_subscriptions = Some(present);
                Some(accepted)
            }
            Accept::EchoPlus(extra) => {
                let mut accepted = requested.clone();
                accepted
                    .resource_subscriptions
                    .get_or_insert_default()
                    .push(extra.to_owned());
                Some(accepted)
            }
        }
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn listen(&self, _context: SubscriptionContext) -> Result<(), ErrorData> {
        self.record("listen");
        Ok(())
    }
}

/// An RBAC-enabled policy with roles `analyst` (skills `analyst_skills`; in
/// restrict mode also `resources = ["file:///pub/*"]`) and `legacy`
/// (neither setting).
fn analyst_policy(restrict: bool, analyst_skills: &[&str]) -> RbacPolicy {
    let skills = analyst_skills
        .iter()
        .map(|grant| (*grant).to_owned())
        .collect();
    let mut analyst = RoleConfig::new("analyst", vec![], vec!["*".to_owned()]).with_skills(skills);
    if restrict {
        analyst = analyst.with_resources(vec!["file:///pub/*".to_owned()]);
    }
    let legacy = RoleConfig::new("legacy", vec![], vec!["*".to_owned()]);
    RbacPolicy::new(
        &RbacConfig::with_roles(vec![analyst, legacy]).with_restrict_resources(restrict),
    )
}

fn shared(policy: RbacPolicy) -> Arc<ArcSwap<RbacPolicy>> {
    Arc::new(ArcSwap::from_pointee(policy))
}

/// The identity of a caller holding `role`.
fn caller(role: &str) -> AuthIdentity {
    AuthIdentity {
        granted_scopes: None,
        name: format!("{role}-key"),
        role: role.to_owned(),
        method: AuthMethod::BearerToken,
        raw_token: None,
        sub: None,
    }
}

/// The log entry of `method` called inside the scope of `role`, or outside
/// any scope when `role` is `None`.
fn seen_as(method: &str, role: Option<&str>) -> SkillCall {
    (
        method.to_owned(),
        role.map(|name| format!("{name}-key")),
        role.map(str::to_owned),
    )
}

/// `request` as JSON-RPC id `id`, carrying the identity of `role` (none for
/// an unresolved caller).
fn sent_as(
    request: ClientRequest,
    id: i64,
    role: Option<&str>,
) -> anyhow::Result<ClientJsonRpcMessage> {
    let mut message = request_message(request, id);
    if let Some(name) = role {
        attach_identity(&mut message, caller(name))?;
    }
    Ok(message)
}

fn list_resources_request() -> ClientRequest {
    ClientRequest::ListResourcesRequest(ListResourcesRequest::with_param(
        PaginatedRequestParams::default(),
    ))
}

fn read_request(uri: &str) -> ClientRequest {
    ClientRequest::ReadResourceRequest(ReadResourceRequest::new(ReadResourceRequestParams::new(
        uri,
    )))
}

fn directory_request(uri: &str) -> ClientRequest {
    ClientRequest::ReadResourceDirectoryRequest(ReadResourceDirectoryRequest::new(
        ReadResourceDirectoryRequestParams::new(uri),
    ))
}

fn get_skill_at(uri: &str) -> ClientRequest {
    ClientRequest::GetSkillRequest(GetSkillRequest::new(GetSkillRequestParams::new(uri)))
}

#[expect(
    deprecated,
    reason = "deliberate: src/rbac_context/tests/resource_rbac.rs::subscribe_request drives the legacy resources/subscribe gate"
)]
fn subscribe_request(uri: &str) -> ClientRequest {
    ClientRequest::SubscribeRequest(SubscribeRequest::new(SubscribeRequestParams::new(uri)))
}

/// A 2026-07-28 `subscriptions/listen` for `filter` as JSON-RPC id `id`.
fn listen_as(
    filter: SubscriptionFilter,
    id: i64,
    role: &str,
) -> anyhow::Result<ClientJsonRpcMessage> {
    let mut meta = RequestMetaObject::default();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_capabilities(ClientCapabilities::default());
    let mut params = SubscriptionsListenRequestParams::new(filter);
    params.meta = Some(meta.clone());
    let request =
        ClientRequest::SubscriptionsListenRequest(SubscriptionsListenRequest::new(params));
    let mut message = sent_as(request, id, Some(role))?;
    attach_meta(&mut message, meta)?;
    Ok(message)
}

/// The URIs of a listing, in order.
fn uris(listed: &ListResourcesResult) -> Vec<String> {
    listed
        .resources
        .iter()
        .map(|entry| entry.uri.clone())
        .collect()
}

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|uri| (*uri).to_owned()).collect()
}

fn not_found() -> ErrorData {
    ErrorData::resource_not_found("resource not found", None)
}

fn unknown_skill() -> ErrorData {
    ErrorData::invalid_params("unknown skill", None)
}

/// One `RbacContextHandler` around a probe, served over a channel so a case
/// can change the shared policy between requests and read every frame.
struct Session {
    inbound: mpsc::UnboundedSender<ClientJsonRpcMessage>,
    outbound: mpsc::UnboundedReceiver<ServerJsonRpcMessage>,
    running: RunningService<RoleServer, RbacContextHandler<ResourceProbe>>,
}

impl Session {
    fn start(probe: ResourceProbe, rbac: Arc<ArcSwap<RbacPolicy>>, filtering: bool) -> Self {
        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound) = mpsc::unbounded_channel();
        let handler = RbacContextHandler::new(probe, rbac, filtering);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(
            handler,
            ChannelTransport {
                inbound: inbound_rx,
                outbound: outbound_tx,
            },
            None,
        );
        Self {
            inbound,
            outbound,
            running,
        }
    }

    fn send(&self, message: ClientJsonRpcMessage) -> anyhow::Result<()> {
        self.inbound
            .send(message)
            .map_err(|_closed| anyhow::anyhow!("service stopped receiving"))
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    /// The next frame the client receives, within a bounded wait.
    async fn next_frame(&mut self) -> anyhow::Result<ServerJsonRpcMessage> {
        timeout(Duration::from_secs(1), self.outbound.recv())
            .await
            .context("bounded wait for the next frame")?
            .context("service closed before answering")
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    /// Send one request and return the frame answering it.
    async fn exchange(
        &mut self,
        message: ClientJsonRpcMessage,
    ) -> anyhow::Result<ServerJsonRpcMessage> {
        self.send(message)?;
        self.next_frame().await
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn finish(self) -> anyhow::Result<()> {
        drop(self.inbound);
        let _quit_reason = self.running.waiting().await.context("service task joins")?;
        Ok(())
    }
}

// cancel-safe: in-memory test code; no lock, permit or state outlives an await.
/// Dispatch one request through a fresh session and return its frame.
async fn dispatch(
    probe: &ResourceProbe,
    rbac: Arc<ArcSwap<RbacPolicy>>,
    message: ClientJsonRpcMessage,
) -> anyhow::Result<ServerJsonRpcMessage> {
    let mut session = Session::start(probe.clone(), rbac, false);
    let frame = session.exchange(message).await?;
    session.finish().await?;
    Ok(frame)
}

fn expect_listing(frame: ServerJsonRpcMessage) -> anyhow::Result<ListResourcesResult> {
    let result = expect_response(frame)?;
    let ServerResult::ListResourcesResult(listed) = result else {
        anyhow::bail!("expected a resource listing, got {result:?}")
    };
    Ok(listed)
}

/// The acknowledged filter, or an error naming what arrived instead.
fn expect_acknowledgement(frame: ServerJsonRpcMessage) -> anyhow::Result<SubscriptionFilter> {
    let ServerJsonRpcMessage::Notification(notification) = frame else {
        anyhow::bail!("expected the acknowledgement, got {frame:?}")
    };
    let ServerNotification::SubscriptionsAcknowledgedNotification(ack) = notification.notification
    else {
        anyhow::bail!("expected the acknowledgement, got {notification:?}")
    };
    Ok(ack.params.notifications)
}

fn expect_skills(frame: ServerJsonRpcMessage) -> anyhow::Result<ListSkillsResult> {
    let result = expect_response(frame)?;
    let ServerResult::ListSkillsResult(listed) = result else {
        anyhow::bail!("expected a skills listing, got {result:?}")
    };
    Ok(listed)
}
