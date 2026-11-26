//! URI constants, scripted answers, role and policy builders, identities and
//! request builders shared by the resource RBAC cases.

#[expect(
    deprecated,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/fixtures.rs::subscribe_request drives the legacy resources/subscribe gate"
)]
use rmcp::model::SubscribeRequest;

use super::*;
/// A skill the `analyst` role is granted.
pub(super) const BILLING_SKILL: &str = "skill://acme/billing/SKILL.md";
/// A skill outside every grant.
pub(super) const HR_SKILL: &str = "skill://acme/hr/SKILL.md";
/// A skill URI that is lexically unsafe.
pub(super) const UNSAFE_SKILL: &str = "skill://a%2Fb/SKILL.md";
/// A `SKILL.md` manifest outside every registered root.
pub(super) const UNREGISTERED_MANIFEST: &str = "file:///x/y/SKILL.md";
/// An ordinary resource the `analyst` role may read in restrict mode.
pub(super) const PUB_FILE: &str = "file:///pub/a.txt";
/// An ordinary resource the `analyst` role may not read in restrict mode.
pub(super) const PRIV_FILE: &str = "file:///priv/b.txt";
/// The cursor every scripted list carries.
pub(super) const CURSOR: &str = "c1";

/// A skill named after the last directory of `uri`, with dynamic resources.
pub(super) fn skill(uri: &str, name: &str) -> Skill {
    Skill::new(
        uri,
        SkillFrontmatter::new(name, "probe skill"),
        SkillResources::Dynamic,
    )
}

/// A granted skill whose manifest lists a file the `analyst` may not read.
pub(super) fn manifest_with_denied_file() -> Skill {
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

pub(super) fn resource(uri: &str) -> Resource {
    Resource::new(uri, "probe-resource")
}

/// The scripted mix of granted, denied, unsafe, unregistered and ordinary
/// entries, in a fixed order.
pub(super) fn mixed_listing() -> Vec<Resource> {
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

pub(super) fn text_contents(uri: &str) -> ResourceContents {
    ResourceContents::text(format!("body of {uri}"), uri)
}

/// How the probe answers `accepted_subscription_filter`.
#[derive(Clone, Copy)]
pub(super) enum Accept {
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
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/fixtures.rs::Script fields are built by the sibling case modules"
)]
pub(super) struct Script {
    pub(super) listing: Vec<Resource>,
    pub(super) skills: Vec<Skill>,
    pub(super) skill: Skill,
    pub(super) read: ReadResourceResponse,
    pub(super) public_ttl: Option<u64>,
    pub(super) accept: Accept,
    /// Installed into the shared policy when a subscription is accepted.
    pub(super) reload_on_accept: Option<(Arc<ArcSwap<RbacPolicy>>, Arc<RbacPolicy>)>,
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

/// An RBAC-enabled policy with roles `analyst` (skills `analyst_skills`; in
/// restrict mode also `resources = ["file:///pub/*"]`) and `legacy`
/// (neither setting).
pub(super) fn analyst_policy(restrict: bool, analyst_skills: &[&str]) -> RbacPolicy {
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

pub(super) fn shared(policy: RbacPolicy) -> Arc<ArcSwap<RbacPolicy>> {
    Arc::new(ArcSwap::from_pointee(policy))
}

/// The identity of a caller holding `role`.
pub(super) fn caller(role: &str) -> AuthIdentity {
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
pub(super) fn seen_as(method: &str, role: Option<&str>) -> SkillCall {
    (
        method.to_owned(),
        role.map(|name| format!("{name}-key")),
        role.map(str::to_owned),
    )
}

/// `request` as JSON-RPC id `id`, carrying the identity of `role` (none for
/// an unresolved caller).
pub(super) fn sent_as(
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

pub(super) fn list_resources_request() -> ClientRequest {
    ClientRequest::ListResourcesRequest(ListResourcesRequest::with_param(
        PaginatedRequestParams::default(),
    ))
}

pub(super) fn read_request(uri: &str) -> ClientRequest {
    ClientRequest::ReadResourceRequest(ReadResourceRequest::new(ReadResourceRequestParams::new(
        uri,
    )))
}

pub(super) fn directory_request(uri: &str) -> ClientRequest {
    ClientRequest::ReadResourceDirectoryRequest(ReadResourceDirectoryRequest::new(
        ReadResourceDirectoryRequestParams::new(uri),
    ))
}

pub(super) fn get_skill_at(uri: &str) -> ClientRequest {
    ClientRequest::GetSkillRequest(GetSkillRequest::new(GetSkillRequestParams::new(uri)))
}

#[expect(
    deprecated,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/fixtures.rs::subscribe_request drives the legacy resources/subscribe gate"
)]
pub(super) fn subscribe_request(uri: &str) -> ClientRequest {
    ClientRequest::SubscribeRequest(SubscribeRequest::new(SubscribeRequestParams::new(uri)))
}

/// A 2026-07-28 `subscriptions/listen` for `filter` as JSON-RPC id `id`.
pub(super) fn listen_as(
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
pub(super) fn uris(listed: &ListResourcesResult) -> Vec<String> {
    listed
        .resources
        .iter()
        .map(|entry| entry.uri.clone())
        .collect()
}

pub(super) fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|uri| (*uri).to_owned()).collect()
}

pub(super) fn not_found() -> ErrorData {
    ErrorData::resource_not_found("resource not found", None)
}

pub(super) fn unknown_skill() -> ErrorData {
    ErrorData::invalid_params("unknown skill", None)
}

/// The exact JSON-RPC error frame for `error` answering id `id`.
pub(super) fn error_frame(id: i64, error: &ErrorData) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": serde_json::to_value(error)?,
    }))
}
