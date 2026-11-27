//! RBAC request-context propagation for `ServerHandler` calls.
//!
//! # Cancel safety
//!
//! The async wrappers in this module are cancel-safe with respect to this
//! module's state.  They extract request identity, install the Tokio
//! task-local RBAC scope around the delegated future, and await the wrapped
//! `ServerHandler`.  Dropping the future drops that task-local scope and
//! does not leak roles, tokens, locks, permits, or other guards.  The
//! wrapped consumer handler's own cancel-safety contract is inherited
//! unchanged.
extern crate alloc;

use alloc::{borrow::Cow, sync::Arc};

use arc_swap::ArcSwap;
use axum::http::request::Parts;
#[expect(
    deprecated,
    reason = "ServerHandler delegation must import legacy logging/subscription parameter types until rmcp removes those methods"
)]
use rmcp::{
    ErrorData, ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CancelTaskParams,
        CancelledNotificationParam, CompleteRequestParams, CompleteResult, CustomNotification,
        CustomRequest, CustomResult, DiscoverResult, ErrorCode, Extensions, GetPromptRequestParams,
        GetPromptResponse, GetSkillRequestMethod, GetSkillRequestParams, GetSkillResult,
        GetTaskParams, GetTaskResult, InitializeRequestParams, InitializeResult, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListSkillsRequestMethod,
        ListSkillsResult, ListToolsResult, PaginatedRequestParams, ProgressNotificationParam,
        ProtocolVersion, ReadResourceDirectoryRequestMethod, ReadResourceDirectoryRequestParams,
        ReadResourceDirectoryResult, ReadResourceRequestParams, ReadResourceResponse,
        ResourceContents, ServerConfig, SetLevelRequestParams, Skill, SkillResources,
        SubscribeRequestParams, SubscriptionFilter, Tool, UnsubscribeRequestParams,
        UpdateTaskParams,
    },
    service::{NotificationContext, RequestContext, RoleServer, SubscriptionContext},
};

use crate::{
    auth::AuthIdentity,
    rbac::{self, RbacDecision, RbacPolicy},
    secret::SecretString,
    session_binding::{IdentityFingerprint, SessionBindingSecret, fingerprint},
    task_binding::{self, RawTaskId},
};

/// Owns RBAC request context and RBAC-derived list visibility.
#[derive(Debug, Clone)]
pub(crate) struct RbacContextHandler<H> {
    /// The wrapped handler.
    inner: H,
    /// Shared, reloadable RBAC policy.
    rbac: Arc<ArcSwap<RbacPolicy>>,
    /// Whether `tools/list` results are filtered by role.
    tool_list_filtering_enabled: bool,
    /// When `Some`, task IDs crossing this boundary are HMAC-bound to the
    /// authenticated identity. `None` leaves them untouched.
    task_binding: Option<SessionBindingSecret>,
}

impl<H> RbacContextHandler<H> {
    /// Construct a handler around `inner` using `rbac`.
    #[must_use]
    pub(crate) const fn new(
        inner: H,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        tool_list_filtering_enabled: bool,
    ) -> Self {
        Self {
            inner,
            rbac,
            tool_list_filtering_enabled,
            task_binding: None,
        }
    }

    /// Enable identity-bound task IDs using `secret`.
    #[must_use]
    pub(crate) fn with_task_binding(mut self, secret: Option<SessionBindingSecret>) -> Self {
        self.task_binding = secret;
        self
    }

    /// Resolve the (secret, fingerprint) pair needed to bind a task ID.
    ///
    /// Returns `None` when binding is disabled or the request carries no
    /// authenticated identity, mirroring the session-binding no-op so
    /// unauthenticated deployments keep working unchanged.
    fn task_binding_for(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Option<(&SessionBindingSecret, IdentityFingerprint)> {
        let secret = self.task_binding.as_ref()?;
        let identity = identity_from_request(context)?;
        Some((secret, fingerprint(&identity)))
    }

    /// Apply role-based filtering to a `tools/list` result.
    fn filtered_tool_list(
        &self,
        mut result: ListToolsResult,
        role: Option<&str>,
    ) -> ListToolsResult {
        let policy = self.rbac.load_full();
        let Some(role_name) = role else {
            return result;
        };
        if !self.tool_list_filtering_enabled || !policy.is_enabled() || role_name.is_empty() {
            return result;
        }

        result
            .tools
            .retain(|tool| policy.check_operation(role_name, &tool.name) == RbacDecision::Allow);
        result.with_cache_scope(CacheScope::Private)
    }
}

/// Skill and resource method names refused as custom fallbacks under RBAC.
///
/// A request whose params fail rmcp's typed variant would otherwise reach
/// the consumer without the per-role checks.
const RESERVED_CUSTOM_METHODS: [&str; 9] = [
    "skills/list",
    "skills/get",
    "resources/directory/read",
    "resources/read",
    "resources/list",
    "resources/templates/list",
    "resources/subscribe",
    "resources/unsubscribe",
    "subscriptions/listen",
];

/// The fixed not-found error for a denied resource; identical for a
/// denied existing and a missing resource.
fn resource_not_found() -> ErrorData {
    ErrorData::resource_not_found("resource not found", None)
}

/// The fixed error for a denied skill; identical for a denied existing and
/// a missing skill.
fn unknown_skill() -> ErrorData {
    ErrorData::invalid_params("unknown skill", None)
}

/// Log an RBAC skills/resources denial with the method and role only, never
/// the URI, params or skill name.
fn log_denial(method: &'static str, role: Option<&str>) {
    tracing::debug!(
        method,
        role = role.unwrap_or_default(),
        "RBAC denied skills/resources request"
    );
}

/// The URI of one `resources/read` content entry; `None` (denied) for a
/// content kind this crate does not know.
fn contents_uri(contents: &ResourceContents) -> Option<&str> {
    match contents {
        ResourceContents::TextResourceContents {
            uri,
            mime_type: _,
            text: _,
            meta: _,
        }
        | ResourceContents::BlobResourceContents {
            uri,
            mime_type: _,
            blob: _,
            meta: _,
        } => Some(uri),
        _ => None,
    }
}

/// Whether `skill` may be shown to `role`: its URI is a granted SKILL URI
/// and every manifest file is accessible. An unknown manifest kind is
/// refused.
fn skill_visible(policy: &RbacPolicy, role: Option<&str>, skill: &Skill) -> bool {
    if !policy.is_skill_uri(&skill.uri) || !policy.resource_access(role, &skill.uri) {
        return false;
    }
    match &skill.resources {
        SkillResources::Files(files) => files
            .iter()
            .all(|file| policy.resource_access(role, &file.uri)),
        SkillResources::Dynamic => true,
        _ => false,
    }
}

/// `requested` with every resource URI that is not universally allowed
/// removed; an emptied list becomes `None`.
fn sanitized_filter(policy: &RbacPolicy, requested: &SubscriptionFilter) -> SubscriptionFilter {
    let mut sanitized = requested.clone();
    sanitized.resource_subscriptions =
        universally_allowed_uris(policy, sanitized.resource_subscriptions);
    sanitized
}

/// Keep the universally allowed URIs; an empty result becomes `None`.
fn universally_allowed_uris(policy: &RbacPolicy, uris: Option<Vec<String>>) -> Option<Vec<String>> {
    uris.map(|mut list| {
        list.retain(|uri| policy.universally_allowed(uri));
        list
    })
    .filter(|list| !list.is_empty())
}

/// Extract the authenticated identity from a request's extensions, if any.
fn identity_from_request(context: &RequestContext<RoleServer>) -> Option<AuthIdentity> {
    context_identity(&context.extensions)
}

/// Verify an external task ID and recover the raw ID the handler knows.
///
/// SECURITY: every failure mode - malformed, unwrapped, signed for a different
/// identity, or signed under a rotated secret - collapses to the *same* error
/// that upstream `rmcp` returns for a genuinely unknown task
/// (`McpError::invalid_params("unknown task: ...")`). Distinguishing them would
/// turn this into an oracle that confirms a task's existence to a non-owner.
///
/// # Errors
///
/// Returns the same `unknown task: <id>` error for every verification failure:
/// malformed, unwrapped, foreign-identity, or rotated-secret IDs.
fn unbind_task_id(
    secret: &SessionBindingSecret,
    external_id: &str,
    fp: &IdentityFingerprint,
) -> Result<RawTaskId, ErrorData> {
    task_binding::unwrap_and_verify(secret, external_id, fp).ok_or_else(|| {
        tracing::warn!("task binding rejected request");
        ErrorData::invalid_params(format!("unknown task: {external_id}"), None)
    })
}

/// Extract the authenticated identity from a notification's extensions, if any.
fn identity_from_notification(context: &NotificationContext<RoleServer>) -> Option<AuthIdentity> {
    context_identity(&context.extensions)
}

/// Extract the authenticated identity from a subscription's request context.
fn identity_from_subscription(context: &SubscriptionContext) -> Option<AuthIdentity> {
    identity_from_request(context.request_context())
}

/// Pull the [`AuthIdentity`] stored in the request extensions, if any.
fn context_identity(extensions: &Extensions) -> Option<AuthIdentity> {
    extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AuthIdentity>())
        .cloned()
}

/// Run `call` inside the RBAC task-local scope for `identity`, if any.
///
/// A missing identity or an empty role runs `call` unscoped, mirroring the
/// no-auth deployment behavior.
// cancel-safe: installs the RBAC task-local scope around `call` and drops it
// with this future; no role, token or guard outlives cancellation.
async fn scope_with_identity<T, F, Fut>(identity: Option<AuthIdentity>, call: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let Some(authenticated) = identity else {
        return call().await;
    };
    if authenticated.role.is_empty() {
        return call().await;
    }

    let token = authenticated
        .raw_token
        .unwrap_or_else(|| SecretString::from(String::new()));
    let sub = authenticated.sub.unwrap_or_default();
    rbac::with_rbac_scope_lazy(authenticated.role, authenticated.name, token, sub, call).await
}

// The methods generated by these two macros delegate through
// `scope_with_identity`, so they inherit its cancel-safety contract: dropping
// the future drops the identity scope installed for the delegated call.
/// Generate request-handling `ServerHandler` methods that scope the request
/// identity around the inner call.
macro_rules! delegate_request {
    ($name:ident, $params:ident, $output:ty) => {
        async fn $name(
            &self,
            request: $params,
            context: RequestContext<RoleServer>,
        ) -> Result<$output, ErrorData> {
            let identity = identity_from_request(&context);
            scope_with_identity(identity, || self.inner.$name(request, context)).await
        }
    };
    ($name:ident, Option<$params:ident>, $output:ty) => {
        async fn $name(
            &self,
            request: Option<$params>,
            context: RequestContext<RoleServer>,
        ) -> Result<$output, ErrorData> {
            let identity = identity_from_request(&context);
            scope_with_identity(identity, || self.inner.$name(request, context)).await
        }
    };
}

/// Generate notification-handling `ServerHandler` methods that scope the
/// notification identity around the inner call.
macro_rules! delegate_notification {
    ($name:ident, $params:ident) => {
        async fn $name(&self, notification: $params, context: NotificationContext<RoleServer>) {
            let identity = identity_from_notification(&context);
            scope_with_identity(identity, || self.inner.$name(notification, context)).await;
        }
    };
}

#[expect(
    deprecated,
    reason = "ServerHandler delegation must include the legacy subscribe/unsubscribe methods until rmcp removes them"
)]
impl<H: ServerHandler> ServerHandler for RbacContextHandler<H> {
    // cancel-safe: scopes the request identity around the inner call;
    // cancellation drops only the scoped future.
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.ping(context)).await
    }

    // cancel-safe: scopes the request identity around the inner call;
    // cancellation drops only the scoped future.
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.initialize(request, context)).await
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    // Synchronous and context-free: there is no request identity to scope, so
    // plain delegation is required - the trait default would shadow an inner
    // override.
    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.negotiate_initialize(request)
    }

    // cancel-safe: scopes the request identity around the inner call;
    // cancellation drops only the scoped future.
    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.discover(context)).await
    }

    delegate_request!(complete, CompleteRequestParams, CompleteResult);
    delegate_request!(set_level, SetLevelRequestParams, ());
    delegate_request!(get_prompt, GetPromptRequestParams, GetPromptResponse);
    delegate_request!(
        list_prompts,
        Option<PaginatedRequestParams>,
        ListPromptsResult
    );
    // Under RBAC the consumer is always called and the result is filtered
    // per role; the filtered result is private to the caller.
    // cancel-safe: filtering runs on the local result after the delegated
    // await; cancellation drops only those locals.
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        let mut result =
            scope_with_identity(identity, || self.inner.list_resources(request, context)).await?;
        if !policy.is_enabled() {
            return Ok(result);
        }
        result
            .resources
            .retain(|resource| policy.resource_access(role.as_deref(), &resource.uri));
        Ok(result.with_cache_scope(CacheScope::Private))
    }

    delegate_request!(
        list_resource_templates,
        Option<PaginatedRequestParams>,
        ListResourceTemplatesResult
    );

    // A denied URI is refused before the consumer runs, and a result that
    // carries any denied content is refused whole, so no body reaches the
    // wire. Both use the same fixed not-found error.
    // cancel-safe: the policy check runs before the delegated await and the
    // result check on local values after it; cancellation drops only those.
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        if policy.is_enabled() && !policy.resource_access(role.as_deref(), &request.uri) {
            log_denial("resources/read", role.as_deref());
            return Err(resource_not_found());
        }
        let response =
            scope_with_identity(identity, || self.inner.read_resource(request, context)).await?;
        if !policy.is_enabled() {
            return Ok(response);
        }
        match response {
            ReadResourceResponse::Complete(result) => {
                if result.contents.iter().all(|contents| {
                    contents_uri(contents)
                        .is_some_and(|uri| policy.resource_access(role.as_deref(), uri))
                }) {
                    Ok(ReadResourceResponse::Complete(
                        result.with_cache_scope(CacheScope::Private),
                    ))
                } else {
                    log_denial("resources/read", role.as_deref());
                    Err(resource_not_found())
                }
            }
            ReadResourceResponse::InputRequired(_) => Ok(response),
            _ => {
                log_denial("resources/read", role.as_deref());
                Err(resource_not_found())
            }
        }
    }

    // A skill directory needs a skills grant, any directory needs access to
    // its URI, and the listing is filtered per role.
    // cancel-safe: the policy check runs before the delegated await and the
    // filtering on the local result after it; cancellation drops only those.
    async fn read_resource_directory(
        &self,
        request: ReadResourceDirectoryRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceDirectoryResult, ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        if policy.is_enabled() {
            if policy.is_skill_uri(&request.uri) && !policy.skills_granted(role.as_deref()) {
                log_denial("resources/directory/read", role.as_deref());
                return Err(ErrorData::method_not_found::<
                    ReadResourceDirectoryRequestMethod,
                >());
            }
            if !policy.resource_access(role.as_deref(), &request.uri) {
                log_denial("resources/directory/read", role.as_deref());
                return Err(resource_not_found());
            }
        }
        let mut result = scope_with_identity(identity, || {
            self.inner.read_resource_directory(request, context)
        })
        .await?;
        if !policy.is_enabled() {
            return Ok(result);
        }
        result
            .resources
            .retain(|resource| policy.resource_access(role.as_deref(), &resource.uri));
        Ok(result.with_cache_scope(CacheScope::Private))
    }

    // A role without a skills grant never reaches the consumer; the listing
    // keeps only the skills the role may see.
    // cancel-safe: the policy check runs before the delegated await and the
    // filtering on the local result after it; cancellation drops only those.
    async fn list_skills(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListSkillsResult, ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        if !policy.skills_granted(role.as_deref()) {
            log_denial("skills/list", role.as_deref());
            return Err(ErrorData::method_not_found::<ListSkillsRequestMethod>());
        }
        let mut result =
            scope_with_identity(identity, || self.inner.list_skills(request, context)).await?;
        if !policy.is_enabled() {
            return Ok(result);
        }
        result
            .skills
            .retain(|skill| skill_visible(&policy, role.as_deref(), skill));
        Ok(result.with_cache_scope(CacheScope::Private))
    }

    // A denied and a missing skill give the same fixed error.
    // cancel-safe: the policy check runs before the delegated await and the
    // result check on local values after it; cancellation drops only those.
    async fn get_skill(
        &self,
        request: GetSkillRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetSkillResult, ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        if !policy.skills_granted(role.as_deref()) {
            log_denial("skills/get", role.as_deref());
            return Err(ErrorData::method_not_found::<GetSkillRequestMethod>());
        }
        if policy.is_enabled()
            && (!policy.is_skill_uri(&request.uri)
                || !policy.resource_access(role.as_deref(), &request.uri))
        {
            log_denial("skills/get", role.as_deref());
            return Err(unknown_skill());
        }
        let result =
            scope_with_identity(identity, || self.inner.get_skill(request, context)).await?;
        if !policy.is_enabled() {
            return Ok(result);
        }
        if !skill_visible(&policy, role.as_deref(), &result.skill) {
            log_denial("skills/get", role.as_deref());
            return Err(unknown_skill());
        }
        Ok(result.with_cache_scope(CacheScope::Private))
    }

    // Synchronous and identity-free: under RBAC the consumer sees only
    // universally allowed resource URIs, so its answer (and with it whether
    // rmcp acknowledges) cannot depend on a role-dependent or skill URI.
    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let policy = self.rbac.load_full();
        if !policy.is_enabled() {
            return self.inner.accepted_subscription_filter(requested);
        }
        let sanitized = sanitized_filter(&policy, requested);
        let candidate = self.inner.accepted_subscription_filter(&sanitized)?;
        let mut accepted = sanitized.intersection(&candidate);
        accepted.resource_subscriptions =
            universally_allowed_uris(&policy, accepted.resource_subscriptions);
        Some(accepted)
    }

    // SECURITY FUTURE-WATCH: rmcp 3.2.0 rejects
    // `ServerNotification::TaskStatusNotification` inside
    // `SubscriptionSink::send` because `SubscriptionFilter` has no task-id
    // selector; clients currently observe task state by polling `tasks/get`.
    // If a future rmcp release makes `notifications/tasks` routable, this
    // wrapper must bind the `DetailedTask.task.task_id` in every task status
    // notification before it leaves the process. Sending it raw would bypass
    // the wrapping done in `call_tool` and `get_task` below. The test
    // `task_status_notifications_remain_unroutable_until_binding_is_added`
    // fails when that upstream change lands.
    // cancel-safe: scopes the subscription identity around the inner call;
    // cancellation drops only the scoped future.
    //
    // Second boundary: a policy reload between acceptance and `listen` must
    // not let an accepted resource URI through, so it is re-checked here
    // against a fresh policy snapshot.
    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_subscription(&context);
        if policy.is_enabled() {
            let role = identity.as_ref().map(|auth| auth.role.clone());
            if context
                .accepted()
                .resource_subscriptions
                .iter()
                .flatten()
                .any(|uri| !policy.resource_access(role.as_deref(), uri))
            {
                log_denial("subscriptions/listen", role.as_deref());
                return Err(resource_not_found());
            }
        }
        scope_with_identity(identity, || self.inner.listen(context)).await
    }

    // cancel-safe: the policy check runs before the delegated await;
    // cancellation drops only the scoped future.
    #[expect(
        deprecated,
        reason = "deliberate: rmcp::handler::server::ServerHandler::subscribe - the legacy subscription must stay gated per role until rmcp removes it"
    )]
    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let policy = self.rbac.load_full();
        let identity = identity_from_request(&context);
        if policy.is_enabled() {
            let role = identity.as_ref().map(|auth| auth.role.clone());
            if !policy.resource_access(role.as_deref(), &request.uri) {
                log_denial("resources/subscribe", role.as_deref());
                return Err(resource_not_found());
            }
        }
        scope_with_identity(identity, || self.inner.subscribe(request, context)).await
    }

    delegate_request!(unsubscribe, UnsubscribeRequestParams, ());
    // cancel-safe: task-ID rewriting happens on local values after the
    // delegated await; cancellation drops only those locals.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let binding = self.task_binding_for(&context);
        let identity = identity_from_request(&context);
        let mut response =
            scope_with_identity(identity, || self.inner.call_tool(request, context)).await?;
        // A tool may answer with a task handle instead of a result; that ID is
        // the client's future handle to this task, so it must leave bound.
        // Other `CallToolResponse` variants carry no task ID and are untouched.
        if let Some((secret, fp)) = binding.as_ref()
            && let CallToolResponse::Task(ref mut task) = response
            && let Some(raw) = RawTaskId::parse(&task.task.task_id)
        {
            task.task.task_id = task_binding::wrap(secret, &raw, fp);
        }
        Ok(response)
    }

    // cancel-safe: filtering runs on the local result after the delegated
    // await; cancellation drops only those locals.
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|auth| auth.role.clone());
        let result =
            scope_with_identity(identity, || self.inner.list_tools(request, context)).await?;
        Ok(self.filtered_tool_list(result, role.as_deref()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    // A skill or resource request whose params fail rmcp's typed variant
    // falls through to `CustomRequest` and skips the typed per-role checks,
    // so under RBAC the reserved names are refused here regardless of grants.
    // Every other method forwards.
    // cancel-safe: the policy check runs before the delegated await;
    // cancellation drops only the scoped future.
    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        if let Some(method) = RESERVED_CUSTOM_METHODS
            .iter()
            .copied()
            .find(|name| *name == request.method)
            && self.rbac.load_full().is_enabled()
        {
            let identity = identity_from_request(&context);
            log_denial(
                method,
                identity.as_ref().map(|auth| auth.role.clone()).as_deref(),
            );
            return Err(ErrorData::new(ErrorCode::METHOD_NOT_FOUND, method, None));
        }
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.on_custom_request(request, context)).await
    }

    delegate_notification!(on_cancelled, CancelledNotificationParam);
    delegate_notification!(on_progress, ProgressNotificationParam);

    // cancel-safe: scopes the notification identity around the inner call;
    // cancellation drops only the scoped future.
    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        let identity = identity_from_notification(&context);
        scope_with_identity(identity, || self.inner.on_initialized(context)).await;
    }

    // cancel-safe: scopes the notification identity around the inner call;
    // cancellation drops only the scoped future.
    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        let identity = identity_from_notification(&context);
        scope_with_identity(identity, || self.inner.on_roots_list_changed(context)).await;
    }

    // cancel-safe: scopes the notification identity around the inner call;
    // cancellation drops only the scoped future.
    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) {
        let identity = identity_from_notification(&context);
        scope_with_identity(identity, || {
            self.inner.on_custom_notification(notification, context)
        })
        .await;
    }

    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    // Task IDs are identity-bound when `task_binding` is enabled, so these
    // cannot use `delegate_request!`: the external ID must be verified and
    // rewritten to the raw ID before the inner handler sees it, and rejected
    // without ever reaching that handler when it belongs to another identity.
    // cancel-safe: task-ID handling runs on local request/result values around
    // the delegated await; cancellation drops only those locals.
    async fn get_task(
        &self,
        mut request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        let binding = self.task_binding_for(&context);
        if let Some((secret, fp)) = binding.as_ref() {
            let raw = unbind_task_id(secret, &request.task_id, fp)?;
            raw.as_str().clone_into(&mut request.task_id);
        }
        let identity = identity_from_request(&context);
        let mut result =
            scope_with_identity(identity, || self.inner.get_task(request, context)).await?;
        if let Some((secret, fp)) = binding.as_ref()
            && let Some(raw) = RawTaskId::parse(&result.task.task.task_id)
        {
            result.task.task.task_id = task_binding::wrap(secret, &raw, fp);
        }
        Ok(result)
    }

    // cancel-safe: task-ID handling runs on local request values before the
    // delegated await; cancellation drops only those locals.
    async fn update_task(
        &self,
        mut request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if let Some((secret, fp)) = self.task_binding_for(&context) {
            let raw = unbind_task_id(secret, &request.task_id, &fp)?;
            raw.as_str().clone_into(&mut request.task_id);
        }
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.update_task(request, context)).await
    }

    // cancel-safe: task-ID handling runs on local request values before the
    // delegated await; cancellation drops only those locals.
    async fn cancel_task(
        &self,
        mut request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if let Some((secret, fp)) = self.task_binding_for(&context) {
            let raw = unbind_task_id(secret, &request.task_id, &fp)?;
            raw.as_str().clone_into(&mut request.task_id);
        }
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.cancel_task(request, context)).await
    }
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use core::{
        convert::Infallible,
        future::{pending, ready},
        time::Duration,
    };
    use std::sync::{Mutex, PoisonError};

    use anyhow::Context as _;
    use axum::http::Request;
    use rmcp::{
        model::{
            ArgumentInfo, CallToolRequest, CancelTaskRequest, CancelledNotification,
            ClientCapabilities, ClientJsonRpcMessage, ClientNotification, ClientRequest,
            CompleteRequest, CreateTaskResult, DetailedTask, DiscoverRequest,
            DiscoverRequestParams, GetExtensions as _, GetSkillRequest, GetTaskRequest,
            Implementation, InitializeRequest, InputResponses, JsonObject, JsonRpcMessage,
            ListPromptsRequest, ListSkillsRequest, ListToolsRequest, ListToolsRequestMethod,
            NotificationNoParam, NumberOrString, PingRequest, Prompt, PromptReference,
            ReadResourceDirectoryRequest, Reference, RequestMetaObject, Resource,
            ServerCapabilities, ServerJsonRpcMessage, ServerNotification, ServerResult,
            SkillFrontmatter, SubscriptionsListenRequest, SubscriptionsListenRequestParams, Task,
            TaskPayload, TaskStatus, TaskStatusNotification, TaskStatusNotificationParams,
            UpdateTaskRequest,
        },
        service::serve_directly,
        transport::Transport,
    };
    use tokio::{
        sync::{Notify, mpsc},
        task::yield_now,
        time::{sleep, timeout},
    };

    use super::*;
    use crate::{
        auth::AuthMethod,
        rbac::{AllowOperationMatching, RbacConfig, RoleConfig},
    };

    mod resource_rbac;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ObservedRole {
        Present(String),
        Missing,
    }

    #[derive(Clone)]
    struct ListToolsHandler {
        pages: Arc<Mutex<VecDeque<ListToolsResult>>>,
        observed_role: Arc<Mutex<Option<ObservedRole>>>,
    }

    impl ListToolsHandler {
        fn new(pages: Vec<ListToolsResult>) -> Self {
            Self {
                pages: Arc::new(Mutex::new(VecDeque::from(pages))),
                observed_role: Arc::new(Mutex::new(None)),
            }
        }

        fn observed_role(&self) -> Option<ObservedRole> {
            let role = self.observed_role.lock().ok()?;
            role.clone()
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler requires async methods; this in-memory test handler returns immediately"
    )]
    impl ServerHandler for ListToolsHandler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::default()
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, ErrorData> {
            if let Ok(mut role) = self.observed_role.lock() {
                *role =
                    Some(rbac::current_role().map_or(ObservedRole::Missing, ObservedRole::Present));
            }
            let result = self
                .pages
                .lock()
                .ok()
                .and_then(|mut pages| pages.pop_front());
            Ok(result.unwrap_or_default())
        }
    }

    struct InMemoryTransport {
        inbound: VecDeque<ClientJsonRpcMessage>,
        outbound: Arc<Mutex<Vec<ServerJsonRpcMessage>>>,
    }

    impl InMemoryTransport {
        fn new(
            messages: Vec<ClientJsonRpcMessage>,
        ) -> (Self, Arc<Mutex<Vec<ServerJsonRpcMessage>>>) {
            let outbound = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inbound: VecDeque::from(messages),
                    outbound: Arc::clone(&outbound),
                },
                outbound,
            )
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp Transport requires async receive/close; this in-memory test transport returns immediately"
    )]
    impl Transport<RoleServer> for InMemoryTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let shared = Arc::clone(&self.outbound);
            async move {
                if let Ok(mut guard) = shared.lock() {
                    guard.push(item);
                }
                Ok(())
            }
        }

        async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
            self.inbound.pop_front()
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn tool(name: &'static str) -> Tool {
        Tool::new(
            name,
            format!("{name} description"),
            Arc::new(JsonObject::default()),
        )
    }

    /// A `tools/list` page the inner handler marks `Public`, the worst case for
    /// a role-filtered list: filtering must force `Private`, and an unfiltered
    /// list must keep `Public`. rmcp fills a missing scope with `Private` for
    /// 2026-07-28 peers, so a page with no scope could not show either.
    fn page(names: &[&'static str]) -> ListToolsResult {
        let mut page =
            ListToolsResult::with_all_items(names.iter().map(|name| tool(name)).collect());
        page.cache_scope = Some(CacheScope::Public);
        page
    }

    fn policy(role: RoleConfig) -> Arc<ArcSwap<RbacPolicy>> {
        Arc::new(ArcSwap::new(Arc::new(RbacPolicy::new(
            &RbacConfig::with_roles(vec![role]),
        ))))
    }

    fn glob_policy(role: RoleConfig) -> Arc<ArcSwap<RbacPolicy>> {
        Arc::new(ArcSwap::new(Arc::new(RbacPolicy::new(
            &RbacConfig::with_roles(vec![role])
                .with_allow_operation_matching(AllowOperationMatching::Glob),
        ))))
    }

    fn policy_with_global_deny(
        role: RoleConfig,
        global_deny: Vec<String>,
    ) -> Arc<ArcSwap<RbacPolicy>> {
        Arc::new(ArcSwap::new(Arc::new(RbacPolicy::new(
            &RbacConfig::with_roles(vec![role])
                .with_allow_operation_matching(AllowOperationMatching::Glob)
                .with_global_deny(global_deny),
        ))))
    }

    fn viewer() -> AuthIdentity {
        AuthIdentity {
            granted_scopes: None,
            name: "viewer-key".to_owned(),
            role: "viewer".to_owned(),
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        }
    }

    fn list_request(id: i64, identity: Option<AuthIdentity>) -> ClientJsonRpcMessage {
        let mut request = ClientRequest::ListToolsRequest(ListToolsRequest {
            method: ListToolsRequestMethod,
            params: None,
            extensions: Extensions::default(),
        });
        // rmcp strips cache hints from results for peers older than 2026-07-28,
        // so the cache-hint assertions need a peer that negotiated that version.
        let _previous_meta = request.extensions_mut().insert(coverage_meta());
        if let Some(present) = identity {
            let mut parts = Request::new(()).into_parts().0;
            let _previous_identity = parts.extensions.insert(present);
            let _previous_parts = request.extensions_mut().insert(parts);
        }
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

    async fn list_tools_via_service(
        inner: ListToolsHandler,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        filtering_enabled: bool,
        identity: Option<AuthIdentity>,
    ) -> anyhow::Result<ListToolsResult> {
        let message = list_request(1, identity);
        let (transport, outbound) = InMemoryTransport::new(vec![message]);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(
            RbacContextHandler::new(inner, rbac, filtering_enabled),
            transport,
            None,
        );
        let _quit_reason = running.waiting().await.context("service task joins")?;

        let messages = outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(frame) = messages.first() else {
            anyhow::bail!("expected one response");
        };
        let ServerJsonRpcMessage::Response(response) = frame else {
            anyhow::bail!("expected JSON-RPC response, got {frame:?}");
        };
        if let ServerResult::ListToolsResult(result) = &response.result {
            Ok(result.clone())
        } else {
            anyhow::bail!("expected tools/list result, got {:?}", response.result);
        }
    }

    async fn list_tools_for_viewer(
        page: ListToolsResult,
        rbac: Arc<ArcSwap<RbacPolicy>>,
    ) -> anyhow::Result<ListToolsResult> {
        list_tools_via_service(
            ListToolsHandler::new(vec![page]),
            rbac,
            true,
            Some(viewer()),
        )
        .await
    }

    #[tokio::test]
    /// Pins that `tools/list` drops tools the role's allowlist rejects.
    async fn list_tools_filters_denied_tools() -> anyhow::Result<()> {
        let rbac = glob_policy(RoleConfig::new(
            "viewer",
            vec!["a_*".to_owned()],
            vec!["*".to_owned()],
        ));

        let result = list_tools_for_viewer(page(&["a_x", "b_y"]), rbac).await?;

        assert_eq!(result.tools, vec![tool("a_x")]);
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
        Ok(())
    }

    #[tokio::test]
    /// Pins that the global deny list removes matching tools from `tools/list`.
    async fn list_tools_applies_global_deny() -> anyhow::Result<()> {
        let rbac = policy_with_global_deny(
            RoleConfig::new("viewer", vec!["*".to_owned()], vec!["*".to_owned()]),
            vec!["*_delete_*".to_owned()],
        );

        let result = list_tools_for_viewer(page(&["safe_read", "user_delete_all"]), rbac).await?;

        assert_eq!(result.tools, vec![tool("safe_read")]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that a disabled policy leaves the tool list unfiltered.
    async fn list_tools_unfiltered_when_rbac_disabled() -> anyhow::Result<()> {
        let result = list_tools_for_viewer(
            page(&["a_x", "b_y"]),
            Arc::new(ArcSwap::new(Arc::new(RbacPolicy::disabled()))),
        )
        .await?;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        // An inner `Public` scope passes through untouched: only filtering forces `Private`.
        assert_eq!(result.cache_scope, Some(CacheScope::Public));
        Ok(())
    }

    #[tokio::test]
    /// Pins that a request without a role leaves the tool list unfiltered.
    async fn list_tools_unfiltered_when_no_role() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));

        let result = list_tools_via_service(
            ListToolsHandler::new(vec![page(&["a_x", "b_y"])]),
            rbac,
            true,
            None,
        )
        .await?;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        // An inner `Public` scope passes through untouched: only filtering forces `Private`.
        assert_eq!(result.cache_scope, Some(CacheScope::Public));
        Ok(())
    }

    #[tokio::test]
    /// Pins that filtering forces the cache scope from public to private.
    async fn list_tools_sets_cache_scope_private_when_filtered() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned(), "b_y".to_owned()],
            vec!["*".to_owned()],
        ));

        let result = list_tools_for_viewer(page(&["a_x", "b_y"]), rbac).await?;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
        Ok(())
    }

    #[tokio::test]
    /// Pins that filtering preserves the inner page's next cursor.
    async fn list_tools_preserves_next_cursor() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let mut inner_page = page(&["a_x", "b_y"]);
        inner_page.next_cursor = Some("next".to_owned());

        let result = list_tools_for_viewer(inner_page, rbac).await?;

        assert_eq!(result.tools, vec![tool("a_x")]);
        assert_eq!(result.next_cursor.as_deref(), Some("next"));
        Ok(())
    }

    #[tokio::test]
    /// Pins that filtering forces a private scope while keeping the TTL.
    async fn list_tools_preserves_ttl_ms_while_forcing_private() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned(), "b_y".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner_page = page(&["a_x", "b_y"]).with_ttl_ms(30_000);

        let result = list_tools_for_viewer(inner_page, rbac).await?;

        assert_eq!(result.ttl_ms, Some(30_000));
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
        Ok(())
    }

    #[tokio::test]
    /// Pins that a fully denied page keeps its live cursor and empty tool list.
    async fn list_tools_allows_empty_page_with_live_cursor() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["allowed_later".to_owned()],
            vec!["*".to_owned()],
        ));
        let mut inner_page = page(&["denied_now"]);
        inner_page.next_cursor = Some("next".to_owned());

        let result = list_tools_for_viewer(inner_page, rbac).await?;

        assert_eq!(result.tools, Vec::<Tool>::new());
        assert_eq!(result.next_cursor.as_deref(), Some("next"));
        Ok(())
    }

    #[tokio::test]
    /// Pins that the inner handler observes the role the wrapper scoped in.
    async fn list_tools_filters_when_role_present_after_delegation() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner = ListToolsHandler::new(vec![page(&["a_x", "b_y"])]);
        let probe = inner.clone();

        let result = list_tools_via_service(inner, rbac, true, Some(viewer())).await?;

        assert_eq!(
            probe.observed_role(),
            Some(ObservedRole::Present("viewer".to_owned()))
        );
        assert_eq!(rbac::current_role(), None);
        assert_eq!(result.tools, vec![tool("a_x")]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that filtering follows a policy reload without restarting.
    async fn list_tools_reflects_reloaded_policy() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner = ListToolsHandler::new(vec![page(&["a_x", "b_y"]), page(&["a_x", "b_y"])]);

        let first =
            list_tools_via_service(inner.clone(), Arc::clone(&rbac), true, Some(viewer())).await?;
        rbac.store(Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["b_y".to_owned()], vec!["*".to_owned()]),
        ]))));
        let second = list_tools_via_service(inner, rbac, true, Some(viewer())).await?;

        assert_eq!(first.tools, vec![tool("a_x")]);
        assert_eq!(second.tools, vec![tool("b_y")]);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Task identity binding
    //
    // These prove the property the feature exists for: a task ID leaked to a
    // second authenticated identity must be useless to it, and the inner
    // handler must never even observe the attempt.
    // ----------------------------------------------------------------------

    /// Records the `task_id` the inner handler actually received, so tests can
    /// prove both that the wrapper is stripped before delegation and that a
    /// rejected call never reaches the handler at all.
    #[derive(Clone, Default)]
    struct TaskProbeHandler {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl TaskProbeHandler {
        fn seen(&self) -> Vec<String> {
            self.seen.lock().map_or_default(|stored| stored.clone())
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler requires async methods; this in-memory test handler returns immediately"
    )]
    impl ServerHandler for TaskProbeHandler {
        fn get_info(&self) -> ServerConfig {
            // rmcp gates `tasks/*` on the server advertising the extension AND
            // the client declaring it, so both must be set up or the request is
            // rejected upstream and never reaches the binding under test.
            ServerConfig::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_tasks()
                    .build(),
            )
        }

        async fn get_task(
            &self,
            request: GetTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<GetTaskResult, ErrorData> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(request.task_id.clone());
            }
            Ok(GetTaskResult::new(DetailedTask::new(
                Task::new(
                    request.task_id,
                    TaskStatus::Working,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
                TaskPayload::Working,
            )))
        }

        async fn cancel_task(
            &self,
            request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(request.task_id);
            }
            Ok(())
        }
    }

    /// The wrapper as it would be if every delegation were deleted: it holds the
    /// probe but overrides nothing, so rmcp's default `ServerHandler` bodies
    /// answer every call and the inner handler is never reached.
    ///
    /// Driving a method against this type is the per-method mutation check: if
    /// the inner probe still observes the call, the observation came from the
    /// harness (or a re-entrant default) rather than from the wrapper's
    /// delegation. `inner` is deliberately never read, hence the `dead_code`
    /// allow.
    #[derive(Clone, Default)]
    struct PassthroughDefaults<H> {
        #[expect(
            dead_code,
            reason = "deliberately never read: this type overrides nothing, so the probe must stay unreached"
        )]
        inner: H,
    }

    impl<H: ServerHandler> PassthroughDefaults<H> {
        fn new(inner: H) -> Self {
            Self { inner }
        }
    }

    impl<H: ServerHandler> ServerHandler for PassthroughDefaults<H> {}

    fn identity_named(name: &str) -> AuthIdentity {
        AuthIdentity {
            granted_scopes: None,
            name: name.to_owned(),
            role: "viewer".to_owned(),
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        }
    }

    fn task_secret() -> SessionBindingSecret {
        SessionBindingSecret::Configured(Arc::new(SecretString::from(
            "task-binding-test-secret-at-least-32-bytes".to_owned(),
        )))
    }

    fn get_task_request(id: i64, task_id: &str, identity: AuthIdentity) -> ClientJsonRpcMessage {
        let mut request =
            ClientRequest::GetTaskRequest(GetTaskRequest::new(GetTaskParams::new(task_id)));
        // The envelope extensions are the canonical runtime home for `_meta`;
        // a `params.meta` set in-memory is only honoured on serialization, so
        // it would never reach `RequestContext::client_capabilities()` here.
        let mut meta = RequestMetaObject::default();
        meta.set_client_capabilities(ClientCapabilities::builder().enable_tasks().build());
        let _previous_meta = request.extensions_mut().insert(meta);
        let mut parts = Request::new(()).into_parts().0;
        let _previous_identity = parts.extensions.insert(identity);
        let _previous_parts = request.extensions_mut().insert(parts);
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

    #[expect(
        clippy::panic,
        reason = "deliberate: src/rbac_context.rs::get_task_via_service panics only when the in-memory service returns no usable frame (harness invariant)"
    )]
    async fn get_task_via_service(
        inner: TaskProbeHandler,
        binding: Option<SessionBindingSecret>,
        task_id: &str,
        identity: AuthIdentity,
    ) -> Result<GetTaskResult, ErrorData> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ));
        let message = get_task_request(1, task_id, identity);
        let (transport, outbound) = InMemoryTransport::new(vec![message]);
        let handler = RbacContextHandler::new(inner, rbac, false).with_task_binding(binding);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);
        let _quit_reason = running.waiting().await.map_err(|error| {
            ErrorData::internal_error(format!("service task join must succeed: {error}"), None)
        })?;

        let messages = outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(frame) = messages.first() else {
            panic!("expected one response");
        };
        match frame {
            ServerJsonRpcMessage::Response(response) => {
                if let ServerResult::GetTaskResult(result) = &response.result {
                    Ok(result.clone())
                } else {
                    panic!("expected tasks/get result, got {:?}", response.result);
                }
            }
            ServerJsonRpcMessage::Error(err) => Err(err.error.clone()),
            other @ (ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_)) => {
                panic!("unexpected message {other:?}");
            }
        }
    }

    #[tokio::test]
    /// Pins that the owner's raw task id is unwrapped inbound and rewrapped outbound.
    async fn task_binding_wraps_outbound_and_unwraps_inbound_for_the_owner() -> anyhow::Result<()> {
        let secret = task_secret();
        let alice = identity_named("alice");
        let fp = fingerprint(&alice);
        let raw = RawTaskId::parse("task-42").context("valid id")?;
        let external = task_binding::wrap(&secret, &raw, &fp);
        let probe = TaskProbeHandler::default();

        let result = get_task_via_service(
            probe.clone(),
            Some(secret.clone()),
            &external,
            alice.clone(),
        )
        .await
        .context("owner may read its own task")?;

        assert_eq!(
            probe.seen(),
            vec!["task-42".to_owned()],
            "inner handler must observe the RAW id, never the wrapper"
        );
        assert_eq!(
            result.task.task.task_id, external,
            "outbound id must leave wrapped"
        );
        assert_ne!(
            result.task.task.task_id, "task-42",
            "raw id must never reach the client"
        );
        Ok(())
    }

    #[tokio::test]
    /// Pins that a second identity is denied and the handler is never called.
    async fn task_binding_denies_a_second_identity_and_never_calls_the_handler()
    -> anyhow::Result<()> {
        let secret = task_secret();
        let alice = identity_named("alice");
        let bob = identity_named("bob");
        let raw = RawTaskId::parse("task-42").context("valid id")?;
        let alices_task = task_binding::wrap(&secret, &raw, &fingerprint(&alice));
        let probe = TaskProbeHandler::default();

        let error = get_task_via_service(probe.clone(), Some(secret), &alices_task, bob)
            .await
            .err()
            .context("bob must not reach alice's task")?;

        assert_eq!(
            error.code,
            ErrorCode::INVALID_PARAMS,
            "must match upstream's unknown-task error code"
        );
        assert!(
            error.message.contains("unknown task"),
            "must be indistinguishable from a nonexistent task, got {:?}",
            error.message
        );
        assert!(
            probe.seen().is_empty(),
            "the inner handler must never see a rejected task id"
        );
        Ok(())
    }

    /// A raw (unwrapped) id must be rejected too, or an attacker could simply
    /// strip the wrapper and hit the handler directly.
    #[tokio::test]
    /// Pins that raw and malformed task IDs are rejected indistinguishably.
    async fn task_binding_rejects_raw_and_malformed_ids_identically() -> anyhow::Result<()> {
        let secret = task_secret();
        let alice = identity_named("alice");
        let probe = TaskProbeHandler::default();

        for candidate in ["task-42", "", "t1.", "t1.a.b", "v1.a.b", "garbage"] {
            let Err(error) = get_task_via_service(
                probe.clone(),
                Some(secret.clone()),
                candidate,
                alice.clone(),
            )
            .await
            else {
                anyhow::bail!("must reject {candidate:?}");
            };
            assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
            assert!(
                error.message.contains("unknown task"),
                "every failure mode must look alike; {candidate:?} gave {:?}",
                error.message
            );
        }
        assert_eq!(probe.seen(), Vec::<String>::new());
        Ok(())
    }

    /// Disabled binding must be perfectly transparent, so existing task-using
    /// consumers are unaffected until they opt in.
    #[tokio::test]
    /// Pins that disabled binding passes task IDs through untouched.
    async fn task_binding_disabled_passes_ids_through_untouched() -> anyhow::Result<()> {
        let probe = TaskProbeHandler::default();

        let result = get_task_via_service(probe.clone(), None, "task-42", identity_named("alice"))
            .await
            .context("pass-through when disabled")?;

        assert_eq!(probe.seen(), vec!["task-42".to_owned()]);
        assert_eq!(result.task.task.task_id, "task-42");
        Ok(())
    }

    #[derive(Clone, Default)]
    struct NotificationProbeHandler {
        send_result: Arc<Mutex<Option<String>>>,
    }

    impl ServerHandler for NotificationProbeHandler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_tool_list_changed()
                    .enable_tasks()
                    .build(),
            )
        }

        fn accepted_subscription_filter(
            &self,
            requested: &SubscriptionFilter,
        ) -> Option<SubscriptionFilter> {
            Some(requested.clone())
        }

        async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
            let task = DetailedTask::new(
                Task::new(
                    "task-42",
                    TaskStatus::Working,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
                TaskPayload::Working,
            );
            let outcome = context
                .sink()
                .send(ServerNotification::TaskStatusNotification(
                    TaskStatusNotification::new(TaskStatusNotificationParams::new(task)),
                ))
                .await;
            if let Ok(mut slot) = self.send_result.lock() {
                *slot = Some(match outcome {
                    Ok(()) => "sent".to_owned(),
                    Err(err) => format!("{err:?}"),
                });
            }
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TaskCancelProbe {
        seen: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ServerHandler for TaskCancelProbe {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(probe_capabilities())
        }

        async fn get_task(
            &self,
            _request: GetTaskParams,
            context: RequestContext<RoleServer>,
        ) -> Result<GetTaskResult, ErrorData> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push("get_task");
            let event = match timeout(Duration::from_secs(10), context.ct.cancelled()).await {
                Ok(()) => "get_task_cancelled",
                Err(_) => "get_task_timeout",
            };
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
            Err(ErrorData::internal_error("cancelled", None))
        }

        fn cancel_task(
            &self,
            _request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push("cancel_task");
            ready(Ok(()))
        }
    }

    /// Pins request cancellation independently of EOF and task cancellation.
    #[tokio::test]
    async fn cancelling_a_tasks_get_request_never_cancels_the_task() -> anyhow::Result<()> {
        // Given: a never-EOF transport carries a task-status request.
        let probe = TaskCancelProbe::default();
        let mut request: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc":"2.0","id":1_u32,"method":"tasks/get","params":{"taskId":"raw-task"}
        }))?;
        attach_meta(&mut request, coverage_meta())?;
        attach_identity(&mut request, viewer())?;
        let notification: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1_u32}
        }))?;
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![request, notification]),
            outbound: Arc::new(Mutex::new(Vec::new())),
        };
        let handler = RbacContextHandler::new(probe.clone(), viewer_policy(), false);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);
        // When: the client cancels request 1, not the underlying task.
        // Then: the handler sees cancellation before service shutdown.
        let observed = timeout(Duration::from_secs(11), async {
            while probe
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
                < 2
            {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let snapshot = probe
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let _quit = running.cancel().await;
        observed.with_context(|| format!("missing get_task_cancelled; log={snapshot:?}"))?;
        assert_eq!(snapshot, vec!["get_task", "get_task_cancelled"]);
        Ok(())
    }

    /// Like [`InMemoryTransport`] but never reports end-of-stream, so a
    /// long-running `subscriptions/listen` handler is not cancelled by the
    /// service shutting down the moment the inbound queue drains.
    struct OpenTransport {
        inbound: VecDeque<ClientJsonRpcMessage>,
        outbound: Arc<Mutex<Vec<ServerJsonRpcMessage>>>,
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp Transport requires async receive/close; this in-memory test transport returns immediately"
    )]
    impl Transport<RoleServer> for OpenTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let shared = Arc::clone(&self.outbound);
            async move {
                if let Ok(mut guard) = shared.lock() {
                    guard.push(item);
                }
                Ok(())
            }
        }

        async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
            if let Some(message) = self.inbound.pop_front() {
                return Some(message);
            }
            pending().await
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Tripwire, not a behavioural test.
    ///
    /// `rmcp` currently refuses to route `notifications/tasks` through
    /// `subscriptions/listen`, so a task status notification cannot carry a raw
    /// task ID past the binding today. This test asserts that refusal still
    /// holds. **It is expected to fail when a future `rmcp` release makes task
    /// notifications routable** - at which point the task ID inside
    /// `TaskStatusNotificationParams` must be wrapped before it leaves the
    /// process, exactly as `call_tool` and `get_task` already wrap theirs.
    #[tokio::test]
    async fn task_status_notifications_remain_unroutable_until_binding_is_added()
    -> anyhow::Result<()> {
        let probe = NotificationProbeHandler::default();
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ));

        let filter = SubscriptionFilter::builder().tools_list_changed().build();
        let mut params = SubscriptionsListenRequestParams::new(filter);
        let mut meta = RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::default());
        params.meta = Some(meta.clone());
        let mut request =
            ClientRequest::SubscriptionsListenRequest(SubscriptionsListenRequest::new(params));
        let _previous_meta = request.extensions_mut().insert(meta);
        let mut parts = Request::new(()).into_parts().0;
        let _previous_identity = parts.extensions.insert(identity_named("alice"));
        let _previous_parts = request.extensions_mut().insert(parts);
        let message = JsonRpcMessage::request(request, NumberOrString::Number(1));

        let outbound = Arc::new(Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![message]),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), rbac, false);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);

        // The transport never closes, so poll for the handler's result instead
        // of joining the service, then cancel it.
        let mut recorded = None;
        for _ in 0_i32..10_000_i32 {
            if let Some(value) = probe.send_result.lock().ok().and_then(|slot| slot.clone()) {
                recorded = Some(value);
                break;
            }
            yield_now().await;
        }
        // Cleanup cancel; a failure here cannot affect the assertion below.
        let _cancel_result = running.cancel().await;

        let Some(outcome) = recorded else {
            let messages = outbound
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            anyhow::bail!("listen was never invoked; server responded: {messages:?}");
        };

        assert!(
            outcome.contains("UnsupportedNotification") && outcome.contains("notifications/tasks"),
            "TRIPWIRE: rmcp now routes task status notifications (got {outcome:?}). \
             This is not a flaky test - bind the task_id inside \
             TaskStatusNotificationParams in RbacContextHandler::listen before \
             shipping this rmcp version, or identity A's raw task ID will leak \
             to whoever is subscribed."
        );
        Ok(())
    }

    /// Overrides only `negotiate_initialize`, so the sentinel value can only
    /// come from an inner override reaching the caller through the wrapper.
    /// `get_info` stays at the test default, so no other path can produce it.
    #[derive(Clone, Default)]
    struct NegotiateProbe;

    impl ServerHandler for NegotiateProbe {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::default()
        }

        fn negotiate_initialize(
            &self,
            _request: &InitializeRequestParams,
        ) -> Result<InitializeResult, ErrorData> {
            let mut info = ServerConfig::new(ServerCapabilities::default());
            info.instructions = Some("inner negotiate_initialize override".to_owned());
            Ok(info)
        }
    }

    #[test]
    /// Pins that the wrapper delegates `negotiate_initialize` to an inner override.
    fn rbac_context_handler_preserves_inner_negotiate_initialize_override() -> anyhow::Result<()> {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ));
        let handler = RbacContextHandler::new(NegotiateProbe, rbac, false);
        let request = InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("delegation-test-client", "0.0.0"),
        );

        // Direct call on the wrapper: negotiation carries no request context,
        // so there is no identity to scope and delegation must be transparent.
        let result = handler
            .negotiate_initialize(&request)
            .context("direct negotiation must succeed")?;

        assert_eq!(
            result.instructions.as_deref(),
            Some("inner negotiate_initialize override"),
            "wrapper must delegate to the inner `negotiate_initialize` override"
        );
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Semantic coverage drivers
    //
    // Each driver proves, by exact equality on the inner probe's record log
    // (and on sentinel values no rmcp default body can produce), that
    // `RbacContextHandler` forwarded the call - and, because the probe reads
    // `current_role()` inside the method body, that it did so inside the
    // identity scope. Every driver also runs the same request against
    // `PassthroughDefaults` - the wrapper with all delegations deleted - and
    // asserts the probe stayed untouched. That second half is the per-method
    // mutation check.
    //
    // No assertion here uses `contains`, `is_empty()` or a length threshold:
    // rmcp's self-re-entrant defaults (`initialize`, `negotiate_initialize`,
    // `discover`) and its ambient handler calls can otherwise make a
    // non-forwarding body look green.
    // ----------------------------------------------------------------------

    /// Two of rmcp's known versions: distinguishable from the default (all of
    /// `KNOWN_VERSIONS`), while still covering an initialize-capable version
    /// and the 2026-07-28 version that `discover` needs.
    const SENTINEL_VERSIONS: [ProtocolVersion; 2] =
        [ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28];

    /// Capabilities the probe advertises so the dispatcher routes tools, task
    /// methods and subscriptions to the wrapper at all.
    fn probe_capabilities() -> ServerCapabilities {
        ServerCapabilities::builder()
            .enable_prompts()
            .enable_resources()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_tasks()
            .build()
    }

    /// The observed call log: `(method, role observed inside the call)`.
    type ObservedCalls = Arc<Mutex<Vec<(&'static str, Option<String>)>>>;

    /// Records each call as `(method, role observed inside the call)` and
    /// answers with a sentinel no rmcp default body can construct. The role is
    /// read from the wrapper's RBAC scope, so the log proves forwarding *and*
    /// scoping.
    ///
    /// Deliberately silent (no record) for `get_info`,
    /// `supported_protocol_versions` and `get_tool`: rmcp calls those outside
    /// dispatch (peer configuration, capability validation), so a record could
    /// not be attributed to the driver. Those three are proven by value
    /// differential against [`PassthroughDefaults`] instead.
    #[derive(Clone, Default)]
    struct ForwardingProbe {
        seen: ObservedCalls,
        task_ids: Arc<Mutex<Vec<String>>>,
        notify: Arc<Notify>,
    }

    impl ForwardingProbe {
        fn record(&self, method: &'static str) {
            let role = rbac::current_role();
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((method, role));
            }
            self.notify.notify_waiters();
        }

        fn record_task_id(&self, task_id: String) {
            if let Ok(mut ids) = self.task_ids.lock() {
                ids.push(task_id);
            }
            self.notify.notify_waiters();
        }

        fn seen(&self) -> Vec<(&'static str, Option<String>)> {
            self.seen.lock().map_or_default(|seen| seen.clone())
        }

        fn task_ids(&self) -> Vec<String> {
            self.task_ids.lock().map_or_default(|ids| ids.clone())
        }

        async fn wait_for_seen_count(&self, count: usize) -> anyhow::Result<()> {
            timeout(Duration::from_secs(1), async {
                while self.seen().len() < count {
                    self.notify.notified().await;
                }
            })
            .await
            .context("delegated handler methods should be observed")?;
            Ok(())
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "coverage drives rmcp's async trait methods, whose probe bodies return immediately"
    )]
    impl ServerHandler for ForwardingProbe {
        fn get_info(&self) -> ServerConfig {
            let mut info = ServerConfig::new(probe_capabilities());
            info.instructions = Some("forwarding-probe".to_owned());
            info
        }

        fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
            Cow::Borrowed(&SENTINEL_VERSIONS)
        }

        fn get_tool(&self, name: &str) -> Option<Tool> {
            Some(Tool::new(
                name.to_owned(),
                "forwarding-probe",
                Arc::new(JsonObject::default()),
            ))
        }

        async fn ping(&self, _context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
            self.record("ping");
            Ok(())
        }

        async fn initialize(
            &self,
            _request: InitializeRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<InitializeResult, ErrorData> {
            self.record("initialize");
            let mut info = InitializeResult::new(probe_capabilities());
            info.instructions = Some("forwarding-probe:initialize".to_owned());
            Ok(info)
        }

        async fn discover(
            &self,
            _context: RequestContext<RoleServer>,
        ) -> Result<DiscoverResult, ErrorData> {
            self.record("discover");
            Ok(DiscoverResult::new(
                SENTINEL_VERSIONS.to_vec(),
                probe_capabilities(),
            ))
        }

        async fn complete(
            &self,
            _request: CompleteRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CompleteResult, ErrorData> {
            self.record("complete");
            Err(ErrorData::invalid_request(
                "forwarding-probe:complete",
                None,
            ))
        }

        async fn list_prompts(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListPromptsResult, ErrorData> {
            self.record("list_prompts");
            Ok(ListPromptsResult::with_all_items(vec![Prompt::new(
                "sentinel-prompt",
                Some("forwarding-probe"),
                None,
            )]))
        }

        async fn on_cancelled(
            &self,
            _notification: CancelledNotificationParam,
            _context: NotificationContext<RoleServer>,
        ) {
            self.record("on_cancelled");
        }

        async fn on_initialized(&self, _context: NotificationContext<RoleServer>) {
            self.record("on_initialized");
        }

        async fn on_roots_list_changed(&self, _context: NotificationContext<RoleServer>) {
            self.record("on_roots_list_changed");
        }

        async fn on_custom_notification(
            &self,
            _notification: CustomNotification,
            _context: NotificationContext<RoleServer>,
        ) {
            self.record("on_custom_notification");
        }

        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, ErrorData> {
            self.record("call_tool");
            Ok(CallToolResponse::Task(CreateTaskResult::new(Task::new(
                "raw-task-call",
                TaskStatus::Working,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ))))
        }

        async fn update_task(
            &self,
            request: UpdateTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("update_task");
            self.record_task_id(request.task_id);
            Ok(())
        }

        async fn cancel_task(
            &self,
            request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("cancel_task");
            self.record_task_id(request.task_id);
            Ok(())
        }
    }

    /// Maps every method the `RbacContextHandler` `ServerHandler` impl defines
    /// to the test that proves the inner handler was reached.
    ///
    /// Parsed by `tests/integration/delegation_guard.rs`, which asserts this table covers
    /// exactly its `DIRECTLY_DELEGATED ∪ BEHAVIORAL_WRAPPED` classification -
    /// so a method cannot be added or reclassified without a driver. The eight
    /// methods attributed to the macro-body drivers are each discharged by that
    /// driver plus the guard's macro-origin pin.
    const SEMANTIC_DRIVERS: &[(&str, &str)] = &[
        (
            "ping",
            "rbac_context_handler_forwards_ping_initialize_and_discover",
        ),
        (
            "initialize",
            "rbac_context_handler_forwards_ping_initialize_and_discover",
        ),
        (
            "negotiate_initialize",
            "rbac_context_handler_preserves_inner_negotiate_initialize_override",
        ),
        (
            "supported_protocol_versions",
            "rbac_context_handler_forwards_direct_sync_methods",
        ),
        (
            "discover",
            "rbac_context_handler_forwards_ping_initialize_and_discover",
        ),
        (
            "complete",
            "rbac_context_handler_forwards_macro_request_plain_arm",
        ),
        (
            "set_level",
            "rbac_context_handler_forwards_macro_request_plain_arm",
        ),
        (
            "get_prompt",
            "rbac_context_handler_forwards_macro_request_plain_arm",
        ),
        (
            "list_prompts",
            "rbac_context_handler_forwards_macro_request_option_arm",
        ),
        (
            "list_resources",
            "rbac_disabled_forwards_every_resource_and_skill_method_unchanged",
        ),
        (
            "list_resource_templates",
            "rbac_context_handler_forwards_macro_request_option_arm",
        ),
        (
            "read_resource",
            "rbac_disabled_forwards_every_resource_and_skill_method_unchanged",
        ),
        (
            "read_resource_directory",
            "rbac_context_handler_forwards_read_resource_directory",
        ),
        ("list_skills", "rbac_context_handler_forwards_list_skills"),
        ("get_skill", "rbac_context_handler_forwards_get_skill"),
        (
            "accepted_subscription_filter",
            "accepted_subscription_filter_sanitizes_inputs_and_outputs",
        ),
        (
            "listen",
            "listen_rechecks_a_policy_reloaded_after_acknowledgement",
        ),
        (
            "subscribe",
            "rbac_disabled_forwards_every_resource_and_skill_method_unchanged",
        ),
        (
            "unsubscribe",
            "rbac_context_handler_forwards_macro_request_plain_arm",
        ),
        (
            "call_tool",
            "rbac_context_handler_forwards_task_producing_call_tool",
        ),
        (
            "list_tools",
            "list_tools_filters_when_role_present_after_delegation",
        ),
        (
            "get_tool",
            "rbac_context_handler_forwards_direct_sync_methods",
        ),
        (
            "on_custom_request",
            "rbac_context_handler_on_custom_request_refuses_reserved_names",
        ),
        (
            "on_cancelled",
            "rbac_context_handler_forwards_macro_notification_arm",
        ),
        (
            "on_progress",
            "rbac_context_handler_forwards_macro_notification_arm",
        ),
        (
            "on_initialized",
            "rbac_context_handler_forwards_notifications",
        ),
        (
            "on_roots_list_changed",
            "rbac_context_handler_forwards_notifications",
        ),
        (
            "on_custom_notification",
            "rbac_context_handler_forwards_notifications",
        ),
        (
            "get_info",
            "rbac_context_handler_forwards_direct_sync_methods",
        ),
        (
            "get_task",
            "task_binding_wraps_outbound_and_unwraps_inbound_for_the_owner",
        ),
        (
            "update_task",
            "rbac_context_handler_forwards_task_binding_on_update_and_cancel",
        ),
        (
            "cancel_task",
            "rbac_context_handler_forwards_task_binding_on_update_and_cancel",
        ),
    ];

    /// `SEMANTIC_DRIVERS` is parsed by `tests/integration/delegation_guard.rs`; this
    /// in-crate check keeps the constant referenced (so it cannot rot as dead
    /// code) and rejects duplicate entries, which the source-level parser
    /// cannot see.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/rbac_context.rs::semantic_drivers_table_is_well_formed keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the semantic-driver table has no duplicate or empty entries.
    fn semantic_drivers_table_is_well_formed() -> anyhow::Result<()> {
        assert_ne!(SEMANTIC_DRIVERS, []);
        let mut names: Vec<&str> = SEMANTIC_DRIVERS.iter().map(|(name, _)| *name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate method in SEMANTIC_DRIVERS");
        for (name, driver) in SEMANTIC_DRIVERS {
            assert_ne!(*name, "");
            assert_ne!(*driver, "");
        }
        Ok(())
    }

    /// Per-request metadata declaring the protocol version and the tasks client
    /// capability that the `tasks/*` gates and a task-returning `call_tool`
    /// require.
    fn coverage_meta() -> RequestMetaObject {
        let mut meta = RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::builder().enable_tasks().build());
        meta
    }

    fn request_message(request: ClientRequest, id: i64) -> ClientJsonRpcMessage {
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

    /// Attach the authenticated identity the way the transport middleware does:
    /// an [`axum`] `Parts` extension carrying the [`AuthIdentity`].
    fn attach_identity(
        message: &mut ClientJsonRpcMessage,
        identity: AuthIdentity,
    ) -> anyhow::Result<()> {
        let mut parts = Request::new(()).into_parts().0;
        let _previous_identity = parts.extensions.insert(identity);
        match message {
            JsonRpcMessage::Request(request) => {
                let _previous_parts = request.request.extensions_mut().insert(parts);
            }
            JsonRpcMessage::Notification(notification) => {
                let _previous_parts = notification.notification.extensions_mut().insert(parts);
            }
            other @ (JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_)) => {
                anyhow::bail!(
                    "coverage drivers only send requests and notifications, got {other:?}"
                );
            }
        }
        Ok(())
    }

    fn attach_meta(
        message: &mut ClientJsonRpcMessage,
        meta: RequestMetaObject,
    ) -> anyhow::Result<()> {
        let JsonRpcMessage::Request(request) = message else {
            anyhow::bail!("only requests carry request metadata");
        };
        let _previous_meta = request.request.extensions_mut().insert(meta);
        Ok(())
    }

    type OutboundFrames = Arc<Mutex<Vec<ServerJsonRpcMessage>>>;

    /// Drive messages through a real service wrapping `inner`, and hand back
    /// the outbound frames. Response order is not a contract - callers match
    /// by JSON-RPC id with [`frame_for`].
    async fn drive_coverage_requests<H>(
        inner: H,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        binding: Option<SessionBindingSecret>,
        messages: Vec<ClientJsonRpcMessage>,
    ) -> anyhow::Result<OutboundFrames>
    where
        H: ServerHandler,
    {
        let (transport, outbound) = InMemoryTransport::new(messages);
        let handler = RbacContextHandler::new(inner, rbac, false).with_task_binding(binding);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);
        let _quit_reason = running.waiting().await.context("service task joins")?;
        Ok(outbound)
    }

    /// Drive one request against the real wrapper, then the same request
    /// against the deleted-delegation control. The control half is the
    /// per-method mutation evidence and is asserted here so no driver can
    /// forget it.
    async fn forward_once<F>(
        build_message: F,
        binding: Option<SessionBindingSecret>,
    ) -> anyhow::Result<(OutboundFrames, ForwardingProbe, OutboundFrames)>
    where
        F: Fn() -> anyhow::Result<ClientJsonRpcMessage>,
    {
        let probe = ForwardingProbe::default();
        let outbound = drive_coverage_requests(
            probe.clone(),
            viewer_policy(),
            binding.clone(),
            vec![build_message()?],
        )
        .await?;

        let control = ForwardingProbe::default();
        let control_outbound = drive_coverage_requests(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            binding,
            vec![build_message()?],
        )
        .await?;
        assert_eq!(
            control.seen(),
            Vec::<(&'static str, Option<String>)>::new(),
            "PassthroughDefaults must not reach the inner handler"
        );
        assert_eq!(
            control.task_ids(),
            Vec::<String>::new(),
            "PassthroughDefaults must not reach the inner handler"
        );

        Ok((outbound, probe, control_outbound))
    }

    fn frame_for(outbound: &OutboundFrames, id: i64) -> anyhow::Result<ServerJsonRpcMessage> {
        let messages = outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let found = messages.into_iter().find(|message| match message {
            ServerJsonRpcMessage::Response(response) => response.id == NumberOrString::Number(id),
            ServerJsonRpcMessage::Error(error) => error.id == Some(NumberOrString::Number(id)),
            ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_) => false,
        });
        let Some(frame) = found else {
            anyhow::bail!("no frame with id {id}");
        };
        Ok(frame)
    }

    fn expect_response(frame: ServerJsonRpcMessage) -> anyhow::Result<ServerResult> {
        match frame {
            ServerJsonRpcMessage::Response(response) => Ok(response.result),
            other @ (ServerJsonRpcMessage::Request(_)
            | ServerJsonRpcMessage::Notification(_)
            | ServerJsonRpcMessage::Error(_)) => {
                anyhow::bail!("expected a response, got {other:?}")
            }
        }
    }

    fn expect_error(frame: ServerJsonRpcMessage) -> anyhow::Result<ErrorData> {
        match frame {
            ServerJsonRpcMessage::Error(error) => Ok(error.error),
            other @ (ServerJsonRpcMessage::Request(_)
            | ServerJsonRpcMessage::Response(_)
            | ServerJsonRpcMessage::Notification(_)) => {
                anyhow::bail!("expected an error, got {other:?}")
            }
        }
    }

    fn viewer_policy() -> Arc<ArcSwap<RbacPolicy>> {
        policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ))
    }

    #[test]
    /// Pins that `get_info`, `get_tool` and `supported_protocol_versions` forward.
    fn rbac_context_handler_forwards_direct_sync_methods() -> anyhow::Result<()> {
        // No record log in this driver: `get_info`, `get_tool` and
        // `supported_protocol_versions` are proven by value differential, so
        // rmcp's ambient calls cannot contaminate the proof.
        let wrapper = RbacContextHandler::new(ForwardingProbe::default(), viewer_policy(), false);
        let control = PassthroughDefaults::<ForwardingProbe>::default();

        // `get_info`: sentinel instructions no default body can produce.
        assert_eq!(
            wrapper.get_info().instructions.as_deref(),
            Some("forwarding-probe")
        );
        assert_eq!(control.get_info().instructions, None);

        // `get_tool`: the default returns `None` unconditionally.
        let tool = wrapper
            .get_tool("sentinel-tool")
            .context("inner get_tool must reach the caller")?;
        assert_eq!(tool.name, "sentinel-tool");
        assert_eq!(control.get_tool("sentinel-tool"), None);

        // `supported_protocol_versions`: the default is all of KNOWN_VERSIONS.
        assert_eq!(
            wrapper.supported_protocol_versions().as_ref(),
            SENTINEL_VERSIONS.as_slice()
        );
        assert_ne!(
            control.supported_protocol_versions().as_ref(),
            SENTINEL_VERSIONS.as_slice()
        );
        Ok(())
    }

    #[tokio::test]
    /// Pins that the plain-params request arm forwards and propagates errors.
    async fn rbac_context_handler_forwards_macro_request_plain_arm() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven method.
        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::CompleteRequest(CompleteRequest::new(
                        CompleteRequestParams::new(
                            Reference::Prompt(PromptReference::new("sentinel-prompt")),
                            ArgumentInfo::new("arg", "value"),
                        ),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer())?;
                Ok(message)
            },
            None,
        )
        .await?;

        // A sentinel *error* proves the `Result` channel, not just entry: the
        // plain-params arm of `delegate_request!` must propagate it verbatim.
        let error = expect_error(frame_for(&outbound, 1)?)?;
        assert_eq!(error.message, "forwarding-probe:complete");
        assert_eq!(probe.seen(), vec![("complete", Some("viewer".to_owned()))]);

        // Since rmcp 3.11 the default gates on the `completions` capability,
        // which `PassthroughDefaults` does not advertise: it answers
        // method-not-found, never the sentinel.
        let default_error = expect_error(frame_for(&control_outbound, 1)?)?;
        assert_eq!(default_error.code, ErrorCode::METHOD_NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    /// Pins that the optional-params request arm forwards to the inner handler.
    async fn rbac_context_handler_forwards_macro_request_option_arm() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven method.
        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::ListPromptsRequest(ListPromptsRequest::with_param(
                        PaginatedRequestParams::default(),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer())?;
                Ok(message)
            },
            None,
        )
        .await?;

        let option_response = expect_response(frame_for(&outbound, 1)?)?;
        let ServerResult::ListPromptsResult(listed) = option_response else {
            anyhow::bail!("expected a prompts/list result, got {option_response:?}")
        };
        assert_eq!(
            listed
                .prompts
                .first()
                .context("the sentinel prompt is present")?
                .name,
            "sentinel-prompt"
        );
        assert_eq!(
            probe.seen(),
            vec![("list_prompts", Some("viewer".to_owned()))]
        );

        // Since rmcp 3.11 the default gates on the `prompts` capability, which
        // `PassthroughDefaults` does not advertise: it answers method-not-found.
        let option_default_error = expect_error(frame_for(&control_outbound, 1)?)?;
        assert_eq!(option_default_error.code, ErrorCode::METHOD_NOT_FOUND);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // SEP-2640 skills drivers
    //
    // `SkillProbe::get_info` advertises exactly `resources` plus skills with
    // `directoryRead` and records nothing: rmcp's skills gate calls it on every
    // request. Each probe method records the identity and role it observes, so
    // the exact log proves forwarding and identity scoping together.
    // ----------------------------------------------------------------------

    const SENTINEL_SKILL_URI: &str = "skill://driver-sentinel-skill/SKILL.md";

    /// The custom-fallback names `on_custom_request` must refuse under RBAC
    /// (plan B-D4). Written out here, not imported, so dropping a name from
    /// the production list fails the driver.
    const RESERVED_NAMES: [&str; 9] = [
        "skills/list",
        "skills/get",
        "resources/directory/read",
        "resources/read",
        "resources/list",
        "resources/templates/list",
        "resources/subscribe",
        "resources/unsubscribe",
        "subscriptions/listen",
    ];

    fn sentinel_skill() -> Skill {
        Skill::new(
            SENTINEL_SKILL_URI,
            SkillFrontmatter::new("driver-sentinel-skill", "driver sentinel"),
            SkillResources::Dynamic,
        )
    }

    fn sentinel_directory_entry() -> Resource {
        Resource::new(
            "test://sentinel-directory/entry",
            "driver-sentinel-resource",
        )
    }

    fn custom_sentinel(method: &str) -> CustomResult {
        CustomResult::new(serde_json::json!({ "sentinel": method }))
    }

    fn skills_capabilities() -> ServerCapabilities {
        ServerCapabilities::builder()
            .enable_resources()
            .enable_skills_with_directory_read()
            .build()
    }

    /// `(method, current_identity(), current_role())` observed inside a call.
    type SkillCall = (String, Option<String>, Option<String>);

    /// The log entry of a call made inside the [`viewer`] identity scope.
    fn scoped(method: &str) -> SkillCall {
        (
            method.to_owned(),
            Some("viewer-key".to_owned()),
            Some("viewer".to_owned()),
        )
    }

    #[derive(Clone)]
    struct SkillProbe {
        capabilities: ServerCapabilities,
        seen: Arc<Mutex<Vec<SkillCall>>>,
    }

    impl Default for SkillProbe {
        fn default() -> Self {
            Self::with_capabilities(skills_capabilities())
        }
    }

    impl SkillProbe {
        fn with_capabilities(capabilities: ServerCapabilities) -> Self {
            Self {
                capabilities,
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record(&self, method: String) {
            let call = (method, rbac::current_identity(), rbac::current_role());
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
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "deliberate: src/rbac_context.rs::tests::SkillProbe implements rmcp's async ServerHandler; the in-memory probe returns immediately"
    )]
    impl ServerHandler for SkillProbe {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(self.capabilities.clone())
        }

        async fn list_skills(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListSkillsResult, ErrorData> {
            self.record("list_skills".to_owned());
            Ok(ListSkillsResult::with_all_items(vec![sentinel_skill()]))
        }

        async fn get_skill(
            &self,
            _request: GetSkillRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<GetSkillResult, ErrorData> {
            self.record("get_skill".to_owned());
            Ok(GetSkillResult::new(sentinel_skill()))
        }

        async fn read_resource_directory(
            &self,
            _request: ReadResourceDirectoryRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<ReadResourceDirectoryResult, ErrorData> {
            self.record("read_resource_directory".to_owned());
            Ok(ListResourcesResult::with_all_items(vec![
                sentinel_directory_entry(),
            ]))
        }

        async fn on_custom_request(
            &self,
            request: CustomRequest,
            _context: RequestContext<RoleServer>,
        ) -> Result<CustomResult, ErrorData> {
            self.record(format!("on_custom_request:{}", request.method));
            Ok(custom_sentinel(&request.method))
        }
    }

    fn disabled_policy() -> Arc<ArcSwap<RbacPolicy>> {
        Arc::new(ArcSwap::from_pointee(RbacPolicy::disabled()))
    }

    fn list_skills_request() -> ClientRequest {
        ClientRequest::ListSkillsRequest(ListSkillsRequest::with_param(
            PaginatedRequestParams::default(),
        ))
    }

    fn get_skill_request() -> ClientRequest {
        ClientRequest::GetSkillRequest(GetSkillRequest::new(GetSkillRequestParams::new(
            SENTINEL_SKILL_URI,
        )))
    }

    fn read_directory_request() -> ClientRequest {
        ClientRequest::ReadResourceDirectoryRequest(ReadResourceDirectoryRequest::new(
            ReadResourceDirectoryRequestParams::new("test://sentinel-directory/"),
        ))
    }

    fn read_skill_directory_request() -> ClientRequest {
        ClientRequest::ReadResourceDirectoryRequest(ReadResourceDirectoryRequest::new(
            ReadResourceDirectoryRequestParams::new("skill://driver-sentinel-skill/"),
        ))
    }

    fn custom_request(method: &str) -> ClientRequest {
        ClientRequest::CustomRequest(CustomRequest::new(method, None))
    }

    /// `request` as JSON-RPC id `id`, carrying the [`viewer`] identity.
    fn as_viewer(request: ClientRequest, id: i64) -> anyhow::Result<ClientJsonRpcMessage> {
        let mut message = request_message(request, id);
        attach_identity(&mut message, viewer())?;
        Ok(message)
    }

    /// Dispatch one message through a real service around `probe` and return
    /// the frame answering JSON-RPC id 1.
    async fn dispatch_skill(
        probe: SkillProbe,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        message: ClientJsonRpcMessage,
    ) -> anyhow::Result<ServerJsonRpcMessage> {
        let outbound = drive_coverage_requests(probe, rbac, None, vec![message]).await?;
        frame_for(&outbound, 1)
    }

    #[tokio::test]
    /// Pins that `skills/list` forwards inside the identity scope with RBAC disabled.
    async fn rbac_context_handler_forwards_list_skills() -> anyhow::Result<()> {
        let probe = SkillProbe::default();
        let frame = dispatch_skill(
            probe.clone(),
            disabled_policy(),
            as_viewer(list_skills_request(), 1)?,
        )
        .await?;
        let result = expect_response(frame)?;
        let ServerResult::ListSkillsResult(listed) = result else {
            anyhow::bail!("expected a skills/list result, got {result:?}")
        };
        assert_eq!(listed.skills, vec![sentinel_skill()]);
        assert_eq!(probe.seen(), vec![scoped("list_skills")]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that `skills/get` forwards inside the identity scope with RBAC disabled.
    async fn rbac_context_handler_forwards_get_skill() -> anyhow::Result<()> {
        let probe = SkillProbe::default();
        let frame = dispatch_skill(
            probe.clone(),
            disabled_policy(),
            as_viewer(get_skill_request(), 1)?,
        )
        .await?;
        let result = expect_response(frame)?;
        let ServerResult::GetSkillResult(fetched) = result else {
            anyhow::bail!("expected a skills/get result, got {result:?}")
        };
        assert_eq!(fetched.skill, sentinel_skill());
        assert_eq!(probe.seen(), vec![scoped("get_skill")]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that `resources/directory/read` forwards inside the identity scope with RBAC disabled.
    async fn rbac_context_handler_forwards_read_resource_directory() -> anyhow::Result<()> {
        let probe = SkillProbe::default();
        let frame = dispatch_skill(
            probe.clone(),
            disabled_policy(),
            as_viewer(read_directory_request(), 1)?,
        )
        .await?;
        let result = expect_response(frame)?;
        let ServerResult::ListResourcesResult(listed) = result else {
            anyhow::bail!("expected a resources/directory/read result, got {result:?}")
        };
        assert_eq!(listed.resources, vec![sentinel_directory_entry()]);
        assert_eq!(probe.seen(), vec![scoped("read_resource_directory")]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that RBAC enabled refuses every typed skills method for a role without a skills grant, without calling the inner handler.
    async fn rbac_context_handler_refuses_skills_while_rbac_enabled() -> anyhow::Result<()> {
        // `viewer_policy` lets the role call every tool but grants no skills:
        // the refusal does not depend on tool grants. A directory read is a
        // skills method only for a skill directory.
        type DenyCase = (fn() -> ClientRequest, ErrorData);
        let cases: [DenyCase; 3] = [
            (
                list_skills_request,
                ErrorData::method_not_found::<ListSkillsRequestMethod>(),
            ),
            (
                get_skill_request,
                ErrorData::method_not_found::<GetSkillRequestMethod>(),
            ),
            (
                read_skill_directory_request,
                ErrorData::method_not_found::<ReadResourceDirectoryRequestMethod>(),
            ),
        ];
        for (build, expected) in cases {
            let probe = SkillProbe::default();
            let frame =
                dispatch_skill(probe.clone(), viewer_policy(), as_viewer(build(), 1)?).await?;
            assert_eq!(expect_error(frame)?, expected);
            assert_eq!(probe.seen(), Vec::<SkillCall>::new());
        }
        Ok(())
    }

    /// A transport fed request by request, so one service (one handler
    /// instance) can answer several requests with state changes in between.
    struct ChannelTransport {
        inbound: mpsc::UnboundedReceiver<ClientJsonRpcMessage>,
        outbound: mpsc::UnboundedSender<ServerJsonRpcMessage>,
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "deliberate: src/rbac_context.rs::tests::ChannelTransport implements rmcp's async Transport; close returns immediately"
    )]
    impl Transport<RoleServer> for ChannelTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let sent = self.outbound.send(item);
            async move {
                // A dropped receiver only means the test stopped listening.
                let _receiver_gone = sent.is_err();
                Ok(())
            }
        }

        async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
            self.inbound.recv().await
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    /// Pins that one handler instance follows the reloadable policy on every skills call.
    async fn rbac_context_handler_skills_follow_policy_reload() -> anyhow::Result<()> {
        let rbac = disabled_policy();
        let probe = SkillProbe::default();
        let (inbound_tx, inbound) = mpsc::unbounded_channel();
        let (outbound, mut outbound_rx) = mpsc::unbounded_channel();
        let handler = RbacContextHandler::new(probe.clone(), Arc::clone(&rbac), false);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(
            handler,
            ChannelTransport { inbound, outbound },
            None,
        );

        let enabled = viewer_policy().load_full();
        let disabled = Arc::new(RbacPolicy::disabled());
        let mut frames = Vec::new();
        for (id, installed) in [(1, &disabled), (2, &enabled), (3, &disabled)] {
            rbac.store(Arc::clone(installed));
            inbound_tx
                .send(as_viewer(list_skills_request(), id)?)
                .map_err(|_closed| anyhow::anyhow!("service stopped receiving"))?;
            let frame = timeout(Duration::from_secs(1), outbound_rx.recv())
                .await
                .context("bounded wait for the skills/list answer")?
                .context("service closed before answering")?;
            frames.push(frame);
        }
        drop(inbound_tx);
        let _quit_reason = running.waiting().await.context("service task joins")?;

        let [first, second, third] = <[ServerJsonRpcMessage; 3]>::try_from(frames)
            .map_err(|got| anyhow::anyhow!("expected three frames, got {got:?}"))?;
        for forwarded in [first, third] {
            let result = expect_response(forwarded)?;
            let ServerResult::ListSkillsResult(listed) = result else {
                anyhow::bail!("expected a skills/list result, got {result:?}")
            };
            assert_eq!(listed.skills, vec![sentinel_skill()]);
        }
        assert_eq!(
            expect_error(second)?,
            ErrorData::method_not_found::<ListSkillsRequestMethod>()
        );
        assert_eq!(
            probe.seen(),
            vec![scoped("list_skills"), scoped("list_skills")]
        );
        Ok(())
    }

    /// A policy granting `viewer` every tool, every skill and every resource.
    fn fully_granted_viewer_policy() -> Arc<ArcSwap<RbacPolicy>> {
        policy(
            RoleConfig::new("viewer", vec!["*".to_owned()], vec!["*".to_owned()])
                .with_skills(vec!["*".to_owned()]),
        )
    }

    /// A `resources/read` whose params fail rmcp's typed variant.
    fn malformed_read_resource() -> anyhow::Result<ClientJsonRpcMessage> {
        let mut message: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_i64,
            "method": "resources/read",
            "params": { "uri": 7_i64 }
        }))?;
        attach_identity(&mut message, viewer())?;
        Ok(message)
    }

    #[tokio::test]
    /// Case 11: under RBAC `on_custom_request` refuses the nine reserved names even for a fully granted role, and forwards the rest.
    async fn rbac_context_handler_on_custom_request_refuses_reserved_names() -> anyhow::Result<()> {
        let probe = SkillProbe::default();
        let allowed_frame = dispatch_skill(
            probe.clone(),
            fully_granted_viewer_policy(),
            as_viewer(custom_request("x-sentinel/custom"), 1)?,
        )
        .await?;
        let allowed = expect_response(allowed_frame)?;
        let ServerResult::CustomResult(allowed_custom) = allowed else {
            anyhow::bail!("expected a custom result, got {allowed:?}")
        };
        assert_eq!(allowed_custom, custom_sentinel("x-sentinel/custom"));
        assert_eq!(
            probe.seen(),
            vec![scoped("on_custom_request:x-sentinel/custom")]
        );

        for name in RESERVED_NAMES {
            let refused = SkillProbe::default();
            let refused_frame = dispatch_skill(
                refused.clone(),
                fully_granted_viewer_policy(),
                as_viewer(custom_request(name), 1)?,
            )
            .await?;
            assert_eq!(
                expect_error(refused_frame)?,
                ErrorData::new(ErrorCode::METHOD_NOT_FOUND, name, None),
                "{name}"
            );
            assert_eq!(refused.seen(), Vec::<SkillCall>::new(), "{name}");

            let forwarded = SkillProbe::default();
            let forwarded_frame = dispatch_skill(
                forwarded.clone(),
                disabled_policy(),
                as_viewer(custom_request(name), 1)?,
            )
            .await?;
            let forwarded_result = expect_response(forwarded_frame)?;
            let ServerResult::CustomResult(forwarded_custom) = forwarded_result else {
                anyhow::bail!("expected a custom result, got {forwarded_result:?}")
            };
            assert_eq!(forwarded_custom, custom_sentinel(name));
            assert_eq!(
                forwarded.seen(),
                vec![scoped(&format!("on_custom_request:{name}"))]
            );
        }

        // A malformed `resources/read` falls through to the custom fallback
        // and never reaches the probe.
        let malformed = SkillProbe::default();
        let malformed_frame = dispatch_skill(
            malformed.clone(),
            fully_granted_viewer_policy(),
            malformed_read_resource()?,
        )
        .await?;
        assert_eq!(
            expect_error(malformed_frame)?,
            ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "resources/read", None)
        );
        assert_eq!(malformed.seen(), Vec::<SkillCall>::new());
        Ok(())
    }

    /// A `skills/get` whose params fail rmcp's typed variant, parsed from raw
    /// JSON-RPC exactly as a transport would.
    fn malformed_get_skill() -> anyhow::Result<ClientJsonRpcMessage> {
        let mut message: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_i64,
            "method": "skills/get",
            "params": { "uri": 7_i64 }
        }))?;
        attach_identity(&mut message, viewer())?;
        Ok(message)
    }

    #[tokio::test]
    /// Pins how a malformed `skills/get` is dispatched, and that RBAC refuses its custom fallback.
    async fn rbac_context_handler_refuses_malformed_skills_fallback() -> anyhow::Result<()> {
        let refused = SkillProbe::default();
        let refused_frame =
            dispatch_skill(refused.clone(), viewer_policy(), malformed_get_skill()?).await?;
        assert_eq!(
            expect_error(refused_frame)?,
            ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "skills/get", None)
        );
        assert_eq!(refused.seen(), Vec::<SkillCall>::new());

        // rmcp 3.11 observed behaviour with RBAC disabled: the untagged
        // `ClientRequest` falls through to `CustomRequest`, skipping the
        // skills gate, and the consumer's `on_custom_request` answers.
        let forwarded = SkillProbe::default();
        let forwarded_frame =
            dispatch_skill(forwarded.clone(), disabled_policy(), malformed_get_skill()?).await?;
        let result = expect_response(forwarded_frame)?;
        let ServerResult::CustomResult(custom) = result else {
            anyhow::bail!("expected a custom result, got {result:?}")
        };
        assert_eq!(custom, custom_sentinel("skills/get"));
        assert_eq!(
            forwarded.seen(),
            vec![scoped("on_custom_request:skills/get")]
        );
        Ok(())
    }

    #[tokio::test]
    /// Pins rmcp's skills capability gate: each row is refused before the inner handler.
    async fn rbac_context_handler_skills_gate_negatives() -> anyhow::Result<()> {
        type GateRow = (ServerCapabilities, fn() -> ClientRequest, ErrorData);
        let rows: [GateRow; 3] = [
            (
                ServerCapabilities::builder().enable_resources().build(),
                list_skills_request,
                ErrorData::method_not_found::<ListSkillsRequestMethod>(),
            ),
            (
                ServerCapabilities::builder().enable_skills().build(),
                list_skills_request,
                ErrorData::internal_error(
                    "the skills extension requires the resources capability",
                    None,
                ),
            ),
            (
                ServerCapabilities::builder()
                    .enable_resources()
                    .enable_skills()
                    .build(),
                read_directory_request,
                ErrorData::method_not_found::<ReadResourceDirectoryRequestMethod>(),
            ),
        ];
        for (capabilities, build, expected) in rows {
            let probe = SkillProbe::with_capabilities(capabilities);
            let frame =
                dispatch_skill(probe.clone(), disabled_policy(), as_viewer(build(), 1)?).await?;
            assert_eq!(expect_error(frame)?, expected);
            assert_eq!(probe.seen(), Vec::<SkillCall>::new());
        }
        Ok(())
    }

    #[tokio::test]
    /// Pins that the notification arm forwards and the passthrough stays silent.
    async fn rbac_context_handler_forwards_macro_notification_arm() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): notifications do not pass through
        // the request prelude, and the probe records nothing ambient, so the
        // expected log is exactly the driven method.
        let probe = ForwardingProbe::default();
        let mut message = JsonRpcMessage::notification(ClientNotification::CancelledNotification(
            CancelledNotification::new(CancelledNotificationParam::new(
                Some(NumberOrString::Number(1)),
                Some("coverage".to_owned()),
            )),
        ));
        attach_identity(&mut message, viewer())?;

        let outbound = Arc::new(Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![message]),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), viewer_policy(), false);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);
        probe.wait_for_seen_count(1).await?;
        let _cancel_result = running.cancel().await;

        // Notifications have no response channel, so record + observed identity
        // is the whole proof.
        assert_eq!(
            probe.seen(),
            vec![("on_cancelled", Some("viewer".to_owned()))]
        );

        // Negative control: the default notification arm does nothing. Dispatch
        // is spawned, so give it a bounded window and assert nothing arrived.
        let control = ForwardingProbe::default();
        let mut control_message =
            JsonRpcMessage::notification(ClientNotification::CancelledNotification(
                CancelledNotification::new(CancelledNotificationParam::new(
                    Some(NumberOrString::Number(1)),
                    Some("coverage".to_owned()),
                )),
            ));
        attach_identity(&mut control_message, viewer())?;
        let control_outbound = Arc::new(Mutex::new(Vec::new()));
        let control_transport = OpenTransport {
            inbound: VecDeque::from(vec![control_message]),
            outbound: Arc::clone(&control_outbound),
        };
        let control_handler = RbacContextHandler::new(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            false,
        );
        let control_running = serve_directly::<RoleServer, _, _, Infallible, _>(
            control_handler,
            control_transport,
            None,
        );
        timeout(Duration::from_millis(250), async {
            yield_now().await;
        })
        .await
        .context("bounded negative-control window")?;
        let _control_cancel_result = control_running.cancel().await;
        assert_eq!(control.seen(), Vec::new());
        Ok(())
    }

    #[tokio::test]
    /// Pins that `ping`, `initialize` and `discover` forward to the inner handler.
    async fn rbac_context_handler_forwards_ping_initialize_and_discover() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe) plus one exact full sequence per
        // method: each request is driven through its own service, and the probe
        // never records the ambient `get_info` / `supported_protocol_versions`
        // calls the prelude may make.
        // `ping` speaks the legacy lifecycle only: adding per-request metadata
        // would make rmcp answer method-not-found before the wrapper.
        let (ping_outbound, ping_probe, ping_control_outbound) = forward_once(
            || {
                let mut message =
                    request_message(ClientRequest::PingRequest(PingRequest::default()), 1);
                attach_identity(&mut message, viewer())?;
                Ok(message)
            },
            None,
        )
        .await?;
        assert!(matches!(
            frame_for(&ping_outbound, 1)?,
            ServerJsonRpcMessage::Response(_)
        ));
        assert!(matches!(
            frame_for(&ping_control_outbound, 1)?,
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(ping_probe.seen(), vec![("ping", Some("viewer".to_owned()))]);

        let (init_outbound, init_probe, init_control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::InitializeRequest(InitializeRequest::new(
                        InitializeRequestParams::new(
                            ClientCapabilities::default(),
                            Implementation::new("coverage-driver", "0.0.0"),
                        ),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer())?;
                Ok(message)
            },
            None,
        )
        .await?;
        let init_response = expect_response(frame_for(&init_outbound, 1)?)?;
        let ServerResult::InitializeResult(initialized) = init_response else {
            anyhow::bail!("expected an initialize result, got {init_response:?}")
        };
        assert_eq!(
            initialized.instructions.as_deref(),
            Some("forwarding-probe:initialize")
        );
        assert_eq!(
            init_probe.seen(),
            vec![("initialize", Some("viewer".to_owned()))]
        );
        let init_default_response = expect_response(frame_for(&init_control_outbound, 1)?)?;
        let ServerResult::InitializeResult(default_initialized) = init_default_response else {
            anyhow::bail!("expected an initialize result, got {init_default_response:?}")
        };
        assert_ne!(
            default_initialized.instructions.as_deref(),
            Some("forwarding-probe:initialize")
        );

        let (discover_outbound, discover_probe, discover_control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::DiscoverRequest(DiscoverRequest::new(
                        DiscoverRequestParams::default(),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer())?;
                attach_meta(&mut message, coverage_meta())?;
                Ok(message)
            },
            None,
        )
        .await?;
        let discover_response = expect_response(frame_for(&discover_outbound, 1)?)?;
        let ServerResult::DiscoverResult(discovered) = discover_response else {
            anyhow::bail!("expected a discover result, got {discover_response:?}")
        };
        assert_eq!(discovered.supported_versions, SENTINEL_VERSIONS.to_vec());
        assert_eq!(
            discover_probe.seen(),
            vec![("discover", Some("viewer".to_owned()))]
        );
        let discover_default_response = expect_response(frame_for(&discover_control_outbound, 1)?)?;
        let ServerResult::DiscoverResult(default_discovered) = discover_default_response else {
            anyhow::bail!("expected a discover result, got {discover_default_response:?}")
        };
        assert_ne!(
            default_discovered.supported_versions,
            SENTINEL_VERSIONS.to_vec()
        );
        Ok(())
    }

    #[tokio::test]
    /// Pins that the three notification methods forward and defaults stay silent.
    async fn rbac_context_handler_forwards_notifications() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven notifications.
        let probe = ForwardingProbe::default();
        let notifications = [
            "notifications/initialized",
            "notifications/roots/list_changed",
            "notifications/custom/coverage",
        ];
        let mut messages = Vec::new();
        for method in notifications {
            let notification = match method {
                "notifications/initialized" => {
                    ClientNotification::InitializedNotification(NotificationNoParam::default())
                }
                "notifications/roots/list_changed" => {
                    ClientNotification::RootsListChangedNotification(NotificationNoParam::default())
                }
                _ => ClientNotification::CustomNotification(CustomNotification::new(
                    method,
                    Some(serde_json::json!({ "coverage": true })),
                )),
            };
            let mut message = JsonRpcMessage::notification(notification);
            attach_identity(&mut message, viewer())?;
            messages.push(message);
        }

        let outbound = Arc::new(Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(messages),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), viewer_policy(), false);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(handler, transport, None);
        probe.wait_for_seen_count(3).await?;
        let _cancel_result = running.cancel().await;

        assert_eq!(
            probe.seen(),
            vec![
                ("on_initialized", Some("viewer".to_owned())),
                ("on_roots_list_changed", Some("viewer".to_owned())),
                ("on_custom_notification", Some("viewer".to_owned())),
            ]
        );

        // Negative control: all three defaults are no-ops; the bounded window
        // is the only way to observe a non-event.
        let control = ForwardingProbe::default();
        let mut control_messages = Vec::new();
        for method in notifications {
            let notification = match method {
                "notifications/initialized" => {
                    ClientNotification::InitializedNotification(NotificationNoParam::default())
                }
                "notifications/roots/list_changed" => {
                    ClientNotification::RootsListChangedNotification(NotificationNoParam::default())
                }
                _ => ClientNotification::CustomNotification(CustomNotification::new(
                    method,
                    Some(serde_json::json!({ "coverage": true })),
                )),
            };
            let mut control_message = JsonRpcMessage::notification(notification);
            attach_identity(&mut control_message, viewer())?;
            control_messages.push(control_message);
        }
        let control_outbound = Arc::new(Mutex::new(Vec::new()));
        let control_transport = OpenTransport {
            inbound: VecDeque::from(control_messages),
            outbound: Arc::clone(&control_outbound),
        };
        let control_handler = RbacContextHandler::new(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            false,
        );
        let control_running = serve_directly::<RoleServer, _, _, Infallible, _>(
            control_handler,
            control_transport,
            None,
        );
        timeout(Duration::from_millis(250), async {
            yield_now().await;
        })
        .await
        .context("bounded negative-control window")?;
        let _control_cancel_result = control_running.cancel().await;
        assert_eq!(control.seen(), Vec::new());
        Ok(())
    }

    #[tokio::test]
    /// Pins that a task-returning `call_tool` binds the outbound task ID.
    async fn rbac_context_handler_forwards_task_producing_call_tool() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven method.
        let secret = task_secret();
        let alice = identity_named("alice");

        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::CallToolRequest(CallToolRequest::new(
                        CallToolRequestParams::new("sentinel-tool"),
                    )),
                    1,
                );
                attach_identity(&mut message, alice.clone())?;
                attach_meta(&mut message, coverage_meta())?;
                Ok(message)
            },
            Some(secret.clone()),
        )
        .await?;

        // The inner returned a raw task ID; the client must see it bound.
        let result = expect_response(frame_for(&outbound, 1)?)?;
        let ServerResult::CreateTaskResult(created) = result else {
            anyhow::bail!("expected a create-task result, got {result:?}")
        };
        assert_ne!(created.task.task_id, "raw-task-call");
        let raw =
            task_binding::unwrap_and_verify(&secret, &created.task.task_id, &fingerprint(&alice))
                .context("the client-visible id must unwrap for its owner")?;
        assert_eq!(raw.as_str(), "raw-task-call");
        assert_eq!(probe.seen(), vec![("call_tool", Some("viewer".to_owned()))]);

        // The default `call_tool` errors, so it cannot produce the sentinel.
        let error = expect_error(frame_for(&control_outbound, 1)?)?;
        assert_eq!(error.code, ErrorCode::METHOD_NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    /// Pins that task binding rewrites update/cancel IDs and rejects a foreign one.
    async fn rbac_context_handler_forwards_task_binding_on_update_and_cancel() -> anyhow::Result<()>
    {
        // Mechanism 1 (ambient-silent probe): the tasks gate calls `get_info`,
        // which this probe does not record, so the expected log is exactly the
        // driven method.
        let secret = task_secret();
        let alice = identity_named("alice");
        let bob = identity_named("bob");
        let alice_fingerprint = fingerprint(&alice);
        let raw_update = RawTaskId::parse("raw-update").context("valid id")?;
        let raw_cancel = RawTaskId::parse("raw-cancel").context("valid id")?;
        let bound_update = task_binding::wrap(&secret, &raw_update, &alice_fingerprint);
        let bound_cancel = task_binding::wrap(&secret, &raw_cancel, &alice_fingerprint);

        let (update_outbound, update_probe, update_control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::UpdateTaskRequest(UpdateTaskRequest::new(
                        UpdateTaskParams::new(bound_update.clone(), InputResponses::new()),
                    )),
                    1,
                );
                attach_identity(&mut message, alice.clone())?;
                attach_meta(&mut message, coverage_meta())?;
                Ok(message)
            },
            Some(secret.clone()),
        )
        .await?;
        assert!(matches!(
            frame_for(&update_outbound, 1)?,
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(
            update_probe.task_ids(),
            vec!["raw-update".to_owned()],
            "the inner handler must observe the RAW id, never the wrapper"
        );
        assert_eq!(
            update_probe.seen(),
            vec![("update_task", Some("viewer".to_owned()))]
        );
        let update_control_error = expect_error(frame_for(&update_control_outbound, 1)?)?;
        assert_eq!(update_control_error.code, ErrorCode::METHOD_NOT_FOUND);

        let (cancel_outbound, cancel_probe, cancel_control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
                        CancelTaskParams::new(bound_cancel.clone()),
                    )),
                    1,
                );
                attach_identity(&mut message, alice.clone())?;
                attach_meta(&mut message, coverage_meta())?;
                Ok(message)
            },
            Some(secret.clone()),
        )
        .await?;
        assert!(matches!(
            frame_for(&cancel_outbound, 1)?,
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(cancel_probe.task_ids(), vec!["raw-cancel".to_owned()]);
        assert_eq!(
            cancel_probe.seen(),
            vec![("cancel_task", Some("viewer".to_owned()))]
        );
        let cancel_control_error = expect_error(frame_for(&cancel_control_outbound, 1)?)?;
        assert_eq!(cancel_control_error.code, ErrorCode::METHOD_NOT_FOUND);

        // A bound id for the wrong identity is rejected before the inner handler
        // records anything.
        let bob_bound = task_binding::wrap(
            &secret,
            &RawTaskId::parse("raw-cancel").context("valid id")?,
            &fingerprint(&bob),
        );
        let mut message = request_message(
            ClientRequest::CancelTaskRequest(CancelTaskRequest::new(CancelTaskParams::new(
                bob_bound,
            ))),
            1,
        );
        attach_identity(&mut message, alice.clone())?;
        attach_meta(&mut message, coverage_meta())?;
        let reject_probe = ForwardingProbe::default();
        let reject_outbound = drive_coverage_requests(
            reject_probe.clone(),
            viewer_policy(),
            Some(secret),
            vec![message],
        )
        .await?;
        let reject_error = expect_error(frame_for(&reject_outbound, 1)?)?;
        assert_eq!(reject_error.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(reject_probe.task_ids(), Vec::<String>::new());
        assert_eq!(
            reject_probe.seen(),
            Vec::<(&'static str, Option<String>)>::new()
        );
        Ok(())
    }
}
