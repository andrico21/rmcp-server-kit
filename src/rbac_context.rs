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

use std::{borrow::Cow, future::Future, sync::Arc};

use arc_swap::ArcSwap;
use axum::http::request::Parts;
#[allow(
    deprecated,
    reason = "ServerHandler delegation must import legacy logging/subscription parameter types until rmcp removes those methods"
)]
use rmcp::{
    ErrorData, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CancelTaskParams, CancelledNotificationParam,
        CompleteRequestParams, CompleteResult, CustomNotification, CustomRequest, CustomResult,
        DiscoverResult, Extensions, GetPromptRequestParams, GetPromptResponse, GetTaskParams,
        GetTaskResult, InitializeRequestParams, InitializeResult, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
        ProgressNotificationParam, ProtocolVersion, ReadResourceRequestParams,
        ReadResourceResponse, ServerConfig, SetLevelRequestParams, SubscribeRequestParams,
        SubscriptionFilter, Tool, UnsubscribeRequestParams, UpdateTaskParams,
    },
    service::{NotificationContext, RequestContext, RoleServer, SubscriptionContext},
};

use crate::{
    auth::AuthIdentity,
    rbac::{RbacDecision, RbacPolicy},
    secret::SecretString,
    session_binding::{IdentityFingerprint, SessionBindingSecret, fingerprint},
    task_binding::{self, RawTaskId},
};

// Owns RBAC request context and RBAC-derived list visibility.
#[derive(Debug, Clone)]
pub(crate) struct RbacContextHandler<H> {
    inner: H,
    rbac: Arc<ArcSwap<RbacPolicy>>,
    tool_list_filtering_enabled: bool,
    /// When `Some`, task IDs crossing this boundary are HMAC-bound to the
    /// authenticated identity. `None` leaves them untouched.
    task_binding: Option<SessionBindingSecret>,
}

impl<H> RbacContextHandler<H> {
    #[must_use]
    pub(crate) fn new(
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

    fn filtered_tool_list(
        &self,
        mut result: ListToolsResult,
        role: Option<&str>,
    ) -> ListToolsResult {
        let policy = self.rbac.load_full();
        let Some(role) = role else {
            return result;
        };
        if !self.tool_list_filtering_enabled || !policy.is_enabled() || role.is_empty() {
            return result;
        }

        result
            .tools
            .retain(|tool| policy.check_operation(role, &tool.name) == RbacDecision::Allow);
        result.with_cache_scope(rmcp::model::CacheScope::Private)
    }
}

fn identity_from_request(context: &RequestContext<RoleServer>) -> Option<AuthIdentity> {
    context_identity(&context.extensions)
}

/// Verify an external task ID and recover the raw ID the handler knows.
///
/// SECURITY: every failure mode -- malformed, unwrapped, signed for a different
/// identity, or signed under a rotated secret -- collapses to the *same* error
/// that upstream `rmcp` returns for a genuinely unknown task
/// (`McpError::invalid_params("unknown task: ...")`). Distinguishing them would
/// turn this into an oracle that confirms a task's existence to a non-owner.
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

fn identity_from_notification(context: &NotificationContext<RoleServer>) -> Option<AuthIdentity> {
    context_identity(&context.extensions)
}

fn identity_from_subscription(context: &SubscriptionContext) -> Option<AuthIdentity> {
    identity_from_request(context.request_context())
}

fn context_identity(extensions: &Extensions) -> Option<AuthIdentity> {
    extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AuthIdentity>())
        .cloned()
}

async fn scope_with_identity<T, F, Fut>(identity: Option<AuthIdentity>, call: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let Some(identity) = identity else {
        return call().await;
    };
    if identity.role.is_empty() {
        return call().await;
    }

    let token = identity
        .raw_token
        .unwrap_or_else(|| SecretString::from(String::new()));
    let sub = identity.sub.unwrap_or_default();
    crate::rbac::with_rbac_scope_lazy(identity.role, identity.name, token, sub, call).await
}

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

macro_rules! delegate_notification {
    ($name:ident, $params:ident) => {
        async fn $name(&self, notification: $params, context: NotificationContext<RoleServer>) {
            let identity = identity_from_notification(&context);
            scope_with_identity(identity, || self.inner.$name(notification, context)).await;
        }
    };
}

#[allow(
    deprecated,
    reason = "ServerHandler delegation must include the legacy subscribe/unsubscribe methods until rmcp removes them"
)]
impl<H: ServerHandler> ServerHandler for RbacContextHandler<H> {
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        let identity = identity_from_request(&context);
        scope_with_identity(identity, || self.inner.ping(context)).await
    }

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
    // plain delegation is required -- the trait default would shadow an inner
    // override.
    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.negotiate_initialize(request)
    }

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
    delegate_request!(
        list_resources,
        Option<PaginatedRequestParams>,
        ListResourcesResult
    );
    delegate_request!(
        list_resource_templates,
        Option<PaginatedRequestParams>,
        ListResourceTemplatesResult
    );
    delegate_request!(
        read_resource,
        ReadResourceRequestParams,
        ReadResourceResponse
    );

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
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
    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let identity = identity_from_subscription(&context);
        scope_with_identity(identity, || self.inner.listen(context)).await
    }

    delegate_request!(subscribe, SubscribeRequestParams, ());
    delegate_request!(unsubscribe, UnsubscribeRequestParams, ());
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

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let identity = identity_from_request(&context);
        let role = identity.as_ref().map(|identity| identity.role.clone());
        let result =
            scope_with_identity(identity, || self.inner.list_tools(request, context)).await?;
        Ok(self.filtered_tool_list(result, role.as_deref()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    delegate_request!(on_custom_request, CustomRequest, CustomResult);
    delegate_notification!(on_cancelled, CancelledNotificationParam);
    delegate_notification!(on_progress, ProgressNotificationParam);

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        let identity = identity_from_notification(&context);
        scope_with_identity(identity, || self.inner.on_initialized(context)).await;
    }

    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        let identity = identity_from_notification(&context);
        scope_with_identity(identity, || self.inner.on_roots_list_changed(context)).await;
    }

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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible, sync::Arc};

    use rmcp::{
        ServerHandler,
        model::{
            ArgumentInfo, CacheScope, CallToolRequest, CallToolRequestParams, CancelTaskRequest,
            CancelledNotification, CancelledNotificationParam, ClientCapabilities,
            ClientJsonRpcMessage, ClientNotification, ClientRequest, CompleteRequest,
            CompleteRequestParams, CreateTaskResult, CustomNotification, DiscoverRequest,
            DiscoverRequestParams, Extensions, GetExtensions, InitializeRequest, JsonObject,
            JsonRpcMessage, ListPromptsRequest, ListPromptsResult, ListToolsRequest,
            ListToolsRequestMethod, ListToolsResult, NumberOrString, PaginatedRequestParams,
            PingRequest, Prompt, PromptReference, Reference, ServerJsonRpcMessage, ServerResult,
            Tool, UpdateTaskRequest,
        },
        service::RoleServer,
        transport::Transport,
    };

    use super::*;
    use crate::{
        auth::AuthMethod,
        rbac::{AllowOperationMatching, RbacConfig, RoleConfig},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ObservedRole {
        Present(String),
        Missing,
    }

    #[derive(Clone)]
    struct ListToolsHandler {
        pages: Arc<std::sync::Mutex<VecDeque<ListToolsResult>>>,
        observed_role: Arc<std::sync::Mutex<Option<ObservedRole>>>,
    }

    impl ListToolsHandler {
        fn new(pages: Vec<ListToolsResult>) -> Self {
            Self {
                pages: Arc::new(std::sync::Mutex::new(VecDeque::from(pages))),
                observed_role: Arc::new(std::sync::Mutex::new(None)),
            }
        }

        fn observed_role(&self) -> Option<ObservedRole> {
            self.observed_role.lock().ok().and_then(|role| role.clone())
        }
    }

    #[allow(
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
                *role = Some(
                    crate::rbac::current_role()
                        .map_or(ObservedRole::Missing, ObservedRole::Present),
                );
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
        outbound: Arc<std::sync::Mutex<Vec<ServerJsonRpcMessage>>>,
    }

    impl InMemoryTransport {
        fn new(
            messages: Vec<ClientJsonRpcMessage>,
        ) -> (Self, Arc<std::sync::Mutex<Vec<ServerJsonRpcMessage>>>) {
            let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    inbound: VecDeque::from(messages),
                    outbound: Arc::clone(&outbound),
                },
                outbound,
            )
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "rmcp Transport requires async receive/close; this in-memory test transport returns immediately"
    )]
    impl Transport<RoleServer> for InMemoryTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let outbound = Arc::clone(&self.outbound);
            async move {
                if let Ok(mut outbound) = outbound.lock() {
                    outbound.push(item);
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

    fn page(names: &[&'static str]) -> ListToolsResult {
        ListToolsResult::with_all_items(names.iter().map(|name| tool(name)).collect())
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
        if let Some(identity) = identity {
            let mut parts = axum::http::Request::new(()).into_parts().0;
            parts.extensions.insert(identity);
            request.extensions_mut().insert(parts);
        }
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

    async fn list_tools_via_service(
        inner: ListToolsHandler,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        filtering_enabled: bool,
        identity: Option<AuthIdentity>,
    ) -> ListToolsResult {
        let message = list_request(1, identity);
        let (transport, outbound) = InMemoryTransport::new(vec![message]);
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            RbacContextHandler::new(inner, rbac, filtering_enabled),
            transport,
            None,
        );
        running.waiting().await.expect("service task joins");

        let messages = outbound.lock().expect("outbound messages lock").clone();
        let Some(message) = messages.first() else {
            panic!("expected one response");
        };
        let ServerJsonRpcMessage::Response(response) = message else {
            panic!("expected JSON-RPC response, got {message:?}");
        };
        if let ServerResult::ListToolsResult(result) = &response.result {
            result.clone()
        } else {
            panic!("expected tools/list result, got {:?}", response.result);
        }
    }

    async fn list_tools_for_viewer(
        page: ListToolsResult,
        rbac: Arc<ArcSwap<RbacPolicy>>,
    ) -> ListToolsResult {
        list_tools_via_service(
            ListToolsHandler::new(vec![page]),
            rbac,
            true,
            Some(viewer()),
        )
        .await
    }

    #[tokio::test]
    async fn list_tools_filters_denied_tools() {
        let rbac = glob_policy(RoleConfig::new(
            "viewer",
            vec!["a_*".to_owned()],
            vec!["*".to_owned()],
        ));

        let result = list_tools_for_viewer(page(&["a_x", "b_y"]), rbac).await;

        assert_eq!(result.tools, vec![tool("a_x")]);
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
    }

    #[tokio::test]
    async fn list_tools_applies_global_deny() {
        let rbac = policy_with_global_deny(
            RoleConfig::new("viewer", vec!["*".to_owned()], vec!["*".to_owned()]),
            vec!["*_delete_*".to_owned()],
        );

        let result = list_tools_for_viewer(page(&["safe_read", "user_delete_all"]), rbac).await;

        assert_eq!(result.tools, vec![tool("safe_read")]);
    }

    #[tokio::test]
    async fn list_tools_unfiltered_when_rbac_disabled() {
        let result = list_tools_for_viewer(
            page(&["a_x", "b_y"]),
            Arc::new(ArcSwap::new(Arc::new(RbacPolicy::disabled()))),
        )
        .await;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        assert_eq!(result.cache_scope, None);
    }

    #[tokio::test]
    async fn list_tools_unfiltered_when_no_role() {
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
        .await;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        assert_eq!(result.cache_scope, None);
    }

    #[tokio::test]
    async fn list_tools_sets_cache_scope_private_when_filtered() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned(), "b_y".to_owned()],
            vec!["*".to_owned()],
        ));
        let mut inner_page = page(&["a_x", "b_y"]);
        inner_page.cache_scope = Some(CacheScope::Public);

        let result = list_tools_for_viewer(inner_page, rbac).await;

        assert_eq!(result.tools, vec![tool("a_x"), tool("b_y")]);
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
    }

    #[tokio::test]
    async fn list_tools_preserves_next_cursor() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let mut inner_page = page(&["a_x", "b_y"]);
        inner_page.next_cursor = Some("next".to_owned());

        let result = list_tools_for_viewer(inner_page, rbac).await;

        assert_eq!(result.tools, vec![tool("a_x")]);
        assert_eq!(result.next_cursor.as_deref(), Some("next"));
    }

    #[tokio::test]
    async fn list_tools_preserves_ttl_ms_while_forcing_private() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned(), "b_y".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner_page = page(&["a_x", "b_y"]).with_ttl_ms(30_000);

        let result = list_tools_for_viewer(inner_page, rbac).await;

        assert_eq!(result.ttl_ms, Some(30_000));
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
    }

    #[tokio::test]
    async fn list_tools_allows_empty_page_with_live_cursor() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["allowed_later".to_owned()],
            vec!["*".to_owned()],
        ));
        let mut inner_page = page(&["denied_now"]);
        inner_page.next_cursor = Some("next".to_owned());

        let result = list_tools_for_viewer(inner_page, rbac).await;

        assert!(result.tools.is_empty());
        assert_eq!(result.next_cursor.as_deref(), Some("next"));
    }

    #[tokio::test]
    async fn list_tools_filters_when_role_present_after_delegation() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner = ListToolsHandler::new(vec![page(&["a_x", "b_y"])]);
        let probe = inner.clone();

        let result = list_tools_via_service(inner, rbac, true, Some(viewer())).await;

        assert_eq!(
            probe.observed_role(),
            Some(ObservedRole::Present("viewer".to_owned()))
        );
        assert_eq!(crate::rbac::current_role(), None);
        assert_eq!(result.tools, vec![tool("a_x")]);
    }

    #[tokio::test]
    async fn list_tools_reflects_reloaded_policy() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["a_x".to_owned()],
            vec!["*".to_owned()],
        ));
        let inner = ListToolsHandler::new(vec![page(&["a_x", "b_y"]), page(&["a_x", "b_y"])]);

        let first =
            list_tools_via_service(inner.clone(), Arc::clone(&rbac), true, Some(viewer())).await;
        rbac.store(Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
            RoleConfig::new("viewer", vec!["b_y".to_owned()], vec!["*".to_owned()]),
        ]))));
        let second = list_tools_via_service(inner, rbac, true, Some(viewer())).await;

        assert_eq!(first.tools, vec![tool("a_x")]);
        assert_eq!(second.tools, vec![tool("b_y")]);
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
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl TaskProbeHandler {
        fn seen(&self) -> Vec<String> {
            self.seen.lock().map(|s| s.clone()).unwrap_or_default()
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler requires async methods; this in-memory test handler returns immediately"
    )]
    impl ServerHandler for TaskProbeHandler {
        fn get_info(&self) -> ServerConfig {
            // rmcp gates `tasks/*` on the server advertising the extension AND
            // the client declaring it, so both must be set up or the request is
            // rejected upstream and never reaches the binding under test.
            ServerConfig::new(
                rmcp::model::ServerCapabilities::builder()
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
            Ok(GetTaskResult::new(rmcp::model::DetailedTask::new(
                rmcp::model::Task::new(
                    request.task_id,
                    rmcp::model::TaskStatus::Working,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
                rmcp::model::TaskPayload::Working,
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
        #[allow(
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
            name: name.to_owned(),
            role: "viewer".to_owned(),
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        }
    }

    fn task_secret() -> SessionBindingSecret {
        SessionBindingSecret::Configured(SecretString::from(
            "task-binding-test-secret-at-least-32-bytes".to_owned(),
        ))
    }

    fn get_task_request(id: i64, task_id: &str, identity: AuthIdentity) -> ClientJsonRpcMessage {
        let mut request = ClientRequest::GetTaskRequest(rmcp::model::GetTaskRequest::new(
            GetTaskParams::new(task_id),
        ));
        // The envelope extensions are the canonical runtime home for `_meta`;
        // a `params.meta` set in-memory is only honoured on serialization, so
        // it would never reach `RequestContext::client_capabilities()` here.
        let mut meta = rmcp::model::RequestMetaObject::default();
        meta.set_client_capabilities(ClientCapabilities::builder().enable_tasks().build());
        request.extensions_mut().insert(meta);
        let mut parts = axum::http::Request::new(()).into_parts().0;
        parts.extensions.insert(identity);
        request.extensions_mut().insert(parts);
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

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
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        running.waiting().await.expect("service task joins");

        let messages = outbound.lock().expect("outbound messages lock").clone();
        let Some(message) = messages.first() else {
            panic!("expected one response");
        };
        match message {
            ServerJsonRpcMessage::Response(response) => {
                if let ServerResult::GetTaskResult(result) = &response.result {
                    Ok(result.clone())
                } else {
                    panic!("expected tasks/get result, got {:?}", response.result);
                }
            }
            ServerJsonRpcMessage::Error(err) => Err(err.error.clone()),
            other @ (ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_)) => {
                panic!("unexpected message {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn task_binding_wraps_outbound_and_unwraps_inbound_for_the_owner() {
        let secret = task_secret();
        let alice = identity_named("alice");
        let fp = fingerprint(&alice);
        let raw = RawTaskId::parse("task-42").expect("valid id");
        let external = task_binding::wrap(&secret, &raw, &fp);
        let probe = TaskProbeHandler::default();

        let result = get_task_via_service(
            probe.clone(),
            Some(secret.clone()),
            &external,
            alice.clone(),
        )
        .await
        .expect("owner may read its own task");

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
    }

    #[tokio::test]
    async fn task_binding_denies_a_second_identity_and_never_calls_the_handler() {
        let secret = task_secret();
        let alice = identity_named("alice");
        let bob = identity_named("bob");
        let raw = RawTaskId::parse("task-42").expect("valid id");
        let alices_task = task_binding::wrap(&secret, &raw, &fingerprint(&alice));
        let probe = TaskProbeHandler::default();

        let err = get_task_via_service(probe.clone(), Some(secret), &alices_task, bob)
            .await
            .expect_err("bob must not reach alice's task");

        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "must match upstream's unknown-task error code"
        );
        assert!(
            err.message.contains("unknown task"),
            "must be indistinguishable from a nonexistent task, got {:?}",
            err.message
        );
        assert!(
            probe.seen().is_empty(),
            "the inner handler must never see a rejected task id"
        );
    }

    /// A raw (unwrapped) id must be rejected too, or an attacker could simply
    /// strip the wrapper and hit the handler directly.
    #[tokio::test]
    async fn task_binding_rejects_raw_and_malformed_ids_identically() {
        let secret = task_secret();
        let alice = identity_named("alice");
        let probe = TaskProbeHandler::default();

        for candidate in ["task-42", "", "t1.", "t1.a.b", "v1.a.b", "garbage"] {
            let Err(err) = get_task_via_service(
                probe.clone(),
                Some(secret.clone()),
                candidate,
                alice.clone(),
            )
            .await
            else {
                panic!("must reject {candidate:?}");
            };
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert!(
                err.message.contains("unknown task"),
                "every failure mode must look alike; {candidate:?} gave {:?}",
                err.message
            );
        }
        assert!(probe.seen().is_empty());
    }

    /// Disabled binding must be perfectly transparent, so existing task-using
    /// consumers are unaffected until they opt in.
    #[tokio::test]
    async fn task_binding_disabled_passes_ids_through_untouched() {
        let probe = TaskProbeHandler::default();

        let result = get_task_via_service(probe.clone(), None, "task-42", identity_named("alice"))
            .await
            .expect("pass-through when disabled");

        assert_eq!(probe.seen(), vec!["task-42".to_owned()]);
        assert_eq!(result.task.task.task_id, "task-42");
    }

    #[derive(Clone, Default)]
    struct NotificationProbeHandler {
        send_result: Arc<std::sync::Mutex<Option<String>>>,
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler requires async methods; this in-memory test handler returns immediately"
    )]
    impl ServerHandler for NotificationProbeHandler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(
                rmcp::model::ServerCapabilities::builder()
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
            let task = rmcp::model::DetailedTask::new(
                rmcp::model::Task::new(
                    "task-42",
                    rmcp::model::TaskStatus::Working,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
                rmcp::model::TaskPayload::Working,
            );
            let outcome = context
                .sink()
                .send(rmcp::model::ServerNotification::TaskStatusNotification(
                    rmcp::model::TaskStatusNotification::new(
                        rmcp::model::TaskStatusNotificationParams::new(task),
                    ),
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

    /// Like [`InMemoryTransport`] but never reports end-of-stream, so a
    /// long-running `subscriptions/listen` handler is not cancelled by the
    /// service shutting down the moment the inbound queue drains.
    struct OpenTransport {
        inbound: VecDeque<ClientJsonRpcMessage>,
        outbound: Arc<std::sync::Mutex<Vec<ServerJsonRpcMessage>>>,
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "rmcp Transport requires async receive/close; this in-memory test transport returns immediately"
    )]
    impl Transport<RoleServer> for OpenTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let outbound = Arc::clone(&self.outbound);
            async move {
                if let Ok(mut outbound) = outbound.lock() {
                    outbound.push(item);
                }
                Ok(())
            }
        }

        async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
            if let Some(message) = self.inbound.pop_front() {
                return Some(message);
            }
            std::future::pending().await
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
    /// notifications routable** -- at which point the task ID inside
    /// `TaskStatusNotificationParams` must be wrapped before it leaves the
    /// process, exactly as `call_tool` and `get_task` already wrap theirs.
    #[tokio::test]
    async fn task_status_notifications_remain_unroutable_until_binding_is_added() {
        let probe = NotificationProbeHandler::default();
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ));

        let filter = SubscriptionFilter::builder().tools_list_changed().build();
        let mut params = rmcp::model::SubscriptionsListenRequestParams::new(filter);
        let mut meta = rmcp::model::RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::default());
        params.meta = Some(meta.clone());
        let mut request = ClientRequest::SubscriptionsListenRequest(
            rmcp::model::SubscriptionsListenRequest::new(params),
        );
        request.extensions_mut().insert(meta);
        let mut parts = axum::http::Request::new(()).into_parts().0;
        parts.extensions.insert(identity_named("alice"));
        request.extensions_mut().insert(parts);
        let message = JsonRpcMessage::request(request, NumberOrString::Number(1));

        let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![message]),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), rbac, false);
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );

        // The transport never closes, so poll for the handler's result instead
        // of joining the service, then cancel it.
        let mut recorded = None;
        for _ in 0..10_000 {
            if let Some(value) = probe.send_result.lock().ok().and_then(|slot| slot.clone()) {
                recorded = Some(value);
                break;
            }
            tokio::task::yield_now().await;
        }
        running.cancel().await.ok();

        let outcome = recorded.unwrap_or_else(|| {
            let msgs = outbound.lock().expect("outbound lock").clone();
            panic!("listen was never invoked; server responded: {msgs:?}")
        });

        assert!(
            outcome.contains("UnsupportedNotification") && outcome.contains("notifications/tasks"),
            "TRIPWIRE: rmcp now routes task status notifications (got {outcome:?}). \
             This is not a flaky test -- bind the task_id inside \
             TaskStatusNotificationParams in RbacContextHandler::listen before \
             shipping this rmcp version, or identity A's raw task ID will leak \
             to whoever is subscribed."
        );
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
            let mut info = ServerConfig::new(rmcp::model::ServerCapabilities::default());
            info.instructions = Some("inner negotiate_initialize override".to_owned());
            Ok(info)
        }
    }

    #[test]
    fn rbac_context_handler_preserves_inner_negotiate_initialize_override() {
        let rbac = policy(RoleConfig::new(
            "viewer",
            vec!["*".to_owned()],
            vec!["*".to_owned()],
        ));
        let handler = RbacContextHandler::new(NegotiateProbe, rbac, false);
        let request = InitializeRequestParams::new(
            ClientCapabilities::default(),
            rmcp::model::Implementation::new("delegation-test-client", "0.0.0"),
        );

        // Direct call on the wrapper: negotiation carries no request context,
        // so there is no identity to scope and delegation must be transparent.
        let result = handler
            .negotiate_initialize(&request)
            .expect("direct negotiation must succeed");

        assert_eq!(
            result.instructions.as_deref(),
            Some("inner negotiate_initialize override"),
            "wrapper must delegate to the inner `negotiate_initialize` override"
        );
    }

    // ----------------------------------------------------------------------
    // Semantic coverage drivers
    //
    // Each driver proves, by exact equality on the inner probe's record log
    // (and on sentinel values no rmcp default body can produce), that
    // `RbacContextHandler` forwarded the call -- and, because the probe reads
    // `current_role()` inside the method body, that it did so inside the
    // identity scope. Every driver also runs the same request against
    // `PassthroughDefaults` -- the wrapper with all delegations deleted -- and
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
    fn probe_capabilities() -> rmcp::model::ServerCapabilities {
        rmcp::model::ServerCapabilities::builder()
            .enable_prompts()
            .enable_resources()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_tasks()
            .build()
    }

    /// The observed call log: `(method, role observed inside the call)`.
    type ObservedCalls = Arc<std::sync::Mutex<Vec<(&'static str, Option<String>)>>>;

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
        task_ids: Arc<std::sync::Mutex<Vec<String>>>,
        notify: Arc<tokio::sync::Notify>,
    }

    impl ForwardingProbe {
        fn record(&self, method: &'static str) {
            let role = crate::rbac::current_role();
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
            self.seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default()
        }

        fn task_ids(&self) -> Vec<String> {
            self.task_ids
                .lock()
                .map(|ids| ids.clone())
                .unwrap_or_default()
        }

        async fn wait_for_seen_count(&self, count: usize) {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while self.seen().len() < count {
                    self.notify.notified().await;
                }
            })
            .await
            .expect("delegated handler methods should be observed");
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        deprecated,
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
            Ok(CallToolResponse::Task(CreateTaskResult::new(
                rmcp::model::Task::new(
                    "raw-task-call",
                    rmcp::model::TaskStatus::Working,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )))
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
    /// Parsed by `tests/delegation_guard.rs`, which asserts this table covers
    /// exactly its `DIRECTLY_DELEGATED ∪ BEHAVIORAL_WRAPPED` classification --
    /// so a method cannot be added or reclassified without a driver. The nine
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
            "rbac_context_handler_forwards_macro_request_option_arm",
        ),
        (
            "list_resource_templates",
            "rbac_context_handler_forwards_macro_request_option_arm",
        ),
        (
            "read_resource",
            "rbac_context_handler_forwards_macro_request_plain_arm",
        ),
        (
            "accepted_subscription_filter",
            "task_status_notifications_remain_unroutable_until_binding_is_added",
        ),
        (
            "listen",
            "task_status_notifications_remain_unroutable_until_binding_is_added",
        ),
        (
            "subscribe",
            "rbac_context_handler_forwards_macro_request_plain_arm",
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
            "rbac_context_handler_forwards_macro_request_plain_arm",
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

    /// `SEMANTIC_DRIVERS` is parsed by `tests/delegation_guard.rs`; this
    /// in-crate check keeps the constant referenced (so it cannot rot as dead
    /// code) and rejects duplicate entries, which the source-level parser
    /// cannot see.
    #[test]
    fn semantic_drivers_table_is_well_formed() {
        assert!(!SEMANTIC_DRIVERS.is_empty());
        let mut names: Vec<&str> = SEMANTIC_DRIVERS.iter().map(|(name, _)| *name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate method in SEMANTIC_DRIVERS");
        for (name, driver) in SEMANTIC_DRIVERS {
            assert!(!name.is_empty());
            assert!(!driver.is_empty());
        }
    }

    /// Per-request metadata declaring the protocol version and the tasks client
    /// capability that the `tasks/*` gates and a task-returning `call_tool`
    /// require.
    fn coverage_meta() -> rmcp::model::RequestMetaObject {
        let mut meta = rmcp::model::RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::builder().enable_tasks().build());
        meta
    }

    fn request_message(request: ClientRequest, id: i64) -> ClientJsonRpcMessage {
        JsonRpcMessage::request(request, NumberOrString::Number(id))
    }

    /// Attach the authenticated identity the way the transport middleware does:
    /// an [`axum`] `Parts` extension carrying the [`AuthIdentity`].
    fn attach_identity(message: &mut ClientJsonRpcMessage, identity: AuthIdentity) {
        let mut parts = axum::http::Request::new(()).into_parts().0;
        parts.extensions.insert(identity);
        match message {
            JsonRpcMessage::Request(request) => {
                request.request.extensions_mut().insert(parts);
            }
            JsonRpcMessage::Notification(notification) => {
                notification.notification.extensions_mut().insert(parts);
            }
            other @ (JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_)) => {
                panic!("coverage drivers only send requests and notifications, got {other:?}")
            }
        }
    }

    fn attach_meta(message: &mut ClientJsonRpcMessage, meta: rmcp::model::RequestMetaObject) {
        let JsonRpcMessage::Request(request) = message else {
            panic!("only requests carry request metadata");
        };
        request.request.extensions_mut().insert(meta);
    }

    type OutboundFrames = Arc<std::sync::Mutex<Vec<ServerJsonRpcMessage>>>;

    /// Drive messages through a real service wrapping `inner`, and hand back
    /// the outbound frames. Response order is not a contract -- callers match
    /// by JSON-RPC id with [`frame_for`].
    async fn drive_coverage_requests<H: ServerHandler>(
        inner: H,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        binding: Option<SessionBindingSecret>,
        messages: Vec<ClientJsonRpcMessage>,
    ) -> OutboundFrames {
        let (transport, outbound) = InMemoryTransport::new(messages);
        let handler = RbacContextHandler::new(inner, rbac, false).with_task_binding(binding);
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        running.waiting().await.expect("service task joins");
        outbound
    }

    /// Drive one request against the real wrapper, then the same request
    /// against the deleted-delegation control. The control half is the
    /// per-method mutation evidence and is asserted here so no driver can
    /// forget it.
    async fn forward_once<F>(
        build_message: F,
        binding: Option<SessionBindingSecret>,
    ) -> (OutboundFrames, ForwardingProbe, OutboundFrames)
    where
        F: Fn() -> ClientJsonRpcMessage,
    {
        let probe = ForwardingProbe::default();
        let outbound = drive_coverage_requests(
            probe.clone(),
            viewer_policy(),
            binding.clone(),
            vec![build_message()],
        )
        .await;

        let control = ForwardingProbe::default();
        let control_outbound = drive_coverage_requests(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            binding,
            vec![build_message()],
        )
        .await;
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

        (outbound, probe, control_outbound)
    }

    fn frame_for(outbound: &OutboundFrames, id: i64) -> ServerJsonRpcMessage {
        let messages = outbound.lock().expect("outbound messages lock").clone();
        messages
            .into_iter()
            .find(|message| match message {
                ServerJsonRpcMessage::Response(response) => {
                    response.id == NumberOrString::Number(id)
                }
                ServerJsonRpcMessage::Error(error) => error.id == Some(NumberOrString::Number(id)),
                ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_) => false,
            })
            .unwrap_or_else(|| panic!("no frame with id {id}"))
    }

    fn expect_response(frame: ServerJsonRpcMessage) -> ServerResult {
        match frame {
            ServerJsonRpcMessage::Response(response) => response.result,
            other @ (ServerJsonRpcMessage::Request(_)
            | ServerJsonRpcMessage::Notification(_)
            | ServerJsonRpcMessage::Error(_)) => {
                panic!("expected a response, got {other:?}")
            }
        }
    }

    fn expect_error(frame: ServerJsonRpcMessage) -> ErrorData {
        match frame {
            ServerJsonRpcMessage::Error(error) => error.error,
            other @ (ServerJsonRpcMessage::Request(_)
            | ServerJsonRpcMessage::Response(_)
            | ServerJsonRpcMessage::Notification(_)) => {
                panic!("expected an error, got {other:?}")
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
    fn rbac_context_handler_forwards_direct_sync_methods() {
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
            .expect("inner get_tool must reach the caller");
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
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_macro_request_plain_arm() {
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
                attach_identity(&mut message, viewer());
                message
            },
            None,
        )
        .await;

        // A sentinel *error* proves the `Result` channel, not just entry: the
        // plain-params arm of `delegate_request!` must propagate it verbatim.
        let error = expect_error(frame_for(&outbound, 1));
        assert_eq!(error.message, "forwarding-probe:complete");
        assert_eq!(probe.seen(), vec![("complete", Some("viewer".to_owned()))]);

        // The default answers `Ok`, so the sentinel error cannot come from it.
        let default_result = expect_response(frame_for(&control_outbound, 1));
        let ServerResult::CompleteResult(default_result) = default_result else {
            panic!("expected a completion result, got {default_result:?}")
        };
        assert_eq!(default_result.completion.values, Vec::<String>::new());
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_macro_request_option_arm() {
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
                attach_identity(&mut message, viewer());
                message
            },
            None,
        )
        .await;

        let result = expect_response(frame_for(&outbound, 1));
        let ServerResult::ListPromptsResult(result) = result else {
            panic!("expected a prompts/list result, got {result:?}")
        };
        assert_eq!(result.prompts[0].name, "sentinel-prompt");
        assert_eq!(
            probe.seen(),
            vec![("list_prompts", Some("viewer".to_owned()))]
        );

        // The default returns an empty page.
        let default_result = expect_response(frame_for(&control_outbound, 1));
        let ServerResult::ListPromptsResult(default_result) = default_result else {
            panic!("expected a prompts/list result, got {default_result:?}")
        };
        assert_eq!(default_result.prompts, Vec::new());
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_macro_notification_arm() {
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
        attach_identity(&mut message, viewer());

        let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![message]),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), viewer_policy(), false);
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        probe.wait_for_seen_count(1).await;
        running.cancel().await.ok();

        // Notifications have no response channel, so record + observed identity
        // is the whole proof.
        assert_eq!(
            probe.seen(),
            vec![("on_cancelled", Some("viewer".to_owned()))]
        );

        // Negative control: the default notification arm does nothing. Dispatch
        // is spawned, so give it a bounded window and assert nothing arrived.
        let control = ForwardingProbe::default();
        let mut message = JsonRpcMessage::notification(ClientNotification::CancelledNotification(
            CancelledNotification::new(CancelledNotificationParam::new(
                Some(NumberOrString::Number(1)),
                Some("coverage".to_owned()),
            )),
        ));
        attach_identity(&mut message, viewer());
        let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(vec![message]),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            false,
        );
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            tokio::task::yield_now().await;
        })
        .await
        .expect("bounded negative-control window");
        running.cancel().await.ok();
        assert_eq!(control.seen(), Vec::new());
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_ping_initialize_and_discover() {
        // Mechanism 1 (ambient-silent probe) plus one exact full sequence per
        // method: each request is driven through its own service, and the probe
        // never records the ambient `get_info` / `supported_protocol_versions`
        // calls the prelude may make.
        // `ping` speaks the legacy lifecycle only: adding per-request metadata
        // would make rmcp answer method-not-found before the wrapper.
        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message =
                    request_message(ClientRequest::PingRequest(PingRequest::default()), 1);
                attach_identity(&mut message, viewer());
                message
            },
            None,
        )
        .await;
        assert!(matches!(
            frame_for(&outbound, 1),
            ServerJsonRpcMessage::Response(_)
        ));
        assert!(matches!(
            frame_for(&control_outbound, 1),
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(probe.seen(), vec![("ping", Some("viewer".to_owned()))]);

        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::InitializeRequest(InitializeRequest::new(
                        InitializeRequestParams::new(
                            ClientCapabilities::default(),
                            rmcp::model::Implementation::new("coverage-driver", "0.0.0"),
                        ),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer());
                message
            },
            None,
        )
        .await;
        let result = expect_response(frame_for(&outbound, 1));
        let ServerResult::InitializeResult(result) = result else {
            panic!("expected an initialize result, got {result:?}")
        };
        assert_eq!(
            result.instructions.as_deref(),
            Some("forwarding-probe:initialize")
        );
        assert_eq!(
            probe.seen(),
            vec![("initialize", Some("viewer".to_owned()))]
        );
        let default_result = expect_response(frame_for(&control_outbound, 1));
        let ServerResult::InitializeResult(default_result) = default_result else {
            panic!("expected an initialize result, got {default_result:?}")
        };
        assert_ne!(
            default_result.instructions.as_deref(),
            Some("forwarding-probe:initialize")
        );

        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::DiscoverRequest(DiscoverRequest::new(
                        DiscoverRequestParams::default(),
                    )),
                    1,
                );
                attach_identity(&mut message, viewer());
                attach_meta(&mut message, coverage_meta());
                message
            },
            None,
        )
        .await;
        let result = expect_response(frame_for(&outbound, 1));
        let ServerResult::DiscoverResult(result) = result else {
            panic!("expected a discover result, got {result:?}")
        };
        assert_eq!(result.supported_versions, SENTINEL_VERSIONS.to_vec());
        assert_eq!(probe.seen(), vec![("discover", Some("viewer".to_owned()))]);
        let default_result = expect_response(frame_for(&control_outbound, 1));
        let ServerResult::DiscoverResult(default_result) = default_result else {
            panic!("expected a discover result, got {default_result:?}")
        };
        assert_ne!(
            default_result.supported_versions,
            SENTINEL_VERSIONS.to_vec()
        );
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_notifications() {
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
                "notifications/initialized" => ClientNotification::InitializedNotification(
                    rmcp::model::NotificationNoParam::default(),
                ),
                "notifications/roots/list_changed" => {
                    ClientNotification::RootsListChangedNotification(
                        rmcp::model::NotificationNoParam::default(),
                    )
                }
                _ => ClientNotification::CustomNotification(CustomNotification::new(
                    method,
                    Some(serde_json::json!({ "coverage": true })),
                )),
            };
            let mut message = JsonRpcMessage::notification(notification);
            attach_identity(&mut message, viewer());
            messages.push(message);
        }

        let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(messages),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(probe.clone(), viewer_policy(), false);
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        probe.wait_for_seen_count(3).await;
        running.cancel().await.ok();

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
        let mut messages = Vec::new();
        for method in notifications {
            let notification = match method {
                "notifications/initialized" => ClientNotification::InitializedNotification(
                    rmcp::model::NotificationNoParam::default(),
                ),
                "notifications/roots/list_changed" => {
                    ClientNotification::RootsListChangedNotification(
                        rmcp::model::NotificationNoParam::default(),
                    )
                }
                _ => ClientNotification::CustomNotification(CustomNotification::new(
                    method,
                    Some(serde_json::json!({ "coverage": true })),
                )),
            };
            let mut message = JsonRpcMessage::notification(notification);
            attach_identity(&mut message, viewer());
            messages.push(message);
        }
        let outbound = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = OpenTransport {
            inbound: VecDeque::from(messages),
            outbound: Arc::clone(&outbound),
        };
        let handler = RbacContextHandler::new(
            PassthroughDefaults::new(control.clone()),
            viewer_policy(),
            false,
        );
        let running = rmcp::service::serve_directly::<RoleServer, _, _, Infallible, _>(
            handler, transport, None,
        );
        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            tokio::task::yield_now().await;
        })
        .await
        .expect("bounded negative-control window");
        running.cancel().await.ok();
        assert_eq!(control.seen(), Vec::new());
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_task_producing_call_tool() {
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
                attach_identity(&mut message, alice.clone());
                attach_meta(&mut message, coverage_meta());
                message
            },
            Some(secret.clone()),
        )
        .await;

        // The inner returned a raw task ID; the client must see it bound.
        let result = expect_response(frame_for(&outbound, 1));
        let ServerResult::CreateTaskResult(created) = result else {
            panic!("expected a create-task result, got {result:?}")
        };
        assert_ne!(created.task.task_id, "raw-task-call");
        let raw =
            task_binding::unwrap_and_verify(&secret, &created.task.task_id, &fingerprint(&alice))
                .expect("the client-visible id must unwrap for its owner");
        assert_eq!(raw.as_str(), "raw-task-call");
        assert_eq!(probe.seen(), vec![("call_tool", Some("viewer".to_owned()))]);

        // The default `call_tool` errors, so it cannot produce the sentinel.
        let error = expect_error(frame_for(&control_outbound, 1));
        assert_eq!(error.code, rmcp::model::ErrorCode::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn rbac_context_handler_forwards_task_binding_on_update_and_cancel() {
        // Mechanism 1 (ambient-silent probe): the tasks gate calls `get_info`,
        // which this probe does not record, so the expected log is exactly the
        // driven method.
        let secret = task_secret();
        let alice = identity_named("alice");
        let bob = identity_named("bob");
        let alice_fingerprint = fingerprint(&alice);
        let raw_update = RawTaskId::parse("raw-update").expect("valid id");
        let raw_cancel = RawTaskId::parse("raw-cancel").expect("valid id");
        let bound_update = task_binding::wrap(&secret, &raw_update, &alice_fingerprint);
        let bound_cancel = task_binding::wrap(&secret, &raw_cancel, &alice_fingerprint);

        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::UpdateTaskRequest(UpdateTaskRequest::new(
                        UpdateTaskParams::new(
                            bound_update.clone(),
                            rmcp::model::InputResponses::new(),
                        ),
                    )),
                    1,
                );
                attach_identity(&mut message, alice.clone());
                attach_meta(&mut message, coverage_meta());
                message
            },
            Some(secret.clone()),
        )
        .await;
        assert!(matches!(
            frame_for(&outbound, 1),
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(
            probe.task_ids(),
            vec!["raw-update".to_owned()],
            "the inner handler must observe the RAW id, never the wrapper"
        );
        assert_eq!(
            probe.seen(),
            vec![("update_task", Some("viewer".to_owned()))]
        );
        let error = expect_error(frame_for(&control_outbound, 1));
        assert_eq!(error.code, rmcp::model::ErrorCode::METHOD_NOT_FOUND);

        let (outbound, probe, control_outbound) = forward_once(
            || {
                let mut message = request_message(
                    ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
                        CancelTaskParams::new(bound_cancel.clone()),
                    )),
                    1,
                );
                attach_identity(&mut message, alice.clone());
                attach_meta(&mut message, coverage_meta());
                message
            },
            Some(secret.clone()),
        )
        .await;
        assert!(matches!(
            frame_for(&outbound, 1),
            ServerJsonRpcMessage::Response(_)
        ));
        assert_eq!(probe.task_ids(), vec!["raw-cancel".to_owned()]);
        assert_eq!(
            probe.seen(),
            vec![("cancel_task", Some("viewer".to_owned()))]
        );
        let error = expect_error(frame_for(&control_outbound, 1));
        assert_eq!(error.code, rmcp::model::ErrorCode::METHOD_NOT_FOUND);

        // A bound id for the wrong identity is rejected before the inner handler
        // records anything.
        let bob_bound = task_binding::wrap(
            &secret,
            &RawTaskId::parse("raw-cancel").expect("valid id"),
            &fingerprint(&bob),
        );
        let mut message = request_message(
            ClientRequest::CancelTaskRequest(CancelTaskRequest::new(CancelTaskParams::new(
                bob_bound,
            ))),
            1,
        );
        attach_identity(&mut message, alice.clone());
        attach_meta(&mut message, coverage_meta());
        let probe = ForwardingProbe::default();
        let outbound =
            drive_coverage_requests(probe.clone(), viewer_policy(), Some(secret), vec![message])
                .await;
        let error = expect_error(frame_for(&outbound, 1));
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(probe.task_ids(), Vec::<String>::new());
        assert_eq!(probe.seen(), Vec::<(&'static str, Option<String>)>::new());
    }
}
