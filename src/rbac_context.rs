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
        ReadResourceResponse, ServerInfo, SetLevelRequestParams, SubscribeRequestParams,
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

    fn get_info(&self) -> ServerInfo {
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
            CacheScope, ClientJsonRpcMessage, ClientRequest, Extensions, GetExtensions, JsonObject,
            JsonRpcMessage, ListToolsRequest, ListToolsRequestMethod, ListToolsResult,
            NumberOrString, PaginatedRequestParams, ServerJsonRpcMessage, ServerResult, Tool,
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
        fn get_info(&self) -> ServerInfo {
            ServerInfo::default()
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
        fn get_info(&self) -> ServerInfo {
            // rmcp gates `tasks/*` on the server advertising the extension AND
            // the client declaring it, so both must be set up or the request is
            // rejected upstream and never reaches the binding under test.
            ServerInfo::new(
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
        meta.set_client_capabilities(
            rmcp::model::ClientCapabilities::builder()
                .enable_tasks()
                .build(),
        );
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
}
