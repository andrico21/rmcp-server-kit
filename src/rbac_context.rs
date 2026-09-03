use std::{borrow::Cow, future::Future};

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

use crate::{auth::AuthIdentity, secret::SecretString};

#[derive(Debug, Clone)]
pub(crate) struct RbacContextHandler<H> {
    inner: H,
}

impl<H> RbacContextHandler<H> {
    #[must_use]
    pub(crate) const fn new(inner: H) -> Self {
        Self { inner }
    }
}

fn identity_from_request(context: &RequestContext<RoleServer>) -> Option<AuthIdentity> {
    context_identity(&context.extensions)
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
    delegate_request!(call_tool, CallToolRequestParams, CallToolResponse);
    delegate_request!(list_tools, Option<PaginatedRequestParams>, ListToolsResult);

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

    delegate_request!(get_task, GetTaskParams, GetTaskResult);
    delegate_request!(update_task, UpdateTaskParams, ());
    delegate_request!(cancel_task, CancelTaskParams, ());
}
