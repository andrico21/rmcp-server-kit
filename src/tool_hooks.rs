//! Opt-in tool-call instrumentation for `ServerHandler` implementations.
//!
//! [`crate::tool_hooks::HookedHandler`] wraps any [`rmcp::ServerHandler`] with:
//!
//! - **Before hooks** (async) that observe `(tool_name, arguments, identity,
//!   role, sub, request_id)` and may [`HookOutcome::Continue`](crate::tool_hooks::HookOutcome::Continue),
//!   [`HookOutcome::Deny`](crate::tool_hooks::HookOutcome::Deny), or
//!   [`HookOutcome::Replace`](crate::tool_hooks::HookOutcome::Replace) the call.
//! - **After hooks** (async) that observe the same context plus a
//!   [`HookDisposition`](crate::tool_hooks::HookDisposition) describing how the call resolved and the
//!   approximate result size in bytes.  After-hooks are spawned via
//!   `tokio::spawn` and never block the response path.
//! - **Result-size capping**: serialized tool results larger than
//!   `max_result_bytes` are replaced with a structured error, preventing
//!   token-expensive or memory-expensive payloads from reaching clients.
//!   The cap applies both to inner-handler results and to
//!   [`HookOutcome::Replace`](crate::tool_hooks::HookOutcome::Replace) payloads.
//!
//! # Cancel safety
//!
//! The transparent `ServerHandler` delegation methods are cancel-safe with
//! respect to this wrapper: cancellation only drops the delegated inner
//! future, so the wrapped handler's own cancel-safety contract is inherited
//! unchanged.  The `call_tool` implementation on
//! [`crate::tool_hooks::HookedHandler`] is the exception and is documented
//! as **NOT cancel-safe** at its definition: once a before-hook or the
//! inner handler has been awaited, cancellation can prevent the paired
//! after-hook from being spawned.
//!
//! This is entirely **opt-in** at the application layer - `rmcp_server_kit::serve()`
//! does not wrap handlers automatically.  Applications that want hooks do:
//!
//! ```no_run
//! use std::sync::Arc;
//! use rmcp_server_kit::tool_hooks::{HookedHandler, HookOutcome, ToolHooks, with_hooks};
//!
//! # #[derive(Clone, Default)]
//! # struct MyHandler;
//! # impl rmcp::ServerHandler for MyHandler {}
//! let handler = MyHandler::default();
//! let hooks = Arc::new(
//!     ToolHooks::new()
//!         .with_max_result_bytes(256 * 1024)
//!         .with_before(Arc::new(|_ctx| Box::pin(async { HookOutcome::Continue })))
//!         .with_after(Arc::new(|_ctx, _disp, _bytes| Box::pin(async {}))),
//! );
//! let _wrapped = with_hooks(handler, hooks);
//! ```

use std::{borrow::Cow, fmt, future::Future, io, pin::Pin, sync::Arc};

#[allow(
    deprecated,
    reason = "transparent ServerHandler delegation must import legacy logging/subscription parameter types until rmcp removes those methods"
)]
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams,
        CancelledNotificationParam, CompleteRequestParams, CompleteResult, ContentBlock,
        CustomNotification, CustomRequest, CustomResult, DiscoverResult, GetPromptRequestParams,
        GetPromptResponse, GetTaskParams, GetTaskResult, InitializeRequestParams, InitializeResult,
        ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
        PaginatedRequestParams, ProgressNotificationParam, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse, ServerConfig, SetLevelRequestParams,
        SubscribeRequestParams, SubscriptionFilter, Tool, UnsubscribeRequestParams,
        UpdateTaskParams,
    },
    service::{NotificationContext, RequestContext, SubscriptionContext},
};

/// Context passed to before/after hooks for a single tool call.
#[derive(Clone)]
#[non_exhaustive]
pub struct ToolCallContext {
    /// Tool name being invoked.
    pub tool_name: String,
    /// JSON arguments as sent by the client (may be `None`).
    pub arguments: Option<serde_json::Value>,
    /// Identity name from the authenticated request, if any.
    pub identity: Option<String>,
    /// RBAC role associated with the request, if any.
    pub role: Option<String>,
    /// OAuth `sub` claim, if present.
    pub sub: Option<String>,
    /// Raw JSON-RPC request id rendered as a string, if available.
    ///
    /// # Log-injection warning
    ///
    /// This value is **client-controlled**. The JSON-RPC `id` may be a string
    /// of the client's choosing, so it can contain newlines, ANSI/terminal
    /// escape sequences, or other control characters. Since 3.14 it is
    /// rendered via [`Display`](std::fmt::Display) (`abc-123`) rather than
    /// [`Debug`](std::fmt::Debug) (`String("abc-123")`), which means control
    /// characters are **no longer escaped for you**.
    ///
    /// [`ToolCallContext`]'s own `Debug` impl is safe - it renders this field
    /// through `Debug`, which escapes. The risk is a hook that writes the raw
    /// value into a log line, e.g. `tracing::info!(request_id = %id, …)`.
    /// Use [`ToolCallContext::request_id_for_log`] instead, which escapes
    /// control characters without adding surrounding quotes.
    pub request_id: Option<String>,
}

impl ToolCallContext {
    /// Return [`request_id`](Self::request_id) with control characters
    /// escaped, safe to write directly into a log line.
    ///
    /// The JSON-RPC request id is client-controlled and may contain newlines
    /// or terminal escape sequences; writing it verbatim into a log allows an
    /// attacker to forge log lines. This escapes via
    /// [`str::escape_debug`], which neutralises control characters, quotes and
    /// backslashes **without** wrapping the value in quotes - so an ordinary
    /// id such as `abc-123` is returned unchanged while `a\nb` becomes
    /// `a\\nb`.
    ///
    /// Returns `None` when no request id was available.
    #[must_use]
    pub fn request_id_for_log(&self) -> Option<String> {
        self.request_id
            .as_deref()
            .map(|id| id.escape_debug().to_string())
    }

    /// Construct a [`ToolCallContext`] with the given tool name and all
    /// optional fields cleared.  Primarily for use in unit tests and
    /// benchmarks of user-supplied hooks; the runtime path populates
    /// these fields from the request and task-local RBAC state.
    #[must_use]
    pub fn for_tool(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            arguments: None,
            identity: None,
            role: None,
            sub: None,
            request_id: None,
        }
    }
}

impl fmt::Debug for ToolCallContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            tool_name,
            arguments,
            identity,
            role,
            sub,
            request_id,
        } = self;
        let mut debug = f.debug_struct("ToolCallContext");
        debug.field("tool_name", tool_name);
        if crate::diagnostics::tool_call_arguments() {
            debug
                .field("arguments", arguments)
                .field("identity", identity)
                .field("role", role)
                .field("sub", sub);
        } else {
            debug
                .field("arguments", &"[REDACTED]")
                .field("identity", &"[REDACTED]")
                .field("role", &"[REDACTED]")
                .field("sub", &"[REDACTED]");
        }
        debug.field("request_id", request_id).finish()
    }
}

/// Outcome returned by a [`BeforeHook`] to control invocation flow.
///
/// - [`HookOutcome::Continue`] - proceed with the wrapped handler.
/// - [`HookOutcome::Deny`] - reject the call with the supplied
///   [`ErrorData`]; the inner handler is **not** called.
/// - [`HookOutcome::Replace`] - return the supplied result instead of
///   invoking the inner handler.  The result is still subject to
///   `max_result_bytes` capping.
#[derive(Debug)]
#[non_exhaustive]
pub enum HookOutcome {
    /// Proceed with the wrapped handler.
    Continue,
    /// Reject the call.  The error is propagated to the client as-is.
    Deny(ErrorData),
    /// Skip the inner handler and return the supplied result instead.
    Replace(Box<CallToolResult>),
}

/// How a tool call resolved, passed to the [`AfterHook`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HookDisposition {
    /// The inner handler ran and returned `Ok`.
    InnerExecuted,
    /// The inner handler ran and returned `Err`.
    InnerErrored,
    /// The before-hook returned [`HookOutcome::Deny`].
    DeniedBefore,
    /// The before-hook returned [`HookOutcome::Replace`].
    ReplacedBefore,
    /// The result (from inner or replace) exceeded `max_result_bytes`
    /// and was substituted with a structured error.
    ResultTooLarge,
}

/// Async before-hook callback type.
///
/// Returns a [`HookOutcome`] controlling whether the inner handler runs.
/// The borrow of `ToolCallContext` is held for the duration of the
/// returned future, which avoids forcing implementations to clone the
/// context for every invocation.
pub type BeforeHook = Arc<
    dyn for<'a> Fn(&'a ToolCallContext) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'a>>
        + Send
        + Sync
        + 'static,
>;

/// Async after-hook callback type.
///
/// Receives the call context, a [`HookDisposition`] describing how the
/// call resolved, and the approximate serialized result size in bytes
/// (`0` for `DeniedBefore` and `InnerErrored`).  Spawned via
/// `tokio::spawn`, so it must not assume it runs before the response is
/// flushed.
pub type AfterHook = Arc<
    dyn for<'a> Fn(
            &'a ToolCallContext,
            HookDisposition,
            usize,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send
        + Sync
        + 'static,
>;

/// Opt-in hooks applied by [`crate::tool_hooks::HookedHandler`].
#[allow(clippy::struct_field_names, reason = "before/after read naturally")]
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ToolHooks {
    /// Hard cap on serialized `CallToolResult` size in bytes.  When
    /// exceeded, the result is replaced with an `is_error=true` result
    /// carrying a `result_too_large` structured error.  `None` disables
    /// the cap.
    pub max_result_bytes: Option<usize>,
    /// Optional before-hook invoked after arg deserialization, before
    /// the wrapped handler is called.
    pub before: Option<BeforeHook>,
    /// Optional after-hook invoked once per normally-resolved call - that
    /// is, on the Deny / Replace / Ok / Err paths.  Spawned via
    /// `tokio::spawn` and never blocks the response path.
    ///
    /// **Not guaranteed under cancellation.**  If the `call_tool` future is
    /// dropped after a before-hook has run but before the call resolves,
    /// the paired after-hook is never spawned.  Do not use before/after
    /// pairing as a mandatory resource guard; make the after-hook
    /// idempotent or tolerant of missing closes (see [`crate::cancel`]).
    pub after: Option<AfterHook>,
}

impl ToolHooks {
    /// Construct an empty [`ToolHooks`] with no cap and no hooks.
    ///
    /// Use the `with_*` builder methods to populate fields; this avoids
    /// the `#[non_exhaustive]` restriction that prevents struct-literal
    /// construction from outside the crate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the serialized result size cap in bytes.
    #[must_use]
    pub fn with_max_result_bytes(mut self, max: usize) -> Self {
        self.max_result_bytes = Some(max);
        self
    }

    /// Set the before-hook.
    #[must_use]
    pub fn with_before(mut self, before: BeforeHook) -> Self {
        self.before = Some(before);
        self
    }

    /// Set the after-hook.
    #[must_use]
    pub fn with_after(mut self, after: AfterHook) -> Self {
        self.after = Some(after);
        self
    }
}

const _HOOKED_HANDLER_DOC_ANCHOR: &str = "HookedHandler";

impl fmt::Debug for ToolHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolHooks")
            .field("max_result_bytes", &self.max_result_bytes)
            .field("before", &self.before.as_ref().map(|_| "<fn>"))
            .field("after", &self.after.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// `ServerHandler` wrapper that applies [`ToolHooks`].
#[derive(Clone)]
pub struct HookedHandler<H: ServerHandler> {
    inner: Arc<H>,
    hooks: Arc<ToolHooks>,
}

impl<H: ServerHandler> fmt::Debug for HookedHandler<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HookedHandler")
            .field("hooks", &self.hooks)
            .finish_non_exhaustive()
    }
}

/// Construct a [`crate::tool_hooks::HookedHandler`] from an inner handler and hooks.
///
/// Returning the wrapped handler is the entire point of this function;
/// dropping it on the floor would silently disable the supplied hooks.
#[must_use = "HookedHandler must be wired into a ServerHandler (e.g. via \
              `serve(..., || hooked)`) to take effect; dropping the returned \
              value silently disables the supplied hooks"]
pub fn with_hooks<H: ServerHandler>(inner: H, hooks: Arc<ToolHooks>) -> HookedHandler<H> {
    HookedHandler {
        inner: Arc::new(inner),
        hooks,
    }
}

impl<H: ServerHandler> HookedHandler<H> {
    /// Access the wrapped handler.
    #[must_use]
    pub fn inner(&self) -> &H {
        &self.inner
    }

    fn build_context(request: &CallToolRequestParams, req_id: Option<String>) -> ToolCallContext {
        ToolCallContext {
            tool_name: request.name.to_string(),
            arguments: request.arguments.clone().map(serde_json::Value::Object),
            identity: crate::rbac::current_identity(),
            role: crate::rbac::current_role(),
            sub: crate::rbac::current_sub(),
            request_id: req_id,
        }
    }

    /// Spawn the after-hook on the current Tokio runtime.  The future
    /// captures clones of `ctx` and the `Arc<AfterHook>` so it can run
    /// independently of the request task; panics inside the after-hook
    /// are caught by Tokio and never poison the response path.
    ///
    /// The spawned task is **instrumented** with the request span via
    /// [`tracing::Instrument`] and re-establishes the per-request RBAC
    /// task-locals (role, identity, token, sub) via
    /// [`crate::rbac::with_rbac_scope`]. Without this, after-hooks lose
    /// their parent span (breaking trace correlation) and observe
    /// `current_role()` / `current_identity()` as `None`.
    fn spawn_after(
        after: Option<&Arc<AfterHookHolder>>,
        ctx: ToolCallContext,
        disposition: HookDisposition,
        size: usize,
    ) {
        if let Some(after) = after {
            use tracing::Instrument;

            let after = Arc::clone(after);
            // Capture the request span before leaving the request task so
            // after-hook log lines are correlated with the originating call.
            let span = tracing::Span::current();
            // Snapshot RBAC task-locals; defaults are empty strings so the
            // re-established scope is a no-op when the request had no
            // authenticated identity (e.g. health checks, anonymous tools).
            let role = crate::rbac::current_role().unwrap_or_default();
            let identity = crate::rbac::current_identity().unwrap_or_default();
            let token = crate::rbac::current_token()
                .unwrap_or_else(|| secrecy::SecretString::from(String::new()));
            let sub = crate::rbac::current_sub().unwrap_or_default();
            tokio::spawn(
                async move {
                    crate::rbac::with_rbac_scope(role, identity, token, sub, async move {
                        let fut = (after.f)(&ctx, disposition, size);
                        fut.await;
                    })
                    .await;
                }
                .instrument(span),
            );
        }
    }
}

/// Internal newtype that owns the [`AfterHook`] so we can `Arc::clone`
/// the *holder* and let the spawned task borrow `ctx` for the lifetime
/// of the future without lifetime acrobatics in `tokio::spawn`.
struct AfterHookHolder {
    f: AfterHook,
}

/// Structured error body returned when a result exceeds `max_result_bytes`.
///
/// `actual` is `None` when the result could not be serialized, so its true
/// size is unknown. It is rendered as `"unknown"` rather than a fabricated
/// number -- operators read `actual_bytes` as a measurement.
fn too_large_result(limit: usize, actual: Option<usize>, tool: &str) -> CallToolResult {
    let actual_desc =
        actual.map_or_else(|| "an unmeasurable number of".to_owned(), |n| n.to_string());
    let body = serde_json::json!({
        "error": "result_too_large",
        "message": format!(
            "tool '{tool}' result of {actual_desc} bytes exceeds the configured \
             max_result_bytes={limit}; ask for a narrower query"
        ),
        "limit_bytes": limit,
        "actual_bytes": actual.map_or_else(
            || serde_json::Value::from("unknown"),
            serde_json::Value::from,
        ),
    });
    let mut r = CallToolResult::error(vec![ContentBlock::text(body.to_string())]);
    r.structured_content = None;
    r
}

/// Outcome of the `max_result_bytes` policy for a measured -- or
/// unmeasurable -- result.
#[derive(Debug, PartialEq, Eq)]
enum SizeVerdict {
    /// Within the cap, or no cap configured. Carries the measured size.
    Pass { size: usize },
    /// Over the cap, or unmeasurable while a cap is configured.
    Replace { limit: usize, actual: Option<usize> },
    /// Unmeasurable and no cap configured: nothing to enforce.
    PassUnmeasured,
}

/// Decide what the size cap does, given an optional size-measurement outcome.
const fn decide_size(size: Option<SizeMeasure>, max: Option<usize>) -> SizeVerdict {
    match size {
        Some(SizeMeasure::Exact(size)) => match max {
            Some(limit) if size > limit => SizeVerdict::Replace {
                limit,
                actual: Some(size),
            },
            Some(_) | None => SizeVerdict::Pass { size },
        },
        Some(SizeMeasure::Exceeded { limit }) => SizeVerdict::Replace {
            limit,
            actual: None,
        },
        None => match max {
            Some(limit) => SizeVerdict::Replace {
                limit,
                actual: None,
            },
            None => SizeVerdict::PassUnmeasured,
        },
    }
}

/// Apply the `max_result_bytes` cap to a result.  Returns the (possibly
/// replaced) result, the size used for accounting, and whether the cap
/// fired.
fn apply_size_cap(
    result: CallToolResult,
    max: Option<usize>,
    tool: &str,
) -> (CallToolResult, usize, bool) {
    let size = if max.is_some() {
        Some(serialized_size(&result, max))
    } else {
        None
    };
    match decide_size(size, max) {
        SizeVerdict::Pass { size } => (result, size, false),
        SizeVerdict::PassUnmeasured => (result, 0, false),
        SizeVerdict::Replace { limit, actual } => {
            tracing::warn!(
                tool = %tool,
                size_bytes = actual.unwrap_or_default(),
                size_measured = actual.is_some(),
                limit_bytes = limit,
                "tool result exceeds max_result_bytes; replacing with structured error"
            );
            let accounted = actual.unwrap_or_else(|| limit.saturating_add(1));
            (too_large_result(limit, actual, tool), accounted, true)
        }
    }
}

#[allow(
    deprecated,
    reason = "transparent ServerHandler delegation must include legacy logging/subscription methods until rmcp removes them"
)]
impl<H: ServerHandler> ServerHandler for HookedHandler<H> {
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        self.inner.ping(context).await
    }

    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.initialize(request, context).await
    }

    // Synchronous negotiation helper: no context and no hooks apply, so plain
    // delegation is the only transparent option -- the trait default would
    // shadow an inner override.
    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.negotiate_initialize(request)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.inner.list_tools(request, context).await
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        self.inner.complete(request, context).await
    }

    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.set_level(request, context).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.inner.list_prompts(request, context).await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        self.inner.get_prompt(request, context).await
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.inner.list_resources(request, context).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.inner.list_resource_templates(request, context).await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.inner.read_resource(request, context).await
    }

    // NOT cancel-safe: this awaits consumer-supplied before-hooks and the
    // consumer's inner handler. After-hooks are dispatched only on the normal
    // Deny/Replace/Ok/Err paths, so a cancellation between the before-hook and
    // the response drops the paired after-hook -- an audit hook can therefore
    // record a started call that is never closed out. Consumers needing
    // guaranteed pairing should make the after-hook idempotent or run the tool
    // body detached (see `crate::cancel`).
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "CallToolResponse is #[non_exhaustive]; the non-Complete MRTR variants (InputRequired/Task) are passed through unchanged"
    )]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let req_id = Some(context.id.to_string());
        let ctx = Self::build_context(&request, req_id);
        let max = self.hooks.max_result_bytes;
        let after_holder = self
            .hooks
            .after
            .as_ref()
            .map(|f| Arc::new(AfterHookHolder { f: Arc::clone(f) }));

        // Before hook: may Continue, Deny, or Replace.
        if let Some(before) = self.hooks.before.as_ref() {
            let outcome = before(&ctx).await;
            match outcome {
                HookOutcome::Continue => {}
                HookOutcome::Deny(err) => {
                    Self::spawn_after(after_holder.as_ref(), ctx, HookDisposition::DeniedBefore, 0);
                    return Err(err);
                }
                HookOutcome::Replace(boxed) => {
                    let (final_result, size, capped) = apply_size_cap(*boxed, max, &ctx.tool_name);
                    let disposition = if capped {
                        HookDisposition::ResultTooLarge
                    } else {
                        HookDisposition::ReplacedBefore
                    };
                    Self::spawn_after(after_holder.as_ref(), ctx, disposition, size);
                    return Ok(final_result.into());
                }
            }
        }

        // Inner handler.
        match self.inner.call_tool(request, context).await {
            // Completed tool result: subject to the size cap + after hook.
            Ok(CallToolResponse::Complete(result)) => {
                let (final_result, size, capped) = apply_size_cap(result, max, &ctx.tool_name);
                let disposition = if capped {
                    HookDisposition::ResultTooLarge
                } else {
                    HookDisposition::InnerExecuted
                };
                Self::spawn_after(after_holder.as_ref(), ctx, disposition, size);
                Ok(final_result.into())
            }
            // MRTR input-required / task responses (rmcp 3.0): no CallToolResult
            // to size-cap, so pass them through unchanged.
            Ok(other) => {
                Self::spawn_after(
                    after_holder.as_ref(),
                    ctx,
                    HookDisposition::InnerExecuted,
                    0,
                );
                Ok(other)
            }
            Err(e) => {
                Self::spawn_after(after_holder.as_ref(), ctx, HookDisposition::InnerErrored, 0);
                Err(e)
            }
        }
    }

    // rmcp 3.0 added task/subscription/discovery request handlers with defaults;
    // delegate them to `inner` so wrapping a handler that implements those stays
    // transparent (otherwise the default would shadow the inner implementation).
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        self.inner.discover(context).await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        self.inner.listen(context).await
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.subscribe(request, context).await
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.unsubscribe(request, context).await
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        self.inner.get_task(request, context).await
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.update_task(request, context).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.cancel_task(request, context).await
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        self.inner.on_custom_request(request, context).await
    }

    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_cancelled(notification, context).await;
    }

    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_progress(notification, context).await;
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_initialized(context).await;
    }

    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_roots_list_changed(context).await;
    }

    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner
            .on_custom_notification(notification, context)
            .await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SizeLimitExceeded;

impl fmt::Display for SizeLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("serialized result exceeded configured size cap")
    }
}

impl std::error::Error for SizeLimitExceeded {}

struct CountingWriter {
    bytes: usize,
    limit: Option<usize>,
}

impl CountingWriter {
    const fn unbounded() -> Self {
        Self {
            bytes: 0,
            limit: None,
        }
    }

    const fn bounded(limit: usize) -> Self {
        Self {
            bytes: 0,
            limit: Some(limit),
        }
    }
}

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next = self.bytes.saturating_add(buf.len());
        if self.limit.is_some_and(|limit| next > limit) {
            Err(io::Error::other(SizeLimitExceeded))
        } else {
            self.bytes = next;
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Outcome of measuring serialized result size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeMeasure {
    /// Exact serialized size in bytes.
    Exact(usize),
    /// Serialization crossed the configured size cap and stopped early.
    Exceeded { limit: usize },
}

/// Serialized byte length, or a deliberate cap-abort outcome.
fn serialized_size(result: &CallToolResult, max: Option<usize>) -> SizeMeasure {
    let mut writer = max.map_or_else(CountingWriter::unbounded, CountingWriter::bounded);
    match serde_json::to_writer(&mut writer, result) {
        Ok(()) => SizeMeasure::Exact(writer.bytes),
        Err(error) if error.io_error_kind() == Some(io::ErrorKind::Other) => {
            SizeMeasure::Exceeded {
                limit: max.unwrap_or(writer.bytes),
            }
        }
        Err(_error) => {
            // `CallToolResult` is made only of infallibly serializable fields
            // (`String`, `bool`, arrays/maps, and serde_json::Value`). There is
            // no inhabitable production value that can reach this branch.
            SizeMeasure::Exact(writer.bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[allow(
        deprecated,
        reason = "delegation tests cover legacy logging/subscription methods"
    )]
    use rmcp::{
        ErrorData, RoleServer, ServerHandler,
        model::{
            CallToolRequestParams, CallToolResponse, CallToolResult, CancelledNotificationParam,
            CompleteRequestParams, CompleteResult, CompletionInfo, ContentBlock,
            CustomNotification, CustomRequest, CustomResult, DiscoverResult,
            GetPromptRequestParams, GetPromptResult, GetTaskParams, GetTaskResult,
            ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
            PaginatedRequestParams, ProgressNotificationParam, Prompt, PromptMessage,
            ProtocolVersion, ReadResourceRequestParams, ReadResourceResult, Resource,
            ResourceContents, ResourceTemplate, Role, ServerConfig, SetLevelRequestParams,
            SubscribeRequestParams, SubscriptionFilter, UnsubscribeRequestParams, UpdateTaskParams,
        },
        service::{RequestContext, SubscriptionContext},
    };
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::*;

    type DelegationTransport = (
        DelegationProbe,
        BufReader<tokio::io::ReadHalf<DuplexStream>>,
        tokio::io::WriteHalf<DuplexStream>,
        rmcp::service::RunningService<RoleServer, HookedHandler<DelegationProbe>>,
    );

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }
    }

    struct CapturedLogsWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogsWriter(Arc::clone(&self.0))
        }
    }

    /// Minimal in-process `ServerHandler` for tests.
    #[derive(Clone, Default)]
    struct TestHandler {
        /// When Some, `call_tool` returns a body of this many 'x' bytes.
        body_bytes: Option<usize>,
    }

    impl ServerHandler for TestHandler {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::default()
        }

        #[allow(
            clippy::unused_async_trait_impl,
            reason = "async is mandated by the rmcp ServerHandler trait signature; this test handler does not await"
        )]
        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, ErrorData> {
            let body = "x".repeat(self.body_bytes.unwrap_or(4));
            Ok(CallToolResult::success(vec![ContentBlock::text(body)]).into())
        }
    }

    #[derive(Clone, Default)]
    struct DelegationProbe {
        seen: Arc<std::sync::Mutex<Vec<&'static str>>>,
        notify: Arc<tokio::sync::Notify>,
    }

    impl DelegationProbe {
        fn record(&self, method: &'static str) {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(method);
            }
            self.notify.notify_waiters();
        }

        fn seen(&self) -> Vec<&'static str> {
            self.seen
                .lock()
                .map(|seen| seen.clone())
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
        reason = "delegation tests cover rmcp async trait methods whose probe implementations return immediately"
    )]
    impl ServerHandler for DelegationProbe {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::default()
        }

        async fn ping(&self, _context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
            self.record("ping");
            Ok(())
        }

        async fn complete(
            &self,
            _request: CompleteRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CompleteResult, ErrorData> {
            self.record("complete");
            let completion = CompletionInfo::with_all_values(vec!["delegated".to_owned()])
                .expect("single completion is within rmcp max");
            Ok(CompleteResult::new(completion))
        }

        async fn set_level(
            &self,
            _request: SetLevelRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("set_level");
            Ok(())
        }

        async fn subscribe(
            &self,
            _request: SubscribeRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("subscribe");
            Ok(())
        }

        async fn unsubscribe(
            &self,
            _request: UnsubscribeRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("unsubscribe");
            Ok(())
        }

        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, ErrorData> {
            self.record("call_tool");
            Ok(CallToolResult::success(vec![ContentBlock::text("inner")]).into())
        }

        async fn on_custom_request(
            &self,
            _request: CustomRequest,
            _context: RequestContext<RoleServer>,
        ) -> Result<CustomResult, ErrorData> {
            self.record("on_custom_request");
            Ok(CustomResult::new(json!({ "delegated": true })))
        }

        async fn on_cancelled(
            &self,
            _notification: CancelledNotificationParam,
            _context: NotificationContext<RoleServer>,
        ) {
            self.record("on_cancelled");
        }

        async fn on_progress(
            &self,
            _notification: ProgressNotificationParam,
            _context: NotificationContext<RoleServer>,
        ) {
            self.record("on_progress");
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

    /// Two of rmcp's five known versions: distinguishable from the default
    /// (all of `KNOWN_VERSIONS`), while still covering an initialize-capable
    /// version and the 2026-07-28 version that `discover` requires.
    const SENTINEL_VERSIONS: [ProtocolVersion; 2] =
        [ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28];

    /// Capabilities the probe advertises so the dispatcher routes prompts,
    /// resources, tools, tool-list-changed subscriptions and tasks to the
    /// wrapper at all.
    fn probe_capabilities() -> rmcp::model::ServerCapabilities {
        rmcp::model::ServerCapabilities::builder()
            .enable_prompts()
            .enable_resources()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_tasks()
            .build()
    }

    /// Records every method it is called with and answers with a sentinel no
    /// rmcp default body can construct, so exact-log equality proves the
    /// wrapper forwarded the call.
    ///
    /// Deliberately silent (no record) for `get_info`,
    /// `supported_protocol_versions` and `get_tool`: rmcp calls those outside
    /// request dispatch (peer configuration, capability validation), so a
    /// record could not be attributed to the driver. Those three are proven by
    /// value differential against [`PassthroughDefaults`] instead.
    #[derive(Clone, Default)]
    struct ForwardingProbe {
        seen: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl ForwardingProbe {
        fn record(&self, method: &'static str) {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(method);
            }
        }

        fn seen(&self) -> Vec<&'static str> {
            self.seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default()
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
                Arc::new(rmcp::model::JsonObject::default()),
            ))
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

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, ErrorData> {
            self.record("list_tools");
            Ok(ListToolsResult::with_all_items(vec![Tool::new(
                "sentinel-tool",
                "forwarding-probe",
                Arc::new(rmcp::model::JsonObject::default()),
            )]))
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

        async fn list_resources(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListResourcesResult, ErrorData> {
            self.record("list_resources");
            Ok(ListResourcesResult::with_all_items(vec![Resource::new(
                "test://sentinel-resource",
                "sentinel-resource",
            )]))
        }

        async fn list_resource_templates(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListResourceTemplatesResult, ErrorData> {
            self.record("list_resource_templates");
            Ok(ListResourceTemplatesResult::with_all_items(vec![
                ResourceTemplate::new("test://sentinel/{id}", "sentinel-template"),
            ]))
        }

        async fn get_prompt(
            &self,
            _request: GetPromptRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<GetPromptResponse, ErrorData> {
            self.record("get_prompt");
            Ok(GetPromptResult::new(vec![PromptMessage::new_text(
                Role::User,
                "forwarding-probe:get_prompt",
            )])
            .into())
        }

        async fn read_resource(
            &self,
            _request: ReadResourceRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<ReadResourceResponse, ErrorData> {
            self.record("read_resource");
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                "forwarding-probe:read_resource",
                "test://sentinel-resource",
            )])
            .into())
        }

        fn accepted_subscription_filter(
            &self,
            requested: &SubscriptionFilter,
        ) -> Option<SubscriptionFilter> {
            self.record("accepted_subscription_filter");
            Some(requested.clone())
        }

        async fn listen(&self, _context: SubscriptionContext) -> Result<(), ErrorData> {
            self.record("listen");
            Ok(())
        }

        async fn get_task(
            &self,
            request: GetTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<GetTaskResult, ErrorData> {
            self.record("get_task");
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

        async fn update_task(
            &self,
            _request: UpdateTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("update_task");
            Err(ErrorData::invalid_request(
                "forwarding-probe:update_task",
                None,
            ))
        }

        async fn cancel_task(
            &self,
            _request: CancelTaskParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<(), ErrorData> {
            self.record("cancel_task");
            Ok(())
        }
    }

    fn delegation_transport(probe: DelegationProbe, hooks: Arc<ToolHooks>) -> DelegationTransport {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (client_read, client_write) = tokio::io::split(client);
        let service = rmcp::service::serve_directly::<RoleServer, _, _, io::Error, _>(
            with_hooks(probe.clone(), hooks),
            server,
            None,
        );
        (probe, BufReader::new(client_read), client_write, service)
    }

    async fn send_json_rpc(
        writer: &mut tokio::io::WriteHalf<DuplexStream>,
        reader: &mut BufReader<tokio::io::ReadHalf<DuplexStream>>,
        request: serde_json::Value,
    ) -> serde_json::Value {
        writer
            .write_all(request.to_string().as_bytes())
            .await
            .expect("write request");
        writer.write_all(b"\n").await.expect("write newline");
        writer.flush().await.expect("flush request");

        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        serde_json::from_str(&line).expect("response is JSON")
    }

    async fn send_notification(
        writer: &mut tokio::io::WriteHalf<DuplexStream>,
        notification: serde_json::Value,
    ) {
        writer
            .write_all(notification.to_string().as_bytes())
            .await
            .expect("write notification");
        writer.write_all(b"\n").await.expect("write newline");
        writer.flush().await.expect("flush notification");
    }

    /// Overrides only `negotiate_initialize`, so the sentinel value can only
    /// come from an inner override reaching the caller through the wrapper.
    /// `get_info` stays at the test default and `initialize` at the upstream
    /// default, so no other path can produce the sentinel.
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
    fn hooked_handler_preserves_inner_negotiate_initialize_override() {
        let handler = with_hooks(NegotiateProbe, Arc::new(ToolHooks::new()));
        let request = InitializeRequestParams::new(
            rmcp::model::ClientCapabilities::default(),
            rmcp::model::Implementation::new("delegation-test-client", "0.0.0"),
        );

        // Called directly on the wrapper (the HTTP path routes `initialize`,
        // which is already delegated); the trait default here would negotiate
        // from `get_info()` + `supported_protocol_versions()`, losing the
        // override.
        let result = handler
            .negotiate_initialize(&request)
            .expect("direct negotiation must succeed");

        assert_eq!(
            result.instructions.as_deref(),
            Some("inner negotiate_initialize override"),
            "wrapper must delegate to the inner `negotiate_initialize` override"
        );
    }

    #[tokio::test]
    async fn hooked_handler_delegates_ping() {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let response = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
        )
        .await;

        assert_eq!(response["result"], json!({}));
        assert_eq!(probe.seen(), vec!["ping"]);
    }

    #[tokio::test]
    async fn hooked_handler_delegates_notifications() {
        let (probe, _reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        send_notification(
            &mut writer,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 1, "reason": "test" }
            }),
        )
        .await;
        send_notification(
            &mut writer,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": { "progressToken": 1, "progress": 0.5 }
            }),
        )
        .await;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
        )
        .await;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/custom/probe" }),
        )
        .await;

        probe.wait_for_seen_count(5).await;
        assert_eq!(
            probe.seen(),
            vec![
                "on_cancelled",
                "on_progress",
                "on_initialized",
                "on_roots_list_changed",
                "on_custom_notification"
            ]
        );
    }

    #[tokio::test]
    #[allow(
        deprecated,
        reason = "set_level is deprecated by rmcp but must delegate"
    )]
    async fn hooked_handler_delegates_completion_and_level() {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let completion = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "completion/complete",
                "params": {
                    "ref": { "type": "ref/prompt", "name": "prompt" },
                    "argument": { "name": "arg", "value": "de" }
                }
            }),
        )
        .await;
        let level = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "logging/setLevel",
                "params": { "level": "debug" }
            }),
        )
        .await;

        assert_eq!(
            completion["result"]["completion"]["values"],
            json!(["delegated"])
        );
        assert_eq!(level["result"], json!({}));
        assert_eq!(probe.seen(), vec!["complete", "set_level"]);
    }

    #[tokio::test]
    #[allow(
        deprecated,
        reason = "subscribe/unsubscribe are deprecated by rmcp but must delegate"
    )]
    async fn hooked_handler_delegates_subscriptions() {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let subscribe = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/subscribe",
                "params": { "uri": "file:///tmp/a" }
            }),
        )
        .await;
        let unsubscribe = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/unsubscribe",
                "params": { "uri": "file:///tmp/a" }
            }),
        )
        .await;

        assert_eq!(subscribe["result"], json!({}));
        assert_eq!(unsubscribe["result"], json!({}));
        assert_eq!(probe.seen(), vec!["subscribe", "unsubscribe"]);
    }

    #[tokio::test]
    async fn hooked_handler_delegates_custom_request() {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let response = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "requests/custom/probe",
                "params": { "x": true }
            }),
        )
        .await;

        assert_eq!(response["result"], json!({ "delegated": true }));
        assert_eq!(probe.seen(), vec!["on_custom_request"]);
    }

    #[tokio::test]
    async fn hooked_handler_still_applies_hooks_to_call_tool() {
        let before_count = Arc::new(AtomicUsize::new(0));
        let before_seen = Arc::clone(&before_count);
        let before: BeforeHook = Arc::new(move |_ctx| {
            let before_seen = Arc::clone(&before_seen);
            Box::pin(async move {
                before_seen.fetch_add(1, Ordering::Relaxed);
                HookOutcome::Continue
            })
        });
        let after_count = Arc::new(AtomicUsize::new(0));
        let after_seen = Arc::clone(&after_count);
        let after_notify = Arc::new(tokio::sync::Notify::new());
        let after_notify_seen = Arc::clone(&after_notify);
        let after: AfterHook = Arc::new(move |_ctx, _disp, _size| {
            let after_seen = Arc::clone(&after_seen);
            let after_notify_seen = Arc::clone(&after_notify_seen);
            Box::pin(async move {
                after_seen.fetch_add(1, Ordering::Relaxed);
                after_notify_seen.notify_waiters();
            })
        });
        let hooks = Arc::new(
            ToolHooks::new()
                .with_before(before)
                .with_after(after)
                .with_max_result_bytes(1024),
        );
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), hooks);

        let response = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "probe", "arguments": {} }
            }),
        )
        .await;

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while after_count.load(Ordering::Relaxed) == 0 {
                after_notify.notified().await;
            }
        })
        .await
        .expect("after hook should run");
        assert_eq!(response["result"]["content"][0]["text"], "inner");
        assert_eq!(probe.seen(), vec!["call_tool"]);
        assert_eq!(before_count.load(Ordering::Relaxed), 1);
        assert_eq!(after_count.load(Ordering::Relaxed), 1);
    }

    // ----------------------------------------------------------------------
    // Semantic coverage drivers
    //
    // Each driver proves, by exact equality on the inner probe's record log
    // (and on sentinel values no rmcp default body can produce), that the
    // wrapper forwarded the call. Every driver runs twice: once against the
    // real wrapper, and once against `PassthroughDefaults` -- the wrapper with
    // all delegations deleted -- where the probe must stay untouched. That
    // second half is the per-method mutation check.
    //
    // No assertion here uses `contains`, `is_empty()` or a length threshold:
    // rmcp's self-re-entrant defaults (`initialize`, `negotiate_initialize`,
    // `discover`) and its ambient handler calls can otherwise make a
    // non-forwarding body look green.
    // ----------------------------------------------------------------------

    /// Maps every method the `HookedHandler` `ServerHandler` impl defines to the
    /// test that proves the inner handler was reached.
    ///
    /// Parsed by `tests/delegation_guard.rs`, which asserts this table covers
    /// exactly its `DIRECTLY_DELEGATED ∪ BEHAVIORAL_WRAPPED` classification --
    /// so a method cannot be added or reclassified without a driver.
    const SEMANTIC_DRIVERS: &[(&str, &str)] = &[
        ("ping", "hooked_handler_delegates_ping"),
        (
            "initialize",
            "hooked_handler_forwards_initialize_and_discover",
        ),
        (
            "negotiate_initialize",
            "hooked_handler_preserves_inner_negotiate_initialize_override",
        ),
        (
            "supported_protocol_versions",
            "hooked_handler_forwards_direct_sync_methods",
        ),
        (
            "discover",
            "hooked_handler_forwards_initialize_and_discover",
        ),
        ("complete", "hooked_handler_delegates_completion_and_level"),
        ("set_level", "hooked_handler_delegates_completion_and_level"),
        (
            "get_prompt",
            "hooked_handler_forwards_prompt_and_resource_reads",
        ),
        ("list_prompts", "hooked_handler_forwards_listing_methods"),
        ("list_resources", "hooked_handler_forwards_listing_methods"),
        (
            "list_resource_templates",
            "hooked_handler_forwards_listing_methods",
        ),
        (
            "read_resource",
            "hooked_handler_forwards_prompt_and_resource_reads",
        ),
        (
            "accepted_subscription_filter",
            "hooked_handler_forwards_subscription_lifecycle",
        ),
        ("listen", "hooked_handler_forwards_subscription_lifecycle"),
        ("subscribe", "hooked_handler_delegates_subscriptions"),
        ("unsubscribe", "hooked_handler_delegates_subscriptions"),
        (
            "call_tool",
            "hooked_handler_still_applies_hooks_to_call_tool",
        ),
        ("list_tools", "hooked_handler_forwards_listing_methods"),
        ("get_tool", "hooked_handler_forwards_direct_sync_methods"),
        (
            "on_custom_request",
            "hooked_handler_delegates_custom_request",
        ),
        ("on_cancelled", "hooked_handler_delegates_notifications"),
        ("on_progress", "hooked_handler_delegates_notifications"),
        ("on_initialized", "hooked_handler_delegates_notifications"),
        (
            "on_roots_list_changed",
            "hooked_handler_delegates_notifications",
        ),
        (
            "on_custom_notification",
            "hooked_handler_delegates_notifications",
        ),
        ("get_info", "hooked_handler_forwards_direct_sync_methods"),
        ("get_task", "hooked_handler_forwards_task_methods"),
        ("update_task", "hooked_handler_forwards_task_methods"),
        ("cancel_task", "hooked_handler_forwards_task_methods"),
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

    /// Per-request metadata satisfying every gate the drivers cross: a protocol
    /// version inside the probe's narrowed list, and client capabilities
    /// declaring the tasks extension that `tasks/*` requires.
    fn coverage_meta() -> serde_json::Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": { "io.modelcontextprotocol/tasks": {} }
            }
        })
    }

    /// A request whose `params._meta` carries [`coverage_meta`].
    fn coverage_request(id: i64, method: &str, mut params: serde_json::Value) -> serde_json::Value {
        let object = params
            .as_object_mut()
            .expect("coverage requests carry an object of params");
        object.insert("_meta".to_owned(), coverage_meta());
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    /// Read one server frame that is already queued (used where a single
    /// request produces two frames: the subscription acknowledgement, then the
    /// response).
    async fn read_json_rpc(
        reader: &mut BufReader<tokio::io::ReadHalf<DuplexStream>>,
    ) -> serde_json::Value {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        serde_json::from_str(&line).expect("response is JSON")
    }

    type ForwardingTransport<P> = (
        BufReader<tokio::io::ReadHalf<DuplexStream>>,
        tokio::io::WriteHalf<DuplexStream>,
        rmcp::service::RunningService<RoleServer, HookedHandler<P>>,
    );

    /// Like [`delegation_transport`], but for a caller-chosen inner handler, so
    /// one driver can run against both the real wrapper and
    /// [`PassthroughDefaults`].
    fn forwarding_transport<P: ServerHandler>(
        inner: P,
        hooks: Arc<ToolHooks>,
    ) -> ForwardingTransport<P> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (client_read, client_write) = tokio::io::split(client);
        let service = rmcp::service::serve_directly::<RoleServer, _, _, io::Error, _>(
            with_hooks(inner, hooks),
            server,
            None,
        );
        (BufReader::new(client_read), client_write, service)
    }

    fn coverage_hooks() -> Arc<ToolHooks> {
        Arc::new(ToolHooks::new())
    }

    #[test]
    fn hooked_handler_forwards_direct_sync_methods() {
        // No record log in this driver: `get_info`, `get_tool` and
        // `supported_protocol_versions` are proven by value differential, so
        // rmcp's ambient calls cannot contaminate the proof.
        let wrapper = with_hooks(ForwardingProbe::default(), coverage_hooks());
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
    async fn hooked_handler_forwards_initialize_and_discover() {
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let initialize = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "coverage-driver", "version": "0.0.0" }
                }
            }),
        )
        .await;
        assert_eq!(
            initialize["result"]["instructions"],
            json!("forwarding-probe:initialize")
        );

        let discover = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "server/discover", json!({})),
        )
        .await;
        assert_eq!(
            discover["result"]["supportedVersions"],
            json!(["2025-11-25", "2026-07-28"])
        );

        // Exact full sequence (mechanism 3): the two driven methods and nothing
        // else. Neither can be produced by a re-entrant default -- the probe
        // overrides `initialize` outright, and `discover` is only reachable
        // through the wrapper's delegation -- so the expected log contains both
        // driven methods, per the ambient-calls invariant.
        assert_eq!(probe.seen(), vec!["initialize", "discover"]);

        // Negative control: with every delegation deleted, both requests are
        // answered by rmcp defaults and the probe stays untouched.
        let control = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_initialize = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "coverage-driver", "version": "0.0.0" }
                }
            }),
        )
        .await;
        let control_discover = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "server/discover", json!({})),
        )
        .await;
        assert_ne!(
            control_initialize["result"]["instructions"],
            json!("forwarding-probe:initialize")
        );
        assert_ne!(
            control_discover["result"]["supportedVersions"],
            json!(["2025-11-25", "2026-07-28"])
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn hooked_handler_forwards_listing_methods() {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let tools = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tools/list", json!({})),
        )
        .await;
        let prompts = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "prompts/list", json!({})),
        )
        .await;
        let resources = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(3, "resources/list", json!({})),
        )
        .await;
        let templates = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(4, "resources/templates/list", json!({})),
        )
        .await;

        assert_eq!(tools["result"]["tools"][0]["name"], json!("sentinel-tool"));
        assert_eq!(
            prompts["result"]["prompts"][0]["name"],
            json!("sentinel-prompt")
        );
        assert_eq!(
            resources["result"]["resources"][0]["uri"],
            json!("test://sentinel-resource")
        );
        assert_eq!(
            templates["result"]["resourceTemplates"][0]["uriTemplate"],
            json!("test://sentinel/{id}")
        );
        assert_eq!(
            probe.seen(),
            vec![
                "list_tools",
                "list_prompts",
                "list_resources",
                "list_resource_templates"
            ]
        );

        // Negative control: the same four requests, answered by defaults --
        // empty result sets, probe untouched.
        let control = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_tools = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tools/list", json!({})),
        )
        .await;
        let control_prompts = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "prompts/list", json!({})),
        )
        .await;
        let control_resources = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(3, "resources/list", json!({})),
        )
        .await;
        let control_templates = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(4, "resources/templates/list", json!({})),
        )
        .await;
        assert_eq!(control_tools["result"]["tools"], json!([]));
        assert_eq!(control_prompts["result"]["prompts"], json!([]));
        assert_eq!(control_resources["result"]["resources"], json!([]));
        assert_eq!(control_templates["result"]["resourceTemplates"], json!([]));
        assert_eq!(control.seen(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn hooked_handler_forwards_prompt_and_resource_reads() {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let prompt = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "prompts/get", json!({ "name": "sentinel-prompt" })),
        )
        .await;
        let resource = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                2,
                "resources/read",
                json!({ "uri": "test://sentinel-resource" }),
            ),
        )
        .await;

        assert_eq!(
            prompt["result"]["messages"][0]["content"]["text"],
            json!("forwarding-probe:get_prompt")
        );
        assert_eq!(
            resource["result"]["contents"][0]["text"],
            json!("forwarding-probe:read_resource")
        );
        assert_eq!(probe.seen(), vec!["get_prompt", "read_resource"]);

        // Negative control: both defaults reject with method-not-found, so the
        // client sees an error and the probe is never entered.
        let control = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_prompt = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "prompts/get", json!({ "name": "sentinel-prompt" })),
        )
        .await;
        let control_resource = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                2,
                "resources/read",
                json!({ "uri": "test://sentinel-resource" }),
            ),
        )
        .await;
        assert_eq!(control_prompt["error"]["code"], json!(-32601));
        assert_eq!(control_resource["error"]["code"], json!(-32601));
        assert_eq!(control.seen(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn hooked_handler_forwards_task_methods() {
        // Mechanism 1 (ambient-silent probe): rmcp calls `get_info` for the
        // tasks-capability gate, which this probe does not record, so the
        // expected log is exactly the driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let get = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tasks/get", json!({ "taskId": "raw-task" })),
        )
        .await;
        let update = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                2,
                "tasks/update",
                json!({ "taskId": "raw-task", "inputResponses": {} }),
            ),
        )
        .await;
        let cancel = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(3, "tasks/cancel", json!({ "taskId": "raw-task" })),
        )
        .await;

        // `DetailedTask` inlines the base task fields at the top level of the
        // result, so the echoed sentinel id sits at `result.taskId`.
        assert_eq!(get["result"]["taskId"], json!("raw-task"));
        assert_eq!(
            update["error"]["message"],
            json!("forwarding-probe:update_task")
        );
        assert_eq!(cancel["result"], json!({ "resultType": "complete" }));
        assert_eq!(probe.seen(), vec!["get_task", "update_task", "cancel_task"]);

        // Negative control: the tasks capability gate rejects both requests
        // before dispatch (the passthrough advertises no `tasks` extension).
        let control = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_get = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tasks/get", json!({ "taskId": "raw-task" })),
        )
        .await;
        assert_eq!(control_get["error"]["code"], json!(-32601));
        assert_eq!(control.seen(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn hooked_handler_forwards_subscription_lifecycle() {
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        // Two frames come back: the acknowledgement is emitted before `listen`
        // runs, the response after it returns.
        let ack = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                1,
                "subscriptions/listen",
                json!({ "notifications": { "toolsListChanged": true } }),
            ),
        )
        .await;
        assert_eq!(
            ack["method"],
            json!("notifications/subscriptions/acknowledged")
        );
        let response = read_json_rpc(&mut reader).await;
        assert_eq!(response["id"], json!(1));
        assert_eq!(response["result"]["resultType"], json!("complete"));

        // Exact full sequence (mechanism 3): this arm calls
        // `accepted_subscription_filter` before `listen`, and both are the
        // wrapper's own delegations -- so the expected log is the two-element
        // ordered sequence, not the singleton `["listen"]`.
        assert_eq!(probe.seen(), vec!["accepted_subscription_filter", "listen"]);

        // Negative control: the default filter hook returns `None`, so rmcp
        // rejects the request before `listen` and the probe stays untouched.
        let control = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_listen = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                1,
                "subscriptions/listen",
                json!({ "notifications": { "toolsListChanged": true } }),
            ),
        )
        .await;
        assert_eq!(control_listen["error"]["code"], json!(-32601));
        assert_eq!(control.seen(), Vec::<&str>::new());
    }

    fn ctx(name: &str) -> ToolCallContext {
        ToolCallContext {
            tool_name: name.to_owned(),
            arguments: None,
            identity: None,
            role: None,
            sub: None,
            request_id: None,
        }
    }

    fn sensitive_ctx() -> ToolCallContext {
        ToolCallContext {
            tool_name: "safe-tool-name".to_owned(),
            arguments: Some(serde_json::json!({ "password": "argument-secret" })),
            identity: Some("identity-secret".to_owned()),
            role: Some("role-secret".to_owned()),
            sub: Some("sub-secret".to_owned()),
            request_id: Some("request-id-visible".to_owned()),
        }
    }

    #[test]
    fn request_id_for_log_escapes_control_characters() {
        let ctx = ToolCallContext {
            request_id: Some("evil\n2026-01-01 INFO forged log line\u{1b}[31m".to_owned()),
            ..ToolCallContext::for_tool("t")
        };
        let escaped = ctx
            .request_id_for_log()
            .expect("request id is present so the accessor returns Some");
        assert!(
            !escaped.contains('\n'),
            "a raw newline lets a client forge log lines: {escaped}"
        );
        assert!(
            !escaped.contains('\u{1b}'),
            "a raw ESC lets a client emit terminal escape sequences: {escaped}"
        );
        assert!(
            escaped.starts_with("evil\\n"),
            "the newline must be escaped, not stripped: {escaped}"
        );
    }

    #[test]
    fn request_id_for_log_leaves_ordinary_ids_unquoted() {
        let ctx = ToolCallContext {
            request_id: Some("abc-123".to_owned()),
            ..ToolCallContext::for_tool("t")
        };
        assert_eq!(
            ctx.request_id_for_log().as_deref(),
            Some("abc-123"),
            "an ordinary id must survive unchanged and unquoted"
        );
        assert_eq!(
            ToolCallContext::for_tool("t").request_id_for_log(),
            None,
            "absent request id yields None"
        );
    }

    #[test]
    fn tool_call_context_debug_redacts_sensitive_fields_by_default() {
        let _guard = crate::diagnostics::ExposureTestGuard::acquire();
        crate::diagnostics::set_diagnostic_exposure(
            &crate::diagnostics::DiagnosticExposure::default(),
        );

        let rendered = format!("{:?}", sensitive_ctx());

        assert!(rendered.contains("safe-tool-name"));
        assert!(rendered.contains("request-id-visible"));
        assert!(rendered.contains("[REDACTED]"));
        for secret in [
            "argument-secret",
            "identity-secret",
            "role-secret",
            "sub-secret",
        ] {
            assert!(
                !rendered.contains(secret),
                "ToolCallContext Debug must not contain {secret}: {rendered}"
            );
        }
    }

    #[test]
    fn tool_call_context_debug_can_show_sensitive_fields_when_enabled() {
        let _guard = crate::diagnostics::ExposureTestGuard::acquire();
        crate::diagnostics::set_diagnostic_exposure(&crate::diagnostics::DiagnosticExposure {
            tool_call_arguments: true,
            ..crate::diagnostics::DiagnosticExposure::default()
        });

        let rendered = format!("{:?}", sensitive_ctx());

        for secret in [
            "argument-secret",
            "identity-secret",
            "role-secret",
            "sub-secret",
        ] {
            assert!(
                rendered.contains(secret),
                "ToolCallContext Debug must contain {secret} when enabled: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn size_cap_replaces_oversized_result() {
        let inner = TestHandler {
            body_bytes: Some(8_192),
        };
        let hooks = Arc::new(ToolHooks {
            max_result_bytes: Some(256),
            before: None,
            after: None,
        });
        let hooked = with_hooks(inner, hooks);

        let small = CallToolResult::success(vec![ContentBlock::text("ok".to_owned())]);
        assert!(exact_size(&small) < 256);

        let big = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);
        let size = exact_size(&big);
        assert!(size > 256);

        let (replaced, accounted, capped) = apply_size_cap(big, Some(256), "whatever");
        assert!(capped);
        assert_eq!(accounted, 257);
        assert_eq!(replaced.is_error, Some(true));
        assert!(matches!(
            replaced.content.first(),
            Some(rmcp::model::ContentBlock::Text(t)) if t.text.contains("result_too_large")
        ));

        // Compile-check that HookedHandler instantiates with the test inner.
        let _ = hooked;
    }

    fn exact_size(result: &CallToolResult) -> usize {
        match serialized_size(result, None) {
            SizeMeasure::Exact(size) => size,
            SizeMeasure::Exceeded { limit } => {
                panic!("unbounded measurement exceeded impossible limit {limit}");
            }
        }
    }

    #[test]
    fn serialized_size_under_cap_is_exact() {
        let result = CallToolResult::success(vec![ContentBlock::text("ok".to_owned())]);
        let exact = serde_json::to_vec(&result).unwrap().len();

        let measured = serialized_size(&result, Some(exact));

        assert_eq!(measured, SizeMeasure::Exact(exact));
    }

    #[test]
    fn serialized_size_over_cap_stops_with_exceeded() {
        let result = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);

        let measured = serialized_size(&result, Some(256));

        assert_eq!(measured, SizeMeasure::Exceeded { limit: 256 });
    }

    #[test]
    fn over_cap_replacement_does_not_log_serialization_failure() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let result = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);

        let (_final_result, accounted, capped) = apply_size_cap(result, Some(256), "big_tool");

        assert!(capped);
        assert_eq!(accounted, 257);
        assert!(
            logs.contents()
                .contains("tool result exceeds max_result_bytes")
        );
        assert!(
            !logs.contents().contains("failed to serialize"),
            "cap-abort must not be logged as serialization failure: {}",
            logs.contents()
        );
    }

    #[test]
    fn disabled_result_cap_skips_measurement() {
        let result = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);

        let (_final_result, accounted, capped) = apply_size_cap(result, None, "uncapped_tool");

        assert!(!capped);
        assert_eq!(accounted, 0);
    }

    #[tokio::test]
    async fn before_hook_deny_builds_error() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let before: BeforeHook = Arc::new(move |ctx_ref| {
            let c = Arc::clone(&c);
            let name = ctx_ref.tool_name.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
                if name == "forbidden" {
                    HookOutcome::Deny(ErrorData::invalid_request("nope", None))
                } else {
                    HookOutcome::Continue
                }
            })
        });

        let hooks = Arc::new(ToolHooks {
            max_result_bytes: None,
            before: Some(before),
            after: None,
        });
        let hooked = with_hooks(TestHandler::default(), hooks);

        let bad_ctx = ctx("forbidden");
        let before_fn = hooked.hooks.before.as_ref().unwrap();
        let outcome = before_fn(&bad_ctx).await;
        assert!(matches!(outcome, HookOutcome::Deny(_)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        let ok_ctx = ctx("allowed");
        let outcome2 = before_fn(&ok_ctx).await;
        assert!(matches!(outcome2, HookOutcome::Continue));
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn too_large_result_mentions_limit_and_actual() {
        let r = too_large_result(100, Some(500), "my_tool");
        let body = serde_json::to_string(&r).unwrap();
        assert!(body.contains("result_too_large"));
        assert!(body.contains("my_tool"));
        assert!(body.contains("100"));
        assert!(body.contains("500"));
    }

    #[test]
    fn decide_size_truth_table() {
        assert_eq!(
            decide_size(Some(SizeMeasure::Exact(10)), Some(100)),
            SizeVerdict::Pass { size: 10 }
        );
        assert_eq!(
            decide_size(Some(SizeMeasure::Exact(100)), Some(100)),
            SizeVerdict::Pass { size: 100 },
            "cap is inclusive: size == limit passes"
        );
        assert_eq!(
            decide_size(Some(SizeMeasure::Exact(101)), Some(100)),
            SizeVerdict::Replace {
                limit: 100,
                actual: Some(101)
            }
        );
        assert_eq!(
            decide_size(Some(SizeMeasure::Exact(999)), None),
            SizeVerdict::Pass { size: 999 }
        );
        assert_eq!(
            decide_size(None, Some(100)),
            SizeVerdict::Replace {
                limit: 100,
                actual: None
            },
            "unmeasurable result must fail closed when a cap is configured"
        );
        assert_eq!(decide_size(None, None), SizeVerdict::PassUnmeasured);
        assert_eq!(
            decide_size(Some(SizeMeasure::Exceeded { limit: 100 }), Some(100)),
            SizeVerdict::Replace {
                limit: 100,
                actual: None
            },
            "cap-abort is not an exact measurement"
        );
    }

    #[test]
    fn too_large_result_does_not_fabricate_a_size_when_unmeasurable() {
        let r = too_large_result(100, None, "my_tool");
        let body = serde_json::to_string(&r).unwrap();
        assert!(body.contains("result_too_large"));
        assert!(body.contains("unknown"));
        assert!(
            !body.contains("101"),
            "the over-limit accounting sentinel must not leak into the client payload"
        );
    }

    #[tokio::test]
    async fn replace_outcome_skips_inner_and_returns_payload() {
        // Returning Replace from before-hook must yield the supplied
        // CallToolResult directly, with no need for the inner handler.
        let before: BeforeHook = Arc::new(|_ctx| {
            Box::pin(async {
                HookOutcome::Replace(Box::new(CallToolResult::success(vec![ContentBlock::text(
                    "from-replace".to_owned(),
                )])))
            })
        });
        let hooks = Arc::new(ToolHooks {
            max_result_bytes: None,
            before: Some(before),
            after: None,
        });
        let _hooked = with_hooks(TestHandler::default(), Arc::clone(&hooks));

        // Exercise the before-hook closure + apply_size_cap helper directly,
        // matching the established test pattern in this module.
        let outcome = (hooks.before.as_ref().unwrap())(&ctx("any")).await;
        let HookOutcome::Replace(boxed) = outcome else {
            panic!("expected HookOutcome::Replace");
        };
        let (result, size, capped) = apply_size_cap(*boxed, None, "any");
        assert!(!capped);
        assert_eq!(size, 0);
        assert!(!result.is_error.unwrap_or(false));
        assert!(matches!(
            result.content.first(),
            Some(rmcp::model::ContentBlock::Text(t)) if t.text == "from-replace"
        ));
    }

    #[tokio::test]
    async fn replace_outcome_subject_to_size_cap() {
        // A Replace payload that exceeds max_result_bytes must be rewritten
        // to result_too_large just like an inner-handler result would be,
        // and the disposition must reflect ResultTooLarge.
        let huge = CallToolResult::success(vec![ContentBlock::text("y".repeat(8_192))]);
        let huge_size = serde_json::to_vec(&huge).unwrap().len();
        assert!(huge_size > 256);

        let (final_result, accounted, capped) = apply_size_cap(huge, Some(256), "replaced_tool");
        assert!(capped);
        assert_eq!(accounted, 257);
        assert_eq!(final_result.is_error, Some(true));
        assert!(matches!(
            final_result.content.first(),
            Some(rmcp::model::ContentBlock::Text(t)) if t.text.contains("result_too_large")
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_hook_fires_exactly_once_via_spawn() {
        // spawn_after must enqueue the after-hook exactly one time per
        // invocation and never block the caller; we wait for the spawned
        // task to run by polling the counter with a short timeout.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let after: AfterHook = Arc::new(move |_ctx, _disp, _size| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
            })
        });
        let holder = Arc::new(AfterHookHolder { f: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("t"),
            HookDisposition::InnerExecuted,
            42,
        );

        // Wait up to 1s for the spawned task to run.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while counter.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_hook_panic_is_isolated_from_response_path() {
        // A panicking after-hook must not affect the request task.  We
        // spawn a panicking after-hook and then verify the current task
        // can still complete an unrelated future to completion.
        let after: AfterHook = Arc::new(|_ctx, _disp, _size| {
            Box::pin(async {
                panic!("intentional panic in after-hook");
            })
        });
        let holder = Arc::new(AfterHookHolder { f: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("boom"),
            HookDisposition::InnerExecuted,
            0,
        );

        // Give Tokio a chance to run + abort the panicking task, then
        // confirm we're still alive and the runtime is healthy.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let still_alive = tokio::spawn(async { 1_u32 + 2 }).await.unwrap();
        assert_eq!(still_alive, 3);
    }
}
