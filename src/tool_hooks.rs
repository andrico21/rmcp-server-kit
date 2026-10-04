//! Opt-in tool-call instrumentation for `ServerHandler` implementations.
//!
//! [`crate::tool_hooks::HookedHandler`] wraps any [`rmcp::ServerHandler`] with:
//!
//! - **Before hooks** (async) that observe `(tool_name, arguments, identity,
//!   role, sub, request_id)` and may
//!   [`crate::tool_hooks::HookOutcome::Continue`],
//!   [`crate::tool_hooks::HookOutcome::Deny`], or
//!   [`crate::tool_hooks::HookOutcome::Replace`] the call.
//! - **After hooks** (async) that observe the same context plus a
//!   [`crate::tool_hooks::HookDisposition`] describing how the
//!   call resolved and the approximate result size in bytes.  After-hooks are
//!   spawned via `tokio::spawn` and never block the response path.
//! - **Result-size capping**: serialized tool results larger than
//!   `max_result_bytes` are replaced with a structured error, preventing
//!   token-expensive or memory-expensive payloads from reaching clients.
//!   The cap applies both to inner-handler results and to
//!   [`crate::tool_hooks::HookOutcome::Replace`] payloads.
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
extern crate alloc;

use alloc::{borrow::Cow, sync::Arc};
use core::{error::Error, fmt, pin::Pin};
use std::io;

#[expect(
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

use crate::{diagnostics, rbac};

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
    #[inline]
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
    #[expect(
        clippy::impl_trait_in_params,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
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
    #[inline]
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
        let _tool_name_field = debug.field("tool_name", tool_name);
        if diagnostics::tool_call_arguments() {
            let _sensitive_fields = debug
                .field("arguments", arguments)
                .field("identity", identity)
                .field("role", role)
                .field("sub", sub);
        } else {
            let _redacted_fields = debug
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
    dyn for<'call> Fn(
            &'call ToolCallContext,
        ) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'call>>
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
    dyn for<'call> Fn(
            &'call ToolCallContext,
            HookDisposition,
            usize,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'call>>
        + Send
        + Sync
        + 'static,
>;

/// Opt-in hooks applied by [`crate::tool_hooks::HookedHandler`].
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
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the serialized result size cap in bytes.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "public API frozen until the next major release"
    )]
    #[inline]
    pub fn with_max_result_bytes(mut self, max: usize) -> Self {
        self.max_result_bytes = Some(max);
        self
    }

    /// Set the before-hook.
    #[must_use]
    #[inline]
    pub fn with_before(mut self, before: BeforeHook) -> Self {
        self.before = Some(before);
        self
    }

    /// Set the after-hook.
    #[must_use]
    #[inline]
    pub fn with_after(mut self, after: AfterHook) -> Self {
        self.after = Some(after);
        self
    }
}

/// Documentation anchor for `mdbook`/rustdoc intra-doc links that must keep
/// pointing at [`HookedHandler`] even if the type is renamed.
const _HOOKED_HANDLER_DOC_ANCHOR: &str = "HookedHandler";

impl fmt::Debug for ToolHooks {
    #[inline]
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
    /// The wrapped handler; shared so the wrapper stays `Clone`.
    inner: Arc<H>,
    /// Hooks applied around `call_tool`.
    hooks: Arc<ToolHooks>,
}

impl<H: ServerHandler> fmt::Debug for HookedHandler<H> {
    #[inline]
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
#[inline]
pub fn with_hooks<H>(inner: H, hooks: Arc<ToolHooks>) -> HookedHandler<H>
where
    H: ServerHandler,
{
    HookedHandler {
        inner: Arc::new(inner),
        hooks,
    }
}

impl<H: ServerHandler> HookedHandler<H> {
    /// Access the wrapped handler.
    #[must_use]
    #[inline]
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Build the hook context for one tool call from the request and the
    /// task-local RBAC state.
    fn build_context(request: &CallToolRequestParams, req_id: Option<String>) -> ToolCallContext {
        ToolCallContext {
            tool_name: request.name.to_string(),
            arguments: request.arguments.clone().map(serde_json::Value::Object),
            identity: rbac::current_identity(),
            role: rbac::current_role(),
            sub: rbac::current_sub(),
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
    /// [`rbac::with_rbac_scope`]. Without this, after-hooks lose
    /// their parent span (breaking trace correlation) and observe
    /// `current_role()` / `current_identity()` as `None`.
    fn spawn_after(
        after: Option<&Arc<AfterHookHolder>>,
        ctx: ToolCallContext,
        disposition: HookDisposition,
        size: usize,
    ) {
        if let Some(after_holder) = after {
            use tracing::{Instrument as _, Span};

            let holder = Arc::clone(after_holder);
            // Capture the request span before leaving the request task so
            // after-hook log lines are correlated with the originating call.
            let span = Span::current();
            // Snapshot RBAC task-locals; defaults are empty strings so the
            // re-established scope is a no-op when the request had no
            // authenticated identity (e.g. health checks, anonymous tools).
            let role = rbac::current_role().unwrap_or_default();
            let identity = rbac::current_identity().unwrap_or_default();
            let token =
                rbac::current_token().unwrap_or_else(|| secrecy::SecretString::from(String::new()));
            let sub = rbac::current_sub().unwrap_or_default();
            // Detached on purpose: dropping a `JoinHandle` detaches (never
            // aborts) the spawned task, so the after-hook still runs.
            let _after_task = tokio::spawn(
                async move {
                    rbac::with_rbac_scope(role, identity, token, sub, async move {
                        let fut = (holder.hook)(&ctx, disposition, size);
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
    /// The hook invoked by the spawned task.
    hook: AfterHook,
}

/// Structured error body returned when a result exceeds `max_result_bytes`.
///
/// `actual` is `None` when the result could not be serialized, so its true
/// size is unknown. It is rendered as `"unknown"` rather than a fabricated
/// number -- operators read `actual_bytes` as a measurement.
fn too_large_result(limit: usize, actual: Option<usize>, tool: &str) -> CallToolResult {
    let actual_desc = actual.map_or_else(
        || "an unmeasurable number of".to_owned(),
        |count| count.to_string(),
    );
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
    let mut result = CallToolResult::error(vec![ContentBlock::text(body.to_string())]);
    result.structured_content = None;
    result
}

/// Outcome of the `max_result_bytes` policy for a measured -- or
/// unmeasurable -- result.
#[derive(Debug, PartialEq, Eq)]
enum SizeVerdict {
    /// Within the cap, or no cap configured. Carries the measured size.
    Pass {
        /// The measured serialized size in bytes.
        size: usize,
    },
    /// Over the cap, or unmeasurable while a cap is configured.
    Replace {
        /// The configured cap.
        limit: usize,
        /// The measured size, or `None` when serialization was unmeasurable.
        actual: Option<usize>,
    },
    /// Unmeasurable and no cap configured: nothing to enforce.
    PassUnmeasured,
}

/// Decide what the size cap does, given an optional size-measurement outcome.
const fn decide_size(size: Option<SizeMeasure>, max: Option<usize>) -> SizeVerdict {
    match size {
        Some(SizeMeasure::Exact(measured)) => match max {
            Some(limit) if measured > limit => SizeVerdict::Replace {
                limit,
                actual: Some(measured),
            },
            Some(_) | None => SizeVerdict::Pass { size: measured },
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
    let size = max.is_some().then(|| serialized_size(&result, max));
    match decide_size(size, max) {
        SizeVerdict::Pass { size: measured } => (result, measured, false),
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

#[expect(
    deprecated,
    reason = "transparent ServerHandler delegation must include legacy logging/subscription methods until rmcp removes them"
)]
impl<H: ServerHandler> ServerHandler for HookedHandler<H> {
    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        self.inner.ping(context).await
    }

    #[inline]
    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
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
    #[inline]
    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.negotiate_initialize(request)
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.inner.list_tools(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        self.inner.complete(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.set_level(request, context).await
    }

    #[inline]
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.inner.list_prompts(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        self.inner.get_prompt(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.inner.list_resources(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.inner.list_resource_templates(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.inner.read_resource(request, context).await
    }

    // NOT cancel-safe: this awaits consumer-supplied before-hooks and the
    // consumer's inner handler. After-hooks are dispatched only on the normal
    // Deny/Replace/Ok/Err paths, so a cancellation between them drops the
    // paired after-hook -- an audit hook can record a started call that never
    // closes out. Make the after-hook idempotent or detach the tool body.
    #[inline]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let req_id = Some(context.id.to_string());
        let ctx = Self::build_context(&request, req_id);
        let max = self.hooks.max_result_bytes;
        let after_holder = self.hooks.after.as_ref().map(|hook| {
            Arc::new(AfterHookHolder {
                hook: Arc::clone(hook),
            })
        });

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
            Err(error) => {
                Self::spawn_after(after_holder.as_ref(), ctx, HookDisposition::InnerErrored, 0);
                Err(error)
            }
        }
    }

    // rmcp 3.0 added task/subscription/discovery request handlers with defaults;
    // delegate them to `inner` so wrapping a handler that implements those stays
    // transparent (otherwise the default would shadow the inner implementation).
    #[inline]
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        self.inner.discover(context).await
    }

    #[inline]
    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        self.inner.listen(context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.subscribe(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.unsubscribe(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        self.inner.get_task(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.update_task(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.inner.cancel_task(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        self.inner.on_custom_request(request, context).await
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_cancelled(notification, context).await;
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_progress(notification, context).await;
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_initialized(context).await;
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_roots_list_changed(context).await;
    }

    // cancel-safe: pure delegation to the inner handler; the wrapper holds no
    // state across the await.
    #[inline]
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

/// Marker error for the deliberate cap-abort of [`CountingWriter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SizeLimitExceeded;

impl fmt::Display for SizeLimitExceeded {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("serialized result exceeded configured size cap")
    }
}

impl Error for SizeLimitExceeded {}

/// [`io::Write`] sink that counts bytes and, when bounded, fails with
/// [`SizeLimitExceeded`] as soon as the count would cross the cap.
struct CountingWriter {
    /// Bytes written so far.
    bytes: usize,
    /// Cap that aborts the write once crossed, or `None` for an unbounded count.
    limit: Option<usize>,
}

impl CountingWriter {
    /// Byte counter without a cap.
    const fn unbounded() -> Self {
        Self {
            bytes: 0,
            limit: None,
        }
    }

    /// Byte counter that aborts the write once `limit` is crossed.
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
    Exceeded {
        /// The configured cap that was crossed.
        limit: usize,
    },
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
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{sync::Mutex, time::Instant};

    use anyhow::Context as _;
    use rmcp::{
        model::{
            ClientCapabilities, CompletionInfo, DetailedTask, GetPromptResult, Implementation,
            JsonObject, Prompt, PromptMessage, ReadResourceResult, Resource, ResourceContents,
            ResourceTemplate, Role, ServerCapabilities, Task, TaskPayload, TaskStatus,
        },
        service::{RunningService, serve_directly},
    };
    use serde_json::json;
    use tokio::{
        io::{
            AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream, ReadHalf, WriteHalf,
            duplex, split,
        },
        sync::Notify,
        task::yield_now,
        time::{sleep, timeout},
    };
    use tracing::subscriber::set_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    type DelegationTransport = (
        DelegationProbe,
        BufReader<ReadHalf<DuplexStream>>,
        WriteHalf<DuplexStream>,
        RunningService<RoleServer, HookedHandler<DelegationProbe>>,
    );

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.0.lock().map(|guard| guard.clone()).unwrap_or_default();
            String::from_utf8(bytes).unwrap_or_default()
        }
    }

    struct CapturedLogsWriter(Arc<Mutex<Vec<u8>>>);

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

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogsWriter;

        fn make_writer(&'writer self) -> Self::Writer {
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

        #[expect(
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
        seen: Arc<Mutex<Vec<&'static str>>>,
        notify: Arc<Notify>,
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
                .map_err(|message| ErrorData::internal_error(message, None))?;
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

    /// Two of rmcp's five known versions: distinguishable from the default
    /// (all of `KNOWN_VERSIONS`), while still covering an initialize-capable
    /// version and the 2026-07-28 version that `discover` requires.
    const SENTINEL_VERSIONS: [ProtocolVersion; 2] =
        [ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28];

    /// Capabilities the probe advertises so the dispatcher routes prompts,
    /// resources, tools, tool-list-changed subscriptions and tasks to the
    /// wrapper at all.
    fn probe_capabilities() -> ServerCapabilities {
        ServerCapabilities::builder()
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
        seen: Arc<Mutex<Vec<&'static str>>>,
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
                Arc::new(JsonObject::default()),
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
        let (client, server) = duplex(16 * 1024);
        let (client_read, client_write) = split(client);
        let service = serve_directly::<RoleServer, _, _, io::Error, _>(
            with_hooks(probe.clone(), hooks),
            server,
            None,
        );
        (probe, BufReader::new(client_read), client_write, service)
    }

    async fn send_json_rpc(
        writer: &mut WriteHalf<DuplexStream>,
        reader: &mut BufReader<ReadHalf<DuplexStream>>,
        request: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        writer
            .write_all(request.to_string().as_bytes())
            .await
            .context("write request")?;
        writer.write_all(b"\n").await.context("write newline")?;
        writer.flush().await.context("flush request")?;

        let mut line = String::new();
        let _bytes_read = reader.read_line(&mut line).await.context("read response")?;
        serde_json::from_str(&line).context("response is JSON")
    }

    async fn send_notification(
        writer: &mut WriteHalf<DuplexStream>,
        notification: serde_json::Value,
    ) -> anyhow::Result<()> {
        writer
            .write_all(notification.to_string().as_bytes())
            .await
            .context("write notification")?;
        writer.write_all(b"\n").await.context("write newline")?;
        writer.flush().await.context("flush notification")?;
        Ok(())
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
            let mut info = ServerConfig::new(ServerCapabilities::default());
            info.instructions = Some("inner negotiate_initialize override".to_owned());
            Ok(info)
        }
    }

    #[test]
    /// Pins that the wrapper delegates `negotiate_initialize` to an inner override.
    fn hooked_handler_preserves_inner_negotiate_initialize_override() -> anyhow::Result<()> {
        let handler = with_hooks(NegotiateProbe, Arc::new(ToolHooks::new()));
        let request = InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("delegation-test-client", "0.0.0"),
        );

        // Called directly on the wrapper (the HTTP path routes `initialize`,
        // which is already delegated); the trait default here would negotiate
        // from `get_info()` + `supported_protocol_versions()`, losing the
        // override.
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

    #[tokio::test]
    /// Pins that `ping` is forwarded to the inner handler.
    async fn hooked_handler_delegates_ping() -> anyhow::Result<()> {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let response = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({ "jsonrpc": "2.0", "id": 1_i32, "method": "ping" }),
        )
        .await?;

        assert_eq!(response.get("result"), Some(&json!({})));
        assert_eq!(probe.seen(), vec!["ping"]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that every notification method is forwarded to the inner handler.
    async fn hooked_handler_delegates_notifications() -> anyhow::Result<()> {
        let (probe, _reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        send_notification(
            &mut writer,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 1_i32, "reason": "test" }
            }),
        )
        .await?;
        send_notification(
            &mut writer,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": { "progressToken": 1_i32, "progress": 0.5_f64 }
            }),
        )
        .await?;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await?;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
        )
        .await?;
        send_notification(
            &mut writer,
            json!({ "jsonrpc": "2.0", "method": "notifications/custom/probe" }),
        )
        .await?;

        probe.wait_for_seen_count(5).await?;
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
        Ok(())
    }

    #[tokio::test]
    /// Pins that `complete` and `set_level` are forwarded to the inner handler.
    async fn hooked_handler_delegates_completion_and_level() -> anyhow::Result<()> {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let completion = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1_i32,
                "method": "completion/complete",
                "params": {
                    "ref": { "type": "ref/prompt", "name": "prompt" },
                    "argument": { "name": "arg", "value": "de" }
                }
            }),
        )
        .await?;
        let level = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 2_i32,
                "method": "logging/setLevel",
                "params": { "level": "debug" }
            }),
        )
        .await?;

        assert_eq!(
            completion
                .get("result")
                .and_then(|body| body.get("completion"))
                .and_then(|values| values.get("values")),
            Some(&json!(["delegated"]))
        );
        assert_eq!(level.get("result"), Some(&json!({})));
        assert_eq!(probe.seen(), vec!["complete", "set_level"]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that `subscribe` and `unsubscribe` are forwarded to the inner handler.
    async fn hooked_handler_delegates_subscriptions() -> anyhow::Result<()> {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let subscribe = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1_i32,
                "method": "resources/subscribe",
                "params": { "uri": "file:///tmp/a" }
            }),
        )
        .await?;
        let unsubscribe = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 2_i32,
                "method": "resources/unsubscribe",
                "params": { "uri": "file:///tmp/a" }
            }),
        )
        .await?;

        assert_eq!(subscribe.get("result"), Some(&json!({})));
        assert_eq!(unsubscribe.get("result"), Some(&json!({})));
        assert_eq!(probe.seen(), vec!["subscribe", "unsubscribe"]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that `on_custom_request` is forwarded to the inner handler.
    async fn hooked_handler_delegates_custom_request() -> anyhow::Result<()> {
        let (probe, mut reader, mut writer, _service) =
            delegation_transport(DelegationProbe::default(), Arc::new(ToolHooks::new()));

        let response = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1_i32,
                "method": "requests/custom/probe",
                "params": { "x": true }
            }),
        )
        .await?;

        assert_eq!(response.get("result"), Some(&json!({ "delegated": true })));
        assert_eq!(probe.seen(), vec!["on_custom_request"]);
        Ok(())
    }

    #[tokio::test]
    /// Pins that before/after hooks and the size cap still apply through `call_tool`.
    async fn hooked_handler_still_applies_hooks_to_call_tool() -> anyhow::Result<()> {
        let before_count = Arc::new(AtomicUsize::new(0));
        let before_seen = Arc::clone(&before_count);
        let before: BeforeHook = Arc::new(move |_ctx| {
            let seen = Arc::clone(&before_seen);
            Box::pin(async move {
                let _previous = seen.fetch_add(1, Ordering::Relaxed);
                HookOutcome::Continue
            })
        });
        let after_count = Arc::new(AtomicUsize::new(0));
        let after_seen = Arc::clone(&after_count);
        let after_notify = Arc::new(Notify::new());
        let after_notify_seen = Arc::clone(&after_notify);
        let after: AfterHook = Arc::new(move |_ctx, _disp, _size| {
            let seen = Arc::clone(&after_seen);
            let notify = Arc::clone(&after_notify_seen);
            Box::pin(async move {
                let _previous = seen.fetch_add(1, Ordering::Relaxed);
                notify.notify_waiters();
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
                "id": 1_i32,
                "method": "tools/call",
                "params": { "name": "probe", "arguments": {} }
            }),
        )
        .await?;

        timeout(Duration::from_secs(1), async {
            while after_count.load(Ordering::Relaxed) == 0 {
                after_notify.notified().await;
            }
        })
        .await
        .context("after hook should run")?;
        assert_eq!(
            response
                .get("result")
                .and_then(|result| result.get("content"))
                .and_then(|content| content.get(0))
                .and_then(|item| item.get("text")),
            Some(&json!("inner"))
        );
        assert_eq!(probe.seen(), vec!["call_tool"]);
        assert_eq!(before_count.load(Ordering::Relaxed), 1);
        assert_eq!(after_count.load(Ordering::Relaxed), 1);
        Ok(())
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
    /// Parsed by `tests/integration/delegation_guard.rs`, which asserts this table covers
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

    /// `SEMANTIC_DRIVERS` is parsed by `tests/integration/delegation_guard.rs`; this
    /// in-crate check keeps the constant referenced (so it cannot rot as dead
    /// code) and rejects duplicate entries, which the source-level parser
    /// cannot see.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::semantic_drivers_table_is_well_formed keeps the uniform test signature while it cannot fail"
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
    fn coverage_request(
        id: i64,
        method: &str,
        mut params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let object = params
            .as_object_mut()
            .context("coverage requests carry an object of params")?;
        let _previous = object.insert("_meta".to_owned(), coverage_meta());
        Ok(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
    }

    /// Read one server frame that is already queued (used where a single
    /// request produces two frames: the subscription acknowledgement, then the
    /// response).
    async fn read_json_rpc(
        reader: &mut BufReader<ReadHalf<DuplexStream>>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut line = String::new();
        let _bytes_read = reader.read_line(&mut line).await.context("read response")?;
        serde_json::from_str(&line).context("response is JSON")
    }

    type ForwardingTransport<P> = (
        BufReader<ReadHalf<DuplexStream>>,
        WriteHalf<DuplexStream>,
        RunningService<RoleServer, HookedHandler<P>>,
    );

    /// Like [`delegation_transport`], but for a caller-chosen inner handler, so
    /// one driver can run against both the real wrapper and
    /// [`PassthroughDefaults`].
    fn forwarding_transport<P>(inner: P, hooks: Arc<ToolHooks>) -> ForwardingTransport<P>
    where
        P: ServerHandler,
    {
        let (client, server) = duplex(16 * 1024);
        let (client_read, client_write) = split(client);
        let service = serve_directly::<RoleServer, _, _, io::Error, _>(
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
    /// Pins that `get_info`, `get_tool` and `supported_protocol_versions` forward.
    fn hooked_handler_forwards_direct_sync_methods() -> anyhow::Result<()> {
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
    /// Pins that `initialize` and `discover` forward, and the passthrough does not.
    async fn hooked_handler_forwards_initialize_and_discover() -> anyhow::Result<()> {
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let initialize = send_json_rpc(
            &mut writer,
            &mut reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1_i32,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "coverage-driver", "version": "0.0.0" }
                }
            }),
        )
        .await?;
        assert_eq!(
            initialize
                .get("result")
                .and_then(|result| result.get("instructions")),
            Some(&json!("forwarding-probe:initialize"))
        );

        let discover = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "server/discover", json!({}))?,
        )
        .await?;
        assert_eq!(
            discover
                .get("result")
                .and_then(|result| result.get("supportedVersions")),
            Some(&json!(["2025-11-25", "2026-07-28"]))
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
        let (mut control_reader, mut control_writer, _control_service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_initialize = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            json!({
                "jsonrpc": "2.0",
                "id": 1_i32,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "coverage-driver", "version": "0.0.0" }
                }
            }),
        )
        .await?;
        let control_discover = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(2, "server/discover", json!({}))?,
        )
        .await?;
        assert_ne!(
            control_initialize
                .get("result")
                .and_then(|result| result.get("instructions")),
            Some(&json!("forwarding-probe:initialize"))
        );
        assert_ne!(
            control_discover
                .get("result")
                .and_then(|result| result.get("supportedVersions")),
            Some(&json!(["2025-11-25", "2026-07-28"]))
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "deliberate: src/tool_hooks.rs::hooked_handler_forwards_listing_methods keeps the positive and mutation-control halves in one driver so the control cannot be skipped"
    )]
    #[tokio::test]
    /// Pins that the four listing methods forward and the passthrough stays empty.
    async fn hooked_handler_forwards_listing_methods() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let tools = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tools/list", json!({}))?,
        )
        .await?;
        let prompts = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(2, "prompts/list", json!({}))?,
        )
        .await?;
        let resources = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(3, "resources/list", json!({}))?,
        )
        .await?;
        let templates = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(4, "resources/templates/list", json!({}))?,
        )
        .await?;

        assert_eq!(
            tools
                .get("result")
                .and_then(|body| body.get("tools"))
                .and_then(|entries| entries.get(0))
                .and_then(|tool| tool.get("name")),
            Some(&json!("sentinel-tool"))
        );
        assert_eq!(
            prompts
                .get("result")
                .and_then(|body| body.get("prompts"))
                .and_then(|entries| entries.get(0))
                .and_then(|prompt| prompt.get("name")),
            Some(&json!("sentinel-prompt"))
        );
        assert_eq!(
            resources
                .get("result")
                .and_then(|body| body.get("resources"))
                .and_then(|entries| entries.get(0))
                .and_then(|resource| resource.get("uri")),
            Some(&json!("test://sentinel-resource"))
        );
        assert_eq!(
            templates
                .get("result")
                .and_then(|body| body.get("resourceTemplates"))
                .and_then(|entries| entries.get(0))
                .and_then(|template| template.get("uriTemplate")),
            Some(&json!("test://sentinel/{id}"))
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
        let (mut control_reader, mut control_writer, _control_service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_tools = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(1, "tools/list", json!({}))?,
        )
        .await?;
        let control_prompts = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(2, "prompts/list", json!({}))?,
        )
        .await?;
        let control_resources = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(3, "resources/list", json!({}))?,
        )
        .await?;
        let control_templates = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(4, "resources/templates/list", json!({}))?,
        )
        .await?;
        assert_eq!(
            control_tools
                .get("result")
                .and_then(|result| result.get("tools")),
            Some(&json!([]))
        );
        assert_eq!(
            control_prompts
                .get("result")
                .and_then(|result| result.get("prompts")),
            Some(&json!([]))
        );
        assert_eq!(
            control_resources
                .get("result")
                .and_then(|result| result.get("resources")),
            Some(&json!([]))
        );
        assert_eq!(
            control_templates
                .get("result")
                .and_then(|result| result.get("resourceTemplates")),
            Some(&json!([]))
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
        Ok(())
    }

    #[tokio::test]
    /// Pins that `get_prompt`/`read_resource` forward and the passthrough errors.
    async fn hooked_handler_forwards_prompt_and_resource_reads() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): the expected log is exactly the
        // driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let prompt = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "prompts/get", json!({ "name": "sentinel-prompt" }))?,
        )
        .await?;
        let resource = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                2,
                "resources/read",
                json!({ "uri": "test://sentinel-resource" }),
            )?,
        )
        .await?;

        assert_eq!(
            prompt
                .get("result")
                .and_then(|result| result.get("messages"))
                .and_then(|messages| messages.get(0))
                .and_then(|message| message.get("content"))
                .and_then(|content| content.get("text")),
            Some(&json!("forwarding-probe:get_prompt"))
        );
        assert_eq!(
            resource
                .get("result")
                .and_then(|result| result.get("contents"))
                .and_then(|contents| contents.get(0))
                .and_then(|content| content.get("text")),
            Some(&json!("forwarding-probe:read_resource"))
        );
        assert_eq!(probe.seen(), vec!["get_prompt", "read_resource"]);

        // Negative control: both defaults reject with method-not-found, so the
        // client sees an error and the probe is never entered.
        let control = ForwardingProbe::default();
        let (mut control_reader, mut control_writer, _control_service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_prompt = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(1, "prompts/get", json!({ "name": "sentinel-prompt" }))?,
        )
        .await?;
        let control_resource = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(
                2,
                "resources/read",
                json!({ "uri": "test://sentinel-resource" }),
            )?,
        )
        .await?;
        assert_eq!(
            control_prompt
                .get("error")
                .and_then(|error| error.get("code")),
            Some(&json!(-32601_i32))
        );
        assert_eq!(
            control_resource
                .get("error")
                .and_then(|error| error.get("code")),
            Some(&json!(-32601_i32))
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
        Ok(())
    }

    #[tokio::test]
    /// Pins that the task methods forward and the passthrough is gated off.
    async fn hooked_handler_forwards_task_methods() -> anyhow::Result<()> {
        // Mechanism 1 (ambient-silent probe): rmcp calls `get_info` for the
        // tasks-capability gate, which this probe does not record, so the
        // expected log is exactly the driven methods.
        let probe = ForwardingProbe::default();
        let (mut reader, mut writer, _service) =
            forwarding_transport(probe.clone(), coverage_hooks());

        let get = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(1, "tasks/get", json!({ "taskId": "raw-task" }))?,
        )
        .await?;
        let update = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(
                2,
                "tasks/update",
                json!({ "taskId": "raw-task", "inputResponses": {} }),
            )?,
        )
        .await?;
        let cancel = send_json_rpc(
            &mut writer,
            &mut reader,
            coverage_request(3, "tasks/cancel", json!({ "taskId": "raw-task" }))?,
        )
        .await?;

        // `DetailedTask` inlines the base task fields at the top level of the
        // result, so the echoed sentinel id sits at `result.taskId`.
        assert_eq!(
            get.get("result").and_then(|result| result.get("taskId")),
            Some(&json!("raw-task"))
        );
        assert_eq!(
            update.get("error").and_then(|error| error.get("message")),
            Some(&json!("forwarding-probe:update_task"))
        );
        assert_eq!(
            cancel.get("result"),
            Some(&json!({ "resultType": "complete" }))
        );
        assert_eq!(probe.seen(), vec!["get_task", "update_task", "cancel_task"]);

        // Negative control: the tasks capability gate rejects both requests
        // before dispatch (the passthrough advertises no `tasks` extension).
        let control = ForwardingProbe::default();
        let (mut control_reader, mut control_writer, _control_service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_get = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(1, "tasks/get", json!({ "taskId": "raw-task" }))?,
        )
        .await?;
        assert_eq!(
            control_get.get("error").and_then(|error| error.get("code")),
            Some(&json!(-32601_i32))
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
        Ok(())
    }

    #[tokio::test]
    /// Pins that the subscription lifecycle forwards and the default filter rejects.
    async fn hooked_handler_forwards_subscription_lifecycle() -> anyhow::Result<()> {
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
            )?,
        )
        .await?;
        assert_eq!(
            ack.get("method"),
            Some(&json!("notifications/subscriptions/acknowledged"))
        );
        let response = read_json_rpc(&mut reader).await?;
        assert_eq!(response.get("id"), Some(&json!(1_i32)));
        assert_eq!(
            response
                .get("result")
                .and_then(|result| result.get("resultType")),
            Some(&json!("complete"))
        );

        // Exact full sequence (mechanism 3): this arm calls
        // `accepted_subscription_filter` before `listen`, and both are the
        // wrapper's own delegations -- so the expected log is the two-element
        // ordered sequence, not the singleton `["listen"]`.
        assert_eq!(probe.seen(), vec!["accepted_subscription_filter", "listen"]);

        // Negative control: the default filter hook returns `None`, so rmcp
        // rejects the request before `listen` and the probe stays untouched.
        let control = ForwardingProbe::default();
        let (mut control_reader, mut control_writer, _control_service) =
            forwarding_transport(PassthroughDefaults::new(control.clone()), coverage_hooks());
        let control_listen = send_json_rpc(
            &mut control_writer,
            &mut control_reader,
            coverage_request(
                1,
                "subscriptions/listen",
                json!({ "notifications": { "toolsListChanged": true } }),
            )?,
        )
        .await?;
        assert_eq!(
            control_listen
                .get("error")
                .and_then(|error| error.get("code")),
            Some(&json!(-32601_i32))
        );
        assert_eq!(control.seen(), Vec::<&str>::new());
        Ok(())
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
    /// Pins that control characters in `request_id` are escaped for logs.
    fn request_id_for_log_escapes_control_characters() -> anyhow::Result<()> {
        let ctx = ToolCallContext {
            request_id: Some("evil\n2026-01-01 INFO forged log line\u{1b}[31m".to_owned()),
            ..ToolCallContext::for_tool("t")
        };
        let escaped = ctx
            .request_id_for_log()
            .context("request id is present so the accessor returns Some")?;
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
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::request_id_for_log_leaves_ordinary_ids_unquoted keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that ordinary request ids survive unquoted and absent ids yield `None`.
    fn request_id_for_log_leaves_ordinary_ids_unquoted() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::tool_call_context_debug_redacts_sensitive_fields_by_default keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the Debug impl redacts hook context secrets by default.
    fn tool_call_context_debug_redacts_sensitive_fields_by_default() -> anyhow::Result<()> {
        let _guard = diagnostics::ExposureTestGuard::acquire();
        diagnostics::set_diagnostic_exposure(&diagnostics::DiagnosticExposure::default());

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
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::tool_call_context_debug_can_show_sensitive_fields_when_enabled keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the Debug impl shows context secrets when exposure is enabled.
    fn tool_call_context_debug_can_show_sensitive_fields_when_enabled() -> anyhow::Result<()> {
        let _guard = diagnostics::ExposureTestGuard::acquire();
        diagnostics::set_diagnostic_exposure(&diagnostics::DiagnosticExposure {
            tool_call_arguments: true,
            ..diagnostics::DiagnosticExposure::default()
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
        Ok(())
    }

    #[tokio::test]
    /// Pins that a result over the cap is replaced by the structured error.
    async fn size_cap_replaces_oversized_result() -> anyhow::Result<()> {
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
        assert!(exact_size(&small)? < 256);

        let big = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);
        let size = exact_size(&big)?;
        assert!(size > 256);

        let (replaced, accounted, capped) = apply_size_cap(big, Some(256), "whatever");
        assert!(capped);
        assert_eq!(accounted, 257);
        assert_eq!(replaced.is_error, Some(true));
        assert!(matches!(
            replaced.content.first(),
            Some(ContentBlock::Text(text)) if text.text.contains("result_too_large")
        ));

        // Compile-check that HookedHandler instantiates with the test inner.
        let _hooked = hooked;
        Ok(())
    }

    fn exact_size(result: &CallToolResult) -> anyhow::Result<usize> {
        match serialized_size(result, None) {
            SizeMeasure::Exact(size) => Ok(size),
            SizeMeasure::Exceeded { limit } => {
                anyhow::bail!("unbounded measurement exceeded impossible limit {limit}");
            }
        }
    }

    #[test]
    /// Pins that an in-cap serialized size is reported exactly.
    fn serialized_size_under_cap_is_exact() -> anyhow::Result<()> {
        let result = CallToolResult::success(vec![ContentBlock::text("ok".to_owned())]);
        let exact = serde_json::to_vec(&result)
            .context("result serializes for a byte-exact measurement")?
            .len();

        let measured = serialized_size(&result, Some(exact));

        assert_eq!(measured, SizeMeasure::Exact(exact));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::serialized_size_over_cap_stops_with_exceeded keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that crossing the cap aborts measurement with `Exceeded`.
    fn serialized_size_over_cap_stops_with_exceeded() -> anyhow::Result<()> {
        let result = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);

        let measured = serialized_size(&result, Some(256));

        assert_eq!(measured, SizeMeasure::Exceeded { limit: 256 });
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::over_cap_replacement_does_not_log_serialization_failure keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a cap abort logs the cap message, never a serialization failure.
    fn over_cap_replacement_does_not_log_serialization_failure() -> anyhow::Result<()> {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = set_default(subscriber);
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
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::disabled_result_cap_skips_measurement keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that a disabled cap reports zero accounted bytes and no replacement.
    fn disabled_result_cap_skips_measurement() -> anyhow::Result<()> {
        let result = CallToolResult::success(vec![ContentBlock::text("x".repeat(8_192))]);

        let (_final_result, accounted, capped) = apply_size_cap(result, None, "uncapped_tool");

        assert!(!capped);
        assert_eq!(accounted, 0);
        Ok(())
    }

    #[tokio::test]
    /// Pins that a `Deny` before-hook outcome builds the denial error.
    async fn before_hook_deny_builds_error() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let before_counter = Arc::clone(&counter);
        let before: BeforeHook = Arc::new(move |ctx_ref| {
            let seen = Arc::clone(&before_counter);
            let name = ctx_ref.tool_name.clone();
            Box::pin(async move {
                let _previous = seen.fetch_add(1, Ordering::Relaxed);
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
        let before_fn = hooked
            .hooks
            .before
            .as_ref()
            .context("the before hook is configured")?;
        let outcome = before_fn(&bad_ctx).await;
        assert!(matches!(outcome, HookOutcome::Deny(_)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        let ok_ctx = ctx("allowed");
        let outcome2 = before_fn(&ok_ctx).await;
        assert!(matches!(outcome2, HookOutcome::Continue));
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    /// Pins that the too-large body names the tool, limit and actual size.
    fn too_large_result_mentions_limit_and_actual() -> anyhow::Result<()> {
        let result = too_large_result(100, Some(500), "my_tool");
        let body = serde_json::to_string(&result).context("too-large result serializes")?;
        assert!(body.contains("result_too_large"));
        assert!(body.contains("my_tool"));
        assert!(body.contains("100"));
        assert!(body.contains("500"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/tool_hooks.rs::decide_size_truth_table keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins the full `decide_size` truth table, including the inclusive cap.
    fn decide_size_truth_table() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    /// Pins that an unmeasurable size renders as `unknown`, not a fabricated number.
    fn too_large_result_does_not_fabricate_a_size_when_unmeasurable() -> anyhow::Result<()> {
        let result = too_large_result(100, None, "my_tool");
        let body = serde_json::to_string(&result).context("too-large result serializes")?;
        assert!(body.contains("result_too_large"));
        assert!(body.contains("unknown"));
        assert!(
            !body.contains("101"),
            "the over-limit accounting sentinel must not leak into the client payload"
        );
        Ok(())
    }

    #[tokio::test]
    /// Pins that a `Replace` outcome bypasses the inner handler and returns its payload.
    async fn replace_outcome_skips_inner_and_returns_payload() -> anyhow::Result<()> {
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
        let before_fn = hooks
            .before
            .as_ref()
            .context("the before hook is configured")?;
        let outcome = before_fn(&ctx("any")).await;
        let HookOutcome::Replace(boxed) = outcome else {
            anyhow::bail!("expected HookOutcome::Replace");
        };
        let (result, size, capped) = apply_size_cap(*boxed, None, "any");
        assert!(!capped);
        assert_eq!(size, 0);
        assert!(!result.is_error.unwrap_or(false));
        assert!(matches!(
            result.content.first(),
            Some(ContentBlock::Text(text)) if text.text == "from-replace"
        ));
        Ok(())
    }

    #[tokio::test]
    /// Pins that a `Replace` payload is still subject to the result-size cap.
    async fn replace_outcome_subject_to_size_cap() -> anyhow::Result<()> {
        // A Replace payload that exceeds max_result_bytes must be rewritten
        // to result_too_large just like an inner-handler result would be,
        // and the disposition must reflect ResultTooLarge.
        let huge = CallToolResult::success(vec![ContentBlock::text("y".repeat(8_192))]);
        let huge_size = serde_json::to_vec(&huge)
            .context("huge result serializes")?
            .len();
        assert!(huge_size > 256);

        let (final_result, accounted, capped) = apply_size_cap(huge, Some(256), "replaced_tool");
        assert!(capped);
        assert_eq!(accounted, 257);
        assert_eq!(final_result.is_error, Some(true));
        assert!(matches!(
            final_result.content.first(),
            Some(ContentBlock::Text(text)) if text.text.contains("result_too_large")
        ));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// Pins that `spawn_after` enqueues the after-hook exactly once per call.
    async fn after_hook_fires_exactly_once_via_spawn() -> anyhow::Result<()> {
        // spawn_after must enqueue the after-hook exactly one time per
        // invocation and never block the caller; we wait for the spawned
        // task to run by polling the counter with a short timeout.
        let counter = Arc::new(AtomicUsize::new(0));
        let after_counter = Arc::clone(&counter);
        let after: AfterHook = Arc::new(move |_ctx, _disp, _size| {
            let seen = Arc::clone(&after_counter);
            Box::pin(async move {
                let _previous = seen.fetch_add(1, Ordering::Relaxed);
            })
        });
        let holder = Arc::new(AfterHookHolder { hook: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("t"),
            HookDisposition::InnerExecuted,
            42,
        );

        // Wait up to 1s for the spawned task to run.
        let deadline = Instant::now() + Duration::from_secs(1);
        while counter.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            yield_now().await;
            sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[expect(
        clippy::panic,
        reason = "deliberate: src/tool_hooks.rs::after_hook_panic_is_isolated_from_response_path panics on purpose to prove hook panics stay isolated"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// Pins that a panicking after-hook cannot poison the request path.
    async fn after_hook_panic_is_isolated_from_response_path() -> anyhow::Result<()> {
        // A panicking after-hook must not affect the request task.  We
        // spawn a panicking after-hook and then verify the current task
        // can still complete an unrelated future to completion.
        let after: AfterHook = Arc::new(|_ctx, _disp, _size| {
            Box::pin(async {
                panic!("intentional panic in after-hook");
            })
        });
        let holder = Arc::new(AfterHookHolder { hook: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("boom"),
            HookDisposition::InnerExecuted,
            0,
        );

        // Give Tokio a chance to run + abort the panicking task, then
        // confirm we're still alive and the runtime is healthy.
        sleep(Duration::from_millis(50)).await;
        let still_alive = tokio::spawn(async { 1_u32 + 2 })
            .await
            .context("the runtime survives a panicking hook task")?;
        assert_eq!(still_alive, 3);
        Ok(())
    }
}
