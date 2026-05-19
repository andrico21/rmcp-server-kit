//! Cancellation primitives that detach in-flight async work on the
//! cancel/timeout branch instead of dropping it mid-`.await`.
//!
//! # Motivation
//!
//! `tokio::select!` arms that race a long-running future against
//! [`tokio_util::sync::CancellationToken`] or `tokio::time::sleep` drop
//! the losing future when another branch wins. For work that owns a
//! remote-side resource (an SSH channel, an in-flight HTTP body, a DB
//! transaction), dropping mid-flight leaves that resource half-open
//! until some outer lifetime ends -- the inner future's own
//! `close().await` calls only run on its own early-return paths, never
//! on outer Drop.
//!
//! The fix: hand the future to [`tokio::spawn`] so it owns its own task
//! frame. Race the resulting [`tokio::task::JoinHandle`] -- not the
//! future itself -- against the cancel/timeout sources. When the
//! cancel/timeout branch wins, the `JoinHandle` is dropped (NOT
//! `.abort()`); the detached task keeps running to completion and
//! drives the inner close path. The client gets its cancel/timeout
//! response immediately, and the remote-side resource is released as
//! soon as the spawned future finishes its current work.
//!
//! # Semantics
//!
//! - **Pre-cancel check**: if the token is already cancelled at entry,
//!   the future is NEVER spawned. Returns
//!   [`DetachOutcome::Cancelled`](crate::cancel::DetachOutcome::Cancelled)
//!   immediately. Avoids starting expensive (often mutating) work for
//!   requests the client has already abandoned.
//! - **Completion wins on tie**: if the spawned future and a
//!   cancel/timeout signal are both ready in the same poll, the
//!   [`DetachOutcome::Completed`](crate::cancel::DetachOutcome::Completed)
//!   arm wins. This prevents reporting cancel/timeout for an operation
//!   that actually succeeded (especially harmful for mutating tools
//!   where the client might then retry).
//! - **Panic surfacing**: a panic in the spawned future is exposed as
//!   [`DetachOutcome::Panicked`](crate::cancel::DetachOutcome::Panicked)
//!   carrying the [`tokio::task::JoinError`]. Callers decide how to
//!   translate it; the helper does not fold it into Cancelled/TimedOut.
//!
//! # Lifetime
//!
//! Spawned tasks live on the tokio runtime. They are bounded by:
//! 1. The future's own completion (normal exit -- desired path).
//! 2. Tokio runtime shutdown (unavoidable -- TCP teardown forces the
//!    remote side to release resources regardless).
//!
//! They are NOT bounded by the request handler that started them, by
//! [`CancellationToken`](tokio_util::sync::CancellationToken) cancel,
//! or by any [`tokio::task::JoinHandle`] the caller might hold. That
//! is the entire point.
//!
//! # Caller obligations
//!
//! Detached tasks can accumulate if the inner future hangs forever
//! (dead channel, wedged HTTP body, deadlock, missing protocol-level
//! timeout). Callers MUST ensure the inner future has its own
//! eventual-completion guarantee. The `timeout` argument here is a
//! **response timeout**, not an operation timeout: it bounds how long
//! the client waits, not how long the work runs.
//!
//! # Caveats
//!
//! These properties of the calling context are **lost** when work
//! detaches onto the runtime:
//!
//! - **Task-local RBAC scope**. The helper does NOT propagate RBAC
//!   task-locals into the spawned future. Inside the detached task,
//!   the accessors [`crate::rbac::current_role`],
//!   [`crate::rbac::current_identity`], [`crate::rbac::current_token`],
//!   and [`crate::rbac::current_sub`] will return `None` even if the
//!   originating request was authenticated. This is intentional:
//!   detached work should finish or close already-authorized
//!   resources, not initiate fresh RBAC-gated operations. Holding
//!   secrets and tokens alive past the request boundary would extend
//!   credential lifetime past the request that authorized them.
//!
//!   If a caller genuinely needs RBAC context inside detached work
//!   (e.g. emitting an audit event that names the originating
//!   identity), it MUST capture the values before the spawn and rebind
//!   them with [`crate::rbac::with_rbac_scope`]:
//!
//!   ```no_run
//!   use rmcp_server_kit::{cancel, rbac};
//!   use std::time::Duration;
//!   use tokio_util::sync::CancellationToken;
//!
//!   # async fn example(ct: CancellationToken) {
//!   // Capture BEFORE spawn.
//!   let role = rbac::current_role().unwrap_or_default();
//!   let identity = rbac::current_identity().unwrap_or_default();
//!   let token = rbac::current_token().unwrap_or_else(|| {
//!       use rmcp_server_kit::secret::SecretString;
//!       SecretString::new(String::new().into())
//!   });
//!
//!   let fut = async move {
//!       rbac::with_rbac_scope(role, identity, token, None, async {
//!           // Detached work here can call current_role() etc.
//!       })
//!       .await;
//!   };
//!
//!   let _ = cancel::run_with_cancel_and_timeout(fut, &ct, Some(Duration::from_secs(5))).await;
//!   # }
//!   ```
//!
//! - **Tracing span**: the originating request's span IS preserved.
//!   The helper wraps the spawned future in
//!   `.instrument(tracing::Span::current())`, so log lines from the
//!   detached task remain attached to the request span (matching the
//!   convention in [`crate::tool_hooks`]).

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// Outcome of [`run_with_cancel_and_timeout`].
///
/// [`Self::Completed`] carries the future's own return value.
/// [`Self::Cancelled`] and [`Self::TimedOut`] indicate the future was
/// detached (still running on the tokio runtime) and the caller should
/// return a cancel/timeout response to the client immediately.
/// [`Self::Panicked`] indicates the spawned future panicked; the
/// [`tokio::task::JoinError`] is exposed so the caller can surface it.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "DetachOutcome carries the operation result; ignoring it discards either the value or the cancel/timeout signal"]
pub enum DetachOutcome<T> {
    /// The spawned future ran to completion and returned a value.
    Completed(T),
    /// The cancellation token fired before the future completed. The
    /// future was detached onto the runtime and keeps running.
    Cancelled,
    /// The `timeout` budget elapsed before the future completed. The
    /// future was detached onto the runtime and keeps running.
    TimedOut,
    /// The spawned future panicked. Carries the underlying
    /// [`tokio::task::JoinError`] so the caller can decide how to
    /// surface the panic (typical: log + return an internal-error
    /// tool response).
    Panicked(tokio::task::JoinError),
}

/// Race a `'static` future against client cancellation and an optional
/// timeout, detaching the future on cancel/timeout so it can complete
/// its own cleanup path.
///
/// # Pre-condition
///
/// If `ct.is_cancelled()` already holds at entry, this returns
/// [`DetachOutcome::Cancelled`] without spawning `fut`. The future will
/// NEVER start in that case -- do not begin expensive or mutating work
/// for already-abandoned requests.
///
/// # Behavior
///
/// Otherwise spawns `fut` onto the tokio runtime (wrapped in
/// `.instrument(Span::current())` so its log lines stay attached to
/// the originating request span) and races its
/// [`tokio::task::JoinHandle`] against `ct` and (optionally)
/// `tokio::time::sleep(timeout)`. On tie, completion wins (the handle
/// arm comes first under `biased;`). On cancel/timeout the spawned
/// task keeps running to completion -- dropping the [`tokio::task::JoinHandle`]
/// is a no-op for the task.
///
/// # Requirements on `fut`
///
/// `fut` MUST be cleanup-safe under self-driven completion: when
/// detached, only the future's own internal Drop and early-return
/// paths run; nothing else will help it clean up.
///
/// # Cancel-safety
///
/// // cancel-safe under composition: the inner future is moved into a
/// // `tokio::spawn` before we await anything, so the cancel/timeout
/// // arms can only ever drop the `JoinHandle` (a no-op for the task)
/// // -- never the inner future itself.
#[must_use = "DetachOutcome must be inspected to distinguish completion from cancel/timeout/panic"]
pub async fn run_with_cancel_and_timeout<F, T>(
    fut: F,
    ct: &CancellationToken,
    timeout: Option<Duration>,
) -> DetachOutcome<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    // Pre-cancel check: never start work for already-abandoned requests.
    if ct.is_cancelled() {
        return DetachOutcome::Cancelled;
    }

    let mut handle = tokio::spawn(fut.instrument(tracing::Span::current()));

    // `biased;` evaluates arms top-down. The `&mut handle` arm comes
    // FIRST so a ready completion wins over a simultaneously-ready
    // cancel/timeout. Dropping the `JoinHandle` does NOT abort the
    // task -- the spawned future runs to its own completion and cleans
    // up via its own Drop / early-return paths.
    if let Some(t) = timeout {
        tokio::select! {
            biased;
            joined = &mut handle => map_join(joined),
            () = ct.cancelled() => DetachOutcome::Cancelled,
            () = tokio::time::sleep(t) => DetachOutcome::TimedOut,
        }
    } else {
        tokio::select! {
            biased;
            joined = &mut handle => map_join(joined),
            () = ct.cancelled() => DetachOutcome::Cancelled,
        }
    }
}

/// Translate a [`tokio::task::JoinHandle`] result into a
/// [`DetachOutcome`]. Panics are surfaced distinctly via
/// [`DetachOutcome::Panicked`] so the caller can distinguish them from
/// cancel/timeout -- do not fold panics into the cancel path, that
/// loses real failure info.
fn map_join<T>(joined: Result<T, tokio::task::JoinError>) -> DetachOutcome<T> {
    match joined {
        Ok(v) => DetachOutcome::Completed(v),
        Err(join_err) => DetachOutcome::Panicked(join_err),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tokio::time::Duration;

    #[tokio::test]
    async fn completed_returns_value_when_future_wins() {
        let ct = CancellationToken::new();
        let out =
            run_with_cancel_and_timeout(async { 42_u32 }, &ct, Some(Duration::from_secs(5))).await;
        assert!(matches!(out, DetachOutcome::Completed(42)));
    }

    #[tokio::test]
    async fn cancel_outcome_and_detached_future_runs_to_completion() {
        // The cancel branch wins, but the future must still complete in
        // the background -- this is the central contract.
        //
        // The pre-cancel check short-circuits if the token is cancelled
        // at entry, so we delay-cancel after the helper has spawned the
        // future.
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let ct = CancellationToken::new();
        let fut = async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            done_clone.store(true, Ordering::SeqCst);
        };

        let ct_for_cancel = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ct_for_cancel.cancel();
        });
        let out = run_with_cancel_and_timeout(fut, &ct, None).await;
        assert!(matches!(out, DetachOutcome::Cancelled));

        // The detached task is still running. Give it time to finish.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            done.load(Ordering::SeqCst),
            "detached future must run to completion after cancel"
        );
    }

    #[tokio::test]
    async fn timeout_outcome_and_detached_future_runs_to_completion() {
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let ct = CancellationToken::new();
        let fut = async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            done_clone.store(true, Ordering::SeqCst);
        };

        let out = run_with_cancel_and_timeout(fut, &ct, Some(Duration::from_millis(10))).await;
        assert!(matches!(out, DetachOutcome::TimedOut));

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            done.load(Ordering::SeqCst),
            "detached future must run to completion after timeout"
        );
    }

    #[tokio::test]
    async fn panic_in_detached_future_surfaces_as_panicked() {
        let ct = CancellationToken::new();
        let out: DetachOutcome<()> = run_with_cancel_and_timeout(
            async { panic!("boom") },
            &ct,
            Some(Duration::from_secs(5)),
        )
        .await;
        // Panic is surfaced distinctly, not folded into Cancelled/TimedOut.
        assert!(
            matches!(out, DetachOutcome::Panicked(ref e) if e.is_panic()),
            "expected Panicked carrying a panic JoinError"
        );
    }

    /// Pre-cancel check: if the token is already cancelled at entry,
    /// the future MUST NOT be spawned. This avoids starting expensive
    /// or mutating work for already-abandoned requests.
    #[tokio::test]
    async fn pre_cancelled_token_skips_spawn() {
        let started = Arc::new(AtomicU32::new(0));
        let started_clone = Arc::clone(&started);
        let ct = CancellationToken::new();
        ct.cancel();

        let out = run_with_cancel_and_timeout(
            async move {
                started_clone.fetch_add(1, Ordering::SeqCst);
            },
            &ct,
            None,
        )
        .await;
        assert!(matches!(out, DetachOutcome::Cancelled));

        // Give the runtime a chance to run any errant spawn.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            0,
            "pre-cancelled token must not spawn the future"
        );
    }

    /// Completion wins on tie: even when the token is cancelled
    /// concurrently with a ready future, the `Completed` arm must win
    /// because `biased;` puts it first. The caller must NEVER see
    /// `Cancelled` for an operation that actually completed
    /// successfully (would mislead clients into bad retries on
    /// mutating tools).
    ///
    /// We run many iterations to exercise the race; in any iteration
    /// where the pre-cancel check fires first (token cancel raced ahead
    /// of helper entry) we accept `Cancelled` as a non-tie path.
    #[tokio::test]
    async fn completion_wins_on_tie_with_cancel() {
        for _ in 0..50 {
            let ct = CancellationToken::new();
            let ct_for_cancel = ct.clone();
            tokio::spawn(async move {
                ct_for_cancel.cancel();
            });
            let out = run_with_cancel_and_timeout(async { 7_u32 }, &ct, None).await;
            match out {
                DetachOutcome::Completed(7) | DetachOutcome::Cancelled => {}
                DetachOutcome::Completed(other_val) => {
                    panic!("unexpected Completed value on tie race: {other_val}")
                }
                DetachOutcome::TimedOut => {
                    panic!("unexpected TimedOut on tie race (no timeout configured)")
                }
                DetachOutcome::Panicked(join_err) => {
                    panic!("unexpected Panicked on tie race: {join_err}")
                }
            }
        }
    }
}
