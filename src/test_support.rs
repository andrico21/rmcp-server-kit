//! Test-only helpers shared by the unit tests of this crate.
//!
//! The one helper is [`isolate`], which re-runs a single test in a fresh
//! process so a log-capture assertion cannot be hit by tracing callsite
//! interest cached from another test's thread.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::{
    env,
    fs::{self, OpenOptions},
    path::PathBuf,
    process::{self, Command, Stdio},
    thread,
};

use anyhow::Context as _;

/// Env var that marks an isolated child; its value is the sentinel path the
/// child writes `started` to.
const ISOLATE_SENTINEL_ENV: &str = "RMCP_SERVER_KIT_ISOLATE_SENTINEL";

/// Per-process sequence that keeps sentinel paths unique.
static ISOLATE_SENTINEL_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Where [`isolate`] left the calling test.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Isolation {
    /// This process is the isolated child: run the test body.
    Child,
    /// The isolated child already ran the body and succeeded: return from the
    /// test without running it again.
    ParentDone,
}

/// Re-runs the calling test alone in a fresh process, so its body cannot see
/// tracing callsite interest cached by a parallel test.
///
/// The reason: a parallel test that reaches the same `tracing` callsite on a
/// thread with no subscriber can cache `Interest::never` for it (tracing-core's
/// single-dispatcher fast path), and a later test whose scoped capture
/// subscriber is installed on another thread then records nothing. A fresh
/// process that runs only the one test has no such thread.
///
/// Call it as the FIRST statement of the test, with the exact libtest name of
/// that test (the path the test appears under in `cargo test -- --list`), and
/// return early on [`Isolation::ParentDone`]:
///
/// ```ignore
/// if isolate("module::tests::the_test")? == Isolation::ParentDone {
///     return Ok(());
/// }
/// // the original body follows unchanged
/// ```
///
/// In the parent this spawns the current executable with
/// `<name> --exact --test-threads=1 --nocapture`, waits for it, and fails
/// unless the child exited successfully AND wrote its `started` sentinel (an
/// `--exact` filter that matches no test exits 0 without running anything).
/// In the child it writes the sentinel and returns [`Isolation::Child`].
///
/// The parent blocks on the child inside the test. That is a deliberate
/// exception to the rule against blocking I/O in async code: the child needs
/// nothing from the parent runtime. It is valid only on the default
/// current-thread `#[tokio::test]` flavor and as the first statement, before
/// any task is spawned; `block_in_place` would panic there and must not be
/// used.
///
/// # Errors
///
/// Returns an error when `exact_test_name` is not the name of the calling
/// test, when the sentinel or the child cannot be set up, or when the child
/// fails or never started.
pub(crate) fn isolate(exact_test_name: &str) -> anyhow::Result<Isolation> {
    // libtest names the test thread with the `--exact` string, so a name that
    // points at another test would pass without running the caller's body.
    // With no thread name, or when libtest ran the test on the main thread
    // (it does so when it cannot create a thread), there is nothing to check.
    let current = thread::current();
    if let Some(actual) = current.name()
        && actual != "main"
    {
        anyhow::ensure!(
            actual == exact_test_name,
            "isolate({exact_test_name:?}) was called from test thread {actual:?}"
        );
    }
    if let Some(sentinel) = env::var_os(ISOLATE_SENTINEL_ENV) {
        fs::write(&sentinel, "started")
            .with_context(|| format!("write sentinel {}", sentinel.to_string_lossy()))?;
        return Ok(Isolation::Child);
    }
    let path = env::temp_dir().join(format!(
        "rmcp-server-kit-isolate-{}-{}",
        process::id(),
        ISOLATE_SENTINEL_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    drop(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("reserve sentinel {}", path.display()))?,
    );
    let sentinel = SentinelFile(path);
    let output = Command::new(env::current_exe()?)
        .args([
            exact_test_name,
            "--exact",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ISOLATE_SENTINEL_ENV, &sentinel.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()?;
    let marker = fs::read_to_string(&sentinel.0)?;
    let child_state = if marker == "started" {
        "started"
    } else {
        "child never started"
    };
    anyhow::ensure!(
        output.status.success() && marker == "started",
        "isolated child failed: status={}, sentinel={child_state}, stdout={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(Isolation::ParentDone)
}

/// Sentinel path removed on drop, so success, failure and early return all
/// clean it up. It is created only by the parent that reserved the path.
struct SentinelFile(PathBuf);

// Drop audit: non-blocking, sync `fs::remove_file`; a failure is logged, never panics.
impl Drop for SentinelFile {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            tracing::warn!(path = %self.0.display(), %error, "sentinel cleanup failed");
        }
    }
}
