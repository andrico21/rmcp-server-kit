extern crate alloc;

use alloc::sync::Arc;
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use std::{
    fs,
    io::{self, Write as _},
    path::Path,
    sync::{
        Mutex, OnceLock,
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

use tracing_subscriber::{
    EnvFilter, Layer as _,
    filter::LevelFilter,
    fmt::{MakeWriter, format::Writer, layer, time::FormatTime},
    layer::SubscriberExt as _,
    registry::LookupSpan,
    util::{SubscriberInitExt as _, TryInitError},
};

use crate::{
    config::ObservabilityConfig,
    diagnostics::{
        DiagnosticExposure, oauth_claim_values, plaintext_oauth_tokens, set_diagnostic_exposure,
        tool_call_arguments,
    },
    error::RmcpServerKitError,
};

/// Capacity of the bounded audit-log channel; overflow drops newest entries.
const AUDIT_LOG_CHANNEL_CAPACITY: usize = 1024;
/// How long the audit writer thread blocks waiting for the next message.
const AUDIT_WRITER_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Maximum time `Drop` waits for the audit writer thread to finish.
const AUDIT_WRITER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Park interval used while polling for the audit writer thread to finish.
const AUDIT_WRITER_JOIN_POLL: Duration = Duration::from_millis(10);
/// Minimum spacing between repeated audit I/O failure warnings on stderr.
const AUDIT_IO_FAILURE_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Timestamp formatter that emits local time via `chrono::Local`.
#[derive(Clone, Copy)]
struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        write!(
            w,
            "{}",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        )
    }
}

/// Initialize structured logging from an [`ObservabilityConfig`].
///
/// Deprecated compatibility entry point. Prefer
/// [`init_tracing_from_config_strict`], which returns a [`TracingGuard`] and
/// fails closed when `audit_log_path` is configured but cannot be opened.
///
/// Respects `RUST_LOG` env var if set; otherwise uses `config.log_level`.
/// When `log_format` is `"json"`, emits machine-readable JSON lines.
/// When `audit_log_path` is set, appends an additional JSON log file
/// at INFO level for audit trail purposes. This legacy function keeps its
/// fail-open behaviour for source compatibility: a failure to prepare the
/// audit sink is logged as a warning after subscriber initialization
/// succeeds, rather than failing this call. "Fail open" applies only to the
/// overall call, never to the audit sink itself: when the configured path
/// cannot be hardened to an owner-only regular file, no audit writer is
/// installed at all, on any platform, rather than writing audit events to
/// an unprotected or attacker-controlled target. On Unix this includes a
/// regular file with more than one hard link. On Windows this includes a
/// reparse point at the final path component (a symbolic link, junction,
/// mount point, or any other reparse tag).
///
/// # Errors
///
/// Returns [`TryInitError`] if a global tracing subscriber has already
/// been installed (e.g. by a previous call to this function or
/// [`init_tracing`]). Callers that want to tolerate double-initialization
/// (such as test harnesses) can ignore the error.
#[deprecated(
    since = "3.8.0",
    note = "use `init_tracing_from_config_strict` and hold the returned `TracingGuard` for process lifetime"
)]
#[inline]
pub fn init_tracing_from_config(config: &ObservabilityConfig) -> Result<(), TryInitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let audit_setup = prepare_tracing_audit_lenient(config);

    // "pretty" and "text" are aliases for human-readable output.
    let result = if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(layer().json().with_timer(LocalTime).with_writer(io::stderr));
        init_with_optional_audit(subscriber, audit_setup.writer)
    } else {
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(layer().with_timer(LocalTime).with_writer(io::stderr));
        init_with_optional_audit(subscriber, audit_setup.writer)
    };

    if result.is_ok() {
        retain_legacy_guard(audit_setup.guard);
        for warning in audit_setup.warnings {
            tracing::warn!(warning = %warning, "audit logging initialization warning");
        }
    }

    result
}

/// Owns background resources installed by strict tracing initialization.
///
/// Hold this guard for the lifetime of the process. When an audit log is
/// configured, the guard owns the dedicated audit writer thread's shutdown
/// signal and join handle. Dropping it signals shutdown and makes a best-effort,
/// time-bounded (5s) attempt to drain queued audit entries, flush the file, and
/// join the writer thread. This is not a durability guarantee: audit events
/// emitted after drop are lost, and if the writer thread is blocked on a slow or
/// stuck filesystem past the timeout, `Drop` returns and remaining queued entries
/// may never reach disk.
#[must_use = "hold TracingGuard for the process lifetime so audit logs keep draining"]
#[non_exhaustive]
pub struct TracingGuard {
    /// Audit writer guard, present only when an audit log is configured.
    audit: Option<AuditWorkerGuard>,
}

impl fmt::Debug for TracingGuard {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracingGuard")
            .field("audit_enabled", &self.audit.is_some())
            .field(
                "diagnostic_plaintext_oauth_tokens",
                &plaintext_oauth_tokens(),
            )
            .field("diagnostic_oauth_claim_values", &oauth_claim_values())
            .field("diagnostic_tool_call_arguments", &tool_call_arguments())
            .finish()
    }
}

impl TracingGuard {
    /// Build a guard with no audit writer attached.
    const fn none() -> Self {
        Self { audit: None }
    }

    /// Wrap an audit writer guard so `Drop` drains it.
    const fn audit(audit: AuditWorkerGuard) -> Self {
        Self { audit: Some(audit) }
    }
}

// Takes the `Option<AuditWorkerGuard>`, delegating cleanup to that guard's
// bounded drain; sync teardown blocks at most `AUDIT_WRITER_JOIN_TIMEOUT`
// (5s) by design, as documented on the type.
// Drop audit (2026-10-04): no I/O or await here, no panic path.
impl Drop for TracingGuard {
    #[inline]
    #[expect(
        let_underscore_drop,
        reason = "deliberate: src/observability.rs::TracingGuard drops the audit guard in place to run its bounded teardown"
    )]
    fn drop(&mut self) {
        let _: Option<AuditWorkerGuard> = self.audit.take();
    }
}

/// Initialize structured logging from an [`ObservabilityConfig`] and fail
/// closed when the configured audit log cannot be opened.
///
/// Respects `RUST_LOG` env var if set; otherwise uses `config.log_level`.
/// When `log_format` is `"json"`, emits machine-readable JSON lines. When
/// `audit_log_path` is set, appends an additional JSON log file at INFO level
/// through a bounded non-blocking channel drained by a dedicated writer thread.
///
/// Hold the returned [`TracingGuard`] for the process lifetime. Dropping it
/// signals the audit writer to stop and makes a best-effort, time-bounded (5s)
/// drain/flush attempt; audit events emitted after drop are lost, and a writer
/// blocked past the timeout may leave queued entries unwritten.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] if audit-log directory creation,
/// audit-log opening, audit writer thread spawning, or global tracing
/// subscriber installation fails. On Unix, opening the audit log also fails
/// this way when the configured path is a symlink at its final component,
/// is not a regular file (a device, FIFO, or socket), is a pre-existing
/// file not owned by this process's effective user, has more than one hard
/// link, or its permissions cannot be corrected to `0o600` and are not
/// already exactly `0o600`. On Windows, opening the audit log also fails
/// this way when the configured path is a reparse point at its final
/// component (a symbolic link, junction, mount point, or any other reparse
/// tag) - checked both before the open and again on the opened handle - or
/// when applying the owner-only DACL fails. See the "Audit-log file
/// permissions" section of the guide for the full contract.
#[inline]
pub fn init_tracing_from_config_strict(
    config: &ObservabilityConfig,
) -> Result<TracingGuard, RmcpServerKitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    let audit_setup = prepare_tracing_audit_strict(config)?;

    // "pretty" and "text" are aliases for human-readable output.
    let result = if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(layer().json().with_timer(LocalTime).with_writer(io::stderr));
        init_with_optional_audit(subscriber, audit_setup.writer)
    } else {
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(layer().with_timer(LocalTime).with_writer(io::stderr));
        init_with_optional_audit(subscriber, audit_setup.writer)
    };

    result.map_err(|error| {
        RmcpServerKitError::Startup(format!("failed to initialize tracing subscriber: {error}"))
    })?;

    // SECURITY: arm the process-global plaintext diagnostic switches only
    // AFTER every fallible step has succeeded. Setting them first meant a
    // failed strict init returned `Err` with secret logging left enabled
    // process-wide, so an embedder that ignored the error (or fell back to
    // the deprecated lenient initializer) would log tokens and claims.
    set_diagnostic_exposure(&DiagnosticExposure {
        plaintext_oauth_tokens: config.log_plaintext_oauth_tokens,
        oauth_claim_values: config.log_oauth_claim_values,
        tool_call_arguments: config.log_tool_call_arguments,
        upstream_error_bodies: config.log_upstream_error_bodies,
    });

    for warning in audit_setup.warnings {
        tracing::warn!(warning = %warning, "audit logging initialization warning");
    }

    Ok(audit_setup.guard)
}

/// Attach an optional audit JSON log layer and initialize the subscriber.
///
/// Extracted to avoid duplicating the audit layer construction in both
/// the JSON and pretty format branches of strict and legacy initialization.
///
/// Uses [`SubscriberInitExt::try_init`] so that a previously-installed
/// global subscriber yields [`TryInitError`] rather than panicking.
///
/// # Errors
///
/// Returns [`TryInitError`] when a global tracing subscriber is already
/// installed.
fn init_with_optional_audit<S>(
    subscriber: S,
    audit_writer: Option<AuditFile>,
) -> Result<(), TryInitError>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static,
{
    if let Some(writer) = audit_writer {
        subscriber
            .with(
                layer()
                    .json()
                    .with_timer(LocalTime)
                    .with_writer(writer)
                    .with_filter(LevelFilter::INFO),
            )
            .try_init()
    } else {
        subscriber.try_init()
    }
}

/// Initialize structured logging with a simple filter string.
///
/// Convenience function for callers that don't use [`ObservabilityConfig`].
/// Respects `RUST_LOG` env var. Falls back to `default_filter` (e.g. `"info"`).
///
/// # Errors
///
/// Returns [`TryInitError`] if a global tracing subscriber has already
/// been installed. This makes the function safe to call repeatedly from
/// tests or embedders without panicking.
#[inline]
pub fn init_tracing(default_filter: &str) -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)))
        .with(layer().with_timer(LocalTime).with_writer(io::stderr))
        .try_init()
}

/// Newtype wrapper around a non-blocking audit writer channel.
///
/// Implements `MakeWriter` so it can be used with `tracing_subscriber::fmt`.
#[derive(Clone)]
struct AuditFile {
    /// Handle to the bounded channel the background writer drains.
    sender: SyncSender<AuditMessage>,
    /// Shared count of entries dropped when the channel was full.
    dropped: Arc<AtomicU64>,
}

impl<'writer> MakeWriter<'writer> for AuditFile {
    type Writer = AuditFileWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        AuditFileWriter {
            sender: self.sender.clone(),
            dropped: Arc::clone(&self.dropped),
        }
    }
}

/// A non-blocking audit writer handle used directly at tracing call sites.
struct AuditFileWriter {
    /// Handle to the bounded channel the background writer drains.
    sender: SyncSender<AuditMessage>,
    /// Shared count of entries dropped when the channel was full.
    dropped: Arc<AtomicU64>,
}

impl io::Write for AuditFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Overflow policy: drop-newest when the bounded channel is full and
        // account for the loss in an atomic counter. Blocking here would put
        // request-handling tokio workers back on the slow/full disk path this
        // writer exists to remove. The background writer emits the aggregate
        // dropped count into the audit log once it catches up.
        if matches!(
            self.sender.try_send(AuditMessage::Write(buf.to_vec())),
            Err(TrySendError::Full(_))
        ) {
            let _previous = self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    #[expect(clippy::let_underscore_must_use, reason = "audit writer must not log")]
    #[expect(
        let_underscore_drop,
        reason = "deliberate: src/observability.rs::AuditFileWriter::flush drops the full-channel send result without logging"
    )]
    fn flush(&mut self) -> io::Result<()> {
        let _: Result<(), TrySendError<AuditMessage>> = self.sender.try_send(AuditMessage::Flush);
        Ok(())
    }
}

/// Message sent from the tracing writer layer to the audit writer thread.
enum AuditMessage {
    /// Raw bytes to append to the audit log.
    Write(Vec<u8>),
    /// Request to flush buffered audit output.
    Flush,
}

/// Shutdown and join handle for the dedicated audit writer thread.
struct AuditWorkerGuard {
    /// Set to true to ask the writer thread to stop.
    shutdown: Arc<AtomicBool>,
    /// Non-blocking wake channel used to nudge the writer thread.
    wake_sender: SyncSender<AuditMessage>,
    /// Join handle for the writer thread, taken on drop.
    thread: Option<JoinHandle<()>>,
}

// Signals shutdown (atomic store plus non-blocking `try_send`), then parks and
// joins the writer thread for at most `AUDIT_WRITER_JOIN_TIMEOUT` (5s). The
// bounded blocking join is deliberate: a last-chance drain that cannot stall a
// request worker past the timeout; every fallible return is handled/discarded.
// Drop audit (2026-10-04): no async work, no panic path; cleanup order fixed.
impl Drop for AuditWorkerGuard {
    #[expect(clippy::let_underscore_must_use, reason = "audit writer must not log")]
    #[expect(
        let_underscore_drop,
        reason = "deliberate: src/observability.rs::AuditWorkerGuard::drop drops the flush and join results in place"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "invariant: src/observability.rs::AuditWorkerGuard::drop - the deadline arithmetic is bounded by AUDIT_WRITER_JOIN_TIMEOUT and cannot overflow within the process lifetime"
    )]
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _: Result<(), TrySendError<AuditMessage>> =
            self.wake_sender.try_send(AuditMessage::Flush);

        let Some(thread) = self.thread.take() else {
            return;
        };
        let deadline = Instant::now() + AUDIT_WRITER_JOIN_TIMEOUT;
        while !thread.is_finished() {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            thread::park_timeout((deadline - now).min(AUDIT_WRITER_JOIN_POLL));
        }
        let _: thread::Result<()> = thread.join();
    }
}

/// Owner of the audit file handle and its bounded message receiver.
struct AuditWorker<W> {
    /// Destination the worker appends audit output to.
    file: W,
    /// Bounded channel receiving writes and flush requests.
    receiver: Receiver<AuditMessage>,
    /// Shared shutdown flag set by the guard.
    shutdown: Arc<AtomicBool>,
    /// Shared count of entries dropped while the channel was full.
    dropped: Arc<AtomicU64>,
    /// Shared count of audit I/O failures, used for warning throttling.
    io_failures: Arc<AtomicU64>,
    /// Time of the last stderr I/O-failure warning, if any.
    last_io_failure_warning: Option<Instant>,
}

impl<W> AuditWorker<W>
where
    W: io::Write,
{
    /// Drain the channel until shutdown, then flush the file.
    fn run(mut self) {
        loop {
            match self.receiver.recv_timeout(AUDIT_WRITER_POLL_INTERVAL) {
                Ok(message) => self.handle_message(message),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
        }

        while let Ok(message) = self.receiver.try_recv() {
            self.handle_message(message);
        }
        self.write_dropped_warning();
        if let Err(error) = self.file.flush() {
            self.record_io_failure("flush", &error);
        }
    }

    /// Apply one write or flush message, recording any I/O failure.
    fn handle_message(&mut self, message: AuditMessage) {
        match message {
            AuditMessage::Write(bytes) => {
                if let Err(error) = self.file.write_all(&bytes) {
                    self.record_io_failure("write", &error);
                }
                self.write_dropped_warning();
            }
            AuditMessage::Flush => {
                self.write_dropped_warning();
                if let Err(error) = self.file.flush() {
                    self.record_io_failure("flush", &error);
                }
            }
        }
    }

    /// Emit one warning line for entries dropped since the last check.
    fn write_dropped_warning(&mut self) {
        let count = self.dropped.swap(0, Ordering::Relaxed);
        if count == 0 {
            return;
        }
        if let Err(error) = writeln!(
            self.file,
            "{{\"level\":\"WARN\",\"target\":\"rmcp_server_kit::observability\",\"message\":\"audit log entries dropped because writer channel was full\",\"dropped\":{count}}}"
        ) {
            self.record_io_failure("write_dropped_warning", &error);
        }
    }

    /// Count an I/O failure and warn on stderr when the interval has elapsed.
    fn record_io_failure(&mut self, operation: &'static str, error: &io::Error) {
        let failure_count = self
            .io_failures
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if self.io_failure_warning_due(Instant::now()) {
            write_audit_io_failure_warning(operation, failure_count, error);
        }
    }

    /// Report whether a new I/O-failure warning is due at `now`.
    fn io_failure_warning_due(&mut self, now: Instant) -> bool {
        let due = self
            .last_io_failure_warning
            .is_none_or(|last| now.duration_since(last) >= AUDIT_IO_FAILURE_WARNING_INTERVAL);
        if due {
            self.last_io_failure_warning = Some(now);
        }
        due
    }
}

/// Write one audit I/O failure line to stderr without re-entering tracing.
#[expect(clippy::let_underscore_must_use, reason = "audit writer must not log")]
#[expect(
    let_underscore_drop,
    reason = "deliberate: src/observability.rs::write_audit_io_failure_warning drops the stderr result without re-entering tracing"
)]
fn write_audit_io_failure_warning(
    operation: &'static str,
    failure_count: u64,
    representative_error: &io::Error,
) {
    // This MUST NOT use tracing/log. The tracing subscriber owns the audit
    // writer that just failed, so re-entering it from the writer thread could
    // recursively enqueue more audit writes or deadlock during shutdown.
    let mut stderr = io::stderr().lock();
    let _: io::Result<()> = writeln!(
        stderr,
        "rmcp-server-kit audit log {operation} failed; failures_total={failure_count}; error={representative_error}"
    );
}

/// Result of preparing an audit sink: writer, guard and setup warnings.
struct AuditSetup {
    /// Non-blocking writer handed to the tracing layer, when configured.
    writer: Option<AuditFile>,
    /// Guard that owns the writer thread, when configured.
    guard: TracingGuard,
    /// Non-fatal problems collected while preparing the audit sink.
    warnings: Vec<String>,
}

impl AuditSetup {
    /// Build an empty setup with no audit sink and no warnings.
    const fn none() -> Self {
        Self {
            writer: None,
            guard: TracingGuard::none(),
            warnings: Vec::new(),
        }
    }
}

/// Open the audit log file for appending and spawn its writer thread.
///
/// Returns a non-blocking writer, its guard, and any warnings encountered while
/// preparing it.
///
/// # Log rotation
///
/// The background writer thread opens the file in append mode and holds a
/// long-lived handle for the lifetime of the [`TracingGuard`]. There is **no**
/// built-in rotation, no SIGHUP-style reopen, and no compression. Operators are
/// expected to use an external rotator such as `logrotate` (Linux) or
/// `newsyslog` (BSD / macOS) configured with `copytruncate` (or equivalent) so
/// the inode this handle points at is preserved across rotations. If the
/// rotator instead renames + recreates the file, this writer will keep writing
/// to the renamed (rotated) inode until the guard is dropped or the process
/// restarts.
///
/// # Errors
///
/// Returns `Err` with a message when the parent directory cannot be created,
/// the audit log cannot be opened, or its writer thread cannot be spawned.
fn open_audit_file(path: &Path) -> Result<AuditSetup, String> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
        && !parent.is_dir()
    {
        return Err(format!(
            "audit log parent path is not a directory: {}",
            parent.display()
        ));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
        && let Err(error) = fs::create_dir_all(parent)
    {
        return Err(format!(
            "failed to create audit log directory {}: {error}",
            parent.display()
        ));
    }

    let file = create_private_audit_file(path)?;
    let warnings = Vec::new();

    let (sender, receiver) = mpsc::sync_channel(AUDIT_LOG_CHANNEL_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_dropped = Arc::clone(&dropped);
    let worker_shutdown = Arc::clone(&shutdown);
    let thread = thread::Builder::new()
        .name("rmcp-audit-log-writer".into())
        .spawn(move || {
            AuditWorker {
                file,
                receiver,
                shutdown: worker_shutdown,
                dropped: worker_dropped,
                io_failures: Arc::new(AtomicU64::new(0)),
                last_io_failure_warning: None,
            }
            .run();
        })
        .map_err(|error| {
            format!(
                "failed to spawn audit log writer for {}: {error}",
                path.display()
            )
        })?;

    Ok(AuditSetup {
        writer: Some(AuditFile {
            sender: sender.clone(),
            dropped,
        }),
        guard: TracingGuard::audit(AuditWorkerGuard {
            shutdown,
            wake_sender: sender,
            thread: Some(thread),
        }),
        warnings,
    })
}

/// Open the configured audit log in strict mode, failing closed on error.
///
/// # Errors
///
/// Returns [`RmcpServerKitError::Startup`] when the configured audit log cannot
/// be opened or its writer thread cannot be spawned.
fn prepare_tracing_audit_strict(
    config: &ObservabilityConfig,
) -> Result<AuditSetup, RmcpServerKitError> {
    config.audit_log_path.as_deref().map_or_else(
        || Ok(AuditSetup::none()),
        |path| {
            open_audit_file(path).map_err(|error| {
                RmcpServerKitError::Startup(format!("audit log initialization failed: {error}"))
            })
        },
    )
}

/// Open the configured audit log, downgrading setup failures to warnings.
fn prepare_tracing_audit_lenient(config: &ObservabilityConfig) -> AuditSetup {
    config
        .audit_log_path
        .as_deref()
        .map_or_else(AuditSetup::none, |path| match open_audit_file(path) {
            Ok(setup) => setup,
            Err(warning) => AuditSetup {
                writer: None,
                guard: TracingGuard::none(),
                warnings: vec![warning],
            },
        })
}

/// Keep the audit guard alive for the process by storing it in the legacy list.
fn retain_legacy_guard(guard: TracingGuard) {
    if guard.audit.is_none() {
        return;
    }

    let mut guards = match legacy_tracing_guards().lock() {
        Ok(guards) => guards,
        Err(poisoned) => poisoned.into_inner(),
    };
    guards.push(guard);
}

/// Process-global storage keeping legacy audit guards alive.
fn legacy_tracing_guards() -> &'static Mutex<Vec<TracingGuard>> {
    static GUARDS: OnceLock<Mutex<Vec<TracingGuard>>> = OnceLock::new();
    GUARDS.get_or_init(|| Mutex::new(Vec::new()))
}

// Named to avoid colliding with `std::io` (already imported above as `io`):
// `harden_audit_handle` and `set_audit_file_mode` hand this across a
// function boundary in their signatures, where a function-body-local `use`
// cannot reach.
#[cfg(unix)]
use rustix::io::Result as RustixIoResult;
#[cfg(unix)]
use rustix::{fd::OwnedFd, io::Errno};

/// Create (or append to) the audit log with owner-only permissions.
///
/// SECURITY: opens with `O_NOFOLLOW` so a symlink planted at the final path
/// component is refused rather than followed (a symlinked *parent*
/// directory is still traversed; only the final component is protected).
/// `O_NONBLOCK` keeps a FIFO planted at the path from blocking this call
/// forever when no reader exists, turning that into a prompt error instead
/// of a startup hang; it is a no-op on a regular file and is cleared again
/// once the handle passes every check, so the writer thread gets plain
/// blocking-file semantics. `O_NOCTTY` stops a tty path from becoming this
/// process's controlling terminal.
///
/// The mode is applied atomically by `open` itself, never by a following
/// `set_permissions`: the two-step form leaves a window in which a freshly
/// created file carries umask-derived permissions, so any local principal
/// could open it before the mode is tightened. The post-open checks
/// (regular file, effective-UID ownership, mode correction, clearing
/// `O_NONBLOCK`) live in [`harden_audit_handle`], which takes the open
/// handle rather than a path so they stay independently testable without
/// privileges: a test can hand it a real handle with a deliberately wrong
/// `effective_uid`, or a `set_mode` that always fails, without needing a
/// foreign-owned fixture or a syscall this suite can make fail for real.
/// Audit logs carry identities and, under the diagnostic switches,
/// credential material.
///
/// This function never deletes a file on failure. The mode is fixed at
/// creation time, so a file this call creates is never exposed at a wider
/// mode, even transiently, and a pre-existing file that fails a check
/// (wrong type, wrong owner) was not created by this process: deleting it
/// would destroy something this process does not own, for no benefit, since
/// nothing was ever written to it.
///
/// # Errors
///
/// Returns `Err` naming the path and the reason when the audit log cannot
/// be opened, is not a regular file, is not owned by this process's
/// effective UID, or its permissions cannot be corrected to `0o600` and are
/// not already exactly `0o600`. A symlinked final component surfaces as
/// `ELOOP` and a FIFO with no reader as `ENXIO`; both get a message naming
/// the specific rule that was refused instead of the bare OS error text.
#[cfg(unix)]
fn create_private_audit_file(path: &Path) -> Result<fs::File, String> {
    use rustix::{
        fs::{Mode, OFlags, open},
        process::geteuid,
    };

    let flags = OFlags::CREATE
        | OFlags::APPEND
        | OFlags::WRONLY
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
        | OFlags::NONBLOCK
        | OFlags::NOCTTY;
    let fd = open(path, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|error| describe_audit_open_error(path, error))?;

    harden_audit_handle(fd, path, geteuid().as_raw(), set_audit_file_mode)
}

/// Widen a platform `st_nlink` value without triggering target-specific Clippy.
#[cfg(unix)]
fn widen_link_count<T>(count: T) -> u64
where
    T: Into<u64>,
{
    count.into()
}

/// Translate an `open` failure on the audit-log path into an operator
/// message that names the specific rule it tripped, for the two errnos
/// this hardening deliberately provokes.
///
/// `O_NOFOLLOW` turns a symlinked final path component into `ELOOP`;
/// `O_NONBLOCK` turns a FIFO with no reader into `ENXIO` instead of
/// blocking startup forever. Every other errno keeps the generic "failed to
/// open" form. Only the path and the OS-level reason are ever named, never
/// a symlink's target.
#[cfg(unix)]
fn describe_audit_open_error(path: &Path, error: Errno) -> String {
    match error {
        Errno::LOOP => format!(
            "audit log path {} is a symbolic link; refusing to follow it",
            path.display()
        ),
        Errno::NXIO => format!(
            "audit log path {} is not a regular file (a FIFO without a \
             reader, or a device with nothing attached)",
            path.display()
        ),
        other => format!("failed to open audit log file {}: {other}", path.display()),
    }
}

/// Harden an already-open audit-log handle: verify it is a regular file
/// owned by `effective_uid`, correct its mode to 0o600, and clear
/// `O_NONBLOCK`.
///
/// The correction accepts a handle already at exactly 0o600 when it fails.
///
/// Split out of `create_private_audit_file` so the regular-file, ownership
/// and mode-correction checks can be driven directly against a real open
/// handle in tests: a wrong `effective_uid` or a failing `set_mode` proves
/// the rejection path without a foreign-owned fixture (which needs
/// privileges this test suite does not assume) or a syscall this suite
/// cannot make fail for real. Keeping the seam handle-based rather than
/// path-based also lets the link-count check use the inspected handle without
/// reopening the path or touching the caller.
///
/// # Errors
///
/// Returns `Err` naming the path and the reason when the handle cannot be
/// inspected, is not a regular file, is not owned by `effective_uid`, has
/// more than one hard link, or `set_mode` fails on a handle not already at
/// 0o600.
#[cfg(unix)]
fn harden_audit_handle(
    fd: OwnedFd,
    path: &Path,
    effective_uid: u32,
    set_mode: fn(&OwnedFd) -> RustixIoResult<()>,
) -> Result<fs::File, String> {
    use rustix::fs::{FileType, Mode, OFlags, fcntl_setfl, fstat};

    let stat = fstat(&fd).map_err(|error| {
        format!(
            "failed to inspect audit log file {}: {error}",
            path.display()
        )
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!(
            "audit log path {} is not a regular file",
            path.display()
        ));
    }
    // `uid_t` (rustix's `RawUid`) is `u32` on every Unix target this crate
    // supports, so this comparison needs no widening.
    if !is_owned_by_effective_user(stat.st_uid, effective_uid) {
        return Err(format!(
            "audit log file {} is not owned by this process's effective user",
            path.display()
        ));
    }

    let link_count = widen_link_count(stat.st_nlink);
    if link_count > 1 {
        return Err(format!(
            "audit log file {} has {link_count} links; refusing hard-linked audit files",
            path.display()
        ));
    }

    // fchmod is always attempted so its side effects on ACL filesystems are
    // kept wherever chmod works. A filesystem that rejects chmod (CIFS/SMB
    // without Unix extensions, vfat, some FUSE or NFS mounts) can still
    // present a pre-created file whose permission bits are already exactly
    // owner-only (no setuid, setgid or sticky bit); that file is accepted
    // because the required state already holds. Any other failure fails
    // closed. Only `Mode` values are compared, so no cast is needed even
    // where `st_mode` is narrower (macOS).
    if let Err(error) = set_mode(&fd)
        && Mode::from_raw_mode(stat.st_mode) != Mode::RUSR | Mode::WUSR
    {
        return Err(format!(
            "failed to set audit log permissions to 0o600 for {}: {error}",
            path.display()
        ));
    }

    // Re-arm blocking semantics now that the handle is confirmed safe: the
    // writer thread (spawned only after this function returns `Ok`) expects
    // a plain blocking file, and `O_NONBLOCK` was only ever needed to keep
    // the checks above from hanging on a FIFO.
    fcntl_setfl(&fd, OFlags::APPEND).map_err(|error| {
        format!(
            "failed to clear non-blocking mode on audit log file {}: {error}",
            path.display()
        )
    })?;

    Ok(fs::File::from(fd))
}

/// Decide whether a file's owner matches this process's effective user.
///
/// A pure comparison over raw UIDs so the ownership rule is unit-testable
/// with fabricated values: proving the rejection path for a file owned by a
/// different user does not require actually creating one, which needs
/// privileges this test suite does not assume.
#[cfg(unix)]
const fn is_owned_by_effective_user(file_uid: u32, effective_uid: u32) -> bool {
    file_uid == effective_uid
}

/// Correct an audit-log handle's mode to owner-only (`0o600`).
///
/// A plain function, not a closure, so production code and a test can both
/// hand `harden_audit_handle` a `set_mode` of the same concrete function
/// pointer type: a test substitutes a different plain function that always
/// fails, proving the "turn a chmod failure into a warning" mutant red
/// without needing the real `fchmod` syscall to fail.
///
/// # Errors
///
/// Returns `Err` when the underlying `fchmod` call fails.
#[cfg(unix)]
fn set_audit_file_mode(fd: &OwnedFd) -> RustixIoResult<()> {
    use rustix::fs::{Mode, fchmod};

    fchmod(fd, Mode::RUSR | Mode::WUSR)
}

/// Win32 `FILE_ATTRIBUTE_REPARSE_POINT` (`0x400`).
///
/// Set in a file or directory's attributes whenever it is a reparse point
/// of ANY tag - a symbolic link, a junction, a mount point, or a
/// filesystem-specific tag such as a cloud-file placeholder or a
/// deduplicated file. Deliberately the raw attribute bit, not
/// `std::fs::FileType::is_symlink`, which is true only for reparse tags
/// carrying the `NAME_SURROGATE` bit (symlinks and junctions): testing the
/// raw bit instead refuses every reparse point, including the ones
/// `is_symlink` would silently let through.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Win32 `FILE_FLAG_OPEN_REPARSE_POINT` (`0x0020_0000`): opens a reparse
/// point itself instead of transparently following it to its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// True when `metadata` names a reparse point of any tag. See
/// [`FILE_ATTRIBUTE_REPARSE_POINT`] for why the raw bit is tested instead
/// of `FileType::is_symlink`.
#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Shared rejection message for both the pre-check and the handle check, so
/// a caller sees the identical wording regardless of which one fired.
#[cfg(windows)]
fn reparse_point_rejection(path: &Path) -> String {
    format!(
        "audit log path {} is a reparse point (a symbolic link, junction, \
         mount point, or another reparse tag); refusing to use it",
        path.display()
    )
}

/// Open `path` for append, creating it if absent, refusing to follow a
/// reparse point either way.
///
/// Returns the open handle together with whether THIS call created the
/// file (`true`) or opened a pre-existing one (`false`); see
/// [`create_private_audit_file`] for why that distinction decides whether
/// a later hardening failure may delete the file.
///
/// # Errors
///
/// Returns `Err` when neither a fresh creation nor an open of an existing
/// file succeeds.
#[cfg(windows)]
fn open_or_create_audit_handle(path: &Path) -> Result<(fs::File, bool), String> {
    use std::os::windows::fs::OpenOptionsExt as _;

    // `create_new(true)` is the only way this call can PROVE it created the
    // file: `CREATE_NEW` fails with `AlreadyExists` on any existing name,
    // reparse point included, so success here is proof of creation; a
    // `symlink_metadata` pre-check that merely observed `NotFound` would be
    // racy (a TOCTOU swap between that check and this open). `custom_flags`
    // requests `FILE_FLAG_OPEN_REPARSE_POINT` explicitly; std also ORs it
    // into the flags whenever `create_new` is set, so it is redundant on
    // this branch and required on the fallback branch below.
    match fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => fs::OpenOptions::new()
            .append(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map(|file| (file, false))
            .map_err(|open_error| {
                format!(
                    "failed to open audit log file {}: {open_error}",
                    path.display()
                )
            }),
        Err(error) => Err(format!(
            "failed to open audit log file {}: {error}",
            path.display()
        )),
    }
}

/// Create (or append to) the audit log with an owner-only DACL.
///
/// SECURITY: Windows has no safe creation-time equivalent of `mode(0o600)`.
/// Rust std cannot pass `SECURITY_ATTRIBUTES` to file creation
/// (rust-lang/libs-team#324), so the file is created and the protected
/// owner-only DACL applied immediately afterwards. That leaves a small
/// create-then-harden window the Unix path does not have: this removes the
/// *persistent* exposure, not the momentary one. It is not parity.
///
/// Before that window opens, this refuses a reparse point at the final path
/// component - a symbolic link, a junction, a mount point, or any other
/// reparse tag - in two steps: a `symlink_metadata` pre-check (never
/// follows the final component) and, after an open that also never follows
/// it (`FILE_FLAG_OPEN_REPARSE_POINT`), an attribute check on the opened
/// handle itself, closing the gap a pre-check alone would leave open to a
/// swap between the two. Neither check ever deletes anything: a rejected
/// reparse point is never removed. A symlinked *parent* directory is still
/// traversed; only the final component is protected, matching the Unix
/// path.
///
/// If hardening fails once the file exists, the handle is dropped and this
/// path is deleted best-effort only when THIS call created it; a
/// pre-existing file that fails hardening is left in place, since deleting
/// it would destroy something this process did not create, for no security
/// benefit. The cleanup is by path, so a principal with write access to the
/// parent directory can race it, the same residual as the by-path DACL
/// application above. The error states whether deletion was attempted and
/// whether it succeeded, so an operator knows whether an unprotected file,
/// or an untouched pre-existing one, may remain at that path. A rejected
/// reparse point and a pre-existing file are never deleted by this code.
///
/// # Errors
///
/// Returns `Err` when the path is a reparse point (checked both before and
/// after the open), when opening or inspecting the file fails, or when
/// applying the owner-only DACL fails.
#[cfg(windows)]
fn create_private_audit_file(path: &Path) -> Result<fs::File, String> {
    use std::ffi::OsString;

    use windows_permissions::{
        LocalBox, SecurityDescriptor,
        constants::{SeObjectType, SecurityInformation},
        utilities::current_process_sid,
        wrappers,
    };

    match fs::symlink_metadata(path) {
        Ok(existing) if is_reparse_point(&existing) => {
            return Err(reparse_point_rejection(path));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect audit log path {}: {error}",
                path.display()
            ));
        }
    }

    let (file, created_by_this_call) = open_or_create_audit_handle(path)?;

    // A TOCTOU swap between the pre-check above and this open would slip
    // past it; the open used `FILE_FLAG_OPEN_REPARSE_POINT`, so this reads
    // the reparse point's own attributes, never the target's.
    let opened_metadata = file.metadata().map_err(|metadata_error| {
        format!(
            "failed to inspect the opened audit log handle for {}: {metadata_error}",
            path.display()
        )
    })?;
    if is_reparse_point(&opened_metadata) {
        drop(file);
        return Err(reparse_point_rejection(path));
    }

    let harden = || -> Result<(), String> {
        let sid = current_process_sid().map_err(|sid_error| {
            format!("cannot determine the current process SID: {sid_error}")
        })?;
        // `D:P` protects the DACL, discarding inherited ACEs; a single
        // FA (full access) ACE for this process's SID is the owner-only grant.
        let sd: LocalBox<SecurityDescriptor> =
            format!("D:P(A;;FA;;;{sid})")
                .parse()
                .map_err(|parse_error| {
                    format!("cannot build an owner-only security descriptor: {parse_error}")
                })?;
        let dacl = sd
            .dacl()
            .ok_or_else(|| "owner-only security descriptor carried no DACL".to_owned())?;
        let name: OsString = path.as_os_str().to_owned();
        wrappers::SetNamedSecurityInfo(
            &name,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .map_err(|set_error| format!("cannot apply the owner-only DACL: {set_error}"))
    };

    match harden() {
        Ok(()) => Ok(file),
        Err(reason) => {
            drop(file);
            let cleanup = if created_by_this_call {
                match fs::remove_file(path) {
                    Ok(()) => "the unprotected file this call created was deleted".to_owned(),
                    Err(remove_error) => format!(
                        "the unprotected file this call created could NOT be deleted \
                         and may remain at {}: {remove_error}",
                        path.display()
                    ),
                }
            } else {
                "a pre-existing file at this path was left in place, not deleted".to_owned()
            };
            Err(format!(
                "audit log ACL hardening failed for {}: {reason}; {cleanup}",
                path.display()
            ))
        }
    }
}

/// Refuse to create an audit log where owner-only access cannot be guaranteed.
///
/// SECURITY: this platform has neither POSIX mode bits nor a supported ACL
/// path. Creating the file anyway would let it inherit directory permissions
/// while the operator believes auditing is protected. Failing here turns a
/// silent security-control failure into an explicit one: strict init reports a
/// startup error, and the deprecated lenient init warns and installs no audit
/// sink.
#[cfg(not(any(unix, windows)))]
fn create_private_audit_file(path: &Path) -> Result<fs::File, String> {
    Err(format!(
        "audit log private permissions are unsupported on this platform: cannot \
         guarantee owner-only access for {}; audit logging disabled",
        path.display()
    ))
}

#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_errors_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        time::Duration,
    };
    #[cfg(unix)]
    use std::io::Write as _;
    #[cfg(all(unix, not(target_os = "macos")))]
    use std::thread;
    use std::{
        env, fs, io,
        path::{Path, PathBuf},
        process,
        sync::{Mutex, mpsc},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context as _;
    use tracing::subscriber;
    #[cfg(unix)]
    use tracing_subscriber::fmt::MakeWriter as _;
    use tracing_subscriber::{Layer as _, filter, fmt, layer::SubscriberExt as _};

    #[cfg(not(windows))]
    use super::prepare_tracing_audit_lenient;
    use super::{AuditMessage, AuditWorker, init_tracing, prepare_tracing_audit_strict};
    use crate::{
        config::ObservabilityConfig,
        diagnostics::{
            DiagnosticExposure, ExposureTestGuard, oauth_claim_values, plaintext_oauth_tokens,
            set_diagnostic_exposure, tool_call_arguments,
        },
        error::RmcpServerKitError,
    };

    struct FailingAuditSink;

    impl io::Write for FailingAuditSink {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected audit sink write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected audit sink flush failure"))
        }
    }

    // Helper structs for default_filter_reaches_audit_layer test.
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);
    impl io::Write for BufferWriter {
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

    struct BufferA(Arc<Mutex<Vec<u8>>>);
    impl<'writer> fmt::MakeWriter<'writer> for BufferA {
        type Writer = BufferWriter;
        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(Arc::clone(&self.0))
        }
    }

    struct BufferB(Arc<Mutex<Vec<u8>>>);
    impl<'writer> fmt::MakeWriter<'writer> for BufferB {
        type Writer = BufferWriter;
        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(Arc::clone(&self.0))
        }
    }

    /// Helper function to build a two-layer subscriber for testing filter reaches.
    fn build_two_layer_test_subscriber(
        buffer_a: &Arc<Mutex<Vec<u8>>>,
        buffer_b: &Arc<Mutex<Vec<u8>>>,
    ) -> impl tracing::Subscriber {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                ObservabilityConfig::default().log_level,
            ))
            .with(fmt::layer().with_writer(BufferA(Arc::clone(buffer_a))))
            .with(
                fmt::layer()
                    .json()
                    .with_writer(BufferB(Arc::clone(buffer_b)))
                    .with_filter(filter::LevelFilter::INFO),
            )
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "tracing! macro expansions add branches"
    )]
    fn emit_filter_test_probes() {
        tracing::info!(target: "rmcp_server_kit::transport", "probe-kit");
        tracing::info!(target: "rmcp_server_kit::oauth", "probe-kit-oauth");
        tracing::info!(target: "rmcp::service", "probe-sdk-info");
        tracing::warn!(target: "rmcp::service", "probe-sdk-warn");
    }

    /// Helper function to run filter reach test logic and return (`a_contents`, `b_contents`).
    fn run_filter_reach_probe() -> anyhow::Result<(String, String)> {
        let buffer_a = Arc::new(Mutex::new(Vec::new()));
        let buffer_b = Arc::new(Mutex::new(Vec::new()));

        let subscriber = build_two_layer_test_subscriber(&buffer_a, &buffer_b);

        subscriber::with_default(subscriber, emit_filter_test_probes);

        let a_bytes = buffer_a
            .lock()
            .map_err(|error| anyhow::anyhow!("buffer a mutex is not poisoned: {error}"))?
            .clone();
        let b_bytes = buffer_b
            .lock()
            .map_err(|error| anyhow::anyhow!("buffer b mutex is not poisoned: {error}"))?
            .clone();
        let a_contents = String::from_utf8(a_bytes).unwrap_or_default();
        let b_contents = String::from_utf8(b_bytes).unwrap_or_default();

        Ok((a_contents, b_contents))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::config_format_valid keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the default observability config selects a supported log format.
    fn config_format_valid() -> anyhow::Result<()> {
        let config = ObservabilityConfig {
            log_level: "debug".into(),
            log_format: "json".into(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
            log_plaintext_oauth_tokens: false,
            log_oauth_claim_values: false,
            log_tool_call_arguments: false,
            log_upstream_error_bodies: false,
        };
        assert!(config.log_format == "json" || config.log_format == "pretty");

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::init_tracing_double_init_returns_err_not_panic keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Calling either `init_tracing` entry point twice in the same process
    /// must NOT panic. The second (and any subsequent) call must return
    /// `Err(TryInitError)` instead. This guards against regressions of the
    /// pre-0.11 `.init()` behaviour, which aborted the process when a
    /// global subscriber was already installed (e.g. by a sibling test).
    ///
    /// All four call orderings are exercised in a single test because the
    /// global tracing subscriber is process-wide state - we cannot rely on
    /// test isolation here.
    fn init_tracing_double_init_returns_err_not_panic() -> anyhow::Result<()> {
        // First call: may succeed or fail depending on whether another
        // test in this binary already installed a subscriber. Either is
        // acceptable; we only require that it does not panic.
        let _first_init = init_tracing("info");

        // Second call: a global subscriber is now guaranteed to exist,
        // so this MUST return Err and MUST NOT panic.
        let second = init_tracing("debug");
        assert!(
            second.is_err(),
            "second init_tracing must return Err once a global subscriber exists"
        );

        // The companion entry point must also report Err rather than panic.
        let cfg = ObservabilityConfig {
            log_level: "info".into(),
            log_format: "pretty".into(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
            log_plaintext_oauth_tokens: false,
            log_oauth_claim_values: false,
            log_tool_call_arguments: false,
            log_upstream_error_bodies: false,
        };
        #[expect(
            deprecated,
            reason = "this regression test explicitly covers the legacy fail-open API"
        )]
        let third = super::init_tracing_from_config(&cfg);
        assert!(
            third.is_err(),
            "init_tracing_from_config must return Err once a global subscriber exists"
        );

        Ok(())
    }

    #[test]
    /// Pins that strict tracing setup fails closed when the audit path cannot be opened.
    fn strict_init_fails_when_audit_path_unopenable() -> anyhow::Result<()> {
        let root_file = unique_temp_path("audit-parent-file")?;
        fs::write(&root_file, b"not a directory").context("create parent file fixture")?;
        let audit_path = root_file.join("audit.log");
        let config = observability_config(Some(audit_path));

        let result = prepare_tracing_audit_strict(&config);

        assert!(
            matches!(result, Err(RmcpServerKitError::Startup(_))),
            "unopenable audit path must fail closed with Startup"
        );
        fs::remove_file(&root_file).context("remove parent file fixture")?;

        Ok(())
    }

    #[test]
    /// Pins that a failed strict init leaves diagnostic exposure disarmed process-wide.
    fn strict_init_leaves_diagnostic_exposure_disarmed_on_startup_failure() -> anyhow::Result<()> {
        // SECURITY regression: exposure used to be armed before the fallible
        // audit setup, so a failed strict init returned Err with plaintext
        // token/claim logging enabled process-wide.
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure::default());
        let root_file = unique_temp_path("audit-parent-file-diagnostics")?;
        fs::write(&root_file, b"not a directory").context("create parent file fixture")?;
        let mut config = observability_config(Some(root_file.join("audit.log")));
        config.log_plaintext_oauth_tokens = true;
        config.log_oauth_claim_values = true;
        config.log_tool_call_arguments = true;

        let result = super::init_tracing_from_config_strict(&config);

        assert!(
            matches!(result, Err(RmcpServerKitError::Startup(_))),
            "unopenable audit path must keep subscriber initialization out of this test"
        );
        assert!(!plaintext_oauth_tokens());
        assert!(!oauth_claim_values());
        assert!(!tool_call_arguments());
        fs::remove_file(&root_file).context("remove parent file fixture")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that strict init installs an audit writer that drains a normal audit line.
    fn strict_init_succeeds_and_writes_audit_line() -> anyhow::Result<()> {
        let dir = unique_temp_path("audit-dir")?;
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_strict(&config).context("strict audit setup succeeds")?;
        let writer = setup
            .writer
            .as_ref()
            .context("audit writer is configured")?;
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .json()
                .with_writer(writer.clone())
                .with_filter(filter::LevelFilter::INFO),
        );

        let flush = subscriber::with_default(subscriber, || {
            tracing::info!(event = "phase3-test", "audit event");
            let mut sink = writer.make_writer();
            sink.flush()
        });
        flush.context("enqueue flush")?;
        drop(setup.guard);

        let contents = fs::read_to_string(&audit_path).context("read flushed audit file")?;
        assert!(
            contents.contains("audit event"),
            "guard drop should drain this normal audit line before timeout; got {contents:?}"
        );
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    /// Pins that the default filter reaches both JSON and pretty audit layers.
    fn default_filter_reaches_audit_layer() -> anyhow::Result<()> {
        let (a_contents, b_contents) = run_filter_reach_probe()?;

        // Both layers should see probe-kit and probe-sdk-warn
        assert!(
            a_contents.contains("probe-kit"),
            "buffer A should contain probe-kit; got: {a_contents:?}"
        );
        assert!(
            b_contents.contains("probe-kit"),
            "buffer B should contain probe-kit; got: {b_contents:?}"
        );
        assert!(
            a_contents.contains("probe-sdk-warn"),
            "buffer A should contain probe-sdk-warn; got: {a_contents:?}"
        );
        assert!(
            b_contents.contains("probe-sdk-warn"),
            "buffer B should contain probe-sdk-warn; got: {b_contents:?}"
        );

        // Neither should see probe-sdk-info
        assert!(
            !a_contents.contains("probe-sdk-info"),
            "buffer A should NOT contain probe-sdk-info; got: {a_contents:?}"
        );
        assert!(
            !b_contents.contains("probe-sdk-info"),
            "buffer B should NOT contain probe-sdk-info; got: {b_contents:?}"
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::audit_worker_counts_write_and_flush_failures_without_panicking keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that write and flush failures are counted without panicking the worker.
    fn audit_worker_counts_write_and_flush_failures_without_panicking() -> anyhow::Result<()> {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let io_failures = Arc::new(AtomicU64::new(0));
        let mut worker = AuditWorker {
            file: FailingAuditSink,
            receiver,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
            io_failures: Arc::clone(&io_failures),
            last_io_failure_warning: Some(Instant::now()),
        };

        worker.handle_message(AuditMessage::Write(b"audit event\n".to_vec()));
        worker.handle_message(AuditMessage::Flush);

        assert_eq!(io_failures.load(Ordering::Relaxed), 2);

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::audit_worker_io_failure_warning_is_time_throttled keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that repeated audit I/O failure warnings are throttled by interval.
    fn audit_worker_io_failure_warning_is_time_throttled() -> anyhow::Result<()> {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut worker = AuditWorker {
            file: FailingAuditSink,
            receiver,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
            io_failures: Arc::new(AtomicU64::new(0)),
            last_io_failure_warning: None,
        };
        let first = Instant::now();

        assert!(worker.io_failure_warning_due(first));
        assert!(!worker.io_failure_warning_due(first + Duration::from_secs(1)));
        assert!(
            worker.io_failure_warning_due(first + super::AUDIT_IO_FAILURE_WARNING_INTERVAL),
            "warning should be eligible again after the throttle interval"
        );

        Ok(())
    }

    #[test]
    /// Pins that strict init without an audit path installs no audit writer.
    fn strict_init_succeeds_with_no_audit_path() -> anyhow::Result<()> {
        let config = observability_config(None);

        let setup =
            prepare_tracing_audit_strict(&config).context("no audit path needs no file I/O")?;

        assert!(
            setup.writer.is_none(),
            "no audit path should install no audit writer"
        );

        Ok(())
    }

    fn observability_config(audit_log_path: Option<PathBuf>) -> ObservabilityConfig {
        ObservabilityConfig {
            log_level: "info".into(),
            log_format: "pretty".into(),
            audit_log_path,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
            log_plaintext_oauth_tokens: false,
            log_oauth_claim_values: false,
            log_tool_call_arguments: false,
            log_upstream_error_bodies: false,
        }
    }

    #[test]
    #[cfg(unix)]
    /// Pins that a freshly created audit log is never group- or world-accessible.
    fn audit_file_is_created_owner_only() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_temp_path("audit-mode")?;
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_strict(&config).context("strict audit setup succeeds")?;
        drop(setup.guard);

        let mode = fs::metadata(&audit_path)
            .context("audit file exists")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "audit log must never be group- or world-accessible, even transiently; \
             got mode {mode:o}"
        );
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that a symlinked audit path is refused before any write, leaving
    /// the symlink target's content and mode untouched. The old code opened
    /// through the symlink, chmodded the target to 0o600, and wrote through
    /// it.
    fn symlinked_audit_path_is_rejected_before_any_write() -> anyhow::Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = unique_temp_path("audit-symlink-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let target_path = dir.join("target.log");
        let marker = "pre-existing target contents, never touched";
        fs::write(&target_path, marker).context("create symlink target")?;
        fs::set_permissions(&target_path, fs::Permissions::from_mode(0o644))
            .context("set target mode")?;
        let audit_path = dir.join("audit.log");
        symlink(&target_path, &audit_path).context("create audit path symlink")?;

        let config = observability_config(Some(audit_path));
        let error = match prepare_tracing_audit_strict(&config) {
            Err(RmcpServerKitError::Startup(message)) => message,
            Err(other) => anyhow::bail!(
                "a symlinked audit path must fail closed with Startup; got a different error variant: {other}"
            ),
            Ok(_) => {
                anyhow::bail!("a symlinked audit path must fail closed with Startup; it succeeded")
            }
        };
        assert!(
            error.contains("is a symbolic link"),
            "error must name the symlink rejection, not a bare OS error; got {error:?}"
        );
        let target_mode = fs::metadata(&target_path)
            .context("read target metadata")?
            .permissions()
            .mode();
        assert_eq!(
            target_mode & 0o777,
            0o644,
            "a refused symlink must leave the target's mode untouched; got {target_mode:o}"
        );
        let target_contents = fs::read_to_string(&target_path).context("read target contents")?;
        assert_eq!(
            target_contents, marker,
            "a refused symlink must leave the target's contents untouched"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that `/dev/null` (a non-regular file) is refused by strict init
    /// and that the refusal never changes its mode. The old code chmodded
    /// through it and only warned when that chmod failed with `EPERM`.
    fn dev_null_is_rejected_by_strict_init_and_its_mode_is_untouched() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let before = fs::metadata("/dev/null")
            .context("stat /dev/null before the attempt")?
            .permissions()
            .mode();

        let config = observability_config(Some(PathBuf::from("/dev/null")));
        let result = prepare_tracing_audit_strict(&config);

        assert!(
            matches!(result, Err(RmcpServerKitError::Startup(_))),
            "a non-regular audit path must fail closed with Startup"
        );
        let after = fs::metadata("/dev/null")
            .context("stat /dev/null after the attempt")?
            .permissions()
            .mode();
        assert_eq!(
            before, after,
            "a refused non-regular audit path must never have its mode touched"
        );

        Ok(())
    }

    /// Send the FIFO test's outcome over its bounded notification channel.
    ///
    /// `None` means the open unexpectedly succeeded; `Some(message)` carries
    /// the rejection reason so the test can assert on it. The send result is
    /// intentionally discarded: a full or disconnected channel means the
    /// receiver already gave up on its bounded `recv_timeout`, at which
    /// point the test has already failed on the timeout and there is no
    /// corrective action this thread could take.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "deliberate: src/observability.rs::notify_fifo_test_outcome: a full or disconnected channel has no corrective action; the test's bounded recv_timeout is the actual correctness check"
    )]
    #[expect(
        let_underscore_drop,
        reason = "deliberate: src/observability.rs::notify_fifo_test_outcome drops the full-or-disconnected send result without logging, same as AuditFileWriter::flush above"
    )]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn notify_fifo_test_outcome(
        sender: &mpsc::SyncSender<Option<String>>,
        outcome: Option<String>,
    ) {
        let _: Result<(), mpsc::TrySendError<Option<String>>> = sender.try_send(outcome);
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    /// Pins that a FIFO at the audit path is refused promptly rather than
    /// blocking startup forever, with a message naming the specific rule
    /// rather than a bare `ENXIO`. `O_WRONLY` on a FIFO with no reader
    /// blocks until one attaches; `O_NONBLOCK` turns that into an immediate
    /// error instead. Linux-only: rustix excludes `mkfifoat` on Apple
    /// targets, so this is skipped on macOS, where the `/dev/null` test
    /// above already covers the non-regular-file rule on every Unix.
    fn fifo_audit_path_is_rejected_promptly_not_hung() -> anyhow::Result<()> {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let dir = unique_temp_path("audit-fifo-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.fifo");
        mkfifoat(CWD, &audit_path, Mode::RUSR | Mode::WUSR)
            .map_err(|error| anyhow::anyhow!("create test fifo: {error}"))?;

        let config = observability_config(Some(audit_path));
        let (sender, receiver) = mpsc::sync_channel(1);
        let _join = thread::spawn(move || {
            let outcome = match prepare_tracing_audit_strict(&config) {
                Ok(setup) => {
                    drop(setup.guard);
                    None
                }
                Err(RmcpServerKitError::Startup(message)) => Some(message),
                Err(other) => Some(format!("unexpected error variant: {other}")),
            };
            notify_fifo_test_outcome(&sender, outcome);
        });

        let outcome = receiver
            .recv_timeout(Duration::from_secs(5))
            .context("opening a FIFO audit path must not hang startup")?;
        let message = outcome.context("a FIFO at the audit path must fail closed, not succeed")?;
        assert!(
            message.contains("is not a regular file"),
            "error must name the non-regular-file rejection, not a bare OS error; got {message:?}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that a pre-existing, self-owned `0o644` audit file is tightened
    /// to `0o600` and accepted.
    fn preexisting_self_owned_file_is_tightened_to_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_temp_path("audit-tighten-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.log");
        fs::write(&audit_path, b"pre-existing").context("create pre-existing audit file")?;
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o644))
            .context("loosen the pre-existing file's mode")?;

        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_strict(&config)
            .context("a self-owned pre-existing file must be accepted")?;
        drop(setup.guard);

        let mode = fs::metadata(&audit_path)
            .context("read tightened file metadata")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a pre-existing self-owned file must be tightened to 0o600; got {mode:o}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that strict init refuses a hard-linked audit file before any
    /// writer is installed or file metadata is changed.
    fn hardlinked_audit_path_is_rejected_by_strict_init_without_changes() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_temp_path("audit-hardlink-strict-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.log");
        let other_path = dir.join("audit.alias");
        let marker = "hard-linked audit fixture, strict rejection leaves it alone";
        fs::write(&audit_path, marker).context("create hardlink target")?;
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o644))
            .context("set hardlink target mode")?;
        fs::hard_link(&audit_path, &other_path).context("create second hardlink")?;

        let config = observability_config(Some(audit_path.clone()));
        let error = match prepare_tracing_audit_strict(&config) {
            Err(RmcpServerKitError::Startup(message)) => message,
            Err(other) => anyhow::bail!(
                "a hard-linked audit path must fail closed with Startup; got a different error variant: {other}"
            ),
            Ok(setup) => {
                drop(setup.guard);
                anyhow::bail!(
                    "a hard-linked audit path must fail closed with Startup; it succeeded"
                )
            }
        };
        assert!(
            error.contains("has 2 links"),
            "error must name the hardlink count; got {error:?}"
        );
        let mode = fs::metadata(&audit_path)
            .context("read hardlink target metadata")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "a refused hard-linked audit file must leave mode untouched; got {mode:o}"
        );
        let contents = fs::read_to_string(&other_path).context("read hardlink alias contents")?;
        assert_eq!(
            contents, marker,
            "a refused hard-linked audit file must leave contents untouched"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that removing the second directory entry makes the same inode safe
    /// for strict init again, and the accepted file is tightened to `0o600`.
    fn single_link_audit_path_is_accepted_after_alias_removed() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_temp_path("audit-hardlink-removed-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.log");
        let other_path = dir.join("audit.alias");
        fs::write(&audit_path, b"single-link fixture").context("create audit file")?;
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o644))
            .context("set audit file mode")?;
        fs::hard_link(&audit_path, &other_path).context("create second hardlink")?;
        fs::remove_file(&other_path).context("remove second hardlink")?;

        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_strict(&config)
            .context("a single-link self-owned audit file must be accepted")?;
        drop(setup.guard);

        let mode = fs::metadata(&audit_path)
            .context("read accepted audit file metadata")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "an accepted single-link audit file must be tightened to 0o600; got {mode:o}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that lenient init treats a hard-linked audit path like any other
    /// hardening failure: warn, install no audit sink, and leave the file alone.
    fn lenient_init_installs_no_sink_for_hardlinked_audit_path() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_temp_path("audit-hardlink-lenient-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.log");
        let other_path = dir.join("audit.alias");
        fs::write(&audit_path, b"lenient hardlink fixture").context("create audit file")?;
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o644))
            .context("set audit file mode")?;
        fs::hard_link(&audit_path, &other_path).context("create second hardlink")?;

        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_lenient(&config);

        assert!(
            setup.writer.is_none(),
            "no audit sink may be installed when a hard-linked path is refused"
        );
        assert!(
            setup
                .warnings
                .iter()
                .any(|warning| warning.contains("has 2 links")),
            "lenient init must warn with the hardlink count; got {:?}",
            setup.warnings
        );
        let mode = fs::metadata(&audit_path)
            .context("read hardlink target metadata")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "a refused hard-linked audit file must leave mode untouched; got {mode:o}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that the hardened open handle ends with plain blocking
    /// semantics: `O_NONBLOCK` is needed only to keep the checks inside
    /// `create_private_audit_file` from hanging on a FIFO, and must not
    /// reach the writer thread.
    fn create_private_audit_file_clears_nonblock_after_hardening() -> anyhow::Result<()> {
        use rustix::fs::{OFlags, fcntl_getfl};

        let dir = unique_temp_path("audit-nonblock-dir")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let audit_path = dir.join("audit.log");

        let file = super::create_private_audit_file(&audit_path)
            .map_err(|error| anyhow::anyhow!("create_private_audit_file: {error}"))?;
        let flags = fcntl_getfl(&file).context("read back the handle's status flags")?;
        assert!(
            !flags.contains(OFlags::NONBLOCK),
            "the hardened handle must not keep O_NONBLOCK set"
        );

        drop(file);
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that `harden_audit_handle` rejects a real, self-owned regular
    /// file when handed an `effective_uid` that does not match its owner,
    /// and that no byte is ever written to it. This drives the seam
    /// directly (the real owner matches the real `geteuid()`, so this
    /// could not be proven by opening through `create_private_audit_file`)
    /// and is the faithful red test for both dropping the ownership check
    /// and writing to the handle before the checks run.
    fn harden_audit_handle_rejects_mismatched_owner_without_writing() -> anyhow::Result<()> {
        use std::os::fd::OwnedFd;

        use rustix::process::geteuid;

        let dir = unique_temp_path("audit-seam-wrong-uid")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();
        let wrong_uid = real_uid.wrapping_add(1);

        let result = super::harden_audit_handle(fd, &path, wrong_uid, super::set_audit_file_mode);

        let error = result
            .err()
            .context("a mismatched effective_uid must be rejected")?;
        assert!(
            error.contains("not owned by this process's effective user"),
            "error must name the ownership problem; got {error:?}"
        );
        let contents = fs::read(&path).context("read fixture file")?;
        assert!(
            contents.is_empty(),
            "a rejected handle must never be written to; got {} bytes",
            contents.len()
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that the hardening seam rejects a regular file with more than one
    /// link before correcting its mode, because every name reaches one inode.
    fn harden_audit_handle_rejects_hardlinked_file_before_chmod() -> anyhow::Result<()> {
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::process::geteuid;

        let dir = unique_temp_path("audit-seam-hardlink")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let other_path = dir.join("audit.alias");
        fs::write(&path, b"hardlink seam fixture").context("create fixture file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .context("set fixture mode")?;
        fs::hard_link(&path, &other_path).context("create second hardlink")?;
        let file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .context("open hard-linked fixture file")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let result = super::harden_audit_handle(fd, &path, real_uid, super::set_audit_file_mode);

        let error = result
            .err()
            .context("a hard-linked audit handle must be rejected")?;
        assert!(
            error.contains("has 2 links"),
            "error must name the hardlink count; got {error:?}"
        );
        let mode = fs::metadata(&path)
            .context("read fixture metadata")?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "a rejected hard-linked handle must not be chmodded; got {mode:o}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that `harden_audit_handle` turns a `set_mode` failure into
    /// `Err` rather than a warning, and never writes to the handle first.
    /// `set_mode` is injected specifically so this can be proven without
    /// making the real `fchmod` syscall fail. The fixture starts at 0o644,
    /// independent of the process umask.
    fn harden_audit_handle_rejects_failing_set_mode() -> anyhow::Result<()> {
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::{io::Errno, process::geteuid};

        fn always_fails(_fd: &OwnedFd) -> super::RustixIoResult<()> {
            Err(Errno::PERM)
        }

        let dir = unique_temp_path("audit-seam-chmod-fail")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .context("widen fixture mode")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let result = super::harden_audit_handle(fd, &path, real_uid, always_fails);

        let error = result
            .err()
            .context("a failing set_mode must be reported, not downgraded to a warning")?;
        assert!(
            error.contains("permissions"),
            "error must mention the permissions failure; got {error:?}"
        );
        let contents = fs::read(&path).context("read fixture file")?;
        assert!(
            contents.is_empty(),
            "a rejected handle must never be written to; got {} bytes",
            contents.len()
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that `harden_audit_handle` rejects a handle that is not a
    /// regular file, independent of the open path: cheap and
    /// platform-independent, unlike the FIFO test above, this needs no
    /// privileges and no special fixture.
    fn harden_audit_handle_rejects_non_regular_file() -> anyhow::Result<()> {
        use std::os::fd::OwnedFd;

        use rustix::process::geteuid;

        let file = fs::OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .context("open /dev/null read-only")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let result = super::harden_audit_handle(
            fd,
            Path::new("/dev/null"),
            real_uid,
            super::set_audit_file_mode,
        );

        let error = result
            .err()
            .context("a non-regular handle must be rejected")?;
        assert!(
            error.contains("not a regular file"),
            "error must name the regular-file rule; got {error:?}"
        );

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins the seam's success path directly: a self-owned regular file,
    /// the real effective UID, and the real `fchmod` end with mode
    /// `0o600` and no `O_NONBLOCK` on the returned handle. The fixture
    /// starts at 0o644, independent of the process umask.
    fn harden_audit_handle_accepts_self_owned_file_and_clears_nonblock() -> anyhow::Result<()> {
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::{
            fs::{OFlags, fcntl_getfl},
            process::geteuid,
        };

        let dir = unique_temp_path("audit-seam-success")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .context("widen fixture mode")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let hardened = super::harden_audit_handle(fd, &path, real_uid, super::set_audit_file_mode)
            .map_err(|error| anyhow::anyhow!("harden_audit_handle: {error}"))?;

        let mode = fs::metadata(&path)
            .context("read fixture metadata")?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "handle must end 0o600; got {mode:o}");
        let flags = fcntl_getfl(&hardened).context("read back status flags")?;
        assert!(
            !flags.contains(OFlags::NONBLOCK),
            "handle must not keep O_NONBLOCK set"
        );

        drop(hardened);
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that a self-owned regular file already at exactly 0o600 is
    /// accepted when fchmod fails, as on a filesystem that rejects chmod,
    /// and that the handle still loses `O_NONBLOCK`.
    fn harden_audit_handle_accepts_0600_when_set_mode_fails() -> anyhow::Result<()> {
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::{
            fs::{OFlags, fcntl_getfl, fcntl_setfl},
            io::Errno,
            process::geteuid,
        };

        fn always_fails(_fd: &OwnedFd) -> super::RustixIoResult<()> {
            Err(Errno::PERM)
        }

        let dir = unique_temp_path("audit-seam-chmod-fail-0600")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("set fixture mode")?;
        let fd = OwnedFd::from(file);
        fcntl_setfl(&fd, OFlags::APPEND | OFlags::NONBLOCK).context("arm O_NONBLOCK")?;
        anyhow::ensure!(
            fcntl_getfl(&fd)
                .context("read fixture status flags")?
                .contains(OFlags::NONBLOCK),
            "fixture handle must start with O_NONBLOCK set"
        );
        let real_uid = geteuid().as_raw();

        let hardened = super::harden_audit_handle(fd, &path, real_uid, always_fails)
            .map_err(|error| anyhow::anyhow!("harden_audit_handle: {error}"))?;

        let mode = fs::metadata(&path)
            .context("read fixture metadata")?
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o600, "handle must stay 0o600; got {mode:o}");
        let flags = fcntl_getfl(&hardened).context("read back status flags")?;
        assert!(
            !flags.contains(OFlags::NONBLOCK),
            "handle must not keep O_NONBLOCK set"
        );

        drop(hardened);
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that fchmod is still attempted on a file already at 0o600, so
    /// its side effects on ACL filesystems are kept wherever chmod works.
    fn harden_audit_handle_still_attempts_set_mode_at_0600() -> anyhow::Result<()> {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::process::geteuid;

        static CALLS: AtomicUsize = AtomicUsize::new(0);

        #[expect(
            clippy::unnecessary_wraps,
            reason = "deliberate: src/observability.rs::harden_audit_handle takes a fallible set_mode fn pointer, so this counting seam must return a Result"
        )]
        fn counting(_fd: &OwnedFd) -> super::RustixIoResult<()> {
            let _previous = CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        let dir = unique_temp_path("audit-seam-chmod-attempt-0600")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("set fixture mode")?;
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let hardened = super::harden_audit_handle(fd, &path, real_uid, counting)
            .map_err(|error| anyhow::anyhow!("harden_audit_handle: {error}"))?;

        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "set_mode must be attempted exactly once even at 0o600"
        );

        drop(hardened);
        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    /// Pins that setuid, setgid and sticky bits count: a file at 0o4600 is
    /// not accepted when fchmod fails.
    fn harden_audit_handle_rejects_special_bits_when_set_mode_fails() -> anyhow::Result<()> {
        use std::os::{fd::OwnedFd, unix::fs::PermissionsExt as _};

        use rustix::{io::Errno, process::geteuid};

        fn always_fails(_fd: &OwnedFd) -> super::RustixIoResult<()> {
            Err(Errno::PERM)
        }

        let dir = unique_temp_path("audit-seam-chmod-fail-special")?;
        fs::create_dir_all(&dir).context("create fixture dir")?;
        let path = dir.join("audit.log");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("open a real self-owned file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4600))
            .context("set fixture mode")?;
        let fixture_mode = fs::metadata(&path)
            .context("read fixture metadata")?
            .permissions()
            .mode();
        anyhow::ensure!(
            fixture_mode & 0o7777 == 0o4600,
            "fixture must carry the setuid bit; got {fixture_mode:o}"
        );
        let fd = OwnedFd::from(file);
        let real_uid = geteuid().as_raw();

        let result = super::harden_audit_handle(fd, &path, real_uid, always_fails);

        let error = result
            .err()
            .context("a 0o4600 handle must be rejected when set_mode fails")?;
        assert!(
            error.contains("permissions"),
            "error must mention the permissions failure; got {error:?}"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::lenient_init_installs_no_sink_when_hardening_fails keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    #[cfg(unix)]
    /// Pins that lenient (deprecated) init installs no audit sink when
    /// hardening fails: the cross-platform behaviour the guard at the bottom
    /// of this module pins for a platform with no private-permission
    /// support, exercised here through a real Unix failure mode.
    fn lenient_init_installs_no_sink_when_hardening_fails() -> anyhow::Result<()> {
        let config = observability_config(Some(PathBuf::from("/dev/null")));

        let setup = prepare_tracing_audit_lenient(&config);

        assert!(
            setup.writer.is_none(),
            "no audit sink may be installed when hardening fails"
        );
        assert!(
            !setup.warnings.is_empty(),
            "lenient init must warn rather than fail silently; got {:?}",
            setup.warnings
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::ownership_check_rejects_foreign_uid_without_requiring_root keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    #[cfg(unix)]
    /// Pins the ownership-match decision directly against fabricated UIDs:
    /// proving the rejection path with a REAL foreign-owned file needs
    /// privileges (root, or a user-namespace / idmapped-mount setup) that
    /// this test suite does not assume and CI does not grant.
    fn ownership_check_rejects_foreign_uid_without_requiring_root() -> anyhow::Result<()> {
        assert!(super::is_owned_by_effective_user(1000, 1000));
        assert!(!super::is_owned_by_effective_user(1000, 0));
        assert!(!super::is_owned_by_effective_user(0, 1000));

        Ok(())
    }

    /// The audit log must end up with a protected, owner-only DACL: exactly one
    /// ACE, granting this process's SID, with inherited entries discarded.
    ///
    /// Read back through `windows-permissions` rather than shelling out to
    /// `icacls`, so the assertion does not depend on a subprocess.
    #[test]
    #[cfg(windows)]
    fn audit_file_dacl_is_owner_only() -> anyhow::Result<()> {
        use windows_permissions::{
            constants::{SeObjectType, SecurityInformation},
            utilities, wrappers,
        };

        let dir = unique_temp_path("audit-dacl")?;
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));

        let setup = prepare_tracing_audit_strict(&config)
            .context("Windows audit logging must succeed once the DACL is applied")?;
        drop(setup.guard);

        assert!(
            audit_path.exists(),
            "the audit file must be created on Windows, not refused"
        );

        let security_descriptor = wrappers::GetNamedSecurityInfo(
            audit_path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl,
        )
        .context("reading the audit file security descriptor must succeed")?;
        let dacl = security_descriptor
            .dacl()
            .context("the audit file must carry a DACL")?;

        let expected =
            utilities::current_process_sid().context("current process SID must be resolvable")?;

        assert_eq!(
            dacl.len(),
            1,
            "a protected owner-only DACL must contain exactly one ACE; \
             more means inherited entries survived"
        );
        let ace = dacl.get_ace(0).context("the single ACE must be readable")?;
        assert_eq!(
            ace.sid().context("the ACE must name a SID")?,
            &*expected,
            "the only ACE must grant this process's SID"
        );

        fs::remove_dir_all(&dir).context("remove audit temp dir")?;

        Ok(())
    }

    /// Pins that a pre-existing regular audit-log file is still accepted
    /// through the open-existing fallback of `open_or_create_audit_handle`
    /// (strict init returns only when the DACL step succeeded) and that
    /// its contents are not altered.
    #[test]
    #[cfg(windows)]
    fn windows_preexisting_audit_file_is_accepted_without_alteration() -> anyhow::Result<()> {
        let dir = unique_temp_path("audit-preexisting")?;
        fs::create_dir_all(&dir).context("create preexisting-file temp dir")?;
        let audit_path = dir.join("audit.log");
        fs::write(&audit_path, b"pre-existing audit content\n")
            .context("write pre-existing audit file")?;
        let config = observability_config(Some(audit_path.clone()));

        let setup = prepare_tracing_audit_strict(&config)
            .context("a pre-existing regular audit file must still be accepted")?;
        drop(setup.guard);

        assert!(
            audit_path.exists(),
            "the pre-existing audit file must not be deleted"
        );
        let contents = fs::read(&audit_path).context("read audit file contents")?;
        assert_eq!(
            contents, b"pre-existing audit content\n",
            "opening for append must not truncate or alter pre-existing contents"
        );

        fs::remove_dir_all(&dir).context("remove preexisting-file temp dir")?;

        Ok(())
    }

    /// Pins that a junction at the final path component is refused before
    /// any write, naming the specific reparse-point rejection (a directory
    /// cannot be opened for append anyway, so only that specific message
    /// proves the reparse-point check ran before any open attempt), and
    /// that the junction and its target directory both survive untouched.
    /// Creating a junction needs no special privilege on Windows.
    #[test]
    #[cfg(windows)]
    fn windows_junctioned_audit_path_is_rejected_before_any_write() -> anyhow::Result<()> {
        let dir = unique_temp_path("audit-junction")?;
        fs::create_dir_all(&dir).context("create junction base dir")?;
        let target_dir = dir.join("junction-target");
        fs::create_dir_all(&target_dir).context("create junction target dir")?;
        let link_path = dir.join("audit.log");

        let status = process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link_path)
            .arg(&target_dir)
            .status()
            .context("spawn mklink /J to build this test's junction fixture")?;
        assert!(
            status.success(),
            "mklink /J must succeed to set up this test's fixture; got {status:?}"
        );

        let config = observability_config(Some(link_path.clone()));
        let err = prepare_tracing_audit_strict(&config)
            .err()
            .context("a junctioned audit path must fail closed with Startup")?;
        let msg = err.to_string();
        assert!(
            msg.contains("reparse point"),
            "error must name the reparse-point rejection; got {msg:?}"
        );

        assert!(
            link_path.exists(),
            "the junction itself must still exist after the rejection"
        );
        assert!(
            target_dir.exists(),
            "the junction's target directory must still exist after the rejection"
        );

        fs::remove_dir(&link_path)
            .context("remove the junction without recursing into its target")?;
        fs::remove_dir_all(&dir).context("remove junction temp dir")?;

        Ok(())
    }

    /// Pins that a file symlink at the final path component is refused
    /// before any write, naming the specific reparse-point rejection, and
    /// that the symlink's target file and contents survive untouched.
    /// Creating a file symlink needs `SeCreateSymbolicLinkPrivilege` or
    /// Developer Mode; when the runner grants neither, `symlink_file` fails
    /// with raw OS error 1314 (`ERROR_PRIVILEGE_NOT_HELD`), which this test
    /// detects and returns early from rather than failing for a privilege
    /// it does not control. That raw code, not `io::ErrorKind`, is the
    /// correct check: std's own `decode_error_kind` has no match arm for
    /// 1314, so it falls through to `ErrorKind::Uncategorized`, and std's
    /// own test suite (`library/std/src/fs/tests.rs`) checks
    /// `raw_os_error() == Some(1314)` for exactly this reason. The skip is
    /// silent (no output) because libtest captures the output of a
    /// passing test - but only when the privilege is missing AND
    /// `RMCP_REQUIRE_SYMLINK_TESTS` is not exactly `1`; CI sets that
    /// variable so the missing-privilege path fails instead of skipping.
    #[test]
    #[cfg(windows)]
    fn windows_symlinked_audit_path_is_rejected_before_any_write() -> anyhow::Result<()> {
        const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

        let dir = unique_temp_path("audit-symlink")?;
        fs::create_dir_all(&dir).context("create symlink base dir")?;
        let target_path = dir.join("target.log");
        let link_path = dir.join("audit.log");
        fs::write(&target_path, b"pre-existing target contents\n")
            .context("write symlink target")?;

        if let Err(error) = std::os::windows::fs::symlink_file(&target_path, &link_path) {
            if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) {
                fs::remove_dir_all(&dir).context("remove symlink temp dir")?;
                anyhow::ensure!(
                    env::var_os("RMCP_REQUIRE_SYMLINK_TESTS").as_deref()
                        != Some(std::ffi::OsStr::new("1")),
                    "creating a file symlink needs SeCreateSymbolicLinkPrivilege or Windows Developer Mode, and RMCP_REQUIRE_SYMLINK_TESTS=1 forbids skipping this test"
                );
                return Ok(());
            }
            return Err(error).context("create file symlink fixture");
        }

        let config = observability_config(Some(link_path.clone()));
        let err = prepare_tracing_audit_strict(&config)
            .err()
            .context("a symlinked audit path must fail closed with Startup")?;
        let msg = err.to_string();
        assert!(
            msg.contains("reparse point"),
            "error must name the reparse-point rejection; got {msg:?}"
        );

        let contents = fs::read(&target_path).context("read symlink target contents")?;
        assert_eq!(
            contents, b"pre-existing target contents\n",
            "the symlink target file's contents must be unchanged"
        );
        assert!(
            link_path.exists(),
            "the symlink itself must still exist after the rejection"
        );
        assert!(
            target_path.exists(),
            "the symlink target file must still exist after the rejection"
        );

        fs::remove_dir_all(&dir).context("remove symlink temp dir")?;

        Ok(())
    }

    #[test]
    #[cfg(not(any(unix, windows)))]
    /// Pins that strict init refuses audit logging where owner-only access is unguaranteed.
    fn strict_init_refuses_audit_log_without_private_permissions() -> anyhow::Result<()> {
        let dir = unique_temp_path("audit-unsupported")?;
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));

        let err = prepare_tracing_audit_strict(&config)
            .err()
            .context("audit logging must fail closed where owner-only access is unguaranteed")?;
        let msg = err.to_string();
        assert!(
            msg.contains("private permissions are unsupported"),
            "error must explain why auditing was refused; got {msg:?}"
        );
        assert!(
            !audit_path.exists(),
            "the audit file must NOT be created when its permissions cannot be guaranteed"
        );

        Ok(())
    }

    #[test]
    #[cfg(not(any(unix, windows)))]
    /// Pins that lenient init warns and installs no audit sink where permissions are unsupported.
    fn lenient_init_warns_and_installs_no_audit_sink() -> anyhow::Result<()> {
        let dir = unique_temp_path("audit-lenient")?;
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));

        let setup = prepare_tracing_audit_lenient(&config);
        assert!(
            setup.writer.is_none(),
            "no audit sink may be installed when permissions cannot be guaranteed"
        );
        assert!(
            setup
                .warnings
                .iter()
                .any(|warning| warning.contains("private permissions are unsupported")),
            "lenient init must warn rather than fail silently; got {:?}",
            setup.warnings
        );
        assert!(!audit_path.exists(), "no audit file may be created");

        Ok(())
    }

    /// Builds a unique temp path for a fixture, failing on a pre-epoch system clock.
    fn unique_temp_path(label: &str) -> anyhow::Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time is after Unix epoch")?
            .as_nanos();
        Ok(env::temp_dir().join(format!("rmcp-server-kit-{label}-{}-{nanos}", process::id())))
    }

    // -----------------------------------------------------------------
    // Guard against `\"`-escaping in JSON log output (WO-T2).
    //
    // With JSON logging (`.json()`, wired above in this module), a field
    // recorded with the Debug sigil (`?`) is rendered via `format!("{:?}")`
    // and then embedded in a JSON string; if the Debug output itself
    // contains quotes, the JSON serializer escapes them -
    // `"request_id":"String(\"abc-123\")"` instead of
    // `"request_id":"abc-123"`. This is a heuristic TRIPWIRE modelled on
    // `crate::error`'s guard, not a proof: it enforces two syntactic rules
    // and does not attempt data-flow analysis.
    // -----------------------------------------------------------------

    /// Drop comment lines and everything from a `#[cfg(test)]`-annotated
    /// `mod tests` or `pub(crate) mod tests` onward. Mirrors `crate::error`'s guard.
    fn production_source(src: &str) -> String {
        let lines: Vec<&str> = src.lines().collect();
        let mut out = String::with_capacity(src.len());
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed == "#[cfg(test)]"
                && lines
                    .get(index.saturating_add(1))
                    .is_some_and(|following_line| {
                        let declaration = following_line.trim_start();
                        declaration.starts_with("mod tests")
                            || declaration.starts_with("pub(crate) mod tests")
                    })
            {
                break;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Index of the `)` matching the `(` at byte offset `open`, respecting
    /// nested delimiters and string literals so a `)` or `,` inside a
    /// message string cannot confuse the scan.
    fn find_matching_paren(text: &str, open: usize) -> Option<usize> {
        let mut depth = 0_i32;
        let mut in_string = false;
        let mut escape = false;
        for (index, character) in text.get(open..)?.char_indices() {
            if in_string {
                if escape {
                    escape = false;
                } else if character == '\\' {
                    escape = true;
                } else {
                    in_string = character != '"';
                }
                continue;
            }
            match character {
                '"' => in_string = true,
                '(' => depth = depth.saturating_add(1_i32),
                ')' => {
                    depth = depth.saturating_sub(1_i32);
                    if depth == 0_i32 {
                        return Some(open.saturating_add(index));
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Split a macro argument list on top-level commas, respecting nested
    /// delimiters and string literals.
    fn split_top_level_args(args: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut depth = 0_i32;
        let mut in_string = false;
        let mut escape = false;
        let mut start = 0_usize;
        for (index, character) in args.char_indices() {
            if in_string {
                if escape {
                    escape = false;
                } else if character == '\\' {
                    escape = true;
                } else {
                    in_string = character != '"';
                }
                continue;
            }
            match character {
                '"' => in_string = true,
                '(' | '[' | '{' => depth = depth.saturating_add(1_i32),
                ')' | ']' | '}' => depth = depth.saturating_sub(1_i32),
                ',' if depth == 0_i32 => {
                    out.push(args.get(start..index).unwrap_or_default().trim());
                    start = index.saturating_add(1);
                }
                _ => {}
            }
        }
        let tail = args.get(start..).unwrap_or_default().trim();
        if !tail.is_empty() {
            out.push(tail);
        }
        out
    }

    /// Whether `ident` is a plain ASCII identifier, i.e. `[A-Za-z_][A-Za-z0-9_]*`.
    fn is_plain_identifier(ident: &str) -> bool {
        let mut chars = ident.chars();
        matches!(chars.next(), Some(letter) if letter.is_ascii_alphabetic() || letter == '_')
            && chars.all(|letter| letter.is_ascii_alphanumeric() || letter == '_')
    }

    /// Rule A: a `format!(...)` format string that is *only* a single Debug
    /// placeholder (`"{:?}"` or `"{value:?}"`) - unconditional
    /// Debug-stringification with no surrounding human-readable text.
    #[expect(
        clippy::literal_string_with_formatting_args,
        reason = "comparing scanned source text against a literal pattern, not passing it to a formatting macro"
    )]
    fn is_bare_debug_format_string(unquoted: &str) -> bool {
        unquoted == "{:?}"
            || unquoted
                .strip_prefix('{')
                .and_then(|stripped| stripped.strip_suffix(":?}"))
                .is_some_and(is_plain_identifier)
    }

    /// Every production `format!(...)` call whose format string matches
    /// [`is_bare_debug_format_string`]. Scans `format!` invocations only -
    /// a `tracing::warn!("... {:?}", x)` message string is not this shape
    /// (see `rule_a_ignores...` below).
    fn find_bare_debug_format_calls(src: &str) -> Vec<String> {
        let scanned = production_source(src);
        let needle = "format!(";
        let mut hits = Vec::new();
        let mut from = 0_usize;
        while let Some(rel) = scanned
            .get(from..)
            .and_then(|haystack| haystack.find(needle))
        {
            let call_start = from.saturating_add(rel);
            let open = call_start.saturating_add(needle.len()).saturating_sub(1);
            let Some(close) = find_matching_paren(&scanned, open) else {
                break;
            };
            let args = scanned
                .get(open.saturating_add(1)..close)
                .unwrap_or_default();
            let first_arg = split_top_level_args(args).into_iter().next();
            if let Some(quoted) = first_arg
                && let Some(unquoted) = quoted
                    .strip_prefix('"')
                    .and_then(|stripped| stripped.strip_suffix('"'))
                && is_bare_debug_format_string(unquoted)
            {
                hits.push(scanned.get(call_start..=close).unwrap_or(quoted).to_owned());
            }
            from = close.saturating_add(1);
        }
        hits
    }

    /// Rule B: a Debug-sigil (`?`) structured field inside a
    /// `tracing::{trace,debug,info,warn,error}!` call, covering both
    /// `field = ?expr` and shorthand `?field`.
    fn is_debug_sigil_field(arg: &str) -> bool {
        if let Some(rest) = arg.strip_prefix('?') {
            return is_plain_identifier(rest);
        }
        let Some(eq) = arg.find('=') else {
            return false;
        };
        let is_bare_eq = arg.as_bytes().get(eq.saturating_add(1)) != Some(&b'=')
            && (eq == 0 || arg.as_bytes().get(eq.saturating_sub(1)) != Some(&b'='));
        is_bare_eq
            && is_plain_identifier(arg.get(..eq).unwrap_or_default().trim())
            && arg
                .get(eq.saturating_add(1)..)
                .unwrap_or_default()
                .trim_start()
                .starts_with('?')
    }

    const TRACING_MACROS: &[&str] = &[
        "tracing::trace!(",
        "tracing::debug!(",
        "tracing::info!(",
        "tracing::warn!(",
        "tracing::error!(",
    ];

    /// Every Debug-sigil structured field inside a production
    /// `tracing::*!` call, as raw field text (e.g. `"url = ?raw"`,
    /// `"?identity"`) for allowlist matching.
    fn find_debug_sigil_fields(src: &str) -> Vec<String> {
        let scanned = production_source(src);
        let mut hits = Vec::new();
        for macro_prefix in TRACING_MACROS {
            let mut from = 0_usize;
            while let Some(rel) = scanned
                .get(from..)
                .and_then(|haystack| haystack.find(macro_prefix))
            {
                let call_start = from.saturating_add(rel);
                let open = call_start
                    .saturating_add(macro_prefix.len())
                    .saturating_sub(1);
                let Some(close) = find_matching_paren(&scanned, open) else {
                    break;
                };
                let args = scanned
                    .get(open.saturating_add(1)..close)
                    .unwrap_or_default();
                for arg in split_top_level_args(args) {
                    if is_debug_sigil_field(arg) {
                        hits.push(arg.to_owned());
                    }
                }
                from = close.saturating_add(1);
            }
        }
        hits
    }

    /// Rule B allowlist: `(file path relative to the crate root, exact
    /// field-text needle, reason)`. Keyed by needle text rather than line
    /// number so it survives unrelated line drift elsewhere in the file.
    const RULE_B_ALLOWLIST: &[(&str, &str, &str)] = &[
        (
            "src/mtls_revocation.rs",
            "url = ?raw",
            "deliberate control-character escaping of attacker-supplied input - see the log-injection note at the call site",
        ),
        (
            "src/oauth.rs",
            "?alg",
            "unit-variant enum (JwtValidationFailure); Debug renders an unquoted identifier",
        ),
        (
            "src/oauth.rs",
            "?failure",
            "unit-variant enum (JwtValidationFailure); Debug renders an unquoted identifier",
        ),
        (
            "src/oauth.rs",
            "alg = ?header.alg",
            "unit-variant enum (jsonwebtoken::Algorithm); Debug renders an unquoted identifier",
        ),
        (
            "src/oauth.rs",
            "family = ?family",
            "unit-variant enum (JwkKeyFamily); Debug renders an unquoted identifier",
        ),
        (
            "src/transport.rs",
            "reason = ?reason",
            "unit-variant enum (FallbackReason); Debug renders an unquoted identifier",
        ),
    ];

    /// Whether `(file, needle)` appears in the Rule B allowlist.
    fn is_allowlisted(file: &str, needle: &str) -> bool {
        RULE_B_ALLOWLIST
            .iter()
            .any(|(entry_file, entry_needle, _)| *entry_file == file && *entry_needle == needle)
    }

    /// Walks every `src/*.rs` file, calling `visit` with its path and source, and returns the count.
    fn scan_production_src(mut visit: impl FnMut(&Path, &str)) -> anyhow::Result<usize> {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let entries = fs::read_dir(&src_dir).context("src/ is readable")?;
        let mut scanned_files = 0_usize;
        for entry in entries {
            let path = entry.context("dir entry")?.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let src = fs::read_to_string(&path).context("source file is readable")?;
            scanned_files = scanned_files.saturating_add(1);
            visit(&path, &src);
        }
        Ok(scanned_files)
    }

    #[test]
    /// Pins that no production `format!` unconditionally Debug-stringifies a value.
    fn production_source_has_no_bare_debug_format_calls() -> anyhow::Result<()> {
        let mut offenders: Vec<String> = Vec::new();
        let scanned_files = scan_production_src(|path, src| {
            for hit in find_bare_debug_format_calls(src) {
                offenders.push(format!("{}: {hit}", path.display()));
            }
        })?;
        assert!(
            scanned_files > 10,
            "guard scanned only {scanned_files} files; the walk is broken"
        );
        assert!(
            offenders.is_empty(),
            "production `format!(...)` must not unconditionally Debug-stringify a value with \
             no surrounding text - JSON logging escapes embedded quotes (e.g. \
             `\"request_id\":\"String(\\\"abc-123\\\")\"`). Use `.to_string()` on a `Display` \
             value instead:\n{}",
            offenders.join("\n")
        );

        Ok(())
    }

    #[test]
    /// Pins that no production tracing field uses the Debug sigil without allowlisting.
    fn production_source_has_no_unallowlisted_debug_sigil_tracing_fields() -> anyhow::Result<()> {
        let mut offenders: Vec<String> = Vec::new();
        let scanned_files = scan_production_src(|path, src| {
            let rel = path
                .file_name()
                .map(|name| format!("src/{}", name.to_string_lossy()))
                .unwrap_or_default();
            for hit in find_debug_sigil_fields(src) {
                if !is_allowlisted(&rel, &hit) {
                    offenders.push(format!("{rel}: {hit}"));
                }
            }
        })?;
        assert!(
            scanned_files > 10,
            "guard scanned only {scanned_files} files; the walk is broken"
        );
        assert!(
            offenders.is_empty(),
            "production tracing::{{trace,debug,info,warn,error}}! calls must not use the Debug \
             sigil (`?`) on a structured field unless explicitly allowlisted - JSON logging \
             escapes embedded quotes in the Debug rendering. Use `%` (Display) instead, or add \
             an entry to RULE_B_ALLOWLIST with a reason if Debug really is intended:\n{}",
            offenders.join("\n")
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::rule_a_detects_bare_debug_format_synthetic_violations keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    #[expect(
        clippy::literal_string_with_formatting_args,
        reason = "the format-shaped text is the fixture under test, not a format call"
    )]
    /// Pins that Rule A's matcher actually flags synthetic bare-Debug `format!` calls.
    fn rule_a_detects_bare_debug_format_synthetic_violations() -> anyhow::Result<()> {
        // Without this, a broken matcher would be indistinguishable from a
        // clean codebase and the guard would rot into a no-op.
        assert_eq!(
            find_bare_debug_format_calls("fn f() { let s = format!(\"{:?}\", value); }").len(),
            1
        );
        assert_eq!(
            find_bare_debug_format_calls("fn f() { let s = format!(\"{value:?}\"); }").len(),
            1
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::rule_a_ignores_debug_embedded_in_larger_text_and_tracing_message_strings keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    #[expect(
        clippy::literal_string_with_formatting_args,
        reason = "the format-shaped text is the fixture under test, not a format call"
    )]
    /// Pins that Rule A ignores Debug embedded in prose and tracing message strings.
    fn rule_a_ignores_debug_embedded_in_larger_text_and_tracing_message_strings()
    -> anyhow::Result<()> {
        // Diagnostic messages that embed Debug inside human-readable text
        // are outside this bug class - the quoting is often desirable
        // there (it delimits an untrusted value).
        assert_eq!(
            find_bare_debug_format_calls(
                "fn f() { let s = format!(\"invalid CRL DER: {error:?}\"); }"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            find_bare_debug_format_calls(
                "fn f() { let s = format!(\"CIDR {raw:?} missing '/' prefix length\"); }"
            ),
            Vec::<String>::new()
        );
        // `tracing::warn!("... {:?}", X)` is a message-text format, not a
        // structured field, and must not fire Rule A.
        assert_eq!(
            find_bare_debug_format_calls(
                "fn f() { tracing::warn!(\"shutting down (grace period: {timeout:?})\"); }"
            ),
            Vec::<String>::new()
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::rule_b_detects_debug_sigil_field_synthetic_violations keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that Rule B's matcher flags synthetic Debug-sigil tracing fields.
    fn rule_b_detects_debug_sigil_field_synthetic_violations() -> anyhow::Result<()> {
        assert_eq!(
            find_debug_sigil_fields("fn f() { tracing::warn!(allowed = ?value, \"x\"); }").len(),
            1
        );
        assert_eq!(
            find_debug_sigil_fields("fn f() { tracing::debug!(?identity, \"x\"); }").len(),
            1
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::rule_b_allows_display_sigil_and_bare_fields keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that Rule B ignores Display-sigil and bare (non-Debug) tracing fields.
    fn rule_b_allows_display_sigil_and_bare_fields() -> anyhow::Result<()> {
        assert_eq!(
            find_debug_sigil_fields(
                "fn f() { tracing::warn!(origin = logged, duplicate_origin_headers, %method, %path, \"x\"); }"
            ),
            Vec::<String>::new()
        );

        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/observability.rs::rule_b_ignores_comments_test_modules_and_try_operator keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that Rule B ignores comments, test modules, and the `?` operator.
    fn rule_b_ignores_comments_test_modules_and_try_operator() -> anyhow::Result<()> {
        let in_doc_comment = "/// BAD: tracing::debug!(?identity)\nfn f() {}";
        assert_eq!(
            find_debug_sigil_fields(in_doc_comment),
            Vec::<String>::new()
        );

        let in_test_module =
            "#[cfg(test)]\nmod tests {\n    fn t() { tracing::debug!(?identity, \"x\"); }\n}";
        assert_eq!(
            find_debug_sigil_fields(in_test_module),
            Vec::<String>::new()
        );

        let in_pub_crate_test_module =
            "#[cfg(test)]\npub(crate) mod tests { fn t() { tracing::debug!(?identity, \"x\"); } }";
        assert_eq!(
            find_debug_sigil_fields(in_pub_crate_test_module),
            Vec::<String>::new()
        );

        // The try operator `?` must never be confused for the Debug sigil:
        // it is always followed by a statement terminator or `.`, never
        // glued directly to an identifier, but this fixture pins that a
        // scan across a whole function body containing `?` finds nothing.
        let try_operator = "fn f() -> Option<()> { let _ = maybe_thing()?; Some(()) }";
        assert_eq!(find_debug_sigil_fields(try_operator), Vec::<String>::new());

        Ok(())
    }
}
