use std::{
    fmt,
    io::{self, Write as _},
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tracing_subscriber::{
    EnvFilter, Layer as _,
    fmt::time::FormatTime,
    layer::SubscriberExt,
    util::{SubscriberInitExt, TryInitError},
};

use crate::{config::ObservabilityConfig, error::RmcpServerKitError};

const AUDIT_LOG_CHANNEL_CAPACITY: usize = 1024;
const AUDIT_WRITER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const AUDIT_WRITER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const AUDIT_WRITER_JOIN_POLL: Duration = Duration::from_millis(10);
const AUDIT_IO_FAILURE_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Timestamp formatter that emits local time via `chrono::Local`.
#[derive(Clone, Copy)]
struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
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
/// fail-open audit-log behaviour for source compatibility: audit setup errors
/// are logged as warnings after subscriber initialization succeeds.
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
pub fn init_tracing_from_config(config: &ObservabilityConfig) -> Result<(), TryInitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let audit_setup = prepare_tracing_audit_lenient(config);

    // "pretty" and "text" are aliases for human-readable output.
    let result = if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(LocalTime)
                .with_writer(io::stderr),
        );
        init_with_optional_audit(subscriber, audit_setup.writer)
    } else {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(io::stderr),
        );
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
    audit: Option<AuditWorkerGuard>,
}

impl fmt::Debug for TracingGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracingGuard")
            .field("audit_enabled", &self.audit.is_some())
            .finish()
    }
}

impl TracingGuard {
    const fn none() -> Self {
        Self { audit: None }
    }

    const fn audit(audit: AuditWorkerGuard) -> Self {
        Self { audit: Some(audit) }
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        let _ = self.audit.take();
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
/// subscriber installation fails.
pub fn init_tracing_from_config_strict(
    config: &ObservabilityConfig,
) -> Result<TracingGuard, RmcpServerKitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    let audit_setup = prepare_tracing_audit_strict(config)?;

    // "pretty" and "text" are aliases for human-readable output.
    let result = if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(LocalTime)
                .with_writer(io::stderr),
        );
        init_with_optional_audit(subscriber, audit_setup.writer)
    } else {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(io::stderr),
        );
        init_with_optional_audit(subscriber, audit_setup.writer)
    };

    result.map_err(|error| {
        RmcpServerKitError::Startup(format!("failed to initialize tracing subscriber: {error}"))
    })?;

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
fn init_with_optional_audit<S>(
    subscriber: S,
    audit_writer: Option<AuditFile>,
) -> Result<(), TryInitError>
where
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync
        + 'static,
{
    if let Some(writer) = audit_writer {
        subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(LocalTime)
                    .with_writer(writer)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
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
pub fn init_tracing(default_filter: &str) -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)))
        .with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(io::stderr),
        )
        .try_init()
}

/// Newtype wrapper around a non-blocking audit writer channel.
///
/// Implements `MakeWriter` so it can be used with `tracing_subscriber::fmt`.
#[derive(Clone)]
struct AuditFile {
    sender: SyncSender<AuditMessage>,
    dropped: Arc<AtomicU64>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AuditFile {
    type Writer = AuditFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        AuditFileWriter {
            sender: self.sender.clone(),
            dropped: Arc::clone(&self.dropped),
        }
    }
}

/// A non-blocking audit writer handle used directly at tracing call sites.
struct AuditFileWriter {
    sender: SyncSender<AuditMessage>,
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
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.sender.try_send(AuditMessage::Flush);
        Ok(())
    }
}

enum AuditMessage {
    Write(Vec<u8>),
    Flush,
}

struct AuditWorkerGuard {
    shutdown: Arc<AtomicBool>,
    wake_sender: SyncSender<AuditMessage>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for AuditWorkerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_sender.try_send(AuditMessage::Flush);

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
        let _ = thread.join();
    }
}

struct AuditWorker<W> {
    file: W,
    receiver: Receiver<AuditMessage>,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    io_failures: Arc<AtomicU64>,
    last_io_failure_warning: Option<Instant>,
}

impl<W> AuditWorker<W>
where
    W: io::Write,
{
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

    fn record_io_failure(&mut self, operation: &'static str, error: &io::Error) {
        let failure_count = self.io_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if self.io_failure_warning_due(Instant::now()) {
            write_audit_io_failure_warning(operation, failure_count, error);
        }
    }

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

#[allow(
    clippy::print_stderr,
    reason = "audit writer failure reporting deliberately uses process stderr as the last-resort sink; routing through tracing would recurse into the failing audit writer"
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
    let _ = writeln!(
        stderr,
        "rmcp-server-kit audit log {operation} failed; failures_total={failure_count}; error={representative_error}"
    );
}

struct AuditSetup {
    writer: Option<AuditFile>,
    guard: TracingGuard,
    warnings: Vec<String>,
}

impl AuditSetup {
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
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(format!(
            "failed to create audit log directory {}: {e}",
            parent.display()
        ));
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("failed to open audit log file {}: {e}", path.display()))?;

    let warnings = audit_file_permission_warnings(&file);

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
        .map_err(|e| {
            format!(
                "failed to spawn audit log writer for {}: {e}",
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

fn prepare_tracing_audit_strict(
    config: &ObservabilityConfig,
) -> Result<AuditSetup, RmcpServerKitError> {
    match config.audit_log_path.as_deref() {
        Some(path) => open_audit_file(path).map_err(|error| {
            RmcpServerKitError::Startup(format!("audit log initialization failed: {error}"))
        }),
        None => Ok(AuditSetup::none()),
    }
}

fn prepare_tracing_audit_lenient(config: &ObservabilityConfig) -> AuditSetup {
    match config.audit_log_path.as_deref() {
        Some(path) => match open_audit_file(path) {
            Ok(setup) => setup,
            Err(warning) => AuditSetup {
                writer: None,
                guard: TracingGuard::none(),
                warnings: vec![warning],
            },
        },
        None => AuditSetup::none(),
    }
}

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

fn legacy_tracing_guards() -> &'static Mutex<Vec<TracingGuard>> {
    static GUARDS: OnceLock<Mutex<Vec<TracingGuard>>> = OnceLock::new();
    GUARDS.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(unix)]
fn audit_file_permission_warnings(file: &std::fs::File) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;

    let mut warnings = Vec::new();
    if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        warnings.push(format!("failed to set audit log permissions to 0o600: {e}"));
    }
    warnings
}

#[cfg(not(unix))]
fn audit_file_permission_warnings(_file: &std::fs::File) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "test-only relaxations; production code uses ? and tracing"
    )]
    use std::{
        io::Write as _,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use tracing_subscriber::{Layer as _, fmt::MakeWriter as _, layer::SubscriberExt as _};

    use super::{AuditMessage, AuditWorker, init_tracing, prepare_tracing_audit_strict};
    use crate::{config::ObservabilityConfig, error::RmcpServerKitError};

    struct FailingAuditSink;

    impl std::io::Write for FailingAuditSink {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected audit sink write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("injected audit sink flush failure"))
        }
    }

    #[test]
    fn config_format_valid() {
        let config = ObservabilityConfig {
            log_level: "debug".into(),
            log_format: "json".into(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
        };
        assert!(config.log_format == "json" || config.log_format == "pretty");
    }

    /// Calling either `init_tracing` entry point twice in the same process
    /// must NOT panic. The second (and any subsequent) call must return
    /// `Err(TryInitError)` instead. This guards against regressions of the
    /// pre-0.11 `.init()` behaviour, which aborted the process when a
    /// global subscriber was already installed (e.g. by a sibling test).
    ///
    /// All four call orderings are exercised in a single test because the
    /// global tracing subscriber is process-wide state - we cannot rely on
    /// test isolation here.
    #[test]
    fn init_tracing_double_init_returns_err_not_panic() {
        // First call: may succeed or fail depending on whether another
        // test in this binary already installed a subscriber. Either is
        // acceptable; we only require that it does not panic.
        let _ = init_tracing("info");

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
        };
        #[allow(
            deprecated,
            reason = "this regression test explicitly covers the legacy fail-open API"
        )]
        let third = super::init_tracing_from_config(&cfg);
        assert!(
            third.is_err(),
            "init_tracing_from_config must return Err once a global subscriber exists"
        );
    }

    #[test]
    fn strict_init_fails_when_audit_path_unopenable() {
        let root_file = unique_temp_path("audit-parent-file");
        std::fs::write(&root_file, b"not a directory").expect("create parent file fixture");
        let audit_path = root_file.join("audit.log");
        let config = observability_config(Some(audit_path));

        let result = prepare_tracing_audit_strict(&config);

        assert!(
            matches!(result, Err(RmcpServerKitError::Startup(_))),
            "unopenable audit path must fail closed with Startup"
        );
        std::fs::remove_file(&root_file).expect("remove parent file fixture");
    }

    #[test]
    fn strict_init_succeeds_and_writes_audit_line() {
        let dir = unique_temp_path("audit-dir");
        let audit_path = dir.join("audit.log");
        let config = observability_config(Some(audit_path.clone()));
        let setup = prepare_tracing_audit_strict(&config).expect("strict audit setup succeeds");
        let writer = setup.writer.as_ref().expect("audit writer is configured");
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer.clone())
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(event = "phase3-test", "audit event");
            let mut sink = writer.make_writer();
            sink.flush().expect("enqueue flush");
        });
        drop(setup.guard);

        let contents = std::fs::read_to_string(&audit_path).expect("read flushed audit file");
        assert!(
            contents.contains("audit event"),
            "guard drop should drain this normal audit line before timeout; got {contents:?}"
        );
        std::fs::remove_dir_all(&dir).expect("remove audit temp dir");
    }

    #[test]
    fn audit_worker_counts_write_and_flush_failures_without_panicking() {
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
    }

    #[test]
    fn audit_worker_io_failure_warning_is_time_throttled() {
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
    }

    #[test]
    fn strict_init_succeeds_with_no_audit_path() {
        let config = observability_config(None);

        let setup = prepare_tracing_audit_strict(&config).expect("no audit path needs no file I/O");

        assert!(
            setup.writer.is_none(),
            "no audit path should install no audit writer"
        );
    }

    fn observability_config(audit_log_path: Option<PathBuf>) -> ObservabilityConfig {
        ObservabilityConfig {
            log_level: "info".into(),
            log_format: "pretty".into(),
            audit_log_path,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rmcp-server-kit-{label}-{}-{nanos}",
            std::process::id()
        ))
    }
}
