//! Structural guard: our delegating wrappers vs the upstream `ServerHandler` surface.
//!
//! rmcp gives every `ServerHandler` method a default body, so dropping a
//! delegation compiles silently and only shows up as a behaviour difference at
//! runtime: the trait default shadows an inner handler's override. This guard
//! reads the trait surface straight from the rmcp source pinned in `Cargo.lock`
//! (no new dependencies) and asserts that both wrappers classify every upstream
//! method as one of:
//!
//! - `DIRECTLY_DELEGATED` - the wrapper forwards to the inner handler unchanged.
//! - `BEHAVIORAL_WRAPPED` - the wrapper adds behaviour (hooks, result-size cap,
//!   identity scoping, task-ID binding, tool-list filtering) around the inner call.
//! - `INTENTIONALLY_DEFAULTED` - deliberately left to the upstream default.
//!
//! It fails loudly when rmcp adds, removes, or renames a method, when a name is
//! classified twice, or when a set lists a method rmcp does not have.
//!
//! It does NOT prove the wrapper impl actually contains the delegation (a
//! default trait body makes that unobservable at compile time). Direct-call
//! transparency tests in `src/tool_hooks.rs` and `src/rbac_context.rs` cover the
//! negotiation entry point; extend them when adding coverage here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "a drift guard must fail loudly; panicking is the failure mode. \
              Every slice here is taken at a byte offset produced by `str::find` \
              on an ASCII delimiter, by the ASCII brace scan, or by the byte \
              length of an extracted ASCII identifier, so it always lands on a \
              char boundary"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

/// `ServerHandler` method count in the rmcp version `Cargo.lock` pins. Bump
/// together with an rmcp upgrade, after reviewing the upstream diff and
/// updating both wrappers.
const EXPECTED_UPSTREAM_METHOD_COUNT: usize = 29;

/// `HookedHandler`: every method except `call_tool` forwards unchanged.
const HOOKED_HANDLER_DIRECTLY_DELEGATED: &[&str] = &[
    "ping",
    "initialize",
    "negotiate_initialize",
    "supported_protocol_versions",
    "discover",
    "complete",
    "set_level",
    "get_prompt",
    "list_prompts",
    "list_resources",
    "list_resource_templates",
    "read_resource",
    "accepted_subscription_filter",
    "listen",
    "subscribe",
    "unsubscribe",
    "list_tools",
    "get_tool",
    "on_custom_request",
    "on_cancelled",
    "on_progress",
    "on_initialized",
    "on_roots_list_changed",
    "on_custom_notification",
    "get_info",
    "get_task",
    "update_task",
    "cancel_task",
];

/// `HookedHandler::call_tool` runs before/after hooks and enforces the
/// result-size cap around the inner call.
const HOOKED_HANDLER_BEHAVIORAL_WRAPPED: &[&str] = &["call_tool"];

const HOOKED_HANDLER_INTENTIONALLY_DEFAULTED: &[&str] = &[];

/// `RbacContextHandler`: methods that carry neither an identity to scope nor a
/// task ID to bind.
const RBAC_CONTEXT_HANDLER_DIRECTLY_DELEGATED: &[&str] = &[
    "supported_protocol_versions",
    "accepted_subscription_filter",
    "get_tool",
    "get_info",
    "negotiate_initialize",
];

/// Everything else scopes the request/notification identity, binds task IDs
/// (`get_task` / `update_task` / `cancel_task`), or filters tool lists.
const RBAC_CONTEXT_HANDLER_BEHAVIORAL_WRAPPED: &[&str] = &[
    "ping",
    "initialize",
    "discover",
    "complete",
    "set_level",
    "get_prompt",
    "list_prompts",
    "list_resources",
    "list_resource_templates",
    "read_resource",
    "listen",
    "subscribe",
    "unsubscribe",
    "call_tool",
    "list_tools",
    "on_custom_request",
    "on_cancelled",
    "on_progress",
    "on_initialized",
    "on_roots_list_changed",
    "on_custom_notification",
    "get_task",
    "update_task",
    "cancel_task",
];

const RBAC_CONTEXT_HANDLER_INTENTIONALLY_DEFAULTED: &[&str] = &[];

/// `HookedHandler`'s production `ServerHandler` impl lives here
/// (crate-root-relative).
const HOOKED_HANDLER_SOURCE: &str = "src/tool_hooks.rs";

/// `RbacContextHandler`'s production `ServerHandler` impl lives here
/// (crate-root-relative).
const RBAC_CONTEXT_HANDLER_SOURCE: &str = "src/rbac_context.rs";

/// Column-0 anchor for the production `HookedHandler` impl. Deliberately the
/// full generic form: the `#[cfg(test)]` modules in the same file contain decoy
/// `impl ServerHandler for ...` blocks that are indented and non-generic.
const HOOKED_HANDLER_IMPL_ANCHOR: &str =
    "impl<H: ServerHandler> ServerHandler for HookedHandler<H> {";

/// Column-0 anchor for the production `RbacContextHandler` impl (same reasoning
/// as [`HOOKED_HANDLER_IMPL_ANCHOR`]).
const RBAC_CONTEXT_HANDLER_IMPL_ANCHOR: &str =
    "impl<H: ServerHandler> ServerHandler for RbacContextHandler<H> {";

/// Methods the `HookedHandler` impl defines (all literal `fn` declarations).
const HOOKED_HANDLER_IMPL_METHOD_COUNT: usize = 29;

/// Methods the `RbacContextHandler` impl defines: 17 literal `fn` declarations
/// plus 12 `delegate_request!` / `delegate_notification!` invocations.
const RBAC_CONTEXT_HANDLER_IMPL_METHOD_COUNT: usize = 29;

#[test]
fn hooked_handler_coverage_matches_upstream_surface() {
    assert_coverage(
        "HookedHandler",
        HOOKED_HANDLER_DIRECTLY_DELEGATED,
        HOOKED_HANDLER_BEHAVIORAL_WRAPPED,
        HOOKED_HANDLER_INTENTIONALLY_DEFAULTED,
    );
    assert_impl_coverage(
        "HookedHandler",
        HOOKED_HANDLER_SOURCE,
        HOOKED_HANDLER_IMPL_ANCHOR,
        HOOKED_HANDLER_IMPL_METHOD_COUNT,
        HOOKED_HANDLER_DIRECTLY_DELEGATED,
        HOOKED_HANDLER_BEHAVIORAL_WRAPPED,
        HOOKED_HANDLER_INTENTIONALLY_DEFAULTED,
    );
}

#[test]
fn rbac_context_handler_coverage_matches_upstream_surface() {
    assert_coverage(
        "RbacContextHandler",
        RBAC_CONTEXT_HANDLER_DIRECTLY_DELEGATED,
        RBAC_CONTEXT_HANDLER_BEHAVIORAL_WRAPPED,
        RBAC_CONTEXT_HANDLER_INTENTIONALLY_DEFAULTED,
    );
    assert_impl_coverage(
        "RbacContextHandler",
        RBAC_CONTEXT_HANDLER_SOURCE,
        RBAC_CONTEXT_HANDLER_IMPL_ANCHOR,
        RBAC_CONTEXT_HANDLER_IMPL_METHOD_COUNT,
        RBAC_CONTEXT_HANDLER_DIRECTLY_DELEGATED,
        RBAC_CONTEXT_HANDLER_BEHAVIORAL_WRAPPED,
        RBAC_CONTEXT_HANDLER_INTENTIONALLY_DEFAULTED,
    );
}

fn assert_coverage(
    wrapper: &str,
    directly_delegated: &[&str],
    behavioral_wrapped: &[&str],
    intentionally_defaulted: &[&str],
) {
    let upstream = upstream_server_handler_methods();

    let direct: BTreeSet<&str> = directly_delegated.iter().copied().collect();
    let behavioral: BTreeSet<&str> = behavioral_wrapped.iter().copied().collect();
    let defaulted: BTreeSet<&str> = intentionally_defaulted.iter().copied().collect();

    assert_eq!(
        direct.len(),
        directly_delegated.len(),
        "{wrapper}: duplicate name in DIRECTLY_DELEGATED"
    );
    assert_eq!(
        behavioral.len(),
        behavioral_wrapped.len(),
        "{wrapper}: duplicate name in BEHAVIORAL_WRAPPED"
    );
    assert_eq!(
        defaulted.len(),
        intentionally_defaulted.len(),
        "{wrapper}: duplicate name in INTENTIONALLY_DEFAULTED"
    );

    assert!(
        direct.is_disjoint(&behavioral),
        "{wrapper}: DIRECTLY_DELEGATED and BEHAVIORAL_WRAPPED overlap: {:?}",
        direct.intersection(&behavioral).collect::<Vec<_>>()
    );
    assert!(
        direct.is_disjoint(&defaulted),
        "{wrapper}: DIRECTLY_DELEGATED and INTENTIONALLY_DEFAULTED overlap: {:?}",
        direct.intersection(&defaulted).collect::<Vec<_>>()
    );
    assert!(
        behavioral.is_disjoint(&defaulted),
        "{wrapper}: BEHAVIORAL_WRAPPED and INTENTIONALLY_DEFAULTED overlap: {:?}",
        behavioral.intersection(&defaulted).collect::<Vec<_>>()
    );
    assert!(
        defaulted.is_empty(),
        "{wrapper}: INTENTIONALLY_DEFAULTED must stay empty; found {defaulted:?}. \
         Leaving a method to rmcp's default is a deliberate decision: relax this \
         assertion and record why, rather than adding names here."
    );

    let union: BTreeSet<&str> = direct
        .union(&behavioral)
        .copied()
        .chain(defaulted.iter().copied())
        .collect();
    let upstream_names: BTreeSet<&str> = upstream.iter().map(String::as_str).collect();

    let missing: Vec<&str> = upstream_names.difference(&union).copied().collect();
    let unknown: Vec<&str> = union.difference(&upstream_names).copied().collect();

    assert!(
        missing.is_empty() && unknown.is_empty(),
        "{wrapper}: coverage does not match rmcp's `ServerHandler` surface. \
         Missing from both sets: {missing:?}; not an rmcp method: {unknown:?}. \
         After an rmcp upgrade, review the upstream diff, add the delegations, then \
         update the coverage lists and EXPECTED_UPSTREAM_METHOD_COUNT."
    );
}

/// Extract the `ServerHandler` method names from the `server_handler_methods!`
/// macro body in the rmcp source `Cargo.lock` pins.
///
/// The trait itself only invokes the macro, so the method surface lives in the
/// macro's `() => { ... }` arm; method names are the `fn <name>(` declarations
/// that are not part of a doc comment or attribute.
fn upstream_server_handler_methods() -> Vec<String> {
    let source_path = rmcp_source_path();
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));

    let macro_at = source
        .find("macro_rules! server_handler_methods")
        .unwrap_or_else(|| {
            panic!(
                "{}: `server_handler_methods!` macro not found -- rmcp restructured \
             `ServerHandler`; update this guard",
                source_path.display()
            )
        });
    let Some(arm_offset) = source[macro_at..].find("() => {") else {
        panic!(
            "{}: no `() => {{` arm after `macro_rules! server_handler_methods`",
            source_path.display()
        );
    };
    let arm_at = macro_at + arm_offset;

    let Some(open_offset) = source[arm_at..].find('{') else {
        panic!("{}: macro arm has no body brace", source_path.display());
    };
    let open = arm_at + open_offset;

    // Brace-depth scan from the arm's opening brace. Doc-comment code fences
    // inside the arm are brace-balanced, so a byte-level scan lands on the arm's
    // true closing brace.
    let mut depth = 0usize;
    let mut body_end = None;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    body_end = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let body_end = body_end.unwrap_or_else(|| {
        panic!(
            "{}: unbalanced braces while scanning the macro body",
            source_path.display()
        )
    });
    let body = &source[open + 1..body_end];

    let mut names = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") || trimmed.starts_with("#[") {
            continue;
        }
        let trimmed = trimmed.strip_prefix("async ").unwrap_or(trimmed);
        let Some(rest) = trimmed.strip_prefix("fn ") else {
            continue;
        };
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if !name.is_empty() && rest[name.len()..].trim_start().starts_with('(') {
            names.push(name);
        }
    }

    assert!(
        !names.is_empty(),
        "{}: macro parse matched zero methods -- inspect the rmcp source layout \
         and this parser (silently skipping would recreate the drift it guards against)",
        source_path.display()
    );
    assert_eq!(
        names.len(),
        EXPECTED_UPSTREAM_METHOD_COUNT,
        "rmcp's `ServerHandler` surface changed ({} methods, expected {}): {names:?}. \
         Review the upstream diff, add/remove delegations in HookedHandler and \
         RbacContextHandler, then update the coverage lists in this file and \
         EXPECTED_UPSTREAM_METHOD_COUNT.",
        names.len(),
        EXPECTED_UPSTREAM_METHOD_COUNT
    );

    names
}

/// Locate rmcp's `src/handler/server.rs` for the version `Cargo.lock` pins.
///
/// `RMCP_SRC_DIR` (the rmcp crate root, i.e. the directory containing its
/// `Cargo.toml`) overrides the registry search for atypical layouts.
fn rmcp_source_path() -> PathBuf {
    if let Ok(dir) = env::var("RMCP_SRC_DIR") {
        let candidate = Path::new(&dir)
            .join("src")
            .join("handler")
            .join("server.rs");
        assert!(
            candidate.is_file(),
            "RMCP_SRC_DIR={dir} does not contain src/handler/server.rs"
        );
        return candidate;
    }

    let version = rmcp_version_from_lockfile();
    let registry_src = Path::new("registry").join("src");
    let mut registry_roots = Vec::new();
    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        registry_roots.push(PathBuf::from(cargo_home).join(&registry_src));
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        registry_roots.push(
            PathBuf::from(user_profile)
                .join(".cargo")
                .join(&registry_src),
        );
    }
    if let Ok(home) = env::var("HOME") {
        registry_roots.push(PathBuf::from(home).join(".cargo").join(&registry_src));
    }

    for root in &registry_roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry
                .path()
                .join(format!("rmcp-{version}"))
                .join("src")
                .join("handler")
                .join("server.rs");
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    panic!(
        "could not locate rmcp-{version} sources under {registry_roots:?}; set \
         RMCP_SRC_DIR to the rmcp crate root, or run `cargo fetch` to populate \
         the registry"
    );
}

/// Read the pinned rmcp version from the workspace `Cargo.lock`.
fn rmcp_version_from_lockfile() -> String {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let lock = fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", lock_path.display()));

    let mut in_rmcp_package = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_rmcp_package = false;
        } else if line == "name = \"rmcp\"" {
            in_rmcp_package = true;
        } else if in_rmcp_package && let Some(version) = line.strip_prefix("version = \"") {
            return version.trim_end_matches('"').to_owned();
        }
    }

    panic!("no `rmcp` package entry in {}", lock_path.display());
}

/// Assert the wrapper impl *contains* a method for every classified name, and
/// nothing beyond the classification.
///
/// This is presence, not semantic proof: a body could still fail to forward to
/// the inner handler, which rmcp's default bodies make unobservable at compile
/// time. Semantic coverage stays with the direct-call probes in
/// `src/tool_hooks.rs` and `src/rbac_context.rs`.
fn assert_impl_coverage(
    wrapper: &str,
    source_rel: &str,
    impl_anchor: &str,
    expected_impl_method_count: usize,
    directly_delegated: &[&str],
    behavioral_wrapped: &[&str],
    intentionally_defaulted: &[&str],
) {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(source_rel);
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));

    let found = wrapper_impl_methods(&source, source_rel, impl_anchor);

    // `INTENTIONALLY_DEFAULTED` is deliberately not part of `classified`: a
    // defaulted method that the impl defines fails as unclassified below, and
    // the explicit loop gives that case its own message.
    let classified: BTreeSet<&str> = directly_delegated
        .iter()
        .chain(behavioral_wrapped.iter())
        .copied()
        .collect();

    let missing: Vec<&str> = classified
        .iter()
        .copied()
        .filter(|name| !found.contains(*name))
        .collect();
    let unclassified: Vec<&str> = found
        .iter()
        .filter(|name| !classified.contains(name.as_str()))
        .map(String::as_str)
        .collect();

    assert!(
        missing.is_empty() && unclassified.is_empty(),
        "{wrapper}: the impl in {source_rel} does not match the classification. \
         Classified but with no method in the impl: {missing:?}; methods in the \
         impl that are not classified: {unclassified:?}. Fix the impl (or the \
         scanner) first; only change the classification when the wrapper \
         genuinely changed."
    );

    for name in intentionally_defaulted {
        assert!(
            !found.contains(*name),
            "{wrapper}: `{name}` is classified INTENTIONALLY_DEFAULTED but \
             {source_rel} defines it; classify it instead of leaving it defaulted"
        );
    }

    assert_eq!(
        found.len(),
        expected_impl_method_count,
        "{wrapper}: impl scan found {} methods in {source_rel}, expected {}. \
         Either the wrapper genuinely changed (update the count) or the scanner \
         mis-scoped (fix the scanner -- do not weaken these assertions).",
        found.len(),
        expected_impl_method_count
    );
}

/// Collect the method names the anchored wrapper impl contains.
///
/// Scoped strictly inside the impl body (so the `macro_rules!` definitions and
/// the test-module decoys elsewhere in the file cannot contribute), the scan
/// takes literal `fn` / `async fn` declarations and the first argument of
/// `delegate_request!(` / `delegate_notification!(` invocations at brace depth
/// 1, and nothing else.
fn wrapper_impl_methods(source: &str, source_rel: &str, impl_anchor: &str) -> BTreeSet<String> {
    let occurrences = source.matches(impl_anchor).count();
    assert_eq!(
        occurrences, 1,
        "{source_rel}: expected exactly one `{impl_anchor}`; found {occurrences}. \
         The wrapper impl moved, was duplicated, or a decoy impl was added."
    );

    let anchor_at = source
        .find(impl_anchor)
        .unwrap_or_else(|| panic!("{source_rel}: impl anchor `{impl_anchor}` not found"));
    let Some(open_offset) = impl_anchor.rfind('{') else {
        panic!("{source_rel}: impl anchor `{impl_anchor}` must include the body-opening brace");
    };
    let body = balanced_body(source, anchor_at + open_offset);

    let mut names = BTreeSet::new();
    scan_impl_body(body, &mut names);
    names
}

/// Return the text between the braces of the block opening at byte index
/// `open` (`source.as_bytes()[open]` must be `{`).
fn balanced_body(source: &str, open: usize) -> &str {
    assert_eq!(
        source.as_bytes().get(open),
        Some(&b'{'),
        "balanced_body must start at an opening brace"
    );

    let mut depth = 0usize;
    let mut end = None;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }

    let end = end.unwrap_or_else(|| panic!("unbalanced braces from byte offset {open}"));
    &source[open + 1..end]
}

/// Walk the impl body line by line, collecting declarations at depth zero
/// relative to the body (absolute brace depth 1) and tracking depth across
/// lines so method bodies and nested items cannot contribute names.
fn scan_impl_body(body: &str, names: &mut BTreeSet<String>) {
    let mut depth = 0usize;
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        if depth == 0 {
            collect_declaration(&body[offset..], names);
        }
        let mut line_depth = depth;
        for byte in line.bytes() {
            match byte {
                b'{' => line_depth += 1,
                b'}' => line_depth = line_depth.saturating_sub(1),
                _ => {}
            }
        }
        depth = line_depth;
        offset += line.len();
    }
}

/// Collect the declaration the line at the start of `rest` introduces, if any:
/// a literal `fn` / `async fn` declaration, or a `delegate_request!(` /
/// `delegate_notification!(` invocation.
///
/// Doc-comment and attribute lines are skipped. Macro invocations may put their
/// first argument on a later line, so the identifier is read from the source
/// following the opening paren rather than from the current line; matching
/// includes the paren, which is what keeps a bare token mention in a comment
/// from registering as an invocation.
fn collect_declaration(rest: &str, names: &mut BTreeSet<String>) {
    let trimmed = rest.trim_start();
    if trimmed.starts_with("///") || trimmed.starts_with("#[") {
        return;
    }

    let after_async = trimmed.strip_prefix("async ").unwrap_or(trimmed);
    if let Some(after_fn) = after_async.strip_prefix("fn ") {
        insert_identifier(after_fn, names);
        return;
    }

    for macro_open in ["delegate_request!(", "delegate_notification!("] {
        if let Some(after_open) = trimmed.strip_prefix(macro_open) {
            insert_identifier(after_open, names);
            return;
        }
    }
}

/// Insert the leading identifier of `text` into `names`, after skipping
/// whitespace (which may include the newline separating a macro's opening paren
/// from its first argument).
fn insert_identifier(text: &str, names: &mut BTreeSet<String>) {
    let name: String = text
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    if !name.is_empty() {
        names.insert(name);
    }
}

// ---------------------------------------------------------------------------
// Semantic completeness and macro-origin gates
//
// The impl-presence guard above proves each wrapper *contains* a method; these
// gates prove every method is also *driven* by an in-crate semantic driver, and
// that the methods discharged by the three macro-body drivers are still
// macro-generated.
// ---------------------------------------------------------------------------

/// Methods with no possible semantic driver, per wrapper. Must stay empty: no
/// `ServerHandler` method is structurally unreachable -- each is drivable
/// through dispatch or a direct call. Legitimising an entry is a deliberate
/// code change: relax this assertion and record why, rather than adding names.
const HOOKED_HANDLER_SEMANTICALLY_UNPROVABLE: &[&str] = &[];

/// See [`HOOKED_HANDLER_SEMANTICALLY_UNPROVABLE`].
const RBAC_CONTEXT_HANDLER_SEMANTICALLY_UNPROVABLE: &[&str] = &[];

/// How a method becomes part of a wrapper impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodOrigin {
    /// A literal `fn` / `async fn` written out in the impl.
    LiteralFn,
    /// Generated by `delegate_request!($name, $params, $output)`.
    DelegateRequestPlainArm,
    /// Generated by `delegate_request!($name, Option<$params>, $output)`.
    DelegateRequestOptionArm,
    /// Generated by `delegate_notification!`.
    DelegateNotification,
}

/// Origin pins for the twelve `RbacContextHandler` methods the three
/// macro-body drivers discharge. If one of these becomes a literal `fn`, none
/// of those drivers covers it any more, so this gate fails until the method
/// gains its own semantic driver.
const RBAC_CONTEXT_HANDLER_MACRO_ORIGINS: &[(&str, MethodOrigin)] = &[
    ("complete", MethodOrigin::DelegateRequestPlainArm),
    ("set_level", MethodOrigin::DelegateRequestPlainArm),
    ("get_prompt", MethodOrigin::DelegateRequestPlainArm),
    ("read_resource", MethodOrigin::DelegateRequestPlainArm),
    ("subscribe", MethodOrigin::DelegateRequestPlainArm),
    ("unsubscribe", MethodOrigin::DelegateRequestPlainArm),
    ("on_custom_request", MethodOrigin::DelegateRequestPlainArm),
    ("list_prompts", MethodOrigin::DelegateRequestOptionArm),
    ("list_resources", MethodOrigin::DelegateRequestOptionArm),
    (
        "list_resource_templates",
        MethodOrigin::DelegateRequestOptionArm,
    ),
    ("on_cancelled", MethodOrigin::DelegateNotification),
    ("on_progress", MethodOrigin::DelegateNotification),
];

#[test]
fn hooked_handler_semantic_drivers_cover_the_classification() {
    assert_driver_table_complete(
        "HookedHandler",
        HOOKED_HANDLER_SOURCE,
        HOOKED_HANDLER_DIRECTLY_DELEGATED,
        HOOKED_HANDLER_BEHAVIORAL_WRAPPED,
        HOOKED_HANDLER_SEMANTICALLY_UNPROVABLE,
    );
}

#[test]
fn rbac_context_handler_semantic_drivers_and_macro_origins_hold() {
    assert_driver_table_complete(
        "RbacContextHandler",
        RBAC_CONTEXT_HANDLER_SOURCE,
        RBAC_CONTEXT_HANDLER_DIRECTLY_DELEGATED,
        RBAC_CONTEXT_HANDLER_BEHAVIORAL_WRAPPED,
        RBAC_CONTEXT_HANDLER_SEMANTICALLY_UNPROVABLE,
    );
    assert_macro_origins(
        "RbacContextHandler",
        RBAC_CONTEXT_HANDLER_SOURCE,
        RBAC_CONTEXT_HANDLER_IMPL_ANCHOR,
        RBAC_CONTEXT_HANDLER_MACRO_ORIGINS,
    );
}

/// Assert the in-crate `SEMANTIC_DRIVERS` table covers exactly the
/// classification (minus the explicitly enumerated unprovable set).
fn assert_driver_table_complete(
    wrapper: &str,
    source_rel: &str,
    directly_delegated: &[&str],
    behavioral_wrapped: &[&str],
    semantically_unprovable: &[&str],
) {
    assert!(
        semantically_unprovable.is_empty(),
        "{wrapper}: SEMANTICALLY_UNPROVABLE must stay empty; found \
         {semantically_unprovable:?}. No method is structurally unreachable -- every one \
         is drivable through dispatch or a direct call -- so legitimising an entry means \
         relaxing this assertion and recording why, not adding a name."
    );

    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(source_rel);
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
    let driven = driver_table_names(&source, source_rel);

    let expected: BTreeSet<&str> = directly_delegated
        .iter()
        .chain(behavioral_wrapped.iter())
        .copied()
        .collect();

    let missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|name| !driven.contains(*name))
        .collect();
    let unclassified: Vec<&str> = driven
        .iter()
        .filter(|name| !expected.contains(name.as_str()))
        .map(String::as_str)
        .collect();

    assert!(
        missing.is_empty() && unclassified.is_empty(),
        "{wrapper}: the SEMANTIC_DRIVERS table in {source_rel} does not cover the \
         classification. Classified but not driven: {missing:?}; driven but not \
         classified: {unclassified:?}. Add a driver (or a macro-origin pin) -- do not \
         relax this equality."
    );
}

/// Assert each pinned method still has the origin its macro-body driver assumes.
fn assert_macro_origins(
    wrapper: &str,
    source_rel: &str,
    impl_anchor: &str,
    pins: &[(&str, MethodOrigin)],
) {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(source_rel);
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
    let origins = wrapper_impl_origins(&source, source_rel, impl_anchor);

    let mismatched: Vec<String> = pins
        .iter()
        .filter(|(name, expected)| origins.get(*name) != Some(expected))
        .map(|(name, expected)| {
            format!(
                "{name}: pinned {expected:?}, impl has {:?}",
                origins.get(*name)
            )
        })
        .collect();

    assert!(
        mismatched.is_empty(),
        "{wrapper}: macro-origin pins no longer hold: {mismatched:?}. A method that became \
         a literal `fn` is no longer discharged by its shared macro-body driver -- give it \
         its own semantic driver, and change the pin only when the impl genuinely changed."
    );
}

/// Names listed in the in-crate `SEMANTIC_DRIVERS` table of `source_rel`.
///
/// Entries are `("name", "driver")`; rustfmt splits long ones across lines, so
/// the scan looks for the `("` opener anywhere rather than anchoring on line
/// starts.
fn driver_table_names(source: &str, source_rel: &str) -> BTreeSet<String> {
    const MARKER: &str = "const SEMANTIC_DRIVERS";

    let start = source
        .find(MARKER)
        .unwrap_or_else(|| panic!("{source_rel}: no `{MARKER}` table found"));
    let rest = &source[start..];
    let end = rest
        .find("\n    ];")
        .unwrap_or_else(|| panic!("{source_rel}: `SEMANTIC_DRIVERS` table is not terminated"));
    let table = &rest[..end];

    let mut names = BTreeSet::new();
    let mut search = table;
    while let Some(at) = search.find('(') {
        let after = &search[at + 1..];
        let after_ws = after.trim_start();
        if let Some(after_quote) = after_ws.strip_prefix('"') {
            let name = after_quote.split('"').next().unwrap_or_default();
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
            search = after_quote;
        } else {
            search = after;
        }
    }

    assert!(
        !names.is_empty(),
        "{source_rel}: `SEMANTIC_DRIVERS` parsed to zero names -- the table shape changed; \
         update this parser rather than relaxing the gate"
    );
    names
}

/// Classify every method in the anchored impl body by how it is written.
fn wrapper_impl_origins(
    source: &str,
    source_rel: &str,
    impl_anchor: &str,
) -> BTreeMap<String, MethodOrigin> {
    let anchor_at = source
        .find(impl_anchor)
        .unwrap_or_else(|| panic!("{source_rel}: impl anchor `{impl_anchor}` not found"));
    let Some(open_offset) = impl_anchor.rfind('{') else {
        panic!("{source_rel}: impl anchor `{impl_anchor}` must include the body-opening brace");
    };
    let body = balanced_body(source, anchor_at + open_offset);

    let mut origins = BTreeMap::new();
    let mut depth = 0usize;
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        if depth == 0 {
            collect_origin(&body[offset..], &mut origins);
        }
        let mut line_depth = depth;
        for byte in line.bytes() {
            match byte {
                b'{' => line_depth += 1,
                b'}' => line_depth = line_depth.saturating_sub(1),
                _ => {}
            }
        }
        depth = line_depth;
        offset += line.len();
    }
    origins
}

/// Classify the depth-1 declaration that opens the impl-body slice `rest`.
fn collect_origin(rest: &str, origins: &mut BTreeMap<String, MethodOrigin>) {
    let trimmed = rest.trim_start();
    if trimmed.starts_with("///") || trimmed.starts_with("#[") {
        return;
    }

    let after_async = trimmed.strip_prefix("async ").unwrap_or(trimmed);
    if let Some(after_fn) = after_async.strip_prefix("fn ") {
        let name = leading_identifier(after_fn);
        if !name.is_empty() {
            origins.insert(name, MethodOrigin::LiteralFn);
        }
        return;
    }

    let invocations: [(&str, Option<MethodOrigin>); 2] = [
        ("delegate_request!(", None),
        (
            "delegate_notification!(",
            Some(MethodOrigin::DelegateNotification),
        ),
    ];
    for (macro_open, pinned) in invocations {
        let Some(after_open) = trimmed.strip_prefix(macro_open) else {
            continue;
        };
        let (name, second_argument) = parse_macro_arguments(after_open);
        if name.is_empty() {
            return;
        }
        let origin = pinned.unwrap_or_else(|| {
            if second_argument.starts_with("Option") {
                MethodOrigin::DelegateRequestOptionArm
            } else {
                MethodOrigin::DelegateRequestPlainArm
            }
        });
        origins.insert(name, origin);
        return;
    }
}

/// The leading identifier of `text`, skipping whitespace (which may include the
/// newline separating a macro's opening paren from its first argument).
fn leading_identifier(text: &str) -> String {
    text.trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect()
}

/// The first two arguments of a delegation-macro invocation, starting after the
/// opening paren. Invocations may span lines, so this reads from the source
/// rather than from one line.
fn parse_macro_arguments(rest: &str) -> (String, String) {
    let after_open = rest.trim_start();
    let name: String = after_open
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    let after_name = &after_open[name.len()..];
    let after_comma = after_name
        .trim_start()
        .strip_prefix(',')
        .unwrap_or(after_name)
        .trim_start();
    let second: String = after_comma
        .chars()
        .take_while(|ch| !matches!(ch, ',' | ')'))
        .collect();
    (name, second.trim().to_owned())
}
