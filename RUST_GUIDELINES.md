# Rust Development Guidelines: DOs and DON'Ts

Comprehensive rules for writing idiomatic, performant, and defensive Rust code.
Synthesized from Rust Design Patterns, defensive programming patterns, and
production anti-patterns. Every rule has a rationale and a code example.

---

## 1. Ownership and Borrowing

### DO: Accept borrowed types in function arguments

Accept `&str` over `&String`, `&[T]` over `&Vec<T>`, `&T` over `&Box<T>`.
The borrowed type is strictly more flexible -- callers can pass owned or
borrowed data without conversion.

```rust
// BAD: Forces caller to have a String
fn process(name: &String) { /* ... */ }

// GOOD: Accepts &String, &str, string literals, slices
fn process(name: &str) { /* ... */ }
```

Same for slices:

```rust
// BAD
fn sum(values: &Vec<i32>) -> i32 { values.iter().sum() }

// GOOD
fn sum(values: &[i32]) -> i32 { values.iter().sum() }
```

### DO: Use `mem::take` / `mem::replace` instead of cloning owned values in enums

When you need to move a field out of a `&mut` reference, use `mem::take`
(if `Default` is implemented) or `mem::replace` to swap in a placeholder.

```rust
use std::mem;

// BAD: Clones the string unnecessarily
fn transform(e: &mut MyEnum) {
    if let MyEnum::A { name, .. } = e {
        *e = MyEnum::B { name: name.clone() };
    }
}

// GOOD: Moves the string out with zero allocation
fn transform(e: &mut MyEnum) {
    if let MyEnum::A { name, .. } = e {
        *e = MyEnum::B { name: mem::take(name) };
    }
}
```

### DO: Move ownership when the caller does not need the value afterward

If a function should own data, take it by value. Do not clone then pass.

```rust
// BAD
let copy = config.clone();
consume(copy);

// GOOD: Move if original is not used after
consume(config);
```

### DO: Return consumed arguments on error

When a fallible function takes ownership of an argument, return it inside the
error variant so the caller can retry without cloning.

```rust
pub struct SendError(pub String);

pub fn send(value: String) -> Result<(), SendError> {
    if fails() {
        return Err(SendError(value)); // Caller gets it back
    }
    Ok(())
}
```

### DO: Use `*_mut` insertion methods (Rust 1.95+)

`Vec::push_mut`, `Vec::insert_mut`, `VecDeque::push_{front,back}_mut`, and
`LinkedList::push_{front,back}_mut` return `&mut T` to the inserted element.
Prefer them over the two-step `push` + `last_mut().unwrap()` pattern, which
requires `unwrap`/`expect` that this workspace's `unwrap_used = "deny"`
rule forbids.

```rust
// BAD (requires unwrap):
v.push(x);
let last = v.last_mut().expect("just pushed");

// GOOD:
let last = v.push_mut(x);
```

### DON'T: Clone to satisfy the borrow checker

If the borrow checker rejects your code, the fix is almost never `.clone()`.
Restructure ownership, use borrowing, or decompose the struct.

```rust
// BAD: Cloning to dodge the borrow checker
let data = items.clone();
process(&items, data);

// GOOD: Borrow differently or restructure
process_refs(&items);
```

When `.clone()` IS acceptable:
- Cloning `Arc<T>` or `Rc<T>` (reference count bump, not deep copy)
- `Copy` types (`i32`, `bool`) -- these are cheap stack copies
- Rare, proven-necessary deep copies in non-hot paths
- Tests and prototypes

---

## 2. Error Handling

### DO: Propagate errors with `?`

Use the `?` operator to propagate errors. Define typed errors with `thiserror`
or use `anyhow` for application code.

```rust
// BAD
fn read_config(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}

// GOOD
fn read_config(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
```

### DO: Use `unwrap_or`, `unwrap_or_else`, `unwrap_or_default` for fallbacks

```rust
// BAD
let port = config.get("port").unwrap();

// GOOD
let port = config.get("port").unwrap_or(&"8080");
```

### DON'T: Use `unwrap()` / `expect()` in library code

These panic on failure, crashing the thread. Reserve them for:
- Tests (`#[cfg(test)]`)
- Proven invariants with a comment explaining why it cannot fail
- Prototypes that will be replaced

```rust
// BAD: Library code that panics
pub fn parse_port(s: &str) -> u16 {
    s.parse().expect("invalid port")
}

// GOOD: Return a Result
pub fn parse_port(s: &str) -> Result<u16, std::num::ParseIntError> {
    s.parse()
}
```

### DO: Use `TryFrom` when conversion can fail, not `From`

If your `From` impl contains `unwrap`, `expect`, or a default fallback for
error cases, it should be `TryFrom`.

```rust
// BAD: From that hides failure
impl From<&str> for Port {
    fn from(s: &str) -> Self {
        Port(s.parse().unwrap_or(8080))
    }
}

// GOOD: TryFrom makes fallibility explicit
impl TryFrom<&str> for Port {
    type Error = std::num::ParseIntError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Port(s.parse()?))
    }
}
```

---

## 3. Type Safety and Defensive Programming

### DO: Use the newtype pattern for domain types

Wrap primitive types to prevent mixing up semantically different values.
Zero-cost at runtime.

```rust
// BAD: Easy to swap arguments
fn transfer(from: u64, to: u64, amount: u64) {}

// GOOD: Compiler catches mistakes
struct AccountId(u64);
struct Amount(u64);
fn transfer(from: AccountId, to: AccountId, amount: Amount) {}
```

### DO: Force construction through validated constructors

Prevent invalid state by making struct fields private and requiring
construction through a `new()` that validates.

```rust
pub struct Port {
    value: u16,
    _private: (), // Prevents external struct literal construction
}

impl Port {
    pub fn new(value: u16) -> Result<Self, &'static str> {
        if value == 0 {
            return Err("port cannot be zero");
        }
        Ok(Self { value, _private: () })
    }

    pub fn value(&self) -> u16 { self.value }
}
```

For library crates, use `#[non_exhaustive]` to prevent external construction
and signal that fields may be added:

```rust
#[non_exhaustive]
pub struct Config {
    pub timeout: Duration,
    pub retries: u32,
}
```

### DO: Use `#[must_use]` on important return types

Prevents callers from accidentally ignoring results.

```rust
#[must_use = "config must be applied to take effect"]
pub struct Config { /* ... */ }

#[must_use]
pub fn validate(input: &str) -> Result<(), ValidationError> { /* ... */ }
```

### DO: Use enums instead of boolean parameters

Boolean parameters are unreadable at the call site and error-prone.

```rust
// BAD: What do these booleans mean?
process_data(&data, true, false, true);

// GOOD: Self-documenting
enum Compression { Strong, None }
enum Encryption { Aes, None }
enum Validation { Enabled, Disabled }

fn process_data(
    data: &[u8],
    compression: Compression,
    encryption: Encryption,
    validation: Validation,
) { /* ... */ }
```

For functions with many options, use a parameter struct with preset
constructors:

```rust
struct ProcessParams {
    compression: Compression,
    encryption: Encryption,
}

impl ProcessParams {
    pub fn production() -> Self { /* ... */ }
    pub fn development() -> Self { /* ... */ }
}
```

### DO: Use exhaustive `match` -- avoid wildcard catch-all

Wildcard `_` in match arms hides new variants added later.

```rust
// BAD: New variants silently fall through
match status {
    Status::Active => handle_active(),
    Status::Inactive => handle_inactive(),
    _ => {} // Hides future variants
}

// GOOD: Compiler forces you to handle new variants
match status {
    Status::Active => handle_active(),
    Status::Inactive => handle_inactive(),
    Status::Pending => handle_pending(),
    Status::Suspended => handle_suspended(),
}

// OK: Explicitly group variants with shared logic
match status {
    Status::Active => handle_active(),
    Status::Inactive | Status::Suspended => handle_disabled(),
    Status::Pending => handle_pending(),
}
```

### DO: Use slice pattern matching instead of index + length check

Decoupling length check from indexing creates implicit invariants the compiler
cannot enforce.

```rust
// BAD: Length check and index are decoupled
if !users.is_empty() {
    let first = &users[0]; // Can panic if refactored
}

// GOOD: Compiler guarantees access is safe
match users.as_slice() {
    [] => handle_empty(),
    [single] => handle_one(single),
    [first, rest @ ..] => handle_many(first, rest),
}
```

### DO: Destructure structs in trait impls for future-proofing

When implementing `PartialEq`, `Hash`, `Debug`, etc. manually, destructure the
struct so the compiler forces you to handle new fields.

```rust
impl PartialEq for Order {
    fn eq(&self, other: &Self) -> bool {
        let Self { item, quantity, timestamp: _ } = self;
        let Self { item: other_item, quantity: other_qty, timestamp: _ } = other;
        item == other_item && quantity == other_qty
    }
}
// Adding a new field will cause a compile error until addressed
```

### DO: Name unused destructured variables descriptively

```rust
// BAD: Unclear what is being ignored
match rocket {
    Rocket { _, _, .. } => {}
}

// GOOD: Clear intent
match rocket {
    Rocket { has_fuel: _, has_crew: _, .. } => {}
}
```

### DON'T: Use `..Default::default()` lazily

It silently fills new fields with defaults, hiding potential bugs when fields
are added later.

```rust
// BAD: New fields silently get defaults
let config = Config {
    timeout: Duration::from_secs(30),
    ..Default::default()
};

// GOOD: Explicit about every field
let config = Config {
    timeout: Duration::from_secs(30),
    retries: 3,
    verbose: false,
};

// ACCEPTABLE: Destructure default first for visibility
let Config { timeout, retries, verbose } = Config::default();
let config = Config {
    timeout: Duration::from_secs(30), // Override
    retries,  // Use default (visible)
    verbose,  // Use default (visible)
};
```

---

## 4. Performance

### DON'T: Clone gratuitously

Every `.clone()` on a heap type (`String`, `Vec<T>`) allocates. In hot paths
this is a top performance killer.

```rust
// BAD: Unnecessary allocation for HashMap lookup
fn lookup(key: String, map: &HashMap<String, String>) -> Option<&String> {
    let k = key.clone();
    map.get(&k)
}

// GOOD: Borrow directly -- HashMap<String, _> accepts &str lookups
fn lookup(key: &str, map: &HashMap<String, String>) -> Option<&String> {
    map.get(key)
}
```

### DON'T: Use redundant wrapper types

```rust
// BAD: Double indirection
Box<Vec<T>>    // Just use Vec<T>
Box<String>    // Just use String
Arc<String>    // Use Arc<str>
```

### DON'T: Collect into Vec just to iterate again

```rust
// BAD: Allocates a Vec for no reason
let v: Vec<_> = iter.collect();
for x in v { process(x); }

// GOOD: Iterate directly
for x in iter { process(x); }
```

### DON'T: Use `String::from` / `format!` for static content when `&str` suffices

```rust
// BAD: Heap allocation for a constant
let msg = String::from("hello");
let msg = format!("hello");

// GOOD: Use &str when the receiver accepts it
let msg: &str = "hello";
```

### DO: Use `format!` for string concatenation with mixed content

When combining literal and dynamic strings, `format!` is more readable than
manual `push_str` chains. For hot paths, pre-allocate with
`String::with_capacity` and `push_str`.

```rust
// Readable: format! for mixed content
let greeting = format!("Hello, {name}! You have {count} items.");

// Fast: manual push for hot paths
let mut s = String::with_capacity(64);
s.push_str("Hello, ");
s.push_str(name);
```

### DO: Use temporary mutability pattern

Constrain mutability to initialization, then shadow as immutable.

```rust
let data = {
    let mut data = get_vec();
    data.sort();
    data // Returned immutable
};
// `data` is now immutable -- no accidental modification
```

---

## 5. Async Rules

### DON'T: Call blocking I/O in async functions

Blocking calls (`std::fs`, `std::net`, heavy computation) stall the async
runtime's worker thread, starving other tasks.

```rust
// BAD: Blocks the Tokio runtime
async fn read_config(path: &str) -> String {
    std::fs::read_to_string(path).unwrap() // BLOCKS!
}

// GOOD: Use async I/O
async fn read_config(path: &str) -> Result<String, tokio::io::Error> {
    tokio::fs::read_to_string(path).await
}

// GOOD: For unavoidable blocking, use spawn_blocking
async fn compute_hash(data: Vec<u8>) -> Vec<u8> {
    tokio::task::spawn_blocking(move || {
        expensive_hash(&data)
    }).await.unwrap()
}
```

### DO: Use `tokio::select!` for cancellation and timeouts

```rust
tokio::select! {
    result = do_work() => handle_result(result),
    _ = tokio::time::sleep(Duration::from_secs(30)) => {
        tracing::warn!("operation timed out");
    }
}
```

### DON'T: Hold locks across `.await` points

`std::sync::Mutex` is not async-aware. Holding it across an `.await` blocks
the entire thread if another task tries to acquire it.

```rust
// BAD
let guard = mutex.lock().unwrap();
do_async_work().await; // other tasks contend on the locked mutex
drop(guard);

// GOOD: minimize lock scope
{
    let guard = mutex.lock().unwrap();
    let data = guard.clone(); // or extract what you need
} // lock released before await
do_async_work_with(data).await;

// OR: use tokio::sync::Mutex if you must hold across await
let guard = async_mutex.lock().await;
do_async_work().await;
drop(guard);
```

### DO: Use `tokio::task::yield_now()` in CPU-bound async loops

If you must do CPU work in an async context, yield periodically to avoid
starving other tasks.

---

## 6. Design Patterns to USE

### Builder Pattern

Use for complex object construction, especially when Rust lacks default
arguments and overloading.

```rust
let server = ServerBuilder::new()
    .port(8080)
    .max_connections(100)
    .tls_config(tls)
    .build()?;
```

### RAII Guards

Tie resource lifecycle to scope. The guard's `Drop` impl ensures cleanup even
on early return or panic.

```rust
let _guard = acquire_lock(&resource);
// Lock released automatically when _guard goes out of scope,
// even if this function returns early or panics
```

### Strategy Pattern via Traits or Closures

Use traits for polymorphic behavior. Closures work for lightweight strategies.

```rust
// Trait-based strategy
trait Formatter {
    fn format(&self, data: &Data) -> String;
}

// Closure-based strategy
fn process<F: Fn(&Data) -> String>(data: &Data, format: F) -> String {
    format(data)
}
```

### Struct Decomposition for Independent Borrowing

When the borrow checker blocks you from borrowing different fields of a
struct, decompose into smaller structs.

```rust
// Instead of one large struct where borrowing one field locks all:
struct Server {
    config: ServerConfig,  // Can borrow independently
    state: ServerState,    // Can borrow independently
}
```

### Newtype for Implementing Foreign Traits

When the orphan rule prevents `impl ForeignTrait for ForeignType`, wrap in a
newtype.

```rust
struct AuditFile(Arc<File>);

impl io::Write for AuditFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}
```

### Closure Variable Rebinding

Control what a closure captures by rebinding variables in a scope block.

```rust
let handler = {
    let db = Arc::clone(&db);      // Clone Arc, not the database
    let config = config.as_ref();   // Borrow
    move |req| handle(req, &db, config)
};
```

### `cfg_select!` for Compile-Time Selection (Rust 1.95+)

`cfg_select!` is a stable compile-time `match`-like macro that replaces the
`cfg-if` crate. Prefer it in new code; do not proactively migrate existing
`cfg-if` usages.

```rust
cfg_select! {
    unix => { fn init() { /* unix */ } }
    windows => { fn init() { /* windows */ } }
    _ => { fn init() { /* fallback */ } }
}
```

### `Default` + `new()` Constructors

Implement both. `Default` enables use with `unwrap_or_default()` and generic
containers. `new()` is the expected Rust constructor convention.

```rust
#[derive(Default)]
pub struct Config {
    pub timeout: Duration,
    pub retries: u32,
}

impl Config {
    pub fn new(timeout: Duration, retries: u32) -> Self {
        Self { timeout, retries }
    }
}
```

---

## 7. Anti-Patterns to AVOID

### Deref Polymorphism (Fake Inheritance)

Do not implement `Deref` to emulate OO inheritance. `Deref` is for smart
pointers and collections, not for "struct B extends struct A".

```rust
// BAD: Fake inheritance via Deref
impl Deref for Bar {
    type Target = Foo;
    fn deref(&self) -> &Foo { &self.foo }
}

// GOOD: Explicit delegation or trait-based composition
impl Bar {
    fn method(&self) { self.foo.method() }
}
```

Why it is wrong:
- Surprises readers -- it is an implicit, undocumented conversion
- Does not create a subtype relationship
- Traits on `Foo` are NOT automatically available for `Bar`
- Breaks generic programming and bounds checking

### `#![deny(warnings)]` in Source Code

This opts you out of Rust's stability guarantees. New compiler versions may
introduce new warnings, breaking your build.

```rust
// BAD: In source code
#![deny(warnings)]

// GOOD: In CI only
// RUSTFLAGS="-D warnings" cargo build

// GOOD: Deny specific lints
#![deny(unused, dead_code)]
```

### Overreliance on `String` in APIs

Accept `&str` for reading, `impl Into<String>` for ownership transfer.

```rust
// BAD
fn greet(name: String) -> String { format!("Hello, {name}") }

// GOOD
fn greet(name: &str) -> String { format!("Hello, {name}") }

// GOOD: When you need ownership
fn set_name(&mut self, name: impl Into<String>) {
    self.name = name.into();
}
```

---

## 8. API Design

### DO: Accept `impl Into<String>` for owned string parameters

```rust
// Flexible: accepts &str, String, Cow, etc.
pub fn new(name: impl Into<String>) -> Self {
    Self { name: name.into() }
}

// Usage:
let a = Config::new("literal");        // no allocation if optimized
let b = Config::new(owned_string);     // moves, no clone
```

### DO: Return `Result` from constructors that validate

```rust
pub fn new(port: u16) -> Result<Self, ConfigError> {
    if port == 0 {
        return Err(ConfigError::InvalidPort);
    }
    Ok(Self { port })
}
```

### DO: Use builder pattern for configs with many optional fields

See Section 6 (Builder Pattern) for full examples.

### DON'T: Use more than 3-4 boolean parameters

Replace booleans with descriptive enums or a parameter struct.
See Section 3 (enums instead of booleans) for examples.

### DON'T: Expose internal types in public APIs

Wrap third-party types so you can swap implementations without breaking
callers.

---

## 9. Clippy and Lints

### Recommended Clippy Lints

Add to your `Cargo.toml`:

```toml
[lints.clippy]
all = "deny"
pedantic = "warn"
```

### Defensive Programming Lints

```toml
[lints.clippy]
indexing_slicing = "deny"          # Prefer .get() or pattern matching
fallible_impl_from = "deny"        # From impls that should be TryFrom
wildcard_enum_match_arm = "deny"   # No catch-all _ in enums
fn_params_excessive_bools = "deny" # Too many bool params
must_use_candidate = "warn"        # Suggest #[must_use]
unneeded_field_pattern = "warn"    # Unnecessary .. in patterns
```

### Panic Prevention Lints

A server process must never panic in production. These lints enforce
compile-time prevention of runtime panics.

```toml
[lints.clippy]
unwrap_used = "deny"               # No .unwrap() anywhere - use ?, unwrap_or, etc.
expect_used = "warn"               # .expect() is marginally better but still panics
panic = "deny"                     # No intentional panic!() in production paths
todo = "deny"                      # No todo!() - these panic at runtime
unimplemented = "deny"             # No unimplemented!() - same as todo
unreachable = "warn"               # Prefer compiler-proven unreachable via match
```

Note: `unwrap_used = "deny"` is stricter than the Section 2 guidance
("no unwrap in library code"). For a server binary, panics in *any* code
path - library or application - crash the process. Use `?`, `unwrap_or`,
`unwrap_or_else`, `unwrap_or_default`, or explicit `match` instead.

Exceptions are allowed only with `#[allow(clippy::unwrap_used)]` and a
comment explaining why the value is guaranteed to be `Some`/`Ok`.

Clippy 1.95 added an `allow-unwrap-types` config key for `clippy.toml`
that lets `unwrap_used` / `expect_used` ignore specific types. **Do not
enable this** in this workspace - the deny is intentional. Fix the call
site or add a local `#[allow(...)]` with justification.

### Debug Artifact Prevention Lints

Debug macros and raw stdout/stderr writes must never reach production.
Use `tracing` for all output.

```toml
[lints.clippy]
dbg_macro = "deny"                 # No dbg!() - use tracing::debug!
print_stdout = "deny"              # No println!() - use tracing::info!
print_stderr = "deny"              # No eprintln!() - use tracing::error!
```

### Complexity Lints

Flag functions that are too complex to reason about or review safely.

```toml
[lints.clippy]
cognitive_complexity = "warn"      # Functions exceeding complexity threshold
too_many_lines = "warn"            # Functions that should be decomposed
```

### String Handling Lints

Catch unnecessary string conversions and allocations.

```toml
[lints.clippy]
string_to_string = "warn"         # String::to_string() - already a String
str_to_string = "warn"            # Prefer .to_owned() or .into()
```

### Library Crate Hygiene Lints

For library crates (e.g. `mcpx`), public API surface must be
future-proof and documented.

```toml
[lints.clippy]
exhaustive_enums = "warn"          # Public enums should use #[non_exhaustive]
exhaustive_structs = "warn"        # Public structs should use #[non_exhaustive]
```

### Performance-Related Clippy Lints

```toml
[lints.clippy]
redundant_clone = "warn"          # Clone on a value that is not used after
implicit_clone = "warn"           # .to_owned() / .to_string() where clone suffices
needless_pass_by_value = "warn"   # Pass by ref instead of by value
large_enum_variant = "warn"       # Consider boxing large variants
box_collection = "warn"           # Box<Vec<T>> -> Vec<T>
rc_buffer = "warn"                # Rc<String> -> Rc<str>
clone_on_ref_ptr = "warn"         # Arc::clone(&x) over x.clone()
```

Clippy 1.95 added two `complexity`-tier lints that are already covered by
`clippy::all = "deny"` and do not need separate declarations:

- `manual_checked_ops` - prefer `checked_add`/`checked_sub`/`checked_mul`
  over hand-rolled overflow checks.
- `manual_take` - prefer `std::mem::take(&mut x)` over
  `mem::replace(&mut x, Default::default())`.

### General Quality Lints

```toml
[lints.rust]
missing_debug_implementations = "warn"
trivial_casts = "warn"
trivial_numeric_casts = "warn"
unused_extern_crates = "warn"
unused_import_braces = "warn"
unused_qualifications = "warn"
```

### Crate-Level Safety Lints

These Rust-level lints enforce safety invariants at the crate boundary.

```toml
[lints.rust]
unsafe_code = "forbid"             # Forbid unsafe entirely if not needed
unreachable_pub = "warn"           # pub items not reachable from crate root
missing_docs = "warn"              # At minimum for public API (library crates)
```

`unsafe_code = "forbid"` should be set in every crate that does not need
`unsafe`. For crates that require specific `unsafe` blocks, use
`unsafe_code = "deny"` at crate level and `#[allow(unsafe_code)]` on the
individual items with a safety comment explaining the invariant.

For library crates, `missing_docs = "warn"` ensures every public item
has documentation. Promote to `"deny"` once existing docs are complete.

### DO: Use `cargo fmt` for consistent formatting

```bash
cargo fmt --all -- --check  # CI: fail on unformatted code
cargo fmt --all             # local: auto-format
```

### DO: Configure `rustfmt.toml` for import organization

Standardize import ordering and grouping across the workspace. Create a
`rustfmt.toml` at the workspace root:

```toml
# rustfmt.toml
imports_granularity = "Crate"       # Group imports by crate, not individual items
group_imports = "StdExternalCrate"  # Separate std, external, and crate imports
```

This produces consistent import blocks:

```rust
// std imports
use std::collections::HashMap;
use std::sync::Arc;

// external crate imports
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// crate imports
use crate::config::ServerConfig;
use crate::error::AppError;
```

### DO: Profile before optimizing

```bash
cargo install flamegraph
cargo flamegraph --bin my-server

# For async code:
cargo install tokio-console
# Add tokio-console subscriber, then:
tokio-console
```

---

## 10. Web Application Security (OWASP)

Rules for HTTP services built with axum, tower, or similar frameworks.
Based on [OWASP Top 10](https://owasp.org/www-project-top-ten/),
[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
and the [owasp-headers](https://docs.rs/owasp-headers) crate.

### DO: Set OWASP-recommended HTTP response headers on every response

Add these headers via a tower middleware layer so they apply uniformly.
The definitive list is maintained at
`https://owasp.org/www-project-secure-headers/ci/headers_add.json`.

Required headers (defaults from OSHP):

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `deny` |
| `Content-Security-Policy` | `default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), microphone=()` (trim to what you actually need) |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cache-Control` | `no-store, max-age=0` (for API responses; static assets may differ) |
| `X-DNS-Prefetch-Control` | `off` |
| `X-Permitted-Cross-Domain-Policies` | `none` |

```rust
// tower middleware example (axum)
use axum::http::header;
use tower_http::set_header::SetResponseHeaderLayer;

let app = Router::new()
    .route("/mcp", post(handler))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("deny"),
    ));
// Or use the `owasp-headers` crate to get all at once:
//   headers.extend(owasp_headers::headers());
```

### DO: Strip server-fingerprinting headers

Remove headers that leak technology stack details. The full removal list is at
`https://owasp.org/www-project-secure-headers/ci/headers_remove.json`.

At minimum, suppress:
- `Server` (web server name/version)
- `X-Powered-By` (framework name)
- `X-AspNet-Version`, `X-AspNetMvc-Version`
- Any `X-*` header containing build hashes, internal hostnames, or tracing IDs

```rust
// Axum: do NOT set a Server header, or override it
use tower_http::set_header::SetResponseHeaderLayer;
app.layer(SetResponseHeaderLayer::overriding(
    HeaderName::from_static("server"),
    HeaderValue::from_static(""),
));
```

### DO: Validate and sanitize all external input at system boundaries

- **Parameterized queries only** -- never interpolate user input into SQL,
  shell commands, or API paths.
- **Type-driven validation** -- use newtypes + validated constructors (SS3)
  for IDs, hostnames, container names, image references, etc.
- **Length limits** -- enforce maximum lengths on all string inputs before
  processing.
- Prefer allowlists over denylists for input validation patterns.

```rust
// BAD: String interpolation in API path
let path = format!("/containers/{user_input}/json");

// GOOD: Validate the identifier first
fn validate_id(id: &str) -> Result<&str, Error> {
    if id.is_empty() || id.len() > 128
        || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::InvalidId(id.into()));
    }
    Ok(id)
}
let path = format!("/containers/{}/json", validate_id(user_input)?);
```

### DO: Prevent SSRF (Server-Side Request Forgery)

When the server makes HTTP requests based on user-supplied URLs:

- Parse with a URL library, then validate the scheme (`https` only, or
  explicit allowlist).
- Reject private/loopback IPs (`127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fe80::/10`, `169.254.0.0/16`).
- Reject hostnames ending in `.local`, `.internal`, `.localhost`.
- Use a DNS resolution allowlist when possible.

```rust
use std::net::IpAddr;

fn is_safe_target(ip: IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_private()
            || v4.is_link_local()
            || v4.octets()[0] == 169 && v4.octets()[1] == 254)
}
```

### DON'T: Leak internal details in error responses

Error messages returned to clients must not contain:
- Stack traces or panic messages
- File paths, line numbers, or source code
- Internal hostnames, IPs, or port numbers
- SQL queries or ORM error strings
- Dependency version numbers

```rust
// BAD: Forwards internal error to the client
Err(e) => HttpResponse::InternalServerError().body(format!("{e:#}"))

// GOOD: Log the detail, return a generic message
Err(e) => {
    tracing::error!(error = %e, "request failed");
    HttpResponse::InternalServerError().body("internal server error")
}
```

For structured JSON-RPC/MCP errors, use generic error codes and messages.
The detailed cause goes to the server log, never the wire.

### DON'T: Hardcode secrets in source code

- API keys, passwords, TLS private keys, and JWT signing secrets must come
  from environment variables, config files (excluded from VCS), or a secrets
  manager.
- Use `secrecy::Secret<String>` (from the `secrecy` crate) to wrap secrets
  so they are zeroized on drop and redacted in `Debug`/`Display` output.
- Never log secrets. Redact sensitive fields before passing to `tracing`.

```rust
use secrecy::{ExposeSecret, Secret};

struct DbConfig {
    url: Secret<String>,
}

impl DbConfig {
    fn connect(&self) -> Result<Connection> {
        Connection::open(self.url.expose_secret())
    }
}
// println!("{:?}", config) prints url: Secret([REDACTED])
```

### DO: Use cryptographically secure randomness for security-sensitive values

- Tokens, nonces, salts, session IDs: use `rand::rngs::OsRng` or the
  `getrandom` crate.
- Never use `rand::thread_rng()` for cryptographic material -- it may not
  be backed by a CSPRNG on all platforms.
- Prefer `rand::fill()` into a fixed-size byte array, then encode with
  base64 or hex.

### DO: Enforce TLS and certificate validation

- Always use `rustls` with `webpki-roots` (or system roots) -- never
  disable certificate verification.
- Set `min_protocol_version = Some(TLSv1_2)` or higher.
- For mTLS, validate the client certificate chain and check the CN/SAN.

### DO: Audit dependencies regularly

- Run `cargo audit` in CI on every PR (checks RustSec advisory DB).
- Run `cargo deny check` for license compliance, duplicate crate detection,
  and banned crate policies.
- Pin dependencies with `Cargo.lock` in version control for binaries.
- Review new transitive dependencies before merging.

### DO: Configure `cargo deny` with a `deny.toml`

A bare `cargo deny check` with no configuration is better than nothing,
but a `deny.toml` makes policies explicit and enforceable.

```toml
# deny.toml - workspace root
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
unlicensed = "deny"
copyleft = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "OpenSSL",
    "BSL-1.0",
    "CC0-1.0",
]

[bans]
multiple-versions = "warn"
wildcards = "deny"            # No * version specs
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

Adjust the license allowlist to your organization's policy. The `[sources]`
section prevents dependencies from unknown registries or arbitrary git repos.

### DO: Use `cargo vet` for supply chain trust

`cargo audit` checks for *known* vulnerabilities. `cargo vet` tracks
*who reviewed which crate version* - it answers "has a human on our team
actually looked at this code?"

```bash
cargo install cargo-vet
cargo vet init              # First time: create vet config
cargo vet                   # Check: are all deps vetted?
cargo vet certify <crate>   # Record: "I reviewed this crate"
```

For a security-sensitive server handling auth and credentials, `cargo vet`
is the difference between "no known CVEs" and "someone actually read this
dependency's source code."

### DO: Implement proper logging and monitoring

- Log authentication attempts (success and failure) with source IP.
- Log authorization denials with the identity, requested resource, and
  reason.
- Use structured logging (`tracing` with JSON output) so logs are machine-
  parseable.
- Never log request/response bodies that may contain credentials, tokens,
  or PII.
- Set up alerting on anomalous patterns (burst of 401s, rate limit hits).

---

## 11. Quick Reference Checklist

Use this when reviewing code:

**Ownership**
- [ ] Functions accept borrowed types (`&str`, `&[T]`) not owned references (`&String`, `&Vec<T>`)
- [ ] No `.clone()` used to work around the borrow checker
- [ ] `mem::take` / `mem::replace` used instead of clone for owned enum fields
- [ ] Consumed arguments returned in error variants for retryable operations

**Error Handling**
- [ ] No `unwrap()` / `expect()` in library code (only tests or proven invariants)
- [ ] Errors propagated with `?`, not swallowed or panicked
- [ ] `TryFrom` used when conversion can fail (not `From` with hidden fallbacks)

**Type Safety**
- [ ] Newtypes used for domain concepts (IDs, amounts, durations)
- [ ] Enums used instead of `bool` params where meaning is unclear
- [ ] `match` arms are exhaustive -- no wildcard `_` catch-all on owned enums
- [ ] Struct fields private with validated constructors (for library types)
- [ ] `#[must_use]` on types/functions where ignoring the result is a bug

**Performance**
- [ ] No `Box<Vec<T>>`, `Box<String>`, `Arc<String>`
- [ ] No collect-then-iterate -- iterate directly
- [ ] No `String::from("...")` where `&str` is accepted
- [ ] HashMap lookups use `&str`, not cloned `String` keys
- [ ] `core::hint::cold_path()` marks genuinely unlikely branches (Rust 1.95+); perf hint only, never correctness

**Async**
- [ ] No `std::fs` / `std::net` in async functions
- [ ] Blocking work wrapped in `spawn_blocking`
- [ ] Timeouts use `tokio::select!`
- [ ] No `std::sync::Mutex` held across `.await` points

**Defensive**
- [ ] No `..Default::default()` hiding new fields
- [ ] Manual trait impls destructure the struct (future-proof)
- [ ] No `Deref` for fake inheritance
- [ ] Named ignores in patterns (`has_fuel: _` not just `_`)

**API Design**
- [ ] Owned string params use `impl Into<String>`, read-only params use `&str`
- [ ] Constructors with validation return `Result`
- [ ] No more than 3-4 boolean parameters (use enums or param struct)
- [ ] Third-party types wrapped, not exposed in public APIs

**Web Security (OWASP)**
- [ ] OWASP security headers set on all HTTP responses (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- [ ] Server-fingerprinting headers stripped (Server, X-Powered-By)
- [ ] External input validated at system boundary (length, charset, allowlist)
- [ ] No string interpolation of user input into SQL, shell commands, or API paths
- [ ] Error responses do not leak internals (stack traces, file paths, SQL, IPs)
- [ ] Secrets loaded from env/config, never hardcoded; wrapped in `Secret<T>`
- [ ] Cryptographic randomness uses OsRng, not thread_rng
- [ ] TLS enabled with certificate validation; min TLS 1.2
- [ ] `cargo audit` and `cargo deny` run in CI
- [ ] Auth attempts and RBAC denials logged with structured tracing

**Runtime Safety**
- [ ] No `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` in production paths
- [ ] No `dbg!()`, `println!()`, `eprintln!()` - use `tracing` macros
- [ ] `unsafe_code = "forbid"` set at crate level (or `deny` with per-item `#[allow]` + safety comment)
- [ ] Functions below cognitive complexity threshold (no god functions)
- [ ] Prefer `Atomic*::update` / `try_update` over hand-rolled `compare_exchange` loops (Rust 1.95+)
- [ ] Prefer `Vec::push_mut` / `VecDeque::push_{front,back}_mut` / `LinkedList::push_{front,back}_mut` over `push` + `last_mut().unwrap()` (Rust 1.95+)

**Supply Chain**
- [ ] `deny.toml` configured with license allowlist, banned crates, source restrictions
- [ ] `cargo vet` tracking crate review status
- [ ] No dependencies from unknown registries or arbitrary git repos
- [ ] All dependency versions are latest stable
- [ ] `Cargo.lock` committed for binary crates

**Testing**
- [ ] Property-based tests for input validation, parsing, serialization roundtrips
- [ ] Mutation testing confirms tests catch real bugs (not just coverage theater)
- [ ] Test tiers documented: unit (autonomous) vs integration (mocked) vs e2e (live)
- [ ] No deleted or skipped tests to make the build pass

**Tooling**
- [ ] `cargo fmt --check` in CI
- [ ] `cargo clippy -D warnings` with full lint set in CI
- [ ] `cargo audit` and `cargo deny check` in CI
- [ ] `cargo semver-checks` in CI for library crates
- [ ] `rustfmt.toml` with `imports_granularity` and `group_imports` configured

---

## 12. Development Tooling

### Required CI Tools

These tools MUST run in CI on every PR. Failure blocks merge.

```bash
cargo fmt --all -- --check                          # Formatting
cargo clippy --all-targets --all-features -- -D warnings  # Lints
cargo test --all-features                           # Tests
cargo audit                                         # Security advisories
cargo deny check                                    # License, bans, duplicates
```

### Recommended CI Tools

These tools SHOULD run in CI. Warnings are informational, not blocking.

| Tool | Purpose | Install | Run |
|------|---------|---------|-----|
| `cargo-semver-checks` | Catches accidental breaking changes in library crate public APIs | `cargo install cargo-semver-checks` | `cargo semver-checks check-release` |
| `cargo-machete` | Finds unused dependencies (bloat, compile time, attack surface) | `cargo install cargo-machete` | `cargo machete` |
| `cargo-geiger` | Counts `unsafe` usage including transitive dependencies | `cargo install cargo-geiger` | `cargo geiger --all-features` |
| `taplo` | TOML linter/formatter for `Cargo.toml` consistency | `cargo install taplo-cli` | `taplo check` / `taplo fmt --check` |

`cargo-semver-checks` is **critical for library crates** - it detects
breaking API changes that would otherwise only surface when downstream
consumers upgrade. Run it on every PR that touches the library crate.

### Recommended Local Tools

| Tool | Purpose | Install | Run |
|------|---------|---------|-----|
| `cargo-nextest` | Faster test runner with parallel execution and JUnit output | `cargo install cargo-nextest` | `cargo nextest run --all-features` |
| `cargo-llvm-cov` | Source-level code coverage (more accurate than tarpaulin for async) | `cargo install cargo-llvm-cov` | `cargo llvm-cov --all-features --html` |
| `cargo-mutants` | Mutation testing - verifies tests actually catch bugs | `cargo install cargo-mutants` | `cargo mutants --all-features` |
| `cargo-bloat` | Binary size analysis - find what contributes to binary size | `cargo install cargo-bloat` | `cargo bloat --release -n 20` |
| `cargo-expand` | Expand macros - see what proc macros / derive macros generate | `cargo install cargo-expand` | `cargo expand <module>` |
| `flamegraph` | CPU profiling via perf/dtrace | `cargo install flamegraph` | `cargo flamegraph --bin <name>` |
| `tokio-console` | Async runtime introspection | `cargo install tokio-console` | `tokio-console` |

### Version Policy

Always use the latest stable Rust toolchain. Crate dependencies must
target the latest stable version - check with `cargo search <crate> --limit 1`
before adding or updating. Run version checks regularly (at least monthly).
No `rust-toolchain.toml` pin; CI uses whatever `stable` resolves to.

---

## 13. Testing Quality

### DO: Use property-based testing for input validation and parsing

Unit tests check specific cases you thought of. Property-based tests
generate thousands of random inputs, finding edge cases humans miss.

Use `proptest` or `quickcheck` for:
- Input validation functions (does it reject all invalid inputs?)
- Serialization/deserialization roundtrips (`serialize(deserialize(x)) == x`)
- Parsers (no panics on arbitrary input)
- Numeric boundaries and overflow conditions

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn port_rejects_zero(port in 0u16..=0u16) {
        assert!(Port::new(port).is_err());
    }

    #[test]
    fn port_accepts_valid(port in 1u16..=65535u16) {
        assert!(Port::new(port).is_ok());
    }

    #[test]
    fn config_roundtrip(config in arb_config()) {
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }
}
```

For MCP tool input schemas, property-based tests are especially valuable:
generate random tool arguments and verify the handler either succeeds
or returns a well-formed error - never panics.

### DO: Use mutation testing to verify test effectiveness

Code coverage measures "which lines ran." Mutation testing measures
"would the tests catch a bug?"

`cargo-mutants` modifies your code (e.g. flipping `<` to `>=`, removing
a function call, replacing a return value) and checks if tests still pass.
If they do, your tests are not catching that class of bug.

```bash
cargo mutants --all-features          # Run all mutations
cargo mutants --file src/auth.rs      # Target specific module
```

Prioritize mutation testing on:
- Authentication and authorization logic
- Input validation
- Error handling paths
- Business logic (tool handlers)

### DON'T: Delete or skip failing tests to make the build pass

Fix the code, not the tests. If a test is genuinely wrong (testing the
wrong behavior), fix the test with a comment explaining what changed and
why. Never silently delete a test.

### DO: Separate test tiers

Organize tests by what they need to run:

```
tests/
├── unit/           # No I/O, no network, fast - run always
├── integration/    # Mocked external services - run in CI
└── e2e/            # Live services required - run with human setup
```

Document which tier each test belongs to. The AI team must know which
tests they can run autonomously vs which require human-assisted setup.

---

## References

- [Rust Design Patterns](https://rust-unofficial.github.io/patterns/) -- idioms, design patterns, and guidelines
- [Rust Anti-Patterns](https://rust-unofficial.github.io/patterns/anti_patterns/) -- common solutions that create more problems
- [7 Rust Anti-Patterns Killing Your Performance](https://medium.com/solo-devs/the-7-rust-anti-patterns-that-are-secretly-killing-your-performance-and-how-to-fix-them-in-2025-dcebfdef7b54) -- clone epidemic, blocking async, unwrap addiction
- [Patterns for Defensive Programming in Rust](https://corrode.dev/blog/defensive-programming/) -- constructors, exhaustive matching, `#[must_use]`, clippy lints
