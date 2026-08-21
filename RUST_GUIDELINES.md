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

### DON'T: Use a single lifetime to parameterize both inputs and stored references

When a function takes an input reference AND a `&mut` collection that stores
references, sharing one lifetime is usually wrong. The mutable reference makes
the lifetime parameter **invariant** (Rustonomicon: *"as soon as you try to
stuff them in something like a mutable reference, they inherit invariance"*),
so the compiler is forced to choose a single `'a` that satisfies every call
site. The function compiles, isolated tests pass, and the trap only springs
when a real caller tries to reuse the collection across inputs with disjoint
scopes.

```rust
// BAD: 'a parameterizes both the input and the cached values.
fn first_word<'a>(s: &'a str, cache: &mut HashMap<String, &'a str>) -> &'a str {
    if let Some(cached) = cache.get(s) { return cached; }
    let word = s.split_whitespace().next().unwrap_or("");
    cache.insert(s.to_string(), word);
    word
}

// Caller that the function-local tests never exercise:
let mut cache: HashMap<String, &str> = HashMap::new();
{
    let s1 = String::from("hello world");
    first_word(&s1, &mut cache);
}   // <- error[E0597]: `s1` does not live long enough
    //    s1 dropped here while still borrowed by `cache`.
let s2 = String::from("foo bar");
first_word(&s2, &mut cache);   // forces the borrow of s1 to extend to here
```

Verified against `rustc 1.94` — the function builds clean, but the caller
fails to compile because `cache`'s element type `&'a str` is invariant in
`'a`, so the compiler cannot let `s1` end its scope while `cache` is still
alive. Once you wire the function into application code, every input must
outlive the cache itself — almost never what you wanted.

```rust
// GOOD: store owned values when the collection outlives any single input
fn first_word<'a>(s: &'a str, cache: &mut HashMap<String, String>) -> &'a str {
    let _ = cache.entry(s.to_string())
        .or_insert_with(|| s.split_whitespace().next().unwrap_or("").to_string());
    s.split_whitespace().next().unwrap_or("")
}

// GOOD: split lifetimes with an explicit outlives bound when borrowing is required
fn first_word<'cache, 'input: 'cache>(
    s: &'input str,
    cache: &mut HashMap<String, &'cache str>,
) -> &'cache str { /* ... */ }
```

Rule of thumb: every time you add explicit lifetimes to a signature, sketch a
real caller in your head — specifically one where the inputs have disjoint
scopes from each other and from the collection. If `'a` appears inside both
a `&mut` and the data being stored, it is invariant; the signature compiles
in isolation but constrains every caller to keep all inputs alive for as
long as the collection. Prefer owned storage in the collection, or split
the lifetimes with an explicit outlives bound.

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

### DO: Use `bool::try_from(n)` for strict 0/1 wire fields (Rust 1.95+)

At boundaries where the encoding is "strictly 0 or 1, anything else is
malformed" (NVS single-byte flags, MQTT retain/dup bits, hOn protocol
bitfields stored as bytes, JSON `0`/`1` from a strict producer), prefer
`bool::try_from(n)?` over `n != 0`. The `!= 0` form silently accepts `2`,
`42`, `0xFF` as `true`, hiding upstream corruption. `TryFrom` makes the
"any non-0/1 is a bug" contract explicit and surfaces it as a parse error
the caller can report.

```rust
// BAD: any nonzero byte becomes true, including garbage from a torn NVS write
let display_on: bool = nvs_byte != 0;

// GOOD: strict — 0 or 1, anything else is a malformed record
let display_on = bool::try_from(nvs_byte)
    .map_err(|_| StorageError::InvalidFlag { tag: 0x09, value: nvs_byte })?;
```

Keep the plain `!= 0` form when you specifically mean "any nonzero is
truthy" (e.g. a C-style int from a library that documents that contract).

### DO: Use `bool::ok_or` / `ok_or_else` for guard clauses (Rust 1.98+)

Rust 1.98 stabilized `bool::ok_or` and `bool::ok_or_else`, which turn a
predicate into a `Result<(), E>`. They collapse the ubiquitous
"check-then-early-return" guard into a single `?`-able expression, which reads
better and keeps validation chains flat.

```rust
// BAD: four lines of ceremony per invariant, and the happy path drifts
// further right with every added check
fn validate(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.port == 0 {
        return Err(ConfigError::InvalidPort);
    }
    if cfg.max_body > HARD_CAP {
        return Err(ConfigError::BodyTooLarge);
    }
    Ok(())
}

// GOOD: one line per invariant, uniform shape, easy to add to
fn validate(cfg: &Config) -> Result<(), ConfigError> {
    (cfg.port != 0).ok_or(ConfigError::InvalidPort)?;
    (cfg.max_body <= HARD_CAP).ok_or(ConfigError::BodyTooLarge)?;
    Ok(())
}
```

Use `ok_or_else` when constructing the error is non-trivial (allocates,
formats, or captures context), so the cost is paid only on the failure path:

```rust
(cfg.max_body <= HARD_CAP)
    .ok_or_else(|| ConfigError::BodyTooLarge { got: cfg.max_body, cap: HARD_CAP })?;
```

Note the polarity: the receiver is the condition that must hold for success.
`true` yields `Ok(())`, `false` yields `Err(e)` -- the same convention as
`Option::ok_or`. Write the predicate as the *invariant*, not as the failure
condition.

### DO: Use `NonZero::from_str_radix` to parse directly into a non-zero type (Rust 1.98+)

Rust 1.98 stabilized `NonZero<{integer}>::from_str_radix` (`const`-stable). It
collapses parse-then-narrow into one fallible step, so the zero case is a parse
error rather than a second failure mode you have to remember to handle.

```rust
// BAD: two failure modes, two error types to reconcile
let n: u32 = s.parse()?;
let rate = NonZeroU32::new(n).ok_or(ConfigError::ZeroRate)?;

// GOOD: one step, one error type; invalid and zero both surface as ParseIntError
let rate = NonZeroU32::from_str_radix(s, 10)?;
```

This matters wherever a domain type is inherently non-zero -- rate limits,
capacities, retry counts, connection-pool sizes, timer periods. Parsing
straight into `NonZero` means the invalid state is unrepresentable from the
boundary inward (Section 3), instead of being re-checked at each use site.

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

**Caution (Rust 1.98+): `#[non_exhaustive]` now conflicts with `#[repr(transparent)]`.**
[Rust 1.98 made `repr(transparent)` stricter about which fields count as having
"trivial" layout](https://github.com/rust-lang/rust/pull/155299). Three
categories are **no longer trivial**:

- `repr(C)` types
- types with private fields
- `#[non_exhaustive]` types

This collides with two other rules in this section. The newtype pattern often
reaches for `#[repr(transparent)]` to guarantee zero-cost layout, while
validated constructors mandate **private fields** and library hygiene mandates
`#[non_exhaustive]` (enforced by `exhaustive_structs` / `exhaustive_enums`,
Section 9). A transparent newtype wrapping any of the three is now rejected.

```rust
// BAD (Rust 1.98+): the wrapped type is #[non_exhaustive], so it no longer
// has "trivial" layout and cannot satisfy repr(transparent).
#[repr(transparent)]
pub struct Wrapper(InnerNonExhaustive);

// GOOD: drop repr(transparent) unless you genuinely need the ABI guarantee
// (FFI, transmute-compatibility). A plain newtype is already zero-cost for
// ordinary Rust-to-Rust use -- repr(transparent) only matters at an ABI boundary.
pub struct Wrapper(InnerNonExhaustive);
```

Rule of thumb: reach for `#[repr(transparent)]` **only** when you need a
guaranteed identical ABI (FFI declarations, `transmute` compatibility). For
pure-Rust domain newtypes it buys nothing the optimizer does not already give
you, and on 1.98+ it actively fights `#[non_exhaustive]` and private fields.

### DO: Use `#[must_use]` on important return types

Prevents callers from accidentally ignoring results.

```rust
#[must_use = "config must be applied to take effect"]
pub struct Config { /* ... */ }

#[must_use]
pub fn validate(input: &str) -> Result<(), ValidationError> { /* ... */ }
```

**Note (Rust 1.97+):** the `must_use` lint now sees through infallible
result-like wrappers. `Result<T, Uninhabited>` and `ControlFlow<Uninhabited, T>`
-- where the error / break arm is an uninhabited type such as `!` or
`core::convert::Infallible` -- are treated as `T` for the lint. A `#[must_use]`
value returned inside a can't-fail `Result` therefore still triggers the
unused-result warning; you no longer silently lose the check by wrapping in an
infallible `Result`. (Clippy applied the same rule to `double_must_use` and
`let_underscore_must_use` back in 1.95.)

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

**Note (Rust 1.95+):** `if let` guards in `match` arms (stabilized in 1.95)
do **NOT** participate in exhaustiveness checking — same rule as plain `if`
guards. A new tool may suggest collapsing arms behind an `if let` guard
and dropping the wildcard; the compiler will still require either an
exhaustive listing or a `_` arm. Do not use an `if let` guard as
justification for removing a previously-required wildcard.

```rust
// The `if let` guard does NOT cover Status::Pending — the wildcard or an
// explicit Pending arm is still required for the match to compile.
match status {
    Status::Active if let Some(uid) = current_user() => handle_active(uid),
    Status::Inactive => handle_inactive(),
    _ => {} // still mandatory
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

### DON'T: Mix manual and derived comparison impls (Rust 1.98+)

The destructuring technique above deliberately *ignores* fields (`timestamp: _`).
That is fine on its own, but it becomes a correctness hazard the moment the
same type also **derives** an ordering or equality trait, because the derive
compares **every** field. Rust 1.98 made two changes that turn this
previously-latent inconsistency into observable behaviour change:

- [Rust 1.98 implements a fast path for `derive(PartialOrd)` when `Ord` is also
  derived](https://github.com/rust-lang/rust/pull/155598). The release notes
  state plainly that this "can break crates where a type's `PartialOrd` and
  `Ord` impls were inconsistent." Code that limped along on 1.97 with a
  hand-written `PartialOrd` disagreeing with a derived `Ord` may now take a
  different branch.
- Rust 1.98 closed a hole in pattern-matching
  [structural equality](https://doc.rust-lang.org/reference/patterns.html#constant-patterns),
  rejecting matches on constants where a manual `PartialEq` disagrees with an
  existing `derive(PartialEq)` impl.

```rust
// BAD: manual PartialEq ignores `timestamp`, but the derives order by it.
// `a == b` can be true while `a.cmp(&b) != Ordering::Equal`. This violates
// the Ord contract, and 1.98's derive fast path can now expose it.
#[derive(PartialOrd, Ord, Eq)]
struct Order { item: String, quantity: u32, timestamp: Instant }

impl PartialEq for Order {
    fn eq(&self, other: &Self) -> bool {
        let Self { item, quantity, timestamp: _ } = self;
        let Self { item: other_item, quantity: other_qty, timestamp: _ } = other;
        item == other_item && quantity == other_qty
    }
}

// GOOD: hand-write the whole comparison family, consistently, from the same
// destructured field set. The compiler still forces you to revisit every impl
// when a field is added.
impl PartialEq for Order { /* compares item, quantity */ }
impl Eq for Order {}
impl Ord for Order {
    fn cmp(&self, other: &Self) -> Ordering {
        let Self { item, quantity, timestamp: _ } = self;
        let Self { item: other_item, quantity: other_qty, timestamp: _ } = other;
        item.cmp(other_item).then(quantity.cmp(other_qty))
    }
}
impl PartialOrd for Order {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
```

Rules:

- Comparison traits are **all-manual or all-derived**. Never split the family.
  If `PartialEq` is hand-written, then `Eq`, `PartialOrd`, and `Ord` must be
  hand-written too, over the **same** field set.
- The invariant to preserve: `a == b` **iff** `a.cmp(&b) == Ordering::Equal`,
  and `partial_cmp` must agree with `cmp`. Deriving `Ord` while hand-writing
  `PartialEq` breaks this silently.
- A type with a manual `PartialEq` must **not** be used in a constant pattern
  (`match x { MY_CONST => ... }`) -- 1.98 rejects this.
- If you only want to ignore a field for *equality* and have no ordering
  requirement, do not derive `PartialOrd`/`Ord` at all. Deriving traits you do
  not need is what creates the inconsistency.

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

### DO: Allocate large buffers via `Vec`, not `Box::new([0; N])`

`Box::new([0u8; 1 << 20])` constructs the array **on the stack first**, then
moves it to the heap. In debug builds this overflows the stack. In release,
rustc *sometimes* placement-allocates directly into the box, but that is
not guaranteed by the language -- a single intermediate `let` binding can
materialize the stack copy and crash.

```rust
// BAD: stack overflow in debug, brittle in release
let buf = Box::new([0u8; 1024 * 1024]);

// GOOD: heap allocation guaranteed by Vec
let buf: Box<[u8]> = vec![0u8; 1024 * 1024].into_boxed_slice();
```

**ESP32 firmware note:** this matters more on embedded than on desktop.
This workspace's task stacks are sized in tens of KB (see CLAUDE.md
"Hardware Memory Budget"). A 4 KB array on the stack of a task with an
8 KB stack is half the budget. For any buffer >= 1 KB inside an embassy
task, allocate via `Vec` / `Box::<[u8]>::new_uninit_slice` (with explicit
`assume_init`) or a static `StaticCell` -- never via `Box::new([0; N])`
or a stack-local array bound to a `let`.

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

### DON'T: Use algebraic float methods where the result must be reproducible (Rust 1.98+)

Rust 1.98 stabilized `algebraic_add`, `algebraic_sub`, `algebraic_mul`,
`algebraic_div`, and `algebraic_rem` on `f32` and `f64` (all `const`-stable).
They permit the optimizer to apply the algebraic properties of *real* numbers
-- associativity, distributivity, reassociation -- even though those properties
do **not** hold for IEEE-754 floats. The effect is comparable to `-ffast-math`
in C, and it unlocks loop vectorization that ordinary float ops block.

The critical property: **they are non-deterministic.** The exact set of
optimizations is unspecified, and the compiler is free to choose differently
across call sites, optimization levels, targets, and compiler versions. They
never cause undefined behaviour, but they do not produce a single defined
answer.

```rust
// Ordinary float addition is not associative, so this is pinned to
// left-associative evaluation: ((a + b) + c) + d
let total = a + b + c + d;

// algebraic_add lets the compiler reassociate, e.g. (a + b) + (c + d),
// evaluating partial sums in parallel. Faster, but a different result.
let total = a.algebraic_add(b).algebraic_add(c).algebraic_add(d);
```

Never use `algebraic_*` for a value that is:

- **compared** for equality or ordering (including sort keys and dedup)
- **hashed**, or used as a map key
- **serialized**, persisted, or sent over the wire
- **asserted on** in a test (results may differ between debug and release)
- part of **billing, quota, rate-limit, or audit** accounting
- fed into an **alerting threshold** or any control-flow decision that must be
  reproducible across nodes

Acceptable uses are throughput-oriented numeric kernels where the result is
already approximate and no consumer depends on bit-exactness: DSP filters,
sensor smoothing, audio/graphics mixing, ML inference, physics integration.

**Server note.** For an HTTP/MCP server this rule is close to absolute. Metrics
that feed alerting, rate-limit accounting, and timing budgets must all be
reproducible; two replicas computing different values from the same inputs is a
debugging nightmare. Prefer integer or fixed-point arithmetic for anything
resembling accounting.

**ESP32 firmware note.** This is where `algebraic_*` genuinely pays off. Sensor
fusion, IIR/FIR filtering, FFT bins, and PID loops are all approximate by
nature, and the reassociation frequently enables vectorization or lets the
compiler fold a division into a reciprocal multiply -- a real win on a
microcontroller. Use them there, but keep them out of any value that is
reported over MQTT, persisted to NVS, or compared against a setpoint that
triggers actuation.

### DO: Prefer std bit-manipulation methods over hand-rolled equivalents (Rust 1.97+)

Rust 1.97 stabilized a family of `const fn` bit helpers on every integer
type and on `NonZero<_>`. Prefer them over hand-rolled shift / mask /
`leading_zeros` arithmetic: they are branch-free, express intent directly,
and remove the off-by-one and zero-input traps that hand-rolled versions
invite. Same rationale as the `manual_checked_ops` lint (Section 9) -- let
the standard library say what you mean.

| Method | Returns | Example |
|--------|---------|---------|
| `n.bit_width()` | `u32` -- min bits to represent `n` | `0b1110u8.bit_width() == 4`; `0` for `0` |
| `n.isolate_highest_one()` | value with only the top set bit kept | `0b0110_0100u8 -> 0b0100_0000`; `0` for `0` |
| `n.isolate_lowest_one()` | value with only the bottom set bit kept | `0b0110_0100u8 -> 0b0000_0100`; `0` for `0` |
| `n.highest_one()` | `Option<u32>` -- index of the top set bit | `0b1_1111u8 -> Some(4)`; `None` for `0` |
| `n.lowest_one()` | `Option<u32>` -- index of the bottom set bit | `0b1_1111u8 -> Some(0)`; `None` for `0` |

```rust
// BAD: hand-rolled, easy to get the off-by-one or the zero case wrong
let top_bit_mask = 1u32 << (u32::BITS - 1 - x.leading_zeros()); // underflows at x == 0
let width = u32::BITS - x.leading_zeros();

// GOOD (Rust 1.97+): intent is explicit, zero is handled, all const fn
let top_bit_mask = x.isolate_highest_one(); // 0 when x == 0, no shift overflow
let width = x.bit_width();                   // 0 when x == 0
```

Note the two shapes: `isolate_*_one` returns the **bit itself** (a mask),
while `highest_one` / `lowest_one` return the **index** as `Option<u32>`
(`None` when the input is zero -- no `u32::BITS` sentinel to special-case).

**Now lint-enforced (Clippy 1.98+).** This was prose-only guidance when it was
introduced. Clippy 1.98 added
[`manual_isolate_lowest_one`](https://github.com/rust-lang/rust-clippy/pull/17037),
which flags the hand-rolled `x & x.wrapping_neg()` and `x & -x` forms and
suggests `x.isolate_lowest_one()`. It is a **`complexity`-tier** lint, so it is
already covered by `clippy::all = "deny"` -- no separate declaration needed. The
lint is MSRV-aware via the `msrv` key in `clippy.toml` (or `package.rust-version`),
so it stays quiet on crates pinned below 1.97.

MSRV note: these are 1.97 APIs. Adopting them raises your minimum toolchain
to 1.97 -- honor your MSRV policy (Section 12). This is a non-issue for any
crate already on `rust-version = "1.98.0"` or later; check before using them
in a crate that pins an older toolchain (notably `no_std` / ESP32 crates,
which often lag stable to match a vendor HAL release).

### DO: Format integers with `format_into` + `NumBuffer` instead of allocating (Rust 1.98+)

Rust 1.98 stabilized `core::fmt::NumBuffer<T>` and `<{integer}>::format_into`.
`NumBuffer::<T>::new()` is `const`-stable and sized to hold the decimal form of
any value of `T`; `format_into` writes into it and returns a `&str` borrowed
from the buffer. It also bypasses most of the dynamic dispatch that buffered
`write!` formatting incurs.

```rust
use core::fmt::NumBuffer;

// BAD: heap allocation per call, in a hot path
let s = value.to_string();
let s = format!("{value}");

// GOOD: no allocation, buffer reusable across iterations
let mut buf = NumBuffer::<u64>::new();
for value in values {
    let s: &str = value.format_into(&mut buf);
    sink.write_str(s)?;
}
```

Two consequences worth acting on:

- **Supply chain (Section 10).** The
  [`itoa-benchmark`](https://github.com/dtolnay/itoa-benchmark) repo now shows
  `format_into` performing on par with `itoa` itself. That makes `itoa` -- and
  similar integer-formatting micro-crates -- a removable dependency. Fewer
  transitive deps is less audit surface. Check with `cargo machete` /
  `cargo tree` after migrating.
- **ESP32 / `no_std` relevance.** `NumBuffer` lives in `core`, not `alloc`.
  This is the idiomatic way to render integers into a log line, a display
  buffer, or an MQTT payload on a target with no allocator, replacing
  `heapless::String` + `write!` juggling and hand-sized `[u8; 20]` scratch
  arrays.

### DO: Use `substr_range` / `subslice_range` to recover offsets, never pointer arithmetic (Rust 1.98+)

Recovering "where did this sub-slice come from in the parent buffer?" was
previously done with raw address subtraction, which requires `unsafe`, is easy
to get wrong under provenance rules, and is silently incorrect if the sub-slice
did not actually originate from that parent. Rust 1.98 stabilized
`str::substr_range` and `[T]::subslice_range` for exactly this.

```rust
// BAD: unsafe, provenance-hostile, and forbidden under `unsafe_code = "forbid"`
let offset = unsafe { sub.as_ptr().offset_from(parent.as_ptr()) as usize };
let range = offset..offset + sub.len();

// GOOD: safe, returns None when `sub` is not a subslice of `parent`
let range: Option<Range<usize>> = parent.substr_range(sub);   // &str
let range: Option<Range<usize>> = parent.subslice_range(sub); // &[T]
```

Both return `Option`, so the "not actually a subslice" case is handled rather
than producing a garbage offset. Neither performs a search -- they are pure
address math on a slice you already hold.

Caveat: `subslice_range` **panics if `T` is a zero-sized type**. Guard generic
code, or restrict the call to concrete element types.

This is the safe replacement for a pattern that previously forced an `unsafe`
block, which makes it directly useful in crates running `unsafe_code = "forbid"`
-- tokenizers, header parsers, and span-tracking error reporters no longer need
an escape hatch.

### DO: Use `Atomic<T>::from_mut` family instead of transmuting to atomics (Rust 1.98+)

Rust 1.98 stabilized `Atomic<T>::from_mut`, `Atomic<T>::from_mut_slice`, and
`Atomic<T>::get_mut_slice`. These convert between exclusively-borrowed plain
storage and an atomic view. Because `&mut` proves there is no concurrent
access, the conversion is sound and requires no `unsafe`.

```rust
// BAD: unsafe slice transmute, easy to get wrong and forbidden under
// `unsafe_code = "forbid"`
let atomics: &mut [AtomicU32] =
    unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr().cast(), v.len()) };

// GOOD: safe, checked conversion
let atomics: &mut [Atomic<u32>] = Atomic::from_mut_slice(&mut v);
```

Typical use: build or initialize a buffer single-threaded through plain `&mut`
access, then hand out an atomic view to worker threads -- without paying for
atomic operations during the initialization phase and without an `unsafe` block
at the boundary.

### DO: Use `ptr::read_unaligned` (or `from_le_bytes`) for multi-byte reads from `&[u8]`

ESP32-C3 and C6 are RISC-V (`riscv32imc` / `riscv32imac`). Unlike x86, RISC-V
does **not** guarantee that unaligned loads work. Depending on CPU
configuration, an unaligned multi-byte load either traps and is emulated by
an exception handler (10-100x slower) or raises `LoadStoreMisaligned` and
panics. Safe Rust never produces unaligned loads because references are
always aligned -- the hazard appears **only in `unsafe` code that
casts a `*const u8` to `*const u16`/`u32`/etc.** This workspace's lint
posture is `unsafe_code = "deny"` plus SAFETY-commented `#[allow(unsafe_code)]`
(see CLAUDE.md "Memory Safety Checklist"), so unsafe blocks **do** exist
and the alignment rule applies.

```rust
// BAD: undefined behaviour on RISC-V if buf.as_ptr().add(2) is not 2-aligned.
// `*const u16` deref and `ptr::read::<u16>` BOTH require T-alignment.
// `&[u8]` is only 1-byte aligned. This compiles, runs on x86, traps on ESP32.
let value: u16 = unsafe { *(buf.as_ptr().add(2) as *const u16) };
let value: u16 = unsafe { core::ptr::read(buf.as_ptr().add(2) as *const u16) };

// GOOD: safe, no `unsafe`, optimizer emits one load on platforms that allow it.
// Note: no `unwrap()` and no `buf[2..4]` indexing -- both are deny-level in
// Section 9 (`unwrap_used`, `indexing_slicing`). Propagate the error instead.
let bytes: [u8; 2] = buf.get(2..4).ok_or(FrameError::Truncated)?
    .try_into().map_err(|_| FrameError::Truncated)?;
let value = u16::from_le_bytes(bytes);

// GOOD: when slice-to-array conversion is awkward (e.g. C FFI struct copy-out),
// `read_unaligned` is the unsafe escape hatch. It explicitly tolerates any
// alignment. SAFETY: comment must justify provenance and bounds.
// SAFETY: `buf` is &[u8; >=4] from validated MQTT frame, `offset+2 <= len`.
let value: u16 = unsafe { core::ptr::read_unaligned(buf.as_ptr().add(2) as *const u16) };
```

Rules:

- **Applicability.** This whole section only bites in crates that permit
  `unsafe`. Under `unsafe_code = "forbid"` (Section 9) the hazardous forms are
  unrepresentable, so the rule is moot -- server/library crates can skip it.
  Firmware crates should be on `unsafe_code = "deny"` with justified per-item
  `#[allow(unsafe_code)]`, which is exactly where this applies.
- For multi-byte reads out of `&[u8]` buffers, prefer the safe idiom:
  `u16::from_le_bytes(...)` (or `from_be_bytes`) over a bounds-checked slice.
  Bounds-check once and reuse the result. Note that `slice.try_into().unwrap()`
  appears in a lot of sample code but violates `unwrap_used = "deny"` --
  propagate the `TryFromSliceError` instead:

  ```rust
  // GOOD: no unwrap, no unsafe, error is propagated
  let bytes: [u8; 2] = buf.get(2..4).ok_or(ParseError::Truncated)?
      .try_into().map_err(|_| ParseError::Truncated)?;
  let value = u16::from_le_bytes(bytes);
  ```

- If you must use raw pointers (FFI struct read-out, `repr(C)` overlay),
  use `core::ptr::read_unaligned` -- never `ptr::read` or `*ptr` on a
  cast pointer.
- **Rust 1.98+ removed two former excuses for reaching into `unsafe` here.**
  If the goal was recovering a sub-slice's offset in its parent, use
  `subslice_range` / `substr_range`. If the goal was viewing a plain buffer as
  atomics, use `Atomic::from_mut_slice`. Both are documented above in this
  section and are safe.
- This bug class is **invisible on x86 CI**. Unaligned loads succeed
  silently on host machines. The trap only fires on the target hardware,
  so code review and the guideline are the primary defenses. Miri does not
  help here either -- it targets the host (Section 12).
- Hot sites in this workspace: `haier.rs` UART frame parsing (u16
  power/current/PM2.5 fields out of `&[u8]` payloads), `ota.rs` ESP32
  image header parsing (u32 segment count out of streamed firmware
  buffer), `mqtt.rs` packet-length and packet-ID parsing out of TCP RX
  buffers, `tls.rs` mbedTLS FFI boundary where C writes into Rust-owned
  buffers.
- `bytemuck::pod_read_unaligned` is a safe wrapper for `Pod` types if you
  want zero `unsafe`; pulling the dep in is acceptable when the parsing
  surface area grows.

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

**LLM-bias note.** LLM-generated async code defaults to `std::sync::Mutex`
because that type dominates non-async Rust in training data. Review every
`Mutex` import in async modules:

- `tokio` async tasks: use `tokio::sync::Mutex` when the guard may live
  across `.await`; `std::sync::Mutex` only when the critical section is
  strictly synchronous and short.
- This firmware (embassy, `no_std`): use `embassy_sync::mutex::Mutex` for
  async-aware locks. `embassy_sync::blocking_mutex::Mutex` (with the
  `CriticalSectionRawMutex` raw mutex) is correct **only** when the
  critical section never `.await`s -- typical use is for `Signal`,
  `Channel`, or shared state read/written without yielding.
- `clippy::await_holding_lock` catches the obvious case (guard variable
  visibly alive across `.await` in the same function) but does **not**
  see through helper-function returns, struct fields, or
  `MutexGuard::map`. Treat the lint as necessary but not sufficient.

### DO: Use `tokio::task::yield_now()` in CPU-bound async loops

If you must do CPU work in an async context, yield periodically to avoid
starving other tasks.

### DO: Annotate every async fn with cancel safety (cancel-safe / NOT cancel-safe)

Futures in Rust are cancellable at **every** `.await` point. Any future used
inside `tokio::select!`, `tokio::time::timeout`, `embassy_futures::select`,
or `JoinHandle::abort` can be dropped between awaits, leaving partial state.
Cancel safety is **not expressible in the type system** -- there is no
`CancelSafe` marker trait. It lives only in documentation, and a refactor
that moves a previously-sequential function into a `select!` arm will
silently turn correct code into a duplicate-write / partial-state bug.

LLM-generated code almost never raises this on its own. Treat the
annotation as mandatory, not optional.

```rust
// NOT cancel-safe: if dropped between insert() and send_ack(), we wrote
// to the DB but never acknowledged, so the client will retry and we duplicate.
async fn process(stream: TcpStream, db: &Db) -> Result<()> {
    let data = read_message(&stream).await?;
    db.insert(&data).await?;       // <-- if cancelled here, dup on retry
    send_ack(&stream).await?;
    Ok(())
}

// GOOD: isolate the non-cancel-safe section so outer cancellation can't tear it.
async fn process(stream: TcpStream, db: Arc<Db>) -> Result<()> {
    let data = read_message(&stream).await?;
    // cancel-safe: read_message is cancel-safe per tokio docs.
    let handle = tokio::spawn(async move {
        db.insert(&data).await?;
        send_ack(&stream).await?;
        Ok::<_, Error>(())
    });
    handle.await?
}
```

Rules:

- Every async fn that may run inside `select!`, `timeout`, or an `abort`-able
  task MUST carry a `// cancel-safe: <reason>` or
  `// NOT cancel-safe: <reason>` doc comment. No exceptions.
- "All awaits are idempotent" is **not** a valid reason -- idempotency is
  about retries, not about partial state between awaits.
- Consult tokio docs per call. E.g. `AsyncReadExt::read` is cancel-safe,
  `read_exact` is NOT.
- For embassy on this firmware: `embassy_futures::select` cancels the
  losing branch by dropping its future. Same rules apply. See the
  `IR -> UART Flow` section in CLAUDE.md -- `haier_task` races a UART
  read against the command channel via `select`, so any future placed on
  either arm must be cancel-safe or wrapped in an unabortable region.

### DO: Audit Drop impls of async resources (transactions, connections, guards)

Drop runs on every exit path, including panics and cancellation. For types
returned from `.await` (DB transactions, pooled connections, async file
handles), the Drop impl may perform I/O. In an async runtime this can
either run blocking code on a worker thread or silently no-op.

```rust
// Subtle bug: commit() can itself fail. The tx then drops in an indeterminate
// state. Different libraries handle this differently:
//   - sqlx: Drop queues a rollback that runs on the *next* async invocation of
//     the underlying connection (or when returned to the pool). If nothing
//     drives the connection after the drop, the rollback never executes.
//     Source: launchbadge/sqlx, sqlx-core/src/transaction.rs Drop impl.
//   - deadpool-postgres: wraps tokio_postgres, which uses similar deferred
//     cleanup via the connection's background task; the rollback may not run
//     if the runtime is shutting down.
async fn run(pool: &Pool) -> Result<Data> {
    let tx = pool.get().await?.transaction().await?;
    match do_work(&tx).await {
        Ok(result) => { tx.commit().await?; Ok(result) }
        Err(e)    => { tx.rollback().await?; Err(e) }
    }
}
```

Rules:

- For every async resource type you `.await` into scope, know what its Drop
  does -- read the source, not just the docs.
- Prefer explicit `commit` / `rollback` / `close` on every path. Do not
  rely on Drop to clean up async work.
- If Drop is the only cleanup path, document it at the call site.

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

**Formatting note (Rust 1.98+):**
[rustfmt now discovers module files declared inside `cfg_select!`](https://github.com/rust-lang/rust/pull/158372).
Previously those `mod` declarations were invisible to rustfmt and the modules
behind them went unformatted. On 1.98 they are picked up, so "this may cause
more code to be formatted which was previously ignored."

Practical consequence: if your CI runs `cargo fmt --all -- --check` as a
blocking gate (Section 12), introducing `cfg_select!` -- or simply upgrading to
1.98 with existing `cfg_select!` usage -- can fail the gate on files nobody
touched. Run `cargo fmt --all` once at the upgrade and commit the result as a
separate formatting-only change, so the reformat does not contaminate a
feature diff.

This is most likely to bite `no_std` / ESP32 crates, where platform- and
peripheral-gated module trees are common and `cfg_select!` is the natural
replacement for `cfg-if`.

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

// GOOD: Deny a specific, curated set of lints you have chosen to enforce
#![deny(unused, dead_code)]
```

Enforce "no warnings" at the CI boundary instead. **Rust 1.97+** stabilized
Cargo's [`build.warnings`](https://doc.rust-lang.org/cargo/reference/config.html#buildwarnings)
config, which is now the preferred mechanism -- it is cache-friendly
(changing it does **not** invalidate the build cache, unlike `RUSTFLAGS`)
and it applies only to your **local** packages, never to dependencies.

```toml
# .cargo/config.toml -- deny warnings for local packages
[build]
warnings = "deny"     # "warn" (default) | "allow" | "deny"
```

```bash
# Or per-invocation via env var (no cache bust, trivial to toggle):
CARGO_BUILD_WARNINGS=deny  cargo check --workspace   # CI: fail on any warning
CARGO_BUILD_WARNINGS=allow cargo check               # local: silence transient noise
# Pair with --keep-going to collect every warning, not just the first package's:
CARGO_BUILD_WARNINGS=deny  cargo check --workspace --keep-going

# Pre-1.97 fallback (busts the build cache, blunt instrument):
RUSTFLAGS="-D warnings" cargo build
```

Caveat: `build.warnings` gates rustc's `warnings` lint group only. The
`linker_messages` lint (Rust 1.97+, see Section 9) is deliberately **not**
in that group, so neither `build.warnings = "deny"` nor `RUSTFLAGS="-D warnings"`
affects it -- escalate it separately if you want linker output to fail CI.

### Blanket Impls in Public APIs (Semver Hazard)

`impl<T: SomeBound> MyTrait for T` in a published crate is a semver hazard.
Downstream code may already have its own `impl MyTrait for Foo` that
compiles today; if you later add a second blanket impl, narrow the bound,
or add another impl that overlaps, downstream compilation breaks. The
breakage surfaces only on the consumer's CI, often months later.

```rust
// BAD in a public API: any downstream `impl MyTrait for ConcreteType`
// becomes a coherence-error tripwire on future versions of this crate.
pub trait MyTrait { fn do_it(&self) -> String; }
impl<T: Display> MyTrait for T {
    fn do_it(&self) -> String { format!("{}", self) }
}

// GOOD: per-type impls, or seal the trait so downstream can't impl it.
pub trait MyTrait: sealed::Sealed { fn do_it(&self) -> String; }
mod sealed { pub trait Sealed {} }
impl sealed::Sealed for String {}
impl MyTrait for String { fn do_it(&self) -> String { self.clone() } }
```

Rules:

- Blanket impls in `pub` trait-or-type combinations require the trait to
  be **sealed** (private supertrait pattern) so only this crate can add
  impls.
- If the trait is meant to be implementable downstream, write per-type
  impls in this crate -- no blanket impls.
- Internal (`pub(crate)` or smaller) blanket impls are fine.

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
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
# AI-generated code: extra unstable lints catch patterns pedantic misses.
# Expect noise; allow specific lints individually below with a justification.
nursery = { level = "warn", priority = -1 }
```

**`priority = -1` is mandatory on group entries.** Cargo evaluates `[lints]`
in priority order, and entries at equal priority conflict when a group and an
individual lint overlap. Without the lower priority on the groups, a
per-lint override such as `missing_const_for_fn = "allow"` fights the
`nursery` group entry and Cargo rejects the manifest. The bare
`all = "deny"` form only works if you never override a single lint from that
group -- which is not a realistic end state.

Group-level `allow`s should always carry a comment saying *why*, e.g.:

```toml
# nursery allow: opting fns into `const` is a one-way semver promise
# (removing `const` later is breaking), and the lint has known false
# positives. Keep it a deliberate per-fn decision, not lint-driven churn.
missing_const_for_fn = "allow"
```

### Clippy Thresholds (`clippy.toml`)

Several lints below are threshold-driven and are near-useless at their
defaults. Pin the thresholds in a `clippy.toml` at the crate (or workspace)
root so the numbers are reviewable and consistent:

```toml
# clippy.toml
cognitive-complexity-threshold = 25   # drives `cognitive_complexity`
too-many-lines-threshold = 100        # drives `too_many_lines`
max-fn-params-bools = 3               # drives `fn_params_excessive_bools`
enum-variant-size-threshold = 200     # drives `large_enum_variant`
```

Note the split: **lint levels** live in `Cargo.toml` under `[lints.clippy]`,
**lint configuration** lives in `clippy.toml`. They are different files and
neither can express the other.

`clippy.toml` also accepts an `msrv` key, which falls back to
`package.rust-version`. MSRV-aware lints (including 1.98's
`manual_isolate_lowest_one`, Section 4) stay silent when the suggested API
postdates your MSRV -- so keep `rust-version` accurate rather than setting
`msrv` twice.

### Defensive Programming Lints

```toml
[lints.clippy]
indexing_slicing = "deny"          # Prefer .get() or pattern matching
fallible_impl_from = "deny"        # From impls that should be TryFrom
wildcard_enum_match_arm = "deny"   # No catch-all _ in enums
fn_params_excessive_bools = "deny" # Too many bool params
must_use_candidate = "warn"        # Suggest #[must_use]
unneeded_field_pattern = "warn"    # Unnecessary .. in patterns
await_holding_lock = "deny"        # Held std/parking_lot MutexGuard across .await
                                   # (catches the obvious case only -- still
                                   # review every Mutex import in async modules)
cast_ptr_alignment = "deny"        # *const u8 as *const u16 -- UB on RISC-V
                                   # (see Section 4 "ptr::read_unaligned")
```

**Omit the pointer lints when the crate sets `unsafe_code = "forbid"`.**
`cast_ptr_alignment`, `transmute_ptr_to_ref`, and `not_unsafe_ptr_arg_deref`
all describe hazards that are unreachable without an `unsafe` block. In a
crate that forbids `unsafe` outright they are dead configuration -- keep them
for firmware and FFI crates (which run `unsafe_code = "deny"`), drop them
elsewhere and say so in a comment so the omission reads as deliberate rather
than forgotten.

### Panic Prevention Lints

A server process must never panic in production. These lints enforce
compile-time prevention of runtime panics.

```toml
[lints.clippy]
unwrap_used = "deny"               # No .unwrap() anywhere - use ?, unwrap_or, etc.
expect_used = "deny"               # .expect() is marginally better but still panics
panic = "deny"                     # No intentional panic!() in production paths
todo = "deny"                      # No todo!() - these panic at runtime
unimplemented = "deny"             # No unimplemented!() - same as todo
unreachable = "warn"               # Prefer compiler-proven unreachable via match
```

`expect_used = "deny"` (not `"warn"`): a panic is a panic regardless of whether
it carries a message. The message improves the postmortem but does not keep the
process alive. Denying both makes the exception path explicit -- an
`#[allow(clippy::expect_used)]` with a justification comment -- rather than
letting `expect` accumulate silently as warnings nobody clears.

The one broadly defensible exception is a `const` initializer, where the
"panic" is a compile-time evaluation failure and cannot occur at runtime:

```rust
// SAFETY/INVARIANT: 30 is a non-zero literal; this is evaluated at compile
// time, so a failure here is a build error, never a runtime panic.
const DEFAULT_AUTH_RATE: NonZeroU32 = NonZeroU32::new(30).unwrap();
```

Note that Rust 1.98's `NonZero::from_str_radix` (Section 2) removes the need
for this shape when the value comes from a string rather than a literal.

**Liveness, not just panics (Clippy 1.98+).** A server can also be taken down
by a loop that never terminates. Clippy 1.98 added
[`for_unbounded_range`](https://github.com/rust-lang/rust-clippy/pull/16257),
which flags `for` loops over unbounded integer or `char` ranges that may wrap,
panic, or spin forever:

```rust
// BAD: wraps or panics at u8::MAX depending on profile; never terminates cleanly
for i in 250u8.. { }

// GOOD: bounded
for i in 250u8..=u8::MAX { }
```

It is a **`suspicious`-tier** lint, so `clippy::all = "deny"` already covers it
-- no separate declaration needed.

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
str_to_string = "warn"            # Prefer .to_owned() or .into()
string_slice = "warn"             # `&s[a..b]` panics on non-char-boundary
```

`string_slice` is the string-specific companion to `indexing_slicing`
(Defensive Programming Lints, above). Byte-range slicing of a `str` panics
when an index falls inside a multi-byte UTF-8 sequence -- and that is
attacker-reachable wherever the slice bounds derive from external input.
Non-ASCII input is a realistic trigger for anything parsing headers, tokens,
tool arguments, or identifiers.

```rust
// BAD: panics if byte 8 is not a char boundary (e.g. "naïve-token")
let prefix = &token[..8];

// GOOD: never panics, and the truncation point is explicit
let prefix = token.get(..8).unwrap_or(token);
// GOOD: iterate by chars when you mean "first 8 characters"
let prefix: String = token.chars().take(8).collect();
```

**Removed: `string_to_string`.** This lint no longer exists -- Clippy
deprecated it, and
[`implicit_clone`](https://github.com/rust-lang/rust-clippy/blob/master/clippy_lints/src/deprecated_lints.rs)
(already enabled under "Performance-Related Clippy Lints" below) covers the
same `String::to_string()` cases. Declaring it now produces an
`unknown_lints` warning. Delete it from existing manifests.

**`with_capacity_zero` (Clippy 1.98+).** Flags
`Vec::with_capacity(0)`, `String::with_capacity(0)`, `PathBuf::with_capacity(0)`,
`OsString::with_capacity(0)`, and the equivalent collection constructors, all of
which are just a more expensive spelling of `new()`. It is a **`pedantic`-tier**
lint, so it is **not** covered by `clippy::all = "deny"` -- but it *is* active
for anyone running `pedantic = "warn"` as recommended above. Usually just follow
the suggestion; the exception is a capacity computed at runtime that happens to
be zero, where the literal-zero form is not what you wrote anyway.

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
clone_on_ref_ptr = "deny"         # Arc::clone(&x) over x.clone()
```

`clone_on_ref_ptr = "deny"` (not `"warn"`): `x.clone()` on an `Arc`/`Rc` is
indistinguishable at a glance from a deep clone of the pointee. Forcing the
explicit `Arc::clone(&x)` spelling makes "this is a refcount bump, not an
allocation" visible at every call site -- which is precisely the distinction
Section 1 relies on when it says cloning an `Arc` is acceptable.

Clippy 1.95 added two `complexity`-tier lints that are already covered by
`clippy::all = "deny"` and do not need separate declarations:

- `manual_checked_ops` - prefer `checked_add`/`checked_sub`/`checked_mul`
  over hand-rolled overflow checks.
- `manual_take` - prefer `std::mem::take(&mut x)` over
  `mem::replace(&mut x, Default::default())`.

### Numeric and Pointer Cast Lints

`as` casts are silent. They truncate, wrap, and change signedness without a
diagnostic, which makes them a poor fit for a codebase that otherwise denies
`unwrap`. These two lints push every cast toward an explicit, checked form.

```toml
[lints.clippy]
cast_lossless = "warn"            # `x as u64` where `u64::from(x)` is infallible
ptr_as_ptr = "warn"               # `p as *const T` -> `p.cast::<T>()`
```

- `cast_lossless` catches *widening* casts that cannot fail and should be
  spelled as a `From` conversion, so the reader can tell at a glance that no
  data is lost. It pairs with `clippy::all`'s existing coverage of the
  *narrowing* direction (`cast_possible_truncation` under `pedantic`), where
  the fix is `TryFrom` and a real error path (Section 2).
- `ptr_as_ptr` is worth keeping even under `unsafe_code = "forbid"`: `.cast()`
  preserves mutability and constness in the type system, whereas an `as` cast
  will happily convert `*const T` to `*mut T` if you typo the target type.

```rust
// BAD: `as` hides which conversions are lossless and which are not
let total = count as u64;
let p = raw as *const Header;

// GOOD: infallible widening is explicit; narrowing gets a real error path
let total = u64::from(count);
let port = u16::try_from(raw_port).map_err(|_| ConfigError::PortOutOfRange)?;
let p = raw.cast::<Header>();
```

### Documentation Lints

```toml
[lints.clippy]
doc_markdown = "allow"            # see rationale below
duration_suboptimal_units = "allow"
```

Both are **deliberate opt-outs**, listed here so their absence reads as a
decision rather than an oversight:

- `doc_markdown` (pedantic) demands backticks around anything resembling an
  identifier in prose. On docs that legitimately discuss protocol and product
  names -- `OAuth`, `JWKS`, `RFC 7239`, `PowerShell` -- it produces a
  steady stream of false positives, and the churn of backticking proper nouns
  degrades readability. Turn it back on only if you also maintain a
  `doc-valid-idents` list in `clippy.toml`.
- `duration_suboptimal_units` (pedantic) rewrites e.g.
  `Duration::from_millis(5000)` into `from_secs(5)`. That is fine in
  isolation, but harmful where a family of related constants is deliberately
  expressed in one unit so they can be compared by eye
  (`from_millis(500)` / `from_millis(5_000)` / `from_millis(30_000)`).

### Group-Level Allows Must Carry a Reason

Enabling `pedantic` and `nursery` at `warn` (plus CI's `-D warnings`) means
some lints will need to be switched off. Each one is a standing decision and
must say why, in the manifest, next to the `allow`:

```toml
[lints.clippy]
# nursery allow: opting fns into `const` is a one-way semver promise
# (removing `const` later is breaking) and the lint has documented false
# positives; keep it a deliberate per-fn decision, not lint-driven churn.
missing_const_for_fn = "allow"

# nursery allow: antagonistic to rustc's `unreachable_pub = "warn"`, which
# prefers `pub(crate)` for crate-internal items. Two lints, opposite advice.
redundant_pub_crate = "allow"

# nursery allow: frequently degrades readability -- the rewrite contorts
# poisoned-lock `match` idioms and multi-statement tracing arms that are
# clearer as `if let` / `let ... else`.
option_if_let_else = "allow"
```

An `allow` without a reason is indistinguishable from a lint someone
silenced to make CI green. Rust's `reason = "..."` attribute field
(usable on `#[allow]` / `#[expect]` in code) is the in-source equivalent and
should be used at every suppression site -- see the "Panic Prevention Lints"
exception policy above.

### Clippy 1.98 New Lints

Clippy 1.98 added seven lints. **Five require no action** -- they land in tiers
already covered by `clippy::all = "deny"`. Two are `pedantic` and therefore
need an explicit decision from anyone running `pedantic = "warn"`.

| Lint | Tier | Covered by `all = "deny"`? | Action |
|------|------|----------------------------|--------|
| [`for_unbounded_range`](https://github.com/rust-lang/rust-clippy/pull/16257) | suspicious | yes | none -- see "Panic Prevention" above |
| [`by_ref_peekable_peek`](https://github.com/rust-lang/rust-clippy/pull/17042) | suspicious | yes | none -- real bug class, see below |
| [`manual_isolate_lowest_one`](https://github.com/rust-lang/rust-clippy/pull/17037) | complexity | yes | none -- enforces the Section 4 bit-ops rule |
| [`unnecessary_unwrap_unchecked`](https://github.com/rust-lang/rust-clippy/pull/16252) | complexity | yes | none -- moot under `unsafe_code = "forbid"` |
| [`chunks_exact_to_as_chunks`](https://github.com/rust-lang/rust-clippy/pull/16931) | style | yes | none |
| [`with_capacity_zero`](https://github.com/rust-lang/rust-clippy/pull/17192) | **pedantic** | **no** | decide -- see "String Handling" above |
| [`unused_async_trait_impl`](https://github.com/rust-lang/rust-clippy/pull/16244) | **pedantic** | **no** | **decide -- see below** |

`by_ref_peekable_peek` is worth knowing on sight because it is a genuine
silent-data-loss bug, not a style nit. `.by_ref().peekable()` builds a
*temporary* `Peekable` adapter; peeking pulls an item out of the underlying
iterator, and when the temporary is dropped that item is gone:

```rust
// BAD: consumes an item from `iter` and then discards it
let first = iter.by_ref().peekable().peek();

// GOOD: if you meant to consume, say so
let first = iter.next();
// GOOD: if you meant to peek, keep the Peekable alive
let mut peekable = iter.by_ref().peekable();
let first = peekable.peek();
```

**`unused_async_trait_impl` needs a deliberate decision.** It fires on an
`async fn` in a trait impl whose body never `.await`s, and suggests rewriting
the signature to `fn … -> impl Future` returning `std::future::ready(..)`.

```rust
// Lint fires: no .await in the body
impl ServerHandler for MyHandler {
    async fn get_info(&self) -> ServerInfo { ServerInfo::default() }
}

// Suggested rewrite
impl ServerHandler for MyHandler {
    fn get_info(&self) -> impl Future<Output = ServerInfo> {
        std::future::ready(ServerInfo::default())
    }
}
```

The suggestion is technically correct -- it avoids a state machine for a value
that is immediately ready -- but the rewrite is often **impossible**, not merely
undesirable: when you are *implementing* a foreign trait, the `async fn`
signature is dictated by that trait and cannot be changed from your side.

**Prefer a per-item `#[allow]` with a `reason`, not a crate-level allow.** A
blanket `unused_async_trait_impl = "allow"` in `Cargo.toml` also silences the
cases where the lint is right (a genuinely unnecessary `async fn` you *could*
desugar, or a forgotten `.await`). Scope the exemption to the impls where the
trait forces your hand:

```rust
#[expect(
    clippy::unused_async_trait_impl,
    reason = "async is mandated by the ServerHandler trait signature; the \
              impl cannot drop it without failing to satisfy the trait"
)]
impl ServerHandler for MyHandler {
    async fn get_info(&self) -> ServerInfo { ServerInfo::default() }
}
```

Real-world instances of exactly this in a `-D warnings` build: axum's
`FromRequestParts::from_request_parts` and rmcp's `ServerHandler::call_tool`.
Both are foreign traits whose async signature is fixed, so the lint's suggested
rewrite would simply not compile.

Prefer `#[expect(...)]` over `#[allow(...)]` where your MSRV permits: it warns
if the lint *stops* firing, so the exemption is removed automatically once the
upstream trait changes or the impl grows a real `.await`.

Reserve a crate-level `unused_async_trait_impl = "allow"` for the case where the
noise is genuinely pervasive across many first-party impls -- and say so in a
comment, because it is the blunter instrument.

### Clippy 1.98 Removals and Moves

- **`from_iter_instead_of_collect` was removed.** Previously `pedantic`; Clippy
  [deprecated it](https://github.com/rust-lang/rust-clippy/pull/17208) as
  "proved problematic". Delete any explicit declaration.
- **`empty_enums` moved `pedantic` → `nursery`**
  ([PR #17298](https://github.com/rust-lang/rust-clippy/pull/17298)). No effect
  if you run both groups at `warn` as recommended; it silently disappears if
  you run `pedantic` without `nursery`.
- **`result_large_err` / `result_unit_err` now fire on `async fn`**
  ([PR #17130](https://github.com/rust-lang/rust-clippy/pull/17130)). Both are
  in `clippy::all`, so async-heavy crates may see **new** denials on upgrade
  from previously-exempt async signatures. This is the most likely source of a
  surprise `-D warnings` failure when moving to 1.98.

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
dead_code_pub_in_binary = "warn"   # Rust 1.97+: unused `pub` items in a binary
                                   # crate (allow-by-default; opt in for bins)
```

`unsafe_code = "forbid"` should be set in every crate that does not need
`unsafe`. For crates that require specific `unsafe` blocks, use
`unsafe_code = "deny"` at crate level and `#[allow(unsafe_code)]` on the
individual items with a safety comment explaining the invariant.

**Rust 1.98+: the lint now covers unsafe *attributes*, not just unsafe blocks.**
[Rust 1.98 made `UNSAFE_CODE` fire consistently for all unsafe
attributes](https://github.com/rust-lang/rust/pull/157201). In edition 2024
these carry an explicit `unsafe(...)` wrapper:

```rust
#[unsafe(no_mangle)]        // now trips unsafe_code
#[unsafe(export_name = "…")] // now trips unsafe_code
#[unsafe(link_section = "…")] // now trips unsafe_code
#[unsafe(naked)]             // now trips unsafe_code
```

Consequences:

- A crate with `unsafe_code = "forbid"` that used any of these attributes
  **compiled on 1.97 and fails on 1.98**. This is the most likely 1.98 upgrade
  break for an otherwise `unsafe`-free crate. `forbid` cannot be locally
  overridden -- you must downgrade to `deny` + a justified per-item
  `#[allow(unsafe_code)]`, or remove the attribute.
- ESP32 / embedded relevance: `#[unsafe(link_section)]` and
  `#[unsafe(no_mangle)]` are common in firmware for placing data in specific
  memory regions and for exporting interrupt/entry symbols. Firmware crates
  should be on `unsafe_code = "deny"` (not `forbid`) precisely so these
  attributes remain expressible with a `// SAFETY:` justification.
- `unsafe_code` is **allow-by-default**, so it is not in the `warnings` lint
  group. Neither `RUSTFLAGS="-D warnings"` nor Cargo's `build.warnings`
  (Section 7) will enable it. It must be set explicitly in `[lints.rust]` --
  which is exactly why it appears in the table above.

### Runtime Symbol Definition Lints (Rust 1.98+)

Rust 1.98 added two lints that flag definitions of symbols the Rust runtime
reserves for itself -- currently `core` runtime symbols such as `memcmp`,
`memset`, and `strlen`, with coverage
[planned to expand in the next few releases](https://github.com/rust-lang/rust/pull/155521).
It also added a lint for `core::ffi::c_void` used as a return type.

| Lint | Default | In `warnings` group? | Covered by `-D warnings` / `build.warnings`? |
|------|---------|----------------------|-----------------------------------------------|
| `invalid_runtime_symbol_definitions` | **deny** | **no** | n/a -- already error-level |
| `suspicious_runtime_symbol_definitions` | warn | yes | yes |
| `c_void_returns` | warn | yes | yes |

Sources: [PR #155521](https://github.com/rust-lang/rust/pull/155521),
[PR #156379](https://github.com/rust-lang/rust/pull/156379).

These matter mainly for `no_std` / firmware crates and anything doing FFI:
defining your own `memcpy`/`memset` (a real pattern in bare-metal Rust) or
returning `c_void` from an `extern "C"` shim. Pure-Rust server crates with
`unsafe_code = "forbid"` will never trip them. Note the same
`warnings`-group asymmetry documented for `linker_messages` below:
`invalid_runtime_symbol_definitions` is deny-by-default and sits **outside**
the `warnings` group, so its level must be changed explicitly rather than via
a blanket warnings policy.

For library crates, `missing_docs = "warn"` ensures every public item
has documentation. Promote to `"deny"` once existing docs are complete.

For **binary** crates, `dead_code_pub_in_binary` (Rust 1.97+, allow-by-default)
extends dead-code detection to `pub` items. A binary has no public API, so
`pub` should not suppress the unused-code warning the way it does in a
library. It complements `unreachable_pub`: the latter flags `pub` that ought
to be `pub(crate)`, the former flags `pub` items that are simply never used.
Opt in for binary crates; leave it off for library crates, where `pub` items
are the intended API surface.

### Linker Diagnostics (Rust 1.97+)

Rust 1.97 stopped hiding linker stderr. Links that previously succeeded
silently now surface their output through a new warn-by-default
`linker_messages` lint:

```text
warning: linker stderr: <message>
  |
  = note: `#[warn(linker_messages)]` on by default
```

This is high-signal for any crate that links C libraries (`libopus`,
mbedTLS, OpenSSL, platform SDKs) or uses a custom linker script -- several
real defects were found upstream once this output stopped being swallowed.
Two properties matter:

- `linker_messages` is **not** part of the `warnings` lint group. Neither
  `RUSTFLAGS="-D warnings"` nor Cargo's `build.warnings = "deny"` (Section 7)
  affects it -- set its level explicitly.
- Linker output is platform-dependent and rustc does not control it
  precisely, so treat it as advisory. rustc already filters common false
  positives; triage the rest and silence known-benign, platform-specific
  noise deliberately rather than globally.

```toml
[lints.rust]
# Default is "warn". Escalate to "deny" only once the output is known-clean
# on every target you build; otherwise pin proven-benign noise to "allow"
# with a comment naming the platform and the exact message.
linker_messages = "warn"
```

### Lints for LLM-generated code

The lints below are individually listed in the other subsections, but
grouped here as the minimum surface specifically targeting failure modes
that pass `cargo build` and `cargo test` on LLM-written Rust. Source:
the Habr "Я заставил LLM писать Rust полгода" article (see References).

```toml
[lints.clippy]
# Async cancel-safety / Mutex hazards (Habr Category 2 + 5)
await_holding_lock = "deny"        # held std MutexGuard across .await
await_holding_refcell_ref = "deny" # held RefCell borrow across .await

# Unsafe alignment / pointer hazards (Habr Category 4)
cast_ptr_alignment = "deny"        # *const u8 as *const u16, ptr::read on unaligned
transmute_ptr_to_ref = "deny"      # mem::transmute hiding lifetime laundering
not_unsafe_ptr_arg_deref = "deny"  # safe fn that deref's a caller-provided ptr

# RAII / Drop hazards (Habr Category 3)
mem_forget = "deny"                # leaks Drop; almost always a bug

# Trait-system semver hazards (Habr Category 6)
# (no direct lint exists; rely on the Section 7 anti-pattern rule and
#  manual review of `impl<T: Bound> Trait for T` patterns.)

# Stack-allocated boxes / large arrays (Habr Category 7)
large_stack_arrays = "warn"        # arrays > clippy threshold on the stack
large_stack_frames = "warn"        # functions with large local frames

# AI-bias hazards (covered by clippy::pedantic + nursery already, but
# called out explicitly because they are high-signal on LLM code):
# - clippy::ptr_as_ptr
# - clippy::cast_lossless
# - clippy::redundant_clone
# - clippy::needless_pass_by_value
```

Limitations to be aware of:

- `await_holding_lock` only catches guards visibly alive across `.await`
  in the same function. Guards returned from a helper, stored in a struct
  field, or produced by `MutexGuard::map` slip past. Treat as necessary
  but not sufficient -- hand-review every `Mutex` import in async modules.
- `cast_ptr_alignment` fires on the obvious cast pattern but not on every
  way to construct a misaligned pointer (e.g. `slice::from_raw_parts` with
  a hand-computed offset). The Section 4 prose rule is still required.
- There is no clippy lint for blanket-impl semver hazards or for async
  cancel safety. Those remain prose-only rules in Sections 7 and 5.
- This workspace also enforces `cargo +nightly miri test` for files with
  `unsafe` (where the target permits -- see Section 12 "Miri caveats").
  Miri is the only reliable catch for the UB cases that pass clippy.

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

**Symbol mangling note (Rust 1.97+):** 1.97 switched the default symbol
mangling scheme to `v0`. Backtraces, `perf` / `flamegraph` output, debuggers,
and `tokio-console` traces may render symbols differently, and **old
demanglers may fail to demangle them entirely**. If a profiler shows raw
`_R...` symbols, update it (or `rustfilt`) to a v0-aware version. This is a
tooling-compatibility note only -- it does not change runtime behavior.

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

### DO: Use `strip_circumfix` for delimiter-wrapped input (Rust 1.98+)

Boundary parsers constantly need to remove a matching prefix *and* suffix:
quoted header values, bracketed IPv6 literals, `<...>` message IDs, fenced
tokens. The chained form is easy to get subtly wrong -- most commonly by
accepting input that has only one of the two delimiters. Rust 1.98 stabilized
`str::strip_circumfix` and `[T]::strip_circumfix`, which strip both atomically
or return `None`.

```rust
// BAD: two independent steps; a lone leading quote silently falls through
// to the `unwrap_or` and is treated as valid unquoted input.
let value = raw.strip_prefix('"')
    .and_then(|s| s.strip_suffix('"'))
    .unwrap_or(raw);

// GOOD: all-or-nothing, and the "malformed" case is explicit
let value = match raw.strip_circumfix("\"", "\"") {
    Some(inner) => inner,          // was properly quoted
    None if !raw.contains('"') => raw,  // legitimately unquoted
    None => return Err(ParseError::UnbalancedQuote),
};
```

Directly applicable to `Forwarded` header parsing (RFC 7239), which uses
quoted strings for `for=` / `by=` values and square brackets around IPv6
literals -- e.g. `for="[2001:db8::1]:4711"`. Stripping quotes and brackets
independently is how port-parsing and IP-parsing bugs get introduced into
client-IP resolution, which is security-relevant when that IP feeds rate
limiting or an allowlist.

### DO: Decode UTF-16 with explicit endianness at boundaries (Rust 1.98+)

Rust 1.98 stabilized `String::from_utf16le`, `from_utf16le_lossy`,
`from_utf16be`, and `from_utf16be_lossy`. These take `&[u8]` directly and
decode with a **stated** byte order.

```rust
// BAD: manual byte-pair assembly, endianness implicit in the shift order,
// and an intermediate Vec<u16> allocation
let units: Vec<u16> = bytes.chunks_exact(2)
    .map(|c| u16::from_le_bytes([c[0], c[1]]))   // also: indexing_slicing
    .collect();
let s = String::from_utf16(&units)?;

// GOOD: endianness is in the function name, no intermediate allocation
let s = String::from_utf16le(bytes)?;
```

Use the fallible (non-`_lossy`) form for anything security-relevant. Silent
U+FFFD substitution can collapse two distinct malformed inputs into the same
string, which is exactly the kind of normalization that defeats an allowlist
comparison. Reserve `_lossy` for display and logging.

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

### DO: Document every accepted advisory, never silently ignore one

`cargo audit` and `cargo deny` both support an `ignore` list. An ignore entry
with no rationale is indistinguishable from an unreviewed vulnerability six
months later. Every entry must name the advisory, state why it does not apply
to this crate, and note whether an upstream fix exists.

```toml
# .cargo/audit.toml
[advisories]
# RUSTSEC-2023-0071: Marvin timing sidechannel in `rsa` 0.9.x. No upstream
# fix. This crate validates JWTs with public keys only and never decrypts
# RSA payloads, so the timing sidechannel does not apply.
ignore = ["RUSTSEC-2023-0071"]
```

Keep `deny.toml` and `.cargo/audit.toml` in sync -- they are read by different
tools and an advisory suppressed in one will still fail the other in CI.

### WATCH: publish-age-aware resolution (`-Zmin-publish-age`, nightly)

A meaningful share of supply-chain attacks are *fresh* releases of an otherwise
reputable crate published from a compromised maintainer account, and caught
within days. Neither `cargo audit` (needs an advisory to exist) nor `cargo vet`
(needs a human review) reacts quickly to that window.

Cargo 1.98 added an **unstable** feature that does:
[`-Zmin-publish-age`](https://github.com/rust-lang/cargo/pull/17012) makes the
resolver skip versions published more recently than a configured age.

```toml
# nightly only -- do NOT depend on this in CI yet
[registry]
global-min-publish-age = "14 days"

[resolver]
incompatible-publish-age = "deny"   # ignore too-new versions unless already in Cargo.lock
```

Not usable on stable and therefore **not** a current requirement. Track it for
stabilization; a 7-14 day quarantine is a cheap, high-leverage control for a
crate handling auth and credentials.

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
- [ ] No single `'a` parameterizing both an input ref and a collection holding refs (lifetime laundering)
- [ ] Consumed arguments returned in error variants for retryable operations

**Error Handling**
- [ ] No `unwrap()` / `expect()` in library code (only tests or proven invariants)
- [ ] Errors propagated with `?`, not swallowed or panicked
- [ ] `TryFrom` used when conversion can fail (not `From` with hidden fallbacks)
- [ ] Guard clauses use `bool::ok_or` / `ok_or_else` rather than four-line `if … return Err` blocks (Rust 1.98+)

**Type Safety**
- [ ] Newtypes used for domain concepts (IDs, amounts, durations)
- [ ] Enums used instead of `bool` params where meaning is unclear
- [ ] `match` arms are exhaustive -- no wildcard `_` catch-all on owned enums
- [ ] Struct fields private with validated constructors (for library types)
- [ ] `#[must_use]` on types/functions where ignoring the result is a bug
- [ ] Comparison traits are all-manual or all-derived -- never a manual `PartialEq` alongside a derived `Ord`/`PartialOrd` (Rust 1.98+ can expose the inconsistency)
- [ ] Types with a manual `PartialEq` are not used in constant patterns (rejected on Rust 1.98+)
- [ ] `#[repr(transparent)]` not applied over `#[non_exhaustive]`, `repr(C)`, or private-field types (Rust 1.98+ rejects these)
- [ ] Non-zero domain values parsed via `NonZero::from_str_radix` rather than parse-then-`NonZero::new` (Rust 1.98+)

**Performance**
- [ ] No `Box<Vec<T>>`, `Box<String>`, `Arc<String>`
- [ ] No collect-then-iterate -- iterate directly
- [ ] No `String::from("...")` where `&str` is accepted
- [ ] HashMap lookups use `&str`, not cloned `String` keys
- [ ] `core::hint::cold_path()` marks genuinely unlikely branches (Rust 1.95+); perf hint only, never correctness
- [ ] Prefer std bit ops `bit_width` / `isolate_highest_one` / `isolate_lowest_one` / `highest_one` / `lowest_one` over hand-rolled shift/mask arithmetic (Rust 1.97+; `isolate_lowest_one` now lint-enforced by Clippy 1.98 `manual_isolate_lowest_one`)
- [ ] No `algebraic_*` float methods on any value that is compared, hashed, serialized, persisted, or asserted on -- they are non-deterministic (Rust 1.98+)
- [ ] Integer formatting in hot / `no_std` paths uses `format_into` + `NumBuffer` instead of `to_string()` / `format!` (Rust 1.98+)
- [ ] Sub-slice offsets recovered with `substr_range` / `subslice_range`, never pointer arithmetic (Rust 1.98+)

**Async**
- [ ] No `std::fs` / `std::net` in async functions
- [ ] Blocking work wrapped in `spawn_blocking`
- [ ] Timeouts use `tokio::select!`
- [ ] No `std::sync::Mutex` held across `.await` points
- [ ] Every async fn that may run inside `select!` / `timeout` / `embassy_futures::select` carries a `// cancel-safe:` or `// NOT cancel-safe:` doc comment with reasoning
- [ ] Drop impls of async resources (transactions, pooled connections, guards) audited; explicit cleanup on every path, never relied on Drop alone
- [ ] No `Box::new([0; N])` for large `N` -- use `vec![0; N].into_boxed_slice()` (especially in embassy tasks with small stacks)

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
- [ ] No blanket `impl<T: Bound> PublicTrait for T` unless `PublicTrait` is sealed

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
- [ ] Delimiter-wrapped input (quoted header values, bracketed IPv6) stripped with `strip_circumfix`, not chained `strip_prefix`/`strip_suffix` (Rust 1.98+)
- [ ] UTF-16 boundary decoding uses the endian-explicit, non-`_lossy` `String::from_utf16{le,be}` (Rust 1.98+); `_lossy` reserved for display
- [ ] Every `cargo audit` / `cargo deny` ignore entry documents the advisory, why it does not apply, and upstream fix status

**Runtime Safety**
- [ ] No `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` in production paths
- [ ] No `dbg!()`, `println!()`, `eprintln!()` - use `tracing` macros
- [ ] `unsafe_code = "forbid"` set at crate level (or `deny` with per-item `#[allow]` + safety comment)
- [ ] Functions below cognitive complexity threshold (no god functions)
- [ ] Prefer `Atomic*::update` / `try_update` over hand-rolled `compare_exchange` loops (Rust 1.95+)
- [ ] Prefer `Vec::push_mut` / `VecDeque::push_{front,back}_mut` / `LinkedList::push_{front,back}_mut` over `push` + `last_mut().unwrap()` (Rust 1.95+)
- [ ] `linker_messages` lint (Rust 1.97+) triaged; escalated or `allow`-ed explicitly (it is NOT in the `warnings` group, so `-D warnings` / `build.warnings` don't cover it)
- [ ] No unsafe *attributes* (`#[unsafe(no_mangle)]`, `#[unsafe(link_section)]`, `#[unsafe(export_name)]`, `#[unsafe(naked)]`) under `unsafe_code = "forbid"` -- Rust 1.98+ now flags these; firmware crates needing them must use `deny` + justified `#[allow]`
- [ ] `invalid_runtime_symbol_definitions` (Rust 1.98+, deny-by-default, NOT in the `warnings` group) considered for `no_std`/FFI crates that define runtime symbols

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
- [ ] No assertions on `{:?}` output as a stable format -- Rust 1.98+ escapes more characters (re-check audit-log / redaction tests on upgrade)
- [ ] Guards/locks inside `assert_eq!` / `assert_ne!` bound to a `let` rather than created inline (Rust 1.98+ changed macro temporary scope)

**Tooling**
- [ ] `cargo fmt --check` in CI
- [ ] `cargo clippy -D warnings` with full lint set in CI
- [ ] rustc warnings denied in CI via `build.warnings = "deny"` / `CARGO_BUILD_WARNINGS=deny` (Rust 1.97+), preferred over `RUSTFLAGS=-Dwarnings` (cache-friendly, local-only)
- [ ] `cargo audit` and `cargo deny check` in CI
- [ ] `cargo semver-checks` in CI for library crates
- [ ] `rustfmt.toml` with `imports_granularity` and `group_imports` configured
- [ ] `cargo miri` run (nightly job) against pure-Rust modules with `unsafe`; HAL/FFI-touching crates exempted with a note; crates on `unsafe_code = "forbid"` legitimately have no Miri job
- [ ] `[lints.clippy]` group entries carry `priority = -1` so per-lint overrides do not conflict
- [ ] `clippy.toml` pins `cognitive-complexity-threshold`, `too-many-lines-threshold`, `max-fn-params-bools`, `enum-variant-size-threshold` (levels live in `Cargo.toml`, config lives here)
- [ ] Deprecated `string_to_string` and `from_iter_instead_of_collect` removed from `[lints.clippy]` (both no longer exist)
- [ ] `string_slice` enabled -- no `&s[a..b]` on `str` with externally-derived bounds (panics on non-char-boundary)
- [ ] Widening casts use `From`/`u64::from`, narrowing casts use `TryFrom` with a real error path -- not bare `as` (`cast_lossless`)
- [ ] Every `allow` in `[lints.clippy]` and every `#[allow]`/`#[expect]` in source carries a `reason` explaining the decision
- [ ] `unused_async_trait_impl` (Clippy 1.98 `pedantic`) handled per-impl via `#[expect(..., reason = ...)]` where a foreign trait mandates the async signature -- not silenced crate-wide; it is not covered by `all = "deny"`
- [ ] One-time `cargo fmt --all` committed separately after adopting `cfg_select!` (Rust 1.98 rustfmt now formats modules declared inside it)

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

**Rust 1.97+:** the `-D warnings` on the clippy line denies warnings only for
the targets clippy compiles. To deny **rustc** warnings across the whole
workspace in a cache-friendly, toggleable way, prefer Cargo's stabilized
`build.warnings` config (Section 7) over `RUSTFLAGS="-D warnings"`:

```bash
CARGO_BUILD_WARNINGS=deny cargo check --workspace --all-features --keep-going
```

**Cargo 1.98:** no action required. The
[1.98 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html)
has **empty `Added` and `Changed` sections** -- no new stable config keys,
manifest fields, or CLI flags. The 1.97 `build.warnings` guidance above
remains current. Two footnotes:

- A [credential-provider fix](https://github.com/rust-lang/cargo/pull/17081)
  strips a trailing `\r` from `cargo:token-from-stdout` tokens, resolving a
  1.96 **Windows** regression that surfaced as a confusing
  `failed to parse header value` during authenticated registry operations
  including `cargo publish`. Relevant if you publish from a Windows
  workstation or runner.
- Everything else in 1.98 is nightly-gated (`-Zmin-publish-age`,
  `-Zhint-msrv`, `-Zcargo-lints`) and must not be relied on in CI.

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
| `cargo miri` | Detects undefined behavior in `unsafe` code: OOB reads, misaligned pointer access, Stacked Borrows violations, uninitialized reads. Catches UB that passes normal tests and `clippy`. | `rustup +nightly component add miri` | `cargo +nightly miri test -p <crate>` |

**Miri caveats -- read before pushing back on a reviewer who asks for it:**

- **It only applies to crates that contain `unsafe` at all.** Miri detects
  undefined behaviour, and safe Rust cannot exhibit UB. A crate with
  `unsafe_code = "forbid"` (Section 9) has nothing for Miri to find, and the
  absence of a Miri job in its CI is correct rather than a gap. Check the
  crate-level lint before treating "no Miri" as a finding. Note that any
  `unsafe` reachable through a *dependency* is that dependency's
  responsibility -- use `cargo-geiger` to see the transitive picture instead.
- **FFI support is experimental and incomplete.** Miri added partial FFI via
  `-Zmiri-native-lib` (Unix-only, 2024-2025). It can pass integer/pointer
  arguments to C functions and trace some memory accesses, but does NOT
  support function pointers passed to C, memory allocated by C and returned
  to Rust, or non-Unix hosts. For this workspace, that means crates calling
  into `mbedtls-rs` *might* work for narrow cases but should not be assumed
  to. Treat FFI-heavy crates as Miri-untested unless someone has explicitly
  validated the specific call pattern.
- **No practical support for bare-metal targets.** Miri targets the host and
  fails on memory-mapped I/O register access. The esp-hal maintainers
  prototyped Miri integration in esp-rs/esp-hal#3297 and closed it with
  "the PACs will make Miri very, very mad." Firmware code that touches
  `esp-hal`, `esp-radio`, or any peripheral register is not Miri-testable
  end-to-end. This is a platform limitation, not a workflow gap.
- **Slow.** Tokio docs warn of a "dramatic increase" in test time; real-world
  CI reports 35%+ time savings from skipping Miri-incompatible tests
  (alloy-rs/core PR #1072). Use a separate nightly CI job, not the per-PR
  critical path.

**ESP32 firmware strategy:**

1. Factor pure-Rust logic (protocol parsers, CRC, state machines,
   byte-stuffing, NEC decode, hOn frame builders) into separate modules
   or `no_std`-but-host-buildable inner crates.
2. Write `#[cfg(test)]` unit tests for those modules. These tests build
   for the host target and CAN run under Miri.
3. Run Miri only against those modules: `cargo +nightly miri test -p haier_proto`
   (or equivalent). The HAL-glue code that calls `esp-hal` stays untested
   by Miri -- that's an inherent limitation of the platform, not a gap to
   apologize for.
4. For HAL-touching `unsafe`: rely on the existing discipline -- every
   `unsafe` block carries a `// SAFETY:` comment justifying the invariant
   (see CLAUDE.md "Memory Safety Checklist"). Human review is the only
   tool we have for those blocks; Miri does not apply.

`cargo-careful` (`cargo install cargo-careful`) is an intermediate option
that enables extra debug checks in std without Miri's interpreter overhead.
It supports FFI but catches a narrower class of bugs. Optional, not
required.

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

### DON'T: Assert on `Debug` output as a stable format (Rust 1.98+)

[Rust 1.98 escapes more characters when printing strings and
chars](https://github.com/rust-lang/rust/pull/155527). Any test that compares
against a literal `{:?}` rendering can newly fail without a code change, and
any log consumer parsing `Debug` output can newly mis-parse.

```rust
// BAD: couples the test to std's Debug formatting, which is not a stable API
assert_eq!(format!("{:?}", value), r#"Config { name: "a\u{7}b" }"#);

// GOOD: assert on the data
assert_eq!(value.name, "a\u{7}b");

// GOOD: if you must snapshot a rendering, own the format
assert_eq!(value.render_redacted(), "Config(name=<redacted>)");
```

This is highest-risk for **audit-log and redaction tests**: those deliberately
feed hostile, control-character-laden identifiers through the formatter and
assert on the result. Re-run them on a 1.98 upgrade specifically. The
underlying rule is unchanged and predates 1.98 -- `Debug` is a debugging aid,
not a wire format -- but 1.98 is when latent violations start failing.

### DO: Re-check borrows inside `assert_eq!` / `assert_ne!` on upgrade (Rust 1.98+)

[Rust 1.98 added a temporary scope to `assert_eq!` and
`assert_ne!`](https://github.com/rust-lang/rust/pull/155739). Temporaries
created inside the macro arguments are now dropped at the end of the assertion
rather than living to the end of the enclosing statement. This is the correct
behaviour and usually invisible, but it can change borrow-checker outcomes for
assertions that lock a mutex, borrow a `RefCell`, or hold a guard inline:

```rust
// May now behave differently: the guard temporary's scope changed
assert_eq!(*shared.lock().unwrap(), expected);

// Robust: bind the guard explicitly so its scope is yours, not the macro's
let guard = shared.lock().map_err(|_| TestError::Poisoned)?;
assert_eq!(*guard, expected);
```

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

- [Rust 1.98.0 release notes](https://doc.rust-lang.org/stable/releases.html#version-1980-2026-08-20)
  and [announcement](https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/) -- basis for
  the "(Rust 1.98+)" annotations. **This document tracks stable Rust through 1.98.**
  The 1.98 items reflected above are:
  - *Behaviour changes that can break existing code:* the
    [`derive(PartialOrd)` fast path](https://github.com/rust-lang/rust/pull/155598)
    and the closed pattern-matching structural-equality hole (Section 3);
    [`UNSAFE_CODE` now firing on unsafe attributes](https://github.com/rust-lang/rust/pull/157201)
    (Section 9); [stricter `repr(transparent)` layout rules](https://github.com/rust-lang/rust/pull/155299)
    (Section 3); [expanded character escaping in `Debug` output](https://github.com/rust-lang/rust/pull/155527)
    and the [`assert_eq!`/`assert_ne!` temporary scope](https://github.com/rust-lang/rust/pull/155739)
    (Section 13); [rustfmt discovering `cfg_select!` modules](https://github.com/rust-lang/rust/pull/158372)
    (Section 6).
  - *New rustc lints:* `invalid_runtime_symbol_definitions` (deny, **not** in the
    `warnings` group), `suspicious_runtime_symbol_definitions`, and
    `c_void_returns` (Section 9).
  - *New APIs adopted as idioms:* `bool::ok_or`/`ok_or_else` and
    `NonZero::from_str_radix` (Section 2); `f32`/`f64` `algebraic_*`,
    `format_into` + `NumBuffer`, `substr_range`/`subslice_range`, and the
    `Atomic<T>::from_mut` family (Section 4); `strip_circumfix` and
    `String::from_utf16{le,be}` (Section 10).
- [Clippy 1.98 changelog](https://github.com/rust-lang/rust-clippy/blob/master/CHANGELOG.md#rust-198)
  -- seven new lints (five auto-covered by `clippy::all = "deny"`;
  `with_capacity_zero` and `unused_async_trait_impl` are `pedantic` and need an
  explicit decision), the removal of `from_iter_instead_of_collect`, the
  `empty_enums` move to `nursery`, and `result_large_err`/`result_unit_err` now
  firing on `async fn` (Section 9).
- [Cargo 1.98 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html)
  -- **no stable `Added` or `Changed` entries.** Everything new is nightly-gated
  (`-Zmin-publish-age`, `-Zhint-msrv`, `-Zcargo-lints`); see Sections 10 and 12.
- [Rust 1.97.0 release notes](https://doc.rust-lang.org/stable/releases.html#version-1970-2026-07-09)
  and [announcement](https://blog.rust-lang.org/2026/07/09/Rust-1.97.0/) -- basis for
  the "(Rust 1.97+)" annotations: Cargo `build.warnings`, the `linker_messages` lint,
  `dead_code_pub_in_binary`, v0 symbol mangling by default, the `must_use` uninhabited-`Result`
  refinement, and the `bit_width` / `isolate_highest_one` / `isolate_lowest_one` /
  `highest_one` / `lowest_one` integer methods.
- [Rust Design Patterns](https://rust-unofficial.github.io/patterns/) -- idioms, design patterns, and guidelines
- [Rust Anti-Patterns](https://rust-unofficial.github.io/patterns/anti_patterns/) -- common solutions that create more problems
- [7 Rust Anti-Patterns Killing Your Performance](https://medium.com/solo-devs/the-7-rust-anti-patterns-that-are-secretly-killing-your-performance-and-how-to-fix-them-in-2025-dcebfdef7b54) -- clone epidemic, blocking async, unwrap addiction
- [Patterns for Defensive Programming in Rust](https://corrode.dev/blog/defensive-programming/) -- constructors, exhaustive matching, `#[must_use]`, clippy lints
- [Я заставил LLM писать Rust полгода (Habr, 2026)](https://habr.com/ru/articles/1035712/) -- LLM-specific Rust failure modes: lifetime laundering, async cancel safety, Drop in async, blanket impl semver hazards, stack-allocated boxes. Source of the cancel-safety and lifetime-laundering rules above.