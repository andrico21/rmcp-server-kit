# Rust Development Guidelines: DOs and DON'Ts

**Universal core.** This is the single source of truth for every Rust project. It tracks
**stable Rust through 1.99** (2026-10-01).

Domain- and project-specific rules live in overlays (`overlays/`). Read this core first, then
every overlay your project's pointer file names, in the order given. Precedence and the
overlay contract are in `README.md`.

Comprehensive rules for writing idiomatic, performant, and defensive Rust code.
Synthesized from Rust Design Patterns, defensive programming patterns, and
production anti-patterns. Every rule has a rationale and a code example.

**Non-negotiables** (each is expanded in the section named):

- Edition 2024, latest stable toolchain, `rust-version` = that toolchain (Section 12).
- The strictest lint profile available on stable, unchanged, in every crate (Section 9).
  There are no group-level allows. Exceptions are `#[expect(lint, reason = "...")]` on the
  narrowest item.
- Warnings are errors: `build.warnings = "deny"` committed in `.cargo/config.toml`, plus
  `-D warnings` on CI (Sections 7, 12).
- `unsafe_code = "forbid"`. Only a crate that loads `overlays/domains/unsafe-ffi.md` may
  lower it to `deny`, and only with per-item `#[expect(unsafe_code, reason = "...")]`.
- Security first, then correctness, then cleanliness. When rules seem to pull apart, that
  is the order of precedence.

---

## 1. Ownership and Borrowing

### DO: Accept borrowed types in function arguments

Accept `&str` over `&String`, `&[T]` over `&Vec<T>`, `&T` over `&Box<T>`.
The borrowed type is strictly more flexible - callers can pass owned or
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
requires `unwrap`/`expect` that an `unwrap_used = "deny"` posture forbids.

```rust
// BAD (requires unwrap):
v.push(x);
let last = v.last_mut().expect("just pushed");

// GOOD:
let last = v.push_mut(x);
```

### DO: Bound a `VecDeque` with `retain_back` (Rust 1.99+)

Sliding windows, recent-event buffers, and audit tails keep the newest `n`
entries. The hand-rolled trim either loops or does `len - n` arithmetic that
panics the moment the buffer is shorter than `n`:

```rust
// BAD: panics when window.len() < n - "attempt to subtract with overflow" in
// debug, an out-of-range drain in release
let len = window.len();
window.drain(..len - n);

// BAD: correct, but a loop of pops for one bulk operation
while window.len() > n { window.pop_front(); }

// GOOD: keeps the last `n` elements; a no-op when there are fewer
window.retain_back(n);
```

`retain_back` is `truncate` from the other end (doc alias `truncate_front`).

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

Verified against `rustc 1.94` - the function builds clean, but the caller
fails to compile because `cache`'s element type `&'a str` is invariant in
`'a`, so the compiler cannot let `s1` end its scope while `cache` is still
alive. Once you wire the function into application code, every input must
outlive the cache itself - almost never what you wanted.

```rust
// GOOD: store owned values when the collection outlives any single input
fn first_word<'a>(s: &'a str, cache: &mut HashMap<String, String>) -> &'a str {
    let _: &mut String = cache.entry(s.to_owned())
        .or_insert_with(|| s.split_whitespace().next().unwrap_or("").to_owned());
    s.split_whitespace().next().unwrap_or("")
}

// GOOD: split lifetimes with an explicit outlives bound when borrowing is required
fn first_word<'cache, 'input: 'cache>(
    s: &'input str,
    cache: &mut HashMap<String, &'cache str>,
) -> &'cache str { /* ... */ }
```

Rule of thumb: every time you add explicit lifetimes to a signature, sketch a
real caller in your head - specifically one where the inputs have disjoint
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
- `Copy` types (`i32`, `bool`) - these are cheap stack copies
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
malformed" (single-byte flags in a binary record, protocol bitfields stored
as bytes, JSON `0`/`1` from a strict producer), prefer
`bool::try_from(n)?` over `n != 0`. The `!= 0` form silently accepts `2`,
`42`, `0xFF` as `true`, hiding upstream corruption. `TryFrom` makes the
"any non-0/1 is a bug" contract explicit and surfaces it as a parse error
the caller can report.

```rust
// BAD: any nonzero byte becomes true, including garbage from a torn write
let display_on: bool = flag_byte != 0;

// GOOD: strict - 0 or 1, anything else is a malformed record
let display_on = bool::try_from(flag_byte)
    .map_err(|_| StorageError::InvalidFlag { tag: 0x09, value: flag_byte })?;
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
`true` yields `Ok(())`, `false` yields `Err(e)` - the same convention as
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

This matters wherever a domain type is inherently non-zero - rate limits,
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
// ordinary Rust-to-Rust use - repr(transparent) only matters at an ABI boundary.
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
result-like wrappers. `Result<T, Uninhabited>` and `ControlFlow<Uninhabited, T>` -
where the error / break arm is an uninhabited type such as `!` or
`core::convert::Infallible` - are treated as `T` for the lint. A `#[must_use]`
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

### DO: Use exhaustive `match` - avoid wildcard catch-all

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
do **NOT** participate in exhaustiveness checking - same rule as plain `if`
guards. A new tool may suggest collapsing arms behind an `if let` guard
and dropping the wildcard; the compiler will still require either an
exhaustive listing or a `_` arm. Do not use an `if let` guard as
justification for removing a previously-required wildcard.

```rust
// The `if let` guard does NOT cover Status::Pending - the wildcard or an
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

**Lint support (Clippy 1.99+), with one blind spot.** Two `restriction` lints
enforce this rule:

- `unnecessary_rest_pattern` flags a `..` that matches no remaining field
  (`S { a, b, c, .. }`): it hides nothing today and silently swallows the next
  field added. It supersedes the older `rest_pat_in_fully_bound_structs` and also
  covers enum struct variants.
- `rest_pattern_accessible_field` flags any `..` that hides fields you could
  have named.

The Section 9 profile denies both crate-wide. Where a `..` is genuinely right (a
large foreign struct in a `match` arm that only cares about one field), the
exception is an `#[expect(clippy::rest_pattern_accessible_field, reason = "...")]`
on that function - not a lint level.

Both lints **ignore `Self { .. }` patterns** and only check patterns that name
the type - while `use_self` (nursery) rewrites such names back to `Self`. Where
the protection matters most - a zeroizing `Drop` that must wipe every secret
field - name the type and opt that item out of `use_self`:

```rust
#[expect(clippy::use_self, reason = "a named path keeps the rest-pattern lints able to see the pattern")]
impl Drop for Credentials {
    fn drop(&mut self) {
        // Exhaustive: a new field is a compile error here until it is wiped or ignored.
        // `let Credentials { password, .. } = self;` would now be flagged.
        let Credentials { user: _, password, totp_seed } = self;
        password.zeroize();
        totp_seed.zeroize();
    }
}
```

Elsewhere keep writing `Self { ... }` - exhaustively, without `..` - and rely on
review.

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
  (`match x { MY_CONST => ... }`) - 1.98 rejects this.
- If you only want to ignore a field for *equality* and have no ordering
  requirement, do not derive `PartialOrd`/`Ord` at all. Deriving traits you do
  not need is what creates the inconsistency.

### DO: Name unused destructured variables descriptively

```rust
// BAD: `..` hides which fields are ignored - and every field added later
let Rocket { name, .. } = rocket;

// GOOD: every field accounted for; a new field is a compile error here
let Rocket { name, has_fuel: _, has_crew: _ } = rocket;
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

### DON'T: Read a `RangeInclusive` after iterating it (values changed in Rust 1.99)

Once an inclusive range has been iterated to the end, its `start()` / `end()`
values are unspecified - and Rust 1.99 changed them
([PR #155114](https://github.com/rust-lang/rust/pull/155114)). After iterating
`254u8..=255` to completion, `start()` is `255` on 1.98 but `0` on 1.99. A range
reused as a resume cursor silently jumps back to the beginning - but only when
it ran to the end, which is exactly the case tests rarely hit.

```rust
// BAD: correct after an early `break`, wrong once the range is exhausted
let mut pending = next_seq..=last_seq;
for seq in pending.by_ref() {
    if !send(seq)? { break; }
}
let resume_from = *pending.start();

// GOOD: make "where to resume" explicit
let mut resume_from = None;
for seq in next_seq..=last_seq {
    if !send(seq)? {
        resume_from = Some(seq);
        break;
    }
}
// `None` means every sequence number was sent
```

`is_empty()` remains a reliable "exhausted?" check; everything else about an
exhausted range's state is off-limits.

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

// GOOD: Borrow directly - HashMap<String, _> accepts &str lookups
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
not guaranteed by the language - a single intermediate `let` binding can
materialize the stack copy and crash.

```rust
// BAD: stack overflow in debug, brittle in release
let buf = Box::new([0u8; 1024 * 1024]);

// GOOD: heap allocation guaranteed by Vec
let buf: Box<[u8]> = vec![0u8; 1024 * 1024].into_boxed_slice();
```

### DO: Use temporary mutability pattern

Constrain mutability to initialization, then shadow as immutable.

```rust
let data = {
    let mut data = get_vec();
    data.sort();
    data // Returned immutable
};
// `data` is now immutable - no accidental modification
```

### DON'T: Use algebraic float methods where the result must be reproducible (Rust 1.98+)

Rust 1.98 stabilized `algebraic_add`, `algebraic_sub`, `algebraic_mul`,
`algebraic_div`, and `algebraic_rem` on `f32` and `f64` (all `const`-stable).
They permit the optimizer to apply the algebraic properties of *real* numbers -
associativity, distributivity, reassociation - even though those properties
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

### DO: Prefer std bit-manipulation methods over hand-rolled equivalents (Rust 1.97+)

Rust 1.97 stabilized a family of `const fn` bit helpers on every integer
type and on `NonZero<_>`. Prefer them over hand-rolled shift / mask /
`leading_zeros` arithmetic: they are branch-free, express intent directly,
and remove the off-by-one and zero-input traps that hand-rolled versions
invite. Same rationale as the `manual_checked_ops` lint (Section 9) - let
the standard library say what you mean.

| Method | Returns | Example |
|--------|---------|---------|
| `n.bit_width()` | `u32` - min bits to represent `n` | `0b1110u8.bit_width() == 4`; `0` for `0` |
| `n.isolate_highest_one()` | value with only the top set bit kept | `0b0110_0100u8 -> 0b0100_0000`; `0` for `0` |
| `n.isolate_lowest_one()` | value with only the bottom set bit kept | `0b0110_0100u8 -> 0b0000_0100`; `0` for `0` |
| `n.highest_one()` | `Option<u32>` - index of the top set bit | `0b1_1111u8 -> Some(4)`; `None` for `0` |
| `n.lowest_one()` | `Option<u32>` - index of the bottom set bit | `0b1_1111u8 -> Some(0)`; `None` for `0` |

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
(`None` when the input is zero - no `u32::BITS` sentinel to special-case).

**Now lint-enforced (Clippy 1.98+).** This was prose-only guidance when it was
introduced. Clippy 1.98 added
[`manual_isolate_lowest_one`](https://github.com/rust-lang/rust-clippy/pull/17037),
which flags the hand-rolled `x & x.wrapping_neg()` and `x & -x` forms and
suggests `x.isolate_lowest_one()`. It is a **`complexity`-tier** lint, so it is
already covered by `clippy::all = "deny"` - no separate declaration needed. The
lint is MSRV-aware via the `msrv` key in `clippy.toml` (or `package.rust-version`),
so it stays quiet on crates pinned below 1.97.

**Clippy 1.99 extends the enforcement.** `manual_bit_width` (pedantic) flags
`T::BITS - x.leading_zeros()` - the BAD line above - and suggests
`x.bit_width()`. `mismatched_bit_width_type` (suspicious) flags the variant where `T` and `x` differ in width, which
is a genuine bug: `u32::BITS - 5u64.leading_zeros()` panics with "attempt to
subtract with overflow" in debug builds and returns 4294967267 in release. The Section 9 profile denies both.

MSRV note: these are 1.97 APIs. Adopting them raises your minimum toolchain
to 1.97 - honor your MSRV policy (Section 12). This is a non-issue for any
crate already on `rust-version = "1.98.0"` or later; check before using them
in a crate that pins an older toolchain (notably `no_std` crates, which often
lag stable to match a vendor HAL release).

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
  `format_into` performing on par with `itoa` itself. That makes `itoa` - and
  similar integer-formatting micro-crates - a removable dependency. Fewer
  transitive deps is less audit surface. Check with `cargo machete` /
  `cargo tree` after migrating.

Rust 1.99 also re-exports it as `std::fmt::NumBuffer` / `alloc::fmt::NumBuffer`
([PR #161430](https://github.com/rust-lang/rust/pull/161430)); keep the `core::fmt`
path in crates whose `rust-version` is still 1.98. `no_std` usage: embedded overlay.

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
than producing a garbage offset. Neither performs a search - they are pure
address math on a slice you already hold.

Caveat: `subslice_range` **panics if `T` is a zero-sized type**. Guard generic
code, or restrict the call to concrete element types.

This is the safe replacement for a pattern that previously forced an `unsafe`
block, which makes it directly useful in crates running `unsafe_code = "forbid"` -
tokenizers, header parsers, and span-tracking error reporters no longer need
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
access, then hand out an atomic view to worker threads - without paying for
atomic operations during the initialization phase and without an `unsafe` block
at the boundary.

### DO: Read multi-byte integers from `&[u8]` with `from_{le,be}_bytes` over a bounds-checked slice

Pull multi-byte fields out of byte buffers in three steps: bounds-check a sub-slice, convert
it to a fixed-size array, and decode with the byte order the format defines. This needs no
`unsafe`, cannot panic, and the optimizer emits a single load on platforms that allow it.

```rust
// GOOD: no unwrap, no indexing, no unsafe; the error is propagated
let bytes: [u8; 2] = buf.get(2..4).ok_or(FrameError::Truncated)?
    .try_into().map_err(|_| FrameError::Truncated)?;
let value = u16::from_le_bytes(bytes);
```

Rules:

- Use `from_be_bytes` / `from_le_bytes` as the protocol or file format defines. Never use
  `from_ne_bytes`: native endianness is non-portable, and `host_endian_bytes` is denied
  (Section 9).
- `slice.try_into().unwrap()` appears in a lot of sample code but violates `unwrap_used`.
  Propagate the `TryFromSliceError` instead, as above.
- `buf[2..4]` violates `indexing_slicing`; use `get`. Bounds-check once and reuse the
  result.
- Reading through a cast raw pointer (`*const u8` to `*const u16`) is undefined behaviour
  on alignment-strict targets. If a crate genuinely needs pointer reads, it loads
  `overlays/domains/unsafe-ffi.md`, which covers `ptr::read_unaligned`.
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
- `clippy::await_holding_lock` catches the obvious case (guard variable
  visibly alive across `.await` in the same function) but does **not**
  see through helper-function returns, struct fields, or
  `MutexGuard::map`. Treat the lint as necessary but not sufficient.

### DO: Use `tokio::task::yield_now()` in CPU-bound async loops

If you must do CPU work in an async context, yield periodically to avoid
starving other tasks.

### DO: Annotate every async fn with cancel safety (cancel-safe / NOT cancel-safe)

Futures in Rust are cancellable at **every** `.await` point. Any future used
inside `tokio::select!`, `tokio::time::timeout`, `JoinHandle::abort`, or the
equivalent select/abort primitive of another executor can be dropped between
awaits, leaving partial state.
Cancel safety is **not expressible in the type system** - there is no
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
- "All awaits are idempotent" is **not** a valid reason - idempotency is
  about retries, not about partial state between awaits.
- Consult tokio docs per call. E.g. `AsyncReadExt::read` is cancel-safe,
  `read_exact` is NOT.
- The same rule holds for any executor whose `select` cancels the losing branch
  by dropping its future. Wherever a task races an I/O read against a command
  channel, every future on either arm must be cancel-safe or wrapped in a region
  that cannot be aborted.

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
  does - read the source, not just the docs.
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
blocking gate (Section 12), introducing `cfg_select!` - or simply upgrading to
1.98 with existing `cfg_select!` usage - can fail the gate on files nobody
touched. Run `cargo fmt --all` once at the upgrade and commit the result as a
separate formatting-only change, so the reformat does not contaminate a
feature diff.

**Lint note (Rust 1.99+):** `unreachable_cfg_select_predicates` - the warning
for an arm that can never be selected, such as any arm after `_ =>` - is now
part of the `unused` lint group
([PR #159179](https://github.com/rust-lang/rust/pull/159179)). A crate that
follows Section 7's `#![deny(unused, ...)]` advice turns such arms into hard
errors. Keep `_ =>` last.

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
- Surprises readers - it is an implicit, undocumented conversion
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
config, which is now the preferred mechanism - it is cache-friendly
(changing it does **not** invalidate the build cache, unlike `RUSTFLAGS`).
It applies to every **local** package: the workspace members, and also any
path dependency such as a vendored crate. Only registry and git dependencies
are exempt, because Cargo caps their lints. A new warning in a vendored crate
therefore fails the build, so patch it in the vendored tree. Rust 1.99's
`fetch_update` deprecation did exactly this to a vendored `hickory-resolver`.

```toml
# .cargo/config.toml - deny warnings for local packages
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
affects it - escalate it separately if you want linker output to fail CI.

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
  impls in this crate - no blanket impls.
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

## 9. Lints: The Strictest Stable Profile

### Policy

- **Every crate uses the profile below, unchanged.** It enables, at `deny`:
  - every rustc lint group and allow-by-default lint;
  - every rustdoc lint;
  - the Clippy groups `all`, `pedantic`, `nursery` and `cargo`;
  - every Clippy `restriction` lint that stable Rust 1.99 provides.

  In numbers: 12 rustc lint groups and 61 individual rustc lints, rustdoc `all`, 4 Clippy groups and 120 of 135 `restriction` lints at `deny`, plus `unsafe_code = "forbid"`. 25 lints are excluded and one contradiction is overridden, each with its reason below.
- **A lint is left out only for a stated reason.** It must be (a) unstable (nightly-only),
  (b) one half of a mutually exclusive pair (Clippy ships several; one side is chosen),
  (c) in contradiction with a rule of this guide, or (d) documented by its own authors as
  not meant for crate-wide use. Every exclusion is listed with its reason under
  [Exclusions](#exclusions). Nothing is left out for convenience.
- **Overlays may add lints and may not remove any.** A project overlay that needs something
  stricter adds it on top of the profile.
- **No group-level `allow` in any manifest.** The single exception is the one documented
  contradiction override inside the profile.
- **Local exceptions use `#[expect(lint, reason = "...")]` on the narrowest item.**
  - `#[allow]` is itself denied (`allow_attributes`), and so is an `expect` without a
    reason (`allow_attributes_without_reason`).
  - `#[expect]` fails the build as soon as the exception stops being needed.
  - An exception that fires only in some builds (a feature, a target, `cfg(test)`) goes
    under `#[cfg_attr(<that cfg>, expect(lint, reason = "..."))]`. A plain `#[expect]` is
    unfulfilled in the other builds, and fails them.
  - An attribute on a macro-invocation statement (e.g. on an `assert!(..)` line) is
    ignored as an "unused attribute"; put the exception on the enclosing `fn` or `mod`.
  - `allow_attributes` checks only outer `#[allow]`, so an inner `#![allow(..)]` passes it
    unseen. Never write one: use `#![expect(lint, reason = "...")]`, and keep
    `grep -rn --include='*.rs' '#!\[allow(' <your source dirs>` empty in CI.
- **Warnings are errors everywhere.** Commit `build.warnings = "deny"` in
  `.cargo/config.toml` (Section 7) and keep `-D warnings` on the CI clippy and rustdoc lines
  (Section 12).
- **Re-baseline on every toolchain bump** with the completeness check below, so that lints
  added by the new release enter the profile.

### The profile

Workspace root `Cargo.toml`:

```toml
[workspace.lints.rust]
# Every rustc lint group, at deny (individual entries below override at priority 0)
future_incompatible = { level = "deny", priority = -1 }
let_underscore = { level = "deny", priority = -1 }
nonstandard_style = { level = "deny", priority = -1 }
rust_2018_idioms = { level = "deny", priority = -1 }
rust_2018_compatibility = { level = "deny", priority = -1 }
rust_2021_compatibility = { level = "deny", priority = -1 }
rust_2024_compatibility = { level = "deny", priority = -1 }
unused = { level = "deny", priority = -1 }
keyword_idents = { level = "deny", priority = -1 }
refining_impl_trait = { level = "deny", priority = -1 }
deprecated_safe = { level = "deny", priority = -1 }
unknown_or_malformed_diagnostic_attributes = { level = "deny", priority = -1 }
# Overridable only by the unsafe-ffi overlay
unsafe_code = "forbid"
# Every allow-by-default rustc lint available on stable, plus warn-by-default ones made explicit
absolute_paths_not_starting_with_crate = "deny"
ambiguous_negative_literals = "deny"
closure_returning_async_block = "deny"
confusable_idents = "deny"
dead_code_pub_in_binary = "deny"
deprecated_in_future = "deny"
deprecated_safe_2024 = "deny"
deref_into_dyn_supertrait = "deny"
edition_2024_expr_fragment_specifier = "deny"
elided_lifetimes_in_paths = "deny"
explicit_outlives_requirements = "deny"
ffi_unwind_calls = "deny"
if_let_rescope = "deny"
impl_trait_overcaptures = "deny"
impl_trait_redundant_captures = "deny"
keyword_idents_2018 = "deny"
keyword_idents_2024 = "deny"
let_underscore_drop = "deny"
linker_messages = "deny"
macro_use_extern_crate = "deny"
meta_variable_misuse = "deny"
missing_abi = "deny"
missing_copy_implementations = "deny"
missing_debug_implementations = "deny"
missing_docs = "deny"
missing_unsafe_on_extern = "deny"
mixed_script_confusables = "deny"
non_ascii_idents = "deny"
raw_borrows_via_references = "deny"
redundant_imports = "deny"
redundant_lifetimes = "deny"
renamed_and_removed_lints = "deny"
rust_2021_incompatible_closure_captures = "deny"
rust_2021_incompatible_or_patterns = "deny"
rust_2021_prefixes_incompatible_syntax = "deny"
rust_2021_prelude_collisions = "deny"
rust_2024_guarded_string_incompatible_syntax = "deny"
rust_2024_incompatible_pat = "deny"
rust_2024_prelude_collisions = "deny"
single_use_lifetimes = "deny"
tail_expr_drop_order = "deny"
text_direction_codepoint_in_comment = "deny"
text_direction_codepoint_in_literal = "deny"
trivial_casts = "deny"
trivial_numeric_casts = "deny"
uncommon_codepoints = "deny"
unexpected_cfgs = "deny"
unit_bindings = "deny"
unknown_lints = "deny"
unnameable_types = "deny"
unreachable_pub = "deny"
unsafe_attr_outside_unsafe = "deny"
unsafe_op_in_unsafe_fn = "deny"
unstable_features = "deny"
unused_extern_crates = "deny"
unused_import_braces = "deny"
unused_lifetimes = "deny"
unused_macro_rules = "deny"
unused_qualifications = "deny"
unused_results = "deny"
variant_size_differences = "deny"

[workspace.lints.rustdoc]
all = { level = "deny", priority = -1 }

[workspace.lints.clippy]
# Every Clippy group
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
nursery = { level = "deny", priority = -1 }
cargo = { level = "deny", priority = -1 }
# Every `restriction` lint except the documented exclusions (120 of 135)
absolute_paths = "deny"
alloc_instead_of_core = "deny"
allow_attributes = "deny"
allow_attributes_without_reason = "deny"
arithmetic_side_effects = "deny"
as_conversions = "deny"
as_pointer_underscore = "deny"
as_underscore = "deny"
assertions_on_result_states = "deny"
cfg_not_test = "deny"
clone_on_ref_ptr = "deny"
cognitive_complexity = "deny"
create_dir = "deny"
dbg_macro = "deny"
decimal_literal_representation = "deny"
default_numeric_fallback = "deny"
default_union_representation = "deny"
definition_in_module_root = "deny"
deref_by_slicing = "deny"
disallowed_script_idents = "deny"
doc_include_without_cfg = "deny"
doc_paragraphs_missing_punctuation = "deny"
else_if_without_else = "deny"
empty_drop = "deny"
empty_enum_variants_with_brackets = "deny"
empty_structs_with_brackets = "deny"
error_impl_error = "deny"
exhaustive_enums = "deny"
exhaustive_structs = "deny"
exit = "deny"
expect_used = "deny"
field_scoped_visibility_modifiers = "deny"
filetype_is_file = "deny"
float_arithmetic = "deny"
float_cmp_const = "deny"
fn_to_numeric_cast_any = "deny"
get_unwrap = "deny"
host_endian_bytes = "deny"
if_then_some_else_none = "deny"
impl_trait_in_params = "deny"
indexing_slicing = "deny"
infinite_loop = "deny"
inline_asm_x86_att_syntax = "deny"
inline_modules = "deny"
inline_trait_bounds = "deny"
integer_division = "deny"
integer_division_remainder_used = "deny"
iter_over_hash_type = "deny"
large_include_file = "deny"
let_underscore_must_use = "deny"
let_underscore_untyped = "deny"
lossy_float_literal = "deny"
map_err_ignore = "deny"
map_with_unused_argument_over_ranges = "deny"
mem_forget = "deny"
min_ident_chars = "deny"
missing_assert_message = "deny"
missing_asserts_for_indexing = "deny"
missing_docs_in_private_items = "deny"
missing_inline_in_public_items = "deny"
mixed_read_write_in_expression = "deny"
mod_module_files = "deny"
module_name_repetitions = "deny"
modulo_arithmetic = "deny"
multiple_inherent_impl = "deny"
multiple_unsafe_ops_per_block = "deny"
mutex_atomic = "deny"
mutex_integer = "deny"
needless_raw_strings = "deny"
non_ascii_literal = "deny"
non_zero_suggestions = "deny"
panic = "deny"
panic_in_result_fn = "deny"
partial_pub_fields = "deny"
pathbuf_init_then_push = "deny"
pointer_format = "deny"
precedence_bits = "deny"
print_stderr = "deny"
print_stdout = "deny"
pub_use = "deny"
pub_without_shorthand = "deny"   # keeps pub(crate) / pub(super), the form rustfmt writes
rc_buffer = "deny"
rc_mutex = "deny"
redundant_test_prefix = "deny"
ref_patterns = "deny"
renamed_function_params = "deny"
rest_pat_in_fully_bound_structs = "deny"
rest_pattern_accessible_field = "deny"
return_and_then = "deny"
same_name_method = "deny"
semicolon_inside_block = "deny"
shadow_reuse = "deny"
shadow_same = "deny"
shadow_unrelated = "deny"
single_char_lifetime_names = "deny"
std_instead_of_alloc = "deny"
std_instead_of_core = "deny"
str_to_string = "deny"
string_add = "deny"
string_lit_chars_any = "deny"
string_slice = "deny"
suspicious_xor_used_as_pow = "deny"
tests_outside_test_module = "deny"
todo = "deny"
try_err = "deny"
undocumented_unsafe_blocks = "deny"
unimplemented = "deny"
unnecessary_rest_pattern = "deny"
unnecessary_safety_comment = "deny"
unnecessary_safety_doc = "deny"
unnecessary_self_imports = "deny"
unreachable = "deny"
unseparated_literal_suffix = "deny"
unused_result_ok = "deny"
unused_trait_names = "deny"
unwrap_in_result = "deny"
unwrap_used = "deny"
use_debug = "deny"
verbose_file_reads = "deny"
wildcard_enum_match_arm = "deny"
# Contradiction override: rustc `unreachable_pub` (denied above) and nursery's
# `redundant_pub_crate` give opposite advice on `pub(crate)`; rustc's wins.
redundant_pub_crate = "allow"
```

Every member crate inherits it:

```toml
[lints]
workspace = true
```

A single-package repository uses the same three tables as `[lints.rust]`,
`[lints.rustdoc]` and `[lints.clippy]`.

**Verified** on stable 1.99.0:
- The profile produces no unknown-lint or unstable-lint warnings. This matters because
  the `unknown_lints` warning ignores `-D warnings`, so a nightly-only name would silently
  do nothing.
- A minimal package (library, binary, unit tests, integration tests, rustdoc) passes
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` under it, together with the
  `clippy.toml` below.

### `clippy.toml`

Lint *levels* live in `Cargo.toml`; lint *configuration* lives in `clippy.toml` at the
workspace root. Neither file can express the other.

```toml
# clippy.toml - workspace root
avoid-breaking-exported-api = false   # report even when the fix changes public API
check-private-items = true            # missing_*_doc lints cover private items too
allow-unwrap-in-tests = false         # tests follow the same panic rules
allow-expect-in-tests = false
allow-panic-in-tests = false
allow-dbg-in-tests = false
allow-print-in-tests = false
allow-indexing-slicing-in-tests = false
warn-on-all-wildcard-imports = true
allow-mixed-uninlined-format-args = false
cognitive-complexity-threshold = 25   # drives `cognitive_complexity`
too-many-lines-threshold = 100        # drives `too_many_lines`
max-fn-params-bools = 3               # drives `fn_params_excessive_bools`
enum-variant-size-threshold = 200     # drives `large_enum_variant`
allowed-duplicate-crates = []         # each unavoidable duplicate, with a reason comment
doc-valid-idents = [".."]             # ".." keeps Clippy's defaults; append proper nouns
```

- **`msrv`** is deliberately absent; Clippy falls back to `package.rust-version`. Keep that
  accurate rather than setting `msrv` twice.
- **`allowed-duplicate-crates`**: list every unavoidable duplicate, each with a comment
  naming the dependency chain that forces it. Mirror the same list in `deny.toml`
  `[bans] skip` (Section 10).
- **`doc-valid-idents`**: `".."` keeps Clippy's defaults. Append the product and protocol
  names your docs use, so `doc_markdown` stays satisfiable without backticking proper nouns.

### Exclusions

| Lint | Kind | Reason |
|------|------|--------|
| `deprecated_llvm_intrinsic` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `implicit_provenance_casts` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `multiple_supertrait_upcastable` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `must_not_suspend` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `non_exhaustive_omitted_patterns` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `resolving_to_items_shadowing_supertrait_items` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `shadowing_supertrait_items` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `unqualified_local_imports` | rustc | unstable on Rust 1.99 (nightly-only); stable rustc reports it as an unknown lint |
| `linker_info` | rustc | informational by design; the actionable lint is `linker_messages` (denied below) |
| `unused_crate_dependencies` | rustc | per-compilation-unit false positives in multi-target packages; use `cargo machete` (and Cargo 1.100's `cargo::unused_dependencies`) |
| `clippy::arbitrary_source_item_ordering` | restriction | it demands alphabetical enum variants; reordering changes implicit discriminants and derived `Ord` |
| `clippy::big_endian_bytes` | restriction | endianness is protocol-defined; the guide mandates explicit `from_be_bytes`/`from_le_bytes` |
| `clippy::implicit_return` | restriction | contradicts `needless_return` (style); explicit `return` is non-idiomatic |
| `clippy::inline_asm_x86_intel_syntax` | restriction | mutually exclusive with `inline_asm_x86_att_syntax` (chosen: Intel, Rust's default) |
| `clippy::little_endian_bytes` | restriction | endianness is protocol-defined; the guide mandates explicit `from_be_bytes`/`from_le_bytes` |
| `clippy::missing_trait_methods` | restriction | its docs: enable on a specific `impl`, not globally (Section 9 shows per-impl use) |
| `clippy::pattern_type_mismatch` | restriction | requires `ref` bindings, which `ref_patterns` (denied) forbids |
| `clippy::pub_with_shorthand` | restriction | mutually exclusive with `pub_without_shorthand` (kept). Despite its name it rejects the shorthand `pub(crate)` and asks for `pub(in crate)`, which rustfmt rewrites back to `pub(crate)` |
| `clippy::question_mark_used` | restriction | contradicts the core rule "propagate errors with `?`" and `question_mark` (style) |
| `clippy::redundant_type_annotations` | restriction | contradicts the typed discard that `unused_results` and `let_underscore_untyped` require: on a non-generic method call it rejects `let _: &mut Message = msg.add_query(q);`, the only form left |
| `clippy::self_named_module_files` | restriction | mutually exclusive with `mod_module_files` (chosen: no `mod.rs`) |
| `clippy::semicolon_outside_block` | restriction | mutually exclusive with `semicolon_inside_block` (chosen) |
| `clippy::separated_literal_suffix` | restriction | mutually exclusive with `unseparated_literal_suffix` (chosen: `1_u32`) |
| `clippy::single_call_fn` | restriction | contradicts `too_many_lines`/`cognitive_complexity` decomposition (helpers called once) |
| `clippy::unneeded_field_pattern` | restriction | contradicts exhaustive destructuring (Section 3) and `rest_pattern_accessible_field` |
| `clippy::redundant_pub_crate` | nursery, set to `allow` | contradicts rustc `unreachable_pub` (denied): opposite advice on `pub(crate)` |

**Per-item use of an excluded lint is encouraged where its intent applies.** Opt in with
`#[deny(lint, reason = "...")]`, never with `#[expect]`. An `expect` of a lint that the
profile leaves off is *fulfilled* by the very violation it should catch, and it fails the
build on compliant code instead. Example: `missing_trait_methods` on a delegating wrapper:

```rust
#[deny(clippy::missing_trait_methods, reason = "every Read method must delegate to the inner reader")]
impl Read for AuditedReader { /* ... */ }
```

That `deny` fails the build while a provided method is still implicit. `allow_attributes`
does not object to it, because it denies only `#[allow]`.

### Keeping the profile complete

Run this after every toolchain bump. It must print **exactly** the names in the
exclusions table above. Any other name is a new lint: add it to the profile, or record why
it meets an exclusion criterion.

```bash
rustc -W help \
  | awk '$2 == "allow" { gsub("-", "_", $1); print $1 }' | sort > /tmp/rustc-allow.txt
rustup run stable clippy-driver -W help \
  | sed -n 's/^ *clippy::restriction  *//p' | tr ',' '\n' \
  | sed 's/^ *clippy:://; s/-/_/g' | sort > /tmp/clippy-restriction.txt
grep -oE '^[a-z0-9_]+' Cargo.toml | sort -u > /tmp/manifest-lints.txt
comm -23 /tmp/rustc-allow.txt /tmp/manifest-lints.txt
comm -23 /tmp/clippy-restriction.txt /tmp/manifest-lints.txt
```

### Satisfying the profile

The patterns below come up immediately. All were exercised against the profile.

- **Tests:**
  - Unit tests live in an inline `#[cfg(test)] mod tests { ... }`. `inline_modules` does
    not lint test modules.
  - Integration tests in `tests/<name>.rs` also wrap their `#[test]` functions in
    `#[cfg(test)] mod tests { ... }` (`tests_outside_test_module`).
  - Every test function gets a doc comment that says what it pins
    (`missing_docs_in_private_items`).
  - Three doc lints are about rendered API documentation and do not fit test code. Rustdoc
    never renders test code, and a test panics exactly when it fails. The lints are
    `missing_panics_doc`, `missing_errors_doc` and `too_long_first_doc_paragraph`; the
    first two reach test code only through `check-private-items`. Put one
    `#[expect(<those that fire there>, reason = "test code is not rendered API documentation")]`
    on each test module, instead of a `# Panics` section on every test. Production code,
    private items included, writes the sections.
  - `missing_assert_message` does not lint test code. Give an assertion a message wherever
    a bare failure would be unclear.
  - Tests return `Result` and use `?` instead of `unwrap`/`expect`. A test that also asserts
    trips `panic_in_result_fn`, which guards production code; a test fails by panicking.
    Such a test module carries both expectations:

    ```rust
    #[cfg(test)]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    mod tests { /* ... */ }
    ```
- **Binaries:**
  - A binary with no unit tests sets `test = false` in its `[[bin]]` table.
  - `main` returns `ExitCode` or `Result` (`exit` denies `process::exit`).
  - User-facing output goes through `std::io::Write`, because the print macros are denied.
  - Diagnostics go through `tracing`.
- **Public API of a library:**
  - `missing_const_for_fn` asks for `const` wherever possible. Making a public function
    `const` is a semver commitment; where you deliberately won't make it, put
    `#[expect(clippy::missing_const_for_fn, reason = "...")]` on that function.
  - A re-export facade module carries one module-level
    `#![expect(clippy::pub_use, reason = "public facade")]`.
  - Public types are `#[non_exhaustive]` (`exhaustive_enums`, `exhaustive_structs`).
  - Public functions are `#[inline]` (`missing_inline_in_public_items`).
- **Arithmetic and conversions:**
  - `arithmetic_side_effects`, `integer_division`, `modulo_arithmetic` and `as_conversions`
    rule out bare operators and `as`. Use `checked_*` / `saturating_*` / `wrapping_*` with
    an explicit overflow decision, and `From` / `TryFrom` for conversions.
  - Literals carry a separated suffix or a typed binding: `1_u32`
    (`default_numeric_fallback`, `unseparated_literal_suffix`).
  - Floating-point arithmetic is denied (`float_arithmetic`). A module whose domain is
    approximate (DSP, metrics smoothing) carries a module-level
    `#![expect(clippy::float_arithmetic, reason = "...")]` (see the embedded overlay).
- **Results:**
  - Every expression result is used (`unused_results`). Discard a value explicitly, and
    pick the form by whether its type has drop glue:
    - it owns a destructor (`String`, `Vec`, `Box`, an `Option` of one): `drop(expr);`.
      `let _: T = expr;` is denied for these (`let_underscore_drop`);
    - anything else (`Copy` types, references, plain data): `let _: T = expr;`, typed per
      `let_underscore_untyped`. `drop` is denied for these (`dropping_copy_types`,
      `dropping_references`, `drop_non_drop`). `redundant_type_annotations` is excluded
      because it would reject this form too.
  - A `#[must_use]` value is not discarded at all, by `let _` (`let_underscore_must_use`)
    or by `drop`; handle it.
- **Secrets:** a type that holds secret material must not be `Copy`. Give it
  `#[expect(missing_copy_implementations, reason = "secret material must not be implicitly copied")]`.
- **Layout and visibility:**
  - No `mod.rs` (`mod_module_files`). No non-test inline modules (`inline_modules`).
  - Crate-internal items are `pub(crate)` (`unreachable_pub`); see the override row in the
    exclusions table.
- **Imports:**
  - Prefer `core::` / `alloc::` paths over `std::` where the item lives there
    (`std_instead_of_core`, `std_instead_of_alloc`; a std crate declares
    `extern crate alloc;`).
  - No absolute paths inside code (`absolute_paths`).
- **Duplicated dependencies** fail both `multiple_crate_versions` and cargo-deny's
  `multiple-versions = "deny"`. Prefer `cargo update` / aligning versions. What is truly
  unavoidable goes into `allowed-duplicate-crates` and `[bans] skip`, with reasons.

### Lint rationale by area

The profile enables everything; this subsection explains why the most consequential lints
matter. Do not read it as a configuration source.

#### Group priorities

**`priority = -1` is mandatory on group entries.** Cargo evaluates `[lints]` in priority
order, and entries at equal priority conflict when a group and an individual lint overlap.
The groups sit at `-1` so that the profile's individual entries are unambiguous. One example
is the `redundant_pub_crate = "allow"` contradiction override inside the `nursery` group.

#### Defensive programming

- `indexing_slicing`: prefer `.get()` or pattern matching.
- `fallible_impl_from`: `From` impls that should be `TryFrom`.
- `wildcard_enum_match_arm`: no catch-all `_` in enum matches.
- `fn_params_excessive_bools`: too many `bool` parameters (threshold in `clippy.toml`).
- `must_use_candidate`: suggests `#[must_use]`.
- `await_holding_lock`: a std or parking_lot `MutexGuard` held across `.await`. It catches
  the obvious case only; still review every `Mutex` import in async modules.
- `cast_ptr_alignment`: `*const u8 as *const u16` is UB if unaligned (the unsafe-ffi overlay
  covers `ptr::read_unaligned`).

The pointer lints (`cast_ptr_alignment`, `transmute_ptr_to_ref`,
`not_unsafe_ptr_arg_deref`) describe hazards that are unreachable without an `unsafe` block.
In a crate on `unsafe_code = "forbid"` they never fire. They stay in the profile so the
configuration is identical everywhere, and they become live the moment a crate loads the
unsafe-ffi overlay.

#### Panic prevention

A server process must never panic in production. These lints enforce
compile-time prevention of runtime panics:

- `unwrap_used`: no `.unwrap()` anywhere; use `?`, `unwrap_or`, etc.
- `expect_used`: `.expect()` is marginally better but still panics.
- `panic`: no intentional `panic!()` in production paths.
- `todo`: no `todo!()`; these panic at runtime.
- `unimplemented`: no `unimplemented!()`, same as `todo`.
- `unreachable`: prefer compiler-proven unreachability via exhaustive `match`.
- `unwrap_in_result`, `panic_in_result_fn`, `get_unwrap`, `indexing_slicing`, `string_slice`
  close the remaining back doors.

`expect_used` is at the same level as `unwrap_used`: a panic is a panic regardless of
whether it carries a message. The message improves the postmortem but does not keep the
process alive. Denying both makes every exception path explicit as a
`#[expect(clippy::expect_used, reason = "...")]`, rather than letting `expect`
accumulate silently.

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

The profile's `infinite_loop` (restriction) adds the companion check for `loop`s in
functions that do not return `!`.

The profile is stricter than the Section 2 guidance ("no unwrap in library code"). For a
server binary, a panic in *any* code path, library or application, crashes the process.
Use `?`, `unwrap_or`, `unwrap_or_else`, `unwrap_or_default`, or an explicit `match`
instead. Exceptions need `#[expect(clippy::unwrap_used, reason = "...")]` with the reason
stating why the value is guaranteed to be `Some`/`Ok`.

Clippy 1.95 added an `allow-unwrap-types` config key for `clippy.toml`
that lets `unwrap_used` / `expect_used` ignore specific types. **Do not
enable it.** Fix the call site, or add a local `#[expect(..., reason = "...")]`.

#### Debug artifacts

Debug macros and raw stdout/stderr writes must never reach production. Use `tracing` for
all diagnostics:

- `dbg_macro`: no `dbg!()`; use `tracing::debug!`.
- `print_stdout`: no `println!()`; use `tracing::info!`. A CLI's *product* output goes
  through `std::io::Write`.
- `print_stderr`: no `eprintln!()`; use `tracing::error!`.
- `use_debug`: no `{:?}` in non-test formatting; `Debug` is not an output format
  (Section 13).

#### Complexity

`cognitive_complexity` and `too_many_lines` flag functions that are too complex to reason
about or review safely. Their thresholds live in `clippy.toml`. The fix is decomposition
into named helpers; `single_call_fn` is excluded from the profile precisely so that
decomposition stays possible.

#### String handling

- `str_to_string`: prefer `.to_owned()`.
- `string_add`, `string_lit_chars_any`: hidden allocations and slow forms.
- `string_slice`: `&s[a..b]` panics on a non-char boundary.

`string_slice` is the string-specific companion to `indexing_slicing`. Byte-range slicing
of a `str` panics when an index falls inside a multi-byte UTF-8 sequence, and that is
attacker-reachable wherever the slice bounds derive from external input. Non-ASCII input is
a realistic trigger for anything parsing headers, tokens, tool arguments, or identifiers.

```rust
// BAD: panics if byte 8 is not a char boundary (e.g. "naïve-token")
let prefix = &token[..8];

// GOOD: never panics, and the truncation point is explicit
let prefix = token.get(..8).unwrap_or(token);
// GOOD: iterate by chars when you mean "first 8 characters"
let prefix: String = token.chars().take(8).collect();
```

**Removed: `string_to_string`.** This lint no longer exists. Clippy deprecated it, and
[`implicit_clone`](https://github.com/rust-lang/rust-clippy/blob/master/clippy_lints/src/deprecated_lints.rs)
covers the same `String::to_string()` cases. Declaring it produces an `unknown_lints`
warning; delete it from existing manifests.

**`with_capacity_zero` (Clippy 1.98+).** Flags `Vec::with_capacity(0)`,
`String::with_capacity(0)`, `PathBuf::with_capacity(0)`, `OsString::with_capacity(0)`, and
the equivalent collection constructors, all of which are just a more expensive spelling of
`new()`. It is `pedantic`, so the profile denies it. Follow the suggestion. A capacity
computed at runtime that happens to be zero is not what the lint flags.

#### Numeric and pointer casts

`as` casts are silent. They truncate, wrap, and change signedness without a diagnostic,
which makes them a poor fit for a codebase that otherwise denies `unwrap`. The profile
denies `as_conversions` outright. It also carries the finer-grained lints that name the
right replacement:

- `cast_lossless` catches *widening* casts that cannot fail and should be spelled as a
  `From` conversion, so the reader can tell at a glance that no data is lost. Narrowing
  (`cast_possible_truncation`) gets `TryFrom` and a real error path (Section 2).
- `ptr_as_ptr` keeps pointer casts in the type system. `.cast()` preserves mutability and
  constness, whereas an `as` cast will happily convert `*const T` to `*mut T` if you typo
  the target type.

```rust
// BAD: `as` hides which conversions are lossless and which are not
let total = count as u64;
let p = raw as *const Header;

// GOOD: infallible widening is explicit; narrowing gets a real error path
let total = u64::from(count);
let port = u16::try_from(raw_port).map_err(|_| ConfigError::PortOutOfRange)?;
let p = raw.cast::<Header>();
```

#### Documentation

`missing_docs`, `missing_docs_in_private_items`, the `missing_*_doc` family (with
`check-private-items`) and every rustdoc lint are denied.

- Rustdoc lints only run under `rustdoc`, so CI runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` (Section 12).
- `doc_markdown` demands backticks around anything resembling an identifier. Put proper
  nouns that are not code (`OAuth`, `JWKS`, `PowerShell`) into `doc-valid-idents` instead
  of backticking them.
- `duration_suboptimal_units` rewrites `Duration::from_millis(5000)` into `from_secs(5)`.
  Follow it: the values stay comparable because the type is `Duration`, not the literal.

#### Library crates

Public API surface must be future-proof and documented:

- `exhaustive_enums` / `exhaustive_structs`: public types are `#[non_exhaustive]`.
- `missing_inline_in_public_items`: cross-crate inlining is explicit.
- `pub_use`: re-exports are deliberate, with one module-level `expect` per facade.
- `missing_docs`: every public item is documented.

#### Performance

- `redundant_clone`: a clone of a value that is not used afterwards.
- `implicit_clone`: `.to_owned()` / `.to_string()` where `clone` suffices.
- `needless_pass_by_value`: pass by reference instead of by value.
- `large_enum_variant`: consider boxing large variants (threshold in `clippy.toml`).
- `box_collection`: `Box<Vec<T>>` → `Vec<T>`.
- `rc_buffer`: `Rc<String>` → `Rc<str>`.
- `clone_on_ref_ptr`: `Arc::clone(&x)` over `x.clone()`.

`clone_on_ref_ptr`: `x.clone()` on an `Arc`/`Rc` is indistinguishable at a glance from a
deep clone of the pointee. Forcing the explicit `Arc::clone(&x)` spelling makes "this is a
refcount bump, not an allocation" visible at every call site, which is precisely the
distinction Section 1 relies on when it says cloning an `Arc` is acceptable.

Clippy 1.95 added two `complexity`-tier lints:

- `manual_checked_ops`: prefer `checked_add`/`checked_sub`/`checked_mul`
  over hand-rolled overflow checks.
- `manual_take`: prefer `std::mem::take(&mut x)` over
  `mem::replace(&mut x, Default::default())`.

#### Clippy 1.98 new lints

Clippy 1.98 added seven lints. Five land in tiers covered by `clippy::all`; two are
`pedantic`. The Section 9 profile denies all seven.

| Lint | Tier | Covered by `all = "deny"`? | Action |
|------|------|----------------------------|--------|
| [`for_unbounded_range`](https://github.com/rust-lang/rust-clippy/pull/16257) | suspicious | yes | none - see "Panic Prevention" above |
| [`by_ref_peekable_peek`](https://github.com/rust-lang/rust-clippy/pull/17042) | suspicious | yes | none - real bug class, see below |
| [`manual_isolate_lowest_one`](https://github.com/rust-lang/rust-clippy/pull/17037) | complexity | yes | none - enforces the Section 4 bit-ops rule |
| [`unnecessary_unwrap_unchecked`](https://github.com/rust-lang/rust-clippy/pull/16252) | complexity | yes | none - moot under `unsafe_code = "forbid"` |
| [`chunks_exact_to_as_chunks`](https://github.com/rust-lang/rust-clippy/pull/16931) | style | yes | none |
| [`with_capacity_zero`](https://github.com/rust-lang/rust-clippy/pull/17192) | **pedantic** | **no** | follow the suggestion - see "String handling" above |
| [`unused_async_trait_impl`](https://github.com/rust-lang/rust-clippy/pull/16244) | **pedantic** | **no** | per-impl `#[expect]` where a foreign trait mandates `async` - see below |

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
the signature to `fn ... -> impl Future` returning `std::future::ready(..)`.

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

The suggestion is technically correct - it avoids a state machine for a value
that is immediately ready - but the rewrite is often **impossible**, not merely
undesirable: when you are *implementing* a foreign trait, the `async fn`
signature is dictated by that trait and cannot be changed from your side.

**Use a per-item `#[expect]` with a `reason`; a crate-level allow is not permitted by
the profile policy.** A blanket allow would also silence the cases where the lint is right (a genuinely unnecessary `async fn` you *could*
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

`#[expect(...)]` (never `#[allow(...)]`, which the profile denies) warns if the lint
*stops* firing, so the exemption is removed automatically once the
upstream trait changes or the impl grows a real `.await`.

#### Clippy 1.98 removals and moves

- **`from_iter_instead_of_collect` was removed.** Previously `pedantic`; Clippy
  [deprecated it](https://github.com/rust-lang/rust-clippy/pull/17208) as
  "proved problematic". Delete any explicit declaration.
- **`empty_enums` moved `pedantic` -> `nursery`**
  ([PR #17298](https://github.com/rust-lang/rust-clippy/pull/17298)). No effect under
  the profile, which denies both groups.
- **`result_large_err` / `result_unit_err` now fire on `async fn`**
  ([PR #17130](https://github.com/rust-lang/rust-clippy/pull/17130)). Both are
  in `clippy::all`, so async-heavy crates may see **new** denials on upgrade
  from previously-exempt async signatures. This is the most likely source of a
  surprise `-D warnings` failure when moving to 1.98.

#### Clippy 1.99 new lints

Clippy 1.99 added eight lints. The profile denies all of them.

| Lint | Tier | What it enforces |
|------|------|------------------|
| [`nonnull_unchecked_on_box_ptr`](https://github.com/rust-lang/rust-clippy/pull/17336) | complexity | `Box::into_non_null(b)` instead of `unsafe { NonNull::new_unchecked(Box::into_raw(b)) }` (unsafe-ffi overlay) |
| [`mismatched_bit_width_type`](https://github.com/rust-lang/rust-clippy/pull/16902) | suspicious | `u32::BITS - x_u64.leading_zeros()` underflows: a debug panic, and a wrong value in release (Section 4) |
| [`block_scrutinee`](https://github.com/rust-lang/rust-clippy/pull/16855) | suspicious | `if let P = { expr }` (edition 2021 and older only) |
| [`assert_is_empty`](https://github.com/rust-lang/rust-clippy/pull/17149) | pedantic | see below |
| [`manual_bit_width`](https://github.com/rust-lang/rust-clippy/pull/16902) | pedantic | `T::BITS - x.leading_zeros()` → `x.bit_width()` (Section 4) |
| [`unnecessary_rest_pattern`](https://github.com/rust-lang/rust-clippy/pull/15000) | restriction | a `..` that matches nothing (Section 3) |
| [`rest_pattern_accessible_field`](https://github.com/rust-lang/rust-clippy/pull/15000) | restriction | a `..` that hides nameable fields (Section 3) |
| [`definition_in_module_root`](https://github.com/rust-lang/rust-clippy/pull/16965) | restriction | definitions in `mod.rs`; never fires under `mod_module_files` |

**`assert_is_empty`: its suggested fix is the wrong one for this profile.** It flags
`assert!(v.is_empty())` and `assert!(!v.is_empty())` *without a message* (also the
`debug_` forms). It suggests `assert_eq!(v, [] as [T; 0])`, so a failure prints the value.
Two problems with applying that mechanically:

- Printing the value is wrong when it may hold secrets, tokens, credentials, or raw
  request/response bodies. The lint's own *Known problems* section says so.
- `[] as [T; 0]` trips rustc's `trivial_casts`, which the profile denies, so the suggested
  fix itself fails CI.

Give every emptiness assertion a message instead. The lint skips assertions that have one,
the output contains exactly what you chose, and `missing_assert_message` requires the
message anyway:

```rust
// Non-sensitive: put the value in the message
assert!(names.is_empty(), "expected no names, got {names:?}");
// Sensitive: say what failed, never what the value was
assert!(!secret.is_empty(), "credential buffer must not be empty");
// Non-sensitive strings only - assert_eq! prints both values on failure
assert_eq!(label, "", "label should be empty");
// Sensitive strings: boolean form with a message, never assert_eq!
assert!(secret_label.is_empty(), "secret label should be empty");
```

#### Clippy 1.99 behaviour changes

- **`clone_on_copy` now also lints UFCS calls** (`Clone::clone(&x)`, `i32::clone(&x)`).
  `clone_on_ref_ptr` is unaffected: `Arc::clone(&x)` is not `Copy` and stays required.
- **`must_use_candidate`, `double_must_use` and `let_underscore_must_use`** now use the
  compiler's own `#[must_use]` algorithm, so the set of findings shifts on upgrade.
- **`branches_sharing_code`** now also lints `match` arms that end in the same expression.
- **More findings from other broadened lints:**
  - `host_endian_bytes` (and the excluded big/little variants) now match method paths and
    UFCS.
  - `float_cmp_const` now sees inside `assert_eq!`.
  - `unnecessary_safety_comment` now handles compound assignments.

#### Crate-level safety lints

These Rust-level lints enforce safety invariants at the crate boundary.

`unsafe_code = "forbid"` is part of the profile. A crate that genuinely requires
`unsafe` loads `overlays/domains/unsafe-ffi.md`, lowers it to `deny`, and puts
`#[expect(unsafe_code, reason = "...")]` plus a `// SAFETY:` comment on each
individual item.

**Rust 1.98+: the lint now covers unsafe *attributes*, not just unsafe blocks.**
[Rust 1.98 made `UNSAFE_CODE` fire consistently for all unsafe
attributes](https://github.com/rust-lang/rust/pull/157201). In edition 2024
these carry an explicit `unsafe(...)` wrapper:

```rust
#[unsafe(no_mangle)]        // now trips unsafe_code
#[unsafe(export_name = "...")] // now trips unsafe_code
#[unsafe(link_section = "...")] // now trips unsafe_code
#[unsafe(naked)]             // now trips unsafe_code
```

Consequences:

- A crate with `unsafe_code = "forbid"` that used any of these attributes
  **compiled on 1.97 and fails on 1.98**. This is the most likely 1.98 upgrade
  break for an otherwise `unsafe`-free crate. `forbid` cannot be locally
  overridden - you must load the unsafe-ffi overlay (`deny` + a justified per-item
  `#[expect(unsafe_code, reason = "...")]`), or remove the attribute.
- `unsafe_code` is **allow-by-default**, so it is not in the `warnings` lint
  group. Neither `RUSTFLAGS="-D warnings"` nor Cargo's `build.warnings`
  (Section 7) will enable it. It must be set explicitly in `[lints.rust]` -
  which is exactly why it appears in the table above.

#### Runtime symbol definitions

Rust 1.98 and 1.99 added lints that check definitions of symbols the standard library
itself calls:

- `invalid_runtime_symbol_definitions`: deny-by-default, and outside the `warnings` group;
- `suspicious_runtime_symbol_definitions`;
- `c_void_returns`.

Exporting an unmangled symbol needs an unsafe attribute, which `unsafe_code = "forbid"`
rejects. These lints therefore matter only for crates that load
`overlays/domains/unsafe-ffi.md`, which carries the full rules, including the 1.99 POSIX
coverage.

`missing_docs` is denied in every crate, library or binary.

`dead_code_pub_in_binary` (Rust 1.97+, allow-by-default, denied by the profile)
extends dead-code detection to `pub` items. A binary has no public API, so
`pub` should not suppress the unused-code warning the way it does in a
library. It complements `unreachable_pub`: the latter flags `pub` that ought
to be `pub(crate)`, the former flags `pub` items that are simply never used.
It only has an effect in binary crates; in a library, `pub` items are the
intended API surface and the lint stays silent.

#### Linker diagnostics (Rust 1.97+)

Rust 1.97 stopped hiding linker stderr. Links that previously succeeded
silently now surface their output through a new warn-by-default
`linker_messages` lint:

```text
warning: linker stderr: <message>
  |
  = note: `#[warn(linker_messages)]` on by default
```

This is high-signal for any crate that links C libraries (OpenSSL, zlib,
platform SDKs) or uses a custom linker script - several
real defects were found upstream once this output stopped being swallowed.
Two properties matter:

- `linker_messages` is **not** part of the `warnings` lint group. Neither
  `RUSTFLAGS="-D warnings"` nor Cargo's `build.warnings = "deny"` (Section 7)
  affects it - the profile denies it explicitly.
- Linker output is platform-dependent and rustc does not control it
  precisely, so treat it as advisory. rustc already filters common false
  positives. Silence known-benign, platform-specific output at the linker (flags,
  link configuration), never by lowering the lint; record the flag and the exact
  message in the project overlay.

#### Lints for LLM-generated code

All of these are in the profile; they are grouped here as the minimum surface specifically targeting failure modes
that pass `cargo build` and `cargo test` on LLM-written Rust. Source:
the Habr "Я заставил LLM писать Rust полгода" article (see References).

- Async cancel-safety / `Mutex` hazards (Habr Category 2 + 5): `await_holding_lock`,
  `await_holding_refcell_ref`.
- Unsafe alignment / pointer hazards (Habr Category 4): `cast_ptr_alignment`,
  `transmute_ptr_to_ref`, `not_unsafe_ptr_arg_deref` (live only under the unsafe-ffi
  overlay).
- RAII / Drop hazards (Habr Category 3): `mem_forget`.
- Trait-system semver hazards (Habr Category 6): no direct lint exists; rely on the
  Section 7 anti-pattern rule and manual review of `impl<T: Bound> Trait for T`.
- Stack-allocated boxes / large arrays (Habr Category 7): `large_stack_arrays`,
  `large_stack_frames`.
- AI-bias hazards, high-signal on LLM code: `ptr_as_ptr`, `cast_lossless`,
  `redundant_clone`, `needless_pass_by_value`.

Limitations to be aware of:

- `await_holding_lock` only catches guards visibly alive across `.await`
  in the same function. Guards returned from a helper, stored in a struct
  field, or produced by `MutexGuard::map` slip past. Treat as necessary
  but not sufficient - hand-review every `Mutex` import in async modules.
- `cast_ptr_alignment` fires on the obvious cast pattern but not on every
  way to construct a misaligned pointer (e.g. `slice::from_raw_parts` with
  a hand-computed offset). The Section 4 prose rule is still required.
- There is no clippy lint for blanket-impl semver hazards or for async
  cancel safety. Those remain prose-only rules in Sections 7 and 5.
- Crates that permit `unsafe` (unsafe-ffi overlay) also run `cargo +nightly miri test`
  where the target permits (Section 12 "Miri caveats"). Miri is the only reliable catch
  for the UB cases that pass clippy.

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
tooling-compatibility note only - it does not change runtime behavior.

---

## 10. Security and Supply Chain

These rules apply to every crate, since every crate handles untrusted input, secrets, or
third-party code. Domain rules live in overlays:
- HTTP services (response headers, fingerprinting, SSRF, error responses):
  `overlays/domains/http-services.md`.
- Credential-bearing protocol clients: `overlays/domains/kerberos-credential-protocols.md`.

### DO: Validate and sanitize all external input at system boundaries

- **Parameterized queries only** - never interpolate user input into SQL,
  shell commands, or API paths.
- **Type-driven validation** - use newtypes + validated constructors (SS3)
  for IDs, hostnames, container names, image references, etc.
- **Length limits** - enforce maximum lengths on all string inputs before
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
tokens. The chained form is easy to get subtly wrong - most commonly by
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

### DO: Make lossy UTF-8 decoding cheap and visible (Rust 1.99+)

The rule from the UTF-16 item above applies to UTF-8 too: anything
security-relevant uses the fallible decoder; lossy decoding is for display and
logging only. Rust 1.99 stabilized two helpers that make the display path
cheaper and keep the "this input was malformed" signal:

```rust
// BAD: always copies, even when `bytes` is valid UTF-8 - and the fact that
// the input had to be repaired is lost.
let text = String::from_utf8_lossy(&bytes).into_owned();

// GOOD (display only): consumes the owned Vec; no copy needed when it is valid.
let text = String::from_utf8_lossy_owned(bytes);

// GOOD (audit / diagnostics): keep the malformation signal, still get display
// text, and do not re-validate the valid prefix.
let (text, malformed) = match String::from_utf8(bytes) {
    Ok(text) => (text, false),
    Err(e) => (e.into_utf8_lossy(), true),
};
tracing::warn!(malformed, %text, "peer reply");
```

`from_utf8_lossy_owned` does not *guarantee* reusing the allocation. Either way
the result is display text: never compare, allowlist, classify, or hash it.

### DO: Set file times through an open handle; use `set_times_nofollow` only when you mean the link itself (Rust 1.99+)

Rust 1.99 stabilized `std::fs::set_times` and `std::fs::set_times_nofollow`.
Both take a **path**, and `set_times` **follows symlinks**. If any directory
on that path is writable by another principal, the file can be swapped for a
symlink between your check and your call, and you set the timestamps of
whatever the link points at. Timestamps drive rotation, retention, backup,
cache freshness, and renewal decisions - this is an integrity issue, not a
cosmetic one.

```rust
use std::fs::{self, File, FileTimes};

// BAD when any directory on `path` is writable by someone else: resolved at
// call time, follows symlinks, may not be the file you validated a moment ago.
fs::set_times(&path, FileTimes::new().set_modified(issued_at))?;

// GOOD: set the times through the handle you created and wrote (File::set_times
// is stable since 1.75). `create_new` refuses to open anything already there,
// including a planted symlink.
let mut file = File::create_new(&tmp_path)?;
file.write_all(&payload)?;
file.set_times(FileTimes::new().set_modified(issued_at))?;

// GOOD: when the path may legitimately be a symlink and you mean the link
// itself (mirroring a tree), say so.
fs::set_times_nofollow(&link_path, FileTimes::new().set_modified(now))?;
```

Rules:

- Prefer `File::set_times` on the handle you created, validated, or wrote.
- Use path-based `fs::set_times` only inside directories no other principal
  can write to.
- Use `fs::set_times_nofollow` only when you mean the final path component
  itself. It does not pin parent directories, and it does not stop the file
  being replaced by another non-symlink file - an untrusted path still needs a
  handle-based (open, validate, then operate on the handle) flow.
- Supply chain: `std` now covers what the `filetime` crate was typically used
  for (`set_file_times`, `set_symlink_file_times`) - one fewer dependency to
  audit (`cargo machete`, Section 12).
- MSRV: the free functions are 1.99 APIs; `File::set_times` is 1.75.

### DON'T: Hardcode secrets in source code

- API keys, passwords, TLS private keys, and JWT signing secrets must come
  from environment variables, config files (excluded from VCS), or a secrets
  manager.
- Use `secrecy::Secret<String>` (from the `secrecy` crate) to wrap secrets
  so they are zeroized on drop and redacted in `Debug`/`Display` output.
- Never log secrets. Redact sensitive fields before passing to `tracing`.
- Zeroization belongs to the value (`secrecy::Secret`, `zeroize::Zeroizing`).
  Do not rely on a custom `#[global_allocator]` to erase secrets: the Rust 1.99
  `GlobalAlloc` docs state that allocations may be stack-promoted, merged, or
  skipped, so the deallocation may never reach the allocator. When `dealloc`
  is called, the allocator may overwrite the bytes, but it cannot rely on
  reading initialized contents.

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
- Never use `rand::thread_rng()` for cryptographic material - it may not
  be backed by a CSPRNG on all platforms.
- Prefer `rand::fill()` into a fixed-size byte array, then encode with
  base64 or hex.

### DO: Enforce TLS and certificate validation

- Always use `rustls` with `webpki-roots` (or system roots) - never
  disable certificate verification.
- Set `min_protocol_version = Some(TLSv1_2)` or higher.
- For mTLS, validate the client certificate chain and check the CN/SAN.
- **Scope note.** Credential-bearing protocol clients (Kerberos, LDAP password-modify,
  SASL/SCRAM) carry further obligations: `overlays/domains/kerberos-credential-protocols.md`.

### DO: Audit dependencies regularly

- Run `cargo audit` in CI on every PR (checks RustSec advisory DB).
- Run `cargo deny check` for license compliance, duplicate crate detection,
  and banned crate policies.
- Pin dependencies with `Cargo.lock` in version control for binaries.
- Review new transitive dependencies before merging.

### DO: Configure `cargo deny` with a `deny.toml`

A bare `cargo deny check` with no configuration is better than nothing,
but a `deny.toml` makes policies explicit and enforceable. These are the strictest settings
that parse on cargo-deny 0.19 (verified with 0.19.6):

```toml
# deny.toml - workspace root
[graph]
all-features = true           # optional dependencies are held to the same policy

[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
# Scope, NOT a lint level: one of "all" | "workspace" | "transitive" | "none".
# "all" - transitive deps are where most RUSTSEC exposure actually lives.
unmaintained = "all"
unsound = "all"
yanked = "deny"

[licenses]
confidence-threshold = 0.93
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "BSL-1.0",
]

[bans]
multiple-versions = "deny"    # unavoidable duplicates go into `skip`, each with a reason
wildcards = "deny"            # No * version specs
allow-wildcard-paths = false
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
required-git-spec = "rev"     # git dependencies pinned to a commit
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

Adjust the license allowlist to your organization's policy. The list above is a starting
point; a real workspace will need entries for whatever its transitive deps actually carry
(e.g. `Apache-2.0 WITH LLVM-exception`, `CDLA-Permissive-2.0`). The `[sources]` section
prevents dependencies from unknown registries or arbitrary git repos. Keep `[bans] skip` in
step with `allowed-duplicate-crates` in `clippy.toml` (Section 9).

- **Path dependencies state their version too.** Under `wildcards = "deny"` with
  `allow-wildcard-paths = false`, a bare `path` counts as a wildcard and fails `bans`.
  Write `member = { version = "0.1.0", path = "../member" }`.
- **`all-features = true`** checks the dependencies that only an optional feature pulls
  in. Without it they go unchecked, and a `skip` entry for one is reported as never
  encountered.

> **Do not add `vulnerability`, `unlicensed`, `copyleft`, or `notice` keys.** They were
> removed in [cargo-deny #611][deny-611] and are now a hard `error[deprecated]` that fails
> config parsing outright (verified against cargo-deny 0.19). This is not a loosening:
> `vulnerability` and `unlicensed` became unconditional errors, so the behaviour they used to
> configure is now the default and cannot be downgraded. Likewise `unmaintained` changed
> from a lint level to a *scope*. `unmaintained = "warn"` no longer parses; it fails with
> `error[unexpected-value]` on cargo-deny 0.19.6.
>
> If you copy a `deny.toml` from an older guide or blog post, run `cargo deny check` before
> committing it. A stale sample fails at config load, not at policy evaluation, so the error
> can look unrelated to the file you just added.

[deny-611]: https://github.com/EmbarkStudios/cargo-deny/pull/611

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

Keep `deny.toml` and `.cargo/audit.toml` in sync - they are read by different
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
# nightly only - do NOT depend on this in CI yet
[registry]
global-min-publish-age = "14 days"

[resolver]
incompatible-publish-age = "deny"   # ignore too-new versions unless already in Cargo.lock
```

Not usable on stable and therefore **not** a current requirement. Track it for
stabilization; a 7-14 day quarantine is a cheap, high-leverage control for a
crate handling auth and credentials.

**Update (Cargo 1.99 changelog page):** stabilization is merged for **Cargo 1.100**,
scheduled for 2026-11-12, as `registry.global-min-publish-age`. Keep this a WATCH
item until 1.100 ships, then re-verify the stable key names against the 1.100
documentation before promoting it to a DO - the nightly snippet above may not
match the stabilized surface.

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
- [ ] Guard clauses use `bool::ok_or` / `ok_or_else` rather than four-line `if ... return Err` blocks (Rust 1.98+)

**Type Safety**
- [ ] Newtypes used for domain concepts (IDs, amounts, durations)
- [ ] Enums used instead of `bool` params where meaning is unclear
- [ ] `match` arms are exhaustive - no wildcard `_` catch-all on owned enums
- [ ] Struct fields private with validated constructors (for library types)
- [ ] `#[must_use]` on types/functions where ignoring the result is a bug
- [ ] Comparison traits are all-manual or all-derived - never a manual `PartialEq` alongside a derived `Ord`/`PartialOrd` (Rust 1.98+ can expose the inconsistency)
- [ ] Types with a manual `PartialEq` are not used in constant patterns (rejected on Rust 1.98+)
- [ ] `#[repr(transparent)]` not applied over `#[non_exhaustive]`, `repr(C)`, or private-field types (Rust 1.98+ rejects these)
- [ ] Non-zero domain values parsed via `NonZero::from_str_radix` rather than parse-then-`NonZero::new` (Rust 1.98+)
- [ ] No `RangeInclusive` read (`start()`/`end()`) or reused as a cursor after it has been iterated to exhaustion (values changed in Rust 1.99)

**Performance**
- [ ] No `Box<Vec<T>>`, `Box<String>`, `Arc<String>`
- [ ] No collect-then-iterate - iterate directly
- [ ] No `String::from("...")` where `&str` is accepted
- [ ] HashMap lookups use `&str`, not cloned `String` keys
- [ ] `core::hint::cold_path()` marks genuinely unlikely branches (Rust 1.95+); perf hint only, never correctness
- [ ] Prefer std bit ops `bit_width` / `isolate_highest_one` / `isolate_lowest_one` / `highest_one` / `lowest_one` over hand-rolled shift/mask arithmetic (Rust 1.97+; lint-enforced by Clippy 1.98 `manual_isolate_lowest_one` and Clippy 1.99 `manual_bit_width` / `mismatched_bit_width_type`)
- [ ] No `algebraic_*` float methods on any value that is compared, hashed, serialized, persisted, or asserted on - they are non-deterministic (Rust 1.98+)
- [ ] Integer formatting in hot / `no_std` paths uses `format_into` + `NumBuffer` instead of `to_string()` / `format!` (Rust 1.98+)
- [ ] Sub-slice offsets recovered with `substr_range` / `subslice_range`, never pointer arithmetic (Rust 1.98+)

**Async**
- [ ] No `std::fs` / `std::net` in async functions
- [ ] Blocking work wrapped in `spawn_blocking`
- [ ] Timeouts use `tokio::select!`
- [ ] No `std::sync::Mutex` held across `.await` points
- [ ] Every async fn that may run inside `select!` / `timeout` / an executor's abort primitive carries a `// cancel-safe:` or `// NOT cancel-safe:` doc comment with reasoning
- [ ] Drop impls of async resources (transactions, pooled connections, guards) audited; explicit cleanup on every path, never relied on Drop alone
- [ ] No `Box::new([0; N])` for large `N` - use `vec![0; N].into_boxed_slice()` (especially on small stacks)

**Defensive**
- [ ] No `..Default::default()` hiding new fields
- [ ] Manual trait impls destructure the struct (future-proof)
- [ ] No `Deref` for fake inheritance
- [ ] Struct patterns in manual trait / `Drop` / redaction impls are exhaustive (no `..`); ignored fields named (`timestamp: _`)
- [ ] No `&s[a..b]` on a `str` with externally-derived bounds (`string_slice`); use `get(..)` or char iteration
- [ ] Widening conversions use `From`, narrowing ones `TryFrom` with a real error path; no bare `as` (`as_conversions`, `cast_lossless`)

**API Design**
- [ ] Owned string params use `impl Into<String>`, read-only params use `&str`
- [ ] Constructors with validation return `Result`
- [ ] No more than 3-4 boolean parameters (use enums or param struct)
- [ ] Third-party types wrapped, not exposed in public APIs
- [ ] No blanket `impl<T: Bound> PublicTrait for T` unless `PublicTrait` is sealed

**Security**
- [ ] External input validated at system boundary (length, charset, allowlist)
- [ ] No string interpolation of user input into SQL, shell commands, or API paths
- [ ] Secrets loaded from env/config, never hardcoded; wrapped in `Secret<T>`
- [ ] Cryptographic randomness uses OsRng, not thread_rng
- [ ] TLS enabled with certificate validation; min TLS 1.2
- [ ] `cargo audit` and `cargo deny` run in CI
- [ ] Auth attempts and RBAC denials logged with structured tracing
- [ ] Delimiter-wrapped input (quoted header values, bracketed IPv6) stripped with `strip_circumfix`, not chained `strip_prefix`/`strip_suffix` (Rust 1.98+)
- [ ] UTF-16 boundary decoding uses the endian-explicit, non-`_lossy` `String::from_utf16{le,be}` (Rust 1.98+); `_lossy` reserved for display
- [ ] Every `cargo audit` / `cargo deny` ignore entry documents the advisory, why it does not apply, and upstream fix status
- [ ] File timestamps set via `File::set_times` on a handle you created/validated; path-based `fs::set_times` only in directories no other principal can write; `fs::set_times_nofollow` only when the link itself is meant - it does not make an untrusted path safe (Rust 1.99+)
- [ ] Zeroization attached to the secret values (`Secret` / `Zeroizing`), never delegated to a custom `#[global_allocator]`
- [ ] Lossy UTF-8 only for display/logging: owned bytes use `String::from_utf8_lossy_owned`; where malformation matters, `String::from_utf8` + `into_utf8_lossy` records it (Rust 1.99+)
- [ ] `deny.toml` matches Section 10 (parses on current cargo-deny; `multiple-versions = "deny"`; git deps pinned to `rev`)

**Runtime Safety**
- [ ] No `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` in production paths
- [ ] No `dbg!()`, `println!()`, `eprintln!()` - use `tracing` macros
- [ ] `unsafe_code = "forbid"` set at crate level (or `deny` + per-item `#[expect(unsafe_code, reason)]` + `// SAFETY:` under the unsafe-ffi overlay)
- [ ] Functions below cognitive complexity threshold (no god functions)
- [ ] Prefer `Atomic*::update` / `try_update` over hand-rolled `compare_exchange` loops (Rust 1.95+)
- [ ] Prefer `Vec::push_mut` / `VecDeque::push_{front,back}_mut` / `LinkedList::push_{front,back}_mut` over `push` + `last_mut().unwrap()` (Rust 1.95+)
- [ ] `linker_messages` (Rust 1.97+) denied by the profile; benign platform output silenced at the linker, never by lowering the lint (it is NOT in the `warnings` group)
- [ ] No unsafe *attributes* (`#[unsafe(no_mangle)]`, `#[unsafe(link_section)]`, `#[unsafe(export_name)]`, `#[unsafe(naked)]`) under `unsafe_code = "forbid"` - Rust 1.98+ now flags these; firmware crates needing them must use `deny` + justified `#[allow]`
- [ ] Bounded `VecDeque` windows trimmed with `retain_back(n)` (Rust 1.99+), not `drain(..len - n)`

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
- [ ] No assertions on `{:?}` output as a stable format - 1.98 escapes more characters, 1.99 stopped escaping U+FF9E/U+FF9F (re-check audit-log / redaction tests on every toolchain bump)
- [ ] Guards/locks inside `assert_eq!` / `assert_ne!` bound to a `let` rather than created inline (Rust 1.98+ changed macro temporary scope)

**Tooling**
- [ ] `cargo fmt --check` in CI
- [ ] `cargo clippy --all-targets -- -D warnings` with the Section 9 profile in CI
- [ ] rustc warnings denied in CI via `build.warnings = "deny"` / `CARGO_BUILD_WARNINGS=deny` (Rust 1.97+), preferred over `RUSTFLAGS=-Dwarnings` (cache-friendly, local-only)
- [ ] `cargo audit` and `cargo deny check` in CI
- [ ] `cargo semver-checks` in CI for library crates
- [ ] `rustfmt.toml` with `imports_granularity` and `group_imports` configured
- [ ] `cargo miri` run (nightly job) against pure-Rust modules with `unsafe`; HAL/FFI-touching crates exempted with a note; crates on `unsafe_code = "forbid"` legitimately have no Miri job
- [ ] `[lints.clippy]` group entries carry `priority = -1` so per-lint overrides do not conflict
- [ ] `clippy.toml` matches Section 9 (levels live in `Cargo.toml`, configuration lives here)
- [ ] Deprecated `string_to_string` and `from_iter_instead_of_collect` removed from `[lints.clippy]` (both no longer exist)
- [ ] `unused_async_trait_impl` (Clippy 1.98 `pedantic`) handled per-impl via `#[expect(..., reason = ...)]` where a foreign trait mandates the async signature - never silenced crate-wide
- [ ] One-time `cargo fmt --all` committed separately after adopting `cfg_select!` (Rust 1.98 rustfmt now formats modules declared inside it)
- [ ] Workspace `Cargo.toml` carries the Section 9 lint profile unchanged; every member has `[lints] workspace = true`; no group-level allows
- [ ] Every local exception is `#[expect(lint, reason = "...")]` on the narrowest item (`#[allow]` is denied)
- [ ] Section 9 completeness check run after the last toolchain bump; it prints exactly the documented exclusions
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` and `cargo machete` in CI
- [ ] `unneeded_field_pattern` removed from manifests; `unnecessary_rest_pattern` and `rest_pattern_accessible_field` enforced via the profile (neither lint sees `Self { .. }`)
- [ ] Clippy 1.99 `assert_is_empty` (pedantic) handled by giving emptiness assertions a message - value in the message only when it is safe to print; never the `[] as [T; 0]` rewrite (`trivial_casts`)
- [ ] `[lints]` entries use `snake_case` lint names (Cargo 1.99 deprecates hyphens)
- [ ] `[profile.debug]` only with `rust-version >= 1.99`; inherited `default-features = false` only in edition-2024 members with `rust-version >= 1.99` (hard errors on older Cargo; ignored with a warning outside edition 2024)

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
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features  # Rustdoc lints
cargo machete                                       # Unused dependencies
```

- **Default features too.** `--all-features` never compiles code under
  `cfg(not(feature = "..."))`, and in a workspace one member can turn another's features
  on. So also lint and test each library crate alone at its default features:
  `cargo clippy -p <library> --all-targets -- -D warnings` and `cargo test -p <library>`.
- **Vendored crates.** If the repository vendors third-party crates as path dependencies
  (`vendor/`), run machete on the first-party crates only, e.g. `cargo machete crates`.
  The vendored trees are upstream code and outside the profile.

**Rust 1.97+:** the `-D warnings` on the clippy line denies warnings only for
the targets clippy compiles. To deny **rustc** warnings across the whole
workspace in a cache-friendly, toggleable way, prefer Cargo's stabilized
`build.warnings` config (Section 7) over `RUSTFLAGS="-D warnings"`:

```bash
CARGO_BUILD_WARNINGS=deny cargo check --workspace --all-features --keep-going
```

**Cargo 1.98:** no action required. The
[1.98 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html)
has **empty `Added` and `Changed` sections** - no new stable config keys,
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

**Cargo 1.99:** two default changes, one new manifest capability, one deprecation.

- **Incremental compilation is off when `CI` is set**
  ([#17220](https://github.com/rust-lang/cargo/pull/17220)). Precedence:
  `CARGO_INCREMENTAL` > `build.incremental` > `CI` > `profile.*.incremental`.
  CI caches shrink without a cache action or an explicit `CARGO_INCREMENTAL=0`;
  keep that variable only while CI still runs pre-1.99 toolchains.
- **New built-in `debug` profile**
  ([#17214](https://github.com/rust-lang/cargo/pull/17214)). Today it is
  identical to `dev`; Cargo plans to move `dev` toward faster iteration and keep
  debugger-friendly settings in `debug`. `cargo install --debug` already uses it.
  `--profile debug` and `[profile.debug]` are **errors** on Cargo 1.98 and older
  ("profile name `debug` is reserved"), so use them only with
  `rust-version = "1.99"` or later.
- **Edition-2024 members can drop an inherited dependency's default features**
  ([RFC 3945](https://github.com/rust-lang/rfcs/pull/3945)):
  `dep = { workspace = true, default-features = false }` now takes effect. Use it
  to keep each member's feature set - and attack surface - minimal, e.g. a member
  that must not compile a dependency's default TLS backend. Two caveats: on
  Cargo 1.98 and older this exact line is a **hard error that stops the whole
  workspace from loading**, so raise `rust-version` to 1.99 in the same change;
  and features still unify across members built together - verify with
  `cargo tree -e features -p <member>`, not by reading the manifest. Edition-2021
  members still get the defaults (with a warning).
- **Hyphenated lint names in `[lints]` are deprecated**
  ([#17051](https://github.com/rust-lang/cargo/pull/17051)):
  `unexpected-cfgs = ...` warns and will stop working in a future edition. Write
  `unexpected_cfgs`. Threshold keys in `clippy.toml` (e.g.
  `cognitive-complexity-threshold`) are configuration, not lint names, and stay
  hyphenated.

**Rust 1.99 upgrade notes** (things that can newly fail; no configuration needed):

- **Legacy numeric constants are deprecated**
  ([PR #146882](https://github.com/rust-lang/rust/pull/146882)): `std::u32::MAX`,
  `std::i64::MIN`, `std::f64::EPSILON` and friends now raise `deprecated`
  warnings, so a `build.warnings = "deny"` gate fails where they appear. Use the
  associated constants (`u32::MAX`, `f64::EPSILON`); `std::f64::consts::PI` and
  the rest of `consts` are unaffected. Clippy's `legacy_numeric_constants`
  (style, already denied by `clippy::all`) flagged these first.
- **`semicolon_in_expressions_from_non_local_macros`** is a new warn-by-default
  future-incompatibility lint for macros **from dependencies** that expand to
  `expr;` in expression position. Do not allow it crate-wide. Report it upstream;
  if you must silence it meanwhile, scope the exemption to the enclosing item
  with `#[expect(..., reason = "<upstream issue URL>")]`. Library crates that
  export `macro_rules!`: exercise each macro in expression position from
  `tests/` (a separate crate, where this lint now fires).
- **Doctests:** an attribute that applies to nothing at the end of a doc code
  block is now an error, and `#[doc(cfg(...))]` no longer hides doctests from
  running. Run `cargo test --doc` on library crates as part of the upgrade.

### Recommended CI Tools

These tools SHOULD run in CI. Warnings are informational, not blocking.

| Tool | Purpose | Install | Run |
|------|---------|---------|-----|
| `cargo-semver-checks` | Catches accidental breaking changes in library crate public APIs | `cargo install cargo-semver-checks` | `cargo semver-checks check-release` |
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

**Miri caveats - read before pushing back on a reviewer who asks for it:**

- **It only applies to crates that contain `unsafe` at all.** Miri detects
  undefined behaviour, and safe Rust cannot exhibit UB. A crate with
  `unsafe_code = "forbid"` (Section 9) has nothing for Miri to find, and the
  absence of a Miri job in its CI is correct rather than a gap. Check the
  crate-level lint before treating "no Miri" as a finding. Note that any
  `unsafe` reachable through a *dependency* is that dependency's
  responsibility - use `cargo-geiger` to see the transitive picture instead.
- **Slow.** Tokio docs warn of a "dramatic increase" in test time; real-world
  CI reports 35%+ time savings from skipping Miri-incompatible tests
  (alloy-rs/core PR #1072). Use a separate nightly CI job, not the per-PR
  critical path.

FFI-specific Miri limits and `cargo-careful`: `overlays/domains/unsafe-ffi.md`. Bare-metal and
HAL-bound crates: `overlays/domains/embedded-no-std.md`.

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
underlying rule is unchanged and predates 1.98 - `Debug` is a debugging aid,
not a wire format - but 1.98 is when latent violations start failing.

Rust 1.99 changed the escaping again, in the other direction: U+FF9E and U+FF9F
(halfwidth katakana sound marks) are no longer escaped - `{:?}` of
`"\u{FF9E}"` was `"\u{ff9e}"` on 1.98 and is the raw character on 1.99
([PR #158057](https://github.com/rust-lang/rust/pull/158057)). Two consecutive
releases changed `Debug` string output; treat every toolchain bump as a
potential snapshot break.

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
|--- unit/           # No I/O, no network, fast - run always
|--- integration/    # Mocked external services - run in CI
`--- e2e/            # Live services required - run with human setup
```

Document which tier each test belongs to. The AI team must know which
tests they can run autonomously vs which require human-assisted setup.

---

## References

- [Rust 1.99.0 release notes](https://github.com/rust-lang/rust/releases/tag/1.99.0)
  and [announcement](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/) - basis for
  the "(Rust 1.99+)" annotations. **This document tracks stable Rust through 1.99.**
  For 1.99, prefer the GitHub release over doc.rust-lang.org/stable/releases.html.
  The latter is an older revision: it says static PIE was enabled for "gnu and musl"
  targets (the PR covers gnu only), and it omits the union-pattern compatibility note.
  The 1.99 items reflected in this core are:
  - *Security:* handle-based file times and `set_times_nofollow`, lossy UTF-8 kept to
    display paths, value-attached zeroization (Section 10).
  - *New APIs adopted as idioms:* `VecDeque::retain_back` (Section 1);
    `String::from_utf8_lossy_owned` / `FromUtf8Error::into_utf8_lossy` (Section 10);
    `std::fmt::NumBuffer` (Section 4).
  - *Behaviour changes:*
    - `RangeInclusive` post-exhaustion values (Section 3);
    - `Debug` escaping of U+FF9E/U+FF9F (Section 13);
    - `unreachable_cfg_select_predicates` joining `unused` (Section 6);
    - deprecated legacy numeric constants,
      `semicolon_in_expressions_from_non_local_macros`, and doctest changes (Section 12).
  - *Unsafe and FFI* (`overlays/domains/unsafe-ffi.md`):
    - runtime-symbol lints extended to POSIX symbols;
    - the withdrawn tagged-union pattern idiom
      ([reference#2303](https://github.com/rust-lang/reference/pull/2303));
    - `Box::leak` "unleaking" vs `Box::into_non_null` / `Vec::into_parts`;
    - C-variadic definitions;
    - the `Pin::new_unchecked` / `PinSafePointer` contract.
- [Clippy 1.99 changelog](https://github.com/rust-lang/rust-clippy/blob/master/CHANGELOG.md#rust-199) -
  eight new lints, all denied by the profile, plus the `clone_on_copy` UFCS extension and
  the `#[must_use]` algorithm change (Section 9).
- [Cargo 1.99 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html#cargo-199-2026-10-01) -
  the `debug` profile, incremental off under `CI`, the edition-2024 `default-features`
  override, and hyphenated `[lints]` names deprecated (Section 12).
- Lint inventory for the Section 9 profile: `rustc -W help` and
  `rustup run stable clippy-driver -W help` on 1.99.0. The completeness check is in
  Section 9.
- [cargo-deny #611](https://github.com/EmbarkStudios/cargo-deny/pull/611) and cargo-deny
  0.19.6 - the `deny.toml` schema used in Section 10.
- [Rust 1.98.0 release notes](https://doc.rust-lang.org/stable/releases.html#version-1980-2026-08-20)
  and [announcement](https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/) - basis for
  the "(Rust 1.98+)" annotations.
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
- [Clippy 1.98 changelog](https://github.com/rust-lang/rust-clippy/blob/master/CHANGELOG.md#rust-198) -
  seven new lints (five auto-covered by `clippy::all = "deny"`;
  `with_capacity_zero` and `unused_async_trait_impl` are `pedantic` and need an
  explicit decision), the removal of `from_iter_instead_of_collect`, the
  `empty_enums` move to `nursery`, and `result_large_err`/`result_unit_err` now
  firing on `async fn` (Section 9).
- [Cargo 1.98 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html) -
  **no stable `Added` or `Changed` entries.** Everything new is nightly-gated
  (`-Zmin-publish-age`, `-Zhint-msrv`, `-Zcargo-lints`); see Sections 10 and 12.
- [Rust 1.97.0 release notes](https://doc.rust-lang.org/stable/releases.html#version-1970-2026-07-09)
  and [announcement](https://blog.rust-lang.org/2026/07/09/Rust-1.97.0/) - basis for
  the "(Rust 1.97+)" annotations: Cargo `build.warnings`, the `linker_messages` lint,
  `dead_code_pub_in_binary`, v0 symbol mangling by default, the `must_use` uninhabited-`Result`
  refinement, and the `bit_width` / `isolate_highest_one` / `isolate_lowest_one` /
  `highest_one` / `lowest_one` integer methods.
- [Rust Design Patterns](https://rust-unofficial.github.io/patterns/) - idioms, design patterns, and guidelines
- [Rust Anti-Patterns](https://rust-unofficial.github.io/patterns/anti_patterns/) - common solutions that create more problems
- [7 Rust Anti-Patterns Killing Your Performance](https://medium.com/solo-devs/the-7-rust-anti-patterns-that-are-secretly-killing-your-performance-and-how-to-fix-them-in-2025-dcebfdef7b54) - clone epidemic, blocking async, unwrap addiction
- [Patterns for Defensive Programming in Rust](https://corrode.dev/blog/defensive-programming/) - constructors, exhaustive matching, `#[must_use]`, clippy lints
- [Я заставил LLM писать Rust полгода (Habr, 2026)](https://habr.com/ru/articles/1035712/) - LLM-specific Rust failure modes: lifetime laundering, async cancel safety, Drop in async, blanket impl semver hazards, stack-allocated boxes. Source of the cancel-safety and lifetime-laundering rules above.
