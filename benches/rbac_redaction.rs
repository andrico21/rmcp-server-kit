//! Microbenchmark for [`RbacPolicy::redact_arg`].
//!
//! `redact_arg` runs on every per-argument allow-list rejection in the
//! RBAC middleware (see `src/rbac.rs`). It computes an HMAC-SHA256 over
//! the rejected value and returns the first 8 hex characters. The hot
//! path must stay well under 10µs per call so a burst of denials cannot
//! noticeably amplify request latency.
//!
//! The CI gate `bench-thresholds` runs this bench and asserts
//! `mean < 10_000 ns` via `scripts/check-bench-threshold.{sh,ps1}`.
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::modulo_arithmetic,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::integer_division_remainder_used,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::arithmetic_side_effects,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::min_ident_chars,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::default_numeric_fallback,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::missing_docs_in_private_items,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::std_instead_of_core,
        reason = "lint-migration: benches/rbac_redaction.rs"
    )
)]
#![expect(unused_results, reason = "lint-migration: benches/rbac_redaction.rs")]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rmcp_server_kit::rbac::{RbacConfig, RbacPolicy};

fn bench_redact_arg(c: &mut Criterion) {
    let policy = RbacPolicy::new(&RbacConfig::default());
    // 256-byte representative argument value (matches plan H-S3 spec).
    let value: String = (0..256)
        .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap_or(0)))
        .collect();

    c.bench_function("bench_redact_arg", |b| {
        b.iter(|| {
            let out = policy.redact_arg(black_box(&value));
            black_box(out);
        });
    });
}

criterion_group!(benches, bench_redact_arg);
criterion_main!(benches);
