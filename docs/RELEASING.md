# Releasing `rmcp-server-kit`

## Cadence

`rmcp-server-kit` follows strict [SemVer 2.0.0](https://semver.org/) from `1.0.0`
onward.

- **Patch** (`1.x.y`): bug fixes, docs, non-breaking dependency updates.
  Ship whenever backlog justifies it.
- **Minor** (`1.x.0`): backward-compatible new features and additive
  public API. New methods on `#[non_exhaustive]` types and new variants
  on `#[non_exhaustive]` enums are minor-bumped, not major.
- **Major** (`x.0.0`): reserved for breaking changes. Avoid until
  unavoidable; bundle related breaks together and provide a migration
  guide in [`docs/MIGRATION.md`](MIGRATION.md).

## Pre-flight checklist

1. All CI jobs green on `main`.
2. `cargo +nightly fmt --all -- --check` clean.
3. `cargo clippy --all-targets --all-features -- -D warnings` clean.
4. `cargo test --all-features` passes on Linux / macOS / Windows.
5. `cargo deny check` and `cargo audit` clean.
6. `cargo doc --no-deps --all-features` — no broken intra-doc links.
7. `cargo publish --dry-run --all-features` succeeds.

## Step-by-step

```bash
# 1. Pick the version
export NEW_VERSION=1.0.1

# 2. Update CHANGELOG.md
#    - Move "Unreleased" items under "## [$NEW_VERSION] - YYYY-MM-DD"
#    - Add a fresh empty "## [Unreleased]" header at the top

# 3. Bump version in Cargo.toml
sed -i 's/^version = ".*"$/version = "'$NEW_VERSION'"/' Cargo.toml

# 4. Commit and push
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release $NEW_VERSION"
git push origin main

# 5. Tag
git tag -a "$NEW_VERSION" -m "rmcp-server-kit $NEW_VERSION"
git push origin "$NEW_VERSION"
```

> **Tag the canonical remote only.** `.gitlab-ci.yml` fires its own
> `cargo publish` on any `MAJOR.MINOR.PATCH` tag, so pushing the tag to the
> GitLab mirror as well would attempt a duplicate upload.

### A note on `cargo vet` and the version bump

Releases used to require an extra step here: run `cargo vet` so
`supply-chain/imports.lock` recorded the new version as
`audited_as` the previous one. That existed because
`supply-chain/config.toml` set `audit-as-crates-io = true` for this crate,
which asked cargo-vet to audit **our own package** as though it were a
third-party crates.io dependency. The requirement was then satisfied with a
self-exemption — an explicit trust-without-audit marker — so it asserted no
security property at all.

Worse, exemptions pin an exact version, so every release orphaned it and the
`cargo vet` CI job went red until somebody regenerated the entry. Because the
job was `continue-on-error: true`, that failure was invisible; it stayed red
from the 3.2.0 release until it was noticed during the 3.3.0 cycle.

The policy is now `audit-as-crates-io = false`, which is the correct setting
for a first-party crate you author and publish — the `true` variant exists for
a local path/git crate that shadows a crates.io crate of the same name and
should inherit its audit requirements. The self-exemption and the
`unpublished` marker are gone, the per-release chore is gone, and the CI job
is blocking rather than advisory.

`supply-chain/config.toml` is rewritten by cargo-vet and does not preserve
comments, which is why this rationale lives here. Do not set the policy back
to `true` without reading this section.


The `release.yml` workflow then:

1. Verifies the tag matches the crate version.
2. Runs `cargo publish --dry-run`.
3. Runs `cargo publish` (requires `CARGO_REGISTRY_TOKEN` secret).
4. Creates a GitHub release with auto-generated notes.

## Yanking

If a release needs to be withdrawn:

```bash
cargo yank --version $VERSION rmcp-server-kit
```

Then cut a follow-up patch release that fixes the issue and document both
in CHANGELOG.md under a `### Security` or `### Fixed` subsection.

## Downstream coordination

When publishing a release that affects downstream crates (e.g.
`atlassian-mcp`):

1. Update the downstream `Cargo.toml` to the new version.
2. Run the downstream test suite against the new `rmcp-server-kit`.
3. Open a PR on the downstream repo; link back to the `rmcp-server-kit` release
   notes.
