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

1. **All CI jobs green on `main` - verify this before tagging, not after.**
   `release.yml` is gated on `CI` via `workflow_run`, so a red CI silently
   *skips* the publish job. The 3.4.0 and 3.5.0 tags were both pushed onto red
   CI and neither ever reached crates.io; the tags exist but the versions do
   not. Check with `gh run list --limit 5` and confirm the run for your commit
   concluded `success`.
2. `cargo +nightly fmt --all -- --check` clean.
3. Clippy clean on **every feature combination CI lints**, not just
   `--all-features`. `--all-features` cannot see code inside
   `#[cfg(not(feature = "..."))]`, which is exactly where the 3.5.0 breakage
   hid:

   ```bash
   for f in "--no-default-features" "" "--features metrics" "--features oauth" "--all-features"; do
     cargo clippy --all-targets $f -- -D warnings || echo "FAILED: ${f:-default}"
   done
   ```
4. `cargo test --all-features` **and** `cargo test --no-default-features` pass.
   CI runs the suite on Linux / macOS / Windows; tests that parse
   `include_str!` content must be line-ending agnostic or they pass locally and
   fail on `windows-latest` (`core.autocrlf` gives CI a CRLF checkout).
5. `cargo deny check` and `cargo audit` clean.
6. `cargo vet --locked` clean. `Cargo.lock` **is committed** (see `.gitignore`
   for why), so this is deterministic and no longer depends on what upstream
   published today. When you bump dependencies, run `cargo update` and
   `cargo vet regenerate exemptions` together in the same reviewed commit.
7. `cargo doc --no-deps --all-features` - no broken intra-doc links.
8. `cargo publish --dry-run --all-features` succeeds.

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

# 5. WAIT for CI to go green on the pushed commit BEFORE tagging.
#    release.yml runs on `workflow_run` of CI; if CI fails, the publish job is
#    skipped and the tag becomes an orphan pointing at an unpublished version.
gh run watch "$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"

# 6. Tag only once CI is green
git tag -a "$NEW_VERSION" -m "rmcp-server-kit $NEW_VERSION"
git push origin "$NEW_VERSION"

# 7. Confirm the release actually published. Do not assume.
gh run list --limit 5
curl -s "https://crates.io/api/v1/crates/rmcp-server-kit" | jq -r '.crate.max_version'
```

> **A pushed tag is not a release.** Verify `max_version` on crates.io matches
> the tag before considering the release done.

> **The GitLab mirror does not publish releases.** Tags pushed there are inert;
> crates.io publication is handled only by the canonical GitHub release path.

### A note on `cargo vet` and the version bump

Releases used to require an extra step here: run `cargo vet` so
`supply-chain/imports.lock` recorded the new version as
`audited_as` the previous one. That existed because
`supply-chain/config.toml` set `audit-as-crates-io = true` for this crate,
which asked cargo-vet to audit **our own package** as though it were a
third-party crates.io dependency. The requirement was then satisfied with a
self-exemption - an explicit trust-without-audit marker - so it asserted no
security property at all.

Worse, exemptions pin an exact version, so every release orphaned it and the
`cargo vet` CI job went red until somebody regenerated the entry. Because the
job was `continue-on-error: true`, that failure was invisible; it stayed red
from the 3.2.0 release until it was noticed during the 3.3.0 cycle.

The policy is now `audit-as-crates-io = false`, which is the correct setting
for a first-party crate you author and publish - the `true` variant exists for
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
4. Creates a GitHub release with auto-generated notes -- but only when this
   run actually performed the `cargo publish` upload. If the version was
   already on crates.io before this run (the publish step reports
   `published=false`), this step is skipped, because the run that truly
   uploaded the bytes already created that release.

### Recovering a missing GitHub release

Because "Create GitHub release" is now gated on `steps.publish.outputs.published
== 'true'`, only the run that actually uploaded the crate creates the release.
That closes a recovery path the pipeline used to have for free: previously, if
run A published successfully but its release-creation step failed transiently, a
later run B -- which sees the version already on crates.io -- would create the
release instead. Now run B reports `published=false` and skips the step, so
**no** run will auto-create that release. You must create it by hand, and only
after proving the published bytes are the ones this tag describes.

```bash
# 1. Confirm a CI run actually published this version, and which SHA it used.
gh run list --workflow=Release --limit 10          # find the run; note its head_sha
git rev-parse "<tag>^{commit}"                      # must equal that head_sha

# 2. Reconstruct the package from the tag and compare against the registry.
git checkout "<tag>"
cargo package --all-features                        # produces target/package/<crate>-<tag>.crate
sha256sum "target/package/rmcp-server-kit-<tag>.crate"
# Retrieve the published checksum from the crates.io sparse index and compare.
# (Index path is derived from the crate name; rmcp-server-kit -> rm/cp/.)
curl -sS https://index.crates.io/rm/cp/rmcp-server-kit \
  | jq -r 'select(.vers=="<tag>") | .cksum'
# The two hex digests must match.

# 3. ONLY if step 2 matches:
gh release create "<tag>" --notes-file <path-to-extracted-CHANGELOG-section>
```

If the two checksums do **not** match, **stop**. That is exactly the
out-of-band-publish case this gating exists to surface: creating a release then
would certify bytes the pipeline never uploaded. Note also that `cargo package`
output is **not** guaranteed byte-reproducible across toolchain versions, so a
difference is not automatically proof of tampering; if the hashes differ, re-run
step 2 with the exact toolchain from the publishing run's log before concluding
the mismatch is real.

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
