#!/usr/bin/env python3
"""Semantic equality: the vendored core Section 9 profile vs Cargo.toml (D-13).

The core profile is located by content markers (not line numbers) inside the
TOML fence of ``docs/rust-guidelines/RUST_GUIDELINES.md``.  It is compared, as
parsed TOML, against ``Cargo.toml``'s ``[lints]`` tables, modulo the recorded
toolchain deltas in ``scripts/lint-ratchet/profile-deltas.toml`` (D-14 iii).

``--clippy-toml`` additionally compares ``clippy.toml`` with the core sample;
the only keys allowed to differ are ``doc-valid-idents`` and
``allowed-duplicate-crates`` (both append-only over the sample).

Exits 1 on mismatch.  Runnable: ``python3 profile_eq.py --self-test``.
"""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CORE_REL = Path("docs/rust-guidelines/RUST_GUIDELINES.md")
CLIPPY_EXTRA_KEYS = {"doc-valid-idents", "allowed-duplicate-crates"}


def find_fence(text: str, marker: str) -> str | None:
    """Return the body of the first fenced block containing *marker*."""
    lines = text.splitlines()
    body: list[str] = []
    inside = False
    for line in lines:
        if not inside and line.lstrip().startswith("```"):
            inside = True
            body = []
            continue
        if inside and line.lstrip().startswith("```"):
            if marker in "\n".join(body):
                return "\n".join(body)
            inside = False
            continue
        if inside:
            body.append(line)
    return None


def normalise_profile(profile: dict) -> dict:
    """``{table: {lint: {level, priority?}}}`` with scalar levels expanded."""
    out: dict[str, dict[str, dict]] = {}
    for table, entries in profile.items():
        norm: dict[str, dict] = {}
        for lint, value in entries.items():
            if isinstance(value, str):
                norm[lint] = {"level": value}
            elif isinstance(value, dict):
                norm[lint] = dict(value)
            else:
                norm[lint] = {"level": value}
        out[table] = norm
    return out


def apply_deltas(expected: dict, deltas: dict) -> dict:
    for entry in deltas.get("rename", []):
        _move_lint(expected, entry["from"], entry["to"])
    for entry in deltas.get("removed", []):
        _drop_lint(expected, entry["lint"])
    for entry in deltas.get("level", []):
        table, lint = _find_lint(expected, entry["lint"])
        if table is not None:
            expected[table][lint]["level"] = entry["level"]
    return expected


def _find_lint(profile: dict, lint: str):
    candidates = [lint]
    if "::" in lint:
        candidates.append(lint.split("::", 1)[1])
    candidates.append(lint.rsplit("::", 1)[-1])
    for cand in candidates:
        for table, entries in profile.items():
            if cand in entries:
                return table, cand
    return None, None


def _drop_lint(profile: dict, lint: str) -> None:
    table, key = _find_lint(profile, lint)
    if table is not None:
        del profile[table][key]


def _move_lint(profile: dict, old: str, new: str) -> None:
    table, key = _find_lint(profile, old)
    if table is not None:
        bare = new.split("::", 1)[1] if "::" in new else new
        profile[table][bare] = profile[table].pop(key)


def diff_profiles(core: dict, cargo: dict) -> list[str]:
    diffs: list[str] = []
    for table in sorted(set(core) | set(cargo)):
        c = core.get(table, {})
        g = cargo.get(table, {})
        for lint in sorted(set(c) | set(g)):
            if lint not in g:
                diffs.append(f"{table}.{lint}: missing in Cargo.toml (core: {c[lint]})")
            elif lint not in c:
                diffs.append(f"{table}.{lint}: extra in Cargo.toml (cargo: {g[lint]})")
            elif c[lint] != g[lint]:
                diffs.append(f"{table}.{lint}: core={c[lint]} cargo={g[lint]}")
    return diffs


def diff_clippy(sample: dict, actual: dict) -> list[str]:
    diffs: list[str] = []
    for key, value in sample.items():
        if key not in actual:
            diffs.append(f"{key}: missing in clippy.toml")
            continue
        got = actual[key]
        if key in CLIPPY_EXTRA_KEYS:
            if isinstance(value, list) and isinstance(got, list):
                missing = [v for v in value if v not in got]
                if missing:
                    diffs.append(f"{key}: clippy.toml drops sample entries {missing}")
            elif got != value:
                diffs.append(f"{key}: core={value} clippy={got}")
        elif got != value:
            diffs.append(f"{key}: core={value} clippy={got}")
    for key in actual:
        if key not in sample and key not in CLIPPY_EXTRA_KEYS:
            diffs.append(f"{key}: extra key not allowed in clippy.toml")
    return diffs


def check(root: Path, clippy_toml: bool = False):
    core_path = root / CORE_REL
    core_text = core_path.read_text(encoding="utf-8")
    profile_fence = find_fence(core_text, "[workspace.lints.rust]")
    if profile_fence is None:
        return False, ["could not locate the core profile fence"]
    profile_fence = profile_fence.replace("[workspace.lints.", "[lints.")
    core_profile = normalise_profile(tomllib.loads(profile_fence).get("lints", {}))

    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    cargo_profile = normalise_profile(cargo.get("lints", {}))

    deltas_path = root / "scripts/lint-ratchet/profile-deltas.toml"
    deltas = tomllib.loads(deltas_path.read_text(encoding="utf-8")) if deltas_path.exists() else {}
    apply_deltas(core_profile, deltas)

    diffs = diff_profiles(core_profile, cargo_profile)

    if clippy_toml:
        sample_fence = find_fence(core_text, "avoid-breaking-exported-api")
        if sample_fence is None:
            diffs.append("could not locate the core clippy.toml fence")
        else:
            sample = tomllib.loads(sample_fence)
            actual = tomllib.loads((root / "clippy.toml").read_text(encoding="utf-8"))
            diffs.extend(diff_clippy(sample, actual))

    return (not diffs), diffs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clippy-toml", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    ok, diffs = check(Path(args.root), args.clippy_toml)
    if ok:
        print("profile_eq: core profile matches Cargo.toml" +
              (" and clippy.toml" if args.clippy_toml else ""))
        return 0
    print(f"profile_eq: {len(diffs)} mismatch(es) against the vendored core profile:")
    for d in diffs:
        print(f"  {d}")
    return 1


def _self_test() -> int:
    import tempfile

    failures = []

    def check_cond(label, cond):
        if not cond:
            failures.append(label)

    profile = (
        "[workspace.lints.rust]\n"
        "future_incompatible = { level = \"deny\", priority = -1 }\n"
        "unsafe_code = \"forbid\"\n"
        "missing_docs = \"deny\"\n"
        "\n"
        "[workspace.lints.rustdoc]\n"
        "all = { level = \"deny\", priority = -1 }\n"
        "\n"
        "[workspace.lints.clippy]\n"
        "all = { level = \"deny\", priority = -1 }\n"
        "unwrap_used = \"deny\"\n"
    )
    sample = (
        "# clippy.toml\n"
        "avoid-breaking-exported-api = false\n"
        "cognitive-complexity-threshold = 25\n"
        "allowed-duplicate-crates = []\n"
        "doc-valid-idents = [\"..\"]\n"
    )
    md = (
        "# core\n\n```toml\n" + profile.replace("\n", "\n") + "```\n\n"
        "```toml\n" + sample + "```\n"
    )
    cargo_ok = (
        "[package]\nname = \"x\"\n\n"
        "[lints.rust]\n"
        "future_incompatible = { level = \"deny\", priority = -1 }\n"
        "unsafe_code = \"forbid\"\n"
        "missing_docs = \"deny\"\n\n"
        "[lints.rustdoc]\n"
        "all = { level = \"deny\", priority = -1 }\n\n"
        "[lints.clippy]\n"
        "all = { level = \"deny\", priority = -1 }\n"
        "unwrap_used = \"deny\"\n"
    )
    clippy_ok = (
        "avoid-breaking-exported-api = false\n"
        "cognitive-complexity-threshold = 25\n"
        "allowed-duplicate-crates = [\"sha2@0.10\"]\n"
        "doc-valid-idents = [\"..\", \"McpServer\"]\n"
    )

    def build(td, cargo_text, clippy_text, deltas_text):
        (Path(td) / "docs/rust-guidelines").mkdir(parents=True)
        (Path(td) / CORE_REL).write_bytes(md.encode("utf-8"))
        (Path(td) / "Cargo.toml").write_bytes(cargo_text.encode("utf-8"))
        (Path(td) / "clippy.toml").write_bytes(clippy_text.encode("utf-8"))
        (Path(td) / "scripts/lint-ratchet").mkdir(parents=True)
        (Path(td) / "scripts/lint-ratchet/profile-deltas.toml").write_bytes(deltas_text.encode("utf-8"))

    with tempfile.TemporaryDirectory() as td:
        build(td, cargo_ok, clippy_ok, "# empty\n")
        ok, diffs = check(Path(td), clippy_toml=True)
        check_cond("exact match exits 0", ok and not diffs)

    with tempfile.TemporaryDirectory() as td:
        build(td, cargo_ok.replace("unwrap_used = \"deny\"", "unwrap_used = \"warn\""), clippy_ok, "# empty\n")
        ok, diffs = check(Path(td))
        check_cond("level mismatch exits 1", not ok)
        check_cond("level mismatch names lint", any("unwrap_used" in d for d in diffs))

    with tempfile.TemporaryDirectory() as td:
        renamed = cargo_ok.replace("unwrap_used = \"deny\"", "unwrap_used_v2 = \"deny\"")
        build(td, renamed, clippy_ok, "[[rename]]\nfrom = \"clippy::unwrap_used\"\nto = \"clippy::unwrap_used_v2\"\ntoolchain = \"1.100\"\n")
        ok, diffs = check(Path(td))
        check_cond("rename delta applied", ok and not diffs)

    with tempfile.TemporaryDirectory() as td:
        bad = clippy_ok + "msrv = \"1.99\"\n"
        build(td, cargo_ok, bad, "# empty\n")
        ok, diffs = check(Path(td), clippy_toml=True)
        check_cond("extra clippy key rejected", not ok and any("msrv" in d for d in diffs))

    with tempfile.TemporaryDirectory() as td:
        build(td, cargo_ok, clippy_ok.replace('["..", "McpServer"]', '["McpServer"]'), "# empty\n")
        ok, diffs = check(Path(td), clippy_toml=True)
        check_cond("doc-valid-idents must keep defaults", not ok)

    # CRLF bytes in the fence and Cargo.toml must parse (tomllib accepts CRLF).
    with tempfile.TemporaryDirectory() as td:
        build(td, cargo_ok.replace("\n", "\r\n"), clippy_ok.replace("\n", "\r\n"), "# empty\r\n")
        (Path(td) / CORE_REL).write_bytes(md.replace("\n", "\r\n").encode("utf-8"))
        ok, diffs = check(Path(td))
        check_cond("crlf fence parses", ok and not diffs)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"profile_eq self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("profile_eq self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
