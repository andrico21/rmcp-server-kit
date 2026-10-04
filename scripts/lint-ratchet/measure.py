#!/usr/bin/env python3
"""The count-gate measurement (D-6'').

Measures the *committed* HEAD: ``git archive HEAD`` is extracted into
``~/.cache/rgm-scratch/measure-<pid>``.  The profile levels are set to ``warn``,
only ``lint-migration:`` expects are rewritten to ``warn(`` (balanced-paren
parsing, so ``cfg_attr`` forms work), and each of the 5 feature rows runs
``CARGO_BUILD_WARNINGS=warn cargo +1.99.0 clippy --all-targets <row>
--message-format=json`` against a persistent ``CARGO_TARGET_DIR``
(``$RGM_MEASURE_TARGET``, default ``target/rgm-measure``).

Diagnostics are deduplicated by ``(lint, file, line, column)`` within a row,
then keyed by ``(file, scope, lint, row)``; ``scope`` is ``test`` inside a
``#[cfg(test)]`` item or for files under ``tests/``/``benches/``/``examples/``.
``unfulfilled_lint_expectations``, ``unknown_lints`` and lints recorded as
renamed-from/removed in ``profile-deltas.toml`` are dropped.

The result is written to ``measurement.json`` (``--out``; ``$RGM_MEASUREMENT``)
for ``count_gate.py``.  Runnable: ``python3 measure.py --self-test``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
ROWS = ["", "--no-default-features", "--features oauth", "--features metrics", "--all-features"]
TOOLCHAIN = "1.99.0"
SKIP_CODES = {"unfulfilled_lint_expectations", "unknown_lints"}


def set_profile_warn(cargo_text: str) -> str:
    lines = cargo_text.split("\n")
    out = []
    in_lints = False
    for line in lines:
        if re.match(r"^\[", line):
            in_lints = bool(re.match(r"^\[lints(\.|\])", line))
            out.append(line)
            continue
        if in_lints:
            line = re.sub(r'(\blevel\s*=\s*)"[A-Za-z]+"', r'\1"warn"', line)
            line = re.sub(r'^(\s*[A-Za-z_][A-Za-z0-9_-]*\s*=\s*)"(?:deny|warn|allow|forbid)"',
                          r'\1"warn"', line)
        out.append(line)
    return "\n".join(out)


def rewrite_migration_expects(src: str):
    stripped = common.strip_comments_and_strings(src)
    edits = []
    for call in common.attribute_calls(src, stripped):
        if call["form"] == "expect" and (call["reason"] or "").startswith("lint-migration:"):
            edits.append((call["kw_start"], call["kw_end"]))
    out = src
    for a, b in sorted(edits, reverse=True):
        out = out[:a] + "warn" + out[b:]
    return out, len(edits)


def load_renamed_removed(root: Path) -> set:
    import tomllib
    names: set = set()
    path = root / "scripts/lint-ratchet/profile-deltas.toml"
    if path.exists():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for entry in data.get("rename", []):
            names.add(entry["from"].split("::", 1)[-1])
        for entry in data.get("removed", []):
            names.add(entry["lint"].split("::", 1)[-1])
    return names


def scope_of(file: str, line: int, ranges_cache: dict) -> str:
    if file.startswith(("tests/", "benches/", "examples/")):
        return "test"
    if file.startswith("src/"):
        if file not in ranges_cache:
            p = Path(ranges_cache["_root"]) / file
            if p.exists():
                _, stripped = common.read_source(p)
                ranges_cache[file] = common.cfg_test_line_ranges(stripped)
            else:
                ranges_cache[file] = []
        if common.in_ranges(line, ranges_cache[file]):
            return "test"
    return "prod"


def aggregate(rows_records, root: Path, renamed_removed):
    """``rows_records``: list of ``(row, [json record])`` -> measurement keys."""
    ranges_cache = {"_root": str(root)}
    keys: dict = {}
    for row, records in rows_records:
        seen = set()
        for rec in records:
            if rec.get("reason") != "compiler-message":
                continue
            msg = rec.get("message") or {}
            if msg.get("level") not in ("warning", "error"):
                continue
            code = (msg.get("code") or {}).get("code")
            if not code or code in SKIP_CODES or code.split("::", 1)[-1] in renamed_removed:
                continue
            span = next((s for s in msg.get("spans", []) if s.get("is_primary")), None)
            if not span:
                continue
            file = span.get("file_name")
            # Only in-repo source files are keyed. Dependency and external
            # macro spans (e.g. proptest's `tests_outside_test_module`) carry a
            # machine-specific absolute registry path and cannot be part of a
            # portable per-file baseline.
            if not isinstance(file, str) or not file.startswith(
                    ("src/", "tests/", "benches/", "examples/")):
                continue
            line = span.get("line_start")
            col = span.get("column_start")
            key = (code, file, line, col)
            if key in seen:
                continue
            seen.add(key)
            scope = scope_of(file, line, ranges_cache)
            k = f"{file}|{scope}|{code}|{row}"
            keys[k] = keys.get(k, 0) + 1
    return keys


def run_cargo(scratch: Path, row: str, target_dir: Path):
    cmd = ["cargo", f"+{TOOLCHAIN}", "clippy", "--all-targets"]
    if row:
        cmd += row.split()
    cmd += ["--message-format=json"]
    env = dict(os.environ, CARGO_BUILD_WARNINGS="warn", CARGO_TARGET_DIR=str(target_dir))
    proc = subprocess.run(cmd, cwd=scratch, env=env, capture_output=True, text=True)
    records = []
    for line in proc.stdout.splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records, proc


def measure(root: Path, out_path: Path, rows=ROWS) -> int:
    scratch = Path.home() / ".cache" / "rgm-scratch" / f"measure-{os.getpid()}"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    try:
        archive = subprocess.run(["git", "-C", str(root), "archive", "HEAD"],
                                 capture_output=True, check=True)
        subprocess.run(["tar", "-x", "-C", str(scratch)], input=archive.stdout, check=True)
        cargo_path = scratch / "Cargo.toml"
        cargo_path.write_text(set_profile_warn(cargo_path.read_text(encoding="utf-8")), encoding="utf-8")
        if (scratch / "rust-toolchain.toml").exists():
            (scratch / "rust-toolchain.toml").unlink()
        for path in common.iter_rust_files(scratch):
            raw = path.read_bytes().decode("utf-8")
            new, n = rewrite_migration_expects(raw)
            if n:
                path.write_bytes(new.encode("utf-8"))
        target_dir = Path(os.environ.get("RGM_MEASURE_TARGET", str(root / "target" / "rgm-measure")))
        rows_records = []
        for row in rows:
            records, proc = run_cargo(scratch, row, target_dir)
            if proc.returncode != 0:
                print(f"measure: clippy failed for row {row!r} (exit {proc.returncode})", file=sys.stderr)
                print(proc.stderr[-4000:], file=sys.stderr)
                return 2
            rows_records.append((row, records))
        renamed_removed = load_renamed_removed(root)
        keys = aggregate(rows_records, scratch, renamed_removed)
        payload = {"toolchain": TOOLCHAIN, "rows": rows, "keys": keys}
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        total = sum(keys.values())
        print(f"measure: wrote {out_path} ({len(keys)} key(s), {total} diagnostic(s))")
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--out", default=os.environ.get("RGM_MEASUREMENT", "measurement.json"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    return measure(Path(args.root), Path(args.out))


def _self_test() -> int:
    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    cargo = (
        "[package]\nname = \"x\"\n\n"
        "[lints.rust]\nunsafe_code = \"forbid\"\nmissing_docs = \"deny\"\n"
        "future_incompatible = { level = \"deny\", priority = -1 }\n\n"
        "[lints.clippy]\nunwrap_used = \"deny\"\nall = { level = \"deny\", priority = -1 }\n\n"
        "[profile.release]\nopt-level = 3\n"
    )
    out = set_profile_warn(cargo)
    check("rust level to warn", 'unsafe_code = "warn"' in out and 'missing_docs = "warn"' in out)
    check("clippy level to warn", 'unwrap_used = "warn"' in out)
    check("level = key to warn", 'level = "warn"' in out)
    check("priority untouched", 'priority = -1' in out)
    check("other tables untouched", 'opt-level = 3' in out)

    src = (
        "#[expect(clippy::a, reason = \"lint-migration: src/a.rs\")]\n"
        "#[expect(clippy::b, reason = \"permanent reason\")]\n"
        "#[cfg_attr(test, expect(clippy::c, reason = \"lint-migration: src/a.rs\"))]\n"
        "// #[expect(clippy::d, reason = \"lint-migration: comment\")]\n"
        "fn f() {}\n"
    )
    new, n = rewrite_migration_expects(src)
    check("two expects rewritten", n == 2)
    check("migration becomes warn", "#[warn(clippy::a," in new)
    check("cfg_attr migration becomes warn", "cfg_attr(test, warn(clippy::c," in new)
    check("permanent untouched", "#[expect(clippy::b" in new)
    check("comment untouched", "// #[expect(clippy::d" in new)

    crlf = "#[expect(clippy::a, reason = \"lint-migration: x\")]\r\nfn f() {}\r\n"
    new2, n2 = rewrite_migration_expects(crlf)
    check("crlf rewritten", n2 == 1 and "#[warn(clippy::a," in new2 and new2.count("\r\n") == 2)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "src").mkdir()
        (td / "src/a.rs").write_text(
            "pub fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n", encoding="utf-8")

        def msg(code, file, line, col):
            return {"reason": "compiler-message", "message": {
                "level": "warning", "code": {"code": code},
                "spans": [{"file_name": file, "line_start": line, "column_start": col, "is_primary": True}]}}

        records = [
            msg("clippy::unwrap_used", "src/a.rs", 1, 1),
            msg("clippy::unwrap_used", "src/a.rs", 1, 1),           # dup
            msg("clippy::unwrap_used", "src/a.rs", 5, 5),           # test scope
            msg("clippy::nonexistent", "src/a.rs", 2, 1),           # renamed/removed
            msg("unknown_lints", "src/a.rs", 2, 1),                 # skipped
            msg("clippy::indexing_slicing", "tests/e2e.rs", 4, 1),  # tests/ -> test
        ]
        keys = aggregate([("--all-features", records)], td, {"nonexistent"})
        check("dedup", keys.get("src/a.rs|prod|clippy::unwrap_used|--all-features") == 1)
        check("scope test", keys.get("src/a.rs|test|clippy::unwrap_used|--all-features") == 1)
        check("renamed/removed dropped", not any("nonexistent" in k for k in keys))
        check("unknown_lints dropped", not any("unknown_lints" in k for k in keys))
        check("tests dir is test scope", keys.get("tests/e2e.rs|test|clippy::indexing_slicing|--all-features") == 1)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"measure self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("measure self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
