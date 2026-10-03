#!/usr/bin/env python3
"""The count gate (D-6''): compare a measurement with per-file baselines.

Baselines live at ``scripts/lint-ratchet/baseline/<source path>.json`` - one
file per source file, so parallel lanes never conflict.  A key or a baseline
file that is absent counts as 0, so a new ``(file, scope, lint, row)`` key
fails the gate.  ``--init`` writes baselines; ``--update`` only lowers them;
``--rebaseline --toolchain X`` is reserved for the D-14(iv) rust-version bump.

Runnable: ``python3 count_gate.py --self-test``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = Path(__file__).resolve().parent / "baseline"
DEFAULT_MEASUREMENT = "measurement.json"


def key_string(file: str, scope: str, lint: str, row: str) -> str:
    return f"{file}|{scope}|{lint}|{row}"


def split_key(key: str):
    file, scope, lint, row = key.split("|", 3)
    return file, scope, lint, row


def load_measurement(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_path(baseline_dir: Path, file: str) -> Path:
    return baseline_dir / f"{file}.json"


def load_baseline(baseline_dir: Path, file: str) -> dict:
    path = baseline_path(baseline_dir, file)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("keys", {})


def _by_file(measurement: dict) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for key, count in measurement.get("keys", {}).items():
        file, scope, lint, row = split_key(key)
        short = f"{scope}|{lint}|{row}"
        out.setdefault(file, {})[short] = count
    return out


def compare(measurement: dict, baseline_dir: Path):
    """Return ``(violations, per_file_totals)``."""
    violations = []
    totals = {}
    for file, keys in sorted(_by_file(measurement).items()):
        baseline = load_baseline(baseline_dir, file)
        totals[file] = sum(keys.values())
        for short, count in sorted(keys.items()):
            allowed = baseline.get(short, 0)
            if count > allowed:
                scope, lint, row = short.split("|", 2)
                violations.append((file, scope, lint, row, count, allowed))
    return violations, totals


def write_baselines(measurement: dict, baseline_dir: Path, files=None, lower_only=False, toolchain=None) -> int:
    written = 0
    for file, keys in sorted(_by_file(measurement).items()):
        if files and file not in files:
            continue
        path = baseline_path(baseline_dir, file)
        current = load_baseline(baseline_dir, file)
        if lower_only:
            merged = {k: min(v, current.get(k, v)) for k, v in keys.items()}
        else:
            merged = dict(keys)
        payload = {"file": file, "toolchain": toolchain or measurement.get("toolchain", "unknown"), "keys": merged}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written += 1
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--measurement", default=os.environ.get("RGM_MEASUREMENT", DEFAULT_MEASUREMENT))
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--rebaseline", action="store_true")
    ap.add_argument("--toolchain")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    measurement_path = Path(args.measurement)
    if not measurement_path.exists():
        print(f"count_gate: measurement not found: {measurement_path}", file=sys.stderr)
        return 2
    measurement = load_measurement(measurement_path)
    baseline_dir = Path(args.baseline)

    if args.rebaseline and not args.toolchain:
        print("count_gate: --rebaseline requires --toolchain (D-14 iv)", file=sys.stderr)
        return 2

    if args.init or args.rebaseline:
        n = write_baselines(measurement, baseline_dir, files=args.files,
                            toolchain=args.toolchain)
        print(f"count_gate: wrote {n} baseline file(s)")
        return 0
    if args.update:
        n = write_baselines(measurement, baseline_dir, files=args.files, lower_only=True)
        print(f"count_gate: lowered {n} baseline file(s)")
        return 0

    violations, totals = compare(measurement, baseline_dir)
    if args.report:
        for file, total in sorted(totals.items()):
            print(f"{file}: {total}")
    for file, scope, lint, row, count, allowed in violations:
        print(f"{file} [{scope}] {lint} row={row!r}: {count} > baseline {allowed}", file=sys.stderr)
    if violations:
        print(f"count_gate: FAILED ({len(violations)} key(s) above baseline)", file=sys.stderr)
        return 1
    print(f"count_gate: ok ({len(measurement.get('keys', {}))} key(s) within baseline)")
    return 0


def _self_test() -> int:
    import tempfile

    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    def write_measurement(path: Path, keys):
        path.write_text(json.dumps({"toolchain": "1.99.0", "keys": keys}), encoding="utf-8")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        base = td / "baseline"
        m = td / "measurement.json"
        write_measurement(m, {
            "src/a.rs|prod|clippy::unwrap_used|--all-features": 3,
            "src/a.rs|test|clippy::panic|--all-features": 2,
        })
        n = write_baselines(load_measurement(m), base)
        check("init writes one file per source file", n == 1)
        check("per-file baseline path", (base / "src/a.rs.json").exists())
        v, totals = compare(load_measurement(m), base)
        check("equal passes", not v)
        check("report totals", totals["src/a.rs"] == 5)

        write_measurement(m, {
            "src/a.rs|prod|clippy::unwrap_used|--all-features": 4,
            "src/a.rs|test|clippy::panic|--all-features": 2,
        })
        v, _ = compare(load_measurement(m), base)
        check("raise fails", len(v) == 1 and v[0][2] == "clippy::unwrap_used")

        write_measurement(m, {
            "src/a.rs|prod|clippy::unwrap_used|--all-features": 3,
            "src/a.rs|prod|clippy::expect_used|--all-features": 1,
        })
        v, _ = compare(load_measurement(m), base)
        check("new key fails", any(x[2] == "clippy::expect_used" for x in v))

        # --update only lowers
        write_measurement(m, {
            "src/a.rs|prod|clippy::unwrap_used|--all-features": 1,
            "src/a.rs|test|clippy::panic|--all-features": 9,
        })
        write_baselines(load_measurement(m), base, lower_only=True)
        bl = load_baseline(base, "src/a.rs")
        check("update lowers", bl["prod|clippy::unwrap_used|--all-features"] == 1)
        check("update never raises", bl["test|clippy::panic|--all-features"] == 2)

        # absent baseline file counts as 0
        write_measurement(m, {"src/new.rs|prod|clippy::todo|": 1})
        v, _ = compare(load_measurement(m), base)
        check("absent baseline file fails", len(v) == 1)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"count_gate self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("count_gate self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
