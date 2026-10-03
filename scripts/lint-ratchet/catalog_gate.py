#!/usr/bin/env python3
"""Catalog gate (D-6''): every permanent ``expect`` reason is catalogued.

Every ``expect`` reason outside the generated ``lint-migration:`` namespace must
match a D-6'' catalog prefix; ``deliberate:`` / ``invariant:`` details must
carry a ``::`` symbol path or a ``G-8`` reference.  The ``(file, lint, reason)``
triples in ``scripts/lint-ratchet/converted-allows.toml`` (written by task 11)
are exempt.

Runnable: ``python3 catalog_gate.py --self-test``.
"""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

CATALOG = [
    "public API frozen until the next major release",
    "public API: unused inside the unit-test harness",
    "public facade",
    "test code is not rendered API documentation",
    "a test fails by panicking",
    "criterion API",
    "proptest API",
    "should_panic test: the panic is the assertion",
    "constant-time: <detail>",
    "deliberate: <detail>",
    "foreign non-exhaustive enum: <type>",
    "audit writer must not log",
    "write! into String cannot fail",
    "rustls verifier path",
    "invariant: <detail>",
    "external macro: <macro>",
    "new in <version>; pending guidelines re-baseline",
]
GENERATED_PREFIX = "lint-migration:"


def _template_regex(template: str) -> re.Pattern:
    parts = re.split(r"<[^>]+>", template)
    return re.compile("^" + ".+?".join(re.escape(p) for p in parts) + "$")


CATALOG_RE = [(_template_regex(t), t) for t in CATALOG]


def _catalog_match(reason: str) -> bool:
    return any(rx.match(reason) for rx, _ in CATALOG_RE)


def _detail_ok(reason: str) -> bool:
    if reason.startswith("deliberate: "):
        detail = reason[len("deliberate: "):]
    elif reason.startswith("invariant: "):
        detail = reason[len("invariant: "):]
    else:
        return True
    return "::" in detail or re.search(r"\bG-8\b", detail) is not None


def load_whitelist(root: Path) -> set:
    path = root / "scripts/lint-ratchet/converted-allows.toml"
    if not path.exists():
        return set()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = set()
    for entry in data.get("converted", []):
        out.add((entry.get("file"), entry.get("lint"), entry.get("reason")))
    return out


def check(root: Path, files=None):
    whitelist = load_whitelist(root)
    if files is None:
        files = list(common.iter_rust_files(root))
    violations = []
    checked = 0
    for path in files:
        try:
            rel = str(Path(path).resolve().relative_to(root.resolve()))
        except ValueError:
            rel = str(path)
        original, stripped = common.read_source(path)
        for call in common.attribute_calls(original, stripped):
            if call["form"] != "expect":
                continue
            reason = call["reason"]
            line = common.line_of(stripped, call["kw_start"])
            if reason is None:
                violations.append((rel, line, call["lints"], "<missing reason>"))
                continue
            if reason.startswith(GENERATED_PREFIX):
                continue
            for lint in call["lints"]:
                if (rel, lint, reason) in whitelist:
                    continue
                checked += 1
                if not _catalog_match(reason) or not _detail_ok(reason):
                    violations.append((rel, line, [lint], reason))
    return violations, checked


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", action="store_true", help="print every checked expect")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    files = [Path(f) for f in args.files] if args.files else None
    violations, checked = check(ROOT, files)
    if args.report:
        print(f"catalog_gate: checked {checked} permanent expect(s)")
    for rel, line, lints, reason in violations:
        print(f"{rel}:{line}: {', '.join(lints)}: {reason!r}", file=sys.stderr)
    if violations:
        print(f"catalog_gate: FAILED ({len(violations)} uncatalogued expect(s))", file=sys.stderr)
        return 1
    print(f"catalog_gate: ok ({checked} catalogued expect(s))")
    return 0


def _self_test() -> int:
    import tempfile

    failures = []

    def check_cond(label, cond):
        if not cond:
            failures.append(label)

    good = (
        "#[expect(clippy::pub_use, reason = \"public facade\")]\n"
        "#[expect(clippy::module_name_repetitions, reason = \"public API frozen until the next major release\")]\n"
        "#[expect(clippy::expect_used, reason = \"deliberate: src/x.rs::build\")]\n"
        "#[expect(clippy::unwrap_used, reason = \"lint-migration: src/x.rs\")]\n"
        "#[cfg_attr(test, expect(clippy::panic, reason = \"criterion API\"))]\n"
        "fn f() {}\n"
    )
    bad_detail = "#[expect(clippy::unwrap_used, reason = \"deliberate: because I said so\")]\nfn g() {}\n"
    bad_reason = "#[expect(clippy::unwrap_used, reason = \"because I said so\")]\nfn h() {}\n"
    missing = "#[expect(clippy::unwrap_used)]\nfn i() {}\n"
    whitelisted = "#[expect(clippy::unwrap_used, reason = \"legacy reviewed reason\")]\nfn j() {}\n"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        sdir = td / "src"
        sdir.mkdir()
        (sdir / "good.rs").write_bytes(good.encode())
        v, checked = check(td)
        check_cond("catalogued expects pass", not v)
        check_cond("generated expect skipped", checked == 4)

        (sdir / "bad_detail.rs").write_bytes(bad_detail.encode())
        v, _ = check(td, [sdir / "bad_detail.rs"])
        check_cond("bare deliberate detail fails", len(v) == 1)

        (sdir / "bad_reason.rs").write_bytes(bad_reason.encode())
        v, _ = check(td, [sdir / "bad_reason.rs"])
        check_cond("non-catalog reason fails", len(v) == 1)

        (sdir / "missing.rs").write_bytes(missing.encode())
        v, _ = check(td, [sdir / "missing.rs"])
        check_cond("missing reason fails", len(v) == 1)

        sdir2 = td / "scripts/lint-ratchet"
        sdir2.mkdir(parents=True)
        (sdir2 / "converted-allows.toml").write_bytes(
            '[[converted]]\nfile = "src/whitelisted.rs"\nlint = "clippy::unwrap_used"\n'
            'reason = "legacy reviewed reason"\n'.encode()
        )
        (sdir / "whitelisted.rs").write_bytes(whitelisted.encode())
        v, _ = check(td, [sdir / "whitelisted.rs"])
        check_cond("whitelisted triple exempt", not v)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"catalog_gate self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("catalog_gate self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
