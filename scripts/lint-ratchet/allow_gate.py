#!/usr/bin/env python3
"""Count ``allow`` attributes (IS-6 / N-16 vii).

Strips comments and strings first, then counts ``#[allow(``, ``#![allow(`` and
``cfg_attr(.., allow(..))``.  ``--report`` (default) prints the total and every
hit; ``--enforce`` exits 1 when a hit exists.

Runnable: ``python3 allow_gate.py --self-test``.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def scan(files):
    """Return ``[(path, line, lints, predicate)]`` for every allow attribute."""
    hits = []
    for path in files:
        original, stripped = common.read_source(path)
        for call in common.attribute_calls(original, stripped):
            if call["form"] != "allow":
                continue
            hits.append((
                str(path),
                common.line_of(stripped, call["kw_start"]),
                call["lints"],
                call["predicate"],
            ))
    return hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", action="store_true", help="print every hit (default)")
    ap.add_argument("--enforce", action="store_true", help="exit 1 when a hit exists")
    ap.add_argument("--files", nargs="+", help="source files (default: src tests benches examples)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    if args.files:
        files = [Path(f) for f in args.files]
    else:
        files = list(common.iter_rust_files(ROOT))

    hits = scan(files)
    for path, line, lints, predicate in hits:
        guard = f"cfg_attr({predicate}, ...)" if predicate else ""
        detail = ", ".join(lints)
        print(f"{path}:{line}: allow({detail}){(' ' + guard) if guard else ''}")
    print(f"allow_gate: {len(hits)} allow attribute(s) in {len(files)} file(s)")

    if args.enforce and hits:
        print("allow_gate: FAILED (allow attributes are forbidden)", file=sys.stderr)
        return 1
    return 0


def _self_test() -> int:
    import tempfile

    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    fixtures = {
        "nested.rs": (
            "// #[allow(clippy::comment)]\n"
            'const S: &str = "#[allow(clippy::string)]";\n'
            "#[cfg_attr(test, allow(clippy::unwrap_used))]\n"
            "fn a() {}\n"
        ),
        "multi.rs": "#[allow(clippy::unwrap_used, clippy::expect_used, dead_code)]\nfn b() {}\n",
        "inner.rs": "#![allow(dead_code)]\n#![cfg_attr(test, allow(clippy::panic))]\nfn c() {}\n",
        "crlf.rs": "let a = 1;\r\n#[allow(clippy::print_stdout)]\r\nfn d() {}\r\n",
        "none.rs": "// allow(not_an_attribute)\nlet s = \"allow(x)\";\nfn e() {}\n",
    }
    with tempfile.TemporaryDirectory() as td:
        for name, text in fixtures.items():
            (Path(td) / name).write_bytes(text.encode("utf-8"))
        files = sorted(Path(td).glob("*.rs"))
        hits = scan(files)
        by_file = {}
        for path, line, lints, pred in hits:
            by_file.setdefault(Path(path).name, []).append((line, lints, pred))
        check("comment/string not counted", "nested.rs" in by_file and by_file["nested.rs"][0][0] == 3)
        check("nested cfg_attr counted once", len(by_file.get("nested.rs", [])) == 1)
        check("multi-lint is one attribute",
              len(by_file.get("multi.rs", [])) == 1 and by_file["multi.rs"][0][1] ==
              ["clippy::unwrap_used", "clippy::expect_used", "dead_code"])
        check("inner allow", len(by_file.get("inner.rs", [])) == 2)
        check("inner cfg_attr predicate", by_file["inner.rs"][1][2] == "test")
        check("crlf line number", by_file.get("crlf.rs", [])[0][0] == 2)
        check("no false positive", "none.rs" not in by_file)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"allow_gate self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("allow_gate self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
