#!/usr/bin/env python3
"""Prose-rule gates (D-12).

Four independent checks, each with a ``--only <name>`` selector:

* ``cancel-safety`` - every production ``async fn`` in ``src/`` (outside a
  ``cfg(test)`` item) has ``// cancel-safe:`` within the 6 lines above it, or a
  ``# Cancel safety`` section in its doc block.
* ``test-docs``    - every ``#[test]`` / ``#[tokio::test]`` / ``#[should_panic]``
  fn has a ``///`` line.
* ``test-result``  - every ``#[test]`` / ``#[tokio::test]`` fn returns ``Result``
  (``-> anyhow::Result<()>`` or ``-> Result<..>``), except ``#[should_panic]``
  tests and proptest-generated tests.
* ``drop-audit``   - every ``impl Drop for`` in ``src/`` has ``// Drop audit``
  within the 3 lines above (the plan's six production Drop impls).

``--report`` (default) prints the counts and each violation; ``--enforce`` exits
1 when a violation exists.  Runnable: ``python3 prose_gates.py --self-test``.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

FN_RE = re.compile(r"(?<![A-Za-z0-9_.])fn\s+([A-Za-z_][A-Za-z0-9_]*)")
DROP_RE = re.compile(r"\bimpl(?:<[^>{}]*>)?\s+Drop\s+for\b")
PROPTEST_RE = re.compile(r"\bproptest!\s*\{")

CANCEL_LOOKBACK = 6
DROP_LOOKBACK = 3
ONLY_CHOICES = ("cancel-safety", "test-docs", "test-result", "drop-audit")


def _next_code_pos(stripped: str, pos: int) -> int:
    n = len(stripped)
    i = pos
    while i < n:
        if stripped[i] == "#":
            j = i + 1
            if j < n and stripped[j] == "!":
                j += 1
            if j < n and stripped[j] == "[":
                close = common.match_bracket(stripped, j)
                if close is not None:
                    i = close + 1
                    continue
        if stripped[i].isspace():
            i += 1
            continue
        return i
    return -1


def _attributes_by_item(stripped: str):
    """Map item start line -> list of attribute body strings."""
    groups: dict[int, list[str]] = {}
    for start, end, _inner, body in common.iter_attributes(stripped):
        pos = _next_code_pos(stripped, end)
        if pos < 0:
            continue
        line = common.line_of(stripped, pos)
        groups.setdefault(line, []).append(body)
    return groups


def _is_test_attr(body: str) -> bool:
    t = body.strip()
    return t == "test" or re.match(r"(tokio::test|should_panic)\b", t) is not None


def _is_should_panic(body: str) -> bool:
    return re.match(r"should_panic\b", body.strip()) is not None


def _fn_items(stripped: str):
    """Yield ``(line, offset, name, signature, attrs)`` for every fn definition."""
    groups = _attributes_by_item(stripped)
    for m in FN_RE.finditer(stripped):
        line = common.line_of(stripped, m.start())
        cut = len(stripped)
        for ch in ("{", ";"):
            p = stripped.find(ch, m.end())
            if 0 <= p < cut:
                cut = p
        sig = stripped[m.start():cut]
        yield line, m.start(), m.group(1), sig, groups.get(line, [])


def _doc_block(orig_lines, item_line: int):
    """Contiguous attribute/doc lines directly above *item_line* (1-based)."""
    out = []
    i = item_line - 2  # 0-based index of the line just above
    while i >= 0:
        line = orig_lines[i]
        s = line.lstrip()
        if s == "" or s.startswith("//") or s.startswith("#["):
            out.append(line)
            i -= 1
            continue
        break
    return out


def _proptest_ranges(stripped: str):
    ranges = []
    for m in PROPTEST_RE.finditer(stripped):
        brace = stripped.find("{", m.end() - 1)
        if brace < 0:
            continue
        close = common.match_bracket(stripped, brace)
        ranges.append((m.start(), close if close is not None else len(stripped)))
    return ranges


def scan_file(path: Path, only: set[str]):
    """Return ``{gate: [(line, detail), ...]}`` for one file."""
    original, stripped = common.read_source(path)
    orig_lines = original.splitlines()
    out = {g: [] for g in ONLY_CHOICES}

    if "cancel-safety" in only or "drop-audit" in only:
        test_ranges = common.cfg_test_line_ranges(stripped)

    if "cancel-safety" in only:
        stripped_lines = stripped.splitlines()
        for line, _off, name, _sig, _attrs in _fn_items(stripped):
            linetext = stripped_lines[line - 1] if line - 1 < len(stripped_lines) else ""
            if not re.search(r"\basync\b[^;{]*\bfn\b", linetext):
                continue
            if common.in_ranges(line, test_ranges):
                continue
            above = orig_lines[max(0, line - 1 - CANCEL_LOOKBACK):line - 1]
            if any("cancel-safe:" in l for l in above):
                continue
            doc = _doc_block(orig_lines, line)
            if any("Cancel safety" in l for l in doc):
                continue
            out["cancel-safety"].append((line, f"async fn {name}"))

    if "test-docs" in only or "test-result" in only:
        proptest = _proptest_ranges(stripped)
        for line, off, name, sig, attrs in _fn_items(stripped):
            test_attr = [b for b in attrs if _is_test_attr(b)]
            if not test_attr:
                continue
            if any(a <= off <= b for a, b in proptest):
                continue
            should_panic = any(_is_should_panic(b) for b in attrs)
            if "test-docs" in only:
                doc = _doc_block(orig_lines, line)
                if not any(l.lstrip().startswith("///") for l in doc):
                    out["test-docs"].append((line, f"fn {name}"))
            if "test-result" in only and not should_panic:
                arrow = sig.find("->")
                if arrow < 0 or "Result" not in sig[arrow:]:
                    out["test-result"].append((line, f"fn {name}"))

    if "drop-audit" in only:
        for m in DROP_RE.finditer(stripped):
            line = common.line_of(stripped, m.start())
            above = orig_lines[max(0, line - 1 - DROP_LOOKBACK):line - 1]
            if any("Drop audit" in l for l in above):
                continue
            out["drop-audit"].append((line, "impl Drop for"))

    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", action="store_true", help="print counts and violations (default)")
    ap.add_argument("--enforce", action="store_true", help="exit 1 on any violation")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--only", action="append", choices=ONLY_CHOICES)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    only = set(args.only) if args.only else set(ONLY_CHOICES)
    explicit = bool(args.files)
    if args.files:
        files = [Path(f) for f in args.files]
    else:
        files = list(common.iter_rust_files(ROOT))

    totals = {g: [] for g in ONLY_CHOICES}
    for path in files:
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        in_src = str(rel).startswith("src" + "/")
        results = scan_file(path, only)
        for gate, hits in results.items():
            # cancel-safety and drop-audit are production (src/) gates by
            # default; --files overrides.
            if not explicit and gate in ("cancel-safety", "drop-audit") and not in_src:
                continue
            for line, detail in hits:
                totals[gate].append((path, line, detail))

    labels = {
        "cancel-safety": "unannotated production async fn",
        "test-docs": "undocumented test fn",
        "test-result": "test fn not returning Result",
        "drop-audit": "unaudited Drop impl",
    }
    for gate in ONLY_CHOICES:
        if gate not in only:
            continue
        hits = totals[gate]
        print(f"{gate}: {len(hits)} {labels[gate]}")
        if args.report:
            for path, line, detail in hits:
                try:
                    shown = path.relative_to(ROOT)
                except ValueError:
                    shown = path
                print(f"  {shown}:{line}: {detail}")

    violations = sum(len(totals[g]) for g in only)
    if args.enforce and violations:
        print("prose_gates: FAILED", file=sys.stderr)
        return 1
    return 0


def _self_test() -> int:
    import tempfile

    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    src = (
        "//! module docs\n"                       # 1
        "use std::io;\n"                          # 2
        "\n"                                      # 3
        "/// # Cancel safety\n"                   # 4
        "/// Stays alive.\n"                      # 5
        "pub async fn documented() {}\n"          # 6
        "\n"                                      # 7
        "// cancel-safe: never held across await\n"  # 8
        "async fn adjacent() {}\n"                # 9
        "\n"                                      # 10
        "\n"                                      # 11
        "\n"                                      # 12
        "\n"                                      # 13
        "\n"                                      # 14
        "async fn missing() {}\n"                 # 15
        "\n"                                      # 16
        "#[cfg(test)]\n"                          # 17
        "mod tests {\n"                           # 18
        "    #[test]\n"                           # 19
        "    fn undocumented() {}\n"              # 20
        "    /// documented\n"                    # 21
        "    #[test]\n"                           # 22
        "    fn documented_fn() -> anyhow::Result<()> { Ok(()) }\n"  # 23
        "    /// panics on purpose\n"             # 24
        "    #[test]\n"                           # 25
        "    #[should_panic]\n"                   # 26
        "    fn panics() {}\n"                    # 27
        "}\n"                                     # 28
        "\n"                                      # 29
        "impl Drop for Guard {\n"                 # 30
        "    fn drop(&mut self) {}\n"             # 31
        "}\n"                                     # 32
        "\n"                                      # 33
        "// Drop audit: releases the handle\n"    # 34
        "impl Drop for Audited {\n"               # 35
        "    fn drop(&mut self) {}\n"             # 36
        "}\n"                                     # 37
    )
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "src" / "lib.rs"
        p.parent.mkdir(parents=True)
        p.write_bytes(src.encode("utf-8"))
        results = scan_file(p, set(ONLY_CHOICES))
        check("cancel-safety count", len(results["cancel-safety"]) == 1)
        check("cancel-safety flags missing", results["cancel-safety"] and results["cancel-safety"][0][0] == 15)
        check("test-docs count", len(results["test-docs"]) == 1)
        check("test-docs flags undocumented", results["test-docs"] and results["test-docs"][0][0] == 20)
        check("test-result excludes should_panic", len(results["test-result"]) == 1)
        check("test-result flags undocumented", results["test-result"] and results["test-result"][0][0] == 20)
        check("drop-audit count", len(results["drop-audit"]) == 1)
        check("drop-audit flags guard", results["drop-audit"] and results["drop-audit"][0][0] == 30)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"prose_gates self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("prose_gates self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
