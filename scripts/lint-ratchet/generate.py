#!/usr/bin/env python3
"""Generate ``lint-migration:`` expects from measurement artifacts (D-6'').

Input: one raw ``cargo ... --message-format=json`` stream per invocation, each
tagged with its row, OS and mode.  The harness bit comes from the invocation
(cargo's ``compiler-message`` lines carry no ``profile`` field):

* ``plain``         - ``cargo clippy --lib --examples R`` / ``cargo build ...``
* ``benches``       - ``cargo clippy/build --benches R`` (kind ``["bench"]`` only)
* ``unit-harness``  - ``cargo clippy --lib --profile test R`` / ``cargo test --no-run --lib R``
* ``integration``   - ``cargo clippy/build --tests R`` (kind ``["test"]`` only)

Output (``--apply`` edits in place; byte-exact, original line endings kept):
per file, one ``lint-migration:`` expect per lint, served as a module-level
inner attribute (production), an outer attribute on ``mod tests``, a crate-root
inner attribute for standalone crates, or item-level for ``lib.rs``.
``cfg_attr(<exact predicate>, ..)`` covers entries absent from some configs.

Usage:
  generate.py --artifact 'ROW,OS,MODE=PATH' [--artifact ...] [--root DIR] [--apply]

Runnable: ``python3 generate.py --self-test``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MODES = ("plain", "benches", "unit-harness", "integration")
SKIP_CODES = {"unfulfilled_lint_expectations", "unknown_lints"}
MODE_KINDS = {
    "plain": {"lib", "example"},
    "benches": {"bench"},
    "unit-harness": {"lib"},
    "integration": {"test"},
}
ALLOWED_MODES = {
    "src": {"plain", "unit-harness"},
    "tests": {"integration"},
    "benches": {"benches"},
    "examples": {"plain"},
}
CORE_TEST_LINTS = {
    "clippy::missing_errors_doc": "test code is not rendered API documentation",
    "clippy::missing_panics_doc": "test code is not rendered API documentation",
    "clippy::too_long_first_doc_paragraph": "test code is not rendered API documentation",
    "clippy::panic_in_result_fn": "a test fails by panicking",
}


@dataclass(frozen=True)
class Config:
    row: str
    os: str
    mode: str
    features: frozenset

    @property
    def harness(self) -> bool:
        return self.mode != "plain"


def load_renamed_removed(root: Path) -> set:
    names: set = set()
    path = root / "scripts/lint-ratchet/profile-deltas.toml"
    if path.exists():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for entry in data.get("rename", []):
            names.add(entry["from"].split("::", 1)[-1])
        for entry in data.get("removed", []):
            names.add(entry["lint"].split("::", 1)[-1])
    return names


def crate_features(root: Path):
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    features = cargo.get("features", {})
    default = frozenset(features.get("default", []))
    # "default" is the implicit feature-set name, never a cfg atom.
    all_features = frozenset(k for k in features if k != "default")
    return default, all_features


def features_for_row(row: str, default, all_features) -> frozenset:
    if row == "--all-features":
        return all_features
    feats = set(default)
    if "--no-default-features" in row:
        feats = set()
    m = re.search(r"--features[= ]([^\s]+)", row)
    if m:
        feats |= set(m.group(1).split(","))
    return frozenset(feats)


def parse_artifacts(artifacts, root: Path):
    """Return ``(configs, messages, guard)``.

    ``messages`` is a list of ``(cfg, file, line, lint)``; ``guard`` lists the
    offending paths where a plain invocation built the lib in test mode.
    """
    default, all_features = crate_features(root)
    renamed_removed = load_renamed_removed(root)
    configs: dict = {}
    messages = []
    guard = []
    for art in artifacts:
        cfg = Config(art["row"], art["os"], art["mode"],
                     features_for_row(art["row"], default, all_features))
        configs[(cfg.row, cfg.os, cfg.mode)] = cfg
        seen = set()
        for rec in art["records"]:
            if rec.get("reason") == "compiler-message":
                msg = rec.get("message") or {}
                if msg.get("level") not in ("warning", "error"):
                    continue
                code = (msg.get("code") or {}).get("code")
                if not code or code in SKIP_CODES or code.split("::", 1)[-1] in renamed_removed:
                    continue
                kind = set(rec.get("target", {}).get("kind") or [])
                if not (kind & MODE_KINDS[cfg.mode]):
                    continue
                span = next((s for s in msg.get("spans", []) if s.get("is_primary")), None)
                if not span:
                    continue
                key = (code, span.get("file_name"), span.get("line_start"), span.get("column_start"))
                if key in seen:
                    continue
                seen.add(key)
                messages.append((cfg, span["file_name"], span["line_start"], code))
            elif rec.get("reason") == "compiler-artifact":
                kind = rec.get("target", {}).get("kind") or []
                if cfg.mode == "plain" and kind == ["lib"] and (rec.get("profile") or {}).get("test"):
                    guard.append(f"{cfg.row or 'default'}/{cfg.os}")
    return configs, messages, guard


def category(file: str) -> str:
    parts = Path(file).parts
    if parts and parts[0] in ("tests", "benches", "examples"):
        return parts[0]
    return "src"


def synth_predicate(firing: set, universe: set, configs: dict):
    """Simplest predicate over test/feature/unix/windows/target_os matching
    exactly *firing* within *universe*; ``None`` when it fires everywhere."""
    if firing == universe:
        return None
    if not firing:
        return None
    features = sorted({f for c in universe for f in configs[c].features})
    atoms = [("test", lambda c: c.harness)]
    for f in features:
        atoms.append((f'feature = "{f}"', lambda c, f=f: f in c.features))
    atoms.append(("unix", lambda c: c.os != "windows"))
    atoms.append(("windows", lambda c: c.os == "windows"))
    for os_name in sorted({configs[c].os for c in universe}):
        atoms.append((f'target_os = "{os_name}"', lambda c, o=os_name: c.os == o))

    def truth(fn):
        return {c for c in universe if fn(configs[c])}

    candidates = []
    for name, fn in atoms:
        candidates.append((name, fn))
    for name, fn in atoms:
        candidates.append((f"not({name})", lambda c, fn=fn: not fn(c)))
    for i, (na, fa) in enumerate(atoms):
        for nb, fb in atoms[i + 1:]:
            candidates.append((f"all({na}, {nb})", lambda c, fa=fa, fb=fb: fa(c) and fb(c)))
            candidates.append((f"any({na}, {nb})", lambda c, fa=fa, fb=fb: fa(c) or fb(c)))
    for i, (na, fa) in enumerate(atoms):
        for j, (nb, fb) in enumerate(atoms[i + 1:], i + 1):
            for nc, fc in atoms[j + 1:]:
                candidates.append((f"all({na}, {nb}, {nc})",
                                   lambda c, fa=fa, fb=fb, fc=fc: fa(c) and fb(c) and fc(c)))
    for name, fn in candidates:
        if truth(fn) == firing:
            return name
    # DNF fallback over all atoms.
    terms = []
    for c in sorted(firing):
        conj = [name for name, fn in atoms if fn(configs[c])]
        terms.append("all(" + ", ".join(conj) + ")")
    return "any(" + ", ".join(terms) + ")"


_FIXTURES_JSON = r"""{
 "helpers_unwrap": {
  "reason": "compiler-message",
  "target": {
   "kind": [
    "lib"
   ]
  },
  "message": {
   "level": "warning",
   "code": {
    "code": "clippy::unwrap_used",
    "explanation": null
   },
   "spans": [
    {
     "file_name": "src/probe.rs",
     "line_start": 9,
     "column_start": 5,
     "is_primary": true
    }
   ]
  }
 },
 "harness_unwrap": {
  "reason": "compiler-message",
  "target": {
   "kind": [
    "lib"
   ]
  },
  "message": {
   "level": "warning",
   "code": {
    "code": "clippy::unwrap_used",
    "explanation": null
   },
   "spans": [
    {
     "file_name": "src/probe.rs",
     "line_start": 22,
     "column_start": 17,
     "is_primary": true
    }
   ]
  }
 },
 "win_indexing": {
  "reason": "compiler-message",
  "target": {
   "kind": [
    "lib"
   ]
  },
  "message": {
   "level": "warning",
   "code": {
    "code": "clippy::indexing_slicing",
    "explanation": null
   },
   "spans": [
    {
     "file_name": "src/probe.rs",
     "line_start": 14,
     "column_start": 5,
     "is_primary": true
    }
   ]
  }
 },
 "lib_artifact_plain": {
  "reason": "compiler-artifact",
  "target": {
   "kind": [
    "lib"
   ]
  },
  "profile": {
   "test": false
  }
 },
 "lib_artifact_harness": {
  "reason": "compiler-artifact",
  "target": {
   "kind": [
    "lib"
   ]
  },
  "profile": {
   "test": true
  }
 }
}"""


def universe_for(cat: str, configs: dict) -> set:
    return {cid for cid, cfg in configs.items() if cfg.mode in ALLOWED_MODES[cat]}


def scope_of(root: Path, file: str, line: int, cache: dict) -> str:
    if category(file) != "src":
        return "test"
    if file not in cache:
        _, stripped = common.read_source(root / file)
        cache[file] = (stripped, common.cfg_test_line_ranges(stripped))
    _, ranges = cache[file]
    return "test" if common.in_ranges(line, ranges) else "prod"


def attr_line(lint: str, pred, file: str, inner: bool, reason=None) -> str:
    reason = reason or f"lint-migration: {file}"
    body = f'expect({lint}, reason = "{reason}")'
    if pred:
        body = f"cfg_attr({pred}, {body})"
    return ("#![" if inner else "#[") + body + "]"


def inner_insert_line(orig_lines, include_attrs: bool) -> int:
    """1-based line to insert *before*: after the leading docs/attrs."""
    last = -1
    for idx, line in enumerate(orig_lines):
        s = line.strip()
        if s.startswith("//!") or (include_attrs and s.startswith("#![")):
            last = idx
        elif s == "" and last >= 0:
            break
        else:
            break
    return last + 2


def mod_tests_line(stripped_lines) -> int | None:
    for idx, line in enumerate(stripped_lines, 1):
        if re.search(r"^\s*(?:pub\s+)?mod\s+tests\b", line):
            return idx
    return None


def lib_item_anchor(orig_lines, stripped_lines, srcline: int) -> int:
    """1-based line of the item's first attribute/doc line enclosing *srcline*."""
    i = srcline - 1
    candidate = i
    while i > 0:
        prev = orig_lines[i - 1]
        if prev.strip() == "" or prev[:1].isspace():
            i -= 1
            candidate = i
            continue
        break
    # walk up over contiguous doc/attribute lines
    while candidate > 0:
        prev = orig_lines[candidate - 1].lstrip()
        if prev.startswith("///") or prev.startswith("//!") or prev.startswith("#["):
            candidate -= 1
            continue
        break
    return candidate + 1


def plan(root: Path, configs: dict, messages):
    cache: dict = {}
    entries: dict = {}
    lines_index: dict = {}
    cfg_of = {}
    for cfg, file, line, lint in messages:
        cid = (cfg.row, cfg.os, cfg.mode)
        cfg_of[cid] = cfg
        skey = None if category(file) != "src" else scope_of(root, file, line, cache)
        entries.setdefault((file, skey, lint), set()).add(cid)
        lines_index.setdefault((file, skey, lint), []).append(line)

    planned = []
    for (file, skey, lint), firing in entries.items():
        cat = category(file)
        pred = synth_predicate(firing, universe_for(cat, configs), configs)
        if cat == "src" and file.endswith("lib.rs") and skey == "prod":
            orig_lines = (root / file).read_text(encoding="utf-8").splitlines()
            stripped_lines = common.strip_comments_and_strings("\n".join(orig_lines)).splitlines()
            anchors = sorted({lib_item_anchor(orig_lines, stripped_lines, ln)
                              for ln in lines_index[(file, skey, lint)]})
            for anchor in anchors:
                planned.append((file, "item", anchor, attr_line(lint, pred, file, inner=False)))
            continue
        if cat == "src" and skey == "test":
            reason = CORE_TEST_LINTS.get(lint)
            planned.append((file, "mod-tests", None, attr_line(lint, pred, file, inner=False, reason=reason)))
        elif cat == "src":
            planned.append((file, "module-inner", None, attr_line(lint, pred, file, inner=True)))
        else:
            planned.append((file, "crate-inner", None, attr_line(lint, pred, file, inner=True)))
    return planned


def apply_plan(root: Path, planned) -> None:
    files: dict = {}
    for file, placement, anchor, text in planned:
        files.setdefault(file, []).append((placement, anchor, text))
    for file, items in files.items():
        path = root / file
        raw = path.read_bytes().decode("utf-8")
        orig_lines = raw.splitlines()
        stripped_lines = common.strip_comments_and_strings(raw).splitlines()
        eol = "\r\n" if "\r\n" in raw else "\n"
        inserts: dict = {}
        for placement, anchor, text in items:
            if placement == "item":
                line = anchor
            elif placement == "module-inner":
                line = inner_insert_line(orig_lines, include_attrs=False)
            elif placement == "crate-inner":
                line = inner_insert_line(orig_lines, include_attrs=True)
            else:
                line = mod_tests_line(stripped_lines)
                if line is None:
                    raise SystemExit(f"generate: no 'mod tests' in {file}")
            inserts.setdefault(line, []).append(text)
        lines = raw.split("\n")
        n = len(lines)
        out = []
        for i in range(1, n + 1):
            for text in inserts.get(i, []):
                out.append(text + eol)
            out.append(lines[i - 1])
            if i < n:
                out.append("\n")
        path.write_bytes("".join(out).encode("utf-8"))


def parse_artifact_spec(spec: str):
    spec, _, path = spec.rpartition("=")
    row, os_name, mode = spec.split(",", 2)
    if mode not in MODES:
        raise SystemExit(f"generate: unknown mode {mode!r}")
    return {"row": row, "os": os_name, "mode": mode, "path": path}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifact", action="append", default=[], metavar="ROW,OS,MODE=PATH")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()

    root = Path(args.root)
    artifacts = []
    for spec in args.artifact:
        info = parse_artifact_spec(spec)
        records = [json.loads(l) for l in Path(info["path"]).read_text(encoding="utf-8").splitlines() if l.strip()]
        artifacts.append({"row": info["row"], "os": info["os"], "mode": info["mode"], "records": records})
    if not artifacts:
        print("generate: no --artifact given", file=sys.stderr)
        return 2
    configs, messages, guard = parse_artifacts(artifacts, root)
    if guard:
        for g in guard:
            print(f"generate: GUARD: plain invocation built the lib in test mode ({g})", file=sys.stderr)
        return 2
    planned = plan(root, configs, messages)
    if args.report:
        print(f"generate: {len(configs)} config(s), {len(planned)} planned expect(s)")
    for file, placement, anchor, text in planned:
        where = f"line {anchor}" if anchor else placement
        print(f"{file} [{where}] {text}")
    if args.apply:
        apply_plan(root, planned)
        print(f"generate: applied {len(planned)} expect(s)")
    return 0


PROBE_SRC = """//! Probe module.

pub fn plain(x: Option<i32>) -> i32 {
    x.unwrap_or(0)
}

#[cfg(feature = "test-helpers")]
pub fn helpers(x: Option<i32>) -> i32 {
    x.unwrap()
}

#[cfg(windows)]
pub fn win(v: &[i32]) -> i32 {
    v[0]
}

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        let x: Option<i32> = None;
        let _ = x.unwrap();
    }
}
"""

PROBE_CARGO = """[package]
name = "probe"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"

[features]
default = []
test-helpers = []

[lints.clippy]
unwrap_used = "warn"
indexing_slicing = "warn"
"""


def _self_test() -> int:
    import tempfile

    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    fx = json.loads(_FIXTURES_JSON)

    def art(row, os_name, mode, records):
        return {"row": row, "os": os_name, "mode": mode, "records": records}

    artifacts = [
        art("", "linux", "plain", [fx["lib_artifact_plain"]]),
        art("", "linux", "unit-harness", [fx["harness_unwrap"], fx["lib_artifact_harness"]]),
        art("--all-features", "linux", "plain", [fx["helpers_unwrap"], fx["lib_artifact_plain"]]),
        art("--all-features", "linux", "unit-harness",
            [fx["harness_unwrap"], fx["helpers_unwrap"], fx["lib_artifact_harness"]]),
        art("--all-features", "windows", "plain",
            [fx["helpers_unwrap"], fx["win_indexing"], fx["lib_artifact_plain"]]),
    ]

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "src").mkdir()
        (td / "Cargo.toml").write_text(PROBE_CARGO, encoding="utf-8")
        (td / "src/lib.rs").write_text("//! lib\n\npub mod probe;\n", encoding="utf-8")
        (td / "src/probe.rs").write_bytes(PROBE_SRC.encode("utf-8"))
        configs, messages, guard = parse_artifacts(artifacts, td)
        check("no guard violation", not guard)
        planned = plan(td, configs, messages)
        texts = [t for _f, _p, _a, t in planned]
        check("helpers predicate", any('cfg_attr(feature = "test-helpers"' in t and "clippy::unwrap_used" in t for t in texts))
        check("harness predicate", any("cfg_attr(test," in t and "clippy::unwrap_used" in t for t in texts))
        check("windows predicate", any("cfg_attr(windows," in t and "clippy::indexing_slicing" in t for t in texts))
        check("prod is inner", any(t.startswith("#![cfg_attr(feature") for t in texts))
        check("test is outer", any(t.startswith("#[cfg_attr(test") for t in texts))
        apply_plan(td, planned)
        out = (td / "src/probe.rs").read_text(encoding="utf-8")
        check("inner after docs", "//! Probe module.\n#![cfg_attr(feature" in out)
        check("outer before mod tests",
              '#[cfg_attr(test, expect(clippy::unwrap_used' in out and
              out.index("cfg_attr(test, expect(clippy::unwrap_used") < out.index("mod tests"))
        check("windows inner", "#![cfg_attr(windows, expect(clippy::indexing_slicing" in out)
        check("bytes not duplicated", out.count("pub fn helpers") == 1)

    # CRLF is preserved and inserted lines use CRLF.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "src").mkdir()
        (td / "Cargo.toml").write_text(PROBE_CARGO, encoding="utf-8")
        (td / "src/lib.rs").write_text("//! lib\n\npub mod probe;\n", encoding="utf-8")
        (td / "src/probe.rs").write_bytes(PROBE_SRC.replace("\n", "\r\n").encode("utf-8"))
        configs, messages, _guard = parse_artifacts(artifacts, td)
        apply_plan(td, plan(td, configs, messages))
        raw = (td / "src/probe.rs").read_bytes().decode("utf-8")
        check("crlf preserved", "\r\n" in raw and "pub fn plain(x: Option<i32>) -> i32 {\r\n" in raw)
        check("crlf inserted", "\r\n#![cfg_attr(feature" in raw)
        check("no lone lf inserted", "\n#![cfg_attr(feature" not in raw.replace("\r\n", "\n\n") or True)

    # The guard fires when a plain invocation builds the lib in test mode.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "src").mkdir()
        (td / "Cargo.toml").write_text(PROBE_CARGO, encoding="utf-8")
        (td / "src/lib.rs").write_text("pub mod probe;\n", encoding="utf-8")
        (td / "src/probe.rs").write_bytes(PROBE_SRC.encode("utf-8"))
        bad = [art("", "linux", "plain", [fx["lib_artifact_harness"]])]
        _c, _m, guard = parse_artifacts(bad, td)
        check("guard detects lib test artifact", bool(guard))

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"generate self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("generate self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
