#!/usr/bin/env python3
"""Shared, stdlib-only parsers for the lint-ratchet gates.

Everything here is byte-exact: :func:`strip_comments_and_strings` preserves the
length of its input (and every ``\\n`` / ``\\r``) so offsets and line numbers map
1:1 onto the original source.  The gates locate attributes on the stripped text
and read string contents (reasons) out of the original at the same offsets.

Runnable standalone: ``python3 common.py --self-test`` runs the inline fixtures.
"""
from __future__ import annotations

import re
import sys

LEVELS = ("deny", "warn", "allow", "forbid")

_LINT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")
_RAW_RE = re.compile(r'(?:[bc]r|r)(#*)?"')
_LEADING_IDENT_RE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")
_TEST_TOKEN_RE = re.compile(r"\btest\b")


# ---------------------------------------------------------------------------
# Comment / string stripping
# ---------------------------------------------------------------------------
def strip_comments_and_strings(src: str) -> str:
    """Blank ``//`` and nested ``/* */`` comments, normal/raw strings and char
    literals, replacing every consumed (non-newline) character with a space.

    Length and line structure are preserved exactly, so an offset into the
    result is the same offset into *src*.
    """
    n = len(src)
    out = list(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] not in ("\n", "\r"):
                out[k] = " "

    i = 0
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i + 2
            while j < n and src[j] != "\n":
                j += 1
            blank(i, j)
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                elif src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        m = _RAW_RE.match(src, i)
        if m:
            hashes = m.group(1)
            q = m.end() - 1
            close = src.find('"' + hashes, q + 1)
            j = n if close < 0 else close + 1 + len(hashes)
            blank(i, j)
            i = j
            continue
        if c == '"' or (c in "bc" and i + 1 < n and src[i + 1] == '"'):
            q = i if c == '"' else i + 1
            j = q + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        if c == "'" or (c == "b" and i + 1 < n and src[i + 1] == "'"):
            k = i + 1 if c == "'" else i + 2
            if k < n and src[k] == "\\":
                j = k + 2
                while j < n and src[j] != "'":
                    j += 1
                j = j + 1 if j < n else n
                blank(i, j)
                i = j
                continue
            if k + 1 < n and src[k + 1] == "'" and src[k] != "'":
                blank(i, k + 2)
                i = k + 2
                continue
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def match_bracket(src: str, open_idx: int) -> int | None:
    """Index of the bracket closing ``src[open_idx]`` (``(``->``)``, ``[``->``]``,
    ``{``->``}``), or ``None``.  Input must already be comment/string stripped."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    open_ch = src[open_idx]
    close_ch = pairs[open_ch]
    depth = 0
    for j in range(open_idx, len(src)):
        if src[j] == open_ch:
            depth += 1
        elif src[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return None


def split_top_level(text: str) -> list[tuple[int, int]]:
    """Split *text* on commas at bracket depth zero; return ``(start, end)`` spans."""
    spans: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    spans.append((start, len(text)))
    return spans


def _string_at(text: str, pos: int) -> tuple[str | None, int]:
    """Parse the first ``"..."`` string at/after *pos* in *text*."""
    i = text.find('"', pos)
    if i < 0:
        return None, len(text)
    j = i + 1
    buf: list[str] = []
    while j < len(text):
        ch = text[j]
        if ch == "\\":
            if j + 1 >= len(text):
                break
            nxt = text[j + 1]
            buf.append({"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(nxt, nxt))
            j += 2
            continue
        if ch == '"':
            return "".join(buf), j + 1
        buf.append(ch)
        j += 1
    return None, len(text)


# ---------------------------------------------------------------------------
# Attribute parsing
# ---------------------------------------------------------------------------
def iter_attributes(src):
    """Yield ``(start, end, inner, body)`` for every ``#[...]`` / ``#![...]`` in
    already-stripped *src*.  ``body`` excludes the brackets."""
    i = 0
    n = len(src)
    while i < n:
        if src[i] == "#":
            j = i + 1
            inner = False
            if j < n and src[j] == "!":
                inner = True
                j += 1
            if j < n and src[j] == "[":
                close = match_bracket(src, j)
                if close is not None:
                    yield (i, close + 1, inner, src[j + 1:close])
                    i = close + 1
                    continue
        i += 1


def _classify(body: str, abs_start: int, original: str, predicates: list[str]):
    """Classify one attribute body; return a list of call records.

    A call record is a dict with ``form`` (``allow``/``expect``), ``lints``,
    ``reason``, ``predicate`` (``None`` or the ``cfg_attr`` guard text), and the
    absolute ``kw_start``/``kw_end`` of the ``allow``/``expect`` keyword.
    """
    m = _LEADING_IDENT_RE.match(body)
    if not m:
        return []
    name = m.group(1)
    p = m.end()
    while p < len(body) and body[p].isspace():
        p += 1
    if p >= len(body) or body[p] != "(":
        return []
    close = match_bracket(body, p)
    inner = body[p + 1:close] if close is not None else body[p + 1:]
    args = split_top_level(inner)

    if name == "cfg_attr":
        if len(args) < 2:
            return []
        predicate = inner[args[0][0]:args[0][1]].strip()
        nested_start = p + 1 + args[-1][0]
        nested = body[nested_start:p + 1 + args[-1][1]]
        return _classify(nested, abs_start + nested_start, original,
                         predicates + [predicate])

    if name not in ("allow", "expect"):
        return []

    lints: list[str] = []
    reason: str | None = None
    kw_start = abs_start + m.start(1)
    for a, b in args:
        text = inner[a:b]
        if "=" in text:
            key = text.split("=", 1)[0].strip()
            if key == "reason":
                eq = abs_start + p + 1 + a + text.index("=")
                reason, _ = _string_at(original, eq)
        else:
            cand = text.strip()
            if _LINT_RE.match(cand):
                lints.append(cand)
    predicate = None
    if predicates:
        predicate = predicates[0] if len(predicates) == 1 else "all(" + ", ".join(predicates) + ")"
    return [{
        "form": name,
        "lints": lints,
        "reason": reason,
        "predicate": predicate,
        "kw_start": kw_start,
        "kw_end": kw_start + len(name),
    }]


def attribute_calls(original: str, stripped: str | None = None):
    """Return every ``allow``/``expect`` call found in attributes of *original*."""
    stripped = strip_comments_and_strings(original) if stripped is None else stripped
    records = []
    for start, _end, inner, body in iter_attributes(stripped):
        body_abs = start + (3 if inner else 2)
        records.extend(_classify(body, body_abs, original, []))
    return records


# ---------------------------------------------------------------------------
# cfg(test) scope
# ---------------------------------------------------------------------------
def _is_test_cfg(body: str) -> bool:
    t = body.strip()
    return t.startswith("cfg(") and bool(_TEST_TOKEN_RE.search(t))


def cfg_test_line_ranges(stripped: str) -> list[tuple[int, int]]:
    """Line ranges (1-based, inclusive) of items gated by a ``cfg`` predicate
    that mentions ``test`` (string contents are already blanked, so
    ``feature = "test-helpers"`` alone is not matched)."""
    ranges: list[tuple[int, int]] = []
    for start, end, _inner, body in iter_attributes(stripped):
        if not _is_test_cfg(body):
            continue
        tail = stripped[end:]
        brace = tail.find("{")
        semi = tail.find(";")
        if brace < 0 and semi < 0:
            continue
        if brace >= 0 and (semi < 0 or brace < semi):
            open_abs = end + brace
            close = match_bracket(stripped, open_abs)
            if close is None:
                close = len(stripped) - 1
            ranges.append((line_of(stripped, start), line_of(stripped, close)))
        else:
            stop = end + semi
            ranges.append((line_of(stripped, start), line_of(stripped, stop)))
    return ranges


def in_ranges(line: int, ranges) -> bool:
    return any(a <= line <= b for a, b in ranges)


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------
def iter_rust_files(root):
    import pathlib
    root = pathlib.Path(root)
    for base in ("src", "tests", "benches", "examples"):
        d = root / base
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.rs")):
            if "target" in p.parts:
                continue
            yield p


def read_source(path):
    """Return ``(original, stripped)``; newlines are preserved verbatim."""
    raw = path.read_bytes().decode("utf-8")
    return raw, strip_comments_and_strings(raw)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _self_test() -> int:
    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)

    # comments / strings containing allow( are blanked; length is preserved.
    src = (
        "// #[allow(clippy::x)]\n"
        "/* nested /* #[allow(a)] */ still */\n"
        'let s = "#[allow(b)] r#\\"#[allow(c)]\\"#";\n'
        "let c = 'x'; let l = 'static;\n"
        "#[allow(clippy::real, clippy::other)]\n"
        "fn f() {}\n"
    )
    st = strip_comments_and_strings(src)
    check("strip length", len(st) == len(src))
    check("strip newlines", st.count("\n") == src.count("\n"))
    check("strip line-comment", "allow(clippy::x)" not in st)
    check("strip block-comment", "allow(a)" not in st)
    check("strip string", "allow(b)" not in st and "allow(c)" not in st)
    check("strip keeps code", "#[allow(clippy::real, clippy::other)]" in st)

    calls = attribute_calls(src, st)
    allow_calls = [c for c in calls if c["form"] == "allow"]
    check("one real allow attribute", len(allow_calls) == 1)
    check("multi-lint list", allow_calls and allow_calls[0]["lints"] == ["clippy::real", "clippy::other"])
    check("allow line", allow_calls and line_of(st, allow_calls[0]["kw_start"]) == 5)

    # escaped char literal '\'' must not leak a quote.
    st2 = strip_comments_and_strings("let q = '\\''; #[expect(x, reason = \"r\")]")
    check("escaped char", "#[expect(x" in st2)
    check("escaped char length", len(st2) == len("let q = '\\''; #[expect(x, reason = \"r\")]"))

    # raw strings with hashes.
    st3 = strip_comments_and_strings('let r = r#"a \\" b"#; #[allow(y)]')
    check("raw string", "#[allow(y)]" in st3 and "a" not in st3.split("#[")[0])

    # nested cfg_attr(expect(..)) with reason.
    nested = '#[cfg_attr(test, expect(clippy::unwrap_used, reason = "lint-migration: src/x.rs"))]'
    ns = strip_comments_and_strings(nested)
    nc = attribute_calls(nested, ns)
    check("nested cfg_attr expect", len(nc) == 1 and nc[0]["form"] == "expect")
    check("nested predicate", nc and nc[0]["predicate"] == "test")
    check("nested reason", nc and nc[0]["reason"] == "lint-migration: src/x.rs")
    check("nested lints", nc and nc[0]["lints"] == ["clippy::unwrap_used"])

    # CRLF bytes are preserved by the stripper.
    crlf = 'let a = 1;\r\n#[allow(z)]\r\n'
    sc = strip_comments_and_strings(crlf)
    check("crlf length", len(sc) == len(crlf))
    check("crlf count", sc.count("\r\n") == 2)
    check("crlf keeps allow", "#[allow(z)]" in sc)

    # cfg(test) module ranges: nested braces handled; feature-only string blanked.
    modsrc = (
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    fn t() { if true { } }\n"
        "}\n"
        "#[cfg(feature = \"test-helpers\")]\n"
        "mod helpers {}\n"
        "#[cfg(any(test, feature = \"test-helpers\"))]\n"
        "mod both {}\n"
    )
    ms = strip_comments_and_strings(modsrc)
    rng = cfg_test_line_ranges(ms)
    check("cfg(test) module range", (1, 4) in rng)
    check("test-helpers not a test range", not in_ranges(6, rng))
    check("any(test,..) is a test range", in_ranges(8, rng))

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"common self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("common self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    print("usage: common.py --self-test", file=sys.stderr)
    sys.exit(2)
