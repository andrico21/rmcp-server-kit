#!/usr/bin/env python3
"""Gate the repository's single-hyphen dash convention.

Reports prose, banner, string, arrow and Unicode dash forms in tracked text
files outside the vendored guideline tree. Command-line flags, HTML comments,
Mermaid arrows, generated anchor syntax, Markdown rules and table separators
are exempt. ``--enforce`` exits nonzero when a violation exists; ``--self-test``
runs inline fixtures.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOUBLE_DASH = "-" * 2
TOKEN_RE = re.compile(r"(?<!-)" + re.escape(DOUBLE_DASH) + r"(?!-)")
UNICODE_DASH_RE = re.compile("[\u2012\u2013\u2014\u2015]")
COMMAND_RE = re.compile(
    r"(^|[\s`(|$;&])"
    r"(bash|cargo|cargo-\w+|clippy-driver|curl|gh|git|lychee|python3?|pwsh|"
    r"rtk|rustc|rustup|sh|sha256sum|taplo|run:)\b"
)


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    column: int
    kind: str
    context: str


def git_ls_files(root: Path) -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [root / line for line in proc.stdout.splitlines() if line]


def is_scanned_path(path: Path) -> bool:
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    return not rel.as_posix().startswith("docs/rust-guidelines/")


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def rust_regions(text: str) -> tuple[list[str], list[str]]:
    regions = ["code"] * len(text)
    fences = [""] * len(text)
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            for j in range(i, end):
                regions[j] = "comment"
            i = end
            continue
        if text.startswith("/*", i):
            depth = 1
            end = i + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            for j in range(i, end):
                regions[j] = "comment"
            i = end
            continue
        match = re.match(r'b?r(#*)"', text[i : i + 40])
        if match and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + match.group(1)
            end = text.find(close, i + match.end())
            end = len(text) if end < 0 else end + len(close)
            for j in range(i, end):
                regions[j] = "string"
            i = end
            continue
        if text[i] == '"':
            end = i + 1
            while end < len(text) and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end = min(len(text), end + 1)
            for j in range(i, end):
                regions[j] = "string"
            i = end
            continue
        if text[i] == "'":
            match = re.match(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'", text[i : i + 14])
            if match:
                for j in range(i, i + match.end()):
                    regions[j] = "string"
                i += match.end()
                continue
        i += 1
    return regions, fences


def python_regions(text: str) -> tuple[list[str], list[str]]:
    regions = ["code"] * len(text)
    fences = [""] * len(text)
    i = 0
    while i < len(text):
        if text[i] == "#":
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            for j in range(i, end):
                regions[j] = "comment"
            i = end
            continue
        match = re.match(r"[rbfRBF]{0,2}(\"\"\"|'''|\"|')", text[i : i + 6])
        if match and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            quote = match.group(1)
            end = i + match.end()
            while end < len(text) and not text.startswith(quote, end):
                if quote in ('"', "'") and text[end] == "\n":
                    break
                end += 2 if text[end] == "\\" else 1
            end = min(len(text), end + len(quote))
            for j in range(i, end):
                regions[j] = "string"
            i = end
            continue
        i += 1
    return regions, fences


def hash_comment_regions(text: str) -> tuple[list[str], list[str]]:
    regions = ["code"] * len(text)
    fences = [""] * len(text)
    for match in re.finditer(r"(^|[ \t])#[^\n]*", text):
        for j in range(match.start(), match.end()):
            regions[j] = "comment"
    return regions, fences


def markdown_regions(text: str) -> tuple[list[str], list[str]]:
    regions = ["prose"] * len(text)
    fences = [""] * len(text)
    pos = 0
    in_fence = False
    fence_lang = ""
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            if not in_fence:
                parts = stripped[3:].strip().split()
                fence_lang = parts[0].lower() if parts else ""
            for j in range(pos, pos + len(line)):
                regions[j] = "code"
                fences[j] = fence_lang
            in_fence = not in_fence
            if not in_fence:
                fence_lang = ""
        elif in_fence:
            for j in range(pos, pos + len(line)):
                regions[j] = "code"
                fences[j] = fence_lang
        else:
            for match in re.finditer(r"`[^`]*`", line):
                for j in range(pos + match.start(), pos + match.end()):
                    regions[j] = "code"
        pos += len(line) + 1
    return regions, fences


def regions_for(path: Path, text: str) -> tuple[list[str], list[str]]:
    name = path.name
    if name.endswith(".rs"):
        return rust_regions(text)
    if name.endswith(".py"):
        return python_regions(text)
    if name.endswith(".md"):
        return markdown_regions(text)
    return hash_comment_regions(text)


def line_bounds(text: str, index: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return start, len(text) if end < 0 else end


def classify_token(path: Path, text: str, regions: list[str], fences: list[str], index: int) -> str:
    start, end = line_bounds(text, index)
    line = text[start:end]
    column = index - start
    before = text[index - 1] if index > 0 else "\n"
    after = text[index + 2] if index + 2 < len(text) else "\n"
    if index < len(fences) and fences[index] in {"mermaid", "mmd"}:
        return "exempt"
    if text[max(0, index - 2) : index] == "<!":
        return "exempt"
    if after == ">" and text.rfind("<!--", 0, index) > text.rfind("-->", 0, index):
        return "exempt"
    if before == "<" or after == ">":
        return "arrow"
    if re.search(r"https?://\S*$", line[:column]):
        return "exempt"
    if re.search(r"\]\(#[^)\s]*$", line[:column]):
        return "exempt"
    if before.isalnum() and after.isalnum() and re.search(r"#[\w-]*$", line[:column]):
        return "exempt"
    if re.match(r"[A-Za-z]", after) and before in " \t`(\"'[=|\n":
        return "exempt"
    if before in " \t" and COMMAND_RE.search(line[:column]):
        rest = text[index + 2 : index + 40]
        if re.match(r" +(-|\$|\{|<)", rest):
            return "exempt"
        if re.search(r"\bgit\b", line[:column]) and re.match(r" +[\w./]", rest):
            return "exempt"
        next_start = end + 1
        next_end = text.find("\n", next_start)
        next_line = text[next_start : (next_end if next_end >= 0 else len(text))].lstrip()
        if after == "\n" and next_line.startswith("-"):
            return "exempt"
    region = regions[index] if index < len(regions) else "code"
    if path.suffix == ".md" and region == "code":
        if re.match(r"\s*(//|#)", line) or " // " in line[:column] or " # " in line[:column]:
            return "prose"
        if COMMAND_RE.search(line[:column]):
            return "exempt"
        return "prose" if before == " " and after in " \n" else "exempt"
    if region == "string":
        return "string"
    pattern = r"^\s*(//[!/]?|#+)\s*" + re.escape(DOUBLE_DASH) + r"\s.*\S\s" + re.escape(DOUBLE_DASH) + r"\s*$"
    if re.match(pattern, line):
        return "banner"
    return "prose"


def scan_file(path: Path) -> list[Violation]:
    text = read_text(path)
    if text is None:
        return []
    regions, fences = regions_for(path, text)
    violations: list[Violation] = []
    for match in TOKEN_RE.finditer(text):
        kind = classify_token(path, text, regions, fences, match.start())
        if kind == "exempt":
            continue
        start, end = line_bounds(text, match.start())
        violations.append(
            Violation(path, text.count("\n", 0, match.start()) + 1, match.start() - start + 1, kind, text[start:end].strip())
        )
    for match in UNICODE_DASH_RE.finditer(text):
        start, end = line_bounds(text, match.start())
        violations.append(
            Violation(path, text.count("\n", 0, match.start()) + 1, match.start() - start + 1, "unicode", text[start:end].strip())
        )
    return violations


def scan(paths: list[Path]) -> list[Violation]:
    out: list[Violation] = []
    for path in paths:
        if not path.is_file() or not is_scanned_path(path):
            continue
        out.extend(scan_file(path))
    return out


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def print_report(violations: list[Violation], file_count: int) -> None:
    for violation in violations:
        print(
            f"{display_path(violation.path)}:{violation.line}:{violation.column}: "
            f"{violation.kind}: {violation.context}"
        )
    print(f"dash_gate: {len(violations)} violation(s) in {file_count} file(s)")


def self_test() -> int:
    fixtures: dict[str, tuple[str, int, set[str]]] = {
        "prose.md": ("alpha -- beta\n", 1, {"prose"}),
        "banner.rs": ("// -- part --\nfn main() {}\n", 2, {"banner"}),
        "string.rs": ('const MSG: &str = "alpha -- beta";\n', 1, {"string"}),
        "arrow.txt": ("left <-- right\n", 1, {"arrow"}),
        "unicode.md": ("alpha \u2014 beta\n", 1, {"unicode"}),
        "cli.md": ("Run `cargo clippy -- -D warnings` before merging.\n", 0, set()),
        "mermaid.md": ("```mermaid\nA-->>B\nB --> C\n```\n", 0, set()),
        "html.md": ("<!-- generated -->\n", 0, set()),
        "rule.md": ("---\n| a | b |\n|---|---|\n", 0, set()),
        "shield.md": ("https://img.shields.io/badge/license-Apache--2.0-blue.svg\n", 0, set()),
        "anchor.md": ("[old](#a--b)\n", 0, set()),
        "separator.md": ("Run `cargo run -- --literal` to pass a separator.\n", 0, set()),
    }
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        for name, (content, expected_count, expected_kinds) in fixtures.items():
            path = temp / name
            path.write_text(content, encoding="utf-8")
            found = scan_file(path)
            kinds = {item.kind for item in found}
            if len(found) != expected_count or kinds != expected_kinds:
                failures.append(f"{name}: got {len(found)} {sorted(kinds)}, expected {expected_count} {sorted(expected_kinds)}")
    if failures:
        for failure in failures:
            print(f"dash_gate self-test FAIL: {failure}")
        return 1
    print("dash_gate self-test PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print violations (default)")
    parser.add_argument("--enforce", action="store_true", help="exit 1 when violations exist")
    parser.add_argument("--files", nargs="+", help="scan these files instead of tracked files")
    parser.add_argument("--self-test", action="store_true", help="run inline fixtures")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    paths = [Path(item).resolve() for item in args.files] if args.files else git_ls_files(ROOT)
    violations = scan(paths)
    print_report(violations, len(paths))
    if args.enforce and violations:
        print("dash_gate: FAILED (dash convention violation)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
