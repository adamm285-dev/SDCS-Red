#!/usr/bin/env python3
"""Diff-scoped AST mutation testing for SDCS_Red (Meta ACH verification).

Mutates only changed source lines (from `git diff` or explicit `--files`) inside
an isolated temporary copy of the project, runs the test command on each mutant,
and reports every mutant that survived (the test command still exited 0).

Designed for Bucket 6 (Meta ACH Mutation Check) in SDCS_Red:
- Automates the 2 to 3 Meta ACH mutations in tempfile.TemporaryDirectory() sandboxes.
- Zero external dependencies: Python stdlib only.
- Strict Windows PowerShell safety (no here-string hangs).
- Exit codes: 0 no surviving mutants (all killed), 1 surviving mutant(s) found, 2 usage/error.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

TEST_DIR_PREFIXES = ("tests/", "test/", "__tests__/")
TEXT_MUTATE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs", ".zig")
SUPPORTED_EXTS = (".py",) + TEXT_MUTATE_EXTS
SKIP_LINE_PREFIXES = ("//", "/*", "*", "import ", "export type ", "package ", "use ")

LEXICAL_RULES: List[Tuple[str, re.Pattern[str], str]] = [
    ("=== -> !==", re.compile(r"==="), "!=="),
    ("!== -> ===", re.compile(r"!=="), "==="),
    ("== -> !=", re.compile(r"(?<![=!<>])==(?!=)"), "!="),
    ("!= -> ==", re.compile(r"(?<![=!<>])!=(?!=)"), "=="),
    ("<= -> <", re.compile(r"<="), "<"),
    (">= -> >", re.compile(r">="), ">"),
    ("< -> <=", re.compile(r"(?<![<-])<(?![=<])"), "<="),
    ("> -> >=", re.compile(r"(?<![=>-])>(?![=>])"), ">="),
    ("&& -> ||", re.compile(r"&&"), "||"),
    ("|| -> &&", re.compile(r"\|\|"), "&&"),
    ("true -> false", re.compile(r"\btrue\b"), "false"),
    ("false -> true", re.compile(r"\bfalse\b"), "true"),
    ("+ -> -", re.compile(r"(?<=\s)\+(?=\s)"), "-"),
    ("- -> +", re.compile(r"(?<=\s)-(?=\s)"), "+"),
]


def is_test_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    base = os.path.basename(norm)
    if norm.startswith(TEST_DIR_PREFIXES) or "/tests/" in norm or "/test/" in norm:
        return True
    return base.startswith("test_") or any(
        base.endswith(suf)
        for suf in ("_test.py", "_test.go", "_test.rs", ".test.ts", ".test.js", ".spec.ts", ".spec.js")
    )


def run_git(repo: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
    )


def changed_source_lines(
    repo: str, base: str, include_tests: bool, include_untracked: bool
) -> Dict[str, List[int]]:
    proc = run_git(repo, "diff", "--unified=0", base)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git diff against {base} failed")
    targets: Dict[str, List[int]] = {}
    current: Optional[str] = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            rel = line[6:].strip().replace("\\", "/")
            if rel.endswith(SUPPORTED_EXTS) and (include_tests or not is_test_path(rel)):
                current = rel
                targets.setdefault(current, [])
            else:
                current = None
        elif line.startswith("@@ ") and current:
            for token in line.split(" "):
                if token.startswith("+"):
                    body = token[1:]
                    if "," in body:
                        start_s, count_s = body.split(",", 1)
                        start, count = int(start_s), int(count_s)
                    else:
                        start, count = int(body), 1
                    if count > 0:
                        targets[current].extend(range(start, start + count))
                    break
    if include_untracked:
        untracked = run_git(repo, "ls-files", "--others", "--exclude-standard")
        if untracked.returncode == 0:
            for raw_rel in untracked.stdout.splitlines():
                rel = raw_rel.strip().replace("\\", "/")
                if rel.endswith(SUPPORTED_EXTS) and (include_tests or not is_test_path(rel)):
                    full = os.path.join(repo, rel)
                    if os.path.isfile(full):
                        with open(full, encoding="utf-8", errors="replace") as handle:
                            count = len(handle.read().splitlines())
                        targets[rel] = list(range(1, count + 1))
    return {k: sorted(set(v)) for k, v in targets.items() if v}


def line_offsets(source: str) -> List[int]:
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def span_to_indices(offsets: List[int], node: ast.AST) -> Optional[Tuple[int, int]]:
    lineno = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    end_lineno = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if None in (lineno, col, end_lineno, end_col):
        return None
    if lineno < 1 or end_lineno > len(offsets) - 1:
        return None
    start = offsets[lineno - 1] + col
    end = offsets[end_lineno - 1] + end_col
    return (start, end) if 0 <= start < end else None


def mask_strings_and_comments(line: str) -> str:
    chars = list(line)
    i = 0
    n = len(chars)
    while i < n:
        ch = chars[i]
        if ch == "/" and i + 1 < n and chars[i + 1] == "/":
            for j in range(i, n):
                if chars[j] != "\n":
                    chars[j] = " "
            break
        if ch in ('"', "'", "`"):
            quote = ch
            chars[i] = " "
            i += 1
            while i < n:
                if chars[i] == "\\" and i + 1 < n:
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    continue
                cur = chars[i]
                if cur != "\n":
                    chars[i] = " "
                i += 1
                if cur == quote:
                    break
            continue
        i += 1
    return "".join(chars)


def generate_lexical_mutants(
    source: str, rel_path: str, target_lines: Optional[Sequence[int]]
) -> List[Dict[str, Any]]:
    allowed = set(target_lines) if target_lines is not None else None
    lines = source.splitlines(keepends=True)
    mutants: List[Dict[str, Any]] = []
    seen: set[Tuple[int, str]] = set()

    for idx, orig_line in enumerate(lines, 1):
        if allowed is not None and idx not in allowed:
            continue
        stripped = orig_line.strip()
        if not stripped or stripped.startswith(SKIP_LINE_PREFIXES):
            continue
        masked = mask_strings_and_comments(orig_line)
        for label, pat, repl in LEXICAL_RULES:
            if label in ("< -> <=", "> -> >=") and (
                ": " in masked
                and any(t in masked for t in ("Array<", "Map<", "Set<", "Promise<", "Vec<", "Option<", "Result<"))
            ):
                continue
            for match in pat.finditer(masked):
                mut_line = orig_line[: match.start()] + repl + orig_line[match.end() :]
                key = (idx, mut_line)
                if mut_line == orig_line or key in seen:
                    continue
                seen.add(key)
                new_src = "".join(lines[: idx - 1] + [mut_line] + lines[idx:])
                mutants.append({
                    "file": rel_path,
                    "line": idx,
                    "operator": label,
                    "before": orig_line.strip(),
                    "after": mut_line.strip(),
                    "source": new_src,
                })
                break
    return mutants


def generate_python_mutants(
    source: str, rel_path: str, target_lines: Optional[Sequence[int]]
) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    allowed = set(target_lines) if target_lines is not None else None
    lines = source.splitlines(keepends=True)
    offsets = line_offsets(source)
    mutants: List[Dict[str, Any]] = []
    seen: set[Tuple[int, str]] = set()

    cmp_ops = {
        ast.Eq: ("==", "!="),
        ast.NotEq: ("!=", "=="),
        ast.Lt: ("<", "<="),
        ast.LtE: ("<=", "<"),
        ast.Gt: (">", ">="),
        ast.GtE: (">=", ">"),
        ast.Is: (" is ", " is not "),
        ast.IsNot: (" is not ", " is "),
        ast.In: (" in ", " not in "),
        ast.NotIn: (" not in ", " in "),
    }
    bin_ops = {
        ast.Add: (" + ", " - "),
        ast.Sub: (" - ", " + "),
        ast.Mult: (" * ", " + "),
        ast.FloorDiv: (" // ", " / "),
    }

    def add_mutant(lineno: int, label: str, before_line: str, after_line: str, new_source: str) -> None:
        if new_source == source:
            return
        try:
            ast.parse(new_source)
        except SyntaxError:
            return
        key = (lineno, after_line)
        if key in seen:
            return
        seen.add(key)
        mutants.append({
            "file": rel_path,
            "line": lineno,
            "operator": label,
            "before": before_line.strip(),
            "after": after_line.strip(),
            "source": new_source,
        })

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", None)
        if lineno is None or lineno > len(lines):
            continue
        if allowed is not None and lineno not in allowed:
            continue
        orig_line = lines[lineno - 1]
        span = span_to_indices(offsets, node)

        if isinstance(node, ast.Compare) and len(node.ops) == 1 and span:
            pair = cmp_ops.get(type(node.ops[0]))
            snippet = source[span[0] : span[1]]
            if pair and pair[0] in snippet:
                replaced = snippet.replace(pair[0], pair[1], 1)
                new_src = source[: span[0]] + replaced + source[span[1] :]
                add_mutant(lineno, f"{pair[0].strip()} -> {pair[1].strip()}", orig_line, new_src.splitlines()[lineno - 1], new_src)

        elif isinstance(node, ast.BoolOp) and span:
            snippet = source[span[0] : span[1]]
            if isinstance(node.op, ast.And) and " and " in snippet:
                replaced = snippet.replace(" and ", " or ", 1)
                new_src = source[: span[0]] + replaced + source[span[1] :]
                add_mutant(lineno, "and -> or", orig_line, new_src.splitlines()[lineno - 1], new_src)
            elif isinstance(node.op, ast.Or) and " or " in snippet:
                replaced = snippet.replace(" or ", " and ", 1)
                new_src = source[: span[0]] + replaced + source[span[1] :]
                add_mutant(lineno, "or -> and", orig_line, new_src.splitlines()[lineno - 1], new_src)

        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and span:
            snippet = source[span[0] : span[1]]
            if snippet.startswith("not "):
                replaced = snippet[4:]
                new_src = source[: span[0]] + replaced + source[span[1] :]
                add_mutant(lineno, "remove not", orig_line, new_src.splitlines()[lineno - 1], new_src)

        elif isinstance(node, ast.BinOp) and span:
            pair = bin_ops.get(type(node.op))
            snippet = source[span[0] : span[1]]
            if pair and pair[0] in snippet:
                replaced = snippet.replace(pair[0], pair[1], 1)
                new_src = source[: span[0]] + replaced + source[span[1] :]
                add_mutant(lineno, f"{pair[0].strip()} -> {pair[1].strip()}", orig_line, new_src.splitlines()[lineno - 1], new_src)

        elif isinstance(node, ast.Constant) and span:
            if isinstance(node.value, bool):
                new_val = "False" if node.value else "True"
                new_src = source[: span[0]] + new_val + source[span[1] :]
                add_mutant(lineno, f"{node.value} -> {new_val}", orig_line, new_src.splitlines()[lineno - 1], new_src)
            elif isinstance(node.value, int) and node.value in (0, 1):
                new_val = "1" if node.value == 0 else "0"
                new_src = source[: span[0]] + new_val + source[span[1] :]
                add_mutant(lineno, f"{node.value} -> {new_val}", orig_line, new_src.splitlines()[lineno - 1], new_src)

        elif isinstance(node, ast.Return) and node.value is not None:
            if not (isinstance(node.value, ast.Constant) and node.value.value is None):
                indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]
                nl = "\n" if orig_line.endswith("\n") else ""
                mut_line = f"{indent}return None{nl}"
                new_src = "".join(lines[: lineno - 1] + [mut_line] + lines[lineno:])
                add_mutant(lineno, "return -> return None", orig_line, mut_line, new_src)

    mutants.sort(key=lambda m: (str(m["file"]), int(m["line"]), str(m["operator"])))
    return mutants


def generate_mutants(source: str, rel_path: str, target_lines: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    if rel_path.endswith(".py"):
        return generate_python_mutants(source, rel_path, target_lines)
    if rel_path.endswith(TEXT_MUTATE_EXTS):
        return generate_lexical_mutants(source, rel_path, target_lines)
    return []


def run_cmd(cmd: str, cwd: str, timeout: int) -> Tuple[int, bool]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, False
    except subprocess.TimeoutExpired:
        return -1, True


def copy_project(repo: str, dest: str) -> None:
    def ignore(_src: str, names: List[str]) -> List[str]:
        skip = {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".DS_Store",
            "node_modules",
            ".venv",
            "venv",
        }
        return [n for n in names if n in skip or n.endswith(".pyc")]

    shutil.copytree(repo, dest, dirs_exist_ok=True, symlinks=True, ignore=ignore)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cmd", required=True, help="test command that must exit 0 on unmodified code")
    parser.add_argument("--repo", default=".", help="project root directory (default: .)")
    parser.add_argument("--base", default="HEAD", help="git base revision for diff scope (default: HEAD)")
    parser.add_argument("--files", nargs="+", help="explicit source files (relative to --repo) instead of git diff")
    parser.add_argument("--include-tests", action="store_true", help="also mutate test files in git diff")
    parser.add_argument("--max-mutants", type=int, default=10, help="cap on mutants tested (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="seconds per mutant run (default: 30)")
    parser.add_argument("--json", dest="json_out", help="write structured mutation report to JSON file")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"mutate_diff.py: error: not a directory: {repo}", file=sys.stderr)
        return 2

    try:
        if args.files:
            targets: Dict[str, Optional[List[int]]] = {}
            for rel in args.files:
                norm_rel = rel.replace("\\", "/")
                full = os.path.join(repo, norm_rel)
                if not os.path.isfile(full):
                    raise RuntimeError(f"file not found: {norm_rel}")
                targets[norm_rel] = None
        else:
            targets = dict(changed_source_lines(repo, args.base, args.include_tests, include_untracked=True))
    except RuntimeError as exc:
        print(f"mutate_diff.py: error: {exc}", file=sys.stderr)
        return 2

    all_mutants: List[Dict[str, Any]] = []
    originals: Dict[str, str] = {}
    for rel, lines in sorted(targets.items()):
        full = os.path.join(repo, rel)
        if not os.path.isfile(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as handle:
            src = handle.read()
        originals[rel] = src
        all_mutants.extend(generate_mutants(src, rel, lines))

    truncated = len(all_mutants) > args.max_mutants
    mutants = all_mutants[: args.max_mutants]

    with tempfile.TemporaryDirectory(prefix="mutate-diff-") as scratch:
        copy_project(repo, scratch)
        base_code, base_timeout = run_cmd(args.cmd, scratch, args.timeout)
        if base_code != 0 or base_timeout:
            detail = f"timed out after {args.timeout}s" if base_timeout else f"exited {base_code}"
            print(f"mutate_diff.py: error: baseline test command failed ({detail}); fix baseline first", file=sys.stderr)
            return 2

        if not mutants:
            print("MUTATE: CLEAN (0 mutable lines in scope)")
            if args.json_out:
                with open(args.json_out, "w", encoding="utf-8") as handle:
                    json.dump({"verdict": "CLEAN", "total": 0, "killed": 0, "survived": [], "timed_out": 0}, handle, indent=2)
            return 0

        killed = 0
        timed_out = 0
        survived: List[Dict[str, Any]] = []
        start = time.monotonic()

        for mut in mutants:
            rel = str(mut["file"])
            target_path = os.path.join(scratch, rel)
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write(str(mut["source"]))
            try:
                rc, to = run_cmd(args.cmd, scratch, args.timeout)
            finally:
                with open(target_path, "w", encoding="utf-8") as handle:
                    handle.write(originals[rel])
            if to:
                timed_out += 1
                killed += 1
            elif rc != 0:
                killed += 1
            else:
                survived.append({
                    "file": rel,
                    "line": mut["line"],
                    "operator": mut["operator"],
                    "before": mut["before"],
                    "after": mut["after"],
                })

    elapsed = round(time.monotonic() - start, 2)
    tested = len(mutants)
    print(
        f"scope: {len(targets)} file(s), {tested} mutant(s) tested in {elapsed}s"
        + (f" (capped from {len(all_mutants)})" if truncated else "")
    )
    for item in survived:
        print(f"SURVIVED {item['file']}:{item['line']} [{item['operator']}] {item['before']}  ==>  {item['after']}")
    verdict = "CLEAN" if not survived else "SURVIVORS"
    print(f"MUTATE: {verdict} ({killed} killed, {len(survived)} survived, {timed_out} timed out)")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "verdict": verdict,
                    "total": tested,
                    "generated": len(all_mutants),
                    "killed": killed,
                    "timed_out": timed_out,
                    "survived": survived,
                },
                handle,
                indent=2,
            )
    return 0 if not survived else 1


if __name__ == "__main__":
    sys.exit(main())
