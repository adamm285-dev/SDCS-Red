"""SDCS_Red deterministic AST, polyglot, and call-graph pre-scanner.

Collects mechanical evidence (hollow wiring, sharp edges, loop/diff-ranked
hot-path hazards, blast radius, and optional Bookkeeper radar warnings) before
an adversarial review subagent or swarm wave runs. Zero external dependencies:
stdlib only.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
from collections.abc import Sequence
from pathlib import Path
from typing import Any

EXCLUDED_DIRS = frozenset(
    {
        ".agents",
        ".git",
        ".githooks",
        ".hg",
        ".idea",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".sdcs",
        ".svn",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "dist",
        "env",
        "lib",
        "node_modules",
        "sessions",
        "targets",
        "third_party",
        "vendor",
        "venv",
    }
)

_CPP_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cu", ".cuh"})
_APPLE_SUFFIXES = frozenset({".swift", ".m", ".mm"})
_JVM_SUFFIXES = frozenset({".java", ".kt", ".kts", ".scala"})
_SYSTEMS_SUFFIXES = frozenset({".zig", ".nim"})
_RUBY_PHP_SUFFIXES = frozenset({".rb", ".php"})
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh"})
_BATCH_SUFFIXES = frozenset({".bat", ".cmd"})
_PS_SUFFIXES = frozenset({".ps1", ".psm1", ".psd1"})
SCRIPT_SUFFIXES = _SHELL_SUFFIXES | _BATCH_SUFFIXES | _PS_SUFFIXES
POLYGLOT_SUFFIXES = (
    frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".dart", ".go", ".rs"})
    | _CPP_SUFFIXES
    | _APPLE_SUFFIXES
    | _JVM_SUFFIXES
    | _SYSTEMS_SUFFIXES
    | _RUBY_PHP_SUFFIXES
    | SCRIPT_SUFFIXES
)
SUPPORTED_SUFFIXES = frozenset({".py"}) | POLYGLOT_SUFFIXES
_TEST_DIR_NAMES = frozenset({"tests", "test", "__tests__", "spec", "specs"})

ENTRY_SYMBOL_NAMES = frozenset({"main", "cli", "app"})
_ENTRYPOINT_FILENAMES = frozenset({"cli.py", "__main__.py", "main.py", "app.py", "server.py"})
_ENTRYPOINT_FUNCTIONS = frozenset(
    {
        "main",
        "cli",
        "app",
        "run",
        "create_app",
        "create_mcp_server",
        "build_server",
        "run_mcp_server",
    }
)
_HOLLOW_EXEMPT_BASES = frozenset(
    {
        "Protocol",
        "ABC",
        "Exception",
        "BaseException",
        "NodeVisitor",
        "NodeTransformer",
        "BaseHTTPRequestHandler",
    }
)
_HOLLOW_EXEMPT_METHODS = frozenset(
    {
        "__init__",
        "__enter__",
        "__exit__",
        "__aenter__",
        "__aexit__",
        "log_message",
    }
)
_ISLAND_EXEMPT_DECORATORS = frozenset(
    {
        "abstractmethod",
        "callback",
        "command",
        "delete",
        "fixture",
        "get",
        "hookimpl",
        "overload",
        "patch",
        "post",
        "prompt",
        "put",
        "resource",
        "route",
        "tool",
    }
)

SUBPROCESS_ATTRS = frozenset({"run", "Popen", "call", "check_output", "check_call"})
OS_EXEC_ATTRS = frozenset({"system", "popen"})
SHARP_BRANCH_NAMES = frozenset({"dry_run", "force", "bypass", "skip"})
_CONFIG_CONTAINER_NAMES = frozenset(
    {"args", "opts", "options", "config", "cfg", "flags", "params", "settings"}
)
FALLBACK_EXCEPTION_NAMES = frozenset(
    {"Exception", "BaseException", "NotImplementedError", "ImportError", "ModuleNotFoundError"}
)
_HIGH_PRIORITY_FALLBACK_EXCEPTIONS = frozenset(
    {"bare except", "NotImplementedError", "ImportError", "ModuleNotFoundError"}
)
_PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_HIGH_HAZARD_KINDS = frozenset({"shell_injection_risk", "subprocess_call", "recursive_walk", "sleep_call", "unbounded_http_call"})

_TOOL_POISON_INSTRUCTION_RE = re.compile(
    r"(?i)\b(?:always\s+(?:forward|send|pass|include|exfiltrate|leak|override|ignore)|"
    r"do\s+not\s+(?:validate|check|sanitize|enforce|block)|"
    r"ignore\s+(?:previous|all|safety|guardrail|rule)|"
    r"bypass\s+(?:auth|token|permission|gate|approval)|"
    r"system\s+prompt\s+override|"
    r"from\s+now\s+on\s+always)\b"
)
_POLYGLOT_EMPTY_JS_RE = re.compile(
    r"(?ms)\b(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*(?::\s*[^\{;\n]+)?\{\s*\}"
)
_POLYGLOT_EMPTY_GO_RE = re.compile(
    r"(?ms)\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)(?:\s*(?:\([^)]*\)|[^{\n]+))?\{\s*\}"
)
_POLYGLOT_EMPTY_RUST_RE = re.compile(
    r"(?ms)\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\([^)]*\)(?:\s*->\s*[^{\n]+)?\{\s*(?:(?:todo|unimplemented)!\s*\([^;]*\)\s*;?\s*)?\}"
)
_POLYGLOT_EMPTY_SWIFT_RE = re.compile(
    r"(?ms)\bfunc\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\([^)]*\)(?:\s*(?:throws|async|rethrows)\s*)*(?:\s*->\s*[^{\n]+)?\{\s*\}"
)
_SWIFT_FORCE_UNWRAP_RE = re.compile(r"(?m)\b[A-Za-z_0-9\]\)]+!\.(?:[A-Za-z_]|\()")
_POLYGLOT_THROW_TODO_RE = re.compile(
    r"(?i)\bthrow\s+new\s+(?:Error|UnimplementedError)\s*\(\s*[\"'][^\"']*(?:todo|not\s+implemented|unimplemented)[^\"']*[\"']"
)
_POLYGLOT_UNIMPL_CALL_RE = re.compile(r"\b(?:UnimplementedError\s*\(|(?:todo|unimplemented)!\s*\()")
_POLYGLOT_CATCH_EMPTY_RE = re.compile(r"(?ms)\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}")
_POLYGLOT_CATCH_RETURN_RE = re.compile(
    r"(?ms)\bcatch\s*(?:\([^)]*\))?\s*\{\s*return\s+(null|nullptr|NULL|undefined|false|0|\"\"|''|\[\s*\]|\{\s*\})\s*;?\s*\}"
)
_POLYGLOT_ENV_RE = re.compile(
    r"(?:\b(?:process\.env|import\.meta\.env|Deno\.env\.get|os\.Getenv|std::env::var|Platform\.environment)\b|\bstd::getenv\s*\(|(?<![.\w:])getenv\s*\()"
)
_MD_IMAGE_LEAK_RE = re.compile(r'!\[[^\]]*\]\([^)]+\)', re.IGNORECASE)
# Shell, Batch & PowerShell Trap Detectors
_SHELL_UNQUOTED_EVAL_RE = re.compile(r'''(?m)(?<![.\w])eval\s+["']?\$[A-Za-z_0-9{]''')
_SHELL_QUOTED_GLOB_ARRAY_RE = re.compile(r'''(?m)\b[A-Za-z_0-9]+\s*=\s*\([^)]*"[\*\?][^"\)]*"[^)]*\)''')
_BATCH_DELAYED_EXPANSION_RE = re.compile(r'''(?im)^\s*setlocal\s+enabledelayedexpansion\b''')
_BATCH_IF_ERRORLEVEL_RE = re.compile(r'''(?im)\bif\s+(?:not\s+)?errorlevel\s+\d+\b''')
_PS_READ_HOST_RE = re.compile(r'''(?im)\bRead-Host\b''')

_POLYGLOT_UNSAFE_SINK_RE = re.compile(
    r"(?:\beval\s*\(|\bdangerouslySetInnerHTML\b|\.(?:innerHTML|outerHTML)\s*=|\bdocument\.write\s*\()"
)
_POLYGLOT_SUBPROCESS_RE = re.compile(
    r"(?:\b(?:execSync|spawnSync|execFileSync|exec\.Command)\b|Command::new\b|\bstd::system\s*\(|(?<![.\w:])(?:_popen|popen)\s*\()"
)
_CPP_PY_HANDLE_MEMBER_RE = re.compile(
    r"(?m)^[ \t]*(?:mutable\s+|static\s+)*(?:nanobind|nb|pybind11|py)::(?:callable|function|object)\b[^;()\n]*;"
)
_CPP_UNCHECKED_PARSE_RE = re.compile(
    r"\b(?:std::sto(?:i|l|ll|ul|ull|f|d|ld)\s*\([^,\n)]+\)|(?:std::)?strto(?:l|ll|ul|ull|d|f)\s*\([^,\n]+,\s*(?:nullptr|NULL|0)\b)"
)
_POLYGLOT_FS_READ_RE = re.compile(r"\b(?:readFileSync|readdirSync)\b")
_POLYGLOT_LOOP_START_RE = re.compile(
    r"\b(?:for\s*\(|for\s+[A-Za-z_][^{;\n]*\b(?:range|in)\b|while\s*\(|loop\s*\{)|\.(?:forEach|map)\s*\("
)
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _is_test_relpath(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    name = parts[-1].lower()
    if any(part.lower() in _TEST_DIR_NAMES for part in parts[:-1]):
        return True
    if name.startswith("test_"):
        return True
    stem, _, ext = name.rpartition(".")
    if not ext:
        return False
    return stem.endswith("_test") or stem.endswith(".test") or stem.endswith(".spec")


def _has_excluded_dir(rel_parts: Sequence[str], extra_excluded: frozenset[str] | set[str] = frozenset()) -> bool:
    excluded = EXCLUDED_DIRS | extra_excluded if extra_excluded else EXCLUDED_DIRS
    return any(part in excluded or part.endswith(".egg-info") for part in rel_parts)


def _discover_python_files(
    repo_root: Path, extra_excluded: frozenset[str] | set[str] = frozenset()
) -> tuple[list[Path], list[Path]]:
    """Return (source_files, test_files) across Python files outside excluded dirs."""
    source_files: list[Path] = []
    test_files: list[Path] = []
    excluded = EXCLUDED_DIRS | extra_excluded if extra_excluded else EXCLUDED_DIRS
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in excluded and not d.endswith(".egg-info")
        )
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            path = Path(dirpath) / fname
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                continue
            if _is_test_relpath(rel.as_posix()):
                test_files.append(path)
            else:
                source_files.append(path)
    return source_files, test_files


def _discover_polyglot_files(
    repo_root: Path, extra_excluded: frozenset[str] | set[str] = frozenset()
) -> tuple[list[Path], list[Path]]:
    """Return (source_files, test_files) across polyglot files outside excluded dirs."""
    source_files: list[Path] = []
    test_files: list[Path] = []
    excluded = EXCLUDED_DIRS | extra_excluded if extra_excluded else EXCLUDED_DIRS
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in excluded and not d.endswith(".egg-info")
        )
        for fname in sorted(filenames):
            path = Path(dirpath) / fname
            if path.suffix.lower() not in POLYGLOT_SUFFIXES:
                continue
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                continue
            if _is_test_relpath(rel.as_posix()):
                test_files.append(path)
            else:
                source_files.append(path)
    return source_files, test_files


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _parse_unified_diff_lines(diff_text: str, changed_lines_by_file: dict[str, set[int]]) -> None:
    current_file: str | None = None
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            target = raw_line[4:]
            if target == "/dev/null":
                current_file = None
            elif target.startswith("b/"):
                current_file = target[2:]
            else:
                current_file = target
            continue
        if current_file is None:
            continue
        m = _HUNK_HEADER_RE.match(raw_line)
        if not m:
            continue
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count > 0:
            changed_lines_by_file.setdefault(current_file, set()).update(
                range(start, start + count)
            )


def _discover_git_diff_scope(
    repo_root: Path, git_ref: str, extra_excluded: frozenset[str] | set[str] = frozenset()
) -> tuple[list[str], list[str], dict[str, set[int]], str | None]:
    """Discover modified, staged, and untracked files (plus unscanned files) via git."""
    worktree_check = _run_git(repo_root, ["rev-parse", "--is-inside-work-tree"])
    if worktree_check is None or worktree_check.returncode != 0:
        return [], [], {}, "not a git worktree; falling back to default scope"
    if worktree_check.stdout.strip().lower() != "true":
        return [], [], {}, "not a git worktree; falling back to default scope"

    verify_proc = _run_git(repo_root, ["rev-parse", "--verify", "--quiet", git_ref])
    has_ref = verify_proc is not None and verify_proc.returncode == 0
    if not has_ref and git_ref != "HEAD":
        return [], [], {}, f"git ref '{git_ref}' not found; falling back to default scope"

    rel_candidates: set[str] = set()
    changed_lines_by_file: dict[str, set[int]] = {}

    if has_ref:
        diff_names = _run_git(repo_root, ["diff", "--name-only", "--diff-filter=ACMRTUXB", git_ref])
        if diff_names is not None and diff_names.returncode == 0:
            for line in diff_names.stdout.splitlines():
                if line.strip():
                    rel_candidates.add(line.strip().replace("\\", "/"))

        diff_patch = _run_git(repo_root, ["-c", "diff.noprefix=false", "diff", "-U0", git_ref])
        if diff_patch is not None and diff_patch.returncode == 0:
            _parse_unified_diff_lines(diff_patch.stdout, changed_lines_by_file)

    cached_names = _run_git(
        repo_root, ["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"]
    )
    if cached_names is not None and cached_names.returncode == 0:
        for line in cached_names.stdout.splitlines():
            if line.strip():
                rel_candidates.add(line.strip().replace("\\", "/"))

    cached_patch = _run_git(repo_root, ["-c", "diff.noprefix=false", "diff", "--cached", "-U0"])
    if cached_patch is not None and cached_patch.returncode == 0:
        _parse_unified_diff_lines(cached_patch.stdout, changed_lines_by_file)

    untracked_names = _run_git(repo_root, ["ls-files", "--others", "--exclude-standard"])
    untracked_set: set[str] = set()
    if untracked_names is not None and untracked_names.returncode == 0:
        for line in untracked_names.stdout.splitlines():
            clean = line.strip().replace("\\", "/")
            if clean:
                rel_candidates.add(clean)
                untracked_set.add(clean)

    filtered_files: list[str] = []
    unscanned_files: list[str] = []
    for rel in sorted(rel_candidates):
        rel_obj = Path(rel)
        if _has_excluded_dir(rel_obj.parts[:-1], extra_excluded=extra_excluded):
            continue
        disk_path = (repo_root / rel_obj).resolve()
        if not disk_path.is_file():
            continue
        if disk_path.suffix.lower() not in SUPPORTED_SUFFIXES:
            unscanned_files.append(rel)
            continue
        filtered_files.append(rel)
        if rel in untracked_set or not has_ref:
            line_count = max(
                1, len(disk_path.read_text(encoding="utf-8", errors="replace").splitlines())
            )
            changed_lines_by_file.setdefault(rel, set()).update(range(1, line_count + 1))

    return filtered_files, unscanned_files, changed_lines_by_file, None


def _resolve_target_files(
    repo_root: Path,
    explicit_files: list[str] | None,
    all_sources: list[Path],
    git_diff_files: list[str] | None = None,
    git_diff_active: bool = False,
) -> tuple[list[Path], str]:
    """Resolve target source/test files and report which scoping mode was used."""

    def _resolve_list(raw_items: list[str], out: list[Path], seen: set[Path]) -> None:
        for raw_item in raw_items:
            candidate = Path(raw_item)
            if not candidate.is_absolute():
                in_repo = (repo_root / candidate).resolve()
                candidate = in_repo if in_repo.exists() else candidate.resolve()
            else:
                candidate = candidate.resolve()
            if (
                candidate.is_file()
                and candidate.suffix.lower() in SUPPORTED_SUFFIXES
                and candidate not in seen
            ):
                seen.add(candidate)
                out.append(candidate)

    if git_diff_active:
        resolved: list[Path] = []
        seen: set[Path] = set()
        if git_diff_files:
            _resolve_list(git_diff_files, resolved, seen)
        if explicit_files:
            _resolve_list(explicit_files, resolved, seen)
        return resolved, "git_diff"

    if explicit_files:
        resolved = []
        seen = set()
        _resolve_list(explicit_files, resolved, seen)
        return resolved, "explicit_files"

    return list(all_sources), "repo_default"


def _parse_file(path: Path) -> tuple[str, ast.Module | None]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return text, None
    return text, tree


def _collect_imported_module_paths(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Extracts imported module paths and dotted string literals from a Python AST."""
    imported_paths: set[str] = set()
    dotted_strings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_paths.add(alias.name)
                if alias.name.startswith("src."):
                    imported_paths.add(alias.name[4:])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_paths.add(node.module)
                if node.module.startswith("src."):
                    imported_paths.add(node.module[4:])
                for alias in node.names:
                    full = f"{node.module}.{alias.name}"
                    imported_paths.add(full)
                    if node.module.startswith("src."):
                        imported_paths.add(f"{node.module[4:]}.{alias.name}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.strip()
            if val and " " not in val and "." in val:
                dotted_strings.add(val)
                if val.startswith("src."):
                    dotted_strings.add(val[4:])
    return imported_paths, dotted_strings


def _collect_symbol_ref_lines(tree: ast.Module) -> dict[str, set[int]]:
    refs: dict[str, set[int]] = {}
    for node in ast.walk(tree):
        ln = getattr(node, "lineno", 0) or 0
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Load, ast.Del)):
            refs.setdefault(node.id, set()).add(ln)
        elif isinstance(node, ast.Attribute):
            refs.setdefault(node.attr, set()).add(ln)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                refs.setdefault(alias.name, set()).add(ln)
    return refs


def _extract_init_exports(tree: ast.Module) -> set[str]:
    import_exports: set[str] = set()
    explicit_all: set[str] = set()
    has_all = False
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    import_exports.add(alias.asname or alias.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
                has_all = True
                if node.value is not None:
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            explicit_all.add(sub.value)
    return explicit_all if has_all else import_exports


def _extract_pyproject_scripts(repo_root: Path) -> set[str]:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        return set()
    try:
        text = pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    sections = re.findall(r"(?ms)^\[project\.(?:gui-)?scripts\]\s*\n(.*?)(?=^\[|\Z)", text)
    if not sections:
        return set()
    symbols: set[str] = set()
    for block in sections:
        for m in re.finditer(r'=\s*["\'][^"\']+:([A-Za-z_][A-Za-z0-9_]*)["\']', block):
            symbols.add(m.group(1))
    return symbols


def _prod_callers_for(
    symbol: str,
    def_rel: str,
    def_start: int,
    def_end: int,
    refs_by_prod_file: dict[str, dict[str, set[int]]],
) -> list[str]:
    callers: list[str] = []
    for rel_path, ref_map in refs_by_prod_file.items():
        ref_lines = ref_map.get(symbol)
        if not ref_lines:
            continue
        if rel_path != def_rel or any(ln < def_start or ln > def_end for ln in ref_lines):
            callers.append(rel_path)
    return sorted(callers)


def _call_dotted_name(node: ast.expr) -> str:
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            names.add(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.add(dec.attr)
        elif isinstance(dec, ast.Call):
            names.add(_call_dotted_name(dec.func).split(".")[-1])
    return names


def _is_hollow_exempt_class(cls_node: ast.ClassDef) -> bool:
    for base in cls_node.bases:
        cur = base.value if isinstance(base, ast.Subscript) else base
        base_name = _call_dotted_name(cur).split(".")[-1]
        if base_name in _HOLLOW_EXEMPT_BASES or base_name.endswith("Error"):
            return True
    return False


def _is_object_only_bases(class_node: ast.ClassDef | None) -> bool:
    if class_node is None or not class_node.bases:
        return True
    return all(isinstance(b, ast.Name) and b.id == "object" for b in class_node.bases)


def _strip_leading_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _hollow_reason(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    class_node: ast.ClassDef | None = None,
) -> str | None:
    if class_node is not None:
        if _is_hollow_exempt_class(class_node):
            return None
        if fn.name in _HOLLOW_EXEMPT_METHODS or fn.name.startswith("visit_"):
            return None
    effective = _strip_leading_docstring(fn.body)
    if not effective:
        return "empty function body"
    if len(effective) != 1:
        return None
    stmt = effective[0]
    if isinstance(stmt, ast.Pass):
        return "body is only pass"
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    ):
        return "body is only Ellipsis (...)"
    if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call):
        raised = _call_dotted_name(stmt.exc.func).split(".")[-1]
        if raised == "NotImplementedError":
            return "raises NotImplementedError unconditionally"
    if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Name):
        if stmt.exc.id == "NotImplementedError":
            return "raises NotImplementedError unconditionally"
    if isinstance(stmt, ast.Return):
        val = stmt.value
        if val is None or (isinstance(val, ast.Constant) and val.value is None):
            return "unconditionally returns None"
        if isinstance(val, ast.List) and not val.elts:
            return "unconditionally returns []"
        if isinstance(val, ast.Dict) and not val.keys:
            return "unconditionally returns {}"
    return None


def _all_param_names(args: ast.arguments) -> list[str]:
    names: list[str] = []
    for group in (args.posonlyargs, args.args, args.kwonlyargs):
        for arg in group:
            names.append(arg.arg)
    return names


def _bound_arg_names(args: ast.arguments) -> set[str]:
    names = {a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _collect_loaded_names_in_fn_scope(
    nodes: Sequence[ast.AST],
    shadowed: frozenset[str] = frozenset(),
) -> set[str]:
    """Collect loaded/deleted identifier names across function bodies with def/lambda shadowing."""
    used: set[str] = set()
    stack: list[tuple[ast.AST, frozenset[str]]] = [(n, shadowed) for n in nodes]
    while stack:
        node, cur_shadowed = stack.pop()
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Load, ast.Del)) and node.id not in cur_shadowed:
                used.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                stack.append((dec, cur_shadowed))
            for dflt in node.args.defaults:
                stack.append((dflt, cur_shadowed))
            for kdflt in node.args.kw_defaults:
                if kdflt is not None:
                    stack.append((kdflt, cur_shadowed))
            all_fn_args = (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
                + ([node.args.vararg] if node.args.vararg is not None else [])
                + ([node.args.kwarg] if node.args.kwarg is not None else [])
            )
            for arg in all_fn_args:
                if arg.annotation is not None:
                    stack.append((arg.annotation, cur_shadowed))
            if node.returns is not None:
                stack.append((node.returns, cur_shadowed))
            inner_shadowed = cur_shadowed | frozenset(_bound_arg_names(node.args))
            for stmt in node.body:
                stack.append((stmt, inner_shadowed))
        elif isinstance(node, ast.Lambda):
            for dflt in node.args.defaults:
                stack.append((dflt, cur_shadowed))
            for kdflt in node.args.kw_defaults:
                if kdflt is not None:
                    stack.append((kdflt, cur_shadowed))
            inner_shadowed = cur_shadowed | frozenset(_bound_arg_names(node.args))
            stack.append((node.body, inner_shadowed))
        else:
            for child in ast.iter_child_nodes(node):
                stack.append((child, cur_shadowed))
    return used


def _unused_params(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    class_node: ast.ClassDef | None = None,
) -> list[str]:
    if class_node is not None and not _is_object_only_bases(class_node):
        return []
    if fn.name.startswith(("pytest_", "visit_", "do_", "log_")) or (
        fn.name.startswith("__") and fn.name.endswith("__")
    ):
        return []
    if fn.name == "lifespan":
        decs = _decorator_names(fn)
        if "asynccontextmanager" in decs:
            all_args = fn.args.posonlyargs + fn.args.args
            pnames = [a.arg for a in all_args if a.arg not in {"self", "cls"}]
            if pnames == ["app"] and not fn.args.vararg and not fn.args.kwonlyargs and not fn.args.kwarg:
                return []
    params = _all_param_names(fn.args)
    if not params:
        return []
    used_names = _collect_loaded_names_in_fn_scope(fn.body)
    if "locals" in used_names or "vars" in used_names:
        return []
    unused: list[str] = []
    for name in params:
        if name in {"self", "cls"} or name.startswith("_"):
            continue
        if name not in used_names:
            unused.append(name)
    return unused


def _empty_return_label(expr: ast.expr | None) -> str | None:
    if expr is None:
        return "None"
    if isinstance(expr, ast.Constant):
        if expr.value in (None, False, 0, ""):
            return repr(expr.value)
    if isinstance(expr, ast.List) and not expr.elts:
        return "[]"
    if isinstance(expr, ast.Dict) and not expr.keys:
        return "{}"
    if isinstance(expr, ast.Tuple) and not expr.elts:
        return "()"
    return None


def _handler_exception_label(handler: ast.ExceptHandler) -> str:
    if handler.type is None:
        return "bare except"
    if isinstance(handler.type, ast.Tuple):
        names = [_call_dotted_name(elt) or ast.dump(elt) for elt in handler.type.elts]
        return ", ".join(names)
    return _call_dotted_name(handler.type) or ast.dump(handler.type)


def _is_broad_or_stub_handler(label: str) -> bool:
    if label == "bare except":
        return True
    parts = [p.strip().split(".")[-1] for p in label.split(",")]
    return any(p in FALLBACK_EXCEPTION_NAMES for p in parts)


def _fallback_priority(label: str, ret_value: str, in_diff: bool) -> str:
    parts = {p.strip().split(".")[-1] for p in label.split(",")}
    if label in _HIGH_PRIORITY_FALLBACK_EXCEPTIONS or (parts & _HIGH_PRIORITY_FALLBACK_EXCEPTIONS):
        return "HIGH"
    if in_diff:
        return "HIGH"
    if ret_value != "pass":
        return "MEDIUM"
    return "LOW"


def _hazard_priority(kind: str, in_loop: bool, in_diff: bool) -> str:
    if kind == "pruned_walk":
        return "LOW"
    if in_loop or (in_diff and kind in _HIGH_HAZARD_KINDS):
        return "HIGH"
    if kind in _HIGH_HAZARD_KINDS or in_diff:
        return "MEDIUM"
    return "LOW"


def _extract_silent_fallback(handler: ast.ExceptHandler) -> tuple[str, str] | None:
    label = _handler_exception_label(handler)
    if not _is_broad_or_stub_handler(label):
        return None
    has_raise = any(isinstance(sub, ast.Raise) for sub in ast.walk(handler))
    if has_raise:
        return None
    if len(handler.body) == 1:
        stmt = handler.body[0]
        if isinstance(stmt, ast.Pass):
            return label, "pass"
        if isinstance(stmt, ast.Return):
            ret = _empty_return_label(stmt.value)
            if ret is not None:
                return label, ret
    return None


def _is_bool_annotation(ann: ast.expr | None) -> bool:
    if ann is None:
        return False
    return _call_dotted_name(ann).split(".")[-1] == "bool"


def _boolean_flag_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    flags: list[str] = []
    positional = list(fn.args.posonlyargs) + list(fn.args.args)
    defaults = fn.args.defaults
    default_offset = len(positional) - len(defaults)
    for idx, arg in enumerate(positional):
        if arg.arg in {"self", "cls"} or arg.arg.startswith("_"):
            continue
        dflt = defaults[idx - default_offset] if idx >= default_offset else None
        is_bool_default = isinstance(dflt, ast.Constant) and isinstance(dflt.value, bool)
        if is_bool_default or _is_bool_annotation(arg.annotation):
            flags.append(arg.arg)
    for arg, dflt in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
        if arg.arg in {"self", "cls"} or arg.arg.startswith("_"):
            continue
        is_bool_default = isinstance(dflt, ast.Constant) and isinstance(dflt.value, bool)
        if is_bool_default or _is_bool_annotation(arg.annotation):
            flags.append(arg.arg)
    return flags


def _rel_posix(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _filter_scoped_problems(problems: list[str], scoped_files: set[str] | None) -> list[str]:
    if scoped_files is None:
        return problems
    filtered: list[str] = []
    for prob in problems:
        m = re.match(r"^([^:\n]+):\d+:", prob)
        if m:
            prob_rel = m.group(1).replace("\\", "/")
            if prob_rel not in scoped_files:
                continue
        filtered.append(prob)
    return filtered


def _load_gate_l_problems(
    repo_root: Path,
    scoped_files: set[str] | None = None,
) -> tuple[list[str], str | None]:
    if importlib.util.find_spec("sdcs.verifier.mocks") is None:
        sdcs_bin = shutil.which("sdcs")
        if sdcs_bin is None:
            return [], "sdcs.verifier.mocks not installed in current Python environment"
        try:
            proc = subprocess.run(
                [sdcs_bin, "verify", "--mocks", "--repo-root", str(repo_root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return [], f"sdcs CLI verify --mocks failed: {exc}"
        if proc.returncode == 0:
            return [], None
        problems = [
            line[4:].strip()
            for line in (proc.stdout + "\n" + proc.stderr).splitlines()
            if line.startswith("  - ") and line[4:].strip()
        ]
        if not problems:
            return [], f"sdcs CLI verify --mocks exited {proc.returncode}"
        return _filter_scoped_problems(problems, scoped_files), None

    from sdcs.verifier.mocks import check_mock_ledger

    report = check_mock_ledger(repo_root)
    return _filter_scoped_problems(list(report.problems), scoped_files), None


def _load_radar_warnings(
    repo_root: Path,
    target_paths: list[Path],
    symbols: list[str],
) -> dict[str, Any]:
    if not (repo_root / "decisions.md").is_file():
        return {"available": False, "reason": "decisions.md not found", "warnings": []}

    rel_tokens = [_rel_posix(repo_root, p) for p in target_paths[:8]]
    sym_tokens = symbols[:16]
    query = " ".join(rel_tokens + sym_tokens).strip()
    if not query:
        return {"available": True, "warnings": []}

    if importlib.util.find_spec("sdcs.bookkeeper") is None:
        sdcs_bin = shutil.which("sdcs")
        if sdcs_bin is None:
            return {"available": False, "reason": "sdcs.bookkeeper not installed", "warnings": []}
        try:
            proc = subprocess.run(
                [sdcs_bin, "bookkeeper", "radar", query, "--json", "--repo-root", str(repo_root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"available": False, "reason": f"sdcs CLI radar failed: {exc}", "warnings": []}
        if proc.returncode != 0:
            return {
                "available": False,
                "reason": f"sdcs CLI radar exited {proc.returncode}",
                "warnings": [],
            }
        try:
            res = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {
                "available": False,
                "reason": "sdcs CLI radar returned invalid JSON",
                "warnings": [],
            }
        return {
            "available": True,
            "choice": res.get("choice", "NO_MATCH"),
            "noul": res.get("noul", 0.0),
            "warnings": res.get("matches", []),
        }

    from sdcs.bookkeeper import decide

    res = decide(repo_root, query, questions=sym_tokens[:4] or None, include_warehouse=True)
    return {
        "available": True,
        "choice": res.get("choice", "NO_MATCH"),
        "noul": res.get("noul", 0.0),
        "warnings": res.get("matches", []),
    }


def _scan_function_details(
    rel_file: str,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    qualname: str,
    skip_stub_checks: bool,
    hollow_stubs: list[dict[str, Any]],
    decorative_params: list[dict[str, Any]],
    sharp_edges: list[dict[str, Any]],
    class_node: ast.ClassDef | None = None,
) -> None:
    decs = _decorator_names(fn)
    is_abstract_or_overload = bool(decs & {"abstractmethod", "overload"})

    if not skip_stub_checks and not is_abstract_or_overload:
        reason = _hollow_reason(fn, class_node=class_node)
        if reason is not None:
            hollow_stubs.append(
                {
                    "file": rel_file,
                    "line": fn.lineno,
                    "symbol": qualname,
                    "reason": reason,
                }
            )
        if "property" not in decs:
            for pname in _unused_params(fn, class_node=class_node):
                decorative_params.append(
                    {
                        "file": rel_file,
                        "line": fn.lineno,
                        "symbol": qualname,
                        "param": pname,
                    }
                )

    for bparam in _boolean_flag_params(fn):
        sharp_edges.append(
            {
                "file": rel_file,
                "line": fn.lineno,
                "kind": "boolean_flag_param",
                "symbol": qualname,
                "detail": f"parameter '{bparam}' toggles control flow",
            }
        )

    is_tool_surface = fn.name.startswith("execute_") or fn.name.startswith("tool_") or bool(decs & {"tool", "call_tool", "command"})
    if is_tool_surface:
        sharp_edges.append(
            {
                "file": rel_file,
                "line": fn.lineno,
                "kind": "cli_or_mcp_surface",
                "symbol": qualname,
                "detail": f"entrypoint or tool surface with {len(_all_param_names(fn.args))} parameter(s)",
            }
        )
        # Check for tool docstring prompt injection / instruction poisoning (AIGoat MCP03)
        doc = ast.get_docstring(fn)
        if doc and _TOOL_POISON_INSTRUCTION_RE.search(doc):
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": fn.lineno,
                    "kind": "mcp_tool_poisoning",
                    "symbol": qualname,
                    "detail": "tool docstring contains instruction poisoning keywords (prompt-injection / override risk)",
                }
            )

        # Check for untyped or loose parameter annotations (AutoMalTool MCP confused deputy risk)
        for arg in fn.args.args + fn.args.kwonlyargs:
            if arg.arg in {"self", "cls"}:
                continue
            if arg.annotation is None:
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": arg.lineno if hasattr(arg, "lineno") else fn.lineno,
                        "kind": "mcp_untyped_param_sink",
                        "symbol": qualname,
                        "detail": f"tool parameter '{arg.arg}' has no type annotation (confused-deputy / unvalidated injection risk)",
                    }
                )
            else:
                ann_str = ast.unparse(arg.annotation).replace(" ", "")
                if ann_str in {"dict", "Dict", "Any", "object", "dict[str,Any]", "Dict[str,Any]", "typing.Any", "typing.Dict"}:
                    sharp_edges.append(
                        {
                            "file": rel_file,
                            "line": arg.lineno if hasattr(arg, "lineno") else fn.lineno,
                            "kind": "mcp_untyped_param_sink",
                            "symbol": qualname,
                            "detail": f"tool parameter '{arg.arg}' typed as loose '{ann_str}' without schema constraints (confused-deputy risk)",
                        }
                    )
        if fn.args.kwarg is not None:
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": fn.args.kwarg.lineno if hasattr(fn.args.kwarg, "lineno") else fn.lineno,
                    "kind": "mcp_untyped_param_sink",
                    "symbol": qualname,
                    "detail": f"tool accepts arbitrary **{fn.args.kwarg.arg} kwargs without explicit parameter boundaries",
                }
            )


def _child_stmt_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    blocks: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        sub = getattr(stmt, attr, None)
        if isinstance(sub, list) and sub:
            blocks.append(sub)
    for handler in getattr(stmt, "handlers", ()) or ():
        if getattr(handler, "body", None):
            blocks.append(handler.body)
    for case in getattr(stmt, "cases", ()) or ():
        if getattr(case, "body", None):
            blocks.append(case.body)
    return blocks


def _scan_nested_stmts(
    rel_file: str,
    stmts: list[ast.stmt],
    scope_prefix: str,
    skip_stub_checks: bool,
    hollow_stubs: list[dict[str, Any]],
    decorative_params: list[dict[str, Any]],
    sharp_edges: list[dict[str, Any]],
    enclosing_class: ast.ClassDef | None = None,
    is_class_body: bool = False,
) -> None:
    cls_ctx = enclosing_class if is_class_body else None
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qual = f"{scope_prefix}.{stmt.name}" if scope_prefix else stmt.name
            _scan_function_details(
                rel_file,
                stmt,
                qual,
                skip_stub_checks=skip_stub_checks,
                hollow_stubs=hollow_stubs,
                decorative_params=decorative_params,
                sharp_edges=sharp_edges,
                class_node=cls_ctx,
            )
            _scan_nested_stmts(
                rel_file,
                stmt.body,
                qual,
                skip_stub_checks,
                hollow_stubs,
                decorative_params,
                sharp_edges,
                enclosing_class=None,
                is_class_body=False,
            )
        elif isinstance(stmt, ast.ClassDef):
            qual = f"{scope_prefix}.{stmt.name}" if scope_prefix else stmt.name
            skip_cls = skip_stub_checks or _is_hollow_exempt_class(stmt)
            _scan_nested_stmts(
                rel_file,
                stmt.body,
                qual,
                skip_cls,
                hollow_stubs,
                decorative_params,
                sharp_edges,
                enclosing_class=stmt,
                is_class_body=True,
            )
        elif isinstance(
            stmt,
            (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While),
        ) or stmt.__class__.__name__ in {"TryStar", "Match"}:
            for block in _child_stmt_blocks(stmt):
                _scan_nested_stmts(
                    rel_file,
                    block,
                    scope_prefix,
                    skip_stub_checks,
                    hollow_stubs,
                    decorative_params,
                    sharp_edges,
                    enclosing_class=enclosing_class,
                    is_class_body=is_class_body,
                )


def _is_docstring_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _body_mutates_dirnames(stmts: list[ast.stmt], dir_var: str) -> bool:
    stack: list[ast.AST] = list(stmts)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Name)
                    and tgt.value.id == dir_var
                    and isinstance(tgt.slice, ast.Slice)
                ):
                    return True
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                if (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Name)
                    and tgt.value.id == dir_var
                    and isinstance(tgt.slice, ast.Slice)
                ):
                    return True
        elif isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == dir_var
                and node.func.attr in {"remove", "clear", "pop"}
            ):
                return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _is_pruned_os_walk_for(for_node: ast.For | ast.AsyncFor) -> ast.Call | None:
    if not isinstance(for_node.iter, ast.Call):
        return None
    if _call_dotted_name(for_node.iter.func) != "os.walk":
        return None
    if not isinstance(for_node.target, (ast.Tuple, ast.List)) or len(for_node.target.elts) < 2:
        return None
    dir_elt = for_node.target.elts[1]
    if not isinstance(dir_elt, ast.Name):
        return None
    if _body_mutates_dirnames(for_node.body, dir_elt.id):
        return for_node.iter
    return None


def _scan_inline_html_js_string(
    rel_file: str,
    raw_text: str,
    start_lineno: int,
    end_lineno: int | None,
    scope: str,
    sharp_edges: list[dict[str, Any]],
) -> None:
    low = raw_text.lower()
    if "<script" not in low and "<html" not in low and "<!doctype html" not in low:
        return
    clean = _strip_polyglot_comments(raw_text)
    for offset, line in enumerate(clean.splitlines()):
        lineno = start_lineno + offset
        if end_lineno is not None and lineno > end_lineno:
            lineno = end_lineno
        for m in _POLYGLOT_UNSAFE_SINK_RE.finditer(line):
            sink = m.group(0).rstrip("(=").strip()
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "unsafe_dynamic_sink",
                    "symbol": scope,
                    "detail": f"{sink} (inline HTML/JS)",
                }
            )


def _walk_body_hazards(
    rel_file: str,
    tree: ast.Module,
    silent_fallbacks: list[dict[str, Any]],
    sharp_edges: list[dict[str, Any]],
    hot_path_hazards: list[dict[str, Any]],
    changed_lines: set[int] | None = None,
) -> None:
    diff_lines = changed_lines or set()
    pruned_walk_calls: set[int] = set()

    def _visit(
        node: ast.AST,
        scope: str,
        loop_depth: int,
        param_names: frozenset[str],
    ) -> None:
        if isinstance(node, ast.ExceptHandler):
            extracted = _extract_silent_fallback(node)
            if extracted is not None:
                label, ret = extracted
                in_diff = node.lineno in diff_lines
                silent_fallbacks.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "symbol": scope,
                        "exception": label,
                        "return_value": ret,
                        "priority": _fallback_priority(label, ret, in_diff),
                        "in_diff": in_diff,
                    }
                )
        elif isinstance(node, ast.If):
            hits: set[str] = set()
            for sub in ast.walk(node.test):
                if (
                    isinstance(sub, ast.Name)
                    and sub.id in SHARP_BRANCH_NAMES
                    and sub.id in param_names
                ):
                    hits.add(sub.id)
                elif (
                    isinstance(sub, ast.Attribute)
                    and sub.attr in SHARP_BRANCH_NAMES
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in _CONFIG_CONTAINER_NAMES
                ):
                    hits.add(f"{sub.value.id}.{sub.attr}")
            if hits:
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": "flag_branch",
                        "symbol": scope,
                        "detail": f"branch guarded by {', '.join(sorted(hits))}",
                    }
                )
        elif isinstance(node, ast.Subscript):
            if _call_dotted_name(node.value) == "os.environ":
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": "env_override",
                        "symbol": scope,
                        "detail": "direct os.environ subscript",
                    }
                )
        elif isinstance(node, ast.Call):
            dotted = _call_dotted_name(node.func)
            tail = dotted.split(".")[-1] if dotted else ""
            in_loop = loop_depth > 0
            in_diff = node.lineno in diff_lines
            hz_kind: str | None = None
            hz_detail: str = dotted or tail
            if dotted in {f"subprocess.{a}" for a in SUBPROCESS_ATTRS} or dotted in {
                f"os.{a}" for a in OS_EXEC_ATTRS
            }:
                has_shell_true = any(
                    kw.arg == "shell"
                    and (
                        (isinstance(kw.value, ast.Constant) and bool(kw.value.value))
                        or not isinstance(kw.value, ast.Constant)
                    )
                    for kw in node.keywords
                )
                if has_shell_true:
                    hz_kind = "shell_injection_risk"
                    hz_detail = f"{dotted or tail} (shell=True)"
                else:
                    hz_kind = "subprocess_call"
            elif dotted in {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.delete",
                "requests.patch",
                "requests.request",
                "urllib.request.urlopen",
                "httpx.get",
                "httpx.post",
                "httpx.put",
                "httpx.delete",
                "httpx.patch",
                "httpx.request",
            }:
                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    hz_kind = "unbounded_http_call"
                    hz_detail = f"{dotted} (missing timeout)"
            elif id(node) in pruned_walk_calls:
                hz_kind = "pruned_walk"
                hz_detail = "os.walk (pruned dirnames[:])"
            elif dotted == "os.walk" or tail == "rglob" or dotted == "glob.glob":
                hz_kind = "recursive_walk"
            elif dotted in {"time.sleep", "asyncio.sleep"}:
                hz_kind = "sleep_call"
            elif tail in {"read_text", "read_bytes"} or (
                isinstance(node.func, ast.Attribute) and tail == "read" and not node.args
            ):
                hz_kind = "unbounded_file_read"

            if hz_kind is not None:
                hot_path_hazards.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": hz_kind,
                        "symbol": scope,
                        "detail": hz_detail,
                        "priority": _hazard_priority(hz_kind, in_loop, in_diff),
                        "in_loop": in_loop,
                        "in_diff": in_diff,
                    }
                )
            elif dotted in {"os.getenv", "os.environ.get"}:
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": "env_override",
                        "symbol": scope,
                        "detail": dotted,
                    }
                )
            elif tail in {"add_argument", "add_parser"}:
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": "cli_or_mcp_surface",
                        "symbol": scope,
                        "detail": f"CLI option definition via {tail}()",
                    }
                )
        elif isinstance(node, ast.JoinedStr):
            tmpl_parts: list[str] = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    tmpl_parts.append(part.value)
                else:
                    tmpl_parts.append("{expr}")
                    _visit(part, scope, loop_depth, param_names)
            joined_repr = "".join(tmpl_parts)
            if "![" in joined_repr and "](" in joined_repr:
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": node.lineno,
                        "kind": "markdown_image_leak_risk",
                        "symbol": scope,
                        "detail": "Dynamic markdown image interpolation in f-string (potential secret/token exfiltration)",
                    }
                )
            _scan_inline_html_js_string(
                rel_file,
                joined_repr,
                node.lineno,
                getattr(node, "end_lineno", None),
                scope,
                sharp_edges,
            )
            return
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            _scan_inline_html_js_string(
                rel_file,
                node.value,
                node.lineno,
                getattr(node, "end_lineno", None),
                scope,
                sharp_edges,
            )
            return

        if isinstance(node, ast.Module):
            stmts = node.body[1:] if node.body and _is_docstring_stmt(node.body[0]) else node.body
            for stmt in stmts:
                _visit(stmt, scope, loop_depth, param_names)
            return

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            next_scope = f"{scope}.{node.name}" if scope != "<module>" else node.name
            fn_params = param_names | frozenset(_bound_arg_names(node.args))
            for dec in node.decorator_list:
                _visit(dec, scope, loop_depth, param_names)
            for dflt in node.args.defaults:
                _visit(dflt, scope, loop_depth, param_names)
            for kdflt in node.args.kw_defaults:
                if kdflt is not None:
                    _visit(kdflt, scope, loop_depth, param_names)
            stmts = node.body[1:] if node.body and _is_docstring_stmt(node.body[0]) else node.body
            for stmt in stmts:
                _visit(stmt, next_scope, 0, fn_params)
            return

        if isinstance(node, ast.ClassDef):
            next_scope = f"{scope}.{node.name}" if scope != "<module>" else node.name
            for dec in node.decorator_list:
                _visit(dec, scope, loop_depth, param_names)
            for base in node.bases:
                _visit(base, scope, loop_depth, param_names)
            for kw in node.keywords:
                _visit(kw, scope, loop_depth, param_names)
            stmts = node.body[1:] if node.body and _is_docstring_stmt(node.body[0]) else node.body
            for stmt in stmts:
                _visit(stmt, next_scope, 0, param_names)
            return

        if isinstance(node, (ast.For, ast.AsyncFor)):
            pruned_call = _is_pruned_os_walk_for(node)
            if pruned_call is not None:
                pruned_walk_calls.add(id(pruned_call))
            _visit(node.target, scope, loop_depth, param_names)
            _visit(node.iter, scope, loop_depth, param_names)
            for stmt in node.body:
                _visit(stmt, scope, loop_depth + 1, param_names)
            for stmt in node.orelse:
                _visit(stmt, scope, loop_depth, param_names)
            return

        if isinstance(node, ast.While):
            _visit(node.test, scope, loop_depth + 1, param_names)
            for stmt in node.body:
                _visit(stmt, scope, loop_depth + 1, param_names)
            for stmt in node.orelse:
                _visit(stmt, scope, loop_depth, param_names)
            return

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if node.generators:
                _visit(node.generators[0].iter, scope, loop_depth, param_names)
                _visit(node.generators[0].target, scope, loop_depth + 1, param_names)
                for cond in node.generators[0].ifs:
                    _visit(cond, scope, loop_depth + 1, param_names)
                for gen in node.generators[1:]:
                    _visit(gen, scope, loop_depth + 1, param_names)
            _visit(node.elt, scope, loop_depth + 1, param_names)
            return

        if isinstance(node, ast.DictComp):
            if node.generators:
                _visit(node.generators[0].iter, scope, loop_depth, param_names)
                _visit(node.generators[0].target, scope, loop_depth + 1, param_names)
                for cond in node.generators[0].ifs:
                    _visit(cond, scope, loop_depth + 1, param_names)
                for gen in node.generators[1:]:
                    _visit(gen, scope, loop_depth + 1, param_names)
            _visit(node.key, scope, loop_depth + 1, param_names)
            _visit(node.value, scope, loop_depth + 1, param_names)
            return

        for child in ast.iter_child_nodes(node):
            _visit(child, scope, loop_depth, param_names)

    _visit(tree, "<module>", 0, frozenset())


def _strip_polyglot_comments(text: str, sfx: str = "") -> str:
    """Blank out block and line comments while preserving line count."""
    sfx = sfx.lower()
    if sfx in _BATCH_SUFFIXES:
        # Strip REM and :: lines in batch scripts
        return re.sub(r"(?im)^[ \t]*(?:REM\b|::)[^\n]*", "", text)
    if sfx in _SHELL_SUFFIXES or sfx in _PS_SUFFIXES:
        # Strip # comment-only lines in shell/powershell
        return re.sub(r"(?m)^[ \t]*#[^\n]*", "", text)
    no_block = re.sub(
        r"/\*[\s\S]*?\*/",
        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
        text,
    )
    return re.sub(r"(?m)^[ \t]*//[^\n]*", "", no_block)


def _polyglot_in_loop_lines(lines: list[str]) -> set[int]:
    """Heuristically track brace-delimited loop regions across polyglot source lines."""
    in_loop_lines: set[int] = set()
    brace_stack: list[bool] = []
    pending_loop = False
    for lineno, line in enumerate(lines, 1):
        if _POLYGLOT_LOOP_START_RE.search(line):
            pending_loop = True
        currently_in_loop = any(brace_stack) or pending_loop
        if currently_in_loop:
            in_loop_lines.add(lineno)
        for ch in line:
            if ch == "{":
                brace_stack.append(pending_loop)
                pending_loop = False
            elif ch == "}" and brace_stack:
                brace_stack.pop()
        if ";" in line and "{" not in line and not line.rstrip().endswith(")"):
            pending_loop = False
    return in_loop_lines


def _mask_cpp_strings(text: str) -> str:
    """Replace C/C++ string and char literal contents (and quotes) with spaces, keeping offsets."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_quote: str | None = None
    while i < n:
        ch = text[i]
        if in_quote is not None:
            if ch == "\\" and i + 1 < n:
                out.append("  " if text[i + 1] != "\n" else " \n")
                i += 2
                continue
            if ch == in_quote:
                in_quote = None
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = ch
            out.append(" ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _scan_cpp_pybind_none_args(clean_text: str, rel_file: str) -> list[dict[str, Any]]:
    """Flag C++ nanobind/pybind11 .def bindings checking None without .none()/=none() on arg."""
    masked = _mask_cpp_strings(clean_text)
    findings: list[dict[str, Any]] = []
    def_re = re.compile(r"\.\s*def(?:_static)?\s*\(")
    sym_re = re.compile(r'\.\s*def(?:_static)?\s*\(\s*"([^"]+)"')
    none_check_re = re.compile(r"(?:\.\s*is_none\s*\(|\bwrap_optional_\w*\s*\()")
    arg_re = re.compile(r"(?:nb|py)::arg\s*\(\s*\"([^\"]+)\"\s*\)")
    allow_none_re = re.compile(
        r"\.\s*none\s*\(\s*\)|=\s*(?:nb|py)::none\s*\(\s*\)|=\s*std::nullopt\b|=\s*nullptr\b"
    )
    ident_re = re.compile(
        r"\b([A-Za-z_]\w*)\s*\.\s*is_none\s*\(|\bwrap_optional_\w*\s*\(\s*([A-Za-z_]\w*)"
    )

    for m in def_re.finditer(masked):
        open_paren = masked.find("(", m.start())
        if open_paren < 0:
            continue
        depth = 0
        end_paren = -1
        for idx in range(open_paren, len(masked)):
            ch = masked[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end_paren = idx
                    break
        if end_paren < 0:
            continue

        call_clean = clean_text[m.start() : end_paren + 1]
        call_masked = masked[m.start() : end_paren + 1]
        if not none_check_re.search(call_masked):
            continue

        top_chars: list[str] = []
        brace_depth = 0
        for c_ch, m_ch in zip(call_clean, call_masked):
            if m_ch == "{":
                brace_depth += 1
                top_chars.append(" ")
            elif m_ch == "}":
                brace_depth = max(0, brace_depth - 1)
                top_chars.append(" ")
            elif brace_depth == 0:
                top_chars.append(c_ch)
            else:
                top_chars.append("\n" if c_ch == "\n" else " ")
        top_level = "".join(top_chars)

        parsed_args: list[tuple[str, bool]] = []
        for am in arg_re.finditer(top_level):
            tail_start = am.end()
            p_depth = 0
            in_q: str | None = None
            j = tail_start
            while j < len(top_level):
                ch = top_level[j]
                if in_q is not None:
                    if ch == "\\" and j + 1 < len(top_level):
                        j += 2
                        continue
                    if ch == in_q:
                        in_q = None
                    j += 1
                    continue
                if ch in ('"', "'"):
                    in_q = ch
                elif ch == "(":
                    p_depth += 1
                elif ch == ")":
                    if p_depth == 0:
                        break
                    p_depth -= 1
                elif ch == "," and p_depth == 0:
                    break
                j += 1
            tail = top_level[tail_start:j]
            parsed_args.append((am.group(1), bool(allow_none_re.search(tail))))

        if not parsed_args:
            continue

        tested_idents = {g1 or g2 for g1, g2 in ident_re.findall(call_masked) if (g1 or g2)}
        matched_args = [(name, ok) for name, ok in parsed_args if name in tested_idents]
        if matched_args:
            has_missing_none = any(not ok for _, ok in matched_args)
        else:
            has_missing_none = not any(ok for _, ok in parsed_args)

        if has_missing_none:
            sym_m = sym_re.match(call_clean)
            symbol = sym_m.group(1) if sym_m else "<cpp>"
            lineno = clean_text[: m.start()].count("\n") + 1
            findings.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "pybind_missing_none_arg",
                    "symbol": symbol,
                    "detail": (
                        "optional None check (.is_none() / wrap_optional_*) inside binding "
                        "without .none() or = nb::none()/py::none() on nb::arg/py::arg"
                    ),
                }
            )
    return findings


def _scan_polyglot_file(
    rel_file: str,
    path: Path,
    changed_lines: set[int] | None,
    hollow_stubs: list[dict[str, Any]],
    silent_fallbacks: list[dict[str, Any]],
    sharp_edges: list[dict[str, Any]],
    hot_path_hazards: list[dict[str, Any]],
    discovered_symbols: list[str],
) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    sfx = path.suffix.lower()
    clean_text = _strip_polyglot_comments(text, sfx=sfx)
    lines = clean_text.splitlines()
    diff_lines = changed_lines or set()
    loop_lines = _polyglot_in_loop_lines(lines)
    stub_spans: list[tuple[int, int]] = []

    for pat in (_POLYGLOT_EMPTY_JS_RE, _POLYGLOT_EMPTY_GO_RE, _POLYGLOT_EMPTY_RUST_RE, _POLYGLOT_EMPTY_SWIFT_RE):
        for m in pat.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sym = m.group(1)
            discovered_symbols.append(sym)
            stub_spans.append((m.start(), m.end()))
            hollow_stubs.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "symbol": sym,
                    "reason": "empty function body",
                }
            )

    for pat, label in (
        (_POLYGLOT_THROW_TODO_RE, "throws unimplemented/TODO stub"),
        (_POLYGLOT_UNIMPL_CALL_RE, "explicit unimplemented/todo macro call"),
    ):
        for m in pat.finditer(clean_text):
            if any(start <= m.start() <= end for start, end in stub_spans):
                continue
            lineno = clean_text[: m.start()].count("\n") + 1
            hollow_stubs.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "symbol": "<polyglot>",
                    "reason": label,
                }
            )

    for m in _POLYGLOT_CATCH_EMPTY_RE.finditer(clean_text):
        lineno = clean_text[: m.start()].count("\n") + 1
        in_diff = lineno in diff_lines
        silent_fallbacks.append(
            {
                "file": rel_file,
                "line": lineno,
                "symbol": "<catch>",
                "exception": "catch",
                "return_value": "pass",
                "priority": _fallback_priority("catch", "pass", in_diff),
                "in_diff": in_diff,
            }
        )

    for m in _POLYGLOT_CATCH_RETURN_RE.finditer(clean_text):
        lineno = clean_text[: m.start()].count("\n") + 1
        ret_val = re.sub(r"\s+", "", m.group(1))
        in_diff = lineno in diff_lines
        silent_fallbacks.append(
            {
                "file": rel_file,
                "line": lineno,
                "symbol": "<catch>",
                "exception": "catch",
                "return_value": ret_val,
                "priority": _fallback_priority("catch", ret_val, in_diff),
                "in_diff": in_diff,
            }
        )

    is_cpp = path.suffix.lower() in _CPP_SUFFIXES
    if is_cpp:
        for m in _CPP_PY_HANDLE_MEMBER_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "py_object_field",
                    "symbol": "<cpp>",
                    "detail": (
                        "Python callable/object stored on C++ field or static "
                        "(verify GIL and exit cleanup)"
                    ),
                }
            )
        sharp_edges.extend(_scan_cpp_pybind_none_args(clean_text, rel_file))

    is_shell = sfx in _SHELL_SUFFIXES
    is_batch = sfx in _BATCH_SUFFIXES
    is_ps = sfx in _PS_SUFFIXES

    if is_shell:
        for m in _SHELL_UNQUOTED_EVAL_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "shell_eval_injection",
                    "symbol": "<shell>",
                    "detail": "eval on parameter/variable expansion risks arbitrary code injection",
                }
            )
        for m in _SHELL_QUOTED_GLOB_ARRAY_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "shell_quoted_glob_array",
                    "symbol": "<shell>",
                    "detail": "quoted wildcard in array/paren list prevents glob expansion (matches 0 files)",
                }
            )

    if is_batch:
        for m in _BATCH_DELAYED_EXPANSION_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "batch_delayed_expansion_trap",
                    "symbol": "<batch>",
                    "detail": "EnableDelayedExpansion strips exclamation marks (!) from folder and file paths",
                }
            )
        for m in _BATCH_IF_ERRORLEVEL_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "batch_errorlevel_trap",
                    "symbol": "<batch>",
                    "detail": "IF ERRORLEVEL N checks >= N, not == N (prefer IF %ERRORLEVEL% EQU N or verify ordering)",
                }
            )

    if is_ps:
        for m in _PS_READ_HOST_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "ps_read_host_noninteractive",
                    "symbol": "<powershell>",
                    "detail": "Read-Host crashes or hangs under PowerShell -NonInteractive / CI runtimes",
                }
            )

    is_apple = sfx in _APPLE_SUFFIXES
    if is_apple:
        for m in _SWIFT_FORCE_UNWRAP_RE.finditer(clean_text):
            lineno = clean_text[: m.start()].count("\n") + 1
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "swift_force_unwrap_nil_crash",
                    "symbol": "<swift>",
                    "detail": "forced unwrap (!) operator on chained member call causes fatalError crash on nil",
                }
            )

    for lineno, line in enumerate(lines, 1):
        in_diff = lineno in diff_lines
        in_loop = lineno in loop_lines
        for m in _POLYGLOT_ENV_RE.finditer(line):
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "env_override",
                    "symbol": "<polyglot>",
                    "detail": m.group(0).rstrip("( \t"),
                }
            )
        for m in _POLYGLOT_UNSAFE_SINK_RE.finditer(line):
            sharp_edges.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "unsafe_dynamic_sink",
                    "symbol": "<polyglot>",
                    "detail": m.group(0).rstrip("(=").strip(),
                }
            )
        if is_cpp:
            for m in _CPP_UNCHECKED_PARSE_RE.finditer(line):
                sharp_edges.append(
                    {
                        "file": rel_file,
                        "line": lineno,
                        "kind": "unchecked_numeric_parse",
                        "symbol": "<cpp>",
                        "detail": "numeric parse without consumed-index or endptr validation",
                    }
                )
        for m in _POLYGLOT_SUBPROCESS_RE.finditer(line):
            hot_path_hazards.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "subprocess_call",
                    "symbol": "<polyglot>",
                    "detail": m.group(0).rstrip("( \t"),
                    "priority": _hazard_priority("subprocess_call", in_loop, in_diff),
                    "in_loop": in_loop,
                    "in_diff": in_diff,
                }
            )
        for m in _POLYGLOT_FS_READ_RE.finditer(line):
            hot_path_hazards.append(
                {
                    "file": rel_file,
                    "line": lineno,
                    "kind": "unbounded_file_read",
                    "symbol": "<polyglot>",
                    "detail": m.group(0),
                    "priority": _hazard_priority("unbounded_file_read", in_loop, in_diff),
                    "in_loop": in_loop,
                    "in_diff": in_diff,
                }
            )


def run_prescan(
    repo_root: Path,
    explicit_files: list[str] | None = None,
    git_diff_ref: str | None = None,
    exclude_dirs: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Execute deterministic pre-scan checks across target repository files."""
    repo_root = repo_root.resolve()
    extra_excluded = frozenset(exclude_dirs) if exclude_dirs else frozenset()
    py_sources, py_tests = _discover_python_files(repo_root, extra_excluded=extra_excluded)
    poly_sources, _ = _discover_polyglot_files(repo_root, extra_excluded=extra_excluded)
    all_sources = py_sources + poly_sources

    git_diff_files: list[str] | None = None
    unscanned_diff_files: list[str] = []
    changed_lines_by_file: dict[str, set[int]] = {}
    git_note: str | None = None
    git_diff_active = False
    if git_diff_ref is not None:
        (
            git_diff_files,
            unscanned_diff_files,
            changed_lines_by_file,
            git_note,
        ) = _discover_git_diff_scope(repo_root, git_diff_ref, extra_excluded=extra_excluded)
        git_diff_active = git_note is None

    target_files, scope_mode = _resolve_target_files(
        repo_root,
        explicit_files,
        all_sources,
        git_diff_files=git_diff_files,
        git_diff_active=git_diff_active,
    )

    refs_by_prod_file: dict[str, dict[str, set[int]]] = {}
    refs_by_test_file: dict[str, dict[str, set[int]]] = {}
    imported_module_paths: set[str] = set()
    dotted_string_tokens: set[str] = set()
    exported_symbols: set[str] = _extract_pyproject_scripts(repo_root)
    parsed_targets: dict[Path, ast.Module] = {}

    for src in py_sources:
        _, tree = _parse_file(src)
        if tree is None:
            continue
        rel = _rel_posix(repo_root, src)
        refs_by_prod_file[rel] = _collect_symbol_ref_lines(tree)
        m_paths, d_strings = _collect_imported_module_paths(tree)
        imported_module_paths.update(m_paths)
        dotted_string_tokens.update(d_strings)
        if src.name == "__init__.py":
            exported_symbols.update(_extract_init_exports(tree))
        if src in target_files:
            parsed_targets[src] = tree

    for tst in py_tests:
        _, tree = _parse_file(tst)
        if tree is None:
            continue
        rel = _rel_posix(repo_root, tst)
        refs_by_test_file[rel] = _collect_symbol_ref_lines(tree)

    for tgt in target_files:
        if tgt.suffix.lower() != ".py":
            continue
        if tgt not in parsed_targets:
            _, tree = _parse_file(tgt)
            if tree is not None:
                parsed_targets[tgt] = tree
                rel = _rel_posix(repo_root, tgt)
                if _is_test_relpath(rel):
                    refs_by_test_file[rel] = _collect_symbol_ref_lines(tree)
                else:
                    refs_by_prod_file[rel] = _collect_symbol_ref_lines(tree)
                    if tgt.name == "__init__.py":
                        exported_symbols.update(_extract_init_exports(tree))

    test_only_islands: list[dict[str, Any]] = []
    orphaned_modules: list[dict[str, Any]] = []
    hollow_stubs: list[dict[str, Any]] = []
    decorative_params: list[dict[str, Any]] = []
    silent_fallbacks: list[dict[str, Any]] = []
    sharp_edges: list[dict[str, Any]] = []
    hot_path_hazards: list[dict[str, Any]] = []
    blast_radius: dict[str, dict[str, Any]] = {}
    discovered_symbols: list[str] = []

    for tgt in target_files:
        rel = _rel_posix(repo_root, tgt)
        is_target_test = _is_test_relpath(rel)
        if tgt.suffix.lower() != ".py":
            if not is_target_test:
                _scan_polyglot_file(
                    rel,
                    tgt,
                    changed_lines_by_file.get(rel),
                    hollow_stubs,
                    silent_fallbacks,
                    sharp_edges,
                    hot_path_hazards,
                    discovered_symbols,
                )
            continue

        tree = parsed_targets.get(tgt)
        if tree is None:
            continue
        is_entrypoint_or_init = tgt.name in {"__init__.py"} | _ENTRYPOINT_FILENAMES

        if not is_target_test:
            _walk_body_hazards(
                rel,
                tree,
                silent_fallbacks,
                sharp_edges,
                hot_path_hazards,
                changed_lines=changed_lines_by_file.get(rel),
            )

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                sym_name = node.name
                discovered_symbols.append(sym_name)
                end_ln = getattr(node, "end_lineno", node.lineno) or node.lineno
                prod_callers = _prod_callers_for(
                    sym_name, rel, node.lineno, end_ln, refs_by_prod_file
                )
                test_callers = sorted(
                    f for f, refs in refs_by_test_file.items() if f != rel and sym_name in refs
                )
                blast_radius[f"{rel}::{sym_name}"] = {
                    "file": rel,
                    "line": node.lineno,
                    "prod_callers": prod_callers,
                    "test_callers": test_callers,
                }
                decs = _decorator_names(node)
                is_cls_exempt = isinstance(node, ast.ClassDef) and _is_hollow_exempt_class(node)
                if (
                    not is_target_test
                    and not is_entrypoint_or_init
                    and not sym_name.startswith("_")
                    and not sym_name.startswith("pytest_")
                    and sym_name not in ENTRY_SYMBOL_NAMES
                    and sym_name not in _ENTRYPOINT_FUNCTIONS
                    and sym_name not in exported_symbols
                    and not (decs & _ISLAND_EXEMPT_DECORATORS)
                    and not is_cls_exempt
                    and test_callers
                    and not prod_callers
                ):
                    test_only_islands.append(
                        {
                            "file": rel,
                            "line": node.lineno,
                            "symbol": sym_name,
                            "test_callers": test_callers,
                        }
                    )

                if isinstance(node, ast.ClassDef):
                    skip_cls_stubs = is_target_test or _is_hollow_exempt_class(node)
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            qual = f"{sym_name}.{item.name}"
                            discovered_symbols.append(qual)
                            _scan_function_details(
                                rel,
                                item,
                                qual,
                                skip_stub_checks=skip_cls_stubs,
                                hollow_stubs=hollow_stubs,
                                decorative_params=decorative_params,
                                sharp_edges=sharp_edges,
                                class_node=node,
                            )
                            _scan_nested_stmts(
                                rel,
                                item.body,
                                qual,
                                skip_cls_stubs,
                                hollow_stubs,
                                decorative_params,
                                sharp_edges,
                                enclosing_class=None,
                                is_class_body=False,
                            )
                        else:
                            _scan_nested_stmts(
                                rel,
                                [item],
                                sym_name,
                                skip_cls_stubs,
                                hollow_stubs,
                                decorative_params,
                                sharp_edges,
                                enclosing_class=node,
                                is_class_body=True,
                            )
                else:
                    _scan_function_details(
                        rel,
                        node,
                        sym_name,
                        skip_stub_checks=is_target_test,
                        hollow_stubs=hollow_stubs,
                        decorative_params=decorative_params,
                        sharp_edges=sharp_edges,
                    )
                    _scan_nested_stmts(
                        rel,
                        node.body,
                        sym_name,
                        is_target_test,
                        hollow_stubs,
                        decorative_params,
                        sharp_edges,
                    )
            else:
                _scan_nested_stmts(
                    rel,
                    [node],
                    "",
                    is_target_test,
                    hollow_stubs,
                    decorative_params,
                    sharp_edges,
                )

    silent_fallbacks.sort(
        key=lambda item: (
            _PRIORITY_ORDER.get(item.get("priority", "LOW"), 3),
            item["file"],
            item["line"],
        )
    )
    hot_path_hazards.sort(
        key=lambda item: (
            _PRIORITY_ORDER.get(item.get("priority", "LOW"), 3),
            item["file"],
            item["line"],
        )
    )

    scanned_rel = [_rel_posix(repo_root, p) for p in target_files]
    scoped_filter = set(scanned_rel) if scope_mode in {"git_diff", "explicit_files"} else None
    # Orphaned-Module Check (src/*.py with 0 production callers or entrypoint references)
    src_dir = repo_root / "src"
    if src_dir.exists():
        entry_stems = frozenset({"__init__", "__main__", "cli", "main", "app", "server"})
        for tgt in py_sources:
            t_stem = tgt.stem
            if t_stem in entry_stems or t_stem.startswith("_"):
                continue
            try:
                rel_src = tgt.relative_to(src_dir)
            except ValueError:
                continue
            rel_repo = _rel_posix(repo_root, tgt)
            if scoped_filter and rel_repo not in scoped_filter:
                continue
            parts = list(rel_src.parts)
            parts[-1] = t_stem
            mod_dotted = ".".join(parts)
            is_ref = any(
                imp == mod_dotted
                or imp.startswith(mod_dotted + ".")
                or imp.endswith("." + mod_dotted)
                for imp in imported_module_paths
            ) or any(
                st == mod_dotted
                or st.startswith(mod_dotted + ".")
                or st.endswith("." + mod_dotted)
                for st in dotted_string_tokens
            )
            if not is_ref:
                orphaned_modules.append(
                    {
                        "file": rel_repo,
                        "line": 1,
                        "symbol": mod_dotted,
                        "detail": f"Module `{mod_dotted}` has 0 production importers",
                    }
                )

    gate_l_problems, gate_l_note = _load_gate_l_problems(repo_root, scoped_files=scoped_filter)
    radar_warnings = _load_radar_warnings(repo_root, target_files, discovered_symbols)

    hollow_wiring: dict[str, Any] = {
        "gate_l_problems": gate_l_problems,
        "test_only_islands": test_only_islands,
        "orphaned_modules": orphaned_modules,
        "hollow_stubs": hollow_stubs,
        "decorative_params": decorative_params,
        "silent_fallbacks": silent_fallbacks,
    }
    if gate_l_note is not None:
        hollow_wiring["gate_l_note"] = gate_l_note

    result: dict[str, Any] = {
        "repo_root": str(repo_root),
        "scope_mode": scope_mode,
        "scanned_files": scanned_rel,
        "hollow_wiring": hollow_wiring,
        "sharp_edges": sharp_edges,
        "hot_path_hazards": hot_path_hazards,
        "blast_radius": blast_radius,
        "radar_warnings": radar_warnings,
    }
    if git_diff_ref is not None:
        result["git_diff_ref"] = git_diff_ref
        result["unscanned_diff_files"] = unscanned_diff_files
    if git_note is not None:
        result["git_diff_note"] = git_note
    return result


def _format_human_summary(report: dict[str, Any]) -> str:
    hw = report["hollow_wiring"]
    high_fb = sum(1 for item in hw["silent_fallbacks"] if item.get("priority") == "HIGH")
    high_hz = sum(1 for item in report["hot_path_hazards"] if item.get("priority") == "HIGH")
    unscanned = report.get("unscanned_diff_files") or []
    lines = [
        f"SDCS_Red Pre-Scan ({len(report['scanned_files'])} file(s), mode={report.get('scope_mode', 'repo_default')})",
        f"- Gate L problems: {len(hw['gate_l_problems'])}",
        f"- Test-Only Islands: {len(hw['test_only_islands'])}",
        f"- Orphaned modules: {len(hw.get('orphaned_modules', []))}",
        f"- Hollow stubs: {len(hw['hollow_stubs'])}",
        f"- Decorative params: {len(hw['decorative_params'])}",
        f"- Silent fallbacks: {len(hw['silent_fallbacks'])} ({high_fb} HIGH)",
        f"- Sharp edges: {len(report['sharp_edges'])}",
        f"- Hot-path hazards: {len(report['hot_path_hazards'])} ({high_hz} HIGH)"
        + (f" [+{report['out_of_diff_hazards_suppressed']} out-of-diff suppressed]" if report.get("out_of_diff_hazards_suppressed") else ""),
        f"- Radar choice: {report['radar_warnings'].get('choice', 'unavailable')}",
    ]
    if unscanned:
        lines.append(f"- Unscanned diff files: {len(unscanned)}")
    categories: list[tuple[str, list[Any]]] = [
        ("Unscanned diff files", unscanned),
        ("Gate L problems", hw.get("gate_l_problems") or []),
        ("Test-Only Islands", hw.get("test_only_islands") or []),
        ("Orphaned modules", hw.get("orphaned_modules") or []),
        ("Hollow stubs", hw.get("hollow_stubs") or []),
        ("Decorative params", hw.get("decorative_params") or []),
        ("Silent fallbacks", hw.get("silent_fallbacks") or []),
        ("Sharp edges", report.get("sharp_edges") or []),
        ("Hot-path hazards", report.get("hot_path_hazards") or []),
    ]
    for label, entries in categories:
        if not entries:
            continue
        lines.append(f"\n[{label}]")
        for item in entries[:12]:
            if not isinstance(item, dict):
                lines.append(f"  * {item}")
                continue
            loc = f"{item.get('file', '?')}:{item.get('line', '?')}"
            sym = item.get("symbol")
            sym_part = f" ({sym})" if sym else ""
            parts: list[str] = []
            if item.get("priority"):
                parts.append(f"[{item['priority']}]")
            if item.get("in_loop"):
                parts.append("in_loop=True")
            if item.get("kind"):
                parts.append(str(item["kind"]))
            if item.get("detail"):
                parts.append(str(item["detail"]))
            if item.get("param"):
                parts.append(f"param={item['param']}")
            if item.get("exception") is not None:
                parts.append(f"except {item.get('exception')} -> {item.get('return_value')}")
            if item.get("test_callers"):
                parts.append(f"test_callers={item['test_callers']}")
            suffix = " | ".join(parts)
            lines.append(f"  * {loc}{sym_part}" + (f": {suffix}" if suffix else ""))
        if len(entries) > 12:
            lines.append(f"  ... ({len(entries) - 12} more; run with --json)")
    lines.append("\nTip: pass --json for full call-graph, blast_radius, and radar_warnings JSON.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SDCS_Red deterministic AST, polyglot, and call-graph pre-scanner."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="Target repository root directory (default: current directory).",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        default=None,
        help="Optional list of Python or polyglot files to focus the pre-scan on.",
    )
    parser.add_argument(
        "--git-diff",
        nargs="?",
        const="HEAD",
        default=None,
        metavar="REF",
        help="Auto-scope pre-scan to changed/untracked files against REF (default: HEAD).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full machine-readable JSON output.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact JSON output: filter blast_radius down to symbols with zero prod_callers.",
    )
    parser.add_argument(
        "--omit-blast-radius",
        action="store_true",
        help="Omit blast_radius from JSON output to minimize output size on large diffs.",
    )
    parser.add_argument(
        "--exclude-dirs",
        nargs="*",
        default=None,
        metavar="DIR",
        help="Additional directories to prune from file discovery and call-graph walks.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write pre-scan output to PATH as UTF-8 without BOM and print confirmation.",
    )
    args = parser.parse_args(argv)
    report = run_prescan(
        args.repo_root,
        args.files,
        git_diff_ref=args.git_diff,
        exclude_dirs=args.exclude_dirs,
    )
    if args.omit_blast_radius:
        report.pop("blast_radius", None)
    elif args.compact:
        br = report.get("blast_radius")
        if isinstance(br, dict):
            report["blast_radius"] = {
                sym: meta
                for sym, meta in br.items()
                if not (isinstance(meta, dict) and meta.get("prod_callers"))
            }
        if args.git_diff is not None:
            all_hazards = report.get("hot_path_hazards") or []
            in_diff_hazards = [h for h in all_hazards if h.get("in_diff") is True]
            suppressed = len(all_hazards) - len(in_diff_hazards)
            report["hot_path_hazards"] = in_diff_hazards
            report["out_of_diff_hazards_suppressed"] = suppressed
    rendered = json.dumps(report, indent=2) if args.json else _format_human_summary(report)
    if args.output is not None:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote SDCS_Red pre-scan report to {out_path}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
