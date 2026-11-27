#!/usr/bin/env python3
"""Prove a git working-tree fix or regression test against a base commit.

Runs the test command on the current working tree (must pass), then runs a negative
control in an isolated temporary worktree or directory against base (default: HEAD):
- Copies newly added or modified test files into the clean base tree.
- Verifies that the test command FAILS on the unpatched base.
- Confirms the new test is a genuine discriminator, eliminating tautological green tests.

Designed for SDCS_Red:
- Zero external dependencies: Python stdlib only.
- Strict Windows PowerShell safety (no here-string hangs).
- Exit codes: 0 PROVEN (failed on base, passed on current), 1 NOT PROVEN, 2 error/usage.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

TEST_DIR_PREFIXES = ("tests/", "test/", "__tests__/")
TEST_SUFFIXES = (
    "_test.py",
    "_test.go",
    "_test.rs",
    ".test.js",
    ".test.ts",
    ".test.jsx",
    ".test.tsx",
    ".spec.js",
    ".spec.ts",
)


def is_test_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    base = os.path.basename(norm)
    if norm.startswith(TEST_DIR_PREFIXES) or "/tests/" in norm or "/test/" in norm:
        return True
    return base.startswith("test_") or any(base.endswith(suf) for suf in TEST_SUFFIXES)


def run_git(repo: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
    )


def run_check(cmd: str, cwd: str, timeout: int) -> Dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    start = time.monotonic()
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
        elapsed = round(time.monotonic() - start, 2)
        return {
            "returncode": proc.returncode,
            "timed_out": False,
            "elapsed_seconds": elapsed,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - start, 2)
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", errors="replace")
        return {
            "returncode": -1,
            "timed_out": True,
            "elapsed_seconds": elapsed,
            "stdout": out[-4000:],
            "stderr": err[-4000:],
        }


def collect_changes(repo: str, base: str) -> Tuple[List[str], List[str], str]:
    proc = run_git(repo, "diff", "--name-only", "--diff-filter=ACMRTUXB", base)
    tracked: List[str] = []
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            line = line.strip().replace("\\", "/")
            if line:
                tracked.append(line)

    untracked_proc = run_git(repo, "ls-files", "--others", "--exclude-standard")
    untracked: List[str] = []
    if untracked_proc.returncode == 0:
        for line in untracked_proc.stdout.splitlines():
            line = line.strip().replace("\\", "/")
            if line:
                untracked.append(line)

    digest = hashlib.sha256()
    for rel in sorted(set(tracked) | set(untracked)):
        full = os.path.join(repo, rel)
        if os.path.isfile(full):
            digest.update(rel.encode("utf-8"))
            with open(full, "rb") as handle:
                digest.update(handle.read())
    return sorted(set(tracked)), sorted(set(untracked)), digest.hexdigest()[:16]


def select_test_files(
    tracked: Sequence[str],
    untracked: Sequence[str],
    explicit: Sequence[str],
) -> List[str]:
    all_paths = sorted(set(tracked) | set(untracked))
    if not explicit:
        return [p for p in all_paths if is_test_path(p)]
    chosen: List[str] = []
    for rel in all_paths:
        norm = rel.replace("\\", "/")
        for pat in explicit:
            pnorm = pat.replace("\\", "/").rstrip("/")
            if norm == pnorm or norm.startswith(pnorm + "/") or fnmatch.fnmatch(norm, pnorm):
                chosen.append(rel)
                break
    return sorted(set(chosen))


def create_base_worktree(repo: str, base: str, dest: str) -> None:
    proc = run_git(repo, "worktree", "add", "--detach", dest, base)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"could not create git worktree at {base}")


def remove_base_worktree(repo: str, dest: str) -> None:
    run_git(repo, "worktree", "remove", "--force", dest)
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cmd", required=True, help="test command to verify (must pass on current, fail on base)")
    parser.add_argument("--repo", default=".", help="project root directory (default: .)")
    parser.add_argument("--base", default="HEAD", help="git base revision (default: HEAD)")
    parser.add_argument(
        "--keep-tests",
        nargs="*",
        default=[],
        help="explicit test paths or glob patterns to copy into the base tree",
    )
    parser.add_argument(
        "--expect-failure",
        help="substring that must appear in stdout/stderr of the base failure",
    )
    parser.add_argument("--timeout", type=int, default=60, help="seconds per check run (default: 60)")
    parser.add_argument("--json", dest="json_out", help="write structured proof report to JSON file")
    return parser


def run_proof(
    repo: str,
    base: str,
    cmd: str,
    keep_tests: Sequence[str],
    expect_failure: Optional[str],
    timeout: int,
) -> Tuple[bool, Dict[str, Any]]:
    tracked, untracked, diff_sha = collect_changes(repo, base)
    test_files = select_test_files(tracked, untracked, keep_tests)
    current = run_check(cmd, repo, timeout)
    info: Dict[str, Any] = {
        "base": base,
        "diff_sha256": diff_sha,
        "command": cmd,
        "changed_files": tracked,
        "untracked_files": untracked,
        "kept_test_files": test_files,
        "expected_failure": expect_failure,
        "current": current,
    }
    if current["returncode"] != 0:
        info["reason"] = f"check failed on current tree (exit {current['returncode']})"
        return False, info

    if not test_files:
        info["reason"] = "no new or modified test files detected in diff to prove against base"
        return False, info

    tmp_parent = tempfile.mkdtemp(prefix="prove-diff-base-")
    tmp = os.path.join(tmp_parent, "wt")
    try:
        create_base_worktree(repo, base, tmp)
        for rel in test_files:
            src = os.path.join(repo, rel)
            dst = os.path.join(tmp, rel)
            if os.path.isfile(src):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
        control = run_check(cmd, tmp, timeout)
    finally:
        remove_base_worktree(repo, tmp)
        shutil.rmtree(tmp_parent, ignore_errors=True)

    info["control"] = control
    if control["returncode"] == 0 and not control.get("timed_out"):
        info["reason"] = "check passed on unpatched base; test is tautological (does not prove the fix)"
        return False, info

    if expect_failure:
        diag = str(control.get("stdout", "")) + str(control.get("stderr", ""))
        if expect_failure not in diag:
            info["reason"] = f"base failed but expected diagnostic '{expect_failure}' was not found"
            return False, info

    return True, info


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"prove_diff.py: error: not a directory: {repo}", file=sys.stderr)
        return 2

    rev = run_git(repo, "rev-parse", "--verify", args.base)
    if rev.returncode != 0:
        print(f"prove_diff.py: error: invalid git repo or base {args.base!r}: {rev.stderr.strip()}", file=sys.stderr)
        return 2

    try:
        proven, info = run_proof(repo, args.base, args.cmd, args.keep_tests, args.expect_failure, args.timeout)
    except RuntimeError as exc:
        print(f"prove_diff.py: error: {exc}", file=sys.stderr)
        return 2

    verdict = "PROVEN" if proven else "NOT PROVEN"
    info["verdict"] = verdict

    if proven:
        print(f"PROVE: {verdict} (passed on current, failed on base as expected)")
        print(f"  Kept test files: {', '.join(info['kept_test_files'])}")
        print(f"  Base exit: {info['control']['returncode']} in {info['control']['elapsed_seconds']}s")
    else:
        print(f"PROVE: {verdict}")
        print(f"  Reason: {info.get('reason')}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(info, handle, indent=2)

    return 0 if proven else 1


if __name__ == "__main__":
    sys.exit(main())
