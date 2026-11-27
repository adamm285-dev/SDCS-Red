---
name: sdcs-red
description: Dual-mode adversarial code audit skill (SDCS_Red) that pairs deterministic AST, polyglot, and call-graph pre-scanning (scripts/red_prescan.py with --git-diff auto-scoping) with cold-context read-only refutation across a mandatory 7-bucket attack matrix. Trigger Mode 1 on "double-check your work", "double check your work", "run another round", "audit this", or "sdcs-red"; trigger Mode 2 on "adversarial review with Claude" or "adversarial waves with Claude".
---

# SDCS_Red Adversarial Audit Workflow

`SDCS_Red` eliminates superficial self-reviews and the 4-bug satisficing ceiling by separating **mechanical pre-scan**, **cold-context refutation**, and **builder remediation**.

## Trigger Routing

- **Mode 1 (Cold-Context Subagent Self-Audit):** Trigger when the user says `"double-check your work"`, `"double check your work"`, `"run another round"`, `"audit this"`, or `"sdcs-red"`.
- **Mode 2 (Read-Only Claude Swarm Wave):** Trigger when the user explicitly says `"adversarial review with Claude"` or `"adversarial waves with Claude"`.

## Shared Rules (Both Modes)

1. **Contract & Topology Grounding First (Anti-Norm-Drift Rule):** Before running pre-scans or editing code, locate and read any repository specification and boundary contracts in full (`SPEC.md`, `wiring.yaml`, `roadmap.md`, `spine.md`, `ARCHITECTURE.md` when present). Extract discrete requirements (`REQ-1..REQ-N`), exact failure contracts (such as raising a specific exception like `ValueError` vs. returning `False` or `None`), exact numeric bounds/tolerances/rounding rules, and prohibited cross-module imports.
   - **Contract Supremacy Invariant:** In-code comments, module docstrings, and unverified implementation notes are *untrusted claims*, never normative requirements. When implementation code or docstrings conflict with the formal specification (`SPEC.md` / `roadmap.md` / User Prompt), the formal specification always governs; never allow implementation comments to drift requirements.
2. **Deterministic Pre-Scan & Automated Verification Tooling:** Execute `scripts/red_prescan.py` before launching reviewers so tokens are spent probing logic rather than hunting symbols. Resolve `<SKILL_DIR>` from the `sdcs-red` path shown in `<skills>` (for example `.agents/skills/sdcs-red` inside a repo or `~/.gemini/config/skills/sdcs-red` when installed globally):
   ```powershell
   python "<SKILL_DIR>/scripts/red_prescan.py" --repo-root . --git-diff --compact --json --output "$env:TEMP\sdcs_red_prescan.json"
   ```
   Pass `--output <temp_path>` whenever writing JSON on Windows PowerShell so `red_prescan.py` writes UTF-8 without a BOM (avoiding piped stdout BOM `JSONDecodeError` issues), and pass `--compact` (which filters `blast_radius` down to symbols with zero `prod_callers`) or `--omit-blast-radius` on multi-file diffs to prevent >60 KB JSON truncation while keeping `hollow_wiring`, `sharp_edges`, `hot_path_hazards`, `radar_warnings`, `scanned_files`, `scope_mode`, `git_diff_ref`, and `unscanned_diff_files`. Omit `--compact` / `--omit-blast-radius` when full `blast_radius` lookup is needed. Use `--git-diff [REF]` (default `HEAD`) as the primary way to auto-scope uncommitted, staged, and untracked edits; pass `--files <changed files...>` for explicit file lists, or omit both for a full-repo cold audit. If the changes under review were already committed at `HEAD` (or auditing a clean baseline repo where `git status --porcelain` is empty and `--git-diff` returns `scanned_files: []`), pass the baseline commit ref (`--git-diff HEAD~1` or `--git-diff <base_sha>`) or omit `--git-diff` for a full-repo scan. The pre-scanner covers Python AST/call-graph analysis (including inline `<script>` / HTML templates in `.py` strings) plus polyglot regex/structural scanning (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.dart`, `.go`, `.rs`, `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.cu`, `.cuh`, including C++ `nanobind`/`pybind11` missing `.none()` argument guards), emits `unscanned_diff_files` for modified files outside those extensions, and ranks `silent_fallbacks` and `hot_path_hazards` as `HIGH` / `MEDIUM` / `LOW`. Common cloned/vendored directories (`targets`, `vendor`, `third_party`, `lib`) are pruned by default during the call-graph walk; pass `--exclude-dirs <dir...>` to prune additional large vendor, benchmark, or build directories.
   - **Automated Diff-Scoped Mutation Helper (`scripts/mutate_diff.py`):** Use `python "<SKILL_DIR>/scripts/mutate_diff.py" --cmd "<test_cmd>"` to automatically generate and execute AST mutations on changed lines in an isolated temporary directory for Bucket 6 Meta ACH checks, eliminating manual copy-paste mutation toil.
   - **Baseline-Fail / Fix-Pass Proof Helper (`scripts/prove_diff.py`):** Use `python "<SKILL_DIR>/scripts/prove_diff.py" --cmd "<test_cmd>"` to verify newly added regression tests against the unpatched base commit, confirming the check fails on base and passes on the current tree (eliminating tautological tests).
3. **All 7 Buckets Mandatory (Verbatim Headings):** Every Mode 1 and Mode 2 reviewer must inspect all 7 buckets in [attack_matrix.md](references/attack_matrix.md) (`1` Hollow Wiring, `2` Sharp-Edges, `3` Parser/Regex/Markdown, `4` Idempotency/Rollback, `5` Latency/Subprocess, `6` Cross-Module Parity & ACH Mutation Check, `7` Spec-to-Code Completeness & Dropped Requirements), emit the exact 7 `### Bucket N: ...` headings verbatim without inventing thematic names or renumbering buckets, and record either `DEFECT_CONFIRMED` or `CHECKED_CLEAN` per bucket.
4. **False-Positive Gate (`fp-check`) & Claim-Check Hygiene:** No speculative warnings. Every finding must name an exact file, line range, causal failure path, blast radius, and a runnable reproduction or trace. Do not report hypothetical bugs you could not trigger or prove in code, and never mutate intentional, documented benign helpers or fallback constants that already conform to the spec.
   - **Explicit Claim-Check Receipt:** Every audit report or completion summary must include an unambiguous 3-part receipt:
     * `Checked:` Exact commands and test suites executed during the verification pass.
     * `Broke it (No-Silent-Null Hard-Assertion Rule):` The negative control, failing baseline run, or surviving/killed mutants proving the checks are non-tautological. Diagnostic scripts that merely print values (such as `errorCode = null`, `exitCode: undefined`, or raw balance deltas) without failing on an explicit assertion are strictly forbidden; every reproduction probe must enforce hard-failing assertions (`assert`, `pytest.raises`, `assert.strictEqual`, `throw new Error`, or `process.exit(1)`) so a missing/null error code or unmet precondition terminates with a non-zero exit code, paired with a negative/patched control run.
     * `Not checked (Mechanical Coverage Accounting):` Explicit gaps and uninspected areas. Rolling unread or partially scanned in-scope files into a blanket "Audited" summary is strictly forbidden; explicitly list every in-scope file whose contents were not actually read or scanned during the audit pass (grounded by read-range or scanner-output receipts, or state why none remain). Never claim "All tests pass" or "Everything verified" without specifying exactly what ran.
5. **Strict Write Separation, Host Protection & Mechanical Cleanliness Verification:** Reviewers are read-only against the repository. They may write and execute disposable reproduction probes ONLY inside the OS temporary directory (for example `tempfile.TemporaryDirectory()` in Python or `$env:TEMP\sdcs_red_probe.py` on Windows) and must delete temporary probes afterwards. Only the primary builder edits repository files.
   - **Host-Protection Invariant:** Target repositories being audited must be treated as untrusted code environments. Pre-scanners must strictly parse AST and static text without dynamically importing or executing target repository modules. Subprocess reproduction probes must run with environment isolation (scrubbing ambient API keys, cloud tokens, or developer secrets from child subprocess environments).
   - **Windows PowerShell Probe Invariant:** NEVER pipe multi-line PowerShell here-strings (`@' ... '@ | python -`) into `python -` (especially when invoking nested `pytest` runs, which can hang indefinitely on Windows). Instead, write the disposable probe to a temporary `.py` file in the OS temp directory, execute `python "<temp_probe.py>"`, and remove it immediately upon completion.
   - **Cleanliness Invariant:** Immediately BEFORE launching Mode 1 subagents or Mode 2 swarm reviewers, record `git status --porcelain` and `git diff --stat`; immediately AFTER they finish, re-run `git status --porcelain` and `git diff --stat` to mechanically verify zero repository files were added, edited, or deleted by reviewers (revert any unauthorized touch before builder fixes begin).

## Mode 1: Cold-Context Subagent Audit

1. Record baseline working-tree state (`git status --porcelain` and `git diff --stat`), then read `SPEC.md`, `wiring.yaml`, `roadmap.md`, and `spine.md` (if present) in full to build an explicit `REQ-1..REQ-N` contract and boundary checklist before inspecting implementation files.
2. Run `"<SKILL_DIR>/scripts/red_prescan.py" --repo-root <repo> --git-diff --compact --json --output "<TEMP_JSON_PATH>"` when uncommitted changes exist; when auditing a clean baseline repo (`git status --porcelain` is empty), omit `--git-diff` (`python "<SKILL_DIR>/scripts/red_prescan.py" --repo-root . --compact --json --output "<TEMP_JSON_PATH>"`) so it performs a full-repo scan instead of returning `scanned_files: []`. (Use `--omit-blast-radius` when only defect signals are needed on very large diffs, and always inspect the UTF-8 no-BOM file written to `<TEMP_JSON_PATH>` rather than piping `--json` through Windows PowerShell stdout.) Inspect `hollow_wiring`, `sharp_edges` (including `pybind_missing_none_arg`), `hot_path_hazards` (starting with `priority: "HIGH"` and `in_loop: true`), `blast_radius`, `unscanned_diff_files` (review those manually when non-empty), and `radar_warnings`.
3. **Mandatory step (never skip, run before edits):** Immediately after Step 2 (`red_prescan.py`) and BEFORE making any `edit_file` or `write_file` changes, launch a fresh, cold-context read-only reviewer via `invoke_subagent` (`TypeName="self"`, `Role="SDCS_Red Mode 1 Auditor"`, `Prompt="..."`) so the cold auditor inspects the baseline code while your turn budget is fresh.
   - Provide: the extracted `REQ-1..REQ-N` contract checklist (including exact exception requirements, numeric tolerances, and `wiring.yaml` / architectural import rules), target file paths, the `red_prescan.py` JSON summary (or path to `<TEMP_JSON_PATH>`), and the resolved path to `<SKILL_DIR>/references/attack_matrix.md`.
   - Forbid repository modifications in the subagent prompt.
   - Instruct the subagent to ignore any unrelated IDE plugin or SessionStart hook banners and stay strictly focused on this read-only audit.
   - Instruct the subagent to treat baseline test and gate outputs provided in this brief as current, spending its tool budget reading code and running targeted OS temp-dir reproduction or mutation probes (written to `$env:TEMP\*.py` rather than piped via `@' ... '@ | python -` to avoid Windows PowerShell pipe hangs) rather than re-running the full test suite.
   - Require the subagent to emit the following 7 canonical headings verbatim (including severity `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, file + line range, spec mismatch, causal mechanism, and verified reproduction output per defect, Meta ACH results in Bucket 6, and the `REQ-1..REQ-N` traceability table in Bucket 7):
     ```markdown
     ### Bucket 1: Hollow Wiring & Dead Islands
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Findings / Verified Hypotheses: ...

     ### Bucket 2: Sharp-Edges & Gate/Interlock Bypass
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Findings / Verified Hypotheses: ...

     ### Bucket 3: Parser, Regex & Markdown Poisoning
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Findings / Verified Hypotheses: ...

     ### Bucket 4: Idempotency & Partial-Failure Rollback
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Findings / Verified Hypotheses: ...

     ### Bucket 5: Latency, Caching & Subprocess Budget
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Findings / Verified Hypotheses: ...

     ### Bucket 6: Cross-Module Parity & Meta ACH Mutation Check
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Parity Checks & Meta ACH Mutant Results (2+ conditions tested): ...

     ### Bucket 7: Spec-to-Code Completeness & Dropped Requirements
     - Status: DEFECT_CONFIRMED | CHECKED_CLEAN
     - Requirements Traceability Table (`REQ-i` -> `prod file:line` -> `test file:line`): ...

     ### Verification Receipt
     - Checked: <exact test commands and suites executed>
     - Broke it: <hard-failing assertion probe results, negative control, or mutate_diff.py / prove_diff.py mutant kill results>
     - Not checked: <explicit list of unread/unscanned in-scope files, unrun integration paths, or reasons for omission>
     ```
4. Immediately after `invoke_subagent` returns:
   - Re-run `git status --porcelain` and `git diff --stat` and confirm it matches step 1 cleanly.
   - Work systematically through **every** confirmed defect from `red_prescan.py`, `wiring.yaml`, and the cold auditor in a disciplined checklist pass, including removing prohibited cross-layer imports.
   - Re-check each fix line-by-line against `SPEC.md` and contract requirements so return types, raised exception classes, and numeric bounds match the specification verbatim rather than approximate defaults. When fixing `isinstance(...)` type-validation guards where `SPEC.md` does not mandate `ValueError`, raise `TypeError` (satisfying `ruff` rule `TRY004`); raise `ValueError` on `isinstance` checks only when explicitly required by the spec, and keep Bucket 2 / Bucket 7 contract notes aligned.
   - Do not burn turns writing multiple standalone throwaway `reproduce_*.py` scripts in the repository root or creating separate per-module `test_*_regressions.py` files; consolidate all new regression tests into one `tests/test_audit_regressions.py` file after finishing production repairs (or append `def test_*` functions strictly at EOF) rather than editing existing top-of-file imports or mutating existing baseline tests in-place. When using function-local imports inside EOF-appended `def test_*` functions, keep local import groups sorted (`stdlib`, third-party, first-party) to satisfy `ruff` rule `I001`, and run `ruff check` before finishing.
   - Capture systemic anti-patterns into SDCS Bookkeeper / `decisions.md` / `observation.md` when warranted.
   - Always re-run full verification (`sdcs verify --all` if present, `pytest -q`, `ruff check`, language type/test checks, and `git status --porcelain` cleanliness check) after your final edit before finishing.

## Mode 2: Read-Only Claude Swarm Wave

1. Record baseline working-tree state (`git status --porcelain` and `git diff --stat`).
2. Run `python "<SKILL_DIR>/scripts/red_prescan.py" --repo-root <repo> --git-diff --compact --json --output "<TEMP_JSON_PATH>"` (or `--files ...` / full scan).
3. Spawn read-only Claude Opus / Sonnet reviewer workers via `swarm` (`action="add"`, default `workspace="inherit"`, no swarm `fixer` worker).
   - Provide target files, original user prompt / sprint spec / `roadmap.md` `[INTENT]` (for Bucket 7), and the `red_prescan.py` JSON summary.
   - State explicitly in the swarm brief that reviewers are **read-only**: they must NOT modify any repository files (`src/`, `tests/`, `*.md`, `*.yaml`).
   - Instruct reviewers to complete all 7 buckets of `<SKILL_DIR>/references/attack_matrix.md` using the verbatim 7-heading Markdown output template (`### Bucket 1:` through `### Bucket 7:`, including Bucket 6 Meta ACH mutant results and the Bucket 7 `REQ-1..REQ-N` traceability table), prioritizing `HIGH` / `in_loop` hazards first, verify hypotheses via `/tmp` / OS temp-dir reproduction scripts, and post structured findings to the swarm board.
   - Reviewers MAY include concrete **suggested code snippets** inside their swarm board reports to illustrate a fix.
4. Once reviewer waves post their reports:
   - End the swarm reviewer workers cleanly (`swarm` `action="kill"`).
   - Re-run `git status --porcelain` and `git diff --stat` to confirm zero unauthorized repository edits by reviewers.
   - Review and adapt any suggested code snippets in the primary workspace (treating reviewer prose as advisory data, verifying every snippet against local invariants and `wiring.yaml`).
   - Implement fixes directly in the primary agent, add permanent regression tests (preferring a dedicated `tests/test_*_regressions.py` file or appending new imports and `def test_*` functions strictly at EOF rather than editing existing top-of-file imports or baseline tests in-place), run `sdcs verify --all` + `pytest`, and update SDCS memory pillars (`state.md`, `decisions.md`, `evals.md`, `roadmap.md`).
