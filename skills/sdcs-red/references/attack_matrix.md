# SDCS_Red Mandatory 7-Bucket Refutation Matrix

Every adversarial audit wave MUST actively test hypotheses across ALL 7 buckets below using the verbatim `### Bucket 1:` through `### Bucket 7:` headings from `SKILL.md` (never invent thematic bucket titles or renumber buckets). Stopping early after finding 3 or 4 bugs in Bucket 1 or Bucket 2 is forbidden. Mark each bucket either `DEFECT_CONFIRMED` (with file, line range, mechanism, and runnable repro) or `CHECKED_CLEAN` (naming the exact hypothesis tested and why it holds), include Meta ACH mutant results in Bucket 6, include a `REQ-1..REQ-N -> prod file:line -> test file:line` traceability table in Bucket 7, and enforce the Verification Receipt rules (hard-failing assertions for `Broke it` probes and mechanical coverage accounting for `Not checked`).

## Bucket 1: Hollow Wiring & Dead Islands
- **Target failures:** Features implemented cleanly in a helper or library module and covered by unit tests, yet never called from production workflows, CLI handlers, stager hooks, or MCP tools.
- **Concrete checks:**
  - Verify every public helper created or modified has at least one live production caller (`prod_callers` in `red_prescan.py`).
  - Check for orphaned modules under `src/`: ensure every newly added `.py` module is imported by at least one production module or declared entrypoint (`orphaned_modules` in `red_prescan.py` and Gate K `PY_ORPHANED_MODULE`).
  - Inspect boolean flags, keyword options, and CLI arguments for decorative acceptance where the value is ignored or only toggled in tests.
  - Check new functions for hollow bodies (`pass`, `...`, empty literals, unconditional `None`) or `except NotImplementedError` / `except ImportError` / `except Exception` blocks returning empty success payloads (`False`, `None`, `[]`, `{}`), especially broad `except` handlers that silently mask syntax, parse, or validation failures where the specification requires raising a specific exception.
  - Scrutinize test assertions and status checks for 200-OK error traps: verify tests do not assert HTTP 200 or return True while ignoring error responses wrapped in successful transport layers (such as 502/503 gateways, rate limits, or empty mock payloads masked as success).
  - Confirm `MOCK(M-NNN)` markers and `MOCKS.md` entries exist for any intentional placeholder (`sdcs verify --mocks`).

## Bucket 2: Sharp-Edges & Gate/Interlock Bypass
- **Target failures:** Flags, alternate code paths, MCP wrappers, environment overrides, or convenience options that allow callers (or models) to bypass safety gates, invariants, or architectural constraints.
- **Concrete checks:**
  - Compare MCP tool surfaces vs CLI commands vs internal Python APIs: ensure restricted flags (`auto_resolve_strike3`, `--no-elastic`, force flags, dry-run shortcuts) are not accidentally exposed to untrusted surfaces or left skipping validation.
  - Audit MCP and agentic tool boundaries for tool poisoning and confused deputy hazards: verify tool descriptions, parameter schemas, and default arguments do not permit arbitrary filesystem traversal, command injection, or untrusted URL fetches without validation.
  - Vetting MCP Tool Schemas: check that tool functions (`@tool`, `@server.call_tool`, `execute_*`) enforce strict, typed parameter schemas; flag untyped parameters, loose `dict` / `Any` dictionaries, or unconstrained `**kwargs` (`mcp_untyped_param_sink` in `red_prescan.py`) that allow adversaries to smuggle unexpected injection arguments to internal helpers.
  - MCP Tool-Description & Rug-Pull Poisoning Defense (AIGoat MCP03/MCP04): inspect tool docstrings, markdown descriptions, and schema declarations for embedded prompt-injection instructions (e.g. phrases instructing the model to always forward tokens, bypass approval gates, or exfiltrate state); verify that tool definitions cannot undergo dynamic schema rug-pulls or parameter redefinition without strict registration interlocks.
  - Agentic Memory & State-Store Poisoning Defense: audit long-term memory updates (`state.md`, scratchpads, ticket stores) to verify that external untrusted payload text (e.g. issues, reviews, commit messages) cannot persist directives that alter subsequent agent turns, hijack execution goals, or subvert constitutional rules.
  - Verify indirect prompt injection defenses: ensure parsers handling untrusted inputs (scraped web pages, external tool outputs, user-supplied Markdown/files) delimit untrusted content and cannot manipulate control flow, override system prompts, or trigger privileged tool invocations.
  - Test alternate input shapes (empty strings, uppercase/lowercase extensions, symlinks, relative paths, Windows vs POSIX separators, `cwd != repo_root`).
  - Verify pre-flight checks run BEFORE irreversible mutations or strike resets, never after.
  - Audit module imports across every package against `wiring.yaml` and declared architectural layer boundaries to catch prohibited cross-subsystem imports (such as an entry or intake layer importing storage internals directly) and traps in `decisions.md` (use `radar_warnings` from `red_prescan.py`).
  - Audit outbound network requests (HTTP/RPC webhooks, callbacks, token URLs) for Server-Side Request Forgery (SSRF) and DNS rebinding hazards: ensure requests block private/loopback/cloud metadata IP ranges (such as 169.254.169.254, 127.0.0.1, ::1) and enforce explicit connection and read timeouts.
  - Audit subprocess and CLI execution surfaces for shell injection: ensure subprocess calls avoid shell=True, use strict argv argument lists, and sanitize any dynamic arguments interpolated into shell commands.
  - Audit shell (.sh), batch (.bat/.cmd), and PowerShell (.ps1) scripts for runtime environment traps:
    * Shell: detect unquoted `eval $var` / `eval "${var}"` injection and double-quoted wildcard elements in arrays (e.g. `files=("*.txt")` which prevents glob expansion and matches 0 files).
    * Batch: detect `setlocal EnableDelayedExpansion` eating exclamation marks (`!`) in paths and `IF ERRORLEVEL N` which tests `>= N` rather than `== N`.
    * PowerShell: detect `Read-Host` invocations that hang or crash under `-NonInteractive` / automated runtimes.
  - Scrutinize any dynamic code evaluation (`eval`, `exec`, `Function`): remember that `eval(expr, {"__builtins__": {}})` is still exploitable via object and attribute traversal gadgets and must be replaced with a strict `ast.parse(..., mode="eval")` AST node whitelist evaluator that raises the spec-required exception (`ValueError`) on syntax errors or disallowed AST nodes instead of returning `False`.
  - Check C++ `nanobind`/`pybind11` `.def(...)` bindings (`pybind_missing_none_arg` in `red_prescan.py`): any binding checking `.is_none()` or calling `wrap_optional_*` requires `.none()` or `= nb::none()`/`= py::none()` on `nb::arg`/`py::arg`. For Python `isinstance(...)` guards where `SPEC.md` does not mandate `ValueError`, raise `TypeError` to satisfy `ruff` rule `TRY004`.

## Bucket 3: Parser, Regex & Markdown Poisoning
- **Target failures:** Fragile string splitting, regex anchors, or AST walkers that break on valid real-world Markdown, docstrings, comments, code fences, or edge formatting.
- **Concrete checks:**
  - Feed multi-paragraph text, code blocks containing fake headers (`## Fake Header` inside triple backticks), inline code containing punctuation, Unicode characters, and Windows `\r\n` line endings into Markdown/text parsers.
  - Audit Markdown and Generative UI rendering sinks for data exfiltration: verify that user-controlled strings or runtime tokens cannot be interpolated into Markdown image tags (`![...](url)`) or HTML tags without strict protocol/host validation, preventing ambient secrets or context leakage to external servers.
  - Check CLI and terminal output formatting for terminal escape sequence injection: verify ANSI escape codes in untrusted input strings are stripped or escaped before printing to console logs.
  - Check tokenizer/scorer normalization on camelCase, snake_case, kebab-case, dotted module paths, and mixed multi-word queries (`radar`).
  - Verify AST visitors handle `AsyncFunctionDef`, `@classmethod`/`@staticmethod`, decorated functions, nested functions, closures, parameter shadowing, `posonlyargs`, `kwonlyargs`, and multi-line docstrings.

## Bucket 4: Idempotency & Partial-Failure Rollback
- **Target failures:** Interrupted writes, repeated invocations, or half-completed state transitions that corrupt ledgers, counters, indexes, or caches.
- **Concrete checks:**
  - Call mutation workflows twice on the same state and verify no duplicate bullets, double-counted strikes, or runaway section headers.
  - Simulate failures midway through multi-file operations (e.g., Gate T rejection during patch application, invalid syntax after staging) and verify working files and ledgers remain consistent and atomic.
  - Check empty/missing file initialization (missing `.sdcs/`, missing `MOCKS.md`, empty `decisions.md`, missing `sessions/manifest.jsonl`).

## Bucket 5: Latency, Caching & Subprocess Budget
- **Target failures:** Accidental quadratic scans, unbounded file reads, recursive directory walks over huge trees, blocking sleeps, or hidden subprocess invocations inside `<5ms` hot paths.
- **Concrete checks:**
  - Audit `priority: "HIGH"` and `in_loop: true` items from `red_prescan.py` first before reviewing `MEDIUM` or `LOW` entries.
  - Audit hot paths (`bookkeeper radar`, `hydrate`, `verify`) for `subprocess.*`, `os.walk`, unguarded `.rglob`, `time.sleep`, or repeated full-repo disk parsing inside loops.
  - Verify exclusions skip `.git`, `.venv`, `node_modules`, `__pycache__`, and `.sdcs` scratch directories during scans.
  - Inspect cache keys and invalidation rules to confirm stale cache entries cannot survive file edits (`mtime`, content hash, or `sdcs verify --cache-invariance`).

## Bucket 6: Cross-Module Parity & Meta ACH Mutation Check
- **Target failures:** Divergent behavior between parallel code paths (CLI vs MCP vs programmatic API, dual-synced skill files, schema writers vs readers) and subtle off-by-one or inverted conditions.
- **Concrete checks:**
  - **Cross-module parity:** Compare writer vs reader schemas (staged JSON keys, JSON CLI output keys, MCP response fields, mirrored skill copies) for key name mismatches or dropped fields, and compare shared lookup tables, scale or precision maps, rounding modes, and numeric constants across modules and across languages in polyglot codebases (such as Python vs. TypeScript/JavaScript) to catch silent drift.
  - **Meta ACH Mutation Check:** Pick the 2 highest-risk boolean conditions or threshold comparisons changed in the target scope and mentally/empirically negate them (`not`, `<` vs `<=`, `and` vs `or`, off-by-one slice bounds) to confirm existing or new tests fail loudly.
  - **No-Silent-Null Hard-Assertion Rule (`Broke it`):** Any reproduction probe or negative control test must use explicit, hard-failing assertions (`assert`, `pytest.raises`, `assert.strictEqual`, `throw new Error`, `process.exit(1)`) rather than exit-code-0 logging scripts that merely print values (such as `errorCode = null`, `exitCode: undefined`, or raw balance deltas); probes must guarantee non-zero exit codes when an error code is missing or a precondition fails.

## Bucket 7: Spec-to-Code Completeness & Dropped Requirements
- **Target failures:** Requirements, acceptance criteria, or edge behaviors stated in the user prompt, sprint spec, or `roadmap.md` `[INTENT]` that the builder silently skipped, only partially implemented, or broke baseline behavior while adding.
- **Concrete checks:**
  - Enumerate every discrete requirement from `SPEC.md`, the user prompt, sprint spec, or active `roadmap.md` `[INTENT]` into a numbered checklist (`REQ-1..REQ-N`).
  - **Anti-Norm-Drift Rule:** Ground requirements exclusively in official specs and user prompts. Reject in-code comments, docstrings, or unofficial README assertions that contradict formal requirements; flag any requirement inferred solely from implementation comments as ungrounded.
  - Map each `REQ-i` to both a production `file:line` implementation and an executable test `file:line` verification; flag any requirement with missing production wiring, partial edge-case coverage, or missing tests as `DEFECT_CONFIRMED`.
  - Verify exact numeric bounds (including asymmetric past vs. future limits or precision rules) and exact error-signaling contracts (raising a specified exception such as `ValueError` or `TypeError` per `ruff` `TRY004` vs. returning `False` or `None`) line-by-line against `SPEC.md` and `roadmap.md` `[INTENT]`.
  - Verify test-count monotonicity: ensure changes do not silently drop test counts (`TEST_COUNT_FLOOR_VIOLATION`), skip existing tests, or introduce collection errors that artificially reduce test coverage.
  - Confirm `tests/test_audit_regressions.py` additions sort any function-local imports cleanly (`ruff` `I001`) and run `ruff check` alongside existing baseline tests and `wiring.yaml` subsystem boundary checks.
  - **Mechanical Coverage Accounting (`Not checked`):** Forbid rolling unread or partially scanned in-scope files into a blanket "Audited" summary; `Verification Receipt -> Not checked:` must explicitly enumerate every in-scope file whose contents were not read or scanned during the audit pass (grounded by read-range or scanner-output receipts, or explicitly state why none remain).
