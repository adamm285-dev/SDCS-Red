# `sdcs-red`: Dual-Mode Adversarial Code Audit Kit for AI Agents

`sdcs-red` is a dual-mode adversarial code review and verification engine designed for autonomous coding agents (Antigravity, Claude Code, Codex, and Cursor). It pairs deterministic polyglot AST pre-scanning with cold-context read-only refutation across a mandatory 7-bucket attack matrix.

---

## Why `sdcs-red` Exists

Polite, agreeable code reviews miss subtle runtime failures, silent fallbacks, and boundary traps. LLM agents reviewing their own or peers' implementations suffer from positive confirmation bias: if the diff looks clean on paper, they assume it works.

`sdcs-red` enforces an adversarial refutation posture:
1. **Separation of Concerns:** The auditor runs in a fresh, read-only subagent context with no author rationale or commit justifications.
2. **Deterministic Pre-Scanning:** `red_prescan.py` runs offline in sub-second time, flagging hollow stubs, shadowing, unbounded networks, shell injection risks, and polyglot traps before the model even reads the diff.
3. **Mandatory 7-Bucket Matrix:** The review cannot terminate early after discovering two or three surface defects. All seven failure modes must be explicitly audited or accounted for.
4. **Hard-Failing Negative Control Probes:** Claims of vulnerabilities or regressions must be proved using non-zero exit code reproduction scripts (`Broke it`), preventing silent-null or false-positive assertions.
5. **Mutation Verification:** `mutate_diff.py` deliberately injects boundary inversions and operator mutations to prove whether existing unit tests are rigorous enough to catch regressions.

---

## Architectural Modes

### Mode 1: Self-Audit & Pre-Flight Review (Single-Agent / Subagent)
Triggered whenever asking for a pre-commit audit, "double-check your work", or "run another round":
- Auto-scopes using `git diff` against `HEAD` or target branch.
- Deterministic pre-scan flags hot spots and AST hazards.
- Cold subagent audits the scoped diff against all 7 buckets.
- Produces a structured **Verification Receipt** with `Checked:`, `Broke it:`, and `Not checked:`.

### Mode 2: Adversarial Multi-Agent Waves (Red Team vs. Author)
Triggered for high-stakes refactoring, security reviews, or multi-turn agent challenges:
- **Wave 1 (Red Attack):** Read-only red agent explores diff, writes hard-failing repro probes, and submits findings.
- **Wave 2 (Author Remediation):** Author agent fixes true positives, proves fixes with tests, and adds rejection lessons.
- **Wave 3 (Verification & Mutation):** Red agent re-runs hard probes to confirm fixes, runs `mutate_diff.py`, and signs off.

---

## The 7 Mandatory Attack Buckets

Every audit pass must inspect each of the following buckets:

| Bucket | Focus Area | High-Yield Traps & Checks |
| :--- | :--- | :--- |
| **1. Spec & Scope Drift** | Requirements compliance & contract supremacy | Silent requirement drops, dropped CLI flags, untracked mid-session contract drift. |
| **2. Architectural Boundaries** | Declarative topology & layer leaks | Layer violations, cross-boundary imports, unauthorized persistence access. |
| **3. Hollow Stubs & Decorative Signatures** | Phantom implementations & unused parameters | Empty handlers, `pass` bodies, unused parameters shadowing outer scopes. |
| **4. Silent Fallbacks & Error Swallowing** | Resiliency masking critical failures | Bare `except: pass`, fallback defaults hiding upstream API crashes, missing return types. |
| **5. Runtime Sharp Edges & Shell Traps** | OS command execution & environment brittleness | `$USER` `eval`, unquoted array globs, PowerShell `-NonInteractive` hangs, batch delayed expansion. |
| **6. Hot-Path Inefficiencies & Leaks** | O(N^2) loops & unreleased handles | Regex compilation inside tight loops, unbounded network timeouts, unclosed file descriptors. |
| **7. Grounding, Tests & Negative Controls** | Verification fidelity & mutant kill rate | Tests asserting on `None`, tautological assertions, weak test assertions exposed by mutation. |

---

## Comprehensive Polyglot Engine

`red_prescan.py` supports deterministic static analysis across diverse languages and runtimes:

- **Python:** Full AST inspection (`ast.parse`), parameter shadowing, unused argument detection, loop-nested compilation, loose MCP tool schemas (`**kwargs`, untyped dicts).
- **Apple & Xcode:** Swift, Objective-C, Objective-C++ (`.swift`, `.m`, `.mm`). Detects empty `func` stubs, chained force-unwraps (`!`) causing `fatalError` nil crashes.
- **JVM Languages:** Java, Kotlin, Scala (`.java`, `.kt`, `.kts`, `.scala`). Detects empty methods and unhandled exceptions.
- **Systems Languages:** C, C++, CUDA (`.c`, `.cpp`, `.cu`), Zig (`.zig`), Nim (`.nim`), Rust (`.rs`), Go (`.go`). Detects `todo!()` macros and nanobind/pybind missing `None` argument guards.
- **Web & Scripting:** TypeScript/JavaScript (`.ts`, `.tsx`, `.js`), Dart (`.dart`), Ruby (`.rb`), PHP (`.php`). Detects dynamic `eval` injection and empty callbacks.
- **Shell & Batch:** Bash/Zsh (`.sh`), Windows Batch (`.bat`), PowerShell (`.ps1`). Detects `EnableDelayedExpansion` exclamation mark loss, `if errorlevel` ordering traps, and `Read-Host` non-interactive hangs.

---

## Repository Structure

```
sdcs-red/
├── pyproject.toml              # Build & test configuration (zero runtime dependencies)
├── README.md                   # Complete skill & toolchain documentation
├── SKILL.md                    # Core Antigravity / Claude skill specification
├── references/
│   └── attack_matrix.md        # Comprehensive 7-bucket audit guidance & examples
├── scripts/
│   ├── red_prescan.py          # Deterministic polyglot pre-scanner with git-diff auto-scoping
│   ├── mutate_diff.py          # Mutation testing runner for verifying test rigor
│   └── prove_diff.py           # Hard-assertion negative control verification helper
└── tests/
    └── test_sdcs_red.py        # Comprehensive test suite (32 tests covering all engines)
```

---

## Verification Receipt Contract

Every audit concludes with an unambiguous, human-verifiable receipt:

```markdown
### Verification Receipt
- Checked: [Exact files, functions, and lines audited against all 7 buckets]
- Broke it: [Failing reproduction script paths or 'None' if all probes passed]
- Not checked: [Explicit list of in-scope files not read or scanned during this pass]
```

### The No-Silent-Null Rule
Reproduction probes in `Broke it:` must use hard-failing assertions (`assert`, `pytest.raises`, `process.exit(1)`). Diagnostic scripts that merely print output while exiting with code 0 are strictly rejected.

---

## Installation & Usage

### Running Locally
To test and run the static analyzer directly:
```bash
python scripts/red_prescan.py --repo-root . --json
```

To run against a git diff:
```bash
python scripts/red_prescan.py --git-diff HEAD~1 --compact
```

To run unit tests:
```bash
pytest tests/test_sdcs_red.py -v
```

### Installing into AI Agent Environments
- **Antigravity / Gemini CLI:** Copy `sdcs-red/` into `~/.gemini/config/skills/sdcs-red/`.
- **Claude Code / Cursor:** Copy `sdcs-red/` into your workspace `.agents/skills/sdcs-red/` or `skills/sdcs-red/`.

---

## License

MIT License. Designed and maintained as part of the SDCS ecosystem.
