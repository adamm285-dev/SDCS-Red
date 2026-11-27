<div align="center">

# 🔴 SDCS_Red

### *Dual-Mode Adversarial Code Review & AST Verification Engine for AI Agents*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero-Read Pre-Scan](https://img.shields.io/badge/Pre--Scan-Sub--Second%20AST-orange.svg)]()
[![Polyglot Coverage](https://img.shields.io/badge/Polyglot-12%2B%20Languages-success.svg)]()
[![Agents: Antigravity | Claude | Cursor](https://img.shields.io/badge/Agents-Antigravity%20%7C%20Claude%20%7C%20Cursor-purple.svg)]()

<br/>

**Stop polite, agreeable code reviews from approving broken software.**  
SDCS_Red pairs deterministic polyglot AST pre-scanning with cold-context adversarial refutation across a mandatory 7-bucket attack matrix.

<br/>

[Key Features](#key-features) •
[Why SDCS_Red](#why-sdcs_red-exists) •
[Dual Modes](#architectural-modes) •
[The 7 Buckets](#the-7-mandatory-attack-buckets) •
[Polyglot Matrix](#polyglot-engine-coverage) •
[Verification Receipt](#verification-receipt-contract) •
[Quick Start](#quick-start)

---

</div>

<br/>

## 🎯 Key Features

<div align="center">

| ⚡ Deterministic Pre-Scan | 🧊 Cold-Context Isolation | 🧬 Mutation Verification | 🛡️ Polyglot Traps |
| :---: | :---: | :---: | :---: |
| Sub-second AST scan runs offline before LLM context is loaded. | Reviewer agent operates cold with zero author rationale. | Injects mutations to test if test suites actually catch bugs. | Catches shell `eval`, batch expansion, Swift unwraps, etc. |

</div>

---

## 💡 Why SDCS_Red Exists

> **The Polite Agent Trap:** Coding agents reviewing their own or peer code naturally suffer from confirmation bias. If the diff looks clean on paper, they assume it works in runtime.

SDCS_Red enforces an uncompromising refutation posture:

1. **Cold-Context Separation:** The auditor runs in a fresh, read-only subagent context with no author rationale or commit justifications.
2. **Deterministic Pre-Scanning:** `red_prescan.py` runs offline in sub-second time, flagging hollow stubs, shadowing, unbounded networks, shell injection risks, and polyglot traps before the model even reads the diff.
3. **Mandatory 7-Bucket Matrix:** The review cannot terminate early after finding two or three surface defects. All seven failure modes must be explicitly audited or accounted for.
4. **Hard-Failing Negative Control Probes:** Claims of vulnerabilities or regressions must be proved using non-zero exit code reproduction scripts (`Broke it`), preventing silent-null or false-positive assertions.
5. **Mutation Verification:** `mutate_diff.py` deliberately injects boundary inversions and operator mutations to prove whether existing unit tests are rigorous enough to catch regressions.

---

## 🔄 Architectural Modes

### Mode 1: Self-Audit & Pre-Flight Review (Single-Agent / Subagent)
*Triggered on "double-check your work", "pre-flight check", or "sdcs-red":*
- Auto-scopes using `git diff` against `HEAD` or target branch.
- Deterministic pre-scan flags hot spots and AST hazards.
- Cold subagent audits the scoped diff against all 7 buckets.
- Produces a structured **Verification Receipt** with `Checked:`, `Broke it:`, and `Not checked:`.

### Mode 2: Adversarial Multi-Agent Waves (Red Team vs. Author)
*Triggered on "adversarial review with Claude" or high-stakes refactoring:*
- **Wave 1 (Red Attack):** Read-only red agent explores diff, writes hard-failing repro probes, and submits findings.
- **Wave 2 (Author Remediation):** Author agent fixes true positives, proves fixes with tests, and adds rejection lessons.
- **Wave 3 (Verification & Mutation):** Red agent re-runs hard probes to confirm fixes, runs `mutate_diff.py`, and signs off.

---

## 🥊 The 7 Mandatory Attack Buckets

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

## 🌐 Polyglot Engine Coverage

`red_prescan.py` runs deterministic static analysis across diverse languages and runtimes:

```
├── Python              Full AST inspection, parameter shadowing, unused argument detection, loop regex compilation
├── Apple & Xcode       Swift (.swift), Objective-C (.m, .mm) — empty funcs, chained force-unwraps (!)
├── JVM Languages       Java (.java), Kotlin (.kt, .kts), Scala (.scala) — empty methods, exception swallowing
├── Systems Languages   C/C++/CUDA (.c, .cpp, .cu), Zig (.zig), Nim (.nim), Rust (.rs), Go (.go) — todo!() macros
├── Web & Scripting     TypeScript/JavaScript (.ts, .tsx, .js), Dart (.dart), Ruby (.rb), PHP (.php) — eval injection
└── Shell & Batch       Bash/Zsh (.sh), Windows Batch (.bat), PowerShell (.ps1) — DelayedExpansion, errorlevel
```

---

## 📜 Verification Receipt Contract

Every audit concludes with an unambiguous, human-verifiable receipt:

```markdown
### Verification Receipt
- Checked: [Exact files, functions, and lines audited against all 7 buckets]
- Broke it: [Failing reproduction script paths or 'None' if all probes passed]
- Not checked: [Explicit list of in-scope files not read or scanned during this pass]
```

### ⚠️ The No-Silent-Null Rule
Reproduction probes in `Broke it:` must use hard-failing assertions (`assert`, `pytest.raises`, `process.exit(1)`). Diagnostic scripts that merely print output while exiting with code 0 are strictly rejected.

---

## 🚀 Quick Start

### Direct CLI Analysis
```bash
# Scan full repository offline (JSON output)
python scripts/red_prescan.py --repo-root . --json

# Auto-scope against git diff
python scripts/red_prescan.py --git-diff HEAD~1 --compact

# Run mutation tester on modified lines
python scripts/mutate_diff.py --git-diff HEAD~1
```

### Install into AI Agent Environments
- **Antigravity / Gemini CLI:** Copy `sdcs-red/` into `~/.gemini/config/skills/sdcs-red/`.
- **Claude Code / Cursor:** Copy `sdcs-red/` into your workspace `.agents/skills/sdcs-red/` or `skills/sdcs-red/`.

---

<div align="center">

Part of the **Spec-Driven Cognitive Scaffolding (SDCS)** ecosystem.  
*Engineered for high-assurance autonomous development.*

</div>
