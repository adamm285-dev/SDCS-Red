# Executive Briefing: SDCS_Red (Spec-Driven Cognitive Scaffolding Adversarial Audit Kit)

## Overview & Vision
SDCS_Red is an adversarial code review and verification kit built specifically for autonomous AI coding agents (such as Google Antigravity, Anthropic Claude Code, OpenAI Codex, and Cursor). 

In traditional AI software engineering, LLMs reviewing their own or other agents' code suffer from a critical flaw: **agreeable confirmation bias**. If a code diff appears well-formatted, well-commented, and syntactically clean, the reviewing agent almost always accepts it as correct, missing subtle runtime traps, silent fallbacks, and boundary leaks.

SDCS_Red solves this by placing the auditor in a **cold, adversarial refutation posture**:
- The auditor does not review to validate; the auditor reviews to break.
- Claims of defects must be proven with hard-failing reproduction scripts (`Broke it`).
- Reviews must audit across a mandatory 7-bucket attack matrix without early termination.

---

## The Core Architecture

### 1. Zero-Read Deterministic Pre-Scanning (`red_prescan.py`)
Before an AI agent spends tokens reading raw code, `red_prescan.py` runs sub-second AST analysis offline:
- Scopes dynamically to `git diff` against `HEAD` or target branches.
- Detects hollow function stubs and empty methods across 12+ programming languages.
- Detects parameter shadowing, unused decorative parameters, and loose MCP tool interfaces.
- Detects regex recompilation and unreleased file descriptors in loops.
- Detects dangerous runtime sharp edges: shell `eval`, unquoted array globs, batch delayed expansion traps, and PowerShell non-interactive CI hangs.

### 2. Cold-Context Subagent Isolation
Instead of running code review in the active session where the author's rationale and conversational history bias the model, SDCS_Red launches a fresh, isolated, read-only subagent. The reviewer sees only the raw diff and the pre-scanner telemetry, forcing objective inspection.

### 3. The 7 Mandatory Attack Buckets
Auditors cannot stop after identifying a few surface issues. They must audit across all 7 dimensions:
1. **Spec & Scope Drift:** Verification of contract supremacy and preventing silent requirement loss.
2. **Architectural Boundaries:** Verification of declarative import graphs and layer isolation.
3. **Hollow Stubs & Decorative Signatures:** Eliminating placeholder implementations and fake mocks.
4. **Silent Fallbacks & Error Swallowing:** Eliminating bare `except: pass` and fallback defaults that hide upstream crashes.
5. **Runtime Sharp Edges & Shell Traps:** Preventing OS command execution failures and shell environment traps.
6. **Hot-Path Inefficiencies & Resource Leaks:** Eliminating unclosed handles and O(N^2) loops.
7. **Grounding, Tests & Negative Controls:** Verifying that tests actually fail when bugs are present.

### 4. Mutation Testing & Test Suite Hardening (`mutate_diff.py`)
Passing unit tests are not proof of correctness. `mutate_diff.py` injects subtle mutations (inverting comparison operators, altering constants, returning `None`) into modified lines to prove whether existing unit tests are strict enough to catch regressions.

### 5. The Verification Receipt Contract
Every audit run terminates with an unambiguous contract:
- `Checked:` Exact files, functions, and line ranges audited.
- `Broke it:` Explicit reproduction scripts that fail with non-zero exit codes.
- `Not checked:` Exact in-scope files that were not examined, preventing false claims of complete coverage.

---

## Polyglot Support Matrix
SDCS_Red provides pre-scanning and static verification across:
- **Python:** Full AST tree traversal, parameter shadowing, loose MCP tool schemas.
- **Apple & Xcode:** Swift, Objective-C, Objective-C++ (`.swift`, `.m`, `.mm`) with detection of fatal nil force-unwraps (`!`).
- **JVM Languages:** Java, Kotlin, Scala (`.java`, `.kt`, `.kts`, `.scala`).
- **Systems Languages:** C, C++, CUDA (`.c`, `.cpp`, `.cu`), Zig (`.zig`), Nim (`.nim`), Rust (`.rs`), Go (`.go`).
- **Web & Scripting:** TypeScript, JavaScript, Dart, Ruby, PHP.
- **Shell & Batch:** Bash, Zsh, Windows Command Prompt Batch, PowerShell.

---

## Key Takeaways for Teams & Executives
1. **Higher Code Reliability:** Catches subtle runtime crashes before code reaches production or CI pipelines.
2. **Token Efficiency:** Sub-second local pre-scanning flags high-risk lines before invoking expensive LLM reasoning turns.
3. **Framework Agnostic:** Drops seamlessly into Antigravity skills, Claude Code slash commands, or standalone CI/CD workflows.
