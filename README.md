# Security Workflow — Enterprise Code Security Review Plugin

Claude Code plugin + Python MCP process engine delivering a full closed loop: **Scan → Tiered Fix → Ticket Workflow → Timeout Audit → Deployment Gate**.

## Architecture

```
Claude Code Plugin Layer                     MCP Process Engine (Python)
┌────────────────────────────────┐     ┌──────────────────────────┐
│  commands/                     │     │  security_workflow/      │
│   /security-workflow:review    │─RPC─│   mcp_server.py (entry)   │
│   /security-workflow:deploy    │     │   core/         (engine)  │
│                                │     │   definition/   (enums)   │
│  agents/                       │     │   model/        (data)    │
│   security-scanner             │     │   persistence/  (storage) │
│   quick-fix                    │     │   timer/        (timeout) │
│                                │     │   spi/          (extend)  │
│  hooks/                        │     │   report/       (reports) │
│   check-bash.sh (pre-check)    │     └──────────────────────────┘
│   auto-fix-security.sh         │
└────────────────────────────────┘
```

## Quick Start

### Prerequisites

| Requirement | Required? | Notes |
|-------------|-----------|-------|
| Python 3.10+ | 🟡 Optional | MCP process engine (ticket workflow, deployment gate). Scanning works without it. |
| Bash 4.0+ | ✅ Required | Hook script runtime. macOS ships 3.2 — upgrade with `brew install bash`; Linux has 5.x built-in; Windows needs Git Bash or WSL. |
| Git | ✅ Required | Scripts prefer `git ls-files` for tracked files (auto-respects `.gitignore`). |
| Perl 5+ | ✅ Required | `auto-fix-security.sh` uses it for cross-platform safe line deletion. macOS/Linux built-in; Windows included with Git Bash. |
| GNU grep | 🟡 Recommended | macOS BSD grep lacks `\b` word boundary support — all scan patterns silently fail. Install: `brew install grep` (then use `ggrep`). |
| Claude Code | ✅ Required | Plugin host. |

Python side has zero dependencies — standard library only (`json`, `datetime`, `pathlib`, `threading`, `enum`), no `pip install` needed.

### 1. Install the Plugin

```bash
claude plugins marketplace add security-workflow hanchuntao/security-workflow
claude plugins install security-workflow@security-workflow
```

After installation, `/security-workflow:review` and `/security-workflow:deploy` are ready. The MCP process engine is auto-started by Claude Code (via `.mcp.json` config) — no manual steps required.

### 2. Verify the MCP Engine

```bash
cd security-workflow
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | python3 -m security_workflow.mcp_server
```

Expected output contains `"serverInfo":{"name":"security-workflow-mcp-engine","version":"1.0.1"}`.

If output is garbled or errors, check Python ≥ 3.10 and that `security_workflow/` is in the current working directory.

### 3. Run Integration Tests

```bash
python3 tests/integration_test.py
```

Simulates the full pipeline: `/security-workflow:review` → ticket creation → `/security-workflow:deploy` gate → remediation loop → re-gate. Outputs audit trail and PASS/FAIL verdict.

### 4. Manual Component Testing

```bash
# Security pre-check hook (single file)
bash hooks/check-bash.sh tests/vuln_cases/high_risk_demo.py   # Expected: High-Risk block exit 2
bash hooks/check-bash.sh tests/vuln_cases/mid_risk_demo.js    # Expected: Medium-Risk warn exit 1
bash hooks/check-bash.sh tests/vuln_cases/low_risk_demo.ts    # Expected: Pass exit 0

# Security pre-check hook (full project)
bash hooks/check-bash.sh                                      # Scan entire repo

# Low-risk auto-fix (dry run — safe default)
bash hooks/auto-fix-security.sh

# Low-risk auto-fix (apply mode)
SECURITY_FIX_APPLY=true bash hooks/auto-fix-security.sh
```

## Command Reference

This plugin provides two core commands corresponding to **two distinct stages** of the R&D pipeline:

```
Code → Save → git commit → /review (Code Review — discover issues)
                               │
                               ▼
                      quick-fix remediation + ticket closure
                               │
                               ▼
                      /deploy (Deploy Gate — verify & release) → 🚀 Production
```

> **Analogy**: `review` is the factory QA inspection — checks every part for cracks, sends flawed ones to repair, signs off when fixed, files the paperwork. `deploy` is the control tower's takeoff clearance — the plane is on the runway, the tower runs the final mandatory checklist: landing gear fixed? all maintenance tickets signed? One failure means grounding — no exceptions.

---

### `/security-workflow:review` — Code Security Review (Discovery Stage)

Performs static code security scanning during the **development phase**, detecting OWASP Top 10, enterprise security standards, and compliance items. On finding issues, orchestrates the quick-fix engine for remediation plans, creates security tickets, and tracks the full workflow with a complete audit trail.

**Trigger timing**: After file save, before Git commit, during MR/PR review

```
/security-workflow:review scope=project level=all mode=full workflow=true
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| scope | file / project | project | `project` = full deep scan; `file` = current file only |
| level | low / mid / high / all | all | Minimum risk level to report. `low` = ≥Low; `high` = High only |
| mode | increment / full | full | `increment` = changed files only (fast); `full` = entire codebase (thorough) |
| workflow | true / false | true | `true` = auto-create tickets and integrate with MCP process engine for closed-loop tracking |

---

### `/security-workflow:deploy` — Production Deployment Gate (Verification Stage)

The **final mandatory security check** executed before production release — the last line of defense in the R&D pipeline. It is not another scan, but rather **verifies that all known vulnerabilities have been remediated and all security tickets are closed** — any unpatched High/Medium vulnerability directly blocks deployment with zero exemption.

**Trigger timing**: Before formal release, CI/CD pipeline gate

```
/security-workflow:deploy branch=main
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| branch | branch name | main | Target deployment branch; precisely validates fix status on that branch |
| skip-review | false | false | **Permanently locked to false in production.** Cannot skip security review. |
| force | true / false | false | `true` = emergency hotfix forced deploy (requires security lead approval; mandatory retrospective within 24h) |
| workflow | true / false | true | `true` = integrate with process engine to update ticket state and retain audit trail |

**Hard Blocking Rules (No Exemption)**:
- 🔴 Production branch has **any unpatched High-risk vulnerability** → 100% block deployment
- 🟡 Medium vulnerabilities **accumulated in bulk or long-overdue without remediation** → auto-escalated to blocking level
- 📋 **Open security tickets** exist (pending review / pending fix / pending re-review) → block release
- ⏰ Overdue, unprocessed tickets → auto-escalate with security lead notification

**Relationship with `review`**: `deploy` depends on vulnerability data and ticket state produced during the `review` stage. Without `review`'s scan findings, `deploy` has nothing to verify. The two work in series, forming a complete "Discover → Fix → Verify → Release" security closed loop.

## Project Name Configuration

Ticket creation requires a project name. **Auto-detected by default** — no manual configuration needed:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 | `SECURITY_WORKFLOW_PROJECT` env var | Highest priority, ideal for CI/CD |
| 2 | `.security-workflow` config file | Create `{"project": "my-app"}` in project root |
| 3 | Current directory name | Default fallback, zero config needed |

```bash
# Option 1: Environment variable (recommended for CI/CD)
export SECURITY_WORKFLOW_PROJECT="my-backend-api"

# Option 2: Config file (recommended within a project)
echo '{"project": "my-backend-api"}' > .security-workflow

# Option 3: Do nothing — auto-detects directory name
# cd ~/work/my-backend-api → project = "my-backend-api"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_FIX_APPLY` | false | `true` enables actual fix application (default is dry-run) |
| `SECURITY_FIX_VERBOSE` | false | `true` outputs full diff |
| `SECURITY_WORKFLOW_DATA` | .security-workflow-data | Unified data directory (logs, backups, tickets, audit) |
| `SECURITY_WORKFLOW_PROJECT` | (current dir name) | Project name for ticket grouping and deploy gate filtering |
| `SECURITY_WORKFLOW_ENGINE_PATH` | ./security_workflow | MCP engine Python package path |
| `SECURITY_WORKFLOW_DEBUG` | false | `true` enables full traceback output (should be off in production) |
| `SECURITY_WORKFLOW_ENV` | production | Runtime environment identifier |

## Hooks

### check-bash.sh — Security Pre-Check

| Trigger | Behavior |
|---------|----------|
| File save | Single-file incremental scan |
| Pre-command execution | Full project scan |
| Pre-Git commit | Full project scan |

Exit codes: `0` = Pass, `1` = Medium-Risk Warning (non-blocking), `2` = High-Risk Block

**Covered File Types** (33 extensions, mainstream languages + config files):

| Category | Extensions |
|----------|------------|
| Scripting / Dynamic | `.py` `.js` `.ts` `.rb` `.php` `.lua` |
| Compiled | `.java` `.go` `.rs` `.c` `.cpp` `.cc` `.cxx` `.h` `.hpp` `.hxx` `.cs` `.swift` `.kt` `.kts` `.scala` `.dart` |
| Frontend | `.vue` `.html` |
| Shell | `.sh` `.bash` `.zsh` |
| Config | `.yml` `.yaml` `.json` `.xml` `.toml` `.ini` `.cfg` `.conf` |
| Database | `.sql` |

### auto-fix-security.sh — Low-Risk Auto-Fix

- **Triggers only before Git commit** (not on file save)
- **Dry-run by default**: set `SECURITY_FIX_APPLY=true` to actually modify files
- **Surgical matching**: only removes `console.log("debug...")` / `print("temp...")` / `pdb.set_trace()` / `debugger;` / empty TODO comments
- **Backup + rollback**: auto-backup before changes, auto-restore on failure
- **Audit log**: every run writes to `$SECURITY_WORKFLOW_DATA/fix-audit/`

## Cross-Platform Compatibility

| Dependency | macOS | Linux | Windows |
|------------|-------|-------|---------|
| Bash 4.0+ | `brew install bash` | Built-in | Git Bash / WSL |
| GNU grep (`\b` support) | `brew install grep` | Built-in | Git Bash built-in |
| Perl 5+ | Built-in | Built-in | Git Bash built-in |
| Git | `xcode-select --install` | `apt install git` | Git Bash / WSL |
| Python 3.10+ | 🟡 Optional (built-in 3.x, check version) | 🟡 Optional | 🟡 Optional |

> **macOS Alert**: macOS's built-in BSD grep **does not support `\b` word boundaries**, which silently disables all security scan patterns (no errors, but nothing matches). After installing GNU grep, `check-bash.sh` auto-detects and warns on startup.

## Unified Data Directory

All runtime artifacts are stored under `$SECURITY_WORKFLOW_DATA` (default `.security-workflow-data/`):

```
.security-workflow-data/
├── fix-audit/                     # auto-fix-security.sh output
│   ├── fix-{timestamp}.log        #   Audit logs
│   └── backups/{timestamp}/       #   Pre-fix backups
├── tickets.json                   # MCP engine ticket storage
├── audit_log.jsonl                # MCP engine operation trail
├── notifications.jsonl            # Notification records
└── reports/                       # Auto-generated by /review & /deploy
    ├── {project}-review.md        #   Review report (findings + strategy + TODOs)
    └── {project}-deploy.md        #   Gate report (admission + blocking + closure)
```

Added to `.gitignore` — no accidental commits.

## Directory Structure

```
security-workflow/
├── .claude-plugin/plugin.json     # Plugin registration
├── .mcp.json                      # MCP engine connection config
├── commands/                      # /security-workflow:review|deploy
├── agents/                        # security-scanner, quick-fix
├── skills/                        # Security review patterns
├── hooks/                         # check-bash.sh, auto-fix-security.sh
├── security_workflow/             # Python MCP process engine
│   ├── mcp_server.py              #   Entry point (7 tools)
│   ├── core/                      #   Ticket workflow, gate decisions
│   ├── definition/                #   Enums + shared constants
│   ├── model/                     #   Data models
│   ├── persistence/               #   JSON persistence
│   ├── timer/                     #   Timeout calculation
│   ├── spi/                       #   Notification extension points
│   └── report/                    #   Audit report auto-generation
├── tests/
│   ├── vuln_cases/                # Vulnerability test samples (High/Medium/Low)
│   └── integration_test.py        # End-to-end integration test
└── examples/                      # Multi-language secure coding templates
```

## Changelog

### v1.0.2 (2026-06-25) — Report Auto-Generation + Bug Fix Release

**Added:**
- `security_workflow/report/` — Report engine with separate templates for review/deploy. Reports auto-saved to `.security-workflow-data/reports/` after `/security-workflow:review` and `/security-workflow:deploy`.
- `security_workflow/definition/constants.py` — Shared constants module, eliminating hardcoded path duplication in persistence/spi.
- MCP `generate_report` tool (7th tool), supporting both `review` and `deploy` report types.
- `auto-fix-security.sh` Bash version check (4.0+), giving macOS users a clear upgrade instruction instead of syntax errors.

**Fixed (7 Low + 3 Medium):**
- 🔧 Low: `persistence/__init__.py` / `spi/__init__.py` hardcoded default paths → shared constants
- 🔧 Low: `check-bash.sh` TARGET path validation + wc exit code differentiation
- 🔧 Low: `auto-fix-security.sh` Perl `-s` switch safe argument passing (prevent variable injection)
- 🔧 Low: `integration_test.py` `sys.path.insert(0)` → `append` (prevent module hijacking)
- 🟡 Medium: `mcp_server.py` traceback no longer leaks to client via JSON-RPC error.data
- 🟡 Medium: `mcp_server.py` traceback writes to stderr controlled by `SECURITY_WORKFLOW_DEBUG` env var
- 🟡 Medium: `core/__init__.py` config file path now uses `resolve()` normalization + project root fence validation

**Report file naming:** stable overwrite (`{project}-{review|deploy}.md`), no accumulation.

### v1.0.1 (2026-06-25) — Smoke Test Fix Release

**Fixed bugs (6):**
- CRITICAL #2: `review.md`/`deploy.md` — YAML frontmatter brackets parsed as flow sequences, commands couldn't load → quoted
- BUG #5: `auto-fix-security.sh` — `[\s:_,-]` inside POSIX ERE brackets didn't recognize `\s`, all match patterns never hit → changed to `[[:space:]:_,-]`
- BUG #6: `auto-fix-security.sh` — accessing uninitialized associative array key under `set -u` crashed → added `${VAR-}` defaults
- CRITICAL #3: `auto-fix-security.sh` — rewritten from raw `sed -i` to perl + dry-run + surgical match + backup/rollback
- CRITICAL #4: `check-bash.sh` — replaced `grep -v "#"` with `sed -E` for precise comment stripping
- CRITICAL #1: `security-scanner.md` — verified no BOM, no leading text with xxd; unreproducible

**Added:**
- Complete Python MCP process engine implementation (10 .py files, 6 MCP tools)
- `tests/integration_test.py` — `/security-workflow:review` → `/security-workflow:deploy` end-to-end integration test
- Unified data directory `$SECURITY_WORKFLOW_DATA`
- `.gitignore` to prevent accidental runtime data commits

**Verified:**
- `check-bash.sh`: 3/3 correct classification (High block exit 2, Medium warn exit 1, Low pass exit 0)
- `auto-fix-security.sh`: dry-run detection 2/2, actual fix precision-deleted 2 lines, backup + logs complete
- MCP engine: 6/6 tools responsive, ticket create→transition→reject→gate→audit full pipeline passes
- Integration test: 8/8 steps passed, PASS
