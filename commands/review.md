---
description: Enterprise-grade code security review — scan, tiered fix, ticket workflow, security gate, full closed loop
argument-hint: "[scope=project|file] [level=low|mid|high|all] [mode=increment|full] [workflow=true|false]"
allowed-tools: "Read, Grep, Glob, Bash(git diff:*), Bash(git log:*)"
---

# /review
## Overview

Enterprise-grade code security review command. Orchestrates the security-scanner agent, quick-fix agent, and security-workflow process engine to deliver a fully automated closed loop: **scan → risk classification → fix → ticket creation → workflow tracking → security gate**.

Covers daily incremental checks, MR code reviews, and pre-release full-scope security audits. This is the sole entry point for the entire security pipeline.

## Core Capabilities (Production Closed Loop)
1. Full/incremental security scan with strict 3-tier risk classification (High/Medium/Low)
2. Auto-matching fix strategy per vulnerability level (Manual for High, Semi-auto for Medium, Full-auto for Low)
3. Auto-created standardized security review tickets with appropriate initial workflow states
4. Process engine integration for timeout alerts, escalations, rejections, and deployment blocks
5. Structured audit reports meeting compliance and enterprise security audit requirements

## Parameters
| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| scope | file / project | project | Scan scope: single file or entire project |
| level | low / mid / high / all | all | Minimum risk level to report |
| mode | increment / full | full | `increment` = changed files only (fast); `full` = entire codebase (thorough) |
| workflow | true / false | true | Whether to create tickets and integrate with the process engine |

## Usage Examples
```
# Full-scope deep security review (required for production release)
/review scope=project level=all mode=full workflow=true

# Single-file incremental review (daily development)
/review scope=file level=all mode=increment workflow=true

# High-risk focused review (urgent gate check)
/review scope=project level=high mode=full workflow=true
```

## Execution Pipeline (100% aligned with dual-agent spec)
### Step 1: Initialize Scan Rules
Determine scan scope, mode, and risk threshold from parameters. Invoke security-scanner with standardized scan rules matching the unified vulnerability classification.

### Step 2: Structured Vulnerability Output
Scanner produces 9 fixed structured fields: `risk_id`, `risk_level`, `file_path`, `line_no`, `risk_desc`, `compliance_rule`, `fix_suggest`, `scan_mode`, `workflow_status`. These serve as the single source of truth for remediation and ticket workflow.

### Step 3: Match Tiered Fix Strategy
Invoke quick-fix with differentiated remediation aligned to global rules:
1. **High**: Forbidden auto-fix. Generate precise remediation plan only. Ticket state: "Pending manual fix + dual review + deploy blocked"
2. **Medium**: Generate semi-auto fix code, requires human confirmation. Ticket state: "Pending fix confirmation + deadline tracked"
3. **Low**: Fully automatic silent fix. Ticket auto-closed with audit trail retained.

### Step 4: Process Engine Ticket Integration
When `workflow=true`, the process engine is automatically triggered:
1. Initialize ticket states per vulnerability level
2. High-risk flaws auto-block MR merge and release
3. Medium-risk flaws start deadline timers; overdue tickets auto-escalate to security lead
4. Full-chain logs (scan → fix → review) preserved for compliance audit

### Step 5: Generate & Persist Review Report
`generate_review_report()` aggregates global risk stats, per-vulnerability details, fix plans, ticket states, and security rating into a structured Markdown report saved at `.security-workflow-data/reports/{project}-review-{timestamp}.md`. The report includes 6 sections: global risk summary, ticket status, per-vulnerability details, deployment admission decision, remediation requirements, and audit compliance declaration.

## Production Constraints
1. Release reviews MUST use `mode=full level=all`; incremental scans cannot substitute deployment gate checks
2. Detection of any High-risk vulnerability forcibly blocks the release pipeline — no skip or bypass
3. All scan, fix, and ticket change records are permanently and structurally preserved; no deletion or tampering
4. Strictly follow dual-agent classification rules; no unauthorized downgrading of vulnerability severity or skipping remediation
5. Overdue Medium-risk vulnerabilities auto-escalate and trigger a secondary review alert

## Output Specification
1. Global risk summary: High/Medium/Low vulnerability counts, overall project security rating
2. Per-vulnerability structured details: fully aligned with Scanner output fields
3. Tiered fix results: fix mode, before/after code diff, risk elimination notes
4. Security ticket status: current workflow state, pending actions, deadline
5. Compliance audit conclusion: compliance verdict, remediation requirements, deployment admission decision

## Dependencies
1. **Agents**: security-scanner (scan data source), quick-fix (vulnerability remediation)
2. **Engine**: security-workflow process engine (ticket workflow, gate, timeout alerts)
3. **Hooks**: file-save and pre-commit security pre-check capabilities
