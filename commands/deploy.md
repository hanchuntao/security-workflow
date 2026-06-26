---
description: Production deployment security gate — mandatory full scan, block unpatched vulnerabilities, compliance admission check
argument-hint: "[branch=main|test|hotfix] [skip-review=false] [force=false] [workflow=true]"
allowed-tools: "Read, Grep, Glob, Bash(git:*), Bash(git diff:*), Bash(git log:*)"
---

# /deploy
## Overview

Enterprise production deployment security gate — the **last line of defense** in the R&D pipeline. Orchestrates the `/review` standard, security-scanner engine, quick-fix remediation rules, and security-workflow process engine to enforce a mandatory security compliance check. Blocks deployment of unpatched vulnerabilities and unreviewed code. No bypass, no exemption.

This command is the sole admission checkpoint for production release. Every branch and version must pass this gate before deployment.

## Core Capabilities (Mandatory Gate)
1. Pre-deployment full-scope deep security scan, replicating formal production review standards — no incremental shortcuts
2. Strict verification of High/Medium/Low vulnerability fix status with tiered blocking rules
3. Validate security review ticket closure status — dual review and fix re-review completeness
4. Process engine integration to update deployment ticket state and record release audit trail
5. Produce a compliance admission verdict and archivable deployment security report for audit requirements

## Parameters
| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| branch | branch name | main | Target branch for deployment; gate checks code on this branch precisely |
| skip-review | true / false | false | Whether to skip security review validation (**permanently locked to false in production**) |
| force | true / false | false | Force deployment — emergency hotfix only; requires security lead approval and post-launch review within 24h |
| workflow | true / false | true | Integrate with process engine to update ticket state and retain release audit trail |

## Usage Examples
```
# Standard production deployment gate (mandatory)
/deploy branch=main skip-review=false force=false workflow=true

# Test environment deployment (same compliance checks, no forced blocking)
/deploy branch=test skip-review=false force=false workflow=true

# Emergency hotfix forced deployment (requires post-launch security review)
/deploy branch=hotfix skip-review=false force=true workflow=true
```

## Execution Pipeline (100% aligned with full security pipeline)
### Step 1: Pre-Deployment Initialization Check
Lock the target branch code. Force-enable **full scan mode + all risk levels**. Incremental scans are not accepted as a substitute for deployment gate validation. Aligned with `/review` production release standards.

### Step 2: Trigger Full-Scope Security Scan
Invoke security-scanner to perform deep scan using unified vulnerability classification and structured output fields. Covers OWASP Top 10, enterprise security standards, and compliance check items. Precisely identifies all residual security vulnerabilities.

### Step 3: Vulnerability Fix Status Enforcement
Cross-reference quick-fix tiered remediation rules. Validate each vulnerability's closure status with rigid blocking rules:
1. **High**: Any unclosed High vulnerability → immediate deployment block. Requires mandatory manual fix + dual security review before release.
2. **Medium**: Incomplete or unconfirmed Medium fixes → deployment block. Must complete remediation and review within deadline.
3. **Low**: Unclosed Low optimization items → recorded in risk ledger; does not block deployment, but mandatory inclusion in next iteration fix list.

### Step 4: Security Ticket Closure Verification
Integrate with security-workflow process engine to verify all security review tickets on the current branch:
1. Verify all High-vulnerability tickets have completed the "Fix → Review → Closure" full lifecycle
2. Verify Medium-vulnerability tickets are within remediation deadlines with no overdue items
3. Check for any pending review, pending fix, or pending re-review tickets
4. Overdue or unreviewed tickets auto-trigger process escalation with security lead notification

### Step 5: Generate & Persist Deployment Security Report
`generate_review_report(report_type="deploy")` produces a structured Markdown report based on scan results, vulnerability fix status, and ticket closure state. Saved to `.security-workflow-data/reports/{project}-deploy-{timestamp}.md`. The report includes 6 sections: global risk summary, ticket status, per-vulnerability details, deployment admission decision (with blocking reasons), remediation requirements, and audit compliance declaration. Full-chain audit logs are retained and process ticket state is updated.

## Hard Blocking Rules (No Exemption)
1. Any unpatched High-risk vulnerability on production branch → **100% block deployment**, no bypass
2. Any High-vulnerability ticket not yet reviewed or re-reviewed → directly block the release pipeline
3. `skip-review` parameter is permanently locked to `false` in production; manual override has no effect
4. `force` deployment is only allowed for production emergency hotfixes; a mandatory security retrospective and vulnerability fix filing must be completed within 24 hours post-launch
5. Accumulated or long-overdue Medium vulnerabilities auto-escalate to deployment-blocking level; version iteration release is forbidden

## Output Specification
1. Branch info: branch name, scan mode, check timestamp, compliance verdict
2. Vulnerability risk summary: counts of unclosed High/Medium/Low vulnerabilities, risk breakdown
3. Ticket status verification: list of open tickets, overdue alerts, pending actions
4. Deployment admission conclusion: explicit **ALLOWED** / **BLOCKED** verdict
5. Remediation guidance: precise fix plans for unclosed vulnerabilities, ticket handling instructions
6. Audit archive: complete deployment security check trail — traceable, reviewable, compliance-verifiable

## Pipeline Dependencies
1. **Upstream**: `/review` command, security-scanner agent, quick-fix agent
2. **Core**: security-workflow process engine (ticket verification, state updates, timeout alerts, audit retention)
3. **Pre-requisite**: File-save and Git pre-commit security hook results to ensure zero oversight
