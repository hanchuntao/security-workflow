# SKILL: security-review-patterns
## Purpose
Unified enterprise code security review standards, SAST scan rules, vulnerability classification norms, auto-fix strategies, and process audit rules. All scanning, fixing, ticket workflow, and deployment gate operations must strictly follow this specification, ensuring pipeline-wide consistency, compliance control, and auditability.

## Scope
1. security-scanner full/incremental vulnerability scan judgments
2. quick-fix 3-tier vulnerability remediation execution
3. `/review` code security review process validation
4. `/deploy` deployment security gate admission decisions
5. Security ticket workflow — transitions, timeouts, escalations, rejections, closure audits

## Sub-Specification Chapters
1. sast-scan.md: SAST static scan rules, risk classification criteria, vulnerability judgment standards
2. code-review-rule.md: Manual code security review checklist, MR review standards
3. workflow-audit.md: Security approval workflow transitions, timeout management, audit retention standards

## Mandatory Execution Rules
1. All agents, commands, and hooks must align with this specification system — no custom rules allowed
2. Vulnerability risk level, fix strategy, and ticket state are strictly 1:1:1 bound — no exceptions
3. All production security gates, reviews, and remediation actions must be logged and archived
4. All specification updates must sync across the entire pipeline to maintain global consistency
