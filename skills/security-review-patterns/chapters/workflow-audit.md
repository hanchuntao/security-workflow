# Security Workflow Audit & Transition Specification

## I. Ticket State Transition Standards
1. **High-risk tickets**: Pending manual fix → Dual review → Fix re-review → Closed & archived
2. **Medium-risk tickets**: Pending fix confirmation → Manual fix → Single review → Closed (deadline-tracked)
3. **Low-risk tickets**: Pending auto-fix → Auto fixing → Auto closed & archived

## II. Timeout Management Rules
1. High-risk vulnerability tickets: 72 hours without remediation triggers auto-timeout, escalation to security lead + R&D lead
2. Medium-risk vulnerability tickets: 5 business days without remediation triggers auto-escalation warning
3. Overdue tickets block associated version deployments; mandatory priority remediation

## III. Escalation & Review Rules
1. High-risk vulnerabilities require mandatory dual security review and bidirectional re-review
2. Overdue tickets and newly created High-risk tickets auto-escalate to team lead
3. Rejected remediation tickets must include explicit rejection reasons and remediation guidance

## IV. Audit Retention Standards
1. All scan records, fix diffs, review comments, and transition trails are permanently and structurally stored
2. Security risks can be traced by project, branch, version, and time dimensions
3. All records satisfy compliance audit and verification requirements

## V. Deployment Risk Control Rules
1. Unclosed High-risk ticket exists → Directly block deployment
2. Overdue unresolved Medium-risk ticket exists → Block deployment
3. Un-reviewed vulnerability ticket exists → Block deployment
4. Low-risk unoptimized items → Logged in ledger, does not block deployment
