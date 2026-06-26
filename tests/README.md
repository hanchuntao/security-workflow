# Security Plugin Tests

## Purpose
This directory is the official test suite for the security review plugin, used to:
1. Verify scanner detection rule accuracy (no false positives, no false negatives)
2. Verify quick-fix tiered remediation strategy effectiveness
3. Automated regression after version iterations to prevent rule degradation
4. Enterprise acceptance and rule update validation with standard samples

## Test Categories
- **High-risk** cases: injection, privilege escalation, key leaks, RCE, sensitive data exposure
- **Medium-risk** cases: weak crypto, insecure random, missing security headers, log leakage
- **Low-risk** cases: dead code, invalid comments, redundant imports

## Test Execution
1. Manually run `/review scope=project mode=full` to validate case recognition
2. Compare scan classification and fix strategy against official spec
3. After rule updates, run the full regression suite

## Acceptance Criteria
All test samples must align 100% with enterprise production standards for risk classification, fix mode, and ticket state transitions.
