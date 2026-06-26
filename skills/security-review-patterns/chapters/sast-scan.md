# SAST Static Security Scan Specification (Enterprise Production Standard)

## I. Core Scanning Principles
1. **Full coverage**: OWASP Top 10 + enterprise security coding standards
2. **Zero omission**: Do not skip comments, test code, dead code, or config file vulnerabilities
3. **Precise classification**: Strictly follow High/Medium/Low 3-tier criteria; no downgrading or missed judgments
4. **Scenario differentiation**: Distinguish between incremental daily scan, full review scan, and deployment gate scan intensity

## II. Rigid Risk Classification Criteria
### 1. High-Risk Vulnerabilities (Production Blocking)
**Definition**: Vulnerabilities directly exploitable by external attackers leading to server compromise, data breach, privilege escalation, or business paralysis. Must be 100% remediated. Deployment forbidden.

**Includes**: All injection types, privilege escalation / unauthorized access, key leaks, remote code execution, plaintext sensitive data transmission/storage, high-risk component vulnerabilities.

### 2. Medium-Risk Vulnerabilities (Deadline-Tracked Remediation)
**Definition**: Cannot be directly exploited remotely, but pose potential security risks. Long-term accumulation can lead to security incidents. Must be remediated within deadline.

**Includes**: Weak encryption, insecure random numbers, missing API protection, insecure configuration, log data masking defects.

### 3. Low-Risk Vulnerabilities (Auto-Optimize)
**Definition**: No direct attack risk. Coding standards issues and residual redundancy only. Does not affect production security. Can be auto-fixed and optimized.

**Includes**: Abandoned dangerous code, invalid security comments, redundant high-risk imports, non-standard security coding.

## III. Mandatory Scan Check Items
1. **Code-layer**: Injection, XSS, privilege escalation, unauthorized access, deserialization, file operation risks
2. **Credential-layer**: Hardcoded keys, passwords, tokens, private keys, sensitive credential leaks
3. **Data-layer**: Plaintext sensitive data storage, plaintext transmission, privacy data in logs
4. **Crypto-layer**: Weak algorithms, insecure random, fixed keys, unsalted hashing
5. **Config-layer**: CORS wildcard, missing security headers, debug endpoints exposed
6. **Dependency-layer**: Third-party components and framework versions with known CVE vulnerabilities

## IV. Scan Output Specification
1. Must output all 9 structured fields, compatible with fix agent and process engine
2. Each vulnerability must specify risk level, compliance basis, and implementable fix recommendation
3. Distinguish scan mode, tagging incremental vs. full scan context
4. Summarize global risk statistics and security rating

## V. Scan Exemption Rules
### Production Code
No vulnerability exemption privileges. All detected risks must complete remediation or receive documented approval by risk level.

### Scanner Self-Test Fixtures (Exempt Directories)
The following directories contain intentionally crafted vulnerability samples to verify scanner/hook detection capability. They must be skipped during scanning:

- `tests/vuln_cases/`
- `tests/vuln_samples/`
- `tests/security_test_fixtures/`

> This rule is 100% aligned with `security-scanner.md` section IV-Addendum and `hooks/check-bash.sh` skip_vuln_dirs().
