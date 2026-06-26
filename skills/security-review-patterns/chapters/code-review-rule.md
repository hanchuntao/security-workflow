# Manual Code Security Review Specification (MR Review Production Standard)

## I. Review Applicability
MR merges, version iterations, pre-release manual security review, complementing automated scanning for full-dimensional security validation.

## II. Core Review Checklist
### 1. Authorization Security
- Do endpoints have login authentication and token validity checks?
- Do data operations verify data ownership to prevent horizontal/vertical privilege escalation?
- Do admin endpoints have role-based permission enforcement?
- Are sensitive operations doubly verified and forgery-resistant?

### 2. Data Security
- Are phone numbers, ID numbers, bank cards, and privacy data properly masked?
- Is sensitive data stored or transmitted in plaintext?
- Do logs forbid printing sensitive privacy data, keys, and cookies?
- Do data export endpoints have permission and rate limiting?

### 3. Code Security
- No raw user input concatenation, no native SQL concatenation, no command execution risks
- No hardcoded keys, passwords, tokens, private keys, or other sensitive credentials
- No dangerous functions, insecure cryptography, or insecure random usage
- Abandoned dangerous code and debug code have been cleaned up

### 4. Configuration Security
- Production environments have debug mode, swagger, and dev backends disabled
- Security response headers are complete; CORS is compliant
- Cookies are configured with HttpOnly, Secure, and SameSite

### 5. Business Logic Security
- Login, verification code, payment, and order endpoints prevent brute-force and replay attacks
- SMS, email, and push notification endpoints prevent abuse and have rate limits
- Verification codes expire and are non-reusable
- Core fields (amount, quantity, points) are not client-side tamperable

## III. Review Classification Verdict
1. **High-risk vulnerabilities present**: Reject MR; mandatory remediation before re-review
2. **Medium-risk vulnerabilities present**: Deadline-tracked remediation; may merge temporarily with documented remediation plan
3. **Low-risk issues only**: Auto-pass; added to iterative optimization backlog

## IV. Review Documentation Standards
1. All review comments, remediation records, and re-review results are permanently retained in tickets
2. High-risk vulnerabilities require dual review with signed reviewer records
3. Review verdicts are included in the version release audit report
