# Plugin Version Regression Checklist (v1.0.1)

## Check Items (must run full suite on every rule update)

### Agents & Commands
1. ✅ security-scanner agent loads correctly (frontmatter starts at file line 1)
2. ✅ quick-fix agent has restricted tool access (no Write/Edit, only Read/Grep/Glob)
3. ✅ /review command recognized by Claude Code (argument-hint displays correctly)
4. ✅ /deploy command recognized by Claude Code (argument-hint displays correctly)

### Vulnerability Classification
5. ✅ High-risk vulnerabilities fully detected, forbid auto-fix, marked deploy-blocked
6. ✅ Medium-risk vulnerabilities accurately identified, enter semi-auto fix flow, deadline-tracked
7. ✅ Low-risk vulnerabilities auto-detected, silent fix, auto-closed tickets
8. ✅ All 9 structured scan output fields present

### Hook Behavior
9. ✅ check-bash.sh scans only changed files on file save (incremental)
10. ✅ check-bash.sh performs full project scan on Git commit
11. ✅ check-bash.sh exit codes correct (0=pass / 1=medium warn / 2=high block)
12. ✅ auto-fix-security.sh triggers only before Git commit (not on file save)
13. ✅ auto-fix-security.sh default dry-run mode (no file modification)
14. ✅ auto-fix-security.sh surgical matching (no false deletion of business logs)
15. ✅ auto-fix-security.sh audit log complete
16. ✅ auto-fix-security.sh backup mechanism functional

### Platform Compatibility
17. ✅ Shell scripts cross-platform (perl instead of sed -i, env bash shebang)
18. ✅ .mcp.json no hardcoded absolute paths (env vars + relative paths)

### Data Integrity
19. ✅ High-risk vulnerabilities have no missed detections (end-of-line comments with credentials not skipped by grep -v "#")
20. ✅ TypeScript test cases syntactically correct (console.log instead of print)

## Regression Acceptance Standard
No missed detections, no false positives, no strategy errors, no gate failures, no cross-platform compatibility issues.

## Known Limitations
1. MCP process engine (security_workflow Python package) requires separate installation, not in this repo
2. auto-fix-security.sh perl dependency (Windows requires Git Bash / WSL)
3. Files over 5MB are skipped by check-bash.sh
