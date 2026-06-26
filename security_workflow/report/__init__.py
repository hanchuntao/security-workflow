"""Audit report auto-generation module — separate templates for /review and /deploy."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..persistence import STORAGE_ROOT

REPORTS_DIR = STORAGE_ROOT / "reports"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S UTC")


def _counts(tickets: list[dict[str, Any]]) -> dict[str, int]:
    """Count vulnerabilities per risk level.

    Keys use Chinese enum values to match stored ticket data.
    """
    c = {"高危": 0, "中危": 0, "低危": 0}
    for t in tickets:
        level = t.get("risk_level", "")
        if level in c:
            c[level] += len(t.get("findings", []))
    return c


def _flatten(tickets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten findings across tickets, attaching ticket metadata."""
    flat: list[dict[str, Any]] = []
    for t in tickets:
        for f in t.get("findings", []):
            f["_ticket_id"] = t.get("ticket_id", "")
            f["_ticket_status"] = t.get("status", "")
        flat.extend(t.get("findings", []))
    return flat


# ═══════════════════════════════════════════════════════════════════════════════
#  Review Report — scan findings + fix strategy + action items
# ═══════════════════════════════════════════════════════════════════════════════

def generate_review_report(
    project: str,
    branch: str,
    scan_mode: str,
    tickets: list[dict[str, Any]],
) -> str:
    """Generate a /review code security review report.

    Focus: scan scope, vulnerability findings, fix strategy, remediation plan, next steps.
    """
    now = _now()
    counts = _counts(tickets)
    all_findings = _flatten(tickets)
    total = sum(counts.values())

    # Security rating
    if counts["高危"] > 0:
        rating = "🔴 HIGH — Deployment blocked, immediate remediation required"
    elif counts["中危"] > 0:
        rating = "🟡 MEDIUM — Remediate within deadline, then re-review"
    elif counts["低危"] > 0:
        rating = "🟢 GOOD — Low-risk items logged in ledger"
    else:
        rating = "✅ EXCELLENT — No security risks found"

    L: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────
    L.append("# 🔍 Code Security Review Report — `/review`")
    L.append("")
    L.append(f"| Project | Branch | Scan Mode | Review Time |")
    L.append(f"|---------|--------|-----------|-------------|")
    L.append(f"| `{project}` | `{branch}` | {scan_mode} | {now} |")
    L.append("")

    # ── I. Scan Results Summary ─────────────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## I. Scan Results Summary")
    L.append("")
    L.append("| Risk Level | Vulnerabilities | Fix Strategy | Blocks Deployment |")
    L.append("|------------|----------------|-------------|-------------------|")
    L.append(f"| 🔴 High | {counts['高危']} | Manual fix + dual review | **Yes** |")
    L.append(f"| 🟡 Medium | {counts['中危']} | Semi-auto confirmed + deadline | Yes after timeout |")
    L.append(f"| 🟢 Low | {counts['低危']} | Full-auto silent fix | No |")
    L.append(f"| **Total** | **{total}** | | |")
    L.append("")
    L.append(f"**Security Rating:** {rating}")
    L.append("")

    # ── II. Vulnerability Details ───────────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## II. Vulnerability Details")
    L.append("")

    for level, emoji, label in [("高危", "🔴", "High"), ("中危", "🟡", "Medium"), ("低危", "🟢", "Low")]:
        items = [f for f in all_findings if f.get("risk_level") == level]
        if not items:
            continue
        L.append(f"### {emoji} {label} ({len(items)} items)")
        L.append("")
        L.append("| risk_id | File:Line | Description | Compliance | Fix Suggestion |")
        L.append("|---------|-----------|-------------|------------|----------------|")
        for f in items:
            rid = f.get("risk_id", "")
            fp = f.get("file_path", "")
            ln = f.get("line_no", "")
            desc = f.get("risk_desc", "")[:45]
            rule = (f.get("compliance_rule", "") or "")[:20]
            fix = (f.get("fix_suggest", "") or "")[:35]
            L.append(f"| `{rid}` | `{fp}:{ln}` | {desc} | {rule} | {fix} |")
        L.append("")

    # ── III. Fix Strategy & Remediation Plan ────────────────────────────
    L.append("---")
    L.append("")
    L.append("## III. Fix Strategy & Remediation Plan")
    L.append("")

    for level, emoji, strategy, deadline_note in [
        ("高危", "🔴", "Manual fix (auto-fix forbidden)", "Within 72 hours"),
        ("中危", "🟡", "Semi-auto confirmed fix (human approval required)", "Within 5 business days"),
        ("低危", "🟢", "Full-auto silent fix (no human intervention)", "Auto-closed within 7 days"),
    ]:
        related = [t for t in tickets if t.get("risk_level") == level]
        if not related:
            continue
        L.append(f"### {emoji} {level} — {strategy}")
        L.append("")
        L.append(f"| Ticket ID | Findings | Status | Deadline |")
        L.append(f"|-----------|----------|--------|----------|")
        for t in related:
            tid = t.get("ticket_id", "")
            fcnt = len(t.get("findings", []))
            status = t.get("status", "")
            deadline = (t.get("deadline", "") or "")[:16]
            L.append(f"| `{tid}` | {fcnt} | **{status}** | {deadline} |")
        L.append("")
        L.append(f"⏱️ Deadline: {deadline_note}")
        L.append("")

    # ── IV. High-Risk Detailed Fix Guidance ─────────────────────────────
    if counts["高危"] > 0:
        L.append("---")
        L.append("")
        L.append("## IV. High-Risk Detailed Fix Guidance")
        L.append("")
        L.append("> ⚠️ The following vulnerabilities **must NOT be auto-fixed**. They require manual remediation and dual security review.")
        L.append("")
        high_items = [f for f in all_findings if f.get("risk_level") == "高危"]
        for i, f in enumerate(high_items, 1):
            rid = f.get("risk_id", "")
            fp = f.get("file_path", "")
            ln = f.get("line_no", "")
            desc = f.get("risk_desc", "")
            rule = f.get("compliance_rule", "")
            fix = f.get("fix_suggest", "")
            L.append(f"**{i}. `{rid}` — `{fp}:{ln}`**")
            L.append(f"- Description: {desc}")
            L.append(f"- Compliance: {rule}")
            L.append(f"- Fix suggestion: {fix}")
            L.append("")

    # ── V. Next Steps ───────────────────────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## V. Next Steps")
    L.append("")
    L.append("1. **Immediately:** Assign security owner to High-risk tickets — complete remediation within 72 hours")
    L.append("2. **This week:** Confirm Medium-risk fix plans and execute — close within 5 business days")
    L.append("3. **Auto:** Low-risk items handled by `auto-fix-security.sh` (or pending auto-closure)")
    L.append("4. **Before release:** Run `/deploy` to validate the gate — ensure zero blocking items")
    L.append("")

    # ── VI. Audit Compliance Statement ───────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## VI. Audit Compliance Statement")
    L.append("")
    L.append(f"- ✅ Full-project scan completed — {total} security risks detected")
    L.append("- ✅ Aligned with OWASP Top 10 + Enterprise Security Coding Standards")
    L.append("- ✅ Tiered fix strategy: High (Manual) / Medium (Semi-auto) / Low (Full-auto)")
    L.append("- ✅ Ticket data structurally stored with complete, traceable audit trail")
    L.append(f"- {'⚠️ Unclosed High-risk vulnerabilities exist — /deploy will be BLOCKED' if counts['高危'] > 0 else '✅ No High-risk vulnerabilities — ready for /deploy stage'}")
    L.append("")
    L.append(f"*Report generated: {now} | Engine: security-workflow-mcp-engine v1.0.1*")
    L.append(f"*Data directory: {STORAGE_ROOT}*")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════════
#  Deploy Report — gate verdict + blocking reasons + closure validation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_deploy_report(
    project: str,
    branch: str,
    tickets: list[dict[str, Any]],
    deploy_gate: dict[str, Any],
) -> str:
    """Generate a /deploy security gate report.

    Focus: gate check results, blocking item details, ticket closure status, admission verdict.
    """
    now = _now()
    counts = _counts(tickets)
    total = sum(counts.values())

    # Closure stats — check Chinese "闭环" substring in status values
    closed_count = sum(1 for t in tickets if "闭环" in t.get("status", ""))
    open_count = len(tickets) - closed_count

    allowed = deploy_gate.get("allowed", False)
    verdict = deploy_gate.get("verdict", "")
    blocked = deploy_gate.get("blocked_by", [])
    warnings = deploy_gate.get("warnings", [])

    L: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────
    L.append("# 🚦 Deployment Security Gate Report — `/deploy`")
    L.append("")
    L.append(f"| Project | Branch | Check Time | Workflow |")
    L.append(f"|---------|--------|------------|----------|")
    L.append(f"| `{project}` | `{branch}` | {now} | workflow=true |")
    L.append("")

    # ── I. Admission Verdict (most prominent) ────────────────────────────
    L.append("---")
    L.append("")
    L.append("## I. Admission Verdict")
    L.append("")
    if allowed:
        L.append("```")
        L.append("  ✅   DEPLOY ALLOWED")
        L.append("```")
        L.append("")
        L.append(f"**Verdict:** {verdict}")
        L.append("")
        L.append("The current branch satisfies deployment security gate requirements — no blocking items.")
        if warnings:
            L.append(f"{len(warnings)} warning(s) present. Recommended to track after deployment.")
    else:
        L.append("```")
        L.append("  ⛔   DEPLOY BLOCKED")
        L.append("```")
        L.append("")
        L.append(f"**Verdict:** {verdict}")
        L.append("")
        L.append("The current branch **does NOT** satisfy deployment security gate requirements. All blocked items below must be resolved before re-validation.")
    L.append("")

    # ── II. Blocking Items ──────────────────────────────────────────────
    if blocked:
        L.append("---")
        L.append("")
        L.append("## II. Blocking Items")
        L.append("")
        L.append("| Ticket ID | Risk Level | Blocking Reason | Status | Deadline |")
        L.append("|-----------|------------|-----------------|--------|----------|")
        for b in blocked:
            tid = b.get("ticket_id", "")
            level = b.get("risk_level", "")
            reason = b.get("reason", "")
            match = [t for t in tickets if t.get("ticket_id") == tid]
            status = match[0].get("status", "—") if match else "—"
            deadline = (match[0].get("deadline", "") or "")[:16] if match else "—"
            L.append(f"| `{tid}` | {level} | {reason} | **{status}** | {deadline} |")
        L.append("")
        L.append("> ⛔ All blocking items above must be fully closed before re-running `/deploy`.")
        L.append("")

    # ── III. Ticket Closure Verification ────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## III. Ticket Closure Verification")
    L.append("")
    L.append(f"| Status | Count |")
    L.append(f"|--------|-------|")
    status_groups: dict[str, int] = {}
    for t in tickets:
        s = t.get("status", "Unknown")
        status_groups[s] = status_groups.get(s, 0) + 1
    for s, n in sorted(status_groups.items()):
        L.append(f"| {s} | {n} |")
    L.append("")
    L.append(f"- Closed: {closed_count} / Open: {open_count}")
    L.append("")

    L.append("### Ticket List")
    L.append("")
    L.append("| Ticket ID | Risk Level | Status | Findings | Deadline |")
    L.append("|-----------|------------|--------|----------|----------|")
    for t in tickets:
        tid = t.get("ticket_id", "")
        level = t.get("risk_level", "")
        status = t.get("status", "")
        fcnt = len(t.get("findings", []))
        deadline = (t.get("deadline", "") or "")[:16]
        icon = "✅" if "闭环" in status else "⏳"
        L.append(f"| `{tid}` | {level} | {icon} {status} | {fcnt} | {deadline} |")
    L.append("")

    # ── IV. Fix Completion Summary ──────────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## IV. Fix Completion Summary")
    L.append("")
    L.append("| Risk Level | Total | Closed | Open | Completion |")
    L.append("|------------|-------|--------|------|------------|")
    for level in ["高危", "中危", "低危"]:
        label = {"高危": "High", "中危": "Medium", "低危": "Low"}[level]
        total_l = counts[level]
        closed_l = sum(
            len(t.get("findings", []))
            for t in tickets
            if t.get("risk_level") == level and "闭环" in t.get("status", "")
        )
        open_l = total_l - closed_l
        rate = f"{closed_l / total_l * 100:.0f}%" if total_l > 0 else "—"
        L.append(f"| {label} | {total_l} | {closed_l} | {open_l} | {rate} |")
    L.append("")

    # ── V. Warnings ─────────────────────────────────────────────────────
    if warnings:
        L.append("---")
        L.append("")
        L.append("## V. Warnings")
        L.append("")
        L.append("| Ticket ID | Risk Level | Warning Reason |")
        L.append("|-----------|------------|----------------|")
        for w in warnings:
            L.append(f"| `{w.get('ticket_id','')}` | {w.get('risk_level','')} | {w.get('reason','')} |")
        L.append("")
        L.append("> ⚠️ Warnings do not block this deployment but must be resolved within their deadlines. Overdue items auto-escalate to blocking level.")
        L.append("")

    # ── VI. Audit Compliance Statement ───────────────────────────────────
    L.append("---")
    L.append("")
    L.append("## VI. Audit Compliance Statement")
    L.append("")
    L.append(f"- Check time: {now}")
    L.append(f"- Scope: project `{project}` / branch `{branch}`")
    L.append(f"- Associated tickets: {len(tickets)} ({total} vulnerabilities)")
    L.append(f"- Blocking items: {len(blocked)} / Warnings: {len(warnings)}")
    L.append(f"- Verdict basis: {'All tickets closed' if allowed else 'Unclosed blocking tickets exist'}")
    L.append("- Audit log: `.security-workflow-data/audit_log.jsonl`")
    L.append("- Full-chain operation records structurally stored for compliance audit")
    L.append("")
    L.append(f"*Report generated: {now} | Engine: security-workflow-mcp-engine v1.0.1*")
    L.append(f"*Data directory: {STORAGE_ROOT}*")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════════════

def save_report(content: str, project: str, report_type: str = "review") -> Path:
    """Persist report to the data directory (latest only per project+type; timestamp is in report body)."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{project}-{report_type}.md"
    filepath = REPORTS_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    return filepath


def generate_and_save(
    project: str,
    branch: str,
    scan_mode: str,
    tickets: list[dict[str, Any]],
    deploy_gate: dict[str, Any] | None = None,
    report_type: str = "review",
) -> Path:
    """One-stop: generate a report by type and persist to disk."""
    if report_type == "deploy" and deploy_gate:
        content = generate_deploy_report(
            project=project,
            branch=branch,
            tickets=tickets,
            deploy_gate=deploy_gate,
        )
    else:
        content = generate_review_report(
            project=project,
            branch=branch,
            scan_mode=scan_mode,
            tickets=tickets,
        )
    return save_report(content, project, report_type)
