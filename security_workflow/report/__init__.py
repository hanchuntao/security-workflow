"""Audit report auto-generation module — bilingual: English (default) + Chinese (等保2.0).

Language is controlled by:
  1. Explicit ``lang`` parameter on function calls
  2. ``SECURITY_WORKFLOW_LANG`` environment variable (default: ``en``)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..persistence import STORAGE_ROOT

REPORTS_DIR = STORAGE_ROOT / "reports"

# ── Language resolution ────────────────────────────────────────────────────────

def resolve_lang(explicit: str | None = None) -> str:
    """Resolve report language.

    Priority: explicit parameter > ``SECURITY_WORKFLOW_LANG`` env var > ``"en"``.
    Valid values: ``"en"``, ``"zh"``.
    """
    if explicit and explicit in ("en", "zh"):
        return explicit
    env = os.environ.get("SECURITY_WORKFLOW_LANG", "").strip().lower()
    if env in ("en", "zh"):
        return env
    return "en"


# ── Helpers ────────────────────────────────────────────────────────────────────

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
#  Review Report — bilingual (en / zh)
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_review_report_en(
    project: str,
    branch: str,
    scan_mode: str,
    tickets: list[dict[str, Any]],
) -> str:
    """English /review report."""
    now = _now()
    counts = _counts(tickets)
    all_findings = _flatten(tickets)
    total = sum(counts.values())

    if counts["高危"] > 0:
        rating = "🔴 HIGH — Deployment blocked, immediate remediation required"
    elif counts["中危"] > 0:
        rating = "🟡 MEDIUM — Remediate within deadline, then re-review"
    elif counts["低危"] > 0:
        rating = "🟢 GOOD — Low-risk items logged in ledger"
    else:
        rating = "✅ EXCELLENT — No security risks found"

    L: list[str] = []

    L.append("# 🔍 Code Security Review Report — `/review`")
    L.append("")
    L.append("| Project | Branch | Scan Mode | Review Time |")
    L.append("|---------|--------|-----------|-------------|")
    L.append(f"| `{project}` | `{branch}` | {scan_mode} | {now} |")
    L.append("")

    L.append("---")
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

    L.append("---")
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

    L.append("---")
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
        L.append("| Ticket ID | Findings | Status | Deadline |")
        L.append("|-----------|----------|--------|----------|")
        for t in related:
            tid = t.get("ticket_id", "")
            fcnt = len(t.get("findings", []))
            status = t.get("status", "")
            deadline = (t.get("deadline", "") or "")[:16]
            L.append(f"| `{tid}` | {fcnt} | **{status}** | {deadline} |")
        L.append("")
        L.append(f"⏱️ Deadline: {deadline_note}")
        L.append("")

    if counts["高危"] > 0:
        L.append("---")
        L.append("## IV. High-Risk Detailed Fix Guidance")
        L.append("")
        L.append("> ⚠️ The following vulnerabilities **must NOT be auto-fixed**. They require manual remediation and dual security review.")
        L.append("")
        high_items = [f for f in all_findings if f.get("risk_level") == "高危"]
        for i, f in enumerate(high_items, 1):
            L.append(f"**{i}. `{f.get('risk_id','')}` — `{f.get('file_path','')}:{f.get('line_no','')}`**")
            L.append(f"- Description: {f.get('risk_desc','')}")
            L.append(f"- Compliance: {f.get('compliance_rule','')}")
            L.append(f"- Fix suggestion: {f.get('fix_suggest','')}")
            L.append("")

    L.append("---")
    L.append("## V. Next Steps")
    L.append("")
    L.append("1. **Immediately:** Assign security owner to High-risk tickets — complete remediation within 72 hours")
    L.append("2. **This week:** Confirm Medium-risk fix plans and execute — close within 5 business days")
    L.append("3. **Auto:** Low-risk items handled by `auto-fix-security.sh` (or pending auto-closure)")
    L.append("4. **Before release:** Run `/deploy` to validate the gate — ensure zero blocking items")
    L.append("")

    L.append("---")
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


def _generate_review_report_zh(
    project: str,
    branch: str,
    scan_mode: str,
    tickets: list[dict[str, Any]],
) -> str:
    """中文 /review 评审报告（等保2.0 兼容）."""
    now = _now()
    counts = _counts(tickets)
    all_findings = _flatten(tickets)
    total = sum(counts.values())

    if counts["高危"] > 0:
        rating = "🔴 高危 — 禁止上线，立即整改"
    elif counts["中危"] > 0:
        rating = "🟡 中 — 限期整改后复查"
    elif counts["低危"] > 0:
        rating = "🟢 良好 — 低危项记录台账"
    else:
        rating = "✅ 优秀 — 无安全风险"

    L: list[str] = []

    L.append("# 🔍 代码安全评审报告 — `/review`")
    L.append("")
    L.append("| 项目 | 分支 | 扫描模式 | 评审时间 |")
    L.append("|------|------|---------|---------|")
    L.append(f"| `{project}` | `{branch}` | {scan_mode} | {now} |")
    L.append("")

    L.append("---")
    L.append("## 一、扫描结果汇总")
    L.append("")
    L.append("| 风险等级 | 漏洞数量 | 处理策略 | 阻断上线 |")
    L.append("|----------|---------|---------|----------|")
    L.append(f"| 🔴 高危 | {counts['高危']} | 人工整改 + 双人评审 | **是** |")
    L.append(f"| 🟡 中危 | {counts['中危']} | 半自动确认 + 限期整改 | 超时后阻断 |")
    L.append(f"| 🟢 低危 | {counts['低危']} | 全自动静默修复 | 否 |")
    L.append(f"| **合计** | **{total}** | | |")
    L.append("")
    L.append(f"**安全评级:** {rating}")
    L.append("")

    L.append("---")
    L.append("## 二、漏洞详情")
    L.append("")
    for level, emoji in [("高危", "🔴"), ("中危", "🟡"), ("低危", "🟢")]:
        items = [f for f in all_findings if f.get("risk_level") == level]
        if not items:
            continue
        L.append(f"### {emoji} {level}漏洞 ({len(items)}项)")
        L.append("")
        L.append("| risk_id | 文件:行号 | 漏洞描述 | 合规依据 | 修复建议 |")
        L.append("|---------|-----------|---------|---------|---------|")
        for f in items:
            rid = f.get("risk_id", "")
            fp = f.get("file_path", "")
            ln = f.get("line_no", "")
            desc = f.get("risk_desc", "")[:45]
            rule = (f.get("compliance_rule", "") or "")[:20]
            fix = (f.get("fix_suggest", "") or "")[:35]
            L.append(f"| `{rid}` | `{fp}:{ln}` | {desc} | {rule} | {fix} |")
        L.append("")

    L.append("---")
    L.append("## 三、修复策略与整改计划")
    L.append("")
    for level, emoji, strategy, deadline_note in [
        ("高危", "🔴", "人工整改（禁止自动修复）", "72小时内"),
        ("中危", "🟡", "半自动确认修复（待人工确认）", "5个工作日内"),
        ("低危", "🟢", "全自动静默修复（无需人工干预）", "7天内自动闭环"),
    ]:
        related = [t for t in tickets if t.get("risk_level") == level]
        if not related:
            continue
        L.append(f"### {emoji} {level} — {strategy}")
        L.append("")
        L.append("| 工单 ID | 漏洞数 | 当前状态 | 截止时间 |")
        L.append("|---------|--------|---------|---------|")
        for t in related:
            tid = t.get("ticket_id", "")
            fcnt = len(t.get("findings", []))
            status = t.get("status", "")
            deadline = (t.get("deadline", "") or "")[:16]
            L.append(f"| `{tid}` | {fcnt} | **{status}** | {deadline} |")
        L.append("")
        L.append(f"⏱️ 整改时限: {deadline_note}")
        L.append("")

    if counts["高危"] > 0:
        L.append("---")
        L.append("## 四、高危漏洞详细修复指引")
        L.append("")
        L.append("> ⚠️ 以下漏洞**禁止自动修复**，必须经人工整改后通过双人安全评审。")
        L.append("")
        high_items = [f for f in all_findings if f.get("risk_level") == "高危"]
        for i, f in enumerate(high_items, 1):
            L.append(f"**{i}. `{f.get('risk_id','')}` — `{f.get('file_path','')}:{f.get('line_no','')}`**")
            L.append(f"- 漏洞描述: {f.get('risk_desc','')}")
            L.append(f"- 合规依据: {f.get('compliance_rule','')}")
            L.append(f"- 修复建议: {f.get('fix_suggest','')}")
            L.append("")

    L.append("---")
    L.append("## 五、后续步骤")
    L.append("")
    L.append("1. **立即:** 指派安全责任人处理高危工单，72小时内完成整改")
    L.append("2. **本周:** 确认中危修复方案并执行，5个工作日内闭环")
    L.append("3. **自动:** 低危项已由 `auto-fix-security.sh` 自动处理（或待自动闭环）")
    L.append("4. **上线前:** 执行 `/deploy` 命令校验卡点，确保无阻断项")
    L.append("")

    L.append("---")
    L.append("## 六、审计合规声明")
    L.append("")
    L.append(f"- ✅ 本次扫描覆盖全项目，检出 {total} 项安全风险")
    L.append("- ✅ 遵循 OWASP Top10 + 等保2.0 + 企业安全编码规范")
    L.append("- ✅ 分级修复策略: 高危人工 / 中危半自动 / 低危全自动")
    L.append("- ✅ 工单数据已结构化存储，审计轨迹完整可追溯")
    L.append(f"- {'⚠️ 存在未闭环高危漏洞，/deploy 将被阻断' if counts['高危'] > 0 else '✅ 无高危漏洞，可进入 /deploy 阶段'}")
    L.append("")
    L.append(f"*报告生成: {now} | 引擎: security-workflow-mcp-engine v1.0.1*")
    L.append(f"*数据目录: {STORAGE_ROOT}*")

    return "\n".join(L)


def generate_review_report(
    project: str,
    branch: str,
    scan_mode: str,
    tickets: list[dict[str, Any]],
    lang: str | None = None,
) -> str:
    """Generate a /review code security review report (bilingual)."""
    lang = resolve_lang(lang)
    if lang == "zh":
        return _generate_review_report_zh(project, branch, scan_mode, tickets)
    return _generate_review_report_en(project, branch, scan_mode, tickets)


# ═══════════════════════════════════════════════════════════════════════════════
#  Deploy Report — bilingual (en / zh)
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_deploy_report_en(
    project: str,
    branch: str,
    tickets: list[dict[str, Any]],
    deploy_gate: dict[str, Any],
) -> str:
    """English /deploy report."""
    now = _now()
    counts = _counts(tickets)
    total = sum(counts.values())

    closed_count = sum(1 for t in tickets if "闭环" in t.get("status", ""))
    open_count = len(tickets) - closed_count

    allowed = deploy_gate.get("allowed", False)
    verdict = deploy_gate.get("verdict", "")
    blocked = deploy_gate.get("blocked_by", [])
    warnings = deploy_gate.get("warnings", [])

    L: list[str] = []

    L.append("# 🚦 Deployment Security Gate Report — `/deploy`")
    L.append("")
    L.append("| Project | Branch | Check Time | Workflow |")
    L.append("|---------|--------|------------|----------|")
    L.append(f"| `{project}` | `{branch}` | {now} | workflow=true |")
    L.append("")

    L.append("---")
    L.append("## I. Admission Verdict")
    L.append("")
    if allowed:
        L.append("```\n  ✅   DEPLOY ALLOWED\n```")
        L.append("")
        L.append(f"**Verdict:** {verdict}")
        L.append("")
        L.append("The current branch satisfies deployment security gate requirements — no blocking items.")
        if warnings:
            L.append(f"{len(warnings)} warning(s) present. Recommended to track after deployment.")
    else:
        L.append("```\n  ⛔   DEPLOY BLOCKED\n```")
        L.append("")
        L.append(f"**Verdict:** {verdict}")
        L.append("")
        L.append("The current branch **does NOT** satisfy deployment security gate requirements. All blocked items below must be resolved before re-validation.")
    L.append("")

    if blocked:
        L.append("---")
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

    L.append("---")
    L.append("## III. Ticket Closure Verification")
    L.append("")
    L.append("| Status | Count |")
    L.append("|--------|-------|")
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

    L.append("---")
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

    if warnings:
        L.append("---")
        L.append("## V. Warnings")
        L.append("")
        L.append("| Ticket ID | Risk Level | Warning Reason |")
        L.append("|-----------|------------|----------------|")
        for w in warnings:
            L.append(f"| `{w.get('ticket_id','')}` | {w.get('risk_level','')} | {w.get('reason','')} |")
        L.append("")
        L.append("> ⚠️ Warnings do not block this deployment but must be resolved within their deadlines. Overdue items auto-escalate to blocking level.")
        L.append("")

    L.append("---")
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


def _generate_deploy_report_zh(
    project: str,
    branch: str,
    tickets: list[dict[str, Any]],
    deploy_gate: dict[str, Any],
) -> str:
    """中文 /deploy 上线安全卡点报告（等保2.0 兼容）."""
    now = _now()
    counts = _counts(tickets)
    total = sum(counts.values())

    closed_count = sum(1 for t in tickets if "闭环" in t.get("status", ""))
    open_count = len(tickets) - closed_count

    allowed = deploy_gate.get("allowed", False)
    verdict = deploy_gate.get("verdict", "")
    blocked = deploy_gate.get("blocked_by", [])
    warnings = deploy_gate.get("warnings", [])

    L: list[str] = []

    L.append("# 🚦 上线安全卡点报告 — `/deploy`")
    L.append("")
    L.append("| 项目 | 分支 | 校验时间 | 工单联动 |")
    L.append("|------|------|---------|---------|")
    L.append(f"| `{project}` | `{branch}` | {now} | workflow=true |")
    L.append("")

    L.append("---")
    L.append("## 一、准入判定")
    L.append("")
    if allowed:
        L.append("```\n  ✅  允 许 上 线\n```")
        L.append("")
        L.append(f"**结论:** {verdict}")
        L.append("")
        L.append("当前分支满足上线安全卡点要求，无阻断项。")
        if warnings:
            L.append(f"存在 {len(warnings)} 个警告项，建议在上线后持续跟踪。")
    else:
        L.append("```\n  ⛔  阻 断 上 线\n```")
        L.append("")
        L.append(f"**结论:** {verdict}")
        L.append("")
        L.append("当前分支**不满足**上线安全卡点要求，必须处理以下阻断项后方可重新校验。")
    L.append("")

    if blocked:
        L.append("---")
        L.append("## 二、阻断项")
        L.append("")
        L.append("| 工单 ID | 风险等级 | 阻断原因 | 当前状态 | 截止时间 |")
        L.append("|---------|---------|---------|---------|---------|")
        for b in blocked:
            tid = b.get("ticket_id", "")
            level = b.get("risk_level", "")
            reason = b.get("reason", "")
            match = [t for t in tickets if t.get("ticket_id") == tid]
            status = match[0].get("status", "—") if match else "—"
            deadline = (match[0].get("deadline", "") or "")[:16] if match else "—"
            L.append(f"| `{tid}` | {level} | {reason} | **{status}** | {deadline} |")
        L.append("")
        L.append("> ⛔ 以上阻断项必须全部闭环后，重新执行 `/deploy` 校验。")
        L.append("")

    L.append("---")
    L.append("## 三、工单闭环校验")
    L.append("")
    L.append("| 状态 | 数量 |")
    L.append("|------|------|")
    status_groups: dict[str, int] = {}
    for t in tickets:
        s = t.get("status", "未知")
        status_groups[s] = status_groups.get(s, 0) + 1
    for s, n in sorted(status_groups.items()):
        L.append(f"| {s} | {n} |")
    L.append("")
    L.append(f"- 已闭环: {closed_count} / 未闭环: {open_count}")
    L.append("")

    L.append("### 工单清单")
    L.append("")
    L.append("| 工单 ID | 风险等级 | 状态 | 漏洞数 | 截止时间 |")
    L.append("|---------|---------|------|--------|---------|")
    for t in tickets:
        tid = t.get("ticket_id", "")
        level = t.get("risk_level", "")
        status = t.get("status", "")
        fcnt = len(t.get("findings", []))
        deadline = (t.get("deadline", "") or "")[:16]
        icon = "✅" if "闭环" in status else "⏳"
        L.append(f"| `{tid}` | {level} | {icon} {status} | {fcnt} | {deadline} |")
    L.append("")

    L.append("---")
    L.append("## 四、修复完成情况")
    L.append("")
    L.append("| 风险等级 | 漏洞总数 | 已闭环 | 未闭环 | 完成率 |")
    L.append("|----------|---------|--------|--------|--------|")
    for level in ["高危", "中危", "低危"]:
        total_l = counts[level]
        closed_l = sum(
            len(t.get("findings", []))
            for t in tickets
            if t.get("risk_level") == level and "闭环" in t.get("status", "")
        )
        open_l = total_l - closed_l
        rate = f"{closed_l / total_l * 100:.0f}%" if total_l > 0 else "—"
        L.append(f"| {level} | {total_l} | {closed_l} | {open_l} | {rate} |")
    L.append("")

    if warnings:
        L.append("---")
        L.append("## 五、警告项")
        L.append("")
        L.append("| 工单 ID | 风险等级 | 警告原因 |")
        L.append("|---------|---------|---------|")
        for w in warnings:
            L.append(f"| `{w.get('ticket_id','')}` | {w.get('risk_level','')} | {w.get('reason','')} |")
        L.append("")
        L.append("> ⚠️ 警告项不阻断本次上线，但需在上线后限期处理。超期未处理将自动升级为阻断。")
        L.append("")

    L.append("---")
    L.append("## 六、审计合规声明")
    L.append("")
    L.append(f"- 校验时间: {now}")
    L.append(f"- 校验范围: 项目 `{project}` / 分支 `{branch}`")
    L.append(f"- 关联工单: {len(tickets)} 张（{total} 项漏洞）")
    L.append(f"- 阻断项: {len(blocked)} / 警告项: {len(warnings)}")
    L.append(f"- 判定依据: {'全部工单已闭环' if allowed else '存在未闭环阻断级工单'}")
    L.append("- 审计日志: `.security-workflow-data/audit_log.jsonl`")
    L.append("- 全链路操作记录已完成结构化存储，满足等保2.0审计要求")
    L.append("")
    L.append(f"*报告生成: {now} | 引擎: security-workflow-mcp-engine v1.0.1*")
    L.append(f"*数据目录: {STORAGE_ROOT}*")

    return "\n".join(L)


def generate_deploy_report(
    project: str,
    branch: str,
    tickets: list[dict[str, Any]],
    deploy_gate: dict[str, Any],
    lang: str | None = None,
) -> str:
    """Generate a /deploy security gate report (bilingual)."""
    lang = resolve_lang(lang)
    if lang == "zh":
        return _generate_deploy_report_zh(project, branch, tickets, deploy_gate)
    return _generate_deploy_report_en(project, branch, tickets, deploy_gate)


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
    lang: str | None = None,
) -> Path:
    """One-stop: generate a report by type and persist to disk (bilingual)."""
    lang = resolve_lang(lang)
    if report_type == "deploy" and deploy_gate:
        content = generate_deploy_report(
            project=project,
            branch=branch,
            tickets=tickets,
            deploy_gate=deploy_gate,
            lang=lang,
        )
    else:
        content = generate_review_report(
            project=project,
            branch=branch,
            scan_mode=scan_mode,
            tickets=tickets,
            lang=lang,
        )
    return save_report(content, project, report_type)
