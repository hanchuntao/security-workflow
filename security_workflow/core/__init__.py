"""核心引擎 — 工单流转、状态变更、上线卡点判定."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..definition.enums import (
    RiskLevel,
    TicketStatus,
    TRANSITION_MAP,
    initial_status,
    is_blocking_status,
    is_closed_status,
)

# ── 项目名自动检测 ────────────────────────────────────────────────────────────

# 缓存在模块级别，避免重复读取
_cached_project: str | None = None


def detect_project_name() -> str:
    """自动检测当前项目名。

    优先级:
    1. 环境变量 SECURITY_WORKFLOW_PROJECT
    2. .security-workflow 配置文件中的 project 字段
    3. 当前工作目录名

    结果缓存在模块级别，首次调用后不再重复检测。
    """
    global _cached_project
    if _cached_project is not None:
        return _cached_project

    # 1. 环境变量
    env_project = os.environ.get("SECURITY_WORKFLOW_PROJECT", "").strip()
    if env_project:
        _cached_project = env_project
        return _cached_project

    # 2. 配置文件
    config_path = Path(".security-workflow")
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config_project = config.get("project", "").strip()
            if config_project:
                _cached_project = config_project
                return _cached_project
        except (json.JSONDecodeError, OSError):
            pass

    # 3. 工作目录名
    _cached_project = Path.cwd().name
    return _cached_project
from ..model import Ticket, ScanFinding, AuditEntry
from ..persistence import save_ticket, load_ticket, load_all_tickets, append_audit
from ..timer import is_overdue


def create_ticket(
    ticket_id: str,
    risk_level_str: str,
    findings_data: list[dict[str, Any]],
    branch: str = "",
    project: str = "",
) -> Ticket:
    """创建安全评审工单。

    project 为空时自动检测：
      1. $SECURITY_WORKFLOW_PROJECT 环境变量
      2. .security-workflow 配置文件 project 字段
      3. 当前目录名
    """
    risk_level = RiskLevel(risk_level_str)

    # 自动检测项目名
    if not project:
        project = detect_project_name()

    findings: list[ScanFinding] = []
    for fd in findings_data:
        findings.append(
            ScanFinding(
                risk_id=fd["risk_id"],
                risk_level=RiskLevel(fd["risk_level"]),
                file_path=fd["file_path"],
                line_no=int(fd["line_no"]),
                risk_desc=fd["risk_desc"],
                compliance_rule=fd.get("compliance_rule", ""),
                fix_suggest=fd.get("fix_suggest", ""),
                scan_mode=fd.get("scan_mode", ""),
                workflow_status=initial_status(risk_level),
            )
        )

    ticket = Ticket.create(
        ticket_id=ticket_id,
        risk_level=risk_level,
        findings=findings,
        branch=branch,
        project=project,
    )

    save_ticket(ticket)

    append_audit(
        AuditEntry(
            timestamp=ticket.created_at,
            ticket_id=ticket_id,
            action="created",
            from_status="",
            to_status=ticket.status.value,
            operator="system",
            detail=f"工单创建 — 风险等级: {risk_level.value}, 漏洞数: {len(findings)}",
        )
    )

    return ticket


def transition_ticket(
    ticket_id: str,
    target_status_str: str,
    operator: str = "system",
    detail: str = "",
) -> Ticket:
    """工单状态流转."""
    target = TicketStatus(target_status_str)
    ticket = load_ticket(ticket_id)
    if ticket is None:
        raise ValueError(f"工单不存在: {ticket_id}")

    # 检查流转是否合法
    allowed = TRANSITION_MAP.get(ticket.status, [])
    if target not in allowed:
        raise ValueError(
            f"非法的状态流转: {ticket.status.value} → {target.value}."
            f" 允许的目标状态: {[s.value for s in allowed]}"
        )

    old_status = ticket.status
    old_status_str = old_status.value

    ticket.status = target
    ticket.updated_at = datetime.now(timezone.utc).isoformat()

    save_ticket(ticket)

    append_audit(
        AuditEntry(
            timestamp=ticket.updated_at,
            ticket_id=ticket_id,
            action="transitioned",
            from_status=old_status_str,
            to_status=target.value,
            operator=operator,
            detail=detail or f"状态变更: {old_status_str} → {target.value}",
        )
    )

    return ticket


def reject_ticket(ticket_id: str, reason: str, operator: str) -> Ticket:
    """驳回工单（要求重新整改）."""
    if not reason.strip():
        raise ValueError("驳回工单必须填写驳回原因")

    ticket = load_ticket(ticket_id)
    if ticket is None:
        raise ValueError(f"工单不存在: {ticket_id}")

    ticket.reject_reason = reason
    return transition_ticket(
        ticket_id=ticket_id,
        target_status_str=TicketStatus.REJECTED.value,
        operator=operator,
        detail=f"驳回原因: {reason}",
    )


def check_and_mark_overdue() -> list[Ticket]:
    """扫描所有工单，将超时工单标记为 OVERDUE."""
    overdue_tickets: list[Ticket] = []
    all_tickets = load_all_tickets()

    for ticket in all_tickets:
        if is_closed_status(ticket.status):
            continue
        if ticket.status == TicketStatus.OVERDUE:
            overdue_tickets.append(ticket)
            continue
        if is_overdue(ticket.deadline):
            try:
                updated = transition_ticket(
                    ticket_id=ticket.ticket_id,
                    target_status_str=TicketStatus.OVERDUE.value,
                    operator="system",
                    detail=f"超时自动标记 — 截止时间: {ticket.deadline}",
                )
                overdue_tickets.append(updated)
            except ValueError:
                continue  # 状态不允许流转则跳过

    return overdue_tickets


def check_deploy_gate(project: str = "", branch: str = "") -> dict[str, Any]:
    """上线卡点校验 — 返回是否允许上线及阻断原因."""
    all_tickets = load_all_tickets()

    blocked_by: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    # 先刷新超时状态
    check_and_mark_overdue()

    # 重新加载 (超时状态可能已更新)
    all_tickets = load_all_tickets()

    for ticket in all_tickets:
        # 过滤项目和分支
        if project and ticket.project and ticket.project != project:
            continue
        if branch and ticket.branch and ticket.branch != branch:
            continue

        if is_closed_status(ticket.status):
            continue  # 已闭环，不阻断

        entry = {
            "ticket_id": ticket.ticket_id,
            "risk_level": ticket.risk_level.value,
            "status": ticket.status.value,
            "deadline": ticket.deadline,
            "findings_count": len(ticket.findings),
        }

        if ticket.risk_level == RiskLevel.HIGH and not is_closed_status(ticket.status):
            # 规则1: 存在未闭环高危工单 → 直接阻断
            entry["reason"] = "存在未闭环高危漏洞工单，禁止上线"
            blocked_by.append(entry)

        elif ticket.risk_level == RiskLevel.MEDIUM:
            if ticket.status == TicketStatus.OVERDUE:
                # 规则2: 存在超时未整改中危工单 → 阻断
                entry["reason"] = "存在超时未整改中危工单，禁止上线"
                blocked_by.append(entry)
            elif not is_closed_status(ticket.status):
                # 规则3: 存在未闭环中危工单 → 警告（不阻断）
                entry["reason"] = "存在未闭环中危工单，建议限期整改"
                warnings.append(entry)

        elif ticket.risk_level == RiskLevel.LOW and not is_closed_status(ticket.status):
            # 低危仅记录台账
            entry["reason"] = "低危未优化项，记录台账不阻断"
            warnings.append(entry)

    allowed = len(blocked_by) == 0

    return {
        "allowed": allowed,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_by": blocked_by,
        "warnings": warnings,
        "verdict": "允许上线" if allowed else "阻断上线",
    }
