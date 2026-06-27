"""Core engine — ticket lifecycle, state transitions, deployment gate decisions."""

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

# ── Project name auto-detection ─────────────────────────────────────────────────

# Cached at module level to avoid repeated reads
_cached_project: str | None = None


def detect_project_name() -> str:
    """Auto-detect the current project name.

    Priority:
    1. SECURITY_WORKFLOW_PROJECT environment variable
    2. .security-workflow config file 'project' field
    3. Current working directory name

    Result is cached at module level; detection runs only once.
    """
    global _cached_project
    if _cached_project is not None:
        return _cached_project

    # 1. Environment variable
    env_project = os.environ.get("SECURITY_WORKFLOW_PROJECT", "").strip()
    if env_project:
        _cached_project = env_project
        return _cached_project

    # 2. Config file (path normalization + project root fence validation)
    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
    config_path = (PROJECT_ROOT / ".security-workflow").resolve()
    # Fence check: ensure resolved config path is within project root
    # Use casefold() for case-insensitive comparison (Windows-safe) and compare
    # fully resolved paths to prevent symlink escape
    root_str = str(PROJECT_ROOT.resolve()).casefold()
    config_str = str(config_path).casefold()
    if not config_str.startswith(root_str + os.sep) and config_str != root_str:
        # Path escape — skip invalid config
        _cached_project = Path.cwd().name
        return _cached_project
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config_project = config.get("project", "").strip()
            if config_project:
                _cached_project = config_project
                return _cached_project
        except (json.JSONDecodeError, OSError):
            pass

    # 3. Working directory name
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
    """Create a security review ticket.

    When project is empty, auto-detect via:
      1. $SECURITY_WORKFLOW_PROJECT env var
      2. .security-workflow config file 'project' field
      3. Current directory name
    """
    risk_level = RiskLevel(risk_level_str)

    # Auto-detect project name
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
            detail=f"Ticket created — risk level: {risk_level.value}, findings: {len(findings)}",
        )
    )

    return ticket


def transition_ticket(
    ticket_id: str,
    target_status_str: str,
    operator: str = "system",
    detail: str = "",
) -> Ticket:
    """Transition a ticket to a new state."""
    target = TicketStatus(target_status_str)
    ticket = load_ticket(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket not found: {ticket_id}")

    # Validate transition legality
    allowed = TRANSITION_MAP.get(ticket.status, [])
    if target not in allowed:
        raise ValueError(
            f"Illegal state transition: {ticket.status.value} → {target.value}."
            f" Allowed targets: {[s.value for s in allowed]}"
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
            detail=detail or f"State change: {old_status_str} → {target.value}",
        )
    )

    return ticket


def reject_ticket(ticket_id: str, reason: str, operator: str) -> Ticket:
    """Reject a ticket (requires re-remediation)."""
    if not reason.strip():
        raise ValueError("Rejection reason is required")

    ticket = load_ticket(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket not found: {ticket_id}")

    ticket.reject_reason = reason
    return transition_ticket(
        ticket_id=ticket_id,
        target_status_str=TicketStatus.REJECTED.value,
        operator=operator,
        detail=f"Rejection reason: {reason}",
    )


def check_and_mark_overdue() -> list[Ticket]:
    """Scan all tickets and mark overdue ones as OVERDUE."""
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
                    detail=f"Auto-marked overdue — deadline: {ticket.deadline}",
                )
                overdue_tickets.append(updated)
            except ValueError:
                continue  # Skip if state transition not allowed

    return overdue_tickets


def check_deploy_gate(project: str = "", branch: str = "") -> dict[str, Any]:
    """Deployment gate check — returns whether deployment is allowed and blocking reasons."""
    all_tickets = load_all_tickets()

    blocked_by: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    # Refresh overdue status first
    check_and_mark_overdue()

    # Reload (overdue status may have changed)
    all_tickets = load_all_tickets()

    for ticket in all_tickets:
        # Filter by project and branch
        if project and ticket.project and ticket.project != project:
            continue
        if branch and ticket.branch and ticket.branch != branch:
            continue

        if is_closed_status(ticket.status):
            continue  # Already closed, not blocking

        entry = {
            "ticket_id": ticket.ticket_id,
            "risk_level": ticket.risk_level.value,
            "status": ticket.status.value,
            "deadline": ticket.deadline,
            "findings_count": len(ticket.findings),
        }

        if ticket.risk_level == RiskLevel.HIGH and not is_closed_status(ticket.status):
            # Rule 1: Unclosed High-risk ticket → direct block
            entry["reason"] = "Unclosed High-risk vulnerability ticket — deployment blocked"
            blocked_by.append(entry)

        elif ticket.risk_level == RiskLevel.MEDIUM:
            if ticket.status == TicketStatus.OVERDUE:
                # Rule 2: Overdue unresolved Medium-risk ticket → block
                entry["reason"] = "Overdue unresolved Medium-risk ticket — deployment blocked"
                blocked_by.append(entry)
            elif not is_closed_status(ticket.status):
                # Rule 3: Unclosed Medium-risk ticket → warning (non-blocking)
                entry["reason"] = "Unclosed Medium-risk ticket — fix within deadline recommended"
                warnings.append(entry)

        elif ticket.risk_level == RiskLevel.LOW and not is_closed_status(ticket.status):
            # Low-risk logged to ledger only
            entry["reason"] = "Low-risk unoptimized item — logged, not blocking"
            warnings.append(entry)

    allowed = len(blocked_by) == 0

    return {
        "allowed": allowed,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_by": blocked_by,
        "warnings": warnings,
        "verdict": "ALLOWED" if allowed else "BLOCKED",
    }


def generate_review_report(
    project: str = "",
    branch: str = "",
    scan_mode: str = "全量扫描",
    report_type: str = "review",
    lang: str | None = None,
) -> dict[str, Any]:
    """One-stop: collect ticket data → generate report → persist to disk.

    Called by /review and /deploy commands at the end of their pipeline.

    Args:
        lang: Report language (``"en"`` or ``"zh"``). Defaults to
               ``SECURITY_WORKFLOW_LANG`` env var, falling back to ``"en"``.

    Returns:
        {"filepath": str, "ticket_count": int, "finding_count": int, ...}
    """
    from ..report import generate_and_save

    all_tickets = load_all_tickets()

    # Filter tickets by specified project/branch
    filtered: list[dict] = []
    for t in all_tickets:
        if project and t.project and t.project != project:
            continue
        if branch and t.branch and t.branch != branch:
            continue
        filtered.append(t.to_dict())

    # Run deploy gate (to show blocking status in the report)
    gate = check_deploy_gate(project=project, branch=branch) if report_type == "deploy" else None

    # Auto-detect project name
    effective_project = project or detect_project_name()

    filepath = generate_and_save(
        project=effective_project,
        branch=branch or "main",
        scan_mode=scan_mode,
        tickets=filtered,
        deploy_gate=gate,
        report_type=report_type,
        lang=lang,
    )

    total_findings = sum(len(t.get("findings", [])) for t in filtered)

    return {
        "filepath": str(filepath),
        "project": effective_project,
        "ticket_count": len(filtered),
        "finding_count": total_findings,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
