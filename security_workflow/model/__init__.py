"""Data models for tickets, audit entries, and scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from ..definition.enums import RiskLevel, TicketStatus, initial_status


@dataclass
class ScanFinding:
    """Single vulnerability scan result — aligned with security-scanner 9-field structured output."""

    risk_id: str
    risk_level: RiskLevel
    file_path: str
    line_no: int
    risk_desc: str
    compliance_rule: str
    fix_suggest: str
    scan_mode: str  # "full scan" | "incremental change scan" | "MR review scan" | "deployment gate scan"
    workflow_status: TicketStatus


@dataclass
class Ticket:
    """Security review ticket."""

    ticket_id: str
    risk_level: RiskLevel
    status: TicketStatus
    findings: list[ScanFinding] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    deadline: str = ""          # ISO-format deadline
    assignee: str = ""          # Current assignee
    reviewer1: str = ""         # Reviewer 1 (required for High)
    reviewer2: str = ""         # Reviewer 2 (required for High)
    reject_reason: str = ""     # Rejection reason
    branch: str = ""            # Associated branch
    project: str = ""           # Associated project

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["status"] = self.status.value
        d["findings"] = [asdict(f) for f in self.findings]
        for f_dict, finding in zip(d["findings"], self.findings):
            f_dict["risk_level"] = finding.risk_level.value
            f_dict["workflow_status"] = finding.workflow_status.value
        return d

    @classmethod
    def create(
        cls,
        ticket_id: str,
        risk_level: RiskLevel,
        findings: list[ScanFinding],
        branch: str = "",
        project: str = "",
    ) -> Ticket:
        """Factory method: create a ticket with auto-set initial status and deadline."""
        status = initial_status(risk_level)
        # Set deadline
        from ..timer.clock import compute_deadline
        deadline = compute_deadline(risk_level)

        return cls(
            ticket_id=ticket_id,
            risk_level=risk_level,
            status=status,
            findings=findings,
            deadline=deadline,
            branch=branch,
            project=project,
        )


@dataclass
class AuditEntry:
    """Audit log entry."""

    timestamp: str
    ticket_id: str
    action: str          # "created" | "transitioned" | "rejected" | "closed" | "overdue"
    from_status: str
    to_status: str
    operator: str        # "system" | "reviewer:name" | "auto"
    detail: str = ""     # Additional notes

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
