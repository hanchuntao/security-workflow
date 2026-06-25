"""Data models for tickets, audit entries, and scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from ..definition.enums import RiskLevel, TicketStatus, initial_status


@dataclass
class ScanFinding:
    """单条漏洞扫描结果 — 对齐 security-scanner 9 项结构化输出."""

    risk_id: str
    risk_level: RiskLevel
    file_path: str
    line_no: int
    risk_desc: str
    compliance_rule: str
    fix_suggest: str
    scan_mode: str  # "全量扫描" | "增量变更扫描" | "MR评审扫描" | "上线卡点扫描"
    workflow_status: TicketStatus


@dataclass
class Ticket:
    """安全评审工单."""

    ticket_id: str
    risk_level: RiskLevel
    status: TicketStatus
    findings: list[ScanFinding] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    deadline: str = ""          # ISO-format 截止时间
    assignee: str = ""          # 当前处理人
    reviewer1: str = ""         # 复核人1 (高危强制)
    reviewer2: str = ""         # 复核人2 (高危强制)
    reject_reason: str = ""     # 驳回原因
    branch: str = ""            # 关联分支
    project: str = ""           # 关联项目

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
        """工厂方法：创建工单并自动设置初始状态."""
        status = initial_status(risk_level)
        # 设定截止时间
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
    """审计日志条目."""

    timestamp: str
    ticket_id: str
    action: str          # "created" | "transitioned" | "rejected" | "closed" | "overdue"
    from_status: str
    to_status: str
    operator: str        # "system" | "reviewer:name" | "auto"
    detail: str = ""     # 补充说明

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
