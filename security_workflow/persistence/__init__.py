"""Persistence layer — JSON file storage for audit logs and ticket state."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from ..model import Ticket, ScanFinding, AuditEntry
from ..definition.enums import RiskLevel, TicketStatus
from ..definition.constants import DEFAULT_DATA_DIR

# Storage root directory (overridable via environment variable)
STORAGE_ROOT = Path(os.environ.get("SECURITY_WORKFLOW_DATA", DEFAULT_DATA_DIR))
lock = threading.Lock()


def _tickets_file() -> Path:
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    return STORAGE_ROOT / "tickets.json"


def _audit_file() -> Path:
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    return STORAGE_ROOT / "audit_log.jsonl"


def _read_json(path: Path) -> dict[str, Any]:
    """Thread-safe JSON read."""
    with lock:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Thread-safe JSON write."""
    with lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def save_ticket(ticket: Ticket) -> None:
    """Save or update a ticket."""
    all_tickets = _read_json(_tickets_file())
    all_tickets[ticket.ticket_id] = ticket.to_dict()
    _write_json(_tickets_file(), all_tickets)


def load_ticket(ticket_id: str) -> Ticket | None:
    """Load a single ticket by ID."""
    all_tickets = _read_json(_tickets_file())
    data = all_tickets.get(ticket_id)
    if not data:
        return None
    return _dict_to_ticket(data)


def load_all_tickets() -> list[Ticket]:
    """Load all tickets."""
    all_tickets = _read_json(_tickets_file())
    tickets: list[Ticket] = []
    for data in all_tickets.values():
        try:
            tickets.append(_dict_to_ticket(data))
        except (KeyError, TypeError):
            continue
    return tickets


def append_audit(entry: AuditEntry) -> None:
    """Append an audit log entry."""
    with lock:
        _audit_file().parent.mkdir(parents=True, exist_ok=True)
        with open(_audit_file(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False, default=str) + "\n")


def read_audit_trail(ticket_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Read audit trail, optionally filtered by ticket_id."""
    if not _audit_file().exists():
        return []
    entries: list[dict[str, Any]] = []
    with lock:
        with open(_audit_file(), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ticket_id is None or entry.get("ticket_id") == ticket_id:
                    entries.append(entry)
    return entries[-limit:] if limit > 0 else entries


def _dict_to_ticket(data: dict[str, Any]) -> Ticket:
    """Reconstruct a Ticket object from a dict."""
    findings = []
    for f_data in data.get("findings", []):
        findings.append(
            ScanFinding(
                risk_id=f_data["risk_id"],
                risk_level=RiskLevel(f_data["risk_level"]),
                file_path=f_data["file_path"],
                line_no=f_data["line_no"],
                risk_desc=f_data["risk_desc"],
                compliance_rule=f_data.get("compliance_rule", ""),
                fix_suggest=f_data.get("fix_suggest", ""),
                scan_mode=f_data.get("scan_mode", ""),
                workflow_status=TicketStatus(f_data["workflow_status"]),
            )
        )

    return Ticket(
        ticket_id=data["ticket_id"],
        risk_level=RiskLevel(data["risk_level"]),
        status=TicketStatus(data["status"]),
        findings=findings,
        created_at=data.get("created_at", ""),
        updated_at=data.get("updated_at", ""),
        deadline=data.get("deadline", ""),
        assignee=data.get("assignee", ""),
        reviewer1=data.get("reviewer1", ""),
        reviewer2=data.get("reviewer2", ""),
        reject_reason=data.get("reject_reason", ""),
        branch=data.get("branch", ""),
        project=data.get("project", ""),
    )
