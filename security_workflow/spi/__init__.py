"""Service Provider Interface — alert notifications, audit writing.

Built-in FileNotificationProvider (writes to unified data directory).
Extensible to enterprise IM/email/Webhook integrations.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..definition.enums import RiskLevel
from ..definition.constants import DEFAULT_DATA_DIR

# Data directory (shared with persistence)
DATA_ROOT = Path(os.environ.get("SECURITY_WORKFLOW_DATA", DEFAULT_DATA_DIR))
_notify_lock = threading.Lock()


def _notify_log() -> Path:
    """Notification record file path."""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    return DATA_ROOT / "notifications.jsonl"


def _emit(level: str, ticket_id: str, detail: str, extra: dict | None = None) -> None:
    """Write a structured notification record."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "ticket_id": ticket_id,
        "detail": detail,
        "extra": extra or {},
    }
    with _notify_lock:
        with open(_notify_log(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


def notify_high_risk(ticket_id: str, detail: str) -> None:
    """High-risk vulnerability alert — write notification log + console output.

    Production integration guide: call enterprise IM Webhook (Slack/Teams/Discord)
    or SMTP email within this function.
    """
    _emit("HIGH", ticket_id, detail, {"action_required": "Dual security review + Deployment blocked"})
    print(f"[NOTIFY:HIGH] {ticket_id} — {detail}")


def notify_overdue(ticket_id: str, level: RiskLevel, hours: float) -> None:
    """Overdue alert — write notification log + console output."""
    _emit(
        "OVERDUE",
        ticket_id,
        f"{level.value} ticket overdue by {hours:.1f}h",
        {"risk_level": level.value, "overdue_hours": round(hours, 1)},
    )
    print(f"[NOTIFY:OVERDUE] {ticket_id} — {level.value} overdue {hours:.1f}h, please handle immediately")


def notify_deploy_blocked(reason: str) -> None:
    """Deployment block notification — write notification log + console output."""
    _emit("DEPLOY_BLOCKED", "", reason, {})
    print(f"[NOTIFY:DEPLOY_BLOCKED] {reason}")


def read_notifications(limit: int = 50, level: str | None = None) -> list[dict]:
    """Read notification history, optionally filtered by level."""
    log = _notify_log()
    if not log.exists():
        return []
    entries: list[dict] = []
    with _notify_lock:
        with open(log, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if level is None or entry.get("level") == level:
                    entries.append(entry)
    return entries[-limit:] if limit > 0 else entries
