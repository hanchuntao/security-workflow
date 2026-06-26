"""Timeout calculation and detection."""

from datetime import datetime, timezone, timedelta

from ..definition.enums import RiskLevel


# Timeout thresholds (aligned with workflow-audit.md)
DEADLINE_HOURS: dict[RiskLevel, int] = {
    RiskLevel.HIGH: 72,     # 72 hours without fix triggers timeout
    RiskLevel.MEDIUM: 120,  # 5 business days (24h×5)
    RiskLevel.LOW: 168,     # 7 days (Low non-blocking, log only)
}


def compute_deadline(level: RiskLevel) -> str:
    """Calculate ticket deadline based on risk level."""
    hours = DEADLINE_HOURS.get(level, 72)
    deadline = datetime.now(timezone.utc) + timedelta(hours=hours)
    return deadline.isoformat()


def is_overdue(deadline_iso: str) -> bool:
    """Check whether a ticket has exceeded its deadline."""
    if not deadline_iso:
        return False
    try:
        deadline = datetime.fromisoformat(deadline_iso)
        return datetime.now(timezone.utc) > deadline
    except (ValueError, TypeError):
        return False


def overdue_duration_hours(deadline_iso: str) -> float:
    """Return overdue duration in hours; 0 if not overdue."""
    if not deadline_iso or not is_overdue(deadline_iso):
        return 0.0
    deadline = datetime.fromisoformat(deadline_iso)
    delta = datetime.now(timezone.utc) - deadline
    return delta.total_seconds() / 3600
