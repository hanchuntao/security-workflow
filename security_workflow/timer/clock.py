"""超时计算与检测."""

from datetime import datetime, timezone, timedelta

from ..definition.enums import RiskLevel


# 超时阈值 (与 workflow-audit.md 对齐)
DEADLINE_HOURS: dict[RiskLevel, int] = {
    RiskLevel.HIGH: 72,     # 72 小时未整改触发超时
    RiskLevel.MEDIUM: 120,  # 5 个工作日 (24h×5)
    RiskLevel.LOW: 168,     # 7 天 (低危不阻断，仅记录)
}


def compute_deadline(level: RiskLevel) -> str:
    """根据风险等级计算工单截止时间."""
    hours = DEADLINE_HOURS.get(level, 72)
    deadline = datetime.now(timezone.utc) + timedelta(hours=hours)
    return deadline.isoformat()


def is_overdue(deadline_iso: str) -> bool:
    """判断工单是否已超时."""
    if not deadline_iso:
        return False
    try:
        deadline = datetime.fromisoformat(deadline_iso)
        return datetime.now(timezone.utc) > deadline
    except (ValueError, TypeError):
        return False


def overdue_duration_hours(deadline_iso: str) -> float:
    """返回超时时长（小时），未超时返回 0."""
    if not deadline_iso or not is_overdue(deadline_iso):
        return 0.0
    deadline = datetime.fromisoformat(deadline_iso)
    delta = datetime.now(timezone.utc) - deadline
    return delta.total_seconds() / 3600
