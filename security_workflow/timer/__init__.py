"""超时时钟 — 中危限期整改、高危超时升级."""

from .clock import compute_deadline, is_overdue, overdue_duration_hours

__all__ = ["compute_deadline", "is_overdue", "overdue_duration_hours"]
