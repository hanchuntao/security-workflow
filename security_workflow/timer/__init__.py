"""Timeout clock — Medium-risk deadline tracking, High-risk overdue escalation."""

from .clock import compute_deadline, is_overdue, overdue_duration_hours

__all__ = ["compute_deadline", "is_overdue", "overdue_duration_hours"]
