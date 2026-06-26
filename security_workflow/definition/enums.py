"""Unified enum definitions — 100% aligned with agents/commands spec."""

from enum import Enum


class RiskLevel(str, Enum):
    """Vulnerability risk level — 1:1 aligned with security-scanner.md 3-tier system.

    NOTE: Enum string values are preserved in Chinese for backward compatibility
    with existing ticket data. DO NOT change these values without a data migration.
    """

    HIGH = "高危"       # Blocking: forbid auto-fix, block deployment
    MEDIUM = "中危"     # Remediation: semi-auto confirmed, deadline tracked
    LOW = "低危"        # Optimization: full-auto silent fix, non-blocking


class TicketStatus(str, Enum):
    """Ticket workflow status — aligned with workflow-audit.md state transition standards.

    NOTE: Enum string values are preserved in Chinese for backward compatibility.
    """

    # High-risk flow: Pending manual fix → Dual review → Re-review → Closed
    HIGH_PENDING_FIX = "待人工整改"
    HIGH_PENDING_REVIEW = "双人评审中"
    HIGH_PENDING_RECHECK = "整改复核中"
    HIGH_CLOSED = "闭环归档"

    # Medium-risk flow: Pending fix confirmation → Manual fix → Single review → Closed
    MEDIUM_PENDING_CONFIRM = "待修复确认"
    MEDIUM_IN_FIX = "人工整改中"
    MEDIUM_IN_REVIEW = "单人复核中"
    MEDIUM_CLOSED = "限期闭环"

    # Low-risk flow: Pending auto-fix → Auto fixing → Auto closed
    LOW_PENDING_AUTO = "待自动修复"
    LOW_AUTO_FIXING = "自动整改中"
    LOW_AUTO_CLOSED = "自动闭环归档"

    # Universal
    REJECTED = "已驳回"
    OVERDUE = "已超时"


# State transition map — which target states are reachable from each current state
TRANSITION_MAP: dict[TicketStatus, list[TicketStatus]] = {
    # High
    TicketStatus.HIGH_PENDING_FIX: [
        TicketStatus.HIGH_PENDING_REVIEW,
        TicketStatus.REJECTED,
        TicketStatus.OVERDUE,
    ],
    TicketStatus.HIGH_PENDING_REVIEW: [
        TicketStatus.HIGH_PENDING_RECHECK,
        TicketStatus.REJECTED,
    ],
    TicketStatus.HIGH_PENDING_RECHECK: [
        TicketStatus.HIGH_CLOSED,
        TicketStatus.REJECTED,
    ],
    # Medium
    TicketStatus.MEDIUM_PENDING_CONFIRM: [
        TicketStatus.MEDIUM_IN_FIX,
        TicketStatus.REJECTED,
        TicketStatus.OVERDUE,
    ],
    TicketStatus.MEDIUM_IN_FIX: [
        TicketStatus.MEDIUM_IN_REVIEW,
        TicketStatus.REJECTED,
    ],
    TicketStatus.MEDIUM_IN_REVIEW: [
        TicketStatus.MEDIUM_CLOSED,
        TicketStatus.REJECTED,
    ],
    # Low
    TicketStatus.LOW_PENDING_AUTO: [
        TicketStatus.LOW_AUTO_FIXING,
    ],
    TicketStatus.LOW_AUTO_FIXING: [
        TicketStatus.LOW_AUTO_CLOSED,
    ],
    # Rejected can be resubmitted
    TicketStatus.REJECTED: [
        TicketStatus.HIGH_PENDING_FIX,
        TicketStatus.MEDIUM_PENDING_CONFIRM,
    ],
    # Overdue can only be escalated
    TicketStatus.OVERDUE: [
        TicketStatus.HIGH_PENDING_FIX,
        TicketStatus.MEDIUM_PENDING_CONFIRM,
    ],
}


def initial_status(level: RiskLevel) -> TicketStatus:
    """Return the initial ticket status for a given risk level."""
    mapping = {
        RiskLevel.HIGH: TicketStatus.HIGH_PENDING_FIX,
        RiskLevel.MEDIUM: TicketStatus.MEDIUM_PENDING_CONFIRM,
        RiskLevel.LOW: TicketStatus.LOW_PENDING_AUTO,
    }
    return mapping[level]


def is_closed_status(status: TicketStatus) -> bool:
    """Check whether a ticket status represents a closed state."""
    return status in (
        TicketStatus.HIGH_CLOSED,
        TicketStatus.MEDIUM_CLOSED,
        TicketStatus.LOW_AUTO_CLOSED,
    )


def is_blocking_status(status: TicketStatus) -> bool:
    """Check whether a ticket status blocks deployment."""
    return status not in (
        TicketStatus.HIGH_CLOSED,
        TicketStatus.MEDIUM_CLOSED,
        TicketStatus.LOW_AUTO_CLOSED,
        TicketStatus.LOW_AUTO_FIXING,
    )
