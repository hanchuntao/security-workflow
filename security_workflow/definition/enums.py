"""统一枚举定义 — 与 agents/commands 规范 100% 对齐."""

from enum import Enum


class RiskLevel(str, Enum):
    """漏洞风险等级 — 与 security-scanner.md 三级体系一一对应."""

    HIGH = "高危"       # 阻断级：禁止自动修复、拦截上线
    MEDIUM = "中危"     # 整改级：半自动确认、限期整改
    LOW = "低危"        # 优化级：全自动静默修复、不阻塞


class TicketStatus(str, Enum):
    """工单流转状态 — 与 workflow-audit.md 工单状态流转标准对齐."""

    # 高危流程: 待人工整改 → 双人评审 → 整改复核 → 闭环归档
    HIGH_PENDING_FIX = "待人工整改"
    HIGH_PENDING_REVIEW = "双人评审中"
    HIGH_PENDING_RECHECK = "整改复核中"
    HIGH_CLOSED = "闭环归档"

    # 中危流程: 待修复确认 → 人工整改 → 单人复核 → 限期闭环
    MEDIUM_PENDING_CONFIRM = "待修复确认"
    MEDIUM_IN_FIX = "人工整改中"
    MEDIUM_IN_REVIEW = "单人复核中"
    MEDIUM_CLOSED = "限期闭环"

    # 低危流程: 待自动修复 → 自动整改 → 自动闭环归档
    LOW_PENDING_AUTO = "待自动修复"
    LOW_AUTO_FIXING = "自动整改中"
    LOW_AUTO_CLOSED = "自动闭环归档"

    # 通用
    REJECTED = "已驳回"
    OVERDUE = "已超时"


# 状态流转映射 — 当前状态可以流转到哪些目标状态
TRANSITION_MAP: dict[TicketStatus, list[TicketStatus]] = {
    # 高危
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
    # 中危
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
    # 低危
    TicketStatus.LOW_PENDING_AUTO: [
        TicketStatus.LOW_AUTO_FIXING,
    ],
    TicketStatus.LOW_AUTO_FIXING: [
        TicketStatus.LOW_AUTO_CLOSED,
    ],
    # 驳回后可重新提交
    TicketStatus.REJECTED: [
        TicketStatus.HIGH_PENDING_FIX,
        TicketStatus.MEDIUM_PENDING_CONFIRM,
    ],
    # 超时后只能升级
    TicketStatus.OVERDUE: [
        TicketStatus.HIGH_PENDING_FIX,
        TicketStatus.MEDIUM_PENDING_CONFIRM,
    ],
}


def initial_status(level: RiskLevel) -> TicketStatus:
    """根据风险等级返回工单初始状态."""
    mapping = {
        RiskLevel.HIGH: TicketStatus.HIGH_PENDING_FIX,
        RiskLevel.MEDIUM: TicketStatus.MEDIUM_PENDING_CONFIRM,
        RiskLevel.LOW: TicketStatus.LOW_PENDING_AUTO,
    }
    return mapping[level]


def is_closed_status(status: TicketStatus) -> bool:
    """判断工单是否已闭环."""
    return status in (
        TicketStatus.HIGH_CLOSED,
        TicketStatus.MEDIUM_CLOSED,
        TicketStatus.LOW_AUTO_CLOSED,
    )


def is_blocking_status(status: TicketStatus) -> bool:
    """判断工单状态是否阻断上线."""
    return status not in (
        TicketStatus.HIGH_CLOSED,
        TicketStatus.MEDIUM_CLOSED,
        TicketStatus.LOW_AUTO_CLOSED,
        TicketStatus.LOW_AUTO_FIXING,
    )
