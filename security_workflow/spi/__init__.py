"""服务提供者接口 — 告警通知、审计写入.

内置 FileNotificationProvider（写入统一数据目录），可扩展对接企业 IM/邮件/Webhook.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..definition.enums import RiskLevel
from ..definition.constants import DEFAULT_DATA_DIR

# 数据目录（与 persistence 共用）
DATA_ROOT = Path(os.environ.get("SECURITY_WORKFLOW_DATA", DEFAULT_DATA_DIR))
_notify_lock = threading.Lock()


def _notify_log() -> Path:
    """通知记录文件."""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    return DATA_ROOT / "notifications.jsonl"


def _emit(level: str, ticket_id: str, detail: str, extra: dict | None = None) -> None:
    """写入结构化通知记录."""
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
    """高危漏洞告警 — 写入通知日志 + 控制台输出.

    生产对接指引: 在此函数内调用企业 IM Webhook (企业微信/飞书/钉钉) 或 SMTP 邮件.
    """
    _emit("HIGH", ticket_id, detail, {"action_required": "双人安全评审 + 禁止上线"})
    print(f"[NOTIFY:HIGH] {ticket_id} — {detail}")


def notify_overdue(ticket_id: str, level: RiskLevel, hours: float) -> None:
    """超时告警 — 写入通知日志 + 控制台输出."""
    _emit(
        "OVERDUE",
        ticket_id,
        f"{level.value}工单超时 {hours:.1f}h",
        {"risk_level": level.value, "overdue_hours": round(hours, 1)},
    )
    print(f"[NOTIFY:OVERDUE] {ticket_id} — {level.value}超时 {hours:.1f}h，请立即处理")


def notify_deploy_blocked(reason: str) -> None:
    """上线阻断通知 — 写入通知日志 + 控制台输出."""
    _emit("DEPLOY_BLOCKED", "", reason, {})
    print(f"[NOTIFY:DEPLOY_BLOCKED] {reason}")


def read_notifications(limit: int = 50, level: str | None = None) -> list[dict]:
    """读取通知历史，可按级别过滤."""
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
