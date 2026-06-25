#!/usr/bin/env python3
"""MCP Server — security-workflow-mcp-engine 入口.

暴露 6 个 MCP tools:
  - create_ticket      创建安全评审工单
  - transition_ticket  工单状态流转
  - reject_ticket      驳回工单
  - check_deploy_gate  上线卡点校验
  - list_tickets       工单列表
  - get_audit_trail    审计轨迹查询

协议: JSON-RPC 2.0 over stdio, 遵循 MCP (Model Context Protocol).
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .core import create_ticket, transition_ticket, reject_ticket, check_deploy_gate, generate_review_report
from .persistence import load_ticket, load_all_tickets, read_audit_trail

# ── JSON-RPC dispatcher ────────────────────────────────────────────────────────

TOOLS: dict[str, dict[str, Any]] = {
    "create_ticket": {
        "description": "创建安全评审工单。根据扫描结果自动初始化工单状态与截止时间。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string", "description": "工单唯一编号"},
                "risk_level": {"type": "string", "enum": ["高危", "中危", "低危"]},
                "findings": {"type": "array", "description": "漏洞扫描结果列表"},
                "branch": {"type": "string", "description": "关联分支"},
                "project": {"type": "string", "description": "关联项目"},
            },
            "required": ["ticket_id", "risk_level", "findings"],
        },
    },
    "transition_ticket": {
        "description": "工单状态流转。按分级流程将工单从当前状态迁移至下一合法状态。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "target_status": {"type": "string", "description": "目标状态"},
                "operator": {"type": "string", "default": "system"},
                "detail": {"type": "string", "default": ""},
            },
            "required": ["ticket_id", "target_status"],
        },
    },
    "reject_ticket": {
        "description": "驳回工单 — 必须填写驳回原因与整改指引。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "reason": {"type": "string", "description": "驳回原因（必填）"},
                "operator": {"type": "string"},
            },
            "required": ["ticket_id", "reason", "operator"],
        },
    },
    "check_deploy_gate": {
        "description": "上线安全卡点校验。检查是否存在未闭环高危/超时中危工单，返回是否允许上线。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "default": ""},
                "branch": {"type": "string", "default": ""},
            },
        },
    },
    "list_tickets": {
        "description": "列出所有安全评审工单及其当前状态。",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    "get_audit_trail": {
        "description": "查询审计轨迹 — 按工单或全量查询操作记录。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string", "description": "可选，按工单过滤"},
                "limit": {"type": "integer", "default": 100},
            },
        },
    },
    "generate_report": {
        "description": "生成安全评审报告并落盘。自动汇总工单、漏洞、上线卡点数据，输出 Markdown 报告。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "default": "", "description": "项目名"},
                "branch": {"type": "string", "default": "", "description": "分支名"},
                "scan_mode": {"type": "string", "default": "全量扫描", "description": "扫描模式"},
                "report_type": {"type": "string", "enum": ["review", "deploy"], "default": "review"},
            },
        },
    },
}


def handle_request(req: dict[str, Any]) -> dict[str, Any]:
    """处理单个 JSON-RPC 请求."""
    method = req.get("method", "")
    req_id = req.get("id")

    # ── initialize ──────────────────────────────────────────────────────
    if method == "initialize":
        return _jsonrpc_result(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "security-workflow-mcp-engine",
                "version": "1.0.1",
            },
        })

    # ── notifications ───────────────────────────────────────────────────
    if method == "notifications/initialized":
        return {}  # No response for notifications

    # ── tools/list ──────────────────────────────────────────────────────
    if method == "tools/list":
        tool_list = [
            {"name": name, "description": info["description"], "inputSchema": info["inputSchema"]}
            for name, info in TOOLS.items()
        ]
        return _jsonrpc_result(req_id, {"tools": tool_list})

    # ── tools/call ──────────────────────────────────────────────────────
    if method == "tools/call":
        tool_name = req.get("params", {}).get("name", "")
        arguments = req.get("params", {}).get("arguments", {})

        if tool_name not in TOOLS:
            return _jsonrpc_error(req_id, -32601, f"Unknown tool: {tool_name}")

        try:
            result = _dispatch_tool(tool_name, arguments)
            return _jsonrpc_result(req_id, {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2, default=str)}]
            })
        except Exception as e:
            return _jsonrpc_error(req_id, -32000, str(e), traceback.format_exc())

    # ── unknown ─────────────────────────────────────────────────────────
    return _jsonrpc_error(req_id, -32601, f"Unknown method: {method}")


def _dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """路由到具体工具实现."""
    if name == "create_ticket":
        ticket = create_ticket(
            ticket_id=args["ticket_id"],
            risk_level_str=args["risk_level"],
            findings_data=args["findings"],
            branch=args.get("branch", ""),
            project=args.get("project", ""),
        )
        return {"success": True, "ticket": ticket.to_dict()}

    elif name == "transition_ticket":
        ticket = transition_ticket(
            ticket_id=args["ticket_id"],
            target_status_str=args["target_status"],
            operator=args.get("operator", "system"),
            detail=args.get("detail", ""),
        )
        return {"success": True, "ticket": ticket.to_dict()}

    elif name == "reject_ticket":
        ticket = reject_ticket(
            ticket_id=args["ticket_id"],
            reason=args["reason"],
            operator=args["operator"],
        )
        return {"success": True, "ticket": ticket.to_dict()}

    elif name == "check_deploy_gate":
        return check_deploy_gate(
            project=args.get("project", ""),
            branch=args.get("branch", ""),
        )

    elif name == "list_tickets":
        tickets = load_all_tickets()
        return {
            "count": len(tickets),
            "tickets": [t.to_dict() for t in tickets],
        }

    elif name == "get_audit_trail":
        entries = read_audit_trail(
            ticket_id=args.get("ticket_id"),
            limit=args.get("limit", 100),
        )
        return {"count": len(entries), "entries": entries}

    elif name == "generate_report":
        result = generate_review_report(
            project=args.get("project", ""),
            branch=args.get("branch", ""),
            scan_mode=args.get("scan_mode", "全量扫描"),
            report_type=args.get("report_type", "review"),
        )
        return {"success": True, "report": result}

    raise ValueError(f"Unknown tool: {name}")


# ── JSON-RPC helpers ───────────────────────────────────────────────────────────

def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def _jsonrpc_error(req_id: Any, code: int, message: str, data: str = "") -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": err,
    }


# ── Main entry ─────────────────────────────────────────────────────────────────

def main() -> None:
    """MCP server 主循环 — stdin → process → stdout."""
    # 启动时刷新超时状态
    try:
        from .core import check_and_mark_overdue
        check_and_mark_overdue()
    except Exception:
        pass  # 静默处理 — 首次运行可能无数据

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            if response:  # 通知类请求无响应
                sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            sys.stdout.write(
                json.dumps(
                    _jsonrpc_error(None, -32700, "Parse error", line),
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stdout.flush()
        except Exception:
            tb = traceback.format_exc()
            sys.stderr.write(f"[security-workflow-engine] {tb}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
