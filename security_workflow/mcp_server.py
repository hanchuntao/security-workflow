#!/usr/bin/env python3
"""MCP Server — security-workflow-mcp-engine entry point.

Exposes 7 MCP tools:
  - create_ticket      Create security review ticket
  - transition_ticket  Transition ticket state
  - reject_ticket      Reject ticket
  - check_deploy_gate  Deployment gate check
  - list_tickets       List all tickets
  - get_audit_trail    Query audit trail
  - generate_report    Generate & persist review/deploy report

Protocol: JSON-RPC 2.0 over stdio, conforming to MCP (Model Context Protocol).
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .core import create_ticket, transition_ticket, reject_ticket, check_deploy_gate, generate_review_report
from .persistence import load_ticket, load_all_tickets, read_audit_trail

# ── JSON-RPC dispatcher ───────────────────────────────────────────────────

TOOLS: dict[str, dict[str, Any]] = {
    "create_ticket": {
        "description": "Create a security review ticket. Auto-initializes ticket status and deadline based on scan results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string", "description": "Unique ticket ID"},
                "risk_level": {"type": "string", "enum": ["高危", "中危", "低危"], "description": "Risk level (High/Medium/Low — enum values are Chinese for backward compat)"},
                "findings": {"type": "array", "description": "Vulnerability scan results"},
                "branch": {"type": "string", "description": "Associated branch"},
                "project": {"type": "string", "description": "Associated project"},
            },
            "required": ["ticket_id", "risk_level", "findings"],
        },
    },
    "transition_ticket": {
        "description": "Transition a ticket to the next valid state in its workflow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "target_status": {"type": "string", "description": "Target status"},
                "operator": {"type": "string", "default": "system"},
                "detail": {"type": "string", "default": ""},
            },
            "required": ["ticket_id", "target_status"],
        },
    },
    "reject_ticket": {
        "description": "Reject a ticket — rejection reason and remediation guidance are required.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "reason": {"type": "string", "description": "Rejection reason (required)"},
                "operator": {"type": "string"},
            },
            "required": ["ticket_id", "reason", "operator"],
        },
    },
    "check_deploy_gate": {
        "description": "Deployment security gate check. Verifies if there are unclosed High-risk or overdue Medium-risk tickets. Returns whether deployment is allowed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "default": ""},
                "branch": {"type": "string", "default": ""},
            },
        },
    },
    "list_tickets": {
        "description": "List all security review tickets and their current states.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    "get_audit_trail": {
        "description": "Query audit trail — view operation records by ticket or globally.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string", "description": "Optional — filter by ticket"},
                "limit": {"type": "integer", "default": 100},
            },
        },
    },
    "generate_report": {
        "description": "Generate and persist a security review or deployment report. Supports English (default) and Chinese (set lang=zh or SECURITY_WORKFLOW_LANG=zh for 等保2.0 compliance).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "default": "", "description": "Project name"},
                "branch": {"type": "string", "default": "", "description": "Branch name"},
                "scan_mode": {"type": "string", "default": "full", "description": "Scan mode"},
                "report_type": {"type": "string", "enum": ["review", "deploy"], "default": "review"},
                "lang": {"type": "string", "enum": ["en", "zh"], "default": "en", "description": "Report language (en/zh). Also controllable via SECURITY_WORKFLOW_LANG env var."},
            },
        },
    },
}


def handle_request(req: dict[str, Any]) -> dict[str, Any]:
    """Handle a single JSON-RPC request."""
    method = req.get("method", "")
    req_id = req.get("id")

    # ── initialize ─────────────────────────────────────────────────
    if method == "initialize":
        return _jsonrpc_result(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "security-workflow-mcp-engine",
                "version": "1.0.1",
            },
        })

    # ── notifications ──────────────────────────────────────────────
    if method == "notifications/initialized":
        return {}  # No response for notifications

    # ── tools/list ─────────────────────────────────────────────────
    if method == "tools/list":
        tool_list = [
            {"name": name, "description": info["description"], "inputSchema": info["inputSchema"]}
            for name, info in TOOLS.items()
        ]
        return _jsonrpc_result(req_id, {"tools": tool_list})

    # ── tools/call ─────────────────────────────────────────────────
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
            sys.stderr.write(f"[security-workflow-engine] Tool dispatch error ({tool_name}): {type(e).__name__}: {e}\n")
            sys.stderr.flush()
            return _jsonrpc_error(req_id, -32000, f"Internal error: {type(e).__name__}", "")

    # ── unknown ────────────────────────────────────────────────────
    return _jsonrpc_error(req_id, -32601, f"Unknown method: {method}")


def _dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Route to the concrete tool implementation."""
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
            scan_mode=args.get("scan_mode", "full"),
            report_type=args.get("report_type", "review"),
            lang=args.get("lang"),
        )
        return {"success": True, "report": result}

    raise ValueError(f"Unknown tool: {name}")


# ── JSON-RPC helpers ──────────────────────────────────────────────────────

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


# ── Main entry ────────────────────────────────────────────────────────────

def main() -> None:
    """MCP server main loop — stdin → process → stdout."""
    # Refresh overdue status on startup
    try:
        from .core import check_and_mark_overdue
        check_and_mark_overdue()
    except Exception:
        pass  # Silent — may have no data on first run

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
            if os.environ.get("SECURITY_WORKFLOW_DEBUG", "").lower() in ("1", "true"):
                tb = traceback.format_exc()
                sys.stderr.write(f"[security-workflow-engine] {tb}\n")
            else:
                sys.stderr.write("[security-workflow-engine] Error processing request\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
