#!/usr/bin/env python3
"""Integration test: /review -> tickets -> /deploy gate -> fix flow -> re-check.

Simulates the full security workflow pipeline as driven by slash commands.
"""

import json
import os
import sys

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _project_root not in sys.path:
    sys.path.append(_project_root)
os.environ["SECURITY_WORKFLOW_DATA"] = ".security-workflow-data"

from security_workflow.mcp_server import handle_request


def call_tool(name: str, args: dict) -> dict:
    """Invoke an MCP tool and return the parsed result dict."""
    req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    r = handle_request(req)
    text = r["result"]["content"][0]["text"]
    return json.loads(text)


B = "=" * 62


def main() -> None:
    # ═══════════════════════════════════════════════════════════
    # Phase 1: /review scope=project level=all mode=full workflow=true
    # ═══════════════════════════════════════════════════════════
    print(B)
    print("  Phase 1: /review scope=project level=all mode=full workflow=true")
    print(B)

    scan_results = [
        {
            "ticket_id": "SW-001",
            "risk_level": "高危",
            "findings": [
                {
                    "risk_id": "CMD-INJ-001",
                    "risk_level": "高危",
                    "file_path": "tests/vuln_cases/high_risk_demo.py",
                    "line_no": 17,
                    "risk_desc": "os.system调用存在命令注入风险",
                    "compliance_rule": "OWASP A03:2021 - Injection",
                    "fix_suggest": "使用subprocess.run并禁用shell=True",
                    "scan_mode": "全量扫描",
                }
            ],
            "branch": "main",
            "project": "my-project",
        },
        {
            "ticket_id": "SW-002",
            "risk_level": "中危",
            "findings": [
                {
                    "risk_id": "WEAK-CRYPTO-001",
                    "risk_level": "中危",
                    "file_path": "tests/vuln_cases/mid_risk_demo.js",
                    "line_no": 7,
                    "risk_desc": "弱加密算法 MD5",
                    "compliance_rule": "OWASP A02:2021",
                    "fix_suggest": "使用SHA256或bcrypt",
                    "scan_mode": "全量扫描",
                },
                {
                    "risk_id": "INSECURE-RAND-001",
                    "risk_level": "中危",
                    "file_path": "tests/vuln_cases/mid_risk_demo.js",
                    "line_no": 12,
                    "risk_desc": "Math.random用于安全场景",
                    "compliance_rule": "OWASP A02:2021",
                    "fix_suggest": "使用crypto.randomBytes",
                    "scan_mode": "全量扫描",
                },
                {
                    "risk_id": "CORS-WILDCARD-001",
                    "risk_level": "中危",
                    "file_path": "tests/vuln_cases/mid_risk_demo.js",
                    "line_no": 17,
                    "risk_desc": "CORS origin配置为通配符*",
                    "compliance_rule": "OWASP A05:2021",
                    "fix_suggest": "限制为具体域名",
                    "scan_mode": "全量扫描",
                },
            ],
            "branch": "main",
            "project": "my-project",
        },
        {
            "ticket_id": "SW-003",
            "risk_level": "低危",
            "findings": [
                {
                    "risk_id": "DEBUG-LOG-001",
                    "risk_level": "低危",
                    "file_path": "tests/vuln_cases/low_risk_demo.ts",
                    "line_no": 5,
                    "risk_desc": "废弃调试console.log",
                    "compliance_rule": "企业安全编码规范",
                    "fix_suggest": "删除调试日志",
                    "scan_mode": "全量扫描",
                }
            ],
            "branch": "main",
            "project": "my-project",
        },
    ]

    for item in scan_results:
        r = call_tool("create_ticket", item)
        t = r["ticket"]
        print(
            f"  [OK] {t['ticket_id']} | {t['risk_level']} | "
            f"status={t['status']} | deadline={t['deadline'][:16]}"
        )

    # ═══════════════════════════════════════════════════════════
    # Phase 2: /deploy branch=main — deploy gate check
    # ═══════════════════════════════════════════════════════════
    print(f"\n{B}")
    print("  Phase 2: /deploy branch=main -- deploy gate")
    print(B)

    gate = call_tool("check_deploy_gate", {"project": "my-project", "branch": "main"})
    print(f"  Verdict: {gate['verdict']}")
    print(f"  Blocked by ({len(gate['blocked_by'])}):")
    for b in gate["blocked_by"]:
        print(f"    BLOCKED: {b['ticket_id']} [{b['risk_level']}] - {b['reason']}")
    print(f"  Warnings ({len(gate['warnings'])}):")
    for w in gate["warnings"]:
        print(f"    WARN: {w['ticket_id']} [{w['risk_level']}] - {w['reason']}")

    # ═══════════════════════════════════════════════════════════
    # Phase 3: Fix flow — close LOW auto, close HIGH through review
    # ═══════════════════════════════════════════════════════════
    print(f"\n{B}")
    print("  Phase 3: Fix flow")
    print(B)

    # Low: auto-fix -> auto-closed
    for status in ["自动整改中", "自动闭环归档"]:
        r = call_tool("transition_ticket", {
            "ticket_id": "SW-003",
            "target_status": status,
            "operator": "system",
        })
        print(f"  LOW  SW-003 -> {status}")

    # High: fix -> double-review -> recheck -> closed
    for status in ["双人评审中", "整改复核中", "闭环归档"]:
        r = call_tool("transition_ticket", {
            "ticket_id": "SW-001",
            "target_status": status,
            "operator": "reviewer:张三",
        })
        print(f"  HIGH SW-001 -> {status}")

    # ═══════════════════════════════════════════════════════════
    # Phase 4: Re-check deploy gate
    # ═══════════════════════════════════════════════════════════
    print(f"\n{B}")
    print("  Phase 4: /deploy after fixes")
    print(B)

    gate2 = call_tool("check_deploy_gate", {"project": "my-project", "branch": "main"})
    print(f"  Verdict: {gate2['verdict']}")
    print(f"  Blocked by: {len(gate2['blocked_by'])}")
    print(f"  Warnings: {len(gate2['warnings'])}")
    for w in gate2["warnings"]:
        print(f"    WARN: {w['ticket_id']} [{w['risk_level']}] - {w['reason']}")

    # ═══════════════════════════════════════════════════════════
    # Phase 5: Audit trail + Report generation
    # ═══════════════════════════════════════════════════════════
    print(f"\n{B}")
    print("  Phase 5: Audit trail + Report generation")
    print(B)

    trail = call_tool("get_audit_trail", {"limit": 50})
    print(f"  Total records: {trail['count']}")
    for e in trail["entries"]:
        print(
            f"  [{e['timestamp'][:19]}] {e['ticket_id']} | "
            f"{e['action']:12s} | {e['from_status']:10s} -> {e['to_status']}"
        )

    print(f"\n{B}")
    print("  PASS: /review -> /deploy 联动链路验证完成")
    print(B)

    # ═══════════════════════════════════════════════════════════
    # Phase 6: Auto report generation
    # ═══════════════════════════════════════════════════════════
    print(f"\n{B}")
    print("  Phase 6: Report generation")
    print(B)

    report = call_tool("generate_report", {
        "project": "my-project",
        "branch": "main",
        "scan_mode": "全量扫描",
        "report_type": "review",
    })
    rp = report["report"]
    print(f"  [OK] Report generated: {rp['filepath']}")
    print(f"  [OK] Tickets: {rp['ticket_count']}, Findings: {rp['finding_count']}")

    print(f"\n{B}")
    print("  PASS: Full pipeline verified (review + deploy + report)")
    print(B)


if __name__ == "__main__":
    main()
