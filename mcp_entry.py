#!/usr/bin/env python3
"""MCP engine entry point — self-locating, zero-config.

Works regardless of working directory or PYTHONPATH.
Uses __file__ to find the plugin root and the security_workflow package.
"""
import sys
from pathlib import Path

_PLUGIN_ROOT = Path(__file__).resolve().parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from security_workflow.mcp_server import main

if __name__ == "__main__":
    main()
