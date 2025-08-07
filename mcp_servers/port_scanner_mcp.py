#!/usr/bin/env python3
"""
BanzAI Port Scanner MCP Server Entry Point
Command-line entry point for the port scanner MCP server
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp.port_scanner_mcp import PortScannerMCPServer

if __name__ == "__main__":
    server = PortScannerMCPServer()
    server.run() 