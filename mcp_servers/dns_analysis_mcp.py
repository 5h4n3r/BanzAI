#!/usr/bin/env python3
"""
BanzAI DNS Analysis MCP Server Entry Point
Command-line entry point for the DNS analysis MCP server
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp.dns_analysis_mcp import DNSAnalysisMCPServer

if __name__ == "__main__":
    server = DNSAnalysisMCPServer()
    server.run() 