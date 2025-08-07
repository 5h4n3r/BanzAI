#!/usr/bin/env python3
"""
BanzAI Subdomain MCP Server Entry Point
Command-line entry point for the subdomain MCP server
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp.subdomain_mcp import SubdomainMCPServer

if __name__ == "__main__":
    server = SubdomainMCPServer()
    server.run() 