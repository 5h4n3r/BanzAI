#!/usr/bin/env python3
"""
BanzAI Supabase MCP Server Entry Point
Command-line entry point for the Supabase MCP server
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp.supabase_mcp import SupabaseMCPServer

if __name__ == "__main__":
    server = SupabaseMCPServer()
    server.run() 