#!/usr/bin/env python3
"""
BanzAI Directory Fuzzer MCP Server Entry Point
Command-line entry point for the directory fuzzer MCP server
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp.directory_fuzzer_mcp import DirectoryFuzzerMCPServer

if __name__ == "__main__":
    server = DirectoryFuzzerMCPServer()
    server.run() 