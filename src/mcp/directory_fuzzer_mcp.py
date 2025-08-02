#!/usr/bin/env python3
"""
BanzAI Directory Fuzzer MCP Server
MCP adapter for the directory fuzzing functionality
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from .base_mcp_server import BaseMCPServer

class DirectoryFuzzerMCPServer(BaseMCPServer):
    """MCP server for directory fuzzing functionality"""
    
    def __init__(self, http_url: str = "http://localhost:8004"):
        super().__init__("banzai-directory-fuzzer", "1.0.0")
        self.http_url = http_url
        # Defer session creation until needed
        self.session = None
        # Increase timeout for large wordlists (10 minutes)
        self.timeout = aiohttp.ClientTimeout(total=600)
    
    async def _ensure_session(self):
        """Ensure HTTP session is created"""
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def __aenter__(self):
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_tools(self) -> List[Dict[str, Any]]:
        """Return the list of tools this server provides"""
        return [
            {
                "name": "directory_fuzz",
                "description": "Perform directory fuzzing on a target with auto-calibration to filter false positives",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to fuzz (e.g., http://example.com)"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist to use for fuzzing",
                            "default": "common"
                        },
                        "extensions": {
                            "type": "string",
                            "description": "File extensions to test (comma-separated)",
                            "default": "php,html,txt"
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Number of threads to use",
                            "default": 10
                        },
                        "auto_calibration": {
                            "type": "boolean",
                            "description": "Enable auto-calibration to filter false positives from generic responses",
                            "default": True
                        },
                        "filter_size": {
                            "type": "string",
                            "description": "Filter by response size (e.g., '>100,<1000')",
                            "default": None
                        },
                        "filter_words": {
                            "type": "string",
                            "description": "Filter by word count (e.g., '>10,<100')",
                            "default": None
                        },
                        "filter_lines": {
                            "type": "string",
                            "description": "Filter by line count (e.g., '>5,<50')",
                            "default": None
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "store_results",
                "description": "Store directory fuzzing results in the database",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Project name to store results in"
                        },
                        "target": {
                            "type": "string",
                            "description": "Target that was scanned"
                        },
                        "scan_data": {
                            "type": "object",
                            "description": "Directory fuzzing results data"
                        }
                    },
                    "required": ["project_name", "target", "scan_data"]
                }
            }
        ]
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with given arguments"""
        await self._ensure_session()
        
        if name == "directory_fuzz":
            return await self._directory_fuzz(arguments)
        elif name == "store_results":
            return await self._store_results(arguments)
        else:
            return {"error": f"Unknown tool: {name}"}
    
    async def _directory_fuzz(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform directory fuzzing on a target"""
        try:
            target = arguments.get("target")
            if not target:
                return {"error": "Target is required"}
            
            # Convert extensions string to list for HTTP API
            extensions_str = arguments.get("extensions", "php,html,txt")
            extensions_list = [ext.strip() for ext in extensions_str.split(",")]
            
            # Call the HTTP API
            async with self.session.post(
                f"{self.http_url}/fuzz",
                json={
                    "target": target,
                    "wordlist": arguments.get("wordlist", "common"),
                    "extensions": extensions_list,
                    "threads": arguments.get("threads", 10),
                    "auto_calibration": arguments.get("auto_calibration", True),
                    "filter_size": arguments.get("filter_size"),
                    "filter_words": arguments.get("filter_words"),
                    "filter_lines": arguments.get("filter_lines")
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "target": target,
                        "discovered_paths": result.get("discovered_paths", []),
                        "total_requests": result.get("total_requests", 0),
                        "successful_requests": result.get("successful_requests", 0),
                        "summary": f"Found {len(result.get('discovered_paths', []))} paths with auto-calibration filtering"
                    }
                else:
                    error_text = await response.text()
                    return {"error": f"HTTP {response.status}: {error_text}"}
                    
        except Exception as e:
            return {"error": f"Directory fuzzing failed: {str(e)}"} 

    async def _store_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Store directory fuzzing results in the database"""
        project_name = arguments.get("project_name")
        target = arguments.get("target")
        scan_data = arguments.get("scan_data")
        
        if not all([project_name, target, scan_data]):
            return {"error": "project_name, target, and scan_data are required"}
        
        # Store results via Supabase MCP wrapper
        supabase_url = "http://localhost:8003"
        store_data = {
            "project_name": project_name,
            "target": target,
            "scan_type": "dir_fuzz",
            "scan_data": scan_data
        }
        
        try:
            async with self.session.post(f"{supabase_url}/store_scan_results", json=store_data) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "message": f"Directory fuzzing results for {target} stored in project '{project_name}'",
                        "result": result
                    }
                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "error": f"Failed to store results: {error_text}"
                    }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to store results: {str(e)}"
            } 