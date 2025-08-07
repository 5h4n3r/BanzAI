#!/usr/bin/env python3
"""
BanzAI Subdomain MCP Server
MCP adapter for the subdomain enumeration functionality
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from .base_mcp_server import BaseMCPServer

class SubdomainMCPServer(BaseMCPServer):
    """MCP server for subdomain enumeration functionality"""
    
    def __init__(self, http_url: str = "http://localhost:8001"):
        super().__init__("banzai-subdomain", "1.0.0")
        self.http_url = http_url
        # Defer session creation until needed
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=60)  # 1 minute timeout
    
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
                "name": "enumerate_subdomains",
                "description": "Enumerate subdomains for a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to enumerate subdomains for"
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Number of threads to use",
                            "default": 10
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds",
                            "default": 30
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "store_results",
                "description": "Store subdomain enumeration results in the database",
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
                            "description": "Subdomain enumeration results data"
                        }
                    },
                    "required": ["project_name", "target", "scan_data"]
                }
            }
        ]
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with given arguments"""
        await self._ensure_session()
        
        if name == "enumerate_subdomains":
            return await self._enumerate_subdomains(arguments)
        elif name == "store_results":
            return await self._store_results(arguments)
        else:
            return {"error": f"Unknown tool: {name}"}
    
    async def _enumerate_subdomains(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate subdomains for a domain"""
        try:
            domain = arguments.get("domain")
            if not domain:
                return {"error": "Domain is required"}
            
            # Call the HTTP API
            async with self.session.post(
                f"{self.http_url}/enumerate",
                json={
                    "domain": domain,
                    "threads": arguments.get("threads", 10),
                    "timeout": arguments.get("timeout", 30)
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "domain": domain,
                        "subdomains": result.get("subdomains", []),
                        "dns_records": result.get("dns_records", {}),
                        "summary": f"Found {len(result.get('subdomains', []))} subdomains"
                    }
                else:
                    error_text = await response.text()
                    return {"error": f"HTTP {response.status}: {error_text}"}
                    
        except Exception as e:
            return {"error": f"Subdomain enumeration failed: {str(e)}"} 

    async def _store_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Store subdomain enumeration results in the database"""
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
            "scan_type": "subdomain_enum",
            "scan_data": scan_data
        }
        
        try:
            async with self.session.post(f"{supabase_url}/store_scan_results", json=store_data) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "message": f"Subdomain enumeration results for {target} stored in project '{project_name}'",
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