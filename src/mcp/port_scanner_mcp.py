#!/usr/bin/env python3
"""
BanzAI Port Scanner MCP Server
MCP adapter for the port scanning functionality
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from .base_mcp_server import BaseMCPServer

class PortScannerMCPServer(BaseMCPServer):
    """MCP server for port scanning functionality"""
    
    def __init__(self, http_url: str = "http://localhost:8000"):
        super().__init__("banzai-port-scanner", "1.0.0")
        self.http_url = http_url
        # Defer session creation until needed
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=600)  # 10 minute timeout
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self):
        """Ensure HTTP session is created"""
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def get_tools(self) -> List[Dict[str, Any]]:
        """Return the list of tools this server provides"""
        return [
            {
                "name": "port_scan",
                "description": "Perform a comprehensive port scan on a target",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or hostname to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port range to scan (e.g., '1-1000', '80,443,8080')",
                            "default": "1-1000"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["tcp", "udp", "both"],
                            "description": "Type of scan to perform",
                            "default": "tcp"
                        },
                        "timing": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 5,
                            "description": "Timing template (0-5, higher = faster)",
                            "default": 3
                        },
                        "service_detection": {
                            "type": "boolean",
                            "description": "Enable service and version detection",
                            "default": True
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "syn_scan",
                "description": "Perform a SYN scan on a target (requires privileges)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or hostname to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port range to scan (e.g., '1-1000', '80,443,8080')",
                            "default": "1-1000"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "quick_port_scan",
                "description": "Perform a quick scan of common ports",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or hostname to scan"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "web_port_scan",
                "description": "Scan for web services (HTTP/HTTPS)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or hostname to scan"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "database_port_scan",
                "description": "Scan for database services",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or hostname to scan"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "store_results",
                "description": "Store port scan results in the database",
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
                            "description": "Port scan results data"
                        }
                    },
                    "required": ["project_name", "target", "scan_data"]
                }
            }
        ]
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool by name with the given arguments"""
        await self._ensure_session()
        
        if name == "port_scan":
            return await self._port_scan(arguments)
        elif name == "syn_scan":
            return await self._syn_scan(arguments)
        elif name == "quick_port_scan":
            return await self._quick_port_scan(arguments)
        elif name == "web_port_scan":
            return await self._web_port_scan(arguments)
        elif name == "database_port_scan":
            return await self._database_port_scan(arguments)
        elif name == "store_results":
            return await self._store_results(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    
    async def _port_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a comprehensive port scan"""
        target = arguments.get("target")
        if not target:
            raise ValueError("Target is required")
        
        data = {
            "target": target,
            "ports": arguments.get("ports", "1-65535"),
            "scan_type": arguments.get("scan_type", "tcp"),
            "timing": arguments.get("timing", 3),
            "service_detection": arguments.get("service_detection", True)
        }
        
        async with self.session.post(f"{self.http_url}/scan", json=data) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Port scan failed: {error_text}")
            
            result = await response.json()
            return {
                "success": True,
                "target": target,
                "scan_type": "comprehensive",
                "open_ports_count": len(result.get("open_ports", [])),
                "scan_duration": result.get("scan_duration", 0),
                "open_ports": result.get("open_ports", []),
                "summary": f"Found {len(result.get('open_ports', []))} open ports on {target}"
            }
    
    async def _syn_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a SYN scan"""
        target = arguments.get("target")
        if not target:
            raise ValueError("Target is required")
        
        ports = arguments.get("ports", "1-65535")
        async with self.session.post(f"{self.http_url}/scan/syn?target={target}&ports={ports}") as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"SYN scan failed: {error_text}")
            
            result = await response.json()
            return {
                "success": True,
                "target": target,
                "scan_type": "syn",
                "open_ports_count": len(result.get("open_ports", [])),
                "scan_duration": result.get("scan_duration", 0),
                "open_ports": result.get("open_ports", []),
                "summary": f"SYN scan found {len(result.get('open_ports', []))} open ports on {target}"
            }
    
    async def _quick_port_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a quick port scan"""
        target = arguments.get("target")
        if not target:
            raise ValueError("Target is required")
        
        async with self.session.post(f"{self.http_url}/scan/quick?target={target}") as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Quick port scan failed: {error_text}")
            
            result = await response.json()
            return {
                "success": True,
                "target": target,
                "scan_type": "quick",
                "open_ports_count": len(result.get("open_ports", [])),
                "scan_duration": result.get("scan_duration", 0),
                "open_ports": result.get("open_ports", []),
                "summary": f"Quick scan found {len(result.get('open_ports', []))} open ports on {target}"
            }
    
    async def _web_port_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for web services"""
        target = arguments.get("target")
        if not target:
            raise ValueError("Target is required")
        
        async with self.session.post(f"{self.http_url}/scan/web?target={target}") as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Web port scan failed: {error_text}")
            
            result = await response.json()
            return {
                "success": True,
                "target": target,
                "scan_type": "web",
                "open_ports_count": len(result.get("open_ports", [])),
                "scan_duration": result.get("scan_duration", 0),
                "open_ports": result.get("open_ports", []),
                "summary": f"Web scan found {len(result.get('open_ports', []))} web services on {target}"
            }
    
    async def _database_port_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for database services"""
        target = arguments.get("target")
        if not target:
            raise ValueError("Target is required")
        
        async with self.session.post(f"{self.http_url}/scan/database?target={target}") as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Database port scan failed: {error_text}")
            
            result = await response.json()
            return {
                "success": True,
                "target": target,
                "scan_type": "database",
                "open_ports_count": len(result.get("open_ports", [])),
                "scan_duration": result.get("scan_duration", 0),
                "open_ports": result.get("open_ports", []),
                "summary": f"Database scan found {len(result.get('open_ports', []))} database services on {target}"
            }

    async def _store_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Store port scan results in the database"""
        project_name = arguments.get("project_name")
        target = arguments.get("target")
        scan_data = arguments.get("scan_data")
        
        if not all([project_name, target, scan_data]):
            raise ValueError("project_name, target, and scan_data are required")
        
        # Store results via Supabase MCP wrapper
        supabase_url = "http://localhost:8003"
        store_data = {
            "project_name": project_name,
            "target": target,
            "scan_type": "port_scan",
            "scan_data": scan_data
        }
        
        try:
            async with self.session.post(f"{supabase_url}/store_scan_results", json=store_data) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "message": f"Port scan results for {target} stored in project '{project_name}'",
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

async def main():
    """Main entry point for the MCP server"""
    server = PortScannerMCPServer()
    async with server:
        await server.run()

if __name__ == "__main__":
    asyncio.run(main()) 