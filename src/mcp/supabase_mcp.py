#!/usr/bin/env python3
"""
BanzAI Supabase MCP Server
MCP server for focused Supabase database operations
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, Any, List, Optional
from .base_mcp_server import BaseMCPServer

class SupabaseMCPServer(BaseMCPServer):
    """MCP server for focused Supabase database operations"""

    def __init__(self):
        super().__init__("banzai-supabase", "1.0.0")
        self.supabase_url = "http://localhost:8003"
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=600)  # 10 minute timeout
        
        # Simple in-memory cache with TTL
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes

    async def get_tools(self) -> List[Dict[str, Any]]:
        """Get available Supabase tools"""
        return [
            {
                "name": "store_scan_results",
                "description": "Store scan results in the database",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Project name"
                        },
                        "target": {
                            "type": "string", 
                            "description": "Target that was scanned"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["port_scan", "subdomain_enum", "dns_analysis", "dir_fuzz"],
                            "description": "Type of scan performed"
                        },
                        "scan_data": {
                            "type": "object",
                            "description": "Scan results data"
                        }
                    },
                    "required": ["project_name", "target", "scan_type", "scan_data"]
                }
            },
            {
                "name": "get_latest_scan",
                "description": "Get the latest scan results for a target",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to get scan results for"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["port_scan", "subdomain_enum", "dns_analysis", "dir_fuzz"],
                            "description": "Type of scan to retrieve"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "get_scan_history",
                "description": "Get scan history for a target or project",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to get history for"
                        },
                        "project_name": {
                            "type": "string",
                            "description": "Project to get history for"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["port_scan", "subdomain_enum", "dns_analysis", "dir_fuzz"],
                            "description": "Type of scan to filter by"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results",
                            "default": 10
                        }
                    }
                }
            },
            {
                "name": "get_asset_summary",
                "description": "Get summary of assets and findings for a project",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Project name"
                        },
                        "target": {
                            "type": "string",
                            "description": "Specific target within project"
                        }
                    }
                }
            },

        ]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Supabase tool"""
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
            
        try:
            if name == "store_scan_results":
                return await self._store_scan_results(arguments)
            elif name == "get_latest_scan":
                return await self._get_latest_scan(arguments)
            elif name == "get_scan_history":
                return await self._get_scan_history(arguments)
            elif name == "get_asset_summary":
                return await self._get_asset_summary(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Database operation timed out",
                "timeout": True
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _store_scan_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Store scan results in database using the new HTTP API"""
        project_name = arguments["project_name"]
        target = arguments["target"]
        scan_type = arguments["scan_type"] 
        scan_data = arguments["scan_data"]

        try:
            # Use the new HTTP endpoint instead of raw SQL
            async with self.session.post(
                f"{self.supabase_url}/store_scan_results",
                json={
                    "project_name": project_name,
                    "target": target,
                    "scan_type": scan_type,
                    "scan_data": scan_data
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    # Clear cache for this target
                    self._clear_cache(target)
                    return result
                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "error": f"HTTP {response.status}: {error_text}"
                    }
                    
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Request timed out after 30 seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Request failed: {str(e)}"
            }

    async def _get_latest_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get latest scan results for a target"""
        target = arguments["target"]
        scan_type = arguments.get("scan_type")
        
        # Check cache first
        cache_key = f"latest_{target}_{scan_type or 'all'}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            # First find the project for this target
            project_response = await self.session.get(
                f"{self.supabase_url}/projects",
                params={"target_domain": target}
            )
            
            if project_response.status != 200:
                return {
                    "success": False,
                    "target": target,
                    "error": "Failed to find project for target"
                }
            
            project_data = await project_response.json()
            if not project_data.get("projects"):
                return {
                    "success": False,
                    "target": target,
                    "error": "No project found for target"
                }
            
            project_id = project_data["projects"][0]["id"]
            
            # Get scans for this project
            scan_params = {"project_id": project_id, "limit": 1}
            if scan_type:
                scan_params["scan_type"] = scan_type
                
            scan_response = await self.session.get(
                f"{self.supabase_url}/scans",
                params=scan_params
            )
            
            if scan_response.status != 200:
                return {
                    "success": False,
                    "target": target,
                    "error": "Failed to retrieve scan data"
                }
            
            scan_data = await scan_response.json()
            if scan_data.get("scans"):
                latest_scan = scan_data["scans"][0]
                response = {
                    "success": True,
                    "target": target,
                    "scan_type": scan_type,
                    "latest_scan": {
                        "scan_type": latest_scan["scan_type"],
                        "scan_data": latest_scan["results"],
                        "created_at": latest_scan["completed_at"]
                    }
                }
                
                # Cache the result
                self._set_cached(cache_key, response)
                return response
            else:
                return {
                    "success": False,
                    "target": target,
                    "error": "No scan results found"
                }
                
        except Exception as e:
            return {
                "success": False,
                "target": target,
                "error": f"Database query failed: {str(e)}"
            }

    async def _get_scan_history(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan history"""
        target = arguments.get("target")
        project_name = arguments.get("project_name")
        scan_type = arguments.get("scan_type")
        limit = arguments.get("limit", 10)

        try:
            # Find project(s) based on criteria
            project_params = {}
            if target:
                project_params["target_domain"] = target
            if project_name:
                project_params["name"] = project_name
                
            project_response = await self.session.get(
                f"{self.supabase_url}/projects",
                params=project_params
            )
            
            if project_response.status != 200:
                return {
                    "success": False,
                    "error": "Failed to find projects"
                }
            
            project_data = await project_response.json()
            if not project_data.get("projects"):
                return {
                    "success": True,
                    "history": [],
                    "count": 0
                }
            
            # Get scans for all matching projects
            all_scans = []
            for project in project_data["projects"]:
                scan_params = {"project_id": project["id"], "limit": limit}
                if scan_type:
                    scan_params["scan_type"] = scan_type
                    
                scan_response = await self.session.get(
                    f"{self.supabase_url}/scans",
                    params=scan_params
                )
                
                if scan_response.status == 200:
                    scan_data = await scan_response.json()
                    for scan in scan_data.get("scans", []):
                        all_scans.append({
                            "project_name": project["name"],
                            "target": project["target_domain"],
                            "scan_type": scan["scan_type"],
                            "created_at": scan["completed_at"]
                        })
            
            # Sort by created_at and limit results
            all_scans.sort(key=lambda x: x["created_at"], reverse=True)
            all_scans = all_scans[:limit]
            
            return {
                "success": True,
                "history": all_scans,
                "count": len(all_scans)
            }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to retrieve scan history: {str(e)}"
            }

    async def _get_asset_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get asset summary for project"""
        project_name = arguments.get("project_name")
        target = arguments.get("target")

        try:
            # Find project(s) based on criteria
            project_params = {}
            if project_name:
                project_params["name"] = project_name
            if target:
                project_params["target_domain"] = target
                
            project_response = await self.session.get(
                f"{self.supabase_url}/projects",
                params=project_params
            )
            
            if project_response.status != 200:
                return {
                    "success": False,
                    "error": "Failed to find projects"
                }
            
            project_data = await project_response.json()
            if not project_data.get("projects"):
                return {
                    "success": True,
                    "project_name": project_name,
                    "target": target,
                    "summary": {
                        "total_projects": 0,
                        "total_assets": 0,
                        "total_scans": 0,
                        "total_findings": 0,
                        "scan_types": [],
                        "last_scan": None
                    }
                }
            
            projects = project_data["projects"]
            total_projects = len(projects)
            
            # Collect data from all matching projects
            all_assets = []
            all_scans = []
            all_findings = []
            scan_types = set()
            last_scan_time = None
            
            for project in projects:
                project_id = project["id"]
                
                # Get assets for this project
                assets_response = await self.session.get(
                    f"{self.supabase_url}/assets",
                    params={"project_id": project_id}
                )
                
                if assets_response.status == 200:
                    assets_data = await assets_response.json()
                    all_assets.extend(assets_data.get("assets", []))
                
                # Get scans for this project
                scans_response = await self.session.get(
                    f"{self.supabase_url}/scans",
                    params={"project_id": project_id, "limit": 100}
                )
                
                if scans_response.status == 200:
                    scans_data = await scans_response.json()
                    project_scans = scans_data.get("scans", [])
                    all_scans.extend(project_scans)
                    
                    # Track scan types and last scan time
                    for scan in project_scans:
                        scan_types.add(scan.get("scan_type", "unknown"))
                        scan_time = scan.get("completed_at")
                        if scan_time and (last_scan_time is None or scan_time > last_scan_time):
                            last_scan_time = scan_time
                
                # Get findings for this project
                findings_response = await self.session.get(
                    f"{self.supabase_url}/findings",
                    params={"project_id": project_id}
                )
                
                if findings_response.status == 200:
                    findings_data = await findings_response.json()
                    all_findings.extend(findings_data.get("findings", []))
            
            # Generate summary
            summary = {
                "total_projects": total_projects,
                "total_assets": len(all_assets),
                "total_scans": len(all_scans),
                "total_findings": len(all_findings),
                "scan_types": list(scan_types),
                "last_scan": last_scan_time,
                "asset_types": {},
                "finding_categories": {}
            }
            
            # Count asset types
            for asset in all_assets:
                asset_type = asset.get("asset_type", "unknown")
                summary["asset_types"][asset_type] = summary["asset_types"].get(asset_type, 0) + 1
            
            # Count finding categories
            for finding in all_findings:
                category = finding.get("category", "unknown")
                summary["finding_categories"][category] = summary["finding_categories"].get(category, 0) + 1
            
            return {
                "success": True,
                "project_name": project_name,
                "target": target,
                "summary": summary
            }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to generate asset summary: {str(e)}"
            }



    async def _store_findings(self, project_name: str, target: str, finding_type: str, findings: List[Any]) -> bool:
        """Store individual findings"""
        try:
            # This method is deprecated since _execute_query is broken
            # Findings are now stored via the Supabase API server directly
            return True
            
        except Exception as e:
            return False

    async def _execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Execute SQL query via Supabase MCP wrapper with timeout"""
        try:
            # This method is deprecated since the /query endpoint is broken
            # All database operations should use direct table operations instead
            return None
                    
        except Exception as e:
            return None

    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if not expired"""
        if key in self.cache:
            timestamp, data = self.cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return data
            else:
                # Remove expired entry
                del self.cache[key]
        return None

    def _set_cached(self, key: str, data: Dict[str, Any]) -> None:
        """Cache result with timestamp"""
        self.cache[key] = (time.time(), data)

    def _clear_cache(self, target: str) -> None:
        """Clear cache entries for a target"""
        keys_to_remove = [key for key in self.cache.keys() if target in key]
        for key in keys_to_remove:
            del self.cache[key]

    async def __aenter__(self):
        """Async context manager entry"""
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            self.session = None

if __name__ == "__main__":
    server = SupabaseMCPServer()
    server.run() 