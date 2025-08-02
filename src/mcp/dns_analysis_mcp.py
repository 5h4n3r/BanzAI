#!/usr/bin/env python3
"""
BanzAI DNS Analysis MCP Server
MCP adapter for DNS analysis and enumeration functionality
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from .base_mcp_server import BaseMCPServer

class DNSAnalysisMCPServer(BaseMCPServer):
    """MCP server for DNS analysis functionality"""
    
    def __init__(self, http_url: str = "http://localhost:8002"):
        super().__init__("banzai-dns-analysis", "1.0.0")
        self.http_url = http_url
        # Defer session creation until needed
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=600)  # 10 minute timeout
    
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
                "name": "dns_analyze",
                "description": "Perform comprehensive DNS analysis on a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to analyze"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "get_nameservers",
                "description": "Get nameservers for a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to get nameservers for"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "zone_transfer",
                "description": "Attempt zone transfer for a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to attempt zone transfer for"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "enumerate_dns_records",
                "description": "Enumerate DNS records for a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to enumerate records for"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "attempt_zone_transfer",
                "description": "Attempt zone transfer for a domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to attempt zone transfer for"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "detect_takeover_candidates",
                "description": "Detect potential subdomain takeover candidates",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to check for takeover candidates"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "reverse_dns_lookup",
                "description": "Perform reverse DNS lookup for an IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {
                            "type": "string",
                            "description": "IP address to perform reverse DNS lookup for"
                        }
                    },
                    "required": ["ip_address"]
                }
            },
            {
                "name": "store_results",
                "description": "Store DNS analysis results in the database",
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
                            "description": "DNS analysis results data"
                        }
                    },
                    "required": ["project_name", "target", "scan_data"]
                }
            }
        ]
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool by name with the given arguments"""
        await self._ensure_session()
        
        if name == "dns_analyze":
            return await self._dns_analyze(arguments)
        elif name == "get_nameservers":
            return await self._get_nameservers(arguments)
        elif name == "enumerate_dns_records":
            return await self._enumerate_dns_records(arguments)
        elif name == "attempt_zone_transfer":
            return await self._attempt_zone_transfer(arguments)
        elif name == "detect_takeover_candidates":
            return await self._detect_takeover_candidates(arguments)
        elif name == "reverse_dns_lookup":
            return await self._reverse_dns_lookup(arguments)
        elif name == "store_results":
            return await self._store_results(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    
    async def _dns_analyze(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive DNS analysis"""
        domain = arguments.get("domain")
        if not domain:
            raise ValueError("Domain is required")
        
        try:
            data = {"domain": domain}
            async with self.session.post(f"{self.http_url}/analyze", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"DNS analysis failed: {error_text}")
                
                result = await response.json()
                return self._format_dns_analysis_result(result, domain)
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    async def _get_nameservers(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get nameservers for a domain"""
        domain = arguments.get("domain")
        if not domain:
            raise ValueError("Domain is required")
        
        try:
            data = {"domain": domain}
            async with self.session.post(f"{self.http_url}/nameservers", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Nameserver lookup failed: {error_text}")
                
                result = await response.json()
                nameservers = result.get("nameservers", [])
                
                return {
                    "success": True,
                    "domain": domain,
                    "nameservers": nameservers,
                    "count": len(nameservers),
                    "summary": f"Found {len(nameservers)} nameservers for {domain}"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    async def _enumerate_dns_records(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate DNS records for a domain"""
        domain = arguments.get("domain")
        if not domain:
            raise ValueError("Domain is required")
        
        try:
            data = {"domain": domain}
            async with self.session.post(f"{self.http_url}/records", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"DNS record enumeration failed: {error_text}")
                
                result = await response.json()
                records = result.get("records", {})
                
                # Count records by type
                record_counts = {record_type: len(records_list) for record_type, records_list in records.items()}
                total_records = sum(record_counts.values())
                
                return {
                    "success": True,
                    "domain": domain,
                    "total_records": total_records,
                    "record_counts": record_counts,
                    "records": records,
                    "summary": f"Found {total_records} DNS records for {domain} across {len(record_counts)} record types"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    async def _attempt_zone_transfer(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt zone transfer from a domain's nameservers"""
        domain = arguments.get("domain")
        if not domain:
            raise ValueError("Domain is required")
        
        try:
            data = {"domain": domain}
            async with self.session.post(f"{self.http_url}/zone_transfer", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Zone transfer attempt failed: {error_text}")
                
                result = await response.json()
                zone_transfer = result.get("zone_transfer", {})
                
                if zone_transfer.get("success"):
                    records = zone_transfer.get("records", [])
                    return {
                        "success": True,
                        "domain": domain,
                        "nameserver": result.get("nameserver"),
                        "zone_transfer_successful": True,
                        "records_found": len(records),
                        "records": records,
                        "summary": f"Zone transfer successful for {domain} - found {len(records)} records"
                    }
                else:
                    return {
                        "success": True,
                        "domain": domain,
                        "nameserver": result.get("nameserver"),
                        "zone_transfer_successful": False,
                        "error": zone_transfer.get("error", "Unknown error"),
                        "summary": f"Zone transfer failed for {domain}: {zone_transfer.get('error', 'Unknown error')}"
                    }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    async def _detect_takeover_candidates(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential subdomain takeover candidates"""
        domain = arguments.get("domain")
        if not domain:
            raise ValueError("Domain is required")
        
        try:
            data = {"domain": domain}
            async with self.session.post(f"{self.http_url}/takeover", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Takeover detection failed: {error_text}")
                
                result = await response.json()
                candidates = result.get("takeover_candidates", [])
                
                return {
                    "success": True,
                    "domain": domain,
                    "candidates_found": len(candidates),
                    "candidates": candidates,
                    "summary": f"Found {len(candidates)} potential takeover candidates for {domain}"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    async def _reverse_dns_lookup(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Perform reverse DNS lookup on an IP address"""
        ip = arguments.get("ip_address")
        if not ip:
            raise ValueError("IP address is required")
        
        try:
            # Use the dedicated reverse DNS endpoint
            data = {"domain": ip}
            async with self.session.post(f"{self.http_url}/reverse_dns", json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Reverse DNS lookup failed: {error_text}")
                
                result = await response.json()
                ptr_records = result.get("ptr_records", [])
                
                return {
                    "success": True,
                    "ip": ip,
                    "reverse_domain": result.get("reverse_domain"),
                    "ptr_records": ptr_records,
                    "hostnames": [record.get("value") for record in ptr_records],
                    "count": len(ptr_records),
                    "summary": f"Reverse DNS lookup for {ip} found {len(ptr_records)} hostnames",
                    "debug_info": result.get("debug_info", {})
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "ip": ip
            }
    
    async def _store_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Store DNS analysis results in the database"""
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
            "scan_type": "dns_analysis",
            "scan_data": scan_data
        }
        
        try:
            async with self.session.post(f"{supabase_url}/store_scan_results", json=store_data) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "success": True,
                        "message": f"DNS analysis results for {target} stored in project '{project_name}'",
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
    
    def _format_dns_analysis_result(self, result: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Format comprehensive DNS analysis result"""
        nameservers = result.get("nameservers", [])
        zone_transfer = result.get("zone_transfer", {})
        records = result.get("records", {})
        takeover_candidates = result.get("takeover_candidates", [])
        
        # Count records by type
        record_counts = {record_type: len(records_list) for record_type, records_list in records.items()}
        total_records = sum(record_counts.values())
        
        # Create summary
        summary_parts = []
        summary_parts.append(f"Found {len(nameservers)} nameservers")
        summary_parts.append(f"{total_records} DNS records across {len(record_counts)} types")
        
        if zone_transfer.get("success"):
            summary_parts.append("Zone transfer successful")
        else:
            summary_parts.append("Zone transfer failed")
        
        if takeover_candidates:
            summary_parts.append(f"{len(takeover_candidates)} takeover candidates")
        
        summary = f"DNS analysis for {domain}: {', '.join(summary_parts)}"
        
        return {
            "success": True,
            "domain": domain,
            "nameservers": nameservers,
            "nameserver_count": len(nameservers),
            "zone_transfer": {
                "successful": zone_transfer.get("success", False),
                "records_found": len(zone_transfer.get("records", [])),
                "error": zone_transfer.get("error")
            },
            "dns_records": {
                "total": total_records,
                "by_type": record_counts,
                "records": records
            },
            "takeover_candidates": {
                "count": len(takeover_candidates),
                "candidates": takeover_candidates
            },
            "summary": summary
        }

async def main():
    """Main entry point for the MCP server"""
    server = DNSAnalysisMCPServer()
    async with server:
        await server.run()

if __name__ == "__main__":
    asyncio.run(main()) 