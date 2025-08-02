#!/usr/bin/env python3
"""
BanzAI CLI - AI-Powered Penetration Testing Tool
Main command-line interface for orchestrating reconnaissance and scanning
"""

import asyncio
import argparse
import json
import sys
import os
from typing import Optional, List, Dict, Any, Set
from datetime import datetime
from uuid import UUID
import aiohttp
import re

from database.models import (
    ProjectCreate, AssetCreate, ScanCreate, FindingCreate,
    ServiceCreate, WebEndpointCreate, ScanRequest
)
from database.banzai_db import BanzAIDatabase

class BanzAICLI:
    """Main CLI interface for BanzAI"""
    
    def __init__(self):
        self.port_scanner_url = "http://banzai_port_scanner_mcp:8000"
        self.subdomain_server_url = "http://banzai_subdomain_mcp:8001"
        self.dns_server_url = "http://banzai_dns_analysis_mcp:8002"
        self.directory_fuzzer_url = "http://banzai_directory_fuzzer_mcp:8004"
        self.supabase_url = "http://banzai_supabase_mcp:8003"
        
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, target))
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target)) and '.' in target
    
    def _validate_target(self, target: str) -> bool:
        """Validate if target is a valid domain or IP"""
        return self._is_ip(target) or self._is_domain(target)
    
    def _parse_target_file(self, file_path: str) -> List[str]:
        """Parse a text file containing targets (one per line)"""
        targets = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        targets.append(line)
        except FileNotFoundError:
            raise FileNotFoundError(f"Target file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading target file: {e}")
        
        return targets
    
    def _deduplicate_targets(self, targets: List[str]) -> List[str]:
        """Remove duplicates and validate targets"""
        seen = set()
        unique_targets = []
        
        for target in targets:
            target = target.strip().lower()
            if target and target not in seen and self._validate_target(target):
                seen.add(target)
                unique_targets.append(target)
            elif target and not self._validate_target(target):
                print(f"⚠️  Warning: Invalid target '{target}' - skipping")
        
        return unique_targets
    
    async def _make_request(self, url: str, method: str = "GET", data: Dict = None) -> Dict:
        """Make HTTP request to MCP servers"""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        async with self.session.request(method, url, json=data) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Request failed: {error_text}")
            return await response.json()
    
    async def create_project(self, name: str, description: str = None, target_domain: str = None) -> Dict:
        """Create a new project"""
        async with BanzAIDatabase(self.supabase_url) as db:
            project = ProjectCreate(
                name=name,
                description=description,
                target_domain=target_domain
            )
            result = await db.create_project(project)
            return result.model_dump()
    
    async def list_projects(self) -> List[Dict]:
        """List all projects"""
        async with BanzAIDatabase(self.supabase_url) as db:
            projects = await db.list_projects()
            return [project.model_dump() for project in projects]
    
    async def discover_assets(self, target: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive asset discovery for a single target"""
        print(f"🔍 Starting comprehensive asset discovery for {target}...")
        
        discovered_assets = {
            "target": target,
            "subdomains": set(),
            "ips": set(),
            "domains": set(),
            "discovery_methods": {}
        }
        
        # Subdomain enumeration (if target is a domain)
        if self._is_domain(target):
            try:
                print(f"  🌐 Running subdomain enumeration...")
                subdomain_result = await self.subdomain_enumeration(target, project_id)
                subdomains = subdomain_result.get("subdomains", [])
                discovered_assets["subdomains"].update(subdomains)
                discovered_assets["discovery_methods"]["subdomain_enum"] = len(subdomains)
                print(f"    ✅ Found {len(subdomains)} subdomains")
            except Exception as e:
                print(f"    ⚠️  Subdomain enumeration failed: {e}")
        
        # DNS analysis
        try:
            print(f"  🔍 Running DNS analysis...")
            dns_result = await self.dns_analysis(target, project_id)
            
            # Extract IPs from DNS results
            if "a_records" in dns_result:
                ips = [record["ip"] for record in dns_result["a_records"]]
                discovered_assets["ips"].update(ips)
                discovered_assets["discovery_methods"]["dns_a"] = len(ips)
            
            if "aaaa_records" in dns_result:
                ips = [record["ip"] for record in dns_result["aaaa_records"]]
                discovered_assets["ips"].update(ips)
                discovered_assets["discovery_methods"]["dns_aaaa"] = len(ips)
            
            # Extract domains from DNS results
            if "mx_records" in dns_result:
                domains = [record["exchange"] for record in dns_result["mx_records"]]
                discovered_assets["domains"].update(domains)
                discovered_assets["discovery_methods"]["dns_mx"] = len(domains)
            
            if "ns_records" in dns_result:
                domains = [record["nameserver"] for record in dns_result["ns_records"]]
                discovered_assets["domains"].update(domains)
                discovered_assets["discovery_methods"]["dns_ns"] = len(domains)
            
            print(f"    ✅ DNS analysis completed")
        except Exception as e:
            print(f"    ⚠️  DNS analysis failed: {e}")
        
        # Reverse DNS lookup (if target is an IP)
        if self._is_ip(target):
            try:
                print(f"  🔄 Running reverse DNS lookup...")
                # This would require a reverse DNS service
                # For now, we'll skip this
                print(f"    ⚠️  Reverse DNS not implemented yet")
            except Exception as e:
                print(f"    ⚠️  Reverse DNS failed: {e}")
        
        # Convert sets to lists for JSON serialization
        result = {
            "target": discovered_assets["target"],
            "subdomains": list(discovered_assets["subdomains"]),
            "ips": list(discovered_assets["ips"]),
            "domains": list(discovered_assets["domains"]),
            "discovery_methods": discovered_assets["discovery_methods"],
            "total_assets": len(discovered_assets["subdomains"]) + len(discovered_assets["ips"]) + len(discovered_assets["domains"])
        }
        
        print(f"  📊 Discovery Summary:")
        print(f"    • Subdomains: {len(discovered_assets['subdomains'])}")
        print(f"    • IPs: {len(discovered_assets['ips'])}")
        print(f"    • Domains: {len(discovered_assets['domains'])}")
        print(f"    • Total: {result['total_assets']}")
        
        return result
    
    async def port_scan_parallel(self, targets: List[str], project_id: Optional[str] = None, 
                                scan_type: str = "quick", max_concurrent: int = 5) -> Dict[str, Any]:
        """Perform port scanning on multiple targets in parallel"""
        print(f"🔍 Starting parallel port scanning of {len(targets)} targets...")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {}
        
        async def scan_single_target(target: str) -> tuple:
            async with semaphore:
                try:
                    print(f"  🔍 Scanning {target}...")
                    scan_result = await self.port_scan(target, project_id, scan_type=scan_type)
                    return target, scan_result
                except Exception as e:
                    error_msg = str(e)
                    # Check if it's a DNS resolution failure
                    if "Name or service not known" in error_msg or "Failed to resolve domain" in error_msg:
                        return target, {"error": "DNS resolution failed", "type": "dns_failure"}
                    else:
                        print(f"    ⚠️  Failed to scan {target}: {error_msg}")
                        return target, {"error": error_msg, "type": "scan_failure"}
        
        # Create tasks for all targets
        tasks = [scan_single_target(target) for target in targets]
        
        # Execute all scans in parallel
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for target, result in scan_results:
            if isinstance(result, Exception):
                results[target] = {"error": str(result), "type": "scan_failure"}
            else:
                results[target] = result
        
        # Summary with better categorization
        successful_scans = sum(1 for r in results.values() if "error" not in r)
        dns_failures = sum(1 for r in results.values() if r.get("type") == "dns_failure")
        other_failures = sum(1 for r in results.values() if r.get("type") == "scan_failure")
        
        print(f"📊 Parallel Scan Summary:")
        print(f"  • Successful: {successful_scans}")
        if dns_failures > 0:
            print(f"  • DNS failures: {dns_failures}")
        if other_failures > 0:
            print(f"  • Other failures: {other_failures}")
        print(f"  • Total: {len(results)}")
        
        return {
            "scan_results": results,
            "summary": {
                "total_targets": len(targets),
                "successful_scans": successful_scans,
                "dns_failures": dns_failures,
                "other_failures": other_failures,
                "failed_scans": dns_failures + other_failures
            }
        }
    
    async def port_scan(self, target: str, project_id: Optional[str] = None, 
                       ports: str = "1-65535", scan_type: str = "quick") -> Dict:
        """Perform port scanning"""
        print(f"🔍 Starting port scan of {target}...")
        
        # Determine scan endpoint based on type
        if scan_type == "quick":
            endpoint = f"{self.port_scanner_url}/scan/quick?target={target}"
            data = None
        elif scan_type == "syn":
            endpoint = f"{self.port_scanner_url}/scan/syn?target={target}&ports={ports}"
            data = None
        elif scan_type == "web":
            endpoint = f"{self.port_scanner_url}/scan/web?target={target}"
            data = None
        elif scan_type == "database":
            endpoint = f"{self.port_scanner_url}/scan/database?target={target}"
            data = None
        else:
            endpoint = f"{self.port_scanner_url}/scan"
            data = {
                "target": target,
                "ports": ports,
                "scan_type": "tcp",
                "timing": 3,
                "service_detection": True
            }
        
        result = await self._make_request(endpoint, "POST", data)
        
        # Store results in database if project_id provided
        if project_id and self.session:
            try:
                async with BanzAIDatabase(self.supabase_url) as db:
                    # Ensure project_id is a UUID
                    project_uuid = UUID(project_id) if isinstance(project_id, str) else project_id
                    
                    # Create asset if it doesn't exist
                    asset = AssetCreate(
                        project_id=project_uuid,
                        type="ip" if self._is_ip(target) else "domain",
                        value=target,
                        status="scanned"
                    )
                    asset_result = await db.create_asset(asset)
                    
                    # Create scan record
                    scan = ScanCreate(
                        project_id=project_uuid,
                        asset_id=asset_result.id,
                        scan_type="port_scan",
                        status="completed",
                        results=result
                    )
                    await db.create_scan(scan)
                    
                    # Store discovered services
                    for port_info in result.get("open_ports", []):
                        service = ServiceCreate(
                            asset_id=asset_result.id,
                            port=port_info["port"],
                            protocol=port_info["protocol"],
                            service_name=port_info["service"],
                            banner=port_info.get("banner")
                        )
                        await db.create_service(service)
                        
            except Exception as e:
                print(f"⚠️  Warning: Failed to store results in database: {e}")
        
        return result
    
    async def subdomain_enumeration(self, domain: str, project_id: Optional[str] = None) -> Dict:
        """Perform subdomain enumeration"""
        print(f"🌐 Starting subdomain enumeration for {domain}...")
        
        result = await self._make_request(
            f"{self.subdomain_server_url}/enumerate",
            "POST",
            {"domain": domain}
        )
        
        # Store results in database if project_id provided
        if project_id and self.session:
            try:
                async with BanzAIDatabase(self.supabase_url) as db:
                    # Ensure project_id is a UUID
                    project_uuid = UUID(project_id) if isinstance(project_id, str) else project_id
                    
                    for subdomain in result.get("subdomains", []):
                        asset = AssetCreate(
                            project_id=project_uuid,
                            type="subdomain",
                            value=subdomain,
                            status="discovered"
                        )
                        await db.create_asset(asset)
                        
            except Exception as e:
                print(f"⚠️  Warning: Failed to store results in database: {e}")
        
        return result
    
    async def dns_analysis(self, domain: str, project_id: Optional[str] = None) -> Dict:
        """Perform DNS analysis"""
        print(f"🔍 Starting DNS analysis for {domain}...")
        
        result = await self._make_request(
            f"{self.dns_server_url}/analyze",
            "POST",
            {"domain": domain}
        )
        
        return result
    
    async def directory_fuzzing(self, target: str, project_id: Optional[str] = None,
                               wordlist: str = "common", auto_calibration: bool = True,
                               filter_size: str = None, filter_words: str = None,
                               filter_lines: str = None) -> Dict:
        """Perform directory fuzzing with auto-calibration to filter false positives"""
        print(f"📁 Starting directory fuzzing for {target}...")
        if auto_calibration:
            print(f"🔍 Auto-calibration enabled to filter false positives")
        
        data = {
            "target": target,
            "wordlist": wordlist,
            "threads": 15,  # More conservative than 50
            "timeout": 10,
            "rate_limit": 30,  # Add rate limiting
            "auto_calibration": auto_calibration
        }
        
        # Add optional filters
        if filter_size:
            data["filter_size"] = filter_size
        if filter_words:
            data["filter_words"] = filter_words
        if filter_lines:
            data["filter_lines"] = filter_lines
        
        result = await self._make_request(
            f"{self.directory_fuzzer_url}/fuzz",
            "POST",
            data
        )
        
        # Store results in database if project_id provided
        if project_id and self.session:
            try:
                async with BanzAIDatabase(self.supabase_url) as db:
                    # Ensure project_id is a UUID
                    project_uuid = UUID(project_id) if isinstance(project_id, str) else project_id
                    
                    # Find or create asset
                    assets = await db.list_assets(project_id=project_uuid)
                    asset = None
                    for a in assets:
                        if a.value in target or target in a.value:
                            asset = a
                            break
                    
                    if not asset:
                        asset = AssetCreate(
                            project_id=project_uuid,
                            type="url",
                            value=target,
                            status="scanned"
                        )
                        asset = await db.create_asset(asset)
                    
                    # Store discovered endpoints
                    for path_info in result.get("discovered_paths", []):
                        endpoint = WebEndpointCreate(
                            asset_id=asset.id,
                            path=path_info["path"],
                            method="GET",
                            status_code=path_info["status_code"],
                            content_length=path_info["content_length"],
                            content_type=path_info.get("content_type"),
                            headers=path_info.get("headers", {})
                        )
                        await db.create_web_endpoint(endpoint)
                        
            except Exception as e:
                print(f"⚠️  Warning: Failed to store results in database: {e}")
        
        return result
    

    
    async def enhanced_reconnaissance(self, targets: List[str], project_name: str, 
                                    scan_type: str = "quick", max_concurrent: int = 5) -> Dict:
        """Enhanced reconnaissance workflow with comprehensive asset discovery and parallel scanning"""
        print(f"🚀 Starting enhanced reconnaissance for {len(targets)} targets")
        print(f"📋 Creating project: {project_name}")
        
        # Create project
        project = await self.create_project(project_name, target_domain=", ".join(targets[:3]))
        project_id = project["id"]
        
        results = {
            "project": project,
            "targets": targets,
            "asset_discovery": {},
            "port_scans": {},
            "summary": {}
        }
        
        try:
            # Phase 1: Asset Discovery
            print(f"\n🔍 Phase 1: Comprehensive Asset Discovery")
            all_discovered_assets = set()
            
            for target in targets:
                print(f"\n  🎯 Processing target: {target}")
                discovery_result = await self.discover_assets(target, project_id)
                results["asset_discovery"][target] = discovery_result
                
                # Collect all discovered assets
                all_discovered_assets.update(discovery_result["subdomains"])
                all_discovered_assets.update(discovery_result["ips"])
                all_discovered_assets.update(discovery_result["domains"])
            
            # Add original targets to the list
            all_discovered_assets.update(targets)
            
            # Convert to list and deduplicate
            all_targets = list(all_discovered_assets)
            print(f"\n📊 Total unique assets discovered: {len(all_targets)}")
            
            # Phase 2: Parallel Port Scanning
            print(f"\n🔍 Phase 2: Parallel Port Scanning")
            if all_targets:
                scan_results = await self.port_scan_parallel(all_targets, project_id, scan_type, max_concurrent)
                results["port_scans"] = scan_results["scan_results"]
                results["summary"]["scan_summary"] = scan_results["summary"]
            
            # Phase 3: Directory Fuzzing (for web services)
            print(f"\n📁 Phase 3: Directory Fuzzing")
            web_ports = [80, 443, 8080, 8443, 3000, 8000, 8888, 9000]
            web_targets = []
            
            # Find targets with web services
            for target, scan_result in results["port_scans"].items():
                if "error" not in scan_result and scan_result.get("open_ports"):
                    web_ports_found = [p["port"] for p in scan_result["open_ports"] if p["port"] in web_ports]
                    if web_ports_found:
                        web_targets.append(target)
            
            if web_targets:
                print(f"  🌐 Found {len(web_targets)} targets with web services")
                fuzz_results = {}
                for target in web_targets[:5]:  # Limit to first 5 to avoid overwhelming
                    try:
                        print(f"    📁 Fuzzing {target}...")
                        fuzz_result = await self.directory_fuzzing(f"http://{target}", project_id)
                        fuzz_results[target] = fuzz_result
                    except Exception as e:
                        print(f"      ⚠️  Failed to fuzz {target}: {e}")
                        fuzz_results[target] = {"error": str(e)}
                
                results["dir_fuzz"] = fuzz_results
            else:
                print("  ⚠️  No web services found for directory fuzzing")
            
            # Generate summary
            total_assets = len(all_targets)
            successful_scans = sum(1 for r in results["port_scans"].values() if "error" not in r)
            dns_failures = sum(1 for r in results["port_scans"].values() if r.get("type") == "dns_failure")
            other_failures = sum(1 for r in results["port_scans"].values() if r.get("type") == "scan_failure")
            web_targets_count = len(web_targets)
            
            results["summary"]["final"] = {
                "total_targets": len(targets),
                "total_assets_discovered": total_assets,
                "successful_port_scans": successful_scans,
                "dns_failures": dns_failures,
                "other_failures": other_failures,
                "web_targets_found": web_targets_count,
                "project_id": project_id
            }
            
            print(f"\n✅ Enhanced reconnaissance completed for project: {project_name}")
            print(f"📊 Final Summary:")
            print(f"  • Original targets: {len(targets)}")
            print(f"  • Total assets discovered: {total_assets}")
            print(f"  • Successful port scans: {successful_scans}")
            if dns_failures > 0:
                print(f"  • DNS failures: {dns_failures}")
            if other_failures > 0:
                print(f"  • Other failures: {other_failures}")
            print(f"  • Web targets found: {web_targets_count}")
            
        except Exception as e:
            print(f"\n❌ Error during enhanced reconnaissance: {e}")
            results["error"] = str(e)
        
        return results
    
    async def full_reconnaissance(self, target: str, project_name: str) -> Dict:
        """Legacy full reconnaissance workflow (single target)"""
        return await self.enhanced_reconnaissance([target], project_name)
    
    def print_results(self, results: Dict, format_type: str = "table"):
        """Print results in specified format"""
        if format_type == "json":
            print(json.dumps(results, indent=2))
        else:
            self._print_table(results)
    
    def _print_table(self, results: Dict):
        """Print results in table format"""
        if "open_ports" in results:
            print(f"\n📊 Port Scan Results for {results['target']}")
            print(f"⏱️  Duration: {results.get('scan_duration', 0):.2f}s")
            print(f"🔢 Ports Scanned: {results.get('ports_scanned', 0)}")
            print(f"✅ Open Ports: {len(results.get('open_ports', []))}")
            
            if results.get("open_ports"):
                print("\n┌──────┬──────────┬─────────────┬─────────────┐")
                print("│ Port │ Protocol │ Service     │ Version     │")
                print("├──────┼──────────┼─────────────┼─────────────┤")
                for port_info in results["open_ports"]:
                    port = port_info["port"]
                    protocol = port_info["protocol"]
                    service = port_info["service"][:10]
                    version = (port_info.get("version", "") or "")[:10]
                    print(f"│ {port:4d} │ {protocol:8s} │ {service:10s} │ {version:10s} │")
                print("└──────┴──────────┴─────────────┴─────────────┘")
        
        elif "subdomains" in results:
            print(f"\n🌐 Subdomain Enumeration Results for {results['domain']}")
            print(f"⏱️  Duration: {results.get('duration', 0):.2f}s")
            print(f"🔍 Subdomains Found: {len(results.get('subdomains', []))}")
            
            if results.get("subdomains"):
                print("\nDiscovered Subdomains:")
                for subdomain in results["subdomains"]:
                    print(f"  • {subdomain}")
        
        elif "discovered_paths" in results:
            print(f"\n📁 Directory Fuzzing Results for {results['target']}")
            print(f"⏱️  Duration: {results.get('scan_duration', 0):.2f}s")
            print(f"🔍 Paths Found: {len(results.get('discovered_paths', []))}")
            
            if results.get("discovered_paths"):
                print("\n┌─────────────┬──────────┬─────────────┬─────────────┐")
                print("│ Path        │ Status   │ Length      │ Type        │")
                print("├─────────────┼──────────┼─────────────┼─────────────┤")
                for path_info in results["discovered_paths"]:
                    path = path_info["path"][:10]
                    status = path_info["status_code"]
                    length = path_info["content_length"]
                    content_type = (path_info.get("content_type", "") or "")[:10]
                    print(f"│ {path:10s} │ {status:7d} │ {length:10d} │ {content_type:10s} │")
                print("└─────────────┴──────────┴─────────────┴─────────────┘")
        
        elif "summary" in results:
            print(f"\n📊 Enhanced Reconnaissance Summary")
            if "final" in results["summary"]:
                final = results["summary"]["final"]
                print(f"  • Original targets: {final.get('total_targets', 0)}")
                print(f"  • Total assets discovered: {final.get('total_assets_discovered', 0)}")
                print(f"  • Successful port scans: {final.get('successful_port_scans', 0)}")
                if final.get('dns_failures', 0) > 0:
                    print(f"  • DNS failures: {final.get('dns_failures', 0)}")
                if final.get('other_failures', 0) > 0:
                    print(f"  • Other failures: {final.get('other_failures', 0)}")
                print(f"  • Web targets found: {final.get('web_targets_found', 0)}")
        


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="BanzAI - AI-Powered Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enhanced reconnaissance with single target
  python src/cli_main.py recon example.com "Example Project"
  
  # Enhanced reconnaissance with file input
  python src/cli_main.py recon --file targets.txt "Multi-Target Project"
  
  # Enhanced reconnaissance with multiple targets
  python src/cli_main.py recon --targets example.com,test.com,demo.org "Multi-Target Project"
  
  # Quick port scan
  python src/cli_main.py scan 192.168.1.1 --type quick
  
  # Subdomain enumeration
  python src/cli_main.py subdomains example.com
  
  # Directory fuzzing
  python src/cli_main.py fuzz https://example.com
  

  
  # List projects
  python src/cli_main.py projects
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Enhanced reconnaissance command
    recon_parser = subparsers.add_parser("recon", help="Enhanced reconnaissance workflow")
    recon_parser.add_argument("target", nargs="?", help="Target domain or IP (optional if using --file)")
    recon_parser.add_argument("project_name", help="Project name")
    recon_parser.add_argument("--file", help="File containing targets (one per line)")
    recon_parser.add_argument("--targets", help="Comma-separated list of targets")
    recon_parser.add_argument("--scan-type", choices=["quick", "web", "database", "full"], 
                             default="quick", help="Port scan type")
    recon_parser.add_argument("--max-concurrent", type=int, default=5, 
                             help="Maximum concurrent port scans")
    
    # Port scan command
    scan_parser = subparsers.add_parser("scan", help="Port scanning")
    scan_parser.add_argument("target", help="Target IP or hostname")
    scan_parser.add_argument("--type", choices=["quick", "web", "database", "full"], 
                           default="quick", help="Scan type")
    scan_parser.add_argument("--ports", default="1-65535", help="Port range")
    scan_parser.add_argument("--project-id", help="Project ID for database storage")
    
    # Subdomain enumeration command
    subdomain_parser = subparsers.add_parser("subdomains", help="Subdomain enumeration")
    subdomain_parser.add_argument("domain", help="Target domain")
    subdomain_parser.add_argument("--project-id", help="Project ID for database storage")
    
    # DNS analysis command
    dns_parser = subparsers.add_parser("dns", help="DNS analysis")
    dns_parser.add_argument("domain", help="Target domain")
    dns_parser.add_argument("--project-id", help="Project ID for database storage")
    
    # Directory fuzzing command
    fuzz_parser = subparsers.add_parser("fuzz", help="Directory fuzzing")
    fuzz_parser.add_argument("target", help="Target URL")
    fuzz_parser.add_argument("--wordlist", default="common", help="Wordlist to use")
    fuzz_parser.add_argument("--project-id", help="Project ID for database storage")
    

    
    # Project management commands
    projects_parser = subparsers.add_parser("projects", help="Project management")
    projects_parser.add_argument("--list", action="store_true", help="List all projects")
    projects_parser.add_argument("--create", help="Create new project")
    projects_parser.add_argument("--description", help="Project description")
    projects_parser.add_argument("--target", help="Target domain")
    
    # Global options
    parser.add_argument("--format", choices=["table", "json"], default="table", 
                       help="Output format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    async with BanzAICLI() as cli:
        try:
            if args.command == "recon":
                # Collect targets from various sources
                targets = []
                
                # From file
                if args.file:
                    file_targets = cli._parse_target_file(args.file)
                    targets.extend(file_targets)
                
                # From comma-separated list
                if args.targets:
                    list_targets = [t.strip() for t in args.targets.split(",")]
                    targets.extend(list_targets)
                
                # From single target argument
                if args.target:
                    targets.append(args.target)
                
                # Validate and deduplicate
                if not targets:
                    print("❌ Error: No targets specified. Use --file, --targets, or provide a target argument.")
                    return
                
                targets = cli._deduplicate_targets(targets)
                print(f"🎯 Targets to process: {targets}")
                
                results = await cli.enhanced_reconnaissance(
                    targets, 
                    args.project_name,
                    scan_type=args.scan_type,
                    max_concurrent=args.max_concurrent
                )
                cli.print_results(results, args.format)
            
            elif args.command == "scan":
                results = await cli.port_scan(args.target, args.project_id, 
                                            scan_type=args.type, ports=args.ports)
                cli.print_results(results, args.format)
            
            elif args.command == "subdomains":
                results = await cli.subdomain_enumeration(args.domain, args.project_id)
                cli.print_results(results, args.format)
            
            elif args.command == "dns":
                results = await cli.dns_analysis(args.domain, args.project_id)
                cli.print_results(results, args.format)
            
            elif args.command == "fuzz":
                results = await cli.directory_fuzzing(args.target, args.project_id, args.wordlist)
                cli.print_results(results, args.format)
            

            
            elif args.command == "projects":
                if args.list:
                    projects = await cli.list_projects()
                    print("\n📋 Projects:")
                    for project in projects:
                        print(f"  • {project['name']} (ID: {project['id']})")
                        print(f"    Target: {project.get('target_domain', 'N/A')}")
                        print(f"    Status: {project['status']}")
                        print(f"    Created: {project['created_at']}")
                        print()
                elif args.create:
                    project = await cli.create_project(args.create, args.description, args.target)
                    print(f"✅ Created project: {project['name']} (ID: {project['id']})")
                else:
                    projects_parser.print_help()
            
        except Exception as e:
            print(f"❌ Error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main()) 