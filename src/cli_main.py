#!/usr/bin/env python3
"""
BanzAI CLI - AI-Powered Penetration Testing Tool
Main command-line interface for orchestrating reconnaissance and scanning
"""

import asyncio
import argparse
import json
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
import aiohttp

from database.models import (
    ProjectCreate, AssetCreate, ScanCreate, FindingCreate,
    ServiceCreate, WebEndpointCreate, ScanRequest
)
from database.banzai_db import BanzAIDatabase

class BanzAICLI:
    """Main CLI interface for BanzAI"""
    
    def __init__(self):
        self.scan_server_url = "http://banzai_scan_server:8000"
        self.subdomain_server_url = "http://banzai_subdomain_server:8000"
        self.dns_server_url = "http://banzai_dns_analysis_server:8000"
        self.directory_fuzzer_url = "http://banzai_directory_fuzzer:8004"
        self.supabase_url = "http://banzai_supabase_mcp:8003"
        
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
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
    
    async def port_scan(self, target: str, project_id: Optional[str] = None, 
                       ports: str = "1-65535", scan_type: str = "quick") -> Dict:
        """Perform port scanning"""
        print(f"🔍 Starting port scan of {target}...")
        
        # Determine scan endpoint based on type
        if scan_type == "quick":
            endpoint = f"{self.scan_server_url}/scan/quick?target={target}"
            data = None
        elif scan_type == "web":
            endpoint = f"{self.scan_server_url}/scan/web?target={target}"
            data = None
        elif scan_type == "database":
            endpoint = f"{self.scan_server_url}/scan/database?target={target}"
            data = None
        else:
            endpoint = f"{self.scan_server_url}/scan"
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
                               wordlist: str = "common") -> Dict:
        """Perform directory fuzzing"""
        print(f"📁 Starting directory fuzzing for {target}...")
        
        data = {
            "target": target,
            "wordlist": wordlist,
            "threads": 50,
            "timeout": 10
        }
        
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
    
    async def full_reconnaissance(self, target: str, project_name: str) -> Dict:
        """Perform full reconnaissance workflow"""
        print(f"🚀 Starting full reconnaissance for {target}")
        print(f"📋 Creating project: {project_name}")
        
        # Create project
        project = await self.create_project(project_name, target_domain=target)
        project_id = project["id"]
        
        results = {
            "project": project,
            "port_scan": None,
            "subdomain_enum": None,
            "dns_analysis": None,
            "directory_fuzz": None
        }
        
        try:
            # Port scan
            print("\n🔍 Phase 1: Port Scanning")
            results["port_scan"] = await self.port_scan(target, project_id, scan_type="quick")
            
            # Subdomain enumeration
            print("\n🌐 Phase 2: Subdomain Enumeration")
            results["subdomain_enum"] = await self.subdomain_enumeration(target, project_id)
            
            # DNS analysis
            print("\n🔍 Phase 3: DNS Analysis")
            results["dns_analysis"] = await self.dns_analysis(target, project_id)
            
            # Directory fuzzing (if web ports found)
            web_ports = [80, 443, 8080, 8443, 3000, 8000, 8888, 9000]
            found_web_ports = [p["port"] for p in results["port_scan"].get("open_ports", []) 
                             if p["port"] in web_ports]
            
            if found_web_ports:
                print(f"\n📁 Phase 4: Directory Fuzzing (found web ports: {found_web_ports})")
                web_target = f"http://{target}" if 80 in found_web_ports else f"https://{target}"
                results["directory_fuzz"] = await self.directory_fuzzing(web_target, project_id)
            else:
                print("\n📁 Phase 4: Directory Fuzzing (skipped - no web ports found)")
            
            print(f"\n✅ Full reconnaissance completed for project: {project_name}")
            
        except Exception as e:
            print(f"\n❌ Error during reconnaissance: {e}")
        
        return results
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, target))
    
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

async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="BanzAI - AI-Powered Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a new project and run full reconnaissance
  python src/cli_main.py recon example.com "Example Project"
  
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
    
    # Reconnaissance command
    recon_parser = subparsers.add_parser("recon", help="Full reconnaissance workflow")
    recon_parser.add_argument("target", help="Target domain or IP")
    recon_parser.add_argument("project_name", help="Project name")
    
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
                results = await cli.full_reconnaissance(args.target, args.project_name)
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
                results = await cli.directory_fuzzing(args.target, args.project_id, 
                                                    wordlist=args.wordlist)
                cli.print_results(results, args.format)
            
            elif args.command == "projects":
                if args.list:
                    projects = await cli.list_projects()
                    if args.format == "json":
                        print(json.dumps(projects, indent=2))
                    else:
                        print("\n📋 Projects:")
                        for project in projects:
                            print(f"  • {project['name']} ({project['id']})")
                            print(f"    Target: {project.get('target_domain', 'N/A')}")
                            print(f"    Status: {project['status']}")
                            print(f"    Assets: {project['assets_count']}, Scans: {project['scans_count']}, Findings: {project['findings_count']}")
                            print()
                
                elif args.create:
                    project = await cli.create_project(args.create, args.description, args.target)
                    print(f"✅ Created project: {project['name']} ({project['id']})")
        
        except Exception as e:
            print(f"❌ Error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 