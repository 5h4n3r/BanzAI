#!/usr/bin/env python3
"""
Custom Python-based Supabase MCP Server
Direct Supabase integration without Node.js wrapper
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import uuid4
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import logging

# Configure logging to only show errors
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Global variable for Supabase client
supabase_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for FastAPI startup and shutdown."""
    global supabase_client
    
    # Startup
    if supabase_client is None:
        print("[ERROR] Supabase client not initialized during startup")
        raise RuntimeError("Supabase client not initialized")
    
    # Initialize database schema
    try:
        print("[INFO] Initializing database schema...")
        await supabase_client.initialize_database()
        print("[INFO] Database schema initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize database schema: {e}")
        # Don't fail startup, just log the error
    
    print("[INFO] Supabase MCP server ready to accept requests")
    
    yield
    
    # Shutdown
    print("[INFO] Shutting down Supabase MCP server")

app = FastAPI(lifespan=lifespan)

class SupabaseClient:
    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        # Debug logging (without exposing sensitive data)
        print(f"[DEBUG] SUPABASE_URL: {self.supabase_url}")
        print(f"[DEBUG] SUPABASE_SERVICE_ROLE_KEY: {'***SET***' if self.supabase_key else '***NOT SET***'}")
        
        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
        
        try:
            print("[DEBUG] Creating Supabase client...")
            self.client: Client = create_client(self.supabase_url, self.supabase_key)
            print("[DEBUG] Supabase client created successfully")
            
            # Test the connection
            print("[DEBUG] Testing Supabase connection...")
            test_result = self.client.table('projects').select('count', count='exact').limit(1).execute()
            print(f"[DEBUG] Connection test result: {test_result}")
            
        except Exception as e:
            print(f"[DEBUG] Error creating Supabase client: {e}")
            raise
    
    async def list_tables(self) -> Dict[str, Any]:
        """List all tables in the database."""
        try:
            # For now, return the known tables
            # In a full implementation, you'd query the information_schema
            known_tables = [
                "projects", "assets", "scans", "services", 
                "web_endpoints", "findings"
            ]
            
            return {
                "success": True,
                "tables": known_tables,
                "count": len(known_tables)
            }
        except Exception as e:
            logger.error(f"List tables error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def create_project(self, name: str, target_domain: str, description: str = None) -> Dict[str, Any]:
        """Create a new project."""
        try:
            project_data = {
                "id": str(uuid4()),
                "name": name,
                "target_domain": target_domain,
                "description": description or f"Project for {target_domain}",
                "status": "active",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            result = self.client.table('projects').insert(project_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "project": result.data[0],
                    "id": result.data[0]['id']
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create project"
                }
        except Exception as e:
            logger.error(f"Create project error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def find_project(self, name: str) -> Dict[str, Any]:
        """Find project by name."""
        try:
            result = self.client.table('projects').select('*').eq('name', name).order('created_at', desc=True).limit(1).execute()
            
            if result.data:
                return {
                    "success": True,
                    "project": result.data[0],
                    "id": result.data[0]['id']
                }
            else:
                return {
                    "success": False,
                    "error": "Project not found"
                }
        except Exception as e:
            logger.error(f"Find project error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def create_asset(self, project_id: str, asset_type: str, value: str, status: str = "discovered") -> Dict[str, Any]:
        """Create a new asset."""
        try:
            # First check if asset already exists
            existing_result = self.client.table('assets').select('*').eq('project_id', project_id).eq('type', asset_type).eq('value', value).execute()
            
            if existing_result.data:
                # Asset already exists, return it
                return {
                    "success": True,
                    "asset": existing_result.data[0],
                    "id": existing_result.data[0]['id'],
                    "existing": True
                }
            
            # Create new asset
            asset_data = {
                "id": str(uuid4()),
                "project_id": project_id,
                "type": asset_type,
                "value": value,
                "status": status,
                "metadata": {},
                "discovered_at": datetime.utcnow().isoformat()
            }
            
            result = self.client.table('assets').insert(asset_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "asset": result.data[0],
                    "id": result.data[0]['id'],
                    "existing": False
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create asset"
                }
        except Exception as e:
            logger.error(f"Create asset error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def create_scan(self, project_id: str, scan_type: str, results: Dict[str, Any], status: str = "completed") -> Dict[str, Any]:
        """Create a new scan record."""
        try:
            scan_data = {
                "id": str(uuid4()),
                "project_id": project_id,
                "scan_type": scan_type,
                "status": status,
                "configuration": {},
                "results": results,
                "started_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat()
            }
            
            result = self.client.table('scans').insert(scan_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "scan": result.data[0],
                    "id": result.data[0]['id']
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create scan"
                }
        except Exception as e:
            logger.error(f"Create scan error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def create_service(self, asset_id: str, port: int, protocol: str, service_name: str = None, banner: str = None) -> Dict[str, Any]:
        """Create a service record."""
        try:
            # Check if service already exists
            existing = self.client.table('services').select('*').eq('asset_id', asset_id).eq('port', port).eq('protocol', protocol).execute()
            
            if existing.data:
                return {
                    "success": True,
                    "id": existing.data[0]['id'],
                    "message": "Service already exists"
                }
            
            # Create new service
            service_data = {
                "asset_id": asset_id,
                "port": port,
                "protocol": protocol,
                "service_name": service_name or "",
                "banner": banner or ""
            }
            
            result = self.client.table('services').insert(service_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "id": result.data[0]['id'],
                    "message": "Service created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create service"
                }
                
        except Exception as e:
            logger.error(f"Create service error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def create_finding(self, project_id: str, asset_id: str, scan_id: str, 
                           category: str, title: str, description: str = None, 
                           evidence: Dict[str, Any] = None, remediation: str = None) -> Dict[str, Any]:
        """Create a security finding."""
        try:
            finding_data = {
                "project_id": project_id,
                "asset_id": asset_id,
                "scan_id": scan_id,
                "category": category,
                "title": title,
                "description": description or "",
                "evidence": evidence or {},
                "remediation": remediation or ""
            }
            
            result = self.client.table('findings').insert(finding_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "id": result.data[0]['id'],
                    "message": "Finding created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create finding"
                }
                
        except Exception as e:
            logger.error(f"Create finding error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def create_web_endpoint(self, asset_id: str, path: str, method: str = "GET", 
                                status_code: int = None, content_length: int = None,
                                content_type: str = None, title: str = None, 
                                headers: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a web endpoint record."""
        try:
            # Check if web endpoint already exists
            existing = self.client.table('web_endpoints').select('*').eq('asset_id', asset_id).eq('path', path).eq('method', method).execute()
            
            if existing.data:
                return {
                    "success": True,
                    "id": existing.data[0]['id'],
                    "message": "Web endpoint already exists"
                }
            
            # Create new web endpoint - try without headers first
            endpoint_data = {
                "asset_id": asset_id,
                "path": path,
                "method": method,
                "status_code": status_code,
                "content_length": content_length,
                "content_type": content_type,
                "title": title or ""
            }
            
            result = self.client.table('web_endpoints').insert(endpoint_data).execute()
            
            if result.data:
                return {
                    "success": True,
                    "id": result.data[0]['id'],
                    "message": "Web endpoint created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create web endpoint"
                }
                
        except Exception as e:
            logger.error(f"Create web endpoint error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def initialize_database(self) -> Dict[str, Any]:
        """Initialize the database schema using direct table operations."""
        results = []
        
        try:
            # Check if tables exist and create them if they don't
            tables_to_check = ['projects', 'assets', 'scans', 'services', 'web_endpoints', 'findings']
            
            for table_name in tables_to_check:
                try:
                    # Try to query the table - if it exists, this will work
                    test_result = self.client.table(table_name).select('id').limit(1).execute()
                    results.append({"table": table_name, "success": True, "message": "Table exists"})
                except Exception as e:
                    # Table doesn't exist, but we can't create it via RPC since exec_sql doesn't exist
                    # Just log that the table is missing and continue
                    results.append({"table": table_name, "success": False, "message": f"Table missing: {str(e)}"})
            
            # Note: DNS categories are now included in the schema.sql file
            # No manual constraint update needed for new installations
            
            # Force refresh the Supabase client schema cache
            try:
                # Recreate the client to refresh schema cache
                self.client = create_client(self.supabase_url, self.supabase_key)
                print("[DEBUG] Supabase client recreated to refresh schema cache")
                
                # Force schema cache refresh by making a test query
                try:
                    test_result = self.client.table('findings').select('id').limit(1).execute()
                    print("[DEBUG] Schema cache refresh successful - findings table accessible")
                except Exception as schema_error:
                    print(f"[WARNING] Schema cache refresh failed: {schema_error}")
                    
            except Exception as e:
                print(f"[WARNING] Failed to recreate Supabase client: {e}")
            
        except Exception as e:
            results.append({"error": f"Database initialization failed: {str(e)}"})
        
        return {
            "message": "Database initialization completed",
            "results": results
        }

    async def update_findings_constraint(self) -> Dict[str, Any]:
        """Update the findings table constraint to include DNS-specific categories."""
        try:
            # First, try to drop the existing constraint (if it exists)
            try:
                drop_constraint_sql = "ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_category_check;"
                # Note: We can't execute this directly since exec_sql doesn't exist
                # But we'll try to add the new constraint anyway
                print("[INFO] Attempting to update findings category constraint...")
            except Exception as e:
                print(f"[WARNING] Could not drop existing constraint: {e}")
            
            # Define the new constraint with DNS categories
            new_constraint_sql = """
            ALTER TABLE findings ADD CONSTRAINT findings_category_check 
            CHECK (category IN (
                'open_service', 'web_discovery', 
                'dns_infrastructure', 'dns_security', 'dns_vulnerability', 'email_security'
            ));
            """
            
            # Since we can't execute SQL directly, we'll try to insert a test record
            # to see if the constraint is already updated
            test_finding = {
                "project_id": "00000000-0000-0000-0000-000000000000",  # Dummy UUID
                "asset_id": "00000000-0000-0000-0000-000000000000",    # Dummy UUID
                "scan_id": "00000000-0000-0000-0000-000000000000",     # Dummy UUID
                "category": "dns_infrastructure",
                "title": "Test DNS Category",
                "description": "Test to check if DNS categories are allowed"
            }
            
            try:
                # Try to insert a test record with DNS category
                test_result = self.client.table('findings').insert(test_finding).execute()
                print("[SUCCESS] DNS categories are already allowed in the database")
                return {"success": True, "message": "DNS categories already supported"}
            except Exception as insert_error:
                if "findings_category_check" in str(insert_error):
                    print("[INFO] DNS categories not yet supported, constraint needs manual update")
                    print("[INFO] Please run this SQL manually in your Supabase database:")
                    print(new_constraint_sql)
                    return {
                        "success": False, 
                        "message": "DNS categories not supported yet",
                        "required_sql": new_constraint_sql
                    }
                else:
                    print(f"[WARNING] Unexpected error testing DNS categories: {insert_error}")
                    return {"success": False, "error": str(insert_error)}
                    
        except Exception as e:
            print(f"[ERROR] Failed to update findings constraint: {e}")
            return {"success": False, "error": str(e)}

# Initialize Supabase client
try:
    supabase_client = SupabaseClient()
    print("[INFO] Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {e}")
    supabase_client = None

# Pydantic models for API requests
class QueryRequest(BaseModel):
    query: str
    params: Optional[Dict[str, Any]] = None

class StoreScanResultsRequest(BaseModel):
    project_name: str
    target: str
    scan_type: str
    scan_data: Dict[str, Any]

# API endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "supabase_initialized": supabase_client is not None,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/debug")
async def debug_info():
    """Debug endpoint to show configuration and test Supabase connection."""
    debug_info = {
        "supabase_initialized": supabase_client is not None,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if supabase_client:
        try:
            # Test a simple list_tables call
            result = await supabase_client.list_tables()
            debug_info["supabase_test_query"] = "success"
            debug_info["supabase_response"] = result
            
            # Try to get web_endpoints table info
            try:
                web_endpoints_result = supabase_client.table('web_endpoints').select('*').limit(1).execute()
                debug_info["web_endpoints_test"] = "success"
                debug_info["web_endpoints_sample"] = web_endpoints_result.data if web_endpoints_result.data else []
            except Exception as e:
                debug_info["web_endpoints_test"] = "failed"
                debug_info["web_endpoints_error"] = str(e)
            
            # Try to get findings table info
            try:
                findings_result = supabase_client.table('findings').select('*').limit(1).execute()
                debug_info["findings_test"] = "success"
                debug_info["findings_sample"] = findings_result.data if findings_result.data else []
            except Exception as e:
                debug_info["findings_test"] = "failed"
                debug_info["findings_error"] = str(e)
                
        except Exception as e:
            debug_info["supabase_test_query"] = "failed"
            debug_info["supabase_error"] = str(e)
    
    return debug_info

@app.post("/query")
async def execute_query(request: QueryRequest):
    """Execute a raw SQL query."""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # This method is no longer used for direct SQL execution,
        # but keeping it for compatibility if other parts of the system call it.
        # The new initialize_database handles schema creation.
        result = {"success": False, "error": "This endpoint is deprecated. Use /initialize for schema setup."}
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tables")
async def list_tables():
    """List all tables in the database."""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        result = await supabase_client.list_tables()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/initialize")
async def initialize_database():
    """Initialize the database schema."""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        result = await supabase_client.initialize_database()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/check_constraints")
async def check_constraints():
    """Check the current database constraints and provide update instructions."""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        result = await supabase_client.update_findings_constraint()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/projects")
async def get_projects(target_domain: str = None, name: str = None):
    """Get projects with optional filtering"""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # Build query based on parameters
        query = supabase_client.client.table('projects').select('*')
        
        if target_domain:
            query = query.eq('target_domain', target_domain)
        if name:
            query = query.eq('name', name)
            
        result = query.execute()
        
        return {
            "success": True,
            "projects": result.data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scans")
async def get_scans(project_id: str = None, scan_type: str = None, limit: int = 10):
    """Get scans with optional filtering"""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # Build query based on parameters
        query = supabase_client.client.table('scans').select('*')
        
        if project_id:
            query = query.eq('project_id', project_id)
        if scan_type:
            query = query.eq('scan_type', scan_type)
            
        # Add limit and order by completed_at desc
        query = query.order('completed_at', desc=True).limit(limit)
        
        result = query.execute()
        
        return {
            "success": True,
            "scans": result.data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/assets")
async def get_assets(project_id: str = None, asset_type: str = None):
    """Get assets with optional filtering"""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # Build query based on parameters
        query = supabase_client.client.table('assets').select('*')
        
        if project_id:
            query = query.eq('project_id', project_id)
        if asset_type:
            query = query.eq('asset_type', asset_type)
            
        result = query.execute()
        
        return {
            "success": True,
            "assets": result.data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/findings")
async def get_findings(project_id: str = None, category: str = None):
    """Get findings with optional filtering"""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # Build query based on parameters
        query = supabase_client.client.table('findings').select('*')
        
        if project_id:
            query = query.eq('project_id', project_id)
        if category:
            query = query.eq('category', category)
            
        result = query.execute()
        
        return {
            "success": True,
            "findings": result.data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/store_scan_results")
async def store_scan_results(request: StoreScanResultsRequest):
    """Store scan results in the database, creating project if needed."""
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Supabase client not configured")
    
    try:
        # First, try to find existing project
        find_result = await supabase_client.find_project(request.project_name)
        project_id = None
        
        if find_result.get("success"):
            project_id = find_result["id"]
        else:
            # Create new project if not found
            create_result = await supabase_client.create_project(
                request.project_name,
                request.target,
                f"Project for {request.target}"
            )
            
            if create_result.get("success"):
                project_id = create_result["id"]
            else:
                raise Exception(f"Failed to create project: {create_result.get('error')}")
        
        if not project_id:
            raise Exception("Failed to create or find project")
        
        # Store the scan results
        scan_result = await supabase_client.create_scan(
            project_id,
            request.scan_type,
            request.scan_data
        )
        
        if not scan_result.get("success"):
            raise Exception(f"Failed to create scan: {scan_result.get('error')}")
        
        # Handle specific scan types
        if request.scan_type == "port_scan" and "open_ports" in request.scan_data:
            # Create asset for the target
            asset_result = await supabase_client.create_asset(
                project_id,
                "domain",
                request.target,
                "scanned"
            )
            
            if asset_result.get("success"):
                asset_id = asset_result["id"]
                
                # Store each open port as a service
                for port_data in request.scan_data["open_ports"]:
                    port = port_data.get("port")
                    protocol = port_data.get("protocol", "tcp")
                    service_name = port_data.get("service", "")
                    banner = port_data.get("banner", "")
                    
                    await supabase_client.create_service(
                        asset_id,
                        port,
                        protocol,
                        service_name,
                        banner
                    )
                
                # Create security findings for potentially vulnerable services
                vulnerable_ports = {
                    21: "FTP (File Transfer Protocol) - Consider using SFTP or FTPS",
                    22: "SSH (Secure Shell) - Ensure strong authentication and key-based access",
                    23: "Telnet - Highly insecure, should be disabled",
                    25: "SMTP (Simple Mail Transfer Protocol) - Ensure proper authentication",
                    53: "DNS (Domain Name System) - Monitor for DNS attacks",
                    80: "HTTP - Consider upgrading to HTTPS",
                    110: "POP3 (Post Office Protocol) - Use POP3S with encryption",
                    143: "IMAP (Internet Message Access Protocol) - Use IMAPS with encryption",
                    443: "HTTPS - Ensure proper SSL/TLS configuration",
                    445: "SMB (Server Message Block) - Ensure proper authentication",
                    1433: "Microsoft SQL Server - Ensure strong authentication",
                    1521: "Oracle Database - Ensure proper security configuration",
                    3306: "MySQL Database - Ensure strong authentication",
                    3389: "RDP (Remote Desktop Protocol) - Use strong authentication",
                    5432: "PostgreSQL Database - Ensure proper security configuration",
                    5900: "VNC (Virtual Network Computing) - Use VNC over SSH",
                    6379: "Redis Database - Ensure authentication is enabled",
                    8080: "HTTP Alternative Port - Consider using standard port 80/443",
                    8443: "HTTPS Alternative Port - Ensure proper SSL/TLS configuration"
                }
                
                for port_data in request.scan_data["open_ports"]:
                    port = port_data.get("port")
                    service_name = port_data.get("service", "")
                    
                    if port in vulnerable_ports and scan_result.get("id"):
                        await supabase_client.create_finding(
                            project_id=project_id,
                            asset_id=asset_id,
                            scan_id=scan_result["id"],
                            category="open_service",
                            title=f"Potentially Vulnerable Service: {service_name} on port {port}",
                            description=f"Detected {service_name} service running on port {port}. {vulnerable_ports[port]}",
                            evidence={
                                "port": port,
                                "service": service_name,
                                "protocol": port_data.get("protocol", "tcp"),
                                "banner": port_data.get("banner", "")
                            },
                            remediation=vulnerable_ports[port]
                        )

        elif request.scan_type == "subdomain_enum" and "subdomains" in request.scan_data:
            # Store each subdomain as an asset
            subdomains = request.scan_data.get("subdomains", [])
            for subdomain in subdomains:
                await supabase_client.create_asset(
                    project_id,
                    "subdomain",
                    subdomain,
                    "discovered"
                )
        
        elif request.scan_type == "dns_analysis" and "dns_records" in request.scan_data:
            # Store DNS records as assets
            dns_records = request.scan_data.get("dns_records", {})
            records = dns_records.get("records", {})
            
            # Create asset for the main domain
            domain_asset_result = await supabase_client.create_asset(
                project_id,
                "domain",
                request.target,
                "discovered"
            )
            
            domain_asset_id = None
            if domain_asset_result.get("success"):
                domain_asset_id = domain_asset_result["id"]
            
            # Store only actual subdomains as assets (not DNS infrastructure records)
            subdomains = dns_records.get("subdomains", [])
            for subdomain in subdomains:
                await supabase_client.create_asset(
                    project_id,
                    "subdomain",
                    subdomain,
                    "discovered"
                )
            
            # Store DNS infrastructure findings
            if domain_asset_id and scan_result.get("id"):
                # Store nameserver information
                nameservers = dns_records.get("nameservers", [])
                if nameservers:
                    await supabase_client.create_finding(
                        project_id=project_id,
                        asset_id=domain_asset_id,
                        scan_id=scan_result["id"],
                        category="dns_infrastructure",
                        title=f"DNS Nameservers: {', '.join(nameservers)}",
                        description=f"Domain uses nameservers: {', '.join(nameservers)}. This reveals the DNS provider and potential DNS-based attack vectors.",
                        evidence={"nameservers": nameservers, "scan_type": "dns_analysis"},
                        remediation="Monitor DNS provider for any suspicious changes or DNS-based attacks."
                    )
                
                # Store email infrastructure information
                mx_records = records.get("MX", [])
                if mx_records:
                    await supabase_client.create_finding(
                        project_id=project_id,
                        asset_id=domain_asset_id,
                        scan_id=scan_result["id"],
                        category="dns_infrastructure",
                        title=f"Email Infrastructure: {len(mx_records)} MX records found",
                        description=f"Email infrastructure details: {', '.join([str(mx) for mx in mx_records])}. This reveals email provider and potential email-based attack vectors.",
                        evidence={"mx_records": mx_records, "scan_type": "dns_analysis"},
                        remediation="Ensure proper email security measures (SPF, DKIM, DMARC) are configured."
                    )
                
                # Store TXT records (SPF, DKIM, etc.)
                txt_records = records.get("TXT", [])
                if txt_records:
                    await supabase_client.create_finding(
                        project_id=project_id,
                        asset_id=domain_asset_id,
                        scan_id=scan_result["id"],
                        category="email_security",
                        title=f"Email Security Records: {len(txt_records)} TXT records found",
                        description=f"Email security records found: {', '.join([str(txt) for txt in txt_records])}. These include SPF, DKIM, and other email security configurations.",
                        evidence={"txt_records": txt_records, "scan_type": "dns_analysis"},
                        remediation="Review and ensure all email security records are properly configured and up to date."
                    )
            
            # Store security findings for takeover candidates
            takeover_candidates = dns_records.get("takeover_candidates", [])
            for candidate in takeover_candidates:
                if domain_asset_id and scan_result.get("id"):
                    await supabase_client.create_finding(
                        project_id=project_id,
                        asset_id=domain_asset_id,
                        scan_id=scan_result["id"],
                        category="dns_vulnerability",
                        title=f"Potential Subdomain Takeover: {candidate}",
                        description=f"Detected potential subdomain takeover candidate: {candidate}. This subdomain points to a third-party service that may be vulnerable to takeover.",
                        evidence={"candidate": candidate, "scan_type": "dns_analysis"},
                        remediation="Verify ownership of the subdomain and ensure it's properly configured. Consider removing unused subdomains or implementing proper DNS security controls."
                    )
            
            # Store findings for zone transfer attempts
            zone_transfer = dns_records.get("zone_transfer", {})
            if zone_transfer.get("success") and domain_asset_id and scan_result.get("id"):
                await supabase_client.create_finding(
                    project_id=project_id,
                    asset_id=domain_asset_id,
                    scan_id=scan_result["id"],
                    category="dns_vulnerability",
                    title="Zone Transfer Allowed",
                    description="DNS zone transfer is allowed, which can expose sensitive DNS information including all subdomains.",
                    evidence={"zone_transfer_success": True, "records_count": len(zone_transfer.get("records", []))},
                    remediation="Disable zone transfers on DNS servers by configuring them to reject AXFR requests from unauthorized sources."
                )
            elif zone_transfer.get("success") == False and domain_asset_id and scan_result.get("id"):
                # This is actually good - zone transfer is blocked
                await supabase_client.create_finding(
                    project_id=project_id,
                    asset_id=domain_asset_id,
                    scan_id=scan_result["id"],
                    category="dns_security",
                    title="Zone Transfer Blocked",
                    description="DNS zone transfer is properly blocked, which is a good security practice.",
                    evidence={"zone_transfer_success": False, "error": zone_transfer.get("error", "Unknown")},
                    remediation="Continue to monitor and maintain this security control."
                )

        elif request.scan_type == "dir_fuzz" and "discovered_paths" in request.scan_data:
            # Create asset for the target domain
            asset_result = await supabase_client.create_asset(
                project_id,
                "domain",
                request.target,
                "scanned"
            )
            
            if asset_result.get("success"):
                asset_id = asset_result["id"]
                
                # Store discovered paths as web endpoints
                discovered_paths = request.scan_data.get("discovered_paths", [])
                for path_data in discovered_paths:
                    if isinstance(path_data, dict):
                        path = path_data.get("path", "")
                        status_code = path_data.get("status_code")
                        content_length = path_data.get("content_length")
                        content_type = path_data.get("content_type", "")
                        
                        if path:
                            await supabase_client.create_web_endpoint(
                                asset_id=asset_id,
                                path=path,
                                method="GET",
                                status_code=status_code,
                                content_length=content_length,
                                content_type=content_type
                            )
                
                # Create security findings for discovered endpoints
                if discovered_paths and scan_result.get("id"):
                    await supabase_client.create_finding(
                        project_id=project_id,
                        asset_id=asset_id,
                        scan_id=scan_result["id"],
                        category="web_discovery",
                        title=f"Directory Fuzzing Results: {len(discovered_paths)} endpoints discovered",
                        description=f"Directory fuzzing discovered {len(discovered_paths)} endpoints on {request.target}. Review these endpoints for potential security issues.",
                        evidence={
                            "endpoints": discovered_paths,
                            "scan_type": "dir_fuzz",
                            "target": request.target
                        },
                        remediation="Review discovered endpoints for sensitive information, backup files, or potential vulnerabilities. Remove or secure any unnecessary endpoints."
                    )
        
        return {
            "success": True,
            "message": f"Scan results for {request.target} stored in project '{request.project_name}'",
            "project_id": project_id,
            "scan_type": request.scan_type
        }
        
    except Exception as e:
        logger.error(f"Store scan results error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    
    # Ensure Supabase client is initialized before starting server
    if supabase_client is None:
        print("[ERROR] Supabase client failed to initialize. Exiting.")
        sys.exit(1)
    
    print("[INFO] Starting Supabase MCP server on port 8003...")
    uvicorn.run(app, host="0.0.0.0", port=8003) 