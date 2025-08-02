"""
BanzAI Database Integration Layer
Handles all database operations using Supabase MCP server
"""

import asyncio
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
from uuid import UUID, uuid4
import aiohttp
import sys

from .models import (
    Project, ProjectCreate, ProjectResponse,
    Asset, AssetCreate, AssetResponse,
    Scan, ScanCreate, ScanResponse,
    Finding, FindingCreate,
    Service, ServiceCreate,
    WebEndpoint, WebEndpointCreate,
    ScanRequest, ProjectSummary
)

class BanzAIDatabase:
    """Database integration layer for BanzAI using Supabase MCP server"""
    
    def __init__(self, supabase_url: str = "http://localhost:8003"):
        self.supabase_url = supabase_url
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _execute_query(self, query: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a SQL query via Supabase MCP server"""
        if not self.session:
            raise RuntimeError("Database session not initialized. Use async context manager.")
        
        # Handle parameter substitution for MCP server (doesn't support $1, $2 style)
        if params and "params" in params:
            param_values = params["params"]
            # Replace $1, $2, etc. with actual values
            for i, value in enumerate(param_values, 1):
                if value is None:
                    # Handle NULL values
                    query = query.replace(f"${i}", "NULL")
                elif isinstance(value, str):
                    # Escape single quotes in strings
                    escaped_value = value.replace("'", "''")
                    query = query.replace(f"${i}", f"'{escaped_value}'")
                else:
                    query = query.replace(f"${i}", str(value))
        
        async with self.session.post(
            f"{self.supabase_url}/query",
            json={"query": query}
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Database query failed: {error_text}")
            
            result = await response.json()
            
            # Check for error responses first
            if "result" in result and "isError" in result["result"] and result["result"]["isError"]:
                # Handle error response
                if "content" in result["result"]:
                    content_text = result["result"]["content"][0]["text"]
                    try:
                        error_data = json.loads(content_text)
                        if "error" in error_data:
                            raise Exception(f"Database error: {error_data['error']['message']}")
                    except json.JSONDecodeError:
                        raise Exception(f"Database error: {content_text}")
                else:
                    raise Exception("Database error: Unknown error response")
            
            # Parse successful MCP response format
            if "result" in result and "content" in result["result"]:
                content_text = result["result"]["content"][0]["text"]
                
                # The content_text is a JSON string, so we need to unescape it first
                try:
                    unescaped_text = json.loads(content_text)
                except json.JSONDecodeError:
                    unescaped_text = content_text
                
                # Check if it's wrapped in untrusted-data tags
                import re
                # Look for the pattern: <untrusted-data-xxx>\n[JSON_DATA]\n</untrusted-data-xxx>
                data_match = re.search(r'<untrusted-data-[^>]+>\s*\n(.*?)\s*\n\s*</untrusted-data-[^>]+>', unescaped_text, re.DOTALL)
                
                if data_match:
                    # Extract data from untrusted-data wrapper
                    actual_data = data_match.group(1).strip()
                    try:
                        parsed_data = json.loads(actual_data)
                        return {"result": parsed_data}
                    except json.JSONDecodeError:
                        return {"result": actual_data}
                else:
                    # Direct JSON in text field
                    try:
                        parsed_data = json.loads(unescaped_text)
                        return {"result": parsed_data}
                    except json.JSONDecodeError:
                        return {"result": unescaped_text}
            else:
                # Fallback to direct result
                return result
    
    async def _execute_table_operation(self, table: str, operation: str, data: Dict[str, Any] = None, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a table operation via Supabase MCP server"""
        if not self.session:
            raise RuntimeError("Database session not initialized. Use async context manager.")
        
        payload = {
            "operation": operation,
            "data": data or {},
            "filters": filters or {}
        }
        
        async with self.session.post(
            f"{self.supabase_url}/table/{table}",
            json=payload
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Table operation failed: {error_text}")
            
            result = await response.json()
            return result
    
    # Project Operations
    async def create_project(self, project: ProjectCreate) -> Project:
        """Create a new project"""
        query = """
        INSERT INTO projects (name, description, target_domain, status)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        """
        params = [project.name, project.description, project.target_domain, project.status.value]
        
        result = await self._execute_query(query, {"params": params})
        return Project(**result["result"][0])
    
    async def get_project(self, project_id: UUID) -> Optional[Project]:
        """Get a project by ID"""
        query = "SELECT * FROM projects WHERE id = $1"
        result = await self._execute_query(query, {"params": [str(project_id)]})
        
        if result["result"]:
            return Project(**result["result"][0])
        return None
    
    async def list_projects(self) -> List[ProjectSummary]:
        """List all projects with summary statistics"""
        query = """
        SELECT 
            p.*,
            COUNT(DISTINCT a.id) as assets_count,
            COUNT(DISTINCT s.id) as scans_count,
            COUNT(DISTINCT f.id) as findings_count
        FROM projects p
        LEFT JOIN assets a ON p.id = a.project_id
        LEFT JOIN scans s ON p.id = s.project_id
        LEFT JOIN findings f ON p.id = f.project_id
        GROUP BY p.id
        ORDER BY p.created_at DESC
        """
        
        result = await self._execute_query(query)
        return [ProjectSummary(**row) for row in result["result"]]
    
    async def update_project(self, project_id: UUID, updates: Dict[str, Any]) -> Optional[Project]:
        """Update a project"""
        set_clauses = []
        params = []
        param_count = 1
        
        for key, value in updates.items():
            if key in ["name", "description", "target_domain", "status"]:
                set_clauses.append(f"{key} = ${param_count}")
                params.append(value)
                param_count += 1
        
        if not set_clauses:
            return None
        
        query = f"""
        UPDATE projects 
        SET {', '.join(set_clauses)}, updated_at = NOW()
        WHERE id = ${param_count}
        RETURNING *
        """
        params.append(str(project_id))
        
        result = await self._execute_query(query, {"params": params})
        if result["result"]:
            return Project(**result["result"][0])
        return None
    
    # Asset Operations
    async def create_asset(self, asset: AssetCreate) -> Asset:
        """Create a new asset"""
        query = """
        INSERT INTO assets (project_id, type, value, status, metadata)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """
        params = [
            str(asset.project_id), 
            asset.type.value, 
            asset.value, 
            asset.status.value,
            json.dumps(asset.metadata)
        ]
        
        result = await self._execute_query(query, {"params": params})
        return Asset(**result["result"][0])
    
    async def get_asset(self, asset_id: UUID) -> Optional[Asset]:
        """Get an asset by ID"""
        query = "SELECT * FROM assets WHERE id = $1"
        result = await self._execute_query(query, {"params": [str(asset_id)]})
        
        if result["result"]:
            return Asset(**result["result"][0])
        return None
    
    async def list_assets(self, project_id: Optional[UUID] = None, asset_type: Optional[str] = None) -> List[Asset]:
        """List assets with optional filtering"""
        query = "SELECT * FROM assets WHERE 1=1"
        params = []
        param_count = 1
        
        if project_id:
            query += f" AND project_id = ${param_count}"
            params.append(str(project_id))
            param_count += 1
        
        if asset_type:
            query += f" AND type = ${param_count}"
            params.append(asset_type)
            param_count += 1
        
        query += " ORDER BY discovered_at DESC"
        
        result = await self._execute_query(query, {"params": params})
        return [Asset(**row) for row in result["result"]]
    
    # Scan Operations
    async def create_scan(self, scan: ScanCreate) -> Scan:
        """Create a new scan"""
        query = """
        INSERT INTO scans (project_id, asset_id, scan_type, status, configuration, results)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        """
        params = [
            str(scan.project_id),
            str(scan.asset_id),
            scan.scan_type.value,
            scan.status.value,
            json.dumps(scan.configuration),
            json.dumps(scan.results)
        ]
        
        result = await self._execute_query(query, {"params": params})
        return Scan(**result["result"][0])
    
    async def update_scan_status(self, scan_id: UUID, status: str, results: Optional[Dict[str, Any]] = None, error_message: Optional[str] = None) -> Optional[Scan]:
        """Update scan status and results"""
        query = """
        UPDATE scans 
        SET status = $1, results = $2, error_message = $3, completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN NOW() ELSE completed_at END
        WHERE id = $4
        RETURNING *
        """
        params = [
            status,
            json.dumps(results or {}),
            error_message,
            str(scan_id)
        ]
        
        result = await self._execute_query(query, {"params": params})
        if result["result"]:
            return Scan(**result["result"][0])
        return None
    
    async def get_scan(self, scan_id: UUID) -> Optional[Scan]:
        """Get a scan by ID"""
        query = "SELECT * FROM scans WHERE id = $1"
        result = await self._execute_query(query, {"params": [str(scan_id)]})
        
        if result["result"]:
            return Scan(**result["result"][0])
        return None
    
    async def list_scans(self, project_id: Optional[UUID] = None, asset_id: Optional[UUID] = None) -> List[Scan]:
        """List scans with optional filtering"""
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        param_count = 1
        
        if project_id:
            query += f" AND project_id = ${param_count}"
            params.append(str(project_id))
            param_count += 1
        
        if asset_id:
            query += f" AND asset_id = ${param_count}"
            params.append(str(asset_id))
            param_count += 1
        
        query += " ORDER BY started_at DESC"
        
        result = await self._execute_query(query, {"params": params})
        return [Scan(**row) for row in result["result"]]
    
    # Service Operations
    async def create_service(self, service: ServiceCreate) -> Service:
        """Create a new service"""
        query = """
        INSERT INTO services (asset_id, port, protocol, service_name, banner)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """
        params = [
            str(service.asset_id),
            service.port,
            service.protocol,
            service.service_name,
            service.banner
        ]
        
        result = await self._execute_query(query, {"params": params})
        return Service(**result["result"][0])
    
    async def list_services(self, asset_id: Optional[UUID] = None) -> List[Service]:
        """List services with optional filtering"""
        query = "SELECT * FROM services WHERE 1=1"
        params = []
        param_count = 1
        
        if asset_id:
            query += f" AND asset_id = ${param_count}"
            params.append(str(asset_id))
            param_count += 1
        
        query += " ORDER BY port ASC"
        
        result = await self._execute_query(query, {"params": params})
        return [Service(**row) for row in result["result"]]
    
    # Web Endpoint Operations
    async def create_web_endpoint(self, endpoint: WebEndpointCreate) -> WebEndpoint:
        """Create a new web endpoint"""
        query = """
        INSERT INTO web_endpoints (asset_id, path, method, status_code, content_length, content_type, title, headers)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        """
        params = [
            str(endpoint.asset_id),
            endpoint.path,
            endpoint.method,
            endpoint.status_code,
            endpoint.content_length,
            endpoint.content_type,
            endpoint.title,
            json.dumps(endpoint.headers)
        ]
        
        result = await self._execute_query(query, {"params": params})
        return WebEndpoint(**result["result"][0])
    
    async def list_web_endpoints(self, asset_id: Optional[UUID] = None) -> List[WebEndpoint]:
        """List web endpoints with optional filtering"""
        query = "SELECT * FROM web_endpoints WHERE 1=1"
        params = []
        param_count = 1
        
        if asset_id:
            query += f" AND asset_id = ${param_count}"
            params.append(str(asset_id))
            param_count += 1
        
        query += " ORDER BY path ASC"
        
        result = await self._execute_query(query, {"params": params})
        return [WebEndpoint(**row) for row in result["result"]]
    
    # Finding Operations
    async def create_finding(self, finding: FindingCreate) -> Finding:
        """Create a new finding"""
        query = """
        INSERT INTO findings (project_id, asset_id, scan_id, severity, category, title, description, evidence, remediation, cve_ids)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        """
        params = [
            str(finding.project_id),
            str(finding.asset_id),
            str(finding.scan_id),
            finding.severity.value,
            finding.category,
            finding.title,
            finding.description,
            json.dumps(finding.evidence),
            finding.remediation,
            finding.cve_ids
        ]
        
        result = await self._execute_query(query, {"params": params})
        return Finding(**result["result"][0])
    
    async def list_findings(self, project_id: Optional[UUID] = None, severity: Optional[str] = None) -> List[Finding]:
        """List findings with optional filtering"""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        param_count = 1
        
        if project_id:
            query += f" AND project_id = ${param_count}"
            params.append(str(project_id))
            param_count += 1
        
        if severity:
            query += f" AND severity = ${param_count}"
            params.append(severity)
            param_count += 1
        
        query += " ORDER BY severity DESC, created_at DESC"
        
        result = await self._execute_query(query, {"params": params})
        return [Finding(**row) for row in result["result"]]
    
    # Database Initialization
    async def initialize_database(self) -> bool:
        """Initialize the database with the schema"""
        try:
            # Read and execute the schema
            with open("src/database/schema.sql", "r") as f:
                schema = f.read()
            
            # Split into individual statements and execute
            statements = [stmt.strip() for stmt in schema.split(";") if stmt.strip()]
            
            for statement in statements:
                if statement:
                    await self._execute_query(statement)
            
            return True
        except Exception as e:
            print(f"Database initialization failed: {e}")
            return False
    
    # Utility Methods
    async def get_project_summary(self, project_id: UUID) -> Optional[ProjectResponse]:
        """Get a project with summary statistics"""
        project = await self.get_project(project_id)
        if not project:
            return None
        
        assets = await self.list_assets(project_id=project_id)
        scans = await self.list_scans(project_id=project_id)
        findings = await self.list_findings(project_id=project_id)
        
        return ProjectResponse(
            **project.model_dump(),
            assets_count=len(assets),
            scans_count=len(scans),
            findings_count=len(findings)
        )
    
    async def get_asset_details(self, asset_id: UUID) -> Optional[AssetResponse]:
        """Get an asset with all associated data"""
        asset = await self.get_asset(asset_id)
        if not asset:
            return None
        
        scans = await self.list_scans(asset_id=asset_id)
        services = await self.list_services(asset_id=asset_id)
        web_endpoints = await self.list_web_endpoints(asset_id=asset_id)
        findings = await self.list_findings(project_id=asset.project_id)
        
        return AssetResponse(
            **asset.model_dump(),
            scans=scans,
            services=services,
            web_endpoints=web_endpoints,
            findings=findings
        ) 