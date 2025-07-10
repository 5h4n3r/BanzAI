import os
import aiohttp
from typing import Dict, Any, Optional
from src.database.models import Project, Asset, ScanResult, Finding

SUPABASE_MCP_URL = os.getenv("SUPABASE_MCP_URL", "http://localhost:8003")

class SupabaseMCPClient:
    def __init__(self, base_url: str = SUPABASE_MCP_URL):
        self.base_url = base_url.rstrip("/")

    async def _make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make HTTP request to our Supabase MCP wrapper."""
        url = f"{self.base_url}{endpoint}"
        async with aiohttp.ClientSession() as session:
            if method.upper() == "GET":
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            else:
                async with session.post(url, json=data or {}) as resp:
                    resp.raise_for_status()
                    return await resp.json()

    async def health_check(self) -> Dict[str, Any]:
        """Check if the Supabase MCP wrapper is healthy."""
        return await self._make_request("GET", "/health")

    async def list_tables(self) -> Dict[str, Any]:
        """List all tables in the database."""
        return await self._make_request("GET", "/tables")

    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a raw SQL query."""
        return await self._make_request("POST", "/query", {
            "query": query,
            "params": params or {}
        })

    async def table_operation(self, table: str, operation: str, data: Optional[Dict[str, Any]] = None, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform table operations."""
        return await self._make_request("POST", f"/table/{table}", {
            "operation": operation,
            "data": data,
            "filters": filters
        })

    # Domain-specific wrappers
    async def create_project(self, project: Project) -> Dict[str, Any]:
        """Create a new project."""
        data = project.dict(exclude_unset=True, exclude={'id'})
        return await self.table_operation("projects", "insert", data=data)

    async def create_asset(self, asset: Asset) -> Dict[str, Any]:
        """Create a new asset."""
        data = asset.dict(exclude_unset=True, exclude={'id'})
        return await self.table_operation("assets", "insert", data=data)

    async def create_scan(self, scan: ScanResult) -> Dict[str, Any]:
        """Create a new scan."""
        data = scan.dict(exclude_unset=True, exclude={'id'})
        return await self.table_operation("scans", "insert", data=data)

    async def create_finding(self, finding: Finding) -> Dict[str, Any]:
        """Create a new finding."""
        data = finding.dict(exclude_unset=True, exclude={'id'})
        return await self.table_operation("findings", "insert", data=data)

    async def list_projects(self) -> Dict[str, Any]:
        """List all projects."""
        return await self.table_operation("projects", "select")

    async def list_assets(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """List assets, optionally filtered by project."""
        filters = {"project_id": project_id} if project_id else {}
        return await self.table_operation("assets", "select", filters=filters)

    async def list_scans(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """List scans, optionally filtered by project."""
        filters = {"project_id": project_id} if project_id else {}
        return await self.table_operation("scans", "select", filters=filters)

    async def list_findings(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """List findings, optionally filtered by project."""
        filters = {"project_id": project_id} if project_id else {}
        return await self.table_operation("findings", "select", filters=filters) 