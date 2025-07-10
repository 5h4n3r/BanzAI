#!/usr/bin/env python3
"""
Supabase MCP Server Wrapper
Provides HTTP API access to the Supabase MCP server
"""

import asyncio
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class SupabaseMCPWrapper:
    def __init__(self):
        self.project_ref = os.getenv("SUPABASE_PROJECT_REF")
        self.access_token = os.getenv("SUPABASE_ACCESS_TOKEN")
        
        if not self.project_ref or not self.access_token:
            raise ValueError("SUPABASE_PROJECT_REF and SUPABASE_ACCESS_TOKEN must be set")
    
    async def call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Supabase MCP tool via stdio."""
        try:
            # Start the MCP server process
            cmd = [
                "/app/node_modules/.bin/mcp-server-supabase",
                "--project-ref", self.project_ref,
                "--access-token", self.access_token
            ]
            print(f"[DEBUG] Running MCP server command: {' '.join(cmd)}", file=sys.stderr)
            
            # Create input for the MCP server
            # Initialize MCP connection first
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "roots": {"listChanged": True},
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "banzai-mcp-wrapper",
                        "version": "1.0.0"
                    }
                }
            }
            
            # Send tool call request
            tool_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            
            # Combine both requests
            input_data = json.dumps(init_request) + "\n" + json.dumps(tool_request) + "\n"
            print(f"[DEBUG] Sending: {input_data}", file=sys.stderr)
            
            # Use subprocess.run for simpler handling
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                env={"SUPABASE_ACCESS_TOKEN": self.access_token}
            )
            
            print(f"[DEBUG] Return code: {result.returncode}", file=sys.stderr)
            print(f"[DEBUG] Stdout: {result.stdout}", file=sys.stderr)
            print(f"[DEBUG] Stderr: {result.stderr}", file=sys.stderr)
            
            if result.returncode != 0:
                raise Exception(f"MCP server error (code {result.returncode}): {result.stderr}")
            
            # Parse responses - should get two JSON responses
            responses = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        responses.append(json.loads(line.strip()))
                    except json.JSONDecodeError as e:
                        print(f"[DEBUG] Failed to parse line: {line}", file=sys.stderr)
                        continue
            
            print(f"[DEBUG] Parsed {len(responses)} responses", file=sys.stderr)
            
            # Return the tool response (should be the second one)
            if len(responses) >= 2:
                return responses[1]  # Tool response
            elif len(responses) == 1:
                return responses[0]  # Maybe only got one response
            else:
                raise Exception("No valid JSON responses from MCP server")
            
        except Exception as e:
            print(f"[DEBUG] Exception in call_mcp_tool: {e}", file=sys.stderr)
            raise Exception(f"Failed to call MCP tool: {str(e)}")

# Initialize wrapper
try:
    mcp_wrapper = SupabaseMCPWrapper()
except Exception as e:
    print(f"Warning: Supabase MCP wrapper not initialized: {e}", file=sys.stderr)
    mcp_wrapper = None

class QueryRequest(BaseModel):
    query: str
    params: Optional[Dict[str, Any]] = None

class TableRequest(BaseModel):
    table: str
    operation: str = "select"  # select, insert, update, delete
    data: Optional[Dict[str, Any]] = None
    filters: Optional[Dict[str, Any]] = None

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "wrapper_initialized": mcp_wrapper is not None}

@app.get("/debug")
async def debug_info():
    """Debug endpoint to show configuration and test MCP server."""
    debug_info = {
        "project_ref": mcp_wrapper.project_ref if mcp_wrapper else None,
        "access_token_set": bool(mcp_wrapper.access_token if mcp_wrapper else None),
        "wrapper_initialized": mcp_wrapper is not None
    }
    
    if mcp_wrapper:
        try:
            # Test a simple list_tables call
            result = await mcp_wrapper.call_mcp_tool("list_tables", {})
            debug_info["mcp_test_query"] = "success"
            debug_info["mcp_response"] = result
        except Exception as e:
            debug_info["mcp_test_query"] = "failed"
            debug_info["mcp_error"] = str(e)
    
    return debug_info

@app.post("/query")
async def execute_query(request: QueryRequest):
    """Execute a raw SQL query using the execute_sql tool."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        result = await mcp_wrapper.call_mcp_tool("execute_sql", {
            "query": request.query
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/table/{table_name}")
async def table_operation(table_name: str, request: TableRequest):
    """Perform table operations using execute_sql tool."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        if request.operation == "select":
            # Build SELECT query
            where_clause = ""
            if request.filters:
                conditions = []
                for key, value in request.filters.items():
                    if isinstance(value, str):
                        conditions.append(f"{key} = '{value}'")
                    else:
                        conditions.append(f"{key} = {value}")
                where_clause = " WHERE " + " AND ".join(conditions)
            
            sql = f"SELECT * FROM {table_name}{where_clause}"
            
        elif request.operation == "insert":
            if not request.data:
                raise HTTPException(status_code=400, detail="Data required for insert")
            
            columns = ", ".join(request.data.keys())
            values = []
            for value in request.data.values():
                if isinstance(value, str):
                    values.append(f"'{value}'")
                else:
                    values.append(str(value))
            values_str = ", ".join(values)
            sql = f"INSERT INTO {table_name} ({columns}) VALUES ({values_str}) RETURNING *"
            
        else:
            raise HTTPException(status_code=400, detail=f"Operation {request.operation} not supported")
        
        result = await mcp_wrapper.call_mcp_tool("execute_sql", {"query": sql})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tables")
async def list_tables():
    """List all tables using the list_tables tool."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        result = await mcp_wrapper.call_mcp_tool("list_tables", {})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/initialize")
async def initialize_database():
    """Initialize the database schema using execute_sql tool."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    # Split the schema into individual statements
    schema_statements = [
        # Projects table
        """CREATE TABLE IF NOT EXISTS projects (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            target_domain TEXT,
            status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived', 'on_hold')),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )""",
        
        # Assets table
        """CREATE TABLE IF NOT EXISTS assets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            type TEXT NOT NULL CHECK (type IN ('domain', 'subdomain', 'ip', 'url')),
            value TEXT NOT NULL,
            status TEXT DEFAULT 'discovered' CHECK (status IN ('discovered', 'verified', 'scanned', 'error')),
            metadata JSONB DEFAULT '{}',
            discovered_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(project_id, type, value)
        )""",
        
        # Scans table
        """CREATE TABLE IF NOT EXISTS scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
            scan_type TEXT NOT NULL CHECK (scan_type IN ('port_scan', 'subdomain_enum', 'dns_analysis', 'dir_fuzz')),
            status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
            configuration JSONB DEFAULT '{}',
            results JSONB DEFAULT '{}',
            started_at TIMESTAMPTZ DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )""",
        
        # Services table
        """CREATE TABLE IF NOT EXISTS services (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
            service_name TEXT,
            version TEXT,
            banner TEXT,
            state TEXT DEFAULT 'open' CHECK (state IN ('open', 'closed', 'filtered')),
            confidence INTEGER DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 100),
            discovered_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(asset_id, port, protocol)
        )""",
        
        # Web endpoints table
        """CREATE TABLE IF NOT EXISTS web_endpoints (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
            path TEXT NOT NULL,
            method TEXT DEFAULT 'GET' CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')),
            status_code INTEGER,
            content_length INTEGER,
            content_type TEXT,
            title TEXT,
            discovered_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(asset_id, path, method)
        )""",
        
        # Findings table
        """CREATE TABLE IF NOT EXISTS findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
            scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
            category TEXT NOT NULL CHECK (category IN ('info', 'low', 'medium', 'high', 'critical')),
            title TEXT NOT NULL,
            description TEXT,
            evidence JSONB DEFAULT '{}',
            remediation TEXT,
            status TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false_positive', 'resolved')),
            discovered_at TIMESTAMPTZ DEFAULT NOW()
        )""",
        
        # Create indexes
        "CREATE INDEX IF NOT EXISTS idx_assets_project_id ON assets(project_id)",
        "CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type)",
        "CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id)",
        "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
        "CREATE INDEX IF NOT EXISTS idx_services_asset_id ON services(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_web_endpoints_asset_id ON web_endpoints(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_project_id ON findings(project_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
        
        # Update trigger function
        """CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql'""",
        
        # Create trigger
        """DROP TRIGGER IF EXISTS update_projects_updated_at ON projects;
        CREATE TRIGGER update_projects_updated_at 
            BEFORE UPDATE ON projects 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()"""
    ]
    
    results = []
    for i, statement in enumerate(schema_statements):
        try:
            result = await mcp_wrapper.call_mcp_tool("execute_sql", {
                "query": statement
            })
            results.append({"statement": i+1, "success": True, "result": result})
        except Exception as e:
            results.append({"statement": i+1, "success": False, "error": str(e)})
    
    return {
        "message": "Database initialization completed",
        "results": results
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003) 