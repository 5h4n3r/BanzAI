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
    
    async def call_mcp_server(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call the Supabase MCP server via stdio."""
        try:
            # Start the MCP server process
            cmd = [
                "/app/node_modules/.bin/mcp-server-supabase",
                "--project-ref", self.project_ref
            ]
            print(f"[DEBUG] Running MCP server command: {' '.join(cmd)}", file=sys.stderr)
            
            # Send MCP request
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            }
            
            stdin_data = json.dumps(request) + "\n"
            
            # Use subprocess.run instead of asyncio for better stdio handling
            import subprocess
            result = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True,
                text=True,
                env={"SUPABASE_ACCESS_TOKEN": self.access_token}
            )
            
            if result.returncode != 0:
                print(f"[DEBUG] MCP server stderr: {result.stderr}", file=sys.stderr)
                raise Exception(f"MCP server error: {result.stderr}")
            
            # Parse response
            response = json.loads(result.stdout.strip())
            return response
            
        except Exception as e:
            print(f"[DEBUG] Exception in call_mcp_server: {e}", file=sys.stderr)
            raise Exception(f"Failed to call MCP server: {str(e)}")

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
    return {"status": "healthy", "supabase_configured": mcp_wrapper is not None}

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
            # Test a simple query
            result = await mcp_wrapper.call_mcp_server("sql/query", {
                "query": "SELECT 1 as test",
                "params": {}
            })
            debug_info["mcp_test_query"] = "success"
            debug_info["mcp_response"] = result
        except Exception as e:
            debug_info["mcp_test_query"] = "failed"
            debug_info["mcp_error"] = str(e)
    
    return debug_info

@app.post("/query")
async def execute_query(request: QueryRequest):
    """Execute a raw SQL query."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        result = await mcp_wrapper.call_mcp_server("sql/query", {
            "query": request.query,
            "params": request.params or {}
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/table/{table_name}")
async def table_operation(table_name: str, request: TableRequest):
    """Perform table operations."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        if request.operation == "select":
            result = await mcp_wrapper.call_mcp_server("sql/query", {
                "query": f"SELECT * FROM {table_name}",
                "params": request.filters or {}
            })
        elif request.operation == "insert":
            if not request.data:
                raise HTTPException(status_code=400, detail="Data required for insert")
            
            columns = ", ".join(request.data.keys())
            values = ", ".join([f"${i+1}" for i in range(len(request.data))])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({values}) RETURNING *"
            
            result = await mcp_wrapper.call_mcp_server("sql/query", {
                "query": query,
                "params": list(request.data.values())
            })
        else:
            raise HTTPException(status_code=400, detail=f"Operation {request.operation} not supported")
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tables")
async def list_tables():
    """List all tables in the database."""
    if not mcp_wrapper:
        raise HTTPException(status_code=500, detail="Supabase MCP wrapper not configured")
    
    try:
        result = await mcp_wrapper.call_mcp_server("sql/query", {
            "query": "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
            "params": {}
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003) 