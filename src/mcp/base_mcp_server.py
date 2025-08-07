#!/usr/bin/env python3
"""
Base MCP Server Implementation
Provides common functionality for all BanzAI MCP servers
"""

import asyncio
import json
import sys
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseMCPServer(ABC):
    """Abstract base class for all BanzAI MCP servers"""
    
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.request_timeout = 600  # 10 minutes timeout for individual operations
        self.initialized = False
        
    @abstractmethod
    async def get_tools(self) -> List[Dict[str, Any]]:
        """Return list of available tools"""
        pass
    
    @abstractmethod
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with given arguments"""
        pass
    
    async def get_resources(self) -> List[Dict[str, Any]]:
        """Return list of available resources (optional)"""
        return []
    
    async def get_prompts(self) -> List[Dict[str, Any]]:
        """Return list of available prompts (optional)"""
        return []
    
    async def handle_initialize(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialization request"""
        try:
            self.initialized = True
            return {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": self.name,
                    "version": self.version
                }
            }
        except Exception as e:
            return {"error": f"Initialization failed: {str(e)}"}
    
    async def handle_tools_list(self) -> Dict[str, Any]:
        """Handle tools/list request with timeout"""
        try:
            tools = await asyncio.wait_for(
                self.get_tools(),
                timeout=self.request_timeout
            )
            return {"tools": tools}
        except asyncio.TimeoutError:
            return {"error": "Tools list request timed out"}
        except Exception as e:
            return {"error": f"Failed to list tools: {str(e)}"}
    
    async def handle_tools_call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request with timeout"""
        try:
            if not self.initialized:
                return {"error": "Server not initialized"}
                
            tool_name = request.get("name")
            arguments = request.get("arguments", {})
            
            if not tool_name:
                return {"error": "Tool name is required"}
            
            # Execute tool with timeout
            result = await asyncio.wait_for(
                self.call_tool(tool_name, arguments),
                timeout=self.request_timeout
            )
            
            # Ensure result is properly formatted for MCP
            if isinstance(result, dict):
                if "content" not in result:
                    # Wrap non-MCP formatted results
                    result = {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    }
                return result
            else:
                # Handle string or other types
                return {
                    "content": [
                        {
                            "type": "text", 
                            "text": str(result)
                        }
                    ]
                }
                
        except asyncio.TimeoutError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "success": False,
                            "error": f"Tool '{tool_name}' execution timed out after {self.request_timeout} seconds",
                            "timeout": True
                        }, indent=2)
                    }
                ]
            }
        except Exception as e:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "success": False,
                            "error": str(e)
                        }, indent=2)
                    }
                ]
            }
    
    async def handle_resources_list(self) -> Dict[str, Any]:
        """Handle resources/list request with timeout"""
        try:
            resources = await asyncio.wait_for(
                self.get_resources(),
                timeout=10  # Shorter timeout for resource listing
            )
            return {"resources": resources}
        except asyncio.TimeoutError:
            return {"error": "Resources list request timed out"}
        except Exception as e:
            return {"error": f"Failed to list resources: {str(e)}"}
    
    async def handle_prompts_list(self) -> Dict[str, Any]:
        """Handle prompts/list request with timeout"""
        try:
            prompts = await asyncio.wait_for(
                self.get_prompts(),
                timeout=10  # Shorter timeout for prompt listing
            )
            return {"prompts": prompts}
        except asyncio.TimeoutError:
            return {"error": "Prompts list request timed out"}
        except Exception as e:
            return {"error": f"Failed to list prompts: {str(e)}"}
    
    async def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process an incoming MCP request with comprehensive error handling"""
        try:
            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")
            
            if method == "initialize":
                result = await self.handle_initialize(params)
            elif method == "tools/list":
                result = await self.handle_tools_list()
            elif method == "tools/call":
                result = await self.handle_tools_call(params)
            elif method == "resources/list":
                result = await self.handle_resources_list()
            elif method == "prompts/list":
                result = await self.handle_prompts_list()
            elif method == "notifications/initialized":
                # Handle initialization notification
                return None  # No response needed for notifications
            else:
                result = {"error": f"Unknown method: {method}"}
            
            # Format response according to JSON-RPC 2.0
            response = {
                "jsonrpc": "2.0",
                "id": request_id if request_id is not None else 0
            }
            
            if "error" in result:
                response["error"] = {
                    "code": -32603,  # Internal error
                    "message": result["error"]
                }
            else:
                response["result"] = result
                
            return response
            
        except Exception as e:
            # Fallback error response
            return {
                "jsonrpc": "2.0",
                "id": request.get("id", 0),
                "error": {
                    "code": -32603,
                    "message": f"Internal server error: {str(e)}"
                }
            }
    
    def run(self):
        """Run the MCP server with proper error handling"""
        async def handle_stdio():
            """Handle stdio communication with timeout and error recovery"""
            while True:
                try:
                    # Read line with timeout
                    line = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline),
                        timeout=300  # 5 minute timeout for reading input
                    )
                    
                    if not line:
                        break  # EOF
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse JSON request
                    try:
                        request = json.loads(line)
                    except json.JSONDecodeError as e:
                        # Send error response for malformed JSON
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": 0,
                            "error": {
                                "code": -32700,  # Parse error
                                "message": f"Parse error: {str(e)}"
                            }
                        }
                        print(json.dumps(error_response), flush=True)
                        continue
                    
                    # Process request with timeout
                    try:
                        response = await asyncio.wait_for(
                            self.process_request(request),
                            timeout=self.request_timeout + 10  # Extra buffer for processing
                        )
                        
                        if response is not None:
                            print(json.dumps(response), flush=True)
                            
                    except asyncio.TimeoutError:
                        # Send timeout error response
                        timeout_response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id", 0),
                            "error": {
                                "code": -32001,  # Server error
                                "message": "Request processing timed out"
                            }
                        }
                        print(json.dumps(timeout_response), flush=True)
                        
                    except Exception as e:
                        # Send general error response
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id", 0),
                            "error": {
                                "code": -32603,  # Internal error
                                "message": f"Internal error: {str(e)}"
                            }
                        }
                        print(json.dumps(error_response), flush=True)
                        
                except asyncio.TimeoutError:
                    # Input timeout - this is normal, just continue
                    continue
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    # Log error but continue running
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": 0,
                        "error": {
                            "code": -32603,
                            "message": f"Server error: {str(e)}"
                        }
                    }
                    print(json.dumps(error_response), flush=True)
        
        # Run the main handler
        try:
            asyncio.run(handle_stdio())
        except KeyboardInterrupt:
            pass
        except Exception as e:
            # Final fallback error
            error_response = {
                "jsonrpc": "2.0",
                "id": 0,
                "error": {
                    "code": -32603,
                    "message": f"Fatal server error: {str(e)}"
                }
            }
            print(json.dumps(error_response), flush=True) 