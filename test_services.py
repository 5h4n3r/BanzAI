#!/usr/bin/env python3
"""
Test script for BanzAI services
"""

import asyncio
import aiohttp
import json

async def test_health():
    """Test health endpoints."""
    async with aiohttp.ClientSession() as session:
        # Test Supabase MCP wrapper health
        async with session.get("http://localhost:8003/health") as resp:
            print(f"✅ Supabase Health: {await resp.json()}")
        
        # Test scan server health
        async with session.get("http://localhost:8000/docs") as resp:
            print(f"✅ Scan Server: {resp.status}")
        
        # Test subdomain server health
        async with session.get("http://localhost:8001/docs") as resp:
            print(f"✅ Subdomain Server: {resp.status}")
        
        # Test DNS server health
        async with session.get("http://localhost:8002/docs") as resp:
            print(f"✅ DNS Server: {resp.status}")

async def test_scan_server():
    """Test scan server functionality."""
    async with aiohttp.ClientSession() as session:
        try:
            data = {"target": "127.0.0.1", "ports": "1-100"}
            async with session.post("http://localhost:8000/scan", json=data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Scan Server Test: {result}")
                else:
                    error = await resp.text()
                    print(f"❌ Scan Server Error: {error}")
        except Exception as e:
            print(f"❌ Scan Server Exception: {e}")

async def test_subdomain_server():
    """Test subdomain server functionality."""
    async with aiohttp.ClientSession() as session:
        try:
            data = {"domain": "example.com"}
            async with session.post("http://localhost:8001/enumerate", json=data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Subdomain Server Test: {result}")
                else:
                    error = await resp.text()
                    print(f"❌ Subdomain Server Error: {error}")
        except Exception as e:
            print(f"❌ Subdomain Server Exception: {e}")

async def test_dns_server():
    """Test DNS server functionality."""
    async with aiohttp.ClientSession() as session:
        try:
            data = {"domain": "example.com"}
            async with session.post("http://localhost:8002/analyze", json=data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ DNS Server Test: {result}")
                else:
                    error = await resp.text()
                    print(f"❌ DNS Server Error: {error}")
        except Exception as e:
            print(f"❌ DNS Server Exception: {e}")

async def test_supabase_mcp():
    """Test Supabase MCP functionality."""
    async with aiohttp.ClientSession() as session:
        try:
            # Test tables endpoint
            async with session.get("http://localhost:8003/tables") as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"✅ Supabase Tables: {result}")
                else:
                    error = await resp.text()
                    print(f"❌ Supabase Tables Error: {error}")
        except Exception as e:
            print(f"❌ Supabase MCP Exception: {e}")

async def main():
    """Run all tests."""
    print("🚀 Testing BanzAI Services...")
    print("=" * 50)
    
    await test_health()
    print()
    
    await test_scan_server()
    print()
    
    await test_subdomain_server()
    print()
    
    await test_dns_server()
    print()
    
    await test_supabase_mcp()
    print()
    
    print("🏁 Testing complete!")

if __name__ == "__main__":
    asyncio.run(main()) 