#!/usr/bin/env python3
"""
BanzAI Test Script
Verifies all services are working correctly
"""

import asyncio
import aiohttp
import json
from datetime import datetime

class BanzAITester:
    """Test all BanzAI services"""
    
    def __init__(self):
        self.services = {
            "Port Scanner": "http://localhost:8000/health",
            "Subdomain Server": "http://localhost:8001/health", 
            "DNS Analysis": "http://localhost:8002/health",
            "Supabase MCP": "http://localhost:8003/health",
            "Directory Fuzzer": "http://localhost:8004/health"
        }
        
        self.test_targets = {
            "port_scan": "scanme.nmap.org",
            "subdomain": "google.com",
            "dns": "google.com",
            "fuzz": "http://httpbin.org"
        }
    
    async def test_service_health(self, session: aiohttp.ClientSession, name: str, url: str) -> bool:
        """Test if a service is healthy"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ {name}: {data.get('status', 'healthy')}")
                    return True
                else:
                    print(f"❌ {name}: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ {name}: {str(e)}")
            return False
    
    async def test_port_scan(self, session: aiohttp.ClientSession) -> bool:
        """Test port scanning functionality"""
        try:
            print(f"\n🔍 Testing Port Scan: {self.test_targets['port_scan']}")
            
            # Test quick scan
            async with session.post(
                "http://localhost:8000/scan/quick",
                json={"target": self.test_targets['port_scan']}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    open_ports = len(result.get("open_ports", []))
                    print(f"✅ Port scan completed: {open_ports} open ports found")
                    return True
                else:
                    print(f"❌ Port scan failed: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Port scan error: {str(e)}")
            return False
    
    async def test_subdomain_enum(self, session: aiohttp.ClientSession) -> bool:
        """Test subdomain enumeration"""
        try:
            print(f"\n🌐 Testing Subdomain Enumeration: {self.test_targets['subdomain']}")
            
            async with session.post(
                "http://localhost:8001/enumerate",
                json={"domain": self.test_targets['subdomain']}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    subdomains = len(result.get("subdomains", []))
                    print(f"✅ Subdomain enumeration completed: {subdomains} subdomains found")
                    return True
                else:
                    print(f"❌ Subdomain enumeration failed: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Subdomain enumeration error: {str(e)}")
            return False
    
    async def test_dns_analysis(self, session: aiohttp.ClientSession) -> bool:
        """Test DNS analysis"""
        try:
            print(f"\n🔍 Testing DNS Analysis: {self.test_targets['dns']}")
            
            async with session.post(
                "http://localhost:8002/analyze",
                json={"domain": self.test_targets['dns']}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    records = len(result.get("records", {}))
                    print(f"✅ DNS analysis completed: {records} record types found")
                    return True
                else:
                    print(f"❌ DNS analysis failed: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ DNS analysis error: {str(e)}")
            return False
    
    async def test_directory_fuzzing(self, session: aiohttp.ClientSession) -> bool:
        """Test directory fuzzing"""
        try:
            print(f"\n📁 Testing Directory Fuzzing: {self.test_targets['fuzz']}")
            
            async with session.post(
                "http://localhost:8004/fuzz/quick",
                json={"target": self.test_targets['fuzz']}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    paths = len(result.get("discovered_paths", []))
                    print(f"✅ Directory fuzzing completed: {paths} paths found")
                    return True
                else:
                    print(f"❌ Directory fuzzing failed: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Directory fuzzing error: {str(e)}")
            return False
    
    async def test_database_operations(self, session: aiohttp.ClientSession) -> bool:
        """Test database operations"""
        try:
            print(f"\n🗄️ Testing Database Operations")
            
            # Test creating a project
            async with session.post(
                "http://localhost:8003/query",
                json={
                    "query": "INSERT INTO projects (name, description, target_domain) VALUES ($1, $2, $3) RETURNING *",
                    "params": ["Test Project", "Test Description", "test.com"]
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"✅ Database write test passed")
                    
                    # Test reading projects
                    async with session.post(
                        "http://localhost:8003/query",
                        json={
                            "query": "SELECT * FROM projects WHERE name = $1",
                            "params": ["Test Project"]
                        }
                    ) as read_response:
                        if read_response.status == 200:
                            read_result = await read_response.json()
                            print(f"✅ Database read test passed")
                            return True
                        else:
                            print(f"❌ Database read test failed")
                            return False
                else:
                    print(f"❌ Database write test failed: HTTP {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Database test error: {str(e)}")
            return False
    
    async def run_all_tests(self):
        """Run all tests"""
        print("🚀 BanzAI Service Test Suite")
        print("=" * 50)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        async with aiohttp.ClientSession() as session:
            # Test service health
            print("\n🏥 Testing Service Health:")
            health_results = []
            for name, url in self.services.items():
                result = await self.test_service_health(session, name, url)
                health_results.append(result)
            
            # Test functionality
            print("\n🧪 Testing Functionality:")
            func_results = []
            
            func_results.append(await self.test_port_scan(session))
            func_results.append(await self.test_subdomain_enum(session))
            func_results.append(await self.test_dns_analysis(session))
            func_results.append(await self.test_directory_fuzzing(session))
            func_results.append(await self.test_database_operations(session))
            
            # Summary
            print("\n" + "=" * 50)
            print("📊 Test Summary:")
            print(f"Service Health: {sum(health_results)}/{len(health_results)} services healthy")
            print(f"Functionality: {sum(func_results)}/{len(func_results)} tests passed")
            
            if all(health_results) and all(func_results):
                print("🎉 All tests passed! BanzAI is ready to use.")
                return True
            else:
                print("⚠️  Some tests failed. Check the logs above for details.")
                return False

async def main():
    """Main test function"""
    tester = BanzAITester()
    success = await tester.run_all_tests()
    
    if success:
        print("\n🚀 Ready to start reconnaissance!")
        print("Try: python src/cli_main.py recon example.com 'Test Project'")
    else:
        print("\n❌ Please fix the failing services before proceeding.")
    
    return success

if __name__ == "__main__":
    asyncio.run(main()) 