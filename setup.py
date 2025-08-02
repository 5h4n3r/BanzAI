#!/usr/bin/env python3
"""
BanzAI Setup Script
Helps users get BanzAI running quickly
"""

import os
import sys
import subprocess
import asyncio
import aiohttp
from pathlib import Path

class BanzAISetup:
    """Setup helper for BanzAI"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.env_file = self.project_root / ".env"
        self.docker_compose_file = self.project_root / "docker-compose.yml"
    
    def check_prerequisites(self):
        """Check if prerequisites are installed"""
        print("🔍 Checking prerequisites...")
        
        # Check Docker
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Docker is installed")
            else:
                print("❌ Docker is not installed or not accessible")
                return False
        except FileNotFoundError:
            print("❌ Docker is not installed")
            return False
        
        # Check Docker Compose
        try:
            result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Docker Compose is installed")
            else:
                print("❌ Docker Compose is not installed or not accessible")
                return False
        except FileNotFoundError:
            print("❌ Docker Compose is not installed")
            return False
        
        # Check Python
        if sys.version_info >= (3, 8):
            print("✅ Python 3.8+ is installed")
        else:
            print("❌ Python 3.8+ is required")
            return False
        
        return True
    
    def setup_environment(self):
        """Setup environment variables"""
        print("\n🔧 Setting up environment...")
        
        if self.env_file.exists():
            print("✅ .env file already exists")
            return True
        
        print("📝 Creating .env file...")
        
        # Get Supabase credentials
        print("\n🔑 Supabase Configuration Required:")
        print("You need to create a Supabase project and get your credentials.")
        print("Visit: https://supabase.com")
        
        supabase_url = input("Enter your Supabase Project URL: ").strip()
        service_role_key = input("Enter your Supabase Service Role Key: ").strip()
        
        if not supabase_url or not service_role_key:
            print("❌ Supabase credentials are required")
            return False
        
        # Create .env file
        env_content = f"""# BanzAI Environment Configuration
SUPABASE_URL={supabase_url}
SUPABASE_SERVICE_ROLE_KEY={service_role_key}

# Optional: Override default ports
# PORT_SCANNER_PORT=8000
# SUBDOMAIN_SERVER_PORT=8001
# DNS_ANALYSIS_PORT=8002
# SUPABASE_MCP_PORT=8003
# DIRECTORY_FUZZER_PORT=8004
"""
        
        try:
            with open(self.env_file, 'w') as f:
                f.write(env_content)
            print("✅ .env file created successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
            return False
    
    def build_services(self):
        """Build Docker services"""
        print("\n🏗️ Building Docker services...")
        
        try:
            result = subprocess.run(
                ["docker-compose", "build"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("✅ Docker services built successfully")
                return True
            else:
                print(f"❌ Failed to build services: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Build error: {e}")
            return False
    
    def start_services(self):
        """Start all services"""
        print("\n🚀 Starting BanzAI services...")
        
        try:
            # Start services in background
            process = subprocess.Popen(
                ["docker-compose", "up", "-d"],
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                print("✅ Services started successfully")
                return True
            else:
                print(f"❌ Failed to start services: {stderr}")
                return False
        except Exception as e:
            print(f"❌ Start error: {e}")
            return False
    
    async def wait_for_services(self, timeout: int = 60):
        """Wait for services to be ready"""
        print(f"\n⏳ Waiting for services to be ready (timeout: {timeout}s)...")
        
        services = {
            "Port Scanner API": "http://localhost:8000/health",
            "Subdomain API": "http://localhost:8001/health",
            "DNS Analysis API": "http://localhost:8002/health", 
            "Supabase API": "http://localhost:8003/health",
            "Directory Fuzzer API": "http://localhost:8004/health"
        }
        
        ready_services = set()
        start_time = asyncio.get_event_loop().time()
        
        async with aiohttp.ClientSession() as session:
            while len(ready_services) < len(services):
                if asyncio.get_event_loop().time() - start_time > timeout:
                    print(f"❌ Timeout waiting for services. Ready: {len(ready_services)}/{len(services)}")
                    return False
                
                for name, url in services.items():
                    if name in ready_services:
                        continue
                    
                    try:
                        async with session.get(url, timeout=5) as response:
                            if response.status == 200:
                                ready_services.add(name)
                                print(f"✅ {name} is ready")
                    except:
                        pass
                
                if len(ready_services) < len(services):
                    await asyncio.sleep(2)
        
        print("✅ All services are ready!")
        return True
    
    def run_tests(self):
        """Run the test suite"""
        print("\n🧪 Running test suite...")
        
        try:
            result = subprocess.run(
                [sys.executable, "test_banzai.py"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            print(result.stdout)
            if result.stderr:
                print(f"Warnings: {result.stderr}")
            
            return result.returncode == 0
        except FileNotFoundError:
            print("⚠️  No test file found, skipping tests")
            return True
        except Exception as e:
            print(f"❌ Test error: {e}")
            return False
    
    def show_next_steps(self):
        """Show next steps for the user"""
        print("\n" + "=" * 60)
        print("🎉 BanzAI Setup Complete!")
        print("=" * 60)
        
        print("\n📖 Next Steps:")
        print("1. Read the documentation: README.md")
        print("2. Try the CLI: python src/cli_main.py --help")
        print("3. Configure Claude Desktop: Copy claude_desktop_config.example to your Claude config")
        print("4. Start reconnaissance: python src/cli_main.py recon example.com 'My Project'")
        
        print("\n🔧 Useful Commands:")
        print("  # View service logs")
        print("  docker-compose logs -f")
        print("")
        print("  # Stop services")
        print("  docker-compose down")
        print("")
        print("  # Restart services")
        print("  docker-compose restart")
        print("")
        print("  # Update services")
        print("  docker-compose pull && docker-compose up -d")
        
        print("\n🌐 Service URLs:")
        print("  Port Scanner API:     http://localhost:8000")
        print("  Subdomain API:        http://localhost:8001")
        print("  DNS Analysis API:     http://localhost:8002")
        print("  Supabase API:         http://localhost:8003")
        print("  Directory Fuzzer API: http://localhost:8004")
        
        print("\n📚 Documentation:")
        print("  - README.md: Complete documentation")
        print("  - src/cli_main.py: CLI usage examples")
        print("  - mcp_servers/: Individual service documentation")
        print("  - MCP_INTEGRATION.md: Claude Desktop integration guide")
        
        print("\n🚀 Happy Hacking!")

async def main():
    """Main setup function"""
    setup = BanzAISetup()
    
    print("🚀 BanzAI Setup Wizard")
    print("=" * 40)
    
    # Check prerequisites
    if not setup.check_prerequisites():
        print("\n❌ Prerequisites not met. Please install the required software.")
        sys.exit(1)
    
    # Setup environment
    if not setup.setup_environment():
        print("\n❌ Environment setup failed.")
        sys.exit(1)
    
    # Build services
    if not setup.build_services():
        print("\n❌ Service build failed.")
        sys.exit(1)
    
    # Start services
    if not setup.start_services():
        print("\n❌ Service startup failed.")
        sys.exit(1)
    
    # Wait for services
    if not await setup.wait_for_services():
        print("\n❌ Services failed to start properly.")
        sys.exit(1)
    
    # Run tests
    if not setup.run_tests():
        print("\n⚠️  Some tests failed, but setup may still be functional.")
    
    # Show next steps
    setup.show_next_steps()

if __name__ == "__main__":
    asyncio.run(main()) 