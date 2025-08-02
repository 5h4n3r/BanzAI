# 🚀 BanzAI - AI-Powered Penetration Testing Tool

**BanzAI** combines reconnaissance tools with AI-driven analysis through Claude Desktop integration. Built with a microservices architecture, it provides security testing capabilities with data storage.

## 🌟 Core Features

- **Port Scanning**: Advanced nmap-based scanning with SYN scan support
- **Subdomain Enumeration**: Comprehensive subdomain discovery
- **DNS Analysis**: Deep DNS reconnaissance and analysis
- **Directory Fuzzing**: Web path discovery using ffuf (in progress)
- **Data Persistence**: Supabase PostgreSQL database integration
- **Claude Desktop Integration**: AI-powered analysis and workflow automation

## 🚀 Quick Start

### Prerequisites

- **Docker Desktop** (must be running)
- **Python 3.11+** with UV package manager
- **Supabase account** and project
- **Claude Desktop** (for AI integration)

### 1. Clone and Setup

```bash
git clone <repository-url>
cd defcon
```

### 2. Install Python Dependencies

```bash
# Install UV (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

### 3. Configure Environment

Create a `.env` file in the project root:

```bash
SUPABASE_URL=your_supabase_project_url_here
SUPABASE_PROJECT_REF=your_project_ref
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_ANON_KEY=your_supabase_anon_key_here
SUPABASE_MCP_URL=http://localhost:8003
```

**Get your Supabase credentials:**
1. Go to [supabase.com](https://supabase.com) and create a project
2. Navigate to Settings → API
3. Copy your Project URL, Project Referral, Anon key and Service Role Key

### 4. Start Services

```bash
# Start all services (Docker Desktop must be running)
docker-compose up --build -d

# Verify services are running
docker-compose ps
```

### 5. Configure Claude Desktop

Create your Claude Desktop configuration file:

**On macOS:**
```bash
mkdir -p ~/Library/Application\ Support/Claude
```

**On Windows:**
```bash
# The config file should be in: %APPDATA%\Roaming\Claude\claude_desktop_config.json
```

**Create the config file with this content:**

**macOS config:**
```json
{
  "mcpServers": {
    "banzai-port-scanner": {
      "command": "/Users/username/Tools/BanzAI/.venv/bin/python",
      "args": ["/Users/username/Tools/BanzAI/mcp_servers/port_scanner_mcp.py"]
    },
    "banzai-supabase": {
      "command": "/Users/username/Tools/BanzAI/.venv/bin/python",
      "args": ["/Users/username/Tools/BanzAI/mcp_servers/supabase_mcp.py"]
    },
    "banzai-dns-analysis": {
      "command": "/Users/username/Tools/BanzAI/.venv/bin/python",
      "args": ["/Users/username/Tools/BanzAI/mcp_servers/dns_analysis_mcp.py"]
    },
    "banzai-subdomain": {
      "command": "/Users/username/Tools/BanzAI/.venv/bin/python",
      "args": ["/Users/username/Tools/BanzAI/mcp_servers/subdomain_mcp.py"]
    },
    "banzai-directory-fuzzer": {
      "command": "/Users/username/Tools/BanzAI/.venv/bin/python",
      "args": ["/Users/username/Tools/BanzAI/mcp_servers/directory_fuzzer_mcp.py"]
    }
  }
}
```

**Windows config:**
```json
{
  "mcpServers": {
    "banzai-port-scanner": {
      "command": "C:/Users/username/Tools/BanzAI/.venv/Scripts/python.exe",
      "args": ["C:/Users/username/Tools/BanzAI/mcp_servers/port_scanner_mcp.py"]
    },
    "banzai-supabase": {
      "command": "C:/Users/username/Tools/BanzAI/.venv/Scripts/python.exe",
      "args": ["C:/Users/username/Tools/BanzAI/mcp_servers/supabase_mcp.py"]
    },
    "banzai-dns-analysis": {
      "command": "C:/Users/username/Tools/BanzAI/.venv/Scripts/python.exe",
      "args": ["C:/Users/username/Tools/BanzAI/mcp_servers/dns_analysis_mcp.py"]
    },
    "banzai-subdomain": {
      "command": "C:/Users/username/Tools/BanzAI/.venv/Scripts/python.exe",
      "args": ["C:/Users/username/Tools/BanzAI/mcp_servers/subdomain_mcp.py"]
    },
    "banzai-directory-fuzzer": {
      "command": "C:/Users/username/Tools/BanzAI/.venv/Scripts/python.exe",
      "args": ["C:/Users/username/Tools/BanzAI/mcp_servers/directory_fuzzer_mcp.py"]
    }
  }
}
```

**Replace `username` with your actual username and adjust the project path as needed.**

### 6. Start Reconnaissance

Ask Claude to perform reconnaissance tasks:
- "Scan ports on example.com"
- "Find subdomains for example.com"
- "Analyze DNS for example.com"
- "Fuzz directories on https://example.com"

## 📖 Usage

### Claude Desktop Integration

Once configured, Claude Desktop will have access to these tools:

- **Port Scanner**: `quick_scan`, `syn_scan`, `web_scan`, `database_scan`
- **Subdomain Enumeration**: `enumerate_subdomains`
- **DNS Analysis**: `analyze_dns`
- **Directory Fuzzing**: `fuzz_directories`
- **Database Operations**: `store_scan_results`, `get_latest_scan`

**Example Claude conversation:**
```
"Perform full recon on scanme.nmap.org
"Scan the ports of example.com using a SYN scan"
"Enumerate subdomains for test.com"
"Analyze DNS records for demo.org"
"Fuzz directories on https://example.com"
```

BanzAI uses a two-layer architecture:

### HTTP API Servers (Docker Backend)
- **Port Scanner API** (`port_scanner_api.py`) - nmap-based scanning
- **Subdomain API** (`subdomain_api.py`) - subdomain enumeration
- **DNS Analysis API** (`dns_analysis_api.py`) - DNS reconnaissance
- **Directory Fuzzer API** (`directory_fuzzer_api.py`) - web path discovery
- **Supabase API** (`supabase_api.py`) - database operations

### MCP Servers (Python Adapters)
- `port_scanner_mcp.py` - Port scanning tools for Claude
- `subdomain_mcp.py` - Subdomain enumeration tools
- `dns_analysis_mcp.py` - DNS analysis tools
- `directory_fuzzer_mcp.py` - Directory fuzzing tools
- `supabase_mcp.py` - Database operations

**How it works:**
1. **Claude Desktop** → **Python MCP scripts** (on your machine)
2. **Python scripts** → **HTTP API calls** to Docker containers
3. **Docker containers** → **Perform actual scanning**
4. **Results** → **Flow back through the chain**
- `supabase_mcp.py` - Database operations

### Docker Services

The `docker-compose.yml` defines these services:
- `banzai_port_scanner_mcp` (Port 8000)
- `banzai_subdomain_mcp` (Port 8001)
- `banzai_dns_analysis_mcp` (Port 8002)
- `banzai_supabase_mcp` (Port 8003)
- `banzai_directory_fuzzer_mcp` (Port 8004)

## 🛠️ Troubleshooting

### Common Issues

**Docker services won't start:**
- Ensure Docker Desktop is running
- Verify ports 8000-8004 are not in use

**Claude Desktop can't connect:**
- Verify Python path in config is correct
- Check that MCP servers are running (`docker-compose ps`)

**Supabase connection errors:**
- Verify `.env` file exists and has correct credentials
- Check Supabase project is active
- Ensure service role key has proper permissions

### Logs and Debugging

```bash
# View all service logs
docker-compose logs

# View specific service logs
docker-compose logs banzai_port_scanner_mcp

# Restart services
docker-compose restart

# Rebuild and restart
docker-compose up --build -d
```

## 📊 Data Storage

All scan results are automatically stored in Supabase with this structure:

- **Projects**: Organize reconnaissance activities
- **Assets**: Store discovered targets (domains, IPs, subdomains)
- **Scans**: Track scan metadata and results
- **Services**: Store discovered services and their details
- **Web Endpoints**: Store discovered web paths

## 🔒 Security & Legal

- **Authorization Required**: Always obtain proper authorization before testing
- **Network Security**: Use VPNs and secure networks for testing
- **Data Privacy**: Sensitive data is stored in your Supabase instance
- **Rate Limiting**: Tools include built-in rate limiting to avoid overwhelming targets

## 🛡️ OPSEC Considerations

**⚠️ CRITICAL: This tool is NOT suitable for live client engagements without security modifications.**

### Key Security Issues
- **Claude stores all data**: Reconnaissance results are stored in Claude's conversation history and cannot be deleted
- **No API authentication**: HTTP endpoints (ports 8000-8004) lack OAuth2 or other authentication
- **No encryption**: Communications and stored data are not encrypted
- **Exposed services**: Docker containers expose ports to the host network

### Safe Usage
- ✅ **Use for**: Educational purposes, personal testing, authorized lab environments
- ❌ **Do NOT use for**: Live client engagements, production environments, or unauthorized targets

### Before Production Use
Implement: OAuth2 authentication, TLS encryption, rate limiting, data encryption, and proper access controls.

## 📄 License

This project is licensed under the MIT License.

---

**BanzAI** - Empowering security professionals with AI-driven reconnaissance capabilities. 🚀