# 🚀 BanzAI - AI-Powered Penetration Testing Tool

**BanzAI** is a comprehensive, modular penetration testing platform that combines powerful reconnaissance tools with AI-driven analysis and persistent data storage. Built with a microservices architecture using MCP (Model Context Protocol) servers, it provides enterprise-grade security testing capabilities.

## 🌟 Features

### 🔍 **Reconnaissance & Discovery**
- **Port Scanning**: Advanced nmap-based scanning with service detection
- **Subdomain Enumeration**: Using Subfinder for comprehensive subdomain discovery
- **DNS Analysis**: Deep DNS reconnaissance with DNSX
- **Directory Fuzzing**: Web path discovery using ffuf

### 🗄️ **Data Persistence**
- **Supabase Integration**: Cloud-native PostgreSQL database
- **Structured Data Model**: Comprehensive schema for projects, assets, scans, and findings
- **Real-time Updates**: Live data synchronization across all tools

### 🏗️ **Modular Architecture**
- **MCP Servers**: Independent microservices for each tool
- **Docker Containerization**: Easy deployment and scaling
- **RESTful APIs**: Standardized interfaces for all operations

### 🎯 **Use Cases**
- **Security Assessments**: Comprehensive penetration testing workflows
- **Asset Discovery**: Automated reconnaissance and mapping
- **Vulnerability Research**: Structured data collection and analysis
- **Red Team Operations**: Coordinated attack surface mapping

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Supabase account and project
- Go 1.24+ (for tool compilation)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd banzai
```

### 2. Configure Environment
Create a `.env` file with your Supabase credentials:
```bash
SUPABASE_PROJECT_REF=your_project_ref
SUPABASE_ACCESS_TOKEN=your_access_token
```

### 3. Build and Start Services
```bash
docker-compose up --build
```

### 4. Initialize Database
```bash
# The database schema will be automatically created on first run
# You can also manually initialize it via the API
```

## 📖 Usage

### Command Line Interface

BanzAI provides a comprehensive CLI for orchestrating reconnaissance workflows:

```bash
# Full reconnaissance workflow
python src/cli_main.py recon example.com "Example Project"

# Quick port scan
python src/cli_main.py scan 192.168.1.1 --type quick

# Subdomain enumeration
python src/cli_main.py subdomains example.com

# Directory fuzzing
python src/cli_main.py fuzz https://example.com --wordlist common

# Project management
python src/cli_main.py projects --list
python src/cli_main.py projects --create "New Project" --target example.com
```

### API Endpoints

Each MCP server exposes RESTful APIs:

#### Port Scanner (Port 8000)
```bash
# Quick scan
curl -X POST http://localhost:8000/scan/quick -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'

# Web services scan
curl -X POST http://localhost:8000/scan/web -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Custom scan
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "ports": "1-1000", "scan_type": "tcp"}'
```

#### Subdomain Enumeration (Port 8001)
```bash
curl -X POST http://localhost:8001/enumerate -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### DNS Analysis (Port 8002)
```bash
curl -X POST http://localhost:8002/analyze -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### Directory Fuzzer (Port 8004)
```bash
curl -X POST http://localhost:8004/fuzz -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "wordlist": "common"}'
```

## 🏗️ Architecture

### MCP Servers

BanzAI uses a microservices architecture with specialized MCP servers:

1. **Scan Server** (`banzai_scan_server`)
   - Port scanning with nmap
   - Service detection and version identification
   - NSE script execution

2. **Subdomain Server** (`banzai_subdomain_server`)
   - Subdomain enumeration with Subfinder
   - DNS resolution and validation

3. **DNS Analysis Server** (`banzai_dns_analysis_server`)
   - Comprehensive DNS reconnaissance
   - Record type analysis

4. **Directory Fuzzer** (`banzai_directory_fuzzer`)
   - Web path discovery with ffuf
   - Multiple wordlist support
   - Configurable scanning parameters

5. **Supabase MCP Wrapper** (`banzai_supabase_mcp`)
   - Database integration layer
   - Real-time data synchronization

### Database Schema

The database uses a comprehensive schema with the following main entities:

- **Projects**: Organize reconnaissance activities
- **Assets**: Store discovered targets (domains, IPs, subdomains)
- **Scans**: Track scan metadata and results
- **Services**: Store discovered services and their details
- **Web Endpoints**: Store discovered web paths
- **Findings**: Store security findings and vulnerabilities

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_PROJECT_REF` | Your Supabase project reference | Yes |
| `SUPABASE_ACCESS_TOKEN` | Your Supabase access token | Yes |

### Docker Configuration

The `docker-compose.yml` file defines all services:

```yaml
services:
  banzai_scan_server:        # Port 8000
  banzai_subdomain_server:   # Port 8001
  banzai_dns_analysis_server: # Port 8002
  banzai_supabase_mcp:       # Port 8003
  banzai_directory_fuzzer:   # Port 8004
```

### Tool Configuration

Each tool can be configured via environment variables or API parameters:

- **Nmap**: Timing templates, scan types, NSE scripts
- **Subfinder**: Sources, resolvers, rate limiting
- **ffuf**: Wordlists, threads, rate limiting, status codes

## 📊 Data Model

### Projects
```sql
CREATE TABLE projects (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    target_domain TEXT,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Assets
```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    type TEXT NOT NULL, -- 'domain', 'subdomain', 'ip', 'url'
    value TEXT NOT NULL,
    status TEXT DEFAULT 'discovered',
    metadata JSONB,
    discovered_at TIMESTAMP
);
```

### Scans
```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    asset_id UUID REFERENCES assets(id),
    scan_type TEXT NOT NULL, -- 'port_scan', 'subdomain_enum', 'dns_analysis', 'dir_fuzz'
    status TEXT DEFAULT 'pending',
    configuration JSONB,
    results JSONB,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

## 🛠️ Development

### Local Development Setup

1. **Install Dependencies**
```bash
pip install -r requirements.txt
npm install
```

2. **Start Individual Services**
```bash
# Start Supabase MCP wrapper
python mcp_servers/supabase_mcp_wrapper.py

# Start scan server
python mcp_servers/scan_server.py

# Start other services...
```

3. **Run Tests**
```bash
python -m pytest tests/
```

### Adding New Tools

1. **Create MCP Server**
```python
# mcp_servers/new_tool_server.py
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ToolRequest(BaseModel):
    target: str
    # Add other parameters

@app.post("/tool")
async def run_tool(request: ToolRequest):
    # Implement tool logic
    pass
```

2. **Add to Docker Compose**
```yaml
banzai_new_tool:
  build: .
  ports:
    - "8005:8005"
  command: python mcp_servers/new_tool_server.py
```

3. **Update CLI**
```python
# Add to BanzAICLI class
async def new_tool(self, target: str, project_id: Optional[str] = None):
    # Implement tool integration
    pass
```

## 🔒 Security Considerations

- **Authorization**: Implement proper access controls for production use
- **Rate Limiting**: Configure appropriate rate limits for external tools
- **Data Privacy**: Ensure sensitive data is properly handled and encrypted
- **Network Security**: Use VPNs and secure networks for testing
- **Legal Compliance**: Always obtain proper authorization before testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Documentation**: Check the docs/ directory for detailed documentation
- **Community**: Join our Discord/Telegram for community support

## 🎯 Roadmap

- [ ] **Vulnerability Scanning**: Integration with tools like Nuclei
- [ ] **Web Application Testing**: Burp Suite integration
- [ ] **AI Analysis**: Machine learning for finding prioritization
- [ ] **Reporting**: Automated report generation
- [ ] **Team Collaboration**: Multi-user support
- [ ] **API Security**: OAuth2 and API key management
- [ ] **Cloud Integration**: AWS, Azure, GCP reconnaissance
- [ ] **Mobile Testing**: Android/iOS application testing

---

**BanzAI** - Empowering security professionals with AI-driven reconnaissance and testing capabilities. 🚀