# AI-Powered External Attack Surface Testing Tool

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run a port scan:
   ```bash
   python src/cli_main.py scan --target 127.0.0.1 --ports 1-1000
   ```

## Project Overview

Develop a comprehensive Python-based penetration testing framework that leverages AI and Model Context Protocol (MCP) servers for automated external attack surface assessment. The tool should integrate seamlessly with Claude Desktop and support local LLM alternatives.

## Core Objectives

### Primary Features

- **Port Scanning & Service Detection**: Comprehensive TCP/UDP port scanning with service fingerprinting
- **Subdomain Discovery**: Multiple enumeration techniques (DNS brute force, certificate transparency, search engines)
- **DNS Analysis**: Zone transfers, DNS record enumeration, subdomain takeover detection
- **Attack Surface Mapping**: Web application discovery, technology stack identification
- **Vulnerability Assessment**: Basic vulnerability scanning and security misconfigurations
- **Reporting**: AI-generated executive summaries and technical findings

### AI Integration Requirements

- **Claude Desktop Compatibility**: Primary AI interface through Claude Desktop MCP
- **Local LLM Support**: Fallback option for offline/private deployments
- **Intelligent Analysis**: AI-driven result correlation and prioritization
- **Natural Language Queries**: Allow users to ask questions about discovered assets
- **Automated Reporting**: AI-generated findings summaries and recommendations

## Technical Architecture

### Development Environment

- **Primary IDE**: Cursor with integrated MCP servers
- **Language**: Python 3.9+
- **MCP Integration**: Native MCP server support for tool interactions
- **Database**: Supabase for centralized data storage and sharing

### MCP Server Integration

1. **Core MCP Servers**:
    - Custom penetration testing MCP server
    - Supabase MCP server for data persistence
    - GitHub MCP server for version control and collaboration
2. **Cursor-Specific Integration**:
    - Leverage Cursor's built-in MCP capabilities
    - Code generation and debugging assistance
    - Real-time collaboration features

## Development Roadmap

### Phase 1: Foundation & MCP Integration (Weeks 1-2)

- [ ]  Set up basic Python project structure
- [ ]  Implement core MCP server for penetration testing tools
- [ ]  Establish Claude Desktop connectivity
- [ ]  Create basic CLI interface
- [ ]  Test AI interaction workflows

### Phase 2: Core Reconnaissance Features (Weeks 3-4)

- [ ]  Port scanning module (nmap integration)
- [ ]  Subdomain discovery engine
- [ ]  DNS enumeration capabilities
- [ ]  Basic service detection
- [ ]  Results storage in local database

### Phase 3: Database Integration (Week 5)

- [ ]  Supabase MCP server integration
- [ ]  Data models for assets, scans, and findings
- [ ]  Sync between local and cloud storage
- [ ]  Multi-user collaboration features

### Phase 4: Advanced Features (Weeks 6-7)

- [ ]  Web application discovery
- [ ]  Technology stack identification
- [ ]  Basic vulnerability scanning
- [ ]  Screenshot and visual reconnaissance
- [ ]  AI-powered result correlation

### Phase 5: Reporting & Analysis (Week 8)

- [ ]  AI-generated executive summaries
- [ ]  Technical report generation
- [ ]  Risk prioritization algorithms
- [ ]  Export capabilities (PDF, JSON, XML)

### Phase 6: Security Hardening (Weeks 9-10)

- [ ]  Input validation and sanitization
- [ ]  Rate limiting and throttling
- [ ]  Secure credential management
- [ ]  Audit logging
- [ ]  Docker containerization evaluation

## Key Requirements

### Technical Specifications

- **Performance**: Async/await for concurrent operations
- **Reliability**: Robust error handling and retry mechanisms
- **Extensibility**: Plugin architecture for custom modules
- **Security**: Secure handling of credentials and sensitive data
- **Compliance**: Responsible disclosure guidelines and legal considerations

### Integration Points

- **Claude Desktop**: Primary AI interface via MCP
- **Local LLM**: Ollama or similar for offline capabilities
- **Cursor IDE**: Development environment with MCP integration
- **Supabase**: Cloud database for persistent storage
- **GitHub**: Version control and collaboration via MCP

### Data Models

- **Assets**: IPs, domains, subdomains, services
- **Scans**: Scan metadata, timestamps, configurations
- **Findings**: Vulnerabilities, misconfigurations, notes
- **Reports**: AI-generated summaries and recommendations

## Success Criteria

1. Successfully scan and enumerate external attack surfaces
2. Seamless AI integration for analysis and reporting
3. Stable MCP server communication
4. Reliable data persistence and sharing
5. User-friendly interface accessible via Claude Desktop
6. Comprehensive documentation and testing

## Important Notes

- **Authorization Required**: Tool must only be used on systems you own or have explicit written permission to test
- **Legal Compliance**: Ensure all activities comply with local laws and regulations
- **Responsible Use**: Implement safeguards against unauthorized usage
- **Documentation**: Maintain clear usage guidelines and ethical considerations

## Future Enhancements

- Container orchestration for MCP servers
- Advanced AI model fine-tuning
- Integration with threat intelligence feeds
- Mobile companion application
- Enterprise dashboard and analytics