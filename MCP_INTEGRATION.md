# BanzAI MCP Integration Guide

This guide explains how to integrate BanzAI with Claude Desktop using the Model Context Protocol (MCP).

## Overview

BanzAI provides MCP adapters that allow Claude Desktop to directly access reconnaissance and security scanning tools. The MCP layer acts as an adapter on top of the existing HTTP APIs, providing a standardized interface for AI interaction.

## Architecture

```
Claude Desktop
       ↓
   MCP Protocol
       ↓
BanzAI MCP Servers (Adapters)
       ↓
HTTP APIs (Existing)
       ↓
Security Tools (nmap, ffuf, etc.)
```

## Available MCP Servers

### 1. Port Scanner MCP Server (`banzai-port-scanner`)
**Tools:**
- `port_scan` - Comprehensive port scanning with various scan types
- `quick_port_scan` - Quick scan of common ports
- `syn_scan` - SYN scan (requires privileges)
- `web_port_scan` - Web services scanning
- `database_port_scan` - Database services scanning

### 2. Supabase MCP Server (`banzai-supabase`)
**Tools:**
- `store_scan_results` - Store scan results in the database
- `get_latest_scan` - Get the latest scan results for a target
- `get_scan_history` - Get scan history for a target over a time period
- `get_asset_summary` - Get a summary of all assets and findings for a project
- `find_similar_targets` - Find targets with similar characteristics
- `get_vulnerability_trends` - Get vulnerability trends across all scans

### 3. DNS Analysis MCP Server (`banzai-dns-analysis`)
**Tools:**
- `dns_analyze` - Comprehensive DNS analysis including nameservers, records, zone transfer, and takeover detection
- `get_nameservers` - Get nameservers for a domain
- `enumerate_dns_records` - Enumerate DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)
- `attempt_zone_transfer` - Attempt zone transfer from a domain's nameservers
- `detect_takeover_candidates` - Detect potential subdomain takeover candidates
- `reverse_dns_lookup` - Perform reverse DNS lookup on an IP address

### 4. Subdomain Enumeration MCP Server (`banzai-subdomain`)
**Tools:**
- `enumerate_subdomains` - Enumerate subdomains using various techniques
- `brute_force_subdomains` - Brute force subdomain discovery
- `certificate_transparency` - Find subdomains from SSL certificates
- `search_engine_discovery` - Find subdomains from search engines
- `dns_enumeration` - DNS-based subdomain enumeration

### 5. Directory Fuzzer MCP Server (`banzai-directory-fuzzer`)
**Tools:**
- `directory_fuzz` - Directory and file fuzzing
- `common_directories` - Scan for common directories
- `file_extensions` - Scan with various file extensions
- `recursive_fuzzing` - Recursive directory fuzzing
- `custom_wordlist` - Use custom wordlist for fuzzing

## Setup Instructions

### 1. Prerequisites

- BanzAI HTTP API servers running (via Docker)
- Claude Desktop installed and configured
- Python 3.11+ with required dependencies

### 2. Start BanzAI Services

```bash
# Start all HTTP API servers
docker-compose up --build

# Verify services are running
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health
curl http://localhost:8004/health
```

### 3. Configure Claude Desktop

1. Open Claude Desktop
2. Go to Settings → Developer
3. Add the following MCP server configuration:

```json
{
  "mcpServers": {
    "banzai-port-scanner": {
      "command": "python",
      "args": [
        "mcp_servers/port_scanner_mcp.py"
      ]
    },
    "banzai-supabase": {
      "command": "python",
      "args": [
        "mcp_servers/supabase_mcp.py"
      ]
    },
    "banzai-dns-analysis": {
      "command": "python",
      "args": [
        "mcp_servers/dns_analysis_mcp.py"
      ]
    },
    "banzai-subdomain": {
      "command": "python",
      "args": [
        "mcp_servers/subdomain_mcp.py"
      ]
    },
    "banzai-directory-fuzzer": {
      "command": "python",
      "args": [
        "mcp_servers/directory_fuzzer_mcp.py"
      ]
    }
  }
}
```

4. Restart Claude Desktop

## Usage Examples

### Basic Port Scanning

**Prompt:** "Scan the ports on scanme.nmap.org"

Claude will use the `quick_port_scan` tool from the port scanner MCP server.

### SYN Scanning

**Prompt:** "Perform a SYN scan on 192.168.1.1"

Claude will use the `syn_scan` tool from the port scanner MCP server.

### DNS Analysis

**Prompt:** "Analyze the DNS configuration for example.com"

Claude will use the `dns_analyze` tool from the DNS analysis MCP server to examine nameservers, records, and potential security issues.

### Subdomain Enumeration

**Prompt:** "Find subdomains for example.com"

Claude will use the `enumerate_subdomains` tool from the subdomain MCP server.

### Directory Fuzzing

**Prompt:** "Fuzz directories on http://example.com"

Claude will use the `directory_fuzz` tool from the directory fuzzer MCP server.

### Historical Analysis

**Prompt:** "How has the attack surface of example.com changed in the last 30 days?"

Claude will use the `get_scan_history` tool from the Supabase MCP server to analyze trends and changes.

### Vulnerability Trends

**Prompt:** "What are the most common vulnerabilities across all our scans?"

Claude will use the `get_vulnerability_trends` tool from the Supabase MCP server to identify patterns.

## Tool Schemas

### Port Scanner Tools

```json
{
  "name": "quick_port_scan",
  "description": "Perform a quick scan of common ports",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target IP address or hostname to scan"
      }
    },
    "required": ["target"]
  }
}
```

```json
{
  "name": "syn_scan",
  "description": "Perform a SYN scan on a target (requires privileges)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target IP address or hostname to scan"
      },
      "ports": {
        "type": "string",
        "description": "Port range to scan (e.g., '1-1000', '80,443,8080')",
        "default": "1-1000"
      }
    },
    "required": ["target"]
  }
}
```

### DNS Analysis Tools

```json
{
  "name": "dns_analyze",
  "description": "Perform comprehensive DNS analysis on a domain including nameservers, records, zone transfer attempts, and takeover detection",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain to analyze"
      }
    },
    "required": ["domain"]
  }
}
```

### Subdomain Enumeration Tools

```json
{
  "name": "enumerate_subdomains",
  "description": "Enumerate subdomains using various techniques",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain to enumerate subdomains for"
      },
      "techniques": {
        "type": "array",
        "items": {
          "type": "string",
          "enum": ["brute_force", "certificate_transparency", "search_engines", "dns"]
        },
        "description": "Techniques to use for enumeration",
        "default": ["certificate_transparency", "search_engines"]
      }
    },
    "required": ["domain"]
  }
}
```

### Directory Fuzzer Tools

```json
{
  "name": "directory_fuzz",
  "description": "Perform directory and file fuzzing on a web application",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target URL to fuzz"
      },
      "wordlist": {
        "type": "string",
        "description": "Wordlist to use for fuzzing",
        "default": "common"
      },
      "extensions": {
        "type": "array",
        "items": {
          "type": "string"
        },
        "description": "File extensions to test",
        "default": ["php", "html", "txt"]
      }
    },
    "required": ["target"]
  }
}
```

## Response Format

All MCP tools return structured JSON responses with the following format:

```json
{
  "success": true,
  "target": "example.com",
  "scan_type": "quick",
  "summary": "Quick scan found 3 open ports on example.com",
  "data": {
    // Tool-specific data
  }
}
```

## Error Handling

MCP servers handle errors gracefully and return structured error responses:

```json
{
  "success": false,
  "error": "Target is not reachable",
  "target": "invalid-target.com"
}
```

## Troubleshooting

### Common Issues

1. **MCP servers not found**
   - Ensure Python path is correct
   - Check that MCP server files are executable
   - Verify Claude Desktop configuration

2. **HTTP API connection errors**
   - Ensure Docker containers are running
   - Check service health: `curl http://localhost:8000/health`
   - Verify network connectivity

3. **Tool execution failures**
   - Check tool dependencies (nmap, ffuf, etc.)
   - Verify target accessibility
   - Review error logs

### Debug Mode

Enable debug logging by setting environment variables:

```bash
export BANZAI_DEBUG=1
export MCP_DEBUG=1
```

### Testing Individual Components

```bash
# Test HTTP APIs
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health
curl http://localhost:8004/health

# Test individual MCP server
python mcp_servers/port_scanner_mcp.py
```

## Security Considerations

1. **Target Validation**: All tools validate targets before scanning
2. **Rate Limiting**: Built-in rate limiting to prevent abuse
3. **Error Handling**: Graceful error handling without exposing sensitive information
4. **Logging**: Comprehensive logging for audit trails

## Performance Optimization

1. **Concurrent Scanning**: Multiple tools can run in parallel
2. **Caching**: Results can be cached to avoid redundant scans
3. **Resource Management**: Automatic cleanup of temporary files
4. **Timeout Handling**: Configurable timeouts for long-running scans

## Future Enhancements

1. **Additional Tools**: More specialized scanning tools
2. **Result Correlation**: AI-powered result analysis
3. **Custom Workflows**: User-defined reconnaissance workflows
4. **Integration APIs**: Third-party tool integration

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review error logs
3. Test individual components
4. Verify configuration settings

## License

This MCP integration is part of the BanzAI project and follows the same licensing terms. 