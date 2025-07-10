#!/usr/bin/env python3
"""
BanzAI Directory Fuzzing MCP Server
Uses ffuf for web directory and file discovery
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import List, Dict, Optional, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI()

class DirectoryFuzzRequest(BaseModel):
    target: str = Field(..., description="Target URL (e.g., https://example.com)")
    wordlist: Optional[str] = Field("common", description="Wordlist to use: common, big, custom")
    extensions: Optional[List[str]] = Field([], description="File extensions to test")
    threads: Optional[int] = Field(50, description="Number of threads")
    rate_limit: Optional[int] = Field(0, description="Rate limit (requests per second)")
    timeout: Optional[int] = Field(10, description="Request timeout in seconds")
    custom_wordlist: Optional[List[str]] = Field(None, description="Custom wordlist paths")
    follow_redirects: Optional[bool] = Field(True, description="Follow redirects")
    match_status: Optional[List[int]] = Field([200, 204, 301, 302, 307, 401, 403], description="Status codes to match")
    exclude_status: Optional[List[int]] = Field([404], description="Status codes to exclude")
    output_format: Optional[str] = Field("json", description="Output format: json, csv, md")

class DirectoryFuzzResult(BaseModel):
    target: str
    wordlist_used: str
    total_requests: int
    successful_requests: int
    discovered_paths: List[Dict[str, Any]]
    scan_duration: float
    timestamp: str

class DirectoryFuzzer:
    """Directory fuzzing using ffuf"""
    
    def __init__(self):
        self.wordlists = {
            "common": "/usr/share/wordlists/dirb/common.txt",
            "big": "/usr/share/wordlists/dirb/big.txt",
            "medium": "/usr/share/wordlists/dirb/medium.txt",
            "small": "/usr/share/wordlists/dirb/small.txt"
        }
        
        # Fallback wordlists if standard ones don't exist
        self.fallback_wordlists = {
            "common": [
                "admin", "login", "wp-admin", "phpmyadmin", "config", "backup",
                "api", "test", "dev", "stage", "beta", "old", "new", "temp",
                "files", "upload", "download", "images", "css", "js", "assets",
                "includes", "lib", "src", "bin", "etc", "var", "tmp", "cache",
                "logs", "data", "db", "database", "sql", "xml", "json", "txt",
                "pdf", "doc", "xls", "zip", "tar", "gz", "rar", "bak", "old",
                "backup", "copy", "archive", "v1", "v2", "version", "latest"
            ],
            "big": [
                # Common web paths
                "admin", "administrator", "login", "logout", "register", "signup",
                "dashboard", "panel", "control", "manage", "management", "admin-panel",
                "wp-admin", "wp-content", "wp-includes", "wordpress", "joomla", "drupal",
                "phpmyadmin", "mysql", "database", "db", "sql", "config", "configuration",
                "settings", "setup", "install", "installation", "update", "upgrade",
                "backup", "backups", "bak", "old", "archive", "temp", "tmp", "cache",
                "logs", "log", "error", "debug", "test", "testing", "dev", "development",
                "stage", "staging", "beta", "alpha", "prod", "production", "live",
                "api", "rest", "graphql", "swagger", "docs", "documentation",
                "files", "file", "upload", "download", "media", "images", "img",
                "css", "js", "javascript", "assets", "static", "public", "private",
                "includes", "include", "lib", "library", "src", "source", "bin",
                "etc", "var", "usr", "home", "root", "system", "sys", "web",
                "www", "html", "htdocs", "public_html", "sites", "domains",
                "cgi-bin", "cgi", "scripts", "script", "tools", "util", "utils",
                "help", "support", "contact", "about", "info", "faq", "terms",
                "privacy", "policy", "legal", "sitemap", "robots", "favicon",
                "apple-touch-icon", "manifest", "service-worker", "sw.js"
            ]
        }
    
    def _get_wordlist_path(self, wordlist_name: str) -> str:
        """Get the path to a wordlist file"""
        if wordlist_name in self.wordlists:
            wordlist_path = self.wordlists[wordlist_name]
            if os.path.exists(wordlist_path):
                return wordlist_path
        
        # Create temporary wordlist file with fallback content
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        fallback_words = self.fallback_wordlists.get(wordlist_name, self.fallback_wordlists["common"])
        
        for word in fallback_words:
            temp_file.write(f"{word}\n")
        temp_file.close()
        
        return temp_file.name
    
    def _build_ffuf_command(self, target: str, wordlist_path: str, extensions: List[str], 
                           threads: int, rate_limit: int, timeout: int, 
                           follow_redirects: bool, match_status: List[int], 
                           exclude_status: List[int]) -> List[str]:
        """Build the ffuf command"""
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist_path,
            "-t", str(threads),
            "-timeout", str(timeout),
            "-o", "-",
            "-of", "json"
        ]
        
        # Add extensions if specified
        if extensions:
            ext_str = ",".join(extensions)
            cmd.extend(["-e", ext_str])
        
        # Add rate limiting
        if rate_limit > 0:
            cmd.extend(["-rate", str(rate_limit)])
        
        # Add redirect following
        if follow_redirects:
            cmd.append("-r")
        
        # Add status code matching
        if match_status:
            status_str = ",".join(map(str, match_status))
            cmd.extend(["-mc", status_str])
        
        # Add status code exclusion
        if exclude_status:
            status_str = ",".join(map(str, exclude_status))
            cmd.extend(["-fc", status_str])
        
        return cmd
    
    async def fuzz_directory(self, request: DirectoryFuzzRequest) -> DirectoryFuzzResult:
        """Perform directory fuzzing using ffuf"""
        import time
        start_time = time.time()
        
        try:
            # Get wordlist path
            wordlist_path = self._get_wordlist_path(request.wordlist)
            
            # Build ffuf command
            cmd = self._build_ffuf_command(
                target=request.target,
                wordlist_path=wordlist_path,
                extensions=request.extensions,
                threads=request.threads,
                rate_limit=request.rate_limit,
                timeout=request.timeout,
                follow_redirects=request.follow_redirects,
                match_status=request.match_status,
                exclude_status=request.exclude_status
            )
            
            print(f"[DEBUG] Running ffuf command: {' '.join(cmd)}")
            
            # Run ffuf
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown ffuf error"
                raise Exception(f"ffuf failed: {error_msg}")
            
            # Parse results
            results_json = stdout.decode().strip()
            if not results_json:
                # No results found
                return DirectoryFuzzResult(
                    target=request.target,
                    wordlist_used=request.wordlist,
                    total_requests=0,
                    successful_requests=0,
                    discovered_paths=[],
                    scan_duration=time.time() - start_time,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # Parse ffuf JSON output
            ffuf_results = json.loads(results_json)
            discovered_paths = []
            total_requests = 0
            successful_requests = 0
            
            if "results" in ffuf_results:
                for result in ffuf_results["results"]:
                    discovered_paths.append({
                        "url": result.get("url", ""),
                        "path": result.get("input", {}).get("FUZZ", ""),
                        "status_code": result.get("status", 0),
                        "content_length": result.get("length", 0),
                        "content_type": result.get("content-type", ""),
                        "redirect_location": result.get("redirectlocation", ""),
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0)
                    })
                    successful_requests += 1
            
            # Get total requests from ffuf stats
            if "config" in ffuf_results:
                total_requests = ffuf_results["config"].get("total_requests", 0)
            
            scan_duration = time.time() - start_time
            
            # Clean up temporary wordlist file
            if wordlist_path.startswith("/tmp"):
                try:
                    os.unlink(wordlist_path)
                except:
                    pass
            
            return DirectoryFuzzResult(
                target=request.target,
                wordlist_used=request.wordlist,
                total_requests=total_requests,
                successful_requests=successful_requests,
                discovered_paths=discovered_paths,
                scan_duration=scan_duration,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
        except Exception as e:
            raise Exception(f"Directory fuzzing failed: {str(e)}")

# Initialize fuzzer
fuzzer = DirectoryFuzzer()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "directory_fuzzer"}

@app.post("/fuzz")
async def fuzz_directory(request: DirectoryFuzzRequest):
    """Perform directory fuzzing"""
    try:
        result = await fuzzer.fuzz_directory(request)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/wordlists")
async def list_wordlists():
    """List available wordlists"""
    return {
        "available_wordlists": list(fuzzer.wordlists.keys()),
        "fallback_wordlists": list(fuzzer.fallback_wordlists.keys())
    }

@app.post("/fuzz/quick")
async def quick_fuzz(target: str):
    """Quick directory fuzzing with default settings"""
    request = DirectoryFuzzRequest(
        target=target,
        wordlist="common",
        threads=20,
        timeout=5
    )
    
    try:
        result = await fuzzer.fuzz_directory(request)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004) 