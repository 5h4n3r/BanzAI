from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
import json
from typing import List, Dict
import subprocess
from pathlib import Path
import uvicorn

app = FastAPI()

class EnumRequest(BaseModel):
    domain: str
    threads: int = 10
    timeout: int = 240

class SubdomainResult(BaseModel):
    domain: str
    subdomains: List[str]
    dns_records: Dict[str, List[str]]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "subdomain_enumerator"}

@app.post("/enumerate")
async def enumerate_subdomains(request: EnumRequest):
    try:
        # Create temporary files for output
        subfinder_output = Path("/tmp/subfinder_output.txt")
        dnsx_output = Path("/tmp/dnsx_output.txt")
        
        # Run subfinder
        subfinder_cmd = [
            "subfinder",
            "-d", request.domain,
            "-t", str(request.threads),
            "-timeout", str(request.timeout),
            "-o", str(subfinder_output)
        ]
        
        print(f"[DEBUG] Running subfinder with command: {' '.join(subfinder_cmd)}")
        
        # Run DNSX on subfinder results
        dnsx_cmd = [
            "dnsx",
            "-l", str(subfinder_output),
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns",
            "-json",
            "-o", str(dnsx_output)
        ]
        
        print(f"[DEBUG] Running dnsx with command: {' '.join(dnsx_cmd)}")
        
        # Execute commands
        subfinder_process = await asyncio.create_subprocess_exec(
            *subfinder_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await subfinder_process.communicate()
        
        if not subfinder_output.exists():
            raise HTTPException(status_code=500, detail="Subfinder failed to generate output")
            
        dnsx_process = await asyncio.create_subprocess_exec(
            *dnsx_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await dnsx_process.communicate()
        
        # Parse results
        subdomains = set()
        dns_records = {
            "A": [], "AAAA": [], "CNAME": [], 
            "MX": [], "TXT": [], "NS": []
        }
        
        if dnsx_output.exists():
            with open(dnsx_output) as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        host = record.get("host", "")
                        if host:
                            subdomains.add(host)
                        # Add DNS records (flatten lists)
                        for record_type in dns_records.keys():
                            if record_type.lower() in record:
                                values = record[record_type.lower()]
                                if isinstance(values, list):
                                    dns_records[record_type].extend(values)
                                elif isinstance(values, str):
                                    dns_records[record_type].append(values)
                    except json.JSONDecodeError:
                        continue
        
        # Cleanup
        subfinder_output.unlink(missing_ok=True)
        dnsx_output.unlink(missing_ok=True)
        
        return SubdomainResult(
            domain=request.domain,
            subdomains=sorted(list(subdomains)),
            dns_records=dns_records
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001) 