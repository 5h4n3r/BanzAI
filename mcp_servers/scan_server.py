from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from src.core.scanner import PortScanner

app = FastAPI()
scanner = PortScanner()

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    ports: str = Field("1-65535", description="Port range to scan (e.g., '1-1000', '80,443,8080')")
    scan_type: str = Field("tcp", description="Scan type: tcp, udp, or both")
    timing: int = Field(3, description="Timing template (0-5, higher = faster)")
    service_detection: bool = Field(True, description="Enable service detection")
    script_scan: Optional[List[str]] = Field(None, description="NSE scripts to run")

class ScanResponse(BaseModel):
    target: str
    scan_type: str
    ports_scanned: int
    open_ports: List[dict]
    scan_duration: float
    timestamp: str

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "port_scanner"}

@app.post("/scan")
async def scan(request: ScanRequest):
    """Perform port scanning with enhanced options"""
    try:
        print(f"[INFO] Starting scan for target: {request.target}")
        result = await scanner.scan_target(
            request.target, 
            request.ports,
            scan_type=request.scan_type,
            timing=request.timing,
            service_detection=request.service_detection,
            script_scan=request.script_scan
        )
        print(f"[INFO] Scan completed for {request.target}: {len(result.open_ports)} open ports found")
        return result.dict()
    except Exception as e:
        print(f"[ERROR] Scan failed for {request.target}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/scan/quick")
async def quick_scan(target: str):
    """Quick scan of common ports"""
    try:
        request = ScanRequest(
            target=target,
            ports="21-23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080",
            scan_type="tcp",
            timing=3,
            service_detection=True
        )
        return await scan(request)
    except Exception as e:
        print(f"[ERROR] Quick scan failed for {target}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {str(e)}")

@app.post("/scan/web")
async def web_scan(target: str):
    """Scan for web services"""
    request = ScanRequest(
        target=target,
        ports="80,443,8080,8443,3000,8000,8888,9000",
        scan_type="tcp",
        timing=3,
        service_detection=True,
        script_scan=["http-title", "http-server-header"]
    )
    return await scan(request)

@app.post("/scan/database")
async def database_scan(target: str):
    """Scan for database services"""
    request = ScanRequest(
        target=target,
        ports="1433,3306,5432,6379,27017,9200,11211",
        scan_type="tcp",
        timing=3,
        service_detection=True,
        script_scan=["banner"]
    )
    return await scan(request) 