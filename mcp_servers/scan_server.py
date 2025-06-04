from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.core.scanner import PortScanner

app = FastAPI()
scanner = PortScanner()

class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"

@app.post("/scan")
async def scan(request: ScanRequest):
    try:
        result = await scanner.scan_target(request.target, request.ports)
        return result.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 