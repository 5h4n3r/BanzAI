from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.core.dns_analysis import DNSAnalyzer

app = FastAPI()
analyzer = DNSAnalyzer()

class AnalysisRequest(BaseModel):
    domain: str

@app.post("/analyze")
async def analyze_domain(request: AnalysisRequest):
    """Perform comprehensive DNS analysis on a domain."""
    try:
        result = await analyzer.analyze_domain(request.domain)
        return result.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/nameservers")
async def get_nameservers(request: AnalysisRequest):
    """Get nameservers for a domain."""
    try:
        nameservers = await analyzer.get_nameservers(request.domain)
        return {"domain": request.domain, "nameservers": nameservers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/zone_transfer")
async def attempt_zone_transfer(request: AnalysisRequest):
    """Attempt zone transfer for a domain."""
    try:
        nameservers = await analyzer.get_nameservers(request.domain)
        if not nameservers:
            raise HTTPException(status_code=404, detail="No nameservers found")
        
        zone_transfer = await analyzer.attempt_zone_transfer(request.domain, nameservers[0])
        return {
            "domain": request.domain,
            "nameserver": nameservers[0],
            "zone_transfer": zone_transfer.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/records")
async def enumerate_records(request: AnalysisRequest):
    """Enumerate DNS records for a domain."""
    try:
        records = await analyzer.enumerate_dns_records(request.domain)
        return {"domain": request.domain, "records": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/takeover")
async def detect_takeover(request: AnalysisRequest):
    """Detect potential subdomain takeover candidates."""
    try:
        candidates = await analyzer.detect_takeover_candidates(request.domain)
        return {"domain": request.domain, "takeover_candidates": candidates}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 