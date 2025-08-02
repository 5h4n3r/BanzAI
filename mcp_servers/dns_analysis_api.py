from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.core.dns_analysis import DNSAnalyzer
import uvicorn

app = FastAPI()
analyzer = DNSAnalyzer()

class AnalysisRequest(BaseModel):
    domain: str

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "dns_analysis"}

@app.post("/analyze")
async def analyze_domain(request: AnalysisRequest):
    """Perform comprehensive DNS analysis on a domain."""
    try:
        result = await analyzer.analyze_domain(request.domain)
        return result.model_dump()
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
            "zone_transfer": zone_transfer.model_dump()
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

@app.post("/reverse_dns")
async def reverse_dns_lookup(request: AnalysisRequest):
    """Perform reverse DNS lookup on an IP address."""
    try:
        # Convert IP to reverse DNS format
        ip_parts = request.domain.split('.')
        if len(ip_parts) != 4:
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        reverse_domain = f"{'.'.join(reversed(ip_parts))}.in-addr.arpa"
        
        # Try multiple DNS resolvers for better reverse DNS support
        ptr_data = []
        lookup_method = "none"
        
        # Method 1: Try with Google DNS (8.8.8.8)
        try:
            import dns.asyncresolver
            google_resolver = dns.asyncresolver.Resolver()
            google_resolver.nameservers = ['8.8.8.8']
            ptr_records = await google_resolver.resolve(reverse_domain, 'PTR')
            ptr_data = [{"type": "PTR", "value": str(rdata)} for rdata in ptr_records]
            lookup_method = "google_dns"
        except Exception:
            # Method 2: Try with Cloudflare DNS (1.1.1.1)
            try:
                cloudflare_resolver = dns.asyncresolver.Resolver()
                cloudflare_resolver.nameservers = ['1.1.1.1']
                ptr_records = await cloudflare_resolver.resolve(reverse_domain, 'PTR')
                ptr_data = [{"type": "PTR", "value": str(rdata)} for rdata in ptr_records]
                lookup_method = "cloudflare_dns"
            except Exception:
                # Method 3: Try with default resolver
                try:
                    ptr_records = await analyzer.resolver.resolve(reverse_domain, 'PTR')
                    ptr_data = [{"type": "PTR", "value": str(rdata)} for rdata in ptr_records]
                    lookup_method = "default_resolver"
                except Exception:
                    ptr_data = []
        
        return {
            "ip": request.domain,
            "reverse_domain": reverse_domain,
            "ptr_records": ptr_data,
            "debug_info": {
                "reverse_domain": reverse_domain,
                "lookup_method": lookup_method
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002) 