import dns.asyncresolver
import dns.zone
import dns.query
import dns.rdatatype
import asyncio
from typing import Dict, List, Set, Optional
from pydantic import BaseModel

class DNSRecord(BaseModel):
    type: str
    value: str
    ttl: Optional[int] = None

class ZoneTransferResult(BaseModel):
    success: bool
    records: List[DNSRecord]
    error: Optional[str] = None

class DNSAnalysisResult(BaseModel):
    domain: str
    nameservers: List[str]
    zone_transfer: ZoneTransferResult
    records: Dict[str, List[DNSRecord]]
    takeover_candidates: List[str]

class DNSAnalyzer:
    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']
        
    async def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain."""
        try:
            answers = await self.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []

    async def attempt_zone_transfer(self, domain: str, nameserver: str) -> ZoneTransferResult:
        """Attempt zone transfer from a nameserver."""
        try:
            zone = await asyncio.to_thread(dns.zone.from_xfr, dns.query.xfr(nameserver, domain))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(DNSRecord(
                            type=str(rdataset.rdtype),
                            value=str(rdata),
                            ttl=rdataset.ttl
                        ))
            return ZoneTransferResult(success=True, records=records)
        except Exception as e:
            return ZoneTransferResult(success=False, records=[], error=str(e))

    async def enumerate_dns_records(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """Enumerate various DNS record types for a domain."""
        results = {record_type: [] for record_type in self.record_types}
        
        tasks = []
        for record_type in self.record_types:
            tasks.append(self._resolve_record_type(domain, record_type, results))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _resolve_record_type(self, domain: str, record_type: str, results: Dict[str, List[DNSRecord]]):
        """Resolve a specific DNS record type."""
        try:
            answers = await self.resolver.resolve(domain, record_type)
            for rdata in answers:
                results[record_type].append(DNSRecord(
                    type=record_type,
                    value=str(rdata)
                ))
        except Exception:
            pass  # Record type not found or other error

    async def detect_takeover_candidates(self, domain: str) -> List[str]:
        """Detect potential subdomain takeover candidates."""
        candidates = []
        
        # Common takeover patterns
        takeover_patterns = [
            'dev', 'staging', 'test', 'demo', 'uat', 'qa',
            'admin', 'portal', 'api', 'cdn', 'mail'
        ]
        
        for sub in takeover_patterns:
            fqdn = f"{sub}.{domain}"
            try:
                answers = await self.resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    cname_target = str(rdata)
                    # Check for common takeover targets
                    if any(service in cname_target.lower() for service in [
                        'github.io', 'herokuapp.com', 'azurewebsites.net',
                        'cloudfront.net', 's3.amazonaws.com', 'firebaseapp.com'
                    ]):
                        candidates.append(f"{fqdn} -> {cname_target}")
            except Exception:
                continue
                
        return candidates

    async def analyze_domain(self, domain: str) -> DNSAnalysisResult:
        """Perform comprehensive DNS analysis on a domain."""
        # Get nameservers
        nameservers = await self.get_nameservers(domain)
        
        # Attempt zone transfer from first nameserver
        zone_transfer = ZoneTransferResult(success=False, records=[], error="No nameservers found")
        if nameservers:
            zone_transfer = await self.attempt_zone_transfer(domain, nameservers[0])
        
        # Enumerate DNS records
        records = await self.enumerate_dns_records(domain)
        
        # Detect takeover candidates
        takeover_candidates = await self.detect_takeover_candidates(domain)
        
        return DNSAnalysisResult(
            domain=domain,
            nameservers=nameservers,
            zone_transfer=zone_transfer,
            records=records,
            takeover_candidates=takeover_candidates
        ) 