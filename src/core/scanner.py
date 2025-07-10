from typing import List, Dict
from pydantic import BaseModel
import nmap
import asyncio

class ScanResult(BaseModel):
    target: str
    ports: List[int]
    services: Dict[int, str]
    timestamp: str

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    async def scan_target(self, target: str, ports: str = "1-1000") -> ScanResult:
        try:
            # Run the blocking scan in a thread
            await asyncio.to_thread(self.nm.scan, target, ports)
            scan_data = self.nm[target]
            open_ports = []
            services = {}
            for port in scan_data.get('tcp', {}):
                if scan_data['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
                    services[port] = scan_data['tcp'][port]['name']
            # Handle missing scanstats gracefully
            timestamp = scan_data.get('scanstats', {}).get('timestr', 'Unknown')
            return ScanResult(
                target=target,
                ports=open_ports,
                services=services,
                timestamp=timestamp
            )
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}") 