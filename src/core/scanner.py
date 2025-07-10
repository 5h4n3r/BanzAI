from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import nmap
import asyncio
import time
from datetime import datetime

class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    script_output: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    target: str
    scan_type: str
    ports_scanned: int
    open_ports: List[PortInfo]
    scan_duration: float
    timestamp: str
    scan_stats: Optional[Dict[str, Any]] = None

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    async def scan_target(self, target: str, ports: str = "1-65535", 
                         scan_type: str = "tcp", timing: int = 3,
                         service_detection: bool = True, 
                         script_scan: Optional[List[str]] = None) -> ScanResult:
        """
        Enhanced port scanning with multiple options
        
        Args:
            target: Target IP or hostname
            ports: Port range or list (e.g., "1-1000", "80,443,8080")
            scan_type: "tcp", "udp", or "both"
            timing: Timing template (0-5, higher = faster)
            service_detection: Enable service/version detection
            script_scan: List of NSE scripts to run
        """
        start_time = time.time()
        
        try:
            # Build nmap arguments
            arguments = []
            
            # Add scan type
            if scan_type == "tcp":
                arguments.append("-sS")  # SYN scan
            elif scan_type == "udp":
                arguments.append("-sU")  # UDP scan
            elif scan_type == "both":
                arguments.append("-sS -sU")  # Both TCP and UDP
            
            # Add timing
            arguments.append(f"-T{timing}")
            
            # Add service detection
            if service_detection:
                arguments.append("-sV")
            
            # Add script scanning
            if script_scan:
                script_str = ",".join(script_scan)
                arguments.append(f"--script={script_str}")
            
            # Add port specification
            arguments.append(f"-p {ports}")
            
            # Combine arguments
            nmap_args = " ".join(arguments)
            
            print(f"[DEBUG] Running nmap: {nmap_args} {target}")
            
            # Run the scan
            await asyncio.to_thread(self.nm.scan, target, arguments=nmap_args)
            
            scan_data = self.nm[target]
            open_ports = []
            ports_scanned = 0
            
            # Process TCP results
            for protocol in ['tcp', 'udp']:
                if protocol in scan_data:
                    for port, port_data in scan_data[protocol].items():
                        ports_scanned += 1
                        if port_data['state'] == 'open':
                            port_info = PortInfo(
                                port=port,
                                protocol=protocol,
                                state=port_data['state'],
                                service=port_data.get('name', 'unknown'),
                                version=port_data.get('version', ''),
                                banner=port_data.get('product', ''),
                                script_output=port_data.get('script', {})
                            )
                            open_ports.append(port_info)
            
            scan_duration = time.time() - start_time
            
            # Get scan statistics
            scan_stats = scan_data.get('scanstats', {})
            
            return ScanResult(
                target=target,
                scan_type=scan_type,
                ports_scanned=ports_scanned,
                open_ports=open_ports,
                scan_duration=scan_duration,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                scan_stats=scan_stats
            )
            
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan of common ports"""
        common_ports = "21-23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080"
        return await self.scan_target(target, common_ports, "tcp", 3, True)
    
    async def web_scan(self, target: str) -> ScanResult:
        """Scan for web services"""
        web_ports = "80,443,8080,8443,3000,8000,8888,9000"
        return await self.scan_target(
            target, web_ports, "tcp", 3, True, 
            ["http-title", "http-server-header"]
        )
    
    async def database_scan(self, target: str) -> ScanResult:
        """Scan for database services"""
        db_ports = "1433,3306,5432,6379,27017,9200,11211"
        return await self.scan_target(
            target, db_ports, "tcp", 3, True, 
            ["banner"]
        ) 