from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class ScanType(str, Enum):
    PORT_SCAN = "port_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    DNS_ANALYSIS = "dns_analysis"
    DIRECTORY_FUZZ = "directory_fuzz"

class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    SUBDOMAIN = "subdomain"
    WEB_APP = "web_app"

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Asset(BaseModel):
    id: Optional[str] = None
    type: AssetType
    value: str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}
    tags: List[str] = []

class ScanResult(BaseModel):
    id: Optional[str] = None
    scan_type: ScanType
    target: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "running"
    results: Dict[str, Any] = {}
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}

class Finding(BaseModel):
    id: Optional[str] = None
    asset_id: str
    scan_id: str
    title: str
    description: str
    severity: Severity
    category: str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = {}
    remediation: Optional[str] = None
    status: str = "open"

class Report(BaseModel):
    id: Optional[str] = None
    title: str
    description: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    scan_ids: List[str] = []
    findings: List[str] = []
    summary: Dict[str, Any] = {}
    recommendations: List[str] = []

class Project(BaseModel):
    id: Optional[str] = None
    name: str
    description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assets: List[str] = []
    scans: List[str] = []
    findings: List[str] = []
    reports: List[str] = []
    metadata: Dict[str, Any] = {} 