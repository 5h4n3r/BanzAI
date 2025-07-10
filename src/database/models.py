from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum
import re

# Enums for type safety
class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"

class ScanType(str, Enum):
    PORT_SCAN = "port_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    DNS_ANALYSIS = "dns_analysis"
    DIR_FUZZ = "dir_fuzz"
    VULN_SCAN = "vuln_scan"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class AssetStatus(str, Enum):
    DISCOVERED = "discovered"
    SCANNED = "scanned"
    VULNERABLE = "vulnerable"

class ProjectStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Custom datetime validator for database timestamps
def parse_datetime(value):
    """Parse datetime strings from database with timezone info"""
    if isinstance(value, str):
        # Handle PostgreSQL timestamp format: "2025-07-10 18:12:26.972016+00"
        # Remove timezone info for now since we're storing as UTC
        if '+' in value:
            value = value.split('+')[0].strip()
        elif '-' in value and value.count('-') > 2:  # Has timezone offset
            # Split on last '-' which is the timezone separator
            parts = value.rsplit('-', 1)
            if len(parts) == 2:
                value = parts[0].strip()
        
        # Parse the datetime
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            # Try parsing with microseconds
            try:
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    return value

# Base models
class ProjectBase(BaseModel):
    name: str = Field(..., description="Project name")
    description: Optional[str] = Field(None, description="Project description")
    target_domain: Optional[str] = Field(None, description="Primary target domain")
    status: ProjectStatus = Field(ProjectStatus.ACTIVE, description="Project status")

class AssetBase(BaseModel):
    project_id: UUID = Field(..., description="Associated project ID")
    type: AssetType = Field(..., description="Asset type")
    value: str = Field(..., description="Asset value (domain, IP, etc.)")
    status: AssetStatus = Field(AssetStatus.DISCOVERED, description="Asset status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class ScanBase(BaseModel):
    project_id: UUID = Field(..., description="Associated project ID")
    asset_id: UUID = Field(..., description="Associated asset ID")
    scan_type: ScanType = Field(..., description="Type of scan")
    status: ScanStatus = Field(ScanStatus.PENDING, description="Scan status")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration")
    results: Dict[str, Any] = Field(default_factory=dict, description="Scan results")

class FindingBase(BaseModel):
    project_id: UUID = Field(..., description="Associated project ID")
    asset_id: UUID = Field(..., description="Associated asset ID")
    scan_id: UUID = Field(..., description="Associated scan ID")
    severity: FindingSeverity = Field(..., description="Finding severity")
    category: str = Field(..., description="Finding category")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = Field(None, description="Finding description")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence data")
    remediation: Optional[str] = Field(None, description="Remediation steps")
    cve_ids: List[str] = Field(default_factory=list, description="Associated CVE IDs")

class ServiceBase(BaseModel):
    asset_id: UUID = Field(..., description="Associated asset ID")
    port: int = Field(..., ge=1, le=65535, description="Service port")
    protocol: str = Field("tcp", description="Service protocol")
    service_name: Optional[str] = Field(None, description="Service name")
    banner: Optional[str] = Field(None, description="Service banner")

class WebEndpointBase(BaseModel):
    asset_id: UUID = Field(..., description="Associated asset ID")
    path: str = Field(..., description="Web path")
    method: str = Field("GET", description="HTTP method")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    content_length: Optional[int] = Field(None, description="Content length")
    content_type: Optional[str] = Field(None, description="Content type")
    title: Optional[str] = Field(None, description="Page title")
    headers: Dict[str, Any] = Field(default_factory=dict, description="HTTP headers")

# Create models (for creating new records)
class ProjectCreate(ProjectBase):
    pass

class AssetCreate(AssetBase):
    pass

class ScanCreate(ScanBase):
    pass

class FindingCreate(FindingBase):
    pass

class ServiceCreate(ServiceBase):
    pass

class WebEndpointCreate(WebEndpointBase):
    pass

# Full models (with all fields including IDs and timestamps)
class Project(ProjectBase):
    id: UUID = Field(default_factory=uuid4, description="Project ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

class Asset(AssetBase):
    id: UUID = Field(default_factory=uuid4, description="Asset ID")
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

    @field_validator('discovered_at', 'last_updated', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

class Scan(ScanBase):
    id: UUID = Field(default_factory=uuid4, description="Scan ID")
    started_at: datetime = Field(default_factory=datetime.utcnow, description="Start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message if failed")

    @field_validator('started_at', 'completed_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

class Finding(FindingBase):
    id: UUID = Field(default_factory=uuid4, description="Finding ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

class Service(ServiceBase):
    id: UUID = Field(default_factory=uuid4, description="Service ID")
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")

    @field_validator('discovered_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

class WebEndpoint(WebEndpointBase):
    id: UUID = Field(default_factory=uuid4, description="Web endpoint ID")
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")

    @field_validator('discovered_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v)

    class Config:
        from_attributes = True

# Response models for API endpoints
class ProjectResponse(Project):
    assets_count: int = Field(0, description="Number of assets in project")
    scans_count: int = Field(0, description="Number of scans in project")
    findings_count: int = Field(0, description="Number of findings in project")

class AssetResponse(Asset):
    scans: List[Scan] = Field(default_factory=list, description="Associated scans")
    services: List[Service] = Field(default_factory=list, description="Discovered services")
    web_endpoints: List[WebEndpoint] = Field(default_factory=list, description="Discovered web endpoints")
    findings: List[Finding] = Field(default_factory=list, description="Associated findings")

class ScanResponse(Scan):
    asset: Optional[Asset] = Field(None, description="Associated asset")
    findings: List[Finding] = Field(default_factory=list, description="Findings from this scan")

# Utility models for API requests
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target to scan")
    scan_type: ScanType = Field(..., description="Type of scan to perform")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration")

class ProjectSummary(BaseModel):
    id: UUID
    name: str
    target_domain: Optional[str]
    status: ProjectStatus
    assets_count: int
    scans_count: int
    findings_count: int
    created_at: datetime
    updated_at: datetime

    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def validate_datetime(cls, v):
        return parse_datetime(v) 