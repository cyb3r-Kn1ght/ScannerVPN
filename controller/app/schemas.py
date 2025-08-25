
from pydantic import BaseModel
from typing import List, Any, Dict, Optional, Union
from datetime import datetime
# ============ VPN Profile Schemas ============

class VpnProfileBase(BaseModel):
    filename: str
    hostname: Optional[str] = None
    status: str = "idle"  # idle, connected, disconnected
    in_use_by: List[str] = []  # Danh sách job_id đang sử dụng VPN này
    ip: Optional[str] = None
    country: Optional[str] = None
class VpnProfileCreate(VpnProfileBase):
    pass

class VpnProfileUpdate(BaseModel):
    status: Optional[str] = None
    scanner_id: Optional[str] = None  # job_id
    action: str  # "connect" hoặc "disconnect"

class VpnProfile(VpnProfileBase):
    id: int

    class Config:
        from_attributes = True

class ScanResultCreate(BaseModel):
    target: str
    resolved_ips: List[str] = []
    open_ports: Union[List[int], List[Dict[str, Any]]] = []
    scan_metadata: Dict[str, Any] = {}
    workflow_id: Optional[str] = None
    httpx_results: Optional[List[Dict[str, Any]]] = None
    http_endpoints: Optional[List[Dict[str, Any]]] = None
    http_metadata: Optional[Dict[str, Any]] = None
    
class ScanResult(ScanResultCreate):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True

class ScanJobRequest(BaseModel):
    tool: str                        # Tên tool, trùng với "name" trong tools.yaml
    targets: List[str]
    options: Dict[str, Any] = {}     # Tham số tuỳ biến cho tool, key trùng với tên flag
    vpn_profile: Optional[str] = None
    country: Optional[str] = None    # Country code: "VN", "JP", "KR", etc.

class ScanJob(BaseModel):
    id: int
    job_id: str
    tool: str
    targets: List[str]
    options: Dict[str, Any]
    status: str
    scanner_job_name: Optional[str] = None
    error_message: Optional[str] = None
    
    # VPN Information
    vpn_profile: Optional[str] = None
    vpn_country: Optional[str] = None
    vpn_hostname: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None
    
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class PaginationInfo(BaseModel):
    total_items: int
    total_pages: int
    current_page: int
    page_size: int
    has_next: bool
    has_previous: bool

class PaginatedScanResults(BaseModel):
    pagination: PaginationInfo
    results: List[ScanResult]

class PaginatedScanJobs(BaseModel):
    pagination: PaginationInfo
    results: List[ScanJob]

# ============ Workflow Schemas ============

class WorkflowStep(BaseModel):
    tool_id: str                     # Tool name: "dns-lookup", "port-scan", "httpx-scan", "nuclei-scan", "wpscan-scan"
    params: Dict[str, Any] = {}      # Tool-specific parameters

class WorkflowRequest(BaseModel):
    targets: List[str]               # List of targets to scan
    strategy: str = "wide"           # "wide" (rộng - quét tất cả IP bằng 1 tool) hoặc "deep" (sâu - quét 1 IP bằng tất cả tools)
    steps: List[WorkflowStep]        # List of scanning steps
    vpn_profile: Optional[str] = None # VPN profile để dùng cho tất cả steps
    country: Optional[str] = None     # Country code cho VPN selection

class WorkflowJob(BaseModel):
    id: int
    workflow_id: str
    targets: List[str]
    strategy: str
    status: str                      # "pending", "running", "completed", "failed", "cancelled"
    
    # VPN Information (shared across all steps)
    vpn_profile: Optional[str] = None
    vpn_country: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None
    
    # Progress tracking
    total_steps: int
    completed_steps: int
    failed_steps: int
    
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class WorkflowStepResult(BaseModel):
    step_order: int
    tool_id: str
    job_id: str
    status: str
    params: Dict[str, Any]

class WorkflowDetail(BaseModel):
    workflow: WorkflowJob
    sub_jobs: List[ScanJob]
    progress: Dict[str, Any]

class PaginatedWorkflows(BaseModel):
    pagination: PaginationInfo
    results: List[WorkflowJob]
