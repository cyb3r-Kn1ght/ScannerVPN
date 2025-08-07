from pydantic import BaseModel
from typing import List, Any, Dict, Optional
from datetime import datetime

class ScanResultCreate(BaseModel):
    target: str
    resolved_ips: List[str] = []
    open_ports: List[int] = []
    scan_metadata: Dict[str, Any] = {}

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
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
