# app/schemas/scan_result.py
from pydantic import BaseModel
from typing import List, Any, Dict, Optional, Union
from datetime import datetime
from .common import PaginationInfo # <--- Import từ file common

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

class PaginatedScanResults(BaseModel):
    pagination: PaginationInfo
    results: List[ScanResult]