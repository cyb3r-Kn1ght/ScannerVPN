# app/crud/crud_scan_result.py
import math
from sqlalchemy.orm import Session
from app.models.scan_result import ScanResult
from app.schemas.scan_result import ScanResultCreate, PaginatedScanResults, PaginationInfo

def create(db: Session, *, result_in: ScanResultCreate) -> ScanResult:
    """Lưu một kết quả quét mới vào DB."""
    scan_metadata = dict(result_in.scan_metadata) if result_in.scan_metadata else {}
    for k in ["httpx_results", "http_endpoints", "http_metadata"]:
        v = getattr(result_in, k, None)
        if v is not None:
            scan_metadata[k] = v

    db_obj = ScanResult(
        target=result_in.target,
        resolved_ips=result_in.resolved_ips,
        open_ports=result_in.open_ports,
        scan_metadata=scan_metadata,
        workflow_id=result_in.workflow_id
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def get_multi_paginated(db: Session, *, page: int, page_size: int, workflow_id: str | None, job_id: str | None) -> PaginatedScanResults:
    """Lấy danh sách kết quả, có phân trang và lọc."""
    query = db.query(ScanResult)
    if workflow_id:
        query = query.filter(ScanResult.workflow_id == workflow_id)
    if job_id:
        query = query.filter(ScanResult.scan_metadata.op('->>')('job_id') == job_id)

    total_items = query.count()
    offset = (page - 1) * page_size
    results = query.order_by(ScanResult.id.desc()).offset(offset).limit(page_size).all()

    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1

    pagination = PaginationInfo(
        total_items=total_items,
        total_pages=total_pages,
        current_page=page,
        page_size=page_size,
        has_next=page < total_pages,
        has_previous=page > 1
    )
    return PaginatedScanResults(pagination=pagination, results=results)