# Thêm endpoint: GET /api/sub_jobs/{sub_job_id}/results
from fastapi import APIRouter, Depends, Query, status, HTTPException
from typing import Optional
from app.schemas import scan_result
from app.services.result_service import ResultService
from app.api.deps import get_result_service, get_db
from sqlalchemy.orm import Session

router = APIRouter()

# Thêm endpoint: GET /api/sub_jobs/{sub_job_id}/results
@router.get("/api/sub_jobs/{sub_job_id}/results", summary="Lấy kết quả của sub-job, tự động merge nếu là port-scan chia nhỏ")
def get_sub_job_results(
        sub_job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        result_service: ResultService = Depends(get_result_service),
        db: Session = Depends(get_db)
):
        return result_service.get_sub_job_results(sub_job_id=sub_job_id, page=page, page_size=page_size, db=db)

# Giữ nguyên endpoint gốc: POST /api/scan_results
@router.post("/api/scan_results", status_code=status.HTTP_204_NO_CONTENT, summary="Callback để scanner-node gửi kết quả về")
def receive_scan_result(
        *,
        result_in: scan_result.ScanResultCreate,
        result_service: ResultService = Depends(get_result_service)
):
    """
    Endpoint này được các scanner pod gọi để gửi trả kết quả quét.
    Nó sẽ lưu kết quả và cập nhật trạng thái của job/workflow tương ứng.
    """
    result_service.process_incoming_result(result_in=result_in)

# Giữ nguyên endpoint gốc: GET /api/scan_results
@router.get("/api/scan_results", response_model=scan_result.PaginatedScanResults, summary="Lấy danh sách kết quả quét")
def get_scan_results(
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        workflow_id: Optional[str] = Query(None),
        job_id: Optional[str] = Query(None),
        result_service: ResultService = Depends(get_result_service)
):
    """
    Lấy danh sách các kết quả quét đã được lưu, có hỗ trợ phân trang và lọc.
    """
    return result_service.get_paginated_results(page=page, page_size=page_size, workflow_id=workflow_id, job_id=job_id)