# app/api/endpoints/scan_results.py
from fastapi import APIRouter, Depends, Query, status
from typing import Optional
from app import schemas
from services.result_service import ResultService
from api.deps import get_result_service

router = APIRouter()

# Giữ nguyên endpoint gốc: POST /api/scan_results
@router.post("/api/scan_results", status_code=status.HTTP_204_NO_CONTENT, summary="Callback để scanner-node gửi kết quả về")
def receive_scan_result(
        *,
        result_in: schemas.scan_result.ScanResultCreate,
        result_service: ResultService = Depends(get_result_service)
):
    """
    Endpoint này được các scanner pod gọi để gửi trả kết quả quét.
    Nó sẽ lưu kết quả và cập nhật trạng thái của job/workflow tương ứng.
    """
    result_service.process_incoming_result(result_in=result_in)

# Giữ nguyên endpoint gốc: GET /api/scan_results
@router.get("/api/scan_results", response_model=schemas.scan_result.PaginatedScanResults, summary="Lấy danh sách kết quả quét")
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