# app/api/endpoints/scan_jobs.py
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app import crud, models
from app.schemas import scan_job
from app.services.scan_job_service import ScanJobService
from api.deps import get_db, get_scan_job_service

router = APIRouter()

# Giữ nguyên các endpoint gốc cho từng tool
@router.post("/api/scan/{tool_name}", status_code=201, summary="Tạo job quét đơn lẻ cho một tool cụ thể")
async def create_tool_scan(
        tool_name: str,
    req: scan_job.ScanJobRequest,
        scan_job_service: ScanJobService = Depends(get_scan_job_service)
):
    req.tool = tool_name
    return await scan_job_service.create_and_dispatch_scan(job_in=req)

# Giữ nguyên endpoint gốc: GET /api/scan_jobs/{job_id}
@router.get("/api/scan_jobs/{job_id}", response_model=scan_job.ScanJob, summary="Lấy thông tin chi tiết của một scan job")
def get_scan_job_details(
        job_id: str,
        db: Session = Depends(get_db)
):
    job = crud.crud_scan_job.get(db=db, job_id=job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

# Giữ nguyên endpoint gốc: GET /api/scan_jobs
@router.get("/api/scan_jobs", response_model=List[scan_job.ScanJob], summary="Lấy danh sách các scan job")
def get_scan_jobs_list(
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1),
        db: Session = Depends(get_db)
):
    # Logic này đơn giản, có thể gọi trực tiếp CRUD
    jobs = db.query(models.ScanJob).order_by(models.ScanJob.id.desc()).offset(skip).limit(limit).all()
    return jobs

# Giữ nguyên endpoint gốc: DELETE /api/scan_jobs/{job_id}
@router.delete("/api/scan_jobs/{job_id}", summary="Xóa một scan job và tất cả tài nguyên liên quan")
def delete_scan_job(
        job_id: str,
        scan_job_service: ScanJobService = Depends(get_scan_job_service)
):
    return scan_job_service.delete_scan_job(job_id=job_id)

# Giữ nguyên endpoint gốc: PATCH /api/scan_jobs/{job_id}/status
@router.patch("/api/scan_jobs/{job_id}/status", summary="Cập nhật trạng thái của một scan job")
def update_job_status(
        job_id: str,
        status_update: Dict[str, Any] = Body(...),
        db: Session = Depends(get_db)
):
    job_db = crud.crud_scan_job.get(db=db, job_id=job_id)
    if not job_db:
        raise HTTPException(status_code=404, detail="Job not found")

    new_status = status_update.get("status")
    if new_status not in ["submitted", "running", "completed", "failed"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    updated_job = crud.crud_scan_job.update(db=db, db_obj=job_db, obj_in={"status": new_status})
    return {"job_id": updated_job.job_id, "status": updated_job.status}