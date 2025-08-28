# app/crud/crud_scan_job.py
from sqlalchemy.orm import Session
from typing import Any, Dict, List
from app.models.scan_job import ScanJob
from app.models.scan_result import ScanResult

def get(db: Session, *, job_id: str) -> ScanJob | None:
    """Lấy một scan job bằng job_id."""
    return db.query(ScanJob).filter(ScanJob.job_id == job_id).first()

def get_by_workflow(db: Session, *, workflow_id: str) -> list[ScanJob]:
    """Lấy tất cả các sub-job của một workflow."""
    return db.query(ScanJob).filter(ScanJob.workflow_id == workflow_id).order_by(ScanJob.step_order).all()

def create(db: Session, *, job_obj: ScanJob) -> ScanJob:
    """Tạo một scan job mới trong DB từ một đối tượng ScanJob đã được khởi tạo."""
    db.add(job_obj)
    db.commit()
    db.refresh(job_obj)
    return job_obj

def update(db: Session, *, db_obj: ScanJob, obj_in: Dict[str, Any]) -> ScanJob:
    """Cập nhật thông tin của một scan job."""
    for field, value in obj_in.items():
        setattr(db_obj, field, value)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def remove_and_related_results(db: Session, *, db_obj: ScanJob):
    """Xóa một scan job và tất cả các kết quả liên quan của nó."""
    # Xóa các kết quả scan liên quan
    db.query(ScanResult).filter(
        ScanResult.workflow_id == db_obj.workflow_id,
        ScanResult.scan_metadata.op('->>')('job_id') == db_obj.job_id
    ).delete(synchronize_session=False)

    # Xóa job
    db.delete(db_obj)
    db.commit()