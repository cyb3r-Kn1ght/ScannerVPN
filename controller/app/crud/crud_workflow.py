# app/crud/crud_workflow.py
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.models.workflow_job import WorkflowJob
from app.schemas.workflow import WorkflowRequest

def get_workflow_by_id(db: Session, *, workflow_id: str) -> WorkflowJob | None:
    """Lấy một workflow bằng workflow_id."""
    return db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()

def create_workflow(db: Session, *, workflow_in: WorkflowRequest, workflow_id: str) -> WorkflowJob:
    """Tạo một bản ghi workflow mới trong DB."""
    db_obj = WorkflowJob(
        workflow_id=workflow_id,
        targets=workflow_in.targets,
        strategy=workflow_in.strategy,
        total_steps=0,  # Sẽ được cập nhật sau khi tạo sub-jobs
        vpn_profile=workflow_in.vpn_profile,
        vpn_country=workflow_in.country
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def update(db: Session, *, db_obj: WorkflowJob, obj_in: Dict[str, Any]) -> WorkflowJob:
    """Cập nhật thông tin của một workflow job."""
    for field, value in obj_in.items():
        setattr(db_obj, field, value)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def get_multi(db: Session, *, skip: int = 0, limit: int = 100) -> list[WorkflowJob]:
    """Lấy danh sách các workflow, sắp xếp theo ID giảm dần."""
    return db.query(WorkflowJob).order_by(WorkflowJob.id.desc()).offset(skip).limit(limit).all()

def remove(db: Session, *, db_obj: WorkflowJob):
    """Xóa một workflow job khỏi DB."""
    db.delete(db_obj)
    db.commit()