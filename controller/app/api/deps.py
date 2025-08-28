# app/api/deps.py
from fastapi import Depends
from sqlalchemy.orm import Session
from db.session import SessionLocal
from services.admin_service import AdminService
from services.workflow_service import WorkflowService
from services.result_service import ResultService
from services.scan_job_service import ScanJobService

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_admin_service(db: Session = Depends(get_db)) -> AdminService:
    return AdminService(db)

def get_workflow_service(db: Session = Depends(get_db)) -> WorkflowService:
    return WorkflowService(db)

def get_result_service(db: Session = Depends(get_db)) -> ResultService:
    return ResultService(db)

def get_scan_job_service(db: Session = Depends(get_db)) -> ScanJobService:
    return ScanJobService(db)