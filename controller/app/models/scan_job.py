# app/models/scan_job.py
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base import Base # <--- Import từ base
import datetime

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, index=True)
    scanner_job_name = Column(String, nullable=True)
    tool = Column(String, index=True)
    targets = Column(JSON)
    options = Column(JSON)
    status = Column(String, default="submitted")
    error_message = Column(String, nullable=True)
    vpn_profile = Column(String, nullable=True)
    vpn_country = Column(String, nullable=True)
    vpn_hostname = Column(String, nullable=True)
    vpn_assignment = Column(JSON, nullable=True)
    workflow_id = Column(String, ForeignKey("workflow_jobs.workflow_id"), nullable=True)
    workflow = relationship("WorkflowJob", back_populates="sub_jobs")
    step_order = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)