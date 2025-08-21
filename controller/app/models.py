from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime


Base = declarative_base()

# ============ VPN Profile Model ============
from sqlalchemy.types import PickleType
class VpnProfile(Base):
    __tablename__ = "vpn_profiles"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, unique=True, index=True)
    hostname = Column(String, nullable=True)
    status = Column(String, default="idle")  # idle, connected, disconnected
    in_use_by = Column(PickleType, default=list)  # List các job_id đang sử dụng VPN này

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    target = Column(String, index=True)
    resolved_ips = Column(JSON)
    open_ports = Column(JSON)
    scan_metadata = Column("metadata", JSON)
    workflow_id = Column(String, index=True, nullable=True)  # Direct workflow_id field

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, index=True)
    tool = Column(String, index=True)
    targets = Column(JSON)
    options = Column(JSON)
    status = Column(String, default="pending")  # pending, submitted, running, completed, failed
    scanner_job_name = Column(String, nullable=True)
    error_message = Column(String, nullable=True)
    
    # VPN Information
    vpn_profile = Column(String, nullable=True)  # VPN filename được assign
    vpn_country = Column(String, nullable=True)  # Country code (VN, JP, KR, etc.)
    vpn_hostname = Column(String, nullable=True)  # VPN server hostname
    vpn_assignment = Column(JSON, nullable=True)  # Full VPN assignment metadata
    
    # Workflow relationship
    workflow_id = Column(String, ForeignKey("workflow_jobs.workflow_id"), nullable=True)
    workflow = relationship("WorkflowJob", back_populates="sub_jobs")
    
    # Step info trong workflow
    step_order = Column(Integer, nullable=True)  # 1, 2, 3, 4...
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class WorkflowJob(Base):
    """Job tổng chứa nhiều tool jobs"""
    __tablename__ = "workflow_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(String, unique=True, index=True)  # workflow-abc123
    targets = Column(JSON)
    strategy = Column(String, default="wide")  # wide, deep
    status = Column(String, default="pending")  # pending, running, completed, failed, cancelled
    
    # VPN chung cho toàn bộ workflow
    vpn_profile = Column(String, nullable=True)
    vpn_country = Column(String, nullable=True)
    vpn_assignment = Column(JSON, nullable=True)
    
    # Progress tracking
    total_steps = Column(Integer, default=0)
    completed_steps = Column(Integer, default=0)
    failed_steps = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationship với sub-jobs
    sub_jobs = relationship("ScanJob", back_populates="workflow")
