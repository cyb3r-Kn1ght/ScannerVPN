from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    target = Column(String, index=True)
    resolved_ips = Column(JSON)
    open_ports = Column(JSON)
    scan_metadata = Column("metadata", JSON)

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
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
