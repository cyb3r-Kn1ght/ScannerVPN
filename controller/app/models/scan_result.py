# app/models/scan_result.py
from sqlalchemy import Column, Integer, String, DateTime, JSON
from app.db.base import Base # <--- Import từ base
import datetime

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    target = Column(String, index=True)
    resolved_ips = Column(JSON)
    open_ports = Column(JSON)
    scan_metadata = Column("metadata", JSON)
    workflow_id = Column(String, index=True, nullable=True)