# app/services/ip_pool_service.py
from sqlalchemy.orm import Session
from app.models.ip_pool import IpPool

def get_ip_pool_targets(db: Session) -> list:
    """Lấy danh sách target từ bảng ip_pool."""
    return [row.target for row in db.query(IpPool).all()]
