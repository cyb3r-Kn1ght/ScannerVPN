# app/models/ip_pool.py
from sqlalchemy import Column, Integer, String
from app.db.base import Base

class IpPool(Base):
    __tablename__ = "ip_pool"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, unique=True, index=True)
