# app/schemas/vpn_profile.py
from pydantic import BaseModel
from typing import List, Optional

class VpnProfileBase(BaseModel):
    filename: str
    hostname: Optional[str] = None
    status: str = "idle"
    in_use_by: List[str] = []
    ip: Optional[str] = None
    country: Optional[str] = None

class VpnProfileCreate(VpnProfileBase):
    pass

class VpnProfileUpdate(BaseModel):
    status: Optional[str] = None
    scanner_id: Optional[str] = None
    action: str

class VpnProfile(VpnProfileBase):
    id: int

    class Config:
        from_attributes = True