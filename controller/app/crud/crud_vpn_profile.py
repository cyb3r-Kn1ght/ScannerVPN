# app/crud/crud_vpn_profile.py
from sqlalchemy.orm import Session
from app.models.vpn_profile import VpnProfile

def get_all(db: Session) -> list[VpnProfile]:
    return db.query(VpnProfile).all()

def get_by_filename(db: Session, *, filename: str) -> VpnProfile | None:
    return db.query(VpnProfile).filter(VpnProfile.filename == filename).first()

def update_status(db: Session, *, vpn_profile: VpnProfile, action: str, scanner_id: str | None, status: str | None) -> VpnProfile:
    """Cập nhật trạng thái và danh sách sử dụng của một VPN profile."""
    if action == "connect":
        if scanner_id and scanner_id not in (vpn_profile.in_use_by or []):
            new_in_use = list(vpn_profile.in_use_by or [])
            new_in_use.append(scanner_id)
            vpn_profile.in_use_by = new_in_use
        vpn_profile.status = status or "connected"
    elif action == "disconnect":
        if scanner_id and scanner_id in (vpn_profile.in_use_by or []):
            new_in_use = [sid for sid in (vpn_profile.in_use_by or []) if sid != scanner_id]
            vpn_profile.in_use_by = new_in_use
        if not vpn_profile.in_use_by:
            vpn_profile.status = status or "idle"

    db.add(vpn_profile)
    db.commit()
    db.refresh(vpn_profile)
    return vpn_profile