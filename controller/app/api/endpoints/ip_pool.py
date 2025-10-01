
# app/api/endpoints/ip_pool.py
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.ip_pool import IpPool
from pydantic import BaseModel


router = APIRouter()

class TargetsRequest(BaseModel):
    targets: list[str]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/api/ip_pool/add", summary="Thêm nhiều target vào IP pool")
def add_ip_pool_targets(req: TargetsRequest, db: Session = Depends(get_db)):
    if not req.targets or not isinstance(req.targets, list):
        raise HTTPException(status_code=400, detail="targets must be a non-empty list")
    results = []
    for target in req.targets:
        if not target:
            continue
        existing = db.query(IpPool).filter(IpPool.target == target).first()
        if existing:
            results.append({"target": target, "status": "exists"})
            continue
        ip = IpPool(target=target)
        db.add(ip)
        db.commit()
        db.refresh(ip)
        results.append({"id": ip.id, "target": ip.target, "status": "added"})
    return results

@router.get("/api/ip_pool/list", summary="Lấy danh sách target trong IP pool")
def list_ip_pool_targets(db: Session = Depends(get_db)):
    targets = db.query(IpPool).all()
    return [ip.target for ip in targets]

@router.delete("/api/ip_pool/delete", summary="Xoá target khỏi IP pool")
def delete_ip_pool_target(target: str, db: Session = Depends(get_db)):
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    ip = db.query(IpPool).filter(IpPool.target == target).first()
    if not ip:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(ip)
    db.commit()
    return {"status": "deleted", "target": target}
