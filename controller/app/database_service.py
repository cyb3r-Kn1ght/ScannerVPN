# Dữ liệu VPN mẫu (có thể tách ra file riêng nếu muốn)
VPN_PROFILES_BOOTSTRAP = {
    "VN": [
        {"filename": "103.57.130.113.ovpn", "hostname": "103.57.130.113", "ip": "103.57.130.113", "country": "VN"},
        {"filename": "vpngate_42.115.224.83_udp_1457.ovpn", "hostname": "vpngate_42.115.224.83_udp_1457", "ip": "42.115.224.83", "country": "VN"},
        {"filename": "vpngate_42.115.224.83_tcp_1416.ovpn", "hostname": "vpngate_42.115.224.83_tcp_1416", "ip": "42.115.224.83", "country": "VN"},
        {"filename": "vpngate_42.114.45.17_udp_1233.ovpn", "hostname": "vpngate_42.114.45.17_udp_1233", "ip": "42.114.45.17", "country": "VN"},
        {"filename": "vpngate_42.114.45.17_tcp_1443.ovpn", "hostname": "vpngate_42.114.45.17_tcp_1443", "ip": "42.114.45.17", "country": "VN"}
    ],
    "KR": [
        {"filename": "vpngate_221.168.226.24_tcp_1353.ovpn", "hostname": "vpngate_221.168.226.24_tcp_1353", "ip": "221.168.226.24", "country": "KR"},
        {"filename": "vpngate_61.255.180.199_udp_1619.ovpn", "hostname": "vpngate_61.255.180.199_udp_1619", "ip": "61.255.180.199", "country": "KR"},
        {"filename": "vpngate_61.255.180.199_tcp_1909.ovpn", "hostname": "vpngate_61.255.180.199_tcp_1909", "ip": "61.255.180.199", "country": "KR"},
        {"filename": "vpngate_221.168.226.24_udp_1670.ovpn", "hostname": "vpngate_221.168.226.24_udp_1670", "ip": "221.168.226.24", "country": "KR"},
        {"filename": "vpngate_121.139.214.237_tcp_1961.ovpn", "hostname": "vpngate_121.139.214.237_tcp_1961", "ip": "121.139.214.237", "country": "KR"}
    ],
    "JP": [
        {"filename": "vpngate_106.155.167.26_udp_1635.ovpn", "hostname": "vpngate_106.155.167.26_udp_1635", "ip": "106.155.167.26", "country": "JP"},
        {"filename": "vpngate_106.155.167.26_tcp_1878.ovpn", "hostname": "vpngate_106.155.167.26_tcp_1878", "ip": "106.155.167.26", "country": "JP"},
        {"filename": "vpngate_180.35.137.120_tcp_5555.ovpn", "hostname": "vpngate_180.35.137.120_tcp_5555", "ip": "180.35.137.120", "country": "JP"},
        {"filename": "vpngate_219.100.37.113_tcp_443.ovpn", "hostname": "vpngate_219.100.37.113_tcp_443", "ip": "219.100.37.113", "country": "JP"}
    ],
    "GB": [
        {"filename": "45.149.184.180.ovpn", "hostname": "45.149.184.180", "ip": "45.149.184.180", "country": "GB"}
    ],
    "HK": [
        {"filename": "70.36.97.79.ovpn", "hostname": "70.36.97.79", "ip": "70.36.97.79", "country": "HK"}
    ]
}

def init_vpn_profiles_if_empty(db, vpn_data=VPN_PROFILES_BOOTSTRAP):
    """
    Khởi tạo dữ liệu bảng vpn_profiles nếu bảng đang trống.
    vpn_data: dict dạng {country: [list profile dict]}
    """
    from app.models import VpnProfile
    if db.query(VpnProfile).count() == 0:
        for country, profiles in vpn_data.items():
            for p in profiles:
                vpn = VpnProfile(
                    filename=p["filename"],
                    hostname=p["hostname"],
                    ip=p["ip"],
                    country=country,
                    status="idle",
                    in_use_by=[]
                )
                db.add(vpn)
        db.commit()
# ============ VPN Profile CRUD ============
from app import models, schemas
from fastapi import HTTPException
from sqlalchemy.orm import Session

def get_vpn_profiles(db: Session):
    vpn_profiles = db.query(models.VpnProfile).all()
    return [schemas.VpnProfile.from_orm(v) for v in vpn_profiles]

def update_vpn_profile_status(db: Session, filename: str, action: str, scanner_id: str = None, status: str = None):
    vpn = db.query(models.VpnProfile).filter(models.VpnProfile.filename == filename).first()
    if not vpn:
        raise HTTPException(status_code=404, detail="VPN profile not found")
    if action == "connect":
        if scanner_id and scanner_id not in (vpn.in_use_by or []):
            new_in_use = list(vpn.in_use_by or [])
            new_in_use.append(scanner_id)
            vpn.in_use_by = new_in_use  # Gán lại để SQLAlchemy nhận biết thay đổi
        vpn.status = status or "connected"
    elif action == "disconnect":
        if scanner_id and scanner_id in (vpn.in_use_by or []):
            new_in_use = [sid for sid in (vpn.in_use_by or []) if sid != scanner_id]
            vpn.in_use_by = new_in_use
        if not vpn.in_use_by:
            vpn.status = status or "idle"
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
    db.commit()
    db.refresh(vpn)
    return schemas.VpnProfile.from_orm(vpn)
# --- Generic Pagination Helper ---
from sqlalchemy.orm import Query
def get_paginated_list(query: Query, schema_cls, page=1, page_size=10):
    total_items = query.count()
    import math
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1
    offset = (page - 1) * page_size
    has_next = page < total_pages
    has_previous = page > 1
    results = query.offset(offset).limit(page_size).all()
    from app import schemas
    pagination_info = schemas.PaginationInfo(
        total_items=total_items,
        total_pages=total_pages,
        current_page=page,
        page_size=page_size,
        has_next=has_next,
        has_previous=has_previous
    )
    return schema_cls(
        pagination=pagination_info,
        results=results
    )
# --- Workflow Status Query ---
def get_workflow_status(workflow_id: str, db):
    """
    Lấy trạng thái hiện tại của workflow, bao gồm workflow, sub_jobs, progress (theo mockStatusData).
    Bổ sung: trả về target(s), vpn (quốc gia), thời gian tạo workflow.
    """
    workflow = db.query(models.WorkflowJob).filter(
        models.WorkflowJob.workflow_id == workflow_id
    ).first()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Get sub-jobs
    sub_jobs = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id
    ).order_by(models.ScanJob.step_order).all()

    sub_job_list = []
    for job in sub_jobs:
        job_dict = {
            "job_id": job.job_id,
            "tool": job.tool,
            "status": job.status,
            "step_order": job.step_order
        }
        if job.error_message:
            job_dict["error_message"] = job.error_message
        sub_job_list.append(job_dict)

    # Progress calculation
    completed = sum(1 for job in sub_jobs if job.status == "completed")
    failed = sum(1 for job in sub_jobs if job.status == "failed")
    total = workflow.total_steps or len(sub_jobs)
    percentage = ((completed + failed) / total * 100) if total > 0 else 0

    # Compose workflow info
    workflow_info = {
        "workflow_id": workflow.workflow_id,
        "status": workflow.status,
        "updated_at": getattr(workflow, "updated_at", None) or getattr(workflow, "timestamp", None),
        "created_at": getattr(workflow, "created_at", None) or getattr(workflow, "timestamp", None),
        "targets": getattr(workflow, "targets", []),
        "vpn": getattr(workflow, "vpn_country", None) or getattr(workflow, "vpn_profile", None)
    }

    return {
        "workflow": workflow_info,
        "sub_jobs": sub_job_list,
        "progress": {
            "completed": completed,
            "total": total,
            "failed": failed,
            "percentage": percentage
        }
    }
# --- Additional DB Query Functions ---
from app import schemas
from typing import Optional

def read_scan_results(db, page=1, page_size=10, limit=None, target=None, job_id=None, workflow_id=None, latest=False):
    if limit is not None:
        page_size = limit
    query = db.query(models.ScanResult)
    if target:
        query = query.filter(models.ScanResult.target == target)
    if job_id:
        query = query.filter(models.ScanResult.scan_metadata.op('->>')('job_id') == job_id)
    if workflow_id:
        query = query.filter(models.ScanResult.workflow_id == workflow_id)
    if latest:
        query = query.order_by(models.ScanResult.timestamp.desc())
    else:
        query = query.order_by(models.ScanResult.id.desc())
    total_items = query.count()
    import math
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1
    offset = (page - 1) * page_size
    has_next = page < total_pages
    has_previous = page > 1
    results = query.offset(offset).limit(page_size).all()
    pagination_info = schemas.PaginationInfo(
        total_items=total_items,
        total_pages=total_pages,
        current_page=page,
        page_size=page_size,
        has_next=has_next,
        has_previous=has_previous
    )
    return schemas.PaginatedScanResults(
        pagination=pagination_info,
        results=results
    )

def read_scan_results_list(db, skip=0, limit=100, target=None, job_id=None, latest=False):
    query = db.query(models.ScanResult)
    if target:
        query = query.filter(models.ScanResult.target == target)
    if job_id:
        query = query.filter(models.ScanResult.scan_metadata.op('->>')('job_id') == job_id)
    if latest:
        query = query.order_by(models.ScanResult.timestamp.desc())
    else:
        query = query.order_by(models.ScanResult.id.desc())
    return query.offset(skip).limit(limit).all()

def read_scan_jobs(db, page=1, page_size=10):
    query = db.query(models.ScanJob).order_by(models.ScanJob.id.desc())
    total_items = query.count()
    import math
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1
    offset = (page - 1) * page_size
    has_next = page < total_pages
    has_previous = page > 1
    results = query.offset(offset).limit(page_size).all()
    pagination_info = schemas.PaginationInfo(
        total_items=total_items,
        total_pages=total_pages,
        current_page=page,
        page_size=page_size,
        has_next=has_next,
        has_previous=has_previous
    )
    return schemas.PaginatedScanJobs(
        pagination=pagination_info,
        results=results
    )

def read_scan_jobs_list(db, skip=0, limit=100):
    return db.query(models.ScanJob).order_by(models.ScanJob.id.desc()).offset(skip).limit(limit).all()
# --- GET/QUERY FUNCTIONS ---
from fastapi import HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
from app import models

def get_sub_job_results(sub_job_id: str, db: Session, page: int = 1, page_size: int = 10):
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == sub_job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Sub-job not found")
    results_query = db.query(models.ScanResult).filter(
        models.ScanResult.scan_metadata.op('->>')('job_id') == sub_job_id
    )
    total_items = results_query.count()
    import math
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1
    offset = (page - 1) * page_size
    has_next = page < total_pages
    has_previous = page > 1
    results = results_query.offset(offset).limit(page_size).all()
    tool = job.tool
    out = []
    for r in results:
        meta = r.scan_metadata or {}
        if isinstance(meta, str):
            import json
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        if tool == "dns-lookup":
            out.append({"target": r.target, "resolved_ips": r.resolved_ips or []})
        elif tool == "port-scan":
            for p in r.open_ports or []:
                out.append({"ip": r.target, "port": p.get("port"), "protocol": p.get("protocol"), "service": p.get("service")})
        elif tool == "httpx-scan":
            for ep in meta.get("httpx_results", []):
                out.append(ep)
        elif tool == "nuclei-scan":
            for finding in meta.get("nuclei_results", []):
                info = finding.get("info", {}) or {}
                out_item = {
                    "template": finding.get("template"),
                    "template-id": finding.get("template-id"),
                    "template-url": finding.get("template-url"),
                    "name": info.get("name") or finding.get("name"),
                    "severity": info.get("severity") or finding.get("severity"),
                    "tags": info.get("tags") or finding.get("tags"),
                    "matched_at": finding.get("matched-at"),
                    "type": finding.get("type"),
                    "host": finding.get("host"),
                    "ip": finding.get("ip"),
                    "port": finding.get("port"),
                    "timestamp": finding.get("timestamp")
                }
                # Gather all other fields as extra_fields
                extra = {}
                for k, v in finding.items():
                    if k not in ("template", "template-id", "template-url", "type", "host", "ip", "port", "timestamp", "matched-at", "matcher-status", "info"):
                        extra[k] = v
                for k, v in info.items():
                    if k not in ("name", "severity", "tags"):
                        extra[k] = v
                if extra:
                    out_item["extra_fields"] = extra
                out.append(out_item)
        elif tool == "wpscan-scan":
            for finding in meta.get("wpscan_results", []):
                out.append({
                    "name": finding.get("name"),
                    "confidence": finding.get("confidence"),
                    "fixed_in": finding.get("fixed_in"),
                    "references": finding.get("references")
                })
        elif tool == "dirsearch-scan":
            for f in meta.get("dirsearch_results", []):
                out.append(f)
        else:
            out.append(meta)
    pagination_info = {
        "total_items": total_items,
        "total_pages": total_pages,
        "current_page": page,
        "page_size": page_size,
        "has_next": has_next,
        "has_previous": has_previous
    }
    return {"pagination": pagination_info, "results": out}

def get_workflow_summary(workflow_id: str, db: Session):
    workflow = db.query(models.WorkflowJob).filter(
        models.WorkflowJob.workflow_id == workflow_id
    ).first()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    sub_jobs = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id
    ).all()
    job_ids = [job.job_id for job in sub_jobs]
    scan_results = db.query(models.ScanResult).filter(
        models.ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
    ).all()
    summary_by_target = {}
    for r in scan_results:
        tgt = r.target
        if tgt not in summary_by_target:
            summary_by_target[tgt] = {
                "target": tgt,
                "dns_records": [],
                "open_ports": [],
                "web_technologies": set(),
                "vulnerabilities": []
            }
        if r.resolved_ips:
            summary_by_target[tgt]["dns_records"].extend(r.resolved_ips)
        if r.open_ports:
            for p in r.open_ports:
                summary_by_target[tgt]["open_ports"].append({
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service")
                })
        meta = r.scan_metadata or {}
        if isinstance(meta, str):
            import json
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        if "httpx_results" in meta:
            for ep in meta["httpx_results"]:
                ws = ep.get("webserver")
                if ws:
                    summary_by_target[tgt]["web_technologies"].add(ws)
        if "nuclei_results" in meta:
            for finding in meta["nuclei_results"]:
                info = finding.get("info", {})
                name = finding.get("name") or info.get("name")
                sev = finding.get("severity") or info.get("severity")
                if name and sev:
                    summary_by_target[tgt]["vulnerabilities"].append({"name": name, "severity": sev})
    for tgt in summary_by_target:
        summary_by_target[tgt]["web_technologies"] = list(summary_by_target[tgt]["web_technologies"])
    return {"summary": list(summary_by_target.values())}

def read_scan_job(job_id: str, db: Session):
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job
import logging
from app import models, database
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

def clear_all_database_tables():
    """
    Xóa toàn bộ dữ liệu từ tất cả các bảng trong database.
    Cẩn thận: Thao tác này không thể hoàn tác!
    """
    with database.SessionLocal() as db:
        workflow_count = db.query(models.WorkflowJob).count()
        scan_job_count = db.query(models.ScanJob).count()
        scan_result_count = db.query(models.ScanResult).count()
        logger.info(f"Clearing database: {workflow_count} workflows, {scan_job_count} scan jobs, {scan_result_count} scan results")
        db.query(models.ScanResult).delete()
        db.query(models.ScanJob).delete()
        db.query(models.WorkflowJob).delete()
        db.commit()
        logger.info("Database cleared successfully")
        return {
            "status": "success",
            "message": "All database tables cleared successfully",
            "deleted_counts": {
                "workflows": workflow_count,
                "scan_jobs": scan_job_count,
                "scan_results": scan_result_count
            }
        }

def clear_scan_results_only():
    """
    Xóa chỉ bảng scan_results, giữ lại workflows và scan_jobs.
    """
    with database.SessionLocal() as db:
        result_count = db.query(models.ScanResult).count()
        logger.info(f"Clearing scan_results table: {result_count} records")
        db.query(models.ScanResult).delete()
        db.commit()
        logger.info("Scan results cleared successfully")
        return {
            "status": "success",
            "message": "Scan results table cleared successfully",
            "deleted_count": result_count
        }

def clear_workflows_and_jobs():
    """
    Xóa workflows và scan_jobs, giữ lại scan_results.
    """
    with database.SessionLocal() as db:
        workflow_count = db.query(models.WorkflowJob).count()
        scan_job_count = db.query(models.ScanJob).count()
        logger.info(f"Clearing workflows and jobs: {workflow_count} workflows, {scan_job_count} scan jobs")
        db.query(models.ScanJob).delete()
        db.query(models.WorkflowJob).delete()
        db.commit()
        logger.info("Workflows and jobs cleared successfully")
        return {
            "status": "success",
            "message": "Workflows and scan jobs cleared successfully",
            "deleted_counts": {
                "workflows": workflow_count,
                "scan_jobs": scan_job_count
            }
        }
