
import os
import json
import math
import random
import asyncio
import yaml
import httpx
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from uuid import uuid4
from pydantic import BaseModel
from app import models, schemas, database
from app.database_service import (
    clear_all_database_tables,
    clear_scan_results_only,
    clear_workflows_and_jobs,
    get_sub_job_results,
    get_workflow_summary,
    read_scan_job,
    read_scan_results,
    read_scan_results_list,
    read_scan_jobs,
    read_scan_jobs_list,
    get_workflow_status,
    get_paginated_list
)
from app.vpn_service import VPNService

# Khởi tạo FastAPI app

app = FastAPI()

# --- Auto-populate VPN profiles table if empty ---
from app.database_service import init_vpn_profiles_if_empty
from sqlalchemy.exc import OperationalError
try:
    db = database.SessionLocal()
    init_vpn_profiles_if_empty(db)
    db.close()
except OperationalError as e:
    # Table might not exist yet (first run), ignore
    pass

# Định nghĩa get_db để lấy session DB
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Đường dẫn file tools.yaml
TOOLS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools.yaml")


# Khởi tạo VPNService
vpn_service = VPNService()

# Load TOOLS from tools.yaml
with open(TOOLS_FILE, 'r') as f:
    TOOLS = yaml.safe_load(f).get("tools", [])
    logging.getLogger(__name__).info(f"Loaded {len(TOOLS)} tools: {[t.get('name') for t in TOOLS]}")

# Thiết lập logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Endpoint: GET /api/sub_jobs/{sub_job_id}/results
@app.get("/api/sub_jobs/{sub_job_id}/results")
def get_sub_job_results_endpoint(sub_job_id: str, page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    return get_sub_job_results(sub_job_id, db, page, page_size)
# Endpoint: GET /api/workflows/{workflow_id}/summary

@app.get("/api/workflows/{workflow_id}/summary")
def get_workflow_summary_endpoint(workflow_id: str, db: Session = Depends(get_db)):
    return get_workflow_summary(workflow_id, db)

@app.get("/api/tools")
def list_tools():
    """
    Trả về danh sách các tool, bao gồm id, name, description, fields (dùng cho form frontend).
    """
    logger.info(f"API call to /api/tools, returning {len(TOOLS)} tools (frontend format)")

    # Mapping for each tool to frontend form format
    tool_form_map = {
        "port-scan": {
            "id": "port-scan",
            "name": "Quét Cổng (Port Scan)",
            "description": "Sử dụng Nmap để phát hiện các cổng đang mở trên mục tiêu.",
            "fields": [
                {
                    "name": "all_ports",
                    "label": "Quét toàn bộ 65535 cổng",
                    "component": "Switch",
                    "defaultValue": False
                },
                {
                    "name": "ports",
                    "label": "Hoặc nhập các cổng cụ thể",
                    "component": "TextInput",
                    "placeholder": "vd: 80,443,8080"
                },
                {
                    "name": "scan_type",
                    "label": "Loại scan",
                    "component": "Select",
                    "defaultValue": "-sS",
                    "data": [
                        {"value": "-sS", "label": "TCP SYN (-sS)"},
                        {"value": "-sT", "label": "TCP Connect (-sT)"}
                    ]
                }
            ]
        },
        "nuclei-scan": {
            "id": "nuclei-scan",
            "name": "Quét Lỗ hổng (Nuclei)",
            "description": "Sử dụng Nuclei để tìm kiếm các lỗ hổng đã biết.",
            "fields": [
                {
                    "name": "severity",
                    "label": "Mức độ nghiêm trọng",
                    "component": "MultiSelect",
                    "defaultValue": ["high", "critical"],
                    "data": ["info", "low", "medium", "high", "critical"]
                },
                {
                    "name": "templates",
                    "label": "Chạy các mẫu cụ thể (tùy chọn)",
                    "component": "MultiSelect",
                    "placeholder": "Để trống để chạy các mẫu được đề xuất",
                    "data": ["cves", "default-logins", "exposed-panels", "vulnerabilities"]
                }
            ]
        },
        "wpscan-scan": {
            "id": "wpscan-scan",
            "name": "Quét WordPress (WPScan)",
            "description": "Tìm kiếm các lỗ hổng phổ biến trên các trang web WordPress.",
            "fields": [
                {
                    "name": "enumerate",
                    "label": "Phát hiện các thành phần",
                    "component": "MultiSelect",
                    "defaultValue": ["p", "t"],
                    "data": [
                        {"value": "p", "label": "Plugins (p)"},
                        {"value": "t", "label": "Themes (t)"},
                        {"value": "u", "label": "Users (u)"}
                    ]
                }
            ]
        },
        "dns-lookup": {
            "id": "dns-lookup",
            "name": "Phân giải DNS",
            "description": "Thực hiện các truy vấn DNS cơ bản.",
            "fields": []
        },
        "httpx-scan": {
            "id": "httpx-scan",
            "name": "Kiểm tra HTTPX",
            "description": "Kiểm tra thông tin HTTP, tiêu đề, trạng thái, SSL, v.v.",
            "fields": [
                {
                    "name": "follow_redirects",
                    "label": "Theo dõi chuyển hướng (redirect)",
                    "component": "Switch",
                    "defaultValue": True
                },
                {
                    "name": "status_codes",
                    "label": "Chỉ lấy các mã trạng thái (tuỳ chọn)",
                    "component": "TextInput",
                    "placeholder": "vd: 200,301,302"
                }
            ]
        },
        "dirsearch-scan": {
            "id": "dirsearch-scan",
            "name": "Quét thư mục (Dirsearch)",
            "description": "Tìm kiếm các thư mục và file ẩn trên web server.",
            "fields": [
                {
                    "name": "extensions",
                    "label": "Phần mở rộng cần quét",
                    "component": "TextInput",
                    "placeholder": "vd: php,asp,aspx"
                },
                {
                    "name": "threads",
                    "label": "Số luồng (threads)",
                    "component": "NumberInput",
                    "defaultValue": 10
                }
            ]
        }
    }

    # Only return tools that are actually loaded in TOOLS
    frontend_tools = []
    for t in TOOLS:
        tid = t.get("name")
        if tid in tool_form_map:
            frontend_tools.append(tool_form_map[tid])
        else:
            # Fallback: minimal info
            frontend_tools.append({
                "id": tid,
                "name": t.get("name", tid),
                "description": t.get("description", ""),
                "fields": []
            })

    return {"tools": frontend_tools}

@app.post("/api/scan_results", status_code=status.HTTP_204_NO_CONTENT)
def create_scan_result(
    payload: schemas.ScanResultCreate,
    db: Session = Depends(get_db)
):
    """
    Nhận POST từ Scanner Node, lưu kết quả vào DB.
    Cập nhật job status thành 'completed' khi nhận được kết quả.
    """
    # Merge các trường httpx_results, http_endpoints, http_metadata vào scan_metadata nếu có
    scan_metadata = dict(payload.scan_metadata) if payload.scan_metadata else {}
    for k in ["httpx_results", "http_endpoints", "http_metadata"]:
        v = getattr(payload, k, None)
        if v is not None:
            scan_metadata[k] = v
    # Lưu scan result
    db_obj = models.ScanResult(
        target=payload.target,
        resolved_ips=payload.resolved_ips,
        open_ports=payload.open_ports,
        scan_metadata=scan_metadata,
        workflow_id=payload.workflow_id
    )
    db.add(db_obj)
    
    # Cập nhật job status thành completed nếu có job_id
    if payload.scan_metadata and 'job_id' in payload.scan_metadata:
        job_id = payload.scan_metadata['job_id']
        job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
        if job:
            job.status = "completed"
            logger.info(f"Updated job {job_id} status to completed")
            
            # Update workflow progress if job belongs to workflow
            if job.workflow_id:
                update_workflow_progress(job.workflow_id, db)
    
    db.commit()
    return

def update_workflow_progress(workflow_id: str, db: Session):
    """Update workflow completion status"""
    workflow = db.query(models.WorkflowJob).filter(
        models.WorkflowJob.workflow_id == workflow_id
    ).first()
    
    if not workflow:
        return
    
    # Count completed/failed jobs
    completed = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id,
        models.ScanJob.status == "completed"
    ).count()
    
    failed = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id,
        models.ScanJob.status == "failed"
    ).count()
    
    workflow.completed_steps = completed
    workflow.failed_steps = failed
    
    # Update workflow status
    if completed + failed >= workflow.total_steps:
        if failed == 0:
            workflow.status = "completed"
            logger.info(f"Workflow {workflow_id} completed successfully")
        else:
            workflow.status = "partially_failed"
            logger.info(f"Workflow {workflow_id} completed with {failed} failed steps")
    
    db.commit()

@app.get("/api/scan_results", response_model=schemas.PaginatedScanResults)
def read_scan_results_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    target: Optional[str] = Query(None),
    job_id: Optional[str] = Query(None),
    workflow_id: Optional[str] = Query(None),
    latest: bool = Query(False),
    db: Session = Depends(get_db)
):
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
    return get_paginated_list(query, schemas.PaginatedScanResults, page, page_size)

@app.get("/api/scan_results/list", response_model=List[schemas.ScanResult])
def read_scan_results_list_endpoint(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1),
    target: Optional[str] = Query(None),
    job_id: Optional[str] = Query(None),
    latest: bool = Query(False),
    db: Session = Depends(get_db)
):
    return read_scan_results_list(db, skip, limit, target, job_id, latest)

@app.get("/api/scan_jobs", response_model=schemas.PaginatedScanJobs)
def read_scan_jobs_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(models.ScanJob).order_by(models.ScanJob.id.desc())
    return get_paginated_list(query, schemas.PaginatedScanJobs, page, page_size)

@app.get("/api/scan_jobs/list", response_model=List[schemas.ScanJob])
def read_scan_jobs_list_endpoint(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1),
    db: Session = Depends(get_db)
):
    return read_scan_jobs_list(db, skip, limit)

@app.get("/api/scan_jobs/{job_id}", response_model=schemas.ScanJob)
def read_scan_job_endpoint(job_id: str, db: Session = Depends(get_db)):
    return read_scan_job(job_id, db)

@app.patch("/api/scan_jobs/{job_id}/status")
def update_job_status(job_id: str, status_update: dict, db: Session = Depends(get_db)):
    """
    Cập nhật status của một scan job.
    """
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    new_status = status_update.get("status")
    if new_status not in ["submitted", "running", "completed", "failed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    job.status = new_status
    db.commit()
    logger.info(f"Updated job {job_id} status to {new_status}")
    return {"job_id": job_id, "status": new_status}

@app.get("/api/scan_results/latest")
def get_latest_scan_results(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Lấy các scan results mới nhất theo timestamp.
    """
    results = db.query(models.ScanResult).order_by(models.ScanResult.timestamp.desc()).limit(limit).all()
    return results

@app.post("/api/scan", status_code=201)
def create_scan(
    req: schemas.ScanJobRequest,
    db: Session = Depends(get_db)
):
    """
    Gửi scan request tới Scanner Node API.
    """
    # 1. Kiểm tra tool tồn tại
    meta = next((t for t in TOOLS if t.get("name") == req.tool), None)
    if not meta:
        raise HTTPException(status_code=404, detail="Tool not found")

    # 2. Tạo job record trong database
    job_id = f"scan-{req.tool}-{uuid4().hex[:6]}"
    db_job = models.ScanJob(
        job_id=job_id,
        tool=req.tool,
        targets=req.targets,
        options=req.options,
        status="submitted",
        vpn_profile=req.vpn_profile,
        vpn_country=req.country
    )
    db.add(db_job)
    db.commit()

    # 3. Gửi request tới Scanner Node API
    try:
        scanner_node_url = os.getenv("SCANNER_NODE_URL", "http://scanner-node-api:8000")
        scanner_response, vpn_assignment = call_scanner_node(req.tool, req.targets, req.options, job_id, scanner_node_url, req.vpn_profile, req.country)
        
        # 4. Cập nhật job status và VPN info
        db_job.scanner_job_name = scanner_response.get("job_name")
        db_job.status = "running"
        
        # Lưu VPN assignment info nếu có
        if vpn_assignment:
            db_job.vpn_hostname = vpn_assignment.get('hostname')
            db_job.vpn_assignment = vpn_assignment
            if not db_job.vpn_country and vpn_assignment.get('country'):
                db_job.vpn_country = vpn_assignment.get('country')
        
        db.commit()
        
        logger.info(f"Scan job {job_id} submitted to scanner node: {scanner_response}")
        return {"job_id": job_id, "status": "submitted", "scanner_job": scanner_response}
        
    except Exception as e:
        logger.error(f"Error calling scanner node: {e}")
        db_job.status = "failed"
        db_job.error_message = str(e)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to submit scan to scanner node: {e}")

def call_scanner_node(tool: str, targets: List[str], options: Dict[str, Any], job_id: str, scanner_url: str, vpn_profile: str = None, country: str = None, workflow_id: str = None):
    """
    Gọi Scanner Node API để thực hiện scan với VPN assignment.
    """
    # Lấy VPN assignment cho job này
    vpn_assignment = None
    try:
        if vpn_profile:
            # Sử dụng VPN được chỉ định từ dashboard
            logger.info(f"Using specified VPN profile: {vpn_profile} for job {job_id}")
            
            # Tìm VPN thực từ VPN service để lấy metadata đầy đủ
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                all_vpns = loop.run_until_complete(vpn_service.fetch_vpns())
                
                # Tìm VPN profile được chỉ định
                selected_vpn = next((vpn for vpn in all_vpns if vpn.get('filename') == vpn_profile), None)
                
                if selected_vpn:
                    # Sử dụng metadata đầy đủ từ VPN service nhưng ưu tiên country từ dashboard
                    vpn_assignment = selected_vpn.copy()
                    # Override country với giá trị từ dashboard nếu có
                    if country:
                        vpn_assignment['country'] = country
                    elif 'country' not in vpn_assignment or vpn_assignment['country'] == 'Unknown':
                        vpn_assignment['country'] = 'Unknown'
                    
                    logger.info(f"Found VPN metadata: {vpn_assignment.get('country', 'Unknown')} - {selected_vpn.get('hostname', 'Unknown')}")
                else:
                    # Fallback nếu không tìm thấy VPN trong danh sách
                    # Sử dụng country từ dashboard nếu có, nếu không thì "Unknown"
                    fallback_country = country if country else "Unknown"
                    
                    vpn_assignment = {
                        "filename": vpn_profile,
                        "hostname": vpn_profile.replace('.ovpn', ''),
                        "country": fallback_country,
                        "provider": "Manual"
                    }
                    logger.warning(f"VPN profile {vpn_profile} not found in VPN service, using fallback with country: {fallback_country}")
                
                loop.close()
            except Exception as e:
                # Fallback nếu không thể kết nối VPN service  
                # Sử dụng country từ dashboard nếu có, nếu không thì "Unknown"
                fallback_country = country if country else "Unknown"
                
                vpn_assignment = {
                    "filename": vpn_profile,
                    "hostname": vpn_profile.replace('.ovpn', ''),
                    "country": fallback_country,
                    "provider": "Manual"
                }
                logger.warning(f"Failed to fetch VPN metadata for {vpn_profile}: {e}, using fallback with country: {fallback_country}")
            
            logger.info(f"Created VPN assignment: {vpn_assignment}")
        else:
            # Fallback: Random VPN assignment nếu không có VPN chỉ định
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            vpns = loop.run_until_complete(vpn_service.fetch_vpns())
            if vpns:
                import random
                vpn_assignment = random.choice(vpns)
                logger.info(f"Auto-assigned random VPN {vpn_assignment.get('hostname', 'Unknown')} to job {job_id}")
            loop.close()
    except Exception as e:
        logger.warning(f"Failed to assign VPN for job {job_id}: {e}")
    
    payload = {
        "tool": tool,
        "targets": targets,
        "options": options,
        "job_id": job_id,
        "controller_callback_url": os.getenv("CONTROLLER_CALLBACK_URL", "http://controller:8000"),
        "vpn_assignment": vpn_assignment,
        "workflow_id": workflow_id
    }
    
    response = httpx.post(
        f"{scanner_url}/api/scan/execute",
        json=payload,
        timeout=30
    )
    response.raise_for_status()
    return response.json(), vpn_assignment

# Schema riêng cho payload mỗi tool
class ToolRequest(BaseModel):
    targets: List[str]
    options: Dict[str, Any] = {}
    vpn_profile: Optional[str] = None  # Cho phép chỉ định VPN profile từ dashboard
    country: Optional[str] = None      # Country code: "VN", "JP", "KR", etc.

# Endpoint cho từng tool
@app.post("/api/scan/dns-lookup", status_code=201)
def dns_lookup_endpoint(req: ToolRequest, db: Session = Depends(get_db)):
    scan_req = schemas.ScanJobRequest(tool="dns-lookup", targets=req.targets, options=req.options, vpn_profile=req.vpn_profile, country=req.country)
    return create_scan(scan_req, db)

@app.post("/api/scan/port-scan", status_code=201)
def port_scan_endpoint(req: ToolRequest, db: Session = Depends(get_db)):
    scan_req = schemas.ScanJobRequest(tool="port-scan", targets=req.targets, options=req.options, vpn_profile=req.vpn_profile, country=req.country)
    return create_scan(scan_req, db)

@app.post("/api/scan/httpx-scan", status_code=201)
def httpx_scan_endpoint(req: ToolRequest, db: Session = Depends(get_db)):
    scan_req = schemas.ScanJobRequest(tool="httpx-scan", targets=req.targets, options=req.options, vpn_profile=req.vpn_profile, country=req.country)
    return create_scan(scan_req, db)

@app.post("/api/scan/nuclei-scan", status_code=201)
def nuclei_scan_endpoint(req: ToolRequest, db: Session = Depends(get_db)):
    scan_req = schemas.ScanJobRequest(tool="nuclei-scan", targets=req.targets, options=req.options, vpn_profile=req.vpn_profile, country=req.country)
    return create_scan(scan_req, db)

@app.post("/api/scan/wpscan-scan", status_code=201)
def wpscan_scan_endpoint(req: ToolRequest, db: Session = Depends(get_db)):
    scan_req = schemas.ScanJobRequest(tool="wpscan-scan", targets=req.targets, options=req.options, vpn_profile=req.vpn_profile, country=req.country)
    return create_scan(scan_req, db)

# ============ Workflow API Endpoints ============

@app.post("/api/scan/workflow", status_code=201)
def create_workflow_scan(
    req: schemas.WorkflowRequest,
    db: Session = Depends(get_db)
):
    """
    Tạo workflow job với 2 strategies:
    - "wide": Quét tất cả targets bằng 1 tool, rồi chuyển tool khác
    - "deep": Quét 1 target bằng tất cả tools, rồi chuyển target khác
    """
    # Validate tools exist
    available_tools = [t.get("name") for t in TOOLS]
    for step in req.steps:
        if step.tool_id not in available_tools:
            raise HTTPException(status_code=404, detail=f"Tool not found: {step.tool_id}")
    
    # Validate strategy
    if req.strategy not in ["wide", "deep"]:
        raise HTTPException(status_code=400, detail="Strategy must be 'wide' or 'deep'")
    
    # 1. Tạo workflow job tổng
    workflow_id = f"workflow-{uuid4().hex[:8]}"
    
    # Calculate total steps based on strategy
    if req.strategy == "wide":
        # Wide: 1 job per tool (each job scans all targets)
        total_steps = len(req.steps)
    else:
        # Deep: 1 job per (target + tool) combination
        total_steps = len(req.targets) * len(req.steps)
    
    workflow_job = models.WorkflowJob(
        workflow_id=workflow_id,
        targets=req.targets,
        strategy=req.strategy,
        total_steps=total_steps,
        vpn_profile=req.vpn_profile,
        vpn_country=req.country
    )
    db.add(workflow_job)
    db.commit()
    
    # 2. Assign VPN cho workflow (sẽ dùng chung cho tất cả steps)
    vpn_assignment = None
    try:
        if req.vpn_profile:
            # Sử dụng VPN được chỉ định
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            all_vpns = loop.run_until_complete(vpn_service.fetch_vpns())
            
            selected_vpn = next((vpn for vpn in all_vpns if vpn.get('filename') == req.vpn_profile), None)
            if selected_vpn:
                vpn_assignment = selected_vpn.copy()
                if req.country:
                    vpn_assignment['country'] = req.country
            loop.close()
        else:
            # Random VPN assignment
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            vpns = loop.run_until_complete(vpn_service.fetch_vpns())
            if vpns:
                import random
                if req.country:
                    # Filter by country
                    categorized = loop.run_until_complete(vpn_service.categorize_vpns_by_country(vpns))
                    if req.country.upper() in categorized:
                        vpns = categorized[req.country.upper()]
                    
                vpn_assignment = random.choice(vpns) if vpns else None
            loop.close()
            
        if vpn_assignment:
            workflow_job.vpn_assignment = vpn_assignment
            workflow_job.vpn_country = vpn_assignment.get('country')
            db.commit()
            logger.info(f"Assigned VPN {vpn_assignment.get('hostname')} to workflow {workflow_id}")
        
    except Exception as e:
        logger.warning(f"Failed to assign VPN for workflow {workflow_id}: {e}")
    
    # 3. Tạo sub-jobs theo strategy
    sub_jobs = []
    failed_jobs = []
    step_counter = 0
    
    if req.strategy == "wide":
        # Wide Strategy: 1 job per tool, each job handles all targets
        for i, step in enumerate(req.steps):
            try:
                step_counter += 1
                job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                
                sub_job = models.ScanJob(
                    job_id=job_id,
                    tool=step.tool_id,
                    targets=req.targets,  # All targets for this tool
                    options=step.params,
                    workflow_id=workflow_id,
                    step_order=step_counter,
                    vpn_profile=req.vpn_profile,
                    vpn_country=req.country,
                    vpn_assignment=vpn_assignment
                )
                db.add(sub_job)
                sub_jobs.append(sub_job)
                
                logger.info(f"Created WIDE job {job_id} for tool {step.tool_id} with {len(req.targets)} targets")
                
            except Exception as e:
                logger.error(f"Failed to create wide sub-job for step {i+1}: {e}")
                failed_jobs.append({"step": i+1, "tool": step.tool_id, "error": str(e)})
    
    else:  # Deep Strategy
        # Deep Strategy: 1 job per (target + tool) combination
        for target_idx, target in enumerate(req.targets):
            for step_idx, step in enumerate(req.steps):
                try:
                    step_counter += 1
                    job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                    
                    sub_job = models.ScanJob(
                        job_id=job_id,
                        tool=step.tool_id,
                        targets=[target],  # Single target for this job
                        options=step.params,
                        workflow_id=workflow_id,
                        step_order=step_counter,
                        vpn_profile=req.vpn_profile,
                        vpn_country=req.country,
                        vpn_assignment=vpn_assignment
                    )
                    db.add(sub_job)
                    sub_jobs.append(sub_job)
                    
                    logger.info(f"Created DEEP job {job_id} for tool {step.tool_id} with target {target}")
                    
                except Exception as e:
                    logger.error(f"Failed to create deep sub-job for target {target}, tool {step.tool_id}: {e}")
                    failed_jobs.append({
                        "target": target, 
                        "tool": step.tool_id, 
                        "error": str(e)
                    })
    
    db.commit()
    
    # 4. Submit all jobs to scanner nodes (parallel execution)
    successful_submissions = []
    failed_submissions = []
    
    for job in sub_jobs:
        try:
            scanner_node_url = os.getenv("SCANNER_NODE_URL", "http://scanner-node-api:8000")
            scanner_response, _ = call_scanner_node(
                job.tool, 
                job.targets, 
                job.options, 
                job.job_id, 
                scanner_node_url,
                job.vpn_profile,
                job.vpn_country,
                job.workflow_id
            )
            
            # Update job with scanner response
            job.scanner_job_name = scanner_response.get("job_name")
            job.status = "running"
            successful_submissions.append({
                "job_id": job.job_id,
                "tool": job.tool,
                "targets": job.targets,
                "scanner_job": scanner_response.get("job_name")
            })
            
            logger.info(f"Successfully submitted job {job.job_id} to scanner")
            
        except Exception as e:
            logger.error(f"Failed to submit job {job.job_id}: {e}")
            job.status = "failed"
            job.error_message = str(e)
            failed_submissions.append({
                "job_id": job.job_id,
                "tool": job.tool,
                "targets": job.targets,
                "error": str(e)
            })
    
    # Update workflow status
    if len(successful_submissions) > 0:
        workflow_job.status = "running"
    else:
        workflow_job.status = "failed"
    
    db.commit()
    
    return {
        "workflow_id": workflow_id,
        "status": workflow_job.status,
        "strategy": req.strategy,
        "total_steps": total_steps,
        "total_targets": len(req.targets),
        "total_tools": len(req.steps),
        "successful_submissions": len(successful_submissions),
        "failed_submissions": len(failed_submissions),
        "sub_jobs": successful_submissions,
        "errors": failed_submissions + failed_jobs,
        "vpn_assignment": {
            "country": vpn_assignment.get('country') if vpn_assignment else None,
            "hostname": vpn_assignment.get('hostname') if vpn_assignment else None
        } if vpn_assignment else None
    }

@app.get("/api/workflows", response_model=schemas.PaginatedWorkflows)
def get_workflows(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(models.WorkflowJob).order_by(models.WorkflowJob.id.desc())
    return get_paginated_list(query, schemas.PaginatedWorkflows, page, page_size)

@app.get("/api/workflows/{workflow_id}")
def get_workflow_detail(workflow_id: str, db: Session = Depends(get_db)):
    """Get workflow với sub-jobs, tổng hợp kết quả từng tool (nuclei: trường chung + extra_fields)"""
    workflow = db.query(models.WorkflowJob).filter(
        models.WorkflowJob.workflow_id == workflow_id
    ).first()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Get sub-jobs
    sub_jobs = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id
    ).order_by(models.ScanJob.step_order).all()

    # Lấy kết quả từng sub-job (ScanResult)
    job_ids = [job.job_id for job in sub_jobs]
    results_by_job = {}
    if job_ids:
        scan_results = db.query(models.ScanResult).filter(
            models.ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
        ).all()
        for r in scan_results:
            job_id = r.scan_metadata.get('job_id')
            if job_id not in results_by_job:
                results_by_job[job_id] = []
            results_by_job[job_id].append(r)

    def nuclei_flatten(find):
        # Common fields always present
        info = find.get('info', {}) or {}
        out = {
            "template": find.get("template"),
            "template-id": find.get("template-id"),
            "template-url": find.get("template-url"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "tags": info.get("tags"),
            "matched_at": find.get("matched-at"),
            "type": find.get("type"),
            "host": find.get("host"),
            "ip": find.get("ip"),
            "port": find.get("port"),
            "timestamp": find.get("timestamp"),
        }
        # Gather all other fields as extra_fields
        extra = {}
        for k, v in find.items():
            if k not in ("template", "template-id", "template-url", "type", "host", "ip", "port", "timestamp", "matched-at", "matcher-status", "info"):
                extra[k] = v
        # Also add all info fields except name, severity, tags
        for k, v in info.items():
            if k not in ("name", "severity", "tags"):
                extra[k] = v
        if extra:
            out["extra_fields"] = extra
        return out

    def portscan_flatten(r):
        # open_ports là list dict
        return [
            {"ip": r.target, "port": p.get("port"), "service": p.get("service"), "protocol": p.get("protocol"), "version": p.get("version", "")}
            for p in (r.open_ports or [])
        ]

    def dns_flatten(r):
        return {"target": r.target, "resolved_ips": r.resolved_ips}

    import json
    def httpx_flatten(r):
        meta = r.scan_metadata or {}
        # Nếu meta là str (TEXT), parse lại thành dict
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                return []
        if "httpx_results" in meta:
            return meta["httpx_results"]
        if "http_endpoints" in meta:
            return meta["http_endpoints"]
        if "http_metadata" in meta and isinstance(meta["http_metadata"], dict):
            return [meta["http_metadata"]]
        return []

    def dirsearch_flatten(r):
        meta = r.scan_metadata or {}
        return meta.get("dirsearch_results") or []

    def wpscan_flatten(r):
        meta = r.scan_metadata or {}
        return meta.get("wpscan_results") or []

    tool_result_map = {
        "nuclei-scan": lambda r: [nuclei_flatten(f) for f in (r.scan_metadata.get("nuclei_results") or [])],
        "port-scan": portscan_flatten,
        "dns-lookup": lambda r: [dns_flatten(r)],
        "httpx-scan": httpx_flatten,
        "dirsearch-scan": dirsearch_flatten,
        "wpscan-scan": wpscan_flatten,
    }

    sub_job_details = []
    for job in sub_jobs:
        job_id = job.job_id
        tool = job.tool
        job_results = results_by_job.get(job_id, [])
        # Tổng hợp kết quả cho từng tool
        results = []
        if tool in tool_result_map:
            for r in job_results:
                results.extend(tool_result_map[tool](r))
        else:
            # fallback: trả raw scan_metadata
            for r in job_results:
                results.append(r.scan_metadata)

        job_detail = {
            "job_id": job_id,
            "tool": tool,
            "status": job.status,
            "step_order": job.step_order,
            "error_message": job.error_message,
            "results": results,
        }
        sub_job_details.append(job_detail)

    # Tính lại progress thực tế dựa trên trạng thái sub_jobs
    completed = sum(1 for job in sub_jobs if job.status == "completed")
    failed = sum(1 for job in sub_jobs if job.status == "failed")
    total = workflow.total_steps
    percentage = (completed / total * 100) if total > 0 else 0
    return {
        "workflow": workflow,
        "sub_jobs": sub_job_details,
        "progress": {
            "completed": completed,
            "total": total,
            "failed": failed,
            "percentage": percentage
        }
    }

@app.post("/api/workflows/{workflow_id}/cancel")
def cancel_workflow(workflow_id: str, db: Session = Depends(get_db)):
    """Cancel workflow và tất cả sub-jobs"""
    # Cancel workflow
    workflow = db.query(models.WorkflowJob).filter(
        models.WorkflowJob.workflow_id == workflow_id
    ).first()
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    workflow.status = "cancelled"
    
    # Cancel running sub-jobs
    sub_jobs = db.query(models.ScanJob).filter(
        models.ScanJob.workflow_id == workflow_id,
        models.ScanJob.status.in_(["pending", "running"])
    ).all()
    
    for job in sub_jobs:
        job.status = "cancelled"
        # TODO: Cancel K8s job if needed
    
    db.commit()
    return {"status": "cancelled", "cancelled_jobs": len(sub_jobs)}

# Endpoint: GET /api/workflows/{workflow_id}/status
@app.get("/api/workflows/{workflow_id}/status")
def get_workflow_status_endpoint(workflow_id: str, db: Session = Depends(get_db)):
    return get_workflow_status(workflow_id, db)

@app.get("/debug/vpn-service")
async def debug_vpn_service():
    """Debug VPN service status"""
    try:
        proxy_status = "checking..."
        vpn_count = 0
        error_msg = None
        
        try:
            vpns = await vpn_service.fetch_vpns()
            vpn_count = len(vpns)
            proxy_status = "connected"
        except Exception as e:
            error_msg = str(e)
            proxy_status = "failed"
        
        return {
            "vpn_service_status": "initialized",
            "proxy_node": vpn_service.proxy_node,
            "proxy_status": proxy_status,
            "vpn_count": vpn_count,
            "error": error_msg
        }
    except Exception as e:
        return {
            "vpn_service_status": "error",
            "error": str(e)
        }

@app.get("/debug/info")
def debug_info():
    """Simple debug endpoint"""
    return {
        "message": "Debug endpoint working",
        "vpn_service_exists": vpn_service is not None,
        "vpn_proxy_node": getattr(vpn_service, 'proxy_node', 'Not found')
    }

# ============ VPN API Endpoints ============

@app.get("/api/vpns/test")
def test_vpn_sync():
    """Test VPN service với sync method"""
    try:
        vpns = vpn_service.fetch_vpns_sync()
        return {
            "status": "success",
            "proxy_node": vpn_service.proxy_node,
            "total": len(vpns),
            "sample": vpns[:3] if vpns else []
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.get("/api/vpns")
async def get_available_vpns():
    """
    Lấy danh sách VPN có sẵn từ VPN proxy node.
    """
    try:
        vpns = await vpn_service.fetch_vpns()
        logger.info(f"Fetched {len(vpns)} VPNs from proxy node")
        return {
            "status": "success",
            "total": len(vpns),
            "vpns": vpns
        }
    except Exception as e:
        logger.error(f"Error fetching VPNs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch VPNs: {e}")

@app.get("/api/vpns/by-country")
async def get_vpns_by_country():
    """
    Lấy danh sách VPN phân loại theo quốc gia.
    """
    try:
        vpns = await vpn_service.fetch_vpns()
        categorized = await vpn_service.categorize_vpns_by_country(vpns)
        logger.info(f"Categorized VPNs into {len(categorized)} countries")
        return {
            "status": "success",
            "countries": categorized
        }
    except Exception as e:
        logger.error(f"Error categorizing VPNs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to categorize VPNs: {e}")

@app.get("/api/vpns/random")
async def get_random_vpn(country: str = Query(None, description="Country code filter (optional)")):
    """
    Lấy một VPN ngẫu nhiên, có thể lọc theo quốc gia.
    """
    try:
        vpns = await vpn_service.fetch_vpns()
        
        if country:
            # Lọc theo quốc gia nếu được chỉ định
            categorized = await vpn_service.categorize_vpns_by_country(vpns)
            if country.upper() not in categorized:
                raise HTTPException(status_code=404, detail=f"No VPNs found for country: {country}")
            
            available_vpns = categorized[country.upper()]
        else:
            available_vpns = vpns
        
        if not available_vpns:
            raise HTTPException(status_code=404, detail="No VPNs available")
        
        import random
        selected_vpn = random.choice(available_vpns)
        logger.info(f"Selected random VPN: {selected_vpn.get('country', 'Unknown')} - {selected_vpn.get('hostname', 'N/A')}")
        
        return {
            "status": "success",
            "vpn": selected_vpn
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error selecting random VPN: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to select VPN: {e}")

@app.get("/api/vpns/countries")
async def get_available_countries():
    """
    Lấy danh sách các quốc gia có VPN available.
    """
    try:
        vpns = await vpn_service.fetch_vpns()
        categorized = await vpn_service.categorize_vpns_by_country(vpns)
        
        countries = []
        for country_code, vpn_list in categorized.items():
            countries.append({
                "code": country_code,
                "count": len(vpn_list),
                "sample_hostname": vpn_list[0].get('hostname', 'N/A') if vpn_list else None
            })
        
        logger.info(f"Found VPNs in {len(countries)} countries")
        return {
            "status": "success",
            "total_countries": len(countries),
            "countries": countries
        }
    except Exception as e:
        logger.error(f"Error getting country list: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get countries: {e}")

from app.database_service import (
    clear_all_database_tables,
    clear_scan_results_only,
    clear_workflows_and_jobs,
    get_vpn_profiles,
    update_vpn_profile_status
)

@app.delete("/api/database/clear")
async def clear_all_database_tables_endpoint():
    """
    Xóa toàn bộ dữ liệu từ tất cả các bảng trong database.
    Cẩn thận: Thao tác này không thể hoàn tác!
    """
    try:
        return clear_all_database_tables()
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {e}")


@app.delete("/api/database/clear/scan_results")
async def clear_scan_results_only_endpoint():
    """
    Xóa chỉ bảng scan_results, giữ lại workflows và scan_jobs.
    """
    try:
        return clear_scan_results_only()
    except Exception as e:
        logger.error(f"Error clearing scan results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear scan results: {e}")


@app.delete("/api/database/clear/workflows")
async def clear_workflows_and_jobs_endpoint():
    """
    Xóa workflows và scan_jobs, giữ lại scan_results.
    """
    try:
        return clear_workflows_and_jobs()
    except Exception as e:
        logger.error(f"Error clearing workflows and jobs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear workflows and jobs: {e}")

# ============ VPN Profile Management API ============
from fastapi import Body

@app.get("/api/vpn_profiles")
def get_vpn_profiles_endpoint(db: Session = Depends(get_db)):
    """
    Lấy danh sách các VPN profiles trong database (quản lý trạng thái, số lần sử dụng, v.v.).
    Bổ sung thông tin workflow_id của scanner đang sử dụng VPN này.
    """
    vpn_profiles = get_vpn_profiles(db)
    # Bổ sung workflow_id cho mỗi scanner đang sử dụng VPN này
    for vpn in vpn_profiles:
        # scanner_usages là list các dict có scanner_id, status, ...
        usages = getattr(vpn, 'scanner_usages', []) or []
        for usage in usages:
            # Tìm scan job theo scanner_id
            scanner_id = usage.get('scanner_id')
            scan_job = db.query(models.ScanJob).filter(models.ScanJob.job_id == scanner_id).first()
            if scan_job and scan_job.workflow_id:
                usage['workflow_id'] = scan_job.workflow_id
            else:
                usage['workflow_id'] = None
    return vpn_profiles

@app.post("/api/vpn_profiles/update")
def update_vpn_profile_status_endpoint(
    payload: dict = Body(...),
    db: Session = Depends(get_db)
):
    """
    Cập nhật trạng thái hoặc số lần sử dụng của VPN profile (khi connect/disconnect từ scanner tool).
    """
    return update_vpn_profile_status(payload, db)
