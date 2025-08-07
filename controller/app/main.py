from fastapi import FastAPI, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import httpx
import logging
import yaml
import os
from uuid import uuid4
from pydantic import BaseModel

from app import models, schemas, database
from app.vpn_service import VPNService

# Thiết lập logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tạo bảng nếu chưa có
models.Base.metadata.create_all(bind=database.engine)

# Khởi tạo VPN Service
vpn_service = VPNService()

app = FastAPI(
    title="Scanner Controller",
    version="1.0"
)

@app.get("/")
def root():
    """
    Root endpoint để test.
    """
    return {"message": "Scanner Controller API", "status": "running"}

@app.get("/health")
def health():
    """
    Health check endpoint.
    """
    logger.info("Health check endpoint called")
    return {"status": "ok", "tools_loaded": len(TOOLS)}

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Load metadata của các tool từ tools.yaml ở thư mục làm việc
TOOLS_FILE = os.path.join(os.getcwd(), "tools.yaml")
logger.info(f"Looking for tools.yaml at: {TOOLS_FILE}")

if not os.path.exists(TOOLS_FILE):
    logger.error(f"tools.yaml not found at {TOOLS_FILE}")
    # List current directory contents
    logger.info(f"Current directory contents: {os.listdir(os.getcwd())}")
    raise RuntimeError(f"tools.yaml not found at {TOOLS_FILE}")

with open(TOOLS_FILE, 'r') as f:
    TOOLS = yaml.safe_load(f).get("tools", [])
    logger.info(f"Loaded {len(TOOLS)} tools: {[t.get('name') for t in TOOLS]}")

@app.get("/api/tools")
def list_tools():
    """
    Trả về danh sách các tool, bao gồm name, image, description, args.
    """
    logger.info(f"API call to /api/tools, returning {len(TOOLS)} tools")
    return {"tools": TOOLS}

@app.post("/api/scan_results", status_code=status.HTTP_204_NO_CONTENT)
def create_scan_result(
    payload: schemas.ScanResultCreate,
    db: Session = Depends(get_db)
):
    """
    Nhận POST từ Scanner Node, lưu kết quả vào DB.
    """
    db_obj = models.ScanResult(
        target=payload.target,
        resolved_ips=payload.resolved_ips,
        open_ports=payload.open_ports,
        scan_metadata=payload.scan_metadata,
    )
    db.add(db_obj)
    db.commit()
    return

@app.get("/api/scan_results", response_model=List[schemas.ScanResult])
def read_scan_results(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1),
    db: Session = Depends(get_db)
):
    """
    Trả về các scan results, hỗ trợ phân trang bằng skip & limit.
    """
    return db.query(models.ScanResult).offset(skip).limit(limit).all()

@app.get("/api/scan_jobs", response_model=List[schemas.ScanJob])
def read_scan_jobs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1),
    db: Session = Depends(get_db)
):
    """
    Trả về các scan jobs, hỗ trợ phân trang bằng skip & limit.
    """
    return db.query(models.ScanJob).offset(skip).limit(limit).all()

@app.get("/api/scan_jobs/{job_id}", response_model=schemas.ScanJob)
def read_scan_job(job_id: str, db: Session = Depends(get_db)):
    """
    Trả về thông tin của một scan job cụ thể.
    """
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job

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
        status="submitted"
    )
    db.add(db_job)
    db.commit()

    # 3. Gửi request tới Scanner Node API
    try:
        scanner_node_url = os.getenv("SCANNER_NODE_URL", "http://scanner-node-api:8000")
        scanner_response = call_scanner_node(req.tool, req.targets, req.options, job_id, scanner_node_url, req.vpn_profile, req.country)
        
        # 4. Cập nhật job status
        db_job.scanner_job_name = scanner_response.get("job_name")
        db_job.status = "running"
        db.commit()
        
        logger.info(f"Scan job {job_id} submitted to scanner node: {scanner_response}")
        return {"job_id": job_id, "status": "submitted", "scanner_job": scanner_response}
        
    except Exception as e:
        logger.error(f"Error calling scanner node: {e}")
        db_job.status = "failed"
        db_job.error_message = str(e)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to submit scan to scanner node: {e}")

def call_scanner_node(tool: str, targets: List[str], options: Dict[str, Any], job_id: str, scanner_url: str, vpn_profile: str = None, country: str = None):
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
                    # Sử dụng metadata đầy đủ từ VPN service
                    vpn_assignment = selected_vpn.copy()
                    logger.info(f"Found VPN metadata: {selected_vpn.get('country', 'Unknown')} - {selected_vpn.get('hostname', 'Unknown')}")
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
        "vpn_assignment": vpn_assignment
    }
    
    response = httpx.post(
        f"{scanner_url}/api/scan/execute",
        json=payload,
        timeout=30
    )
    response.raise_for_status()
    return response.json()

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
