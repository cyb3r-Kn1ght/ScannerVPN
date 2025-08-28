# app/api/router.py
from fastapi import APIRouter
from api.endpoints import workflows, scan_jobs, scan_results, vpn, admin, utils

api_router = APIRouter()

# Include tất cả các router từ các file endpoint
# FastAPI sẽ tự động xử lý các đường dẫn đầy đủ đã được định nghĩa trong mỗi file
api_router.include_router(workflows.router)
api_router.include_router(scan_jobs.router)
api_router.include_router(scan_results.router)
api_router.include_router(vpn.router)
api_router.include_router(admin.router)
api_router.include_router(utils.router)