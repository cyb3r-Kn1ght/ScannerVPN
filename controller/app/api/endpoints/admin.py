# app/api/endpoints/admin.py
from fastapi import APIRouter, Depends, HTTPException
from services.admin_service import AdminService
from api.deps import get_admin_service

router = APIRouter()

# Giữ nguyên endpoint gốc: DELETE /api/database/clear
@router.delete("/api/database/clear", summary="Xóa toàn bộ dữ liệu")
def clear_all_database(
        admin_service: AdminService = Depends(get_admin_service)
):
    """Xóa toàn bộ dữ liệu. Thao tác này không thể hoàn tác!"""
    return admin_service.clear_all_data()

# Giữ nguyên endpoint gốc: DELETE /api/database/clear/scan_results
@router.delete("/api/database/clear/scan_results", summary="Xóa chỉ kết quả scan")
def clear_results(
        admin_service: AdminService = Depends(get_admin_service)
):
    """Xóa chỉ bảng scan_results, giữ lại workflows và scan_jobs."""
    try:
        return admin_service.clear_scan_results_only()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Giữ nguyên endpoint gốc: DELETE /api/database/clear/workflows
@router.delete("/api/database/clear/workflows", summary="Xóa chỉ workflows và jobs")
def clear_workflows(
        admin_service: AdminService = Depends(get_admin_service)
):
    """Xóa workflows và scan_jobs, giữ lại scan_results."""
    try:
        return admin_service.clear_workflows_and_jobs()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))