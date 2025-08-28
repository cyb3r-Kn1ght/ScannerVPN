# app/api/endpoints/utils.py
import yaml
import os
from fastapi import APIRouter

router = APIRouter()

# Sửa lại đường dẫn thành đường dẫn tuyệt đối bên trong container
TOOLS_FILE = "/app/tools.yaml"

try:
    with open(TOOLS_FILE, 'r') as f:
        TOOLS_CONFIG = yaml.safe_load(f).get("tools", [])
except FileNotFoundError:
    print(f"!!! LỖI: Không tìm thấy file cấu hình tools tại '{TOOLS_FILE}'.")
    TOOLS_CONFIG = []

# Giữ nguyên endpoint gốc: GET /api/tools
@router.get("/api/tools", summary="Lấy danh sách các tool scan được hỗ trợ")
def list_supported_tools():
    """
    Trả về danh sách các tool được định nghĩa trong tools.yaml.
    """
    return {"tools": TOOLS_CONFIG}

# Giữ nguyên endpoint gốc: GET /debug/info
@router.get("/debug/info", summary="Endpoint debug cơ bản")
def get_debug_info():
    return {"status": "ok", "service": "Controller API - Refactored"}