# app/api/endpoints/utils.py
import yaml
import os
import logging
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


# Trả về danh sách các tool đúng format dashboard yêu cầu
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@router.get("/api/tools", summary="Lấy danh sách các tool scan được hỗ trợ (dashboard format)")
def list_supported_tools():
    """
    Trả về danh sách các tool, đúng format dashboard yêu cầu, bổ sung các param thực tế và các cải tiến UI.
    """
    frontend_tools = [
        {
            "id": "port-scan",
            "name": "Quét Cổng (Port Scan)",
            "description": "Sử dụng Nmap để phát hiện các cổng đang mở trên mục tiêu.",
            "fields": [
                {"name": "all_ports", "label": "Quét toàn bộ 65535 cổng", "component": "Switch", "defaultValue": False},
                {"name": "ports", "label": "Hoặc nhập các cổng cụ thể", "component": "TextInput", "placeholder": "vd: 80,443,8080",
                 "presets": [
                     {"label": "Top 1000 Ports", "value": "top-1000"},
                     {"label": "Web Ports", "value": "80,443,8080,8443"},
                     {"label": "Database Ports", "value": "3306,5432,1433,27017"}
                 ]},
                {"name": "scan_type", "label": "Loại scan", "component": "Select", "defaultValue": "-sS",
                 "data": [
                     {"value": "-sS", "label": "TCP SYN (-sS)"},
                     {"value": "-sT", "label": "TCP Connect (-sT)"}
                 ]}
            ]
        },
        {
            "id": "httpx-scan",
            "name": "Kiểm tra HTTPX",
            "description": "Kiểm tra thông tin HTTP, tiêu đề, trạng thái, SSL, v.v.",
            "fields": [
                {"name": "follow_redirects", "label": "Theo dõi chuyển hướng", "component": "Switch", "defaultValue": True},
                {"name": "status_codes", "label": "Lọc theo mã trạng thái", "component": "TagsInput", "placeholder": "vd: 200,301,404",
                 "data": ["200,204", "301,302,307", "400,401,403", "500,502,503"]}
            ]
        },
        {
            "id": "dirsearch-scan",
            "name": "Quét thư mục (Dirsearch)",
            "description": "Tìm kiếm các thư mục và file ẩn trên web server.",
            "fields": [
                {"name": "extensions", "label": "Phần mở rộng cần quét", "component": "TagsInput", "placeholder": "vd: php,asp,aspx",
                 "data": ["php", "html", "js", "aspx", "jsp", "txt", "bak", "config", "env"]},
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 10},
                {"name": "recursive", "label": "Quét đệ quy", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "nuclei-scan",
            "name": "Quét Lỗ hổng (Nuclei)",
            "fields": [
                {"name": "severity", "label": "Mức độ nghiêm trọng", "component": "MultiSelect", "defaultValue": ["high", "critical"], "data": ["info", "low", "medium", "high", "critical"]},
                {"name": "templates", "label": "Chạy các mẫu cụ thể", "component": "MultiSelect", "placeholder": "Để trống để chạy các mẫu đề xuất", "data": ["cves", "default-logins", "exposed-panels", "vulnerabilities"]}
            ]
        },
        {
            "id": "wpscan-scan",
            "name": "Quét WordPress (WPScan)",
            "fields": [
                {"name": "enumerate", "label": "Phát hiện các thành phần", "component": "MultiSelect", "defaultValue": ["p", "t"], "data": [
                    {"value": "p", "label": "Plugins (p)"},
                    {"value": "t", "label": "Themes (t)"},
                    {"value": "u", "label": "Users (u)"}
                ]}
            ]
        },
        {
            "id": "dns-lookup",
            "name": "Phân giải DNS",
            "fields": []
        },
                {
            "id": "sqlmap-scan",
            "name": "Quét SQL Injection (SQLMap)",
            "description": "Tự động phát hiện và khai thác các lỗ hổng SQL injection.",
            "fields": [
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 1},
                {"name": "level", "label": "Mức độ kiểm tra (Level)", "component": "Select", "defaultValue": 1, "data": [
                    {"value": 1, "label": "1 - Cơ bản"},
                    {"value": 2, "label": "2 - Trung bình"},
                    {"value": 3, "label": "3 - Nâng cao"},
                    {"value": 4, "label": "4 - Toàn diện"},
                    {"value": 5, "label": "5 - Chuyên sâu"}
                ]},
                {"name": "risk", "label": "Mức độ rủi ro (Risk)", "component": "Select", "defaultValue": 1, "data": [
                    {"value": 1, "label": "1 - Thấp"},
                    {"value": 2, "label": "2 - Trung bình"},
                    {"value": 3, "label": "3 - Cao"}
                ]},
                {"name": "technique", "label": "Kỹ thuật tấn công", "component": "TextInput", "placeholder": "vd: BEUS (Boolean, Error, Union, Stacked)"},
                {"name": "dbms", "label": "Chỉ định DBMS", "component": "TextInput", "placeholder": "vd: MySQL, PostgreSQL"},
                {"name": "batch", "label": "Chạy tự động (batch mode)", "component": "Switch", "defaultValue": True}
            ]
        }
    ]
    logger.info(f"API call to /api/tools, returning {len(frontend_tools)} tools (dashboard format)")
    return {"tools": frontend_tools}

# Giữ nguyên endpoint gốc: GET /debug/info
@router.get("/debug/info", summary="Endpoint debug cơ bản")
def get_debug_info():
    return {"status": "ok", "service": "Controller API - Refactored"}