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
                 ]},
                {"name": "scanner_count", "label": "Số lượng scanner song song", "component": "NumberInput", "min": 1, "max": 20}
            ]
        },
        {
            "id": "httpx-scan",
            "name": "Kiểm tra HTTPX",
            "description": "Kiểm tra thông tin HTTP, tiêu đề, trạng thái, SSL, v.v.",
            "fields": [
                {"name": "method", "label": "HTTP Method", "component": "Select", "defaultValue": "GET", "data": [
                {"value": "GET", "label": "GET"},
                {"value": "POST", "label": "POST"},
                {"value": "HEAD", "label": "HEAD"}
                ]},
                {"name": "ports", "label": "Cổng quét", "component": "TextInput", "placeholder": "vd: 80,443"},
                {"name": "timeout", "label": "Timeout (giây)", "component": "NumberInput", "defaultValue": 10},
                {"name": "retries", "label": "Số lần thử lại", "component": "NumberInput", "defaultValue": 2},
                {"name": "threads", "label": "Số luồng", "component": "NumberInput", "defaultValue": 10},
                {"name": "status_codes", "label": "Lọc theo mã trạng thái", "component": "TagsInput", "placeholder": "vd: 200,301,404",
                "data": ["200,204", "301,302,307", "400,401,403", "500,502,503"]},
                {"name": "follow_redirects", "label": "Theo dõi chuyển hướng", "component": "Switch", "defaultValue": True},
                {"name": "tech_detect", "label": "Phát hiện công nghệ", "component": "Switch", "defaultValue": True},
                {"name": "title", "label": "Lấy tiêu đề trang", "component": "Switch", "defaultValue": True},
                {"name": "ip", "label": "Lấy địa chỉ IP", "component": "Switch", "defaultValue": True},
                {"name": "web_server", "label": "Lấy thông tin Web Server", "component": "Switch", "defaultValue": True},
                {"name": "response_time", "label": "Lấy thời gian phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "content_length", "label": "Lấy Content-Length", "component": "Switch", "defaultValue": True},
                {"name": "content_type", "label": "Lấy Content-Type", "component": "Switch", "defaultValue": False},
                {"name": "response_size", "label": "Lấy kích thước phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "include_response", "label": "Bao gồm nội dung phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "location", "label": "Lấy Location Header", "component": "Switch", "defaultValue": False},
                {"name": "cname", "label": "Lấy CNAME", "component": "Switch", "defaultValue": False},
                {"name": "cdn", "label": "Kiểm tra CDN", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "dirsearch-scan",
            "name": "Quét thư mục (Dirsearch)",
            "description": "Tìm kiếm các thư mục và file ẩn trên web server.",
            "fields": [
                {"name": "wordlist", "label": "Wordlist", "component": "TextInput", "placeholder": "/app/dicc.txt", "defaultValue": "/app/dicc.txt"},
                {"name": "extensions", "label": "Phần mở rộng cần quét", "component": "TagsInput", "placeholder": "vd: php,asp,aspx",
                "data": ["php", "html", "js", "aspx", "jsp", "txt", "bak", "config", "env"]},
                {"name": "include_status", "label": "Trạng thái HTTP cần lấy", "component": "TagsInput", "placeholder": "vd: 200,204,301,302,307,401,403"},
                {"name": "recursive", "label": "Quét đệ quy", "component": "Switch", "defaultValue": False},
                {"name": "no_extensions", "label": "Không dùng extensions (-e)", "component": "Switch", "defaultValue": False},
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 30},
                {"name": "scanner_count", "label": "Số lượng scanner song song", "component": "NumberInput", "min": 1, "max": 20},
                {"name": "random_agent", "label": "Random User-Agent", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "nuclei-scan",
            "name": "Quét Lỗ hổng (Nuclei)",
            "fields": [
                {"name": "severity", "label": "Mức độ nghiêm trọng", "component": "MultiSelect", "defaultValue": ["high", "critical"], "data": ["info", "low", "medium", "high", "critical"]},
                {"name": "templates", "label": "Chạy các mẫu cụ thể", "component": "MultiSelect", "placeholder": "Để trống để chạy các mẫu đề xuất", "data": ["cves", "default-logins", "exposed-panels", "vulnerabilities"]},
                {"name": "distributed_scanning", "label": "Quét phân tán (Distributed Scanning)", "component": "Switch", "defaultValue": False}
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
                {"name": "data", "label": "POST data/raw hoặc file", "component": "TextInput", "placeholder": "vd: id=1&name=test hoặc file:@post.txt"},
                {"name": "headers", "label": "Headers (JSON hoặc Key:Value)", "component": "TextInput", "placeholder": "vd: {\"User-Agent\":\"sqlmap\"} hoặc User-Agent:sqlmap;X-Forwarded-For:127.0.0.1"},
                {"name": "cookie", "label": "Cookie string", "component": "TextInput", "placeholder": "vd: PHPSESSID=abc; user=admin"},
                {"name": "parameter", "label": "Tham số cần kiểm tra (-p)", "component": "TextInput", "placeholder": "vd: id,username"},
                {"name": "technique", "label": "Kỹ thuật tấn công", "component": "TextInput", "placeholder": "vd: BEUS (Boolean, Error, Union, Stacked)"},
                {"name": "tamper", "label": "Tamper scripts", "component": "TextInput", "placeholder": "vd: between,randomcase"},
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
                {"name": "dbms", "label": "Chỉ định DBMS", "component": "TextInput", "placeholder": "vd: MySQL, PostgreSQL"},
                {"name": "identify_waf", "label": "Thử nhận diện WAF", "component": "Switch", "defaultValue": False},
                {"name": "skip_urlencode", "label": "Không URL-encode payloads", "component": "Switch", "defaultValue": False},
                {"name": "random_agent", "label": "Random User-Agent", "component": "Switch", "defaultValue": False},
                {"name": "batch", "label": "Chạy tự động (batch mode)", "component": "Switch", "defaultValue": True},
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 1},
                {"name": "delay", "label": "Delay giữa requests (giây)", "component": "NumberInput", "defaultValue": 0},
                {"name": "timeout", "label": "Timeout (giây)", "component": "NumberInput", "defaultValue": 30},
                {"name": "retries", "label": "Số lần thử lại", "component": "NumberInput", "defaultValue": 2}
            ]
            },
        {
            "id": "bruteforce-scan",
            "name": "Dò mật khẩu (Bruteforce)",
            "description": "Thực hiện tấn công dò mật khẩu vào các dịch vụ HTTP, SSH, FTP.",
            "fields": [
                {
                    "name": "strategy", 
                    "label": "Chiến lược tấn công", 
                    "component": "Select", 
                    "defaultValue": "dictionary",
                    "data": [
                        {"value": "dictionary", "label": "Dictionary (Một user - nhiều pass)"},
                        {"value": "spray", "label": "Password Spraying (Một pass - nhiều user)"},
                        {"value": "stuffing", "label": "Credential Stuffing (Cặp user:pass)"}
                    ]
                },
                {"name": "concurrency", "label": "Số luồng (concurrency)", "component": "NumberInput", "defaultValue": 2},
                {"name": "users_list", "label": "Danh sách Username", "component": "Textarea", "placeholder": "Nhập mỗi username một dòng..."},
                {"name": "passwords_list", "label": "Danh sách Password", "component": "Textarea", "placeholder": "Nhập mỗi password một dòng..."},
                {"name": "pairs_list", "label": "Danh sách cặp User:Pass", "component": "Textarea", "placeholder": "Nhập mỗi cặp user:pass một dòng..."}
            ]
        }
    ]
    logger.info(f"API call to /api/tools, returning {len(frontend_tools)} tools (dashboard format)")
    return {"tools": frontend_tools}

# Giữ nguyên endpoint gốc: GET /debug/info
@router.get("/debug/info", summary="Endpoint debug cơ bản")
def get_debug_info():
    return {"status": "ok", "service": "Controller API - Refactored"}