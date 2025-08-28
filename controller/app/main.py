# app/main.py
import sys
import os
# Thêm thư mục làm việc hiện tại vào Python Path để đảm bảo import hoạt động
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi import FastAPI
from api.router import api_router
from db.session import SessionLocal, engine
from db.base import Base
from db.init_db import init_vpn_profiles_if_empty # <--- THAY ĐỔI Ở ĐÂY

# --- KHỞI TẠO ỨNG DỤNG ---

# 1. Tạo các bảng trong DB nếu chúng chưa tồn tại
# Lưu ý: Trong môi trường production, nên sử dụng công cụ migrate như Alembic
Base.metadata.create_all(bind=engine)

# 2. Khởi tạo dữ liệu VPN ban đầu nếu bảng vpn_profiles đang trống
try:
    db = SessionLocal()
    init_vpn_profiles_if_empty(db)
    db.close()
except Exception as e:
    # Bỏ qua nếu có lỗi (ví dụ: DB chưa sẵn sàng khi khởi động)
    print(f"Could not initialize VPN profiles: {e}")
    pass

# 3. Khởi tạo đối tượng FastAPI
app = FastAPI(
    title="Distributed Scanner Controller",
    description="Backend điều phối hệ thống quét bảo mật phân tán trên Kubernetes.",
    version="1.0.0-refactored"
)

# 4. Include router chính vào ứng dụng
# Tất cả các endpoint đã được định nghĩa trong các file riêng lẻ và gom lại trong api_router
app.include_router(api_router)

# 5. Tạo một endpoint gốc để kiểm tra "sức khỏe"
@app.get("/health", summary="Endpoint kiểm tra sức khỏe", tags=["Health Check"])
def health_check():
    """
    Kiểm tra xem API có đang hoạt động hay không.
    """
    return {"status": "ok"}