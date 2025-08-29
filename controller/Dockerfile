# Dockerfile (PHIÊN BẢN SỬA LỖI ĐƯỜNG DẪN)
FROM python:3.11-slim
WORKDIR /app

# Copy requirements và các file cấu hình vào trước
# THAY ĐỔI Ở ĐÂY: Thêm "data/" vào trước tên các file .txt
COPY requirements.txt tools.yaml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ nội dung thư mục 'app' vào WORKDIR (/app)
COPY ./app ./app
COPY data ./data
# Tạo thư mục /data để chứa SQLite file
RUN mkdir -p /data

ENV DATABASE_URL=sqlite:////data/scan_results.db

EXPOSE 8000
# Gọi ứng dụng từ main.py (đã được copy vào /app)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
#CMD ["sleep", "3600"]