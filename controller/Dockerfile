FROM python:3.11-slim
WORKDIR /app

# Copy requirements và tools.yaml từ thư mục hiện tại
COPY requirements.txt tools.yaml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy code ứng dụng từ app directory
COPY app/ ./app/

# Copy port list files for portscan splitting logic (from app/ to app/ in image)
COPY app/nmap-ports-top1000.txt app/Ports-1-To-65535.txt ./app/

# Tạo thư mục /data để chứa SQLite file
RUN mkdir /data && chmod a+rwx /data

ENV DATABASE_URL=sqlite:///./data/scan_results.db

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


