# ───────────────────────────────────────────────────────────────
# Stage 1: build httpx CLI bằng Go
# ───────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ───────────────────────────────────────────────────────────────
# Stage 2: runtime image
# ───────────────────────────────────────────────────────────────
FROM python:3.11-slim
# Nếu httpx_scan.py có thêm lib Python (ví dụ ujson), liệt kê trong requirements.txt
WORKDIR /app
COPY requirements.httpx.txt ./
RUN pip install --no-cache-dir -r requirements.httpx.txt

# copy binary httpx từ stage trước
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY *.py ./

# dùng user không root
USER 1000:1000
ENTRYPOINT ["python", "httpx_scan.py"]
