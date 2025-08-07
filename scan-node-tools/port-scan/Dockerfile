FROM python:3.11-slim

# cài nmap và (tuỳ nếu dùng thư viện python-nmap để parse)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY port_scan.py ./

USER 1000:1000
ENTRYPOINT ["python", "port_scan.py"]
