FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates && rm -rf /var/lib/apt/lists/*

# Lấy dirsearch
RUN git clone --depth=1 https://github.com/maurosoria/dirsearch /opt/dirsearch

# Cài deps của dirsearch (kéo cả defusedxml) + socks
WORKDIR /opt/dirsearch
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "requests[socks]"

# Wrapper
WORKDIR /app
COPY dirsearch_scan.py /app/dirsearch_scan.py
RUN chmod +x /app/dirsearch_scan.py

ENTRYPOINT ["python3", "/app/dirsearch_scan.py"]
