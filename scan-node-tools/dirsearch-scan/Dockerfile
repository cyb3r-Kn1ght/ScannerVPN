FROM python:3.11-slim

# Cài các gói cần thiết cho VPN
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates openvpn iproute2 iputils-ping dnsutils curl wget \
    && rm -rf /var/lib/apt/lists/*

# Lấy dirsearch
RUN git clone --depth=1 https://github.com/maurosoria/dirsearch /opt/dirsearch


# Cài deps của dirsearch (kéo cả defusedxml) + socks + requests cho wrapper
WORKDIR /opt/dirsearch
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "requests[socks]" requests


# Wrapper
WORKDIR /app
COPY dirsearch_scan.py /app/dirsearch_scan.py
COPY vpn_manager.py /app/vpn_manager.py
COPY dicc.txt /app/dicc.txt

RUN chmod +x /app/dirsearch_scan.py

ENTRYPOINT ["python3", "-u", "/app/dirsearch_scan.py"]
