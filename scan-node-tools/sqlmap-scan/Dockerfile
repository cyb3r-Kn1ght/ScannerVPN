FROM python:3.11-slim

# Cài các gói cần thiết cho VPN
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates openvpn iproute2 iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Lấy sqlmap
RUN git clone --depth=1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap

# Cài deps cho sqlmap + socks + requests cho wrapper
WORKDIR /opt/sqlmap
RUN pip install --no-cache-dir "requests[socks]" requests

# Wrapper
WORKDIR /app
COPY sqlmap_scan.py /app/sqlmap_scan.py
COPY vpn_manager.py /app/vpn_manager.py
RUN chmod +x /app/sqlmap_scan.py

ENTRYPOINT ["python3", "/app/sqlmap_scan.py"]