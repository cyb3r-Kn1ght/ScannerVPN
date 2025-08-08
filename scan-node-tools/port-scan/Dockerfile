FROM python:3.11-slim

# Cài đặt nmap và các tools cần thiết cho VPN
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        openvpn \
        curl \
        wget \
        iproute2 \
        iptables \
        procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

ENTRYPOINT ["python", "port_scan.py"]
