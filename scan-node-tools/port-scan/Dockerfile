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

# ---
# To always allow SYN scan (-sS), run the container with NET_RAW and NET_ADMIN capabilities:
#
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v $(pwd):/app -w /app python:3.11-slim python port_scan.py ...
#
# Or, if using this Dockerfile:
#   docker build -t portscan .
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN portscan
#
# These capabilities are required for nmap SYN scan to work inside the container.
# ---
