FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt dependencies cơ bản cho VPN và scanning
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    curl \
    openvpn \
    iproute2 \
    iputils-ping \
    net-tools \
    jq \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Cài httpx từ GitHub releases
RUN curl -L https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip -o httpx.zip \
    && unzip httpx.zip \
    && mv httpx /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm httpx.zip

WORKDIR /app

# Copy VPN management scripts
COPY vpn_manager.py /app/vpn_manager.py
COPY scan_with_vpn.sh /app/scan_with_vpn.sh

RUN pip3 install requests
RUN chmod +x /app/scan_with_vpn.sh

# Default command
CMD ["/app/scan_with_vpn.sh"]
