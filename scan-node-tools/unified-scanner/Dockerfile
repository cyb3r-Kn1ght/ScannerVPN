FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt tất cả dependencies
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
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Cài httpx
RUN curl -L https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip -o httpx.zip \
    && unzip httpx.zip \
    && mv httpx /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm httpx.zip

WORKDIR /app

# Copy VPN manager
COPY vpn_manager.py /app/
COPY scan_with_vpn.py /app/

# Copy all scan tools
COPY dns_lookup.py /app/
COPY port_scan.py /app/
COPY httpx_scan.py /app/

# Install Python dependencies
RUN pip3 install requests lxml python-nmap

# Set executable
RUN chmod +x /app/scan_with_vpn.py

CMD ["python3", "/app/scan_with_vpn.py"]
