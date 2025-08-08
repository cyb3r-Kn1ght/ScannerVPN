FROM ubuntu:22.04
# Copy VPN manager và scan script
COPY vpn_manager.py ./
COPY dns_lookup.py ./
COPY requirements.txt ./

# Install Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Entry point sẽ setup VPN trước khi scan
ENTRYPOINT ["/opt/venv/bin/python", "dns_lookup.py"]FRONTEND=noninteractive

# Cài đặt dependencies cho VPN và DNS scanning
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    openvpn \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy VPN manager và scan script
COPY vpn_manager.py ./
COPY dns_lookup.py ./
COPY requirements.txt ./

    # Install Python dependencies
    RUN python3 -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"
    RUN pip install --no-cache-dir -r requirements.txt
    
    # Entry point sẽ setup VPN trước khi scan
ENTRYPOINT ["/opt/venv/bin/python", "dns_lookup.py"]
