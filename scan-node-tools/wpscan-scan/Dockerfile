FROM ruby:3.3-slim

# 1) Thư viện hỗ trợ và VPN tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libcurl4-openssl-dev \
        libssl-dev \
        zlib1g-dev \
        python3 \
        python3-pip \
        openvpn \
        curl \
        wget \
        iproute2 \
        iptables \
        procps && \
    rm -rf /var/lib/apt/lists/*

# 2) Cài wpscan gem
RUN gem install wpscan

# 3) Install Python dependencies
WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# 4) Wrapper
COPY *.py ./
RUN chmod +x ./wpscan_scan.py
ENTRYPOINT ["/opt/venv/bin/python", "./wpscan_scan.py"]
