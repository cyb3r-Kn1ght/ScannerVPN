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

# 3) Wrapper
COPY *.py /app/
RUN chmod +x /app/wpscan_scan.py
ENTRYPOINT ["python3", "/app/wpscan_scan.py"]
