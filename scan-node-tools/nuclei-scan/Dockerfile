FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 1) Thư viện bắt buộc và VPN tools
RUN apt-get update && \
    apt-get install -y \
        curl \
        unzip \
        python3 \
        python3-pip \
        openvpn \
        wget \
        iproute2 \
        iptables \
        procps && \
    rm -rf /var/lib/apt/lists/*

# 2) Cài nuclei (bản stable mới nhất)
RUN curl -L https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep browser_download_url | grep linux_amd64.zip | cut -d '"' -f 4 \
    | xargs curl -L -o nuclei.zip && \
    unzip nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip

# 3) Tải template mặc định
RUN nuclei -update -silent

# 4) Wrapper
COPY *.py /app/
RUN chmod +x /app/nuclei_scan.py
ENTRYPOINT ["python3", "/app/nuclei_scan.py"]
