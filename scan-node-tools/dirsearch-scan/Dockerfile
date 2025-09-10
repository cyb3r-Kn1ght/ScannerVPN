#FROM python:3.11-slim

# Cài các gói cần thiết cho VPN
#RUN apt-get update && apt-get install -y --no-install-recommends \
    #git ca-certificates openvpn iproute2 iputils-ping dnsutils curl wget \
    #&& rm -rf /var/lib/apt/lists/*

# Lấy dirsearch
#RUN git clone --depth=1 https://github.com/maurosoria/dirsearch /opt/dirsearch


# Cài deps của dirsearch (kéo cả defusedxml) + socks + requests cho wrapper
#WORKDIR /opt/dirsearch
#RUN pip install --no-cache-dir -r requirements.txt \
   # && pip install --no-cache-dir "requests[socks]" requests


# Wrapper
#WORKDIR /app
#COPY dirsearch_scan.py /app/dirsearch_scan.py
#COPY vpn_manager.py /app/vpn_manager.py
#COPY dicc.txt /app/dicc.txt

#RUN chmod +x /app/dirsearch_scan.py

#ENTRYPOINT ["python3", "-u", "/app/dirsearch_scan.py"]

# Sử dụng Python 3.11 slim
FROM python:3.11-slim

# Chọn mirror nhanh hơn (Cloudflare hoặc Vinahost)
RUN sed -i 's|deb.debian.org|mirror.cloudflare.com|g' /etc/apt/sources.list

# Cài đặt gói cần thiết với retry 5 lần để tránh treo
RUN set -e; \
    n=0; \
    until [ $n -ge 5 ]; do \
      apt-get update && \
      apt-get install -y --no-install-recommends \
        git ca-certificates openvpn iproute2 iputils-ping dnsutils curl wget \
      && rm -rf /var/lib/apt/lists/* \
      && break; \
      n=$((n+1)); \
      echo "APT update failed, retrying ($n/5)..." && sleep 5; \
    done

# Lấy dirsearch
RUN git clone --depth=1 https://github.com/maurosoria/dirsearch /opt/dirsearch

# Cài deps của dirsearch + requests[socks]
WORKDIR /opt/dirsearch
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "requests[socks]" requests

# Copy wrapper và dicc.txt
WORKDIR /app
COPY dirsearch_scan.py vpn_manager.py dicc.txt /app/

RUN chmod +x /app/dirsearch_scan.py

# Entrypoint
ENTRYPOINT ["python3", "-u", "/app/dirsearch_scan.py"]

