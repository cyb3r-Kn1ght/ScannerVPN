FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Cập nhật & cài curl, python3, pip, openvpn
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    curl \
    openvpn \
    iproute2 iputils-ping net-tools jq \
    net-tools

# Tạo thư mục làm việc
WORKDIR /app

# Sao chép toàn bộ mã nguồn (ví dụ: fetch_vpn.py)
COPY fetch_vpn.py /app/fetch_vpn.py
COPY entrypoint.sh /app/entrypoint.sh
# COPY rotate_vpn.sh /app/rotate_vpn.sh

# Cài thư viện python nếu có
RUN pip3 install requests
RUN chmod +x /app/entrypoint.sh
# RUN chmod +x /app/rotate_vpn.sh

# Lệnh mặc định khi container start (có thể thay)
# CMD ["python3", "/app/fetch_vpn.py"]
CMD ["/app/entrypoint.sh"]