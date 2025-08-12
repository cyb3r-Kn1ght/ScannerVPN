FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Base deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip build-essential wget python3 python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Cài Go (chọn bản ổn, đủ mới để build nuclei)
ARG GO_VERSION=1.21.10
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
 && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
 && ln -s /usr/local/go/bin/go /usr/local/bin/go \
 && rm go${GO_VERSION}.linux-amd64.tar.gz

# Build nuclei từ source (qua Go module proxy, ít lỗi hơn gọi API GitHub)
ENV GOPATH=/root/go
RUN GO111MODULE=on go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && mv /root/go/bin/nuclei /usr/local/bin/nuclei \
 && rm -rf /root/go /usr/local/go

# Clone templates vào chỗ cố định
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates \
 && mkdir -p /root/.local \
 && ln -sf /root/nuclei-templates /root/.local/nuclei-templates

# (tuỳ) đồng bộ chỉ mục templates
RUN nuclei -ut -silent || true

# Wrapper
WORKDIR /app
COPY nuclei_scan.py /app/nuclei_scan.py
RUN chmod +x /app/nuclei_scan.py
ENTRYPOINT ["python3", "/app/nuclei_scan.py"]
