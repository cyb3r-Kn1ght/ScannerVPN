# scan-node-tools/ffuf-entry/Dockerfile
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git && \
    go install github.com/ffuf/ffuf/v2@latest

FROM python:3.11-alpine
RUN apk add --no-cache ca-certificates && update-ca-certificates
COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf
RUN pip install --no-cache-dir requests[socks]==2.32.3 beautifulsoup4==4.12.3 lxml==5.2.2
WORKDIR /app
COPY ffuf_entry.py /app/ffuf_entry.py

RUN adduser -D -u 10001 scanner && chown -R scanner /app
USER scanner

ENTRYPOINT ["python", "/app/ffuf_entry.py"]
