FROM ruby:3.3-slim

# 1) Thư viện hỗ trợ (g++ để build nokogiri)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libcurl4-openssl-dev libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# 2) Cài wpscan gem
RUN gem install wpscan

# 3) Wrapper
COPY wpscan_scan.py /app/
RUN chmod +x /app/wpscan_scan.py
ENTRYPOINT ["python3", "/app/wpscan_scan.py"]
