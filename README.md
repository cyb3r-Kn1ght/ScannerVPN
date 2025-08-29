# ScannerVPN Backend Documentation

---

## 🛡️ 1. Tổng quan hệ thống

> **ScannerVPN** là nền tảng quản lý và điều phối các job quét bảo mật phân tán, hỗ trợ nhiều tool (port-scan, httpx, nuclei, sqlmap, wpscan, bruteforce, dirsearch, dns-lookup, ffuf, ...) với khả năng chia nhỏ công việc (sharding), gom kết quả, quản lý VPN profile, và tích hợp với Kubernetes/Docker.

| Thành phần | Công nghệ |
|------------|-----------|
| Backend    | FastAPI, SQLAlchemy, Pydantic |
| Triển khai | Docker, Kubernetes |

---

## 🚦 2. Các API chính

### 2.1. Quản lý Workflow
- **Tạo workflow:** `POST /api/workflow`  
	Body: JSON theo schema `WorkflowRequest` (nhiều bước, mỗi bước là 1 tool)
- **Lấy danh sách workflow:** `GET /api/workflows`
- **Lấy trạng thái workflow:** `GET /api/workflows/{workflow_id}/status`

### 2.2. Quản lý Scan Job
- **Tạo job quét cho 1 tool:** `POST /api/scan/{tool_name}`  
	Body: JSON theo schema `ScanJobRequest` (tham số hợp lệ tuỳ tool, xem mục 3)
- **Lấy chi tiết job:** `GET /api/scan_jobs/{job_id}`
- **Lấy danh sách job:** `GET /api/scan_jobs?skip=0&limit=100`
- **Xoá job:** `DELETE /api/scan_jobs/{job_id}`
- **Xoá job trên scanner node (không xoá DB):** `DELETE /api/scan_jobs/{job_id}/scanner_job`
- **Cập nhật trạng thái job:** `PATCH /api/scan_jobs/{job_id}/status`  
	Body: `{ "status": "submitted|running|completed|failed" }`

### 2.3. Kết quả sub-job (tool đặc thù)
- **Lấy kết quả sub-job (đã merge/dedup):** `GET /api/sub_jobs/{sub_job_id}/results`

### 2.4. Quản lý VPN
- **Tạo VPN profile:** `POST /api/vpn_profiles`
- **Lấy danh sách VPN profile:** `GET /api/vpn_profiles`
- **Lấy danh sách VPN proxy node:** `GET /api/vpns`

### 2.5. Liệt kê schema tham số hợp lệ cho từng tool
- **Lấy schema tool:** `GET /api/tools`  
	Trả về danh sách các tool và tham số hợp lệ (dùng để build UI hoặc validate request)

---

## 🧩 3. Tham số hợp lệ cho từng tool (theo /api/tools)

### Cách truyền tham số chung và riêng cho từng tool

- **vpn_profile** có thể truyền ở ngoài (áp dụng cho toàn bộ workflow, tất cả các tool sẽ dùng VPN này nếu không chỉ định riêng).
- **port-scan** hỗ trợ truyền `vpn_profile` là một mảng bên trong params để chỉ định VPN cho từng scanner con (shard), ví dụ:
  ```json
  {
    "tool_id": "port-scan",
    "params": {
      "vpn_profile": ["vpn1.ovpn", "vpn2.ovpn", ...],
      ...
    }
  }
  ```
- Các tool khác sẽ ưu tiên vpn_profile trong params nếu có, nếu không sẽ lấy ở ngoài workflow.

### Bảng tham số hợp lệ từng tool

| Tool             | Tham số hợp lệ                                                                                                                         |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **httpx-scan**   | follow_redirects (bool), include_response (bool), timeout (int), retries (int), ports (str), status_code (bool), title (bool), ip (bool), web_server (bool), content_length (bool), tech_detect (bool) |
| **port-scan**    | all_ports (bool), ports (str), scan_type (str), scanner_count (int), vpn_profile (str/list, riêng từng shard), ...                     |
| **nuclei-scan**  | severity (list), templates (list)                                                                                                      |
| **wpscan-scan**  | enumerate (list), api_key (str)                                                                                                        |
| **dns-lookup**   | (không bắt buộc tham số, có thể truyền rỗng)                                                                                           |
| **dirsearch-scan**| extensions (str), threads (int), recursive (bool), include_status (str), no_extensions (bool)                                         |

> Để lấy danh sách tham số hợp lệ mới nhất, luôn gọi `GET /api/tools`.

---

## 📝 4. Ví dụ sử dụng API

### Ví dụ tạo workflow với tất cả tool và đủ tham số hợp lệ

```bash
curl -X POST http://10.102.199.42:8000/api/workflow \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["demo.testfire.net"],
    "vpn_profile": "103.57.130.113.ovpn",
    "steps": [
      {
        "tool_id": "httpx-scan",
        "params": {
          "follow_redirects": true,
          "include_response": true,
          "timeout": 15,
          "retries": 2,
          "ports": "80,443,8080",
          "status_code": true,
          "title": true,
          "ip": true,
          "web_server": true,
          "content_length": true,
          "tech_detect": true
        }
      },
      {
        "tool_id": "port-scan",
        "params": {
          "all_ports": true,
          "ports": "all",
          "scan_type": "-sS",
          "scanner_count": 5,
          "vpn_profile": [
            "70.36.97.79.ovpn",
            "vpngate_42.115.224.83_udp_1457.ovpn",
            "vpngate_42.115.224.83_tcp_1416.ovpn",
            "103.57.130.113.ovpn",
            "vpngate_121.139.214.237_tcp_1961.ovpn"
          ]
        }
      },
      {
        "tool_id": "nuclei-scan",
        "params": {
          "severity": ["info", "low"],
          "templates": ["cves", "default-logins", "exposed-panels", "vulnerabilities"]
        }
      },
      {
        "tool_id": "wpscan-scan",
        "params": {
          "enumerate": ["p", "t", "u"],
          "api_key": "OyiwPdiO9VJhjMOqL6PoWAPC3EpA88mvoowwOASINhO"
        }
      },
      {
        "tool_id": "dns-lookup",
        "params": {}
      },
      {
        "tool_id": "dirsearch-scan",
        "params": {
          "extensions": "php,asp,aspx",
          "threads": 10,
          "recursive": true,
          "include_status": "200,204",
          "no_extensions": false
        }
      }
    ]
  }'
```

### Lấy kết quả sub-job bất kỳ
```bash
curl http://10.102.199.42:8000/api/sub_jobs/{sub_job_id}/results
```

---

## ⚙️ 5. Build & Triển khai

- **Build Docker:**
	```sh
	cd controller
	docker build -t scannervpn-backend .
	```
- **Chạy local:**
	```sh
	cd controller
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
	```
- **Triển khai Kubernetes:**
	- Sử dụng các file trong `manifests/`

---

## 🛠️ 6. Lưu ý vận hành

- Đảm bảo file dữ liệu (ví dụ nmap-ports-top1000.txt) có trong container nếu dùng port-scan.
- Scanner node phải luôn tuân thủ danh sách port được giao (không tự ý quét all nếu không được chỉ định).
- Khi gặp lỗi duplicate port hoặc không chia shard đúng, kiểm tra lại logic sharding và scanner-side code.
- Để cập nhật địa chỉ VPN proxy node, sửa trong file manifest hoặc biến môi trường tương ứng.

---

## 🤝 7. Liên hệ & đóng góp

- Mọi thắc mắc, bug, hoặc đóng góp vui lòng tạo issue hoặc liên hệ maintainer.
