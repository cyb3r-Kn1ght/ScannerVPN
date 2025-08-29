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

Ví dụ response `/api/tools`:

```json
[
	{
		"name": "port-scan",
		"parameters": [
			{"name": "target", "type": "str", "required": true, "desc": "IP/domain cần quét"},
			{"name": "ports", "type": "str", "required": false, "desc": "Danh sách port, ví dụ: 80,443,8080"},
			{"name": "all_ports", "type": "bool", "required": false, "desc": "Quét toàn bộ port"},
			{"name": "top_ports", "type": "int", "required": false, "desc": "Quét top N port phổ biến"},
			{"name": "vpn_profile", "type": "str", "required": false, "desc": "VPN profile sử dụng"}
		]
	},
	{
		"name": "httpx",
		"parameters": [
			{"name": "target", "type": "str", "required": true, "desc": "IP/domain cần quét"},
			{"name": "ports", "type": "str", "required": false, "desc": "Danh sách port"},
			{"name": "vpn_profile", "type": "str", "required": false, "desc": "VPN profile sử dụng"}
		]
	}
	// ...
]
```
> Để lấy danh sách tham số hợp lệ mới nhất, luôn gọi `GET /api/tools`.

---

## 📝 4. Ví dụ sử dụng API

### 4.1. Tạo workflow phức tạp
```json
POST /api/workflow
{
	"name": "Example Workflow",
	"steps": [
		{
			"tool": "port-scan",
			"parameters": {
				"target": "example.com",
				"top_ports": 100
			}
		},
		{
			"tool": "httpx",
			"parameters": {
				"target": "example.com"
			}
		}
	]
}
```

### 4.2. Tạo job quét port-scan đơn lẻ
```json
POST /api/scan/port-scan
{
	"target": "example.com",
	"top_ports": 100
}
```

### 4.3. Lấy kết quả sub-job port-scan
```
GET /api/sub_jobs/{sub_job_id}/results
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
