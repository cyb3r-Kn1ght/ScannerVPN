# Distributed Scanner System (Kubernetes)

## 📝 Tổng quan hệ thống

Hệ thống quét bảo mật phân tán, điều phối qua Controller (FastAPI), thực thi scan qua các Scanner Node API (Python FastAPI, chạy trong Kubernetes), sử dụng các Job/Pod động để thực hiện các tác vụ như port scan, httpx, nuclei, wpscan, dns lookup... Kết quả lưu về database (SQLite).

### Kiến trúc tổng thể

```
Dashboard/User
		↓ (HTTP API)
Controller (FastAPI, DB)
		↓ (API call)
Scanner Node API (FastAPI, K8s)
		↓ (Tạo K8s Job/Pod)
Kubernetes Cluster
		↓ (Kết quả scan)
Controller DB
```

- **Controller**: Điều phối workflow, quản lý DB, cung cấp REST API cho dashboard.
- **Scanner Node API**: Nhận lệnh từ controller, tạo/xóa các K8s Job/Pod để thực thi scan.
- **Scanner Jobs**: Pod động, mỗi job thực hiện 1 tác vụ scan, trả kết quả về controller.

---

## 🚦 Quy trình hoạt động

1. Dashboard gửi yêu cầu scan (qua API Controller)
2. Controller tạo workflow, chia nhỏ thành các scan job (sub-job)
3. Controller gọi Scanner Node API để tạo các K8s Job/Pod tương ứng
4. Scanner Node API tạo K8s Job, Pod thực thi scan tool (portscan, httpx, nuclei...)
5. Pod scan xong gửi kết quả về Controller (API)
6. Controller lưu kết quả vào DB, cập nhật trạng thái workflow
7. Khi cần, Controller/Scanner Node có thể xóa pod/job, workflow, kết quả liên quan

---

## ⚙️ Build & Deploy

### 1. Build Docker images

```bash
cd controller
make build
cd ../scanner-node-api
make build
```

Hoặc build thủ công:
```bash
docker build -t controller:latest ./controller
# Lặp lại cho từng thư mục scan-node-tools/* nếu muốn build riêng từng tool
```

### 2. Deploy lên Kubernetes

```bash
kubectl apply -f manifests/namespace.yaml
kubectl apply -f manifests/controller-deployment.yaml
kubectl apply -f manifests/controller-service.yaml
kubectl apply -f manifests/scanner-node-api-deployment.yaml
kubectl apply -f manifests/scanner-node-api-service.yaml
kubectl apply -f manifests/controller-rbac.yaml
kubectl apply -f manifests/controller-pv.yaml
kubectl apply -f manifests/scanner-node-rbac.yaml
# Có thể apply thêm các job mẫu trong manifests/jobs/*
```

### 3. Port-forward để test API

```bash
kubectl port-forward -n scan-system svc/controller 8000:80
kubectl port-forward -n scan-system svc/scanner-node-api 8080:8080
```

---

## 🚀 Sử dụng API

### Khởi tạo workflow scan
```bash
curl -X POST http://localhost:8000/api/scan/workflow \
	-H "Content-Type: application/json" \
	-d '{
		"targets": ["scanme.nmap.org"],
		"scan_types": ["port-scan", "httpx", "nuclei"],
		"strategy": "wide"
	}'
```

### Xem trạng thái workflow
```bash
curl http://localhost:8000/api/workflows/<workflow_id>
```

### Xem kết quả scan
```bash
curl http://localhost:8000/api/scan_results?workflow_id=<workflow_id>
```

### Xóa job, workflow, pod/job scanner

- Xóa 1 scan job (DB + pod/job):
	```bash
	curl -X DELETE http://localhost:8000/api/scan_jobs/<job_id>/full_delete
	```
- Chỉ xóa pod/job scanner (không xóa DB):
	```bash
	curl -X DELETE http://localhost:8000/api/scan_jobs/<job_id>/scanner_job
	```
- Xóa toàn bộ workflow (toàn bộ sub-job, kết quả, pod/job liên quan):
	```bash
	curl -X DELETE http://localhost:8000/api/workflows/<workflow_id>
	```
- Xóa toàn bộ database (chỉ dùng cho dev/test):
	```bash
	curl -X DELETE http://localhost:8000/api/database/clear
	```

> Khi xóa pod/job đã bị xóa trước đó, API trả về `{ "status": "not found" }` thay vì lỗi dài dòng.

---

## 🛠️ Phát triển & debug

- Xem log controller:
	```bash
	kubectl logs -n scan-system -l app=controller
	```
- Xem log scanner node:
	```bash
	kubectl logs -n scan-system -l app=scanner-node-api
	```
- Xem log pod scan:
	```bash
	kubectl logs -n scan-system -l job-name=<job_name>
	```
- Xem trạng thái resource:
	```bash
	kubectl get pods -n scan-system
	kubectl get jobs -n scan-system
	kubectl get svc -n scan-system
	```

---

## 🔒 Bảo mật & mở rộng

- RBAC tối thiểu cho từng service
- Tách namespace riêng (scan-system)
- Có thể scale scanner-node-api, controller
- Có thể thay SQLite bằng PostgreSQL/MySQL nếu cần

---

## 📚 Tham khảo endpoint chính

- `POST /api/scan/workflow` — Tạo workflow scan mới
- `GET /api/workflows/{workflow_id}` — Xem trạng thái workflow
- `GET /api/scan_results` — Lấy kết quả scan
- `DELETE /api/scan_jobs/{job_id}/full_delete` — Xóa job (DB + pod/job)
- `DELETE /api/scan_jobs/{job_id}/scanner_job` — Chỉ xóa pod/job scanner
- `DELETE /api/workflows/{workflow_id}` — Xóa toàn bộ workflow, sub-job, pod/job
- `DELETE /api/database/clear` — Xóa toàn bộ database (dev/test)

---

## 📦 Thư mục chính

- `controller/` — FastAPI controller, DB, API chính
- `scanner-node-api/` — FastAPI scanner node, quản lý K8s job/pod
- `scan-node-tools/` — Các tool scan (port-scan, httpx, nuclei, wpscan, dns-lookup...)
- `manifests/` — K8s manifests

---

## 📝 Ghi chú

- Đảm bảo đã build image trước khi deploy lên K8s
- Có thể mở rộng thêm tool scan mới bằng cách thêm vào `scan-node-tools/` và cập nhật scanner-node-api
- Khi xóa job/workflow, hệ thống sẽ tự động dọn dẹp pod/job và dữ liệu liên quan
- Nếu cần hướng dẫn chi tiết hơn, xem code hoặc liên hệ maintainer
