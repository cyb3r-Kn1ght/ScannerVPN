# Distributed Scanner System - Kubernetes

🚀 **Hệ thống quét phân tán chạy trên Kubernetes**

## 🏗️ Architecture

```
Dashboard/User
    ↓ (HTTP requests)
Controller (FastAPI)
    ↓ (API calls)
Scanner Node API (K8s Deployment)
    ↓ (creates)
Kubernetes Jobs/Pods
    ↓ (scan results)
Controller Database
```

## 📦 Components

### 1. **Controller**
- REST API nhận yêu cầu quét từ Dashboard
- Lưu trữ kết quả quét trong SQLite database
- Điều phối jobs đến Scanner Node API

### 2. **Scanner Node API** 
- API server chạy trong K8s
- Nhận job requests từ Controller
- Tạo Kubernetes Jobs để thực hiện quét
- Quản lý lifecycle của scan jobs

### 3. **Scanner Jobs**
- Kubernetes Jobs được tạo dynamically
- Mỗi job chạy trong Pod riêng biệt
- Thực hiện DNS lookup, port scan, HTTP fingerprinting
- Gửi kết quả về Controller

## 🚀 Quick Start

### Prerequisites & Kubernetes Setup

#### Option 1: Minikube (Local Development)
```bash
# Install Minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Start Minikube cluster (adjust memory based on your system)
# For systems with 4GB+ RAM:
minikube start --driver=docker --memory=2200 --cpus=2

# For systems with 8GB+ RAM:
# minikube start --driver=docker --memory=4096 --cpus=2

# Verify cluster
kubectl cluster-info
kubectl get nodes
```

#### Option 2: Kind (Kubernetes in Docker)
```bash
# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create cluster
kind create cluster --name scanner-cluster

# Set context
kubectl cluster-info --context kind-scanner-cluster
```

#### Option 3: Remote Kubernetes Cluster
```bash
# Use existing kubeconfig
export KUBECONFIG=/path/to/your/kubeconfig

# Or copy to default location
mkdir -p ~/.kube
cp /path/to/kubeconfig ~/.kube/config

# Test connection
kubectl cluster-info
```

#### Check Prerequisites
```bash
# Kubernetes cluster access
kubectl cluster-info

# Docker for building images  
docker --version

# Make for task automation
make --version
```

### 1. Setup Kubernetes Cluster
```bash
# If using Minikube (adjust memory based on your system)
minikube start --driver=docker --memory=2200 --cpus=2

# If using Kind  
kind create cluster --name scanner-cluster

# Verify cluster is ready
kubectl get nodes
```

### 2. Setup Environment
```bash
make dev-setup
```

### 3. Build Images
```bash
make build
```

### 4. Deploy to Kubernetes
```bash
make deploy
```

### 5. Test System
```bash
make test
```

### 6. Monitor
```bash
make monitor
```

## 📊 Commands

| Command | Description |
|---------|-------------|
| `make deploy` | Deploy to Kubernetes |
| `make test` | Run complete test suite |
| `make monitor` | Monitor K8s resources |
| `make logs` | View service logs |
| `make health` | Check services health |
| `make clean` | Clean up resources |
| `make clean-all` | Remove everything |

## 🔧 Manual Commands

### Deploy step-by-step:
```bash
kubectl apply -f manifests/namespace.yaml
kubectl apply -f manifests/scanner-node-rbac.yaml  
kubectl apply -f manifests/controller-deployment.yaml
kubectl apply -f manifests/controller-service.yaml
kubectl apply -f manifests/scanner-node-api-deployment.yaml
```

### Check deployment:
```bash
kubectl get pods -n scan-system
kubectl get services -n scan-system  
kubectl get jobs -n scan-system
```

### Test API:
```bash
# Port forward services
kubectl port-forward -n scan-system svc/controller 8000:80 &
kubectl port-forward -n scan-system svc/scanner-node-api 8080:8080 &

# Send scan request
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com", "8.8.8.8"],
    "scanner_node_url": "http://localhost:8080",
    "scan_types": ["dns", "port", "http"]
  }'
```

## 📋 API Endpoints

### Controller API (Port 8000)
- `POST /api/scan/start` - Start new scan job
- `GET /api/scan_results` - Get scan results
- `POST /api/scan_results` - Receive results (from scanner)

### Scanner Node API (Port 8080)  
- `POST /api/scan/execute` - Execute scan job (creates K8s Job)
- `GET /api/jobs/status/{job_id}` - Get job status
- `GET /api/jobs/{job_id}/logs` - Get job logs
- `DELETE /api/jobs/{job_id}` - Cleanup job
- `GET /api/health` - Health check

## 🔍 How It Works

1. **Job Request**: Dashboard sends scan request to Controller
2. **Job Dispatch**: Controller calls Scanner Node API 
3. **K8s Job Creation**: Scanner Node API creates Kubernetes Job
4. **Pod Execution**: Job spawns Pod with scanner image
5. **Scanning**: Pod performs DNS, port, HTTP scans
6. **Results**: Pod sends results back to Controller
7. **Storage**: Controller stores results in database
8. **Cleanup**: Job and Pod auto-cleanup after completion

## 🛠️ Development

### Local testing:
```bash
# Build images
make build

# Deploy to local K8s (minikube/kind)
make deploy

# Run tests
make test

# View logs
make logs

# Monitor resources
make monitor
```

### Debugging:
```bash
# Check pod logs
kubectl logs -n scan-system -l app=scanner-job

# Describe resources
kubectl describe deployment controller -n scan-system
kubectl describe deployment scanner-node-api -n scan-system

# Port forward for direct access
kubectl port-forward -n scan-system svc/controller 8000:80
kubectl port-forward -n scan-system svc/scanner-node-api 8080:8080
```

## 🔧 Configuration

### Environment Variables:
- `KUBERNETES_NAMESPACE`: Target namespace (default: scan-system)
- `CONTROLLER_API`: Controller API endpoint
- `DATABASE_URL`: Database connection string

### Scanner Job Configuration:
- CPU: 250m request, 500m limit
- Memory: 512Mi request, 1Gi limit  
- TTL: 3600s (1 hour after completion)
- Restart Policy: Never

## 🚨 Security

- ServiceAccount with minimal RBAC permissions
- Network policies for inter-service communication
- Resource limits to prevent resource exhaustion
- Automatic cleanup of completed jobs

## 🔄 Scaling

- Controller: Single replica (can be scaled)
- Scanner Node API: 2 replicas (can be scaled horizontally)
- Scanner Jobs: Dynamic based on requests
- Database: SQLite (can be replaced with PostgreSQL/MySQL)

## 📊 Monitoring

### Built-in monitoring:
```bash
# Resource usage
kubectl top pods -n scan-system

# Job status
kubectl get jobs -n scan-system

# Service health
make health
```

### Logs:
```bash
# Real-time logs
make follow-logs

# Service logs
make logs

# Job logs  
kubectl logs -n scan-system job/scanner-job-<job-id>
```
