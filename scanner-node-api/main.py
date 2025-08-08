from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Extra
from typing import List, Dict, Any, Optional
import os
import time
import httpx
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes_service import KubernetesService

# Thiết lập logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load in-cluster config or fallback to kubeconfig
try:
    config.load_incluster_config()
except:
    config.load_kube_config()

batch_v1 = client.BatchV1Api()

REGISTRY = os.getenv("REGISTRY", "l4sttr4in/scan-tools")
TAG = os.getenv("TAG", "latest")
NAMESPACE = os.getenv("NAMESPACE", "scan-system")

class ScanRequest(BaseModel):
    tool: str
    targets: List[str]
    options: Dict[str, Any] = {}
    job_id: Optional[str] = None
    controller_callback_url: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None  # VPN config từ Controller

    class Config:
        extra = Extra.ignore  # ignore additional fields like scanner_node_url

app = FastAPI()

# Initialize Kubernetes service
k8s_service = KubernetesService(namespace=NAMESPACE)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan", status_code=201)
def scan(req: ScanRequest):
    return _create_job(req)

@app.post("/api/scan/execute", status_code=201)
def execute_scan(req: ScanRequest, request: Request = None):
    """
    Thực hiện scan - CHỈ được gọi từ Controller.
    """
    # Log request info for security monitoring
    if request:
        client_info = AuthMiddleware.get_client_info(request)
        logger.info(f"Scan request from {client_info['client_ip']} (auth: {client_info['is_authenticated']})")
        
        # Check authentication for production environments
        if not client_info['is_authenticated']:
            logger.warning(f"Unauthorized scan request from {client_info['client_ip']}")
            # In production, you might want to require auth:
            # AuthMiddleware.require_controller_auth(request)
    
    print(f"[DEBUG] Received payload: {req.dict()}")  # Debug line
    print(f"[DEBUG] VPN assignment: {req.vpn_assignment}")  # Debug VPN specifically
    return _create_job(req)


def _create_job(req: ScanRequest):
    job_name = f"{req.tool}-scan-{int(time.time())}"
    
    # Tạo environment variables cho container
    env_vars = [
        client.V1EnvVar(name="TARGETS", value=",".join(req.targets))
    ]
    
    # Thêm controller callback URL - ưu tiên external URL
    if req.controller_callback_url:
        # Convert internal service URL to external IP if needed
        callback_url = req.controller_callback_url
        if "controller.scan-system.svc.cluster.local" in callback_url:
            # Get external controller IP from environment or use default
            external_controller_ip = os.getenv("EXTERNAL_CONTROLLER_IP", "10.102.199.42")  # Ubuntu VM IP
            callback_url = callback_url.replace(
                "controller.scan-system.svc.cluster.local", 
                external_controller_ip
            )
        env_vars.append(client.V1EnvVar(name="CONTROLLER_CALLBACK_URL", value=callback_url))
    
    # Thêm job ID nếu có
    if req.job_id:
        env_vars.append(client.V1EnvVar(name="JOB_ID", value=req.job_id))
    
    # nếu là wpscan
    if req.tool == "wpscan-scan":
        env_vars.append(
            client.V1EnvVar(
                name="WPSCAN_API_TOKEN",
                value_from=client.V1EnvVarSource(
                    secret_key_ref=client.V1SecretKeySelector(
                        name="wpscan-api-token",
                        key="token"
                    )
                )
            )
        )

    # Thêm VPN assignment nếu có
    if req.vpn_assignment:
        import json
        vpn_json = json.dumps(req.vpn_assignment)
        env_vars.append(client.V1EnvVar(name="VPN_ASSIGNMENT", value=vpn_json))
        print(f"[*] Added VPN assignment to job: {req.vpn_assignment.get('hostname', 'Unknown')}")
    
    container = client.V1Container(
        name=req.tool,
        image=f"{REGISTRY}/{req.tool}:latest",
        args=req.targets,
        env=env_vars,
        image_pull_policy="Never",
        security_context=client.V1SecurityContext(
            privileged=True,
            capabilities=client.V1Capabilities(
                add=["NET_ADMIN"]
            )
        ),
        volume_mounts=[
            client.V1VolumeMount(
                name="dev-tun",
                mount_path="/dev/net/tun"
            )
        ]
    )
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(labels={"job-name": job_name}),
        spec=client.V1PodSpec(
            containers=[container],
            restart_policy="Never",
            volumes=[
                client.V1Volume(
                    name="dev-tun",
                    host_path=client.V1HostPathVolumeSource(
                        path="/dev/net/tun",
                        type="CharDevice"
                    )
                )
            ]
        )
    )
    job_spec = client.V1JobSpec(
        template=template,
        backoff_limit=0
    )
    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(name=job_name, namespace=NAMESPACE),
        spec=job_spec
    )
    try:
        batch_v1.create_namespaced_job(namespace=NAMESPACE, body=job)
        return {"job_name": job_name, "status": "created"}
    except client.rest.ApiException as e:
        raise HTTPException(status_code=500, detail=f"Failed to create job: {e}")

# ============ KUBERNETES JOB MANAGEMENT API ============

class CleanupOrphanedRequest(BaseModel):
    known_job_names: List[str]  # Danh sách job names từ controller database

@app.delete("/api/kubernetes/jobs/{job_name}")
def delete_kubernetes_job(job_name: str):
    """
    Xóa một Kubernetes job cụ thể và tất cả pods con.
    """
    return k8s_service.delete_job(job_name)

@app.post("/api/kubernetes/cleanup-orphaned")
def cleanup_orphaned_jobs(req: CleanupOrphanedRequest):
    """
    Tìm và xóa các Kubernetes jobs không có trong danh sách known_job_names.
    """
    return k8s_service.cleanup_orphaned_jobs(req.known_job_names)

@app.get("/api/kubernetes/jobs")
def list_kubernetes_jobs():
    """
    Lấy danh sách tất cả Kubernetes jobs trong namespace.
    """
    try:
        return k8s_service.list_jobs()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/kubernetes/jobs/{job_name}")
def get_kubernetes_job_status(job_name: str):
    """
    Lấy thông tin chi tiết của một Kubernetes job.
    """
    try:
        result = k8s_service.get_job_status(job_name)
        return result
    except Exception as e:
        if "not found" in str(e):
            raise HTTPException(status_code=404, detail=str(e))
        else:
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/kubernetes/pods")
def list_kubernetes_pods():
    """
    Lấy danh sách tất cả pods trong namespace.
    """
    try:
        return k8s_service.list_pods()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/kubernetes/cleanup-orphaned-pods")
def cleanup_orphaned_pods():
    """
    Tìm và xóa các pods không có job owner (orphaned pods).
    """
    return k8s_service.cleanup_orphaned_pods()
