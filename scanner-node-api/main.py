from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Extra
from typing import List, Dict, Any, Optional
import os
import time
import httpx
from kubernetes import client, config

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
    workflow_id: Optional[str] = None  # Workflow ID từ Controller

    class Config:
        extra = Extra.ignore  # ignore additional fields like scanner_node_url

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan", status_code=201)
def scan(req: ScanRequest):
    return _create_job(req)

@app.post("/api/scan/execute", status_code=201)
def execute_scan(req: ScanRequest):
    print(f"[DEBUG] Received payload: {req.dict()}")  # Debug line
    print(f"[DEBUG] VPN assignment: {req.vpn_assignment}")  # Debug VPN specifically
    return _create_job(req)


def _create_job(req: ScanRequest):
    import uuid
    job_name = f"{req.tool}-scan-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    
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
    
    # Thêm scan options nếu có
    if req.options:
        import json
        options_json = json.dumps(req.options)
        env_vars.append(client.V1EnvVar(name="SCAN_OPTIONS", value=options_json))
    
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
    
    # Thêm workflow_id nếu có
    if req.workflow_id:
        env_vars.append(client.V1EnvVar(name="WORKFLOW_ID", value=req.workflow_id))
        print(f"[*] Added workflow_id to job: {req.workflow_id}")
    
    container = client.V1Container(
        name=req.tool,
        image=f"{REGISTRY}/{req.tool}:latest",
        args=req.targets,
        env=env_vars,
        image_pull_policy="Never",
        security_context=client.V1SecurityContext(
            privileged=True,
            capabilities=client.V1Capabilities(
                add=["NET_ADMIN", "NET_RAW"]
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
        print(f"[ERROR] Failed to create job: {e}")
        if hasattr(e, 'body'):
            print(f"[ERROR] Exception body: {e.body}")
        print(f"[ERROR] Job spec: {job}")
        print(f"[ERROR] Env vars: {env_vars}")
        raise HTTPException(status_code=500, detail=f"Failed to create job: {e}")

# Xoá scanner job/pod theo job_id

@app.delete("/api/scanner_jobs/{job_id}")
def delete_scanner_job(job_id: str):
    try:
        # Xoá Job K8s (cả pod sẽ bị xoá theo)
        delete_opts = client.V1DeleteOptions(propagation_policy="Foreground")
        resp = batch_v1.delete_namespaced_job(
            name=job_id,
            namespace=NAMESPACE,
            body=delete_opts
        )
        print(f"[INFO] Deleted K8s job {job_id}: {resp}")
        return {"status": "deleted", "job_id": job_id}
    except client.rest.ApiException as e:
        print(f"[ERROR] Failed to delete job {job_id}: {e}")
        return {"status": "error", "job_id": job_id, "error": str(e)}
