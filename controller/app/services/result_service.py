# app/services/result_service.py
import json
import logging
logging.basicConfig(level=logging.INFO)
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.crud import crud_scan_result, crud_scan_job, crud_workflow, crud_vpn_profile
from app.schemas import scan_result as scan_result_schema
from app.models.scan_result import ScanResult

class ResultService:
    def __init__(self, db: Session):
        self.db = db

    def process_incoming_result(self, result_in: scan_result_schema.ScanResultCreate):
        """Xử lý kết quả do scanner node gửi về, giữ nguyên logic cũ (merge các trường đặc biệt vào scan_metadata, lưu DB, cập nhật job/workflow)."""
        scan_metadata = dict(result_in.scan_metadata) if result_in.scan_metadata else {}
        for k in ["httpx_results", "http_endpoints", "http_metadata"]:
            v = getattr(result_in, k, None)
            if v is not None:
                scan_metadata[k] = v

        db_obj = ScanResult(
            target=result_in.target,
            resolved_ips=result_in.resolved_ips,
            open_ports=result_in.open_ports,
            scan_metadata=scan_metadata,
            workflow_id=result_in.workflow_id
        )
        self.db.add(db_obj)

        job_id = scan_metadata.get('job_id')
        if job_id:
            from app.models.scan_job import ScanJob
            job = self.db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
            if job:
                job.status = "completed"
                if job.workflow_id:
                    crud_workflow.update_workflow_progress(self.db, job.workflow_id, logger=logging.getLogger(__name__))

        self.db.commit()

    # Đã chuyển logic update workflow progress sang crud_workflow.update_workflow_progress

    def get_paginated_results(self, page: int, page_size: int, workflow_id: str | None = None, job_id: str | None = None):
        """Lấy danh sách kết quả có phân trang."""
        return crud_scan_result.get_multi_paginated(
            db=self.db, page=page, page_size=page_size, workflow_id=workflow_id, job_id=job_id
        )

    def get_workflow_summary(self, workflow_id: str):
        """Tổng hợp kết quả của toàn bộ workflow."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        job_ids = [job.job_id for job in sub_jobs]

        scan_results = self.db.query(ScanResult).filter(
            ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
        ).all()

        summary_by_target = {}
        for r in scan_results:
            tgt = r.target
            if tgt not in summary_by_target:
                summary_by_target[tgt] = {
                    "target": tgt, "dns_records": [], "open_ports": [], "web_technologies": set(), "vulnerabilities": []
                }
            if r.resolved_ips:
                summary_by_target[tgt]["dns_records"].extend(r.resolved_ips)
            if r.open_ports:
                for p in r.open_ports:
                    summary_by_target[tgt]["open_ports"].append({ "port": p.get("port"), "protocol": p.get("protocol"), "service": p.get("service") })

            meta = r.scan_metadata or {}
            if isinstance(meta, str):
                try: meta = json.loads(meta)
                except Exception: meta = {}

            if "httpx_results" in meta:
                for ep in meta["httpx_results"]:
                    ws = ep.get("webserver")
                    if ws: summary_by_target[tgt]["web_technologies"].add(ws)
            if "nuclei_results" in meta:
                for finding in meta["nuclei_results"]:
                    info = finding.get("info", {})
                    name = finding.get("name") or info.get("name")
                    sev = finding.get("severity") or info.get("severity")
                    if name and sev: summary_by_target[tgt]["vulnerabilities"].append({"name": name, "severity": sev})

        for tgt in summary_by_target:
            summary_by_target[tgt]["web_technologies"] = list(summary_by_target[tgt]["web_technologies"])

        return {"summary": list(summary_by_target.values())}