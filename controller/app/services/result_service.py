# app/services/result_service.py
import json
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.crud import crud_scan_result, crud_scan_job, crud_workflow, crud_vpn_profile
from app.schemas import scan_result as scan_result_schema
from app.models.scan_result import ScanResult

class ResultService:
    def __init__(self, db: Session):
        self.db = db

    def process_incoming_result(self, result_in: scan_result_schema.ScanResultCreate):
        """Xử lý kết quả do scanner node gửi về."""
        # 1. Lưu kết quả vào DB
        db_result = crud_scan_result.create(db=self.db, result_in=result_in)

        # 2. Cập nhật trạng thái job thành 'completed'
        job_id = db_result.scan_metadata.get('job_id')
        if not job_id:
            return

        job_db = crud_scan_job.get(db=self.db, job_id=job_id)
        if not job_db:
            return

        crud_scan_job.update(self.db, db_obj=job_db, obj_in={"status": "completed"})

        # 3. Cập nhật tiến trình của workflow (nếu có)
        if job_db.workflow_id:
            self._update_workflow_progress(job_db.workflow_id)

    def _update_workflow_progress(self, workflow_id: str):
        """Cập nhật trạng thái và tiến trình của workflow."""
        workflow_db = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow_db:
            return

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        completed = sum(1 for job in sub_jobs if job.status == "completed")
        failed = sum(1 for job in sub_jobs if job.status == "failed")

        update_data = {"completed_steps": completed, "failed_steps": failed}

        if (completed + failed) >= workflow_db.total_steps:
            status = "completed" if failed == 0 else "partially_failed"
            update_data["status"] = status

        crud_workflow.update(self.db, db_obj=workflow_db, obj_in=update_data)

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