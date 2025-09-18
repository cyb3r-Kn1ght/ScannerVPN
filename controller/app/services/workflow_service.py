# app/services/workflow_service.py
import logging
from uuid import uuid4
import asyncio
from sqlalchemy.orm import Session
from fastapi import HTTPException
import httpx

from app.crud import crud_workflow, crud_scan_job
from app.schemas import workflow as workflow_schema, scan_job as scan_job_schema
from app.models.workflow_job import WorkflowJob
from app.models.scan_job import ScanJob
from app.core.config import settings
from app.services.vpn_service import VPNService
from app.services.scan_submission_service import ScanSubmissionService

logger = logging.getLogger(__name__)

class WorkflowService:
    def get_workflow_status(self, workflow_id: str):
        db: Session = self.db
        workflow = db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        # Get sub-jobs
        sub_jobs = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow_id
        ).order_by(ScanJob.step_order).all()

        sub_job_list = []
        for job in sub_jobs:
            job_dict = {
                "job_id": job.job_id,
                "tool": job.tool,
                "status": job.status,
                "step_order": job.step_order
            }
            if getattr(job, "error_message", None):
                job_dict["error_message"] = job.error_message
            sub_job_list.append(job_dict)

        # Progress calculation
        completed = sum(1 for job in sub_jobs if job.status == "completed")
        failed = sum(1 for job in sub_jobs if job.status == "failed")
        total = getattr(workflow, "total_steps", None) or len(sub_jobs)
        percentage = ((completed + failed) / total * 100) if total > 0 else 0

        # Compose workflow info
        workflow_info = {
            "workflow_id": workflow.workflow_id,
            "status": workflow.status,
            "updated_at": getattr(workflow, "updated_at", None) or getattr(workflow, "timestamp", None),
            "created_at": getattr(workflow, "created_at", None) or getattr(workflow, "timestamp", None),
            "targets": getattr(workflow, "targets", []),
            "vpn": getattr(workflow, "vpn_country", None) or getattr(workflow, "vpn_profile", None)
        }

        return {
            "workflow": workflow_info,
            "sub_jobs": sub_job_list,
            "progress": {
                "completed": completed,
                "total": total,
                "failed": failed,
                "percentage": percentage
            }
        }

    def get_workflow_detail(self, workflow_id: str) -> dict:
        """Lấy chi tiết workflow, sub-jobs, tổng hợp kết quả từng tool (giống code cũ)."""
        db = self.db
        import json
        workflow = db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        # Tính lại completed_steps, failed_steps, status cho workflow này
        completed = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow.workflow_id,
            ScanJob.status == "completed"
        ).count()
        failed = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow.workflow_id,
            ScanJob.status == "failed"
        ).count()
        workflow.completed_steps = completed
        workflow.failed_steps = failed
        if completed + failed >= (workflow.total_steps or 0):
            if failed == 0:
                workflow.status = "completed"
            else:
                workflow.status = "partially_failed"
        elif completed + failed == 0:
            workflow.status = "pending"
        else:
            workflow.status = "running"
        db.commit()

        # Get sub-jobs
        sub_jobs = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow_id
        ).order_by(ScanJob.step_order).all()

        # Lấy kết quả từng sub-job (ScanResult)
        job_ids = [job.job_id for job in sub_jobs]
        results_by_job = {}
        if job_ids:
            from app.models.scan_result import ScanResult
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
            ).all()
            for r in scan_results:
                meta = r.scan_metadata or {}
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                job_id = meta.get('job_id')
                if job_id not in results_by_job:
                    results_by_job[job_id] = []
                # Gắn lại scan_metadata đã parse cho flatten
                r.scan_metadata = meta
                results_by_job[job_id].append(r)

        def nuclei_flatten(find):
            info = find.get('info', {}) or {}
            out = {
                "template": find.get("template"),
                "template-id": find.get("template-id"),
                "template-url": find.get("template-url"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "tags": info.get("tags"),
                "matched_at": find.get("matched-at"),
                "type": find.get("type"),
                "host": find.get("host"),
                "ip": find.get("ip"),
                "port": find.get("port"),
                "timestamp": find.get("timestamp"),
            }
            extra = {}
            for k, v in find.items():
                if k not in ("template", "template-id", "template-url", "type", "host", "ip", "port", "timestamp", "matched-at", "matcher-status", "info"):
                    extra[k] = v
            for k, v in info.items():
                if k not in ("name", "severity", "tags"):
                    extra[k] = v
            if extra:
                out["extra_fields"] = extra
            return out

        def portscan_flatten(r):
            return [
                {"ip": r.target, "port": p.get("port"), "service": p.get("service"), "protocol": p.get("protocol"), "version": p.get("version", "")}
                for p in (r.open_ports or [])
            ]

        def dns_flatten(r):
            return {"target": r.target, "resolved_ips": r.resolved_ips}

        def httpx_flatten(r):
            meta = r.scan_metadata or {}
            if "httpx_results" in meta:
                return meta["httpx_results"]
            if "http_endpoints" in meta:
                return meta["http_endpoints"]
            if "http_metadata" in meta and isinstance(meta["http_metadata"], dict):
                return [meta["http_metadata"]]
            return []

        def dirsearch_flatten(r):
            meta = r.scan_metadata or {}
            return meta.get("dirsearch_results") or []

        def wpscan_flatten(r):
            meta = r.scan_metadata or {}
            return meta.get("wpscan_results") or []

        def sqlmap_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ sqlmap_scan.py được lưu trong 'sqlmap_results'
            return meta.get("sqlmap_results") or []
        
        def bruteforce_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ bf_runner.py được lưu trong key 'findings'
            return meta.get("findings") or []

        def ffuf_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ ffuf_entry.py
            if meta.get("fuzz_mode") == "param":
                return meta.get("results") or meta.get("candidates") or []
            else:
                return meta.get("results") or meta.get("targets") or []

        tool_result_map = {
            "nuclei-scan": lambda r: [nuclei_flatten(f) for f in (r.scan_metadata.get("nuclei_results") or [])],
            "port-scan": portscan_flatten,
            "dns-lookup": lambda r: [dns_flatten(r)],
            "httpx-scan": httpx_flatten,
            "dirsearch-scan": dirsearch_flatten,
            "wpscan-scan": wpscan_flatten,
            "sqlmap-scan": sqlmap_flatten,
            "bruteforce-scan": bruteforce_flatten,
            "ffuf-entry": ffuf_flatten
        }

        sub_job_details = []
        for job in sub_jobs:
            job_id = job.job_id
            tool = job.tool
            job_results = results_by_job.get(job_id, [])
            results = []
            if tool in tool_result_map:
                for r in job_results:
                    results.extend(tool_result_map[tool](r))
            else:
                for r in job_results:
                    results.append(r.scan_metadata)

            job_detail = {
                "job_id": job_id,
                "tool": tool,
                "status": job.status,
                "step_order": job.step_order,
                "error_message": job.error_message,
                "results": results,
            }
            sub_job_details.append(job_detail)

        total = workflow.total_steps or 0
        percentage = (completed / total * 100) if total > 0 else 0
        return {
            "workflow": workflow,
            "sub_jobs": sub_job_details,
            "progress": {
                "completed": completed,
                "total": total,
                "failed": failed,
                "percentage": percentage
            }
        }
    def __init__(self, db: Session):
        self.db = db
        self.vpn_service = VPNService()
        self.submission_service = ScanSubmissionService()

    async def _assign_vpn_to_workflow(self, workflow_req: workflow_schema.WorkflowRequest) -> dict | None:
        """Gán VPN cho toàn bộ workflow."""
        try:
            all_vpns = await self.vpn_service.fetch_vpns()
            if not all_vpns: return None

            if workflow_req.vpn_profile:
                selected_vpn = next((v for v in all_vpns if v.get('filename') == workflow_req.vpn_profile), None)
                if not selected_vpn: return None
                vpn_assignment = selected_vpn.copy()
                if workflow_req.country: vpn_assignment['country'] = workflow_req.country
                return vpn_assignment

            if workflow_req.country:
                categorized = await self.vpn_service.categorize_vpns_by_country(all_vpns)
                vpns_in_country = categorized.get(workflow_req.country.upper())
                return self.vpn_service.get_random_vpn(vpns_in_country) if vpns_in_country else None

            return self.vpn_service.get_random_vpn(all_vpns)
        except Exception as e:
            logger.warning(f"Failed to assign VPN for workflow: {e}")
            return None

    async def create_and_dispatch_workflow(self, *, workflow_in: workflow_schema.WorkflowRequest) -> dict:
        """Tạo và thực thi một workflow quét mới."""
        logger.info(f"Creating workflow for targets: {workflow_in.targets}")

        workflow_id = f"workflow-{uuid4().hex[:8]}"
        workflow_db = crud_workflow.create_workflow(db=self.db, workflow_in=workflow_in, workflow_id=workflow_id)

        vpn_assignment = await self._assign_vpn_to_workflow(workflow_in)
        if vpn_assignment:
            crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"vpn_assignment": vpn_assignment, "vpn_country": vpn_assignment.get('country')})
            logger.info(f"Assigned VPN {vpn_assignment.get('hostname')} to workflow {workflow_id}")

        sub_jobs = self._create_sub_jobs_in_db(workflow_db, workflow_in.steps, vpn_assignment)
        crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"total_steps": len(sub_jobs)})

        # Track detailed job submission results
        successful_submissions, failed_submissions = [], []
        sub_jobs_details = []
        errors = []
        for job in sub_jobs:
            try:
                scanner_response, _ = self.submission_service.submit_job(job)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"scanner_job_name": scanner_response.get("job_name"), "status": "running"})
                successful_submissions.append(job)
                sub_jobs_details.append({
                    "job_id": job.job_id,
                    "tool": job.tool,
                    "targets": job.targets,
                    "scanner_job": scanner_response.get("job_name")
                })
            except Exception as e:
                error_message = str(e)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"status": "failed", "error_message": error_message})
                failed_submissions.append(job)
                errors.append({
                    "job_id": job.job_id,
                    "tool": job.tool,
                    "targets": job.targets,
                    "error": error_message
                })

        status = "running" if successful_submissions else "failed"
        crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"status": status})

        # Format vpn_assignment for response (country, hostname only)
        vpn_assignment_resp = None
        if vpn_assignment:
            vpn_assignment_resp = {
                "country": vpn_assignment.get("country"),
                "hostname": vpn_assignment.get("hostname")
            }

        return {
            "workflow_id": workflow_id,
            "status": status,
            "strategy": getattr(workflow_in, "strategy", None),
            "total_steps": len(sub_jobs),
            "total_targets": len(getattr(workflow_in, "targets", []) or []),
            "total_tools": len(getattr(workflow_in, "steps", []) or []),
            "successful_submissions": len(successful_submissions),
            "failed_submissions": len(failed_submissions),
            "sub_jobs": sub_jobs_details,
            "errors": errors,
            "vpn_assignment": vpn_assignment_resp
        }

    def _create_sub_jobs_in_db(self, workflow_db: WorkflowJob, steps: list[workflow_schema.WorkflowStep], vpn_assignment: dict | None) -> list[ScanJob]:
        """Tạo các bản ghi sub-job trong DB, hỗ trợ chia nhỏ cho port-scan và xoay VPN profile."""
        import os
        from app.utils.port_utils import parse_nmap_top_ports, parse_ports_all, parse_ports_custom, split_ports
        sub_jobs_to_create = []
        step_counter = 0

        try:
            for i, step in enumerate(steps):
                # --- Custom logic for port-scan sharding ---
                if step.tool_id == "port-scan":
                    params = step.params.copy() if step.params else {}
                    scanner_count = params.get("scanner_count")
                    vpn_profiles = params.get("vpn_profile")
                    port_option = params.get("ports")
                    if isinstance(vpn_profiles, list) and scanner_count and int(scanner_count) > 1:
                        base_dir = os.path.dirname(os.path.abspath(__file__))
                        if port_option == "top-1000":
                            port_list = parse_nmap_top_ports(os.path.join(base_dir, "../../data/nmap-ports-top1000.txt"))
                        elif port_option == "all":
                            port_list = list(range(1, 65536))
                        else:
                            port_list = parse_ports_custom(port_option)
                        port_chunks = split_ports(port_list, int(scanner_count))
                        def chunk_to_range(chunk):
                            if not chunk:
                                return ""
                            if chunk == list(range(chunk[0], chunk[-1]+1)):
                                return f"{chunk[0]}-{chunk[-1]}"
                            else:
                                return ",".join(str(p) for p in chunk)
                        for idx, chunk in enumerate(port_chunks):
                            if not chunk:
                                continue
                            step_counter += 1
                            job_id = f"scan-port-scan-{uuid4().hex[:6]}"
                            chunk_params = params.copy()
                            chunk_params["ports"] = chunk_to_range(chunk)
                            chunk_vpn = vpn_profiles[idx] if idx < len(vpn_profiles) else None
                            job_obj = ScanJob(
                                job_id=job_id,
                                tool=step.tool_id,
                                targets=workflow_db.targets,
                                options=chunk_params,
                                workflow_id=workflow_db.workflow_id,
                                step_order=step_counter,
                                vpn_profile=chunk_vpn,
                                vpn_country=getattr(workflow_db, "vpn_country", None),
                                vpn_assignment=None
                            )
                            job = crud_scan_job.create(self.db, job_obj=job_obj)
                            sub_jobs_to_create.append(job)
                            logger.info(f"Created port-scan sub-job {job_id} chunk {idx+1}/{scanner_count} with VPN {chunk_vpn} ports {chunk_params['ports']}" )
                        continue
                if step.tool_id == "nuclei-scan":
                    params = step.params.copy() if step.params else {}
                    distributed = params.get("distributed-scanning", False)
                    if str(distributed).lower() == "true":
                        templates = params.get("templates", [])
                        severity = params.get("severity", [])
                        if not templates or not severity:
                            pass
                        else:
                            from app.services.vpn_service import VPNService
                            vpn_service = VPNService()
                            available_vpns = vpn_service.get_available_vpn_profiles()
                            vpn_idx = 0
                            for t in templates:
                                for s in severity:
                                    step_counter += 1
                                    job_id = f"scan-nuclei-scan-{uuid4().hex[:6]}"
                                    job_params = {k: v for k, v in params.items() if k not in ["templates", "severity", "distributed-scanning"]}
                                    job_params["templates"] = [t]
                                    job_params["severity"] = [s]
                                    job_params["distributed-scanning"] = True
                                    if available_vpns and vpn_idx < len(available_vpns):
                                        job_vpn = available_vpns[vpn_idx]
                                        vpn_idx += 1
                                    else:
                                        job_vpn = available_vpns[vpn_idx % len(available_vpns)] if available_vpns else None
                                    import json
                                    job_obj = ScanJob(
                                        job_id=job_id,
                                        tool=step.tool_id,
                                        targets=workflow_db.targets,
                                        options=job_params,
                                        workflow_id=workflow_db.workflow_id,
                                        step_order=step_counter,
                                        vpn_profile=json.dumps(job_vpn) if isinstance(job_vpn, dict) else job_vpn,
                                        vpn_country=getattr(workflow_db, "vpn_country", None),
                                        vpn_assignment=None
                                    )
                                    job = crud_scan_job.create(self.db, job_obj=job_obj)
                                    sub_jobs_to_create.append(job)
                                    logger.info(f"Created nuclei-scan sub-job {job_id} template {t} severity {s} VPN {job_vpn}")
                            continue
                step_counter += 1
                job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                step_params = step.params.copy() if step.params else {}
                if step.tool_id == "dirsearch-scan" and isinstance(step_params, dict):
                    if "threads" in step_params:
                        try:
                            step_params["threads"] = int(step_params["threads"])
                        except Exception:
                            step_params["threads"] = 10
                    if "recursive" in step_params:
                        if step.tool_id == "dirsearch-scan":
                            params = step.params.copy() if step.params else {}
                            scanner_count = params.get("scanner_count")
                            try:
                                scanner_count_int = int(scanner_count) if scanner_count is not None else None
                            except Exception:
                                scanner_count_int = None
                            if scanner_count_int is None or scanner_count_int < 1:
                                raise ValueError("Invalid or missing 'scanner_count' in dirsearch-scan step params. Must be a positive integer.")
                            if scanner_count_int > 1:
                                WORDLIST_LINE_COUNT = 9677
                                lines_per_scanner = WORDLIST_LINE_COUNT // scanner_count_int
                                remainder = WORDLIST_LINE_COUNT % scanner_count_int
                                start_line = 0
                                from app.services.vpn_service import VPNService
                                vpn_service = VPNService()
                                available_vpns = vpn_service.get_available_vpn_profiles()
                                for idx in range(scanner_count_int):
                                    end_line = start_line + lines_per_scanner - 1
                                    if idx < remainder:
                                        end_line += 1
                                    step_counter += 1
                                    job_id = f"scan-dirsearch-scan-{uuid4().hex[:6]}"
                                    chunk_params = params.copy()
                                    chunk_params["wordlist_start"] = start_line
                                    chunk_params["wordlist_end"] = end_line
                                    if available_vpns and idx < len(available_vpns):
                                        chunk_vpn = available_vpns[idx]
                                    elif available_vpns:
                                        chunk_vpn = available_vpns[idx % len(available_vpns)]
                                    else:
                                        chunk_vpn = None
                                    import json
                                    job_obj = ScanJob(
                                        job_id=job_id,
                                        tool=step.tool_id,
                                        targets=workflow_db.targets,
                                        options=chunk_params,
                                        workflow_id=workflow_db.workflow_id,
                                        step_order=step_counter,
                                        vpn_profile=json.dumps(chunk_vpn) if isinstance(chunk_vpn, dict) else chunk_vpn,
                                        vpn_country=getattr(workflow_db, "vpn_country", None),
                                        vpn_assignment=None
                                    )
                                    job = crud_scan_job.create(self.db, job_obj=job_obj)
                                    sub_jobs_to_create.append(job)
                                    logger.info(f"Created dirsearch-scan sub-job {job_id} chunk {idx+1}/{scanner_count_int} with VPN {chunk_vpn} lines {start_line}-{end_line}")
                                    start_line = end_line + 1
                                continue
                        import json
                        step_counter += 1
                        job_id = f"scan-dirsearch-scan-{uuid4().hex[:6]}"
                        job_obj = ScanJob(
                            job_id=job_id,
                            tool=step.tool_id,
                            targets=workflow_db.targets,
                            options=params,
                            workflow_id=workflow_db.workflow_id,
                            step_order=step_counter,
                            vpn_profile=json.dumps(getattr(workflow_db, "vpn_profile", None)) if isinstance(getattr(workflow_db, "vpn_profile", None), dict) else getattr(workflow_db, "vpn_profile", None),
                            vpn_country=getattr(workflow_db, "vpn_country", None),
                            vpn_assignment=json.dumps(vpn_assignment) if isinstance(vpn_assignment, dict) else vpn_assignment
                        )
                        job = crud_scan_job.create(self.db, job_obj=job_obj)
                        sub_jobs_to_create.append(job)
                        logger.info(f"Created dirsearch-scan single job {job_id} with VPN {getattr(workflow_db, 'vpn_profile', None)}")
                        continue
                step_counter += 1
                job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                step_params = step.params.copy() if step.params else {}
                import json
                job_obj = ScanJob(
                    job_id=job_id,
                    tool=step.tool_id,
                    targets=workflow_db.targets,
                    options=step_params,
                    workflow_id=workflow_db.workflow_id,
                    step_order=step_counter,
                    vpn_profile=json.dumps(getattr(workflow_db, "vpn_profile", None)) if isinstance(getattr(workflow_db, "vpn_profile", None), dict) else getattr(workflow_db, "vpn_profile", None),
                    vpn_country=getattr(workflow_db, "vpn_country", None),
                    vpn_assignment=json.dumps(vpn_assignment) if isinstance(vpn_assignment, dict) else vpn_assignment
                )
                job = crud_scan_job.create(self.db, job_obj=job_obj)
                sub_jobs_to_create.append(job)
                logger.info(f"Created generic sub-job {job_id} for tool {step.tool_id} with VPN {getattr(workflow_db, 'vpn_profile', None)}")
            return sub_jobs_to_create
        except Exception as e:
            logger.error(f"Exception in _create_sub_jobs_in_db: {e}")
            return []
    def _submit_sub_jobs(self, sub_jobs: list[ScanJob]) -> tuple[list, list]:
        """Gửi các sub-job tới scanner node."""
        successful_submissions, failed_submissions = [], []
        for job in sub_jobs:
            try:
                scanner_response, _ = self.submission_service.submit_job(job)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"scanner_job_name": scanner_response.get("job_name"), "status": "running"})
                successful_submissions.append(job.job_id)
            except Exception as e:
                error_message = str(e)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"status": "failed", "error_message": error_message})
                failed_submissions.append({"job_id": job.job_id, "error": error_message})
        return successful_submissions, failed_submissions

    def get_status(self, workflow_id: str) -> dict:
        """Lấy trạng thái chi tiết của một workflow."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)

        completed = sum(1 for job in sub_jobs if job.status == "completed")
        failed = sum(1 for job in sub_jobs if job.status == "failed")
        total = workflow.total_steps or len(sub_jobs)
        percentage = ((completed + failed) / total * 100) if total > 0 else 0

        sub_job_list = [
            {"job_id": job.job_id, "tool": job.tool, "status": job.status, "step_order": job.step_order, "error_message": job.error_message}
            for job in sub_jobs
        ]

        workflow_info = {
            "workflow_id": workflow.workflow_id, "status": workflow.status, "updated_at": workflow.updated_at,
            "created_at": workflow.created_at, "targets": workflow.targets,
            "vpn": workflow.vpn_country or workflow.vpn_profile
        }

        return {
            "workflow": workflow_info,
            "sub_jobs": sub_job_list,
            "progress": {"completed": completed, "total": total, "failed": failed, "percentage": percentage}
        }

    def delete_workflow(self, workflow_id: str) -> dict:
        """Xóa workflow và tất cả các tài nguyên liên quan."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        deleted_scanner_jobs = []

        for job in sub_jobs:
            if job.scanner_job_name:
                try:
                    resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{job.scanner_job_name}", timeout=10)
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "status_code": resp.status_code})
                except Exception as e:
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "error": str(e)})

            crud_scan_job.remove_and_related_results(self.db, db_obj=job)

        crud_workflow.remove(self.db, db_obj=workflow)

        logger.info(f"Deleted workflow {workflow_id} and all related resources.")
        return {"status": "deleted", "workflow_id": workflow_id, "deleted_scanner_jobs": deleted_scanner_jobs}
    
    def list_workflows(self, page: int = 1, page_size: int = 10) -> dict:
        """Lấy danh sách workflow, tính lại progress, trả về đúng format dashboard."""
        db = self.db
        from app import schemas as app_schemas
        query = db.query(WorkflowJob).order_by(WorkflowJob.id.desc())
        total = query.count()
        workflows = query.offset((page - 1) * page_size).limit(page_size).all()

        for wf in workflows:
            completed = db.query(ScanJob).filter(
                ScanJob.workflow_id == wf.workflow_id,
                ScanJob.status == "completed"
            ).count()
            failed = db.query(ScanJob).filter(
                ScanJob.workflow_id == wf.workflow_id,
                ScanJob.status == "failed"
            ).count()
            wf.completed_steps = completed
            wf.failed_steps = failed
            if (completed + failed) >= (wf.total_steps or 0):
                if failed == 0:
                    wf.status = "completed"
                else:
                    wf.status = "partially_failed"
            elif (completed + failed) == 0:
                wf.status = "pending"
            else:
                wf.status = "running"
        db.commit()

        def serialize_workflow(wf):
            try:
                return app_schemas.workflow.WorkflowJob.from_orm(wf).dict()
            except Exception:
                return {k: v for k, v in wf.__dict__.items() if not k.startswith('_')}

        return {
            "pagination": {
                "total_items": total,
                "total_pages": (total + page_size - 1) // page_size,
                "current_page": page,
                "page_size": page_size,
                "has_next": (page * page_size) < total,
                "has_previous": page > 1
            },
            "results": [serialize_workflow(wf) for wf in workflows]
        }