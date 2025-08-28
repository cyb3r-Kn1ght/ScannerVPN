# app/services/workflow_service.py
import logging
from uuid import uuid4
import asyncio
from sqlalchemy.orm import Session
from fastapi import HTTPException
import httpx

from app import crud, models, schemas
from core.config import settings
from services.vpn_service import VPNService
from services.scan_submission_service import ScanSubmissionService

logger = logging.getLogger(__name__)

class WorkflowService:
    def __init__(self, db: Session):
        self.db = db
        self.vpn_service = VPNService()
        self.submission_service = ScanSubmissionService()

    async def _assign_vpn_to_workflow(self, workflow_req: schemas.workflow.WorkflowRequest) -> dict | None:
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

    async def create_and_dispatch_workflow(self, *, workflow_in: schemas.workflow.WorkflowRequest) -> dict:
        """Tạo và thực thi một workflow quét mới."""
        logger.info(f"Creating workflow for targets: {workflow_in.targets}")

        workflow_id = f"workflow-{uuid4().hex[:8]}"
        workflow_db = crud.crud_workflow.create_workflow(db=self.db, workflow_in=workflow_in, workflow_id=workflow_id)

        vpn_assignment = await self._assign_vpn_to_workflow(workflow_in)
        if vpn_assignment:
            crud.crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"vpn_assignment": vpn_assignment, "vpn_country": vpn_assignment.get('country')})
            logger.info(f"Assigned VPN {vpn_assignment.get('hostname')} to workflow {workflow_id}")

        sub_jobs = self._create_sub_jobs_in_db(workflow_db, workflow_in.steps, vpn_assignment)

        crud.crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"total_steps": len(sub_jobs)})

        successful_submissions, failed_submissions = self._submit_sub_jobs(sub_jobs)

        status = "running" if successful_submissions else "failed"
        crud.crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"status": status})

        return {
            "workflow_id": workflow_id, "status": status, "total_steps": len(sub_jobs),
            "successful_submissions": len(successful_submissions), "failed_submissions": len(failed_submissions),
            "vpn_assignment": vpn_assignment
        }

    def _create_sub_jobs_in_db(self, workflow_db: models.WorkflowJob, steps: list[schemas.WorkflowStep], vpn_assignment: dict | None) -> list[models.ScanJob]:
        """Tạo các bản ghi sub-job trong DB."""
        sub_jobs_to_create = []
        step_counter = 0

        for step in steps:
            step_counter += 1
            job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
            job = models.ScanJob(
                job_id=job_id, tool=step.tool_id, targets=workflow_db.targets,
                options=step.params, workflow_id=workflow_db.workflow_id, step_order=step_counter,
                vpn_assignment=vpn_assignment
            )
            sub_jobs_to_create.append(job)

        self.db.add_all(sub_jobs_to_create)
        self.db.commit()
        for job in sub_jobs_to_create: self.db.refresh(job)

        return sub_jobs_to_create

    def _submit_sub_jobs(self, sub_jobs: list[models.ScanJob]) -> tuple[list, list]:
        """Gửi các sub-job tới scanner node."""
        successful_submissions, failed_submissions = [], []

        for job in sub_jobs:
            try:
                scanner_response, _ = self.submission_service.submit_job(job)
                crud.crud_scan_job.update(self.db, db_obj=job, obj_in={"scanner_job_name": scanner_response.get("job_name"), "status": "running"})
                successful_submissions.append(job.job_id)
            except Exception as e:
                error_message = str(e)
                crud.crud_scan_job.update(self.db, db_obj=job, obj_in={"status": "failed", "error_message": error_message})
                failed_submissions.append({"job_id": job.job_id, "error": error_message})

        return successful_submissions, failed_submissions

    def get_status(self, workflow_id: str) -> dict:
        """Lấy trạng thái chi tiết của một workflow."""
        workflow = crud.crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud.crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)

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
        workflow = crud.crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud.crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        deleted_scanner_jobs = []

        for job in sub_jobs:
            if job.scanner_job_name:
                try:
                    resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{job.scanner_job_name}", timeout=10)
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "status_code": resp.status_code})
                except Exception as e:
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "error": str(e)})

            crud.crud_scan_job.remove_and_related_results(self.db, db_obj=job)

        crud.crud_workflow.remove(self.db, db_obj=workflow)

        logger.info(f"Deleted workflow {workflow_id} and all related resources.")
        return {"status": "deleted", "workflow_id": workflow_id, "deleted_scanner_jobs": deleted_scanner_jobs}