# app/services/scan_job_service.py
import logging
from uuid import uuid4
from sqlalchemy.orm import Session
from fastapi import HTTPException
import httpx
import asyncio

from app import crud, models, schemas
from app.core.config import settings
from app.services.vpn_service import VPNService
from app.services.scan_submission_service import ScanSubmissionService

logger = logging.getLogger(__name__)

class ScanJobService:
    def __init__(self, db: Session):
        self.db = db
        self.vpn_service = VPNService()
        self.submission_service = ScanSubmissionService()

    async def _assign_vpn_to_job(self, job_in: schemas.scan_job.ScanJobRequest) -> dict | None:
        """Gán VPN cho một job quét đơn lẻ."""
        try:
            # Ưu tiên VPN do người dùng chỉ định
            if job_in.vpn_profile:
                all_vpns = await self.vpn_service.fetch_vpns()
                if not all_vpns: return None

                selected_vpn = next((v for v in all_vpns if v.get('filename') == job_in.vpn_profile), None)
                if not selected_vpn:
                    # Fallback nếu không tìm thấy profile
                    return {"filename": job_in.vpn_profile, "country": job_in.country or "Unknown"}

                vpn_assignment = selected_vpn.copy()
                if job_in.country: vpn_assignment['country'] = job_in.country
                return vpn_assignment

            # Nếu không chỉ định, không gán VPN (để scanner-node tự chọn)
            return None
        except Exception as e:
            logger.warning(f"Failed to assign VPN for single scan: {e}")
            # Fallback an toàn nếu có lỗi
            if job_in.vpn_profile:
                return {"filename": job_in.vpn_profile, "country": job_in.country or "Unknown"}
            return None

    async def create_and_dispatch_scan(self, *, job_in: schemas.scan_job.ScanJobRequest) -> models.ScanJob:
        """Tạo, gán VPN và gửi đi một job quét đơn lẻ."""
        job_id = f"scan-{job_in.tool}-{uuid4().hex[:6]}"

        db_job = models.ScanJob(
            job_id=job_id, tool=job_in.tool, targets=job_in.targets,
            options=job_in.options, status="submitted",
            vpn_profile=job_in.vpn_profile, vpn_country=job_in.country
        )

        vpn_assignment = await self._assign_vpn_to_job(job_in)
        db_job.vpn_assignment = vpn_assignment
        if vpn_assignment:
            db_job.vpn_hostname = vpn_assignment.get('hostname')
            if not db_job.vpn_country: db_job.vpn_country = vpn_assignment.get('country')

        crud.crud_scan_job.create(db=self.db, job_obj=db_job)

        try:
            scanner_response, _ = self.submission_service.submit_job(db_job)
            crud.crud_scan_job.update(self.db, db_obj=db_job, obj_in={
                "scanner_job_name": scanner_response.get("job_name"), "status": "running"
            })
        except Exception as e:
            crud.crud_scan_job.update(self.db, db_obj=db_job, obj_in={"status": "failed", "error_message": str(e)})
            raise HTTPException(status_code=500, detail=f"Failed to submit scan to scanner node: {e}")

        return db_job

    def delete_scan_job(self, job_id: str) -> dict:
        """Xóa một scan job ở cả controller và scanner node."""
        job_db = crud.crud_scan_job.get(db=self.db, job_id=job_id)
        if not job_db:
            raise HTTPException(status_code=404, detail="Scan job not found")

        scanner_job_name = job_db.scanner_job_name
        scanner_node_response = {}
        if scanner_job_name:
            try:
                resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{scanner_job_name}", timeout=10)
                scanner_node_response = {"status_code": resp.status_code, "body": resp.text}
            except Exception as e:
                scanner_node_response = {"error": str(e)}

        crud.crud_scan_job.remove_and_related_results(db=self.db, db_obj=job_db)

        return {"status": "deleted", "job_id": job_id, "scanner_job_name": scanner_job_name, "scanner_node_response": scanner_node_response}