# app/services/scan_submission_service.py
import httpx
import logging
from typing import Dict, Any, Tuple
from app.core.config import settings
from app.models.scan_job import ScanJob

logger = logging.getLogger(__name__)

class ScanSubmissionService:
    def submit_job(self, job: ScanJob) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        """
        Gửi một sub-job tới Scanner Node API và trả về phản hồi.
        """
        # VPN assignment được lấy từ bản ghi job trong DB
        vpn_assignment = job.vpn_assignment
        if not vpn_assignment and job.vpn_profile: # Fallback nếu chưa gán vpn
             vpn_assignment = {"filename": job.vpn_profile, "country": job.vpn_country}

        payload = {
            "tool": job.tool,
            "targets": job.targets,
            "options": job.options,
            "job_id": job.job_id,
            "controller_callback_url": settings.CONTROLLER_CALLBACK_URL,
            "vpn_assignment": vpn_assignment,
            "workflow_id": job.workflow_id
        }

        logger.info(f"Submitting job {job.job_id} to scanner node at {settings.SCANNER_NODE_URL}")

        try:
            response = httpx.post(
                f"{settings.SCANNER_NODE_URL}/api/scan/execute",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            logger.info(f"Successfully submitted job {job.job_id}. Response: {response.json()}")
            return response.json(), vpn_assignment
        except httpx.RequestError as e:
            logger.error(f"HTTP error submitting job {job.job_id}: {e}")
            raise Exception(f"Failed to connect to scanner node: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while submitting job {job.job_id}: {e}")
            raise