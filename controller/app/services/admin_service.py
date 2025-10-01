# app/services/admin_service.py
import logging
from sqlalchemy.orm import Session
from app.models import scan_result
from app.models import scan_job
from app.models import workflow_job

logger = logging.getLogger(__name__)

class AdminService:
    def __init__(self, db: Session):
        self.db = db

    def clear_all_data(self):
        """Xóa toàn bộ dữ liệu từ tất cả các bảng và xóa toàn bộ scanner jobs/pods trên scanner node."""
        logger.info("Clearing all database tables and scanner jobs on scanner node.")

        # Lấy danh sách tất cả scanner_job_name còn lại
        all_scan_jobs = self.db.query(scan_job.ScanJob).all()
        scanner_job_names = [job.scanner_job_name for job in all_scan_jobs if job.scanner_job_name]

        # Gọi API xóa từng scanner job trên scanner node
        import httpx
        from app.core.config import settings
        deleted_scanner_jobs = []
        for sjob in scanner_job_names:
            try:
                resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{sjob}", timeout=10)
                deleted_scanner_jobs.append({"scanner_job": sjob, "status_code": resp.status_code})
            except Exception as e:
                deleted_scanner_jobs.append({"scanner_job": sjob, "error": str(e)})

        workflow_count = self.db.query(workflow_job.WorkflowJob).count()
        scan_job_count = self.db.query(scan_job.ScanJob).count()
        scan_result_count = self.db.query(scan_result.ScanResult).count()

        self.db.query(scan_result.ScanResult).delete()
        self.db.query(scan_job.ScanJob).delete()
        self.db.query(workflow_job.WorkflowJob).delete()
        self.db.commit()

        return {
            "status": "success",
            "message": "All database tables and scanner jobs cleared successfully",
            "deleted_counts": { "workflows": workflow_count, "scan_jobs": scan_job_count, "scan_results": scan_result_count },
            "deleted_scanner_jobs": deleted_scanner_jobs
        }

    def clear_scan_results_only(self):
        """Xóa chỉ bảng scan_results."""
        result_count = self.db.query(scan_result.ScanResult).count()
        logger.info(f"Clearing scan_results table: {result_count} records")
        self.db.query(scan_result.ScanResult).delete()
        self.db.commit()
        return { "status": "success", "message": "Scan results table cleared successfully", "deleted_count": result_count }

    def clear_workflows_and_jobs(self):
        """Xóa workflows và scan_jobs."""
        workflow_count = self.db.query(workflow_job.WorkflowJob).count()
        scan_job_count = self.db.query(scan_job.ScanJob).count()
        logger.info(f"Clearing workflows and jobs: {workflow_count} workflows, {scan_job_count} scan jobs")
        self.db.query(scan_job.ScanJob).delete()
        self.db.query(workflow_job.WorkflowJob).delete()
        self.db.commit()
        return {
            "status": "success", "message": "Workflows and scan jobs cleared successfully",
            "deleted_counts": { "workflows": workflow_count, "scan_jobs": scan_job_count }
        }