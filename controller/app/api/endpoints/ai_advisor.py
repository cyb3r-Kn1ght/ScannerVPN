# app/api/endpoints/ai_advisor.py
import logging
import asyncio
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.ai_advisor_service import AIAdvisorService
from app.services.auto_workflow_service import AutoWorkflowService
from app.models.scan_result import ScanResult
from app.models.scan_job import ScanJob

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/api/ai/analyze-job/{job_id}", summary="Phân tích kết quả của một job bằng AI")
def analyze_job_with_ai(
    job_id: str,
    db: Session = Depends(get_db)
):
    """
    Lấy kết quả của một scan job đã hoàn thành, gửi đến AI để phân tích,
    và trả về các đề xuất hành động.
    """
    # 1. Lấy thông tin job
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Job has not been completed yet. Analysis is only available for completed jobs.")

    # 2. Lấy kết quả của job đó
    scan_results = db.query(ScanResult).filter(
        ScanResult.scan_metadata.op('->>')('job_id') == job_id
    ).all()

    if not scan_results:
        raise HTTPException(status_code=404, detail="No scan results found for this job.")

    # 3. Chuyển đổi kết quả sang dạng dict để service xử lý
    results_data = []
    for result in scan_results:
        results_data.append({
            "target": result.target,
            "open_ports": result.open_ports or [],
            "scan_metadata": result.scan_metadata or {}
        })
    
    # 4. Gọi AI Advisor Service để phân tích
    try:
        ai_service = AIAdvisorService()
        # Chỉ lấy target đầu tiên để phân tích, vì job đơn lẻ thường chỉ có 1 target chính
        target_to_analyze = job.targets[0] if job.targets else "Unknown"

        analysis = ai_service.analyze_scan_results(
            scan_results=results_data,
            current_tool=job.tool,
            target=target_to_analyze
        )
        
        if "error" in analysis:
             raise HTTPException(status_code=500, detail=f"AI analysis failed: {analysis['error']}")

        return analysis

    except Exception as e:
        logger.error(f"Failed during AI analysis for job {job_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error during AI analysis: {str(e)}")

@router.post("/api/ai/analyze", summary="Manually trigger AI analysis for a completed job")
def manual_ai_analysis(
    request_data: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    """
    Manually trigger AI analysis for a completed job
    Request body should contain: {"workflow_id": "...", "job_id": "..."}
    """
    workflow_id = request_data.get("workflow_id")
    job_id = request_data.get("job_id")
    
    if not workflow_id or not job_id:
        raise HTTPException(status_code=400, detail="Both workflow_id and job_id are required")
    
    # Verify job exists
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.workflow_id != workflow_id:
        raise HTTPException(status_code=400, detail="Job does not belong to specified workflow")
    
    try:
        auto_service = AutoWorkflowService(db)
        
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            auto_service.analyze_and_suggest_next_steps(workflow_id, job_id)
        )
        loop.close()
        
        return {
            "message": "AI analysis completed",
            "workflow_id": workflow_id,
            "job_id": job_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@router.get("/api/ai/analyze/{workflow_id}/{job_id}", summary="Get AI analysis for a job without triggering new workflow")
def get_ai_analysis(
    workflow_id: str,
    job_id: str,
    db: Session = Depends(get_db)
):
    """Get AI analysis for a specific job without creating new workflows"""
    
    # Verify job exists
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.workflow_id != workflow_id:
        raise HTTPException(status_code=400, detail="Job does not belong to specified workflow")
    
    # Get scan results for this job
    scan_results = db.query(ScanResult).filter(
        ScanResult.scan_metadata.op('->>')('job_id') == job_id
    ).all()
    
    if not scan_results:
        raise HTTPException(status_code=404, detail="No scan results found for this job")
    
    # Convert to dict format
    results_data = []
    for result in scan_results:
        results_data.append({
            "target": result.target,
            "open_ports": result.open_ports or [],
            "scan_metadata": result.scan_metadata or {}
        })
    
    try:
        ai_advisor = AIAdvisorService()
        
        # Analyze for each target
        analyses = []
        for target in job.targets:
            target_results = [r for r in results_data if r["target"] == target]
            if target_results:
                analysis = ai_advisor.analyze_scan_results(
                    target_results, job.tool, target
                )
                analyses.append({
                    "target": target,
                    "analysis": analysis
                })
        
        return {
            "workflow_id": workflow_id,
            "job_id": job_id,
            "tool": job.tool,
            "targets": job.targets,
            "analyses": analyses
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@router.post("/api/ai/toggle", summary="Enable/disable auto workflow")
def toggle_auto_workflow(
    request_data: Dict[str, bool] = Body(...)
):
    """Enable or disable auto workflow globally"""
    enabled = request_data.get("enabled", True)
    
    # Note: This is a simple toggle. In production, you might want to store this in database
    # or use a more sophisticated configuration management
    from app.core.config import settings
    settings.AUTO_WORKFLOW_ENABLED = enabled
    
    return {
        "message": f"Auto workflow {'enabled' if enabled else 'disabled'}",
        "auto_workflow_enabled": enabled
    }

@router.get("/api/ai/status", summary="Get AI advisor status")
def get_ai_status():
    """Get current status of AI advisor"""
    from app.core.config import settings
    
    try:
        ai_advisor = AIAdvisorService()
        # Test connection to RAG server
        import requests
        response = requests.get(f"{ai_advisor.rag_url}/health", timeout=5)
        rag_status = "connected" if response.status_code == 200 else "unreachable"
    except:
        rag_status = "unreachable"
    
    return {
        "auto_workflow_enabled": getattr(settings, 'AUTO_WORKFLOW_ENABLED', True),
        "rag_server_url": getattr(settings, 'RAG_SERVER_URL', 'Not configured'),
        "rag_server_status": rag_status,
        "max_auto_jobs": getattr(settings, 'MAX_AUTO_WORKFLOW_JOBS', 20)
    }