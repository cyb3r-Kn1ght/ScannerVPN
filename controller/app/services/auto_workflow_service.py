# app/services/auto_workflow_service.py
import logging
import asyncio
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.services.workflow_service import WorkflowService
from app.services.ai_advisor_service import AIAdvisorService
from app.schemas import workflow as workflow_schema
from app.models.scan_result import ScanResult
from app.models.scan_job import ScanJob
from app.core.config import settings

logger = logging.getLogger(__name__)

class AutoWorkflowService:
    def __init__(self, db: Session):
        self.db = db
        self.workflow_service = WorkflowService(db)
        self.ai_advisor = AIAdvisorService()
    
    async def analyze_and_suggest_next_steps(self, workflow_id: str, completed_job_id: str):
        """Phân tích kết quả và tự động tạo bước tiếp theo"""
        
        # Kiểm tra xem auto workflow có enabled không
        if not getattr(settings, 'AUTO_WORKFLOW_ENABLED', True):
            logger.info("Auto workflow is disabled")
            return
        
        try:
            # Lấy thông tin job vừa hoàn thành
            completed_job = self.db.query(ScanJob).filter(
                ScanJob.job_id == completed_job_id
            ).first()
            
            if not completed_job:
                logger.error(f"Job {completed_job_id} not found")
                return
            
            logger.info(f"Analyzing completed job: {completed_job.tool} for targets: {completed_job.targets}")
            
            # Lấy scan results của job này
            scan_results = self.db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id') == completed_job_id
            ).all()
            
            if not scan_results:
                logger.warning(f"No scan results found for job {completed_job_id}")
                return
            
            # Convert sang dict để dễ xử lý
            results_data = []
            for result in scan_results:
                results_data.append({
                    "target": result.target,
                    "open_ports": result.open_ports or [],
                    "scan_metadata": result.scan_metadata or {}
                })
            
            # Phân tích cho từng target
            for target in completed_job.targets:
                target_results = [r for r in results_data if r["target"] == target]
                if not target_results:
                    continue
                
                # Gọi AI để phân tích
                ai_analysis = self.ai_advisor.analyze_scan_results(
                    target_results, completed_job.tool, target
                )
                
                if "error" in ai_analysis:
                    logger.error(f"AI analysis failed for {target}: {ai_analysis['error']}")
                    continue
                
                logger.info(f"AI analysis for {target}: {ai_analysis.get('summary', '')}")
                
                # Parse suggestions và tạo workflow steps mới
                suggested_actions = ai_analysis.get("suggested_actions", [])
                
                if suggested_actions:
                    await self._create_follow_up_workflow(
                        workflow_id, 
                        suggested_actions, 
                        [target],  # Chỉ target này
                        ai_analysis,
                        completed_job
                    )
                else:
                    logger.info(f"No actionable suggestions from AI for {target}")
                    
        except Exception as e:
            logger.error(f"Error in auto workflow analysis: {e}", exc_info=True)
    
    async def _create_follow_up_workflow(
        self, 
        original_workflow_id: str, 
        suggestions: List[Dict], 
        targets: List[str],
        ai_analysis: Dict,
        parent_job: ScanJob
    ):
        """Tạo workflow mới dựa trên AI suggestions"""
        
        try:
            steps = []
            for suggestion in suggestions:
                if suggestion["type"] == "run_tool" and suggestion["confidence"] >= 0.5:
                    tool = suggestion["tool"]
                    
                    # Tạo params phù hợp cho từng tool
                    params = self._get_smart_params_for_tool(tool, ai_analysis, parent_job)
                    
                    steps.append(workflow_schema.WorkflowStep(
                        tool_id=tool,
                        params=params
                    ))
            
            if not steps:
                logger.info("No high-confidence suggestions to execute")
                return
            
            # Tạo workflow request với VPN info từ parent job
            workflow_request = workflow_schema.WorkflowRequest(
                targets=targets,
                steps=steps,
                description=f"AI auto-generated follow-up for {parent_job.tool} scan",
                vpn_profile=parent_job.vpn_profile,
                country=parent_job.vpn_country
            )
            
            # Tạo và dispatch workflow
            result = await self.workflow_service.create_and_dispatch_workflow(
                workflow_in=workflow_request
            )
            
            logger.info(f"Created auto follow-up workflow {result['workflow_id']} with {len(steps)} steps for targets: {targets}")
            
            # Log AI analysis summary
            logger.info(f"AI Analysis Summary: {ai_analysis.get('summary', 'N/A')}")
            
        except Exception as e:
            logger.error(f"Error creating follow-up workflow: {e}", exc_info=True)
    
    def _get_smart_params_for_tool(self, tool: str, ai_analysis: Dict, parent_job: ScanJob) -> Dict:
        """Trả về params thông minh cho từng tool dựa trên AI analysis và parent job"""
        
        base_params = self._get_default_params_for_tool(tool)
        
        # Customize params dựa trên AI analysis và parent job
        ai_response = ai_analysis.get("ai_analysis", "").lower()
        parent_tool = parent_job.tool
        
        if tool == "nuclei-scan":
            # Nếu parent là httpx và AI phát hiện specific technology
            if parent_tool == "httpx-scan" and any(tech in ai_response for tech in ["wordpress", "wp"]):
                base_params["tags"] = "wordpress,wp"
            elif "critical" in ai_response or "high" in ai_response:
                base_params["severity"] = "critical,high"
            else:
                base_params["severity"] = "medium,high,critical"
        
        elif tool == "sqlmap-scan":
            if parent_tool == "httpx-scan":
                # Thử các parameter phổ biến
                base_params.update({
                    "level": 2,
                    "risk": 2,
                    "batch": True,
                    "forms": True,
                    "crawl": 2
                })
        
        elif tool == "dirsearch-scan":
            if "php" in ai_response:
                base_params["extensions"] = "php,phps,php3,php4,php5,phtml"
            elif "asp" in ai_response:
                base_params["extensions"] = "asp,aspx,ashx,asmx"
            else:
                base_params["extensions"] = "php,asp,aspx,jsp,html,js,txt,bak"
            
            base_params["threads"] = 20
        
        elif tool == "wpscan-scan":
            base_params.update({
                "enumerate": ["p", "t", "u", "tt"],  # plugins, themes, users, timthumbs
                "detection_mode": "aggressive"
            })
        
        elif tool == "httpx-scan":
            base_params.update({
                "follow_redirects": True,
                "status_code": True,
                "tech_detect": True,
                "title": True
            })
        
        return base_params
    
    def _get_default_params_for_tool(self, tool: str) -> Dict:
        """Trả về params mặc định cho từng tool"""
        defaults = {
            "sqlmap-scan": {
                "batch": True, 
                "level": 1, 
                "risk": 1,
                "smart": True
            },
            "wpscan-scan": {
                "enumerate": ["p", "t", "u"],
                "detection_mode": "mixed"
            },
            "dirsearch-scan": {
                "extensions": "php,asp,aspx,jsp,html", 
                "threads": 10,
                "exclude_status": "404,403"
            },
            "nuclei-scan": {
                "severity": "medium,high,critical", 
                "rate_limit": 150,
                "bulk_size": 25
            },
            "httpx-scan": {
                "status_code": True,
                "title": True,
                "tech_detect": False
            }
        }
        return defaults.get(tool, {})
    
    def should_continue_workflow(self, workflow_id: str) -> bool:
        """Kiểm tra xem có nên tiếp tục auto workflow không"""
        
        # Đếm số lượng sub-jobs của workflow
        job_count = self.db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow_id
        ).count()
        
        # Giới hạn số lượng jobs để tránh vòng lặp vô tận
        max_jobs = getattr(settings, 'MAX_AUTO_WORKFLOW_JOBS', 20)
        
        if job_count >= max_jobs:
            logger.warning(f"Workflow {workflow_id} reached max jobs limit ({max_jobs})")
            return False
        
        return True
