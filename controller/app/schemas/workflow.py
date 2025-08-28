# app/schemas/workflow.py
from pydantic import BaseModel
from typing import List, Any, Dict, Optional
from datetime import datetime

class WorkflowStep(BaseModel):
    tool_id: str
    params: Dict[str, Any] = {}

class WorkflowRequest(BaseModel):
    targets: List[str]
    strategy: str = "wide"
    steps: List[WorkflowStep]
    vpn_profile: Optional[str] = None
    country: Optional[str] = None

class WorkflowJob(BaseModel):
    id: int
    workflow_id: str
    targets: List[str]
    strategy: str
    status: str
    vpn_profile: Optional[str] = None
    vpn_country: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None
    total_steps: int
    completed_steps: int
    failed_steps: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class WorkflowStepResult(BaseModel):
    step_order: int
    tool_id: str
    job_id: str
    status: str
    params: Dict[str, Any]

class WorkflowDetail(BaseModel):
    workflow: WorkflowJob
    sub_jobs: List[WorkflowStepResult]