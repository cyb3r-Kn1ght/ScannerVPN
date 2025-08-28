# app/api/endpoints/workflows.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.schemas import workflow
from app import crud
from app.services.workflow_service import WorkflowService
from app.services.result_service import ResultService
from app.api.deps import get_workflow_service, get_result_service, get_db

router = APIRouter()

# Giữ nguyên endpoint gốc: POST /api/scan/workflow
@router.post("/api/scan/workflow", status_code=201, summary="Tạo và bắt đầu một workflow quét mới")
async def create_workflow(
        *,
        workflow_in: workflow.WorkflowRequest,
        workflow_service: WorkflowService = Depends(get_workflow_service)
):
    try:
        result = await workflow_service.create_and_dispatch_workflow(workflow_in=workflow_in)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating workflow: {str(e)}")

# Giữ nguyên endpoint gốc: GET /api/workflows/{workflow_id}
@router.get("/api/workflows/{workflow_id}", summary="Lấy trạng thái chi tiết của một workflow")
def get_workflow_details(
    workflow_id: str,
    workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.get_workflow_detail(workflow_id=workflow_id)

# Giữ nguyên endpoint gốc: GET /api/workflows
@router.get("/api/workflows", summary="Lấy danh sách các workflow")
def get_workflows_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.list_workflows(page=page, page_size=page_size)

# Giữ nguyên endpoint gốc: GET /api/workflows/{workflow_id}/summary
@router.get("/api/workflows/{workflow_id}/summary", summary="Lấy bản tóm tắt kết quả của một workflow")
def get_workflow_summary(
        workflow_id: str,
        result_service: ResultService = Depends(get_result_service)
):
    return result_service.get_workflow_summary(workflow_id)

# Giữ nguyên endpoint gốc: DELETE /api/workflows/{workflow_id}
@router.delete("/api/workflows/{workflow_id}", status_code=200, summary="Xóa một workflow và các tài nguyên liên quan")
def delete_workflow(
        workflow_id: str,
        workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.delete_workflow(workflow_id=workflow_id)