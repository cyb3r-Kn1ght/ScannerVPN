# app/api/endpoints/workflows.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app import schemas, crud
from services.workflow_service import WorkflowService
from services.result_service import ResultService
from api.deps import get_workflow_service, get_result_service, get_db

router = APIRouter()

# Giữ nguyên endpoint gốc: POST /api/scan/workflow
@router.post("/api/scan/workflow", status_code=201, summary="Tạo và bắt đầu một workflow quét mới")
async def create_workflow(
        *,
        workflow_in: schemas.workflow.WorkflowRequest,
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
    return workflow_service.get_status(workflow_id=workflow_id)

# Giữ nguyên endpoint gốc: GET /api/workflows
@router.get("/api/workflows", summary="Lấy danh sách các workflow")
def get_workflows_list(
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        db: Session = Depends(get_db)
):
    # Logic này đơn giản, có thể gọi trực tiếp CRUD
    workflows = crud.crud_workflow.get_multi(db, skip=(page-1)*page_size, limit=page_size)
    # NOTE: Phần tính toán lại progress có thể thêm vào đây nếu cần
    return {"results": workflows}

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