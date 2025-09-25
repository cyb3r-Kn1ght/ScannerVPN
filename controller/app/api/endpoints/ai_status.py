from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse
from app.core.config import settings


# Biến toàn cục lưu trạng thái auto_workflow_enabled
AUTO_WORKFLOW_ENABLED = True

router = APIRouter()

@router.get("/api/ai/status", summary="Lấy trạng thái AI")
def get_ai_status():
    import requests
    RAG_SERVER_URL = settings.RAG_SERVER_URL
    rag_status = "offline"
    try:
        r = requests.post(f"{RAG_SERVER_URL}/rag_query", json={"query": "ping"}, timeout=3)
        if r.status_code == 200:
            rag_status = "online"
        else:
            rag_status = "error"
    except Exception:
        rag_status = "offline"

    global AUTO_WORKFLOW_ENABLED
    auto_workflow_enabled = AUTO_WORKFLOW_ENABLED
    max_auto_jobs = 20

    return {
        "rag_server_status": rag_status,
        "auto_workflow_enabled": auto_workflow_enabled,
        "max_auto_jobs": max_auto_jobs
    }

@router.post("/api/ai/toggle-auto-workflow", summary="Bật/Tắt Auto-Workflow")
async def toggle_auto_workflow(data: dict = Body(...)):
    global AUTO_WORKFLOW_ENABLED
    enabled = data.get("enabled")
    if isinstance(enabled, bool):
        AUTO_WORKFLOW_ENABLED = enabled
        # Ghi vào file .env
        try:
            env_path = settings.Config.env_file if hasattr(settings, 'Config') and hasattr(settings.Config, 'env_file') else ".env"
            # Đọc toàn bộ file .env
            lines = []
            found = False
            import os
            if os.path.exists(env_path):
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("AUTO_WORKFLOW_ENABLED="):
                            lines.append(f"AUTO_WORKFLOW_ENABLED={'true' if enabled else 'false'}\n")
                            found = True
                        else:
                            lines.append(line)
            if not found:
                lines.append(f"AUTO_WORKFLOW_ENABLED={'true' if enabled else 'false'}\n")
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception as e:
            return JSONResponse(status_code=500, content={"success": False, "error": f"Ghi file .env lỗi: {e}"})
        return {"success": True, "auto_workflow_enabled": AUTO_WORKFLOW_ENABLED}
    return JSONResponse(status_code=400, content={"success": False, "error": "Missing or invalid 'enabled' field"})
