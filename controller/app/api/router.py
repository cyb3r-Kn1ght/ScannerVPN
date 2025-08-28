# app/api/router.py
from fastapi import APIRouter
from app.api.endpoints import (
    admin,
    scan_jobs,
    scan_results,
    utils,
    vpn,
    workflows,
)

api_router = APIRouter()
api_router.include_router(admin.router)
api_router.include_router(scan_jobs.router)
api_router.include_router(scan_results.router)
api_router.include_router(utils.router)
api_router.include_router(vpn.router)
api_router.include_router(workflows.router)
