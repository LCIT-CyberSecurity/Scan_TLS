from fastapi import APIRouter, Request

from tls_scan_app.database import database_is_ready

router = APIRouter(tags=["health"])


@router.get("/api/health/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/api/health/ready")
def ready(request: Request) -> dict:
    ok = database_is_ready(request.app.state.engine)
    return {"status": "ok" if ok else "degraded", "database": ok}
