"""
SysOps Portal — FastAPI application
===================================

Chạy dev (SQLite, xác thực dev):
    pip install -r requirements.txt
    python seed_demo.py
    uvicorn app:app --reload --port 8080

Chạy production (PostgreSQL, xác thực thật):
    alembic upgrade head
    docker compose up -d

API docs: http://localhost:8080/docs
UI:       http://localhost:8080/
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text

import auth
from auth import ADMIN, Principal, require
from db import IS_SQLITE, engine, get_db
from models import Base
from routers import admin, auth_routes, drift, inventory, ipam, reports, ui

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)
log = logging.getLogger("sysops")

# Tự tạo bảng chỉ dành cho dev/test. Ở production dùng `alembic upgrade head`:
# create_all không bao giờ nâng cấp được schema đã có dữ liệu.
AUTO_CREATE_TABLES = (
    os.getenv("AUTO_CREATE_TABLES", "true" if IS_SQLITE else "false").lower() == "true"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Kiểm tra cấu hình TRƯỚC khi nhận request đầu tiên. Chạy sai cấu hình
    # bảo mật rồi mới phát hiện là chuyện không được phép xảy ra.
    for warning in auth.verify_startup_config():
        log.warning("!! %s", warning)

    if AUTO_CREATE_TABLES:
        Base.metadata.create_all(engine)
        log.info("Đã tạo bảng bằng create_all (chế độ dev)")
    else:
        log.info("Bỏ qua create_all — schema do Alembic quản lý")

    log.info(
        "SysOps Portal khởi động · AUTH_MODE=%s · DB=%s",
        auth.auth_mode(),
        "sqlite" if IS_SQLITE else engine.dialect.name,
    )
    yield


app = FastAPI(
    title="SysOps Portal",
    description="IPAM & quản lý vòng đời VM cho đội IT System",
    version="0.2.0",
    lifespan=lifespan,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(HTTPException)
async def auth_aware_error(request: Request, exc: HTTPException):
    """
    Người dùng trình duyệt gặp 401 phải được đưa tới trang đăng nhập, không
    phải một cục JSON. Client gọi API (và request HTMX) vẫn nhận JSON như cũ
    để không phá vỡ hợp đồng API.
    """
    wants_html = "text/html" in request.headers.get("accept", "")
    is_htmx = request.headers.get("hx-request") == "true"

    if exc.status_code == 401 and wants_html and not is_htmx:
        nxt = quote(request.url.path)
        return RedirectResponse(f"/login?next={nxt}", status_code=303)

    return await http_exception_handler(request, exc)


app.include_router(auth_routes.router)
app.include_router(ipam.router)
app.include_router(inventory.router)
app.include_router(drift.router)
app.include_router(reports.router)
app.include_router(admin.router)
app.include_router(ui.router)


# --------------------------------------------------------------------------- #
# Vận hành
# --------------------------------------------------------------------------- #


@app.get("/healthz", tags=["Ops"], include_in_schema=False)
def healthz():
    """Kiểm tra sống, không cần xác thực — dùng cho load balancer và compose."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:  # noqa: BLE001
        log.error("Healthcheck DB thất bại: %s", exc)
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "auth_mode": auth.auth_mode(),
        "version": app.version,
    }


@app.get("/readyz", tags=["Ops"], include_in_schema=False)
def readyz(db=Depends(get_db)):
    """
    Sẵn sàng phục vụ chưa? Khác healthz: có subnet nào được khai báo không.
    Portal không có subnet thì không trả lời được câu hỏi nào có ích.
    """
    from models import Subnet

    count = len(db.scalars(select(Subnet).where(Subnet.is_active)).all())
    return {"ready": count > 0, "active_subnets": count}


try:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator().instrument(app).expose(app, include_in_schema=False)
    log.info("Đã bật /metrics cho Prometheus")
except ImportError:
    log.info("Chưa cài prometheus-fastapi-instrumentator — bỏ qua /metrics")


@app.get("/api/v1/audit", tags=["Ops"])
def list_audit(
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 200,
    db=Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    """Nhật ký thay đổi. Chỉ admin — đây là bằng chứng phục vụ ISO 27001."""
    from models import AuditLog

    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 1000))
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)

    return {
        "entries": [
            {
                "id": a.id,
                "at": a.at.isoformat(),
                "actor": a.actor,
                "action": a.action,
                "entity_type": a.entity_type,
                "entity_id": a.entity_id,
                "changes": a.changes,
            }
            for a in db.scalars(stmt).all()
        ]
    }
