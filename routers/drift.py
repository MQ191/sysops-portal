"""Router Drift — hàng đợi chênh lệch giữa DB và thực tế."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from auth import SYSOPS, VIEWER, Principal, require
from core import audit, utcnow
from db import get_db
from models import DriftFinding, DriftStatus, Severity

router = APIRouter(prefix="/api/v1", tags=["Drift"])

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ResolveRequest(BaseModel):
    note: str = Field("", max_length=2000)
    status: DriftStatus = DriftStatus.resolved


@router.get("/drift")
def list_drift(
    status: DriftStatus = DriftStatus.open,
    severity: Severity | None = None,
    sla_breached: bool | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    stmt = select(DriftFinding).where(DriftFinding.status == status)
    if severity:
        stmt = stmt.where(DriftFinding.severity == severity)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    findings = list(db.scalars(stmt).all())
    findings.sort(key=lambda f: (SEV_ORDER[f.severity.value], f.first_seen_at))

    now = utcnow()
    if sla_breached is not None:
        findings = [f for f in findings if (f.sla_deadline < now) == sla_breached]

    page = findings[offset : offset + limit]
    return {
        "total": total,
        "count": len(page),
        "offset": offset,
        "findings": [
            {
                "id": f.id,
                "type": f.drift_type.value,
                "severity": f.severity.value,
                "status": f.status.value,
                "subject": f.subject_key,
                "detail": f.detail,
                "first_seen_at": f.first_seen_at.isoformat(),
                "last_seen_at": f.last_seen_at.isoformat(),
                "sla_deadline": f.sla_deadline.isoformat(),
                "sla_breached": f.sla_deadline < now,
                "assigned_to": f.assigned_to,
            }
            for f in page
        ],
    }


@router.post("/drift/{finding_id}/resolve")
def resolve_drift(
    finding_id: str,
    body: ResolveRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """
    Đóng một finding.

    Trước đây `actor` là query param mặc định "system", nghĩa là bất kỳ ai
    cũng đóng được một cảnh báo `ip_conflict` mức critical và ký tên hệ thống.
    Giờ danh tính lấy từ principal, và cần vai trò sysops trở lên.
    """
    f = db.get(DriftFinding, finding_id)
    if not f:
        raise HTTPException(404, "Không tìm thấy finding")
    if body.status not in (DriftStatus.resolved, DriftStatus.acknowledged, DriftStatus.ignored):
        raise HTTPException(400, "Chỉ chuyển được sang resolved/acknowledged/ignored")

    f.status = body.status
    f.resolved_at = utcnow() if body.status == DriftStatus.resolved else None
    f.resolution_note = body.note
    f.assigned_to = p.email
    audit(
        db,
        p.email,
        "resolve_drift",
        "drift_finding",
        f.id,
        {"note": body.note, "status": body.status.value},
    )
    db.commit()
    return {"id": f.id, "status": f.status.value, "by": p.email}
