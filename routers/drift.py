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


DRIFT_TYPE_LABELS = {
    "expired": "Máy ảo quá hạn",
    "unregistered_vm": "VM chưa đăng ký",
    "ghost_vm": "VM bóng ma",
    "shadow_ip": "IP bóng ma",
    "stale_allocation": "IP không phản hồi",
    "spec_mismatch": "Sai lệch cấu hình",
    "missing_owner": "Thiếu chủ sở hữu",
    "missing_expiry": "Thiếu hạn dùng",
    "ip_conflict": "Xung đột IP",
}

SEV_LABELS = {
    "critical": "Nghiêm trọng",
    "high": "Cao",
    "medium": "Trung bình",
    "low": "Thấp",
}


def resolve_finding_display(f: DriftFinding) -> tuple[str, str]:
    if f.device and f.device.name:
        return f.device.name, "vm" if getattr(f.device.device_type, "value", str(f.device.device_type)) == "vm" else "server"
    if isinstance(f.detail, dict) and f.detail.get("name"):
        return str(f.detail["name"]), "vm"
    if f.ip_address and f.ip_address.address:
        return f.ip_address.address, "ip"
    if f.subject_key and f.subject_key.count(".") == 3:
        return f.subject_key, "ip"
    return f.subject_key, "other"


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
    
    result_findings = []
    for f in page:
        subj_display, subj_type = resolve_finding_display(f)
        result_findings.append({
            "id": f.id,
            "type": f.drift_type.value,
            "type_label": DRIFT_TYPE_LABELS.get(f.drift_type.value, f.drift_type.value),
            "severity": f.severity.value,
            "severity_label": SEV_LABELS.get(f.severity.value, f.severity.value),
            "status": f.status.value,
            "subject": f.subject_key,
            "subject_display": subj_display,
            "subject_type": subj_type,
            "detail": f.detail,
            "first_seen_at": f.first_seen_at.isoformat(),
            "last_seen_at": f.last_seen_at.isoformat(),
            "sla_deadline": f.sla_deadline.isoformat(),
            "sla_breached": f.sla_deadline < now,
            "assigned_to": f.assigned_to,
        })

    return {
        "total": total,
        "count": len(page),
        "offset": offset,
        "findings": result_findings,
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
