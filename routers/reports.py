"""Router Reports — số liệu cho đội System và lãnh đạo."""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from auth import VIEWER, Principal, require
from core import utcnow
from db import get_db
from models import (
    Department,
    Device,
    DriftFinding,
    DriftStatus,
    LifecycleStatus,
    Subnet,
)

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


@router.get("/utilization")
def utilization(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    """Tài nguyên đã cấp theo đơn vị — con số lãnh đạo hỏi mỗi tháng."""
    rows = db.execute(
        select(
            Department.code,
            func.count(Device.id),
            func.sum(Device.cpu_cores),
            func.sum(Device.ram_gb),
            func.sum(Device.disk_gb),
        )
        .join(Device, Device.department_id == Department.id)
        .where(Device.lifecycle_status != LifecycleStatus.archived)
        .group_by(Department.code)
    ).all()

    return {
        "by_department": [
            {
                "department": r[0],
                "devices": r[1],
                "vcpu": int(r[2] or 0),
                "ram_gb": float(r[3] or 0),
                "disk_gb": float(r[4] or 0),
            }
            for r in sorted(rows, key=lambda x: -(x[2] or 0))
        ]
    }


@router.get("/expiring")
def expiring(
    days: int = Query(30, ge=0, le=3650),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    cutoff = date.today() + timedelta(days=days)
    devices = list(
        db.scalars(
            select(Device)
            .options(selectinload(Device.department))
            .where(
                Device.expires_at.isnot(None),
                Device.expires_at <= cutoff,
                Device.is_protected.is_(False),
                Device.lifecycle_status.notin_(
                    [LifecycleStatus.archived, LifecycleStatus.shutdown]
                ),
            )
        ).all()
    )
    devices.sort(key=lambda d: d.expires_at)

    return {
        "window_days": days,
        "count": len(devices),
        "reclaimable_vcpu": sum(d.cpu_cores or 0 for d in devices),
        "reclaimable_ram_gb": float(sum(d.ram_gb or 0 for d in devices)),
        "devices": [
            {
                "id": d.id,
                "name": d.name,
                "owner_email": d.owner_email,
                "department": d.department.code if d.department else None,
                "expires_at": d.expires_at.isoformat(),
                "days_left": d.days_to_expiry,
                "ticket_url": d.ticket_url,
            }
            for d in devices
        ],
    }


@router.get("/data-quality")
def data_quality(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    """Chỉ số nói lên tình trạng dữ liệu — mục tiêu là 100% ở mọi dòng."""
    total = db.scalar(select(func.count(Device.id))) or 0
    if total == 0:
        return {"total_devices": 0}

    def pct(n: int) -> float:
        return round(100.0 * n / total, 1)

    def count_where(*conds) -> int:
        return db.scalar(select(func.count(Device.id)).where(*conds)) or 0

    return {
        "total_devices": total,
        "has_owner_pct": pct(count_where(Device.owner_email.isnot(None))),
        "has_expiry_pct": pct(count_where(Device.expires_at.isnot(None))),
        "has_ticket_pct": pct(count_where(Device.ticket_id.isnot(None))),
        "has_asset_code_pct": pct(count_where(Device.asset_code.isnot(None))),
        "open_drift": db.scalar(
            select(func.count(DriftFinding.id)).where(DriftFinding.status == DriftStatus.open)
        )
        or 0,
    }


@router.get("/scanner-health")
def scanner_health(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    """
    Scanner có đang thực sự nhìn thấy từng dải không?

    Báo cáo này tồn tại vì chế độ hỏng nguy hiểm nhất của hệ thống là chế độ
    IM LẶNG: scanner chết, mọi IP bị coi là trống, portal vẫn trả lời tự tin.
    Đây là màn hình đầu tiên cần xem mỗi sáng.
    """
    now = utcnow()
    out = []
    for s in db.scalars(select(Subnet).where(Subnet.is_active)).all():
        stale = s.last_scan_ok_at is None or (now - s.last_scan_ok_at) > timedelta(
            hours=s.scan_staleness_hours
        )
        out.append(
            {
                "cidr": s.cidr,
                "name": s.name,
                "last_scan_ok_at": (s.last_scan_ok_at.isoformat() if s.last_scan_ok_at else None),
                "hours_since": (
                    round((now - s.last_scan_ok_at).total_seconds() / 3600, 1)
                    if s.last_scan_ok_at
                    else None
                ),
                "threshold_hours": s.scan_staleness_hours,
                "stale": stale,
            }
        )

    stale_count = sum(1 for r in out if r["stale"])
    return {
        "healthy": stale_count == 0,
        "stale_subnets": stale_count,
        "total_subnets": len(out),
        "subnets": out,
    }
