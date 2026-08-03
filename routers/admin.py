"""
Router Admin — kích hoạt job thủ công và bảo trì.

Các endpoint ở đây được TECHNICAL-SPEC §7 liệt kê nhưng trước đó chưa tồn tại
trong code: hàm service đã có, nhưng không có cách nào gọi ngoài Celery beat.
Nghĩa là đội System không tự chạy lại được một lượt đồng bộ khi cần.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import services
from auth import ADMIN, SYSOPS, Principal, require
from core import audit, utcnow
from db import get_db
from models import IPAddress, IPReservation, IPStatus, Subnet, SyncRun

router = APIRouter(prefix="/api/v1", tags=["Admin"])


class SubnetCreate(BaseModel):
    cidr: str
    name: str = ""
    vlan_id: int | None = None
    gateway: str | None = None
    purpose: str = "vm"
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None
    reserved_ranges: list[dict] = Field(default_factory=list)
    allocation_policy: str = "lowest_first"
    cooldown_days: int = Field(14, ge=0, le=365)
    scan_staleness_hours: int = Field(12, ge=1, le=720)


# --------------------------------------------------------------------------- #
# Khai báo dải mạng
# --------------------------------------------------------------------------- #


@router.post("/subnets", status_code=201, tags=["IPAM"])
def create_subnet(
    body: SubnetCreate,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    try:
        net = ipaddress.ip_network(body.cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(400, f"CIDR không hợp lệ: {exc}") from exc

    if db.scalar(select(Subnet).where(Subnet.cidr == str(net))):
        raise HTTPException(409, f"Đã khai báo dải {net}")

    if body.allocation_policy not in ("lowest_first", "fill_gaps", "sparse"):
        raise HTTPException(400, "allocation_policy không hợp lệ")

    for rr in body.reserved_ranges:
        if not {"start", "end"} <= set(rr):
            raise HTTPException(400, "reserved_ranges cần khoá 'start' và 'end'")

    s = Subnet(
        cidr=str(net),
        name=body.name,
        vlan_id=body.vlan_id,
        gateway=body.gateway,
        purpose=body.purpose,
        dhcp_range_start=body.dhcp_range_start,
        dhcp_range_end=body.dhcp_range_end,
        reserved_ranges=body.reserved_ranges,
        allocation_policy=body.allocation_policy,
        cooldown_days=body.cooldown_days,
        scan_staleness_hours=body.scan_staleness_hours,
    )
    db.add(s)
    db.flush()
    audit(db, p.email, "create_subnet", "subnet", s.id, {"cidr": s.cidr})
    db.commit()
    return {"id": s.id, "cidr": s.cidr}


# --------------------------------------------------------------------------- #
# Kích hoạt job
# --------------------------------------------------------------------------- #


@router.post("/scan/{cidr:path}")
def trigger_scan(
    cidr: str,
    method: str = "icmp",
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """
    Quét một dải ngay lập tức.

    Chạy đồng bộ có chủ đích: đội System bấm nút này khi đang xử lý sự cố và
    cần câu trả lời ngay, không phải đẩy vào hàng đợi rồi đi hỏi kết quả.
    Một /24 quét song song mất khoảng vài giây.
    """
    if method not in ("icmp", "arp", "tcp_syn"):
        raise HTTPException(400, "method phải là icmp | arp | tcp_syn")
    try:
        result = services.scan_subnet(db, cidr, method)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc

    audit(db, p.email, "trigger_scan", "subnet", cidr, {"method": method})
    db.commit()
    return result


@router.post("/sync/vcenter")
def trigger_vcenter_sync(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """Đồng bộ vCenter thủ công. Read-only, không bao giờ ghi ngược."""
    host = os.getenv("VCENTER_HOST")
    if not host:
        raise HTTPException(503, "Chưa cấu hình VCENTER_HOST")

    try:
        inventory = services.fetch_vcenter_inventory(
            host=host,
            user=os.environ["VCENTER_USER"],
            password=os.environ["VCENTER_PASSWORD"],
            insecure=os.getenv("VCENTER_INSECURE", "false").lower() == "true",
        )
    except KeyError as exc:
        raise HTTPException(503, f"Thiếu biến môi trường {exc}") from exc
    except Exception as exc:
        raise HTTPException(502, f"Không kết nối được vCenter: {exc}") from exc

    result = services.sync_vcenter(db, inventory)
    audit(db, p.email, "trigger_vcenter_sync", "sync_run", "manual", result)
    db.commit()
    return result


@router.get("/sync/runs")
def list_sync_runs(
    kind: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """Lịch sử chạy job — nơi đầu tiên nhìn khi nghi ngờ dữ liệu sai."""
    stmt = select(SyncRun).order_by(SyncRun.started_at.desc()).limit(limit)
    if kind:
        stmt = stmt.where(SyncRun.kind == kind)
    return {
        "runs": [
            {
                "id": r.id,
                "kind": r.kind,
                "subject": r.subject,
                "started_at": r.started_at.isoformat(),
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "ok": r.ok,
                "items_seen": r.items_seen,
                "items_changed": r.items_changed,
                "findings_created": r.findings_created,
                "error": r.error,
            }
            for r in db.scalars(stmt).all()
        ]
    }


# --------------------------------------------------------------------------- #
# Bảo trì
# --------------------------------------------------------------------------- #


def expire_reservations(db: Session) -> dict:
    """Trả IP giữ chỗ quá hạn về free. Chạy mỗi phút qua Celery beat."""
    now = utcnow()
    stale = db.scalars(select(IPReservation).where(IPReservation.expires_at <= now)).all()
    for r in stale:
        ip = db.get(IPAddress, r.ip_address_id)
        if ip and ip.status == IPStatus.reserved:
            ip.status = IPStatus.free
        db.delete(r)
    db.commit()
    return {"released": len(stale)}


def expire_quarantine(db: Session) -> dict:
    """Chuyển IP đã hết thời gian cách ly về trạng thái free."""
    now = utcnow()
    cooldowns = {s.id: s.cooldown_days for s in db.scalars(select(Subnet)).all()}
    moved = 0
    for ip in db.scalars(select(IPAddress).where(IPAddress.status == IPStatus.quarantine)).all():
        days = cooldowns.get(ip.subnet_id, 14)
        if ip.released_at and ip.released_at + timedelta(days=days) <= now:
            ip.status = IPStatus.free
            moved += 1
    db.commit()
    return {"freed": moved}


@router.post("/maintenance/expire-reservations", tags=["Maintenance"])
def api_expire_reservations(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    return expire_reservations(db)


@router.post("/maintenance/expire-quarantine", tags=["Maintenance"])
def api_expire_quarantine(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    return expire_quarantine(db)


@router.post("/maintenance/purge-scans", tags=["Maintenance"])
def api_purge_scans(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    deleted = services.purge_old_scans(db)
    return {"deleted": deleted, "retention_days": services.SCAN_RETENTION_DAYS}


@router.post("/lifecycle/tick", tags=["Maintenance"])
def api_lifecycle_tick(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """Chạy vòng đời thủ công. Không gửi email — dùng để xem trước tác động."""
    return services.lifecycle_tick(db, send_email=None)
