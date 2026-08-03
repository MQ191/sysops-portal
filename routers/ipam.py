"""
Router IPAM — suggest / reserve / commit / release.

Đây là luồng nghiệp vụ cốt lõi và cũng là nơi tập trung nhiều chốt an toàn
nhất. Đọc kèm TECHNICAL-SPEC §4.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import allocator as alloc
from auth import REQUESTER, SYSOPS, VIEWER, Principal, require
from core import (
    active_device,
    audit,
    dept_id,
    device_summary,
    ensure_ip_row,
    find_subnet_for,
    ip_rows_with_devices,
    load_ip_records,
    load_subnet_context,
    open_drift,
    project_id,
    utcnow,
)
from db import engine, get_db
from models import (
    Device,
    DeviceSource,
    DeviceType,
    DriftType,
    IPAddress,
    IPAssignment,
    IPReservation,
    IPStatus,
    LifecycleStatus,
    Subnet,
)

router = APIRouter(prefix="/api/v1", tags=["IPAM"])

RESERVATION_TTL_MINUTES = int(os.getenv("RESERVATION_TTL_MINUTES", "30"))
MAX_RESERVATION_TTL_MINUTES = int(os.getenv("MAX_RESERVATION_TTL_MINUTES", "240"))


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #


class SuggestRequest(BaseModel):
    subnet: str = Field(..., examples=["10.0.76.0/24"])
    department: str | None = Field(None, examples=["SDC11"])
    project: str | None = None
    quantity: int = Field(1, ge=1, le=64)
    contiguous: bool = False
    limit: int = Field(5, ge=1, le=20)


class ReserveRequest(BaseModel):
    address: str
    purpose: str | None = None
    ttl_minutes: int | None = Field(None, ge=1, le=MAX_RESERVATION_TTL_MINUTES)
    # `reserved_by` đã bị bỏ có chủ đích: danh tính lấy từ token/phiên đăng nhập.


class CommitRequest(BaseModel):
    token: str
    device_id: str | None = None
    device_name: str | None = None
    department: str | None = None
    project: str | None = None
    owner_email: str | None = None
    ticket_id: str | None = None
    expires_at: date | None = None
    cpu_cores: int | None = Field(None, ge=1, le=512)
    ram_gb: float | None = Field(None, gt=0, le=8192)
    disk_gb: float | None = Field(None, gt=0, le=1_000_000)
    skip_liveness_check: bool = False


class ReleaseRequest(BaseModel):
    address: str
    reason: str | None = None


# --------------------------------------------------------------------------- #
# Đọc
# --------------------------------------------------------------------------- #


@router.get("/subnets")
def list_subnets(
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    out = []
    now = utcnow()
    for subnet in db.scalars(select(Subnet).where(Subnet.is_active)).all():
        _, ctx = load_subnet_context(db, subnet.cidr)
        records = load_ip_records(db, subnet, ctx)
        stats = alloc.subnet_stats(ctx, records, now)
        stats["scanner_warning"] = ctx.staleness_warning(now)
        stats["last_scan_ok_at"] = (
            subnet.last_scan_ok_at.isoformat() if subnet.last_scan_ok_at else None
        )
        out.append(stats)
    return {"subnets": out}


@router.get("/subnets/{cidr:path}/map")
def subnet_map(
    cidr: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    """Bản đồ toàn bộ IP trong dải — thay thế trực tiếp cho file Google Sheet."""
    subnet, ctx = load_subnet_context(db, cidr)
    records = load_ip_records(db, subnet, ctx)
    now = utcnow()

    dev_by_ip = {}
    for ip in ip_rows_with_devices(db, subnet.id):
        d = active_device(ip)
        if d is not None:
            dev_by_ip[ip.address] = device_summary(d)

    stats = alloc.subnet_stats(ctx, records, now)
    return {
        "subnet": stats,
        "scanner_warning": ctx.staleness_warning(now),
        "addresses": [
            {
                "address": r.address,
                "status": r.status,
                "unusable_reason": ctx.is_structurally_unusable(r.addr_int),
                "device": dev_by_ip.get(r.address),
            }
            for r in records
        ],
    }


@router.post("/ipam/suggest")
def suggest_ip(
    body: SuggestRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    """Gợi ý IP trống an toàn nhất — tính năng cốt lõi của portal."""
    subnet, ctx = load_subnet_context(db, body.subnet)
    records = load_ip_records(db, subnet, ctx)

    result = alloc.suggest(
        ctx,
        records,
        alloc.SuggestionRequest(
            department=body.department,
            project=body.project,
            quantity=body.quantity,
            contiguous=body.contiguous,
            limit=body.limit,
            now=utcnow(),
        ),
    )
    return result.as_dict()


# --------------------------------------------------------------------------- #
# Ghi
# --------------------------------------------------------------------------- #

# Trạng thái không được phép giữ chỗ, kèm lý do đọc được cho người dùng.
_UNRESERVABLE = {
    IPStatus.allocated: "đã cấp cho thiết bị khác",
    IPStatus.blocked: "bị khoá (hạ tầng cố định)",
    IPStatus.conflict: "đang xung đột, cần điều tra trước",
}


@router.post("/ipam/reserve")
def reserve_ip(
    body: ReserveRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    """
    Giữ chỗ IP với TTL.

    Dùng SELECT ... FOR UPDATE NOWAIT trên Postgres: nếu hai người cùng
    xin một IP, người thứ hai nhận lỗi ngay lập tức thay vì chờ khoá,
    và UI sẽ gợi ý IP kế tiếp.
    """
    addr = body.address
    subnet = find_subnet_for(db, addr)
    ip = ensure_ip_row(db, subnet, addr)

    if engine.dialect.name == "postgresql":
        try:
            db.execute(
                select(IPAddress.id).where(IPAddress.id == ip.id).with_for_update(nowait=True)
            )
        except OperationalError:
            db.rollback()
            raise HTTPException(409, "IP đang được xử lý bởi yêu cầu khác") from None

    now = utcnow()
    existing = db.scalar(select(IPReservation).where(IPReservation.ip_address_id == ip.id))
    if existing and existing.expires_at > now:
        raise HTTPException(409, f"IP đang được giữ chỗ bởi {existing.reserved_by}")
    if existing:
        db.delete(existing)
        db.flush()

    if ip.status in _UNRESERVABLE:
        raise HTTPException(409, f"Không giữ chỗ được: IP {_UNRESERVABLE[ip.status]}")

    # Cách ly là chốt an toàn, không phải gợi ý.
    #
    # Trước đây chỉ engine gợi ý mới tôn trọng cooldown, còn endpoint này thì
    # không kiểm tra — nghĩa là một lời gọi API trực tiếp vô hiệu hoá toàn bộ
    # lập luận về ARP cache, rule firewall cũ và whitelist phía khách hàng
    # trong TECHNICAL-SPEC §3.4. Chốt an toàn mà đi vòng được thì không phải
    # chốt an toàn.
    if ip.status == IPStatus.quarantine:
        if ip.released_at is None:
            raise HTTPException(409, "IP đang cách ly nhưng thiếu mốc thu hồi")
        cooldown_end = ip.released_at + timedelta(days=subnet.cooldown_days)
        if cooldown_end > now:
            remaining = (cooldown_end - now).days + 1
            raise HTTPException(
                409,
                f"IP đang trong thời gian cách ly, còn {remaining} ngày "
                f"(hết cách ly {cooldown_end.date().isoformat()}). "
                "Cấp lại ngay sau thu hồi gây lỗi rất khó chẩn đoán: ARP cache "
                "trên switch, rule firewall cũ và whitelist phía khách hàng vẫn "
                "còn trỏ tới địa chỉ này.",
            )

    ttl = body.ttl_minutes or RESERVATION_TTL_MINUTES
    res = IPReservation(
        ip_address_id=ip.id,
        reserved_by=p.email,
        purpose=body.purpose,
        expires_at=now + timedelta(minutes=ttl),
    )
    ip.status = IPStatus.reserved
    db.add(res)
    audit(db, p.email, "reserve_ip", "ip_address", ip.id, {"address": addr})
    db.commit()

    return {
        "address": addr,
        "token": res.token,
        "reserved_by": p.email,
        "expires_at": res.expires_at.isoformat(),
        "ttl_minutes": ttl,
    }


@router.post("/ipam/commit")
def commit_ip(
    body: CommitRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    """
    Chốt cấp IP cho một device.

    Trước khi chốt, hệ thống PING + ARP lại địa chỉ một lần nữa.
    Dữ liệu quét luôn có độ trễ; bước xác minh trực tiếp này là thứ
    ngăn sự cố trùng IP tốt hơn mọi thuật toán chấm điểm.
    """
    res = db.scalar(select(IPReservation).where(IPReservation.token == body.token))
    if not res:
        raise HTTPException(404, "Token giữ chỗ không hợp lệ")
    if res.expires_at <= utcnow():
        raise HTTPException(410, "Giữ chỗ đã hết hạn, vui lòng xin IP lại")

    # Chỉ người giữ chỗ hoặc sysops mới chốt được — nếu không, bất kỳ ai biết
    # token cũng gán được IP cho thiết bị của mình.
    if res.reserved_by != p.email and not p.at_least(SYSOPS):
        raise HTTPException(403, f"Giữ chỗ này thuộc về {res.reserved_by}")

    ip = db.get(IPAddress, res.ip_address_id)

    if body.skip_liveness_check and not p.at_least(SYSOPS):
        raise HTTPException(403, "Chỉ sysops mới được bỏ qua bước xác minh trực tiếp")

    if not body.skip_liveness_check:
        from services import canary_targets, verify_address_is_free

        subnet = db.get(Subnet, ip.subnet_id)
        is_free, evidence = verify_address_is_free(ip.address, canaries=canary_targets(db, subnet))
        if not is_free:
            ip.status = IPStatus.conflict
            ip.conflict_count += 1
            open_drift(
                db,
                DriftType.shadow_ip,
                subject_key=ip.address,
                ip_address_id=ip.id,
                detail={"evidence": evidence, "found_at": "commit-time check"},
            )
            db.delete(res)
            db.commit()
            raise HTTPException(
                409,
                f"{ip.address} không xác nhận được là trống ({evidence}). "
                "Đã đánh dấu xung đột, vui lòng chọn IP khác.",
            )

    # --- Lấy hoặc tạo device ---
    if body.device_id:
        device = db.get(Device, body.device_id)
        if not device:
            raise HTTPException(404, "Không tìm thấy thiết bị")
    else:
        if not body.device_name or not body.owner_email:
            raise HTTPException(400, "Cần device_name và owner_email khi tạo thiết bị mới")
        device = Device(
            name=body.device_name,
            device_type=DeviceType.vm,
            owner_email=body.owner_email,
            requester_email=p.email,
            ticket_id=body.ticket_id,
            provisioned_at=date.today(),
            expires_at=body.expires_at,
            cpu_cores=body.cpu_cores,
            ram_gb=body.ram_gb,
            disk_gb=body.disk_gb,
            source=DeviceSource.manual,
            lifecycle_status=LifecycleStatus.active,
            department_id=dept_id(db, body.department),
            project_id=project_id(db, body.project, body.department),
        )
        db.add(device)
        db.flush()

    # Ràng buộc nghiệp vụ: VM phải có hạn dùng
    if device.device_type == DeviceType.vm and not device.is_protected:
        if not device.expires_at:
            open_drift(
                db,
                DriftType.missing_expiry,
                subject_key=device.id,
                device_id=device.id,
                detail={"device": device.name},
            )

    db.add(IPAssignment(ip_address_id=ip.id, device_id=device.id, is_primary=True))
    ip.status = IPStatus.allocated
    ip.ever_assigned = True
    ip.released_at = None
    db.delete(res)
    audit(
        db,
        p.email,
        "commit_ip",
        "ip_address",
        ip.id,
        {"address": ip.address, "device": device.name},
    )
    db.commit()

    return {
        "address": ip.address,
        "device_id": device.id,
        "device_name": device.name,
        "status": "allocated",
    }


@router.delete("/ipam/reserve/{token}")
def cancel_reservation(
    token: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    res = db.scalar(select(IPReservation).where(IPReservation.token == token))
    if not res:
        raise HTTPException(404, "Không tìm thấy giữ chỗ")
    if res.reserved_by != p.email and not p.at_least(SYSOPS):
        raise HTTPException(403, f"Giữ chỗ này thuộc về {res.reserved_by}")

    ip = db.get(IPAddress, res.ip_address_id)
    ip.status = IPStatus.free
    db.delete(res)
    audit(db, p.email, "cancel_reservation", "ip_address", ip.id, {"address": ip.address})
    db.commit()
    return {"address": ip.address, "status": "free"}


@router.post("/ipam/release")
def release_ip(
    body: ReleaseRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """Thu hồi IP -> chuyển sang cách ly (quarantine), KHÔNG trả về free ngay."""
    ip = db.scalar(select(IPAddress).where(IPAddress.address == body.address))
    if not ip:
        raise HTTPException(404, "Không tìm thấy IP")

    now = utcnow()
    for a in ip.assignments:
        if a.released_at is None:
            a.released_at = now

    ip.status = IPStatus.quarantine
    ip.released_at = now
    audit(
        db,
        p.email,
        "release_ip",
        "ip_address",
        ip.id,
        {"address": ip.address, "reason": body.reason},
    )
    db.commit()

    subnet = db.get(Subnet, ip.subnet_id)
    return {
        "address": ip.address,
        "status": "quarantine",
        "available_after": (now + timedelta(days=subnet.cooldown_days)).isoformat(),
        "cooldown_days": subnet.cooldown_days,
    }
