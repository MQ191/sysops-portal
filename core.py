"""
SysOps Portal — tầng chung giữa các router
==========================================

Chứa hai nhóm:
  1. Chuyển đổi DB -> đối tượng thuần của `allocator`
  2. Tiện ích dùng chung: audit log, mở drift finding, tra cứu subnet

Tách khỏi router để `allocator` vẫn không biết gì về SQLAlchemy, còn router
thì không phải lặp lại logic nạp dữ liệu.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

import allocator as alloc
from models import (
    AuditLog,
    Department,
    Device,
    IPAddress,
    IPAssignment,
    IPReservation,
    IPStatus,
    Project,
    Subnet,
)
from services import open_drift  # nguồn duy nhất — trước đây bị nhân bản ở app.py

__all__ = [
    "active_device",
    "audit",
    "dept_id",
    "device_summary",
    "ensure_ip_row",
    "find_subnet_for",
    "ip_rows_with_devices",
    "load_ip_records",
    "load_subnet_context",
    "open_drift",
    "project_id",
    "utcnow",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def audit(
    db: Session,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    changes: dict | None = None,
) -> None:
    """
    `actor` PHẢI đến từ principal đã xác thực, không bao giờ từ request body.
    Xem auth.py để biết vì sao.
    """
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            changes=changes or {},
        )
    )


# --------------------------------------------------------------------------- #
# DB -> đối tượng thuật toán
# --------------------------------------------------------------------------- #


def load_subnet_context(db: Session, cidr: str) -> tuple[Subnet, alloc.SubnetContext]:
    subnet = db.scalar(select(Subnet).where(Subnet.cidr == cidr))
    if not subnet:
        raise HTTPException(404, f"Không tìm thấy dải mạng {cidr}")
    return subnet, subnet_context(subnet)


def subnet_context(subnet: Subnet) -> alloc.SubnetContext:
    return alloc.SubnetContext(
        cidr=subnet.cidr,
        gateway=subnet.gateway,
        reserved_ranges=[alloc.ReservedRange(**rr) for rr in (subnet.reserved_ranges or [])],
        dhcp_range_start=subnet.dhcp_range_start,
        dhcp_range_end=subnet.dhcp_range_end,
        allocation_policy=subnet.allocation_policy,
        cooldown_days=subnet.cooldown_days,
        name=subnet.name,
        last_scan_ok_at=subnet.last_scan_ok_at,
        scan_staleness_hours=subnet.scan_staleness_hours,
    )


def ip_rows_with_devices(db: Session, subnet_id: str) -> list[IPAddress]:
    """
    Nạp IP kèm assignment/device/department/project trong số truy vấn cố định.

    Trước đây mỗi IP kích hoạt một lazy-load cho `assignments`, rồi mỗi
    assignment thêm một cho `device`, rồi `department` và `project`. Một dải
    /24 sinh ra hơn một nghìn truy vấn cho mỗi lần gọi API — và `/api/v1/subnets`
    lặp lại toàn bộ cho từng dải.
    """
    return list(
        db.scalars(
            select(IPAddress)
            .where(IPAddress.subnet_id == subnet_id)
            .options(
                selectinload(IPAddress.assignments)
                .selectinload(IPAssignment.device)
                .selectinload(Device.department),
                selectinload(IPAddress.assignments)
                .selectinload(IPAssignment.device)
                .selectinload(Device.project),
            )
        ).all()
    )


def active_device(ip: IPAddress) -> Device | None:
    for a in ip.assignments:
        if a.released_at is None:
            return a.device
    return None


def load_ip_records(db: Session, subnet: Subnet, ctx: alloc.SubnetContext) -> list[alloc.IPRecord]:
    """
    Nạp trạng thái IP từ DB, rồi bù đầy các địa chỉ chưa từng có bản ghi.

    Bước bù rất quan trọng: IP chưa bao giờ được cấp thì không có dòng nào
    trong bảng — mà đó lại chính là ứng viên sạch nhất.
    """
    rows = ip_rows_with_devices(db, subnet.id)

    now = utcnow()
    active_reservations = {
        r.ip_address_id: r
        for r in db.scalars(select(IPReservation).where(IPReservation.expires_at > now)).all()
    }

    known: dict[str, alloc.IPRecord] = {}
    for ip in rows:
        dev = active_device(ip)
        res = active_reservations.get(ip.id)
        known[ip.address] = alloc.IPRecord(
            address=ip.address,
            status=ip.status.value,
            consecutive_dead_scans=ip.consecutive_dead_scans,
            last_seen_alive_at=ip.last_seen_alive_at,
            scans_last_7d=ip.scans_last_7d,
            has_arp_or_dns_record=bool(ip.mac_address or ip.hostname),
            ever_assigned=ip.ever_assigned,
            released_at=ip.released_at,
            conflict_count=ip.conflict_count,
            department=(dev.department.code if dev and dev.department else None),
            project=(dev.project.code if dev and dev.project else None),
            criticality=(dev.criticality.value if dev else "normal"),
            reserved_until=res.expires_at if res else None,
        )

    return alloc.build_records_for_subnet(ctx, known)


def device_summary(d: Device) -> dict:
    return {
        "device_id": d.id,
        "name": d.name,
        "asset_code": d.asset_code,
        "department": d.department.code if d.department else None,
        "project": d.project.code if d.project else None,
        "owner_email": d.owner_email,
        "ticket_url": d.ticket_url,
        "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        "power_state": d.power_state.value,
        "cpu_cores": d.cpu_cores,
        "ram_gb": float(d.ram_gb) if d.ram_gb is not None else None,
        "disk_gb": float(d.disk_gb) if d.disk_gb is not None else None,
    }


# --------------------------------------------------------------------------- #
# Tra cứu
# --------------------------------------------------------------------------- #


def ensure_ip_row(db: Session, subnet: Subnet, address: str) -> IPAddress:
    """Lấy hoặc tạo dòng ip_address (IP chưa từng dùng sẽ chưa có dòng)."""
    ip = db.scalar(select(IPAddress).where(IPAddress.address == address))
    if ip:
        return ip
    net = ipaddress.ip_network(subnet.cidr, strict=False)
    if ipaddress.ip_address(address) not in net:
        raise HTTPException(400, f"{address} không thuộc dải {subnet.cidr}")
    ip = IPAddress(subnet_id=subnet.id, address=address, status=IPStatus.free)
    ip.sync_int()
    db.add(ip)
    db.flush()
    return ip


def find_subnet_for(db: Session, address: str) -> Subnet:
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        raise HTTPException(400, f"{address} không phải địa chỉ IP hợp lệ") from None
    for s in db.scalars(select(Subnet).where(Subnet.is_active)).all():
        if target in ipaddress.ip_network(s.cidr, strict=False):
            return s
    raise HTTPException(400, f"{address} không thuộc dải mạng nào đã khai báo")


def dept_id(db: Session, code: str | None) -> str | None:
    if not code:
        return None
    code = code.strip().upper()
    d = db.scalar(select(Department).where(Department.code == code))
    if not d:
        d = Department(code=code, name=code)
        db.add(d)
        db.flush()
    return d.id


def project_id(db: Session, code: str | None, dept: str | None) -> str | None:
    if not code:
        return None
    p = db.scalar(select(Project).where(Project.code == code))
    if not p:
        p = Project(code=code, name=code, department_id=dept_id(db, dept))
        db.add(p)
        db.flush()
    return p.id
