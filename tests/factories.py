"""Dữ liệu mẫu tối thiểu cho test tích hợp."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from models import (
    Criticality,
    Department,
    Device,
    DeviceSource,
    DeviceType,
    IPAddress,
    IPAssignment,
    IPStatus,
    LifecycleStatus,
    PowerState,
    Project,
    ScanResult,
    Subnet,
)

NOW = datetime.now(timezone.utc)
CIDR = "10.0.76.0/24"


def seed_minimal(db, scanner_healthy: bool = True) -> dict:
    """
    Một dải, hai đơn vị, vài device — đủ để chạy toàn bộ luồng nghiệp vụ.

    `scanner_healthy=False` mô phỏng scanner chết: dùng để kiểm tra dead man
    switch, chế độ hỏng nguy hiểm nhất của hệ thống.
    """
    dept = Department(code="SDC11", name="SDC11", manager_email="truong.sdc11@ntq-solution.com.vn")
    dept2 = Department(code="SDC1", name="SDC1")
    db.add_all([dept, dept2])
    db.flush()

    proj = Project(code="NTT", name="NTT", department_id=dept.id)
    db.add(proj)
    db.flush()

    subnet = Subnet(
        cidr=CIDR,
        name="Dải VM dự án",
        gateway="10.0.76.254",
        reserved_ranges=[{"start": "10.0.76.1", "end": "10.0.76.4", "reason": "network infra"}],
        allocation_policy="lowest_first",
        cooldown_days=14,
        scan_staleness_hours=12,
        last_scan_ok_at=(NOW - timedelta(hours=2)) if scanner_healthy else None,
    )
    db.add(subnet)
    db.flush()

    devices = []
    for octet, name, crit, owner, expires in [
        (
            5,
            "SDC1-Tiktok-76.5",
            Criticality.critical,
            "tam.tran@ntq-solution.com.vn",
            date(2027, 12, 31),
        ),
        (
            8,
            "SDC11-NTT-76.8",
            Criticality.normal,
            "linh.nguyen@ntq-solution.com.vn",
            date(2027, 6, 30),
        ),
        (9, "SDC11-NTT-76.9", Criticality.normal, None, None),
    ]:
        d = Device(
            name=name,
            device_type=DeviceType.vm,
            os="Ubuntu 22.04",
            cpu_cores=4,
            ram_gb=8,
            disk_gb=100,
            power_state=PowerState.on,
            department_id=dept.id if "SDC11" in name else dept2.id,
            project_id=proj.id,
            owner_email=owner,
            expires_at=expires,
            criticality=crit,
            source=DeviceSource.imported,
            lifecycle_status=LifecycleStatus.active,
        )
        db.add(d)
        db.flush()

        ip = IPAddress(
            subnet_id=subnet.id,
            address=f"10.0.76.{octet}",
            status=IPStatus.allocated,
            ever_assigned=True,
            scans_last_7d=8,
            last_seen_alive_at=NOW - timedelta(hours=1),
        )
        ip.sync_int()
        db.add(ip)
        db.flush()
        db.add(IPAssignment(ip_address_id=ip.id, device_id=d.id, is_primary=True))
        devices.append(d)

    # IP trống đã quét kỹ — ứng viên tốt
    for octet in range(40, 50):
        ip = IPAddress(
            subnet_id=subnet.id,
            address=f"10.0.76.{octet}",
            status=IPStatus.free,
            consecutive_dead_scans=28,
            scans_last_7d=8,
            ever_assigned=False,
        )
        ip.sync_int()
        db.add(ip)
        db.flush()
        for i in range(8):
            db.add(
                ScanResult(
                    address=ip.address,
                    address_int=ip.address_int,
                    alive=False,
                    method="icmp",
                    scanned_at=NOW - timedelta(hours=4 * i + 1),
                )
            )

    db.commit()
    result = {
        "subnet_id": subnet.id,
        "cidr": CIDR,
        "device_ids": [d.id for d in devices],
    }
    db.close()
    return result
