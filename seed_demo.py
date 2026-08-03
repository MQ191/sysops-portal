"""
Tạo dữ liệu mẫu để chạy thử portal.

Dữ liệu mô phỏng theo đúng 3 file Google Sheet hiện tại — bao gồm cả
các khiếm khuyết thực tế (thiếu owner, thiếu hạn dùng, IP lậu) để thấy
ngay hệ thống phát hiện được gì.

Chạy:  python seed_demo.py
"""

from __future__ import annotations

import ipaddress
import sys
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from db import SessionLocal, engine
from models import (
    Base,
    CredentialRef,
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

# Console Windows mặc định là cp1252 và không in được tiếng Việt — script này
# từng crash ở đúng dòng print cuối, sau khi đã commit xong, khiến người chạy
# tưởng seed thất bại.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NOW = datetime.now(timezone.utc)
TODAY = date.today()


def main() -> None:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()

    # --- Đơn vị ---
    depts = {}
    for code in ["SDC1", "SDC3", "SDC6", "SDC8", "SDC11", "SDCAI", "NES", "NKR", "NTD", "PMO"]:
        d = Department(
            code=code,
            name=code,
            manager_email=f"truong.{code.lower()}@ntq-solution.com.vn",
        )
        db.add(d)
        depts[code] = d
    db.flush()

    # --- Dự án ---
    projects = {}
    for code, dept in [
        ("Tiktok", "SDC1"),
        ("Chatzone", "SDC1"),
        ("CRM", "SDC1"),
        ("Stripe", "SDC1"),
        ("NTT", "SDC11"),
        ("NIGHTLIFE", "SDC11"),
        ("NEXMIGRATION", "SDC11"),
        ("QUADY", "SDC11"),
        ("GLAS", "SDC11"),
        ("CIPPO", "SDC11"),
        ("Fastdesk2", "NES"),
        ("ERM", "NTD"),
        ("NKIA", "NKR"),
        ("COWAY", "SDC3"),
        ("FANPLUS", "SDC6"),
        ("Du lieu quoc gia", "SDCAI"),
    ]:
        p = Project(code=code, name=code, department_id=depts[dept].id)
        db.add(p)
        projects[code] = p
    db.flush()

    # --- Dải mạng ---
    subnets = {}
    for cidr, name, gw, purpose, reserved, policy in [
        (
            "10.0.76.0/24",
            "Dải VM dự án",
            "10.0.76.254",
            "vm",
            [
                {
                    "start": "10.0.76.1",
                    "end": "10.0.76.4",
                    "reason": "gateway, firewall, switch quản trị",
                }
            ],
            "lowest_first",
        ),
        (
            "10.0.64.0/24",
            "Dải VM hạ tầng",
            "10.0.64.254",
            "vm",
            [{"start": "10.0.64.1", "end": "10.0.64.10", "reason": "network infra"}],
            "fill_gaps",
        ),
        (
            "10.0.65.0/24",
            "Dải VM dự án mở rộng",
            "10.0.65.254",
            "vm",
            [{"start": "10.0.65.1", "end": "10.0.65.5", "reason": "network infra"}],
            "lowest_first",
        ),
        (
            "172.16.0.0/24",
            "Dải quản trị ESXi",
            "172.16.0.254",
            "management",
            [{"start": "172.16.0.1", "end": "172.16.0.9", "reason": "network infra"}],
            "sparse",
        ),
    ]:
        s = Subnet(
            cidr=cidr,
            name=name,
            gateway=gw,
            purpose=purpose,
            reserved_ranges=reserved,
            allocation_policy=policy,
            cooldown_days=14,
            # Mô phỏng scanner khoẻ: không có mốc này thì dead man switch bật
            # và mọi gợi ý bị hạ xuống "Dữ liệu quét chưa đủ" — đúng về mặt
            # thiết kế, nhưng bản demo cần thể hiện được trạng thái bình thường.
            last_scan_ok_at=NOW - timedelta(hours=2),
        )
        db.add(s)
        subnets[cidr] = s
    db.flush()

    # --- Thiết bị (theo dữ liệu thực trong 3 sheet) ---
    # (ip, tên, đơn vị, dự án, ticket, cpu, ram, disk, owner, hết hạn, criticality)
    vms = [
        (
            "10.0.76.5",
            "SDC1-Tiktok-76.5",
            "SDC1",
            "Tiktok",
            "8831",
            4,
            8,
            100,
            "tam.tran@ntq-solution.com.vn",
            date(2025, 12, 31),
            "critical",
        ),
        (
            "10.0.76.8",
            "SDC11-NTT-76.8",
            "SDC11",
            "NTT",
            "8873",
            4,
            4,
            50,
            "tam.tran@ntq-solution.com.vn",
            date(2025, 12, 31),
            "normal",
        ),
        (
            "10.0.76.9",
            "SDC1-Chatzone-76.9",
            "SDC1",
            "Chatzone",
            "8971",
            4,
            8,
            100,
            "tam.tran@ntq-solution.com.vn",
            date(2026, 12, 31),
            "normal",
        ),
        (
            "10.0.76.10",
            "SDC1-Chatzone-76.10",
            "SDC1",
            "Chatzone",
            "8992",
            4,
            8,
            100,
            "tam.tran@ntq-solution.com.vn",
            date(2026, 12, 31),
            "normal",
        ),
        (
            "10.0.76.11",
            "NES-Fastdesk2-76.11",
            "NES",
            "Fastdesk2",
            "8995",
            4,
            8,
            100,
            None,
            None,
            "normal",
        ),
        (
            "10.0.76.12",
            "NTD-EMR-76.12",
            "NTD",
            "ERM",
            "9373",
            4,
            8,
            100,
            "hoa.dinh@ntq-solution.com.vn",
            date(2026, 9, 30),
            "normal",
        ),
        (
            "10.0.76.13",
            "NKR-NKIA-76.13",
            "NKR",
            "NKIA",
            "9360",
            4,
            8,
            100,
            "hoa.dinh@ntq-solution.com.vn",
            None,
            "normal",
        ),
        (
            "10.0.76.14",
            "SDC1-CRM-76.14",
            "SDC1",
            "CRM",
            "9374",
            4,
            8,
            100,
            "tam.tran@ntq-solution.com.vn",
            date(2025, 12, 31),
            "critical",
        ),
        (
            "10.0.76.15",
            "SDC3-COWAY-76.15",
            "SDC3",
            "COWAY",
            "9381",
            4,
            8,
            100,
            "vuong.dam@ntq-solution.com.vn",
            date(2025, 11, 30),
            "normal",
        ),
        (
            "10.0.76.16",
            "SDC11-NIGHTLIFE-76.16",
            "SDC11",
            "NIGHTLIFE",
            "9440",
            4,
            8,
            200,
            "linh.nguyen21@ntq-solution.com.vn",
            date(2026, 5, 31),
            "normal",
        ),
        (
            "10.0.76.17",
            "SDC11-NEXMIGRATION-76.17",
            "SDC11",
            "NEXMIGRATION",
            "9476",
            4,
            8,
            100,
            "giang.nguyen13@ntq-solution.com.vn",
            date(2026, 6, 30),
            "normal",
        ),
        (
            "10.0.76.19",
            "SDC8-COWAY-76.19",
            "SDC8",
            "COWAY",
            "9575",
            4,
            8,
            100,
            None,
            None,
            "normal",
        ),
        (
            "10.0.76.20",
            "NES-Fastdesk2-76.20",
            "NES",
            "Fastdesk2",
            "9394",
            4,
            8,
            100,
            None,
            date(2025, 10, 31),
            "normal",
        ),
        (
            "10.0.76.26",
            "SDC6-FANPLUS-76.26",
            "SDC6",
            "FANPLUS",
            "9643",
            4,
            8,
            100,
            None,
            None,
            "normal",
        ),
        (
            "10.0.76.28",
            "SDC1-Stripe-76.28",
            "SDC1",
            "Stripe",
            "9727",
            4,
            8,
            100,
            "tam.tran@ntq-solution.com.vn",
            date(2026, 2, 28),
            "normal",
        ),
        (
            "10.0.76.29",
            "SDC11-OneLive-76.29",
            "SDC11",
            "GLAS",
            None,
            4,
            8,
            50,
            "toan.truong@ntq-solution.com.vn",
            date(2026, 12, 31),
            "normal",
        ),
        (
            "10.0.76.39",
            "SDC11-CIPPO-76.39",
            "SDC11",
            "CIPPO",
            "10455",
            4,
            6,
            60,
            "khai.ngo@ntq-solution.com.vn",
            None,
            "normal",
        ),
        (
            "10.0.65.254",
            "SDC11-GLAS-65.254",
            "SDC11",
            "GLAS",
            None,
            4,
            6,
            50,
            "huyen.duong@ntq-solution.com.vn",
            None,
            "normal",
        ),
        (
            "10.0.65.198",
            "SDC11-QUADY-65.198",
            "SDC11",
            "QUADY",
            "8139",
            6,
            4,
            130,
            "thanh.nguyen20@ntq-solution.com.vn",
            date(2026, 6, 30),
            "normal",
        ),
        (
            "10.0.65.84",
            "SDC11-Quady-65.84",
            "SDC11",
            "QUADY",
            "8335",
            4,
            2,
            50,
            "vuong.dam@ntq-solution.com.vn",
            date(2026, 6, 30),
            "normal",
        ),
        (
            "10.0.64.174",
            "SDC11-ShipOperation-64.174",
            "SDC11",
            "GLAS",
            None,
            4,
            16,
            250,
            "truong.nguyen.huu@ntq-solution.com.vn",
            date(2026, 6, 30),
            "normal",
        ),
        (
            "10.0.64.98",
            "SDC11-WorldVision-64.98",
            "SDC11",
            "GLAS",
            None,
            4,
            4,
            50,
            "hoa.dinh@ntq-solution.com.vn",
            date(2026, 6, 30),
            "normal",
        ),
        (
            "10.0.64.217",
            "SDC11-Clear-64.217",
            "SDC11",
            "GLAS",
            None,
            4,
            16,
            150,
            "hoa.dinh@ntq-solution.com.vn",
            None,
            "normal",
        ),
        (
            "10.0.64.120",
            "SDC11-GLAS-64.120",
            "SDC11",
            "GLAS",
            "7584",
            4,
            8,
            50,
            "toan.truong@ntq-solution.com.vn",
            date(2025, 12, 31),
            "normal",
        ),
    ]

    for addr, name, dept, proj, ticket, cpu, ram, disk, owner, exp, crit in vms:
        subnet = _subnet_for(subnets, addr)
        dev = Device(
            name=name,
            device_type=DeviceType.vm,
            os="Ubuntu 22.04",
            cpu_cores=cpu,
            ram_gb=ram,
            disk_gb=disk,
            power_state=PowerState.on,
            department_id=depts[dept].id,
            project_id=projects[proj].id if proj in projects else None,
            owner_email=owner,
            requester_email=owner,
            ticket_id=ticket,
            provisioned_at=TODAY - timedelta(days=300),
            expires_at=exp,
            lifecycle_status=LifecycleStatus.active,
            source=DeviceSource.imported,
            criticality=Criticality(crit),
        )
        db.add(dev)
        db.flush()

        ip = IPAddress(
            subnet_id=subnet.id,
            address=addr,
            status=IPStatus.allocated,
            ever_assigned=True,
            scans_last_7d=8,
            consecutive_dead_scans=0,
            last_seen_alive_at=NOW - timedelta(hours=2),
        )
        ip.sync_int()
        db.add(ip)
        db.flush()
        db.add(IPAssignment(ip_address_id=ip.id, device_id=dev.id, is_primary=True))

        # Tham chiếu Vault thay cho cột USER/PASS trong sheet
        db.add(
            CredentialRef(
                device_id=dev.id,
                auth_type="ssh_key",
                username="ntq",
                vault_path=f"secret/data/vm/{name.lower()}",
            )
        )

    # --- Server vật lý (file 3100) ---
    for addr, name, os_name in [
        ("172.16.0.10", "ESXi-DL380-Gen10-YK69", "ESXi 6.7"),
        ("172.16.0.11", "ESXi-DL380-Gen10-XQYN", "ESXi 6.7"),
        ("172.16.0.13", "ESXi-DL380-Gen10-VKC7", "ESXi 6.7"),
        ("172.16.0.15", "ESXi-DL380-Gen10-FN40", "ESXi 6.7"),
        ("172.16.0.16", "Backup-0.16", "Windows Server 2019"),
    ]:
        subnet = _subnet_for(subnets, addr)
        dev = Device(
            name=name,
            device_type=DeviceType.physical_server,
            os=os_name,
            cpu_cores=32,
            ram_gb=256,
            disk_gb=4000,
            power_state=PowerState.on,
            owner_email="itsystem@ntq-solution.com.vn",
            is_protected=True,
            criticality=Criticality.critical,
            source=DeviceSource.imported,
            provisioned_at=TODAY - timedelta(days=900),
        )
        db.add(dev)
        db.flush()
        ip = IPAddress(
            subnet_id=subnet.id,
            address=addr,
            status=IPStatus.allocated,
            ever_assigned=True,
            scans_last_7d=8,
            last_seen_alive_at=NOW,
        )
        ip.sync_int()
        db.add(ip)
        db.flush()
        db.add(IPAssignment(ip_address_id=ip.id, device_id=dev.id))

    # --- Các trạng thái đặc biệt để demo ---
    s76 = subnets["10.0.76.0/24"]

    # IP đang cách ly (vừa thu hồi VM)
    for addr, days_ago in [("10.0.76.18", 3), ("10.0.76.21", 20)]:
        ip = IPAddress(
            subnet_id=s76.id,
            address=addr,
            status=IPStatus.quarantine,
            ever_assigned=True,
            released_at=NOW - timedelta(days=days_ago),
            consecutive_dead_scans=days_ago * 4,
            scans_last_7d=8,
        )
        ip.sync_int()
        db.add(ip)

    # IP "lậu": scan thấy sống nhưng không ai khai báo
    for addr in ("10.0.76.33", "10.0.76.34"):
        ip = IPAddress(
            subnet_id=s76.id,
            address=addr,
            status=IPStatus.conflict,
            last_seen_alive_at=NOW - timedelta(hours=1),
            consecutive_alive_scans=6,
            scans_last_7d=8,
            mac_address="00:50:56:9a:1b:2c",
            conflict_count=1,
        )
        ip.sync_int()
        db.add(ip)

    # IP trống đã quét kỹ — ứng viên tốt nhất
    for i in range(40, 56):
        ip = IPAddress(
            subnet_id=s76.id,
            address=f"10.0.76.{i}",
            status=IPStatus.free,
            consecutive_dead_scans=28,
            scans_last_7d=8,
            ever_assigned=False,
        )
        ip.sync_int()
        db.add(ip)

    db.flush()

    # --- Lịch sử quét thật ---
    # `scans_last_7d` giờ được tính từ bảng scan_result chứ không còn là bộ đếm
    # tự tăng. Nếu seed không sinh dữ liệu quét, confidence sẽ bằng 0 và bản
    # demo không phản ánh đúng hệ thống đang chạy.
    scans = 0
    for ip in db.scalars(select(IPAddress)).all():
        alive = ip.status in (IPStatus.allocated, IPStatus.conflict)
        for i in range(8):
            db.add(
                ScanResult(
                    address=ip.address,
                    address_int=ip.address_int,
                    alive=alive,
                    method="icmp",
                    rtt_ms=0.8 if alive else None,
                    scanned_at=NOW - timedelta(hours=4 * i + 2),
                )
            )
            scans += 1
        ip.scans_last_7d = 8

    db.commit()
    db.close()

    print("Đã tạo dữ liệu mẫu.")
    print(f"  Bản ghi quét : {scans}")
    print(f"  Dải mạng : {len(subnets)}")
    print(f"  Đơn vị   : {len(depts)}")
    print(f"  Thiết bị : {len(vms) + 5}")
    print()
    print("Chạy:  uvicorn app:app --reload --port 8080")
    print(
        "Thử :  curl -X POST localhost:8080/api/v1/ipam/suggest "
        "-H 'Content-Type: application/json' "
        '-d \'{"subnet":"10.0.76.0/24","department":"SDC11"}\''
    )


def _subnet_for(subnets: dict, addr: str) -> Subnet:
    target = ipaddress.ip_address(addr)
    for cidr, s in subnets.items():
        if target in ipaddress.ip_network(cidr, strict=False):
            return s
    raise ValueError(f"{addr} không thuộc dải nào")


if __name__ == "__main__":
    main()
