"""
SysOps Portal — background services
===================================

Bốn dịch vụ nền:
  1. network_scan   — quét dải mạng, cập nhật trạng thái sống/chết
  2. vcenter_sync   — đồng bộ inventory VM từ vCenter (read-only)
  3. reconcile      — đối chiếu DB với thực tế, sinh DriftFinding
  4. lifecycle_tick — nhắc hạn và chuyển trạng thái vòng đời

Các hàm này được gọi bởi Celery beat (xem celery_app.py) hoặc thủ công
qua endpoint /api/v1/sync/*.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from models import (
    DRIFT_SEVERITY,
    Device,
    DeviceSource,
    DeviceType,
    DriftFinding,
    DriftStatus,
    DriftType,
    IPAddress,
    IPAssignment,
    IPStatus,
    LifecycleEvent,
    LifecycleStatus,
    PowerState,
    ScanResult,
    Subnet,
    SyncRun,
)

log = logging.getLogger("sysops.services")

# Ngưỡng chống dương tính giả — xem TECHNICAL-SPEC §5.2
ALIVE_CONFIRMATIONS = 3  # số lần quét liên tiếp thấy sống để kết luận "có máy"
DEAD_CONFIRMATIONS = 5  # số lần quét liên tiếp thấy chết để kết luận "trống"

# Quét song song. 254 host nối tiếp × 1s = hơn 4 phút cho một /24, nhân với
# 15 dải là không thể xong trong chu kỳ 4 giờ. Giới hạn để không làm ngập
# switch: 64 gói ICMP đồng thời là an toàn với hạ tầng doanh nghiệp thông thường.
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "64"))
SCAN_TIMEOUT_S = float(os.getenv("SCAN_TIMEOUT_S", "1.0"))

# Số ngày giữ lịch sử quét. Một /24 quét 6 lần/ngày = ~46k dòng/tháng/dải.
SCAN_RETENTION_DAYS = int(os.getenv("SCAN_RETENTION_DAYS", "90"))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# 1. Network scan
# --------------------------------------------------------------------------- #


def ping_host(address: str, timeout_s: float = 1.0) -> tuple[bool, float | None]:
    """
    Ping một địa chỉ. Ưu tiên icmplib (không cần fork process),
    fallback về lệnh ping hệ thống nếu thiếu quyền raw socket.
    """
    try:
        from icmplib import ping as icmp_ping  # type: ignore

        r = icmp_ping(address, count=2, timeout=timeout_s, privileged=False)
        return r.is_alive, (r.avg_rtt if r.is_alive else None)
    except Exception as exc:
        # Im lặng nuốt lỗi ở đây từng là một phần của lỗ hổng "scanner chết mà
        # không ai biết" — không log thì không ai phát hiện ping đang fallback
        # liên tục. Bản thân fallback là hành vi đúng, chỉ thiếu tiếng nói.
        log.debug("icmplib lỗi cho %s (%s), dùng lệnh ping hệ thống", address, exc)

    ping_bin = shutil.which("ping")
    if not ping_bin:
        return False, None
    count_flag = "-n" if os.name == "nt" else "-c"
    try:
        # noqa: S603 — đối số truyền dạng list (không shell=True), nên address
        # không thể tiêm lệnh shell dù có bị thao túng. `address` cũng luôn đến
        # từ ipaddress.ip_network().hosts() hoặc IP đã lưu hợp lệ trong DB.
        proc = subprocess.run(  # noqa: S603
            [ping_bin, count_flag, "2", "-w", str(int(timeout_s * 1000)), address],
            capture_output=True,
            timeout=timeout_s * 4,
        )
        return proc.returncode == 0, None
    except Exception:
        return False, None


async def _ping_many_async(
    addresses: Sequence[str], timeout_s: float = SCAN_TIMEOUT_S
) -> dict[str, tuple[bool, float | None]]:
    """
    Ping hàng loạt song song.

    Ưu tiên `icmplib.async_multiping` (một socket, không fork). Nếu không dùng
    được — thường vì thiếu quyền raw socket hoặc chưa mở
    `net.ipv4.ping_group_range` — rơi về lệnh ping hệ thống chạy song song
    có giới hạn.
    """
    try:
        from icmplib import async_multiping  # type: ignore

        hosts = await async_multiping(
            list(addresses),
            count=2,
            timeout=timeout_s,
            concurrent_tasks=SCAN_CONCURRENCY,
            privileged=False,
        )
        return {h.address: (h.is_alive, h.avg_rtt if h.is_alive else None) for h in hosts}
    except Exception as exc:  # noqa: BLE001 — mọi lỗi đều phải rơi về fallback
        log.warning(
            "icmplib không dùng được (%s: %s) — chuyển sang lệnh ping hệ thống",
            type(exc).__name__,
            exc,
        )

    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    ping_bin = shutil.which("ping")
    if not ping_bin:
        log.error("Không tìm thấy lệnh ping — scanner không hoạt động được")
        return dict.fromkeys(addresses, (False, None))

    count_flag = "-n" if os.name == "nt" else "-c"
    wait_flag = "-w" if os.name == "nt" else "-W"
    wait_val = str(int(timeout_s * 1000)) if os.name == "nt" else str(max(1, int(timeout_s)))

    async def one(addr: str) -> tuple[str, tuple[bool, float | None]]:
        async with sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    ping_bin,
                    count_flag,
                    "2",
                    wait_flag,
                    wait_val,
                    addr,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                rc = await asyncio.wait_for(proc.wait(), timeout=timeout_s * 6)
                return addr, (rc == 0, None)
            except Exception:
                return addr, (False, None)

    results = await asyncio.gather(*(one(a) for a in addresses))
    return dict(results)


def ping_many(
    addresses: Sequence[str], timeout_s: float = SCAN_TIMEOUT_S
) -> dict[str, tuple[bool, float | None]]:
    """Bọc đồng bộ cho `_ping_many_async`, dùng trong Celery task."""
    if not addresses:
        return {}
    return asyncio.run(_ping_many_async(addresses, timeout_s))


def arp_lookup(address: str) -> str | None:
    """Đọc MAC từ bảng ARP cục bộ. Đáng tin nhất khi cùng L2."""
    arp_bin = shutil.which("arp")
    if not arp_bin:
        return None
    try:
        # noqa: S603 — cùng lý do như ping_host: list args, không shell=True.
        out = subprocess.run(  # noqa: S603
            [arp_bin, "-n", address], capture_output=True, text=True, timeout=5
        ).stdout
        for token in out.replace("\n", " ").split():
            if token.count(":") == 5 or token.count("-") == 5:
                return token.lower().replace("-", ":")
    except Exception:
        return None
    return None


def verify_address_is_free(address: str, canaries: Sequence[str] | None = None) -> tuple[bool, str]:
    """
    Kiểm tra trực tiếp ngay tại thời điểm cấp phát.

    Đây là chốt an toàn cuối cùng: dữ liệu quét định kỳ luôn có độ trễ,
    còn bước này chạy ngay trước khi ghi assignment vào DB.

    Hàm này từng có đúng lỗ hổng mà nó sinh ra để bịt: nó gọi `ping_host`,
    và nếu ping hỏng (thiếu quyền raw socket, mất route) thì kết quả luôn là
    "không phản hồi" => luôn kết luận "IP trống" => chốt an toàn trở thành
    con dấu cao su. Nay nó phải TỰ CHỨNG MINH ping đang hoạt động trước, bằng
    cùng cơ chế canary như scanner định kỳ.

    Trả về (is_free, evidence). Không xác minh được thì trả False — chặn cấp
    phát vẫn tốt hơn cấp trùng IP production.
    """
    if canaries:
        canary_results = ping_many(list(canaries))
        if not any(ok for ok, _ in canary_results.values()):
            return False, (
                "không tự xác minh được: không địa chỉ tham chiếu nào phản hồi, "
                "nghĩa là chức năng ping của portal đang hỏng chứ không phải "
                "IP này trống. Kiểm tra scanner rồi thử lại."
            )

    alive, rtt = ping_host(address)
    if alive:
        return False, f"phản hồi ICMP ({rtt:.1f} ms)" if rtt else "phản hồi ICMP"

    mac = arp_lookup(address)
    if mac:
        return False, f"có bản ghi ARP ({mac})"

    return True, "không phản hồi ICMP, không có bản ghi ARP"


def canary_targets(db: Session, subnet: Subnet, limit: int = 12) -> list[str]:
    """
    Chọn các địa chỉ mà ta CHẮC CHẮN phải sống, dùng để tự kiểm tra scanner.

    Gồm gateway và các IP đang gán cho device có `power_state = on`. Nếu quét
    một dải mà KHÔNG địa chỉ nào trong nhóm này phản hồi, kết luận đúng là
    "scanner mù", không phải "cả dải mạng đã chết".
    """
    targets: list[str] = []
    if subnet.gateway:
        targets.append(subnet.gateway)

    rows = db.execute(
        select(IPAddress.address)
        .join(IPAssignment, IPAssignment.ip_address_id == IPAddress.id)
        .join(Device, Device.id == IPAssignment.device_id)
        .where(
            IPAddress.subnet_id == subnet.id,
            IPAssignment.released_at.is_(None),
            Device.power_state == PowerState.on,
        )
        .limit(limit)
    ).all()
    targets.extend(r[0] for r in rows if r[0] not in targets)
    return targets


def scan_subnet(db: Session, cidr: str, method: str = "icmp") -> dict:
    """
    Quét toàn bộ một dải và cập nhật trạng thái.

    Quy tắc chuyển trạng thái được thiết kế thận trọng có chủ đích:
      - Máy tắt tạm thời KHÔNG được coi là IP trống (cần 5 lần chết liên tiếp).
      - IP đang free mà thấy sống 3 lần liên tiếp => conflict, không tự cấp.
    Nguyên nhân: sai sót ở đây gây trùng IP production, tốn hơn nhiều
    so với việc bỏ lỡ vài IP trống.

    CANARY — phần quan trọng nhất của hàm này:
    trước khi tin bất kỳ kết quả "chết" nào, scanner phải chứng minh nó nhìn
    thấy được dải mạng, bằng cách ping các địa chỉ chắc chắn đang sống. Không
    có bước này, một scanner hỏng sẽ lặng lẽ đánh dấu toàn bộ dải là trống và
    hệ thống sẽ tự tin cấp lại những IP đang chạy production.
    """
    subnet = db.scalar(select(Subnet).where(Subnet.cidr == cidr))
    if not subnet:
        raise ValueError(f"Chưa khai báo dải {cidr}")

    run = SyncRun(kind="scan", subject=cidr)
    db.add(run)
    db.flush()

    now = utcnow()
    net = ipaddress.ip_network(cidr, strict=False)
    all_hosts = [str(h) for h in net.hosts()]

    # --- Bước 1: canary ---
    canaries = canary_targets(db, subnet)
    if not canaries:
        run.finished_at = utcnow()
        run.ok = False
        run.error = (
            "Không có địa chỉ tham chiếu nào để tự kiểm tra (dải chưa có "
            "gateway và chưa có device nào đang bật). Bỏ qua lượt quét để "
            "tránh đánh dấu nhầm toàn dải là trống."
        )
        db.commit()
        log.warning("Bỏ qua quét %s: %s", cidr, run.error)
        return {"cidr": cidr, "skipped": True, "reason": run.error}

    canary_results = ping_many(canaries)
    canary_alive = [a for a, (ok, _) in canary_results.items() if ok]

    if not canary_alive:
        run.finished_at = utcnow()
        run.ok = False
        run.error = (
            f"Canary thất bại: không địa chỉ nào trong {len(canaries)} địa chỉ "
            f"tham chiếu phản hồi ({', '.join(canaries[:5])}). Scanner nhiều khả "
            "năng bị mất route, chặn firewall, hoặc thiếu quyền raw socket. "
            "KHÔNG cập nhật trạng thái IP."
        )
        db.commit()
        log.error("Canary thất bại cho %s — huỷ lượt quét", cidr)
        return {"cidr": cidr, "skipped": True, "canary_failed": True, "reason": run.error}

    # --- Bước 2: quét thật, song song ---
    results = ping_many(all_hosts)

    existing = {
        ip.address: ip
        for ip in db.scalars(select(IPAddress).where(IPAddress.subnet_id == subnet.id)).all()
    }

    alive_count = 0
    new_conflicts = 0

    for addr in all_hosts:
        alive, rtt = results.get(addr, (False, None))
        mac = arp_lookup(addr) if alive else None

        db.add(
            ScanResult(
                address=addr,
                address_int=int(ipaddress.ip_address(addr)),
                alive=alive,
                method=method,
                mac_address=mac,
                rtt_ms=rtt,
            )
        )

        ip = existing.get(addr)
        if ip is None:
            if not alive:
                continue  # IP chết chưa từng dùng: không cần tạo dòng
            ip = IPAddress(subnet_id=subnet.id, address=addr, status=IPStatus.free)
            ip.sync_int()
            db.add(ip)
            db.flush()
            existing[addr] = ip

        if alive:
            alive_count += 1
            ip.last_seen_alive_at = now
            ip.consecutive_alive_scans += 1
            ip.consecutive_dead_scans = 0
            if mac:
                ip.mac_address = mac

            if ip.status == IPStatus.free and ip.consecutive_alive_scans >= ALIVE_CONFIRMATIONS:
                ip.status = IPStatus.conflict
                ip.conflict_count += 1
                new_conflicts += 1
                open_drift(
                    db,
                    DriftType.shadow_ip,
                    subject_key=addr,
                    ip_address_id=ip.id,
                    detail={"mac": mac, "method": method},
                )
        else:
            ip.last_seen_dead_at = now
            ip.consecutive_dead_scans += 1
            ip.consecutive_alive_scans = 0

            if (
                ip.status == IPStatus.allocated
                and ip.consecutive_dead_scans >= DEAD_CONFIRMATIONS
                and ip.last_seen_alive_at
                and (now - ip.last_seen_alive_at).days >= 30
            ):
                open_drift(
                    db,
                    DriftType.stale_allocation,
                    subject_key=addr,
                    ip_address_id=ip.id,
                    detail={
                        "dead_scans": ip.consecutive_dead_scans,
                        "last_alive": ip.last_seen_alive_at.isoformat(),
                    },
                )

    # Chỉ mốc này mới cho phép allocator tin vào dữ liệu quét.
    subnet.last_scan_ok_at = now

    refresh_scan_counts(db, subnet.id, now)

    run.finished_at = utcnow()
    run.ok = True
    run.items_seen = len(all_hosts)
    run.findings_created = new_conflicts
    db.commit()

    return {
        "cidr": cidr,
        "scanned": len(all_hosts),
        "alive": alive_count,
        "new_conflicts": new_conflicts,
        "canary_alive": len(canary_alive),
        "canary_total": len(canaries),
    }


def refresh_scan_counts(db: Session, subnet_id: str, now: datetime | None = None) -> int:
    """
    Tính lại `scans_last_7d` từ dữ liệu quét thật.

    Trước đây cột này là bộ đếm `min(n + 1, 99)` — chỉ tăng, không bao giờ
    giảm, và không có cửa sổ 7 ngày nào cả. Sau vài tuần mọi IP đều đạt 99,
    khiến thành phần scan trong công thức confidence luôn bằng 1.0. Tức là
    cột mang tên "số lần quét trong 7 ngày" nhưng thực chất chỉ nói "IP này
    đã tồn tại đủ lâu" — và nó bơm confidence lên vĩnh viễn.
    """
    now = now or utcnow()
    cutoff = now - timedelta(days=7)

    counts = dict(
        db.execute(
            select(ScanResult.address_int, func.count())
            .where(ScanResult.scanned_at >= cutoff)
            .group_by(ScanResult.address_int)
        ).all()
    )

    updated = 0
    for ip in db.scalars(select(IPAddress).where(IPAddress.subnet_id == subnet_id)).all():
        fresh = int(counts.get(ip.address_int, 0))
        if ip.scans_last_7d != fresh:
            ip.scans_last_7d = fresh
            updated += 1
    return updated


def purge_old_scans(db: Session, retention_days: int = SCAN_RETENTION_DAYS) -> int:
    """Xoá lịch sử quét quá hạn. Bảng này lớn nhanh nhất trong toàn schema."""
    cutoff = utcnow() - timedelta(days=retention_days)
    result = db.execute(delete(ScanResult).where(ScanResult.scanned_at < cutoff))
    db.commit()
    return result.rowcount or 0


# --------------------------------------------------------------------------- #
# 2. vCenter sync
# --------------------------------------------------------------------------- #


def fetch_vcenter_inventory(
    host: str, user: str, password: str, insecure: bool = False
) -> list[dict]:
    """
    Lấy inventory VM qua pyVmomi.

    Dùng PropertyCollector thay vì lặp qua từng VM: trên môi trường
    vài trăm VM, cách này nhanh hơn khoảng 50 lần vì chỉ một RPC.

    `insecure` mặc định False có chủ đích — bản trước mặc định True, nghĩa là
    bất kỳ chỗ gọi hàm nào quên truyền tham số đều tắt xác thực chứng chỉ TLS
    mà không ai để ý. Chỉ bật khi vCenter còn dùng chứng chỉ tự ký VÀ người
    vận hành hiểu rủi ro (VCENTER_INSECURE=true trong .env, có cảnh báo kèm).
    """
    import ssl

    from pyVim.connect import Disconnect, SmartConnect  # type: ignore
    from pyVmomi import vim, vmodl  # type: ignore

    # noqa: S323 — chỉ tắt xác thực TLS khi người vận hành bật tường minh qua
    # VCENTER_INSECURE (xem routers/admin.py), không phải hành vi mặc định.
    ctx = ssl._create_unverified_context() if insecure else None  # noqa: S323
    si = SmartConnect(host=host, user=user, pwd=password, sslContext=ctx)
    try:
        content = si.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )

        props = [
            "name",
            "config.uuid",
            "config.hardware.numCPU",
            "config.hardware.memoryMB",
            "config.guestFullName",
            "runtime.powerState",
            "runtime.host",
            "summary.storage.committed",
            "guest.ipAddress",
            "guest.net",
        ]

        spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[
                vmodl.query.PropertyCollector.ObjectSpec(
                    obj=view,
                    skip=True,
                    selectSet=[
                        vmodl.query.PropertyCollector.TraversalSpec(
                            name="tv", path="view", skip=False, type=type(view)
                        )
                    ],
                )
            ],
            propSet=[
                vmodl.query.PropertyCollector.PropertySpec(type=vim.VirtualMachine, pathSet=props)
            ],
        )

        out: list[dict] = []
        for obj in content.propertyCollector.RetrieveContents([spec]):
            d = {p.name: p.val for p in obj.propSet}
            ips: list[str] = []
            for nic in d.get("guest.net", []) or []:
                for ip in getattr(nic, "ipAddress", []) or []:
                    if ":" not in ip and not ip.startswith("169.254."):
                        ips.append(ip)

            committed = d.get("summary.storage.committed") or 0
            host_obj = d.get("runtime.host")

            out.append(
                {
                    "name": d.get("name"),
                    "uuid": d.get("config.uuid"),
                    "cpu_cores": d.get("config.hardware.numCPU"),
                    "ram_gb": round((d.get("config.hardware.memoryMB") or 0) / 1024, 2),
                    "disk_gb": round(committed / (1024**3), 2),
                    "os": d.get("config.guestFullName"),
                    "power_state": str(d.get("runtime.powerState", "unknown")),
                    "hypervisor_host": getattr(host_obj, "name", None),
                    "ips": ips,
                }
            )
        view.Destroy()
        return out
    finally:
        Disconnect(si)


_POWER_MAP = {
    "poweredOn": PowerState.on,
    "poweredOff": PowerState.off,
    "suspended": PowerState.suspended,
}


def sync_vcenter(db: Session, inventory: Iterable[dict]) -> dict:
    """
    Đối chiếu inventory vCenter với DB.

    Quy tắc phân xử khi dữ liệu mâu thuẫn:
      - Field KỸ THUẬT (cpu/ram/disk/power) : vCenter thắng, ghi đè.
      - Field NGHIỆP VỤ (owner/project/hạn) : DB thắng, vCenter không có.
      - Tên khác nhau                        : không tự sửa, sinh finding.

    Đây là điểm mấu chốt: vCenter biết "đang chạy gì", DB biết "của ai".
    Trộn lẫn hai loại thẩm quyền này là nguồn gốc của mọi hệ thống CMDB hỏng.
    """
    run = SyncRun(kind="vcenter")
    db.add(run)
    db.flush()

    inventory = list(inventory)
    seen_uuids: set[str] = set()
    changed = 0
    findings = 0

    for vm in inventory:
        uuid = vm.get("uuid")
        if not uuid:
            continue
        seen_uuids.add(uuid)

        device = db.scalar(select(Device).where(Device.vcenter_uuid == uuid))

        if device is None:
            # Thử khớp theo tên trước khi kết luận là VM lạ
            device = db.scalar(select(Device).where(Device.name == vm["name"]))
            if device is not None:
                device.vcenter_uuid = uuid
                changed += 1
            else:
                device = Device(
                    name=vm["name"],
                    vcenter_uuid=uuid,
                    device_type=DeviceType.vm,
                    source=DeviceSource.vcenter,
                    lifecycle_status=LifecycleStatus.active,
                )
                db.add(device)
                db.flush()
                open_drift(
                    db,
                    DriftType.unregistered_vm,
                    subject_key=uuid,
                    device_id=device.id,
                    detail={
                        "name": vm["name"],
                        "ips": vm.get("ips"),
                        "hint": "VM có trên vCenter nhưng chưa khai báo chủ sở hữu",
                    },
                )
                findings += 1

        # --- Field kỹ thuật: vCenter là thẩm quyền ---
        diffs = {}
        for field, new in (
            ("cpu_cores", vm.get("cpu_cores")),
            ("ram_gb", vm.get("ram_gb")),
            ("disk_gb", vm.get("disk_gb")),
        ):
            old = getattr(device, field)
            if new is not None and old is not None and float(old) != float(new):
                diffs[field] = {"db": float(old), "vcenter": float(new)}
            if new is not None:
                setattr(device, field, new)

        device.power_state = _POWER_MAP.get(vm.get("power_state"), PowerState.unknown)
        device.hypervisor_host = vm.get("hypervisor_host") or device.hypervisor_host
        device.os = vm.get("os") or device.os
        device.last_synced_at = utcnow()
        changed += 1

        if diffs:
            open_drift(
                db,
                DriftType.spec_mismatch,
                subject_key=uuid,
                device_id=device.id,
                detail=diffs,
            )
            findings += 1

        # --- Kiểm tra chất lượng dữ liệu nghiệp vụ ---
        if not device.owner_email and device.source != DeviceSource.discovered:
            open_drift(
                db,
                DriftType.missing_owner,
                subject_key=device.id,
                device_id=device.id,
                detail={"name": device.name},
            )
            findings += 1
        if device.device_type == DeviceType.vm and not device.is_protected:
            if not device.expires_at:
                open_drift(
                    db,
                    DriftType.missing_expiry,
                    subject_key=device.id,
                    device_id=device.id,
                    detail={"name": device.name},
                )
                findings += 1

    # --- VM có trong DB nhưng biến mất khỏi vCenter ---
    for device in db.scalars(
        select(Device).where(
            Device.vcenter_uuid.isnot(None),
            Device.lifecycle_status != LifecycleStatus.archived,
        )
    ).all():
        if device.vcenter_uuid not in seen_uuids:
            open_drift(
                db,
                DriftType.ghost_vm,
                subject_key=device.vcenter_uuid,
                device_id=device.id,
                detail={
                    "name": device.name,
                    "hint": "Còn trong hệ thống quản lý nhưng không còn trên vCenter "
                    "— có thể đã xoá mà chưa thu hồi IP",
                },
            )
            findings += 1

    run.finished_at = utcnow()
    run.ok = True
    run.items_seen = len(inventory)
    run.items_changed = changed
    run.findings_created = findings
    db.commit()

    return {
        "vms_seen": len(inventory),
        "devices_updated": changed,
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
# 3. Drift helper
# --------------------------------------------------------------------------- #


def open_drift(
    db: Session,
    drift_type: DriftType,
    subject_key: str,
    device_id: str | None = None,
    ip_address_id: str | None = None,
    detail: dict | None = None,
) -> DriftFinding:
    """Idempotent — chạy job nhiều lần không sinh finding trùng."""
    existing = db.scalar(
        select(DriftFinding).where(
            DriftFinding.drift_type == drift_type,
            DriftFinding.subject_key == subject_key,
        )
    )
    if existing:
        existing.last_seen_at = utcnow()
        if existing.status == DriftStatus.resolved:
            existing.status = DriftStatus.open
            existing.resolution_note = (
                existing.resolution_note or ""
            ) + " | Tái phát sau khi đã đóng"
        return existing

    f = DriftFinding(
        drift_type=drift_type,
        severity=DRIFT_SEVERITY[drift_type],
        subject_key=subject_key,
        device_id=device_id,
        ip_address_id=ip_address_id,
        detail=detail or {},
    )
    db.add(f)
    return f


# --------------------------------------------------------------------------- #
# 4. Vòng đời
# --------------------------------------------------------------------------- #

REMINDER_DAYS = (30, 7, 1)


def lifecycle_tick(db: Session, send_email=None) -> dict:
    """
    Chạy hằng ngày. Nhắc hạn, chuyển trạng thái, đánh dấu cần thu hồi.

    Cố ý KHÔNG tự shutdown hay xoá VM: hành động phá huỷ luôn cần
    con người phê duyệt. Hệ thống chỉ đưa lên hàng đợi và nhắc.
    """
    today = date.today()
    reminders = 0
    expired = 0

    devices = db.scalars(
        select(Device).where(
            Device.expires_at.isnot(None),
            Device.is_protected.is_(False),
            Device.lifecycle_status.notin_([LifecycleStatus.archived, LifecycleStatus.shutdown]),
        )
    ).all()

    for d in devices:
        days_left = (d.expires_at - today).days

        if days_left in REMINDER_DAYS:
            recipients = [d.owner_email] if d.owner_email else []
            if days_left <= 7 and d.department and d.department.manager_email:
                recipients.append(d.department.manager_email)
            if send_email and recipients:
                ips = ", ".join(a.ip.address for a in d.assignments if a.released_at is None)
                send_email(
                    to=recipients,
                    subject=f"[SysOps] {d.name} hết hạn sau {days_left} ngày",
                    body=(
                        f"Máy chủ {d.name} ({ips}) sẽ hết hạn ngày {d.expires_at}.\n"
                        f"Cấu hình: {d.cpu_cores} vCPU / {d.ram_gb} GB RAM / "
                        f"{d.disk_gb} GB disk.\n"
                        "Bấm link để gia hạn hoặc xác nhận thu hồi."
                    ),
                )
            db.add(
                LifecycleEvent(
                    device_id=d.id,
                    event="reminder_sent",
                    detail={"days_left": days_left, "to": recipients},
                )
            )
            reminders += 1
            if days_left <= 7:
                d.lifecycle_status = LifecycleStatus.expiring

        elif days_left < 0:
            if d.lifecycle_status != LifecycleStatus.pending_reclaim:
                d.lifecycle_status = LifecycleStatus.pending_reclaim
                expired += 1
            if d.power_state == PowerState.on:
                open_drift(
                    db,
                    DriftType.expired,
                    subject_key=d.id,
                    device_id=d.id,
                    detail={
                        "name": d.name,
                        "expired_days_ago": -days_left,
                        "wasted_vcpu": d.cpu_cores,
                        "wasted_ram_gb": float(d.ram_gb or 0),
                    },
                )

    db.commit()
    return {"reminders_sent": reminders, "newly_expired": expired}
