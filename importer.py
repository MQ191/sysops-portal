"""
Import dữ liệu từ 3 Google Sheet hiện tại.

    python importer.py --physical data/physical.csv \
                       --vm       data/vm.csv \
                       --network  data/network.csv

CHỈ LẤY NHỮNG TRƯỜNG PORTAL THỰC SỰ DÙNG
----------------------------------------
Sheet có rất nhiều cột, phần lớn không phục vụ mục tiêu nào của hệ thống.
Nhập bừa cả bảng chỉ làm dữ liệu rác trông giống dữ liệu thật. Lấy đúng:

  IPAM      : địa chỉ IP, thiết bị đang giữ, đơn vị, dự án, trạng thái chạy
  Vòng đời  : người đứng tên, hạn thu hồi, mã ticket, ngày cấp
  Kiểm kê   : mã tài sản, OS, CPU/RAM/Disk, cờ "server mẫu không xoá"

Bỏ hẳn: STT, DÃI MẠNG (suy ra được từ IP), Monitor, VM Tool, và toàn bộ bảng
tra cứu tham khảo dán ở các cột bên phải file 3100.

Nguyên tắc xử lý dữ liệu bẩn:
  - KHÔNG đoán bừa. Ô nào không chắc thì ghi vào needs_review.csv.
  - KHÔNG import cột USER/PASS. Xuất riêng ra vault_import.csv để nạp Vault
    rồi xoá vĩnh viễn khỏi Google Sheet (kể cả version history).
  - Import "như hiện trạng", đánh dấu chỗ thiếu thay vì chặn import.
    Làm sạch trước khi import là cái bẫy khiến dự án không bao giờ khởi động.

Ba đặc điểm của sheet thật mà bản đầu tiên của file này không xử lý được:

  1. Hàng tiêu đề không nằm ở dòng 1 (file network ở dòng 4, file 3100 ở
     dòng 5) — phía trên là tiêu đề trang trí và chú thích.
  2. File 3100 có bảng tra cứu tham khảo ở các cột bên phải dùng lại đúng tên
     cột `OS` và `RAM`. Đọc bằng dict thường thì cột sau đè cột trước, khiến
     MỌI giá trị OS bị lấy nhầm từ bảng tra cứu.
  3. Tên thiết bị có khi chứa địa chỉ IP (`VM-PROXY-192.168.6.5`,
     `VIP của cụm server 10.0.76.24, 10.0.76.25`). Chỉ trích IP từ đúng cột
     IP, không bao giờ từ tên.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from datetime import date, datetime
from typing import Any

from sqlalchemy import select

from db import SessionLocal, engine
from models import (
    Base,
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
    Subnet,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REVIEW_ROWS: list[dict[str, Any]] = []
VAULT_ROWS: list[dict[str, Any]] = []

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Người nhập dùng những chuỗi này để nói "máy này không có hạn thu hồi".
# Đó là thông tin, không phải dữ liệu thiếu — đừng đẩy vào review.
NO_EXPIRY = {"no expire", "no expiry", "no date", "không có date", "khong co date", "lqd"}

# Cột TRẠNG THÁI của file 3100 chứa cả vòng đời lẫn cờ "đừng đụng vào".
PROTECTED_MARKERS = ("không xóa", "không xoá")
STOPPED_MARKERS = ("tạm dừng", "không hoạt động", "không dùng", "stop", "close")


# --------------------------------------------------------------------------- #
# Đọc CSV xuất từ Google Sheet
# --------------------------------------------------------------------------- #


def read_table(path: str) -> list[dict[str, str]]:
    """
    Đọc CSV mà hàng tiêu đề nằm lẫn đâu đó ở đầu file.

    Cắt bảng tại cột tiêu đề rỗng đầu tiên: mọi thứ bên phải là bảng tra cứu
    tham khảo người làm sheet dán thêm, và nó trùng tên cột với dữ liệu thật.
    Với tên cột trùng nhau thì lần xuất hiện ĐẦU TIÊN thắng.
    """
    with open(path, encoding="utf-8-sig", newline="") as f:
        raw = list(csv.reader(f))
    if not raw:
        return []

    best_i, best_score = 0, -1
    for i, row in enumerate(raw[:10]):
        filled = [c.strip() for c in row if c.strip()]
        # Hàng tiêu đề có nhiều ô chữ và không ô nào là địa chỉ IP.
        score = len(filled) - 10 * sum(bool(IP_RE.search(c)) for c in filled)
        if score > best_score:
            best_i, best_score = i, score

    header = [c.strip() for c in raw[best_i]]

    # Cắt tại HAI cột trống liên tiếp — đó là khoảng ngăn giữa bảng dữ liệu và
    # bảng tra cứu tham khảo dán bên phải (file 3100).
    #
    # Không cắt tại cột trống ĐƠN LẺ: sheet xuất từ Google thường có một cột
    # lề trống ở đầu và ở cuối. Cắt ở đó thì bảng còn lại rỗng không — đúng
    # lỗi khiến file network đọc ra 0 dòng.
    cut = len(header)
    for j in range(len(header) - 1):
        if not header[j] and not header[j + 1]:
            cut = j
            break
    header = header[:cut]

    out: list[dict[str, str]] = []
    for row in raw[best_i + 1 :]:
        rec: dict[str, str] = {}
        for j, key in enumerate(header):
            if not key or key in rec:
                continue  # bỏ cột lề không tên; tên trùng thì lần đầu thắng
            rec[key] = (row[j] if j < len(row) else "").strip()
        out.append(rec)
    return out


def col(row: dict, *names: str) -> str:
    """Lấy giá trị theo nhiều tên cột khả dĩ — sheet có lỗi chính tả."""
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n.strip().lower():
                return (v or "").strip()
    return ""


# --------------------------------------------------------------------------- #
# Parser chịu lỗi
# --------------------------------------------------------------------------- #


def parse_date(raw: str | None, context: str = "") -> date | None:
    """
    Sheet đang lẫn lộn 12/31/2025 (MM/DD) và 31/12/2025 (DD/MM).

    Chiến lược: nếu một trong hai thành phần > 12 thì suy ra được thứ tự một
    cách chắc chắn. Nếu cả hai đều <= 12 thì KHÔNG đoán — đưa vào danh sách
    review. Đoán sai một hạn dùng có thể khiến VM production bị thu hồi nhầm.
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None

    low = raw.lower()
    if low in NO_EXPIRY or "no expire" in low:
        return None  # cố ý không có hạn — không phải dữ liệu thiếu
    if low.startswith(("chưa", "chua")):
        return None  # sheet tự khai là chưa có

    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            pass

    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", raw)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            if a > 12 and b <= 12:
                return date(y, b, a)  # DD/MM/YYYY
            if b > 12 and a <= 12:
                return date(y, a, b)  # MM/DD/YYYY
        except ValueError:
            # Ngày không tồn tại trong lịch, ví dụ 31/4 (tháng 4 chỉ có 30
            # ngày). Người nhập gõ nhầm — không có cách nào đoán đúng ý họ.
            REVIEW_ROWS.append({
                "issue": "ngày không tồn tại trên lịch",
                "value": raw, "context": context,
            })
            return None
        if a <= 12 and b <= 12:
            REVIEW_ROWS.append({
                "issue": "ngày nhập nhằng DD/MM hay MM/DD",
                "value": raw, "context": context,
            })
        return None

    REVIEW_ROWS.append({"issue": "không đọc được ngày", "value": raw, "context": context})
    return None


def parse_size(raw: str | None) -> float | None:
    """'50 GB' -> 50.0 · '64GB' -> 64.0 · '16B' (gõ sót) -> 16.0 · '' -> None"""
    if not raw:
        return None
    m = re.search(r"([\d.,]+)", raw.replace(",", "."))
    if not m:
        return None
    try:
        val = float(m.group(1))
    except ValueError:
        return None
    if "tb" in raw.lower():
        val *= 1024
    return val or None


def parse_int(raw: str | None) -> int | None:
    if not raw:
        return None
    m = re.search(r"\d+", raw)
    if not m:
        return None
    return int(m.group()) or None


def extract_ips(raw: str | None) -> list[str]:
    """
    Trích IP từ MỘT ô — chỉ dùng cho đúng cột địa chỉ IP.

    Một ô có thể chứa nhiều IP xuống dòng ('172.16.0.20\\n10.0.64.20').
    Không bao giờ gọi hàm này trên cột tên thiết bị: nhiều tên có chứa IP
    (`VM-PROXY-192.168.6.5`) và sẽ bị trích nhầm thành địa chỉ được cấp.
    """
    if not raw:
        return []
    out, seen = [], set()
    for cand in IP_RE.findall(raw):
        if cand in seen:
            continue
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            continue
        seen.add(cand)
        out.append(cand)
    return out


def extract_ticket(raw: str | None) -> str | None:
    """Lấy mã ticket từ URL GLPI hoặc từ số thuần."""
    if not raw:
        return None
    m = re.search(r"ticket\.form\.php\?id=(\d+)", raw)
    if m:
        return m.group(1)
    m = re.search(r"^\s*(\d{3,6})\s*$", raw)
    return m.group(1) if m else None


def normalize_email(raw: str | None) -> str | None:
    """Sheet có chỗ ghi email đầy đủ, có chỗ chỉ ghi tên đăng nhập."""
    v = (raw or "").strip()
    if not v or " " in v and "@" not in v:
        return v or None
    if "@" not in v:
        return f"{v}@ntq-solution.com.vn"
    return v


def normalize_name(raw: str) -> str:
    """VM-SDC11-NTT-76.8 và SDC11-NTT-76.8 phải quy về cùng một tên."""
    n = " ".join((raw or "").split())  # gộp xuống dòng và khoảng trắng thừa
    for prefix in ("VM-", "vm-", "PC-", "pc-", "SV-", "sv-", "VPC-"):
        if n.startswith(prefix):
            n = n[len(prefix) :]
            break
    return n.strip()


# --------------------------------------------------------------------------- #
# Bộ nhớ đệm tra cứu
#
# Import chạy qua kết nối tới Supabase ở Tokyo. Truy vấn từng dòng sẽ thành
# hàng nghìn round-trip; nạp sẵn vào dict rồi tra trong bộ nhớ.
# --------------------------------------------------------------------------- #


class Cache:
    def __init__(self, db):
        self.db = db
        self.depts = {d.code: d for d in db.scalars(select(Department)).all()}
        self.projects = {p.code: p for p in db.scalars(select(Project)).all()}
        self.devices = {d.name: d for d in db.scalars(select(Device)).all()}
        self.ips = {i.address: i for i in db.scalars(select(IPAddress)).all()}
        self.nets = [
            (ipaddress.ip_network(s.cidr, strict=False), s)
            for s in db.scalars(select(Subnet)).all()
        ]
        # mã tài sản -> thiết bị đang giữ; cột này UNIQUE ở tầng DB
        self.asset_codes: dict[str, str] = {
            d.asset_code: d.name for d in self.devices.values() if d.asset_code
        }

        # địa chỉ -> tên device đang giữ, để phát hiện khai trùng IP
        id2ip = {i.id: i.address for i in self.ips.values()}
        id2dev = {d.id: d.name for d in self.devices.values()}
        self.holder: dict[str, str] = {}
        for a in db.scalars(
            select(IPAssignment).where(IPAssignment.released_at.is_(None))
        ).all():
            addr, dev = id2ip.get(a.ip_address_id), id2dev.get(a.device_id)
            if addr and dev:
                self.holder[addr] = dev

    def dept(self, code: str | None) -> Department | None:
        code = " ".join((code or "").split()).upper()
        if not code:
            return None
        d = self.depts.get(code)
        if not d:
            d = Department(code=code, name=code)
            self.db.add(d)
            self.db.flush()
            self.depts[code] = d
        return d

    def project(self, code: str | None, dept: Department | None) -> Project | None:
        code = " ".join((code or "").split())
        if not code:
            return None
        p = self.projects.get(code)
        if not p:
            p = Project(code=code, name=code, department_id=dept.id if dept else None)
            self.db.add(p)
            self.db.flush()
            self.projects[code] = p
        return p

    def subnet_for(self, address: str) -> Subnet | None:
        t = ipaddress.ip_address(address)
        for net, s in self.nets:
            if t in net:
                return s
        return None


def clean_asset_code(raw: str | None, cache: Cache, context: str) -> str | None:
    """
    Mã tài sản có ràng buộc UNIQUE ở tầng DB, nhưng sheet không đảm bảo điều đó.

    Thực tế gặp phải: `#298447` (một số issue Redmine bị điền nhầm vào cột mã
    tài sản) xuất hiện ở hai server khác nhau. Mã tài sản thật trông như
    `ITDP01526`. Gặp trùng hoặc gặp giá trị không giống mã tài sản thì bỏ qua
    và ghi vào review — chứ không để nó làm vỡ cả lượt import.
    """
    code = (raw or "").strip()
    if not code:
        return None

    if code.startswith("#") or "/" in code or " " in code:
        REVIEW_ROWS.append({
            "issue": "mã tài sản không đúng định dạng (có thể là số ticket điền nhầm cột)",
            "value": code, "context": context,
        })
        return None

    if code in cache.asset_codes:
        REVIEW_ROWS.append({
            "issue": "MÃ TÀI SẢN TRÙNG — mỗi mã chỉ được thuộc một thiết bị",
            "value": code,
            "context": f"{cache.asset_codes[code]} vs {context}",
        })
        return None

    cache.asset_codes[code] = context
    return code


def upsert_device(cache: Cache, name: str, **fields) -> Device:
    """
    Ghép theo tên đã chuẩn hoá; chỉ điền vào ô còn trống.

    File sau không được ghi đè dữ liệu file trước: thứ tự nạp (vật lý -> VM ->
    network) chọn theo độ tin cậy giảm dần của từng nguồn.
    """
    norm = normalize_name(name)
    dev = cache.devices.get(norm)
    if not dev:
        dev = Device(name=norm, aliases=[])
        cache.db.add(dev)
        cache.db.flush()
        cache.devices[norm] = dev

    raw = " ".join((name or "").split())
    if raw != norm and raw not in (dev.aliases or []):
        dev.aliases = (dev.aliases or []) + [raw]

    for k, v in fields.items():
        if v is None:
            continue
        if getattr(dev, k, None) in (None, "", 0):
            setattr(dev, k, v)
    return dev


def attach_ip(cache: Cache, dev: Device, address: str, primary: bool, src: str) -> None:
    subnet = cache.subnet_for(address)
    if not subnet:
        REVIEW_ROWS.append({
            "issue": "IP không thuộc dải mạng nào đã khai báo",
            "value": address, "context": f"{dev.name} ({src})",
        })
        return

    holder = cache.holder.get(address)
    if holder and holder != dev.name:
        REVIEW_ROWS.append({
            "issue": "TRÙNG IP — hai thiết bị cùng khai một địa chỉ",
            "value": address, "context": f"{holder} vs {dev.name} ({src})",
        })
        return
    if holder:
        return  # đã gán cho đúng thiết bị này rồi

    ip = cache.ips.get(address)
    if not ip:
        ip = IPAddress(subnet_id=subnet.id, address=address)
        ip.sync_int()
        cache.db.add(ip)
        cache.db.flush()
        cache.ips[address] = ip

    ip.status = IPStatus.allocated
    ip.ever_assigned = True
    cache.db.add(IPAssignment(ip_address_id=ip.id, device_id=dev.id, is_primary=primary))
    cache.holder[address] = dev.name


# --------------------------------------------------------------------------- #
# Ba trình import
# --------------------------------------------------------------------------- #


def import_physical(db, path: str) -> int:
    """File 3100 — server vật lý / ảo hoá. Nạp TRƯỚC vì chứa mã tài sản."""
    cache = Cache(db)
    n = 0
    for r in read_table(path):
        name = col(r, "TÊN SERVER", "TEN SERVER")
        if not name:
            continue

        status = col(r, "TRẠNG THÁI").lower()
        protected = any(m in status for m in PROTECTED_MARKERS)
        stopped = any(m in status for m in STOPPED_MARKERS)

        dept = cache.dept(col(r, "ĐƠN VỊ"))
        proj = cache.project(col(r, "DỰ ÁN"), dept)
        owner = normalize_email(col(r, "NGƯỜI YÊU CẦU"))

        dev = upsert_device(
            cache, name,
            # Quy ước đặt tên của sheet: SV- là server chuyên dụng, còn lại là
            # máy ảo hoặc máy lắp ráp.
            device_type=(
                DeviceType.physical_server
                if name.upper().startswith(("SV-", "SERVER "))
                else DeviceType.vm
            ),
            asset_code=clean_asset_code(col(r, "ID TÀI SẢN"), cache, f"3100/{name[:40]}"),
            os=col(r, "OS") or None,
            cpu_cores=parse_int(col(r, "CPU")),
            ram_gb=parse_size(col(r, "RAM")),
            disk_gb=parse_size(col(r, "HDD/SSD")),
            department_id=dept.id if dept else None,
            project_id=proj.id if proj else None,
            owner_email=owner,
            requester_email=owner,
            ticket_id=extract_ticket(col(r, "GHI CHÚ")),
            provisioned_at=parse_date(col(r, "NGÀY CẤP"), f"3100/{name[:40]}"),
            expires_at=parse_date(col(r, "DỰ KIẾN THU HỒI"), f"3100/{name[:40]}"),
            power_state=(
                PowerState.off if stopped
                else PowerState.on if "đang hoạt động" in status
                else PowerState.unknown
            ),
            is_protected=protected or None,
            criticality=Criticality.critical if protected else None,
            source=DeviceSource.imported,
            lifecycle_status=LifecycleStatus.shutdown if stopped else LifecycleStatus.active,
        )

        for i, addr in enumerate(extract_ips(col(r, "ĐỊA CHỈ IP"))):
            attach_ip(cache, dev, addr, primary=(i == 0), src="3100")
        n += 1

    db.commit()
    return n


def import_vm(db, path: str) -> int:
    """File Thống kê VM — cấu hình phần cứng và người yêu cầu."""
    cache = Cache(db)
    n = 0
    seen: dict[str, str] = {}

    for r in read_table(path):
        name = col(r, "Name")
        if not name:
            continue

        norm = normalize_name(name)
        ips = extract_ips(col(r, "IP_Address"))

        if norm in seen and ips and seen[norm] != ips[0]:
            # Cùng tên nhưng khác IP: gần như chắc chắn là hai máy khác nhau bị
            # đặt trùng tên. Vẫn nhập cả hai địa chỉ để không mất dữ liệu, và
            # báo cho người xử lý tách ra.
            REVIEW_ROWS.append({
                "issue": "TÊN TRÙNG nhưng khác IP — có thể là hai máy khác nhau",
                "value": f"{seen[norm]} và {ips[0]}", "context": f"VM/{norm}",
            })
        if ips:
            seen.setdefault(norm, ips[0])

        dept = cache.dept(col(r, "Department"))
        power = col(r, "PowerState").lower()
        requester = normalize_email(col(r, "Requester"))

        dev = upsert_device(
            cache, name,
            device_type=DeviceType.vm,
            cpu_cores=parse_int(col(r, "CPU_Cores")),
            ram_gb=parse_size(col(r, "Ram_GB")),
            disk_gb=parse_size(col(r, "Disk_GB")),
            power_state=(
                PowerState.on if "on" in power
                else PowerState.off if "off" in power
                else PowerState.unknown
            ),
            department_id=dept.id if dept else None,
            requester_email=requester,
            owner_email=requester,
            ticket_id=extract_ticket(col(r, "ID_Ticket")),
            source=DeviceSource.imported,
            lifecycle_status=LifecycleStatus.active,
        )

        # Cột "Xác nhận tháng 4/2026" là nơi đội đã rà lại hạn dùng gần nhất,
        # nên nó được quyền ghi đè hạn lấy từ file khác.
        confirm = col(r, "Xác nhận tháng 4/2026")
        exp = parse_date(confirm, f"VM/{name}")
        if exp:
            dev.expires_at = exp
        elif confirm and confirm.lower().startswith(("chưa", "chua")):
            REVIEW_ROWS.append({
                "issue": "thiếu hạn dùng (sheet tự khai)",
                "value": " ".join(confirm.split())[:80], "context": f"VM/{name}",
            })

        for i, addr in enumerate(ips):
            attach_ip(cache, dev, addr, primary=(i == 0), src="VM")
        n += 1

    db.commit()
    return n


def import_network(db, path: str) -> int:
    """
    File Network — nguồn IP chính thức.

    Cột USER và PASS bị tách ra file riêng, KHÔNG bao giờ ghi vào DB.
    """
    cache = Cache(db)
    n = 0
    for r in read_table(path):
        # Tên cột trong sheet gõ thiếu dấu hỏi ở "CHỈ" — nhận cả hai cách viết.
        ips = extract_ips(col(r, "LIST ĐỊA CHI IP", "LIST ĐỊA CHỈ IP"))
        name = col(r, "THIẾT BỊ ĐANG SỬ DỤNG")
        if not ips:
            continue

        if not name:
            # IP đã liệt kê trong sheet nhưng chưa gán thiết bị -> giữ free.
            # Vẫn tạo dòng để bản đồ IP phản ánh đúng dải đã được khai báo.
            for addr in ips:
                if addr in cache.ips:
                    continue
                subnet = cache.subnet_for(addr)
                if not subnet:
                    continue
                ip = IPAddress(subnet_id=subnet.id, address=addr)
                ip.sync_int()
                cache.db.add(ip)
                cache.ips[addr] = ip
            continue

        dept = cache.dept(col(r, "ĐƠN VỊ"))
        proj = cache.project(col(r, "DỰ ÁN"), dept)
        status = col(r, "TRẠNG THÁI").lower()
        stopped = "stop" in status or "close" in name.lower()

        dev = upsert_device(
            cache, name,
            device_type=DeviceType.vm,
            department_id=dept.id if dept else None,
            project_id=proj.id if proj else None,
            ticket_id=extract_ticket(col(r, "GHI CHÚ")),
            expires_at=parse_date(col(r, "Date"), f"network/{name[:40]}"),
            source=DeviceSource.imported,
            power_state=(
                PowerState.on if "running" in status
                else PowerState.off if stopped
                else PowerState.unknown
            ),
            lifecycle_status=LifecycleStatus.shutdown if stopped else LifecycleStatus.active,
        )

        # --- Secret: tách riêng, tuyệt đối không vào DB ---
        user, pw = col(r, "USER"), col(r, "PASS")
        # "dùng key ssh" là ghi chú về phương thức, không phải mật khẩu.
        if pw and "key ssh" not in pw.lower():
            VAULT_ROWS.append({
                "vault_path": f"secret/data/vm/{normalize_name(name).lower()}",
                "device": normalize_name(name),
                "ip": ips[0],
                "username": user,
                "secret": pw,
            })

        for i, addr in enumerate(ips):
            attach_ip(cache, dev, addr, primary=(i == 0), src="network")
        n += 1

    db.commit()
    return n


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def write_csv(path: str, rows_: list[dict], fields: list[str]) -> None:
    if not rows_:
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows_)


def main() -> None:
    ap = argparse.ArgumentParser(description="Import 3 sheet vào SysOps Portal")
    ap.add_argument("--physical", help="CSV file 3100 (server vật lý)")
    ap.add_argument("--vm", help="CSV file Thống kê VM")
    ap.add_argument("--network", help="CSV file Network (IP)")
    ap.add_argument("--create-tables", action="store_true",
                    help="chỉ dùng ở dev; production đã có alembic")
    args = ap.parse_args()

    if args.create_tables:
        Base.metadata.create_all(engine)

    db = SessionLocal()
    if db.scalar(select(Subnet)) is None:
        raise SystemExit(
            "Chưa khai báo dải mạng nào. Tạo subnet trước khi import:\n"
            "  python scripts/declare_subnets.py"
        )

    # Thứ tự bắt buộc: vật lý -> VM -> network.
    # File trước ghi trường nào thì file sau không ghi đè, nên nguồn đáng tin
    # hơn phải chạy trước: 3100 có mã tài sản, VM có cấu hình phần cứng lấy từ
    # vCenter, network chỉ đáng tin về chuyện IP nào đang được dùng.
    if args.physical:
        print(f"  server vật lý : {import_physical(db, args.physical)} dòng")
    if args.vm:
        print(f"  thống kê VM   : {import_vm(db, args.vm)} dòng")
    if args.network:
        print(f"  network/IP    : {import_network(db, args.network)} dòng")

    write_csv("needs_review.csv", REVIEW_ROWS, ["issue", "value", "context"])
    write_csv("vault_import.csv", VAULT_ROWS,
              ["vault_path", "device", "ip", "username", "secret"])

    print()
    print(f"Cần review thủ công : {len(REVIEW_ROWS)} dòng -> needs_review.csv")
    print(f"Secret cần nạp Vault: {len(VAULT_ROWS)} dòng -> vault_import.csv")
    if VAULT_ROWS:
        print()
        print("!! vault_import.csv chứa mật khẩu dạng rõ.")
        print("   1) Nạp vào Vault:  vault kv put -mount=secret ...")
        print("   2) Xoá file này bằng shred/sdelete")
        print("   3) Xoá cột USER/PASS khỏi Google Sheet, kể cả version history")
        print("   4) ĐỔI toàn bộ mật khẩu vừa lộ — chúng đã nằm trong file xuất")
    db.close()


if __name__ == "__main__":
    main()
