"""
Khai báo các dải mạng trước khi import.

    python scripts/declare_subnets.py --dry-run
    python scripts/declare_subnets.py

Danh sách dưới đây suy ra từ chính 3 file CSV (xem scripts/analyze_sheets.py),
chỉ lấy những dải thực sự có thiết bị. Các dải lẻ 1–2 địa chỉ cố ý KHÔNG khai
báo: IP thuộc dải chưa khai sẽ rơi vào needs_review.csv để đội System quyết
định, thay vì bị nuốt im lặng.

GATEWAY ĐỂ TRỐNG CÓ CHỦ ĐÍCH
----------------------------
Sheet không ghi gateway ở đâu cả. Đoán bừa `.254` hay `.1` là nguy hiểm: nếu
đoán sai, thuật toán sẽ coi gateway thật là địa chỉ trống và đem cấp cho VM.
Để trống thì địa chỉ đó chỉ đơn giản không được ưu tiên, không ai bị mất mạng.

Đội System điền gateway sau bằng:
    PATCH /api/v1/subnets/<cidr>   (hoặc sửa trực tiếp trong DB)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from sqlalchemy import select  # noqa: E402

from db import SessionLocal  # noqa: E402
from models import Subnet  # noqa: E402

# Bốn địa chỉ đầu mỗi dải bị bỏ trống trong sheet network (10.0.76.1–.4 không
# có thiết bị nào) — đó là dấu hiệu vùng hạ tầng: gateway, firewall, switch.
INFRA_FIRST_4 = [{"start": None, "end": None, "reason": "gateway, firewall, switch quản trị"}]


def infra(prefix: str, lo: int = 1, hi: int = 4) -> list[dict]:
    return [{
        "start": f"{prefix}.{lo}",
        "end": f"{prefix}.{hi}",
        "reason": "vùng hạ tầng mạng (gateway/firewall/switch)",
    }]


SUBNETS = [
    # (cidr, tên, purpose, reserved_ranges, ghi chú vì sao khai báo)
    (
        "10.0.76.0/23", "Dải VM dự án chính", "vm", infra("10.0.76"),
        "563 IP trong file network — dải chính đang cấp cho dự án",
    ),
    (
        "10.0.64.0/24", "Dải VM hạ tầng & OPMS", "vm", infra("10.0.64", 1, 10),
        "282 IP — nhiều VM hạ tầng, DC/DHCP nằm ở .2-.5",
    ),
    (
        "10.0.65.0/24", "Dải VM lab & template", "vm", infra("10.0.65", 1, 5),
        "235 IP — server template và môi trường lab",
    ),
    (
        "172.16.0.0/24", "Dải quản trị ESXi", "management", infra("172.16.0", 1, 9),
        "11 IP — host ESXi, OpenVPN, backup. Chạm nhầm là mất cả cụm",
    ),
    (
        "192.168.6.0/24", "Dải hạ tầng cũ", "server", [],
        "11 IP — proxy, kế toán, OPMS đời cũ",
    ),
    (
        "10.0.83.0/24", "Dải TCO", "vm", [],
        "5 IP — cụm TCO Alma Linux",
    ),
    (
        "10.0.2.0/24", "Dải server vật lý", "server", [],
        "3 IP — firewall pfSense và host ESXi vật lý",
    ),
    (
        "10.0.66.0/24", "Dải OPMS/Redmine", "vm", [],
        "3 IP — OPMS live và git master",
    ),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="chỉ in ra, không ghi")
    args = ap.parse_args()

    db = SessionLocal()
    existing = {s.cidr for s in db.scalars(select(Subnet)).all()}

    created = skipped = 0
    for cidr, name, purpose, reserved, why in SUBNETS:
        if cidr in existing:
            print(f"  bỏ qua  {cidr:<16} (đã có)")
            skipped += 1
            continue

        print(f"  tạo     {cidr:<16} {name}")
        print(f"          {why}")
        if reserved:
            print(f"          dành riêng: {reserved[0]['start']}–{reserved[0]['end']}")
        print("          gateway: (để trống — đội System điền sau)")

        if not args.dry_run:
            db.add(Subnet(
                cidr=cidr,
                name=name,
                purpose=purpose,
                gateway=None,
                reserved_ranges=reserved,
                allocation_policy="lowest_first",
                cooldown_days=14,
                scan_staleness_hours=12,
            ))
        created += 1

    if args.dry_run:
        print(f"\n[DRY-RUN] sẽ tạo {created} dải, bỏ qua {skipped}. Chưa ghi gì.")
    else:
        db.commit()
        print(f"\nĐã tạo {created} dải mạng, bỏ qua {skipped} dải đã có.")
        print(
            "\nLƯU Ý: mọi dải đang thiếu gateway. Cho tới khi điền, canary của\n"
            "scanner phải dựa vào các VM đang bật thay vì ping gateway."
        )
    db.close()


if __name__ == "__main__":
    main()
