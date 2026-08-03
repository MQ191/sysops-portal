"""
Khảo sát 3 file CSV xuất từ Google Sheet TRƯỚC khi import.

Chạy trước importer.py để biết chính xác sẽ nhập được gì, cái gì phải review,
và những dải mạng nào cần khai báo. Không ghi vào database.

    python scripts/analyze_sheets.py --network a.csv --vm b.csv --physical c.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Giá trị người nhập dùng để nói "không có hạn dùng" — không phải ngày, và
# cũng không phải dữ liệu thiếu. Ghi nhận riêng thay vì ném vào review.
NO_EXPIRY = {"no expire", "no date", "không có date", "khong co date", "lqd"}


def read_rows(path: Path) -> tuple[list[str], list[dict]]:
    """
    Đọc CSV có hàng tiêu đề nằm lẫn đâu đó trong 10 dòng đầu.

    Sheet thật hay có dòng tiêu đề trang trí, dòng trống, chú thích ở trên —
    csv.DictReader mặc định sẽ lấy nhầm dòng đầu tiên làm header.
    """
    raw = list(csv.reader(path.open(encoding="utf-8-sig", newline="")))
    best_i, best_score = 0, -1
    for i, row in enumerate(raw[:10]):
        filled = [c.strip() for c in row if c.strip()]
        # Hàng tiêu đề: nhiều ô có chữ, và không ô nào trông giống địa chỉ IP.
        score = len(filled) - 10 * sum(bool(IP_RE.search(c)) for c in filled)
        if score > best_score:
            best_i, best_score = i, score
    header = [c.strip() for c in raw[best_i]]
    rows = [dict(zip(header, r, strict=False)) for r in raw[best_i + 1 :]]
    return header, rows


def get(row: dict, *names: str) -> str:
    """Lấy giá trị theo nhiều tên cột khả dĩ (sheet có lỗi chính tả)."""
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n.lower():
                return (v or "").strip()
    return ""


def ips_in(text: str) -> list[str]:
    out = []
    for m in IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(m)
            out.append(m)
        except ValueError:
            pass
    return out


def classify_date(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return "trống"
    low = raw.lower()
    if low in NO_EXPIRY or "no expire" in low:
        return "không hết hạn"
    if low.startswith("chưa") or "chưa có" in low:
        return "khai là chưa có"
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", raw)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > 12 or b > 12:
            return "rõ ràng"
        return "NHẬP NHẰNG dd/mm hay mm/dd"
    if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
        return "rõ ràng"
    return "không đọc được"


def section(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def analyze(path: Path, kind: str, cols: dict) -> dict:
    header, rows = read_rows(path)
    section(f"{kind}  —  {path.name}")
    print(f"Hàng tiêu đề nhận diện được: {[h for h in header if h][:9]}")
    print(f"Số dòng dữ liệu: {len(rows)}")

    named, all_ips, dates = 0, [], Counter()
    secrets_found, dup_names, name_seen = [], [], defaultdict(list)
    multi_ip, ip_in_name = [], []

    for i, r in enumerate(rows, start=2):
        name = get(r, *cols["name"])
        ipcell = get(r, *cols["ip"])
        if not name and not ipcell:
            continue

        cell_ips = ips_in(ipcell)
        all_ips += cell_ips
        if len(cell_ips) > 1:
            multi_ip.append((name, cell_ips))

        if name:
            named += 1
            name_seen[name].append(i)
            if ips_in(name):
                ip_in_name.append((i, name))

        if cols.get("date"):
            dates[classify_date(get(r, *cols["date"]))] += 1

        if cols.get("user"):
            u, p = get(r, *cols["user"]), get(r, *cols["pass"])
            # "dùng key ssh" là ghi chú, không phải mật khẩu.
            if p and "key ssh" not in p.lower():
                secrets_found.append((name or f"dòng {i}", u))

    dup_names = {n: v for n, v in name_seen.items() if len(v) > 1}

    print(f"Dòng có tên thiết bị: {named}")
    print(f"Địa chỉ IP tìm thấy : {len(all_ips)} ({len(set(all_ips))} duy nhất)")

    if dates:
        print("\nHạn dùng:")
        for k, v in dates.most_common():
            flag = "  <-- CẦN NGƯỜI XỬ LÝ" if "NHẬP NHẰNG" in k or k == "không đọc được" else ""
            print(f"   {k:<32} {v:>4}{flag}")

    if secrets_found:
        print(f"\n!! MẬT KHẨU DẠNG RÕ: {len(secrets_found)} dòng -> phải nạp Vault, KHÔNG vào DB")
        for n, u in secrets_found[:6]:
            print(f"   {n[:44]:<44} user={u}")
        if len(secrets_found) > 6:
            print(f"   ... và {len(secrets_found) - 6} dòng nữa")

    if dup_names:
        print(f"\n!! TÊN TRÙNG: {len(dup_names)} tên xuất hiện nhiều lần")
        for n, lines in list(dup_names.items())[:5]:
            print(f"   {n[:50]:<50} dòng {lines}")

    if multi_ip:
        print(f"\nDòng có nhiều IP: {len(multi_ip)}")
        for n, ips in multi_ip[:4]:
            print(f"   {n[:40]:<40} {ips}")

    if ip_in_name:
        print(f"\n!! IP NẰM TRONG TÊN (dễ trích nhầm): {len(ip_in_name)}")
        for i, n in ip_in_name[:4]:
            print(f"   dòng {i}: {n[:62]}")

    return {"ips": all_ips, "rows": len(rows), "named": named}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--network")
    ap.add_argument("--vm")
    ap.add_argument("--physical")
    a = ap.parse_args()

    all_ips: list[str] = []

    if a.network:
        r = analyze(Path(a.network), "FILE NETWORK", {
            "name": ["THIẾT BỊ ĐANG SỬ DỤNG"],
            # Sheet gõ thiếu dấu hỏi ở "CHỈ" — chấp nhận cả hai cách viết.
            "ip": ["LIST ĐỊA CHI IP", "LIST ĐỊA CHỈ IP"],
            "date": ["Date"], "user": ["USER"], "pass": ["PASS"],
        })
        all_ips += r["ips"]

    if a.vm:
        r = analyze(Path(a.vm), "FILE THỐNG KÊ VM", {
            "name": ["Name"], "ip": ["IP_Address"],
            "date": ["Xác nhận tháng 4/2026"],
        })
        all_ips += r["ips"]

    if a.physical:
        r = analyze(Path(a.physical), "FILE 3100 (SERVER VẬT LÝ)", {
            "name": ["TÊN SERVER"], "ip": ["ĐỊA CHỈ IP"],
            "date": ["DỰ KIẾN THU HỒI"],
        })
        all_ips += r["ips"]

    # --- Dải mạng cần khai báo ---
    section("DẢI MẠNG CẦN KHAI BÁO TRƯỚC KHI IMPORT")
    by24: Counter = Counter()
    for ip in all_ips:
        by24[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1

    print(f"{'CIDR /24':<20} {'số IP':>6}   ghi chú")
    for cidr, n in sorted(by24.items(), key=lambda kv: -kv[1]):
        note = ""
        if cidr.startswith("10.0.76.") or cidr.startswith("10.0.77."):
            note = "thuộc dải 10.0.76.0/23 trong file network"
        print(f"{cidr:<20} {n:>6}   {note}")

    print(
        "\nIP không thuộc dải nào được khai báo sẽ bị đẩy sang needs_review.csv\n"
        "chứ không bị bỏ im lặng."
    )


if __name__ == "__main__":
    main()
