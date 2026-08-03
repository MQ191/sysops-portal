"""
Xoá mật khẩu dạng rõ khỏi mọi file mà quá trình import đã tạo hoặc đọc.

    python scripts/scrub_secrets.py --dry-run
    python scripts/scrub_secrets.py

Hai việc khác nhau:

  1. `vault_import.csv` — file phái sinh, toàn bộ nội dung là secret.
     Ghi đè bằng dữ liệu ngẫu nhiên rồi xoá.

  2. CSV nguồn — chỉ hai cột USER/PASS là secret, phần còn lại vẫn cần cho
     import. Làm rỗng giá trị trong hai cột đó, giữ nguyên tiêu đề để file
     vẫn đọc được và người xem biết cột đó từng tồn tại.

GIỚI HẠN CẦN BIẾT: ghi đè trước khi xoá chỉ có tác dụng chắc chắn trên ổ cứng
từ. Trên SSD, wear-leveling có thể còn giữ lại bản sao ở khối vật lý khác mà
hệ điều hành không truy cập tới. Vì vậy bước bắt buộc vẫn là ĐỔI MẬT KHẨU —
xoá file chỉ giảm thiệt hại, không đảo ngược việc đã lộ.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent

# Tên cột chứa secret, so sánh không phân biệt hoa thường.
SECRET_COLS = {"user", "pass", "password", "mật khẩu", "mat khau"}

# File phái sinh: xoá hẳn.
DERIVED = [ROOT / "vault_import.csv"]

# CSV nguồn: chỉ làm rỗng cột secret.
SOURCES = [
    ROOT / "data" / "network.csv",
    ROOT / "data" / "vm.csv",
    ROOT / "data" / "physical.csv",
]


def shred(path: Path, dry: bool) -> bool:
    """Ghi đè bằng byte ngẫu nhiên rồi xoá."""
    if not path.exists():
        return False
    size = path.stat().st_size
    if dry:
        print(f"  [DRY] sẽ ghi đè + xoá  {path.name}  ({size} bytes)")
        return True

    with open(path, "r+b") as f:
        for _ in range(3):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    path.unlink()
    print(f"  đã ghi đè 3 lượt rồi xoá  {path.name}  ({size} bytes)")
    return True


def scrub_columns(path: Path, dry: bool, keep_notes: bool = True) -> tuple[int, list[str]]:
    """Làm rỗng giá trị ở các cột secret, giữ nguyên mọi thứ khác."""
    if not path.exists():
        return 0, []

    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        return 0, []

    # Tìm cột secret ở bất kỳ dòng nào trong 10 dòng đầu — tiêu đề của sheet
    # xuất từ Google hay nằm lẫn dưới vài dòng trang trí.
    targets: dict[int, str] = {}
    for row in rows[:10]:
        for j, cell in enumerate(row):
            if cell.strip().lower() in SECRET_COLS:
                targets[j] = cell.strip()
    if not targets:
        return 0, []

    cleared = 0
    for row in rows:
        for j in targets:
            if j < len(row) and row[j].strip():
                # "dùng key ssh" là ghi chú về PHƯƠNG THỨC xác thực, không phải
                # giá trị bí mật — mặc định giữ lại vì nó có ích khi vận hành
                # (biết máy nào dùng key, máy nào còn dùng mật khẩu).
                # Với --clear-notes thì xoá luôn cho sạch tuyệt đối.
                if keep_notes and "key ssh" in row[j].lower():
                    continue
                if row[j].strip().lower() in SECRET_COLS:
                    continue  # đây là chính dòng tiêu đề
                row[j] = ""
                cleared += 1

    if dry:
        print(f"  [DRY] {path.name}: sẽ làm rỗng {cleared} ô ở cột {list(targets.values())}")
        return cleared, list(targets.values())

    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(rows)
    print(f"  {path.name}: đã làm rỗng {cleared} ô ở cột {list(targets.values())}")
    return cleared, list(targets.values())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--clear-notes", action="store_true",
                    help="xoá luôn ghi chú kiểu 'dùng key ssh' trong cột secret")
    ap.add_argument("--also", nargs="*", default=[],
                    help="đường dẫn CSV khác cần làm sạch (ví dụ bản trong Downloads)")
    a = ap.parse_args()

    print("1) File phái sinh — xoá hẳn:")
    n_del = sum(shred(p, a.dry_run) for p in DERIVED)
    if not n_del:
        print("  (không có file nào)")

    print("\n2) CSV nguồn — làm rỗng cột secret:")
    total = 0
    for p in SOURCES + [Path(x) for x in a.also]:
        c, _ = scrub_columns(p, a.dry_run, keep_notes=not a.clear_notes)
        total += c
        if not c and p.exists():
            print(f"  {p.name}: không có cột secret nào")

    print(f"\nTổng: xoá {n_del} file phái sinh, làm rỗng {total} ô mật khẩu.")
    if not a.dry_run:
        print(
            "\nCÒN LẠI NGOÀI TẦM VỚI CỦA SCRIPT NÀY:\n"
            "  · Google Sheet gốc — xoá cột USER/PASS, kể cả version history\n"
            "  · Bản sao đã tải về ở thư mục khác\n"
            "  · Backup/sync của những file trên (OneDrive, Google Drive...)\n"
            "\nVIỆC BẮT BUỘC: đổi toàn bộ mật khẩu đã lộ. Xoá file làm giảm\n"
            "thiệt hại, không đảo ngược được việc chúng đã bị đọc."
        )


if __name__ == "__main__":
    main()
