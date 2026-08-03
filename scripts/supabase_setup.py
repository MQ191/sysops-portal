"""
Kết nối Supabase và chạy migration.

    python scripts/supabase_setup.py --check     # chỉ kiểm tra kết nối
    python scripts/supabase_setup.py --migrate   # chạy alembic upgrade head
    python scripts/supabase_setup.py --migrate --seed   # kèm dữ liệu mẫu

Mật khẩu KHÔNG bao giờ được truyền qua tham số dòng lệnh (nó sẽ nằm trong
lịch sử shell và trong danh sách tiến trình). Script chỉ đọc DATABASE_URL từ
file .env hoặc biến môi trường, và mọi thứ in ra đều đã che phần mật khẩu.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load_dotenv(path: Path) -> dict[str, str]:
    """Đọc .env tối giản — không thêm phụ thuộc chỉ để làm việc này."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def mask(url: str) -> str:
    """Che mật khẩu trước khi in ra màn hình hoặc log."""
    return re.sub(r"(://[^:/@]+:)[^@]*(@)", r"\1***\2", url)


def resolve_url() -> str:
    env = load_dotenv(ROOT / ".env")
    url = os.getenv("DATABASE_URL") or env.get("DATABASE_URL", "")
    if not url:
        raise SystemExit(
            "Chưa có DATABASE_URL.\n"
            "  1) Mở Supabase Dashboard > Connect > ORMs/SQLAlchemy\n"
            "  2) Copy chuỗi kết nối, dán vào file .env ở thư mục gốc dự án:\n"
            "     DATABASE_URL=postgresql+psycopg://postgres.<ref>:<mat-khau>@<pooler-host>:5432/postgres?sslmode=require\n"
            "  3) Chạy lại lệnh này."
        )

    # Supabase đưa chuỗi dạng postgresql:// — SQLAlchemy cần biết driver nào.
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)

    if "sslmode" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"

    if "supabase" in url and ":6543" in url:
        print(
            "LƯU Ý: cổng 6543 là transaction pooler — không chạy được DDL của\n"
            "       Alembic một cách tin cậy. Đổi sang cổng 5432 (session\n"
            "       pooler / direct connection) để migrate."
        )
    return url


def check(url: str) -> None:
    from sqlalchemy import create_engine, text

    print(f"Kết nối: {mask(url)}")
    engine = create_engine(url, future=True, pool_pre_ping=True)
    with engine.connect() as conn:
        ver = conn.execute(text("SELECT version()")).scalar_one()
        db = conn.execute(text("SELECT current_database()")).scalar_one()
        user = conn.execute(text("SELECT current_user")).scalar_one()
        tables = (
            conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema='public' ORDER BY table_name"
                )
            )
            .scalars()
            .all()
        )
        gist = conn.execute(
            text("SELECT count(*) FROM pg_extension WHERE extname='btree_gist'")
        ).scalar_one()

    print(f"  OK · {ver.split(',')[0]}")
    print(f"  database={db} user={user}")
    print(f"  btree_gist: {'đã bật' if gist else 'chưa bật (index GiST sẽ bị bỏ qua)'}")
    print(f"  bảng trong schema public ({len(tables)}): {', '.join(tables) or '(trống)'}")


def migrate(url: str) -> None:
    print("\nChạy: alembic upgrade head")
    env = dict(os.environ, DATABASE_URL=url, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env)
    if r.returncode:
        raise SystemExit(f"Migration thất bại (exit {r.returncode})")
    print("Migration xong.")


def seed(url: str) -> None:
    print("\nNạp dữ liệu mẫu (seed_demo.py)")
    print("CẢNH BÁO: seed_demo xoá sạch mọi bảng trước khi nạp lại.")
    if input("  Gõ 'xoa' để xác nhận: ").strip().lower() != "xoa":
        print("  Bỏ qua seed.")
        return
    env = dict(os.environ, DATABASE_URL=url, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, "seed_demo.py"], cwd=ROOT, env=env)
    if r.returncode:
        raise SystemExit(f"Seed thất bại (exit {r.returncode})")


def main() -> None:
    ap = argparse.ArgumentParser(description="Thiết lập Supabase cho SysOps Portal")
    ap.add_argument("--check", action="store_true", help="kiểm tra kết nối")
    ap.add_argument("--migrate", action="store_true", help="chạy alembic upgrade head")
    ap.add_argument("--seed", action="store_true", help="nạp dữ liệu mẫu (xoá sạch trước)")
    args = ap.parse_args()

    if not (args.check or args.migrate or args.seed):
        ap.print_help()
        return

    url = resolve_url()
    check(url)
    if args.migrate:
        migrate(url)
        check(url)
    if args.seed:
        seed(url)


if __name__ == "__main__":
    main()
