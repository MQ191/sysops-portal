"""
Cấu hình chung cho test.

Dùng MỘT file SQLite tạm cho toàn phiên chạy test, dọn bảng giữa các test
bằng drop_all/create_all thay vì reload module: SQLAlchemy declarative
registry không chịu được việc định nghĩa lại cùng một lớp nhiều lần trong
một tiến trình (quan hệ dạng chuỗi như "CredentialRef" sẽ không tra cứu
được registry cũ, sinh lỗi mapper không liên quan gì tới code đang test).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Phải đặt TRƯỚC lần import app/db đầu tiên trong cả phiên test.
#
# Bộ test XOÁ SẠCH mọi bảng giữa các bài, nên không bao giờ được tự động chạy
# trên DATABASE_URL của môi trường thật. Muốn test trên Postgres thì phải khai
# báo riêng TEST_DATABASE_URL — biến này không trùng tên với biến production,
# nên không có cách nào vô tình trỏ vào cơ sở dữ liệu đang dùng.
#
# (Trước đây dòng này ghi đè DATABASE_URL vô điều kiện, khiến job test-postgres
#  trong CI âm thầm chạy trên SQLite — tức là bài kiểm tra Postgres chưa từng
#  thực sự chạy lần nào.)
_TEST_DB = ROOT / "tests" / "_test.db"
_EXPLICIT = os.getenv("TEST_DATABASE_URL", "").strip()
os.environ["DATABASE_URL"] = _EXPLICIT or f"sqlite:///{_TEST_DB}"

if _EXPLICIT:
    print(f"\n[conftest] Chạy test trên: {_EXPLICIT.split('@')[-1] or _EXPLICIT}")

os.environ["AUTH_MODE"] = "dev"
os.environ["SCANNER_ENABLED"] = "false"
os.environ.setdefault("AUTO_CREATE_TABLES", "false")  # test tự quản lý schema

# AUTH_MODE=dev bị auth.verify_startup_config chặn khi DB không phải SQLite.
# Trong test thì chấp nhận được vì đây là DB dùng-một-lần, nhưng phải nói rõ
# ràng là ta đang cố ý bỏ qua bất biến đó.
if _EXPLICIT and not _EXPLICIT.startswith("sqlite"):
    os.environ["ALLOW_DEV_AUTH_ON_NON_SQLITE"] = "true"
    # noqa: S105 — không phải secret thật; chỉ để verify_startup_config() chịu
    # khởi động. Phiên đăng nhập không được test nào dùng tới.
    os.environ["SESSION_SECRET"] = "chi-dung-trong-test"  # noqa: S105


@pytest.fixture()
def client():
    """TestClient với schema sạch cho mỗi test."""
    import db as db_mod
    import models

    models.Base.metadata.drop_all(db_mod.engine)
    models.Base.metadata.create_all(db_mod.engine)

    from fastapi.testclient import TestClient

    import app as app_mod

    with TestClient(app_mod.app) as c:
        c.app_module = app_mod
        c.db_module = db_mod
        yield c

    from sqlalchemy.orm import close_all_sessions

    close_all_sessions()


def pytest_sessionfinish(session, exitstatus):
    try:
        _TEST_DB.unlink(missing_ok=True)
    except OSError:
        pass
