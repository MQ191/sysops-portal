"""
SysOps Portal — engine & session
================================

Tách khỏi app.py có chủ đích: trước đây `importer.py` và `celery_app.py`
phải `from app import SessionLocal`, tức là dựng cả FastAPI app chỉ để lấy
một session DB. Điều đó tạo vòng phụ thuộc và khiến worker Celery nạp toàn
bộ tầng HTTP mà nó không bao giờ dùng.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sysops.db")

IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=not IS_SQLITE,
    connect_args={"check_same_thread": False} if IS_SQLITE else {},
)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def get_db():
    """Dependency FastAPI. Rollback khi có lỗi để session không rò trạng thái bẩn."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def session_scope() -> Session:
    """Dùng trong Celery task và script CLI, nơi không có dependency injection."""
    return SessionLocal()
