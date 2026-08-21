"""
Lịch chạy job nền.

Tần suất được chọn theo nguyên tắc: dữ liệu càng ảnh hưởng tới quyết định
cấp phát thì càng phải tươi. IP scan quan trọng hơn vCenter sync vì
sai sót về IP gây sự cố mạng ngay lập tức.
"""

from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

import services
from db import SessionLocal

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery("sysops", broker=REDIS_URL, backend=REDIS_URL)
celery.conf.timezone = "Asia/Ho_Chi_Minh"

SUBNETS = os.getenv("SCAN_SUBNETS", "10.0.76.0/24,10.0.64.0/24,10.0.65.0/24,172.16.0.0/24").split(
    ","
)


@celery.task(name="scan_all_subnets")
def scan_all_subnets(method: str = "icmp") -> list[dict]:
    db = SessionLocal()
    try:
        return [services.scan_subnet(db, c.strip(), method) for c in SUBNETS if c.strip()]
    finally:
        db.close()


@celery.task(name="sync_vcenter")
def sync_vcenter_task() -> dict:
    db = SessionLocal()
    try:
        inv = services.fetch_vcenter_inventory(
            host=os.environ["VCENTER_HOST"],
            user=os.environ["VCENTER_USER"],
            password=os.environ["VCENTER_PASSWORD"],
            # Đồng bộ với routers/admin.py: trước đây job định kỳ này luôn
            # chạy insecure=True một cách âm thầm (tham số mặc định cũ), tức
            # là sync 6 giờ/lần không bao giờ xác thực chứng chỉ TLS của
            # vCenter mà không ai biết.
            insecure=os.getenv("VCENTER_INSECURE", "false").lower() == "true",
        )
        return services.sync_vcenter(db, inv)
    finally:
        db.close()


@celery.task(name="lifecycle_tick")
def lifecycle_tick_task() -> dict:
    db = SessionLocal()
    try:
        return services.lifecycle_tick(db, send_email=_send_email)
    finally:
        db.close()


@celery.task(name="maintenance")
def maintenance_task() -> dict:
    """Dọn giữ chỗ hết hạn và IP hết thời gian cách ly."""
    from routers.admin import expire_quarantine, expire_reservations

    db = SessionLocal()
    try:
        return {
            "reservations": expire_reservations(db),
            "quarantine": expire_quarantine(db),
        }
    finally:
        db.close()


def _send_email(to: list[str], subject: str, body: str) -> None:
    import smtplib
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST")
    if not host:
        print(f"[DRY-RUN EMAIL] {to} :: {subject}")
        return

    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", "sysops@ntq-solution.com.vn")
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "25"))) as s:
        s.send_message(msg)


celery.conf.beat_schedule = {
    # Giữ chỗ chỉ sống 30 phút -> phải dọn thường xuyên
    "maintenance-every-minute": {
        "task": "maintenance",
        "schedule": crontab(minute="*"),
    },
    # ICMP sweep 1 lần/ngày lúc 00:00 đêm: giảm tải mạng giờ làm việc
    "icmp-scan": {
        "task": "scan_all_subnets",
        "schedule": crontab(minute=0, hour=0),
        "args": ("icmp",),
    },
    # ARP quét 1 lần/ngày lúc 00:30 đêm (sau khi ICMP sweep xong)
    "arp-scan": {
        "task": "scan_all_subnets",
        "schedule": crontab(minute=30, hour=0),
        "args": ("arp",),
    },
    "vcenter-sync": {
        "task": "sync_vcenter",
        "schedule": crontab(minute=30, hour="*/6"),
    },
    # Nhắc hạn gửi 8h sáng để người nhận đọc trong giờ làm
    "lifecycle": {
        "task": "lifecycle_tick",
        "schedule": crontab(minute=0, hour=8),
    },
}
