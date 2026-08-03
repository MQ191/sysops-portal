"""
SysOps Portal — SQLAlchemy models
=================================

Schema portable giữa PostgreSQL (production) và SQLite (dev/test).
Trên Postgres, cột địa chỉ dùng kiểu INET/MACADDR native; trên SQLite
tự động rơi về String nhờ `.with_variant()`.

Cột `address_int` được lưu song song với `address` một cách có chủ đích:
mọi phép so sánh dải và sắp xếp đều chạy trên số nguyên, nhanh và portable,
trong khi `address` giữ dạng người đọc được.
"""

from __future__ import annotations

import enum
import ipaddress
import uuid
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Kiểu portable ------------------------------------------------------------- #
JsonType = JSON().with_variant(JSONB, "postgresql")


class _PgTextType(TypeDecorator):
    """
    Cột dùng kiểu native của Postgres nhưng LUÔN trả về `str` cho Python.

    Vì sao cần: psycopg tự chuyển `INET` thành `ipaddress.IPv4Address` và
    `MACADDR` thành object riêng, trong khi SQLite trả chuỗi. Hệ quả là mọi
    phép tra cứu theo địa chỉ dạng chuỗi đều im lặng trượt trên Postgres:

        known = {ip.address: ...}        # khoá là IPv4Address
        known["10.0.76.5"]               # -> KeyError, không ai báo lỗi

    Đúng chỗ đó là cách bản đồ IP dựng dữ liệu, nên trên Postgres mọi địa chỉ
    sẽ hiện "trống" dù đã cấp, và thuật toán sẽ đem gợi ý IP đang có máy chạy.
    Đây là cùng một họ lỗi với chuyện datetime naive/aware: chỉ lộ ra trên
    dialect thật, còn test SQLite thì xanh hết.

    Ép về `str` ngay tại tầng kiểu dữ liệu, thay vì rải `str()` khắp nơi và
    chỉ cần quên một chỗ là lỗi quay lại.
    """

    impl = String
    cache_ok = True
    pg_type: Any = None

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql" and self.pg_type is not None:
            return dialect.type_descriptor(self.pg_type())
        return dialect.type_descriptor(String(self.impl.length))

    def process_bind_param(self, value, dialect) -> str | None:
        return str(value) if value is not None else None

    def process_result_value(self, value, dialect) -> str | None:
        return str(value) if value is not None else None


class InetStr(_PgTextType):
    impl = String(45)
    cache_ok = True
    pg_type = INET


class MacStr(_PgTextType):
    impl = String(17)
    cache_ok = True
    pg_type = MACADDR


InetType = InetStr()
MacType = MacStr()


class TZDateTime(TypeDecorator):
    """
    Luôn trả về datetime CÓ timezone (UTC), trên mọi dialect.

    Vì sao cần: SQLite không lưu tzinfo, nên `DateTime(timezone=True)` đọc lên
    thành datetime naive. Toàn bộ logic nghiệp vụ so sánh với
    `datetime.now(timezone.utc)` (aware) => `TypeError: can't compare
    offset-naive and offset-aware datetimes`, làm chết đúng tính năng gợi ý IP.

    Sửa ở tầng kiểu dữ liệu thay vì rải `if tzinfo is None` khắp nơi: chỉ cần
    quên một chỗ là lỗi quay lại, và nó chỉ bung ra lúc chạy thật.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # Dữ liệu naive lọt vào => diễn giải là UTC thay vì giờ máy chủ.
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


# Khoá chính tự tăng, portable.
# SQLite chỉ coi `INTEGER PRIMARY KEY` là alias của rowid; `BIGINT PRIMARY KEY`
# thì KHÔNG tự tăng => mọi INSERT thiếu id đều lỗi NOT NULL. Trên Postgres vẫn
# giữ BIGSERIAL vì scan_result sẽ vượt 2^31 dòng.
AutoBigIntPK = BigInteger().with_variant(Integer, "sqlite")


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Enum
# --------------------------------------------------------------------------- #


class IPStatus(str, enum.Enum):
    free = "free"
    reserved = "reserved"
    allocated = "allocated"
    quarantine = "quarantine"
    blocked = "blocked"
    conflict = "conflict"


class DeviceType(str, enum.Enum):
    vm = "vm"
    physical_server = "physical_server"
    workstation = "workstation"
    network_device = "network_device"
    appliance = "appliance"


class PowerState(str, enum.Enum):
    on = "on"
    off = "off"
    suspended = "suspended"
    unknown = "unknown"


class LifecycleStatus(str, enum.Enum):
    requested = "requested"
    active = "active"
    expiring = "expiring"
    pending_reclaim = "pending_reclaim"
    shutdown = "shutdown"
    archived = "archived"


class DeviceSource(str, enum.Enum):
    manual = "manual"
    vcenter = "vcenter"
    discovered = "discovered"
    imported = "imported"


class Criticality(str, enum.Enum):
    low = "low"
    normal = "normal"
    critical = "critical"


class DriftType(str, enum.Enum):
    ghost_vm = "ghost_vm"
    unregistered_vm = "unregistered_vm"
    shadow_ip = "shadow_ip"
    stale_allocation = "stale_allocation"
    spec_mismatch = "spec_mismatch"
    missing_owner = "missing_owner"
    missing_expiry = "missing_expiry"
    expired = "expired"
    ip_conflict = "ip_conflict"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class DriftStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    ignored = "ignored"


DRIFT_SEVERITY: dict[DriftType, Severity] = {
    DriftType.ip_conflict: Severity.critical,
    DriftType.unregistered_vm: Severity.high,
    DriftType.shadow_ip: Severity.high,
    DriftType.expired: Severity.high,
    DriftType.ghost_vm: Severity.medium,
    DriftType.stale_allocation: Severity.medium,
    DriftType.missing_owner: Severity.medium,
    DriftType.missing_expiry: Severity.medium,
    DriftType.spec_mismatch: Severity.low,
}


# --------------------------------------------------------------------------- #
# Tổ chức
# --------------------------------------------------------------------------- #


class Department(Base):
    __tablename__ = "department"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    code: Mapped[str] = mapped_column(String(32), unique=True)  # SDC1, SDC11, NES...
    name: Mapped[str | None] = mapped_column(String(128))
    manager_email: Mapped[str | None] = mapped_column(String(255))


class Project(Base):
    __tablename__ = "project"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str | None] = mapped_column(String(255))
    department_id: Mapped[str | None] = mapped_column(ForeignKey("department.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


# --------------------------------------------------------------------------- #
# IPAM
# --------------------------------------------------------------------------- #


class Subnet(Base):
    __tablename__ = "subnet"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128), default="")
    gateway: Mapped[str | None] = mapped_column(InetType)
    purpose: Mapped[str] = mapped_column(String(32), default="vm")
    default_department_id: Mapped[str | None] = mapped_column(ForeignKey("department.id"))
    dhcp_range_start: Mapped[str | None] = mapped_column(InetType)
    dhcp_range_end: Mapped[str | None] = mapped_column(InetType)
    reserved_ranges: Mapped[list | None] = mapped_column(JsonType, default=list)
    allocation_policy: Mapped[str] = mapped_column(String(32), default="lowest_first")
    cooldown_days: Mapped[int] = mapped_column(Integer, default=14)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # --- Sức khoẻ scanner (dead man switch) ---
    # Chỉ được cập nhật khi một lượt quét ĐI QUA canary, tức là ta có bằng chứng
    # scanner thực sự nhìn thấy được dải này. Nếu mốc này cũ, confidence phải
    # sụp xuống thay vì trôi lên — xem allocator._confidence.
    last_scan_ok_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    scan_staleness_hours: Mapped[int] = mapped_column(Integer, default=12)

    ips: Mapped[list[IPAddress]] = relationship(back_populates="subnet")

    @property
    def network(self):
        return ipaddress.ip_network(self.cidr, strict=False)


class IPAddress(Base):
    __tablename__ = "ip_address"
    __table_args__ = (
        UniqueConstraint("address", name="uq_ip_address"),
        Index("ix_ip_subnet_status", "subnet_id", "status"),
        Index("ix_ip_addr_int", "address_int"),
        Index("ix_ip_status_released", "status", "released_at"),
        # Index GiST trên INET — nền tảng của truy vấn theo dải
        # (`WHERE address <<= '10.0.76.0/24'`), TECHNICAL-SPEC §10.
        #
        # Khai báo ở model chứ không viết SQL thô trong migration: index tạo
        # bằng SQL thô không nằm trong metadata, nên `alembic check` coi nó là
        # thừa và lần autogenerate sau sẽ sinh lệnh XOÁ nó đi.
        # `postgresql_using`/`postgresql_ops` bị bỏ qua trên SQLite, ở đó nó
        # thành index thường — vô hại.
        Index(
            "ix_ip_address_gist",
            "address",
            postgresql_using="gist",
            postgresql_ops={"address": "inet_ops"},
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    subnet_id: Mapped[str] = mapped_column(ForeignKey("subnet.id"))
    address: Mapped[str] = mapped_column(InetType)
    address_int: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[IPStatus] = mapped_column(
        Enum(IPStatus, native_enum=False), default=IPStatus.free
    )

    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(MacType)

    last_seen_alive_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    last_seen_dead_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    consecutive_dead_scans: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_alive_scans: Mapped[int] = mapped_column(Integer, default=0)
    scans_last_7d: Mapped[int] = mapped_column(Integer, default=0)

    released_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    conflict_count: Mapped[int] = mapped_column(Integer, default=0)
    ever_assigned: Mapped[bool] = mapped_column(Boolean, default=False)

    note: Mapped[str | None] = mapped_column(Text)

    subnet: Mapped[Subnet] = relationship(back_populates="ips")
    assignments: Mapped[list[IPAssignment]] = relationship(
        back_populates="ip", cascade="all, delete-orphan"
    )

    def sync_int(self) -> None:
        self.address_int = int(ipaddress.ip_address(self.address))


class IPReservation(Base):
    """Soft-lock có TTL — chống hai kỹ sư cùng nhận một IP."""

    __tablename__ = "ip_reservation"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip_address_id: Mapped[str] = mapped_column(ForeignKey("ip_address.id"), unique=True)
    token: Mapped[str] = mapped_column(String(36), unique=True, default=_uuid)
    reserved_by: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #


class Device(Base):
    __tablename__ = "device"
    __table_args__ = (
        Index("ix_device_lifecycle", "lifecycle_status", "expires_at"),
        Index("ix_device_dept", "department_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_code: Mapped[str | None] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    aliases: Mapped[list | None] = mapped_column(JsonType, default=list)

    device_type: Mapped[DeviceType] = mapped_column(
        Enum(DeviceType, native_enum=False), default=DeviceType.vm
    )
    hypervisor_host: Mapped[str | None] = mapped_column(String(255))
    vcenter_uuid: Mapped[str | None] = mapped_column(String(64), unique=True)
    os: Mapped[str | None] = mapped_column(String(128))

    cpu_cores: Mapped[int | None] = mapped_column(Integer)
    ram_gb: Mapped[float | None] = mapped_column(Numeric(10, 2))
    disk_gb: Mapped[float | None] = mapped_column(Numeric(10, 2))
    power_state: Mapped[PowerState] = mapped_column(
        Enum(PowerState, native_enum=False), default=PowerState.unknown
    )

    department_id: Mapped[str | None] = mapped_column(ForeignKey("department.id"))
    project_id: Mapped[str | None] = mapped_column(ForeignKey("project.id"))
    owner_email: Mapped[str | None] = mapped_column(String(255))
    requester_email: Mapped[str | None] = mapped_column(String(255))

    ticket_id: Mapped[str | None] = mapped_column(String(32))
    provisioned_at: Mapped[date | None] = mapped_column(Date)
    expires_at: Mapped[date | None] = mapped_column(Date)

    lifecycle_status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, native_enum=False), default=LifecycleStatus.active
    )
    source: Mapped[DeviceSource] = mapped_column(
        Enum(DeviceSource, native_enum=False), default=DeviceSource.manual
    )
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality, native_enum=False), default=Criticality.normal
    )
    is_protected: Mapped[bool] = mapped_column(Boolean, default=False)

    note: Mapped[str | None] = mapped_column(Text)
    last_synced_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow, onupdate=_utcnow)

    department: Mapped[Department | None] = relationship()
    project: Mapped[Project | None] = relationship()
    assignments: Mapped[list[IPAssignment]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    credentials: Mapped[list[CredentialRef]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    TICKET_BASE = "https://itservices.ntq.solutions/front/ticket.form.php?id="

    @property
    def ticket_url(self) -> str | None:
        return f"{self.TICKET_BASE}{self.ticket_id}" if self.ticket_id else None

    @property
    def days_to_expiry(self) -> int | None:
        if not self.expires_at:
            return None
        return (self.expires_at - date.today()).days


class IPAssignment(Base):
    """
    Bảng nối riêng vì một device có thể mang nhiều IP
    (file 3100 có server dùng cả 172.16.0.20 và 10.0.64.20).
    """

    __tablename__ = "ip_assignment"
    __table_args__ = (
        # Chốt chặn cuối ở tầng DB: một IP chỉ thuộc MỘT device tại một thời điểm.
        # Partial index (chỉ áp dụng cho bản ghi chưa thu hồi) để vẫn giữ được
        # lịch sử cấp phát cũ của cùng địa chỉ.
        Index(
            "uq_active_ip_assignment",
            "ip_address_id",
            unique=True,
            postgresql_where=text("released_at IS NULL"),
            sqlite_where=text("released_at IS NULL"),
        ),
        Index("ix_assignment_device", "device_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip_address_id: Mapped[str] = mapped_column(ForeignKey("ip_address.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("device.id"))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=True)
    assigned_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
    released_at: Mapped[datetime | None] = mapped_column(TZDateTime)

    ip: Mapped[IPAddress] = relationship(back_populates="assignments")
    device: Mapped[Device] = relationship(back_populates="assignments")


class CredentialRef(Base):
    """
    CHỈ lưu tham chiếu tới Vault. Tuyệt đối không lưu giá trị mật khẩu.
    Đây là điểm khác biệt quan trọng nhất so với Google Sheet hiện tại.
    """

    __tablename__ = "credential_ref"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(ForeignKey("device.id"))
    auth_type: Mapped[str] = mapped_column(String(32), default="ssh_key")
    username: Mapped[str | None] = mapped_column(String(128))
    vault_path: Mapped[str] = mapped_column(String(512))
    rotated_at: Mapped[datetime | None] = mapped_column(TZDateTime)

    device: Mapped[Device] = relationship(back_populates="credentials")


# --------------------------------------------------------------------------- #
# Đồng bộ / quét / lệch
# --------------------------------------------------------------------------- #


class ScanResult(Base):
    __tablename__ = "scan_result"
    __table_args__ = (
        Index("ix_scan_addr_time", "address_int", "scanned_at"),
        Index(
            "ix_scan_address_gist",
            "address",
            postgresql_using="gist",
            postgresql_ops={"address": "inet_ops"},
        ),
    )

    id: Mapped[int] = mapped_column(AutoBigIntPK, primary_key=True, autoincrement=True)
    address: Mapped[str] = mapped_column(InetType)
    address_int: Mapped[int] = mapped_column(BigInteger)
    alive: Mapped[bool] = mapped_column(Boolean)
    method: Mapped[str] = mapped_column(String(16))  # icmp | arp | tcp_syn | vcenter
    mac_address: Mapped[str | None] = mapped_column(MacType)
    hostname: Mapped[str | None] = mapped_column(String(255))
    rtt_ms: Mapped[float | None] = mapped_column(Numeric(8, 2))
    scanned_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)


class SyncRun(Base):
    __tablename__ = "sync_run"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32))  # vcenter | scan | import
    subject: Mapped[str | None] = mapped_column(String(64))  # CIDR với kind=scan
    started_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    items_seen: Mapped[int] = mapped_column(Integer, default=0)
    items_changed: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class DriftFinding(Base):
    """Chênh lệch giữa DB và thực tế. Không tự sửa — vào hàng đợi cho người xử lý."""

    __tablename__ = "drift_finding"
    __table_args__ = (
        UniqueConstraint("drift_type", "subject_key", name="uq_drift_subject"),
        Index("ix_drift_status_sev", "status", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    drift_type: Mapped[DriftType] = mapped_column(Enum(DriftType, native_enum=False))
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False))
    status: Mapped[DriftStatus] = mapped_column(
        Enum(DriftStatus, native_enum=False), default=DriftStatus.open
    )

    # Khoá tự nhiên của đối tượng bị lệch (IP, vcenter uuid, device id...)
    subject_key: Mapped[str] = mapped_column(String(255))
    device_id: Mapped[str | None] = mapped_column(ForeignKey("device.id"))
    ip_address_id: Mapped[str | None] = mapped_column(ForeignKey("ip_address.id"))

    detail: Mapped[dict | None] = mapped_column(JsonType, default=dict)
    assigned_to: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow, onupdate=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime)
    resolution_note: Mapped[str | None] = mapped_column(Text)

    SLA_HOURS = {
        Severity.critical: 4,
        Severity.high: 48,
        Severity.medium: 168,
        Severity.low: 720,
    }

    @property
    def sla_deadline(self) -> datetime:
        from datetime import timedelta

        return self.first_seen_at + timedelta(hours=self.SLA_HOURS[self.severity])


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_entity", "entity_type", "entity_id"),)

    id: Mapped[int] = mapped_column(AutoBigIntPK, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(64))
    changes: Mapped[dict | None] = mapped_column(JsonType, default=dict)
    at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)


class LifecycleEvent(Base):
    __tablename__ = "lifecycle_event"

    id: Mapped[int] = mapped_column(AutoBigIntPK, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("device.id"))
    event: Mapped[str] = mapped_column(String(64))  # reminder_sent | extended | ...
    detail: Mapped[dict | None] = mapped_column(JsonType, default=dict)
    at: Mapped[datetime] = mapped_column(TZDateTime, default=_utcnow)
