"""Router Inventory — CRUD thiết bị và tham chiếu credential."""

from __future__ import annotations

import os
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from auth import SYSOPS, VIEWER, Principal, require
from core import audit, dept_id, project_id, utcnow
from db import get_db
from models import (
    Criticality,
    Department,
    Device,
    DeviceSource,
    DeviceType,
    IPAssignment,
    LifecycleStatus,
)

router = APIRouter(prefix="/api/v1", tags=["Inventory"])


class DeviceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    device_type: DeviceType = DeviceType.vm
    asset_code: str | None = None
    os: str | None = None
    cpu_cores: int | None = Field(None, ge=1, le=512)
    ram_gb: float | None = Field(None, gt=0, le=8192)
    disk_gb: float | None = Field(None, gt=0, le=1_000_000)
    department: str | None = None
    project: str | None = None
    owner_email: str | None = None
    ticket_id: str | None = None
    expires_at: date | None = None
    criticality: Criticality = Criticality.normal
    is_protected: bool = False
    note: str | None = None


class DevicePatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    os: str | None = None
    owner_email: str | None = None
    department: str | None = None
    project: str | None = None
    ticket_id: str | None = None
    expires_at: date | None = None
    lifecycle_status: LifecycleStatus | None = None
    criticality: Criticality | None = None
    is_protected: bool | None = None
    note: str | None = None


def _device_row(d: Device) -> dict:
    return {
        "id": d.id,
        "asset_code": d.asset_code,
        "name": d.name,
        "type": d.device_type.value,
        "os": d.os,
        "cpu_cores": d.cpu_cores,
        "ram_gb": float(d.ram_gb) if d.ram_gb is not None else None,
        "disk_gb": float(d.disk_gb) if d.disk_gb is not None else None,
        "power_state": d.power_state.value,
        "department": d.department.code if d.department else None,
        "project": d.project.code if d.project else None,
        "owner_email": d.owner_email,
        "ticket_url": d.ticket_url,
        "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        "days_to_expiry": d.days_to_expiry,
        "lifecycle_status": d.lifecycle_status.value,
        "criticality": d.criticality.value,
        "is_protected": d.is_protected,
        "ips": [a.ip.address for a in d.assignments if a.released_at is None],
    }


@router.get("/devices")
def list_devices(
    department: str | None = None,
    lifecycle_status: str | None = None,
    missing_owner: bool = False,
    missing_expiry: bool = False,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    stmt = select(Device).options(
        selectinload(Device.assignments).selectinload(IPAssignment.ip),
        selectinload(Device.department),
        selectinload(Device.project),
    )
    if department:
        stmt = stmt.join(Department).where(Department.code == department)
    if lifecycle_status:
        stmt = stmt.where(Device.lifecycle_status == lifecycle_status)
    if missing_owner:
        stmt = stmt.where(Device.owner_email.is_(None))
    if missing_expiry:
        stmt = stmt.where(Device.expires_at.is_(None))

    devices = db.scalars(stmt.order_by(Device.name).offset(offset).limit(limit)).all()
    return {"count": len(devices), "offset": offset, "devices": [_device_row(d) for d in devices]}


@router.post("/devices", status_code=201)
def create_device(
    body: DeviceCreate,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    if db.scalar(select(Device).where(Device.name == body.name)):
        raise HTTPException(409, f"Đã có thiết bị tên {body.name}")

    d = Device(
        name=body.name,
        device_type=body.device_type,
        asset_code=body.asset_code,
        os=body.os,
        cpu_cores=body.cpu_cores,
        ram_gb=body.ram_gb,
        disk_gb=body.disk_gb,
        department_id=dept_id(db, body.department),
        project_id=project_id(db, body.project, body.department),
        owner_email=body.owner_email,
        requester_email=p.email,
        ticket_id=body.ticket_id,
        expires_at=body.expires_at,
        criticality=body.criticality,
        is_protected=body.is_protected,
        note=body.note,
        provisioned_at=date.today(),
        source=DeviceSource.manual,
        lifecycle_status=LifecycleStatus.active,
    )
    db.add(d)
    db.flush()
    audit(db, p.email, "create_device", "device", d.id, {"name": d.name})
    db.commit()
    return _device_row(d)


@router.patch("/devices/{device_id}")
def patch_device(
    device_id: str,
    body: DevicePatch,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Không tìm thấy thiết bị")

    changes: dict[str, dict] = {}
    for field, value in body.model_dump(exclude_unset=True).items():
        if field == "department":
            new, old = dept_id(db, value), d.department_id
            field, value = "department_id", new
        elif field == "project":
            new, old = project_id(db, value, body.department), d.project_id
            field, value = "project_id", new
        else:
            old = getattr(d, field)

        if old != value:
            changes[field] = {
                "cu": old.value if hasattr(old, "value") else str(old) if old is not None else None,
                "moi": value.value
                if hasattr(value, "value")
                else str(value)
                if value is not None
                else None,
            }
            setattr(d, field, value)

    if changes:
        d.updated_at = utcnow()
        audit(db, p.email, "update_device", "device", d.id, changes)
    db.commit()
    return {"id": d.id, "changed": list(changes), "detail": changes}


@router.get("/devices/{device_id}/credentials")
def device_credentials(
    device_id: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    """
    Trả về ĐƯỜNG DẪN Vault, không bao giờ trả giá trị mật khẩu.
    Người dùng bấm link -> Vault xác thực SSO -> Vault ghi audit log.
    """
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404, "Không tìm thấy thiết bị")

    # Xem đường dẫn credential cũng là hành vi đáng ghi lại: nó cho biết ai
    # đang chuẩn bị truy cập máy nào, kể cả khi Vault mới là nơi cấp giá trị.
    audit(db, p.email, "view_credentials", "device", device.id, {"name": device.name})
    db.commit()

    return {
        "device": device.name,
        "credentials": [
            {
                "auth_type": c.auth_type,
                "username": c.username,
                "vault_path": c.vault_path,
                "vault_url": f"{os.getenv('VAULT_UI', 'https://vault.internal')}/ui/vault/secrets/{c.vault_path}",
                "rotated_at": c.rotated_at.isoformat() if c.rotated_at else None,
            }
            for c in device.credentials
        ],
        "note": "Portal không lưu mật khẩu. Truy cập giá trị qua Vault.",
    }
