"""
UI (Jinja2 + HTMX) — giao diện theo design system "Proton Enterprise".

Toàn bộ HTML đi qua Jinja2 với autoescape bật. Bản trước dựng HTML bằng
f-string, nên tên VM — dữ liệu đến từ vCenter và CSV import, tức là nguồn
không tin cậy — chạy thẳng vào DOM. Một VM đặt tên `"><img src=x onerror=...>`
là chạy được JavaScript trong trình duyệt của đội System, trên chính công cụ
quản trị hạ tầng.

Các trang ở đây chỉ gọi lại chính hàm xử lý của router API, không truy vấn DB
song song: mọi kiểm tra phân quyền và quy tắc nghiệp vụ vì thế chỉ tồn tại ở
một nơi duy nhất.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth import ADMIN, REQUESTER, SYSOPS, VIEWER, Principal, auth_mode, require
from core import active_device, device_summary, find_subnet_for, utcnow
from db import get_db
from models import DriftFinding, DriftStatus, IPAddress, Severity, Subnet
from routers.admin import list_sync_runs, trigger_scan
from routers.drift import (
    DRIFT_TYPE_LABELS,
    SEV_LABELS,
    ResolveRequest,
    list_drift,
    resolve_drift,
    resolve_finding_display,
)
from routers.inventory import list_devices
from routers.ipam import (
    CommitRequest,
    ReleaseRequest,
    ReserveRequest,
    SuggestRequest,
    cancel_reservation,
    commit_ip,
    list_subnets,
    release_ip,
    reserve_ip,
    subnet_map,
    suggest_ip,
)
from routers.reports import data_quality, expiring, scanner_health

router = APIRouter(include_in_schema=False)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True


def _conf_chip(c: float) -> str:
    """Ngưỡng lấy từ allocator.confidence_label để UI và API nói cùng một ngôn ngữ."""
    return "chip-ok" if c >= 0.85 else ("chip-warn" if c >= 0.60 else "chip-error")


templates.env.filters["conf_chip"] = _conf_chip


def _base_ctx(request: Request, p: Principal, active: str) -> dict:
    return {
        "request": request,
        "principal": p,
        "active": active,
        "insecure_mode": auth_mode() == "dev",
    }


def _render(request: Request, p: Principal, active: str, name: str, extra: dict):
    return templates.TemplateResponse(request, name, _base_ctx(request, p, active) | extra)


def _toast(request: Request, kind: str, message: str, title: str = "", status: int = 200):
    """
    Trả về riêng một toast (out-of-band swap) khi hành động không cần đổi
    giao diện gì khác, hoặc khi có lỗi.
    """
    return templates.TemplateResponse(
        request,
        "_toast.html",
        {"request": request, "kind": kind, "message": message, "title": title},
        status_code=status,
    )


def _fragment(request: Request, name: str, ctx: dict, toast: dict | None = None):
    """
    Render một fragment kèm toast đính sau. Gộp ở đây thay vì lặp lại chuỗi
    nối template ở mọi handler.
    """
    html = templates.get_template(name).render(**ctx)
    if toast:
        html += templates.get_template("_toast.html").render(
            request=request,
            kind=toast.get("kind", "ok"),
            message=toast.get("message", ""),
            title=toast.get("title", ""),
        )
    return HTMLResponse(html)


def _err_toast(request: Request, exc: HTTPException, title: str = "Không thực hiện được"):
    """Biến HTTPException của tầng API thành toast đọc được, giữ nguyên mã lỗi."""
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return _toast(request, "error", detail, title, status=200)


# Các hàm router bên dưới được gọi trực tiếp chứ không qua tầng HTTP, nên
# FastAPI không giải quyết `Query(...)` mặc định hộ — phải truyền đủ tham số
# tường minh, nếu không sẽ nhận về chính đối tượng Query.


def _open_drift_findings(db: Session, p: Principal) -> list[dict]:
    return list_drift(
        status=DriftStatus.open,
        severity=None,
        sla_breached=None,
        limit=1000,
        offset=0,
        db=db,
        p=p,
    )["findings"]


# --------------------------------------------------------------------------- #
# Bảng điều khiển
# --------------------------------------------------------------------------- #


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    subnets = list_subnets(db, p)["subnets"]
    health = scanner_health(db, p)
    quality = data_quality(db, p)
    findings = _open_drift_findings(db, p)

    allocated = sum(s["allocated"] for s in subnets)
    usable = sum(s["usable"] for s in subnets)

    # Chỉ đếm critical/high: đây là con số đội System phải hành động trong ngày,
    # gộp cả medium/low vào sẽ làm thẻ cảnh báo mất ý nghĩa.
    critical = sum(1 for f in findings if f["severity"] in ("critical", "high"))

    last_ok = [s["last_scan_ok_at"] for s in subnets if s.get("last_scan_ok_at")]
    hours = None
    if last_ok:
        from datetime import datetime, timezone

        newest = max(datetime.fromisoformat(x) for x in last_ok)
        hours = round((datetime.now(timezone.utc) - newest).total_seconds() / 3600, 1)

    return _render(
        request,
        p,
        "/",
        "dashboard.html",
        {
            "subnets": subnets,
            "stats": {
                "total_devices": quality.get("total_devices", 0),
                "allocated": allocated,
                "usable": usable,
                "utilization_pct": round(100 * allocated / usable) if usable else 0,
                "critical_drift": critical,
                "open_drift": quality.get("open_drift", 0),
                "has_owner_pct": quality.get("has_owner_pct", 0),
                "has_expiry_pct": quality.get("has_expiry_pct", 0),
            },
            "scanner": {
                "healthy": health["healthy"],
                "stale_subnets": health["stale_subnets"],
                "total_subnets": health["total_subnets"],
                "last_ok_hours": hours,
            },
        },
    )


# --------------------------------------------------------------------------- #
# Quản lý IP
# --------------------------------------------------------------------------- #


@router.get("/ip", response_class=HTMLResponse)
def ui_ipam(
    request: Request,
    cidr: str = "",
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    subnets = list_subnets(db, p)["subnets"]
    if not subnets:
        return _render(
            request,
            p,
            "/ip",
            "ipam.html",
            {
                "subnets": [],
                "stats": None,
                "addresses": [],
                "current_cidr": "",
                "scanner_warning": None,
            },
        )

    known = {s["cidr"] for s in subnets}
    current = cidr if cidr in known else subnets[0]["cidr"]

    data = subnet_map(current, db, p)
    rows = db.scalars(select(Subnet).where(Subnet.is_active)).all()
    meta = {s.cidr: s for s in rows}
    for s in subnets:
        m = meta.get(s["cidr"])
        s["cooldown_days"] = m.cooldown_days if m else 14
        s["allocation_policy"] = m.allocation_policy if m else ""

    return _render(
        request,
        p,
        "/ip",
        "ipam.html",
        {
            "subnets": subnets,
            "current_cidr": current,
            "stats": data["subnet"],
            "addresses": data["addresses"],
            "scanner_warning": data["scanner_warning"],
        },
    )


# --------------------------------------------------------------------------- #
# Quản trị Dải mạng (Subnet CRUD UI)
# --------------------------------------------------------------------------- #


@router.get("/ui/subnets/create-form", response_class=HTMLResponse)
def ui_subnet_create_form(
    request: Request,
    p: Principal = Depends(require(ADMIN)),
):
    return _fragment(request, "_subnet_create.html", {"request": request, "principal": p})


@router.post("/ui/subnets/create", response_class=HTMLResponse)
def ui_subnet_create(
    request: Request,
    cidr: str = Form(...),
    name: str = Form(""),
    vlan_id: str = Form(""),
    gateway: str = Form(""),
    allocation_policy: str = Form("lowest_first"),
    cooldown_days: int = Form(14),
    scan_staleness_hours: int = Form(30),
    dhcp_range_start: str = Form(""),
    dhcp_range_end: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    from routers.admin import SubnetCreate, create_subnet

    try:
        vid = int(vlan_id) if vlan_id.strip() else None
        create_subnet(
            SubnetCreate(
                cidr=cidr.strip(),
                name=name.strip(),
                vlan_id=vid,
                gateway=gateway.strip() or None,
                allocation_policy=allocation_policy,
                cooldown_days=cooldown_days,
                scan_staleness_hours=scan_staleness_hours,
                dhcp_range_start=dhcp_range_start.strip() or None,
                dhcp_range_end=dhcp_range_end.strip() or None,
            ),
            db=db,
            p=p,
        )
    except HTTPException as exc:
        return _toast(request, "error", exc.detail, "Lỗi tạo dải mạng")
    except Exception as exc:
        return _toast(request, "error", str(exc), "Lỗi tạo dải mạng")

    return HTMLResponse("<script>window.location.reload();</script>")


@router.get("/ui/subnets/{subnet_id}/edit-form", response_class=HTMLResponse)
def ui_subnet_edit_form(
    request: Request,
    subnet_id: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    s = db.get(Subnet, subnet_id)
    if not s:
        return _toast(request, "error", "Không tìm thấy dải mạng.", "Lỗi")

    return _fragment(
        request,
        "_subnet_edit.html",
        {
            "request": request,
            "principal": p,
            "s": s,
        },
    )


@router.post("/ui/subnets/{subnet_id}/edit", response_class=HTMLResponse)
def ui_subnet_edit(
    request: Request,
    subnet_id: str,
    name: str = Form(""),
    vlan_id: str = Form(""),
    gateway: str = Form(""),
    allocation_policy: str = Form("lowest_first"),
    cooldown_days: int = Form(14),
    scan_staleness_hours: int = Form(30),
    dhcp_range_start: str = Form(""),
    dhcp_range_end: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    from routers.admin import SubnetUpdate, update_subnet

    try:
        vid = int(vlan_id) if vlan_id.strip() else None
        update_subnet(
            subnet_id=subnet_id,
            body=SubnetUpdate(
                name=name.strip(),
                vlan_id=vid,
                gateway=gateway.strip() or None,
                allocation_policy=allocation_policy,
                cooldown_days=cooldown_days,
                scan_staleness_hours=scan_staleness_hours,
                dhcp_range_start=dhcp_range_start.strip() or None,
                dhcp_range_end=dhcp_range_end.strip() or None,
            ),
            db=db,
            p=p,
        )
    except HTTPException as exc:
        return _toast(request, "error", exc.detail, "Lỗi cập nhật")
    except Exception as exc:
        return _toast(request, "error", str(exc), "Lỗi cập nhật")

    return HTMLResponse("<script>window.location.reload();</script>")


@router.post("/ui/subnets/{subnet_id}/delete", response_class=HTMLResponse)
def ui_subnet_delete(
    request: Request,
    subnet_id: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    from routers.admin import delete_subnet

    try:
        delete_subnet(subnet_id=subnet_id, db=db, p=p)
    except HTTPException as exc:
        return _toast(request, "error", exc.detail, "Lỗi xoá dải mạng")
    except Exception as exc:
        return _toast(request, "error", str(exc), "Lỗi xoá dải mạng")

    return HTMLResponse("<script>window.location.reload();</script>")


@router.post("/ui/suggest", response_class=HTMLResponse)
def ui_suggest(
    request: Request,
    subnet: str = Form(""),
    department: str = Form(""),
    project: str = Form(""),
    quantity: int = Form(1),
    contiguous: str = Form("false"),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    data = suggest_ip(
        SuggestRequest(
            subnet=subnet,
            department=department or None,
            project=project or None,
            quantity=max(1, min(quantity, 32)),
            contiguous=(contiguous == "true"),
        ),
        db,
        p,
    )
    return templates.TemplateResponse(
        request,
        "_suggestions.html",
        _base_ctx(request, p, "/ip")
        | {
            "suggestions": data["suggestions"],
            "blocks": data["blocks"],
            "rejected": data["rejected_summary"],
            "scanner_warning": data["scanner_warning"],
            "can_allocate": p.at_least(REQUESTER),
        },
    )


# --------------------------------------------------------------------------- #
# Vòng đời VM
# --------------------------------------------------------------------------- #


PAGE_SIZE = 25


def _vm_ctx(
    db: Session, p: Principal, q: str, department: str, lifecycle_status: str, gap: str, page: int
) -> dict:
    """
    Lọc và phân trang danh sách thiết bị.

    Lọc trong Python chứ không đẩy xuống SQL vì quy mô ở đây là vài trăm tới
    vài nghìn thiết bị — dưới ngưỡng mà một truy vấn phức tạp đáng công viết,
    và tìm theo IP thì phải join qua ip_assignment nên vẫn phải nạp sẵn.
    """
    devices = list_devices(
        department=department or None,
        lifecycle_status=lifecycle_status or None,
        missing_owner=(gap == "owner"),
        missing_expiry=(gap == "expiry"),
        limit=1000,
        offset=0,
        db=db,
        p=p,
    )["devices"]

    needle = q.strip().lower()
    if needle:

        def matches(d: dict) -> bool:
            haystack = [d["name"], d.get("owner_email") or "", d.get("project") or ""]
            haystack += d.get("ips") or []
            return any(needle in str(x).lower() for x in haystack)

        devices = [d for d in devices if matches(d)]

    total = len(devices)
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(1, page), pages)
    start = (page - 1) * PAGE_SIZE

    return {
        "devices": devices[start : start + PAGE_SIZE],
        "total": total,
        "page": page,
        "pages": pages,
        "page_size": PAGE_SIZE,
    }


@router.get("/vm", response_class=HTMLResponse)
def ui_vm(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    ctx = _vm_ctx(db, p, "", "", "", "", 1)
    soon = expiring(days=90, db=db, p=p)

    all_devices = list_devices(
        department=None,
        lifecycle_status=None,
        missing_owner=False,
        missing_expiry=False,
        limit=1000,
        offset=0,
        db=db,
        p=p,
    )["devices"]
    missing = sum(1 for d in all_devices if not d["owner_email"] or not d["expires_at"])
    departments = sorted({d["department"] for d in all_devices if d["department"]})

    return _render(
        request,
        p,
        "/vm",
        "vm.html",
        ctx
        | {
            "departments": departments,
            "summary": {
                "total": len(all_devices),
                "expiring": soon["count"],
                "reclaimable_vcpu": soon["reclaimable_vcpu"],
                "reclaimable_ram_gb": soon["reclaimable_ram_gb"],
                "missing": missing,
            },
        },
    )


@router.get("/ui/vm/table", response_class=HTMLResponse)
def ui_vm_table(
    request: Request,
    q: str = "",
    department: str = "",
    lifecycle_status: str = "",
    gap: str = "",
    page: int = 1,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    ctx = _vm_ctx(db, p, q, department, lifecycle_status, gap, page)
    return _fragment(request, "_vm_table.html", {"request": request, "principal": p} | ctx)


# --------------------------------------------------------------------------- #
# Quét mạng · lệch · nhật ký
# --------------------------------------------------------------------------- #


@router.get("/scan", response_class=HTMLResponse)
def ui_scan(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    health = scanner_health(db, p)
    # Lịch sử job đòi vai trò sysops; người chỉ có quyền xem vẫn thấy được
    # bảng sức khoẻ, chỉ là không thấy chi tiết lượt chạy.
    runs = list_sync_runs(kind=None, limit=50, db=db, p=p)["runs"] if p.at_least(SYSOPS) else []
    return _render(
        request,
        p,
        "/scan",
        "scan.html",
        {"health": health, "runs": runs, "can_scan": p.at_least(SYSOPS)},
    )


@router.get("/drift", response_class=HTMLResponse)
def ui_drift(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    return _render(
        request,
        p,
        "/drift",
        "drift.html",
        _drift_ctx(db, p, "open", "", "")
        | {"cur_status": "open", "cur_severity": "", "cur_sla": ""},
    )


@router.get("/audit", response_class=HTMLResponse)
def ui_audit(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(ADMIN)),
):
    from app import list_audit

    entries = list_audit(entity_type=None, entity_id=None, limit=200, db=db, p=p)["entries"]
    return _render(request, p, "/audit", "audit.html", {"entries": entries})


# --------------------------------------------------------------------------- #
# Luồng cấp phát IP: xem chi tiết -> giữ chỗ -> chốt cấp -> thu hồi
#
# Toàn bộ đi qua chính các handler của routers/ipam.py, nên mọi chốt an toàn
# (cách ly, xác minh trực tiếp lúc commit, kiểm tra chủ sở hữu giữ chỗ) áp
# dụng y hệt như khi gọi API — UI không có đường tắt riêng.
# --------------------------------------------------------------------------- #


def _ip_snapshot(db: Session, address: str) -> tuple[dict, Subnet, dict | None]:
    """Gom dữ liệu một địa chỉ cho drawer chi tiết."""
    subnet = find_subnet_for(db, address)
    row = db.scalar(select(IPAddress).where(IPAddress.address == address))

    ctx_stats = None
    if row is not None:
        dev = active_device(row)
        ctx_stats = {
            "address": row.address,
            "status": row.status.value,
            "last_seen_alive_at": (
                row.last_seen_alive_at.strftime("%Y-%m-%d %H:%M")
                if row.last_seen_alive_at
                else None
            ),
            "consecutive_dead_scans": row.consecutive_dead_scans,
            "scans_last_7d": row.scans_last_7d,
            "mac_address": row.mac_address,
            "conflict_count": row.conflict_count,
            "quarantine_until": (
                (row.released_at + timedelta(days=subnet.cooldown_days)).date().isoformat()
                if row.released_at and row.status.value == "quarantine"
                else None
            ),
        }
        device = device_summary(dev) if dev else None
    else:
        # IP chưa từng được động tới nên chưa có dòng trong bảng — đây chính
        # là ứng viên sạch nhất, không phải lỗi.
        ctx_stats = {
            "address": address,
            "status": "free",
            "last_seen_alive_at": None,
            "consecutive_dead_scans": 0,
            "scans_last_7d": 0,
            "mac_address": None,
            "conflict_count": 0,
            "quarantine_until": None,
        }
        device = None

    # Lý do "không dùng được về mặt cấu trúc" (network/broadcast/gateway/
    # reserved/DHCP) do allocator quyết định, không phải trạng thái trong DB.
    import ipaddress as _ip

    from core import subnet_context

    ctx_stats["unusable_reason"] = subnet_context(subnet).is_structurally_unusable(
        int(_ip.ip_address(address))
    )
    return ctx_stats, subnet, device


@router.get("/ui/ip/{address}", response_class=HTMLResponse)
def ui_ip_detail(
    request: Request,
    address: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    try:
        ip, subnet, device = _ip_snapshot(db, address)
    except HTTPException as exc:
        return _err_toast(request, exc)

    return _fragment(
        request,
        "_ip_detail.html",
        {
            "request": request,
            "principal": p,
            "ip": ip,
            "device": device,
            "subnet": {
                "cidr": subnet.cidr,
                "name": subnet.name,
                "cooldown_days": subnet.cooldown_days,
            },
            "can_allocate": p.at_least(REQUESTER),
            "can_release": p.at_least(SYSOPS),
        },
    )


@router.post("/ui/ip/{address}/reserve", response_class=HTMLResponse)
def ui_reserve(
    request: Request,
    address: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    try:
        res = reserve_ip(ReserveRequest(address=address, purpose="cấp qua portal"), db, p)
    except HTTPException as exc:
        return _err_toast(request, exc, "Không giữ chỗ được")

    subnet = find_subnet_for(db, address)
    last_octet = address.rsplit(".", 1)[-1]
    return _fragment(
        request,
        "_commit_form.html",
        {
            "request": request,
            "principal": p,
            "address": address,
            "token": res["token"],
            "reserved_by": res["reserved_by"],
            "ttl_minutes": res["ttl_minutes"],
            "suggested_name": f"{subnet.name or 'VM'}-{last_octet}".replace(" ", "-"),
            "department": "",
            "project": "",
            "default_expiry": (date.today() + timedelta(days=180)).isoformat(),
            "can_skip_check": p.at_least(SYSOPS),
        },
        toast={
            "kind": "ok",
            "title": f"Đã giữ chỗ {address}",
            "message": f"Giữ trong {res['ttl_minutes']} phút. Khai báo thiết bị để chốt.",
        },
    )


@router.post("/ui/reserve/{token}/cancel", response_class=HTMLResponse)
def ui_cancel_reserve(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    try:
        out = cancel_reservation(token, db, p)
    except HTTPException as exc:
        return _err_toast(request, exc, "Không huỷ được giữ chỗ")
    return _toast(request, "ok", f"Đã trả {out['address']} về trạng thái trống.", "Đã huỷ giữ chỗ")


@router.post("/ui/ip/commit", response_class=HTMLResponse)
def ui_commit(
    request: Request,
    token: str = Form(...),
    device_name: str = Form(...),
    owner_email: str = Form(...),
    department: str = Form(""),
    project: str = Form(""),
    ticket_id: str = Form(""),
    expires_at: str = Form(""),
    cpu_cores: int | None = Form(None),
    ram_gb: float | None = Form(None),
    disk_gb: float | None = Form(None),
    skip_liveness_check: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(REQUESTER)),
):
    try:
        out = commit_ip(
            CommitRequest(
                token=token,
                device_name=device_name.strip(),
                owner_email=owner_email.strip(),
                department=department.strip() or None,
                project=project.strip() or None,
                ticket_id=ticket_id.strip() or None,
                expires_at=date.fromisoformat(expires_at) if expires_at else None,
                cpu_cores=cpu_cores,
                ram_gb=ram_gb,
                disk_gb=disk_gb,
                skip_liveness_check=(skip_liveness_check == "true"),
            ),
            db,
            p,
        )
    except HTTPException as exc:
        return _err_toast(request, exc, "Chốt cấp thất bại")
    except ValueError as exc:
        return _toast(request, "error", f"Dữ liệu không hợp lệ: {exc}", "Chốt cấp thất bại")

    # Nạp lại trang để bản đồ IP và các số liệu phản ánh trạng thái mới.
    resp = _toast(
        request,
        "ok",
        f"{out['address']} đã cấp cho {out['device_name']}.",
        "Cấp phát thành công",
    )
    resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/ui/ip/{address}/release", response_class=HTMLResponse)
def ui_release(
    request: Request,
    address: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    try:
        out = release_ip(ReleaseRequest(address=address, reason="thu hồi qua portal"), db, p)
    except HTTPException as exc:
        return _err_toast(request, exc, "Thu hồi thất bại")

    resp = _toast(
        request,
        "ok",
        f"{address} vào cách ly {out['cooldown_days']} ngày, cấp lại được từ "
        f"{out['available_after'][:10]}.",
        "Đã thu hồi",
    )
    resp.headers["HX-Refresh"] = "true"
    return resp


# --------------------------------------------------------------------------- #
# Hàng đợi lệch: lọc và xử lý
# --------------------------------------------------------------------------- #

_STATUS_LABEL = {
    "open": "Finding đang mở",
    "acknowledged": "Đã tiếp nhận",
    "resolved": "Đã xử lý",
    "ignored": "Đã bỏ qua",
}


def _drift_ctx(db: Session, p: Principal, status: str, severity: str, sla: str) -> dict:
    """Bối cảnh chung cho cả trang đầy đủ và fragment bảng khi lọc."""
    try:
        st = DriftStatus(status)
    except ValueError:
        st = DriftStatus.open

    data = list_drift(
        status=st,
        severity=Severity(severity) if severity else None,
        sla_breached={"breached": True, "ok": False}.get(sla),
        limit=1000,
        offset=0,
        db=db,
        p=p,
    )
    findings = data["findings"]
    return {
        "findings": findings,
        "breached": sum(1 for f in findings if f["sla_breached"]),
        "status_label": _STATUS_LABEL.get(st.value, st.value),
        "can_resolve": p.at_least(SYSOPS),
    }


@router.get("/ui/drift/table", response_class=HTMLResponse)
def ui_drift_table(
    request: Request,
    status: str = "open",
    severity: str = "",
    sla: str = "",
    db: Session = Depends(get_db),
    p: Principal = Depends(require(VIEWER)),
):
    return _fragment(
        request,
        "_drift_table.html",
        {"request": request, "principal": p} | _drift_ctx(db, p, status, severity, sla),
    )


@router.get("/ui/drift/{finding_id}/resolve-form", response_class=HTMLResponse)
def ui_drift_resolve_form(
    request: Request,
    finding_id: str,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    f = db.get(DriftFinding, finding_id)
    if not f:
        return _toast(request, "error", "Finding không còn tồn tại.", "Không tìm thấy")

    subj_display, subj_type = resolve_finding_display(f)
    return _fragment(
        request,
        "_drift_resolve.html",
        {
            "request": request,
            "principal": p,
            "f": {
                "id": f.id,
                "type": f.drift_type.value,
                "type_label": DRIFT_TYPE_LABELS.get(f.drift_type.value, f.drift_type.value),
                "severity": f.severity.value,
                "severity_label": SEV_LABELS.get(f.severity.value, f.severity.value),
                "subject": f.subject_key,
                "subject_display": subj_display,
                "subject_type": subj_type,
                "detail": f.detail or {},
                "first_seen_at": f.first_seen_at.isoformat(),
                "sla_deadline": f.sla_deadline.isoformat(),
                "sla_breached": f.sla_deadline < utcnow(),
            },
        },
    )


@router.post("/ui/drift/{finding_id}/resolve", response_class=HTMLResponse)
def ui_drift_resolve(
    request: Request,
    finding_id: str,
    status: str = Form("resolved"),
    note: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    try:
        out = resolve_drift(
            finding_id, ResolveRequest(note=note, status=DriftStatus(status)), db, p
        )
    except HTTPException as exc:
        return _err_toast(request, exc, "Không đóng được finding")
    except ValueError:
        return _toast(request, "error", f"Trạng thái không hợp lệ: {status}")

    resp = _toast(
        request,
        "ok",
        f"Finding chuyển sang {out['status']}, ghi nhận bởi {out['by']}.",
        "Đã xử lý",
    )
    resp.headers["HX-Refresh"] = "true"
    return resp


# --------------------------------------------------------------------------- #
# Quét thủ công
# --------------------------------------------------------------------------- #


@router.post("/ui/scan/run", response_class=HTMLResponse)
def ui_scan_run(
    request: Request,
    cidr: str = Form(...),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    try:
        out = trigger_scan(cidr=cidr, method="icmp", db=db, p=p)
    except HTTPException as exc:
        return _err_toast(request, exc, "Quét thất bại")

    # Canary thất bại KHÔNG phải lỗi kỹ thuật — lượt quét chạy được nhưng kết
    # quả bị từ chối có chủ đích. Phải nói rõ, vì đây đúng là tình huống dead
    # man switch sinh ra để bắt.
    if out.get("canary_failed"):
        return _toast(request, "error", out["reason"], f"Huỷ quét {cidr}")
    if out.get("skipped"):
        return _toast(request, "error", out["reason"], f"Bỏ qua {cidr}")

    resp = _toast(
        request,
        "ok",
        f"Quét {out['scanned']} địa chỉ · {out['alive']} phản hồi · "
        f"{out['new_conflicts']} xung đột mới "
        f"(canary {out['canary_alive']}/{out['canary_total']}).",
        f"Đã quét xong {cidr}",
    )
    resp.headers["HX-Refresh"] = "true"
    return resp


# --------------------------------------------------------------------------- #
# Đăng nhập / đăng xuất
#
# Người chưa xác thực bị chuyển tới /login thay vì nhận JSON 401 trần trụi —
# xem thêm handler 401 trong app.py.
# --------------------------------------------------------------------------- #


@router.get("/login", response_class=HTMLResponse)
def ui_login_page(request: Request, next: str = "/", error: str = ""):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "mode": auth_mode(),
            "error": error,
            # Chỉ nhận đường dẫn nội bộ: `next` do người dùng kiểm soát, nếu
            # cho phép URL tuyệt đối thì thành lỗ hổng open redirect.
            "next_url": next if next.startswith("/") and not next.startswith("//") else "/",
        },
    )


@router.post("/ui/login")
def ui_login(
    request: Request,
    # Cả hai đều không bắt buộc ở tầng này: chế độ `token` xác định danh tính
    # từ chính token nên ô email để trống được, còn chế độ `dev` thì không
    # kiểm tra mật khẩu. Việc thiếu cái gì do backend xác thực quyết định.
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/"),
):
    from fastapi.responses import RedirectResponse

    from routers.auth_routes import login as api_login

    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    try:
        api_login(response=resp, username=username, password=password)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else "Đăng nhập thất bại"
        return RedirectResponse(
            f"/login?error={quote(detail)}&next={quote(target)}", status_code=303
        )
    return resp


@router.get("/logout")
def ui_logout():
    from fastapi.responses import RedirectResponse

    from auth import SESSION_COOKIE

    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------- #
# Nhập dữ liệu CSV
# --------------------------------------------------------------------------- #


@router.get("/import", response_class=HTMLResponse)
def ui_import_page(
    request: Request,
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    return templates.TemplateResponse(
        request,
        "import.html",
        {
            "request": request,
            "principal": p,
            "active": "/import",
            "scanner_alert": None,
            "insecure_mode": p.via == "dev",
        },
    )


@router.get("/api/v1/import/template/{file_type}")
def get_import_template(
    file_type: str,
    p: Principal = Depends(require(VIEWER)),
):
    templates_data = {
        "physical": (
            "MÃ TÀI SẢN,TÊN SERVER,LOẠI THIẾT BỊ,ĐƠN VỊ SỬ DỤNG,DỰ ÁN,IP QUẢN TRỊ,CPU,RAM,DISK,OS,TRẠNG THÁI,GHI CHÚ\n"
            "SRV-001,SDC-HAPROXY-01,Physical Server,SDC1,Core Infra,10.0.64.10,32,128,2000,Ubuntu 22.04,Đang sử dụng,Server production\n"
            "SRV-002,SDC-DB-PRIMARY,Physical Server,SDC1,Database Cls,10.0.64.11,64,256,4000,RHEL 9,Đang sử dụng,Không xóa\n"
        ),
        "vm": (
            "TÊN VM,CPU (vCPU),RAM (GB),Dung lượng đĩa (GB),Hệ điều hành,Trạng thái Power,Người yêu cầu (Requester),Ngày cấp,Hạn thu hồi,Ghi chú\n"
            "SDC1-APP-TEST-01,4,8,100,Ubuntu 22.04,poweredOn,quang.dang1@ntq-solution.com.vn,2026-01-15,2026-12-31,VM chạy thử nghiệm\n"
            "SDC1-BUILD-01,8,16,200,CentOS 7,poweredOn,sysops@ntq-solution.com.vn,2026-02-01,no expire,Server Jenkins build\n"
        ),
        "network": (
            "LIST ĐỊA CHỈ IP,THIẾT BỊ ĐANG SỬ DỤNG,ĐƠN VỊ,DỰ ÁN,TRẠNG THÁI,USER,PASS,Date,GHI CHÚ\n"
            "10.0.76.10,SDC1-GATEWAY,SDC1,Infra,running,admin,******,2026-12-31,Gateway chính\n"
            "10.0.76.11,SDC1-APP-01,SDC1,Web App,running,root,******,2026-11-30,Server backend\n"
        ),
    }
    content = templates_data.get(file_type)
    if not content:
        raise HTTPException(404, "Không tìm thấy mẫu file yêu cầu")

    filename = f"{file_type}_template.csv"
    return Response(
        content=content.encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/ui/import/submit", response_class=HTMLResponse)
async def ui_import_submit(
    request: Request,
    file_physical: UploadFile | None = File(None),
    file_vm: UploadFile | None = File(None),
    file_network: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    p: Principal = Depends(require(SYSOPS)),
):
    import os
    import tempfile
    from importer import (
        REVIEW_ROWS,
        VAULT_ROWS,
        import_network,
        import_physical,
        import_vm,
    )

    results = []
    has_file = False

    if db.scalar(select(Subnet)) is None:
        return HTMLResponse(
            '<div class="banner banner-danger" style="margin:0">'
            'Chưa có dải mạng nào được khai báo trong hệ thống. Vui lòng khai báo Subnet trước khi import!'
            '</div>'
        )

    REVIEW_ROWS.clear()
    VAULT_ROWS.clear()

    # 1. Physical
    if file_physical and file_physical.filename and file_physical.size and file_physical.size > 0:
        has_file = True
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            tmp.write(await file_physical.read())
            tmp_path = tmp.name
        try:
            n_phys = import_physical(db, tmp_path)
            results.append(f"✓ <b>Server vật lý:</b> Đã nhập thành công <b>{n_phys}</b> dòng")
        except Exception as e:
            results.append(f"✗ <b>Server vật lý lỗi:</b> {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # 2. VM
    if file_vm and file_vm.filename and file_vm.size and file_vm.size > 0:
        has_file = True
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            tmp.write(await file_vm.read())
            tmp_path = tmp.name
        try:
            n_vm = import_vm(db, tmp_path)
            results.append(f"✓ <b>Thống kê VM:</b> Đã nhập thành công <b>{n_vm}</b> dòng")
        except Exception as e:
            results.append(f"✗ <b>Thống kê VM lỗi:</b> {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # 3. Network
    if file_network and file_network.filename and file_network.size and file_network.size > 0:
        has_file = True
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            tmp.write(await file_network.read())
            tmp_path = tmp.name
        try:
            n_net = import_network(db, tmp_path)
            results.append(f"✓ <b>Network/IP:</b> Đã nhập thành công <b>{n_net}</b> dòng")
        except Exception as e:
            results.append(f"✗ <b>Network/IP lỗi:</b> {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    if not has_file:
        return HTMLResponse(
            '<div class="banner banner-warn" style="margin:0">'
            'Vui lòng chọn ít nhất 1 file CSV để thực hiện import.'
            '</div>'
        )

    res_html = [
        '<div class="card" style="padding:20px;border-left:4px solid var(--ok);background:var(--surface-container-low)">',
        '<h4 style="margin:0 0 12px 0;font-size:16px;color:var(--ok)">Kết quả xử lý Import</h4>',
        '<ul style="margin:0;padding-left:20px;line-height:1.8">',
    ]
    for r in results:
        res_html.append(f"<li>{r}</li>")
    res_html.append("</ul>")

    if REVIEW_ROWS:
        res_html.append(
            f'<div style="margin-top:12px;font-size:13px;color:var(--warn)">'
            f"⚠ Có <b>{len(REVIEW_ROWS)}</b> dòng dữ liệu mập mờ cần kiểm tra lại."
            f"</div>"
        )
    if VAULT_ROWS:
        res_html.append(
            f'<div style="margin-top:8px;font-size:13px;color:var(--primary)">'
            f"🛡 Đã phát hiện và tách <b>{len(VAULT_ROWS)}</b> secret sang nạp Vault (không lưu mật khẩu vào DB)."
            f"</div>"
        )

    res_html.append("</div>")
    return HTMLResponse("".join(res_html))
