"""
Test cho các luồng thao tác trên giao diện.

`tests/test_api.py` phủ tầng API. Bộ này phủ phần mà người dùng thực sự chạm
vào: bấm nút trên UI có gọi đúng chốt an toàn không, có báo lỗi đọc được
không, và vai trò thấp có bị chặn cả ở nút bấm lẫn ở endpoint không.

Nguyên tắc: nút bị ẩn KHÔNG được coi là biện pháp bảo mật — mỗi thao tác đều
có thêm một test gọi thẳng endpoint bằng vai trò không đủ quyền.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from tests.factories import CIDR, seed_minimal

SYSOPS = {"X-Dev-User": "quang@ntq-solution.com.vn", "X-Dev-Role": "sysops"}
VIEWER = {"X-Dev-User": "xem@ntq-solution.com.vn", "X-Dev-Role": "viewer"}
REQUESTER = {"X-Dev-User": "xin@ntq-solution.com.vn", "X-Dev-Role": "requester"}

FREE_IP = "10.0.76.45"


@pytest.fixture()
def ui(client):
    seed_minimal(client.db_module.SessionLocal())
    client.headers.update(SYSOPS)
    return client


def _token(html: str) -> str:
    m = re.search(r'name="token" value="([^"]+)"', html)
    assert m, "không tìm thấy token giữ chỗ trong form chốt cấp"
    return m.group(1)


# --------------------------------------------------------------------------- #
# Luồng cấp phát đầy đủ
# --------------------------------------------------------------------------- #


def test_luong_cap_phat_qua_ui(ui):
    """Giữ chỗ -> khai báo thiết bị -> chốt cấp, đúng như kỹ sư thao tác thật."""
    r = ui.post(f"/ui/ip/{FREE_IP}/reserve")
    assert r.status_code == 200
    assert "Khai báo thiết bị" in r.text
    token = _token(r.text)

    r = ui.post(
        "/ui/ip/commit",
        data={
            "token": token,
            "device_name": "SDC11-UI-45",
            "owner_email": "chu.may@ntq-solution.com.vn",
            "department": "SDC11",
            "expires_at": "2027-06-30",
            "cpu_cores": "2",
            "ram_gb": "4",
            "disk_gb": "50",
            "skip_liveness_check": "true",
        },
    )
    assert r.status_code == 200
    assert "Cấp phát thành công" in r.text
    assert r.headers.get("HX-Refresh") == "true"

    body = ui.get(f"/api/v1/subnets/{CIDR}/map").json()
    cell = next(a for a in body["addresses"] if a["address"] == FREE_IP)
    assert cell["status"] == "allocated"
    assert cell["device"]["name"] == "SDC11-UI-45"


def test_thu_hoi_qua_ui_dua_ip_vao_cach_ly(ui):
    token = _token(ui.post(f"/ui/ip/{FREE_IP}/reserve").text)
    ui.post(
        "/ui/ip/commit",
        data={
            "token": token,
            "device_name": "SDC11-UI-TMP",
            "owner_email": "a@b.c",
            "expires_at": "2027-01-01",
            "skip_liveness_check": "true",
        },
    )

    r = ui.post(f"/ui/ip/{FREE_IP}/release")
    assert r.status_code == 200
    assert "Đã thu hồi" in r.text

    # Và cách ly phải chặn được lần giữ chỗ tiếp theo.
    r = ui.post(f"/ui/ip/{FREE_IP}/reserve")
    assert "cách ly" in r.text
    assert "is-error" in r.text


def test_huy_giu_cho_tra_ip_ve_trong(ui):
    token = _token(ui.post(f"/ui/ip/{FREE_IP}/reserve").text)
    r = ui.post(f"/ui/reserve/{token}/cancel")
    assert r.status_code == 200
    assert "Đã huỷ giữ chỗ" in r.text

    r = ui.post("/api/v1/ipam/suggest", json={"subnet": CIDR, "limit": 20})
    assert FREE_IP in [s["address"] for s in r.json()["suggestions"]]


def test_loi_tang_api_hien_thanh_toast_doc_duoc(ui):
    """Token sai phải ra thông báo tiếng Việt, không phải trang lỗi 404."""
    r = ui.post(
        "/ui/ip/commit",
        data={
            "token": "khong-ton-tai",
            "device_name": "x",
            "owner_email": "a@b.c",
            "expires_at": "2027-01-01",
        },
    )
    assert r.status_code == 200
    assert "is-error" in r.text
    assert "Token giữ chỗ không hợp lệ" in r.text


def test_chi_tiet_ip_hien_thong_tin_thiet_bi(ui):
    r = ui.get("/ui/ip/10.0.76.5")
    assert r.status_code == 200
    assert "SDC1-Tiktok-76.5" in r.text
    assert "Thu hồi" in r.text


def test_chi_tiet_ip_chua_co_ban_ghi_van_mo_duoc(ui):
    """IP chưa từng dùng thì chưa có dòng trong bảng — đó là ứng viên tốt nhất."""
    r = ui.get("/ui/ip/10.0.76.200")
    assert r.status_code == 200
    assert "10.0.76.200" in r.text


# --------------------------------------------------------------------------- #
# Phân quyền: nút ẩn VÀ endpoint chặn
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path,method",
    [
        (f"/ui/ip/{FREE_IP}/reserve", "post"),
        (f"/ui/ip/{FREE_IP}/release", "post"),
        ("/ui/scan/run", "post"),
    ],
)
def test_viewer_bi_chan_o_endpoint(ui, path, method):
    data = {"cidr": CIDR} if "scan" in path else None
    r = getattr(ui, method)(path, data=data, headers=VIEWER)
    assert r.status_code == 403


def test_viewer_khong_thay_nut_hanh_dong(ui):
    assert "Giữ chỗ địa chỉ này" not in ui.get("/ui/ip/10.0.76.45", headers=VIEWER).text
    assert "Thu hồi" not in ui.get("/ui/ip/10.0.76.5", headers=VIEWER).text
    assert "Quét ngay" not in ui.get("/scan", headers=VIEWER).text


def test_requester_khong_bo_qua_duoc_xac_minh_truc_tiep(ui):
    """Chỉ sysops mới được tắt chốt an toàn ping-lại-trước-khi-chốt."""
    token = _token(ui.post(f"/ui/ip/{FREE_IP}/reserve", headers=REQUESTER).text)
    r = ui.post(
        "/ui/ip/commit",
        headers=REQUESTER,
        data={
            "token": token,
            "device_name": "x",
            "owner_email": "a@b.c",
            "expires_at": "2027-01-01",
            "skip_liveness_check": "true",
        },
    )
    assert "is-error" in r.text
    assert "sysops" in r.text


def test_form_chot_cap_an_o_bo_qua_voi_requester(ui):
    html = ui.post(f"/ui/ip/{FREE_IP}/reserve", headers=REQUESTER).text
    assert "skip_liveness_check" not in html


# --------------------------------------------------------------------------- #
# Hàng đợi lệch
# --------------------------------------------------------------------------- #


@pytest.fixture()
def finding_id(ui):
    from models import DriftFinding, DriftType
    from services import open_drift

    db = ui.db_module.SessionLocal()
    open_drift(db, DriftType.missing_owner, subject_key="thiet-bi-x", detail={"name": "VM-X"})
    db.commit()
    fid = db.scalar(select(DriftFinding)).id
    db.close()
    return fid


def test_dong_finding_qua_ui(ui, finding_id):
    r = ui.get(f"/ui/drift/{finding_id}/resolve-form")
    assert r.status_code == 200
    assert "Xử lý chênh lệch" in r.text

    r = ui.post(
        f"/ui/drift/{finding_id}/resolve",
        data={"status": "resolved", "note": "đã xác minh với chủ máy"},
    )
    assert r.status_code == 200
    assert "Đã xử lý" in r.text

    assert ui.get("/api/v1/drift").json()["count"] == 0


def test_dong_finding_duoc_ghi_audit_kem_ten_that(ui, finding_id):
    ui.post(
        f"/ui/drift/{finding_id}/resolve",
        data={"status": "ignored", "note": "chấp nhận hiện trạng"},
    )

    admin = dict(SYSOPS, **{"X-Dev-Role": "admin"})
    entries = ui.get("/api/v1/audit", headers=admin).json()["entries"]
    resolved = [a for a in entries if a["action"] == "resolve_drift"]
    assert resolved
    assert resolved[0]["actor"] == SYSOPS["X-Dev-User"]


def test_loc_drift_theo_muc_do(ui, finding_id):
    r = ui.get("/ui/drift/table?status=open&severity=critical&sla=")
    assert r.status_code == 200
    assert "Không có finding nào" in r.text

    r = ui.get("/ui/drift/table?status=open&severity=medium&sla=")
    assert "thiet-bi-x" in r.text


def test_viewer_khong_thay_nut_xu_ly_drift(ui, finding_id):
    assert "Xử lý" not in ui.get("/drift", headers=VIEWER).text
    r = ui.get(f"/ui/drift/{finding_id}/resolve-form", headers=VIEWER)
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Quét thủ công — canary phải chặn kết quả không đáng tin
# --------------------------------------------------------------------------- #


def test_quet_that_bai_canary_bao_loi_ro_rang(ui):
    """
    Máy chạy test không có route tới dải trong dữ liệu mẫu, nên canary sẽ
    thất bại. Đó chính là hành vi đúng: thà không có dữ liệu còn hơn có dữ
    liệu sai khiến portal tưởng cả dải đang trống.
    """
    r = ui.post("/ui/scan/run", data={"cidr": CIDR})
    assert r.status_code == 200
    assert "is-error" in r.text
    assert "Canary thất bại" in r.text or "Bỏ qua" in r.text


# --------------------------------------------------------------------------- #
# Tìm kiếm / lọc / phân trang
# --------------------------------------------------------------------------- #


def _count(html: str) -> int:
    m = re.search(r"(\d+) kết quả", html)
    return int(m.group(1)) if m else -1


def test_tim_kiem_theo_ten_ip_va_owner(ui):
    assert _count(ui.get("/ui/vm/table?q=SDC11").text) == 2
    assert _count(ui.get("/ui/vm/table?q=10.0.76.5").text) == 1
    assert _count(ui.get("/ui/vm/table?q=tam.tran").text) == 1
    assert _count(ui.get("/ui/vm/table?q=khongtontai").text) == 0


def test_loc_thieu_thong_tin(ui):
    # Dữ liệu mẫu cố ý có một thiết bị thiếu cả owner lẫn hạn dùng.
    assert _count(ui.get("/ui/vm/table?gap=owner").text) == 1
    assert _count(ui.get("/ui/vm/table?gap=expiry").text) == 1


def test_tim_kiem_khong_lam_ro_ri_du_lieu_don_vi_khac(ui):
    r = ui.get("/ui/vm/table?department=SDC1")
    assert "SDC1-Tiktok-76.5" in r.text
    assert "SDC11-NTT-76.8" not in r.text


# --------------------------------------------------------------------------- #
# Đăng nhập
# --------------------------------------------------------------------------- #


def test_trang_login_hien_thi(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Đăng nhập" in r.text


def test_login_chan_open_redirect(client):
    r = client.post(
        "/ui/login",
        follow_redirects=False,
        data={"username": "a@b.c", "password": "x", "next": "//evil.example.com"},
    )
    assert r.headers["location"] == "/"


def test_login_giu_duoc_duong_dan_noi_bo(client):
    r = client.post(
        "/ui/login",
        follow_redirects=False,
        data={"username": "a@b.c", "password": "x", "next": "/vm"},
    )
    assert r.headers["location"] == "/vm"


# --------------------------------------------------------------------------- #
# XSS trên các fragment mới
# --------------------------------------------------------------------------- #

PAYLOAD = '"><img src=x onerror=alert(1)>'
RAW_TAG = "<img src=x onerror=alert(1)>"


def test_fragment_chi_tiet_ip_escape_ten_thiet_bi(ui):
    from models import Device

    db = ui.db_module.SessionLocal()
    d = db.scalar(select(Device).where(Device.name == "SDC1-Tiktok-76.5"))
    d.name = PAYLOAD
    db.commit()
    db.close()

    html = ui.get("/ui/ip/10.0.76.5").text
    assert RAW_TAG not in html
    assert "&lt;img" in html


def test_toast_loi_escape_noi_dung(ui):
    """Thông báo lỗi có thể chứa dữ liệu người dùng nhập — vẫn phải escape."""
    r = ui.post(
        "/ui/ip/commit",
        data={
            "token": PAYLOAD,
            "device_name": "x",
            "owner_email": "a@b.c",
            "expires_at": "2027-01-01",
        },
    )
    assert RAW_TAG not in r.text


def test_bang_vm_escape_ket_qua_tim_kiem(ui):
    from models import Device

    db = ui.db_module.SessionLocal()
    d = db.scalar(select(Device).where(Device.name == "SDC11-NTT-76.8"))
    d.name = PAYLOAD
    db.commit()
    db.close()

    html = ui.get("/ui/vm/table?q=img").text
    assert RAW_TAG not in html


# --------------------------------------------------------------------------- #
# Giữ chỗ hết hạn
# --------------------------------------------------------------------------- #


def test_chot_cap_bang_token_het_han_bao_loi_ro(ui):
    from models import IPReservation

    token = _token(ui.post(f"/ui/ip/{FREE_IP}/reserve").text)

    db = ui.db_module.SessionLocal()
    res = db.scalar(select(IPReservation).where(IPReservation.token == token))
    res.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    db.close()

    r = ui.post(
        "/ui/ip/commit",
        data={
            "token": token,
            "device_name": "x",
            "owner_email": "a@b.c",
            "expires_at": "2027-01-01",
            "skip_liveness_check": "true",
        },
    )
    assert "is-error" in r.text
    assert "hết hạn" in r.text
