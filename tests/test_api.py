"""
Test tích hợp toàn bộ luồng API.

Đây là bộ test đáng lẽ phải có ngay từ đầu. Bản bàn giao trước có 20/20 unit
test của `allocator` đều xanh, trong khi `POST /api/v1/ipam/suggest` trả lỗi
500 — vì allocator được tách khỏi DB "để test được", rồi chỉ phần tách ra đó
được test. Tầng chuyển đổi DB -> thuật toán, nơi thực sự hỏng, không có một
dòng test nào.

Nguyên tắc: mỗi chốt an toàn trong TECHNICAL-SPEC phải có một test chứng minh
nó không đi vòng được.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from tests.factories import CIDR, seed_minimal

pytestmark = pytest.mark.usefixtures("client")

DEV = {"X-Dev-User": "quang@ntq-solution.com.vn", "X-Dev-Role": "sysops"}


@pytest.fixture()
def api(client):
    seed_minimal(client.db_module.SessionLocal())
    client.headers.update(DEV)
    return client


# --------------------------------------------------------------------------- #
# Đọc
# --------------------------------------------------------------------------- #


def test_healthz_khong_can_dang_nhap(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["database"] is True


def test_liet_ke_subnet(api):
    r = api.get("/api/v1/subnets")
    assert r.status_code == 200
    subnets = r.json()["subnets"]
    assert len(subnets) == 1
    assert subnets[0]["cidr"] == CIDR


def test_ban_do_dai_mang(api):
    r = api.get(f"/api/v1/subnets/{CIDR}/map")
    assert r.status_code == 200
    data = r.json()
    assert len(data["addresses"]) == 254
    allocated = [a for a in data["addresses"] if a["status"] == "allocated"]
    assert len(allocated) == 3
    assert allocated[0]["device"]["name"]


def test_suggest_tra_ve_ung_vien_co_ly_do(api):
    """Tính năng cốt lõi. Bản trước lỗi 500 ở đúng endpoint này."""
    r = api.post(
        "/api/v1/ipam/suggest", json={"subnet": CIDR, "department": "SDC11", "quantity": 1}
    )
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["suggestions"], "phải có ít nhất một gợi ý"
    top = data["suggestions"][0]
    assert top["reasons"], "mọi gợi ý phải giải thích được vì sao"
    assert 0.0 <= top["confidence"] <= 1.0
    assert data["scanner_warning"] is None, "scanner khoẻ thì không cảnh báo"


def test_suggest_dai_lien_tiep(api):
    r = api.post("/api/v1/ipam/suggest", json={"subnet": CIDR, "quantity": 5, "contiguous": True})
    assert r.status_code == 200
    blocks = r.json()["blocks"]
    assert blocks
    assert len(blocks[0]["addresses"]) == 5


# --------------------------------------------------------------------------- #
# Vòng đời cấp phát
# --------------------------------------------------------------------------- #


def test_luong_day_du_reserve_commit_release(api):
    addr = "10.0.76.45"

    r = api.post("/api/v1/ipam/reserve", json={"address": addr, "purpose": "test"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert r.json()["reserved_by"] == DEV["X-Dev-User"]

    r = api.post(
        "/api/v1/ipam/commit",
        json={
            "token": token,
            "device_name": "SDC11-TEST-76.45",
            "owner_email": "quang@ntq-solution.com.vn",
            "department": "SDC11",
            "expires_at": "2027-01-01",
            "cpu_cores": 2,
            "ram_gb": 4,
            "disk_gb": 50,
            "skip_liveness_check": True,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "allocated"

    r = api.post("/api/v1/ipam/release", json={"address": addr, "reason": "test"})
    assert r.status_code == 200
    assert r.json()["status"] == "quarantine"
    assert r.json()["cooldown_days"] == 14


def test_reserve_hai_lan_thi_nguoi_thu_hai_bi_tu_choi(api):
    addr = "10.0.76.46"
    assert api.post("/api/v1/ipam/reserve", json={"address": addr}).status_code == 200

    other = dict(DEV, **{"X-Dev-User": "khac@ntq-solution.com.vn"})
    r = api.post("/api/v1/ipam/reserve", json={"address": addr}, headers=other)
    assert r.status_code == 409
    assert "giữ chỗ" in r.json()["detail"]


def test_commit_bang_token_cua_nguoi_khac_bi_chan(api):
    r = api.post("/api/v1/ipam/reserve", json={"address": "10.0.76.47"})
    token = r.json()["token"]

    intruder = {"X-Dev-User": "ke.la@ntq-solution.com.vn", "X-Dev-Role": "requester"}
    r = api.post(
        "/api/v1/ipam/commit",
        json={
            "token": token,
            "device_name": "x",
            "owner_email": "a@b.c",
            "skip_liveness_check": True,
        },
        headers=intruder,
    )
    assert r.status_code == 403


def test_bo_qua_xac_minh_truc_tiep_chi_danh_cho_sysops(api):
    r = api.post("/api/v1/ipam/reserve", json={"address": "10.0.76.48"})
    token = r.json()["token"]

    req = {"X-Dev-User": "quang@ntq-solution.com.vn", "X-Dev-Role": "requester"}
    r = api.post(
        "/api/v1/ipam/commit",
        json={
            "token": token,
            "device_name": "x",
            "owner_email": "a@b.c",
            "skip_liveness_check": True,
        },
        headers=req,
    )
    assert r.status_code == 403
    assert "sysops" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# Chốt an toàn: cách ly
# --------------------------------------------------------------------------- #


def test_khong_reserve_duoc_ip_dang_cach_ly(api):
    """
    Lỗ hổng nghiêm trọng của bản trước: engine gợi ý tôn trọng cooldown, nhưng
    endpoint reserve thì không kiểm tra. Một lời gọi API trực tiếp vô hiệu hoá
    toàn bộ cơ chế cách ly (TECHNICAL-SPEC §3.4).
    """
    addr = "10.0.76.45"
    api.post("/api/v1/ipam/reserve", json={"address": addr})
    r = api.post(
        "/api/v1/ipam/commit",
        json={
            "token": api.post("/api/v1/ipam/reserve", json={"address": "10.0.76.49"}).json()[
                "token"
            ],
            "device_name": "tmp",
            "owner_email": "a@b.c",
            "skip_liveness_check": True,
        },
    )
    assert r.status_code == 200

    # Thu hồi 10.0.76.49 -> vào cách ly
    api.post("/api/v1/ipam/release", json={"address": "10.0.76.49"})

    r = api.post("/api/v1/ipam/reserve", json={"address": "10.0.76.49"})
    assert r.status_code == 409, "IP đang cách ly mà vẫn giữ chỗ được"
    assert "cách ly" in r.json()["detail"]


def test_ip_cach_ly_khong_xuat_hien_trong_goi_y(api):
    addr = "10.0.76.44"
    token = api.post("/api/v1/ipam/reserve", json={"address": addr}).json()["token"]
    api.post(
        "/api/v1/ipam/commit",
        json={
            "token": token,
            "device_name": "tmp2",
            "owner_email": "a@b.c",
            "skip_liveness_check": True,
        },
    )
    api.post("/api/v1/ipam/release", json={"address": addr})

    r = api.post("/api/v1/ipam/suggest", json={"subnet": CIDR, "limit": 20})
    assert addr not in [s["address"] for s in r.json()["suggestions"]]


# --------------------------------------------------------------------------- #
# Dead man switch qua API
# --------------------------------------------------------------------------- #


def test_scanner_chet_thi_api_ha_do_tin_cay_va_canh_bao(client):
    seed_minimal(client.db_module.SessionLocal(), scanner_healthy=False)
    client.headers.update(DEV)

    r = client.post("/api/v1/ipam/suggest", json={"subnet": CIDR, "limit": 5})
    assert r.status_code == 200
    data = r.json()

    assert data["scanner_warning"], "phải cảnh báo khi chưa từng quét thành công"
    for s in data["suggestions"]:
        assert s["confidence_label"] != "An toàn cấp ngay"

    health = client.get("/api/v1/reports/scanner-health").json()
    assert health["healthy"] is False
    assert health["stale_subnets"] == 1


def test_bao_cao_suc_khoe_scanner_khi_binh_thuong(api):
    h = api.get("/api/v1/reports/scanner-health").json()
    assert h["healthy"] is True
    assert h["stale_subnets"] == 0


# --------------------------------------------------------------------------- #
# XSS
# --------------------------------------------------------------------------- #


PAYLOAD = '"><img src=x onerror=alert(1)>'

# Chuỗi ký tự "onerror=alert(1)" tự nó không chứa ký tự HTML đặc biệt nào
# (không có <, >, ", &), nên nó vẫn xuất hiện y nguyên trong output kể cả khi
# đã escape đúng — Jinja chỉ escape <, >, &, ", '. Bài kiểm tra thật sự là:
# thẻ <img> có được DIỄN GIẢI thành thẻ thật hay không, tức là ký tự `<`
# (mở thẻ) có bị escape thành `&lt;` hay không.
_RAW_TAG = "<img src=x onerror=alert(1)>"


def test_ten_thiet_bi_doc_hai_bi_escape_trong_ban_do(api):
    """
    XSS lưu trữ đã khai thác được ở bản trước: UI dựng HTML bằng f-string, nên
    tên VM — dữ liệu từ vCenter và CSV, tức nguồn không tin cậy — chạy thẳng
    vào DOM của trình duyệt đội System.
    """
    from models import Device

    db = api.db_module.SessionLocal()
    d = db.scalar(select(Device).where(Device.name == "SDC1-Tiktok-76.5"))
    d.name = PAYLOAD
    db.commit()
    db.close()

    # Tên thiết bị hiện trong tooltip của từng ô trên bản đồ IP (trang /ip).
    html = api.get("/ip").text
    assert _RAW_TAG not in html, "thẻ <img> chạy được nguyên vẹn trong DOM"
    assert "&lt;img" in html, "phải được escape thành thực thể HTML"


def test_ten_thiet_bi_doc_hai_bi_escape_trong_goi_y(api):
    from models import Department

    db = api.db_module.SessionLocal()
    db.add(Department(code=PAYLOAD, name=PAYLOAD))
    db.commit()
    db.close()

    html = api.post(
        "/ui/suggest",
        data={"subnet": CIDR, "department": PAYLOAD, "quantity": "1", "contiguous": "false"},
    ).text
    assert _RAW_TAG not in html, "thẻ <img> chạy được nguyên vẹn trong DOM"
    assert "&lt;img" in html, "phải được escape thành thực thể HTML"


# --------------------------------------------------------------------------- #
# Inventory / drift / báo cáo
# --------------------------------------------------------------------------- #


def test_tao_va_sua_thiet_bi_ghi_audit(api):
    r = api.post(
        "/api/v1/devices",
        json={
            "name": "SDC11-MOI-01",
            "owner_email": "a@ntq-solution.com.vn",
            "department": "SDC11",
            "cpu_cores": 2,
            "ram_gb": 4,
        },
    )
    assert r.status_code == 201, r.text
    did = r.json()["id"]

    r = api.patch(f"/api/v1/devices/{did}", json={"owner_email": "b@ntq-solution.com.vn"})
    assert r.status_code == 200
    assert "owner_email" in r.json()["changed"]

    # /api/v1/audit đòi vai trò admin — DEV cố định là "sysops", nên phải
    # nâng quyền riêng cho lời gọi này thay vì hạ yêu cầu của endpoint.
    admin = dict(DEV, **{"X-Dev-Role": "admin"})
    r = api.get("/api/v1/audit", params={"entity_id": did}, headers=admin)
    assert r.status_code == 200, r.text
    audit = r.json()["entries"]
    actions = {a["action"] for a in audit}
    assert {"create_device", "update_device"} <= actions
    assert all(a["actor"] == DEV["X-Dev-User"] for a in audit)


def test_audit_tu_choi_khi_khong_du_quyen(api):
    r = api.get("/api/v1/audit")  # DEV = role sysops, không đủ cho ADMIN
    assert r.status_code == 403


def test_credential_khong_bao_gio_tra_ve_gia_tri(api):
    from models import CredentialRef, Device

    db = api.db_module.SessionLocal()
    d = db.scalars(select(Device)).first()
    db.add(
        CredentialRef(
            device_id=d.id, auth_type="ssh_key", username="ntq", vault_path="secret/data/vm/test"
        )
    )
    db.commit()
    did = d.id
    db.close()

    body = api.get(f"/api/v1/devices/{did}/credentials").json()
    assert body["credentials"][0]["vault_path"] == "secret/data/vm/test"
    assert "password" not in str(body).lower()
    assert "secret_value" not in str(body)


def test_bao_cao_chat_luong_du_lieu(api):
    q = api.get("/api/v1/reports/data-quality").json()
    assert q["total_devices"] == 3
    # 1 trong 3 device cố tình thiếu owner
    assert q["has_owner_pct"] == pytest.approx(66.7, abs=0.2)


def test_bao_tri_don_giu_cho_het_han(api):
    r = api.post("/api/v1/ipam/reserve", json={"address": "10.0.76.43", "ttl_minutes": 1})
    assert r.status_code == 200

    from models import IPReservation

    db = api.db_module.SessionLocal()
    res = db.scalar(select(IPReservation))
    res.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.commit()
    db.close()

    r = api.post("/api/v1/maintenance/expire-reservations")
    assert r.json()["released"] == 1

    r = api.post("/api/v1/ipam/suggest", json={"subnet": CIDR, "limit": 20})
    assert r.status_code == 200, r.text
    assert "10.0.76.43" in [s["address"] for s in r.json()["suggestions"]]


def test_bao_tri_ket_thuc_cach_ly(api):
    from models import IPAddress

    addr = "10.0.76.42"
    token = api.post("/api/v1/ipam/reserve", json={"address": addr}).json()["token"]
    api.post(
        "/api/v1/ipam/commit",
        json={
            "token": token,
            "device_name": "tmp3",
            "owner_email": "a@b.c",
            "skip_liveness_check": True,
        },
    )
    api.post("/api/v1/ipam/release", json={"address": addr})

    db = api.db_module.SessionLocal()
    ip = db.scalar(select(IPAddress).where(IPAddress.address == addr))
    ip.released_at = datetime.now(timezone.utc) - timedelta(days=20)
    db.commit()
    db.close()

    assert api.post("/api/v1/maintenance/expire-quarantine").json()["freed"] == 1


def test_endpoint_theo_spec_deu_ton_tai(api):
    """
    TECHNICAL-SPEC §7 liệt kê các endpoint này; bản trước thiếu hẳn chúng
    trong khi README ghi 'Hoàn chỉnh'.
    """
    schema = api.get("/openapi.json").json()["paths"]
    for path in [
        "/api/v1/subnets",
        "/api/v1/ipam/suggest",
        "/api/v1/ipam/reserve",
        "/api/v1/ipam/commit",
        "/api/v1/ipam/release",
        "/api/v1/devices",
        "/api/v1/devices/{device_id}/credentials",
        "/api/v1/drift",
        "/api/v1/sync/vcenter",
        "/api/v1/reports/utilization",
        "/api/v1/reports/expiring",
    ]:
        assert path in schema, f"thiếu endpoint {path}"

    assert "post" in schema["/api/v1/devices"]
    assert "patch" in schema["/api/v1/devices/{device_id}"]
