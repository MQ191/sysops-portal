"""
Unit test cho thuật toán gợi ý IP.

Chạy:  pytest test_allocator.py -v

Không cần database — allocator.py cố ý được viết thuần Python
để logic nghiệp vụ quan trọng nhất có thể test nhanh và chắc.
"""

from datetime import datetime, timedelta, timezone

import pytest

import allocator as A

NOW = datetime(2026, 7, 30, 9, 0, tzinfo=timezone.utc)


def ctx(**kw) -> A.SubnetContext:
    defaults = dict(
        cidr="10.0.76.0/24",
        gateway="10.0.76.254",
        reserved_ranges=[A.ReservedRange("10.0.76.1", "10.0.76.4", "network infra")],
        allocation_policy=A.POLICY_LOWEST_FIRST,
        cooldown_days=14,
        name="Dải VM dự án",
        # Mặc định: scanner khoẻ. Phải khai tường minh, vì mặc định của
        # SubnetContext là "chưa từng quét" — trạng thái đó cố tình làm
        # confidence sụp xuống (xem nhóm test dead man switch bên dưới).
        last_scan_ok_at=NOW - timedelta(hours=1),
    )
    defaults.update(kw)
    return A.SubnetContext(**defaults)


def allocated(addr: str, dept: str = "SDC11", crit: str = "normal") -> A.IPRecord:
    return A.IPRecord(
        address=addr,
        status=A.STATUS_ALLOCATED,
        department=dept,
        criticality=crit,
        ever_assigned=True,
    )


def free(addr: str, dead: int = 20, scans: int = 8, **kw) -> A.IPRecord:
    return A.IPRecord(
        address=addr,
        status=A.STATUS_FREE,
        consecutive_dead_scans=dead,
        scans_last_7d=scans,
        **kw,
    )


# --------------------------------------------------------------------------- #
# Lọc cứng
# --------------------------------------------------------------------------- #


def test_loai_dia_chi_ha_tang():
    c = ctx()
    records = A.build_records_for_subnet(c)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))
    addrs = {s.address for s in result.suggestions}

    assert "10.0.76.0" not in addrs, "địa chỉ network phải bị loại"
    assert "10.0.76.255" not in addrs, "địa chỉ broadcast phải bị loại"
    assert "10.0.76.254" not in addrs, "gateway phải bị loại"
    for i in range(1, 5):
        assert f"10.0.76.{i}" not in addrs, "vùng reserved phải bị loại"


def test_loai_ip_da_cap_va_bi_khoa():
    c = ctx()
    known = {
        "10.0.76.10": allocated("10.0.76.10"),
        "10.0.76.11": A.IPRecord("10.0.76.11", status=A.STATUS_BLOCKED),
        "10.0.76.12": A.IPRecord("10.0.76.12", status=A.STATUS_CONFLICT),
    }
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))
    addrs = {s.address for s in result.suggestions}

    assert addrs.isdisjoint({"10.0.76.10", "10.0.76.11", "10.0.76.12"})


def test_ip_dang_cach_ly_khong_duoc_goi_y():
    c = ctx(cooldown_days=14)
    known = {
        "10.0.76.20": A.IPRecord(
            "10.0.76.20",
            status=A.STATUS_QUARANTINE,
            released_at=NOW - timedelta(days=3),  # mới 3/14 ngày
            ever_assigned=True,
        )
    }
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))

    assert "10.0.76.20" not in {s.address for s in result.suggestions}
    assert any("cách ly" in k for k in result.rejected_summary)


def test_het_cach_ly_thi_duoc_goi_y_lai():
    c = ctx(cooldown_days=14)
    known = {
        "10.0.76.20": A.IPRecord(
            "10.0.76.20",
            status=A.STATUS_QUARANTINE,
            released_at=NOW - timedelta(days=40),
            ever_assigned=True,
            consecutive_dead_scans=30,
            scans_last_7d=8,
        )
    }
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))

    assert "10.0.76.20" in {s.address for s in result.suggestions}


def test_ip_vua_thay_song_bi_loai_du_db_ghi_free():
    """Bảo vệ quan trọng nhất: DB nói trống nhưng thực tế có máy."""
    c = ctx()
    known = {
        "10.0.76.30": A.IPRecord(
            "10.0.76.30",
            status=A.STATUS_FREE,
            last_seen_alive_at=NOW - timedelta(days=2),
        )
    }
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))

    assert "10.0.76.30" not in {s.address for s in result.suggestions}


def test_reservation_con_han_bi_loai_het_han_thi_khong():
    c = ctx()
    known = {
        "10.0.76.40": A.IPRecord(
            "10.0.76.40",
            status=A.STATUS_RESERVED,
            reserved_until=NOW + timedelta(minutes=20),
        ),
        "10.0.76.41": A.IPRecord(
            "10.0.76.41",
            status=A.STATUS_RESERVED,
            reserved_until=NOW - timedelta(minutes=5),
        ),
    }
    records = A.build_records_for_subnet(c, known)
    addrs = {
        s.address
        for s in A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW)).suggestions
    }

    assert "10.0.76.40" not in addrs
    assert "10.0.76.41" in addrs, "giữ chỗ hết hạn phải được coi là trống"


# --------------------------------------------------------------------------- #
# Chấm điểm
# --------------------------------------------------------------------------- #


def test_uu_tien_ip_gan_block_cua_don_vi():
    c = ctx(allocation_policy=A.POLICY_SPARSE)
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}", "SDC11") for i in range(16, 22)}
    records = A.build_records_for_subnet(c, known)

    result = A.suggest(c, records, A.SuggestionRequest(department="SDC11", limit=5, now=NOW))
    top = result.suggestions[0]
    octet = int(top.address.split(".")[-1])

    assert 22 <= octet <= 40, f"phải chọn IP gần block SDC11, nhận {top.address}"
    assert any("block SDC11" in r for r in top.reasons)


def test_tranh_ip_sat_he_thong_critical():
    c = ctx(allocation_policy=A.POLICY_LOWEST_FIRST)
    known = {"10.0.76.10": allocated("10.0.76.10", "SDC1", crit="critical")}
    records = A.build_records_for_subnet(c, known)

    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))
    by_addr = {s.address: s for s in result.suggestions}

    # 10.0.76.9 nằm sát VM critical -> phải bị phạt điểm so với 10.0.76.7
    assert by_addr["10.0.76.9"].score < by_addr["10.0.76.7"].score
    assert any("production" in w for w in by_addr["10.0.76.9"].warnings)


def test_phat_ip_co_lich_su_xung_dot():
    c = ctx()
    known = {
        "10.0.76.50": free("10.0.76.50", conflict_count=4, ever_assigned=True),
        "10.0.76.51": free("10.0.76.51", ever_assigned=True),
    }
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW))
    by_addr = {s.address: s for s in result.suggestions}

    assert by_addr["10.0.76.50"].score < by_addr["10.0.76.51"].score
    assert any("xung đột" in w for w in by_addr["10.0.76.50"].warnings)


def test_uu_tien_ip_chua_tung_dung():
    c = ctx()
    known = {
        "10.0.76.60": free("10.0.76.60", ever_assigned=True, released_at=NOW - timedelta(days=200)),
        "10.0.76.61": free("10.0.76.61", ever_assigned=False),
    }
    records = A.build_records_for_subnet(c, known)
    by_addr = {
        s.address: s
        for s in A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW)).suggestions
    }

    assert by_addr["10.0.76.61"].score > by_addr["10.0.76.60"].score


def test_policy_lowest_first_uu_tien_ip_nho():
    c = ctx(allocation_policy=A.POLICY_LOWEST_FIRST)
    records = A.build_records_for_subnet(c)
    result = A.suggest(c, records, A.SuggestionRequest(limit=3, now=NOW))

    assert result.suggestions[0].address == "10.0.76.5", (
        "IP nhỏ nhất còn dùng được (sau vùng reserved 1-4) phải đứng đầu"
    )


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #


def test_confidence_cao_khi_du_du_lieu_quet():
    c = ctx()
    known = {"10.0.76.70": free("10.0.76.70", dead=30, scans=10)}
    records = A.build_records_for_subnet(c, known)
    s = next(
        x
        for x in A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW)).suggestions
        if x.address == "10.0.76.70"
    )
    assert s.confidence >= 0.85
    assert A.confidence_label(s.confidence) == "An toàn cấp ngay"


def test_confidence_thap_khi_thieu_du_lieu_quet():
    c = ctx()
    known = {
        "10.0.76.71": A.IPRecord(
            "10.0.76.71",
            status=A.STATUS_FREE,
            scans_last_7d=0,
            ever_assigned=True,
            released_at=NOW - timedelta(days=20),
            has_arp_or_dns_record=True,
        )
    }
    records = A.build_records_for_subnet(c, known)
    s = next(
        x
        for x in A.suggest(c, records, A.SuggestionRequest(limit=254, now=NOW)).suggestions
        if x.address == "10.0.76.71"
    )
    assert s.confidence < 0.6
    assert any("quét" in w for w in s.warnings)


# --------------------------------------------------------------------------- #
# Dải liên tiếp
# --------------------------------------------------------------------------- #


def test_tim_duoc_dai_lien_tiep():
    c = ctx()
    # Chặn rải rác để chỉ còn một vùng liên tiếp đủ rộng
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}") for i in range(5, 60)}
    for i in range(60, 70):
        known[f"10.0.76.{i}"] = free(f"10.0.76.{i}")
    for i in range(70, 254):
        known[f"10.0.76.{i}"] = allocated(f"10.0.76.{i}")

    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(quantity=5, contiguous=True, now=NOW))

    assert result.blocks, "phải tìm được ít nhất một dải"
    block = result.blocks[0]
    assert len(block.addresses) == 5
    assert block.gaps == 0
    octets = [int(a.split(".")[-1]) for a in block.addresses]
    assert octets == list(range(octets[0], octets[0] + 5))


def test_ha_cap_sang_gan_lien_tiep_khi_khong_du():
    c = ctx()
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}") for i in range(5, 254)}
    # Chỉ chừa ra 3 IP với 1 lỗ hổng xen giữa
    for i in (100, 101, 103):
        known[f"10.0.76.{i}"] = free(f"10.0.76.{i}")

    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(quantity=3, contiguous=True, now=NOW))

    assert result.blocks
    assert result.blocks[0].gaps > 0
    assert any("liên tiếp" in w for w in result.blocks[0].warnings)


def test_cac_dai_de_xuat_khong_chong_lan():
    c = ctx()
    records = A.build_records_for_subnet(c)
    result = A.suggest(c, records, A.SuggestionRequest(quantity=4, contiguous=True, now=NOW))
    seen: set[str] = set()
    for b in result.blocks:
        assert seen.isdisjoint(b.addresses), "các dải đề xuất không được trùng IP"
        seen.update(b.addresses)


# --------------------------------------------------------------------------- #
# Thống kê & giải thích
# --------------------------------------------------------------------------- #


def test_canh_bao_khi_dai_sap_can():
    c = ctx()
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}") for i in range(5, 240)}
    records = A.build_records_for_subnet(c, known)
    stats = A.subnet_stats(c, records, NOW)

    assert stats["utilization"] > 0.85
    assert stats["exhaustion_warning"] is True


def test_giai_thich_ly_do_khi_khong_con_ip():
    """Đội System hay bị hỏi 'sao hết IP?' — hệ thống phải trả lời được."""
    c = ctx()
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}") for i in range(5, 254)}
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(now=NOW))

    assert result.suggestions == []
    assert result.rejected_summary
    assert "Đã cấp cho thiết bị khác" in result.rejected_summary


def test_moi_goi_y_deu_co_ly_do_doc_duoc():
    c = ctx()
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}", "SDC11") for i in range(16, 22)}
    records = A.build_records_for_subnet(c, known)
    result = A.suggest(c, records, A.SuggestionRequest(department="SDC11", limit=5, now=NOW))

    for s in result.suggestions:
        assert s.reasons, f"{s.address} thiếu lý do giải thích"
        assert 0.0 <= s.confidence <= 1.0


def test_ket_qua_on_dinh_khi_chay_lai():
    """Cùng đầu vào phải cho cùng thứ tự — không phụ thuộc thứ tự duyệt."""
    c = ctx()
    known = {f"10.0.76.{i}": allocated(f"10.0.76.{i}", "SDC11") for i in range(16, 30)}
    records = A.build_records_for_subnet(c, known)
    req = A.SuggestionRequest(department="SDC11", limit=5, now=NOW)

    first = [s.address for s in A.suggest(c, records, req).suggestions]
    second = [s.address for s in A.suggest(c, list(reversed(records)), req).suggestions]

    assert first == second


# --------------------------------------------------------------------------- #
# Dead man switch — chống chế độ "càng hỏng càng tự tin"
# --------------------------------------------------------------------------- #


def test_scanner_chet_thi_confidence_sup_xuong():
    """
    Chế độ hỏng nguy hiểm nhất: scanner mất route hoặc thiếu quyền raw socket
    => mọi IP bị coi là chết => dead_streak tăng => portal tự tin gợi ý IP
    đang có máy production chạy. Confidence phải sụp, không được trôi lên.
    """
    healthy = ctx()
    dead = ctx(last_scan_ok_at=NOW - timedelta(hours=48))
    known = {"10.0.76.70": free("10.0.76.70", dead=30, scans=10)}

    def conf(c):
        r = A.suggest(
            c, A.build_records_for_subnet(c, known), A.SuggestionRequest(limit=254, now=NOW)
        )
        return next(x for x in r.suggestions if x.address == "10.0.76.70").confidence

    assert conf(healthy) >= 0.85
    assert conf(dead) < 0.60, "scanner chết mà confidence vẫn cao là lỗi chí mạng"


def test_chua_tung_quet_thi_khong_bao_gio_an_toan_cap_ngay():
    c = ctx(last_scan_ok_at=None)
    known = {"10.0.76.70": free("10.0.76.70", dead=30, scans=99)}
    result = A.suggest(
        c, A.build_records_for_subnet(c, known), A.SuggestionRequest(limit=254, now=NOW)
    )
    s = next(x for x in result.suggestions if x.address == "10.0.76.70")

    assert A.confidence_label(s.confidence) != "An toàn cấp ngay"
    assert result.scanner_warning
    assert "CHƯA từng được quét" in result.scanner_warning


def test_canh_bao_scanner_di_kem_tung_ung_vien():
    """Kỹ sư hay copy một dòng gợi ý rồi đi cấp máy — cảnh báo phải nằm ở dòng đó."""
    c = ctx(last_scan_ok_at=NOW - timedelta(hours=48))
    result = A.suggest(c, A.build_records_for_subnet(c), A.SuggestionRequest(limit=5, now=NOW))

    assert result.suggestions
    for s in result.suggestions:
        assert any("Scanner chưa báo cáo" in w for w in s.warnings)


def test_scanner_khoe_thi_khong_canh_bao_thua():
    c = ctx(last_scan_ok_at=NOW - timedelta(hours=2))
    result = A.suggest(c, A.build_records_for_subnet(c), A.SuggestionRequest(limit=5, now=NOW))

    assert result.scanner_warning is None
    for s in result.suggestions:
        assert not any("Scanner chưa báo cáo" in w for w in s.warnings)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
