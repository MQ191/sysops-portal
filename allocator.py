"""
SysOps Portal — IP Suggestion Engine
====================================

Thuật toán gợi ý IP trống cho việc cấp phát VM/server mới.

Module này CỐ Ý không phụ thuộc vào database hay framework nào:
đầu vào là danh sách IPRecord thuần, đầu ra là danh sách ứng viên đã xếp hạng.
Nhờ vậy có thể unit-test toàn bộ logic nghiệp vụ mà không cần dựng Postgres.

Tài liệu tham chiếu: docs/TECHNICAL-SPEC.md §4
"""

from __future__ import annotations

import ipaddress
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------- #
# Hằng số trạng thái
# --------------------------------------------------------------------------- #

STATUS_FREE = "free"
STATUS_RESERVED = "reserved"
STATUS_ALLOCATED = "allocated"
STATUS_QUARANTINE = "quarantine"
STATUS_BLOCKED = "blocked"
STATUS_CONFLICT = "conflict"

CRITICALITY_LOW = "low"
CRITICALITY_NORMAL = "normal"
CRITICALITY_CRITICAL = "critical"

POLICY_LOWEST_FIRST = "lowest_first"
POLICY_FILL_GAPS = "fill_gaps"
POLICY_SPARSE = "sparse"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Cấu trúc dữ liệu đầu vào
# --------------------------------------------------------------------------- #


@dataclass
class ReservedRange:
    """Vùng địa chỉ bị loại khỏi cấp phát tự động (gateway, switch, firewall...)."""

    start: str
    end: str
    reason: str = ""

    def contains(self, addr_int: int) -> bool:
        return (
            int(ipaddress.ip_address(self.start)) <= addr_int <= int(ipaddress.ip_address(self.end))
        )


@dataclass
class ScoringWeights:
    """
    Trọng số chấm điểm. Đặt ở đây thay vì hardcode để mỗi tổ chức
    tinh chỉnh theo khẩu vị rủi ro riêng mà không phải sửa thuật toán.
    """

    base: float = 100.0
    block_affinity: float = 35.0
    dead_streak: float = 25.0
    never_used: float = 20.0
    policy_fit: float = 15.0
    neighbor_risk: float = -20.0
    recent_release: float = -15.0
    conflict_history: float = -25.0

    # Ngưỡng hành vi
    freshness_window_days: int = 7  # thấy sống trong khoảng này => loại thẳng
    dead_streak_cap: int = 30  # số lần quét chết để đạt điểm tối đa
    affinity_near_window: int = 32  # coi là "gần block" nếu cách <= 32 địa chỉ
    neighbor_radius: int = 2  # bán kính xét rủi ro hàng xóm
    min_scans_for_confidence: int = 5

    # Trần confidence khi dữ liệu quét đã cũ. Đặt DƯỚI ngưỡng đỏ 0.60 để UI
    # luôn hiện "Dữ liệu quét chưa đủ" thay vì "An toàn cấp ngay".
    stale_scan_confidence_cap: float = 0.35


@dataclass
class SubnetContext:
    """Thông tin dải mạng cần cho việc chấm điểm."""

    cidr: str
    gateway: str | None = None
    reserved_ranges: list[ReservedRange] = field(default_factory=list)
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None
    allocation_policy: str = POLICY_LOWEST_FIRST
    cooldown_days: int = 14
    name: str = ""

    # --- Dead man switch ---
    # Mốc lần quét gần nhất ĐƯỢC XÁC THỰC là đáng tin (đã qua canary gateway).
    # None = chưa từng quét thành công.
    last_scan_ok_at: datetime | None = None
    scan_staleness_hours: int = 12

    def __post_init__(self) -> None:
        self.network = ipaddress.ip_network(self.cidr, strict=False)
        self.network_int = int(self.network.network_address)
        self.broadcast_int = int(self.network.broadcast_address)
        self.size = self.network.num_addresses

    def scan_data_is_stale(self, now: datetime) -> bool:
        """
        Scanner có đang thực sự nhìn thấy dải này không?

        Đây là chốt chặn cho chế độ hỏng nguy hiểm nhất của toàn hệ thống:
        khi scanner chết (mất route, thiếu quyền raw socket, container sai
        capability), mọi IP đều bị ghi nhận là "chết". `consecutive_dead_scans`
        tăng đều, `score` tăng, `confidence` tăng — và portal tự tin gợi ý
        "An toàn cấp ngay" cho những IP đang có máy production chạy.

        Nói cách khác: hệ thống càng hỏng thì càng tự tin. Không có hàm này
        thì không có gì phát hiện ra điều đó.
        """
        if self.last_scan_ok_at is None:
            return True
        return now - self.last_scan_ok_at > timedelta(hours=self.scan_staleness_hours)

    def staleness_warning(self, now: datetime) -> str | None:
        if not self.scan_data_is_stale(now):
            return None
        if self.last_scan_ok_at is None:
            return (
                "Dải này CHƯA từng được quét thành công — mọi đánh giá "
                "'IP trống' dưới đây chỉ dựa trên khai báo trong hệ thống, "
                "không có bằng chứng thực tế. Bắt buộc ping tay trước khi cấp."
            )
        hours = int((now - self.last_scan_ok_at).total_seconds() // 3600)
        return (
            f"Scanner chưa báo cáo thành công trong {hours} giờ "
            f"(ngưỡng {self.scan_staleness_hours} giờ). Dữ liệu 'IP trống' "
            "có thể đã lỗi thời — kiểm tra scanner trước khi tin kết quả này."
        )

    def is_structurally_unusable(self, addr_int: int) -> str | None:
        """Loại các địa chỉ không bao giờ được cấp, không phụ thuộc trạng thái DB."""
        if self.network.prefixlen < 31:
            if addr_int == self.network_int:
                return "Địa chỉ network"
            if addr_int == self.broadcast_int:
                return "Địa chỉ broadcast"
        if self.gateway and addr_int == int(ipaddress.ip_address(self.gateway)):
            return "Địa chỉ gateway"
        for rr in self.reserved_ranges:
            if rr.contains(addr_int):
                return f"Nằm trong vùng dành riêng ({rr.reason or 'reserved'})"
        if self.dhcp_range_start and self.dhcp_range_end:
            lo = int(ipaddress.ip_address(self.dhcp_range_start))
            hi = int(ipaddress.ip_address(self.dhcp_range_end))
            if lo <= addr_int <= hi:
                return "Nằm trong dải DHCP động"
        return None


@dataclass
class IPRecord:
    """Ảnh chụp trạng thái một địa chỉ IP, lấy từ bảng ip_address."""

    address: str
    status: str = STATUS_FREE

    # Dữ liệu từ network scan
    consecutive_dead_scans: int = 0
    last_seen_alive_at: datetime | None = None
    scans_last_7d: int = 0
    has_arp_or_dns_record: bool = False

    # Lịch sử cấp phát
    ever_assigned: bool = False
    released_at: datetime | None = None
    conflict_count: int = 0

    # Thông tin device đang giữ IP này (chỉ có khi status = allocated)
    department: str | None = None
    project: str | None = None
    criticality: str = CRITICALITY_NORMAL

    # Soft-lock
    reserved_until: datetime | None = None

    def __post_init__(self) -> None:
        self.addr_int = int(ipaddress.ip_address(self.address))


@dataclass
class SuggestionRequest:
    department: str | None = None
    project: str | None = None
    quantity: int = 1
    contiguous: bool = False
    limit: int = 5
    allow_gaps: int = 0  # số lỗ hổng cho phép khi tìm dải "gần liên tiếp"
    now: datetime | None = None


# --------------------------------------------------------------------------- #
# Cấu trúc dữ liệu đầu ra
# --------------------------------------------------------------------------- #


@dataclass
class Candidate:
    address: str
    score: float
    confidence: float
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "score": round(self.score, 1),
            "confidence": round(self.confidence, 2),
            "confidence_label": confidence_label(self.confidence),
            "reasons": self.reasons,
            "warnings": self.warnings,
        }


@dataclass
class ContiguousBlock:
    addresses: list[str]
    score: float
    confidence: float
    gaps: int = 0
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "addresses": self.addresses,
            "score": round(self.score, 1),
            "confidence": round(self.confidence, 2),
            "gaps": self.gaps,
            "warnings": self.warnings,
        }


@dataclass
class SuggestionResult:
    suggestions: list[Candidate] = field(default_factory=list)
    blocks: list[ContiguousBlock] = field(default_factory=list)
    subnet_stats: dict = field(default_factory=dict)
    rejected_summary: dict = field(default_factory=dict)
    scanner_warning: str | None = None

    def as_dict(self) -> dict:
        return {
            "suggestions": [c.as_dict() for c in self.suggestions],
            "blocks": [b.as_dict() for b in self.blocks],
            "subnet_stats": self.subnet_stats,
            "rejected_summary": self.rejected_summary,
            "scanner_warning": self.scanner_warning,
        }


def confidence_label(c: float) -> str:
    if c >= 0.85:
        return "An toàn cấp ngay"
    if c >= 0.60:
        return "Nên ping xác nhận trước"
    return "Dữ liệu quét chưa đủ"


# --------------------------------------------------------------------------- #
# Bước 2 — Lọc cứng
# --------------------------------------------------------------------------- #


def hard_filter_reason(
    ip: IPRecord,
    ctx: SubnetContext,
    now: datetime,
    weights: ScoringWeights,
) -> str | None:
    """
    Trả về lý do loại bỏ, hoặc None nếu IP đủ điều kiện làm ứng viên.

    Trả về chuỗi lý do (thay vì bool) để dashboard giải thích được
    "vì sao dải này hết IP" — câu hỏi đội System bị hỏi thường xuyên nhất.
    """
    structural = ctx.is_structurally_unusable(ip.addr_int)
    if structural:
        return structural

    if ip.status == STATUS_ALLOCATED:
        return "Đã cấp cho thiết bị khác"
    if ip.status == STATUS_BLOCKED:
        return "Bị khoá (hạ tầng cố định)"
    if ip.status == STATUS_CONFLICT:
        return "Đang xung đột — scan thấy sống nhưng chưa khai báo"
    if ip.status == STATUS_RESERVED:
        if ip.reserved_until and ip.reserved_until > now:
            return "Đang được giữ chỗ bởi yêu cầu khác"
        # Reservation đã hết hạn nhưng job dọn dẹp chưa chạy — coi như trống.

    if ip.status == STATUS_QUARANTINE:
        if ip.released_at is None:
            return "Đang cách ly (thiếu mốc thu hồi)"
        cooldown_end = ip.released_at + timedelta(days=ctx.cooldown_days)
        if cooldown_end > now:
            remaining = (cooldown_end - now).days + 1
            return f"Đang trong thời gian cách ly, còn {remaining} ngày"

    if ip.last_seen_alive_at is not None:
        if now - ip.last_seen_alive_at <= timedelta(days=weights.freshness_window_days):
            return "Vừa phát hiện có thiết bị phản hồi trong 7 ngày qua"

    return None


# --------------------------------------------------------------------------- #
# Bước 3 — Các thành phần chấm điểm
# --------------------------------------------------------------------------- #


def _block_affinity(
    addr_int: int,
    same_dept_ints: Sequence[int],
    ctx: SubnetContext,
    weights: ScoringWeights,
) -> float:
    """
    Ưu tiên IP nằm gần các IP khác của cùng đơn vị/dự án.

    Vì sao quan trọng: firewall rule viết theo dải (10.0.76.16/28) thay vì
    liệt kê từng IP rời rạc. Gom cụm giúp giảm số rule, giảm lỗi cấu hình,
    và khi nhìn IP là đoán được ngay của bộ phận nào.
    """
    if not same_dept_ints:
        return 0.0

    centroid = sum(same_dept_ints) / len(same_dept_ints)
    centroid_affinity = max(0.0, 1.0 - abs(addr_int - centroid) / ctx.size)

    nearest = min(abs(addr_int - x) for x in same_dept_ints)
    nearest_affinity = max(0.0, 1.0 - nearest / weights.affinity_near_window)

    return 0.6 * centroid_affinity + 0.4 * nearest_affinity


def _policy_fit(
    addr_int: int,
    ctx: SubnetContext,
    free_ints: set[int],
    occupied_ints: Sequence[int],
) -> float:
    if ctx.allocation_policy == POLICY_LOWEST_FIRST:
        offset = addr_int - ctx.network_int
        return max(0.0, 1.0 - offset / max(ctx.size, 1))

    if ctx.allocation_policy == POLICY_FILL_GAPS:
        # Đo độ dài chuỗi IP trống liên tiếp chứa địa chỉ này.
        # Lỗ hổng càng nhỏ, điểm càng cao => vá lỗ trước, giữ dải lớn
        # nguyên vẹn cho những yêu cầu cần nhiều IP liên tiếp.
        run = 1
        left = addr_int - 1
        while left in free_ints:
            run += 1
            left -= 1
        right = addr_int + 1
        while right in free_ints:
            run += 1
            right += 1
        return max(0.0, 1.0 - (run - 1) / 16.0)

    if ctx.allocation_policy == POLICY_SPARSE:
        if not occupied_ints:
            return 1.0
        nearest = min(abs(addr_int - x) for x in occupied_ints)
        return min(nearest / 16.0, 1.0)

    return 0.5


def _neighbor_risk(
    addr_int: int,
    critical_ints: set[int],
    weights: ScoringWeights,
) -> tuple[float, list[int]]:
    """
    Phạt IP nằm sát hệ thống production quan trọng.

    Lý do rất thực tế: gõ nhầm một chữ số khi cấu hình (10.0.76.5 thay vì
    10.0.76.6) mà hàng xóm là VM production thì hậu quả nghiêm trọng.
    Để một khoảng đệm quanh hệ thống trọng yếu là rẻ hơn nhiều so với sự cố.
    """
    r = weights.neighbor_radius
    hits = [
        x for x in range(addr_int - r, addr_int + r + 1) if x != addr_int and x in critical_ints
    ]
    max_neighbors = 2 * r
    return (len(hits) / max_neighbors if max_neighbors else 0.0), hits


def _recent_release_penalty(ip: IPRecord, ctx: SubnetContext, now: datetime) -> float:
    """IP vừa hết cách ly vẫn còn rủi ro cấu hình cũ sót lại."""
    if ip.released_at is None:
        return 0.0
    cooldown_end = ip.released_at + timedelta(days=ctx.cooldown_days)
    days_since = (now - cooldown_end).total_seconds() / 86400.0
    if days_since < 0:
        return 1.0
    return max(0.0, 1.0 - days_since / 30.0)


def _confidence(ip: IPRecord, ctx: SubnetContext, now: datetime, weights: ScoringWeights) -> float:
    """
    Mức độ chắc chắn rằng IP này THỰC SỰ trống.

    Tách khỏi score có chủ đích:
      - score      = "IP này có nên dùng không?" (tối ưu vận hành)
      - confidence = "ta có chắc nó trống không?" (rủi ro dữ liệu)
    Một IP có thể điểm cao nhưng confidence thấp vì scanner chưa quét đủ.
    """
    # Dữ liệu quét cũ => ta KHÔNG biết gì cả. Số lần quét trong quá khứ không
    # nói lên tình trạng hiện tại, nên bỏ hẳn thành phần đó và áp trần cứng.
    if ctx.scan_data_is_stale(now):
        stale_confidence = min(
            weights.stale_scan_confidence_cap,
            0.25 * (0.0 if ip.ever_assigned else 1.0)
            + 0.15 * (0.0 if ip.has_arp_or_dns_record else 1.0),
        )
        return stale_confidence

    scan_component = min(ip.scans_last_7d / weights.min_scans_for_confidence, 1.0)

    never_used_component = 0.0 if ip.ever_assigned else 1.0

    cooldown_component = 0.0
    if ip.released_at is None:
        cooldown_component = 1.0
    else:
        cooldown_end = ip.released_at + timedelta(days=ctx.cooldown_days)
        if (now - cooldown_end).days > 30:
            cooldown_component = 1.0

    trace_component = 0.0 if ip.has_arp_or_dns_record else 1.0

    return min(
        1.0,
        0.40 * scan_component
        + 0.25 * never_used_component
        + 0.20 * cooldown_component
        + 0.15 * trace_component,
    )


# --------------------------------------------------------------------------- #
# Hàm chính
# --------------------------------------------------------------------------- #


def suggest(
    ctx: SubnetContext,
    records: Iterable[IPRecord],
    request: SuggestionRequest | None = None,
    weights: ScoringWeights | None = None,
) -> SuggestionResult:
    """Chấm điểm và xếp hạng các IP có thể cấp trong một dải mạng."""
    request = request or SuggestionRequest()
    weights = weights or ScoringWeights()
    now = request.now or _utcnow()

    records = list(records)
    stale_warning = ctx.staleness_warning(now)

    # --- Chỉ mục phụ trợ cho việc chấm điểm ---
    same_dept_ints = [
        r.addr_int
        for r in records
        if r.status == STATUS_ALLOCATED
        and request.department
        and r.department == request.department
    ]
    # Ưu tiên cụm hẹp hơn nếu có dự án cụ thể
    same_project_ints = [
        r.addr_int
        for r in records
        if r.status == STATUS_ALLOCATED and request.project and r.project == request.project
    ]
    affinity_anchor = same_project_ints or same_dept_ints

    critical_ints = {
        r.addr_int
        for r in records
        if r.status == STATUS_ALLOCATED and r.criticality == CRITICALITY_CRITICAL
    }
    occupied_ints = [r.addr_int for r in records if r.status in (STATUS_ALLOCATED, STATUS_RESERVED)]

    # --- Bước 1 + 2: sinh ứng viên & lọc cứng ---
    candidates_raw: list[IPRecord] = []
    rejected: dict[str, int] = {}

    for r in records:
        reason = hard_filter_reason(r, ctx, now, weights)
        if reason is None:
            candidates_raw.append(r)
        else:
            rejected[reason] = rejected.get(reason, 0) + 1

    free_ints = {r.addr_int for r in candidates_raw}

    # --- Bước 3: chấm điểm ---
    scored: list[Candidate] = []
    for r in candidates_raw:
        reasons: list[str] = []
        warnings: list[str] = []

        affinity = _block_affinity(r.addr_int, affinity_anchor, ctx, weights)
        dead_streak = min(r.consecutive_dead_scans, weights.dead_streak_cap) / max(
            weights.dead_streak_cap, 1
        )
        never_used = 0.0 if r.ever_assigned else 1.0
        policy = _policy_fit(r.addr_int, ctx, free_ints, occupied_ints)
        risk, risk_hits = _neighbor_risk(r.addr_int, critical_ints, weights)
        release_pen = _recent_release_penalty(r, ctx, now)
        conflict_pen = min(r.conflict_count / 5.0, 1.0)

        score = (
            weights.base
            + weights.block_affinity * affinity
            + weights.dead_streak * dead_streak
            + weights.never_used * never_used
            + weights.policy_fit * policy
            + weights.neighbor_risk * risk
            + weights.recent_release * release_pen
            + weights.conflict_history * conflict_pen
        )

        # --- Diễn giải cho con người: không bao giờ trả về điểm số trần trụi ---
        if affinity > 0.5 and affinity_anchor:
            label = request.project or request.department
            lo = ipaddress.ip_address(min(affinity_anchor))
            hi = ipaddress.ip_address(max(affinity_anchor))
            reasons.append(f"Nằm trong block {label} ({lo}–{hi})")
        elif request.department and not affinity_anchor:
            reasons.append(
                f"Đơn vị {request.department} chưa có IP nào trong dải này "
                "— địa chỉ này sẽ mở block mới"
            )

        if not r.ever_assigned:
            reasons.append("Chưa từng được cấp cho thiết bị nào")
        if r.consecutive_dead_scans >= 5:
            reasons.append(f"{r.consecutive_dead_scans} lần quét liên tiếp không phản hồi")
        if ctx.allocation_policy == POLICY_FILL_GAPS and policy > 0.7:
            reasons.append("Lấp lỗ hổng nhỏ, giữ nguyên các dải liên tiếp lớn")

        if risk_hits:
            names = ", ".join(str(ipaddress.ip_address(x)) for x in sorted(risk_hits))
            warnings.append(f"Sát hệ thống production quan trọng ({names})")
        if release_pen > 0.3:
            warnings.append("IP mới được thu hồi gần đây, có thể còn cấu hình cũ")
        if r.conflict_count > 0:
            warnings.append(f"Từng ghi nhận {r.conflict_count} lần xung đột địa chỉ")
        if stale_warning:
            # Gắn vào TỪNG ứng viên, không chỉ ở cấp kết quả: kỹ sư hay copy
            # một dòng gợi ý rồi đi cấp máy, cảnh báo phải đi cùng dòng đó.
            warnings.append(stale_warning)
        elif r.scans_last_7d < weights.min_scans_for_confidence:
            warnings.append(f"Chỉ có {r.scans_last_7d} lần quét trong 7 ngày qua")

        scored.append(
            Candidate(
                address=r.address,
                score=score,
                confidence=_confidence(r, ctx, now, weights),
                reasons=reasons,
                warnings=warnings,
            )
        )

    # Sắp xếp: điểm giảm dần, hoà thì ưu tiên confidence, rồi tới IP nhỏ hơn
    scored.sort(key=lambda c: (-c.score, -c.confidence, int(ipaddress.ip_address(c.address))))

    result = SuggestionResult(
        suggestions=scored[: request.limit],
        subnet_stats=subnet_stats(ctx, records, now),
        rejected_summary=dict(sorted(rejected.items(), key=lambda kv: -kv[1])),
        scanner_warning=stale_warning,
    )

    # --- Bước 4: dải liên tiếp ---
    if request.quantity > 1 and request.contiguous:
        result.blocks = find_contiguous_blocks(
            scored, request.quantity, allow_gaps=request.allow_gaps, limit=3
        )
        if not result.blocks and request.allow_gaps == 0:
            # Hạ cấp có kiểm soát: cho phép tối đa 2 lỗ hổng, nhưng nói rõ.
            fallback = find_contiguous_blocks(scored, request.quantity, allow_gaps=2, limit=3)
            for b in fallback:
                b.warnings.append(
                    "Không tìm được dải hoàn toàn liên tiếp — dải này có "
                    f"{b.gaps} địa chỉ xen kẽ không cấp được"
                )
            result.blocks = fallback

    return result


def find_contiguous_blocks(
    candidates: Sequence[Candidate],
    quantity: int,
    allow_gaps: int = 0,
    limit: int = 3,
) -> list[ContiguousBlock]:
    """
    Tìm các dải IP liên tiếp (hoặc gần liên tiếp) tốt nhất.

    Cấp 10.0.76.40-44 cho một dự án tốt hơn hẳn 5 IP rải rác:
    một rule firewall thay vì năm, và đọc log dễ hơn nhiều.

    Điểm của dải = mean(score) - 0.5 * stdev(score)
    Trừ độ lệch chuẩn để phạt dải có IP yếu xen kẽ giữa các IP mạnh:
    một dải đều tay đáng tin hơn một dải điểm cao nhờ vài IP xuất sắc.
    """
    if quantity <= 1 or not candidates:
        return []

    by_int = {int(ipaddress.ip_address(c.address)): c for c in candidates}
    sorted_ints = sorted(by_int)
    blocks: list[ContiguousBlock] = []

    for start in sorted_ints:
        span = quantity + allow_gaps
        window_ints = [x for x in range(start, start + span) if x in by_int]
        if len(window_ints) < quantity:
            continue
        chosen = window_ints[:quantity]
        gaps = (chosen[-1] - chosen[0] + 1) - quantity
        if gaps > allow_gaps:
            continue

        members = [by_int[x] for x in chosen]
        scores = [m.score for m in members]
        spread = statistics.pstdev(scores) if len(scores) > 1 else 0.0
        block_score = statistics.fmean(scores) - 0.5 * spread

        merged_warnings: list[str] = []
        for m in members:
            for w in m.warnings:
                if w not in merged_warnings:
                    merged_warnings.append(w)

        blocks.append(
            ContiguousBlock(
                addresses=[m.address for m in members],
                score=block_score,
                confidence=min(m.confidence for m in members),
                gaps=gaps,
                warnings=merged_warnings,
            )
        )

    blocks.sort(key=lambda b: (-b.score, int(ipaddress.ip_address(b.addresses[0]))))

    # Loại các dải chồng lấn nhau để không đề xuất 5 phương án gần giống hệt
    selected: list[ContiguousBlock] = []
    used: set[str] = set()
    for b in blocks:
        if any(a in used for a in b.addresses):
            continue
        selected.append(b)
        used.update(b.addresses)
        if len(selected) >= limit:
            break
    return selected


def subnet_stats(
    ctx: SubnetContext, records: Sequence[IPRecord], now: datetime | None = None
) -> dict:
    now = now or _utcnow()
    counts: dict[str, int] = {}
    for r in records:
        counts[r.status] = counts.get(r.status, 0) + 1

    usable = sum(1 for r in records if ctx.is_structurally_unusable(r.addr_int) is None)
    allocated = counts.get(STATUS_ALLOCATED, 0)

    return {
        "cidr": ctx.cidr,
        "name": ctx.name,
        "total": len(records),
        "usable": usable,
        "allocated": allocated,
        "free": counts.get(STATUS_FREE, 0),
        "reserved": counts.get(STATUS_RESERVED, 0),
        "quarantine": counts.get(STATUS_QUARANTINE, 0),
        "blocked": counts.get(STATUS_BLOCKED, 0),
        "conflict": counts.get(STATUS_CONFLICT, 0),
        "utilization": round(allocated / usable, 3) if usable else 0.0,
        "exhaustion_warning": bool(usable and allocated / usable > 0.85),
    }


# --------------------------------------------------------------------------- #
# Tiện ích: dựng danh sách IP đầy đủ cho một subnet
# --------------------------------------------------------------------------- #


def build_records_for_subnet(
    ctx: SubnetContext, known: dict[str, IPRecord] | None = None
) -> list[IPRecord]:
    """
    Sinh đủ IPRecord cho mọi địa chỉ trong dải, dùng dữ liệu đã biết nếu có.

    Cần thiết vì bảng ip_address chỉ lưu những IP đã từng được động tới;
    IP chưa bao giờ dùng sẽ không có dòng nào — mà đó chính là ứng viên tốt nhất.
    """
    known = known or {}
    hosts = ctx.network.hosts() if ctx.network.prefixlen < 31 else ctx.network
    out: list[IPRecord] = []
    for addr in hosts:
        s = str(addr)
        out.append(known[s] if s in known else IPRecord(address=s, status=STATUS_FREE))
    return out
