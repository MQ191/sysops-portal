# SysOps Portal — Tài liệu thiết kế kỹ thuật

**Hệ thống quản lý IPAM & vòng đời VM cho đội IT System**
Phiên bản 1.0 · 30/07/2026 · Chủ sở hữu: IT System / DevOps

---

## 1. Bối cảnh và vấn đề

Hiện tại đội IT System quản lý hạ tầng bằng 3 Google Sheet điền tay:

| File | Nội dung | Vấn đề |
|---|---|---|
| `NETWORK – Danh sách địa chỉ IP` | IP, tên thiết bị, đơn vị, dự án, trạng thái, **user/pass**, ngày, link ticket | Điền tay, không đối chiếu thực tế, lưu mật khẩu trong sheet |
| `Thống kê VM` | Tên VM, PowerState, IP, department, ticket, disk/RAM/CPU, requester, hạn dùng | Trùng lặp dữ liệu với file Network, nhiều ô "Chưa có thông tin hạn dùng" |
| `3100 – Server vật lý / ảo hóa` | Tên server, IP, OS, CPU/RAM/HDD, người yêu cầu, trạng thái, ngày cấp, dự kiến thu hồi, mã tài sản | Nhiều cột rỗng, trạng thái tô màu thủ công |

### 1.1 Vấn đề gốc

Một thực thể duy nhất (một máy chủ/VM) đang bị chia làm 3 bản ghi ở 3 nơi, mỗi nơi nhập tay. Hệ quả:

1. **Dữ liệu lệch nhau** — không nơi nào là nguồn sự thật (source of truth).
2. **Không đối chiếu với thực tế** — VM đã xoá trên vCenter vẫn còn trong sheet; VM tạo tay không ai ghi vào sheet.
3. **IP cấp thủ công** — nguy cơ trùng IP giữa hai hệ thống production; không biết IP nào thực sự còn trống.
4. **Không có vòng đời** — VM không có hạn dùng, không có người đứng tên ⇒ không ai dám thu hồi ⇒ lãng phí tài nguyên.
5. **Rủi ro bảo mật nghiêm trọng** — cột USER/PASS nằm trong Google Sheet.

### 1.2 Mục tiêu

| Mục tiêu | Chỉ số đo | Mốc |
|---|---|---|
| Một nguồn sự thật duy nhất | 100% VM/server có bản ghi duy nhất, có mã tài sản | Cuối MVP |
| Xoá bỏ nhập liệu tay | Số giờ IT nhập liệu/tháng → 0 | Sprint 3 |
| Kiểm soát IP | 0 sự cố trùng IP; 100% IP đang sống được khai báo | Sprint 2 |
| Vòng đời tài nguyên | 100% VM có owner + expiry; ≥ 10% VM thu hồi quý đầu | Sprint 4 |
| Bảo mật | 0 mật khẩu lưu trong ứng dụng/sheet | Sprint 0 |

### 1.3 Phạm vi

**Trong phạm vi:** IPAM (dải mạng, IP, gợi ý IP trống), inventory VM + server vật lý, đồng bộ vCenter, quét mạng, phát hiện lệch (drift), vòng đời & thu hồi, dashboard, import từ 3 sheet hiện có.

**Ngoài phạm vi (giai đoạn 1):** thay thế GLPI (GLPI tiếp tục xử lý ticket, portal chỉ tham chiếu `ticket_id`), tự động provision VM, quản lý cloud, quản lý license phần mềm.

---

## 2. Kiến trúc tổng thể

```
┌──────────────────────────────────────────────────────────────────┐
│                          Người dùng                               │
│  IT System (admin)   ·   Dev/PM (xem + xin cấp)   ·   Lãnh đạo    │
└───────────────────────────────┬──────────────────────────────────┘
                                │ HTTPS (SSO/LDAP)
┌───────────────────────────────▼──────────────────────────────────┐
│  SysOps Portal — FastAPI + Jinja2/HTMX                            │
│  ┌────────────┬─────────────┬──────────────┬──────────────────┐  │
│  │ IPAM API   │ Inventory   │ Suggest IP   │ Dashboard/Report │  │
│  │            │ API         │ Engine       │                  │  │
│  └────────────┴─────────────┴──────────────┴──────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Reconcile Engine (đối chiếu 3 nguồn → sinh Drift Finding) │   │
│  └───────────────────────────────────────────────────────────┘   │
└───────┬───────────────────┬───────────────────┬──────────────────┘
        │                   │                   │
┌───────▼──────┐   ┌────────▼────────┐  ┌───────▼────────┐
│ PostgreSQL   │   │ Redis + Celery  │  │ HashiCorp Vault│
│ (nguồn sự    │   │ (job định kỳ)   │  │ (secret — chỉ  │
│  thật)       │   │                 │  │  lưu reference)│
└──────────────┘   └────────┬────────┘  └────────────────┘
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
┌───────▼───────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ vCenter API   │  │ Network Scanner │  │ GLPI REST API   │
│ (pyVmomi)     │  │ (ICMP/ARP/TCP)  │  │ (đọc ticket)    │
└───────────────┘  └─────────────────┘  └─────────────────┘
```

### 2.1 Năm nguyên tắc thiết kế

1. **Cơ sở dữ liệu là nguồn sự thật, không phải vCenter.** vCenter cho biết *thực tế đang chạy gì*; DB cho biết *lẽ ra phải có gì và của ai*. Chênh lệch giữa hai bên là thông tin quý nhất — sinh ra `DriftFinding` để con người xử lý.
2. **Không bao giờ tự động ghi vào vCenter ở giai đoạn 1.** Đồng bộ một chiều (read-only) để tránh rủi ro. Ghi ngược chỉ mở sau khi hệ thống chạy ổn định ≥ 3 tháng.
3. **Không lưu secret.** Bảng `credential_ref` chỉ chứa đường dẫn Vault, không chứa giá trị.
4. **Mọi thay đổi đều có audit log** — ai, lúc nào, đổi field gì, giá trị cũ/mới.
5. **Idempotent sync.** Chạy lại job đồng bộ nhiều lần cho cùng một kết quả.

---

## 3. Mô hình dữ liệu

### 3.1 Sơ đồ quan hệ

```
Site ──< Subnet ──< IPAddress ──< IPAssignment >── Device
                        │                            │
                        │                            ├──< CredentialRef
                        └──< ScanResult              ├──< LifecycleEvent
                                                     └──< DriftFinding
Department ──< Device        Project ──< Device
SyncRun ──< DriftFinding     AuditLog (polymorphic)
IPReservation >── IPAddress
```

### 3.2 `subnet` — dải mạng

| Cột | Kiểu | Ghi chú |
|---|---|---|
| `id` | UUID PK | |
| `cidr` | CIDR unique | `10.0.76.0/24` |
| `vlan_id` | int | |
| `name` | text | "Dải VM dự án SDC" |
| `gateway` | INET | |
| `purpose` | enum | `server`, `vm`, `workstation`, `dmz`, `management`, `backup` |
| `default_department_id` | FK nullable | dùng cho block affinity |
| `dhcp_range_start/end` | INET nullable | vùng loại trừ khỏi cấp tĩnh |
| `reserved_ranges` | JSONB | `[{"start":"10.0.76.1","end":"10.0.76.9","reason":"network infra"}]` |
| `allocation_policy` | enum | `lowest_first`, `fill_gaps`, `sparse` |
| `cooldown_days` | int | mặc định 14 |
| `is_active` | bool | |

> **Vì sao cần `reserved_ranges`:** trong sheet hiện tại `10.0.76.1`–`10.0.76.4` bỏ trống nhưng thực chất là vùng dành cho gateway/firewall/switch. Nếu không khai báo, thuật toán sẽ gợi ý nhầm.

### 3.3 `ip_address` — từng địa chỉ IP

| Cột | Kiểu | Ghi chú |
|---|---|---|
| `id` | UUID PK | |
| `subnet_id` | FK | |
| `address` | INET unique | |
| `status` | enum | xem 3.4 |
| `hostname` | text nullable | từ DNS/scan |
| `mac_address` | macaddr nullable | từ ARP |
| `last_seen_alive_at` | timestamptz nullable | lần cuối scan thấy sống |
| `last_seen_dead_at` | timestamptz nullable | |
| `consecutive_dead_scans` | int default 0 | dùng tính confidence |
| `released_at` | timestamptz nullable | mốc bắt đầu cooldown |
| `conflict_count` | int default 0 | lịch sử xung đột |

Index bắt buộc: `(subnet_id, status)`, GiST trên `(address)`, `(status, released_at)`.

### 3.4 Trạng thái IP (state machine)

| Trạng thái | Nghĩa | Có thể gợi ý? |
|---|---|---|
| `free` | Trống, sẵn sàng cấp | ✅ |
| `reserved` | Đang giữ chỗ tạm (soft-lock, có TTL) | ❌ |
| `allocated` | Đã cấp cho một device | ❌ |
| `quarantine` | Vừa thu hồi, đang trong cooldown | ❌ (hết cooldown → `free`) |
| `blocked` | Hạ tầng cố định (gateway, broadcast, DHCP pool) | ❌ |
| `conflict` | Scan thấy sống nhưng DB ghi `free` — máy "lậu" | ❌ (cần điều tra) |

```
        ┌──────────────── release + cooldown ────────────────┐
        │                                                     │
     free ──reserve──> reserved ──commit──> allocated ────────┘
        │                  │
        │                  └──TTL hết──> free
        │
        └──scan thấy sống──> conflict ──xác minh & khai báo──> allocated
```

> **Vì sao cần `quarantine`:** cấp lại một IP ngay sau khi thu hồi gây lỗi cực khó debug — ARP cache trên switch, rule firewall cũ, cấu hình monitoring, DNS TTL, whitelist phía khách hàng đều còn trỏ tới IP đó. Cooldown mặc định 14 ngày, cấu hình theo subnet.

### 3.5 `device` — VM / server vật lý / thiết bị

| Cột | Kiểu | Ghi chú |
|---|---|---|
| `id` | UUID PK | |
| `asset_code` | text unique nullable | mã tài sản (từ file 3100) |
| `name` | text | `SDC11-NIGHTLIFE-76.16` |
| `device_type` | enum | `vm`, `physical_server`, `workstation`, `network_device`, `appliance` |
| `hypervisor_host` | text nullable | ESXi host chứa VM |
| `vcenter_uuid` | text unique nullable | khoá đối chiếu vCenter |
| `os` | text | `Red Hat`, `ESXi 6.7`, `Windows 10` |
| `cpu_cores` / `ram_gb` / `disk_gb` | int / numeric / numeric | |
| `power_state` | enum | `on`, `off`, `suspended`, `unknown` |
| `department_id` | FK | SDC1, SDC11, NES, NKR, PMO… |
| `project_id` | FK nullable | Tiktok, Chatzone, NKIA, CRM… |
| `owner_email` | text | **người đứng tên** — bắt buộc |
| `requester_email` | text | người yêu cầu ban đầu |
| `ticket_id` | text nullable | mã ticket GLPI |
| `ticket_url` | text generated | `…/front/ticket.form.php?id={ticket_id}` |
| `provisioned_at` | date | ngày cấp |
| `expires_at` | date nullable | **hạn dùng** |
| `lifecycle_status` | enum | `requested`, `active`, `expiring`, `pending_reclaim`, `shutdown`, `archived` |
| `source` | enum | `manual`, `vcenter`, `discovered`, `import` |
| `is_protected` | bool | "Server mẫu, không xoá" |
| `criticality` | enum | `low`, `normal`, `critical` — dùng cho neighbor risk |
| `last_synced_at` | timestamptz | |

**Ràng buộc nghiệp vụ**

- `device_type = 'vm'` và `is_protected = false` ⇒ `expires_at` NOT NULL.
- `owner_email` NOT NULL với mọi thiết bị `source != 'discovered'`.
- Bản ghi `discovered` được phép thiếu field, nhưng nằm trong hàng đợi "cần khai báo".

### 3.6 `ip_assignment` — gán IP cho device

Tách bảng riêng vì **một device có thể có nhiều IP** (file 3100 có server mang cả `172.16.0.20` và `10.0.64.20`).

Cột: `id`, `ip_address_id` FK, `device_id` FK, `is_primary` bool, `assigned_at`, `released_at`.

Unique partial index `(ip_address_id) WHERE released_at IS NULL` — một IP chỉ thuộc một device tại một thời điểm. Đây là chốt chặn cuối cùng ở tầng DB.

### 3.7 `ip_reservation` — giữ chỗ tạm

Chống race condition: hai kỹ sư cùng xin IP một lúc không được nhận cùng một địa chỉ.

Cột: `ip_address_id` FK unique, `token` UUID, `reserved_by` email, `purpose` text, `expires_at` (mặc định +30 phút).

### 3.8 `scan_result` — lịch sử quét

Cột: `id` bigserial, `address` INET, `alive` bool, `method` enum (`icmp`/`arp`/`tcp_syn`/`vcenter`), `mac_address`, `hostname`, `rtt_ms`, `scanned_at`.

Partition theo tháng, giữ 90 ngày — bảng này lớn nhanh (một /24 × 4 lần/ngày × 30 ngày ≈ 30k dòng/tháng).

### 3.9 `drift_finding` — chênh lệch giữa DB và thực tế

| Loại | Mô tả | Mức độ |
|---|---|---|
| `ghost_vm` | Có trong DB, không có trên vCenter | medium |
| `unregistered_vm` | Có trên vCenter, không có trong DB | **high** |
| `shadow_ip` | Scan thấy IP sống, DB ghi `free` | **high** |
| `stale_allocation` | DB ghi `allocated`, scan chết ≥ 30 ngày | medium |
| `spec_mismatch` | CPU/RAM/Disk trong DB ≠ vCenter | low |
| `missing_owner` | Thiếu `owner_email` | medium |
| `missing_expiry` | Thiếu `expires_at` | medium |
| `expired` | Quá `expires_at` mà vẫn `power_state = on` | **high** |
| `ip_conflict` | Hai device khai cùng một IP | **critical** |

Mỗi finding có `status` (`open`/`acknowledged`/`resolved`/`ignored`), `assigned_to`, `first_seen_at`, `last_seen_at`, `resolution_note`.

### 3.10 `credential_ref` — tham chiếu secret

Cột: `device_id` FK, `auth_type` (`ssh_key`/`vault_password`/`ad_domain`), `vault_path` (`secret/data/vm/sdc11-nightlife-76.16`), `username`, `rotated_at`.

> **Nguyên tắc tuyệt đối:** ứng dụng không bao giờ đọc hoặc hiển thị giá trị secret. Người dùng bấm nút → mở tab Vault → xác thực SSO → Vault ghi audit. Portal chỉ điều hướng.

---

## 4. Thuật toán gợi ý IP trống

Đây là tính năng khác biệt chính. Mục tiêu: khi kỹ sư tạo VM mới, hệ thống đề xuất 3–5 IP **an toàn nhất**, kèm lý do và điểm tin cậy — thay vì dò tay trong sheet.

### 4.1 Luồng xử lý

```
Input: subnet | department | project | quantity | contiguous? | criticality
   │
   ├─ B1. Sinh không gian ứng viên
   │      Toàn bộ IP trong subnet, trừ network addr, broadcast,
   │      gateway, reserved_ranges, dhcp_range
   │
   ├─ B2. Lọc cứng (hard filter) — loại bỏ hoàn toàn
   │      • status ∈ {allocated, reserved, blocked, conflict}
   │      • status = quarantine và chưa hết cooldown
   │      • last_seen_alive_at trong vòng freshness_window (7 ngày)
   │      • đang có reservation còn hiệu lực
   │
   ├─ B3. Chấm điểm mềm (soft scoring) — xếp hạng ứng viên còn lại
   │
   ├─ B4. Nếu quantity > 1 và contiguous → tìm dải liên tiếp tốt nhất
   │
   └─ Output: top N ứng viên + score + reasons[] + warnings[] + confidence
```

### 4.2 Công thức chấm điểm

```
score = 100
      + 35 × block_affinity
      + 25 × dead_streak_norm
      + 20 × never_used
      + 15 × policy_fit
      − 20 × neighbor_risk
      − 15 × recent_release_penalty
      − 25 × conflict_history
```

| Thành phần | Ý nghĩa | Cách tính |
|---|---|---|
| `block_affinity` **+35** | Ưu tiên IP nằm gần các IP khác của cùng đơn vị/dự án → dễ viết rule firewall theo dải, dễ đọc khi troubleshoot | `1 − khoảng_cách_tới_trọng_tâm_block / kích_thước_subnet` |
| `dead_streak_norm` **+25** | Càng nhiều lần quét liên tiếp thấy chết, càng chắc chắn trống | `min(consecutive_dead_scans, 30) / 30` |
| `never_used` **+20** | IP chưa từng cấp bao giờ → sạch nhất, không có rác cấu hình cũ | 1 nếu chưa từng có `ip_assignment` |
| `policy_fit` **+15** | Khớp `allocation_policy`: `lowest_first` ưu tiên IP nhỏ; `fill_gaps` ưu tiên lấp lỗ hổng nhỏ; `sparse` ưu tiên cách xa IP đang dùng | 0–1 |
| `neighbor_risk` **−20** | IP sát VM production quan trọng → gõ nhầm một số là ảnh hưởng prod | tỉ lệ IP `critical` trong bán kính ±2 |
| `recent_release_penalty` **−15** | Vừa hết cooldown chưa lâu | `max(0, 1 − ngày_kể_từ_hết_cooldown / 30)` |
| `conflict_history` **−25** | IP từng bị ghi nhận `ip_conflict` hoặc `shadow_ip` | `min(conflict_count / 5, 1)` |

Trọng số đặt trong file cấu hình (`ScoringWeights`), không hardcode — mỗi công ty có khẩu vị rủi ro khác nhau.

### 4.3 Điểm tin cậy (confidence)

Tách riêng khỏi `score`. `score` trả lời *"IP này nên dùng không?"*; `confidence` trả lời *"ta chắc chắn nó trống tới mức nào?"*.

```
confidence = min(1.0,
      0.40 × (số lần quét trong 7 ngày qua ≥ 5 ? 1 : số_lần/5)
    + 0.25 × (chưa từng có assignment ? 1 : 0)
    + 0.20 × (đã qua cooldown > 30 ngày ? 1 : 0)
    + 0.15 × (không có bản ghi ARP/DNS nào ? 1 : 0)
)
```

Hiển thị: `≥ 0.85` xanh — "An toàn cấp ngay" · `0.60–0.85` vàng — "Nên ping xác nhận" · `< 0.60` đỏ — "Dữ liệu quét chưa đủ".

**Quy tắc an toàn bắt buộc:** khi commit, backend tự ping + ARP lại IP đó ngay lập tức. Nếu có phản hồi → huỷ giao dịch, đánh dấu `conflict`, gợi ý IP khác. Không hệ thống nào đúng 100% nếu tin vào dữ liệu quét cũ.

### 4.4 Tìm dải liên tiếp (contiguous block)

Khi dự án xin 5 VM cùng lúc, cấp `10.0.76.40–44` tốt hơn nhiều so với 5 IP rải rác — một rule firewall thay vì năm.

Thuật toán: sliding window kích thước `n` trên danh sách ứng viên đã sắp theo địa chỉ; chỉ nhận cửa sổ mà **mọi** IP đều qua hard filter; điểm cửa sổ = `mean(score) − 0.5 × stdev(score)` (phạt dải có IP yếu xen kẽ). Nếu không có dải liên tiếp, hạ cấp xuống "gần liên tiếp" (cho phép tối đa 2 lỗ hổng) và cảnh báo rõ cho người dùng.

### 4.5 Chống race condition

```sql
BEGIN;
  SELECT id FROM ip_address
   WHERE id = :ip_id AND status = 'free'
     FOR UPDATE NOWAIT;            -- khoá bi quan, fail nhanh nếu đang bị giữ
  UPDATE ip_address SET status = 'reserved' WHERE id = :ip_id;
  INSERT INTO ip_reservation (...) VALUES (...);
COMMIT;
```

- `FOR UPDATE NOWAIT` → người thứ hai nhận lỗi ngay thay vì chờ; hệ thống tự gợi ý IP kế tiếp.
- Reservation TTL 30 phút; job dọn dẹp chạy mỗi phút trả IP hết hạn về `free`.
- Unique partial index trên `ip_assignment` là chốt chặn cuối cùng.

### 4.6 Ví dụ đầu ra

```json
POST /api/v1/ipam/suggest
{ "subnet": "10.0.76.0/24", "department": "SDC11", "quantity": 1 }

{
  "suggestions": [
    { "address": "10.0.76.42", "score": 156.8, "confidence": 0.94,
      "reasons": ["Nằm trong block SDC11 (10.0.76.16–41)",
                  "Chưa từng được cấp",
                  "28 lần quét liên tiếp không phản hồi"],
      "warnings": [] },
    { "address": "10.0.76.43", "score": 154.2, "confidence": 0.94,
      "reasons": ["Nằm trong block SDC11", "Chưa từng được cấp"],
      "warnings": [] },
    { "address": "10.0.76.6", "score": 118.5, "confidence": 0.71,
      "reasons": ["Lấp lỗ hổng nhỏ trong dải hạ tầng"],
      "warnings": ["Sát 10.0.76.5 (VM-SDC1-Tiktok, production)",
                   "Chỉ có 3 lần quét trong 7 ngày qua"] }
  ],
  "subnet_stats": { "total": 254, "allocated": 187, "free": 52,
                    "quarantine": 9, "conflict": 6, "utilization": 0.736 }
}
```

---

## 5. Đồng bộ và phát hiện lệch

### 5.1 vCenter sync (pyVmomi)

Chạy 6 giờ/lần. Dùng `PropertyCollector` lấy hàng loạt thay vì lặp từng VM — nhanh hơn khoảng 50 lần trên môi trường vài trăm VM.

Trường lấy về: `config.uuid`, `name`, `runtime.powerState`, `config.hardware.numCPU`, `config.hardware.memoryMB`, `summary.storage.committed`, `guest.ipAddress`, `guest.net[]`, `guest.guestFullName`, `runtime.host`.

**Quy tắc đối chiếu**, theo thứ tự ưu tiên:

1. `vcenter_uuid` khớp → cùng một VM (kể cả khi đã đổi tên).
2. Không khớp uuid nhưng khớp `name` → cập nhật uuid, ghi audit "phát hiện lại".
3. Không khớp gì → tạo `DriftFinding: unregistered_vm`, đồng thời tạo `device` nháp `source='vcenter'` để đội chỉ cần điền phần nghiệp vụ.

**Xử lý xung đột dữ liệu:** field kỹ thuật (CPU/RAM/Disk/power state) — vCenter thắng, ghi đè. Field nghiệp vụ (owner, project, ticket, hạn dùng) — DB thắng, vCenter không có. `name` khác nhau → không tự đổi, sinh `spec_mismatch` để người xác nhận.

### 5.2 Network scan

Ba lớp quét chạy nối tiếp:

| Lớp | Công cụ | Tần suất | Ghi chú |
|---|---|---|---|
| ICMP sweep | `icmplib` async | 4 giờ/lần | Nhanh, nhưng nhiều host chặn ping |
| TCP SYN | `nmap -sS -PS22,80,443,3389,445` | 12 giờ/lần | Bắt host chặn ICMP |
| ARP | `arp-scan` / đọc bảng ARP switch qua SNMP | 24 giờ/lần | Đáng tin nhất trong cùng L2, lấy được MAC |

**Quy tắc chống dương tính giả (rất quan trọng):** một IP chỉ chuyển sang `conflict` khi **≥ 2 lớp quét khác nhau** hoặc **≥ 3 lần quét liên tiếp cùng lớp** cho kết quả sống. Ngược lại, chỉ chuyển sang `free` sau **≥ 5 lần quét liên tiếp** thấy chết. Máy tắt tạm thời không được coi là IP trống.

Scanner cần chạy trên host có route tới mọi dải (`10.0.2.x`, `10.0.64.x`, `10.0.65.x`, `10.0.76.x`, `172.16.0.x`). Nếu bị chia VLAN, triển khai scanner agent nhẹ ở mỗi vùng, đẩy kết quả về portal qua API.

### 5.3 Hàng đợi xử lý lệch

Drift không tự sửa. Mỗi finding vào hàng đợi có người chịu trách nhiệm và SLA:

| Mức độ | SLA |
|---|---|
| critical (`ip_conflict`) | 4 giờ |
| high (`unregistered_vm`, `shadow_ip`, `expired`) | 2 ngày làm việc |
| medium | 7 ngày |
| low | gom vào review hàng tháng |

---

## 6. Vòng đời tài nguyên & thu hồi

```
requested → active → expiring → pending_reclaim → shutdown → archived
                ↑         │              │
                └─gia hạn─┴──────────────┘
```

| Mốc | Hành động |
|---|---|
| T−30 ngày | Email owner + PM dự án: xác nhận gia hạn hay thu hồi |
| T−7 ngày | Nhắc lần 2, CC trưởng bộ phận. Chuyển `expiring` |
| T−1 ngày | Nhắc lần 3 |
| T+0 | Chuyển `pending_reclaim`, hiện trên dashboard đội System |
| T+7 | Shutdown VM (thủ công, có phê duyệt). Chuyển `shutdown` |
| T+21 | Snapshot + xoá VM. IP → `quarantine`. Chuyển `archived` |

Gia hạn tự phục vụ: owner bấm link trong email → chọn thời hạn mới (tối đa 6 tháng/lần) + lý do → hệ thống ghi nhận, đội System không phải can thiệp.

`is_protected = true` (server mẫu, hạ tầng lõi) được loại khỏi toàn bộ luồng này.

---

## 7. API contract (trích)

| Method | Endpoint | Mô tả |
|---|---|---|
| GET | `/api/v1/subnets` | Danh sách dải mạng + thống kê sử dụng |
| GET | `/api/v1/subnets/{cidr}/map` | Bản đồ trực quan toàn bộ IP trong dải |
| POST | `/api/v1/ipam/suggest` | **Gợi ý IP trống** |
| POST | `/api/v1/ipam/reserve` | Giữ chỗ IP (trả token + TTL) |
| POST | `/api/v1/ipam/commit` | Chốt cấp IP (xác minh lại trước khi chốt) |
| DELETE | `/api/v1/ipam/reserve/{token}` | Huỷ giữ chỗ |
| POST | `/api/v1/ipam/release` | Thu hồi IP → quarantine |
| GET/POST/PATCH | `/api/v1/devices` | CRUD thiết bị |
| GET | `/api/v1/devices/{id}/credentials` | Trả về **vault_path**, không trả secret |
| GET | `/api/v1/drift` | Hàng đợi lệch, lọc theo severity/status |
| POST | `/api/v1/drift/{id}/resolve` | Đóng finding |
| POST | `/api/v1/sync/vcenter` | Kích hoạt đồng bộ thủ công |
| POST | `/api/v1/scan/{cidr}` | Kích hoạt quét thủ công |
| GET | `/api/v1/reports/utilization` | Tài nguyên đã cấp theo đơn vị/dự án |
| GET | `/api/v1/reports/expiring` | VM sắp hết hạn |
| POST | `/api/v1/import/sheet` | Import CSV từ 3 sheet hiện có |

**Phân quyền RBAC**

| Vai trò | Quyền |
|---|---|
| `viewer` | Xem inventory, dashboard của đơn vị mình |
| `requester` | + Tạo yêu cầu cấp VM, gia hạn VM mình đứng tên |
| `sysops` | + Cấp/thu hồi IP, sửa device, xử lý drift |
| `admin` | + Quản lý subnet, cấu hình sync, xem audit log |

---

## 8. Di trú dữ liệu từ 3 sheet

Thứ tự bắt buộc — nạp sai thứ tự sẽ tạo bản ghi mồ côi:

1. **Khai báo subnet trước** (thủ công, ~15 dải): CIDR, gateway, reserved_ranges, purpose.
2. **File 3100 (server vật lý)** → `device` với `device_type='physical_server'`; lấy `asset_code`, OS, trạng thái; đánh `is_protected` cho dòng "Server mẫu, không xoá".
3. **File Thống kê VM** → `device` với `device_type='vm'`; lấy CPU/RAM/Disk, requester, hạn dùng. Ghép với bước 2 theo tên/IP nếu trùng.
4. **File Network** → `ip_address` + `ip_assignment`; ghép vào device theo tên hoặc IP.
5. **Chạy vCenter sync lần đầu** → đối chiếu, sinh danh sách lệch.
6. **Chạy scan lần đầu** → phát hiện IP lậu.
7. **Chiến dịch dọn dữ liệu**: xuất danh sách thiếu owner/hạn dùng, gửi từng trưởng bộ phận, deadline 2 tuần.

**Xử lý dữ liệu bẩn**

- Ngày tháng lẫn lộn `12/31/2025` và `31/12/2025` → parser thử cả hai định dạng; ô nào không chắc thì đưa vào `needs_review.csv` thay vì đoán bừa.
- Ô "Chưa có thông tin hạn dùng" → `expires_at = NULL` + sinh `DriftFinding: missing_expiry`.
- Cột USER/PASS → **không import**. Xuất riêng một file mã hoá, nạp thẳng vào Vault, rồi xoá vĩnh viễn khỏi Google Sheet (kể cả version history).
- Một dòng nhiều IP (`172.16.0.20` + `10.0.64.20`) → tách thành nhiều `ip_assignment`, IP đầu là `is_primary`.
- Tên VM không nhất quán (`VM-SDC11-NTT-76.8` vs `SDC11-NTT-76.8`) → chuẩn hoá về `{DEPT}-{PROJECT}-{last_octet}`, lưu tên cũ vào `aliases[]`.

---

## 9. Bảo mật

| Hạng mục | Yêu cầu |
|---|---|
| Secret | Vault; ứng dụng chỉ lưu path. Bỏ hoàn toàn user/pass dùng chung |
| Truy cập server | SSH key theo user cá nhân qua bastion, ghi log phiên |
| Xác thực portal | SSO/LDAP công ty; bắt buộc MFA cho `sysops` và `admin` |
| Mạng | Portal chỉ truy cập từ mạng nội bộ/VPN. Scanner chạy bằng service account chuyên dụng, quyền tối thiểu |
| vCenter | Tài khoản read-only riêng cho portal |
| Audit | Ghi log mọi thay đổi; log bất biến, giữ 2 năm (phục vụ ISO 27001) |
| Dữ liệu | Backup DB hằng ngày, test restore hằng quý |

---

## 10. Stack và triển khai

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Backend | Python 3.11 + FastAPI | Hệ sinh thái hạ tầng mạnh nhất: `pyVmomi`, `netaddr`, `icmplib`, `python-nmap`. Auto OpenAPI docs |
| DB | PostgreSQL 15 | Kiểu `INET`/`CIDR`/`MACADDR` native + toán tử `<<=`, `&&` cho subnet |
| ORM/Migration | SQLAlchemy 2.0 + Alembic | |
| Job nền | Celery + Redis (APScheduler nếu muốn nhẹ hơn) | Sync & scan định kỳ |
| Frontend | Jinja2 + HTMX + Tailwind | Đội System không có FE chuyên trách; HTMX cho tương tác tốt mà không cần build pipeline |
| Triển khai | Docker Compose trên VM nội bộ | Đơn giản, đúng quy mô |
| Giám sát | Prometheus metrics + Grafana | Tận dụng hạ tầng monitor sẵn có |

> **Vì sao PostgreSQL bắt buộc, không phải MySQL:** truy vấn `SELECT * FROM ip_address WHERE address <<= '10.0.76.0/24'` và index GiST trên `INET` là thứ MySQL không có. Toàn bộ thuật toán gợi ý IP dựa vào đó.

---

## 11. Roadmap

| Sprint | Thời lượng | Nội dung | Tiêu chí hoàn thành |
|---|---|---|---|
| **0** | 1 tuần | Đưa user/pass ra khỏi Google Sheet vào Vault; khoá quyền share sheet | 0 mật khẩu còn trong sheet |
| **1** | 2 tuần | Schema DB + IPAM core + import 3 sheet + màn hình bản đồ IP | Xem được toàn bộ IP mọi dải trên web |
| **2** | 2 tuần | **Gợi ý IP trống** + reserve/commit + network scanner | Cấp IP mới không cần mở sheet |
| **3** | 2 tuần | vCenter sync + reconcile + hàng đợi drift | Biết chính xác VM nào chưa khai báo |
| **4** | 2 tuần | Vòng đời + nhắc hạn tự động + dashboard lãnh đạo | Email nhắc hạn chạy tự động |
| **5** | 2 tuần | Self-service xin cấp VM + tích hợp tạo ticket GLPI | Dev tự xin VM qua portal |

Tổng **11 tuần** với 1 dev backend + 0.5 người từ đội System hỗ trợ nghiệp vụ.
Con số này **không tính thời gian dựng Vault** nếu công ty chưa vận hành —
xem rủi ro "Phụ thuộc Vault chưa đặt tên" bên dưới.

### Rủi ro

| Rủi ro | Giảm thiểu |
|---|---|
| Dữ liệu 3 sheet quá bẩn, import ra rác | Sprint 1 chấp nhận import "như hiện trạng" + đánh dấu cần review, không cố làm sạch trước |
| Scanner bị chặn bởi firewall/VLAN | Khảo sát route ngay tuần 1; chuẩn bị phương án scanner agent phân tán. **Kiểm tra `GET /api/v1/reports/scanner-health` — dead man switch chỉ bảo vệ được nếu ai đó thực sự nhìn vào nó** |
| Đội không dùng, quay lại sheet | **Shadow mode 2 tuần** trước khi khoá sheet: portal chạy song song ở chế độ chỉ đọc, đối chiếu tự động với sheet hiện tại; chỉ khoá quyền edit khi tỉ lệ khớp ≥ 95%. Khoá quá sớm khi portal chưa ổn định đẩy đội quay về Excel cá nhân — tệ hơn hiện trạng, không phải "không có đường lùi thì mới đổi được thói quen" |
| Người viết code rời dự án | Test coverage ≥ 70% cho `ip_allocator` — **nhưng bản thân điều này không đủ**: bản bàn giao đầu tiên có 20/20 unit test allocator xanh trong khi tầng API thật trả lỗi 500. Bắt buộc thêm test tích hợp qua HTTP thật (`tests/test_api.py`) và CI chạy trên cả SQLite lẫn Postgres |
| **Phụ thuộc Vault chưa đặt tên** | Sprint 0 giả định Vault đã sẵn sàng vận hành. Nếu chưa, đây là dự án riêng 3–4 tuần (HA, unseal ceremony, backup, quy trình cấp quyền) — xác nhận trạng thái Vault TRƯỚC khi cam kết mốc Sprint 0 |
| Bus factor = 1 trên toàn bộ hệ thống đường găng | 11 tuần với 1 dev backend, không QA/SRE/FE. Portal trở thành đường găng cấp VM toàn công ty. Tối thiểu cần người thứ hai đọc hiểu được `allocator.py` và `services.py` trước khi go-live |

---

## 12. Chỉ số theo dõi khi vận hành

- Tỉ lệ device có đủ owner + expiry (mục tiêu 100%)
- Số `DriftFinding` đang mở theo mức độ (xu hướng phải giảm)
- Số IP `conflict` phát hiện được — chỉ số sức khỏe mạng
- Tỉ lệ sử dụng từng subnet (cảnh báo khi > 85%)
- Số VM thu hồi/quý và tài nguyên giải phóng (vCPU, GB RAM, GB disk)
- Thời gian trung bình từ lúc xin VM đến lúc bàn giao
- **Số lần `scanner-health` báo `stale` trong tháng** — chỉ số sức khoẻ của
  chính hệ thống giám sát, không phải của mạng

---

## 13. Đợt hardening sau bàn giao đầu tiên

Bản bàn giao đầu tiên có thiết kế đầy đủ nhưng chưa từng chạy thử; kiểm
chứng bằng cách dựng môi trường và chạy thật phát hiện tầng API cốt lõi
không hoạt động dù unit test xanh. Đợt sửa sau đó tập trung vào năm nhóm:

1. **Lệch kiểu dữ liệu khiến tính năng lõi chết trên SQLite** — datetime
   naive/aware và khoá chính không tự tăng. Sửa bằng `TZDateTime` và
   `AutoBigIntPK` ở tầng model (`models.py`) thay vì vá từng điểm gọi.
2. **Không có xác thực, `actor` tự khai qua request body** — thêm `auth.py`
   với RBAC 4 vai trò; `AUTH_MODE=dev` bị chặn cứng ngoài SQLite.
3. **XSS lưu trữ trong UI** — chuyển từ f-string sang Jinja2 autoescape
   (`templates/`).
4. **Chốt cách ly (§3.4) đi vòng được qua `POST /ipam/reserve`** — endpoint
   giờ tự kiểm tra cooldown, không chỉ dựa vào engine gợi ý.
5. **Scanner tuần tự, không tự phát hiện khi chính nó hỏng** — thêm quét
   song song, canary (mục 5.2 mở rộng), và dead man switch: `confidence`
   sụp xuống khi dữ liệu quét cũ thay vì trôi lên do bộ đếm "chết liên tiếp"
   vẫn tăng dù scanner không còn hoạt động.

Chi tiết đầy đủ và trạng thái đã-chạy/chưa-chạy của từng phần: xem
[README.md — Trạng thái MVP](../README.md#trạng-thái-mvp).
