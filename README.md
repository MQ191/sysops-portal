# SysOps Portal — MVP

Hệ thống quản lý IPAM & vòng đời VM cho đội IT System, thay thế 3 Google Sheet
đang điền tay (Network / Thống kê VM / Server 3100).

Thiết kế đầy đủ: [`docs/TECHNICAL-SPEC.md`](./docs/TECHNICAL-SPEC.md)

---

## Quy ước trạng thái (đọc trước khi tin bảng ở cuối file)

Bản bàn giao đầu tiên đánh dấu "Hoàn chỉnh" cho những tính năng chưa từng
chạy qua `pytest` — và tính năng cốt lõi (`POST /api/v1/ipam/suggest`) thực
tế trả lỗi 500 khi chạy thật, dù 20/20 unit test của module `allocator` đều
xanh. Bài học: unit test một module cô lập không chứng minh được tầng ghép
nối nó với phần còn lại hoạt động. Từ nay dùng ba mức, xếp theo mức độ tin
cậy tăng dần:

| Mức | Nghĩa là |
|---|---|
| **Đã viết** | Có code, có thể chưa từng chạy |
| **Đã chạy** | Có test tự động (`pytest tests/`) chứng minh nó hoạt động đúng như mô tả |
| **Đã nghiệm thu** | Đội System đã dùng thật trên dữ liệu thật và ký xác nhận |

Không dùng từ "Hoàn chỉnh" nữa — nó không nói được mức nào ở trên.

---

## Cấu trúc dự án

```
sysops-portal/
├── app.py                  # Lắp ráp FastAPI: lifespan, /healthz, /metrics, mount router
├── auth.py                 # Xác thực (dev/token/ldap) + RBAC 4 vai trò
├── core.py                 # Tầng chung: DB -> đối tượng allocator, audit log
├── db.py                   # Engine & session — tách khỏi app.py để tránh vòng import
├── models.py                # SQLAlchemy schema + TZDateTime, AutoBigIntPK
├── allocator.py             # ★ Thuật toán gợi ý IP (thuần Python, không phụ thuộc DB)
├── services.py              # network scan (async + canary) · vCenter sync · drift · vòng đời
├── celery_app.py            # lịch chạy job nền
├── importer.py               # import 3 sheet CSV
├── seed_demo.py              # dữ liệu mẫu để chạy thử
├── routers/                  # Endpoint HTTP, tách theo domain
│   ├── auth_routes.py         # /auth/login, /auth/me
│   ├── ipam.py                 # /api/v1/subnets, /api/v1/ipam/*
│   ├── inventory.py             # /api/v1/devices
│   ├── drift.py                  # /api/v1/drift
│   ├── reports.py                 # /api/v1/reports/*, /api/v1/reports/scanner-health
│   ├── admin.py                    # /api/v1/scan, /api/v1/sync/vcenter, /api/v1/maintenance/*
│   └── ui.py                        # HTML (Jinja2, autoescape) cho HTMX
├── templates/                       # Jinja2 — thay thế f-string dựng HTML trước đây
├── static/htmx.min.js                # HTMX vendor tại chỗ, không tải từ CDN ngoài
├── migrations/                       # Alembic — thay thế create_all
├── tests/
│   ├── test_allocator.py              # Unit test thuật toán (24 test, không cần DB)
│   ├── test_api.py                     # Test tích hợp toàn bộ luồng HTTP (22 test)
│   ├── factories.py                     # Dữ liệu mẫu cho test
│   └── conftest.py                       # Fixture TestClient + schema sạch mỗi test
├── .github/workflows/ci.yml               # pytest trên SQLite VÀ Postgres thật + ruff + docker build
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
├── .dockerignore                            # Chặn .env/vault_import.csv/*.db khỏi image
├── .env.example
└── docs/
    └── TECHNICAL-SPEC.md
```

---

## Chạy thử trong 3 phút (SQLite, không cần Docker)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt

python seed_demo.py             # tạo dữ liệu mẫu theo đúng 3 sheet
uvicorn app:app --reload --port 8080
```

Mở http://localhost:8080 — bản đồ IP + form gợi ý IP.
API docs: http://localhost:8080/docs

Mặc định `AUTH_MODE=dev`: mọi request tự khai danh tính qua header
`X-Dev-User` / `X-Dev-Role` (role mặc định `admin`). **Chỉ dùng để chạy thử
cục bộ** — ứng dụng từ chối khởi động ở chế độ này nếu `DATABASE_URL` không
phải SQLite, để không ai vô tình mang chế độ mạo danh này lên production.

> Ghi chú: `pyvmomi`, `python-ldap` có thể khó cài trên Windows.
> Nếu chỉ muốn chạy thử nhanh, cài tối thiểu:
> `pip install fastapi uvicorn sqlalchemy pydantic python-multipart jinja2 icmplib pytest httpx`

Thử gợi ý IP:

```bash
curl -X POST localhost:8080/api/v1/ipam/suggest ^
  -H "Content-Type: application/json" ^
  -H "X-Dev-User: ban@ntq-solution.com.vn" ^
  -d "{\"subnet\":\"10.0.76.0/24\",\"department\":\"SDC11\",\"quantity\":1}"
```

Xin 5 IP liên tiếp: thêm `"quantity":5,"contiguous":true`.

Chạy toàn bộ test (46 bài — 24 unit test thuật toán + 22 test tích hợp API):

```bash
pytest tests/ -v
```

---

## Chạy production (PostgreSQL)

```bash
cp .env.example .env
# Bắt buộc điền: DB_PASSWORD, AUTH_MODE (token|ldap), SESSION_SECRET, AUTH_TOKENS
# Tuỳ chọn: VCENTER_*, VAULT_*, LDAP_* tuỳ theo tính năng dùng

docker compose up -d       # chạy migrate trước, rồi mới khởi động api/worker/beat
```

**PostgreSQL là bắt buộc ở production.** SQLite chỉ dùng cho dev — kiểu `INET`
và index GiST của Postgres là nền tảng của toàn bộ truy vấn IPAM.

**`AUTH_MODE=dev` bị chặn cứng khi không phải SQLite** — ứng dụng ném lỗi
ngay lúc khởi động thay vì chạy với xác thực giả trên dữ liệu thật. Chọn
`token` (bearer token cho service account/job nền) hoặc `ldap` (SSO công
ty cho người dùng UI).

Sinh token cho một service account:

```bash
python -m auth mktoken svc-celery@ntq-solution.com.vn sysops
```

Schema quản lý bằng Alembic, không còn `create_all` ở production
(`AUTO_CREATE_TABLES=false` mặc định khi DB không phải SQLite):

```bash
alembic upgrade head          # áp dụng migration
alembic revision --autogenerate -m "mo ta thay doi"   # khi sửa models.py
```

---

## Luồng nghiệp vụ chính

### Cấp IP cho VM mới

```
1. POST /api/v1/ipam/suggest   → nhận 5 ứng viên kèm lý do + độ tin cậy
2. POST /api/v1/ipam/reserve   → giữ chỗ 30 phút, nhận token (yêu cầu vai trò requester+)
3. (kỹ sư tạo VM trên vCenter)
4. POST /api/v1/ipam/commit    → hệ thống PING lại lần cuối rồi mới chốt
```

Bước 4 là chốt an toàn quan trọng nhất: nếu địa chỉ bất ngờ có phản hồi,
giao dịch bị huỷ, IP chuyển sang `conflict` và sinh cảnh báo. Dữ liệu quét
định kỳ luôn có độ trễ — chỉ kiểm tra trực tiếp mới ngăn được trùng IP. Bước
xác minh này còn tự kiểm tra chính nó qua canary (ping gateway/VM đang bật)
trước khi tin kết quả — nếu ping đang hỏng, nó từ chối thay vì báo "trống"
một cách sai lệch.

### Thu hồi

```
POST /api/v1/ipam/release  → IP chuyển sang quarantine (KHÔNG về free ngay)
                             cooldown 14 ngày, tự động về free sau đó
```

Cooldown tồn tại vì ARP cache trên switch, rule firewall cũ, cấu hình
monitoring và whitelist phía khách hàng vẫn còn trỏ tới IP vừa thu hồi.
`POST /api/v1/ipam/reserve` giờ tự kiểm tra và từ chối IP đang trong
cooldown — trước đây chỉ engine gợi ý tôn trọng quy tắc này, còn gọi API
trực tiếp thì đi vòng được.

### Sức khoẻ scanner — xem trước khi tin bất kỳ gợi ý nào

```
GET /api/v1/reports/scanner-health
```

Nếu scanner mất route, thiếu quyền raw socket, hoặc container thiếu
capability, mọi IP sẽ bị ghi nhận "chết" và hệ thống có thể tự tin gợi ý một
IP đang có máy production chạy — đây là chế độ hỏng nguy hiểm nhất của toàn
hệ thống. Mỗi subnet có `last_scan_ok_at`, chỉ được cập nhật khi một lượt
quét đi qua **canary** (ping gateway + VM đang bật trước, chỉ tin phần còn
lại nếu canary sống). Khi dữ liệu quét cũ quá `scan_staleness_hours` (mặc
định 30h — tương thích chu kỳ quét tự động 00:00 hằng đêm), `confidence` của mọi gợi ý trong dải đó bị ép về dưới 0.35 và UI
hiện cảnh báo rõ ràng — không bao giờ "An toàn cấp ngay".

Quét mạng chạy lúc **00:00 đêm** (ICMP) và **00:30** (ARP) với concurrency 64 (~32 KB/dải /24), độc lập hoàn toàn với vCenter API (chỉ đọc) và không gây nghẽn switch. Cần whitelist IP của portal trên firewall nội bộ để tránh kích hoạt rule chống ICMP sweep.

---

## Import từ 3 sheet hiện tại

Xuất mỗi sheet ra CSV rồi:

```bash
python importer.py --physical servers_3100.csv --vm thongke_vm.csv --network network.csv
```

Thứ tự bắt buộc (vật lý → VM → network) vì file 3100 chứa mã tài sản,
là khoá ghép cho hai file còn lại.

Sau khi chạy sẽ có hai file:

| File | Nội dung | Việc cần làm |
|---|---|---|
| `needs_review.csv` | Ngày tháng nhập nhằng, IP không thuộc dải nào, **IP bị khai trùng** | Đội System xử lý thủ công |
| `vault_import.csv` | Toàn bộ user/pass tách ra từ cột USER/PASS | Nạp Vault → xoá file → xoá cột khỏi Google Sheet **kể cả version history** |

Importer cố ý **không đoán bừa**: ngày `05/06/2026` có thể là 5/6 hoặc 6/5,
nên nó đưa vào review thay vì chọn liều. Đoán sai một hạn dùng có thể khiến
VM production bị thu hồi nhầm.

> Tên cột trong `importer.py` đang khớp với tiêu đề tiếng Việt trong sheet hiện tại.
> Nếu tiêu đề khác, sửa lại các chuỗi `r.get("...")` trong ba hàm `import_*`.

> `vault_import.csv` và `needs_review.csv` nằm trong `.gitignore` **và**
> `.dockerignore`. Thiếu `.dockerignore` từng là một lỗ hổng thật: `COPY . .`
> trong Dockerfile sẽ nướng mật khẩu dạng rõ vào một layer image vĩnh viễn,
> bất kể `.gitignore` nói gì.

---

## Bảo mật — điều bắt buộc trước khi chạy production

Ứng dụng **không lưu mật khẩu**. Bảng `credential_ref` chỉ chứa đường dẫn Vault.
`GET /api/v1/devices/{id}/credentials` trả về `vault_path`, không bao giờ trả giá trị,
và chỉ vai trò `sysops` trở lên mới xem được (bản thân việc xem đường dẫn cũng được ghi audit).

Đã có sẵn (đã chạy, có test):

- **RBAC 4 vai trò** (`viewer < requester < sysops < admin`) — xem `auth.py`.
- **`actor` luôn lấy từ danh tính đã xác thực**, không bao giờ từ request body
  — trước đây bất kỳ ai cũng ký tên "system" lên audit log qua tham số
  `actor=system`.
- **UI escape toàn bộ dữ liệu qua Jinja2 autoescape** — trước đây tên VM lấy
  từ vCenter/CSV import (nguồn không tin cậy) chạy thẳng vào DOM qua f-string,
  cho phép XSS lưu trữ trên chính công cụ quản trị hạ tầng.
- **Reserve/commit chỉ người giữ chỗ (hoặc sysops) mới chốt được**, chặn
  người biết token đi cấp IP về tên thiết bị của mình.

Trước khi vận hành với người ngoài đội System:

1. Đặt `AUTH_MODE=ldap` (hoặc `token` cho service account), điền `SESSION_SECRET`.
2. Nạp toàn bộ secret từ `vault_import.csv` vào Vault.
3. Xoá vĩnh viễn cột USER/PASS khỏi Google Sheet (cả version history).
4. Chuyển sang SSH key theo user cá nhân qua bastion; bỏ tài khoản dùng chung.
5. Đặt portal sau VPN/mạng nội bộ; bật MFA cho vai trò `sysops` và `admin` ở tầng LDAP/SSO.

---

## Điểm cần biết trước khi triển khai

**Scanner cần thấy được mọi VLAN.** Nếu `10.0.76.x` và `172.16.0.x` bị tách
L3 và chặn ICMP giữa các vùng, một scanner duy nhất sẽ báo sai hàng loạt.
Khảo sát route trước; nếu bị chặn, tách scanner thành agent nhẹ ở từng vùng,
đẩy kết quả về qua API. **Dù route thông suốt, luôn kiểm tra
`GET /api/v1/reports/scanner-health` sau khi triển khai** — dead man switch
chỉ cảnh báo được nếu chạy đúng cách.

**vCenter chỉ cần quyền read-only.** Giai đoạn 1 đồng bộ một chiều, portal
không bao giờ ghi ngược vào vCenter.

**Drift không tự sửa.** Hệ thống chỉ phát hiện và xếp hàng đợi theo SLA;
mọi hành động phá huỷ (shutdown, xoá VM) đều cần người phê duyệt.

**HashiCorp Vault là phụ thuộc chưa được đặt tên trong roadmap gốc.** Nếu
công ty chưa vận hành Vault, Sprint 0 (1 tuần, theo TECHNICAL-SPEC §11)
không đủ — cần thêm 3–4 tuần cho HA, unseal ceremony, backup, quy trình cấp
quyền, TRƯỚC khi tính giờ cho Sprint 0.

**Đề xuất shadow mode 2 tuần trước khi khoá quyền edit Google Sheet.** Chạy
portal song song ở chế độ chỉ đọc, đối chiếu tự động với sheet hiện tại. Chỉ
khoá quyền edit khi tỉ lệ khớp ≥ 95% — khoá quá sớm mà portal chưa ổn định
sẽ đẩy đội System quay về Excel cá nhân, tệ hơn hiện trạng.

---

## Trạng thái MVP

| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Thuật toán gợi ý IP | **Đã chạy** | 24 unit test (`tests/test_allocator.py`), gồm cả dead man switch |
| Tầng API đầy đủ (suggest/reserve/commit/release/devices/drift/reports) | **Đã chạy** | 22 test tích hợp qua HTTP thật (`tests/test_api.py`), chạy trên cả SQLite và PostgreSQL trong CI |
| Xác thực + RBAC | **Đã chạy** | dev/token/ldap; `AUTH_MODE=dev` bị chặn ngoài SQLite |
| Chống XSS lưu trữ ở UI | **Đã chạy** | Jinja2 autoescape, có test khai thác cụ thể |
| Chốt cách ly (quarantine) không đi vòng được qua API | **Đã chạy** | Có test tái tạo lỗ hổng cũ và xác nhận đã chặn |
| Network scanner | **Đã chạy** (song song + canary), **chưa nghiệm thu** với hạ tầng thật | TCP SYN scan (nmap) vẫn chưa cài đặt |
| Dead man switch cho scanner | **Đã chạy** | `GET /api/v1/reports/scanner-health`, confidence tự sụp khi dữ liệu cũ |
| vCenter sync | **Đã viết**, **chưa chạy** với vCenter thật | Cần môi trường có vCenter để kiểm chứng |
| Import 3 sheet | **Đã viết**, **chưa chạy** trên CSV thật | Cần khớp lại tên cột với export thực tế |
| Alembic migration | **Đã chạy** | up/down/up round-trip xanh trên cả SQLite và Postgres trong CI |
| Docker/.dockerignore chặn secret | **Đã chạy** | CI có bước build thử với secret giả để xác nhận bị chặn |
| Vòng đời + nhắc hạn | **Đã viết**, SMTP dry-run nếu chưa cấu hình | |
| Self-service xin VM + tạo ticket GLPI | **Chưa làm** (Sprint 5) | |

**Còn thiếu trước khi cho người ngoài đội System truy cập:**
1. Chạy thử vCenter sync với vCenter thật của công ty (chưa nghiệm thu).
2. Khớp lại tên cột importer với CSV export thực tế từ 3 sheet (chưa nghiệm thu).
3. Xác nhận Vault đã sẵn sàng vận hành hoặc lên kế hoạch dựng nó (xem mục "Điểm cần biết" ở trên).
4. Chạy shadow mode ≥ 2 tuần trước khi khoá quyền edit sheet.

> Không có Docker trong môi trường thực hiện hardening này, nên bộ test
> Postgres được xác minh qua CI (`.github/workflows/ci.yml`, service
> container Postgres thật) thay vì chạy tay tại chỗ. DDL đã được xác nhận
> render đúng (`INET`, `MACADDR`, `JSONB`, `BIGSERIAL`,
> `TIMESTAMP WITH TIME ZONE`) bằng cách compile schema với dialect Postgres
> offline — xem lịch sử CI để có kết quả chạy thật.
