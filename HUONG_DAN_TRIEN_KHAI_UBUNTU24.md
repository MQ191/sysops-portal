# Hướng dẫn triển khai SysOps Portal trên Ubuntu 24 (VMware)

> Hệ thống: **FastAPI + PostgreSQL 15 + Redis 7 + Celery** (Docker Compose sẵn có)
> Mục tiêu: chạy production trên VM Ubuntu 24.04 LTS (VMware Workstation/ESXi)

---

## 1. Tổng quan kiến trúc

```
[Trình duyệt] 
      │ HTTPS (tùy chọn)
      ▼
[Nginx]  (reverse proxy, cổng 80/443)
      │  proxy → 127.0.0.1:8080
      ▼
[api]  (uvicorn, FastAPI, chỉ nghe localhost:8080)
      │
      ├── [db]     PostgreSQL 15 (volume pgdata)
      ├── [redis]  Redis 7 (broker Celery)
      ├── [migrate] Alembic (chạy 1 lần khi khởi động)
      ├── [worker] Celery worker (scan mạng, vCenter sync, lifecycle)
      └── [beat]   Celery beat (lịch chạy job)
```

**Yêu cầu tối thiểu VM:**
- Ubuntu Server 24.04 LTS (64-bit)
- 2 vCPU, 4 GB RAM, 20 GB disk
- Network: NAT hoặc Bridged (cần truy cập được các VLAN để scan)

---

## 2. Câu hỏi: Dùng Supabase cloud hay tự host PostgreSQL?

| Tiêu chí | Supabase Cloud | PostgreSQL trên VM (khuyến nghị) |
|---|---|---|
| Chi phí | Miễn phí tier, nhưng giới hạn | Miễn phí, không giới hạn |
| Bảo mật | Dữ liệu IP/MAC/credential đi qua internet | Dữ liệu nội bộ, không ra ngoài |
| Scanner | Không ảnh hưởng | Không ảnh hưởng |
| Phụ thuộc internet | Có (mất mạng = mất DB) | Không |
| Migration | Cần cổng 5432 (session pooler), phức tạp | Đơn giản, `docker-compose` sẵn có |
| Phù hợp | Demo/PoC | **Production nội bộ** |

**Kết luận: Khuyến nghị tự host PostgreSQL trên VM** — an toàn, đơn giản, khớp với `docker-compose.yml` có sẵn. (Phụ lục A có hướng dẫn dùng Supabase nếu bạn vẫn muốn.)

---

## 3. Chuẩn bị VM Ubuntu 24

### 3.1. Tạo VM trong VMware
1. **New Virtual Machine** → **Typical**
2. Chọn ISO **Ubuntu Server 24.04 LTS**
3. Cấu hình: 2 vCPU, 4 GB RAM, 20 GB disk
4. Network: **Bridged** (để VM có IP riêng trong mạng nội bộ, cần scan được các VLAN)
5. Cài Ubuntu Server (chọn **OpenSSH server** khi được hỏi)

### 3.2. Cập nhật hệ thống
```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### 3.3. Cài Docker + Docker Compose
```bash
# Cài Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Cài Docker Compose plugin
sudo apt install -y docker-compose-plugin

# Kiểm tra
docker --version
docker compose version
```

---

## 4. Lấy mã nguồn

```bash
# Tạo thư mục dự án
sudo mkdir -p /opt/sysops-portal
sudo chown $USER:$USER /opt/sysops-portal
cd /opt/sysops-portal

# Clone repo (nếu repo public)
git clone https://github.com/MQ191/sysops-portal.git .

# Nếu repo private, dùng SSH:
# git clone git@github.com:MQ191/sysops-portal.git .
```

---

## 5. Cấu hình môi trường (.env)

```bash
cd /opt/sysops-portal
cp .env.example .env
nano .env
```

Điền các giá trị bắt buộc:

```bash
# --- Database ---
DB_PASSWORD=MatKhauManh_ThayDoi_123
DATABASE_URL=postgresql+psycopg://sysops:MatKhauManh_ThayDoi_123@db:5432/sysops

# --- Redis ---
REDIS_URL=redis://redis:6379/0

# --- Xác thực ---
# Chọn token (đơn giản) hoặc ldap (SSO công ty)
AUTH_MODE=token

# Sinh SESSION_SECRET:
#   python3 -c "import secrets;print(secrets.token_urlsafe(48))"
SESSION_SECRET=day_la_session_secret_rat_dai_va_ngau_nhien_48_ky_tu

# Sinh token cho service account (chạy trên máy có Python):
#   python -m auth mktoken svc-celery@ntq-solution.com.vn sysops
# Kết quả dạng: email:role:sha256hex
AUTH_TOKENS=svc-celery@ntq-solution.com.vn:sysops:sha256hex_cua_token

# --- Cookie ---
# Nếu chưa có HTTPS, đặt false
COOKIE_SECURE=false
SESSION_TTL_SECONDS=28800

# --- Scanner ---
# Điền các subnet thực tế của bạn
SCAN_SUBNETS=10.0.76.0/24,10.0.64.0/24,10.0.65.0/24,172.16.0.0/24

# --- vCenter (tùy chọn, bỏ trống nếu chưa dùng) ---
VCENTER_HOST=
VCENTER_USER=
VCENTER_PASSWORD=
VCENTER_INSECURE=false

# --- Vault (tùy chọn) ---
VAULT_ADDR=
VAULT_UI=

# --- Email (bỏ trống = dry-run) ---
SMTP_HOST=
SMTP_PORT=25
SMTP_FROM=sysops@ntq-solution.com.vn

# --- Khác ---
RESERVATION_TTL_MINUTES=30
MAX_RESERVATION_TTL_MINUTES=240
AUTO_CREATE_TABLES=false
LOG_LEVEL=INFO
```

> **Lưu ý quan trọng:** `AUTH_MODE=dev` bị chặn cứng khi dùng PostgreSQL. Bắt buộc dùng `token` hoặc `ldap`.

---

## 6. Build & khởi động

```bash
cd /opt/sysops-portal

# Build image (lần đầu mất vài phút)
docker compose build

# Khởi động toàn bộ (db → redis → migrate → api → worker → beat)
docker compose up -d

# Xem log
docker compose logs -f
```

**Kiểm tra trạng thái:**
```bash
docker compose ps
```
Kết quả mong muốn: `db`, `redis`, `api`, `worker`, `beat` đều `Up`; `migrate` đã `Exited (0)`.

---

## 7. Cài Nginx reverse proxy

### 7.1. Cài Nginx
```bash
sudo apt install -y nginx
```

### 7.2. Tạo cấu hình
```bash
sudo nano /etc/nginx/sites-available/sysops-portal
```

Nội dung:
```nginx
server {
    listen 80;
    server_name _;   # hoặc tên miền/IP của bạn

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket (nếu cần cho HTMX realtime)
    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 7.3. Kích hoạt
```bash
sudo ln -s /etc/nginx/sites-available/sysops-portal /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl restart nginx
```

---

## 8. Cấu hình firewall (UFW)

```bash
sudo apt install -y ufw

# Chỉ mở cổng cần thiết
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp        # HTTP
# sudo ufw allow 443/tcp     # nếu có HTTPS
sudo ufw enable
sudo ufw status
```

---

## 9. Kiểm tra hệ thống

### 9.1. Kiểm tra health
```bash
# Từ VM
curl http://localhost/healthz
# Kết quả: {"status":"ok"} (hoặc tương tự)

# Từ máy khác trong mạng
curl http://<IP_VM>/healthz
```

### 9.2. Truy cập UI
Mở trình duyệt: `http://<IP_VM>/`

### 9.3. Kiểm tra API docs
Mở: `http://<IP_VM>/docs`

### 9.4. Kiểm tra scanner health (quan trọng!)
```bash
curl -H "Authorization: Bearer <TOKEN>" http://<IP_VM>/api/v1/reports/scanner-health
```
> **Bắt buộc kiểm tra mục này** — nếu scanner không thấy mạng, mọi gợi ý IP sẽ sai.

---

## 10. Tạo service account & token

```bash
# Trên máy có Python (hoặc trong container)
cd /opt/sysops-portal
docker compose exec api python -m auth mktoken svc-celery@ntq-solution.com.vn sysops
```

Kết quả in ra token gốc (chỉ hiện 1 lần). Thêm vào `.env`:
```env
AUTH_TOKENS=svc-celery@ntq-solution.com.vn:sysops:<sha256hex>
```

Rồi restart:
```bash
docker compose up -d --force-recreate api worker beat
```

---

## 11. Import dữ liệu từ 3 Google Sheet (tùy chọn)

```bash
# Xuất 3 sheet ra CSV rồi copy vào VM
# Thứ tự bắt buộc: physical → vm → network
docker compose exec api python importer.py \
  --physical servers_3100.csv \
  --vm thongke_vm.csv \
  --network network.csv
```

Kết quả tạo `needs_review.csv` (cần xử lý thủ công) và `vault_import.csv` (nạp Vault rồi xóa).

---

## 12. Backup & phục hồi

### 12.1. Backup PostgreSQL (cron hàng ngày)
```bash
sudo crontab -e
```
Thêm:
```cron
0 2 * * * docker exec $(docker ps -qf name=sysops-portal-db-1) pg_dump -U sysops sysops | gzip > /backup/sysops_$(date +\%Y\%m\%d).sql.gz
```

### 12.2. Phục hồi
```bash
gunzip -c /backup/sysops_YYYYMMDD.sql.gz | docker exec -i $(docker ps -qf name=sysops-portal-db-1) psql -U sysops sysops
```

---

## 13. Khắc phục sự cố thường gặp

| Vấn đề | Nguyên nhân | Giải pháp |
|---|---|---|
| `migrate` lỗi | DB chưa sẵn sàng | `docker compose logs migrate`; chờ db healthy rồi `docker compose up migrate` |
| `api` không khởi động | Thiếu `SESSION_SECRET`/`AUTH_TOKENS` | Kiểm tra `.env`, `docker compose config` |
| Scanner báo mọi host chết | Thiếu `NET_RAW`/setcap | Kiểm tra `docker compose ps` worker có `cap_add`; xem log worker |
| Không truy cập được từ ngoài | Firewall/Nginx | `sudo ufw status`; `sudo nginx -t`; `curl localhost:8080` |
| `AUTH_MODE=dev` bị chặn | Dùng SQLite | Đổi `AUTH_MODE=token` |
| Cổng 6543 Supabase | Transaction pooler | Dùng cổng 5432 (xem Phụ lục A) |

---

## 14. Bảo mật bổ sung (khuyến nghị)

1. **HTTPS** — cài certbot: `sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx`
2. **Đổi mật khẩu DB** mạnh, không dùng mặc định
3. **Giới hạn truy cập** — chỉ cho phép IP nội bộ qua UFW
4. **MFA** cho vai trò `sysops`/`admin` (nếu dùng LDAP)
5. **Xóa `vault_import.csv`** sau khi nạp Vault
6. **Cập nhật** — `docker compose pull && docker compose up -d` định kỳ

---

## Đánh giá tải mạng & an toàn Scanner

- **Ảnh hưởng đến vCenter**: **Không ảnh hưởng**. vCenter sync hoạt động độc lập qua API HTTPS Read-Only (6h/lần), không tham gia vào luồng ping/ARP.
- **Ảnh hưởng tải mạng (Subnets)**: Tải cực nhỏ (~32 KB cho một dải `/24`, lưu lượng ~4–8 KB/s), hoàn toàn an toàn cho switch/router.
- **Lịch chạy tự động**: Mặc định chạy lúc **00:00 hằng đêm** (ICMP) và **00:30** (ARP) ngoài giờ làm việc.
- **Lưu ý Firewall/IDS**: Khai báo IP của máy chủ SysOps Portal vào danh sách **Whitelist/Authorized Scanner** trên Firewall nội bộ để tránh bị chặn gói ICMP Sweep.
- **Chống dương tính giả**: VM Windows chặn ping nhưng đang bật trên vCenter sẽ được ghi nhận là "VM đang chạy nhưng chặn ICMP", hệ thống không coi là IP trống.

---

## Phụ lục A: Dùng Supabase Cloud (nếu vẫn muốn)

> **Cảnh báo:** Dữ liệu IP/MAC/credential sẽ đi qua internet. Chỉ dùng cho demo/POC.

1. Tạo project Supabase → **Connect** → **ORMs/SQLAlchemy**
2. Copy chuỗi kết nối **cổng 5432** (session pooler, KHÔNG dùng 6543)
3. Trong `.env`:
   ```env
   DATABASE_URL=postgresql+psycopg://postgres.<ref>:<mat-khau>@<host>:5432/postgres?sslmode=require
   ```
4. Chạy migration:
   ```bash
   python scripts/supabase_setup.py --check
   python scripts/supabase_setup.py --migrate
   ```
5. **Không dùng docker-compose db service** — chỉ chạy `api`, `worker`, `beat` với `DATABASE_URL` trỏ Supabase.

---

## Tóm tắt các lệnh chính

```bash
# Khởi động
cd /opt/sysops-portal
docker compose up -d

# Xem log
docker compose logs -f api

# Dừng
docker compose down

# Xem trạng thái
docker compose ps

# Restart
docker compose restart api worker beat
```

---

**Chúc bạn triển khai thành công!** Nếu gặp lỗi, hãy chạy `docker compose logs -f` và gửi log để tôi hỗ trợ.