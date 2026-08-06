#!/usr/bin/env bash
# =============================================================================
# Script tự động triển khai SysOps Portal trên Ubuntu 24.04 LTS (VMware)
# Sử dụng: sudo bash deploy_sysops_ubuntu24.sh
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# CẤU HÌNH (sửa lại cho phù hợp)
# -----------------------------------------------------------------------------
APP_DIR="/opt/sysops-portal"
REPO_URL="https://github.com/MQ191/sysops-portal.git"   # nếu repo private: git@github.com:MQ191/sysops-portal.git

# --- Database ---
DB_PASSWORD="MatKhauManh_ThayDoi_123"                    # BẮT BUỘC đổi

# --- Xác thực ---
AUTH_MODE="token"                                        # token | ldap | dev
SESSION_SECRET=""                                        # để trống = tự sinh
SERVICE_EMAIL="svc-celery@ntq-solution.com.vn"           # service account email
SERVICE_ROLE="sysops"                                    # viewer|requester|sysops|admin
AUTH_TOKENS=""                                           # để trống = tự sinh

# --- Scanner ---
SCAN_SUBNETS="10.0.76.0/24,10.0.64.0/24,10.0.65.0/24,172.16.0.0/24"  # Thay bằng subnet thật

# --- Cookie (đặt true nếu có HTTPS) ---
COOKIE_SECURE="false"

# --- vCenter (bỏ trống nếu chưa dùng) ---
VCENTER_HOST=""
VCENTER_USER=""
VCENTER_PASSWORD=""
VCENTER_INSECURE="false"

# --- SMTP (bỏ trống = dry-run) ---
SMTP_HOST=""
SMTP_PORT="25"
SMTP_FROM="sysops@ntq-solution.com.vn"

# --- Backup cron (giờ chạy) ---
BACKUP_HOUR="2"
BACKUP_DIR="/backup/sysops"

# =============================================================================
# MÀU SẮC LOG
# =============================================================================
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "\n${GREEN}===== $1 =====${NC}"; }

# Kiểm tra quyền root
if [[ $EUID -ne 0 ]]; then
    error "Vui lòng chạy với quyền root: sudo bash $0"
    exit 1
fi

# =============================================================================
# BƯỚC 1: Cập nhật hệ thống
# =============================================================================
step "Cập nhật hệ thống"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
# Đảm bảo có các gói cần thiết
apt-get install -y curl git ca-certificates gnupg lsb-release unzip

# =============================================================================
# BƯỚC 2: Cài Docker + Docker Compose plugin
# =============================================================================
step "Cài Docker + Docker Compose"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
else
    info "Docker đã cài sẵn: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
    apt-get install -y docker-compose-plugin
fi

systemctl enable docker
systemctl start docker

# Thêm user hiện tại (SUDO_USER) vào nhóm docker
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    usermod -aG docker "$SUDO_USER"
    info "Đã thêm user $SUDO_USER vào nhóm docker (cần logout/login lại)"
fi

info "Docker: $(docker --version)"
info "Compose: $(docker compose version)"

# =============================================================================
# BƯỚC 3: Tạo thư mục & clone repo
# =============================================================================
step "Clone mã nguồn vào $APP_DIR"
if [[ ! -d "$APP_DIR/.git" ]]; then
    mkdir -p "$APP_DIR"
    if command -v git-credential-ssh &>/dev/null || [[ "$REPO_URL" == git@* ]]; then
        # Dùng SSH (cần key đã đăng ký trên GitHub)
        GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone "$REPO_URL" "$APP_DIR"
    else
        git clone "$REPO_URL" "$APP_DIR"
    fi
else
    info "Repo đã tồn tại, pull mới nhất"
    git -C "$APP_DIR" pull --ff-only || warn "Pull thất bại (kiểm tra kết nối)"
fi
cd "$APP_DIR"

# =============================================================================
# BƯỚC 4: Sinh secret & tạo .env
# =============================================================================
step "Tạo file .env"
if [[ -z "$SESSION_SECRET" ]]; then
    SESSION_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))" 2>/dev/null || openssl rand -base64 48)
fi

# Sinh token nếu chưa có (dùng Python trong container sau, ở đây tạm sinh hash placeholder)
if [[ -z "$AUTH_TOKENS" ]]; then
    info "Bạn cần tạo token. Sau khi khởi động xong chạy:"
    info "  docker compose exec api python -m auth mktoken $SERVICE_EMAIL $SERVICE_ROLE"
    info "Rồi dán kết quả vào AUTH_TOKENS trong .env và restart."
    AUTH_TOKENS=""
fi

cat > .env <<EOF
# --- Database ---
DB_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql+psycopg://sysops:$DB_PASSWORD@db:5432/sysops

# --- Redis ---
REDIS_URL=redis://redis:6379/0

# --- Xác thực ---
AUTH_MODE=$AUTH_MODE
SESSION_SECRET=$SESSION_SECRET
AUTH_TOKENS=$AUTH_TOKENS

# Cookie
COOKIE_SECURE=$COOKIE_SECURE
SESSION_TTL_SECONDS=28800

# --- Scanner ---
SCAN_SUBNETS=$SCAN_SUBNETS

# --- vCenter ---
VCENTER_HOST=$VCENTER_HOST
VCENTER_USER=$VCENTER_USER
VCENTER_PASSWORD=$VCENTER_PASSWORD
VCENTER_INSECURE=$VCENTER_INSECURE

# --- Vault ---
VAULT_ADDR=
VAULT_UI=

# --- SMTP ---
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_FROM=$SMTP_FROM

# --- Khác ---
RESERVATION_TTL_MINUTES=30
MAX_RESERVATION_TTL_MINUTES=240
AUTO_CREATE_TABLES=false
LOG_LEVEL=INFO
EOF

# Phân quyền an toàn
chmod 600 .env
chmod 700 "$APP_DIR"

# =============================================================================
# BƯỚC 5: Tạo .dockerignore (bảo vệ secret)
# =============================================================================
step "Kiểm tra .dockerignore"
if [[ ! -f .dockerignore ]]; then
    cat > .dockerignore <<'EOF'
.env
vault_import.csv
needs_review.csv
*.db
.git
__pycache__/
*.pyc
EOF
fi

# =============================================================================
# BƯỚC 6: Build & khởi động Docker Compose
# =============================================================================
step "Build image (lần đầu mất vài phút)"
docker compose build

step "Khởi động toàn bộ dịch vụ"
docker compose up -d

# Chờ migrate hoàn tất
info "Chờ migrate hoàn tất..."
for i in {1..30}; do
    if [[ "$(docker compose ps -q migrate 2>/dev/null)" == "" ]] || \
       [[ "$(docker inspect -f '{{.State.ExitCode}}' "$(docker compose ps -q migrate 2>/dev/null)" 2>/dev/null)" == "0" ]]; then
        info "Migrate hoàn tất."
        break
    fi
    sleep 2
    if [[ $i -eq 30 ]]; then
        warn "Chưa thấy migrate hoàn tất, kiểm tra: docker compose logs migrate"
    fi
done

# =============================================================================
# BƯỚC 7: Cài & cấu hình Nginx
# =============================================================================
step "Cài & cấu hình Nginx reverse proxy"
if ! command -v nginx &>/dev/null; then
    apt-get install -y nginx
fi

cat > /etc/nginx/sites-available/sysops-portal <<'EOF'
server {
    listen 80;
    server_name _;
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

ln -sf /etc/nginx/sites-available/sysops-portal /etc/nginx/sites-enabled/sysops-portal
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable nginx && systemctl restart nginx

# =============================================================================
# BƯỚC 8: Cấu hình UFW firewall
# =============================================================================
step "Cấu hình firewall UFW"
if ! command -v ufw &>/dev/null; then
    apt-get install -y ufw
fi
ufw allow OpenSSH
ufw allow 80/tcp
# ufw allow 443/tcp   # bỏ comment nếu có HTTPS
ufw --force enable
info "Trạng thái UFW:"
ufw status

# =============================================================================
# BƯỚC 9: Thiết lập backup tự động (cron)
# =============================================================================
step "Thiết lập backup PostgreSQL tự động"
mkdir -p "$BACKUP_DIR"
DB_CONTAINER="$(docker compose ps -q db 2>/dev/null || true)"
if [[ -n "$DB_CONTAINER" ]]; then
    # Viết script backup
    cat > /usr/local/bin/sysops-backup.sh <<EOF
#!/usr/bin/env bash
DB_CONTAINER="\$(docker ps -qf name=sysops-portal-db-1 2>/dev/null || docker ps -qf name=db 2>/dev/null)"
mkdir -p $BACKUP_DIR
if [[ -n "\$DB_CONTAINER" ]]; then
    docker exec "\$DB_CONTAINER" pg_dump -U sysops sysops | gzip > "$BACKUP_DIR/sysops_\$(date +%Y%m%d_%H%M).sql.gz"
    find "$BACKUP_DIR" -name "sysops_*.sql.gz" -mtime +30 -delete
    echo "Backup xong: $BACKUP_DIR/sysops_\$(date +%Y%m%d_%H%M).sql.gz"
else
    echo "Không tìm thấy container db!" >&2
fi
EOF
    chmod +x /usr/local/bin/sysops-backup.sh

    # Cron hàng ngày lúc BACKUP_HOUR:00
    (crontab -l 2>/dev/null | grep -v "sysops-backup" ; echo "0 $BACKUP_HOUR * * * /usr/local/bin/sysops-backup.sh >> $BACKUP_DIR/backup.log 2>&1") | crontab -
    info "Backup hàng ngày lúc $BACKUP_HOUR:00 vào $BACKUP_DIR"
fi

# =============================================================================
# TỔNG KẾT
# =============================================================================
step "HOÀN TẤT TRIỂN KHAI"
IP=$(hostname -I | awk '{print $1}')
info "Thời gian: $(date)"
echo ""
echo "─────────────────────────────────────────────────────────────"
echo "  SysOps Portal đã triển khai thành công!"
echo ""
echo "  Truy cập UI    : http://$IP/"
echo "  API Docs       : http://$IP/docs"
echo "  Health check   : http://$IP/healthz"
echo ""
echo "  Thư mục dự án : $APP_DIR"
echo "  File .env     : $APP_DIR/.env"
echo "  Backup DB     : $BACKUP_DIR (hàng ngày lúc $BACKUP_HOUR:00)"
echo ""
echo "  QUAN TRỌNG:"
echo "  1. Nếu AUTH_MODE=token, tạo token service account:"
echo "     cd $APP_DIR"
echo "     docker compose exec api python -m auth mktoken $SERVICE_EMAIL $SERVICE_ROLE"
echo "     -> dán kết quả vào AUTH_TOKENS trong .env rồi:"
echo "        docker compose up -d --force-recreate api worker beat"
echo "  2. Kiểm tra scanner health (bắt buộc):"
echo "     curl -H 'Authorization: Bearer <TOKEN>' http://$IP/api/v1/reports/scanner-health"
echo "  3. Đổi mật khẩu DB_PASSWORD mạnh hơn trong .env nếu cần"
echo "  4. Xem log: docker compose -f $APP_DIR/docker-compose.yml logs -f"
echo "─────────────────────────────────────────────────────────────"