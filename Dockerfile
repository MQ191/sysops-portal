FROM python:3.11-slim

# nmap + iputils cho scanner; libpq cho psycopg
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap iputils-ping net-tools arp-scan libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore chặn .env, vault_import.csv, *.db khỏi build context.
# Không có file đó, `COPY . .` sẽ nướng mật khẩu dạng rõ vào một layer image
# vĩnh viễn — kể cả khi layer sau xoá file đi.
COPY . .

# Chạy bằng user không đặc quyền.
RUN useradd -m -u 10001 sysops && chown -R sysops:sysops /app

# Cấp quyền raw socket cho ĐÚNG hai binary cần nó, thay vì chạy cả tiến trình
# bằng root. `cap_add: NET_RAW` ở compose chỉ thêm capability vào container —
# tiến trình non-root KHÔNG tự thừa hưởng. Thiếu bước này scanner sẽ im lặng
# báo mọi host là chết, và đó là chế độ hỏng nguy hiểm nhất của hệ thống.
RUN setcap cap_net_raw+ep /bin/ping \
    && setcap cap_net_raw+ep /usr/bin/nmap || true

USER sysops

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
