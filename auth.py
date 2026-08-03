"""
SysOps Portal — xác thực & phân quyền
=====================================

Ba nguyên tắc, theo đúng thứ tự quan trọng:

1. **`actor` không bao giờ đến từ request body.** Trước đây `reserved_by`,
   `actor` là chuỗi client tự khai, nghĩa là bất kỳ ai cũng ký tên "system"
   lên audit log. Một audit log giả mạo được thì tệ hơn không có audit log,
   vì nó tạo cảm giác an toàn giả. Giờ `actor` luôn lấy từ principal đã
   xác thực.

2. **Fail closed.** Không cấu hình được backend thì từ chối phục vụ, không
   im lặng cho qua.

3. **Chế độ dev không thể chạy nhầm ở production.** `AUTH_MODE=dev` bị
   từ chối ngay lúc khởi động nếu DATABASE_URL không phải SQLite. Đây là
   bất biến ở tầng code, không phải một dòng ghi chú trong runbook.

Cấu hình:
    AUTH_MODE=dev                # chỉ chạy được với SQLite
    AUTH_MODE=token              # service account + con người dùng bearer token
    AUTH_MODE=ldap               # SSO/LDAP công ty, có fallback token cho máy

Sinh token cho service account:
    python -m auth mktoken svc-celery@ntq-solution.com.vn sysops
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status

from db import IS_SQLITE

log = logging.getLogger("sysops.auth")

# --------------------------------------------------------------------------- #
# Vai trò
# --------------------------------------------------------------------------- #

VIEWER = "viewer"
REQUESTER = "requester"
SYSOPS = "sysops"
ADMIN = "admin"

# Phân cấp: vai trò cao bao hàm mọi quyền của vai trò thấp hơn.
ROLE_RANK: dict[str, int] = {VIEWER: 0, REQUESTER: 1, SYSOPS: 2, ADMIN: 3}

SESSION_COOKIE = "sysops_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(8 * 3600)))


@dataclass(frozen=True)
class Principal:
    """Danh tính đã được xác thực. Đây là nguồn duy nhất cho `actor`."""

    email: str
    role: str
    via: str  # dev | token | ldap

    def at_least(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[role]


# --------------------------------------------------------------------------- #
# Cấu hình
# --------------------------------------------------------------------------- #


def auth_mode() -> str:
    return os.getenv("AUTH_MODE", "dev").strip().lower()


def _session_secret() -> bytes:
    raw = os.getenv("SESSION_SECRET", "")
    if raw:
        return raw.encode()
    if auth_mode() == "dev":
        # Khoá tạm cho dev: đổi mỗi lần khởi động => restart là mất phiên.
        # Chấp nhận được ở dev, và tránh việc một khoá mặc định bị copy lên prod.
        return _DEV_EPHEMERAL_SECRET
    raise RuntimeError("Thiếu SESSION_SECRET — bắt buộc khi AUTH_MODE != dev")


_DEV_EPHEMERAL_SECRET = secrets.token_bytes(32)


def verify_startup_config() -> list[str]:
    """
    Chạy lúc khởi động. Ném lỗi với cấu hình nguy hiểm, trả cảnh báo với
    cấu hình chấp nhận được nhưng cần biết.
    """
    mode = auth_mode()
    warnings: list[str] = []

    if mode not in ("dev", "token", "ldap"):
        raise RuntimeError(f"AUTH_MODE không hợp lệ: {mode!r}. Chọn: dev | token | ldap")

    if mode == "dev":
        # Cửa thoát DUY NHẤT cho bất biến này là bộ test chạy trên Postgres
        # dùng-một-lần (xem tests/conftest.py). Biến môi trường đặt tên dài và
        # xấu có chủ đích — không ai gõ nhầm nó vào file cấu hình production.
        if not IS_SQLITE and os.getenv("ALLOW_DEV_AUTH_ON_NON_SQLITE") == "true":
            warnings.append(
                "AUTH_MODE=dev đang chạy trên DB không phải SQLite vì "
                "ALLOW_DEV_AUTH_ON_NON_SQLITE=true. Chỉ hợp lệ trong test."
            )
        elif not IS_SQLITE:
            raise RuntimeError(
                "AUTH_MODE=dev bị chặn khi DATABASE_URL không phải SQLite.\n"
                "Chế độ dev cho phép mạo danh bất kỳ ai qua HTTP header — "
                "không bao giờ được chạy trên cơ sở dữ liệu thật.\n"
                "Đặt AUTH_MODE=token hoặc AUTH_MODE=ldap."
            )
        warnings.append(
            "AUTH_MODE=dev: mọi request có thể tự khai danh tính qua header "
            "X-Dev-User. Chỉ dùng để chạy thử cục bộ."
        )

    if mode == "token" and not _load_tokens():
        raise RuntimeError(
            "AUTH_MODE=token nhưng AUTH_TOKENS rỗng — không ai đăng nhập được.\n"
            "Sinh token: python -m auth mktoken <email> <role>"
        )

    if mode == "ldap":
        missing = [k for k in ("LDAP_URI", "LDAP_USER_DN_TEMPLATE") if not os.getenv(k)]
        if missing:
            raise RuntimeError(f"AUTH_MODE=ldap thiếu biến môi trường: {missing}")
        if not _load_tokens():
            warnings.append(
                "Chưa có AUTH_TOKENS: các job nền (Celery) sẽ không gọi được API "
                "vì service account không đăng nhập LDAP tương tác được."
            )

    if mode != "dev" and not os.getenv("SESSION_SECRET"):
        raise RuntimeError("Thiếu SESSION_SECRET — bắt buộc khi AUTH_MODE != dev")

    # Bẫy cấu hình dễ mất giờ nhất: cookie phiên mặc định có cờ Secure, nên
    # khi chạy thử qua http:// trình duyệt nhận cookie rồi không gửi lại —
    # đăng nhập "thành công" mà vẫn như chưa đăng nhập.
    if mode == "dev" and os.getenv("COOKIE_SECURE", "true").lower() == "true":
        warnings.append(
            "COOKIE_SECURE=true nhưng đang ở chế độ dev: nếu chạy qua http:// "
            "thì phiên đăng nhập sẽ không giữ được. Đặt COOKIE_SECURE=false "
            "khi chạy cục bộ không có HTTPS."
        )

    return warnings


# --------------------------------------------------------------------------- #
# Backend 1 — bearer token (service account & người dùng máy)
# --------------------------------------------------------------------------- #


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _load_tokens() -> dict[str, tuple[str, str]]:
    """
    AUTH_TOKENS = "email:role:sha256hex,email2:role2:sha256hex2"

    Lưu hash chứ không lưu token gốc: nếu file .env hay biến môi trường
    của container bị lộ, kẻ đọc được vẫn không đăng nhập được.
    """
    raw = os.getenv("AUTH_TOKENS", "").strip()
    out: dict[str, tuple[str, str]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3:
            log.warning("Bỏ qua mục AUTH_TOKENS sai định dạng: %r", entry[:24])
            continue
        email, role, digest = (p.strip() for p in parts)
        if role not in ROLE_RANK:
            log.warning("Bỏ qua token có vai trò không hợp lệ: %r", role)
            continue
        out[digest.lower()] = (email, role)
    return out


def _principal_from_token(token: str) -> Principal | None:
    digest = hash_token(token)
    for known_digest, (email, role) in _load_tokens().items():
        # compare_digest để thời gian so sánh không rò rỉ thông tin về token.
        if hmac.compare_digest(digest, known_digest):
            return Principal(email=email, role=role, via="token")
    return None


# --------------------------------------------------------------------------- #
# Backend 2 — LDAP (đăng nhập tương tác cho UI)
# --------------------------------------------------------------------------- #


def ldap_authenticate(username: str, password: str) -> Principal | None:
    """
    Bind thật vào LDAP công ty. Vai trò suy ra từ group.

    Cố ý KHÔNG tự tạo tài khoản: người không thuộc group nào chỉ được `viewer`.
    Nâng quyền phải là hành động có chủ đích của admin.
    """
    if not password:
        return None  # LDAP cho phép bind ẩn danh với mật khẩu rỗng — chặn từ đây.

    try:
        import ldap  # type: ignore
    except ImportError:
        log.error("AUTH_MODE=ldap nhưng chưa cài python-ldap")
        return None

    uri = os.environ["LDAP_URI"]
    user_dn = os.environ["LDAP_USER_DN_TEMPLATE"].format(username=username)

    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    try:
        conn.simple_bind_s(user_dn, password)
    except Exception as exc:
        log.info("LDAP bind thất bại cho %s: %s", username, type(exc).__name__)
        return None

    role = VIEWER
    base = os.getenv("LDAP_GROUP_BASE_DN")
    if base:
        group_map = [
            (os.getenv("LDAP_ADMIN_GROUP"), ADMIN),
            (os.getenv("LDAP_SYSOPS_GROUP"), SYSOPS),
            (os.getenv("LDAP_REQUESTER_GROUP"), REQUESTER),
        ]
        for group_cn, mapped_role in group_map:
            if not group_cn:
                continue
            try:
                found = conn.search_s(
                    base,
                    ldap.SCOPE_SUBTREE,
                    f"(&(cn={group_cn})(member={user_dn}))",
                    ["cn"],
                )
                if found:
                    role = mapped_role
                    break
            except Exception:
                log.warning("Không tra được group %s", group_cn)

    email = os.getenv("LDAP_EMAIL_TEMPLATE", "{username}").format(username=username)
    conn.unbind_s()
    return Principal(email=email, role=role, via="ldap")


# --------------------------------------------------------------------------- #
# Backend 3 — dev (chỉ SQLite)
# --------------------------------------------------------------------------- #


def _principal_from_dev_headers(request: Request) -> Principal | None:
    if auth_mode() != "dev":
        return None
    email = request.headers.get("X-Dev-User", "dev@localhost")
    role = request.headers.get("X-Dev-Role", ADMIN).strip().lower()
    if role not in ROLE_RANK:
        role = VIEWER
    return Principal(email=email, role=role, via="dev")


# --------------------------------------------------------------------------- #
# Phiên đăng nhập cho UI (cookie ký HMAC)
# --------------------------------------------------------------------------- #


def issue_session(p: Principal) -> str:
    payload = json.dumps(
        {
            "email": p.email,
            "role": p.role,
            "via": p.via,
            "exp": int(time.time()) + SESSION_TTL_SECONDS,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    sig = hmac.new(_session_secret(), payload, hashlib.sha256).hexdigest()
    return payload.hex() + "." + sig


def _principal_from_session(raw: str | None) -> Principal | None:
    if not raw or "." not in raw:
        return None
    body_hex, _, sig = raw.partition(".")
    try:
        payload = bytes.fromhex(body_hex)
    except ValueError:
        return None
    expected = hmac.new(_session_secret(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if data.get("exp", 0) < time.time():
        return None
    if data.get("role") not in ROLE_RANK:
        return None
    return Principal(email=data["email"], role=data["role"], via=data.get("via", "ldap"))


# --------------------------------------------------------------------------- #
# Dependency
# --------------------------------------------------------------------------- #


def current_principal(request: Request) -> Principal:
    """
    Thứ tự thử: Bearer token -> cookie phiên -> header dev.

    Token đứng trước vì job nền và script luôn dùng token; đường đó phải
    nhanh và không phụ thuộc trạng thái phiên.
    """
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        p = _principal_from_token(header[7:].strip())
        if p:
            return p
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token không hợp lệ",
            headers={"WWW-Authenticate": "Bearer"},
        )

    p = _principal_from_session(request.cookies.get(SESSION_COOKIE))
    if p:
        return p

    p = _principal_from_dev_headers(request)
    if p:
        return p

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Cần đăng nhập",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require(role: str) -> Callable[..., Principal]:
    """
    Dependency phân quyền.

        @router.post("/...", dependencies=[])
        def handler(p: Principal = Depends(require(SYSOPS))): ...
    """

    def _dep(p: Principal = Depends(current_principal)) -> Principal:
        if not p.at_least(role):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Cần vai trò {role} trở lên; tài khoản này là {p.role}",
            )
        return p

    return _dep


# --------------------------------------------------------------------------- #
# CLI: sinh token
# --------------------------------------------------------------------------- #


def _mktoken(email: str, role: str) -> None:
    if role not in ROLE_RANK:
        raise SystemExit(f"Vai trò không hợp lệ: {role}. Chọn: {list(ROLE_RANK)}")
    token = secrets.token_urlsafe(32)
    print("Token (đưa cho client, KHÔNG lưu ở server):")
    print(f"  {token}")
    print()
    print("Thêm dòng này vào AUTH_TOKENS trong .env (chỉ chứa hash):")
    print(f"  {email}:{role}:{hash_token(token)}")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "mktoken":
        _mktoken(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("Dùng: python -m auth mktoken <email> <role>")
