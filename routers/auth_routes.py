"""Đăng nhập / đăng xuất / xem danh tính hiện tại."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Form, HTTPException, Response, status

from auth import (
    ADMIN,
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    Principal,
    _principal_from_token,
    auth_mode,
    current_principal,
    issue_session,
    ldap_authenticate,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.get("/me")
def me(p: Principal = Depends(current_principal)):
    return {"email": p.email, "role": p.role, "via": p.via}


@router.post("/login")
def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    mode = auth_mode()

    if mode == "ldap":
        principal = ldap_authenticate(username, password)
    elif mode == "dev":
        # Dev: không kiểm tra mật khẩu, nhưng chỉ chạy được với SQLite
        # (bất biến này được ép ở auth.verify_startup_config).
        principal = Principal(email=username, role=ADMIN, via="dev")
    else:
        # AUTH_MODE=token: đổi bearer token lấy phiên đăng nhập.
        #
        # Trình duyệt không gắn được header Authorization khi người dùng bấm
        # vào một đường link, nên nếu không có đường này thì ở chế độ token
        # KHÔNG AI vào được giao diện web — chỉ gọi được API bằng curl.
        # Token đóng vai trò chính là thông tin xác thực; đổi nó lấy cookie
        # phiên có thời hạn còn an toàn hơn là dán token vào mọi request.
        principal = _principal_from_token(password.strip())
        if principal and username.strip() and principal.email != username.strip():
            # Token quyết định danh tính, không phải ô tên đăng nhập. Gõ lệch
            # thì báo lỗi thay vì lặng lẽ đăng nhập bằng danh tính khác.
            principal = None

    if not principal:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sai tài khoản hoặc mật khẩu")

    response.set_cookie(
        SESSION_COOKIE,
        issue_session(principal),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        # Portal luôn chạy sau HTTPS ở production; tắt cờ này chỉ ở dev.
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
    )
    return {"email": principal.email, "role": principal.role}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "logged_out"}
