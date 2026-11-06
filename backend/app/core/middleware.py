from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings

log = logging.getLogger("app.request")

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()

        # Origin check for state-changing requests (defence in depth on top of CSRF tokens).
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and origin not in get_settings().allowed_origins:
                return JSONResponse({"detail": "Origin not allowed"}, status_code=403)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            if not request.url.path.startswith("/api/docs"):
                response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if get_settings().cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        log.info(
            "request",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - start) * 1000, 1),
            },
        )
        return response


def client_ip(request: Request) -> str | None:
    # X-Real-IP is only honoured when the app is deployed behind our Nginx (TRUST_PROXY_HEADERS=true);
    # otherwise any client could spoof it to dodge IP-based rate limits.
    if get_settings().trust_proxy_headers:
        forwarded = request.headers.get("x-real-ip")
        if forwarded:
            return forwarded
    return request.client.host if request.client else None
