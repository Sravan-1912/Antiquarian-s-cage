"""OIDC provider endpoints, mounted under /api/v1/oidc (issuer = PUBLIC_BASE_URL + /api/v1/oidc)."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, client_info, rate_limit
from app.core.config import get_settings
from app.core.database import get_db
from app.models import User
from app.security.oidc_keys import get_oidc_key
from app.services import auth, oidc
from app.services.oidc import OIDCError

router = APIRouter(prefix="/oidc", tags=["oidc"])


def _console(path: str, **q: str) -> str:
    return get_settings().public_base_url.rstrip("/") + path + ("?" + urlencode(q) if q else "")


@router.get("/.well-known/openid-configuration")
def well_known():
    return oidc.discovery()


@router.get("/jwks")
def jwks():
    return {"keys": [get_oidc_key().jwk()]}


@router.get("/authorize", dependencies=[Depends(rate_limit("oidc-authorize", 60))])
def authorize(request: Request, db: Session = Depends(get_db)):
    params = dict(request.query_params)
    ci = client_info(request)
    try:
        app, redirect_uri = oidc.validate_authorize_request(db, params)
    except OIDCError as e:
        if not e.redirectable:  # never redirect to an unverified URI
            return RedirectResponse(_console("/sso-error", error=e.error, description=e.description), 303)
        return RedirectResponse(f"{params.get('redirect_uri')}?{urlencode({'error': e.error, 'error_description': e.description, **({'state': params['state']} if params.get('state') else {})})}", 303)

    def back(**q: str) -> RedirectResponse:
        if params.get("state"):
            q["state"] = params["state"]
        return RedirectResponse(f"{redirect_uri}?{urlencode(q)}", 303)

    next_path = "/api/v1/oidc/authorize?" + str(request.query_params)
    sess = auth.resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if sess is None or not sess.mfa_verified or params.get("prompt") == "login":
        return RedirectResponse(_console("/login", next=next_path, app=app.name), 303)
    user = db.get(User, sess.user_id)
    if user is None or user.status != "active":
        return RedirectResponse(_console("/login", next=next_path, app=app.name), 303)
    amr = (sess.amr or {}).get("amr", [])
    if app.mfa_required and "mfa" not in amr:
        return RedirectResponse(_console("/login", next=next_path, app=app.name, step_up="1"), 303)
    if not oidc.assignment_active(db, app, user):
        oidc._event(db, app, user, "sso_authorize", False, "not_assigned", ci.ip, ci.user_agent)
        db.commit()
        return back(error="access_denied", error_description="You have not been granted access to this application")
    code = oidc.issue_code(db, app, user, params, amr, sess.created_at or datetime.now(timezone.utc), ci.ip,
                           ci.user_agent)
    return back(code=code)


def _client_credentials(request: Request, client_id: str | None, client_secret: str | None) -> tuple[str, str | None]:
    hdr = request.headers.get("authorization", "")
    if hdr.lower().startswith("basic "):
        try:
            cid, _, sec = base64.b64decode(hdr[6:]).decode().partition(":")
            from urllib.parse import unquote
            return unquote(cid), unquote(sec)
        except (ValueError, UnicodeDecodeError):
            raise OIDCError("invalid_client", "Malformed Basic credentials", 401)
    return client_id or "", client_secret


@router.post("/token", dependencies=[Depends(rate_limit("oidc-token", 60))])
def token(request: Request, grant_type: str = Form(...), code: str = Form(...), redirect_uri: str = Form(...),
          code_verifier: str = Form(""), client_id: str | None = Form(None), client_secret: str | None = Form(None),
          db: Session = Depends(get_db)):
    ci = client_info(request)
    try:
        if grant_type != "authorization_code":
            raise OIDCError("unsupported_grant_type", "Only authorization_code is supported")
        cid, secret = _client_credentials(request, client_id, client_secret)
        body = oidc.exchange_code(db, client_id=cid, client_secret=secret, code=code, redirect_uri=redirect_uri,
                                  code_verifier=code_verifier, ip=ci.ip, ua=ci.user_agent)
    except OIDCError as e:
        return JSONResponse({"error": e.error, "error_description": e.description}, status_code=e.status,
                            headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.api_route("/userinfo", methods=["GET", "POST"])
def userinfo(request: Request, db: Session = Depends(get_db)):
    hdr = request.headers.get("authorization", "")
    if not hdr.lower().startswith("bearer "):
        return JSONResponse({"error": "invalid_token"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    try:
        return oidc.userinfo(db, hdr[7:])
    except OIDCError as e:
        return JSONResponse({"error": e.error, "error_description": e.description}, status_code=401,
                            headers={"WWW-Authenticate": f'Bearer error="{e.error}"'})


def login_next_is_safe(next_path: str | None) -> bool:
    """Used by the console after sign-in: only our own authorize endpoint may be a post-login destination."""
    return bool(next_path) and next_path.startswith("/api/v1/oidc/authorize?") and "//" not in next_path \
        and "\\" not in next_path and quote(next_path, safe="/?=&%-_.~+") == next_path
