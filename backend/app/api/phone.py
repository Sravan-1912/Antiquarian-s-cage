"""Phone approval sign-in: console endpoints (cookie session + CSRF) and app endpoints (no cookies; the app
authenticates with its per-phone poll secret, and every approval is signed by the biometric-protected key)."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import _set_cookies
from app.api.deps import AuthContext, client_info, current_context, rate_limit, require_permission
from app.core.config import get_settings
from app.core.database import get_db
from app.models import PhoneAuthenticator, User
from app.services import phone_auth
from app.services.auth import AuthError

router = APIRouter(tags=["phone authenticator"])
BROWSER_COOKIE = "cage_phone_req"


def _err(e: phone_auth.PhoneAuthError | AuthError):
    raise HTTPException(e.status, e.message)


# ------------------------------------------------------------------------------------- console (signed-in user)
@router.get("/me/phone-authenticators")
def my_phones(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    rows = db.scalars(select(PhoneAuthenticator).where(PhoneAuthenticator.user_id == ctx.user.id,
                                                       PhoneAuthenticator.revoked_at.is_(None))
                      .order_by(PhoneAuthenticator.created_at)).all()
    return [phone_auth.describe(a) for a in rows]


@router.post("/me/phone-authenticators/pairing", dependencies=[Depends(rate_limit("phone-pairing", 10))])
def start_pairing(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    try:
        _, out = phone_auth.start_pairing(db, ctx.user, ctx.actor)
    except phone_auth.PhoneAuthError as e:
        _err(e)
    db.commit()
    return out


@router.delete("/me/phone-authenticators/{aid}")
def remove_phone(aid: uuid.UUID, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    a = db.get(PhoneAuthenticator, aid)
    if a is None or a.user_id != ctx.user.id or a.revoked_at:
        raise HTTPException(404, "Phone not found")
    phone_auth.revoke(db, a, ctx.actor)
    db.commit()
    return {"removed": True}


@router.get("/users/{user_id}/phone-authenticators")
def admin_list(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
               db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "User not found")
    rows = db.scalars(select(PhoneAuthenticator).where(PhoneAuthenticator.user_id == user_id,
                                                       PhoneAuthenticator.revoked_at.is_(None))).all()
    return [phone_auth.describe(a) for a in rows]


@router.delete("/users/{user_id}/phone-authenticators/{aid}")
def admin_remove(user_id: uuid.UUID, aid: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                 db: Session = Depends(get_db)):
    a = db.get(PhoneAuthenticator, aid)
    if a is None or a.user_id != user_id or a.organization_id != ctx.user.organization_id or a.revoked_at:
        raise HTTPException(404, "Phone not found")
    phone_auth.revoke(db, a, ctx.actor)
    db.commit()
    return {"removed": True}


# ------------------------------------------------------------------------------------- browser sign-in
class PhoneStart(BaseModel):
    email: str = Field(min_length=3, max_length=320)


@router.post("/auth/phone/start", dependencies=[Depends(rate_limit("phone-login", 10))])
def phone_start(body: PhoneStart, request: Request, response: Response, db: Session = Depends(get_db)):
    st = phone_auth.start_login(db, body.email, client_info(request))
    db.commit()
    s = get_settings()
    response.set_cookie(BROWSER_COOKIE, st.browser_secret, max_age=180, httponly=True, secure=s.cookie_secure,
                        samesite="strict", path="/api/v1/auth/phone")
    return {"request_id": str(st.request_id), "number": st.number, "expires_at": st.expires_at}


class PhoneCollect(BaseModel):
    request_id: uuid.UUID


@router.post("/auth/phone/status", dependencies=[Depends(rate_limit("phone-status", 120))])
def phone_status(body: PhoneCollect, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        status, res = phone_auth.collect(db, body.request_id, request.cookies.get(BROWSER_COOKIE, ""),
                                         client_info(request))
    except (phone_auth.PhoneAuthError, AuthError) as e:
        db.commit()
        _err(e)
    db.commit()
    if res is not None:
        _set_cookies(response, res.session_token, res.csrf_token)
        response.delete_cookie(BROWSER_COOKIE, path="/api/v1/auth/phone")
    return {"status": status}


# ------------------------------------------------------------------------------------- authenticator app
class PairBody(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    public_key_pem: str = Field(min_length=100, max_length=4000)
    key_alg: Literal["ES256", "RS256"]
    name: str = Field(min_length=1, max_length=80)
    platform: Literal["android", "ios"]
    signature: str = Field(min_length=10, max_length=2000)


@router.post("/authenticator/pair", dependencies=[Depends(rate_limit("phone-pair", 10))])
def app_pair(body: PairBody, request: Request, db: Session = Depends(get_db)):
    try:
        a, secret = phone_auth.complete_pairing(db, body.token, body.public_key_pem, body.key_alg, body.name,
                                                body.platform, body.signature, client_info(request))
    except phone_auth.PhoneAuthError as e:
        db.commit()
        _err(e)
    user = db.get(User, a.user_id)
    db.commit()
    return {"authenticator_id": str(a.id), "poll_secret": secret, "account": user.email, "name": a.name}


class AppAuth(BaseModel):
    authenticator_id: uuid.UUID
    poll_secret: str = Field(min_length=20, max_length=100)


@router.post("/authenticator/pending", dependencies=[Depends(rate_limit("phone-poll", 120))])
def app_pending(body: AppAuth, db: Session = Depends(get_db)):
    try:
        return {"requests": phone_auth.pending(db, body.authenticator_id, body.poll_secret)}
    except phone_auth.PhoneAuthError as e:
        _err(e)


class DecideBody(AppAuth):
    request_id: uuid.UUID
    decision: Literal["approve", "deny"]
    number: int = Field(ge=0, le=99)
    signature: str = Field(min_length=10, max_length=2000)


@router.post("/authenticator/decide", dependencies=[Depends(rate_limit("phone-decide", 30))])
def app_decide(body: DecideBody, request: Request, db: Session = Depends(get_db)):
    try:
        result = phone_auth.decide(db, body.authenticator_id, body.poll_secret, body.request_id, body.decision,
                                   body.number, body.signature, client_info(request))
    except phone_auth.PhoneAuthError as e:
        db.commit()
        _err(e)
    db.commit()
    return {"result": result}


# ------------------------------------------------------------------------------------- Windows sign-in (console)
@router.get("/me/windows-unlock")
def my_windows_unlock(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    from app.models import WindowsUnlockKey
    from app.services import windows_unlock as wu
    rows = db.scalars(select(WindowsUnlockKey).where(WindowsUnlockKey.user_id == ctx.user.id,
                                                     WindowsUnlockKey.status == "active")).all()
    return [wu.describe(db, k) for k in rows]


@router.delete("/me/windows-unlock/{kid}")
def remove_my_windows_unlock(kid: uuid.UUID, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    from app.models import WindowsUnlockKey
    from app.services import windows_unlock as wu
    k = db.get(WindowsUnlockKey, kid)
    if k is None or k.user_id != ctx.user.id or k.status == "revoked":
        raise HTTPException(404, "Not found")
    wu.revoke(db, k, ctx.actor)
    db.commit()
    return {"removed": True}


@router.get("/devices/{device_id}/windows-unlock")
def device_windows_unlock(device_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("devices:read")),
                          db: Session = Depends(get_db)):
    from app.models import Device, WindowsUnlockKey
    from app.services import windows_unlock as wu
    d = db.get(Device, device_id)
    if d is None or d.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Endpoint not found")
    rows = db.scalars(select(WindowsUnlockKey).where(WindowsUnlockKey.device_id == d.id,
                                                     WindowsUnlockKey.status == "active")).all()
    return [wu.describe(db, k) for k in rows]


@router.delete("/devices/{device_id}/windows-unlock/{kid}")
def device_windows_unlock_remove(device_id: uuid.UUID, kid: uuid.UUID,
                                 ctx: AuthContext = Depends(require_permission("devices:manage")),
                                 db: Session = Depends(get_db)):
    from app.models import WindowsUnlockKey
    from app.services import windows_unlock as wu
    k = db.get(WindowsUnlockKey, kid)
    if k is None or k.device_id != device_id or k.organization_id != ctx.user.organization_id or k.status == "revoked":
        raise HTTPException(404, "Not found")
    wu.revoke(db, k, ctx.actor)
    db.commit()
    return {"removed": True}
