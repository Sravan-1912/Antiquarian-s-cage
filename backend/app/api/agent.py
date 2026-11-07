"""Agent channel (/agent/v1). Separate from the admin API: no cookies, no CSRF, no browser origins.

Every endpoint except /enroll requires a request signed with the device key (see security/pki.py), and in
production additionally a verified client certificate forwarded by the mTLS proxy."""
from __future__ import annotations

import hashlib
from typing import TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from app.api.deps import rate_limit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.middleware import client_ip
from app.core.rate_limit import get_rate_limiter
from app.models import Device, DeviceCertificate
from app.schemas import endpoints as s
from app.security import command_signing, pki
from app.schemas.policies import JobResult
from app.services import policies
from app.services.policies import PolicyError
import uuid
from app.services import devices
from app.services.devices import DeviceError

router = APIRouter(prefix="/agent/v1", tags=["agent"])
M = TypeVar("M", bound=BaseModel)


async def _body(request: Request) -> bytes:
    limit = get_settings().agent_max_body_bytes
    declared = request.headers.get("content-length")
    if declared and int(declared) > limit:
        raise HTTPException(413, "Payload too large")
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(413, "Payload too large")
    return body


def _parse(model: type[M], body: bytes) -> M:
    try:
        return model.model_validate_json(body or b"{}")
    except ValidationError as exc:
        raise HTTPException(422, detail=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]) from exc


def _proxy_cert_fingerprint(escaped_pem: str | None) -> str | None:
    """Nginx forwards the *verified* client certificate as URL-encoded PEM ($ssl_client_escaped_cert).
    We compute the SHA-256 fingerprint ourselves (Nginx's $ssl_client_fingerprint is SHA-1)."""
    if not escaped_pem:
        return None
    from urllib.parse import unquote

    try:
        cert = x509.load_pem_x509_certificate(unquote(escaped_pem).encode())
    except ValueError:
        return None
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class AgentContext:
    def __init__(self, device: Device, cert: DeviceCertificate, body: bytes, ip: str | None):
        self.device, self.cert, self.body, self.ip = device, cert, body, ip


async def agent_auth(request: Request, db: Session = Depends(get_db)) -> AgentContext:
    body = await _body(request)
    h = request.headers
    ip = client_ip(request)
    device_id = h.get("x-cage-device", "")
    if not get_rate_limiter().hit(f"agent:{device_id or ip}", 120, 60):
        raise HTTPException(429, "Too many requests")
    try:
        device, cert = devices.authenticate_agent(
            db, device_id=device_id, timestamp=h.get("x-cage-timestamp", ""), nonce=h.get("x-cage-nonce", ""),
            signature=h.get("x-cage-signature", ""), method=request.method, path=request.url.path, body=body,
            proxy_fingerprint=_proxy_cert_fingerprint(h.get("x-client-cert")) if get_settings().trust_proxy_headers
            else None,
        )
    except DeviceError as e:
        raise HTTPException(e.status, e.message)
    return AgentContext(device, cert, body, ip)


@router.post("/enroll", response_model=s.EnrollResponse, status_code=201,
             dependencies=[Depends(rate_limit("agent-enroll", 10))])
async def enroll(request: Request, db: Session = Depends(get_db)):
    req = _parse(s.EnrollRequest, await _body(request))
    try:
        device, issued = devices.enroll(db, req, client_ip(request))
    except DeviceError as e:
        raise HTTPException(e.status, e.message)
    st = get_settings()
    key = command_signing.get_signing_key()
    return s.EnrollResponse(device_id=device.id, certificate_pem=issued.certificate_pem,
                            ca_certificate_pem=pki.get_ca().cert_pem,
                            heartbeat_interval_seconds=st.heartbeat_interval_seconds,
                            inventory_interval_seconds=st.inventory_interval_seconds,
                            command_key_id=key.key_id, command_public_key=key.public_key_b64)


@router.post("/heartbeat", response_model=s.HeartbeatResponse)
def heartbeat(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    req = _parse(s.HeartbeatRequest, ctx.body)
    return devices.record_heartbeat(db, ctx.device, ctx.cert, req, ctx.ip)


@router.post("/inventory", status_code=202)
def inventory(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    req = _parse(s.InventoryRequest, ctx.body)
    devices.record_inventory(db, ctx.device, req)
    return {"accepted": True}


@router.post("/certificate/renew", response_model=s.RenewResponse)
def renew(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    req = _parse(s.RenewRequest, ctx.body)
    try:
        issued = devices.renew_certificate(db, ctx.device, ctx.cert, req.csr_pem, ctx.ip)
    except DeviceError as e:
        raise HTTPException(e.status, e.message)
    return s.RenewResponse(certificate_pem=issued.certificate_pem, not_after=issued.not_after)


@router.post("/jobs")
def fetch_jobs(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    """Pull model: endpoints never accept inbound connections. Returns signed envelopes only."""
    return policies.fetch_jobs(db, ctx.device)


@router.post("/jobs/{job_id}/result")
def job_result(job_id: uuid.UUID, ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    req = _parse(JobResult, ctx.body)
    try:
        job = policies.record_result(db, ctx.device, job_id, req.status, req.detail, req.previous_state,
                                     req.current_state, ctx.ip)
    except PolicyError as e:
        raise HTTPException(e.status, e.message)
    return {"job_id": str(job.id), "status": job.status}


@router.post("/assist/{session_id}/event")
def assist_event(session_id: uuid.UUID, ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    """Endpoint-side session events: the user ended the session, the local timer expired, or the helper failed."""
    from app.schemas.remote import AgentSessionEvent
    from app.services import remote
    req = _parse(AgentSessionEvent, ctx.body)
    try:
        sess = remote.on_agent_event(db, ctx.device, session_id, req.event, req.detail, ctx.ip)
    except PolicyError as e:
        raise HTTPException(e.status, e.message)
    return {"session_id": str(sess.id), "status": sess.status}


# ------------------------------------------------------------------------------- Windows sign-in from the phone
class UnlockStart(BaseModel):
    model_config = {"extra": "forbid"}
    kind: str
    windows_user: str
    sid: str
    key: str | None = None


class UnlockStatus(BaseModel):
    model_config = {"extra": "forbid"}
    request_id: uuid.UUID
    secret: str


@router.post("/unlock/start")
def unlock_start(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    """Called by the agent on behalf of the local credential provider (lock screen)."""
    from app.services import windows_unlock as wu
    req = _parse(UnlockStart, ctx.body)
    try:
        st = wu.start(db, ctx.device, kind=req.kind, windows_user=req.windows_user, sid=req.sid, key_b64=req.key,
                      ip=ctx.ip)
    except wu.UnlockError as e:
        db.rollback()
        raise HTTPException(e.status, {"code": e.code, "message": e.message})
    db.commit()
    return {"request_id": str(st.request_id), "number": st.number, "secret": st.secret,
            "expires_at": st.expires_at, "approver": st.approver}


@router.post("/unlock/status")
def unlock_status(ctx: AgentContext = Depends(agent_auth), db: Session = Depends(get_db)):
    from app.services import windows_unlock as wu
    req = _parse(UnlockStatus, ctx.body)
    try:
        out = wu.status(db, ctx.device, req.request_id, req.secret, ctx.ip)
    except wu.UnlockError as e:
        db.commit()
        raise HTTPException(e.status, {"code": e.code, "message": e.message})
    db.commit()
    return out
