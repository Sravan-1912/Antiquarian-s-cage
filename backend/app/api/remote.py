"""Remote administration API (admin console)."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, rate_limit, require_permission
from app.api.devices import _get as get_device
from app.core.database import get_db
from app.models import CommandJob, Device, DeviceCertificate, RemoteSession
from app.schemas import remote as s
from app.security import passwords
from app.services import audit, remote
from app.services.policies import PolicyError

router = APIRouter(tags=["remote"])
REMOTE = require_permission("devices:remote")
SHELL = require_permission("devices:shell")
READ_ANY = require_permission("devices:read", "devices:read_assigned", any_of=True)


def _raise(e: PolicyError):
    raise HTTPException(e.status, e.message)


def _reauth(db: Session, ctx: AuthContext, step_up: s.StepUp | None, what: str) -> None:
    """Explicit authorisation for a sensitive action: a fresh password confirmation (step-up), not a cached session."""
    ok = step_up is not None and passwords.verify_password(step_up.password, ctx.user.password_hash)
    if not ok:
        audit.record(db, ctx.user.organization_id, ctx.actor, "remote.reauth_failed", result="denied",
                     metadata={"action": what})
        db.commit()
        raise HTTPException(403, "Password confirmation failed")


def _action_out(db: Session, j: CommandJob) -> s.ActionOut:
    o = s.ActionOut.model_validate(j)
    o.requested_by_label = j.parameters.get("requested_by") or remote.requester_label(db, j.requested_by)
    return o


def _session_out(db: Session, x: RemoteSession) -> s.SessionOut:
    o = s.SessionOut.model_validate(x)
    d = db.get(Device, x.device_id)
    o.device_name = d.display_name if d else None
    return o


@router.post("/devices/{device_id}/actions", response_model=s.ActionOut, status_code=201,
             dependencies=[Depends(rate_limit("remote-action", 30))])
def create_action(device_id: uuid.UUID, body: s.ActionRequest, ctx: AuthContext = Depends(REMOTE),
                  db: Session = Depends(get_db)):
    device = get_device(db, ctx, device_id)
    if body.command in s.SENSITIVE:
        _reauth(db, ctx, body.step_up, body.command)
    try:
        job = remote.create_action(db, device, body.command, body.parameters, body.reason.strip(), ctx.actor)
    except ValidationError as exc:
        raise HTTPException(422, detail=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])
    except PolicyError as e:
        _raise(e)
    return _action_out(db, job)


@router.get("/devices/{device_id}/actions", response_model=list[s.ActionOut])
def list_actions(device_id: uuid.UUID, ctx: AuthContext = Depends(READ_ANY), db: Session = Depends(get_db)):
    get_device(db, ctx, device_id)
    rows = db.scalars(select(CommandJob).where(CommandJob.device_id == device_id,
                                               CommandJob.command.not_like("policy.%"))
                      .order_by(CommandJob.issued_at.desc()).limit(50))
    return [_action_out(db, j) for j in rows]


@router.post("/devices/{device_id}/assist", response_model=s.SessionOut, status_code=201,
             dependencies=[Depends(rate_limit("remote-assist", 10))])
def request_assist(device_id: uuid.UUID, body: s.AssistRequest, ctx: AuthContext = Depends(REMOTE),
                   db: Session = Depends(get_db)):
    device = get_device(db, ctx, device_id)
    cfg = remote.assist_settings(db, ctx.user.organization_id)
    if "devices:read" not in ctx.permissions and not cfg.allow_it_support:
        raise HTTPException(403, "Remote assistance by IT support is disabled by organisation policy")
    _reauth(db, ctx, body.step_up, "assist.start")
    try:
        sess = remote.request_session(db, device, body.reason.strip(), body.max_minutes, ctx.actor)
    except PolicyError as e:
        _raise(e)
    return _session_out(db, sess)


@router.post("/devices/{device_id}/rdp", response_model=s.SessionOut, status_code=201,
             dependencies=[Depends(rate_limit("remote-rdp", 10))])
def request_rdp(device_id: uuid.UUID, body: s.RdpRequest, ctx: AuthContext = Depends(REMOTE),
                db: Session = Depends(get_db)):
    """Start an unattended Remote Desktop session. By design this needs no endpoint consent and no password step-up,
    but the endpoint always shows a visible 'Remote desktop active' banner; the agent fails closed (no session) if it
    cannot show the banner. RBAC (devices:remote) and admin isolation still apply."""
    device = get_device(db, ctx, device_id)
    try:
        sess = remote.request_rdp_session(db, device, body.reason.strip(), body.max_minutes, ctx.actor)
    except PolicyError as e:
        _raise(e)
    return _session_out(db, sess)


@router.post("/remote-sessions/{session_id}/rdp-connect")
def rdp_connect(session_id: uuid.UUID, ctx: AuthContext = Depends(REMOTE), db: Session = Depends(get_db)):
    """Mint a short-lived operator token for the RDP relay. The operator's local helper uses it to open the tunnel
    WebSocket and reach the endpoint's Remote Desktop across any network (no VPN). RBAC + admin isolation apply."""
    sess = db.get(RemoteSession, session_id)
    if sess is None:
        raise HTTPException(404, "Session not found")
    get_device(db, ctx, sess.device_id)  # enforces admin isolation / device access, 404 otherwise
    if sess.mode != "rdp" or sess.status != "active":
        raise HTTPException(409, "No active remote-desktop session for this endpoint")
    from app.services.rdp_relay import mint_token
    # The endpoint's active device public key lets the operator's helper VERIFY the end-to-end (zero-knowledge relay)
    # handshake signature, so a tampering relay cannot substitute its own key. The relay itself never sees the session.
    cert = db.scalar(select(DeviceCertificate).where(DeviceCertificate.device_id == sess.device_id,
                                                     DeviceCertificate.status == "active")
                     .order_by(DeviceCertificate.created_at.desc()).limit(1))
    audit.record(db, ctx.user.organization_id, ctx.actor, "remote.rdp_connect", target_type="device",
                 target_id=sess.device_id, target_label=None, metadata={"session_id": str(sess.id)})
    db.commit()
    return {"session_id": str(sess.id), "operator_token": mint_token(str(sess.id), "operator"),
            "tunnel_path": "/api/v1/rdp/tunnel",
            "endpoint_public_key": cert.public_key_pem if cert else None}


@router.post("/devices/{device_id}/shell", response_model=s.SessionOut, status_code=201,
             dependencies=[Depends(rate_limit("remote-shell", 10))])
def request_shell(device_id: uuid.UUID, body: s.ShellRequest, ctx: AuthContext = Depends(SHELL),
                  db: Session = Depends(get_db)):
    """Open an interactive live-response shell (ARBITRARY command execution — break-glass). RBAC (devices:shell, and
    devices:shell_elevated for an elevated session) and admin isolation apply; the endpoint always shows a visible
    banner, and the agent writes every command + output to the audit trail."""
    if body.elevated and "devices:shell_elevated" not in ctx.permissions:
        raise HTTPException(403, "An elevated (SYSTEM/root) shell requires the devices:shell_elevated permission")
    device = get_device(db, ctx, device_id)
    try:
        sess = remote.request_shell_session(db, device, body.reason.strip(), body.max_minutes, body.elevated, ctx.actor)
    except PolicyError as e:
        _raise(e)
    return _session_out(db, sess)


@router.post("/remote-sessions/{session_id}/shell-connect")
def shell_connect(session_id: uuid.UUID, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    """Mint a short-lived operator token so the console's terminal can attach to the live-response shell over the relay
    (the same mode-agnostic byte relay the RDP tunnel uses). RBAC + admin isolation apply."""
    sess = db.get(RemoteSession, session_id)
    if sess is None:
        raise HTTPException(404, "Session not found")
    get_device(db, ctx, sess.device_id)
    if sess.mode != "shell" or sess.status != "active":
        raise HTTPException(409, "No active live-response shell for this endpoint")
    from app.services.rdp_relay import mint_token
    cert = db.scalar(select(DeviceCertificate).where(DeviceCertificate.device_id == sess.device_id,
                                                     DeviceCertificate.status == "active")
                     .order_by(DeviceCertificate.created_at.desc()).limit(1))
    audit.record(db, ctx.user.organization_id, ctx.actor, "remote.shell_connect", target_type="device",
                 target_id=sess.device_id, target_label=None, metadata={"session_id": str(sess.id)})
    db.commit()
    return {"session_id": str(sess.id), "operator_token": mint_token(str(sess.id), "operator"),
            "tunnel_path": "/api/v1/rdp/tunnel", "endpoint_public_key": cert.public_key_pem if cert else None}


@router.websocket("/rdp/tunnel")
async def rdp_tunnel_operator(ws: WebSocket, session: str, token: str):
    """Operator side of the RDP relay: the operator's local helper dials out here, authorised by the token minted by
    /remote-sessions/{id}/rdp-connect, and the relay copies bytes to the matching endpoint tunnel."""
    from app.services.rdp_relay import hub, verify_token
    if not verify_token(token, session, "operator"):
        await ws.close(code=4401)
        return
    await ws.accept()
    await hub.join(session, "operator", ws)


@router.get("/remote-sessions", response_model=list[s.SessionOut])
def list_sessions(status: Literal["open", "closed"] | None = None, device_id: uuid.UUID | None = None,
                  limit: int = Query(50, ge=1, le=200), ctx: AuthContext = Depends(READ_ANY),
                  db: Session = Depends(get_db)):
    q = select(RemoteSession).where(RemoteSession.organization_id == ctx.user.organization_id)
    if device_id:
        get_device(db, ctx, device_id)
        q = q.where(RemoteSession.device_id == device_id)
    elif "devices:read" not in ctx.permissions:  # IT support: sessions on endpoints assigned to them
        q = q.join(Device, Device.id == RemoteSession.device_id).where(Device.support_owner_id == ctx.user.id)
    rows = list(db.scalars(q.order_by(RemoteSession.created_at.desc()).limit(limit)))
    for x in rows:
        remote.refresh(db, x)
    db.commit()
    if status == "open":
        rows = [x for x in rows if x.status not in remote.TERMINAL]
    elif status == "closed":
        rows = [x for x in rows if x.status in remote.TERMINAL]
    return [_session_out(db, x) for x in rows]


@router.get("/remote-sessions/{sid}", response_model=s.SessionOut)
def get_session(sid: uuid.UUID, ctx: AuthContext = Depends(READ_ANY), db: Session = Depends(get_db)):
    x = db.get(RemoteSession, sid)
    if x is None or x.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Session not found")
    get_device(db, ctx, x.device_id)  # scope check
    remote.refresh(db, x)
    db.commit()
    return _session_out(db, x)


@router.post("/remote-sessions/{sid}/terminate", response_model=s.SessionOut)
def terminate(sid: uuid.UUID, body: s.TerminateRequest, ctx: AuthContext = Depends(REMOTE),
              db: Session = Depends(get_db)):
    x = db.get(RemoteSession, sid)
    if x is None or x.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Session not found")
    get_device(db, ctx, x.device_id)
    try:
        return _session_out(db, remote.terminate(db, x, body.reason.strip(), ctx.actor))
    except PolicyError as e:
        _raise(e)


@router.get("/settings/remote-assistance", response_model=s.AssistSettings)
def get_settings(ctx: AuthContext = Depends(READ_ANY), db: Session = Depends(get_db)):
    return remote.assist_settings(db, ctx.user.organization_id)


@router.put("/settings/remote-assistance", response_model=s.AssistSettings)
def put_settings(body: s.AssistSettings, ctx: AuthContext = Depends(require_permission("org:settings")),
                 db: Session = Depends(get_db)):
    return remote.update_assist_settings(db, ctx.user.organization_id, body, ctx.actor)
