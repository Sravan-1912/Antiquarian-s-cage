from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api import agent, auth, billing, devices, employees, identity, oidc, operations, phone, remote, secops, security_mgmt, users
from app.core.config import get_settings
from app.core.database import session_factory
from app.core.logging import configure_logging
from app.core.middleware import SecurityHeadersMiddleware
from app.security.command_signing import get_signing_key
from app.security.oidc_keys import get_oidc_key
from app.security.pki import get_ca
from app.services.rbac import sync_rbac

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    with session_factory()() as db:
        sync_rbac(db)
        from app.services.subscriptions import sync_plans
        sync_plans(db)
        db.commit()
    get_ca()  # fail fast if the device CA is missing or the passphrase is wrong
    get_signing_key()  # and the command-signing key
    get_oidc_key()  # and the OIDC token-signing key
    scheduler = None
    if get_settings().scheduler_enabled and get_settings().environment != "test":
        from app.workers.tasks import Scheduler
        scheduler = Scheduler()
        scheduler.start()
    log.info("startup complete", extra={"event": "startup"})
    yield
    if scheduler:
        scheduler.shutdown()


def create_app() -> FastAPI:
    s = get_settings()
    docs = s.expose_api_docs or s.environment == "development"
    app = FastAPI(
        title="Antiquarian's Cage API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
    )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Never echo submitted values (could contain passwords) back to the client.
        errors = [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": "Validation failed", "errors": errors}, status_code=422)

    api = APIRouter(prefix="/api/v1")
    api.include_router(auth.router)
    api.include_router(users.router)
    api.include_router(employees.router)
    api.include_router(secops.router)  # before operations: /notifications/preferences
    api.include_router(operations.router)
    api.include_router(remote.router)  # before devices: its /devices/{id}/actions|assist must win over /{op}
    api.include_router(devices.router)
    api.include_router(security_mgmt.router)
    api.include_router(identity.router)
    api.include_router(oidc.router)
    api.include_router(phone.router)
    api.include_router(billing.router)

    @api.get("/health", tags=["health"])
    def health():
        with session_factory()() as db:
            db.execute(text("select 1"))
        return {"status": "ok"}

    app.include_router(api)
    app.include_router(agent.router)
    return app


app = create_app()
