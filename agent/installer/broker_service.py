"""CageBroker Windows service (runs as LocalSystem — the only elevated component). Install from an elevated prompt:

    cage-broker-service.exe --startup auto install
    cage-broker.exe pin --agent-config "%ProgramData%\\AntiquariansCage\\config.json"
    icacls "%ProgramData%\\AntiquariansCage\\broker" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F
    sc.exe start CageBroker

The pipe admits SYSTEM, Administrators and NT SERVICE\\CageAgent only. NOT YET VERIFIED as an installed service —
see documentation/test-log.md.
"""
from __future__ import annotations

import logging
import sys
import threading

import servicemanager
import win32service
import win32serviceutil

from cage_broker import pipe
from cage_broker.__main__ import DEFAULT_ROOT
from cage_broker.core import BrokerState, handle


class CageBrokerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CageBroker"
    _svc_display_name_ = "Antiquarian's Cage Privileged Broker"
    _svc_description_ = "Applies server-signed, allowlisted endpoint policies on behalf of the Antiquarian's Cage agent."

    def __init__(self, args):
        super().__init__(args)
        self.stop = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop.set()
        pipe.wake()

    def SvcDoRun(self):
        DEFAULT_ROOT.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(filename=str(DEFAULT_ROOT / "broker.log"), level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        log = logging.getLogger("cage_broker.service")
        try:
            state = BrokerState(DEFAULT_ROOT)
            servicemanager.LogInfoMsg("Antiquarian's Cage broker starting")
            # The pipe already admits SYSTEM + Administrators, which covers the elevated agent task. Optionally also
            # admit an "NT SERVICE\CageAgent" service account when one exists — but never let an unresolvable account
            # crash the broker (the agent normally runs as an elevated scheduled task, not that service).
            extra_sids = []
            try:
                extra_sids.append(pipe.sid_for("NT SERVICE\\CageAgent"))
            except Exception as exc:  # noqa: BLE001
                log.warning("CageAgent service SID not resolvable (%s); relying on SYSTEM + Administrators ACEs", exc)
            pipe.serve(lambda req: {"pong": True} if req.get("ping") else handle(state, req), extra_sids, self.stop)
        except Exception:  # noqa: BLE001 — log the real cause instead of a silent "Stopped" service
            log.exception("broker service crashed during startup")
            servicemanager.LogErrorMsg("Antiquarian's Cage broker crashed on start; see broker.log")
            raise


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CageBrokerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CageBrokerService)
