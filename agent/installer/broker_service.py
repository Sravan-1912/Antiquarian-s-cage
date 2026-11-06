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
        state = BrokerState(DEFAULT_ROOT)
        servicemanager.LogInfoMsg("Antiquarian's Cage broker starting")
        pipe.serve(lambda req: {"pong": True} if req.get("ping") else handle(state, req),
                   [pipe.sid_for("NT SERVICE\\CageAgent")], self.stop)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CageBrokerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CageBrokerService)
