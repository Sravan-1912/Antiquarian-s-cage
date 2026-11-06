"""Windows service wrapper (pywin32). Install from an elevated prompt:

    cage-agent-service.exe --startup auto install      (PyInstaller build)
    python installer\\service.py --startup auto install (development)

The service is configured to run as the virtual account NT SERVICE\\CageAgent (least privilege), not LocalSystem:
    sc.exe config CageAgent obj= "NT SERVICE\\CageAgent"
Grant that account access to the data directory and enrol with --service-account "NT SERVICE\\CageAgent".
Privileged policy enforcement (Phase 3) will live in a separate broker service with its own allowlist.
"""
from __future__ import annotations

import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

from cage_agent.core import agent, configuration
from cage_agent.core.configuration import AgentPaths


class CageAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CageAgent"
    _svc_display_name_ = "Antiquarian's Cage Agent"
    _svc_description_ = "Reports endpoint inventory and health to the Antiquarian's Cage console."

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_flag = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_flag.set()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        paths = AgentPaths(configuration.DEFAULT_DATA_DIR)
        agent.setup_logging(paths)
        servicemanager.LogInfoMsg("Antiquarian's Cage agent starting")
        try:
            agent.Agent(paths, stop=self.stop_flag).run()
        except Exception as exc:  # surfaced in the Windows event log, not swallowed
            servicemanager.LogErrorMsg(f"Antiquarian's Cage agent failed: {exc}")
            raise


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CageAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CageAgentService)
