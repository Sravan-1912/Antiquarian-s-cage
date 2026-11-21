// Minimal, context-isolated bridge. The renderer stays sandboxed (contextIsolation on, nodeIntegration off); the
// only privileged capability exposed is starting a local RDP tunnel to the backend relay, which the console calls
// after it has authenticated and minted a one-time operator token.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("cageRdp", {
  available: true,
  // info: { sessionId, token, tunnelPath } → opens a local tunnel + launches mstsc; resolves to { port }.
  connect: (info) => ipcRenderer.invoke("cage-rdp-connect", info),
});
