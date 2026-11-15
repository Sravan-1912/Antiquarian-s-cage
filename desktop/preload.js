// No privileged bridge is exposed: the console is a plain web app served from the local
// backend and needs nothing from Node. Kept as an explicit, empty, context-isolated preload
// so the renderer stays sandboxed (contextIsolation on, nodeIntegration off).
