// Electron shell for Antiquarian's Cage.
//
// Spawns the bundled PyInstaller backend (cage-backend.exe), waits for it to print its
// loopback port, polls /api/v1/health, then opens the console in a BrowserWindow. The
// backend is killed when the app quits. Only one instance may run at a time.

const { app, BrowserWindow, Menu, shell, dialog } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");

let backend = null;
let backendPort = null;
let mainWindow = null;

// --- locate the backend executable -------------------------------------------------------------
function backendExePath() {
  // Packaged: extraResources puts it under <resources>/cage-backend/cage-backend.exe
  const packaged = path.join(process.resourcesPath, "cage-backend", "cage-backend.exe");
  if (fs.existsSync(packaged)) return packaged;
  // Dev: the onedir build sits in the repo at backend/dist/cage-backend/
  const dev = path.join(__dirname, "..", "backend", "dist", "cage-backend", "cage-backend.exe");
  if (fs.existsSync(dev)) return dev;
  return null;
}

// --- backend lifecycle -------------------------------------------------------------------------
function startBackend() {
  return new Promise((resolve, reject) => {
    const exe = backendExePath();
    if (!exe) {
      reject(new Error("Backend executable not found (cage-backend.exe)."));
      return;
    }
    backend = spawn(exe, [], { windowsHide: true });

    let settled = false;
    const onReady = (port) => {
      if (settled) return;
      settled = true;
      backendPort = port;
      resolve(port);
    };

    backend.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      process.stdout.write(`[backend] ${text}`);
      const m = text.match(/CAGE_READY port=(\d+)/);
      if (m) onReady(parseInt(m[1], 10));
    });
    backend.stderr.on("data", (chunk) => process.stderr.write(`[backend] ${chunk}`));
    backend.on("error", (err) => { if (!settled) { settled = true; reject(err); } });
    backend.on("exit", (code) => {
      backend = null;
      if (!settled) { settled = true; reject(new Error(`Backend exited early (code ${code}).`)); }
    });

    // Safety net: don't hang forever if the ready line never arrives.
    setTimeout(() => { if (!settled) { settled = true; reject(new Error("Backend did not start in time.")); } }, 60000);
  });
}

function waitForHealth(port, attempts = 60) {
  return new Promise((resolve, reject) => {
    const tryOnce = (n) => {
      const req = http.get({ host: "127.0.0.1", port, path: "/api/v1/health", timeout: 2000 }, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry(n);
      });
      req.on("error", () => retry(n));
      req.on("timeout", () => { req.destroy(); retry(n); });
    };
    const retry = (n) => {
      if (n <= 0) return reject(new Error("Backend health check never passed."));
      setTimeout(() => tryOnce(n - 1), 500);
    };
    tryOnce(attempts);
  });
}

function stopBackend() {
  if (backend) {
    try { backend.kill(); } catch (_) { /* already gone */ }
    backend = null;
  }
}

// --- window ------------------------------------------------------------------------------------
function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: "Antiquarian's Cage",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  Menu.setApplicationMenu(null);

  // External links (http/https to other origins) open in the system browser, not inside the app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(`http://127.0.0.1:${port}`)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.loadURL(`http://127.0.0.1:${port}/`);
  mainWindow.on("closed", () => { mainWindow = null; });
}

// --- app bootstrap -----------------------------------------------------------------------------
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    try {
      const port = await startBackend();
      await waitForHealth(port);
      createWindow(port);
    } catch (err) {
      dialog.showErrorBox("Antiquarian's Cage", `Could not start the application.\n\n${err.message}`);
      stopBackend();
      app.quit();
    }
  });

  app.on("window-all-closed", () => {
    stopBackend();
    app.quit();
  });

  app.on("before-quit", stopBackend);
  app.on("will-quit", stopBackend);
  process.on("exit", stopBackend);
}
