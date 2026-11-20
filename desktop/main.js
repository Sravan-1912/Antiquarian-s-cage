// Electron shell for Antiquarian's Cage.
//
// Spawns the bundled PyInstaller backend (cage-backend.exe), waits for it to print its
// loopback port, polls /api/v1/health, then opens the console in a BrowserWindow. The
// backend is killed when the app quits. Only one instance may run at a time.

const { app, BrowserWindow, Menu, shell, dialog, ipcMain } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const net = require("net");
const path = require("path");
const fs = require("fs");
const WebSocket = require("ws");

let backend = null;
let backendPort = null;
let mainWindow = null;
let appOrigin = null;  // the backend origin the console is loaded from (loopback or a remote/cloud backend)

// --- End-to-end encryption (zero-knowledge relay), operator/initiator side -------------------------
// Mirrors agent/cage_agent/remote/e2e.py byte-for-byte: X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305,
// the endpoint's ephemeral key authenticated by its device key (ECDSA P-256). The backend relay only moves ciphertext.
const crypto = require("crypto");
const E2E_MAGIC = Buffer.from("CAGEE2E1");
const E2E_PROTO = Buffer.from("cage-rdp-e2e-v1");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex"); // DER SPKI header for an X25519 public key

function x25519Raw(pub) { const der = pub.export({ type: "spki", format: "der" }); return der.subarray(der.length - 32); }
function importX25519(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}
function e2eInitiate() { const kp = crypto.generateKeyPairSync("x25519"); return { priv: kp.privateKey, epk: x25519Raw(kp.publicKey) }; }
function e2eComplete(state, epkO, auth, endpointPubPem) {
  const epkE = auth.subarray(0, 32);
  const sigLen = auth.readUInt16BE(32);
  const sig = auth.subarray(34, 34 + sigLen);
  const msg = Buffer.concat([E2E_PROTO, epkO, epkE]);
  if (!crypto.verify("sha256", msg, { key: endpointPubPem, dsaEncoding: "der" }, sig))
    throw new Error("endpoint device signature invalid — possible relay MITM");
  const shared = crypto.diffieHellman({ privateKey: state.priv, publicKey: importX25519(epkE) });
  const okm = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.concat([epkO, epkE]), E2E_PROTO, 64));
  return { kSend: okm.subarray(0, 32), kRecv: okm.subarray(32, 64), sendCtr: 0, recvCtr: 0 }; // operator: send k_i2r, recv k_r2i
}
function e2eNonce(ctr) { const b = Buffer.alloc(12); b.writeBigUInt64BE(BigInt(ctr), 4); return b; }
function e2eSeal(s, pt) {
  const c = crypto.createCipheriv("chacha20-poly1305", s.kSend, e2eNonce(s.sendCtr++), { authTagLength: 16 });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function e2eOpen(s, frame) {
  const d = crypto.createDecipheriv("chacha20-poly1305", s.kRecv, e2eNonce(s.recvCtr++), { authTagLength: 16 });
  d.setAuthTag(frame.subarray(frame.length - 16));
  return Buffer.concat([d.update(frame.subarray(0, frame.length - 16)), d.final()]);
}

// --- RDP relay: tunnel a local mstsc connection out to the backend relay --------------------------
// mstsc → 127.0.0.1:<localPort> (this listener) → WebSocket to <origin>/api/v1/rdp/tunnel → backend relay → endpoint.
// Works across any network: both ends dial out, so no inbound firewall rule is needed anywhere. When the endpoint's
// device public key is known, the stream is end-to-end encrypted (the relay sees only ciphertext).
function startRdpTunnel({ sessionId, token, tunnelPath, endpointPublicKey }) {
  return new Promise((resolve, reject) => {
    const wsBase = appOrigin.replace(/^http/, "ws").replace(/\/$/, "");
    const wsUrl = `${wsBase}${tunnelPath}?session=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(token)}`;
    const server = net.createServer((socket) => {
      const ws = new WebSocket(wsUrl);
      ws.binaryType = "nodebuffer";
      const e2e = !!endpointPublicKey;
      const queue = [];
      let wsOpen = false, sess = null, hs = null, epkO = null, hsDone = !e2e;
      const flush = () => { for (const d of queue) sendUp(d); queue.length = 0; };
      const sendUp = (d) => { if (ws.readyState === WebSocket.OPEN) ws.send(sess ? e2eSeal(sess, d) : d); else queue.push(d); };
      ws.on("open", () => {
        wsOpen = true;
        if (e2e) { hs = e2eInitiate(); epkO = hs.epk; ws.send(Buffer.concat([E2E_MAGIC, epkO])); }  // HELLO (unencrypted)
        else flush();
      });
      ws.on("message", (d) => {
        if (e2e && !hsDone) {
          try { sess = e2eComplete(hs, epkO, d, endpointPublicKey); } catch (err) { socket.destroy(); try { ws.close(); } catch (_) {} return; }
          hsDone = true; flush(); return;
        }
        socket.write(sess ? e2eOpen(sess, d) : d);
      });
      ws.on("close", () => socket.destroy());
      ws.on("error", () => socket.destroy());
      socket.on("data", (d) => { if (wsOpen && hsDone) sendUp(d); else queue.push(d); });
      socket.on("close", () => { try { ws.close(); } catch (_) {} server.close(); });
      socket.on("error", () => { try { ws.close(); } catch (_) {} });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      // Launch the system Remote Desktop client at the local end of the tunnel.
      try { spawn("mstsc", [`/v:127.0.0.1:${port}`], { detached: true, stdio: "ignore" }).unref(); }
      catch (err) { server.close(); reject(err); return; }
      // Close the listener if nothing connects shortly (mstsc failed to launch / was cancelled).
      setTimeout(() => { if (!server._connected) { try { server.close(); } catch (_) {} } }, 60000);
      server.on("connection", () => { server._connected = true; });
      resolve({ port });
    });
  });
}

ipcMain.handle("cage-rdp-connect", async (_e, info) => startRdpTunnel(info));

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
function createWindow(origin) {
  appOrigin = origin;
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
    if (!url.startsWith(origin)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.loadURL(`${origin}/`);
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
      // Remote-backend mode: attach to a shared/cloud backend (so endpoints on other networks are reachable and
      // RDP relays through it) instead of spawning the bundled local backend.
      const remote = (process.env.CAGE_REMOTE_BACKEND_URL || "").trim().replace(/\/$/, "");
      if (remote) {
        createWindow(remote);
      } else {
        const port = await startBackend();
        await waitForHealth(port);
        createWindow(`http://127.0.0.1:${port}`);
      }
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
