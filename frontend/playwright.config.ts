import { defineConfig } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// End-to-end suite against an isolated stack: a throwaway API (fresh SQLite DB, fresh keys) on :8100 and a Vite dev
// server on :5174 proxying to it. The developer's own database and .env are never touched.
// Uses the installed Microsoft Edge (channel 'msedge'), so no browser download is needed.
const API_PORT = 8100
const WEB_PORT = 5174
const STATE = path.resolve(__dirname, '.e2e-state')
const PY = process.env.E2E_PYTHON ?? path.resolve(__dirname, '..', 'backend', '.venv', 'Scripts', 'python.exe')

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1, // one shared backend; tests build on the organisation created by the first
  timeout: 60_000,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: {
    baseURL: `http://localhost:${WEB_PORT}`,
    channel: 'msedge',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: `"${PY}" e2e/run_api.py ${API_PORT} "${STATE}"`,
      url: `http://127.0.0.1:${API_PORT}/api/v1/health`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: { E2E_BASE_URL: `http://localhost:${WEB_PORT}` },
    },
    {
      command: 'npx vite',
      url: `http://localhost:${WEB_PORT}`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: { VITE_PORT: String(WEB_PORT), VITE_API_PROXY_TARGET: `http://127.0.0.1:${API_PORT}` },
    },
  ],
})

export const E2E_STATE = STATE
