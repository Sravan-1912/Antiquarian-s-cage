/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// In development the SPA and API share one origin through this proxy, so cookies stay SameSite=Strict.
const API_TARGET = process.env.VITE_API_PROXY_TARGET ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  server: {
    port: Number(process.env.VITE_PORT ?? 5173),
    strictPort: true,
    proxy: { '/api': { target: API_TARGET, changeOrigin: false } },
  },
  build: { sourcemap: false, outDir: 'dist' },
  test: { environment: 'jsdom', include: ['src/**/*.test.{ts,tsx}'] },
})
