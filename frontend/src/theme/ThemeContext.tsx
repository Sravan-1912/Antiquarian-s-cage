import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

export type ThemeId =
  | 'liquid-glass' | 'custom-wallpaper' | 'obsidian' | 'tokyo-night' | 'catppuccin-mocha' | 'cyberpunk'
  | 'nordic' | 'dracula' | 'gruvbox' | 'alabaster'
  | 'velvet-burgundy' | 'crimson-glass' | 'cabernet-noir' | 'scarlet-ops' | 'garnet-champagne'

export interface ThemeDef {
  id: ThemeId
  name: string
  group: 'Signature' | 'Dark' | 'Light' | 'Red & Burgundy'
  /** [canvas, surface, accent, text] for the live preview card. */
  swatch: [string, string, string, string]
  glass?: boolean
  light?: boolean
}

export const THEMES: ThemeDef[] = [
  { id: 'liquid-glass', name: 'Liquid Glass', group: 'Signature', glass: true, swatch: ['#0a0d16', 'rgba(36,42,66,0.6)', '#7aa2ff', '#d2daf0'] },
  { id: 'custom-wallpaper', name: 'Liquid Glass — Wallpaper', group: 'Signature', glass: true, swatch: ['#15131c', 'rgba(60,60,80,0.5)', '#8ab4ff', '#dbe2f0'] },
  { id: 'obsidian', name: 'Antiquarian Obsidian', group: 'Dark', swatch: ['#000000', '#09090b', '#f5c87a', '#e4e4e7'] },
  { id: 'tokyo-night', name: 'Tokyo Night', group: 'Dark', swatch: ['#1a1b26', '#24283b', '#7dcfff', '#c0caf5'] },
  { id: 'catppuccin-mocha', name: 'Catppuccin Mocha', group: 'Dark', swatch: ['#1e1e2e', '#313244', '#cba6f7', '#cdd6f4'] },
  { id: 'cyberpunk', name: 'Cyberpunk Neon Noir', group: 'Dark', swatch: ['#0b0716', '#160e2c', '#00f0ff', '#e0d3ff'] },
  { id: 'nordic', name: 'Nordic Frost', group: 'Dark', swatch: ['#2e3440', '#3b4252', '#88c0d0', '#e5e9f0'] },
  { id: 'dracula', name: 'Dracula Pro', group: 'Dark', swatch: ['#282a36', '#343746', '#bd93f9', '#f8f8f2'] },
  { id: 'gruvbox', name: 'Gruvbox Warm Dark', group: 'Dark', swatch: ['#282828', '#3c3836', '#fabd2f', '#ebdbb2'] },
  { id: 'alabaster', name: 'Alabaster Daylight', group: 'Light', light: true, swatch: ['#f8f9fb', '#ffffff', '#4f46e5', '#1a2234'] },
  { id: 'velvet-burgundy', name: 'Velvet Burgundy', group: 'Red & Burgundy', swatch: ['#140609', '#240b11', '#d4af7a', '#f7ede8'] },
  { id: 'crimson-glass', name: 'Crimson Liquid Glass', group: 'Red & Burgundy', glass: true, swatch: ['#0d0407', 'rgba(56,16,28,0.6)', '#fb7185', '#f6d3da'] },
  { id: 'cabernet-noir', name: 'Cabernet Noir', group: 'Red & Burgundy', swatch: ['#120e14', '#1f131a', '#a32938', '#e3c9cd'] },
  { id: 'scarlet-ops', name: 'Scarlet Ops', group: 'Red & Burgundy', swatch: ['#08080a', '#121216', '#ef233c', '#e3e3e8'] },
  { id: 'garnet-champagne', name: 'Garnet & Champagne', group: 'Light', light: true, swatch: ['#fbf7f4', '#ffffff', '#7a1626', '#26181a'] },
]

export const DEFAULT_THEME: ThemeId = 'liquid-glass'
const KEY = 'cage-theme'
const WP_KEY = 'cage-wallpaper-cfg'

export interface WallpaperCfg { blur: number; tint: number; dim: number; hasImage: boolean }
const DEFAULT_WP: WallpaperCfg = { blur: 24, tint: 0.55, dim: 0.35, hasImage: false }

// --- tiny IndexedDB store for the (large) wallpaper image, so it never hits localStorage quota ---
function idb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open('cage-theme', 1)
    r.onupgradeneeded = () => r.result.createObjectStore('wallpaper')
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}
async function wpPut(blob: Blob) { const db = await idb(); await new Promise((res, rej) => { const t = db.transaction('wallpaper', 'readwrite'); t.objectStore('wallpaper').put(blob, 'img'); t.oncomplete = () => res(null); t.onerror = () => rej(t.error) }) }
async function wpGet(): Promise<Blob | null> { try { const db = await idb(); return await new Promise((res) => { const g = db.transaction('wallpaper', 'readonly').objectStore('wallpaper').get('img'); g.onsuccess = () => res((g.result as Blob) ?? null); g.onerror = () => res(null) }) } catch { return null } }
async function wpDel() { try { const db = await idb(); db.transaction('wallpaper', 'readwrite').objectStore('wallpaper').delete('img') } catch { /* ignore */ } }

function readTheme(): ThemeId {
  try { const v = localStorage.getItem(KEY) as ThemeId | null; return v && THEMES.some((t) => t.id === v) ? v : DEFAULT_THEME } catch { return DEFAULT_THEME }
}
function readWp(): WallpaperCfg { try { return { ...DEFAULT_WP, ...JSON.parse(localStorage.getItem(WP_KEY) || '{}') } } catch { return DEFAULT_WP } }

function applyWpVars(cfg: WallpaperCfg) {
  const r = document.documentElement.style
  r.setProperty('--cage-wallpaper-blur', `${cfg.blur}px`)
  r.setProperty('--cage-glass-tint', `rgba(18,19,22,${cfg.tint})`)
  r.setProperty('--cage-wallpaper-dim', String(cfg.dim))
}

let currentWpUrl: string | null = null
async function loadWallpaperImage() {
  const blob = await wpGet()
  if (currentWpUrl) { URL.revokeObjectURL(currentWpUrl); currentWpUrl = null }
  if (blob) { currentWpUrl = URL.createObjectURL(blob); document.documentElement.style.setProperty('--cage-wallpaper', `url("${currentWpUrl}")`) }
  else document.documentElement.style.setProperty('--cage-wallpaper', 'none')
}

interface Ctx {
  theme: ThemeId
  setTheme: (id: ThemeId, origin?: { x: number; y: number }) => void
  wallpaper: WallpaperCfg
  setWallpaperCfg: (patch: Partial<WallpaperCfg>) => void
  uploadWallpaper: (file: File) => Promise<void>
  removeWallpaper: () => Promise<void>
}
const ThemeCtx = createContext<Ctx | null>(null)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(readTheme)
  const [wallpaper, setWallpaper] = useState<WallpaperCfg>(readWp)

  useEffect(() => { document.documentElement.dataset.theme = theme }, [theme])
  useEffect(() => { applyWpVars(wallpaper); loadWallpaperImage() }, [])

  const setTheme = useCallback((id: ThemeId, origin?: { x: number; y: number }) => {
    const root = document.documentElement
    if (origin) { root.style.setProperty('--cage-x', `${origin.x}px`); root.style.setProperty('--cage-y', `${origin.y}px`) }
    try { localStorage.setItem(KEY, id) } catch { /* ignore */ }
    const commit = () => setThemeState(id)
    const vt = (document as unknown as { startViewTransition?: (cb: () => void) => void }).startViewTransition
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (vt && !reduce) vt.call(document, commit)
    else commit()
  }, [])

  const setWallpaperCfg = useCallback((patch: Partial<WallpaperCfg>) => {
    setWallpaper((prev) => { const next = { ...prev, ...patch }; applyWpVars(next); try { localStorage.setItem(WP_KEY, JSON.stringify(next)) } catch { /* ignore */ } return next })
  }, [])
  const uploadWallpaper = useCallback(async (file: File) => { await wpPut(file); await loadWallpaperImage(); setWallpaperCfg({ hasImage: true }) }, [setWallpaperCfg])
  const removeWallpaper = useCallback(async () => { await wpDel(); await loadWallpaperImage(); setWallpaperCfg({ hasImage: false }) }, [setWallpaperCfg])

  const value = useMemo<Ctx>(() => ({ theme, setTheme, wallpaper, setWallpaperCfg, uploadWallpaper, removeWallpaper }),
    [theme, setTheme, wallpaper, setWallpaperCfg, uploadWallpaper, removeWallpaper])
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>
}

export function useTheme() {
  const c = useContext(ThemeCtx)
  if (!c) throw new Error('useTheme must be used within ThemeProvider')
  return c
}
