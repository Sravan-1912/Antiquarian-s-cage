import { useRef, useState, type DragEvent } from 'react'
import { Check, ImageUp, Palette, Trash2 } from 'lucide-react'
import { Button, Card, CardHeader } from '@/components/ui/primitives'
import { THEMES, useTheme, type ThemeDef } from '@/theme/ThemeContext'

function ThemeCard({ def, active, onPick }: { def: ThemeDef; active: boolean; onPick: (e: { x: number; y: number }) => void }) {
  const [canvas, surface, accent, text] = def.swatch
  return (
    <button
      type="button"
      onClick={(e) => onPick({ x: e.clientX, y: e.clientY })}
      className={`group relative overflow-hidden rounded-xl border text-left transition focus:outline-none ${
        active ? 'border-[color:var(--cage-accent)] ring-2 ring-[color:var(--cage-accent)]/40' : 'border-ink-700 hover:border-ink-500'}`}
      aria-pressed={active}
    >
      {/* miniature console preview */}
      <div className="relative h-28 w-full" style={{ background: canvas }}>
        {def.glass && <div className="absolute inset-0" style={{ backdropFilter: 'blur(2px)', background: 'linear-gradient(120deg, rgba(255,255,255,0.06), transparent)' }} />}
        <div className="absolute left-0 top-0 h-full w-10 border-r" style={{ background: surface, borderColor: 'rgba(255,255,255,0.08)' }}>
          <div className="mx-auto mt-2 h-1.5 w-5 rounded" style={{ background: accent }} />
          <div className="mx-auto mt-2 h-1 w-6 rounded" style={{ background: text, opacity: 0.4 }} />
          <div className="mx-auto mt-1.5 h-1 w-6 rounded" style={{ background: text, opacity: 0.25 }} />
        </div>
        <div className="absolute left-14 right-3 top-3 rounded-md border p-2" style={{ background: surface, borderColor: 'rgba(255,255,255,0.1)', boxShadow: def.glass ? 'inset 1px 1px 0 rgba(255,255,255,0.18)' : '0 6px 16px -8px rgba(0,0,0,0.5)' }}>
          <div className="h-1.5 w-12 rounded" style={{ background: text, opacity: 0.8 }} />
          <div className="mt-1.5 flex gap-1">
            <span className="h-2 w-2 rounded-full" style={{ background: '#34d399' }} title="success" />
            <span className="h-2 w-2 rounded-full" style={{ background: '#f59e0b' }} title="warning" />
            <span className="h-2 w-2 rounded-full" style={{ background: '#ef4444' }} title="danger" />
            <span className="h-2 w-2 rounded-full" style={{ background: accent }} title="accent" />
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-ink-800 bg-ink-900 px-3 py-2">
        <span className="truncate text-sm font-medium text-silver-100">{def.name}</span>
        {active && <span className="flex size-5 shrink-0 items-center justify-center rounded-full" style={{ background: accent }}><Check className="size-3 text-black" /></span>}
      </div>
    </button>
  )
}

function Slider({ label, value, min, max, step, suffix, onChange }: { label: string; value: number; min: number; max: number; step: number; suffix?: string; onChange: (v: number) => void }) {
  return (
    <label className="block">
      <div className="mb-1 flex justify-between text-xs text-silver-400"><span>{label}</span><span className="tabular-nums text-silver-500">{value}{suffix}</span></div>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))}
        className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-ink-700 accent-[color:var(--cage-accent)]" />
    </label>
  )
}

function WallpaperStudio() {
  const { wallpaper, setWallpaperCfg, uploadWallpaper, removeWallpaper } = useTheme()
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)

  const take = async (file?: File | null) => {
    if (!file || !file.type.startsWith('image/')) return
    setBusy(true); try { await uploadWallpaper(file) } finally { setBusy(false) }
  }
  const onDrop = (e: DragEvent) => { e.preventDefault(); setDragging(false); void take(e.dataTransfer.files?.[0]) }

  return (
    <Card>
      <CardHeader title="Wallpaper Studio" description="Upload any image for the Liquid Glass surface; tune how the frosted cards sit over it." />
      <div className="space-y-4 p-4">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center transition ${dragging ? 'border-[color:var(--cage-accent)] bg-ink-800' : 'border-ink-600 hover:bg-ink-850'}`}
        >
          <ImageUp className="size-6 text-silver-500" />
          <div className="text-sm text-silver-300">{busy ? 'Loading…' : wallpaper.hasImage ? 'Replace wallpaper — drop an image or click' : 'Drop an image here or click to upload'}</div>
          <div className="text-xs text-silver-600">PNG / JPG / WebP · stored locally in your browser</div>
          <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={(e) => void take(e.target.files?.[0])} />
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <Slider label="Glass blur" value={wallpaper.blur} min={8} max={40} step={1} suffix="px" onChange={(v) => setWallpaperCfg({ blur: v })} />
          <Slider label="Surface tint" value={Math.round(wallpaper.tint * 100)} min={10} max={90} step={1} suffix="%" onChange={(v) => setWallpaperCfg({ tint: v / 100 })} />
          <Slider label="Wallpaper dim" value={Math.round(wallpaper.dim * 100)} min={0} max={85} step={1} suffix="%" onChange={(v) => setWallpaperCfg({ dim: v / 100 })} />
        </div>

        {wallpaper.hasImage && (
          <div className="flex justify-end">
            <Button size="sm" variant="ghost" onClick={() => void removeWallpaper()}><Trash2 />Remove image</Button>
          </div>
        )}
      </div>
    </Card>
  )
}

export function ThemesPage() {
  const { theme, setTheme } = useTheme()
  const groups = ['Signature', 'Design Styles', 'Dark', 'Red & Burgundy', 'Light'] as const
  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex items-center gap-2">
        <Palette className="size-5 text-[color:var(--cage-accent)]" />
        <div>
          <h1 className="text-lg font-semibold text-silver-50">Themes</h1>
          <p className="text-sm text-silver-500">Pick a look for the console — it switches instantly and is remembered on this device.</p>
        </div>
      </div>

      {groups.map((g) => {
        const items = THEMES.filter((t) => t.group === g)
        if (!items.length) return null
        return (
          <section key={g} className="space-y-3">
            <h2 className="text-xs font-semibold uppercase tracking-[0.14em] text-silver-600">{g}</h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((def) => <ThemeCard key={def.id} def={def} active={theme === def.id} onPick={(o) => setTheme(def.id, o)} />)}
            </div>
          </section>
        )
      })}

      {theme === 'custom-wallpaper' && <WallpaperStudio />}
    </div>
  )
}
