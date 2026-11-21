import { useLayoutEffect, useState } from 'react'
import { useTheme } from './ThemeContext'

/**
 * Theme-driven chart palette. Every chart (pie/donut/bar/line/area) reads its colors from CSS variables scoped to
 * [data-theme], so switching theme re-colors all visualizations with zero hardcoded hex. recharts needs JS color
 * strings (not var(...)), so this hook snapshots the computed variables and re-reads them whenever the theme changes.
 */
export interface ChartPalette {
  /** Categorical series colors (chart-1..6). */
  series: string[]
  grid: string
  axis: string
  text: string
  /** Slice/bar outline + geometry (neobrutalism = thick black; most themes = none). */
  stroke: string
  strokeWidth: number
  /** Empty-ring track. */
  track: string
  tooltip: { bg: string; border: string; text: string; label: string }
  /** Status hues — preserve green=good / red=bad semantics, tuned per theme. */
  ok: string
  bad: string
  warn: string
  info: string
  neutral: string
  muted: string
  crit: string
  high: string
}

const FALLBACK: ChartPalette = {
  series: ['#34d399', '#38bdf8', '#a78bfa', '#f59e0b', '#94a3b8', '#f472b6'],
  grid: '#202327', axis: '#5f646b', text: '#d8dbde', stroke: 'none', strokeWidth: 0, track: '#202327',
  tooltip: { bg: '#0d0e10', border: '#2b2f34', text: '#d8dbde', label: '#9a9ea4' },
  ok: '#10b981', bad: '#ef4444', warn: '#f59e0b', info: '#38bdf8', neutral: '#64748b', muted: '#5f646b',
  crit: '#dc2626', high: '#f97316',
}

function readPalette(): ChartPalette {
  if (typeof window === 'undefined') return FALLBACK
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string, fb: string) => {
    const raw = cs.getPropertyValue(name).trim()
    return raw || fb
  }
  const sw = parseFloat(v('--chart-stroke-width', '0'))
  return {
    series: [
      v('--chart-1', FALLBACK.series[0]), v('--chart-2', FALLBACK.series[1]), v('--chart-3', FALLBACK.series[2]),
      v('--chart-4', FALLBACK.series[3]), v('--chart-5', FALLBACK.series[4]), v('--chart-6', FALLBACK.series[5]),
    ],
    grid: v('--chart-grid', FALLBACK.grid),
    axis: v('--chart-axis', FALLBACK.axis),
    text: v('--chart-text', FALLBACK.text),
    stroke: v('--chart-stroke', FALLBACK.stroke),
    strokeWidth: Number.isFinite(sw) ? sw : 0,
    track: v('--chart-track', FALLBACK.track),
    tooltip: {
      bg: v('--chart-tooltip-bg', FALLBACK.tooltip.bg),
      border: v('--chart-tooltip-border', FALLBACK.tooltip.border),
      text: v('--chart-tooltip-text', FALLBACK.tooltip.text),
      label: v('--chart-tooltip-label', FALLBACK.tooltip.label),
    },
    ok: v('--chart-ok', FALLBACK.ok), bad: v('--chart-bad', FALLBACK.bad), warn: v('--chart-warn', FALLBACK.warn),
    info: v('--chart-info', FALLBACK.info), neutral: v('--chart-neutral', FALLBACK.neutral), muted: v('--chart-muted', FALLBACK.muted),
    crit: v('--chart-crit', FALLBACK.crit), high: v('--chart-high', FALLBACK.high),
  }
}

export function useChartPalette(): ChartPalette {
  const { theme } = useTheme()
  const [palette, setPalette] = useState<ChartPalette>(() => readPalette())
  useLayoutEffect(() => {
    // data-theme is applied in a sibling passive effect; defer a frame so computed styles reflect the new theme.
    const id = requestAnimationFrame(() => setPalette(readPalette()))
    return () => cancelAnimationFrame(id)
  }, [theme])
  return palette
}

/** Shared recharts helpers built from a palette — keeps axis/tooltip/grid styling identical across every chart. */
export function chartAxis(p: ChartPalette) {
  return { stroke: p.axis, fontSize: 11, tickLine: false, axisLine: false } as const
}
export function chartTooltip(p: ChartPalette) {
  return {
    contentStyle: { background: p.tooltip.bg, border: `1px solid ${p.tooltip.border}`, borderRadius: 6, fontSize: 12, color: p.tooltip.text },
    labelStyle: { color: p.tooltip.label },
    cursor: { fill: 'rgba(255,255,255,0.03)' },
  }
}
