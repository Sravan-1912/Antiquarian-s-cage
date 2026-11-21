import * as React from 'react'
import { createPortal } from 'react-dom'
import { Check, ChevronDown } from 'lucide-react'
import { cn } from '@/utils/format'

/**
 * Theme-matched dropdown. Native <select> option popups are OS-painted (only background/text are styleable), so they
 * can never carry a theme's glass/accent/rounding. This renders the list as a styled panel driven by the same
 * CSS-variable surface tokens as the rest of the console (see theme/controls.css: .cage-select-menu), so the dropdown
 * matches every theme — frosted glass on the glass themes, solid surfaces elsewhere.
 *
 * Drop-in for the old native Select: same props (value, onChange(e => e.target.value), <option> children, id,
 * aria-label, className, disabled). The menu portals into the nearest modal dialog (or <body>) with fixed positioning,
 * so it escapes table/card overflow and stays interactive inside Radix dialogs.
 */
interface Opt { value: string; label: React.ReactNode; disabled?: boolean }

function parseOptions(children: React.ReactNode): Opt[] {
  const out: Opt[] = []
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return
    const el = child as React.ReactElement<{ value?: string | number; children?: React.ReactNode; disabled?: boolean }>
    if (el.type === 'option') {
      const p = el.props
      const value = p.value !== undefined ? String(p.value) : String(p.children ?? '')
      out.push({ value, label: p.children ?? value, disabled: p.disabled })
    } else if (el.type === React.Fragment) {
      out.push(...parseOptions(el.props.children))
    }
  })
  return out
}

type Props = Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'ref'> & {
  onChange?: React.ChangeEventHandler<HTMLSelectElement>
}

export const Select = React.forwardRef<HTMLButtonElement, Props>(function Select(
  { className, value, onChange, children, disabled, id, 'aria-label': ariaLabel },
  ref,
) {
  const options = React.useMemo(() => parseOptions(children), [children])
  const current = String(value ?? '')
  const selected = options.find((o) => o.value === current) ?? options[0]
  const [open, setOpen] = React.useState(false)
  const [active, setActive] = React.useState(0)
  const [pos, setPos] = React.useState<{ left: number; top: number; width: number; up: boolean } | null>(null)
  const btnRef = React.useRef<HTMLButtonElement | null>(null)
  const menuRef = React.useRef<HTMLDivElement | null>(null)
  const setBtn = (n: HTMLButtonElement | null) => { btnRef.current = n; if (typeof ref === 'function') ref(n); else if (ref) ref.current = n }

  const place = React.useCallback(() => {
    const r = btnRef.current?.getBoundingClientRect()
    if (!r) return
    const below = window.innerHeight - r.bottom
    const up = below < 260 && r.top > below
    setPos({ left: r.left, top: up ? r.top : r.bottom, width: r.width, up })
  }, [])

  const openMenu = () => {
    if (disabled) return
    place()
    setActive(Math.max(0, options.findIndex((o) => o.value === current)))
    setOpen(true)
  }
  const commit = (v: string) => {
    onChange?.({ target: { value: v }, currentTarget: { value: v } } as unknown as React.ChangeEvent<HTMLSelectElement>)
    setOpen(false)
    btnRef.current?.focus()
  }

  React.useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node) && !btnRef.current?.contains(e.target as Node)) setOpen(false)
    }
    const reflow = () => place()
    document.addEventListener('mousedown', onDoc)
    window.addEventListener('scroll', reflow, true)
    window.addEventListener('resize', reflow)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      window.removeEventListener('scroll', reflow, true)
      window.removeEventListener('resize', reflow)
    }
  }, [open, place])

  const onKey = (e: React.KeyboardEvent) => {
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openMenu() }
      return
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(options.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0) }
    else if (e.key === 'End') { e.preventDefault(); setActive(options.length - 1) }
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); const o = options[active]; if (o && !o.disabled) commit(o.value) }
    else if (e.key === 'Escape') { e.preventDefault(); setOpen(false); btnRef.current?.focus() }
    else if (e.key === 'Tab') setOpen(false)
  }

  const host = (btnRef.current?.closest('[role="dialog"]') as HTMLElement | null) ?? (typeof document !== 'undefined' ? document.body : null)

  return (
    <>
      <button
        type="button" ref={setBtn} id={id} disabled={disabled} aria-haspopup="listbox" aria-expanded={open} aria-label={ariaLabel}
        onClick={() => (open ? setOpen(false) : openMenu())} onKeyDown={onKey}
        className={cn('cage-input cage-select inline-flex h-9 items-center justify-between gap-2 rounded-md px-2.5 text-sm disabled:opacity-50', className)}
      >
        <span className="truncate text-left">{selected ? selected.label : ''}</span>
        <ChevronDown className={cn('size-4 shrink-0 opacity-60 transition-transform', open && 'rotate-180')} />
      </button>
      {open && pos && host && createPortal(
        <div
          ref={menuRef} role="listbox" tabIndex={-1} className="cage-select-menu"
          style={{ position: 'fixed', left: pos.left, width: pos.width, zIndex: 70,
            ...(pos.up ? { bottom: window.innerHeight - pos.top + 4 } : { top: pos.top + 4 }) }}
        >
          {options.map((o, i) => (
            <div
              key={o.value + i} role="option" aria-selected={o.value === current} aria-disabled={o.disabled || undefined}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => { e.preventDefault(); if (!o.disabled) commit(o.value) }}
              className={cn('cage-select-option flex items-center justify-between gap-2 px-2.5 py-1.5 text-sm',
                i === active && 'is-active', o.disabled && 'is-disabled', o.value === current && 'is-selected')}
            >
              <span className="truncate">{o.label}</span>
              {o.value === current && <Check className="size-3.5 shrink-0" />}
            </div>
          ))}
        </div>,
        host,
      )}
    </>
  )
})
