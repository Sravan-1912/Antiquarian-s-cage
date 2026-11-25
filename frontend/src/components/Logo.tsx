import brandLogo from '@/assets/brand-logo.png'

/** Antiquarian's Cage brand emblem (transparent background, sits on any surface). */
export function LogoMark({ className = 'size-7' }: { className?: string }) {
  return <img src={brandLogo} alt="" aria-hidden="true" className={className} draggable={false} />
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <LogoMark />
      {!compact && (
        <div className="leading-none">
          <div className="text-[13px] font-semibold tracking-[0.18em] text-silver-50">ANTIQUARIAN'S</div>
          <div className="mt-0.5 text-[10px] font-medium tracking-[0.42em] text-emerald-400/90">CAGE</div>
        </div>
      )}
    </div>
  )
}
