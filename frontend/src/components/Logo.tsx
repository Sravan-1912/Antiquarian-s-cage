/** Original Antiquarian's Cage mark: an arched cage over an emerald foundation line. */
export function LogoMark({ className = 'size-7' }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M16 4.5a1.6 1.6 0 1 1 0 3.2 1.6 1.6 0 0 1 0-3.2Z" fill="#34d399" />
      <path d="M7.5 26.5V15.8C7.5 11.1 11.3 7.9 16 7.9s8.5 3.2 8.5 7.9v10.7" fill="none" stroke="#c7c9cc" strokeWidth="1.8" strokeLinecap="round" />
      <path d="M11.8 26.5V11.4M16 26.5V8.2M20.2 26.5V11.4" stroke="#c7c9cc" strokeWidth="1.4" strokeLinecap="round" opacity=".55" />
      <path d="M5.5 26.5h21" stroke="#34d399" strokeWidth="2" strokeLinecap="round" />
      <path d="M7.5 18.5h17" stroke="#c7c9cc" strokeWidth="1.2" opacity=".55" />
    </svg>
  )
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
