import { useEffect, useRef, useState } from 'react'

/**
 * Boot splash: a hacker-green matrix of 0/1 that resolves into the Antiquarian's Cage logo + wordmark, with an
 * "AI Pulse & Gradient Orb" loading animation. Plays once per page load (module flag guards StrictMode double-mount).
 */
const GREEN = '#00ff66'

export function StartupLoader() {
  const [show, setShow] = useState(true)
  const [phase, setPhase] = useState<'rain' | 'reveal' | 'out'>('rain')
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const timers: number[] = []
    if (reduce) {
      setPhase('reveal')
      timers.push(window.setTimeout(() => setPhase('out'), 700))
      timers.push(window.setTimeout(() => setShow(false), 1100))
    } else {
      timers.push(window.setTimeout(() => setPhase('reveal'), 1250))
      timers.push(window.setTimeout(() => setPhase('out'), 2650))
      timers.push(window.setTimeout(() => setShow(false), 3150))
    }
    return () => timers.forEach(clearTimeout)
  }, [])

  // Matrix rain of 0/1 in phosphor green.
  useEffect(() => {
    if (!show) return
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    let raf = 0
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const resize = () => { canvas.width = window.innerWidth * dpr; canvas.height = window.innerHeight * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0) }
    resize()
    window.addEventListener('resize', resize)
    const fontSize = 16
    const columns = Math.ceil(window.innerWidth / fontSize)
    const drops = Array.from({ length: columns }, () => Math.random() * -40)
    const draw = () => {
      ctx.fillStyle = 'rgba(0,0,0,0.12)'
      ctx.fillRect(0, 0, window.innerWidth, window.innerHeight)
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`
      for (let i = 0; i < drops.length; i++) {
        const ch = Math.random() > 0.5 ? '1' : '0'
        const x = i * fontSize
        const y = drops[i] * fontSize
        ctx.fillStyle = Math.random() > 0.96 ? '#c6ffda' : GREEN
        ctx.fillText(ch, x, y)
        if (y > window.innerHeight && Math.random() > 0.975) drops[i] = Math.random() * -20
        drops[i] += 0.6
      }
      raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  }, [show])

  if (!show) return null

  return (
    <div className={`cage-splash ${phase === 'out' ? 'cage-splash-out' : ''}`} role="status" aria-label="Loading Antiquarian's Cage" aria-live="polite">
      <canvas ref={canvasRef} className={`cage-splash-rain ${phase !== 'rain' ? 'cage-splash-rain-dim' : ''}`} />
      <div className={`cage-splash-stage ${phase === 'rain' ? 'cage-splash-stage-hidden' : ''}`}>
        {/* AI Pulse & Gradient Orb */}
        <div className="cage-orb" aria-hidden>
          <span className="cage-orb-core" />
          <span className="cage-orb-ring" />
          <span className="cage-orb-ring cage-orb-ring-2" />
        </div>
        {/* Logo mark */}
        <svg className="cage-splash-mark" viewBox="0 0 64 64" width="56" height="56" aria-hidden>
          <defs>
            <linearGradient id="cageMark" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#8affc1" /><stop offset="1" stopColor={GREEN} />
            </linearGradient>
          </defs>
          <path d="M32 3 55 13V31C55 46 45 56 32 61 19 56 9 46 9 31V13L32 3Z" fill="none" stroke="url(#cageMark)" strokeWidth="2.5" />
          <g stroke="url(#cageMark)" strokeWidth="2" strokeLinecap="round">
            <line x1="23" y1="22" x2="23" y2="44" /><line x1="32" y1="19" x2="32" y2="47" /><line x1="41" y1="22" x2="41" y2="44" />
          </g>
          <circle cx="32" cy="33" r="5.5" fill="url(#cageMark)" />
        </svg>
        <div className="cage-splash-word">ANTIQUARIAN'S CAGE</div>
        <div className="cage-splash-sub">SECURE ENDPOINT CONTROL</div>
        <div className="cage-splash-bar"><span /></div>
      </div>
    </div>
  )
}
