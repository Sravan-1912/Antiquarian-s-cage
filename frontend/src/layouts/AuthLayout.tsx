import type { ReactNode } from 'react'
import { Wordmark } from '@/components/Logo'

export function AuthLayout({ title, subtitle, children, footer }: {
  title: string
  subtitle?: string
  children: ReactNode
  footer?: ReactNode
}) {
  return (
    <div className="grid min-h-full lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <aside className="relative hidden overflow-hidden border-r border-ink-700 bg-ink-950 lg:flex lg:flex-col lg:justify-between lg:p-10">
        <Wordmark />
        <div className="max-w-md">
          <p className="text-2xl font-semibold leading-snug tracking-tight text-silver-50">
            Every endpoint accounted for.<br />Every privileged action on record.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-silver-500">
            Endpoint administration, workforce identity and security operations — governed by least privilege
            and a tamper-evident audit trail.
          </p>
        </div>
        <div className="text-xs text-silver-600">Authorised personnel only. Activity on this console is recorded.</div>
        <svg className="pointer-events-none absolute -right-24 top-1/4 h-[420px] w-[420px] opacity-[0.05]" viewBox="0 0 32 32" aria-hidden>
          <path d="M7.5 26.5V15.8C7.5 11.1 11.3 7.9 16 7.9s8.5 3.2 8.5 7.9v10.7M11.8 26.5V11.4M16 26.5V8.2M20.2 26.5V11.4M7.5 18.5h17" fill="none" stroke="#c7c9cc" strokeWidth=".6" />
        </svg>
      </aside>
      <main className="flex items-center justify-center px-5 py-10">
        <div className="w-full max-w-sm animate-fade-in">
          <div className="mb-8 lg:hidden"><Wordmark /></div>
          <h1 className="text-xl font-semibold tracking-tight text-silver-50">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-silver-500">{subtitle}</p>}
          <div className="mt-6">{children}</div>
          {footer && <div className="mt-6 text-sm text-silver-500">{footer}</div>}
        </div>
      </main>
    </div>
  )
}
