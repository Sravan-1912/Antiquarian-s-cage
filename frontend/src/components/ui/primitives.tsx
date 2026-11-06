/* shadcn/ui-style primitives, adapted to the Antiquarian's Cage palette. */
import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { Loader2 } from 'lucide-react'
import { cn } from '@/utils/format'

export const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors ' +
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 focus-visible:ring-offset-0 ' +
    'disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'bg-emerald-600 text-white hover:bg-emerald-500',
        secondary: 'bg-ink-700 text-silver-100 hover:bg-ink-600 border border-ink-600',
        ghost: 'text-silver-400 hover:bg-ink-700 hover:text-silver-100',
        outline: 'border border-ink-600 text-silver-200 hover:bg-ink-700',
        danger: 'bg-red-600/90 text-white hover:bg-red-500',
      },
      size: { sm: 'h-8 px-3 text-xs', md: 'h-9 px-4', lg: 'h-10 px-5', icon: 'h-9 w-9' },
    },
    defaultVariants: { variant: 'primary', size: 'md' },
  },
)

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  asChild?: boolean
  loading?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild, loading, children, disabled, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return (
      <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} disabled={disabled || loading} {...props}>
        {asChild ? children : (<>{loading && <Loader2 className="animate-spin" />}{children}</>)}
      </Comp>
    )
  },
)
Button.displayName = 'Button'

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'flex h-9 w-full rounded-md border border-ink-600 bg-ink-900 px-3 text-sm text-silver-100 placeholder:text-silver-600',
        'focus:border-emerald-600/70 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 disabled:opacity-50',
        className,
      )}
      {...props}
    />
  ),
)
Input.displayName = 'Input'

export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        'h-9 rounded-md border border-ink-600 bg-ink-900 px-2.5 text-sm text-silver-100',
        'focus:border-emerald-600/70 focus:outline-none focus:ring-2 focus:ring-emerald-500/20',
        className,
      )}
      {...props}
    />
  ),
)
Select.displayName = 'Select'

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn('mb-1.5 block text-xs font-medium text-silver-400', className)} {...props} />
}

export function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint && <p className="mt-1 text-xs text-silver-600">{hint}</p>}
    </div>
  )
}

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-lg border border-ink-700 bg-ink-900', className)} {...props} />
}

export function CardHeader({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-ink-700 px-4 py-3">
      <div>
        <h3 className="text-sm font-medium text-silver-100">{title}</h3>
        {description && <p className="mt-0.5 text-xs text-silver-500">{description}</p>}
      </div>
      {action}
    </div>
  )
}

const tones = {
  neutral: 'bg-ink-700 text-silver-200 border-ink-600',
  success: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  warning: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
  danger: 'bg-red-500/10 text-red-300 border-red-500/25',
  info: 'bg-sky-500/10 text-sky-300 border-sky-500/25',
}

export function Badge({ tone = 'neutral', className, ...props }: React.HTMLAttributes<HTMLSpanElement> & { tone?: keyof typeof tones }) {
  return (
    <span
      className={cn('inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium leading-none', tones[tone], className)}
      {...props}
    />
  )
}

export function statusTone(status: string): keyof typeof tones {
  switch (status) {
    case 'active': case 'success': case 'compliant': return 'success'
    case 'suspended': case 'pending': case 'invited': case 'failure': return 'warning'
    case 'offboarded': case 'disabled': case 'denied': return 'danger'
    default: return 'neutral'
  }
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('size-4 animate-spin text-silver-500', className)} />
}

export function Alert({ tone = 'danger', children }: { tone?: 'danger' | 'success' | 'info' | 'warning'; children: React.ReactNode }) {
  const t = { danger: 'border-red-500/30 bg-red-500/5 text-red-200', success: 'border-emerald-500/30 bg-emerald-500/5 text-emerald-200',
    info: 'border-sky-500/30 bg-sky-500/5 text-sky-200', warning: 'border-amber-500/30 bg-amber-500/5 text-amber-200' }[tone]
  return <div role="alert" className={cn('rounded-md border px-3 py-2 text-sm', t)}>{children}</div>
}

export function EmptyState({ icon: Icon, title, description, action }: {
  icon: React.ComponentType<{ className?: string }>; title: string; description?: string; action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 rounded-full border border-ink-600 bg-ink-800 p-2.5"><Icon className="size-5 text-silver-500" /></div>
      <p className="text-sm font-medium text-silver-200">{title}</p>
      {description && <p className="mt-1 max-w-sm text-xs text-silver-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-silver-50">{title}</h1>
        {description && <p className="mt-0.5 text-sm text-silver-500">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Table({ children }: { children: React.ReactNode }) {
  return <div className="overflow-x-auto"><table className="w-full text-left text-sm">{children}</table></div>
}
export function Th({ children, className }: { children?: React.ReactNode; className?: string }) {
  return <th className={cn('border-b border-ink-700 px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-silver-500', className)}>{children}</th>
}
export function Td({ children, className, ...rest }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn('border-b border-ink-800 px-4 py-2.5 align-middle text-silver-200', className)} {...rest}>{children}</td>
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="flex items-center justify-between px-4 py-2.5 text-xs text-silver-500">
      <span>{total === 0 ? 'No results' : `${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}`}</span>
      <div className="flex gap-1.5">
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</Button>
        <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  )
}
