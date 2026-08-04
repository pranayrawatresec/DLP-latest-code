// Reusable UI primitives for the console. White theme, indigo accent.
import { AlertIcon } from './Icons'

// --- Button -----------------------------------------------------------
const BTN_VARIANTS = {
  primary: 'bg-indigo-600 text-white hover:bg-indigo-700 focus:ring-indigo-600',
  secondary: 'border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 focus:ring-gray-400',
  danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-600',
  dangerGhost: 'border border-red-200 bg-white text-red-700 hover:bg-red-50 focus:ring-red-400',
  ghost: 'text-gray-600 hover:bg-gray-100 focus:ring-gray-400',
}
export function Button({ variant = 'primary', size = 'md', className = '', children, ...rest }) {
  const sizing = size === 'sm' ? 'px-2.5 py-1.5 text-xs' : 'px-3.5 py-2 text-sm'
  return (
    <button
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 ${BTN_VARIANTS[variant]} ${sizing} ${className}`}
      {...rest}
    >
      {children}
    </button>
  )
}

// --- Badge ------------------------------------------------------------
const BADGE_TONES = {
  green: 'bg-green-50 text-green-700 ring-green-200',
  amber: 'bg-amber-50 text-amber-700 ring-amber-200',
  red: 'bg-red-50 text-red-700 ring-red-200',
  gray: 'bg-gray-100 text-gray-600 ring-gray-200',
  blue: 'bg-blue-50 text-blue-700 ring-blue-200',
  indigo: 'bg-indigo-50 text-indigo-700 ring-indigo-200',
}
export function Badge({ tone = 'gray', className = '', children }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${BADGE_TONES[tone]} ${className}`}
    >
      {children}
    </span>
  )
}

// --- Card -------------------------------------------------------------
export function Card({ className = '', children }) {
  return (
    <div className={`rounded-xl border border-gray-200 bg-white ${className}`}>{children}</div>
  )
}

// --- StatCard ---------------------------------------------------------
export function StatCard({ icon, label, value, hint, loading }) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-gray-500">{label}</span>
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
          {icon}
        </span>
      </div>
      <div className="mt-3 text-2xl font-semibold text-gray-900">
        {loading ? <span className="inline-block h-7 w-12 animate-pulse rounded bg-gray-100" /> : value}
      </div>
      {hint && <div className="mt-1 text-xs text-gray-400">{hint}</div>}
    </Card>
  )
}

// --- PageHeader -------------------------------------------------------
export function PageHeader({ title, description, action }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
        {description && <p className="mt-1 text-sm text-gray-500">{description}</p>}
      </div>
      {action}
    </div>
  )
}

// --- EmptyState -------------------------------------------------------
export function EmptyState({ icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      {icon && (
        <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-gray-100 text-gray-400">
          {icon}
        </div>
      )}
      <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-gray-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

// --- Spinner ----------------------------------------------------------
export function Spinner({ className = 'h-5 w-5' }) {
  return (
    <svg className={`animate-spin text-gray-400 ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 0 1 8-8V0C5.4 0 0 5.4 0 12h4z" />
    </svg>
  )
}

// --- Form fields ------------------------------------------------------
export function Field({ label, hint, children, htmlFor }) {
  return (
    <div className="mb-4">
      <label htmlFor={htmlFor} className="mb-1 block text-sm font-medium text-gray-700">
        {label}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-gray-400">{hint}</p>}
    </div>
  )
}
const FIELD_CLASS =
  'block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-600 focus:outline-none focus:ring-1 focus:ring-indigo-600'
export function Input({ className = '', ...rest }) {
  return <input className={`${FIELD_CLASS} ${className}`} {...rest} />
}
export function Select({ className = '', children, ...rest }) {
  return (
    <select className={`${FIELD_CLASS} ${className}`} {...rest}>
      {children}
    </select>
  )
}

// --- Inline alert -----------------------------------------------------
export function InlineAlert({ tone = 'red', children }) {
  const tones = {
    red: 'border-red-200 bg-red-50 text-red-700',
    amber: 'border-amber-200 bg-amber-50 text-amber-800',
    blue: 'border-blue-200 bg-blue-50 text-blue-800',
  }
  return (
    <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${tones[tone]}`}>
      <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
      <div>{children}</div>
    </div>
  )
}
