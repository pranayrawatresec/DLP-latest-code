// Small date/time helpers (no dependency — keep the bundle lean).
export function relativeTime(iso) {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  const diff = Date.now() - then
  const abs = Math.abs(diff)
  const dir = diff >= 0 ? 'ago' : 'from now'
  const unit = (n, u) => `${n} ${u}${n === 1 ? '' : 's'} ${dir}`
  if (abs < 60_000) return 'just now'
  const mins = Math.round(abs / 60_000)
  if (mins < 60) return unit(mins, 'minute')
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return unit(hrs, 'hour')
  const days = Math.round(hrs / 24)
  if (days < 30) return unit(days, 'day')
  const months = Math.round(days / 30)
  if (months < 12) return unit(months, 'month')
  return unit(Math.round(months / 12), 'year')
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}
