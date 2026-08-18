import { useState, useEffect } from 'react'
import { useSelector } from 'react-redux'
import { useGetReadDenyPolicyQuery, useUpdateReadDenyPolicyMutation } from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import { PageHeader, Card, Button, Spinner, InlineAlert, Badge } from '../components/ui/kit'

// --- option metadata --------------------------------------------------------

const MODES = [
  { v: 'off', label: 'Off', tone: 'gray', hint: 'No read protection on endpoints.' },
  {
    v: 'monitor',
    label: 'Monitor',
    tone: 'blue',
    hint: 'Detect and report what it would block, but allow — measure coverage before enforcing.',
  },
  {
    v: 'enforce',
    label: 'Enforce',
    tone: 'green',
    hint: 'Deny untrusted reads of sensitive files for real.',
  },
]

const POSTURES = [
  {
    v: 'blocklist',
    label: 'Blocklist',
    hint: 'Only known remote-access tools / VM workers count as untrusted (unchanged legacy behaviour).',
  },
  {
    v: 'allowlist',
    label: 'Allowlist',
    hint: 'Every process NOT on the Trusted applications list is untrusted (recommended — scales to unknown tools).',
  },
]

const WATCH_PRESETS = [
  { v: '\\Users', label: 'All user files (\\Users)' },
  { v: '\\', label: 'Whole C: drive (\\)' },
]

// --- small controls ---------------------------------------------------------

function Segmented({ value, options, onChange, disabled }) {
  return (
    <div className="inline-flex flex-wrap gap-1 rounded-lg bg-gray-100 p-1">
      {options.map((o) => (
        <button
          key={o.v}
          type="button"
          disabled={disabled}
          onClick={() => onChange(o.v)}
          className={`rounded-md px-3.5 py-1.5 text-sm font-medium transition-colors disabled:opacity-50 ${
            value === o.v
              ? 'bg-white text-indigo-700 shadow-sm ring-1 ring-gray-200'
              : 'text-gray-500 hover:text-gray-700'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

function Toggle({ checked, onChange, disabled, label, hint }) {
  return (
    <label className="flex items-start gap-3 cursor-pointer select-none">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`mt-0.5 relative inline-flex h-5 w-9 flex-none items-center rounded-full transition-colors disabled:opacity-50 ${
          checked ? 'bg-indigo-600' : 'bg-gray-300'
        }`}
      >
        <span
          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
            checked ? 'translate-x-5' : 'translate-x-1'
          }`}
        />
      </button>
      <span>
        <span className="text-sm font-medium text-gray-900">{label}</span>
        {hint && <span className="block text-xs text-gray-500 mt-0.5">{hint}</span>}
      </span>
    </label>
  )
}

function Section({ title, desc, children }) {
  return (
    <div className="py-5 border-b border-gray-100 last:border-b-0">
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        {desc && <p className="text-xs text-gray-500 mt-0.5 max-w-2xl">{desc}</p>}
      </div>
      {children}
    </div>
  )
}

// --- page -------------------------------------------------------------------

export default function ReadDenyPolicy() {
  const canWrite = useSelector(selectHasPermission('read_deny_policy:write'))
  const { data: policy, isLoading, isError } = useGetReadDenyPolicyQuery()
  const [save, { isLoading: saving }] = useUpdateReadDenyPolicyMutation()

  const [form, setForm] = useState(null)
  const [newPath, setNewPath] = useState('')
  const [msg, setMsg] = useState(null) // { kind:'ok'|'err', text }

  useEffect(() => {
    if (policy) setForm({ ...policy, watchPaths: [...(policy.watchPaths || [])] })
  }, [policy])

  if (isLoading || !form) {
    return (
      <>
        <PageHeader title="Read-deny policy" />
        <Card>
          <div className="flex justify-center py-16">{isError ? <InlineAlert>Could not load the policy.</InlineAlert> : <Spinner />}</div>
        </Card>
      </>
    )
  }

  const set = (patch) => {
    setForm((f) => ({ ...f, ...patch }))
    setMsg(null)
  }
  const dirty = policy && JSON.stringify(form) !== JSON.stringify({ ...policy, watchPaths: policy.watchPaths || [] })

  const addPath = (raw) => {
    const p = (raw || '').trim()
    if (!p) return
    if (!form.watchPaths.includes(p)) set({ watchPaths: [...form.watchPaths, p] })
    setNewPath('')
  }
  const removePath = (p) => set({ watchPaths: form.watchPaths.filter((x) => x !== p) })

  async function onSave() {
    setMsg(null)
    try {
      await save({
        mode: form.mode,
        posture: form.posture,
        scanFixed: form.scanFixed,
        watchPaths: form.watchPaths,
        failBlock: form.failBlock,
      }).unwrap()
      setMsg({ kind: 'ok', text: 'Policy saved — endpoints apply it at their next check-in.' })
    } catch (e) {
      setMsg({ kind: 'err', text: e?.data?.error || 'Could not save the policy.' })
    }
  }

  return (
    <>
      <PageHeader
        title="Read-deny policy"
        description="Controls whether endpoints deny untrusted programs the read of sensitive files, and where. Agents apply this to the kernel driver automatically — no command line."
      />

      <Card>
        <div className="px-6">
          <Section
            title="Mode"
            desc="Roll out safely: run Monitor first, review the would-block incidents, add any legitimate apps to Trusted applications, then switch to Enforce."
          >
            <Segmented value={form.mode} options={MODES} onChange={(v) => set({ mode: v })} disabled={!canWrite} />
            <p className="mt-2 text-xs text-gray-500">
              {MODES.find((m) => m.v === form.mode)?.hint}
            </p>
          </Section>

          {form.mode !== 'off' && (
            <>
              <Section
                title="Posture — who counts as untrusted"
                desc="Allowlist is the recommended posture; pair it with a curated Trusted applications list."
              >
                <Segmented
                  value={form.posture}
                  options={POSTURES}
                  onChange={(v) => set({ posture: v })}
                  disabled={!canWrite}
                />
                <p className="mt-2 text-xs text-gray-500">{POSTURES.find((p) => p.v === form.posture)?.hint}</p>
              </Section>

              <Section
                title="Scope — which drives are protected"
                desc="Removable drives (USB) are always protected. Turn this on to also protect folders on the fixed C: drive."
              >
                <Toggle
                  checked={form.scanFixed}
                  onChange={(v) => set({ scanFixed: v })}
                  disabled={!canWrite}
                  label="Protect the fixed drive (C:) under the folders below"
                  hint="Off = removable/USB only."
                />

                {form.scanFixed && (
                  <div className="mt-4 pl-12">
                    <div className="text-xs font-medium text-gray-700 mb-2">Watched folders</div>
                    {form.watchPaths.length === 0 ? (
                      <p className="text-xs text-amber-700 mb-2">
                        Pick at least one folder, or turn off fixed-drive protection.
                      </p>
                    ) : (
                      <ul className="space-y-1.5 mb-3">
                        {form.watchPaths.map((p) => (
                          <li key={p} className="flex items-center gap-2">
                            <code className="font-mono text-xs bg-gray-50 border border-gray-200 rounded px-2 py-1 text-gray-900">
                              {p}
                            </code>
                            {canWrite && (
                              <Button variant="dangerGhost" size="sm" onClick={() => removePath(p)}>
                                Remove
                              </Button>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                    {canWrite && (
                      <>
                        <div className="flex flex-wrap gap-2 mb-2">
                          {WATCH_PRESETS.map((preset) => (
                            <button
                              key={preset.v}
                              type="button"
                              onClick={() => addPath(preset.v)}
                              disabled={form.watchPaths.includes(preset.v)}
                              className="text-xs rounded-md border border-gray-200 px-2.5 py-1 text-gray-600 hover:bg-gray-50 disabled:opacity-40"
                            >
                              + {preset.label}
                            </button>
                          ))}
                        </div>
                        <div className="flex gap-2">
                          <input
                            value={newPath}
                            onChange={(e) => setNewPath(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addPath(newPath))}
                            placeholder="e.g. \Users\finance"
                            className="font-mono text-sm rounded-md border border-gray-300 px-3 py-1.5 w-64 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                          />
                          <Button variant="secondary" size="sm" onClick={() => addPath(newPath)}>
                            Add folder
                          </Button>
                        </div>
                      </>
                    )}
                  </div>
                )}
              </Section>

              <Section
                title="When a file can't be checked"
                desc="If the agent can't verify a file's content (e.g. no fingerprints loaded yet), choose the safe default."
              >
                <Toggle
                  checked={form.failBlock}
                  onChange={(v) => set({ failBlock: v })}
                  disabled={!canWrite}
                  label="Fail secure — block unverifiable reads by untrusted programs"
                  hint="Off = allow and audit (general use). On = block (classified sites)."
                />
              </Section>
            </>
          )}
        </div>

        <div className="flex items-center gap-3 px-6 py-4 border-t border-gray-200 bg-gray-50">
          {canWrite ? (
            <Button onClick={onSave} disabled={!dirty || saving}>
              {saving ? 'Saving…' : 'Save policy'}
            </Button>
          ) : (
            <Badge tone="gray">Read-only — you can't change policy</Badge>
          )}
          {form.mode === 'enforce' && (
            <span className="text-xs text-amber-700">
              Enforce is live — untrusted programs are denied sensitive reads.
            </span>
          )}
          {msg && (
            <span className={`text-sm ${msg.kind === 'ok' ? 'text-green-700' : 'text-red-600'}`}>{msg.text}</span>
          )}
          {policy?.updatedBy && (
            <span className="ml-auto text-xs text-gray-400">last changed by {policy.updatedBy}</span>
          )}
        </div>
      </Card>
    </>
  )
}
