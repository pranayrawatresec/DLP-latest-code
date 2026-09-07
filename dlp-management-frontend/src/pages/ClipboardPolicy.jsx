import { useState, useEffect } from 'react'
import { useSelector } from 'react-redux'
import { useGetClipboardPolicyQuery, useUpdateClipboardPolicyMutation } from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import { PageHeader, Card, Button, Spinner, InlineAlert } from '../components/ui/kit'

// --- option metadata --------------------------------------------------------

const MODES = [
  { v: 'off', label: 'Off', hint: 'No clipboard protection on endpoints.' },
  {
    v: 'monitor',
    label: 'Monitor',
    hint: 'Detect a sensitive copy and raise an incident, but ALLOW the paste — measure before enforcing.',
  },
  {
    v: 'enforce',
    label: 'Enforce',
    hint: 'BLOCK — clear the clipboard on a sensitive copy so the paste yields nothing.',
  },
]

// --- small local controls (mirrors ReadDenyPolicy.jsx) ----------------------

function Toggle({ checked, onChange, disabled, label, hint }) {
  return (
    <label className={`flex items-start gap-3 ${disabled ? 'opacity-50' : 'cursor-pointer'}`}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={`mt-0.5 h-5 w-9 flex-shrink-0 rounded-full transition-colors ${
          checked ? 'bg-indigo-600' : 'bg-gray-300'
        }`}
      >
        <span
          className={`block h-4 w-4 rounded-full bg-white shadow transform transition-transform ${
            checked ? 'translate-x-4' : 'translate-x-0.5'
          }`}
        />
      </button>
      <span className="text-sm">
        <span className="font-medium text-gray-900">{label}</span>
        {hint && <span className="block text-gray-500">{hint}</span>}
      </span>
    </label>
  )
}

function Section({ title, desc, children }) {
  return (
    <div className="border-t border-gray-100 px-6 py-5 first:border-t-0">
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        {desc && <p className="text-xs text-gray-500">{desc}</p>}
      </div>
      {children}
    </div>
  )
}

// --- page -------------------------------------------------------------------

export default function ClipboardPolicy() {
  const canWrite = useSelector(selectHasPermission('clipboard_policy:write'))
  const { data: policy, isLoading, isError } = useGetClipboardPolicyQuery()
  const [updatePolicy, { isLoading: saving }] = useUpdateClipboardPolicyMutation()

  const [mode, setMode] = useState('off')
  const [blockImages, setBlockImages] = useState(false)
  const [failBlock, setFailBlock] = useState(true)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  // Load server state into the form once it arrives.
  useEffect(() => {
    if (policy) {
      setMode(policy.mode ?? 'off')
      setBlockImages(policy.blockImages ?? false)
      setFailBlock(policy.failBlock ?? true)
    }
  }, [policy])

  const dirty =
    policy &&
    (mode !== policy.mode ||
      blockImages !== policy.blockImages ||
      failBlock !== policy.failBlock)

  async function save() {
    setError('')
    setSaved(false)
    try {
      await updatePolicy({ mode, blockImages, failBlock }).unwrap()
      setSaved(true)
    } catch (e) {
      setError(e?.data?.error || 'Could not save the clipboard policy.')
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner />
      </div>
    )
  }

  return (
    <>
      <PageHeader
        title="Clipboard policy"
        description="Stops sensitive content copied to the clipboard from being pasted elsewhere. The DLPAgent service runs a per-session monitor that classifies each copy against the protected-content index; in Enforce it clears the clipboard so the paste yields nothing. A blocked copy is reported as an incident (never the copied content itself)."
      />

      {isError && (
        <div className="mb-4">
          <InlineAlert>Could not load the clipboard policy. Try reloading the page.</InlineAlert>
        </div>
      )}

      <Card>
        <Section
          title="Mode"
          desc="Roll out with Monitor to measure, then switch to Enforce to block. Model: a sensitive copy is blocked regardless of where it would be pasted."
        >
          <div className="space-y-2">
            {MODES.map((m) => (
              <label
                key={m.v}
                className={`flex items-start gap-3 rounded-lg border p-3 ${
                  mode === m.v ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200'
                } ${canWrite ? 'cursor-pointer' : 'opacity-60'}`}
              >
                <input
                  type="radio"
                  name="clip-mode"
                  className="mt-1"
                  checked={mode === m.v}
                  disabled={!canWrite}
                  onChange={() => setMode(m.v)}
                />
                <span className="text-sm">
                  <span className="font-medium text-gray-900">{m.label}</span>
                  <span className="block text-gray-500">{m.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </Section>

        <Section
          title="Images"
          desc="Bitmap/image clipboard data (e.g. a screenshot of a document) can't be content-inspected without OCR."
        >
          <Toggle
            checked={blockImages}
            onChange={setBlockImages}
            disabled={!canWrite}
            label="Block images wholesale"
            hint="When on, any image on the clipboard is blocked in Enforce mode (all-or-nothing, since images can't be scored). When off, images are allowed (a screenshot is a partial hole)."
          />
        </Section>

        <Section
          title="Fail-secure"
          desc="What to do when a verdict can't be produced — e.g. the protected-content index isn't loaded yet, or classification fails."
        >
          <Toggle
            checked={failBlock}
            onChange={setFailBlock}
            disabled={!canWrite}
            label="Block when a verdict can't be produced"
            hint="Recommended for a defence posture: fail closed rather than let a copy through un-inspected. Only applies in Enforce mode."
          />
        </Section>

        <div className="flex items-center gap-3 px-6 py-4">
          <Button onClick={save} disabled={!canWrite || !dirty || saving}>
            {saving ? 'Saving…' : 'Save policy'}
          </Button>
          {!canWrite && <span className="text-xs text-gray-500">Read-only — needs a policy author.</span>}
          {saved && !dirty && <span className="text-xs text-green-600">Saved. Endpoints apply it on next check-in.</span>}
          {error && <span className="text-xs text-red-600">{error}</span>}
        </div>
      </Card>
    </>
  )
}
