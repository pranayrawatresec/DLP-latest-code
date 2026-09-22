import { useState, useEffect } from 'react'
import { useSelector } from 'react-redux'
import { useGetOcrPolicyQuery, useUpdateOcrPolicyMutation } from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import { PageHeader, Card, Button, Spinner, InlineAlert } from '../components/ui/kit'

// Local toggle (mirrors ReadDenyPolicy/ClipboardPolicy).
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

export default function OcrPolicy() {
  const canWrite = useSelector(selectHasPermission('ocr_policy:write'))
  const { data: policy, isLoading, isError } = useGetOcrPolicyQuery()
  const [updatePolicy, { isLoading: saving }] = useUpdateOcrPolicyMutation()

  const [enabled, setEnabled] = useState(false)
  const [failBlock, setFailBlock] = useState(true)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (policy) {
      setEnabled(policy.enabled ?? false)
      setFailBlock(policy.failBlock ?? true)
    }
  }, [policy])

  const dirty = policy && (enabled !== policy.enabled || failBlock !== policy.failBlock)

  async function save() {
    setError('')
    setSaved(false)
    try {
      // maxPixels is left at the server default; expose it later if a site needs to tune cost.
      await updatePolicy({ enabled, failBlock, maxPixels: policy?.maxPixels }).unwrap()
      setSaved(true)
    } catch (e) {
      setError(e?.data?.error || 'Could not save the OCR policy.')
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
        title="OCR / image inspection"
        description="When on, an image (a pasted screenshot, an image file, a scanned/text-less PDF) is read with the endpoint's built-in OCR and scored against the protected-content index — so a screenshot of a classified document is caught too. Honored across every channel: clipboard, USB, read-deny (incl. RDP), and browser upload. Uses the offline OS OCR engine (no third-party model, no network). OCR is CPU-heavy, so it is opt-in."
      />

      {isError && (
        <div className="mb-4">
          <InlineAlert>Could not load the OCR policy. Try reloading the page.</InlineAlert>
        </div>
      )}

      <Card>
        <Section
          title="Image inspection (OCR)"
          desc="Turn OCR on to inspect image content across all channels. On the synchronous read-deny path (incl. RDP) an image can't be OCR'd within the kernel's budget, so an image read by an untrusted process is blocked outright when OCR is on."
        >
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            disabled={!canWrite}
            label="Inspect images with OCR"
            hint="Off = images are handled by each channel's existing image rule (e.g. the clipboard 'block images' toggle). On = images are OCR'd and scored like text."
          />
        </Section>

        <Section
          title="Fail-secure"
          desc="What to do when an image can't be OCR'd or inspected (no OCR language pack, over the size cap, or the read-deny budget)."
        >
          <Toggle
            checked={failBlock}
            onChange={setFailBlock}
            disabled={!canWrite}
            label="Block images that can't be inspected"
            hint="Recommended for a defence posture: an image we can't read shouldn't leave the machine. Only acts where the channel is enforcing."
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
