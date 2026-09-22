import { useState, useEffect, useMemo } from 'react'
import { useSelector } from 'react-redux'
import { useGetMlPolicyQuery, useGetMlLabelsQuery, useUpdateMlPolicyMutation } from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import { PageHeader, Card, Button, Spinner, InlineAlert, Input } from '../components/ui/kit'
import Modal from '../components/ui/Modal'

// ML document classification — the console surface over the agent's on-device ONNX
// classifier. Fingerprinting (IDM/EDM) can only recognise a document someone
// registered; the model recognises what a document IS. The two are ORed in the
// agent, so this page never weakens a fingerprint hit — it only adds sensitivity.
//
// The whole screen is one decision: WHICH of the model's 29 frozen business-function
// classes count as sensitive here. 29 checkboxes is a wall, so they are grouped by
// domain, filterable, and each group has select-all/clear; a live count keeps the
// admin oriented. A per-class confidence override is revealed only once a class is
// selected — the common case is "inherit the global floor".
//
// One control on this page is not like the others: "Deny unclassified reads". The
// endpoint's kernel read path cannot afford inference (500 ms budget, one loop for
// the whole machine), so it only LOOKS UP what the model already said about a file.
// This switch decides what a MISS means, and turning it on before the endpoints have
// finished their discovery sweep denies the FIRST read of every legacy file on every
// machine. So it is fenced off in its own red section, off by default, and gated
// behind a confirmation that makes the operator assert the sweep is done.

// The three display groups (the `domain` the labels endpoint returns). Display only:
// the model's own index order is what the agent and the audit entry use.
const GROUPS = [
  {
    key: 'general',
    title: 'General & administration',
    desc: 'Business functions any organisation has — finance, HR, legal, medical, policy.',
  },
  {
    key: 'education',
    title: 'Education',
    desc: 'School/academy record types.',
  },
  {
    key: 'defence',
    title: 'Defence',
    desc: 'Military and national-security functions. Typically the set a defence site marks sensitive.',
  },
]

const ACTIONS = [
  {
    v: 'audit',
    label: 'Audit',
    hint: 'Raise an incident when the model marks a document sensitive, but ALLOW it — measure the model against real traffic before enforcing.',
  },
  {
    v: 'block',
    label: 'Block',
    hint: 'Treat a model hit like a fingerprint hit: stop the copy/write/upload. Only turn this on once the audit feed looks right.',
  },
]

// --- small local controls (mirrors OcrPolicy/ClipboardPolicy) ---------------

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

// --- helpers ----------------------------------------------------------------

// A confidence is a probability in (0,1]. Empty means "inherit the global floor";
// the server rejects 0, which would mark every document of that class sensitive.
function validConfidence(text) {
  const n = Number(text)
  return text !== '' && Number.isFinite(n) && n > 0 && n <= 1
}

// Server label rows -> the form's { id: overrideText } map ('' = inherit).
function labelsToSelection(rows) {
  const sel = {}
  for (const l of rows || []) {
    sel[l.id] = l.minConfidence === null || l.minConfidence === undefined ? '' : String(l.minConfidence)
  }
  return sel
}

// --- page -------------------------------------------------------------------

export default function MlPolicy() {
  const canWrite = useSelector(selectHasPermission('ml_policy:write'))
  const { data: policy, isLoading, isError } = useGetMlPolicyQuery()
  const { data: labels = [], isError: labelsError } = useGetMlLabelsQuery()
  const [updatePolicy, { isLoading: saving }] = useUpdateMlPolicyMutation()

  const [enabled, setEnabled] = useState(false)
  const [minConfidence, setMinConfidence] = useState('0.70')
  const [action, setAction] = useState('audit')
  const [failBlock, setFailBlock] = useState(true)
  const [denyUnclassified, setDenyUnclassified] = useState(false)
  // { labelId: overrideText } — presence in the map IS the selection.
  const [selection, setSelection] = useState({})
  const [filter, setFilter] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  // The confirmation gate for the posture switch. `sweepAck` resets with the modal:
  // an operator must re-assert the sweep every single time they arm this.
  const [confirmDeny, setConfirmDeny] = useState(false)
  const [sweepAck, setSweepAck] = useState(false)

  // Load server state into the form once it arrives.
  useEffect(() => {
    if (policy) {
      setEnabled(policy.enabled ?? false)
      setMinConfidence(String(policy.minConfidence ?? 0.7))
      setAction(policy.action ?? 'audit')
      setFailBlock(policy.failBlock ?? true)
      // A server that predates migration 022 omits the field; read that as OFF.
      setDenyUnclassified(policy.denyUnclassified ?? false)
      setSelection(labelsToSelection(policy.labels))
    }
  }, [policy])

  // Send the selection in the model's own index order — the order the server stores
  // and audits, so an untouched form serialises identically to what it loaded.
  const payloadLabels = useMemo(() => {
    const order = labels.length ? labels.map((l) => l.id) : Object.keys(selection).sort()
    return order
      .filter((id) => id in selection)
      .map((id) => ({ id, minConfidence: selection[id] === '' ? null : Number(selection[id]) }))
  }, [labels, selection])

  const selectedCount = payloadLabels.length
  const globalOk = validConfidence(minConfidence)
  const overridesOk = Object.values(selection).every((v) => v === '' || validConfidence(v))

  const dirty =
    policy &&
    (enabled !== policy.enabled ||
      action !== policy.action ||
      failBlock !== policy.failBlock ||
      denyUnclassified !== (policy.denyUnclassified ?? false) ||
      Number(minConfidence) !== Number(policy.minConfidence) ||
      JSON.stringify(payloadLabels) !==
        JSON.stringify((policy.labels || []).map((l) => ({ id: l.id, minConfidence: l.minConfidence ?? null }))))

  // Groups, filtered. A filter hit on either the class id or its display name, so
  // "FIN" and "finance" both find the same row.
  const needle = filter.trim().toLowerCase()
  const groups = GROUPS.map((g) => ({
    ...g,
    items: labels.filter(
      (l) =>
        l.domain === g.key &&
        (!needle || l.id.toLowerCase().includes(needle) || l.name.toLowerCase().includes(needle))
    ),
  }))

  function toggleLabel(id, on) {
    setSelection((prev) => {
      const next = { ...prev }
      if (on) next[id] = next[id] ?? ''
      else delete next[id]
      return next
    })
  }

  // Select-all / clear act on what is CURRENTLY VISIBLE in that group, so they stay
  // predictable while a filter is applied.
  function setGroup(items, on) {
    setSelection((prev) => {
      const next = { ...prev }
      for (const l of items) {
        if (on) next[l.id] = next[l.id] ?? ''
        else delete next[l.id]
      }
      return next
    })
  }

  function setOverride(id, text) {
    setSelection((prev) => ({ ...prev, [id]: text }))
  }

  // Arming the posture switch goes through the confirmation; DISARMING is immediate.
  // The asymmetry is deliberate — one direction can take an estate offline, the other
  // can only restore today's behaviour, and nothing should stand between an operator
  // and turning a denial storm off.
  function onDenyToggle(next) {
    if (next) {
      setSweepAck(false)
      setConfirmDeny(true)
    } else {
      setDenyUnclassified(false)
    }
  }

  async function save() {
    setError('')
    setSaved(false)
    try {
      // Whole-object PUT — the server replaces the row and the label set together in
      // one transaction. modelVersion is server-owned; it rides along unchanged.
      await updatePolicy({
        enabled,
        minConfidence: Number(minConfidence),
        action,
        failBlock,
        denyUnclassified,
        modelVersion: policy?.modelVersion,
        labels: payloadLabels,
      }).unwrap()
      setSaved(true)
    } catch (e) {
      setError(e?.data?.error || 'Could not save the classification policy.')
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
        title="Classification (ML)"
        description="A second, independent detection signal. Fingerprinting only recognises documents someone registered; the on-device model recognises what a document IS — one of 29 business-function classes — so an unregistered draft of a nuclear or intelligence report is still caught. The two signals are ORed on the endpoint: this can only ADD sensitivity, never clear a fingerprint hit."
      />

      {isError && (
        <div className="mb-4">
          <InlineAlert>Could not load the classification policy. Try reloading the page.</InlineAlert>
        </div>
      )}
      {labelsError && (
        <div className="mb-4">
          <InlineAlert>Could not load the model's class list. The selection below can't be edited until it loads.</InlineAlert>
        </div>
      )}

      <Card>
        <Section
          title="Document classification"
          desc="The classifier runs entirely ON THE ENDPOINT. Document text is tokenised and scored in the agent's own process — no document content, text or extract is ever sent to this server or off the machine. Only the resulting class id, score and counts appear in an incident."
        >
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            disabled={!canWrite}
            label="Classify documents with the on-device model"
            hint="Off = fingerprinting only (unchanged behaviour). On = every scanned document is also classified, and a hit on a class marked below makes it sensitive."
          />
          <p className="mt-3 text-xs text-gray-400">
            Model version{' '}
            <code className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-gray-600">
              {policy?.modelVersion || 'unknown'}
            </code>{' '}
            · 29 classes · runs offline, no network
          </p>
        </Section>

        <Section
          title="Sensitive classes"
          desc="Tick the business functions that are sensitive at this site. A class left unticked is still predicted, but never makes a document sensitive on its own."
        >
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter classes…"
              className="w-64"
            />
            <span className="text-xs font-medium text-gray-500">
              {selectedCount} of {labels.length || 29} classes marked sensitive
            </span>
            {selectedCount > 0 && canWrite && (
              <Button variant="ghost" size="sm" onClick={() => setSelection({})}>
                Clear all
              </Button>
            )}
          </div>

          <div className="space-y-5">
            {groups.map((g) => {
              const allOn = g.items.length > 0 && g.items.every((l) => l.id in selection)
              return (
                <div key={g.key}>
                  <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
                    <div>
                      <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-700">{g.title}</h4>
                      <p className="text-xs text-gray-400">{g.desc}</p>
                    </div>
                    {g.items.length > 0 && canWrite && (
                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="sm" onClick={() => setGroup(g.items, true)} disabled={allOn}>
                          Select all
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setGroup(g.items, false)}
                          disabled={!g.items.some((l) => l.id in selection)}
                        >
                          Clear
                        </Button>
                      </div>
                    )}
                  </div>

                  {g.items.length === 0 ? (
                    <p className="text-xs text-gray-400">No class in this group matches the filter.</p>
                  ) : (
                    <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
                      {g.items.map((l) => {
                        const on = l.id in selection
                        const bad = on && selection[l.id] !== '' && !validConfidence(selection[l.id])
                        return (
                          <div
                            key={l.id}
                            className={`rounded-lg border p-2.5 ${
                              on ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200'
                            }`}
                          >
                            <label className={`flex items-start gap-2 ${canWrite ? 'cursor-pointer' : 'opacity-60'}`}>
                              <input
                                type="checkbox"
                                className="mt-0.5"
                                checked={on}
                                disabled={!canWrite}
                                onChange={(e) => toggleLabel(l.id, e.target.checked)}
                              />
                              <span className="min-w-0 text-sm">
                                <code className="mr-1.5 rounded border border-gray-200 bg-white px-1.5 py-0.5 font-mono text-[11px] text-gray-900">
                                  {l.id}
                                </code>
                                <span className="text-gray-900">{l.name}</span>
                              </span>
                            </label>
                            {on && (
                              <div className="mt-2 flex items-center gap-2 pl-6">
                                <input
                                  type="number"
                                  step="0.05"
                                  min="0.05"
                                  max="1"
                                  value={selection[l.id]}
                                  disabled={!canWrite}
                                  onChange={(e) => setOverride(l.id, e.target.value)}
                                  placeholder={globalOk ? Number(minConfidence).toFixed(2) : '—'}
                                  className={`w-20 rounded-md border px-2 py-1 text-xs text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-indigo-600 ${
                                    bad ? 'border-red-300' : 'border-gray-300'
                                  }`}
                                />
                                <span className="text-[11px] text-gray-500">
                                  {bad ? 'must be > 0 and ≤ 1' : 'threshold — empty inherits the default'}
                                </span>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {enabled && selectedCount === 0 && (
            <div className="mt-4">
              <InlineAlert tone="amber">
                The classifier is on but no class is marked sensitive, so it will never mark anything. Choose at least
                one class.
              </InlineAlert>
            </div>
          )}
        </Section>

        <Section
          title="Confidence threshold"
          desc="The default floor a prediction must reach before the class counts. A per-class override above wins where it is set."
        >
          <div className="flex items-center gap-2">
            <input
              type="number"
              step="0.05"
              min="0.05"
              max="1"
              value={minConfidence}
              disabled={!canWrite}
              onChange={(e) => setMinConfidence(e.target.value)}
              className={`w-24 rounded-lg border px-3 py-2 text-sm text-gray-900 focus:outline-none focus:ring-1 focus:ring-indigo-600 ${
                globalOk ? 'border-gray-300' : 'border-red-300'
              }`}
            />
            {!globalOk && <span className="text-xs text-red-600">Must be greater than 0 and at most 1.</span>}
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Confidence here is a softmax spread across all 29 classes, not a two-way yes/no — a <b>correct</b>{' '}
            prediction very often sits below 90%, and neighbouring classes (e.g. planning vs logistics) legitimately
            split the score. Start near <b>0.70</b> and tune from what the incident feed actually shows; raising this to
            0.95 mostly buys silence, not accuracy.
          </p>
        </Section>

        <Section
          title="Action"
          desc="What a model hit does on an egress channel (USB write, upload, clipboard copy). A fingerprint hit is unaffected — it keeps enforcing whatever its own channel policy says."
        >
          <div className="space-y-2">
            {ACTIONS.map((a) => (
              <label
                key={a.v}
                className={`flex items-start gap-3 rounded-lg border p-3 ${
                  action === a.v ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200'
                } ${canWrite ? 'cursor-pointer' : 'opacity-60'}`}
              >
                <input
                  type="radio"
                  name="ml-action"
                  className="mt-1"
                  checked={action === a.v}
                  disabled={!canWrite}
                  onChange={() => setAction(a.v)}
                />
                <span className="text-sm">
                  <span className="font-medium text-gray-900">{a.label}</span>
                  <span className="block text-gray-500">{a.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </Section>

        <Section
          title="Fail-secure"
          desc="What to do when the model can't produce a verdict — the model file is missing on that endpoint, fails to load, or inference errors."
        >
          <Toggle
            checked={failBlock}
            onChange={setFailBlock}
            disabled={!canWrite}
            label="Block when the model cannot classify a file"
            hint="Recommended for a defence posture: a document we could not classify shouldn't leave the machine. Only acts on egress channels while the action is Block — the synchronous kernel read path never fail-blocks on the model."
          />
        </Section>

        {/* The posture switch. Deliberately NOT a Section: it gets its own red-cased
            block so it can never be mistaken for one of the ordinary toggles above. */}
        <div className="border-t border-gray-100 px-6 py-5">
          <div className="rounded-xl border-2 border-red-200 bg-red-50/60 p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="rounded-md bg-red-600 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-white">
                Enforcement posture
              </span>
              <h3 className="text-sm font-semibold text-red-900">Deny reads of files the model has not classified yet</h3>
            </div>

            <p className="mb-3 text-xs leading-relaxed text-red-900/80">
              The endpoint cannot run the model on the kernel read path — it has a few hundred milliseconds and one
              queue for the whole machine — so it looks each file up in the classifications it already has. Files get
              there three ways: a watcher classifies them as they are written, a background discovery sweep backfills
              what was already on the disk, and anything scanned on its way out is stored as it goes.
              <br />
              <b>With this on, a file that is not yet in that set is DENIED</b> when an exfil-channel process (remote
              desktop, an untrusted reader) tries to read it. The read is retried automatically once the classifier
              catches up, so the block is temporary per file — but on a machine whose{' '}
              <b>discovery sweep has not finished, that is the first read of every existing document on the disk.</b>
            </p>

            <div className="mb-3 rounded-lg border border-red-200 bg-white px-3 py-2 text-xs text-gray-700">
              <span className="font-semibold text-gray-900">Only enable this after</span> the endpoints have completed
              their discovery sweep and you have confirmed coverage. Rollout order: deploy the agent → let the sweep
              finish → verify coverage → enable here.
            </div>

            <Toggle
              checked={denyUnclassified}
              onChange={onDenyToggle}
              disabled={!canWrite}
              label={denyUnclassified ? 'ARMED — unclassified files are denied on exfil channels' : 'Off — unclassified files fall back to fingerprints only (recommended)'}
              hint={
                denyUnclassified
                  ? 'Every read of a file the classifier has not met is refused until it has been classified.'
                  : 'Today\'s behaviour: an unclassified file is judged on IDM/EDM fingerprints alone, and is queued for classification in the background. No new denials.'
              }
            />

            {denyUnclassified && (
              <div className="mt-3">
                <InlineAlert>
                  Armed. This takes effect on each endpoint at its next check-in and applies to every machine, including
                  ones that have only just been deployed.
                </InlineAlert>
              </div>
            )}
            {denyUnclassified && !enabled && (
              <p className="mt-3 text-xs text-red-900/70">
                Classification is currently off above, so this stays inert until the model is enabled.
              </p>
            )}
            {denyUnclassified && enabled && selectedCount === 0 && (
              <p className="mt-3 text-xs text-red-900/70">
                No class is marked sensitive above, so the model is inert and this stays inert with it.
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 px-6 py-4">
          <Button onClick={save} disabled={!canWrite || !dirty || saving || !globalOk || !overridesOk}>
            {saving ? 'Saving…' : 'Save policy'}
          </Button>
          {!canWrite && <span className="text-xs text-gray-500">Read-only — needs a policy author.</span>}
          {saved && !dirty && <span className="text-xs text-green-600">Saved. Endpoints apply it on next check-in.</span>}
          {error && <span className="text-xs text-red-600">{error}</span>}
        </div>
      </Card>

      {/* Arming the posture switch is a two-step, acknowledged action. It still only
          takes effect on Save — this gate is about making the operator state, before
          they see the switch move, that the precondition is actually met. */}
      <Modal
        open={confirmDeny}
        onClose={() => setConfirmDeny(false)}
        title="Deny reads of unclassified files?"
        description="This changes what endpoints do with files the classifier has never seen."
        size="lg"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmDeny(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              disabled={!sweepAck}
              onClick={() => {
                setDenyUnclassified(true)
                setConfirmDeny(false)
              }}
            >
              Arm deny-unclassified
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm text-gray-700">
          <InlineAlert>
            On every endpoint, a read by an exfil-channel process (remote desktop, an untrusted reader) of any file the
            classifier has not yet classified will be <b>denied</b>. If an endpoint's discovery sweep has not completed,
            that is the first read of every document already on its disk.
          </InlineAlert>
          <p>
            Each denied read queues that file for classification, so the next read of it is decided normally — the
            block is temporary per file, not permanent. What is not temporary is the disruption on a machine with a
            large unswept disk, or on an agent deployed after you turned this on.
          </p>
          <label className="flex items-start gap-2 rounded-lg border border-gray-200 p-3">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={sweepAck}
              onChange={(e) => setSweepAck(e.target.checked)}
            />
            <span className="text-sm text-gray-900">
              The endpoints in scope have <b>completed their discovery sweep</b> and I have verified classification
              coverage.
            </span>
          </label>
          <p className="text-xs text-gray-500">
            Nothing changes until you save the policy, and you can turn this off again at any time without a
            confirmation.
          </p>
        </div>
      </Modal>
    </>
  )
}
