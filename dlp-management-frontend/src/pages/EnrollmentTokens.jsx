import { useState } from 'react'
import {
  useGetEnrollmentTokensQuery,
  useCreateEnrollmentTokenMutation,
  useRevokeEnrollmentTokenMutation,
} from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, Field, Input, Select, InlineAlert } from '../components/ui/kit'
import { KeyIcon, PlusIcon, CopyIcon, CheckIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

const STATUS_TONE = { active: 'green', expired: 'amber', exhausted: 'gray', revoked: 'red' }
const EXPIRY_OPTIONS = [
  { label: '24 hours', hours: 24 },
  { label: '3 days', hours: 72 },
  { label: '7 days', hours: 168 },
  { label: '14 days', hours: 336 },
  { label: '30 days', hours: 720 },
]

export default function EnrollmentTokens() {
  const { data: tokens = [], isLoading } = useGetEnrollmentTokensQuery()
  const [createToken, { isLoading: creating }] = useCreateEnrollmentTokenMutation()
  const [revokeToken] = useRevokeEnrollmentTokenMutation()

  const [showCreate, setShowCreate] = useState(false)
  const [created, setCreated] = useState(null) // the once-visible token result
  const [revoking, setRevoking] = useState(null) // token pending revoke confirm

  return (
    <>
      <PageHeader
        title="Enrollment tokens"
        description="One-time secrets that let a new PC join the deployment. Give a token to IT to embed in the agent installer."
        action={
          <Button onClick={() => setShowCreate(true)}>
            <PlusIcon className="h-4 w-4" /> Create token
          </Button>
        }
      />

      <div className="mb-5">
        <InlineAlert tone="blue">
          A token is spent when an agent enrolls. Set <b>Max uses</b> to the number of PCs in a rollout wave, and a
          short expiry so a leaked token dies on its own. Each enrolled PC still gets its own unique certificate.
        </InlineAlert>
      </div>

      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : tokens.length === 0 ? (
          <EmptyState
            icon={<KeyIcon className="h-6 w-6" />}
            title="No enrollment tokens yet"
            description="Create one to start deploying the agent to your PCs."
            action={<Button onClick={() => setShowCreate(true)}><PlusIcon className="h-4 w-4" /> Create token</Button>}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Description</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Uses</th>
                  <th className="px-4 py-3 font-medium">Expires</th>
                  <th className="px-4 py-3 font-medium">Created by</th>
                  <th className="px-4 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {tokens.map((t) => (
                  <tr key={t.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-gray-900">{t.description || <span className="text-gray-400">—</span>}</td>
                    <td className="px-4 py-3">
                      <Badge tone={STATUS_TONE[t.status]}>{t.status}</Badge>
                    </td>
                    <td className="px-4 py-3 text-gray-600">
                      {t.useCount} / {t.maxUses}
                      <span className="ml-1 text-xs text-gray-400">({t.remaining} left)</span>
                    </td>
                    <td className="px-4 py-3 text-gray-600" title={formatDateTime(t.expiresAt)}>
                      {relativeTime(t.expiresAt)}
                    </td>
                    <td className="px-4 py-3 text-gray-600">{t.createdBy}</td>
                    <td className="px-4 py-3 text-right">
                      {t.status === 'active' && (
                        <Button variant="dangerGhost" size="sm" onClick={() => setRevoking(t)}>
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showCreate && (
        <CreateTokenModal
          creating={creating}
          onClose={() => setShowCreate(false)}
          onCreate={async (payload) => {
            const result = await createToken(payload).unwrap()
            setShowCreate(false)
            setCreated(result)
          }}
        />
      )}

      {created && <RevealTokenModal token={created} onClose={() => setCreated(null)} />}

      {revoking && (
        <Modal
          open
          onClose={() => setRevoking(null)}
          title="Revoke this token?"
          description="Agents that already enrolled keep working. No new PC will be able to use this token."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRevoking(null)}>Cancel</Button>
              <Button
                variant="danger"
                onClick={async () => {
                  await revokeToken(revoking.id)
                  setRevoking(null)
                }}
              >
                Revoke token
              </Button>
            </>
          }
        >
          <p className="text-sm text-gray-600">
            {revoking.description ? <b>{revoking.description}</b> : 'This token'} — {revoking.remaining} use(s) remaining.
          </p>
        </Modal>
      )}
    </>
  )
}

function CreateTokenModal({ onClose, onCreate, creating }) {
  const [description, setDescription] = useState('')
  const [maxUses, setMaxUses] = useState(1)
  const [hours, setHours] = useState(72)
  const [error, setError] = useState(null)

  async function submit() {
    setError(null)
    try {
      await onCreate({ description, maxUses: Number(maxUses), expiresInHours: Number(hours) })
    } catch (e) {
      setError(e?.data?.error || 'Could not create token')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Create enrollment token"
      description="This produces a one-time secret for the agent installer."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={creating}>{creating ? 'Creating…' : 'Create token'}</Button>
        </>
      }
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}
      <Field label="Description" htmlFor="tok-desc" hint="e.g. “Finance dept rollout — wave 1”">
        <Input id="tok-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What is this token for?" />
      </Field>
      <Field label="Max uses" htmlFor="tok-uses" hint="One use per PC. Set to the number of machines in this rollout wave.">
        <Input id="tok-uses" type="number" min="1" value={maxUses} onChange={(e) => setMaxUses(e.target.value)} />
      </Field>
      <Field label="Expires in" htmlFor="tok-exp" hint="A short window limits the damage of a leaked token.">
        <Select id="tok-exp" value={hours} onChange={(e) => setHours(e.target.value)}>
          {EXPIRY_OPTIONS.map((o) => (
            <option key={o.hours} value={o.hours}>{o.label}</option>
          ))}
        </Select>
      </Field>
    </Modal>
  )
}

function RevealTokenModal({ token, onClose }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(token.token)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard blocked — user can select manually */
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title="Token created — copy it now"
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="mb-4">
        <InlineAlert tone="amber">
          This is the only time the token is shown. Store it now — it cannot be retrieved again.
        </InlineAlert>
      </div>

      <label className="mb-1 block text-sm font-medium text-gray-700">Enrollment token</label>
      <div className="flex items-stretch gap-2">
        <code className="flex-1 overflow-x-auto rounded-lg border border-gray-300 bg-gray-50 px-3 py-2 font-mono text-sm text-gray-900">
          {token.token}
        </code>
        <Button variant="secondary" onClick={copy} className="shrink-0">
          {copied ? <><CheckIcon className="h-4 w-4 text-green-600" /> Copied</> : <><CopyIcon className="h-4 w-4" /> Copy</>}
        </Button>
      </div>

      <div className="mt-5 rounded-lg border border-gray-200 bg-gray-50 p-4">
        <div className="text-sm font-semibold text-gray-900">How to deploy</div>
        <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-gray-600">
          <li>Give this token to IT to embed in the agent installer (as the <code className="rounded bg-white px-1 py-0.5 text-xs">TOKEN</code> property), along with the server address.</li>
          <li>Deploy the installer to PCs via Group Policy / SCCM / Intune — in staged rings, not all at once.</li>
          <li>Each PC enrolls once and appears on the <b>Agents</b> page. Valid for <b>{token.maxUses}</b> install(s).</li>
        </ol>
      </div>
    </Modal>
  )
}
