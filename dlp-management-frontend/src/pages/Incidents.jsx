import { useState } from 'react'
import { useSelector } from 'react-redux'
import {
  useGetIncidentsQuery,
  useGetIncidentQuery,
  useUpdateIncidentStatusMutation,
} from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import {
  Card,
  PageHeader,
  Button,
  Badge,
  EmptyState,
  Spinner,
  Input,
  Select,
  Field,
  InlineAlert,
} from '../components/ui/kit'
import { AlertIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

// --- presentation helpers ---------------------------------------------------

const CHANNELS = {
  usb: 'USB / removable',
  'usb-kguard': 'USB (kernel)',
  clipboard: 'Clipboard',
  'web-upload': 'Web upload',
  network: 'Network',
}
const channelLabel = (c) => CHANNELS[c] || c || '—'

function actionBadge(action) {
  const tone = action === 'blocked' ? 'red' : action === 'read_only' ? 'amber' : 'gray'
  return <Badge tone={tone}>{action || 'audited'}</Badge>
}

const STATUS_TONES = { new: 'blue', reviewing: 'amber', resolved: 'green', false_positive: 'gray' }
const STATUS_LABELS = {
  new: 'New',
  reviewing: 'Reviewing',
  resolved: 'Resolved',
  false_positive: 'False positive',
}
function statusBadge(status) {
  return <Badge tone={STATUS_TONES[status] || 'gray'}>{STATUS_LABELS[status] || status}</Badge>
}

function detectionBadge(type) {
  if (!type) return <span className="text-gray-300">—</span>
  return <Badge tone="indigo">{type.toUpperCase()}</Badge>
}

const pct = (n) => (typeof n === 'number' ? `${Math.round(n * 100)}%` : '—')

// --- detail + triage modal --------------------------------------------------

function IncidentDetail({ id, onClose }) {
  const { data: inc, isFetching, isError, error } = useGetIncidentQuery(id)
  const [updateStatus, { isLoading: saving }] = useUpdateIncidentStatusMutation()
  const [status, setStatus] = useState('')
  const [note, setNote] = useState('')
  const [saveErr, setSaveErr] = useState('')

  // Seed the triage form once the incident loads.
  const currentStatus = inc?.status || 'new'
  const effectiveStatus = status || currentStatus

  const onSave = async () => {
    setSaveErr('')
    try {
      await updateStatus({ id, status: effectiveStatus, note: note || undefined }).unwrap()
      onClose()
    } catch (e) {
      setSaveErr(e?.data?.error || 'Could not update status.')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={inc?.reference || 'Incident'}
      description={inc ? `${channelLabel(inc.channel)} · ${formatDateTime(inc.reported_at)}` : ''}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button onClick={onSave} disabled={saving || isFetching}>
            {saving ? 'Saving…' : 'Save triage'}
          </Button>
        </>
      }
    >
      {isFetching ? (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      ) : isError ? (
        <InlineAlert tone="red">
          {error?.status === 403
            ? 'Your role can see the incident list but not the match detail.'
            : 'Could not load this incident.'}
        </InlineAlert>
      ) : (
        <div className="space-y-5">
          {/* Facts grid */}
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <Detail label="File">{inc.file_name || <Muted>—</Muted>}</Detail>
            <Detail label="Action">{actionBadge(inc.action_taken)}</Detail>
            <Detail label="Endpoint">{inc.hostname || <Muted>{inc.agent_id}</Muted>}</Detail>
            <Detail label="User">{inc.os_user || <Muted>unknown</Muted>}</Detail>
            <Detail label="Detection">{detectionBadge(inc.detection_type)}</Detail>
            <Detail label="Status">{statusBadge(inc.status)}</Detail>
            <Detail label="SHA-256" full>
              <code className="break-all font-mono text-xs text-gray-500">
                {inc.file_sha256 || '—'}
              </code>
            </Detail>
          </div>

          {/* Matched protected material (resolved server-side, audited) */}
          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
              Matched protected material
            </h4>
            {renderMatches(inc.resolved)}
          </div>

          {/* Triage */}
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-4">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-gray-500">
              Triage
            </h4>
            {inc.status_by && (
              <p className="mb-3 text-xs text-gray-500">
                Last set to <b>{STATUS_LABELS[inc.status] || inc.status}</b> by {inc.status_by}
                {inc.status_at ? ` · ${relativeTime(inc.status_at)}` : ''}
                {inc.status_note ? ` — “${inc.status_note}”` : ''}
              </p>
            )}
            <div className="flex flex-wrap items-end gap-3">
              <div className="w-52">
                <Field label="Set status">
                  <Select value={effectiveStatus} onChange={(e) => setStatus(e.target.value)}>
                    {Object.entries(STATUS_LABELS).map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </Select>
                </Field>
              </div>
              <div className="flex-1 min-w-[12rem]">
                <Field label="Note (optional)">
                  <Input
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="Reason / disposition…"
                  />
                </Field>
              </div>
            </div>
            {saveErr && (
              <div className="mt-2">
                <InlineAlert tone="red">{saveErr}</InlineAlert>
              </div>
            )}
          </div>
        </div>
      )}
    </Modal>
  )
}

function renderMatches(resolved) {
  const idm = Array.isArray(resolved?.idm) ? resolved.idm : []
  const edm = Array.isArray(resolved?.edm) ? resolved.edm : []
  if (idm.length === 0 && edm.length === 0) {
    return <p className="text-sm text-gray-400">No resolved match detail.</p>
  }
  return (
    <div className="space-y-2">
      {idm.map((m, i) =>
        m.error ? (
          <div key={`idm-${i}`} className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
            IDM match to a version that could not be resolved ({m.error}).
          </div>
        ) : (
          <div key={`idm-${i}`} className="rounded-lg border border-gray-200 px-3 py-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="font-medium text-gray-900">{m.title || 'Protected document'}</span>
              <Badge tone="indigo">IDM · {pct(m.containment)} seen</Badge>
            </div>
            {Array.isArray(m.seqRanges) && m.seqRanges.length > 0 && (
              <div className="mt-1 font-mono text-xs text-gray-500">
                matched ranges:{' '}
                {m.seqRanges.map((r) => `${r[0]}–${r[1]}`).join(', ')}
              </div>
            )}
          </div>
        )
      )}
      {edm.map((m, i) => (
        <div key={`edm-${i}`} className="rounded-lg border border-gray-200 px-3 py-2 text-sm">
          <div className="flex items-center justify-between">
            <span className="font-medium text-gray-900">Exact-data record</span>
            <Badge tone="indigo">EDM · row {m.rowId}</Badge>
          </div>
          {Array.isArray(m.fieldIds) && m.fieldIds.length > 0 && (
            <div className="mt-1 font-mono text-xs text-gray-500">fields: {m.fieldIds.join(', ')}</div>
          )}
        </div>
      ))}
    </div>
  )
}

function Detail({ label, children, full }) {
  return (
    <div className={full ? 'col-span-2' : ''}>
      <div className="text-xs font-medium text-gray-400">{label}</div>
      <div className="mt-0.5 text-gray-900">{children}</div>
    </div>
  )
}
const Muted = ({ children }) => <span className="text-gray-300">{children}</span>

// --- page -------------------------------------------------------------------

export default function Incidents() {
  const canReadDetail = useSelector(selectHasPermission('incidents.read'))
  const [channel, setChannel] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [limit, setLimit] = useState(100)
  const [openId, setOpenId] = useState(null)

  const params = { limit }
  if (channel) params.channel = channel
  if (status) params.status = status
  if (q) params.q = q

  const { data, isFetching } = useGetIncidentsQuery(params)
  const incidents = data || []

  return (
    <>
      <PageHeader
        title="Detection incidents"
        description="Every sensitive file the endpoints blocked or audited — which file, which user, which channel, and how it matched. Match detail is reviewer-only and every detail view is audited."
      />

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-44">
          <label className="mb-1 block text-xs font-medium text-gray-500">Channel</label>
          <Select value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="">All channels</option>
            <option value="usb">USB / removable</option>
            <option value="clipboard">Clipboard</option>
            <option value="web-upload">Web upload</option>
            <option value="network">Network</option>
          </Select>
        </div>
        <div className="w-44">
          <label className="mb-1 block text-xs font-medium text-gray-500">Status</label>
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {Object.entries(STATUS_LABELS).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-56">
          <label className="mb-1 block text-xs font-medium text-gray-500">File name</label>
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search file name…" />
        </div>
        <div className="ml-auto text-sm text-gray-400">{incidents.length} shown</div>
      </div>

      <Card>
        {isFetching && incidents.length === 0 ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : incidents.length === 0 ? (
          <EmptyState
            icon={<AlertIcon className="h-6 w-6" />}
            title="No matching incidents"
            description="When an endpoint blocks or audits a sensitive transfer, it appears here."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Ref</th>
                  <th className="px-4 py-3 font-medium">Time</th>
                  <th className="px-4 py-3 font-medium">Endpoint</th>
                  <th className="px-4 py-3 font-medium">User</th>
                  <th className="px-4 py-3 font-medium">Channel</th>
                  <th className="px-4 py-3 font-medium">File</th>
                  <th className="px-4 py-3 font-medium">Detection</th>
                  <th className="px-4 py-3 font-medium">Action</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {incidents.map((i) => (
                  <tr
                    key={i.id}
                    onClick={() => canReadDetail && setOpenId(i.id)}
                    className={`align-top ${canReadDetail ? 'cursor-pointer hover:bg-gray-50' : ''}`}
                  >
                    <td className="px-4 py-3 font-mono text-xs text-gray-500 whitespace-nowrap">
                      {i.reference}
                    </td>
                    <td
                      className="px-4 py-3 text-gray-600 whitespace-nowrap"
                      title={formatDateTime(i.reported_at)}
                    >
                      {relativeTime(i.reported_at)}
                    </td>
                    <td className="px-4 py-3 text-gray-900 whitespace-nowrap">{i.hostname || '—'}</td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">
                      {i.os_user || <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">
                      {channelLabel(i.channel)}
                    </td>
                    <td
                      className="px-4 py-3 max-w-[18rem] truncate text-gray-900"
                      title={i.file_name || ''}
                    >
                      {i.file_name || <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3">{detectionBadge(i.detection_type)}</td>
                    <td className="px-4 py-3">{actionBadge(i.action_taken)}</td>
                    <td className="px-4 py-3">{statusBadge(i.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {!canReadDetail && incidents.length > 0 && (
        <p className="mt-3 text-xs text-gray-400">
          You can see the incident list. Opening the match detail requires the incident-reviewer role.
        </p>
      )}

      {incidents.length >= limit && (
        <div className="mt-4 flex justify-center">
          <Button variant="secondary" onClick={() => setLimit((l) => l + 100)} disabled={isFetching}>
            {isFetching ? 'Loading…' : `Load more (${incidents.length} shown)`}
          </Button>
        </div>
      )}

      {openId && <IncidentDetail id={openId} onClose={() => setOpenId(null)} />}
    </>
  )
}
