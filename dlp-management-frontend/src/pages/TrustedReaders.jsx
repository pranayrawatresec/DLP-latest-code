import { useState } from 'react'
import { useSelector } from 'react-redux'
import {
  useGetTrustedReadersQuery,
  useCreateTrustedReaderMutation,
  useDeleteTrustedReaderMutation,
} from '../store/apiSlice'
import { selectHasPermission } from '../store/authSlice'
import {
  Card,
  PageHeader,
  Button,
  Badge,
  EmptyState,
  Spinner,
  Field,
  Input,
  Select,
  InlineAlert,
} from '../components/ui/kit'
import { AppWindowIcon, PlusIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

// --- presentation helpers ---------------------------------------------------

const TYPE_LABELS = {
  publisher: 'Publisher',
  path: 'Install path',
  name: 'App name',
}
const TYPE_TONES = {
  publisher: 'green', // strongest identity
  path: 'blue',
  name: 'gray', // weakest
}
const TYPE_HINTS = {
  publisher:
    'The code-signing publisher, e.g. "Adobe Inc." — malware cannot forge a signature. Note: Microsoft signs under three names ("Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"); to cover the OS this way, add all three — or just add a "C:\\Windows" install-path rule.',
  path:
    'An install-path prefix, e.g. "C:\\Program Files\\Adobe" or "C:\\Windows". Strong when the folder is not user-writable. Best way to cover the OS and Office.',
  name:
    'The executable name, e.g. "winword.exe". Weakest — pair with app-control (WDAC/AppLocker).',
}
const TYPE_PLACEHOLDERS = {
  publisher: 'e.g. Microsoft Corporation',
  path: 'e.g. C:\\Program Files\\Adobe',
  name: 'e.g. winword.exe',
}

function typeBadge(t) {
  return <Badge tone={TYPE_TONES[t] || 'gray'}>{TYPE_LABELS[t] || t}</Badge>
}

// --- add-application modal --------------------------------------------------

function AddReaderModal({ onClose }) {
  const [createReader, { isLoading: saving }] = useCreateTrustedReaderMutation()

  const [matchType, setMatchType] = useState('publisher')
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')

  const canSubmit = value.trim().length > 0 && !saving

  async function submit() {
    setError('')
    try {
      await createReader({
        matchType,
        value: value.trim(),
        note: note.trim() || undefined,
      }).unwrap()
      onClose()
    } catch (e) {
      // 409 = already on the allowlist; 400 = validation. Surface the server text.
      setError(e?.data?.error || 'Could not add the application.')
    }
  }

  const typeBtn = (v, label) => (
    <button
      type="button"
      onClick={() => setMatchType(v)}
      className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
        matchType === v
          ? 'bg-white text-indigo-700 shadow-sm ring-1 ring-gray-200'
          : 'text-gray-500 hover:text-gray-700'
      }`}
    >
      {label}
    </button>
  )

  return (
    <Modal
      open
      onClose={onClose}
      title="Add trusted application"
      description="Applications on this list may read sensitive files locally. Everything else is treated as an untrusted reader and denied the read of sensitive content on endpoints (in the allowlist posture)."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {saving ? 'Adding…' : 'Add application'}
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-4">
          <InlineAlert>{error}</InlineAlert>
        </div>
      )}

      <Field label="Identify the application by">
        <div className="inline-flex gap-1 rounded-lg bg-gray-100 p-1">
          {typeBtn('publisher', 'Publisher')}
          {typeBtn('path', 'Install path')}
          {typeBtn('name', 'App name')}
        </div>
      </Field>

      <Field label={TYPE_LABELS[matchType]} htmlFor="tr-value" hint={TYPE_HINTS[matchType]}>
        <Input
          id="tr-value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={TYPE_PLACEHOLDERS[matchType]}
          className={matchType === 'name' || matchType === 'path' ? 'font-mono' : ''}
        />
      </Field>

      <Field label="Note (optional)" htmlFor="tr-note" hint="Why is this application trusted?">
        <Input
          id="tr-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="e.g. approved PDF reader"
        />
      </Field>
    </Modal>
  )
}

// --- page -------------------------------------------------------------------

export default function TrustedReaders() {
  const canWrite = useSelector(selectHasPermission('trusted_readers:write'))
  const { data: readers = [], isLoading, isError } = useGetTrustedReadersQuery()
  const [deleteReader, { isLoading: deleting }] = useDeleteTrustedReaderMutation()

  const [showAdd, setShowAdd] = useState(false)
  const [removing, setRemoving] = useState(null)
  const [deleteErr, setDeleteErr] = useState('')

  async function confirmDelete() {
    setDeleteErr('')
    try {
      await deleteReader(removing.id).unwrap()
      setRemoving(null)
    } catch (e) {
      setDeleteErr(e?.data?.error || 'Could not remove the application.')
    }
  }

  return (
    <>
      <PageHeader
        title="Trusted applications"
        description="The applications allowed to read sensitive content on endpoints. In the read-deny allowlist posture, every other process (unknown tools, malware, remote-access tools) is denied the read of sensitive files — so the bytes never reach a tool that would take them off the machine."
        action={
          canWrite && (
            <Button onClick={() => setShowAdd(true)}>
              <PlusIcon className="h-4 w-4" /> Add application
            </Button>
          )
        }
      />

      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : isError ? (
          <div className="p-6">
            <InlineAlert>Could not load the trusted applications. Try reloading the page.</InlineAlert>
          </div>
        ) : readers.length === 0 ? (
          <EmptyState
            icon={<AppWindowIcon className="h-6 w-6" />}
            title="No trusted applications yet"
            description="Add the applications allowed to read sensitive content (Office, your PDF reader, antivirus, backup, the DLP agent). Roll out in monitor mode first, then enforce."
            action={
              canWrite && (
                <Button onClick={() => setShowAdd(true)}>
                  <PlusIcon className="h-4 w-4" /> Add application
                </Button>
              )
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Identify by</th>
                  <th className="px-4 py-3 font-medium">Value</th>
                  <th className="px-4 py-3 font-medium">Note</th>
                  <th className="px-4 py-3 font-medium">Added by</th>
                  <th className="px-4 py-3 font-medium">Added</th>
                  {canWrite && <th className="px-4 py-3 font-medium"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {readers.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 whitespace-nowrap">{typeBadge(r.matchType)}</td>
                    <td className="px-4 py-3">
                      <code className="font-mono text-xs text-gray-900 break-all">{r.value}</code>
                    </td>
                    <td className="px-4 py-3 max-w-[16rem] truncate text-gray-600" title={r.note || ''}>
                      {r.note || <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">{r.createdBy}</td>
                    <td
                      className="px-4 py-3 text-gray-600 whitespace-nowrap"
                      title={formatDateTime(r.createdAt)}
                    >
                      {relativeTime(r.createdAt)}
                    </td>
                    {canWrite && (
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="dangerGhost"
                          size="sm"
                          onClick={() => {
                            setDeleteErr('')
                            setRemoving(r)
                          }}
                        >
                          Remove
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showAdd && <AddReaderModal onClose={() => setShowAdd(false)} />}

      {removing && (
        <Modal
          open
          onClose={() => setRemoving(null)}
          title="Remove this trusted application?"
          description="It will no longer be allowed to read sensitive content on endpoints. If it legitimately opens sensitive files (an editor, antivirus, backup), removing it can disrupt normal work — remove only tools that should not read protected data."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRemoving(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={confirmDelete} disabled={deleting}>
                {deleting ? 'Removing…' : 'Remove application'}
              </Button>
            </>
          }
        >
          {deleteErr && (
            <div className="mb-3">
              <InlineAlert>{deleteErr}</InlineAlert>
            </div>
          )}
          <div className="flex items-center gap-3 text-sm text-gray-600">
            {typeBadge(removing.matchType)}
            <code className="font-mono text-xs text-gray-900 break-all">{removing.value}</code>
          </div>
        </Modal>
      )}
    </>
  )
}
