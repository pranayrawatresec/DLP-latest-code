import { useState } from 'react'
import { useSelector } from 'react-redux'
import {
  useGetTrustedReadersQuery,
  useCreateTrustedReaderMutation,
  useDeleteTrustedReaderMutation,
  useGetGroupsQuery,
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
  name: 'amber', // weakest / spoofable — flagged so it stands out in the list
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

function AddReaderModal({ groupId, groupLabel, kind = 'allow', onClose }) {
  const [createReader, { isLoading: saving }] = useCreateTrustedReaderMutation()

  const isDeny = kind === 'deny'
  // Trust rules default to Publisher (strongest identity). Block rules default to
  // App name — it catches an app across per-user / machine-wide / MSIX installs,
  // and name-spoofing (the usual weakness of a name rule) barely matters for a
  // block: renaming to evade the block only helps if the renamed binary is still
  // trusted by another rule.
  const [matchType, setMatchType] = useState(isDeny ? 'name' : 'publisher')
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')

  const canSubmit = value.trim().length > 0 && !saving

  async function submit() {
    setError('')
    try {
      await createReader({
        kind,
        matchType,
        value: value.trim(),
        note: note.trim() || undefined,
        groupId: groupId ?? null,
      }).unwrap()
      onClose()
    } catch (e) {
      // 409 = already on the list; 400 = validation. Surface the server text.
      setError(e?.data?.error || `Could not add the ${isDeny ? 'blocked application' : 'application'}.`)
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
      title={isDeny ? 'Add blocked application' : 'Add trusted application'}
      description={
        isDeny
          ? 'A blocked application is denied the read of sensitive content EVEN IF a trust rule (e.g. a publisher) would otherwise allow it. Use it to carve an exfiltration channel (Teams, OneDrive, a browser) out of a broad publisher trust.'
          : 'Applications on this list may read sensitive files locally. Everything else is treated as an untrusted reader and denied the read of sensitive content on endpoints (in the allowlist posture).'
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {saving ? 'Adding…' : isDeny ? 'Block application' : 'Add application'}
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-4">
          <InlineAlert>{error}</InlineAlert>
        </div>
      )}

      {isDeny && (
        <div className="mb-4">
          <InlineAlert tone="amber">
            <b>Blocking closes the default leak, not a determined insider.</b> A blocked app
            installed and run normally can no longer read sensitive files. It cannot stop someone
            who copies or renames a publisher-trusted binary to escape the block while still matching
            the publisher trust — that needs app-control (WDAC/AppLocker) or not trusting the
            publisher at all. Prefer an <b>App name</b> rule (e.g. <code className="font-mono">ms-teams.exe</code>)
            so it catches the app across per-user, machine-wide and Store installs.
          </InlineAlert>
        </div>
      )}

      <div className="mb-4 text-xs text-gray-500">
        Adding to <span className="font-medium text-gray-700">{groupLabel}</span>
      </div>

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

      {matchType === 'name' && !isDeny && (
        <div className="mb-2">
          <InlineAlert tone="amber">
            <b>Name-only rules are easy to fake.</b> Any program with this exact file name is
            trusted — malware renamed to <code className="font-mono">{value.trim() || 'winword.exe'}</code>{' '}
            would be trusted too. Prefer a <b>Publisher</b> or <b>Install-path</b> rule, or only use a
            name rule alongside app-control (WDAC/AppLocker) that pins what may run under that name.
          </InlineAlert>
        </div>
      )}

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

// --- shared table ------------------------------------------------------------

// One rows table, reused by the Trusted and Blocked sections. `removeLabel`
// keeps the action verb accurate ("Remove" trust vs "Unblock").
function ReadersTable({ rows, canWrite, onRemove }) {
  return (
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
          {rows.map((r) => (
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
                  <Button variant="dangerGhost" size="sm" onClick={() => onRemove(r)}>
                    Remove
                  </Button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// --- page -------------------------------------------------------------------

export default function TrustedReaders() {
  const canWrite = useSelector(selectHasPermission('trusted_readers:write'))
  // Scope: 'global' (applies to every group) or a group id (only that group).
  const [scope, setScope] = useState('global')
  const { data: groups = [] } = useGetGroupsQuery()
  const { data: readers = [], isLoading, isError } = useGetTrustedReadersQuery(scope)
  const [deleteReader, { isLoading: deleting }] = useDeleteTrustedReaderMutation()

  // null = the add modal is closed; 'allow' | 'deny' = open for that kind.
  const [addKind, setAddKind] = useState(null)
  const [removing, setRemoving] = useState(null)
  const [deleteErr, setDeleteErr] = useState('')

  const scopeGroupId = scope === 'global' ? null : Number(scope)
  const scopeLabel =
    scope === 'global'
      ? 'Global — every group'
      : groups.find((g) => g.id === scopeGroupId)?.name || 'this group'

  // Split the list by disposition: trusted (allow) readers vs blocked (deny)
  // overrides. Deny wins on the endpoint, so a blocked app is denied even when a
  // trust rule (e.g. a publisher) would otherwise allow it.
  const trusted = readers.filter((r) => (r.kind || 'allow') !== 'deny')
  const blocked = readers.filter((r) => r.kind === 'deny')
  const removingIsDeny = removing?.kind === 'deny'

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
      />

      {/* Scope: global applications (trusted everywhere) vs a specific group. */}
      <Card className="mb-4">
        <div className="flex flex-wrap items-center gap-3 px-6 py-4">
          <label className="text-sm font-medium text-gray-900" htmlFor="tr-scope">
            Applies to
          </label>
          <Select
            id="tr-scope"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            className="w-56"
          >
            <option value="global">Global — every group</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.isDefault ? `${g.name} group only` : `${g.name} only`}
              </option>
            ))}
          </Select>
          <span className="text-xs text-gray-500">
            {scope === 'global'
              ? 'These apps are trusted on every endpoint.'
              : 'Only endpoints in this group also trust these apps (in addition to the global list).'}
          </span>
        </div>
      </Card>

      {/* --- Trusted applications (allow) --- */}
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-900">Trusted applications</h2>
        {canWrite && (
          <Button size="sm" onClick={() => setAddKind('allow')}>
            <PlusIcon className="h-4 w-4" /> Add application
          </Button>
        )}
      </div>
      <Card className="mb-8">
        {isLoading ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : isError ? (
          <div className="p-6">
            <InlineAlert>Could not load the trusted applications. Try reloading the page.</InlineAlert>
          </div>
        ) : trusted.length === 0 ? (
          <EmptyState
            icon={<AppWindowIcon className="h-6 w-6" />}
            title="No trusted applications yet"
            description="Add the applications allowed to read sensitive content (Office, your PDF reader/browser, antivirus, backup, the DLP agent). Curate this list before enforcement — every process not listed is denied the read of sensitive files on endpoints."
            action={
              canWrite && (
                <Button onClick={() => setAddKind('allow')}>
                  <PlusIcon className="h-4 w-4" /> Add application
                </Button>
              )
            }
          />
        ) : (
          <ReadersTable
            rows={trusted}
            canWrite={canWrite}
            onRemove={(r) => {
              setDeleteErr('')
              setRemoving(r)
            }}
          />
        )}
      </Card>

      {/* --- Blocked applications (deny-override) --- */}
      <div className="mb-2 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-900">Blocked applications</h2>
          <p className="text-xs text-gray-500">
            Denied the read of sensitive content <b>even if</b> a trust rule (e.g. a publisher) would
            otherwise allow them — e.g. block Teams/OneDrive while “Microsoft Corporation” stays trusted.
          </p>
        </div>
        {canWrite && (
          <Button variant="secondary" size="sm" onClick={() => setAddKind('deny')}>
            <PlusIcon className="h-4 w-4" /> Block application
          </Button>
        )}
      </div>
      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : blocked.length === 0 ? (
          <EmptyState
            icon={<AppWindowIcon className="h-6 w-6" />}
            title="No blocked applications"
            description="Optionally block trusted-by-publisher apps that can take data off the machine (Teams, OneDrive, consumer cloud). By App name is best — e.g. ms-teams.exe, OneDrive.exe."
            action={
              canWrite && (
                <Button variant="secondary" onClick={() => setAddKind('deny')}>
                  <PlusIcon className="h-4 w-4" /> Block application
                </Button>
              )
            }
          />
        ) : (
          <ReadersTable
            rows={blocked}
            canWrite={canWrite}
            onRemove={(r) => {
              setDeleteErr('')
              setRemoving(r)
            }}
          />
        )}
      </Card>

      {addKind && (
        <AddReaderModal
          groupId={scopeGroupId}
          groupLabel={scopeLabel}
          kind={addKind}
          onClose={() => setAddKind(null)}
        />
      )}

      {removing && (
        <Modal
          open
          onClose={() => setRemoving(null)}
          title={removingIsDeny ? 'Unblock this application?' : 'Remove this trusted application?'}
          description={
            removingIsDeny
              ? 'It will no longer be blocked. If a trust rule (e.g. a publisher) allows it, it will again be able to read sensitive content on endpoints.'
              : 'It will no longer be allowed to read sensitive content on endpoints. If it legitimately opens sensitive files (an editor, antivirus, backup), removing it can disrupt normal work — remove only tools that should not read protected data.'
          }
          footer={
            <>
              <Button variant="secondary" onClick={() => setRemoving(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={confirmDelete} disabled={deleting}>
                {deleting ? 'Removing…' : removingIsDeny ? 'Unblock application' : 'Remove application'}
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
