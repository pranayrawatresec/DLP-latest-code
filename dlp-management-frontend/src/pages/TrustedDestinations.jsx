import { useState } from 'react'
import { useSelector } from 'react-redux'
import {
  useGetTrustedDestinationsQuery,
  useCreateTrustedDestinationMutation,
  useDeleteTrustedDestinationMutation,
  useGetEncryptionKeysQuery,
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
import { UsbIcon, PlusIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

// --- presentation helpers ---------------------------------------------------

const MODE_LABELS = {
  encrypt_sensitive: 'Encrypt sensitive files',
  encrypt_all: 'Encrypt everything',
}
const MODE_HINTS = {
  encrypt_sensitive:
    'Files the detection engine scores as sensitive are sealed; clean files copy in plaintext.',
  encrypt_all:
    'Every file copied to the device is sealed — no scan needed. Use for courier sticks.',
}
function modeBadge(mode) {
  return (
    <Badge tone={mode === 'encrypt_all' ? 'indigo' : 'blue'}>
      {MODE_LABELS[mode] || mode}
    </Badge>
  )
}

// Block-band policy: what to do with a file the engine scores as highly sensitive.
// Only meaningful when the mode is encrypt_sensitive (encrypt_all seals everything).
const BAND_LABELS = {
  seal: 'Seal sensitive',
  block: 'Block sensitive',
}
function bandCell(dest) {
  // encrypt_all seals every file, so the block-band choice does not apply.
  if (dest.mode === 'encrypt_all') {
    return <span className="text-gray-300">—</span>
  }
  const band = dest.onBlockBand === 'seal' ? 'seal' : 'block'
  return <Badge tone={band === 'seal' ? 'amber' : 'gray'}>{BAND_LABELS[band]}</Badge>
}

// Render the device matcher readably: a serial, or a VID:PID hardware id.
function DeviceCell({ matcher }) {
  if (matcher?.serial) {
    return (
      <div>
        <div className="text-xs font-medium text-gray-400">Serial</div>
        <code className="font-mono text-xs text-gray-900">{matcher.serial}</code>
      </div>
    )
  }
  if (matcher?.vid && matcher?.pid) {
    return (
      <div>
        <div className="text-xs font-medium text-gray-400">Hardware id</div>
        <code className="font-mono text-xs text-gray-900">
          VID {matcher.vid.toUpperCase()} : PID {matcher.pid.toUpperCase()}
        </code>
      </div>
    )
  }
  return <span className="text-gray-300">—</span>
}

const HEX4 = /^[0-9a-fA-F]{4}$/

// --- add-device modal -------------------------------------------------------

function AddDeviceModal({ onClose }) {
  const [createDestination, { isLoading: saving }] = useCreateTrustedDestinationMutation()
  const {
    data: keys = [],
    isLoading: keysLoading,
    isError: keysError,
  } = useGetEncryptionKeysQuery()

  const activeKeys = keys.filter((k) => k.state === 'active')
  const noActiveKey = !keysLoading && !keysError && activeKeys.length === 0

  const [matchBy, setMatchBy] = useState('serial') // 'serial' | 'vid_pid'
  const [serial, setSerial] = useState('')
  const [vid, setVid] = useState('')
  const [pid, setPid] = useState('')
  const [mode, setMode] = useState('encrypt_sensitive')
  const [onBlockBand, setOnBlockBand] = useState('block') // 'block' (default) | 'seal'
  const [keyId, setKeyId] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')

  // Auto-pick the key when exactly one is active; otherwise the admin chooses.
  const effectiveKeyId = keyId || (activeKeys.length === 1 ? activeKeys[0].id : '')

  const vidOk = HEX4.test(vid)
  const pidOk = HEX4.test(pid)
  const matcherOk = matchBy === 'serial' ? serial.trim().length > 0 : vidOk && pidOk
  const canSubmit = matcherOk && !noActiveKey && !keysLoading && Boolean(effectiveKeyId) && !saving

  async function submit() {
    setError('')
    const matcher =
      matchBy === 'serial'
        ? { serial: serial.trim() }
        : { vid: vid.toLowerCase(), pid: pid.toLowerCase() }
    try {
      await createDestination({
        channel: 'usb',
        matcher,
        mode,
        // The block-band choice only applies to encrypt_sensitive; encrypt_all
        // seals everything, so we always send the safe default there.
        onBlockBand: mode === 'encrypt_sensitive' ? onBlockBand : 'block',
        keyId: effectiveKeyId || undefined,
        note: note.trim() || undefined,
      }).unwrap()
      onClose()
    } catch (e) {
      // 409 = "no encryption key exists yet" — surface the server's message.
      setError(e?.data?.error || 'Could not add the device.')
    }
  }

  const toggleBtn = (value, label) => (
    <button
      type="button"
      onClick={() => setMatchBy(value)}
      className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
        matchBy === value
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
      title="Add trusted device"
      description="Files copied to this device will be encrypted so only this organisation's enrolled endpoints can open them."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {saving ? 'Adding…' : 'Add device'}
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-4">
          <InlineAlert>{error}</InlineAlert>
        </div>
      )}
      {noActiveKey && (
        <div className="mb-4">
          <InlineAlert tone="amber">
            No active encryption key exists yet. A sysadmin must create one before devices
            can be whitelisted.
          </InlineAlert>
        </div>
      )}
      {keysError && (
        <div className="mb-4">
          <InlineAlert>Could not load the encryption keys.</InlineAlert>
        </div>
      )}

      <Field label="Match device by">
        <div className="inline-flex gap-1 rounded-lg bg-gray-100 p-1">
          {toggleBtn('serial', 'Serial number')}
          {toggleBtn('vid_pid', 'VID / PID')}
        </div>
      </Field>

      {matchBy === 'serial' ? (
        <Field
          label="Device serial"
          htmlFor="td-serial"
          hint="The exact serial of one physical stick (shown on the Incidents page when a device is used)."
        >
          <Input
            id="td-serial"
            value={serial}
            onChange={(e) => setSerial(e.target.value)}
            placeholder="e.g. 0401396FBBF0C89E"
            className="font-mono"
          />
        </Field>
      ) : (
        <Field
          label="Vendor / product id"
          hint="Four hex characters each — matches every device of this make and model."
        >
          <div className="flex items-center gap-2">
            <Input
              id="td-vid"
              value={vid}
              onChange={(e) => setVid(e.target.value)}
              placeholder="VID e.g. 0951"
              maxLength={4}
              className={`w-32 font-mono ${vid && !vidOk ? 'border-red-300' : ''}`}
            />
            <span className="text-gray-400">:</span>
            <Input
              id="td-pid"
              value={pid}
              onChange={(e) => setPid(e.target.value)}
              placeholder="PID e.g. 1666"
              maxLength={4}
              className={`w-32 font-mono ${pid && !pidOk ? 'border-red-300' : ''}`}
            />
          </div>
          {((vid && !vidOk) || (pid && !pidOk)) && (
            <p className="mt-1 text-xs text-red-600">
              VID and PID must each be exactly 4 hex characters (0-9, A-F).
            </p>
          )}
        </Field>
      )}

      <Field label="Encryption mode" htmlFor="td-mode" hint={MODE_HINTS[mode]}>
        <Select id="td-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="encrypt_sensitive">{MODE_LABELS.encrypt_sensitive}</option>
          <option value="encrypt_all">{MODE_LABELS.encrypt_all}</option>
        </Select>
      </Field>

      {/* Block-band choice only matters when clean files copy in plaintext, i.e.
          encrypt_sensitive. encrypt_all seals everything, so this is hidden and
          the request sends the safe default (block). */}
      {mode === 'encrypt_sensitive' && (
        <Field
          label="When a file is highly sensitive (block-band)"
          htmlFor="td-band"
          hint="Seal = the sensitive file leaves armoured instead of blocked."
        >
          <Select
            id="td-band"
            value={onBlockBand}
            onChange={(e) => setOnBlockBand(e.target.value)}
          >
            <option value="block">Block it (default)</option>
            <option value="seal">Encrypt it onto this device</option>
          </Select>
        </Field>
      )}

      <Field
        label="Encryption key"
        htmlFor="td-key"
        hint="The organisation key used to seal files for this device."
      >
        {keysLoading ? (
          <div className="flex items-center gap-2 py-1 text-sm text-gray-400">
            <Spinner className="h-4 w-4" /> Loading keys…
          </div>
        ) : (
          <Select
            id="td-key"
            value={effectiveKeyId}
            onChange={(e) => setKeyId(e.target.value)}
            disabled={noActiveKey}
          >
            {activeKeys.length !== 1 && <option value="">Select a key…</option>}
            {activeKeys.map((k) => (
              <option key={k.id} value={k.id}>
                {k.id} — {k.classification} (v{k.version})
              </option>
            ))}
          </Select>
        )}
      </Field>

      <Field label="Note (optional)" htmlFor="td-note" hint="e.g. “site-A courier stick”">
        <Input
          id="td-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="What is this device for?"
        />
      </Field>
    </Modal>
  )
}

// --- page -------------------------------------------------------------------

export default function TrustedDestinations() {
  const canWrite = useSelector(selectHasPermission('trusted_destinations:write'))
  const { data: destinations = [], isLoading, isError } = useGetTrustedDestinationsQuery()
  const [deleteDestination, { isLoading: deleting }] = useDeleteTrustedDestinationMutation()

  const [showAdd, setShowAdd] = useState(false)
  const [removing, setRemoving] = useState(null) // destination pending delete confirm
  const [deleteErr, setDeleteErr] = useState('')

  async function confirmDelete() {
    setDeleteErr('')
    try {
      await deleteDestination(removing.id).unwrap()
      setRemoving(null)
    } catch (e) {
      setDeleteErr(e?.data?.error || 'Could not remove the device.')
    }
  }

  return (
    <>
      <PageHeader
        title="Trusted USB devices"
        description="Whitelisted removable devices for encrypt-on-write. Copies to these devices are not blocked — they land as sealed .dlpenc files only enrolled endpoints can open."
        action={
          canWrite && (
            <Button onClick={() => setShowAdd(true)}>
              <PlusIcon className="h-4 w-4" /> Add device
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
            <InlineAlert>Could not load the trusted devices. Try reloading the page.</InlineAlert>
          </div>
        ) : destinations.length === 0 ? (
          <EmptyState
            icon={<UsbIcon className="h-6 w-6" />}
            title="No trusted devices yet"
            description="Files copied to these devices are encrypted so only this organisation's enrolled endpoints can open them."
            action={
              canWrite && (
                <Button onClick={() => setShowAdd(true)}>
                  <PlusIcon className="h-4 w-4" /> Add device
                </Button>
              )
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Device</th>
                  <th className="px-4 py-3 font-medium">Mode</th>
                  <th className="px-4 py-3 font-medium">Block-band</th>
                  <th className="px-4 py-3 font-medium">Key</th>
                  <th className="px-4 py-3 font-medium">Note</th>
                  <th className="px-4 py-3 font-medium">Created by</th>
                  <th className="px-4 py-3 font-medium">Added</th>
                  {canWrite && <th className="px-4 py-3 font-medium"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {destinations.map((d) => (
                  <tr key={d.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <DeviceCell matcher={d.matcher} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">{modeBadge(d.mode)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">{bandCell(d)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <code className="font-mono text-xs text-gray-500">{d.keyId}</code>
                    </td>
                    <td className="px-4 py-3 max-w-[16rem] truncate text-gray-600" title={d.note || ''}>
                      {d.note || <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">{d.createdBy}</td>
                    <td
                      className="px-4 py-3 text-gray-600 whitespace-nowrap"
                      title={formatDateTime(d.createdAt)}
                    >
                      {relativeTime(d.createdAt)}
                    </td>
                    {canWrite && (
                      <td className="px-4 py-3 text-right">
                        <Button variant="dangerGhost" size="sm" onClick={() => { setDeleteErr(''); setRemoving(d) }}>
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

      {showAdd && <AddDeviceModal onClose={() => setShowAdd(false)} />}

      {removing && (
        <Modal
          open
          onClose={() => setRemoving(null)}
          title="Remove this trusted device?"
          description="New copies to the device go back to the normal policy (audit / read-only / block). Files already sealed on it stay encrypted and remain openable on enrolled endpoints."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRemoving(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={confirmDelete} disabled={deleting}>
                {deleting ? 'Removing…' : 'Remove device'}
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
            <DeviceCell matcher={removing.matcher} />
            {removing.note && <span>— {removing.note}</span>}
          </div>
        </Modal>
      )}
    </>
  )
}
