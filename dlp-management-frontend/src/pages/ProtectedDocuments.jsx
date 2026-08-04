import { useMemo, useRef, useState } from 'react'
import { useSelector } from 'react-redux'
import { selectHasPermission } from '../store/authSlice'
import {
  useGetCollectionsQuery,
  useCreateCollectionMutation,
  useGetProtectedDocumentsQuery,
  useGetProtectedDocumentQuery,
  useRegisterDocumentMutation,
  useCompileIndexMutation,
  useGetIndexStatusQuery,
} from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, Field, Input, Select, InlineAlert } from '../components/ui/kit'
import { DocumentIcon, UploadIcon, LayersIcon, PlusIcon, RefreshIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

// The registry the DLP fleet screens for: register a document here and every
// agent's next index bundle will recognise it — even renamed, reformatted or
// partially copied. Content goes straight to the encrypted blob store; this
// page only ever sees metadata.

const STATUS_TONE = {
  pending: 'amber',
  extracting: 'blue',
  fingerprinting: 'blue',
  ready: 'green',
  failed: 'red',
}
const ACTIVE_STATUSES = ['pending', 'extracting', 'fingerprinting']
const ACCEPTED = '.txt,.md,.csv,.log,.docx,.xlsx,.pptx,.pdf,.zip'
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024

function formatBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

export default function ProtectedDocuments() {
  const canWrite = useSelector(selectHasPermission('protect:write'))

  const { data: collections = [], isLoading: loadingCollections } = useGetCollectionsQuery()
  const { data: indexStatus } = useGetIndexStatusQuery()
  const [selectedCollection, setSelectedCollection] = useState(null) // null = all

  // Poll while any document is still moving through the worker pipeline so
  // status badges update live without a manual refresh.
  const [polling, setPolling] = useState(false)
  const { data: documents = [], isLoading: loadingDocs } = useGetProtectedDocumentsQuery(
    selectedCollection,
    { pollingInterval: polling ? 2500 : 0 }
  )
  const hasActive = documents.some((d) => ACTIVE_STATUSES.includes(d.status))
  if (hasActive !== polling) setPolling(hasActive)

  const [showNewCollection, setShowNewCollection] = useState(false)
  const [showRegister, setShowRegister] = useState(false)
  const [showCompile, setShowCompile] = useState(false)
  const [detailId, setDetailId] = useState(null)

  const collectionById = useMemo(
    () => Object.fromEntries(collections.map((c) => [c.id, c])),
    [collections]
  )

  return (
    <>
      <PageHeader
        title="Protected documents"
        description="The classified documents every agent screens for. Once registered and fingerprinted, a document is recognised even if renamed, converted, reformatted or partially copied."
        action={
          canWrite && (
            <Button onClick={() => setShowRegister(true)} disabled={collections.length === 0}>
              <UploadIcon className="h-4 w-4" /> Register document
            </Button>
          )
        }
      />

      {!canWrite && (
        <div className="mb-5">
          <InlineAlert tone="blue">
            You have read-only access to this registry. Registering documents requires the
            <b> policy author</b> role.
          </InlineAlert>
        </div>
      )}

      {canWrite && indexStatus && (
        <PublishBanner
          status={indexStatus}
          onCompile={() => setShowCompile(true)}
        />
      )}

      {/* Collections */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <CollectionChip
          label="All collections"
          active={selectedCollection === null}
          onClick={() => setSelectedCollection(null)}
        />
        {collections.map((c) => (
          <CollectionChip
            key={c.id}
            label={c.name}
            count={c.document_count}
            failed={c.failed_count > 0}
            active={selectedCollection === c.id}
            onClick={() => setSelectedCollection(c.id)}
          />
        ))}
        {canWrite && (
          <button
            onClick={() => setShowNewCollection(true)}
            className="inline-flex items-center gap-1 rounded-full border border-dashed border-gray-300 px-3 py-1.5 text-sm text-gray-500 hover:border-gray-400 hover:text-gray-700"
          >
            <PlusIcon className="h-3.5 w-3.5" /> New collection
          </button>
        )}
      </div>

      <Card>
        {loadingCollections || loadingDocs ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : collections.length === 0 ? (
          <EmptyState
            icon={<LayersIcon className="h-6 w-6" />}
            title="No collections yet"
            description="Collections group protected documents (e.g. “Army Operations”). Policies will reference collections, not individual files."
            action={
              canWrite && (
                <Button onClick={() => setShowNewCollection(true)}>
                  <PlusIcon className="h-4 w-4" /> Create the first collection
                </Button>
              )
            }
          />
        ) : documents.length === 0 ? (
          <EmptyState
            icon={<DocumentIcon className="h-6 w-6" />}
            title="No documents registered"
            description="Register a document and the pipeline fingerprints it automatically — extraction, canonicalisation, shingling, winnowing."
            action={
              canWrite && (
                <Button onClick={() => setShowRegister(true)}>
                  <UploadIcon className="h-4 w-4" /> Register document
                </Button>
              )
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Title</th>
                  <th className="px-4 py-3 font-medium">Collection</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Version</th>
                  <th className="px-4 py-3 font-medium">Fingerprints</th>
                  <th className="px-4 py-3 font-medium">Registered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {documents.map((d) => (
                  <tr
                    key={d.id}
                    className="cursor-pointer hover:bg-gray-50"
                    onClick={() => setDetailId(d.id)}
                  >
                    <td className="px-4 py-3 font-medium text-gray-900">{d.title}</td>
                    <td className="px-4 py-3 text-gray-600">
                      {collectionById[d.collection_id]?.name || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={d.status} reason={d.failure_reason} />
                    </td>
                    <td className="px-4 py-3 text-gray-600">
                      {d.current_version ? `v${d.current_version}` : '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-600">
                      {d.status === 'ready' ? d.fingerprint_count : '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-600" title={formatDateTime(d.created_at)}>
                      {relativeTime(d.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {hasActive && (
        <p className="mt-3 flex items-center gap-2 text-xs text-gray-400">
          <Spinner className="h-3.5 w-3.5" /> The pipeline worker is processing — statuses refresh
          automatically. If a document stays <b>pending</b>, check that the worker is running.
        </p>
      )}

      {showNewCollection && <NewCollectionModal onClose={() => setShowNewCollection(false)} />}
      {showRegister && (
        <RegisterDocumentModal
          collections={collections}
          initialCollection={selectedCollection}
          onClose={() => setShowRegister(false)}
        />
      )}
      {showCompile && <CompileIndexModal onClose={() => setShowCompile(false)} />}
      {detailId && <DocumentDetailModal id={detailId} onClose={() => setDetailId(null)} />}
    </>
  )
}

// Contextual publish state: after registering documents, they exist in the
// database but are NOT enforced on any endpoint until the index is compiled and
// agents pick it up. This surfaces that gap and puts the compile action here,
// where the operator just finished uploading — not buried in the header.
function PublishBanner({ status, onCompile }) {
  const pending = (status.pendingDocuments || 0) + (status.pendingEdmSources || 0)
  const last = status.lastCompiled

  if (status.needsCompile) {
    const parts = []
    if (status.pendingDocuments) parts.push(`${status.pendingDocuments} document${status.pendingDocuments > 1 ? 's' : ''}`)
    if (status.pendingEdmSources) parts.push(`${status.pendingEdmSources} data source${status.pendingEdmSources > 1 ? 's' : ''}`)
    return (
      <div className="mb-5 flex flex-col gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <RefreshIcon className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
          <div className="text-sm text-amber-900">
            <div className="font-semibold">
              {parts.join(' and ')} registered since the last index build
            </div>
            <div className="text-amber-700">
              {last
                ? `Endpoints are still enforcing bundle v${last.version}. Compile a new index to publish these to agents.`
                : 'No index has been compiled yet — agents cannot enforce anything until you build the first one.'}
            </div>
          </div>
        </div>
        <Button onClick={onCompile} className="shrink-0">
          <RefreshIcon className="h-4 w-4" /> Compile index
        </Button>
      </div>
    )
  }

  // Everything published — quiet confirmation, compile still available.
  return (
    <div className="mb-5 flex items-center justify-between rounded-lg border border-gray-200 bg-white px-4 py-3">
      <div className="text-sm text-gray-500">
        {last ? (
          <>Index <b className="text-gray-700">v{last.version}</b> is current — all {status.readyDocuments} ready document{status.readyDocuments === 1 ? '' : 's'} are published to agents · built {relativeTime(last.builtAt)}</>
        ) : (
          <>Nothing registered yet.</>
        )}
      </div>
      {last && (
        <Button variant="secondary" size="sm" onClick={onCompile}>
          <RefreshIcon className="h-4 w-4" /> Recompile
        </Button>
      )}
    </div>
  )
}

function CollectionChip({ label, count, failed, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-sm font-medium transition-colors ${
        active
          ? 'border-indigo-200 bg-indigo-50 text-indigo-700'
          : 'border-gray-200 bg-white text-gray-600 hover:bg-gray-50'
      }`}
    >
      {label}
      {count != null && <span className="text-xs text-gray-400">{count}</span>}
      {failed && <span className="h-1.5 w-1.5 rounded-full bg-red-500" title="Has failed documents" />}
    </button>
  )
}

function StatusBadge({ status, reason }) {
  const label = status === 'extracting' || status === 'fingerprinting' ? `processing · ${status}` : status
  return (
    <span className="inline-flex items-center gap-2">
      <Badge tone={STATUS_TONE[status] || 'gray'}>{label}</Badge>
      {status === 'failed' && reason && (
        <code className="rounded bg-red-50 px-1.5 py-0.5 text-[11px] text-red-700">{reason}</code>
      )}
    </span>
  )
}

function NewCollectionModal({ onClose }) {
  const [createCollection, { isLoading }] = useCreateCollectionMutation()
  const [name, setName] = useState('')
  const [classification, setClassification] = useState('secret')
  const [description, setDescription] = useState('')
  const [error, setError] = useState(null)

  async function submit() {
    setError(null)
    try {
      await createCollection({ name, classification, description }).unwrap()
      onClose()
    } catch (e) {
      setError(e?.data?.error || 'Could not create collection')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New collection"
      description="A named group of protected documents. Policies target collections (e.g. “block Army Operations to USB”), so name it the way an operator thinks."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={isLoading || !name.trim()}>
            {isLoading ? 'Creating…' : 'Create collection'}
          </Button>
        </>
      }
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}
      <Field label="Name" htmlFor="col-name" hint="e.g. “Army Operations”, “DRDO Research”">
        <Input id="col-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Collection name" />
      </Field>
      <Field label="Classification" htmlFor="col-class">
        <Select id="col-class" value={classification} onChange={(e) => setClassification(e.target.value)}>
          <option value="top_secret">Top Secret</option>
          <option value="secret">Secret</option>
          <option value="confidential">Confidential</option>
          <option value="restricted">Restricted</option>
        </Select>
      </Field>
      <Field label="Description" htmlFor="col-desc" hint="Optional — what belongs in here.">
        <Input id="col-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this collection protects" />
      </Field>
    </Modal>
  )
}

function RegisterDocumentModal({ collections, initialCollection, onClose }) {
  const [registerDocument, { isLoading }] = useRegisterDocumentMutation()
  const [collectionId, setCollectionId] = useState(initialCollection || collections[0]?.id || '')
  const [title, setTitle] = useState('')
  const [file, setFile] = useState(null)
  const [error, setError] = useState(null)
  const fileRef = useRef(null)
  const titleTouched = useRef(false)

  function pickFile(f) {
    setFile(f || null)
    setError(null)
    if (f && !titleTouched.current) {
      setTitle(f.name.replace(/\.[^.]+$/, ''))
    }
  }

  async function submit() {
    setError(null)
    if (!file) return setError('Choose a file to register')
    if (file.size === 0) return setError('The selected file is empty')
    if (file.size > MAX_UPLOAD_BYTES) return setError('Documents are limited to 100 MB')
    if (!title.trim()) return setError('Title is required')
    try {
      await registerDocument({ collectionId, title: title.trim(), file }).unwrap()
      onClose()
    } catch (e) {
      setError(e?.data?.error || 'Registration failed')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title="Register a protected document"
      description="The file is encrypted at rest and fingerprinted asynchronously. Registering the same title in a collection again creates a new version — old versions stay recognised."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={isLoading}>
            {isLoading ? 'Uploading…' : 'Register document'}
          </Button>
        </>
      }
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}

      <Field label="Collection" htmlFor="reg-col">
        <Select id="reg-col" value={collectionId} onChange={(e) => setCollectionId(e.target.value)}>
          {collections.map((c) => (
            <option key={c.id} value={c.id}>{c.name} · {c.classification}</option>
          ))}
        </Select>
      </Field>

      <Field label="Document" htmlFor="reg-file" hint="Supported: Word, Excel, PowerPoint, PDF (text layer), plain text/CSV, zip archives. Encrypted files can't be fingerprinted.">
        <input
          ref={fileRef}
          id="reg-file"
          type="file"
          accept={ACCEPTED}
          onChange={(e) => pickFile(e.target.files?.[0])}
          className="hidden"
        />
        <button
          type="button"
          onClick={() => fileRef.current?.click()}
          className="flex w-full items-center gap-3 rounded-lg border border-dashed border-gray-300 px-4 py-4 text-left hover:border-gray-400"
        >
          <UploadIcon className="h-5 w-5 shrink-0 text-gray-400" />
          {file ? (
            <span className="min-w-0">
              <span className="block truncate text-sm font-medium text-gray-900">{file.name}</span>
              <span className="text-xs text-gray-400">{formatBytes(file.size)}</span>
            </span>
          ) : (
            <span className="text-sm text-gray-500">Click to choose a file…</span>
          )}
        </button>
      </Field>

      <Field label="Title" htmlFor="reg-title" hint="How this document appears in the registry and in incidents.">
        <Input
          id="reg-title"
          value={title}
          onChange={(e) => {
            titleTouched.current = true
            setTitle(e.target.value)
          }}
          placeholder="e.g. Deployment Order — Northern Command"
        />
      </Field>
    </Modal>
  )
}

function CompileIndexModal({ onClose }) {
  const [compileIndex, { isLoading }] = useCompileIndexMutation()
  const [done, setDone] = useState(false)
  const [error, setError] = useState(null)

  async function submit() {
    setError(null)
    try {
      await compileIndex().unwrap()
      setDone(true)
    } catch (e) {
      setError(e?.data?.error || 'Could not queue the compile job')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Compile index bundle"
      description="Packs every ready document and data source into a new signed index bundle. Agents pick it up at their next check-in."
      footer={
        done ? (
          <Button onClick={onClose}>Done</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={onClose}>Cancel</Button>
            <Button onClick={submit} disabled={isLoading}>
              {isLoading ? 'Queueing…' : 'Compile now'}
            </Button>
          </>
        )
      }
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}
      {done ? (
        <InlineAlert tone="blue">
          Compile queued — the worker is building the bundle. Newly registered documents are only
          enforced on endpoints after this completes and agents check in.
        </InlineAlert>
      ) : (
        <p className="text-sm text-gray-600">
          The bundle contains only irreversible fingerprint hashes — never document text. It is
          signed by the management CA; agents refuse any bundle that fails verification.
        </p>
      )}
    </Modal>
  )
}

function DocumentDetailModal({ id, onClose }) {
  const { data: doc, isLoading } = useGetProtectedDocumentQuery(id)

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={doc ? doc.title : 'Document'}
      description={doc ? `${doc.collection_name} · ${doc.classification}` : undefined}
      footer={<Button variant="secondary" onClick={onClose}>Close</Button>}
    >
      {isLoading || !doc ? (
        <div className="flex justify-center py-10"><Spinner /></div>
      ) : (
        <>
          <div className="mb-4 flex items-center gap-3">
            <StatusBadge status={doc.status} reason={doc.failure_reason} />
            <span className="text-xs text-gray-400" title={formatDateTime(doc.created_at)}>
              registered {relativeTime(doc.created_at)}
            </span>
          </div>

          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-3 py-2 font-medium">Version</th>
                  <th className="px-3 py-2 font-medium">File</th>
                  <th className="px-3 py-2 font-medium">Size</th>
                  <th className="px-3 py-2 font-medium">Fingerprints</th>
                  <th className="px-3 py-2 font-medium">Registered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {doc.versions.map((v) => (
                  <tr key={v.id} className={v.retired_at ? 'text-gray-400' : ''}>
                    <td className="px-3 py-2">
                      v{v.version_no}
                      {v.version_no === doc.current_version && (
                        <Badge tone="green" className="ml-2">current</Badge>
                      )}
                      {v.retired_at && <Badge tone="gray" className="ml-2">retired</Badge>}
                    </td>
                    <td className="px-3 py-2">{v.original_filename || '—'}</td>
                    <td className="px-3 py-2">{formatBytes(Number(v.size_bytes))}</td>
                    <td className="px-3 py-2">{v.fingerprint_count}</td>
                    <td className="px-3 py-2" title={formatDateTime(v.registered_at)}>
                      {relativeTime(v.registered_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-4 text-xs text-gray-400">
            SHA-256 of current file: <code className="break-all">{doc.versions.find((v) => v.version_no === doc.current_version)?.sha256 || '—'}</code>
          </p>
        </>
      )}
    </Modal>
  )
}
