import { useState } from 'react'
import { useGetAuditLogQuery, useVerifyAuditChainQuery } from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, Input, Select } from '../components/ui/kit'
import { ShieldIcon, CheckIcon, AlertIcon, RefreshIcon } from '../components/ui/Icons'
import { relativeTime, formatDateTime } from '../lib/format'

// Map an action to a badge tone by its shape.
function actionTone(action) {
  if (/denied|rejected|refused|lockout|failed/.test(action)) return 'red'
  if (/revoke|retire|disable|delete/.test(action)) return 'amber'
  if (/login$|activated|enroll$|create/.test(action)) return 'green'
  return 'gray'
}

export default function AuditLog() {
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [limit, setLimit] = useState(100)

  const params = { limit }
  if (actor) params.actor = actor
  if (action) params.action = action

  const { data, isFetching } = useGetAuditLogQuery(params)
  const verify = useVerifyAuditChainQuery()

  const entries = data?.entries || []
  const total = data?.total || 0

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every security-relevant action, append-only and hash-chained. It cannot be edited or deleted — tampering breaks the chain."
      />

      {/* Integrity banner */}
      <div className="mb-5">
        {verify.isLoading ? (
          <div className="flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-4 py-3 text-sm text-gray-500">
            <Spinner className="h-4 w-4" /> Verifying chain integrity…
          </div>
        ) : verify.data?.intact ? (
          <div className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-4 py-3">
            <div className="flex items-center gap-2 text-sm text-green-800">
              <CheckIcon className="h-5 w-5 text-green-600" />
              <span><b>Tamper-evident chain intact.</b> All {verify.data.count} entries verified.</span>
            </div>
            <Button variant="secondary" size="sm" onClick={() => verify.refetch()}>
              <RefreshIcon className="h-4 w-4" /> Re-verify
            </Button>
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <AlertIcon className="h-5 w-5 text-red-600" />
            <span><b>Tampering detected.</b> The chain breaks at entry #{verify.data?.brokenAt}. Investigate immediately.</span>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-56">
          <label className="mb-1 block text-xs font-medium text-gray-500">Actor</label>
          <Input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="Filter by actor…" />
        </div>
        <div className="w-56">
          <label className="mb-1 block text-xs font-medium text-gray-500">Action</label>
          <Select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">All actions</option>
            {(data?.availableActions || []).map((a) => <option key={a} value={a}>{a}</option>)}
          </Select>
        </div>
        <div className="ml-auto text-sm text-gray-400">{total} total entries</div>
      </div>

      <Card>
        {isFetching && entries.length === 0 ? (
          <div className="flex justify-center py-16"><Spinner /></div>
        ) : entries.length === 0 ? (
          <EmptyState icon={<ShieldIcon className="h-6 w-6" />} title="No matching entries" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">#</th>
                  <th className="px-4 py-3 font-medium">Time</th>
                  <th className="px-4 py-3 font-medium">Actor</th>
                  <th className="px-4 py-3 font-medium">Action</th>
                  <th className="px-4 py-3 font-medium">Target</th>
                  <th className="px-4 py-3 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {entries.map((e) => (
                  <tr key={e.seq} className="hover:bg-gray-50 align-top">
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">{e.seq}</td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap" title={formatDateTime(e.ts)}>{relativeTime(e.ts)}</td>
                    <td className="px-4 py-3 text-gray-900">{e.actor}</td>
                    <td className="px-4 py-3"><Badge tone={actionTone(e.action)}>{e.action}</Badge></td>
                    <td className="px-4 py-3 max-w-[16rem] truncate text-gray-600" title={e.target || ''}>{e.target || <span className="text-gray-300">—</span>}</td>
                    <td className="px-4 py-3">
                      {e.detail && Object.keys(e.detail).length > 0 ? (
                        <code className="block max-w-[20rem] truncate font-mono text-xs text-gray-500" title={JSON.stringify(e.detail)}>
                          {JSON.stringify(e.detail)}
                        </code>
                      ) : (
                        <span className="text-gray-300">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {entries.length < total && (
        <div className="mt-4 flex justify-center">
          <Button variant="secondary" onClick={() => setLimit((l) => l + 100)} disabled={isFetching}>
            {isFetching ? 'Loading…' : `Load more (${entries.length} of ${total})`}
          </Button>
        </div>
      )}
    </>
  )
}
