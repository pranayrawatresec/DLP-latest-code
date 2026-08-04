import { useState } from 'react'
import { useGetSessionsQuery, useRevokeSessionMutation } from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, InlineAlert } from '../components/ui/kit'
import { LogoutIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDateTime } from '../lib/format'

export default function Sessions() {
  const { data: sessions = [], isLoading } = useGetSessionsQuery()
  const [revokeSession] = useRevokeSessionMutation()
  const [revoking, setRevoking] = useState(null)

  return (
    <>
      <PageHeader
        title="Active sessions"
        description="Every administrator currently signed in. Revoking a session signs that person out immediately."
      />

      <div className="mb-5">
        <InlineAlert tone="blue">
          Server-side sessions can be killed instantly — this is why the console uses sessions rather than
          self-contained tokens. Revoke on a lost laptop or a departing admin.
        </InlineAlert>
      </div>

      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16"><Spinner /></div>
        ) : sessions.length === 0 ? (
          <EmptyState icon={<LogoutIcon className="h-6 w-6" />} title="No active sessions" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Administrator</th>
                  <th className="px-4 py-3 font-medium">Signed in</th>
                  <th className="px-4 py-3 font-medium">Expires</th>
                  <th className="px-4 py-3 font-medium">IP</th>
                  <th className="px-4 py-3 font-medium">Device</th>
                  <th className="px-4 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {sessions.map((s) => (
                  <tr key={s.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-900">{s.email}</span>
                      {s.current && <Badge tone="green" className="ml-2">this session</Badge>}
                    </td>
                    <td className="px-4 py-3 text-gray-600" title={formatDateTime(s.createdAt)}>{relativeTime(s.createdAt)}</td>
                    <td className="px-4 py-3 text-gray-600" title={formatDateTime(s.expiresAt)}>{relativeTime(s.expiresAt)}</td>
                    <td className="px-4 py-3 text-gray-600">{s.ip || '—'}</td>
                    <td className="px-4 py-3 max-w-xs truncate text-gray-500" title={s.userAgent}>{s.userAgent || '—'}</td>
                    <td className="px-4 py-3 text-right">
                      {!s.current && (
                        <Button variant="dangerGhost" size="sm" onClick={() => setRevoking(s)}>Revoke</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {revoking && (
        <Modal
          open
          onClose={() => setRevoking(null)}
          title="Revoke this session?"
          description="The administrator is signed out immediately and must log in again."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRevoking(null)}>Cancel</Button>
              <Button variant="danger" onClick={async () => { await revokeSession(revoking.id); setRevoking(null) }}>Revoke session</Button>
            </>
          }
        >
          <p className="text-sm text-gray-600">Session for <b>{revoking.email}</b>, signed in {relativeTime(revoking.createdAt)}.</p>
        </Modal>
      )}
    </>
  )
}
