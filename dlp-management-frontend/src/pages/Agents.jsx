import { useState } from 'react'
import {
  useGetAgentsQuery,
  useRetireAgentMutation,
  useGetGroupsQuery,
  useAssignAgentGroupMutation,
} from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, Select } from '../components/ui/kit'
import { MonitorIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'
import { relativeTime, formatDate, formatDateTime } from '../lib/format'
import { useSelector } from 'react-redux'
import { selectHasPermission } from '../store/authSlice'

const STATUS_TONE = { active: 'green', enrolled: 'blue', offline: 'amber', retired: 'gray' }

export default function Agents() {
  const { data: agents = [], isLoading } = useGetAgentsQuery()
  const [retireAgent] = useRetireAgentMutation()
  const { data: groups = [] } = useGetGroupsQuery()
  const [assignGroup] = useAssignAgentGroupMutation()
  const canManage = useSelector(selectHasPermission('agents.manage'))
  const nonDefaultGroups = groups.filter((g) => !g.isDefault)
  const [retiring, setRetiring] = useState(null)

  return (
    <>
      <PageHeader
        title="Agents"
        description="Every PC that has enrolled. Each holds a unique certificate and checks in over mutual TLS."
      />

      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16"><Spinner /></div>
        ) : agents.length === 0 ? (
          <EmptyState
            icon={<MonitorIcon className="h-6 w-6" />}
            title="No agents enrolled yet"
            description="Create an enrollment token and deploy the agent to your PCs. Enrolled machines appear here."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Hostname</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Group</th>
                  <th className="px-4 py-3 font-medium">Version</th>
                  <th className="px-4 py-3 font-medium">Last seen</th>
                  <th className="px-4 py-3 font-medium">Cert expires</th>
                  {canManage && <th className="px-4 py-3 font-medium"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {agents.map((a) => (
                  <tr key={a.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-900">{a.hostname}</div>
                      <div className="text-xs text-gray-400">{a.os || '—'}</div>
                    </td>
                    <td className="px-4 py-3"><Badge tone={STATUS_TONE[a.status] || 'gray'}>{a.status}</Badge></td>
                    <td className="px-4 py-3">
                      {canManage && a.status !== 'retired' ? (
                        <Select
                          value={a.group_id ?? ''}
                          onChange={(e) =>
                            assignGroup({
                              id: a.id,
                              groupId: e.target.value === '' ? null : Number(e.target.value),
                            })
                          }
                          className="text-xs py-1"
                          aria-label={`Group for ${a.hostname}`}
                        >
                          <option value="">Default</option>
                          {nonDefaultGroups.map((g) => (
                            <option key={g.id} value={g.id}>
                              {g.name}
                            </option>
                          ))}
                        </Select>
                      ) : (
                        <span className="text-gray-600">{a.group_name || 'Default'}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-600">{a.agent_version || '—'}</td>
                    <td className="px-4 py-3 text-gray-600" title={formatDateTime(a.last_seen)}>{relativeTime(a.last_seen)}</td>
                    <td className="px-4 py-3 text-gray-600">{formatDate(a.cert_not_after)}</td>
                    {canManage && (
                      <td className="px-4 py-3 text-right">
                        {a.status !== 'retired' && (
                          <Button variant="dangerGhost" size="sm" onClick={() => setRetiring(a)}>Retire</Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {retiring && (
        <Modal
          open
          onClose={() => setRetiring(null)}
          title={`Retire ${retiring.hostname}?`}
          description="The agent is refused at its next check-in — no access to the PC is needed. It keeps enforcing cached policy until then (fail-secure)."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRetiring(null)}>Cancel</Button>
              <Button
                variant="danger"
                onClick={async () => {
                  await retireAgent(retiring.id)
                  setRetiring(null)
                }}
              >
                Retire agent
              </Button>
            </>
          }
        >
          <p className="text-sm text-gray-600">This de-enrolls the machine from the deployment. It can re-enroll later with a valid token.</p>
        </Modal>
      )}
    </>
  )
}
