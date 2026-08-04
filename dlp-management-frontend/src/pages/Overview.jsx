import { Link } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { selectUser, selectHasPermission } from '../store/authSlice'
import { useGetAgentsQuery, useGetEnrollmentTokensQuery, useGetUsersQuery } from '../store/apiSlice'
import { Card, PageHeader, StatCard, Badge } from '../components/ui/kit'
import { MonitorIcon, KeyIcon, UsersIcon } from '../components/ui/Icons'

export default function Overview() {
  const user = useSelector(selectUser)
  const canAgents = useSelector(selectHasPermission('agents.read'))
  const canTokens = useSelector(selectHasPermission('enrollment.manage'))
  const canUsers = useSelector(selectHasPermission('users.manage'))

  // Hooks must run unconditionally — skip the fetch when the user lacks access.
  const agents = useGetAgentsQuery(undefined, { skip: !canAgents })
  const tokens = useGetEnrollmentTokensQuery(undefined, { skip: !canTokens })
  const users = useGetUsersQuery(undefined, { skip: !canUsers })

  const activeAgents = (agents.data || []).filter((a) => a.status === 'active').length
  const activeTokens = (tokens.data || []).filter((t) => t.status === 'active').length

  return (
    <>
      <PageHeader
        title={`Welcome${user?.displayName ? `, ${user.displayName}` : ''}`}
        description="On-premise endpoint data leak prevention. Everything here stays on your network."
      />

      <div className="mb-4 flex flex-wrap gap-2">
        {(user?.roles || []).map((r) => <Badge key={r} tone="indigo">{r}</Badge>)}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {canAgents && (
          <StatCard
            icon={<MonitorIcon className="h-5 w-5" />}
            label="Enrolled agents"
            value={(agents.data || []).length}
            hint={`${activeAgents} active`}
            loading={agents.isLoading}
          />
        )}
        {canTokens && (
          <StatCard
            icon={<KeyIcon className="h-5 w-5" />}
            label="Active enrollment tokens"
            value={activeTokens}
            hint={`${(tokens.data || []).length} total`}
            loading={tokens.isLoading}
          />
        )}
        {canUsers && (
          <StatCard
            icon={<UsersIcon className="h-5 w-5" />}
            label="Administrators"
            value={(users.data || []).length}
            loading={users.isLoading}
          />
        )}
      </div>

      {(canTokens || canUsers) && (
        <Card className="mt-6 p-6">
          <h2 className="text-sm font-semibold text-gray-900">Getting started</h2>
          <p className="mt-1 text-sm text-gray-500">Stand up protection across your endpoints in four steps.</p>
          <ol className="mt-4 space-y-3">
            <Step n={1} done={canUsers} title="Create administrator accounts" to={canUsers ? '/administrators' : null}
              body="Add teammates with least-privilege roles — policy authors, incident reviewers, auditors." />
            <Step n={2} title="Mint an enrollment token" to={canTokens ? '/enrollment-tokens' : null}
              body="One token per rollout wave, sized to the number of PCs, with a short expiry." />
            <Step n={3} title="Deploy the agent to your PCs"
              body="IT embeds the token in the installer and pushes it via Group Policy / SCCM / Intune — in staged rings." />
            <Step n={4} title="Watch agents check in" to={canAgents ? '/agents' : null}
              body="Each PC enrolls once and appears on the Agents page, checking in over mutual TLS." />
          </ol>
        </Card>
      )}
    </>
  )
}

function Step({ n, title, body, to, done }) {
  const inner = (
    <div className="flex gap-3">
      <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${done ? 'bg-green-100 text-green-700' : 'bg-indigo-100 text-indigo-700'}`}>{n}</span>
      <div>
        <div className="text-sm font-medium text-gray-900">{title}{to && <span className="ml-1 text-indigo-600">→</span>}</div>
        <div className="text-sm text-gray-500">{body}</div>
      </div>
    </div>
  )
  return to ? <li><Link to={to} className="block rounded-lg -mx-2 px-2 py-1 hover:bg-gray-50">{inner}</Link></li> : <li className="px-0 py-1">{inner}</li>
}
