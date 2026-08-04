import { useState } from 'react'
import { useSelector } from 'react-redux'
import { selectUser } from '../store/authSlice'
import { useGetUsersQuery, useCreateUserMutation, useUpdateUserMutation } from '../store/apiSlice'
import { Card, PageHeader, Button, Badge, EmptyState, Spinner, Field, Input, InlineAlert } from '../components/ui/kit'
import { UsersIcon, PlusIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'

const ALL_ROLES = ['sysadmin', 'policy_author', 'incident_reviewer', 'auditor']

export default function Administrators() {
  const me = useSelector(selectUser)
  const { data: users = [], isLoading } = useGetUsersQuery()
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState(null)

  return (
    <>
      <PageHeader
        title="Administrators"
        description="Console accounts and their roles. Roles are separated so no one person can both leak data and erase the proof."
        action={<Button onClick={() => setShowCreate(true)}><PlusIcon className="h-4 w-4" /> Add administrator</Button>}
      />

      <Card>
        {isLoading ? (
          <div className="flex justify-center py-16"><Spinner /></div>
        ) : users.length === 0 ? (
          <EmptyState icon={<UsersIcon className="h-6 w-6" />} title="No administrators" description="Add one to get started." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Email</th>
                  <th className="px-4 py-3 font-medium">Roles</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-900">{u.email}</div>
                      {u.displayName && <div className="text-xs text-gray-400">{u.displayName}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {u.roles.map((r) => <Badge key={r} tone="indigo">{r}</Badge>)}
                        {u.sodWarning && <Badge tone="amber" >⚠ separation of duties</Badge>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {u.disabled ? <Badge tone="red">disabled</Badge> : <Badge tone="green">active</Badge>}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {u.id === me?.id ? (
                        <span className="text-xs text-gray-400">you</span>
                      ) : (
                        <Button variant="secondary" size="sm" onClick={() => setEditing(u)}>Manage</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
      {editing && <ManageUserModal user={editing} onClose={() => setEditing(null)} />}
    </>
  )
}

function RolePicker({ selected, onToggle }) {
  return (
    <div className="space-y-2">
      {ALL_ROLES.map((role) => (
        <label key={role} className="flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2 text-sm hover:bg-gray-50">
          <input type="checkbox" checked={selected.includes(role)} onChange={() => onToggle(role)} className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600" />
          <span className="font-medium text-gray-800">{role}</span>
        </label>
      ))}
    </div>
  )
}

function CreateUserModal({ onClose }) {
  const [createUser, { isLoading }] = useCreateUserMutation()
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [roles, setRoles] = useState([])
  const [error, setError] = useState(null)

  const toggle = (r) => setRoles((rs) => (rs.includes(r) ? rs.filter((x) => x !== r) : [...rs, r]))

  async function submit() {
    setError(null)
    try {
      await createUser({ email, displayName, password, roles }).unwrap()
      onClose()
    } catch (e) {
      setError(e?.data?.error || 'Could not create administrator')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add administrator"
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button onClick={submit} disabled={isLoading}>{isLoading ? 'Creating…' : 'Create'}</Button></>}
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}
      {roles.length > 1 && <div className="mb-4"><InlineAlert tone="amber">Multiple roles weaken separation of duties. This is allowed but flagged.</InlineAlert></div>}
      <Field label="Email" htmlFor="u-email"><Input id="u-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@organisation.gov" /></Field>
      <Field label="Display name" htmlFor="u-name"><Input id="u-name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></Field>
      <Field label="Temporary password" htmlFor="u-pw" hint="At least 12 characters."><Input id="u-pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      <Field label="Roles"><RolePicker selected={roles} onToggle={toggle} /></Field>
    </Modal>
  )
}

function ManageUserModal({ user, onClose }) {
  const [updateUser, { isLoading }] = useUpdateUserMutation()
  const [roles, setRoles] = useState(user.roles)
  const [error, setError] = useState(null)
  const toggle = (r) => setRoles((rs) => (rs.includes(r) ? rs.filter((x) => x !== r) : [...rs, r]))

  async function save(patch) {
    setError(null)
    try {
      await updateUser({ id: user.id, ...patch }).unwrap()
      onClose()
    } catch (e) {
      setError(e?.data?.error || 'Could not update administrator')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Manage ${user.email}`}
      footer={
        <>
          <Button variant={user.disabled ? 'secondary' : 'dangerGhost'} onClick={() => save({ disabled: !user.disabled })} disabled={isLoading}>
            {user.disabled ? 'Enable account' : 'Disable account'}
          </Button>
          <Button onClick={() => save({ roles })} disabled={isLoading || roles.length === 0}>Save roles</Button>
        </>
      }
    >
      {error && <div className="mb-4"><InlineAlert>{error}</InlineAlert></div>}
      <p className="mb-4 text-sm text-gray-500">Disabling an account revokes its live sessions immediately.</p>
      <Field label="Roles"><RolePicker selected={roles} onToggle={toggle} /></Field>
    </Modal>
  )
}
