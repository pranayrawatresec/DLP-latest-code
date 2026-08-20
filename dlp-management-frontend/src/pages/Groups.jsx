import { useState } from 'react'
import { useSelector } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import {
  useGetGroupsQuery,
  useCreateGroupMutation,
  useUpdateGroupMutation,
  useDeleteGroupMutation,
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
  InlineAlert,
} from '../components/ui/kit'
import { UsersIcon, PlusIcon } from '../components/ui/Icons'
import Modal from '../components/ui/Modal'

// --- create / rename modal --------------------------------------------------

function GroupFormModal({ mode, group, onClose }) {
  const isEdit = mode === 'edit'
  const [createGroup, { isLoading: creating }] = useCreateGroupMutation()
  const [updateGroup, { isLoading: updating }] = useUpdateGroupMutation()
  const saving = creating || updating

  const [name, setName] = useState(group?.name || '')
  const [description, setDescription] = useState(group?.description || '')
  const [error, setError] = useState('')

  const canSubmit = name.trim().length > 0 && !saving

  async function submit() {
    setError('')
    try {
      if (isEdit) {
        await updateGroup({ id: group.id, name: name.trim(), description: description.trim() }).unwrap()
      } else {
        await createGroup({ name: name.trim(), description: description.trim() }).unwrap()
      }
      onClose()
    } catch (e) {
      setError(e?.data?.error || 'Could not save the group.')
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? 'Edit group' : 'New group'}
      description="A group is a named set of endpoints that can carry its own read-deny policy — so you can pilot enforcement on a subset or give a department different rules."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create group'}
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-4">
          <InlineAlert>{error}</InlineAlert>
        </div>
      )}
      <Field label="Group name" htmlFor="grp-name">
        <Input
          id="grp-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Pilot, Finance, Engineering"
          maxLength={64}
        />
      </Field>
      <Field label="Description (optional)" htmlFor="grp-desc" hint="What is this group for?">
        <Input
          id="grp-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="e.g. Enforce pilot ring"
          maxLength={256}
        />
      </Field>
    </Modal>
  )
}

// --- page -------------------------------------------------------------------

export default function Groups() {
  const canWrite = useSelector(selectHasPermission('groups:write'))
  const canEditPolicy = useSelector(selectHasPermission('read_deny_policy:read'))
  const navigate = useNavigate()
  const { data: groups = [], isLoading, isError } = useGetGroupsQuery()
  const [deleteGroup, { isLoading: deleting }] = useDeleteGroupMutation()

  const [form, setForm] = useState(null) // { mode:'create'|'edit', group? }
  const [removing, setRemoving] = useState(null)
  const [deleteErr, setDeleteErr] = useState('')

  async function confirmDelete() {
    setDeleteErr('')
    try {
      await deleteGroup(removing.id).unwrap()
      setRemoving(null)
    } catch (e) {
      setDeleteErr(e?.data?.error || 'Could not delete the group.')
    }
  }

  return (
    <>
      <PageHeader
        title="Endpoint groups"
        description="Target the read-deny policy at a subset of machines: pilot enforcement on a ring, or give a department different rules. The Default group holds every machine not assigned elsewhere and uses the global policy. Assign machines on the Agents page."
        action={
          canWrite && (
            <Button onClick={() => setForm({ mode: 'create' })}>
              <PlusIcon className="h-4 w-4" /> New group
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
            <InlineAlert>Could not load groups. Try reloading the page.</InlineAlert>
          </div>
        ) : groups.length === 0 ? (
          <EmptyState
            icon={<UsersIcon className="h-6 w-6" />}
            title="No groups yet"
            description="Create a group to target policy at a subset of endpoints."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 font-medium">Group</th>
                  <th className="px-4 py-3 font-medium">Machines</th>
                  <th className="px-4 py-3 font-medium">Policy</th>
                  <th className="px-4 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {groups.map((g) => (
                  <tr key={g.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900">{g.name}</span>
                        {g.isDefault && <Badge tone="gray">Default</Badge>}
                      </div>
                      {g.description && <div className="text-xs text-gray-500 mt-0.5">{g.description}</div>}
                    </td>
                    <td className="px-4 py-3 text-gray-700 whitespace-nowrap">{g.agentCount}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {g.isDefault ? (
                        <Badge tone="blue">Global policy</Badge>
                      ) : g.hasPolicyOverride ? (
                        <Badge tone="indigo">Custom policy</Badge>
                      ) : (
                        <Badge tone="gray">Inherits Default</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        {canEditPolicy && (
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => navigate(`/read-deny-policy?group=${g.id}`)}
                          >
                            Edit policy
                          </Button>
                        )}
                        {canWrite && !g.isDefault && (
                          <>
                            <Button variant="ghost" size="sm" onClick={() => setForm({ mode: 'edit', group: g })}>
                              Rename
                            </Button>
                            <Button
                              variant="dangerGhost"
                              size="sm"
                              onClick={() => {
                                setDeleteErr('')
                                setRemoving(g)
                              }}
                            >
                              Delete
                            </Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {form && (
        <GroupFormModal mode={form.mode} group={form.group} onClose={() => setForm(null)} />
      )}

      {removing && (
        <Modal
          open
          onClose={() => setRemoving(null)}
          title="Delete this group?"
          description="Its machines return to the Default group (and the global policy). Any custom policy for this group is discarded. This cannot be undone."
          footer={
            <>
              <Button variant="secondary" onClick={() => setRemoving(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={confirmDelete} disabled={deleting}>
                {deleting ? 'Deleting…' : 'Delete group'}
              </Button>
            </>
          }
        >
          {deleteErr && (
            <div className="mb-3">
              <InlineAlert>{deleteErr}</InlineAlert>
            </div>
          )}
          <div className="text-sm text-gray-700">
            <span className="font-medium">{removing.name}</span>
            {removing.agentCount > 0 && (
              <span className="text-gray-500"> — {removing.agentCount} machine(s) will return to Default</span>
            )}
          </div>
        </Modal>
      )}
    </>
  )
}
