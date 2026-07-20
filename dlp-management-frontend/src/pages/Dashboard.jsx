import { useNavigate } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import { logout, selectUser } from '../store/authSlice'

// Placeholder console home — the real dashboard is Phase 5.
// Its job today: prove the session works and show who you are.
export default function Dashboard() {
  const user = useSelector(selectUser)
  const dispatch = useDispatch()
  const navigate = useNavigate()

  async function handleLogout() {
    await dispatch(logout())
    navigate('/login', { replace: true })
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top bar */}
      <header className="border-b border-gray-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-900">
              <svg
                className="h-4 w-4 text-white"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="text-sm font-semibold text-gray-900">
              DLP Management Console
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">{user.email}</span>
            <button
              onClick={handleLogout}
              className="rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="mx-auto max-w-5xl px-4 py-8">
        <h1 className="text-lg font-semibold text-gray-900">
          Signed in{user.displayName ? ` as ${user.displayName}` : ''}
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Phase 1 foundation — incident feeds, agents and licence views arrive in
          later phases.
        </p>

        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-sm font-medium text-gray-900">Roles</h2>
            <div className="mt-3 flex flex-wrap gap-2">
              {user.roles.map((role) => (
                <span
                  key={role}
                  className="rounded-full bg-gray-100 px-3 py-1 text-xs font-medium text-gray-800"
                >
                  {role}
                </span>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-sm font-medium text-gray-900">Permissions</h2>
            <div className="mt-3 flex flex-wrap gap-2">
              {user.permissions.map((perm) => (
                <span
                  key={perm}
                  className="rounded-full border border-gray-200 px-3 py-1 text-xs text-gray-600"
                >
                  {perm}
                </span>
              ))}
            </div>
          </section>
        </div>
      </main>
    </div>
  )
}
