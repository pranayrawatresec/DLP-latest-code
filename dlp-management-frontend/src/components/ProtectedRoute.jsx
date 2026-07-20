import { Navigate, useLocation } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { selectUser, selectAuthChecking } from '../store/authSlice'

// Route guard: waits for the initial session check, then either renders the
// protected content or bounces to /login (remembering where the user was
// headed so login can return them there).
export default function ProtectedRoute({ children }) {
  const user = useSelector(selectUser)
  const checking = useSelector(selectAuthChecking)
  const location = useLocation()

  if (checking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <span className="text-sm text-gray-400">Loading…</span>
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  return children
}
