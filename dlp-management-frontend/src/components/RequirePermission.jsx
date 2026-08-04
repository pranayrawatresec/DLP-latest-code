import { useSelector } from 'react-redux'
import { selectHasPermission } from '../store/authSlice'
import { EmptyState } from './ui/kit'
import { ShieldIcon } from './ui/Icons'

// Route-level authorization guard. The backend is the real enforcer (403 +
// audit); this just avoids showing a page the user can't use.
export default function RequirePermission({ permission, children }) {
  const allowed = useSelector(selectHasPermission(permission))
  if (!allowed) {
    return (
      <EmptyState
        icon={<ShieldIcon className="h-6 w-6" />}
        title="You don't have access to this page"
        description="Your role doesn't include this permission. Contact a system administrator if you need it."
      />
    )
  }
  return children
}
