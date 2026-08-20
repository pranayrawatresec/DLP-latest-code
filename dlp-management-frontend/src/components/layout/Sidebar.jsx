import { NavLink } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { selectUser } from '../../store/authSlice'
import { ShieldIcon, HomeIcon, KeyIcon, MonitorIcon, UsersIcon, LogoutIcon, DocumentIcon, AlertIcon, UsbIcon, AppWindowIcon, LayersIcon } from '../ui/Icons'

// Nav config — each item declares the permission it needs (null = always).
const NAV = [
  { to: '/', label: 'Overview', icon: HomeIcon, end: true, permission: null },
  { to: '/incidents', label: 'Incidents', icon: AlertIcon, permission: 'incidents.read_metadata' },
  { to: '/protected-documents', label: 'Protected documents', icon: DocumentIcon, permission: 'protect:read' },
  { to: '/trusted-destinations', label: 'Trusted USB devices', icon: UsbIcon, permission: 'trusted_destinations:read' },
  { to: '/trusted-readers', label: 'Trusted applications', icon: AppWindowIcon, permission: 'trusted_readers:read' },
  { to: '/read-deny-policy', label: 'Read-deny policy', icon: ShieldIcon, permission: 'read_deny_policy:read' },
  { to: '/groups', label: 'Endpoint groups', icon: LayersIcon, permission: 'groups:read' },
  { to: '/agents', label: 'Agents', icon: MonitorIcon, permission: 'agents.read' },
  { to: '/enrollment-tokens', label: 'Enrollment tokens', icon: KeyIcon, permission: 'enrollment.manage' },
  { to: '/administrators', label: 'Administrators', icon: UsersIcon, permission: 'users.manage' },
  { to: '/sessions', label: 'Active sessions', icon: LogoutIcon, permission: 'sessions.manage' },
  { to: '/audit', label: 'Audit log', icon: ShieldIcon, permission: 'audit.read' },
]

export default function Sidebar({ onNavigate }) {
  const user = useSelector(selectUser)
  const perms = user?.permissions || []
  const items = NAV.filter((i) => !i.permission || perms.includes(i.permission))

  return (
    <div className="flex h-full flex-col bg-white">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2 border-b border-gray-200 px-4">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-900 text-white">
          <ShieldIcon className="h-5 w-5" />
        </span>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-gray-900">DLP Console</div>
          <div className="text-[11px] text-gray-400">Endpoint Protection</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
              }`
            }
          >
            <Icon className="h-5 w-5 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-gray-200 p-3">
        <p className="px-2 text-[11px] leading-relaxed text-gray-400">
          On-premise · air-gapped · every action audited
        </p>
      </div>
    </div>
  )
}
