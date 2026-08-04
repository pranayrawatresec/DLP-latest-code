import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import { logout, selectUser } from '../../store/authSlice'
import { MenuIcon, LogoutIcon } from '../ui/Icons'

function initials(user) {
  const base = user?.displayName || user?.email || '?'
  return base.trim().slice(0, 2).toUpperCase()
}

export default function Topbar({ onMenu }) {
  const user = useSelector(selectUser)
  const dispatch = useDispatch()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const onClick = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false)
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  async function handleLogout() {
    await dispatch(logout())
    navigate('/login', { replace: true })
  }

  return (
    <header className="flex h-14 items-center justify-between border-b border-gray-200 bg-white px-4">
      <button
        onClick={onMenu}
        className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 md:hidden"
        aria-label="Open menu"
      >
        <MenuIcon className="h-5 w-5" />
      </button>
      <div className="flex-1" />

      <div className="relative" ref={ref}>
        <button
          onClick={() => setOpen((v) => !v)}
          className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-gray-100"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-100 text-xs font-semibold text-indigo-700">
            {initials(user)}
          </span>
          <span className="hidden text-left sm:block">
            <span className="block text-sm font-medium text-gray-900">{user?.email}</span>
            <span className="block text-xs text-gray-400">{(user?.roles || []).join(', ')}</span>
          </span>
        </button>

        {open && (
          <div className="absolute right-0 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-1 shadow-lg">
            <div className="border-b border-gray-100 px-3 py-2">
              <div className="text-sm font-medium text-gray-900">{user?.displayName || 'Administrator'}</div>
              <div className="truncate text-xs text-gray-500">{user?.email}</div>
            </div>
            <button
              onClick={handleLogout}
              className="mt-1 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <LogoutIcon className="h-4 w-4" />
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
