// Inline stroke icons (24x24, currentColor) — no icon dependency.
function S({ children, className = 'w-5 h-5' }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

export const DocumentIcon = (p) => (
  <S {...p}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6M9 13h6M9 17h6" />
  </S>
)
export const UploadIcon = (p) => (
  <S {...p}>
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <path d="M7 8l5-5 5 5M12 3v12" />
  </S>
)
export const LayersIcon = (p) => (
  <S {...p}>
    <path d="M12 2 2 7l10 5 10-5-10-5z" />
    <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
  </S>
)
export const ShieldIcon = (p) => (
  <S {...p}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </S>
)
export const HomeIcon = (p) => (
  <S {...p}>
    <path d="M3 11l9-8 9 8" />
    <path d="M5 10v10h14V10" />
  </S>
)
export const KeyIcon = (p) => (
  <S {...p}>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="M10.5 12.5 21 2m-4 3 3 3m-6 0 3 3" />
  </S>
)
export const MonitorIcon = (p) => (
  <S {...p}>
    <rect x="2" y="4" width="20" height="13" rx="2" />
    <path d="M8 21h8M12 17v4" />
  </S>
)
export const UsersIcon = (p) => (
  <S {...p}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
  </S>
)
export const PlusIcon = (p) => (
  <S {...p}>
    <path d="M12 5v14M5 12h14" />
  </S>
)
export const CopyIcon = (p) => (
  <S {...p}>
    <rect x="9" y="9" width="13" height="13" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </S>
)
export const CheckIcon = (p) => (
  <S {...p}>
    <path d="M20 6 9 17l-5-5" />
  </S>
)
export const XIcon = (p) => (
  <S {...p}>
    <path d="M18 6 6 18M6 6l12 12" />
  </S>
)
export const LogoutIcon = (p) => (
  <S {...p}>
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <path d="M16 17l5-5-5-5M21 12H9" />
  </S>
)
export const MenuIcon = (p) => (
  <S {...p}>
    <path d="M3 12h18M3 6h18M3 18h18" />
  </S>
)
export const AlertIcon = (p) => (
  <S {...p}>
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <path d="M12 9v4M12 17h.01" />
  </S>
)
export const UsbIcon = (p) => (
  <S {...p}>
    <rect x="7" y="9" width="10" height="12" rx="2" />
    <path d="M9 9V3h6v6" />
    <path d="M11 6h.01M13 6h.01" />
  </S>
)
export const RefreshIcon = (p) => (
  <S {...p}>
    <path d="M21 2v6h-6M3 22v-6h6" />
    <path d="M21 8a9 9 0 0 0-15-4L3 8m0 8a9 9 0 0 0 15 4l3-4" />
  </S>
)
