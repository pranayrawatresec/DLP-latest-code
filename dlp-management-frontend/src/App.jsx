import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Agents from './pages/Agents'
import EnrollmentTokens from './pages/EnrollmentTokens'
import Administrators from './pages/Administrators'
import Sessions from './pages/Sessions'
import AuditLog from './pages/AuditLog'
import Incidents from './pages/Incidents'
import ProtectedDocuments from './pages/ProtectedDocuments'
import TrustedDestinations from './pages/TrustedDestinations'
import TrustedReaders from './pages/TrustedReaders'
import AppLayout from './components/layout/AppLayout'
import ProtectedRoute from './components/ProtectedRoute'
import RequirePermission from './components/RequirePermission'

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Overview />} />
        <Route
          path="agents"
          element={<RequirePermission permission="agents.read"><Agents /></RequirePermission>}
        />
        <Route
          path="enrollment-tokens"
          element={<RequirePermission permission="enrollment.manage"><EnrollmentTokens /></RequirePermission>}
        />
        <Route
          path="administrators"
          element={<RequirePermission permission="users.manage"><Administrators /></RequirePermission>}
        />
        <Route
          path="incidents"
          element={<RequirePermission permission="incidents.read_metadata"><Incidents /></RequirePermission>}
        />
        <Route
          path="protected-documents"
          element={<RequirePermission permission="protect:read"><ProtectedDocuments /></RequirePermission>}
        />
        <Route
          path="trusted-destinations"
          element={<RequirePermission permission="trusted_destinations:read"><TrustedDestinations /></RequirePermission>}
        />
        <Route
          path="trusted-readers"
          element={<RequirePermission permission="trusted_readers:read"><TrustedReaders /></RequirePermission>}
        />
        <Route
          path="sessions"
          element={<RequirePermission permission="sessions.manage"><Sessions /></RequirePermission>}
        />
        <Route
          path="audit"
          element={<RequirePermission permission="audit.read"><AuditLog /></RequirePermission>}
        />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
