import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './AuthContext.jsx'
import Layout from './components/Layout.jsx'

import Login from './components/auth/Login.jsx'
import Register from './components/auth/Register.jsx'
import Logout from './components/auth/Logout.jsx'

import Scanner from './components/user/Scanner.jsx'
import UserDashboard from './components/user/UserDashboard.jsx'
import UserProfile from './components/user/UserProfile.jsx'

import AdminDashboard from './components/admin/AdminDashboard.jsx'
import AdminDetectionLogs from './components/admin/AdminDetectionLogs.jsx'
import AdminUserManagement from './components/admin/AdminUserManagement.jsx'
import ModelAnalytics from './components/admin/ModelAnalytics.jsx'
import AdminBlacklist from './components/admin/AdminBlacklist.jsx'

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, ready } = useAuth()
  if (!ready) return <div className="empty">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && user.role !== 'admin')
    return <Navigate to="/scanner" replace />
  return children
}

function GuestRoute({ children }) {
  const { user, ready } = useAuth()
  if (!ready) return <div className="empty">Loading…</div>
  if (user) return <Navigate to={user.role === 'admin' ? '/admin' : '/scanner'} replace />
  return children
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Interfaces 1-3: Auth (no layout chrome) */}
          <Route path="/login" element={<GuestRoute><Login /></GuestRoute>} />
          <Route path="/register" element={<GuestRoute><Register /></GuestRoute>} />
          <Route path="/logout" element={<Logout />} />

          {/* Everything else lives inside the shared Layout with the sidebar nav */}
          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            {/* Interface 4: Analyse URL (both roles) */}
            <Route path="/scanner" element={<Scanner />} />

            {/* Interfaces 5-6: User-only */}
            <Route path="/dashboard" element={<UserDashboard />} />
            <Route path="/profile" element={<UserProfile />} />

            {/* Interfaces 7-10: Admin-only */}
            <Route
              path="/admin"
              element={<ProtectedRoute adminOnly><AdminDashboard /></ProtectedRoute>}
            />
            <Route
              path="/admin/logs"
              element={<ProtectedRoute adminOnly><AdminDetectionLogs /></ProtectedRoute>}
            />
            <Route
              path="/admin/users"
              element={<ProtectedRoute adminOnly><AdminUserManagement /></ProtectedRoute>}
            />
            <Route
              path="/admin/analytics"
              element={<ProtectedRoute adminOnly><ModelAnalytics /></ProtectedRoute>}
            />
            <Route
              path="/admin/blacklist"
              element={<ProtectedRoute adminOnly><AdminBlacklist /></ProtectedRoute>}
            />
            </Route>

          <Route path="*" element={<Navigate to="/scanner" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
