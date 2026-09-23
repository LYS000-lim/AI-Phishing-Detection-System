import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './AuthContext.jsx'
import Layout from './components/Layout.jsx'

// Every route below used to be an eager top-level import, which in Vite dev
// mode (unbundled native ESM) means the browser fires a separate HTTP
// request for every single page's module -- and everything it imports --
// on EVERY navigation, regardless of which one route is actually being
// shown. That's ~20+ round-trips just to render one page. React.lazy()
// defers each route's module (and its own dependencies, e.g. chart.js only
// loading for the two dashboard pages that use it) until that route is
// actually visited, cutting a typical page load down to the 1-2 requests
// it actually needs. (A production `npm run build` bundles everything and
// wouldn't have shown this either way -- this only mattered for the `vite
// dev` server.)
const Profile = lazy(() => import('./components/Profile.jsx'))

const Login = lazy(() => import('./components/auth/Login.jsx'))
const Register = lazy(() => import('./components/auth/Register.jsx'))
const Logout = lazy(() => import('./components/auth/Logout.jsx'))
const ForgotPassword = lazy(() => import('./components/auth/ForgotPassword.jsx'))

const Scanner = lazy(() => import('./components/user/Scanner.jsx'))
const UserDashboard = lazy(() => import('./components/user/UserDashboard.jsx'))
const UserHistory = lazy(() => import('./components/user/UserHistory.jsx'))
const BrowserExtension = lazy(() => import('./components/user/BrowserExtension.jsx'))
const BlockedWebsites = lazy(() => import('./components/user/BlockedWebsites.jsx'))

const AdminDashboard = lazy(() => import('./components/admin/AdminDashboard.jsx'))
const AdminDetectionLogs = lazy(() => import('./components/admin/AdminDetectionLogs.jsx'))
const AdminUserManagement = lazy(() => import('./components/admin/AdminUserManagement.jsx'))
const ModelAnalytics = lazy(() => import('./components/admin/ModelAnalytics.jsx'))
const AdminBlacklist = lazy(() => import('./components/admin/AdminBlacklist.jsx'))
const AdminScanner = lazy(() => import('./components/admin/AdminScanner.jsx'))
const AdminExtensionMonitoring = lazy(() => import('./components/admin/AdminExtensionMonitoring.jsx'))

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
        <Suspense fallback={<div className="empty">Loading…</div>}>
        <Routes>
          {/* Interfaces 1-3: Auth (no layout chrome) */}
          <Route path="/login" element={<GuestRoute><Login /></GuestRoute>} />
          <Route path="/register" element={<GuestRoute><Register /></GuestRoute>} />
          <Route path="/logout" element={<Logout />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<Navigate to="/forgot-password" replace />} />

          {/* Everything else lives inside the shared Layout with the sidebar nav */}
          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            {/* Interface 4: Analyse URL (both roles) */}
            <Route path="/scanner" element={<Scanner />} />

            {/* Interfaces 5-6: User-only */}
            <Route path="/dashboard" element={<UserDashboard />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/history" element={<UserHistory />} />
            <Route path="/browser-extension" element={<BrowserExtension />} />
            <Route path="/blocked-websites" element={<BlockedWebsites />} />

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
            <Route
              path="/admin/scanner"
              element={<ProtectedRoute adminOnly><AdminScanner /></ProtectedRoute>}
            />
            <Route
              path="/admin/extension-monitoring"
              element={<ProtectedRoute adminOnly><AdminExtensionMonitoring /></ProtectedRoute>}
            />
            </Route>

          <Route path="*" element={<Navigate to="/scanner" replace />} />
        </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  )
}
