import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../AuthContext.jsx'

const userLinks = [
  { to: '/scanner', label: 'Analyse URL' },
  { to: '/dashboard', label: 'My Dashboard' },
  { to: '/profile', label: 'Profile & History' },
]

const adminLinks = [
  { to: '/scanner', label: 'Analyse URL' },
  { to: '/admin', label: 'Admin Dashboard' },
  { to: '/admin/logs', label: 'Detection Logs' },
  { to: '/admin/users', label: 'User Management' },
  { to: '/admin/analytics', label: 'Model Analytics' },
  { to: '/admin/blacklist', label: 'Blacklist Database' },
]

export default function Layout() {
  const { user } = useAuth()
  const nav = useNavigate()
  const links = user?.role === 'admin' ? adminLinks : userLinks

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          Phish<span className="accent">Guard</span> AI
        </div>
        <div className="role-badge">{user?.role === 'admin' ? 'Admin' : 'User'}</div>
        <nav className="side-nav">
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.to === '/admin'}
              className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`}
            >
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="side-foot">
          <div className="user-chip">
            <div className="user-name">{user?.full_name}</div>
            <div className="user-email">{user?.email}</div>
          </div>
          <button className="link-btn" onClick={() => nav('/logout')}>
            Log out
          </button>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
