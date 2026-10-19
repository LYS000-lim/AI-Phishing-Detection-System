import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../AuthContext.jsx'

export default function Logout() {
  const { user, ready, logout } = useAuth()
  const nav = useNavigate()
  const [name, setName] = useState('there')
  const [done, setDone] = useState(false)

  useEffect(() => {
    // On a full page load the account is still being fetched from
    // /api/auth/me; wait for it so the goodbye message can use the name.
    if (!ready) return
    if (user?.full_name) setName(user.full_name)
    logout().finally(() => setDone(true))
  }, [ready]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="auth-page">
      <div className="panel auth-panel">
        <h1 className="brand">
          Phish<span className="accent">Guard</span> AI
        </h1>
        <h2>Signed out</h2>
        <p className="empty">
          {done
            ? `Goodbye, ${name}. Your session has ended.`
            : 'Signing you out…'}
        </p>
        <div className="logout-actions">
          <button className="scan-btn" onClick={() => nav('/login')}>
            Log in again
          </button>
        </div>
      </div>
    </div>
  )
}
