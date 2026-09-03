import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../AuthContext.jsx'

export default function Logout() {
  const { user, logout } = useAuth()
  const nav = useNavigate()
  const [name] = useState(user?.full_name || 'there')
  const [done, setDone] = useState(false)

  useEffect(() => {
    logout().finally(() => setDone(true))
  }, [logout])

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
          <Link className="link-btn" to="/login">
            Return to home
          </Link>
        </div>
      </div>
    </div>
  )
}
