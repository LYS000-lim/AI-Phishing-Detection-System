import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../../AuthContext.jsx'

export default function Login() {
  const { login } = useAuth()
  const nav = useNavigate()
  const { state } = useLocation()

  // Register page pushes {justRegistered: true, email: ...} into router state
  const justRegistered = state?.justRegistered === true
  const prefillEmail = state?.email || ''

  const [email, setEmail] = useState(prefillEmail)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const user = await login(email, password)
      nav(user.role === 'admin' ? '/admin' : '/scanner', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-page">
      <form className="panel auth-panel" onSubmit={submit}>
        <h1 className="brand">
          Phish<span className="accent">Guard</span> AI
        </h1>
        <p className="tagline">Sign in to continue</p>

        {justRegistered && (
          <div className="success-banner">
            Your account was created successfully. Please sign in below.
          </div>
        )}

        <label className="auth-label" htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          className="scan-input"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
          required
          autoFocus={!prefillEmail}
        />

        <div className="auth-label-row">
          <label className="auth-label" htmlFor="password">Password</label>
          <Link to="/forgot-password" className="auth-inline-link">Forgot password?</Link>
        </div>
        <input
          id="password"
          type="password"
          className="scan-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          required
          autoFocus={Boolean(prefillEmail)}
        />

        {error && <div className="error-box">{error}</div>}

        <button className="scan-btn auth-submit" disabled={busy} type="submit">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <p className="auth-switch">
          Don't have an account? <Link to="/register">Create one</Link>
        </p>
      </form>
    </div>
  )
}
