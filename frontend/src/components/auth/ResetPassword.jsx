import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { resetPassword } from '../../api.js'
import PasswordRequirements, { isPasswordValid } from '../PasswordRequirements.jsx'
import PasswordMatch from '../PasswordMatch.jsx'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const nav = useNavigate()

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (!isPasswordValid(password)) {
      setError('Password does not meet the requirements below')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    setBusy(true)
    try {
      await resetPassword({ token, new_password: password })
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (!token) {
    return (
      <div className="auth-page">
        <div className="panel auth-panel">
          <h1 className="brand">
            Phish<span className="accent">Guard</span> AI
          </h1>
          <div className="error-box">
            This reset link is missing its token. Please request a new one.
          </div>
          <Link to="/forgot-password" className="scan-btn auth-submit" style={{ display: 'block', textAlign: 'center' }}>
            Request a new link
          </Link>
        </div>
      </div>
    )
  }

  if (done) {
    return (
      <div className="auth-page">
        <div className="panel auth-panel">
          <h1 className="brand">
            Phish<span className="accent">Guard</span> AI
          </h1>
          <div className="success-check" aria-hidden>&#10003;</div>
          <h2 className="success-title">Password reset</h2>
          <p className="success-msg">Your password has been changed. Please sign in with your new password.</p>
          <button className="scan-btn auth-submit" onClick={() => nav('/login', { replace: true })}>
            Continue to sign in
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="auth-page">
      <form className="panel auth-panel" onSubmit={submit}>
        <h1 className="brand">
          Phish<span className="accent">Guard</span> AI
        </h1>
        <p className="tagline">Create a new password</p>

        <label className="auth-label" htmlFor="password">New password</label>
        <input
          id="password"
          type="password"
          className="scan-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
          autoFocus
        />
        <PasswordRequirements password={password} />

        <label className="auth-label" htmlFor="confirm">Confirm new password</label>
        <input
          id="confirm"
          type="password"
          className="scan-input"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          required
        />
        <PasswordMatch password={password} confirm={confirm} />

        {error && <div className="error-box">{error}</div>}

        <button className="scan-btn auth-submit" disabled={busy} type="submit">
          {busy ? 'Resetting…' : 'Reset password'}
        </button>

        <p className="auth-switch">
          <Link to="/login">Back to sign in</Link>
        </p>
      </form>
    </div>
  )
}
