import { useState } from 'react'
import { Link } from 'react-router-dom'
import { forgotPassword } from '../../api.js'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await forgotPassword(email)
      setSent(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (sent) {
    return (
      <div className="auth-page">
        <div className="panel auth-panel">
          <h1 className="brand">
            Phish<span className="accent">Guard</span> AI
          </h1>
          <div className="success-check" aria-hidden>&#10003;</div>
          <h2 className="success-title">Check your email</h2>
          <p className="success-msg">
            If <b>{email}</b> is registered, we've sent a password reset link
            to that address. The link expires in 30 minutes.
          </p>
          <Link to="/login" className="scan-btn auth-submit" style={{ display: 'block', textAlign: 'center' }}>
            Back to sign in
          </Link>
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
        <p className="tagline">Reset your password</p>
        <p className="xai-note" style={{ marginTop: 0 }}>
          Enter the email on your account and we'll send you a link to reset
          your password.
        </p>

        <label className="auth-label" htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          className="scan-input"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
          required
          autoFocus
        />

        {error && <div className="error-box">{error}</div>}

        <button className="scan-btn auth-submit" disabled={busy} type="submit">
          {busy ? 'Sending…' : 'Send reset link'}
        </button>

        <p className="auth-switch">
          <Link to="/login">Back to sign in</Link>
        </p>
      </form>
    </div>
  )
}
