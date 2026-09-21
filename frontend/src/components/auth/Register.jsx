import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../AuthContext.jsx'
import PasswordRequirements, { isPasswordValid } from '../PasswordRequirements.jsx'
import PasswordMatch from '../PasswordMatch.jsx'

const REDIRECT_SECONDS = 4

export default function Register() {
  const { register } = useAuth()
  const nav = useNavigate()

  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [emailError, setEmailError] = useState('')

  // Success-screen state
  const [success, setSuccess] = useState(null)   // { message, user } | null
  const [countdown, setCountdown] = useState(REDIRECT_SECONDS)

  // Once the success screen is showing, run a countdown and auto-redirect.
  useEffect(() => {
    if (!success) return
    if (countdown <= 0) {
      nav('/login', { replace: true, state: { justRegistered: true, email: success.user.email } })
      return
    }
    const t = setTimeout(() => setCountdown((c) => c - 1), 1000)
    return () => clearTimeout(t)
  }, [success, countdown, nav])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setEmailError('')
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
      const res = await register(fullName, email, password)
      setSuccess(res)
    } catch (err) {
      if (err.message.toLowerCase().includes('already been registered')) {
        setEmailError(err.message)
      } else {
        setError(err.message)
      }
    } finally {
      setBusy(false)
    }
  }

  // ---------- Success view ----------
  if (success) {
    return (
      <div className="auth-page">
        <div className="panel auth-panel">
          <h1 className="brand">
            Phish<span className="accent">Guard</span> AI
          </h1>

          <div className="success-check" aria-hidden>&#10003;</div>
          <h2 className="success-title">Registration successful</h2>

          <p className="success-msg">
            Welcome, <b>{success.user.full_name}</b>. Your account has been
            created successfully. Please sign in with your email and
            password to continue.
          </p>

          <div className="success-details">
            <div><span className="k">Email</span><span className="mono">{success.user.email}</span></div>
            <div><span className="k">Role</span><span className="mono">{success.user.role}</span></div>
          </div>

          <button
            className="scan-btn auth-submit"
            onClick={() => nav('/login', {
              replace: true,
              state: { justRegistered: true, email: success.user.email },
            })}
          >
            Continue to sign in
          </button>

          <p className="auth-switch">
            Redirecting to the login page in {countdown} second{countdown === 1 ? '' : 's'}…
          </p>
        </div>
      </div>
    )
  }

  // ---------- Form view ----------
  return (
    <div className="auth-page">
      <form className="panel auth-panel" onSubmit={submit}>
        <h1 className="brand">
          Phish<span className="accent">Guard</span> AI
        </h1>
        <p className="tagline">Create your account</p>

        <label className="auth-label" htmlFor="full_name">Full name</label>
        <input
          id="full_name"
          className="scan-input"
          value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          required
          autoFocus
        />

        <label className="auth-label" htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          className="scan-input"
          value={email}
          onChange={(e) => { setEmail(e.target.value); setEmailError('') }}
          autoComplete="email"
          required
        />
        {emailError && <p className="password-match bad" style={{ marginTop: 4 }}>{emailError}</p>}

        <label className="auth-label" htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          className="scan-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
        />
        <PasswordRequirements password={password} />

        <label className="auth-label" htmlFor="confirm">Confirm password</label>
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
          {busy ? 'Creating account…' : 'Create account'}
        </button>

        <p className="auth-switch">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </form>
    </div>
  )
}
