import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { forgotPassword, resetPassword } from '../../api.js'
import PasswordRequirements, { isPasswordValid } from '../PasswordRequirements.jsx'
import PasswordMatch from '../PasswordMatch.jsx'

// Two steps on one page: (1) email -> a 6-digit code is sent to that
// Gmail/email inbox, (2) enter the code + new password.
export default function ForgotPassword() {
  const nav = useNavigate()
  const [step, setStep] = useState('email') // 'email' | 'code' | 'done'
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')

  const sendCode = async (e) => {
    e?.preventDefault()
    setError('')
    setInfo('')
    setBusy(true)
    try {
      await forgotPassword(email)
      setStep('code')
      setInfo(`If ${email} is registered, a 6-digit code has been sent to it. It expires in 10 minutes.`)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const submitReset = async (e) => {
    e.preventDefault()
    setError('')
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from your email.')
      return
    }
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
      await resetPassword({ email, code, new_password: password })
      setStep('done')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const brand = (
    <h1 className="brand">
      Phish<span className="accent">Guard</span> AI
    </h1>
  )

  if (step === 'done') {
    return (
      <div className="auth-page">
        <div className="panel auth-panel">
          {brand}
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

  if (step === 'code') {
    return (
      <div className="auth-page">
        <form className="panel auth-panel" onSubmit={submitReset}>
          {brand}
          <p className="tagline">Enter verification code</p>
          {info && <p className="xai-note" style={{ marginTop: 0 }}>{info}</p>}

          <label className="auth-label" htmlFor="code">Verification code</label>
          <input
            id="code"
            className="scan-input"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            style={{ letterSpacing: 6, fontSize: 18, textAlign: 'center' }}
            required
            autoFocus
          />

          <label className="auth-label" htmlFor="password">New password</label>
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
            Didn't get it? Check spam, or{' '}
            <button type="button" className="link-btn" disabled={busy} onClick={sendCode}>resend code</button>
            {' · '}
            <button type="button" className="link-btn" onClick={() => { setStep('email'); setError(''); setCode('') }}>change email</button>
          </p>
        </form>
      </div>
    )
  }

  return (
    <div className="auth-page">
      <form className="panel auth-panel" onSubmit={sendCode}>
        {brand}
        <p className="tagline">Reset your password</p>
        <p className="xai-note" style={{ marginTop: 0 }}>
          Enter the email on your account and we'll send a 6-digit
          verification code to your inbox.
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
          {busy ? 'Sending…' : 'Send code'}
        </button>

        <p className="auth-switch">
          <Link to="/login">Back to sign in</Link>
        </p>
      </form>
    </div>
  )
}
