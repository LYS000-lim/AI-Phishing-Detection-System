import { useEffect, useState } from 'react'
import {
  changePassword, myDetections, updateProfile,
} from '../../api.js'
import { useAuth } from '../../AuthContext.jsx'

export default function UserProfile() {
  const { user, refresh } = useAuth()
  const [fullName, setFullName] = useState(user?.full_name || '')
  const [email, setEmail] = useState(user?.email || '')
  const [savingProfile, setSavingProfile] = useState(false)
  const [profileMsg, setProfileMsg] = useState('')

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [savingPwd, setSavingPwd] = useState(false)
  const [pwdMsg, setPwdMsg] = useState('')

  const [history, setHistory] = useState([])
  const [q, setQ] = useState('')
  const [loadingHist, setLoadingHist] = useState(true)

  const loadHistory = () => {
    setLoadingHist(true)
    myDetections(q)
      .then(setHistory)
      .finally(() => setLoadingHist(false))
  }

  useEffect(() => {
    loadHistory()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const saveProfile = async (e) => {
    e.preventDefault()
    setSavingProfile(true)
    setProfileMsg('')
    try {
      await updateProfile({ full_name: fullName, email })
      await refresh()
      setProfileMsg('Profile updated.')
    } catch (err) {
      setProfileMsg(err.message)
    } finally {
      setSavingProfile(false)
    }
  }

  const savePassword = async (e) => {
    e.preventDefault()
    setPwdMsg('')
    if (next !== confirm) {
      setPwdMsg('New passwords do not match')
      return
    }
    setSavingPwd(true)
    try {
      await changePassword({ current_password: current, new_password: next })
      setCurrent(''); setNext(''); setConfirm('')
      setPwdMsg('Password changed.')
    } catch (err) {
      setPwdMsg(err.message)
    } finally {
      setSavingPwd(false)
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Profile &amp; History</h2>
        <p className="tagline">Update your details and review every URL you have scanned.</p>
      </div>

      <div className="split-2">
        <section className="panel">
          <h3>Update profile</h3>
          <form onSubmit={saveProfile}>
            <label className="auth-label">Full name</label>
            <input className="scan-input" value={fullName}
                   onChange={(e) => setFullName(e.target.value)} required />
            <label className="auth-label">Email</label>
            <input className="scan-input" type="email" value={email}
                   onChange={(e) => setEmail(e.target.value)} required />
            <button className="scan-btn" disabled={savingProfile}>
              {savingProfile ? 'Saving…' : 'Save profile'}
            </button>
            {profileMsg && <p className="xai-note" style={{ marginTop: 10 }}>{profileMsg}</p>}
          </form>
        </section>

        <section className="panel">
          <h3>Change password</h3>
          <form onSubmit={savePassword}>
            <label className="auth-label">Current password</label>
            <input className="scan-input" type="password" value={current}
                   onChange={(e) => setCurrent(e.target.value)} required />
            <label className="auth-label">New password</label>
            <input className="scan-input" type="password" value={next}
                   onChange={(e) => setNext(e.target.value)} required />
            <label className="auth-label">Confirm new password</label>
            <input className="scan-input" type="password" value={confirm}
                   onChange={(e) => setConfirm(e.target.value)} required />
            <button className="scan-btn" disabled={savingPwd}>
              {savingPwd ? 'Saving…' : 'Change password'}
            </button>
            {pwdMsg && <p className="xai-note" style={{ marginTop: 10 }}>{pwdMsg}</p>}
          </form>
        </section>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h3>Personal detection history</h3>
          <div className="filters">
            <input
              className="scan-input"
              placeholder="Search by URL…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadHistory()}
            />
            <button className="scan-btn small" onClick={loadHistory}>Search</button>
          </div>
        </div>

        {loadingHist ? (
          <p className="empty">Loading…</p>
        ) : history.length === 0 ? (
          <p className="empty">No scans match this search.</p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>Time</th>
                <th>URL</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Model</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id}>
                  <td>{new Date(h.created_at).toLocaleString()}</td>
                  <td className="mono ellip">{h.url}</td>
                  <td>
                    <span className={`badge ${h.prediction === 'phishing' ? 'phish' : 'legit'}`}>
                      {h.prediction}
                    </span>
                  </td>
                  <td>
                    <span className={`risk-pill risk-${h.risk_level.toLowerCase()}`}>
                      {h.risk_level}
                    </span>
                  </td>
                  <td className="mono">{h.model_used}</td>
                  <td>{(h.confidence * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
