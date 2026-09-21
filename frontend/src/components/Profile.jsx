import { useEffect, useState } from 'react'
import { personalSummary, updateProfile } from '../api.js'
import { useAuth } from '../AuthContext.jsx'

const initialsOf = (name) =>
  (name || '')
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('') || '?'

const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : 'Never')

export default function Profile() {
  const { user, refresh } = useAuth()
  const [editing, setEditing] = useState(false)
  const [fullName, setFullName] = useState(user?.full_name || '')
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')
  const [totalScans, setTotalScans] = useState(null)

  useEffect(() => {
    personalSummary().then((d) => setTotalScans(d.totals.total)).catch(() => {})
  }, [])

  const startEdit = () => {
    setFullName(user?.full_name || '')
    setMsg('')
    setEditing(true)
  }

  const saveName = async (e) => {
    e.preventDefault()
    setSaving(true)
    setMsg('')
    try {
      await updateProfile({ full_name: fullName })
      await refresh()
      setEditing(false)
    } catch (err) {
      setMsg(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Profile</h2>
        <p className="tagline">Your account information.</p>
      </div>

      <section className="panel">
        <h3>Profile Information</h3>
        <div className="profile-card" style={{ marginBottom: 18 }}>
          <div className="avatar-circle">{initialsOf(user?.full_name)}</div>
          <div className="profile-card-info">
            {editing ? (
              <form onSubmit={saveName} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <input
                  className="scan-input"
                  style={{ width: 220, marginTop: 0 }}
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required
                  autoFocus
                />
                <button className="scan-btn small" disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
                <button type="button" className="link-btn" onClick={() => setEditing(false)}>Cancel</button>
              </form>
            ) : (
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <h3 style={{ margin: 0 }}>{user?.full_name}</h3>
                <button type="button" className="link-btn" onClick={startEdit}>Edit Name</button>
              </div>
            )}
            {msg && <p className="password-match bad" style={{ margin: '6px 0 0' }}>{msg}</p>}
          </div>
        </div>

        <dl className="details">
          <dt>Email</dt><dd className="mono">{user?.email}</dd>
          <dt>Role</dt><dd style={{ textTransform: 'capitalize' }}>{user?.role}</dd>
          <dt>Account Status</dt><dd>{user?.is_active === false ? 'Inactive' : 'Active'}</dd>
        </dl>
      </section>

      <section className="panel">
        <h3>Account Activity</h3>
        <div className="tiles">
          <div className="tile">
            <div className="v" style={{ fontSize: 16 }}>
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}
            </div>
            <div className="k">Member Since</div>
          </div>
          <div className="tile">
            <div className="v" style={{ fontSize: 16 }}>{fmt(user?.last_login_at)}</div>
            <div className="k">Last Login</div>
          </div>
          <div className="tile">
            <div className="v" style={{ fontSize: 16 }}>{fmt(user?.last_logout_at)}</div>
            <div className="k">Last Logout</div>
          </div>
          <div className="tile">
            <div className="v">{totalScans ?? '-'}</div>
            <div className="k">Total Scans</div>
          </div>
        </div>
      </section>
    </>
  )
}
