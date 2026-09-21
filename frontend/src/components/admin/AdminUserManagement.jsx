import { useEffect, useState } from 'react'
import {
  adminCreateUser, adminDeleteUser, adminUpdateUser, adminUsers,
} from '../../api.js'
import { useAuth } from '../../AuthContext.jsx'
import PasswordRequirements, { isPasswordValid } from '../PasswordRequirements.jsx'

const EMPTY_NEW_USER = {
  full_name: '', email: '', password: '', confirm: '', role: 'user',
}

export default function AdminUserManagement() {
  const { user: me } = useAuth()
  const [rows, setRows] = useState([])
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [editing, setEditing] = useState(null)
  const [creating, setCreating] = useState(false)
  const [newUser, setNewUser] = useState(EMPTY_NEW_USER)
  const [createBusy, setCreateBusy] = useState(false)
  const [createError, setCreateError] = useState('')

  const load = () => {
    setLoading(true)
    adminUsers(q)
      .then(setRows)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() /* eslint-disable-next-line */ }, [])

  const openCreate = () => {
    setNewUser(EMPTY_NEW_USER)
    setCreateError('')
    setCreating(true)
  }

  const saveCreate = async (e) => {
    e.preventDefault()
    setCreateError('')
    if (!isPasswordValid(newUser.password)) {
      setCreateError('Password does not meet the requirements below')
      return
    }
    if (newUser.password !== newUser.confirm) {
      setCreateError('Passwords do not match')
      return
    }
    setCreateBusy(true)
    try {
      const created = await adminCreateUser({
        full_name: newUser.full_name.trim(),
        email: newUser.email.trim(),
        password: newUser.password,
        role: newUser.role,
      })
      // Newest first (matches the load() ordering)
      setRows((prev) => [created, ...prev])
      setCreating(false)
    } catch (err) {
      setCreateError(err.message)
    } finally {
      setCreateBusy(false)
    }
  }

  const toggleActive = async (u) => {
    try {
      const updated = await adminUpdateUser(u.id, { is_active: !u.is_active })
      setRows((prev) => prev.map((r) => (r.id === u.id ? updated : r)))
    } catch (e) { alert(e.message) }
  }

  const changeRole = async (u, role) => {
    try {
      const updated = await adminUpdateUser(u.id, { role })
      setRows((prev) => prev.map((r) => (r.id === u.id ? updated : r)))
    } catch (e) { alert(e.message) }
  }

  const remove = async (u) => {
    if (!confirm(`Delete ${u.email}? Their detection logs will be removed too.`)) return
    try {
      await adminDeleteUser(u.id)
      setRows((prev) => prev.filter((r) => r.id !== u.id))
    } catch (e) { alert(e.message) }
  }

  const saveEdit = async (e) => {
    e.preventDefault()
    try {
      const updated = await adminUpdateUser(editing.id, {
        full_name: editing.full_name,
        email: editing.email,
      })
      setRows((prev) => prev.map((r) => (r.id === updated.id ? updated : r)))
      setEditing(null)
    } catch (err) { alert(err.message) }
  }

  return (
    <>
      <div className="page-header">
        <h2>User Management</h2>
        <p className="tagline">
          Create new accounts, edit existing ones, and manage roles and
          activation.
        </p>
      </div>

      <section className="panel">
        <div className="panel-head">
          <div className="filters">
            <input
              className="scan-input"
              placeholder="Search name or email…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && load()}
            />
            <button className="scan-btn small" onClick={load}>Search</button>
          </div>
          <button className="scan-btn" onClick={openCreate}>
            + Add New User
          </button>
        </div>

        {error && <div className="error-box">{error}</div>}
        {loading ? (
          <p className="empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">No users match.</p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>User</th><th>Email</th><th>Role</th>
                <th>Status</th><th>Joined</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.full_name}
                    {u.id === me?.id && <span className="tag">you</span>}
                  </td>
                  <td className="mono">{u.email}</td>
                  <td>
                    <select
                      className="scan-input inline"
                      value={u.role}
                      onChange={(e) => changeRole(u, e.target.value)}
                      disabled={u.id === me?.id}
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${u.is_active ? 'legit' : 'phish'}`}>
                      {u.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td>{new Date(u.created_at).toLocaleDateString()}</td>
                  <td>
                    <button className="link-btn" onClick={() => setEditing({ ...u })}>Edit</button>
                    <button className="link-btn" onClick={() => toggleActive(u)} disabled={u.id === me?.id}>
                      {u.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button className="link-btn danger" onClick={() => remove(u)} disabled={u.id === me?.id}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Create-user modal */}
      {creating && (
        <div className="modal-backdrop" onClick={() => !createBusy && setCreating(false)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Add New User</h3>
            <p className="xai-note" style={{ marginTop: 0 }}>
              Create a User or Admin account without going through public
              registration.
            </p>

            <form onSubmit={saveCreate}>
              <label className="auth-label">Full name</label>
              <input
                className="scan-input"
                value={newUser.full_name}
                onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })}
                required
                autoFocus
              />

              <label className="auth-label">Email</label>
              <input
                className="scan-input"
                type="email"
                value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                required
              />

              <label className="auth-label">Password</label>
              <input
                className="scan-input"
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                minLength={8}
                required
              />
              <PasswordRequirements password={newUser.password} />

              <label className="auth-label">Confirm password</label>
              <input
                className="scan-input"
                type="password"
                value={newUser.confirm}
                onChange={(e) => setNewUser({ ...newUser, confirm: e.target.value })}
                minLength={6}
                required
              />

              <label className="auth-label">Role</label>
              <div className="role-row">
                <label className="radio">
                  <input
                    type="radio"
                    name="new-role"
                    value="user"
                    checked={newUser.role === 'user'}
                    onChange={() => setNewUser({ ...newUser, role: 'user' })}
                  />
                  <span>User (can scan URLs, see own history)</span>
                </label>
                <label className="radio">
                  <input
                    type="radio"
                    name="new-role"
                    value="admin"
                    checked={newUser.role === 'admin'}
                    onChange={() => setNewUser({ ...newUser, role: 'admin' })}
                  />
                  <span>Admin (full system access)</span>
                </label>
              </div>

              {createError && <div className="error-box">{createError}</div>}

              <div className="modal-actions">
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setCreating(false)}
                  disabled={createBusy}
                >
                  Cancel
                </button>
                <button type="submit" className="scan-btn" disabled={createBusy}>
                  {createBusy ? 'Creating…' : 'Create account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit-user modal */}
      {editing && (
        <div className="modal-backdrop" onClick={() => setEditing(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Edit user</h3>
            <form onSubmit={saveEdit}>
              <label className="auth-label">Full name</label>
              <input
                className="scan-input"
                value={editing.full_name}
                onChange={(e) => setEditing({ ...editing, full_name: e.target.value })}
              />
              <label className="auth-label">Email</label>
              <input
                className="scan-input"
                type="email"
                value={editing.email}
                onChange={(e) => setEditing({ ...editing, email: e.target.value })}
              />
              <div className="modal-actions">
                <button type="button" className="link-btn" onClick={() => setEditing(null)}>Cancel</button>
                <button type="submit" className="scan-btn">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
