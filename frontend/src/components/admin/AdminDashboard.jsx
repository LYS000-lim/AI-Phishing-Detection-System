import { useEffect, useState } from 'react'
import { adminDashboard } from '../../api.js'
import DashboardVisuals from '../DashboardVisuals.jsx'

const todayISO = () => new Date().toISOString().slice(0, 10)
const daysAgoISO = (n) => {
  const d = new Date()
  d.setDate(d.getDate() - n)
  return d.toISOString().slice(0, 10)
}

export default function AdminDashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [dateFrom, setDateFrom] = useState(daysAgoISO(14))
  const [dateTo, setDateTo] = useState(todayISO())
  const [source, setSource] = useState('')
  const [loading, setLoading] = useState(false)

  const load = (from, to, s) => {
    setLoading(true)
    adminDashboard(14, s, from, to)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load(dateFrom, dateTo, source)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dateFrom, dateTo, source])

  if (error) return <div className="error-box">{error}</div>
  if (!data) return <p className="empty">Loading admin dashboard…</p>

  const {
    totals, top_users,
    blocked_urls_count, pending_reports_count, most_common_attack_type,
    most_targeted_brand, visuals,
  } = data

  return (
    <>
      <div className="page-header">
        <h2>Admin Dashboard</h2>
        <p className="tagline">System-wide monitoring across all users, the website scanner, and the Chrome extension.</p>
      </div>

      <section className="panel">
        <h3>System Overview</h3>
        <div className="tiles">
          <div className="tile"><div className="v">{totals.users}</div><div className="k">Total Users</div></div>
          <div className="tile"><div className="v">{totals.scans}</div><div className="k">Total Scans</div></div>
          <div className="tile"><div className="v" style={{ color: '#ef4444' }}>{totals.phishing}</div><div className="k">Phishing Detection</div></div>
          <div className="tile"><div className="v" style={{ color: '#10b981' }}>{totals.legitimate}</div><div className="k">Legitimate Detection</div></div>
          <div className="tile"><div className="v" style={{ color: '#38bdf8' }}>{totals.extension_detections}</div><div className="k">Extension Detection</div></div>
        </div>
      </section>

      <section className="panel">
        <h3>Threat Intelligence</h3>
        <div className="tiles">
          <div className="tile">
            <div className="v" style={{ fontSize: 16 }}>{most_common_attack_type || 'N/A'}</div>
            <div className="k">Most common attack type</div>
          </div>
          <div className="tile">
            <div className="v" style={{ fontSize: 16 }}>{most_targeted_brand || 'N/A'}</div>
            <div className="k">Most targeted brand</div>
          </div>
          <div className="tile"><div className="v">{blocked_urls_count}</div><div className="k">Blocked URLs</div></div>
          <div className="tile"><div className="v">{pending_reports_count}</div><div className="k">Pending reports</div></div>
        </div>
      </section>

      <DashboardVisuals
        visuals={visuals}
        dateFrom={dateFrom}
        dateTo={dateTo}
        source={source}
        onDateFromChange={setDateFrom}
        onDateToChange={setDateTo}
        onSourceChange={setSource}
        loading={loading}
      />

      <section className="panel">
        <h3>User Activity</h3>
        {top_users.length === 0 ? (
          <p className="empty">No user activity yet.</p>
        ) : (
          <table className="hist">
            <thead><tr><th>User</th><th>Email</th><th>Scans</th></tr></thead>
            <tbody>
              {top_users.map((u) => (
                <tr key={u.email}>
                  <td>{u.user}</td>
                  <td className="mono">{u.email}</td>
                  <td>{u.scans}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
