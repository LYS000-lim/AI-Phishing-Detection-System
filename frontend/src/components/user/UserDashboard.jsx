import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { detectionsDashboardVisuals, personalSummary } from '../../api.js'
import { useAuth } from '../../AuthContext.jsx'
import DashboardVisuals from '../DashboardVisuals.jsx'

// Simple client-side label from the user's own phishing ratio — no backend
// change needed, purely descriptive of scans run so far.
const protectionLevel = (total, phishing) => {
  if (total === 0) return { label: 'N/A', color: '#8ca3c3' }
  const ratio = phishing / total
  if (ratio < 0.1) return { label: 'Good', color: '#10b981' }
  if (ratio < 0.3) return { label: 'Fair', color: '#f59e0b' }
  return { label: 'Needs Attention', color: '#ef4444' }
}

const todayISO = () => new Date().toISOString().slice(0, 10)
const daysAgoISO = (n) => {
  const d = new Date()
  d.setDate(d.getDate() - n)
  return d.toISOString().slice(0, 10)
}

export default function UserDashboard() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  const [visuals, setVisuals] = useState(null)
  const [dateFrom, setDateFrom] = useState(daysAgoISO(14))
  const [dateTo, setDateTo] = useState(todayISO())
  const [source, setSource] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    personalSummary().then(setData).catch((e) => setError(e.message))
  }, [])

  useEffect(() => {
    setLoading(true)
    detectionsDashboardVisuals(14, source, dateFrom, dateTo)
      .then(setVisuals)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [dateFrom, dateTo, source])

  if (error) return <div className="error-box">{error}</div>
  if (!data) return <p className="empty">Loading your dashboard…</p>

  const { totals, recent, phishing_this_month = 0 } = data
  const protection = protectionLevel(totals.total, totals.phishing)

  const advice = phishing_this_month > 0
    ? {
      headline: `Your account detected ${phishing_this_month} phishing attempt${phishing_this_month === 1 ? '' : 's'} this month.`,
      tip: 'Avoid entering credentials on unknown or unexpected websites, and double-check the domain before signing in - even if the page looks familiar.',
    }
    : {
      headline: 'No phishing attempts detected on your account this month.',
      tip: 'Keep scanning links you\'re unsure about before opening them, and never enter your password on a page you reached from an email or message.',
    }

  return (
    <>
      <div className="page-header">
        <h2>Welcome back, {user?.full_name?.split(' ')[0]}</h2>
        <p className="tagline">Your personal detection summary and recent scans.</p>
      </div>

      <section className="panel">
        <h3>Security Overview</h3>
        <div className="tiles">
          <div className="tile">
            <div className="v">{totals.total}</div>
            <div className="k">Total URLs Checked</div>
          </div>
          <div className="tile">
            <div className="v" style={{ color: '#ef4444' }}>{totals.phishing}</div>
            <div className="k">Threats Detected</div>
          </div>
          <div className="tile">
            <div className="v" style={{ color: '#10b981' }}>{totals.legitimate}</div>
            <div className="k">Safe Websites</div>
          </div>
          <div className="tile">
            <div className="v" style={{ color: protection.color }}>{protection.label}</div>
            <div className="k">Protection Status</div>
          </div>
        </div>
      </section>

      <section className="panel">
        <h3>Security Advice</h3>
        <p style={{ margin: '0 0 6px', fontWeight: 600 }}>{advice.headline}</p>
        <p className="xai-note" style={{ margin: 0 }}>{advice.tip}</p>
      </section>

      <section className="panel">
        <h3>Recent Detection Logs</h3>
        {recent.length === 0 ? (
          <p className="empty">
            No scans yet. Head to <Link to="/scanner">Analyse URL</Link> to run one.
          </p>
        ) : (
          <table className="hist">
            <thead>
              <tr><th>Time</th><th>URL</th><th>Verdict</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {recent.map((r) => (
                <tr key={r.id}>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td className="mono ellip">{r.url}</td>
                  <td>
                    <span className={`badge ${r.prediction === 'phishing' ? 'phish' : 'legit'}`}>
                      {r.prediction}
                    </span>
                  </td>
                  <td>
                    <span className={`risk-pill risk-${r.risk_level.toLowerCase()}`}>
                      {r.risk_level}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
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
    </>
  )
}
