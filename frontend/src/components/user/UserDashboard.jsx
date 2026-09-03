import { useEffect, useState } from 'react'
import {
  Chart as ChartJS, ArcElement, BarElement, CategoryScale,
  LinearScale, Tooltip, Legend,
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import { Link } from 'react-router-dom'
import { personalSummary } from '../../api.js'
import { useAuth } from '../../AuthContext.jsx'

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const distLabels = {
  long_url: 'Long URLs',
  https: 'HTTPS URLs',
  ip_domain: 'IP-address URLs',
  suspicious_keywords: 'Suspicious keywords',
  many_subdomains: 'Many subdomains',
}

export default function UserDashboard() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    personalSummary().then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="error-box">{error}</div>
  if (!data) return <p className="empty">Loading your dashboard…</p>

  const { totals, feature_distribution: dist, recent } = data

  const distData = {
    labels: Object.keys(dist).map((k) => distLabels[k] || k),
    datasets: [{
      data: Object.values(dist),
      backgroundColor: '#38bdf8',
      borderRadius: 4,
    }],
  }
  const distOpts = {
    indexAxis: 'y', responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
      y: { ticks: { color: '#e6eef9' }, grid: { display: false } },
    },
  }

  const pieData = {
    labels: ['Phishing', 'Legitimate'],
    datasets: [{
      data: [totals.phishing, totals.legitimate],
      backgroundColor: ['#ef4444', '#10b981'],
      borderWidth: 0,
    }],
  }

  return (
    <>
      <div className="page-header">
        <h2>Welcome back, {user?.full_name?.split(' ')[0]}</h2>
        <p className="tagline">Your personal detection summary and recent scans.</p>
      </div>

      <section className="panel">
        <h3>System Summary</h3>
        <div className="tiles">
          <div className="tile">
            <div className="v">{totals.total}</div>
            <div className="k">Total scans</div>
          </div>
          <div className="tile">
            <div className="v" style={{ color: '#ef4444' }}>{totals.phishing}</div>
            <div className="k">Phishing detected</div>
          </div>
          <div className="tile">
            <div className="v" style={{ color: '#10b981' }}>{totals.legitimate}</div>
            <div className="k">Legitimate</div>
          </div>
        </div>
      </section>

      <div className="split-2">
        <section className="panel">
          <h3>Verdict split</h3>
          {totals.total > 0
            ? <Doughnut data={pieData} options={{ plugins: { legend: { position: 'bottom' } } }} />
            : <p className="empty">Run your first scan to populate this chart.</p>}
        </section>

        <section className="panel">
          <h3>Feature distribution across your scans</h3>
          {totals.total > 0
            ? <Bar data={distData} options={distOpts} />
            : <p className="empty">No scans yet.</p>}
        </section>
      </div>

      <section className="panel">
        <h3>Recent scans</h3>
        {recent.length === 0 ? (
          <p className="empty">
            No scans yet. Head to <Link to="/scanner">Analyse URL</Link> to run one.
          </p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>Time</th>
                <th>URL</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Confidence</th>
              </tr>
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
                  <td>{(r.confidence * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
