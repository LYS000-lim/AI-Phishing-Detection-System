import { useEffect, useState } from 'react'
import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS,
  Legend, LinearScale, LineElement, PointElement, Tooltip,
} from 'chart.js'
import { Doughnut, Line } from 'react-chartjs-2'
import { adminDashboard } from '../../api.js'

ChartJS.register(
  ArcElement, BarElement, CategoryScale, LinearScale,
  LineElement, PointElement, Tooltip, Legend,
)

export default function AdminDashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    adminDashboard().then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="error-box">{error}</div>
  if (!data) return <p className="empty">Loading admin dashboard…</p>

  const { totals, phishing_distribution: dist, trend_14d: trend, top_users } = data

  const trendData = {
    labels: trend.map((d) => d.day),
    datasets: [
      {
        label: 'Phishing',
        data: trend.map((d) => d.phishing),
        borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,.2)',
        tension: .3,
      },
      {
        label: 'Legitimate',
        data: trend.map((d) => d.legitimate),
        borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,.2)',
        tension: .3,
      },
    ],
  }
  const trendOpts = {
    responsive: true,
    plugins: { legend: { labels: { color: '#e6eef9' } } },
    scales: {
      x: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
      y: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
    },
  }

  const pieData = {
    labels: ['Phishing', 'Legitimate'],
    datasets: [{
      data: [dist.phishing, dist.legitimate],
      backgroundColor: ['#ef4444', '#10b981'], borderWidth: 0,
    }],
  }

  return (
    <>
      <div className="page-header">
        <h2>Admin Dashboard</h2>
        <p className="tagline">System-wide overview across all users and detections.</p>
      </div>

      <section className="panel">
        <h3>System totals</h3>
        <div className="tiles">
          <div className="tile"><div className="v">{totals.users}</div><div className="k">Registered users</div></div>
          <div className="tile"><div className="v">{totals.scans}</div><div className="k">Total scans</div></div>
          <div className="tile"><div className="v" style={{ color: '#ef4444' }}>{totals.phishing}</div><div className="k">Phishing</div></div>
          <div className="tile"><div className="v" style={{ color: '#10b981' }}>{totals.legitimate}</div><div className="k">Legitimate</div></div>
        </div>
      </section>

      <div className="split-2">
        <section className="panel">
          <h3>Detection trend (last 14 days)</h3>
          {trend.length > 0
            ? <Line data={trendData} options={trendOpts} />
            : <p className="empty">No scans in the last 14 days.</p>}
        </section>
        <section className="panel">
          <h3>Phishing distribution</h3>
          {totals.scans > 0
            ? <Doughnut data={pieData} options={{ plugins: { legend: { position: 'bottom', labels: { color: '#e6eef9' } } } }} />
            : <p className="empty">No scans recorded yet.</p>}
        </section>
      </div>

      <section className="panel">
        <h3>Top users by scan volume</h3>
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
