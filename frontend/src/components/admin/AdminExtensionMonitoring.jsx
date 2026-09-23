import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import { adminDetections, adminExtensionMonitoring } from '../../api.js'

export default function AdminExtensionMonitoring() {
  const [summary, setSummary] = useState(null)
  const [rows, setRows] = useState([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 20
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = () => {
    setLoading(true)
    setError('')
    Promise.all([
      adminExtensionMonitoring(),
      adminDetections('', '', page, pageSize, '', '', '', '', 'extension'),
    ])
      .then(([s, d]) => { setSummary(s); setRows(d.items); setTotal(d.total) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page])

  const totalPages = Math.ceil(total / pageSize)

  return (
    <>
      <div className="page-header">
        <h2>Browser Extension Monitoring</h2>
        <p className="tagline">System-wide view of detections made through the Chrome extension, across all signed-in users.</p>
      </div>

      {error && <div className="error-box">{error}</div>}

      <section className="panel">
        <h3>Extension Overview</h3>
        <div className="tiles">
          <div className="tile"><div className="v">{summary?.totals.extension_users ?? '-'}</div><div className="k">Total Extension Users</div></div>
          <div className="tile"><div className="v">{summary?.totals.extension_detections ?? '-'}</div><div className="k">Extension Detection Count</div></div>
          <div className="tile"><div className="v" style={{ color: '#ef4444' }}>{summary?.totals.threats_found ?? '-'}</div><div className="k">Threats Found</div></div>
        </div>
      </section>

      <section className="panel">
        <h3>Extension Detection Records</h3>
        {loading ? (
          <p className="empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">No extension detections yet.</p>
        ) : (
          <>
            <table className="hist">
              <thead>
                <tr><th>Time</th><th>User</th><th>URL</th><th>Verdict</th><th>Risk</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>{utcDate(r.created_at).toLocaleString('en-GB')}</td>
                    <td>
                      <div>{r.user_name}</div>
                      <div className="mono muted">{r.user_email}</div>
                    </td>
                    <td className="mono ellip">{r.url}</td>
                    <td><span className={`badge ${r.prediction === 'phishing' ? 'phish' : r.prediction === 'uncertain' ? 'review' : 'legit'}`}>{r.prediction === 'uncertain' ? 'suspicious' : r.prediction}</span></td>
                    <td><span className={`risk-pill risk-${r.risk_level.toLowerCase()}`}>{r.risk_level}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="pagination">
              <button className="link-btn" disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button>
              <span>Page {page} / {totalPages || 1}</span>
              <button className="link-btn" disabled={page === totalPages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </>
        )}
      </section>
    </>
  )
}
