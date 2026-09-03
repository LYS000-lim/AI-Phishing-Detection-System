import { useEffect, useState } from 'react'
import { adminDeleteDetection, adminDetections } from '../../api.js'

export default function AdminDetectionLogs() {
  const [rows, setRows] = useState([])
  const [q, setQ] = useState('')
  const [result, setResult] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState(null)

  const load = () => {
    setLoading(true)
    adminDetections(q, result)
      .then(setRows)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() /* eslint-disable-next-line */ }, [result])

  const remove = async (id) => {
    if (!confirm('Delete this detection log?')) return
    try {
      await adminDeleteDetection(id)
      setRows((prev) => prev.filter((r) => r.id !== id))
    } catch (e) {
      alert(e.message)
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Detection Logs</h2>
        <p className="tagline">
          Every URL scan across all users. Filter, inspect and delete entries.
        </p>
      </div>

      <section className="panel">
        <div className="panel-head">
          <div className="filters">
            <input
              className="scan-input"
              placeholder="Search URL or user email…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && load()}
            />
            <select
              className="scan-input"
              value={result}
              onChange={(e) => setResult(e.target.value)}
            >
              <option value="">All results</option>
              <option value="phishing">Phishing only</option>
              <option value="legitimate">Legitimate only</option>
            </select>
            <button className="scan-btn small" onClick={load}>Apply</button>
          </div>
        </div>

        {error && <div className="error-box">{error}</div>}
        {loading ? (
          <p className="empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">No detections match these filters.</p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>Time</th><th>User</th><th>URL</th><th>Verdict</th>
                <th>Risk</th><th>Model</th><th>IP</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td>
                    <div>{r.user_name}</div>
                    <div className="mono muted">{r.user_email}</div>
                  </td>
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
                  <td className="mono">{r.model_used}</td>
                  <td className="mono">{r.ip_address || '-'}</td>
                  <td>
                    <button className="link-btn" onClick={() => setDetail(r)}>View</button>
                    <button className="link-btn danger" onClick={() => remove(r.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Detection #{detail.id}</h3>
            <dl className="details">
              <dt>URL</dt><dd className="mono">{detail.url}</dd>
              <dt>User</dt><dd>{detail.user_name} ({detail.user_email})</dd>
              <dt>Verdict</dt><dd>{detail.prediction}</dd>
              <dt>Risk Level</dt><dd>{detail.risk_level}</dd>
              <dt>Confidence</dt><dd>{(detail.confidence * 100).toFixed(2)}%</dd>
              <dt>Phishing probability</dt>
              <dd>{(detail.phishing_probability * 100).toFixed(2)}%</dd>
              <dt>Model</dt><dd className="mono">{detail.model_used}</dd>
              <dt>IP</dt><dd className="mono">{detail.ip_address || '-'}</dd>
              <dt>Time</dt><dd>{new Date(detail.created_at).toLocaleString()}</dd>
            </dl>
            <button className="scan-btn" onClick={() => setDetail(null)}>Close</button>
          </div>
        </div>
      )}
    </>
  )
}
