import { useEffect, useState } from 'react'
import { myDetections, myReports } from '../../api.js'

// A "Reason" column full of paragraph-length text is unreadable in a table;
// show a short label and let the user open the full text on demand (same
// pattern as the admin's Blacklist Database page).
const shortReason = (reason) => {
  if (!reason) return null
  const firstSentence = reason.split(/(?<=[.!?])\s/)[0]
  return firstSentence.length <= 60 ? firstSentence : `${reason.slice(0, 57)}…`
}

export default function UserHistory() {
  const [history, setHistory] = useState([])
  const [q, setQ] = useState('')
  const [result, setResult] = useState('')
  const [risk, setRisk] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 20
  const [loadingHist, setLoadingHist] = useState(true)

  const [reports, setReports] = useState([])
  const [loadingReports, setLoadingReports] = useState(true)
  const [viewing, setViewing] = useState(null)

  const loadHistory = () => {
    setLoadingHist(true)
    myDetections(q, result, page, pageSize, risk, '', dateFrom, dateTo, 'website')
      .then((data) => {
        setHistory(data.items)
        setTotal(data.total)
      })
      .finally(() => setLoadingHist(false))
  }

  useEffect(() => {
    loadHistory()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result, risk, page])

  useEffect(() => {
    setLoadingReports(true)
    myReports()
      .then(setReports)
      .finally(() => setLoadingReports(false))
  }, [])

  const totalPages = Math.ceil(total / pageSize)

  return (
    <>
      <div className="page-header">
        <h2>Website Scan History</h2>
        <p className="tagline">Every URL you've manually checked on this website's Analyse URL page.</p>
      </div>

      <section className="panel">
        <div className="filters" style={{ flexWrap: 'wrap', marginBottom: 14 }}>
          <input
            className="scan-input"
            placeholder="Search by URL…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { setPage(1); loadHistory() } }}
          />
          <select className="scan-input" value={result} onChange={(e) => { setPage(1); setResult(e.target.value) }}>
            <option value="">All results</option>
            <option value="phishing">Phishing only</option>
            <option value="legitimate">Legitimate only</option>
          </select>
          <select className="scan-input" value={risk} onChange={(e) => { setPage(1); setRisk(e.target.value) }}>
            <option value="">All risk levels</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <label className="date-filter">
            From
            <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
          </label>
          <label className="date-filter">
            To
            <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
          </label>
          <button className="scan-btn small" onClick={() => { setPage(1); loadHistory() }}>Apply</button>
        </div>

        {loadingHist ? (
          <p className="empty">Loading…</p>
        ) : history.length === 0 ? (
          <p className="empty">No scans match these filters.</p>
        ) : (
          <>
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

            <div className="pagination">
              <button className="link-btn" disabled={page === 1} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <span>Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, total)} of {total} &middot; Page {page} / {totalPages || 1}</span>
              <button className="link-btn" disabled={page === totalPages} onClick={() => setPage(page + 1)}>
                Next
              </button>
            </div>
          </>
        )}
      </section>

      <div className="page-header" style={{ marginTop: 8 }}>
        <h2 style={{ fontSize: 20 }}>My Reported URLs</h2>
        <p className="tagline">
          URLs you personally reported from a scan result. Admins see every
          user's reports on the Blacklist Database page - this is only yours.
        </p>
      </div>

      <section className="panel">
        {loadingReports ? (
          <p className="empty">Loading…</p>
        ) : reports.length === 0 ? (
          <p className="empty">You haven't reported any URLs yet.</p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>URL</th>
                <th>Attack Type</th>
                <th>Detection Reason</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td className="mono ellip">{r.url}</td>
                  <td>{r.attack_type || '-'}</td>
                  <td>
                    {r.detection_reason ? (
                      <>
                        {shortReason(r.detection_reason)}{' '}
                        <button className="link-btn" onClick={() => setViewing(r)}>View</button>
                      </>
                    ) : '-'}
                  </td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {viewing && (
        <div className="modal-backdrop" onClick={() => setViewing(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Detection Reason</h3>
            <dl className="details">
              <dt>URL</dt><dd className="mono">{viewing.url}</dd>
              <dt>Attack type</dt><dd>{viewing.attack_type || '-'}</dd>
            </dl>
            <p style={{ marginTop: 0 }}>{viewing.detection_reason}</p>
            <div className="modal-actions">
              <button className="scan-btn small" onClick={() => setViewing(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
