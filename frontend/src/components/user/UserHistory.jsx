import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import DateRangeFilter from '../DateRangeFilter.jsx'
import { myDetections } from '../../api.js'

export default function UserHistory() {
  const [history, setHistory] = useState([])
  const [q, setQ] = useState('')
  const [result, setResult] = useState('')
  const [risk, setRisk] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [datesValid, setDatesValid] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 20
  const [loadingHist, setLoadingHist] = useState(true)

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
            <option value="uncertain">Suspicious only</option>
            <option value="legitimate">Legitimate only</option>
          </select>
          <select className="scan-input" value={risk} onChange={(e) => { setPage(1); setRisk(e.target.value) }}>
            <option value="">All risk levels</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <DateRangeFilter
            from={dateFrom}
            to={dateTo}
            allowEmpty
            onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
            onValidityChange={setDatesValid}
          />
          <button className="scan-btn small" disabled={!datesValid} onClick={() => { setPage(1); loadHistory() }}>Apply</button>
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
                    <td>{utcDate(h.created_at).toLocaleString('en-GB')}</td>
                    <td className="mono ellip">{h.url}</td>
                    <td>
                      <span className={`badge ${h.prediction === 'phishing' ? 'phish' : h.prediction === 'uncertain' ? 'review' : 'legit'}`}>
                        {h.prediction === 'uncertain' ? 'suspicious' : h.prediction}
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

    </>
  )
}
