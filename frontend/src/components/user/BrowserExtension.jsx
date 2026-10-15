import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import { explainURL, myDetections } from '../../api.js'
import DateRangeFilter from '../DateRangeFilter.jsx'
import ExtensionInfo from '../ExtensionInfo.jsx'
import ShapChart from './ShapChart.jsx'
import { formatDetectedValue } from './Scanner.jsx'

export default function BrowserExtension() {
  const [rows, setRows] = useState([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 10
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [datesValid, setDatesValid] = useState(true)

  const [detail, setDetail] = useState(null)
  const [xai, setXai] = useState(null)
  const [xaiLoading, setXaiLoading] = useState(false)
  const [xaiError, setXaiError] = useState('')

  const load = () => {
    setLoading(true)
    setError('')
    myDetections('', '', page, pageSize, '', '', dateFrom, dateTo, 'extension')
      .then((data) => {
        setRows(data.items)
        setTotal(data.total)
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page])

  const openDetail = (row) => {
    setDetail(row)
    setXai(null)
    setXaiError('')
  }

  const loadXai = async () => {
    setXaiLoading(true)
    setXaiError('')
    try {
      setXai(await explainURL(detail.url))
    } catch (e) {
      setXaiError(e.message)
    } finally {
      setXaiLoading(false)
    }
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <>
      <div className="page-header">
        <h2>🧩 Browser Extension</h2>
        <p className="tagline">
          Install the PhishGuard Chrome extension for real-time phishing
          protection while you browse.
        </p>
      </div>

      <ExtensionInfo />

      <div className="page-header" style={{ marginTop: 8 }}>
        <h2 style={{ fontSize: 20 }}>Detection History</h2>
        <p className="tagline">
          Websites automatically detected by the Chrome extension while
          you're signed in (Extension Settings → Website Account). Manual
          scans from this website's Analyse URL page are tracked separately
          under Website Scan History.
        </p>
      </div>

      {error && <div className="error-box">{error}</div>}

      <section className="panel">
        <h3>Detection Records</h3>
        <div className="filters" style={{ flexWrap: 'wrap', marginBottom: 14 }}>
          <DateRangeFilter
            from={dateFrom}
            to={dateTo}
            allowEmpty
            onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
            onValidityChange={setDatesValid}
          />
          <button className="scan-btn small" disabled={!datesValid} onClick={() => { setPage(1); load() }}>
            Apply
          </button>
        </div>
        {loading ? (
          <p className="empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">
            No extension detections yet. Sign in to your website account from
            the extension's Settings page to start recording history here.
          </p>
        ) : (
          <>
            <table className="hist">
              <thead>
                <tr><th>Time</th><th>URL</th><th>Verdict</th><th>Risk</th><th></th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>{utcDate(r.created_at).toLocaleString('en-GB')}</td>
                    <td className="mono ellip">{r.url}</td>
                    <td>
                      <span className={`badge ${r.prediction === 'phishing' ? 'phish' : r.prediction === 'uncertain' ? 'review' : 'legit'}`}>{r.prediction === 'uncertain' ? 'suspicious' : r.prediction}</span>
                    </td>
                    <td>
                      <span className={`risk-pill risk-${r.risk_level.toLowerCase()}`}>{r.risk_level}</span>
                    </td>
                    <td><button className="link-btn" onClick={() => openDetail(r)}>View</button></td>
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

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()} style={{ maxHeight: '85vh', overflowY: 'auto' }}>
            <h3>Detection #{detail.id}</h3>
            <dl className="details">
              <dt>URL</dt><dd className="mono">{detail.url}</dd>
              <dt>Verdict</dt><dd>{detail.prediction === 'uncertain' ? 'suspicious' : detail.prediction}</dd>
              <dt>Risk Level</dt><dd>{detail.risk_level}</dd>
              <dt>Attack Type</dt><dd>{detail.attack_type || '-'}</dd>
              <dt>Confidence</dt><dd>{(detail.confidence * 100).toFixed(2)}%</dd>
              <dt>Model</dt><dd className="mono">{detail.model_used}</dd>
              <dt>Time</dt><dd>{utcDate(detail.created_at).toLocaleString('en-GB')}</dd>
            </dl>

            {!xai && !xaiLoading && (
              <button className="link-btn" onClick={loadXai}>View Detection Reason / SHAP / LIME</button>
            )}
            {xaiLoading && <p className="empty">Loading explanation…</p>}
            {xaiError && <div className="error-box">{xaiError}</div>}
            {xai && (
              <div style={{ marginTop: 14 }}>
                <h3>Explainable AI</h3>
                {xai.plain_text && <p className="xai-note">{xai.plain_text}</p>}
                <ShapChart explain={xai} formatValue={formatDetectedValue} />
                <div className="split-2">
                  <div>
                    <div className="cm-title">SHAP - top features</div>
                    {xai.shap?.top_features?.length ? (
                      <table className="hist">
                        <thead><tr><th>Feature</th><th>SHAP</th></tr></thead>
                        <tbody>
                          {xai.shap.top_features.slice(0, 6).map((f) => (
                            <tr key={f.feature}><td className="mono">{f.feature}</td><td>{f.shap_value.toFixed(4)}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    ) : <p className="empty">{xai.shap?.note || 'Not available.'}</p>}
                  </div>
                  <div>
                    <div className="cm-title">LIME - top rules</div>
                    {xai.lime?.top_rules?.length ? (
                      <table className="hist">
                        <thead><tr><th>Rule</th><th>Weight</th></tr></thead>
                        <tbody>
                          {xai.lime.top_rules.slice(0, 6).map((r, i) => (
                            <tr key={i}><td className="mono">{r.rule}</td><td>{r.weight.toFixed(4)}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    ) : <p className="empty">{xai.lime?.note || 'Not available.'}</p>}
                  </div>
                </div>
              </div>
            )}

            <div className="modal-actions">
              <button className="scan-btn" onClick={() => setDetail(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
