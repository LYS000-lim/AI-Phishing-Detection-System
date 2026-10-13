import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import DateRangeFilter from '../DateRangeFilter.jsx'
import { adminDeleteDetection, adminDetections, explainURL, exportDetections } from '../../api.js'
import ShapChart from '../user/ShapChart.jsx'
import { formatDetectedValue } from '../user/Scanner.jsx'

const ATTACK_TYPES = [
  'Financial Scam',
  'Credential Theft',
  'Fake Giveaway / Scam',
  'Tech Support / Malware Scam',
  'Domain Spoofing / Brand Impersonation',
]

const SOURCE_LABELS = {
  website: '🌐 Website Scanner',
  extension: '🧩 Chrome Extension',
}

const ATTACK_TYPE_INFO = {
  'Financial Scam': 'The URL references banking, payment, or financial services wording, often used to lure victims into entering account or card details.',
  'Credential Theft': 'The URL combines login/verification wording in a way consistent with harvesting usernames and passwords.',
  'Fake Giveaway / Scam': 'The URL uses prize, reward, or giveaway wording typical of scams that lure victims with a fake offer.',
  'Tech Support / Malware Scam': 'The URL uses security-alert or download wording consistent with fake support scams or malware delivery.',
  'Domain Spoofing / Brand Impersonation': 'The URL structure or wording imitates a trusted brand or domain to appear legitimate at a glance.',
}

export default function AdminDetectionLogs() {
  const [rows, setRows] = useState([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 20
  const [q, setQ] = useState('')
  const [result, setResult] = useState('')
  const [risk, setRisk] = useState('')
  const [attackType, setAttackType] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [source, setSource] = useState('')
  const [datesValid, setDatesValid] = useState(true)
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState(null)
  const [xai, setXai] = useState(null)
  const [xaiLoading, setXaiLoading] = useState(false)
  const [xaiError, setXaiError] = useState('')
  const [exporting, setExporting] = useState(false)

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

  const load = () => {
    setLoading(true)
    adminDetections(q, result, page, pageSize, risk, attackType, dateFrom, dateTo, source)
    .then((data)=>{
        setRows(data.items)
        setTotal(data.total)
        setSummary(data.summary)
    })
    .catch((e) => setError(e.message))
    .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [result, risk, attackType, source, page])

  const currentFilters = () => ({
    q, result, risk, attack_type: attackType, date_from: dateFrom, date_to: dateTo, source,
  })

  const download = async (format) => {
    setExporting(true)
    try {
      await exportDetections(format, currentFilters())
    } catch (e) {
      alert(e.message)
    } finally {
      setExporting(false)
    }
  }

  const remove = async (id) => {
    if (!confirm('Delete this detection log?')) return
    try {
      await adminDeleteDetection(id)
      setRows((prev) => prev.filter((r) => r.id !== id))
    } catch (e) {
      alert(e.message)
    }
  }

  const totalPages = Math.ceil(total / pageSize)

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
          <div className="filters" style={{ flexWrap: 'wrap' }}>
            <input
              className="scan-input"
              placeholder="Search URL or user email…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { setPage(1); load() } }}
            />
            <select
              className="scan-input"
              value={result}
              onChange={(e) => setResult(e.target.value)}
            >
              <option value="">All results</option>
              <option value="phishing">Phishing only</option>
              <option value="uncertain">Suspicious only</option>
              <option value="legitimate">Legitimate only</option>
            </select>
            <select
              className="scan-input"
              value={risk}
              onChange={(e) => setRisk(e.target.value)}
            >
              <option value="">All risk levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <select
              className="scan-input"
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
            >
              <option value="">All attack types</option>
              {ATTACK_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              className="scan-input"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            >
              <option value="">All sources</option>
              <option value="website">Website Scanner</option>
              <option value="extension">Chrome Extension</option>
            </select>
            <DateRangeFilter
              from={dateFrom}
              to={dateTo}
              allowEmpty
              onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
              onValidityChange={setDatesValid}
            />
            <button
              className="scan-btn small"
              disabled={!datesValid}
              onClick={() => {
                setPage(1)
                load()
              }}
            >
              Apply
            </button>
            <button className="scan-btn small secondary" disabled={exporting || !datesValid} onClick={() => download('csv')}>
              Download CSV
            </button>
            <button className="scan-btn small secondary" disabled={exporting || !datesValid} onClick={() => download('pdf')}>
              Download PDF
            </button>
          </div>
        </div>

        {error && <div className="error-box">{error}</div>}

        {summary && (
          <div className="tiles" style={{ marginBottom: 18 }}>
            <div className="tile"><div className="v">{summary.total_detections}</div><div className="k">Total Detection</div></div>
            <div className="tile"><div className="v" style={{ color: 'var(--bad)' }}>{summary.phishing_count}</div><div className="k">Phishing Count</div></div>
            <div className="tile"><div className="v" style={{ color: 'var(--good)' }}>{summary.legitimate_count}</div><div className="k">Legitimate Count</div></div>
            <div className="tile"><div className="v">{summary.detection_rate_pct}%</div><div className="k">Detection Rate</div></div>
            <div className="tile"><div className="v" style={{ fontSize: 16 }}>{summary.most_common_attack_type || 'N/A'}</div><div className="k">Most Common Attack Type</div></div>
            <div className="tile"><div className="v">{summary.average_confidence_pct}%</div><div className="k">Average Confidence</div></div>
          </div>
        )}
        {loading ? (
          <p className="empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">No detections match these filters.</p>
        ) : (
          <>
            <table className="hist">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>URL</th>
                  <th>Source</th>
                  <th>Verdict</th>
                  <th>Risk</th>
                  <th>Model</th>
                  <th>IP</th>
                  <th></th>
                </tr>
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

                    <td>{SOURCE_LABELS[r.source] || r.source}</td>

                    <td>
                      <span className={`badge ${r.prediction === 'phishing' ? 'phish' : r.prediction === 'uncertain' ? 'review' : 'legit'}`}>
                        {r.prediction === 'uncertain' ? 'suspicious' : r.prediction}
                      </span>
                    </td>

                    <td>
                      <span className={`risk-pill risk-${r.risk_level.toLowerCase()}`}>
                        {r.risk_level}
                      </span>
                    </td>

                    <td className="mono">{r.model_used}</td>

                    <td className="mono">
                      {r.ip_address || '-'}
                    </td>

                    <td>
                      <button
                        className="link-btn"
                        onClick={() => openDetail(r)}
                      >
                        View
                      </button>

                      <button
                        className="link-btn danger"
                        onClick={() => remove(r.id)}
                      >
                        Delete
                      </button>
                    </td>

                  </tr>
                ))}
              </tbody>

            </table>


            <div className="pagination">

              <button
                className="link-btn"
                disabled={page === 1}
                onClick={() => setPage(page - 1)}
              >
                Previous
              </button>


              <span>
                Page {page} / {totalPages || 1}
              </span>


              <button
                className="link-btn"
                disabled={page === totalPages}
                onClick={() => setPage(page + 1)}
              >
                Next
              </button>

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
              <dt>User</dt><dd>{detail.user_name} ({detail.user_email})</dd>
              <dt>Source</dt><dd>{SOURCE_LABELS[detail.source] || detail.source}</dd>
              <dt>Verdict</dt><dd>{detail.prediction === 'uncertain' ? 'suspicious' : detail.prediction}</dd>
              <dt>Risk Level</dt><dd>{detail.risk_level}</dd>
              <dt>Attack Type</dt><dd>{detail.attack_type || '-'}</dd>
              <dt>Confidence</dt><dd>{(detail.confidence * 100).toFixed(2)}%</dd>
              <dt>Phishing probability</dt>
              <dd>{(detail.phishing_probability * 100).toFixed(2)}%</dd>
              <dt>Model</dt><dd className="mono">{detail.model_used}</dd>
              <dt>IP</dt><dd className="mono">{detail.ip_address || '-'}</dd>
              <dt>Time</dt><dd>{utcDate(detail.created_at).toLocaleString('en-GB')}</dd>
            </dl>

            {detail.attack_type && ATTACK_TYPE_INFO[detail.attack_type] && (
              <p className="xai-note" style={{ marginTop: -8 }}>
                {ATTACK_TYPE_INFO[detail.attack_type]}
              </p>
            )}

            {!xai && !xaiLoading && (
              <button className="link-btn" onClick={loadXai}>View XAI Explanation</button>
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
                            <tr key={f.feature}>
                              <td className="mono">{f.feature}</td>
                              <td>{f.shap_value.toFixed(4)}</td>
                            </tr>
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
                            <tr key={i}>
                              <td className="mono">{r.rule}</td>
                              <td>{r.weight.toFixed(4)}</td>
                            </tr>
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
