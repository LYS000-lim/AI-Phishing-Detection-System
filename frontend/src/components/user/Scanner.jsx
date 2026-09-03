import { useState } from 'react'
import { scanURL, explainURL } from '../../api.js'

export default function Scanner() {
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [explain, setExplain] = useState(null)
  const [error, setError] = useState('')

  const run = async () => {
    const target = url.trim()
    if (!target) return
    setBusy(true)
    setError('')
    setResult(null)
    setExplain(null)
    try {
      const pred = await scanURL(target)
      setResult(pred)
      const exp = await explainURL(target)
      setExplain(exp)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const isPhish = result?.prediction === 'phishing'
  const riskClass = result?.risk_level?.toLowerCase()

  return (
    <>
      <div className="page-header">
        <h2>Analyse a URL</h2>
        <p className="tagline">
          Paste any URL to check whether it is phishing or legitimate.
        </p>
      </div>

      <section className="panel">
        <h3>Scan a URL</h3>
        <div className="scan-row">
          <input
            className="scan-input"
            placeholder="https://example.com/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !busy && run()}
            aria-label="URL to scan"
          />
          <button className="scan-btn" onClick={run} disabled={busy}>
            {busy ? 'Scanning…' : 'Scan URL'}
          </button>
        </div>
        {error && <div className="error-box">{error}</div>}
      </section>

      {result && (
        <div className={`verdict ${isPhish ? 'phish' : 'legit'}`}>
          <div className="verdict-row">
            <div>
              <div className="verdict-label">
                {isPhish ? 'PHISHING DETECTED' : 'LEGITIMATE'}
              </div>
              <div className="verdict-url mono">{result.url}</div>
            </div>
            <div className={`risk-pill risk-${riskClass}`}>
              Risk: {result.risk_level}
            </div>
          </div>

          <div className="gauge-track">
            <div
              className="gauge-fill"
              style={{ width: `${(result.phishing_probability * 100).toFixed(1)}%` }}
            />
          </div>
          <div className="gauge-caption">
            Phishing {(result.phishing_probability * 100).toFixed(1)}% ·{' '}
            Legitimate {(result.legitimate_probability * 100).toFixed(1)}%
          </div>

          <div className="verdict-meta">
            <span>Model used: <b>{result.model_used}</b></span>
            <span>Confidence: <b>{(result.confidence * 100).toFixed(1)}%</b></span>
          </div>

          {result.attack_type && (
            <div className="attack-box">
              <h4>Phishing Attack Type</h4>

              <p>
                <b>{result.attack_type.category}</b>
              </p>

              <ul>
                {result.attack_type.reason.map((r, index) => (
                  <li key={index}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {result.matched_domain && (
            <div className="trusted-banner">
              <b>Trusted domain allowlist:</b> matched
              &nbsp;<span className="mono">{result.matched_domain}</span>.
              Well-known reputable sites bypass ML classification to
              prevent false positives, mirroring how real detection
              systems combine ML with reputation lists.
            </div>
          )}

          {explain?.plain_text && (
            <p className="plain-text">{explain.plain_text}</p>
          )}
        </div>
      )}

      {result && !result.matched_domain && (
        <div className="xai-grid">
          <section className="panel">
            <h3>SHAP - feature contributions</h3>
            {explain ? (
              <>
                <p className="xai-note">{explain.shap.note}</p>
                {explain.shap.top_features.map((f) => (
                  <div className="xai-item" key={f.feature}>
                    <span className="xai-name mono">{f.feature}</span>
                    <span className={f.shap_value >= 0 ? 'w-neg' : 'w-pos'}>
                      {f.shap_value >= 0 ? '+' : ''}
                      {f.shap_value.toFixed(4)}
                    </span>
                  </div>
                ))}
              </>
            ) : (
              <p className="empty">Computing explanation…</p>
            )}
          </section>

          <section className="panel">
            <h3>LIME - local rules</h3>
            {explain ? (
              <>
                <p className="xai-note">{explain.lime.note}</p>
                {explain.lime.top_rules.map((r) => (
                  <div className="xai-item" key={r.rule}>
                    <span className="xai-name mono">{r.rule}</span>
                    <span className={r.weight >= 0 ? 'w-neg' : 'w-pos'}>
                      {r.weight >= 0 ? '+' : ''}
                      {r.weight.toFixed(4)}
                    </span>
                  </div>
                ))}
              </>
            ) : (
              <p className="empty">Computing explanation…</p>
            )}
          </section>
        </div>
      )}
    </>
  )
}
