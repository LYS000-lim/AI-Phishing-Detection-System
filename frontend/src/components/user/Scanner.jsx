import { useState } from 'react'
import { explainURL, reportURL, scanURL } from '../../api.js'

const pct = (value) => `${((value ?? 0) * 100).toFixed(1)}%`

const displayValue = (value) => {
  if (value == null) return '-'
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return String(value)
    return Number(value).toFixed(5).replace(/0+$/, '').replace(/\.$/, '')
  }
  return String(value)
}

const signed = (value) => {
  const n = Number(value || 0)
  return `${n >= 0 ? '+' : ''}${n.toFixed(5)}`
}

const splitReason = (reason) => {
  const text = String(reason || '')
  const separator = ' — '
  const index = text.indexOf(separator)

  if (index === -1) {
    return { label: '', text }
  }

  return {
    label: text.slice(0, index),
    text: text.slice(index + separator.length),
  }
}

export default function Scanner() {
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [explain, setExplain] = useState(null)
  const [error, setError] = useState('')
  const [reported, setReported] = useState(false)
  const [reporting, setReporting] = useState(false)

  const run = async () => {
    const target = url.trim()
    if (!target) return

    setBusy(true)
    setError('')
    setResult(null)
    setExplain(null)
    setReported(false)

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

  const handleReport = async () => {
    if (!result) return

    setReporting(true)
    setError('')

    try {
      const reasons = explain?.why_detected?.length
        ? explain.why_detected.join(' ')
        : explain?.plain_text || 'Detected suspicious phishing characteristics'

      await reportURL({
        url: result.url,
        attack_type:
          explain?.attack_analysis?.category ||
          result.attack_type?.category ||
          null,
        detection_reason: reasons,
      })

      setReported(true)
    } catch (e) {
      setError(e.message)
    } finally {
      setReporting(false)
    }
  }

  const isTrusted = Boolean(result?.trusted_domain || result?.matched_domain)
  const isPhish = Boolean(result) && !isTrusted && result.prediction === 'phishing'
  const isLegitimate = Boolean(result) && !isTrusted && result.prediction === 'legitimate'
  const riskClass = result?.risk_level?.toLowerCase() || 'low'

  const attack = explain?.attack_analysis || result?.attack_type
  const reasons = explain?.why_detected || []
  const evidence = explain?.evidence || []

  return (
    <>
      <div className="page-header">
        <h2>Analyse a URL</h2>
        <p className="tagline">
          Paste any URL to check whether it is phishing or legitimate.
        </p>
      </div>

      <section className="panel scanner-panel">
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
        <section className={`scan-result ${isTrusted ? 'trusted' : isPhish ? 'phish' : 'legit'}`}>
          <div className="result-kicker">Scan Result</div>

          <div className="result-header">
            <div>
              <div className="result-status">
                <span className="status-icon" aria-hidden>
                  {isPhish ? '⚠' : '✓'}
                </span>
                {isTrusted
                  ? 'TRUSTED DOMAIN VERIFIED'
                  : isPhish
                    ? 'PHISHING DETECTED'
                    : 'LEGITIMATE'}
              </div>
              <div className="result-url mono">{result.url}</div>
            </div>

            <span className={`risk-pill risk-${riskClass}`}>
              Risk: {result.risk_level}
            </span>
          </div>

          {isTrusted ? (
            <div className="result-metrics trusted-metrics">
              <div className="metric-card">
                <span className="metric-label">Security Status</span>
                <strong>{result.security_status || 'Trusted Website'}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Verification Method</span>
                <strong>Trusted Domain Allowlist</strong>
              </div>
            </div>
          ) : (
            <div className="result-metrics">
              <div className="metric-card">
                <span className="metric-label">Phishing Probability</span>
                <strong>{pct(result.phishing_probability)}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Legitimate Probability</span>
                <strong>{pct(result.legitimate_probability)}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Model Used</span>
                <strong>{result.model_used}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Confidence</span>
                <strong>{pct(result.confidence)}</strong>
              </div>
            </div>
          )}

          {isPhish && (
            <div className="result-actions">
              <button
                className="report-btn"
                onClick={handleReport}
                disabled={reporting || reported}
              >
                {reported
                  ? 'URL Reported'
                  : reporting
                    ? 'Reporting…'
                    : 'Report URL'}
              </button>
            </div>
          )}
        </section>
      )}

      {isTrusted && (
        <>
          <section className="panel result-section trusted-section">
            <h3>Trusted Domain Verification</h3>

            <div className="verification-item">
              <div className="verification-title">
                <span className="check-icon">✓</span>
                Official domain matched:
              </div>
              <div className="matched-domain mono">{result.matched_domain}</div>
              <p>
                This website has been verified as an official trusted domain.
                The domain reputation matches known legitimate services,
                indicating a low risk of phishing activity.
              </p>
            </div>

            <div className="verification-item">
              <div className="verification-title">
                <span className="check-icon">✓</span>
                URL Pattern Analysis
              </div>
              <p>
                The URL structure does not contain suspicious characteristics
                commonly observed in phishing websites.
              </p>
            </div>
          </section>

          <section className="panel result-section ai-not-required">
            <h3>AI Analysis</h3>
            <p className="analysis-not-required">
              <strong>Not required.</strong> Trusted domain verification completed
              successfully.
            </p>
          </section>
        </>
      )}

      {isPhish && (
        <>
          <section className="panel result-section attack-analysis">
            <h3>Phishing Attack Analysis</h3>

            <div className="analysis-grid">
              <div className="analysis-field">
                <span className="analysis-label">Attack Category</span>
                <strong>{attack?.category || 'Phishing Attack'}</strong>
              </div>
              <div className="analysis-field">
                <span className="analysis-label">Attack Technique</span>
                <strong>
                  {attack?.technique || attack?.techniques?.join(' / ') || 'Suspicious URL Pattern'}
                </strong>
              </div>
            </div>

            {attack?.indicators?.length > 0 && (
              <div className="analysis-copy">
                {attack.indicators.slice(0, 3).map((text, index) => (
                  <p key={index}>{text}</p>
                ))}
              </div>
            )}
          </section>

          <section className="panel result-section">
            <h3>Why was this detected?</h3>
            <p className="section-intro">
              This URL was classified as <strong>PHISHING</strong> with{' '}
              <strong>{result.risk_level.toLowerCase()} risk</strong>. Each point below
              corresponds directly to an AI Explanation Evidence card:
            </p>

            <ul className="reason-list phishing-reasons">
              {(reasons.length ? reasons : attack?.reason || []).slice(0, 3).map((reason, index) => {
                const parsed = splitReason(reason)
                return (
                  <li key={index}>
                    {parsed.label && <strong className="reason-label">{parsed.label}</strong>}
                    <span>{parsed.text}</span>
                  </li>
                )
              })}
            </ul>
          </section>

          <section className="panel result-section">
            <h3>AI Explanation Evidence</h3>
            <p className="section-intro">
              Only the most important model contributors are shown.
            </p>

            {!explain ? (
              <p className="empty">Computing explanation…</p>
            ) : evidence.length === 0 ? (
              <p className="empty">No strong explanation evidence was available.</p>
            ) : (
              <div className="evidence-list">
                {evidence.map((item) => (
                  <article className="evidence-card phishing-evidence" key={item.feature}>
                    <div className="evidence-title">
                      <span aria-hidden>⚠</span>
                      {item.title}
                    </div>
                    {item.description && <p>{item.description}</p>}
                    <dl className="evidence-details">
                      <dt>Feature</dt>
                      <dd className="mono">{item.feature}</dd>
                      <dt>Detected Value</dt>
                      <dd className="mono">{displayValue(item.detected_value)}</dd>
                      <dt>SHAP Contribution</dt>
                      <dd className="mono evidence-danger">{signed(item.shap_contribution)}</dd>
                      <dt>LIME Contribution</dt>
                      <dd className="mono evidence-danger">{signed(item.lime_contribution)}</dd>
                    </dl>
                  </article>
                ))}
              </div>
            )}
          </section>
        </>
      )}

      {isLegitimate && (
        <>
          <section className="panel result-section security-analysis">
            <h3>Security Analysis</h3>
            <div className="security-ok">
              <span className="check-icon">✓</span>
              <strong>No suspicious phishing indicators were detected.</strong>
            </div>
            <p>
              The URL structure matches characteristics commonly associated with
              legitimate websites.
            </p>
          </section>

          <section className="panel result-section">
            <h3>Why was this classified as legitimate?</h3>
            <p className="section-intro">
              The AI model identified no significant phishing patterns from the URL.
              Each point below corresponds directly to an AI Explanation Evidence card:
            </p>
            <ul className="reason-list legitimate-reasons">
              {reasons.slice(0, 3).map((reason, index) => {
                const parsed = splitReason(reason)
                return (
                  <li key={index}>
                    {parsed.label && <strong className="reason-label">{parsed.label}</strong>}
                    <span>{parsed.text}</span>
                  </li>
                )
              })}
            </ul>
          </section>

          <section className="panel result-section">
            <h3>AI Explanation Evidence</h3>
            <p className="section-intro">
              Only evidence supporting the legitimate classification is shown.
            </p>

            {!explain ? (
              <p className="empty">Computing explanation…</p>
            ) : evidence.length === 0 ? (
              <p className="empty">No strong supporting evidence was available.</p>
            ) : (
              <div className="evidence-list">
                {evidence.map((item) => (
                  <article className="evidence-card legitimate-evidence" key={item.feature}>
                    <div className="evidence-title">
                      <span className="check-icon" aria-hidden>✓</span>
                      {item.title}
                    </div>
                    {item.description && <p>{item.description}</p>}
                    <dl className="evidence-details">
                      <dt>Feature</dt>
                      <dd className="mono">{item.feature}</dd>
                      <dt>Detected Value</dt>
                      <dd className="mono">{displayValue(item.detected_value)}</dd>
                      <dt>Contribution</dt>
                      <dd className="evidence-good">
                        {item.support || 'Supports legitimate classification'}
                      </dd>
                    </dl>
                  </article>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </>
  )
}
