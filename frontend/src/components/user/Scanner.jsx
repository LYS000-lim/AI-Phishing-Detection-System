import { useState } from 'react'
import { explainURL, reportURL, scanURL } from '../../api.js'
import ShapChart from './ShapChart.jsx'

const pct = (value) => `${((value ?? 0) * 100).toFixed(1)}%`
const joinList = (items) => (items.length <= 1
  ? (items[0] || '')
  : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`)

// Categorizes the raw model confidence (max class probability, always >=50%
// since the model picks the higher-probability class) into a plain-language
// label + short explanation, so users see "Medium" instead of just "58%".
// Display-only — does not change the underlying probability or verdict.
const confidenceInfo = (value, prediction, uncertainReason, legitReason, escalatedBy, lookalike) => {
  const value100 = (value ?? 0) * 100
  const noun = prediction === 'phishing' ? 'phishing' : 'legitimate'

  if (escalatedBy === 'brand_impersonation' && lookalike) {
    return {
      label: 'High',
      text: 'The address imitates a brand name with a look-alike spelling, a deliberate typosquatting trick, so the result is phishing even where the URL pattern alone looks normal.',
    }
  }
  if (uncertainReason === 'brand_impersonation' && lookalike) {
    return {
      label: 'Low',
      text: 'The URL pattern alone looks normal, but part of the address is a one-letter misspelling of a brand name, a common typosquatting pattern.',
    }
  }
  if (escalatedBy === 'brand_impersonation') {
    return {
      label: 'Medium',
      text: "The URL pattern alone was borderline; the brand name on a domain that is not the brand's own raised this result to phishing.",
    }
  }
  if (uncertainReason === 'brand_impersonation') {
    return {
      label: 'Low',
      text: "The URL pattern alone looks normal, but it uses a brand name on a domain that is not one of that brand's established websites.",
    }
  }

  if (escalatedBy === 'new_domain') {
    return {
      label: 'High',
      text: 'The URL pattern alone was not conclusive, but the website\'s domain was registered very recently. Together with the URL score, the domain\'s age puts it in the phishing range.',
    }
  }
  if (uncertainReason === 'new_domain') {
    return {
      label: 'Low',
      text: 'The URL pattern alone looks normal, but the website\'s domain is new, which is common for phishing websites.',
    }
  }
  if (legitReason === 'established_domain') {
    return {
      label: 'Medium',
      text: 'The URL pattern score is high, but the website\'s domain has existed for many years. Taking the domain\'s age into account brings it below the warning level.',
    }
  }
  if (uncertainReason === 'established_domain') {
    return {
      label: 'Low',
      text: 'The URL pattern score alone would be phishing, but the domain has existed for many years, so with the domain\'s age it is only rated suspicious.',
    }
  }
  if (escalatedBy === 'page_check') {
    return {
      label: 'High',
      text: 'The live page check found the page itself doing what phishing pages do, so the result is phishing even though the URL score alone was only suspicious.',
    }
  }
  if (legitReason === 'page_check') {
    return {
      label: 'Medium',
      text: 'The URL alone looked suspicious, but the live page check found a normal page of this well-established website.',
    }
  }
  if (legitReason === 'reputable_site') {
    return {
      label: 'Medium',
      text: "The URL pattern score is high because of the address's length and structure, but the domain is well established, the model does not flag its homepage and the address has no phishing lure, so it is treated as legitimate.",
    }
  }
  if (uncertainReason === 'short_link') {
    return {
      label: 'Low',
      text: 'A short link hides the website it opens, so the URL pattern score says nothing about that website.',
    }
  }

  if (legitReason === 'http_reputable') {
    return {
      label: 'Medium',
      text: 'The URL pattern score is high only because the site uses plain HTTP. The domain is well established and the same address over HTTPS scores as legitimate, so it is treated as legitimate - but the connection is not encrypted.',
    }
  }

  if (prediction === 'uncertain') {
    return {
      label: 'Low',
      text: uncertainReason === 'reputable_domain'
        ? 'The URL pattern alone scores high, but the domain\'s reputation outweighs it, so this is not treated as a confirmed phishing result.'
        : uncertainReason === 'https_only'
        ? 'The phishing score is driven mainly by the missing HTTPS connection rather than a broad match with known phishing patterns.'
        : 'The phishing score is below the level the system requires to confirm a URL as phishing.',
    }
  }

  if (value100 >= 80) {
    return {
      label: 'High',
      text: `The model found strong indicators that match patterns commonly associated with ${noun} URLs.`,
    }
  }
  if (value100 >= 60) {
    return {
      label: 'Medium',
      text: 'The model detected some suspicious characteristics, but some URL patterns overlap between phishing and legitimate websites. The result should be interpreted together with the explanation evidence below.',
    }
  }
  return {
    label: 'Low',
    text: 'The URL contains mixed characteristics, and the model found limited evidence strongly supporting either classification.',
  }
}

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

const BOOLEAN_FEATURES = new Set(['IsHTTPS', 'IsDomainIP', 'HasObfuscation', 'HasBrandOutsideDomain'])

const COUNT_UNITS = {
  URLLength: 'characters',
  DomainLength: 'characters',
  NoOfLettersInURL: 'letters',
  NoOfDegitsInURL: 'digits',
  NoOfSubDomain: 'subdomains',
  TLDLength: 'characters',
  NoOfObfuscatedChar: 'characters',
  NoOfEqualsInURL: "'=' characters",
  NoOfQMarkInURL: "'?' characters",
  NoOfAmpersandInURL: "'&' characters",
  NoOfOtherSpecialCharsInURL: 'characters',
  NoOfSuspiciousWords: 'words',
}

const RATIO_FEATURES = new Set([
  'LetterRatioInURL',
  'DegitRatioInURL',
  'SpacialCharRatioInURL',
  'ObfuscationRatio',
])

// Renders a raw feature value in plain language for non-technical readers.
// The mono "Feature" row alongside it still shows the raw code (e.g. URLLength)
// for technical/academic transparency.
export const formatDetectedValue = (feature, value) => {
  if (value == null) return '-'

  if (BOOLEAN_FEATURES.has(feature)) {
    return Number(value) === 1 ? 'Yes' : 'No'
  }

  if (RATIO_FEATURES.has(feature)) {
    return pct(value)
  }

  if (COUNT_UNITS[feature]) {
    const unit = COUNT_UNITS[feature]
    return `${displayValue(value)} ${Number(value) === 1 ? unit.replace(/s$/, '').replace(/s'$/, "'") : unit}`
  }

  return displayValue(value)
}

// Mirrors the mapping in extension/common.js (pgRecommendation) — keep in sync.
const RECOMMENDATIONS = {
  'Credential Theft': 'Do not enter your username or password on this site.',
  'Financial Scam': 'Do not enter any payment or banking information.',
  'Fake Giveaway / Scam': 'Do not provide personal information or make any payment.',
  'Tech Support / Malware Scam': 'Do not download or install anything from this site, and do not call any phone number shown.',
  'Brand Impersonation': "Verify you are on the brand's official domain before entering any information.",
  // Name used before 2026-10-21; kept for older history records.
  'Domain Spoofing / Brand Impersonation': "Verify you are on the brand's official domain before entering any information.",
}
const recommendationFor = (category) =>
  RECOMMENDATIONS[category] || 'Avoid entering any personal or account information on this website.'

const DEMO_EXAMPLES = [
  { url: 'https://www.google.com', safe: true },
  { url: 'http://paypal-login-security.test', safe: false },
  { url: 'http://amazon-account-verification.test', safe: false },
]

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

// Plain wording for how long ago a domain was registered.
const ageText = (days) => {
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`
  if (days < 365) return `about ${Math.round(days / 30.4)} months ago`
  const years = Math.round(days / 365.25)
  return `about ${years} year${years === 1 ? '' : 's'} ago`
}

export default function Scanner({ scanFn = scanURL }) {
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [explain, setExplain] = useState(null)
  const [error, setError] = useState('')
  const [reported, setReported] = useState(false)
  const [reporting, setReporting] = useState(false)

  const run = async (overrideUrl) => {
    const target = (overrideUrl ?? url).trim()
    if (!target) return

    setBusy(true)
    setError('')
    setResult(null)
    setExplain(null)
    setReported(false)

    try {
      const pred = await scanFn(target)
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
  const isUncertain = Boolean(result) && !isTrusted && result.prediction === 'uncertain'
  const isBorderline = isUncertain && result.uncertain_reason === 'borderline'
  const isReputable = isUncertain && result.uncertain_reason === 'reputable_domain'
  const isHttpsOnly = isUncertain && result.uncertain_reason === 'https_only'
  const isHttpReputable = Boolean(result) && !isTrusted && result.legit_reason === 'http_reputable'
  const isBrand = isUncertain && result.uncertain_reason === 'brand_impersonation'
  const isBrandEscalated = isPhish && result.escalated_by === 'brand_impersonation'
  const isReputableSite = Boolean(result) && !isTrusted && result.legit_reason === 'reputable_site'
  const isPageLegit = Boolean(result) && !isTrusted && result.legit_reason === 'page_check'
  const isPageEscalated = isPhish && result.escalated_by === 'page_check'
  const pageCheck = explain?.page_check || result?.page_check
  const stage2 = result?.stage2 || explain?.stage2
  const isNewDomain = Boolean(result) && !isTrusted
    && (result.uncertain_reason === 'new_domain' || result.escalated_by === 'new_domain')
  const isEstablished = Boolean(result) && !isTrusted
    && (result.uncertain_reason === 'established_domain' || result.legit_reason === 'established_domain')
  // The score shown, on one scale for every verdict path (backend
  // score_view.py), always in the verdict's band.
  const score = result?.score || explain?.score
  const ruleDecided = score?.source === 'rule'
  const isShortLink = isUncertain && result.uncertain_reason === 'short_link'
  // What kept a warning on a well-established domain (login wording, another
  // brand's name, a link to another website, a user@ prefix).
  const lures = result?.lures || []
  // What the rule that decided the verdict found (shown when ruleDecided).
  const overrideNote = (isBrand || isBrandEscalated) && result?.lookalike
    ? `Verdict raised: "${result.lookalike}" imitates "${result.brand}" on a domain that is not the brand's own`
    : isBrand || isBrandEscalated
    ? `Verdict raised: "${result?.brand}" used on a domain that is not the brand's own`
    : isNewDomain
    ? `Final verdict from the domain-age check: domain registered ${stage2 ? ageText(stage2.age_days) : 'recently'}`
    : isEstablished
    ? `Final verdict from the domain-age check: domain registered in ${stage2 ? stage2.registered.slice(0, 4) : 'the past'}`
    : isPageEscalated
    ? 'Verdict raised by the live page check'
    : isPageLegit
    ? 'Final verdict from the live page check: a normal page of this website'
    : isReputableSite
    ? `Final verdict from domain reputation (Tranco #${result?.reputation?.rank?.toLocaleString()}) with no phishing lure in the address`
    : isShortLink
    ? 'Final verdict from the short-link check: the destination is hidden'
    : isReputable
    ? `Final verdict capped by domain reputation (Tranco #${result?.reputation?.rank?.toLocaleString()})`
    : isHttpReputable
    ? 'Final verdict from the HTTP check + domain reputation'
    : 'Final verdict softened: missing HTTPS is the main signal'
  const rep = result?.reputation
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
          Enter a website URL to analyse. Example: https://example.com
        </p>
      </div>

      <section className="panel scanner-panel">
        <h3>Scan a URL</h3>
        <div className="scan-row">
          <input
            className="scan-input"
            placeholder="google.com or https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !busy && run()}
            aria-label="URL to scan"
          />
          <button className="scan-btn" onClick={() => run()} disabled={busy}>
            {busy ? 'Scanning…' : 'Scan URL'}
          </button>
        </div>
        {error && <div className="error-box">{error}</div>}

        <div className="demo-examples">
          <span className="demo-label">Try examples:</span>
          {DEMO_EXAMPLES.map((example) => (
            <button
              key={example.url}
              type="button"
              className={`demo-chip ${example.safe ? 'safe' : 'danger'}`}
              disabled={busy}
              onClick={() => { setUrl(example.url); run(example.url) }}
            >
              {example.safe ? '✓' : '⚠'} {example.url}
            </button>
          ))}
        </div>
      </section>

      {result && (
        <section className={`scan-result ${isTrusted ? 'trusted' : isPhish ? 'phish' : isUncertain ? 'uncertain' : 'legit'}`}>
          <div className="result-kicker">Scan Result</div>

          <div className="result-header">
            <div>
              <div className="result-status">
                <span className="status-icon" aria-hidden>
                  {isPhish || isUncertain ? '⚠' : '✓'}
                </span>
                {isTrusted
                  ? 'TRUSTED DOMAIN VERIFIED'
                  : isPhish
                    ? 'PHISHING DETECTED'
                    : isUncertain
                      ? 'SUSPICIOUS – PROCEED WITH CAUTION'
                      : 'LEGITIMATE'}
              </div>
              <div className="result-url mono">{result.url}</div>
              {result.checked_url && (
                <div className="result-redirect">
                  {result.unicode_host
                    ? 'Written with special Unicode letters – browsers open it as:'
                    : 'Redirect link – the result is for the address it opens:'}{' '}
                  <span className="mono">{result.checked_url}</span>
                </div>
              )}
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
                <span className="metric-label">Score</span>
                <strong>{pct(score?.risk_score)}</strong>
                {ruleDecided && <span className="metric-sub">{overrideNote}</span>}
              </div>
              <div className="metric-card">
                <span className="metric-label">Model Used</span>
                <strong>{result.model_used}</strong>
              </div>
              <div className="metric-card">
                <span className="metric-label">Confidence</span>
                <strong>{confidenceInfo(score?.confidence, result.prediction, result.uncertain_reason, result.legit_reason, result.escalated_by, result.lookalike).label}</strong>
                {score?.confidence != null && <span className="metric-sub">{pct(score.confidence)}</span>}
              </div>
            </div>
          )}

          {!isTrusted && (
            <p className="confidence-note">
              {confidenceInfo(score?.confidence, result.prediction, result.uncertain_reason, result.legit_reason, result.escalated_by, result.lookalike).text}
            </p>
          )}

          {isPhish && (
            <>
              <div className="security-recommendation">
                <span className="rec-icon" aria-hidden>⚠</span>
                <div>
                  <div className="rec-label">Security Recommendation</div>
                  <div>{recommendationFor(attack?.category)}</div>
                </div>
              </div>

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
            </>
          )}

          {isUncertain && (
            <>
              <div className="security-recommendation low-confidence-note">
                <span className="rec-icon" aria-hidden>ℹ</span>
                <div>
                  <div className="rec-label">Low-confidence result</div>
                  {isBrand && result.lookalike ? (
                  <div>
                    This address contains <strong>{result.lookalike}</strong>, a one-letter
                    misspelling of <strong>{result.brand}</strong>, on a domain that is not an
                    established {result.brand} website. This is <strong>not a confirmed
                    phishing detection</strong> – open {result.brand} through its official
                    website before entering passwords or payment details.
                  </div>
                  ) : isBrand ? (
                  <div>
                    This address uses the brand name <strong>{result.brand}</strong> on a
                    domain that is not an established {result.brand} website. It may be a
                    regional or partner site, or an impersonation. This is <strong>not a
                    confirmed phishing detection</strong> – open {result.brand} through its
                    official website before entering passwords or payment details.
                  </div>
                  ) : isNewDomain ? (
                  <div>
                    This website's domain <strong>{stage2?.domain}</strong> was registered{' '}
                    {stage2 ? ageText(stage2.age_days) : 'recently'}. New domains are common for
                    phishing websites. This is <strong>not a confirmed phishing detection</strong> –
                    do not enter passwords or payment details unless you are sure who runs this website.
                  </div>
                  ) : isEstablished ? (
                  <div>
                    The address pattern resembles phishing, but the domain{' '}
                    <strong>{stage2?.domain}</strong> has existed since {stage2?.registered?.slice(0, 4)}.
                    This is <strong>not a confirmed phishing detection</strong> – check the address
                    carefully before entering passwords or payment details.
                  </div>
                  ) : isShortLink ? (
                  <div>
                    This is a short link (<strong>{rep?.domain}</strong>), so the address does
                    not show which website it opens. This is <strong>not a confirmed phishing
                    detection</strong> – open it only if you trust who sent it, and check the
                    address of the page it opens before entering passwords or payment details.
                  </div>
                  ) : isReputable ? (
                  <div>
                    The address pattern resembles phishing, but it belongs
                    to <strong>{rep?.domain}</strong>, a well-established website (ranked
                    #{rep?.rank?.toLocaleString()} globally). This is <strong>not a confirmed
                    phishing detection</strong> – make sure the domain is exactly {rep?.domain}{' '}
                    before entering passwords or payment details.
                    {lures.length > 0 && ` The address also contains ${joinList(lures)}, which a phishing page on a shared or hacked website relies on.`}
                    {rep?.shared && ' Anyone can share documents or pages on this service, so also check who shared the link.'}
                  </div>
                  ) : (
                  <div>
                    The AI model is not certain about this URL
                    {isBorderline ? ` (${pct(score?.risk_score)} risk score)` : ''}.{' '}
                    {isBorderline
                      ? 'Some URL characteristics resemble phishing, but not strongly enough to confirm it.'
                      : 'It was flagged mainly because the site does not use a secure HTTPS connection.'}
                    {lures.length > 0 && ` The address also contains ${joinList(lures)}, which a phishing page on a shared or hacked website relies on.`}
                    {' '}This is <strong>not a confirmed phishing detection</strong> – check
                    the domain name carefully before entering passwords or payment details.
                  </div>
                  )}
                </div>
              </div>

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
                      : 'Report as Suspicious'}
                </button>
              </div>
            </>
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
                Not run: the domain is on the trusted list, so the URL model,
                the domain-age check and the live page check were not needed.
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
              <strong>{result.risk_level.toLowerCase()} risk</strong>{' '}
              {ruleDecided
                ? `by the ${score.decided_by.charAt(0).toLowerCase()}${score.decided_by.slice(1)}. The ML model's own view of the address is listed with the other findings below.`
                : score?.source === 'domain_age'
                ? "because its URL pattern together with its domain's age falls in the phishing range."
                : 'because several characteristics matched patterns commonly found in phishing websites.'}
            </p>

            <p className="reason-lead">The AI identified:</p>
            <ul className="reason-list phishing-reasons">
              {(reasons.length ? reasons : attack?.reason || []).slice(0, 7).map((reason, index) => {
                const parsed = splitReason(reason)
                return (
                  <li key={index}>
                    {parsed.label && <strong className="reason-label">{parsed.label}</strong>}
                    <span>{parsed.text}</span>
                  </li>
                )
              })}
            </ul>

            <p className="section-footnote">
              The individual feature contributions are shown in the AI Explanation
              Evidence section below.
            </p>
          </section>

          <ShapChart
            explain={explain}
            formatValue={formatDetectedValue}
            overrideNote={ruleDecided ? `These are model scores only. The final verdict above also depends on a rule (${overrideNote.charAt(0).toLowerCase()}${overrideNote.slice(1)}).` : null}
          />

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
                    {item.found && (
                      <p>
                        <span className="evidence-kicker">What the AI found: </span>
                        {item.found}
                      </p>
                    )}
                    {item.why_it_matters && (
                      <p>
                        <span className="evidence-kicker">Why this matters: </span>
                        {item.why_it_matters}
                      </p>
                    )}
                    <dl className="evidence-details">
                      <dt>Feature</dt>
                      <dd className="mono">{item.feature}</dd>
                      <dt>Detected Value</dt>
                      <dd className="mono">{formatDetectedValue(item.feature, item.detected_value)}</dd>
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

      {isUncertain && (
        <>
          <section className="panel result-section security-analysis">
            <h3>Security Analysis</h3>
            <div className="security-recommendation" style={{ marginTop: 0 }}>
              <span className="rec-icon" aria-hidden>⚠</span>
              <strong>Suspicious – this website could not be confirmed as safe.</strong>
            </div>
            {(explain?.security_analysis || []).map((line, index) => (
              <p key={index}>{line}</p>
            ))}
          </section>

          <section className="panel result-section">
            <h3>Why is this URL marked suspicious?</h3>
            <p className="section-intro">
              This URL was <strong>not classified as confirmed phishing</strong> —
              {isBrand && result?.lookalike
                ? ` it contains "${result.lookalike}", a one-letter misspelling of "${result.brand}", on a domain that is not the brand's own, so these signals are treated as caution flags rather than proof:`
                : isBrand
                ? ` it uses the brand name "${result?.brand}" on a domain that is not the brand's own, so these signals are treated as caution flags rather than proof:`
                : isNewDomain
                ? ' its URL pattern alone looks normal, but its domain is new, so these signals are treated as caution flags rather than proof:'
                : isEstablished
                ? ' its URL pattern resembles phishing, but its domain has existed for many years, so these signals are treated as caution flags rather than proof:'
                : isShortLink
                ? ' it is a short link, so the address does not show the website it opens; the signals below describe only the short link itself:'
                : isReputable
                ? ` its address pattern resembles phishing, but ${rep?.domain} is a well-established website, so these signals are treated as caution flags rather than proof:`
                : isBorderline
                ? ' its phishing score is in the borderline range, so these signals are treated as caution flags rather than proof:'
                : ' the model\'s own top signal for it is a missing HTTPS connection, which is treated as a caution flag rather than proof:'}
            </p>

            <p className="reason-lead">The AI identified:</p>
            <ul className="reason-list phishing-reasons">
              {reasons.slice(0, 7).map((reason, index) => {
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

          <ShapChart
            explain={explain}
            formatValue={formatDetectedValue}
            overrideNote={ruleDecided ? `These are model scores only. The final verdict above also depends on a rule (${overrideNote.charAt(0).toLowerCase()}${overrideNote.slice(1)}).` : null}
          />

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
                      <span aria-hidden>❓</span>
                      {item.title}
                    </div>
                    {item.found && (
                      <p>
                        <span className="evidence-kicker">What the AI found: </span>
                        {item.found}
                      </p>
                    )}
                    {item.why_it_matters && (
                      <p>
                        <span className="evidence-kicker">Why this matters: </span>
                        {item.why_it_matters}
                      </p>
                    )}
                    <dl className="evidence-details">
                      <dt>Feature</dt>
                      <dd className="mono">{item.feature}</dd>
                      <dt>Detected Value</dt>
                      <dd className="mono">{formatDetectedValue(item.feature, item.detected_value)}</dd>
                      <dt>SHAP Contribution</dt>
                      <dd className="mono">{signed(item.shap_contribution)}</dd>
                      <dt>LIME Contribution</dt>
                      <dd className="mono">{signed(item.lime_contribution)}</dd>
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
              <strong>
                {isEstablished
                  ? 'This website\'s domain has existed for many years.'
                  : isPageLegit
                  ? 'The live page check found a normal page of this website.'
                  : isReputableSite
                  ? 'No phishing lure was found on this well-established website.'
                  : isHttpReputable
                  ? 'No phishing pattern was found apart from the missing HTTPS connection.'
                  : 'No suspicious phishing indicators were detected.'}
              </strong>
            </div>
            {(isReputableSite || isHttpReputable || isPageLegit || isEstablished) && explain?.security_analysis ? (
              explain.security_analysis.map((line, index) => <p key={index}>{line}</p>)
            ) : (
              <p>
                The URL structure matches characteristics commonly associated with
                legitimate websites.
              </p>
            )}
          </section>

          <section className="panel result-section">
            <h3>Why was this classified as legitimate?</h3>
            <p className="section-intro">
              {isEstablished
                ? 'The URL pattern alone scored this address high, but the domain\'s age shows why it is still legitimate. The AI Explanation Evidence section further down shows the signals (SHAP/LIME) that support this result:'
                : isPageLegit
                ? 'On the URL alone this address looked suspicious, but the live page check shows why it is still legitimate. The AI Explanation Evidence section further down shows the signals (SHAP/LIME) that support this result:'
                : isReputableSite
                ? 'The URL pattern alone scored this address high. The checks below show why it is still legitimate. The AI Explanation Evidence section further down shows the signals (SHAP/LIME) that support this result:'
                : isHttpReputable
                ? 'The only warning signal for this URL is the missing HTTPS connection. The explanation below is in plain language — the AI Explanation Evidence section further down shows the technical model signals (SHAP/LIME) behind it:'
                : 'The AI model identified no significant phishing patterns from the URL. The explanation below is in plain language — the AI Explanation Evidence section further down shows the technical model signals (SHAP/LIME) behind it:'}
            </p>
            <ul className="reason-list legitimate-reasons">
              {reasons.slice(0, 7).map((reason, index) => {
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

          <ShapChart
            explain={explain}
            formatValue={formatDetectedValue}
            overrideNote={ruleDecided ? `These are model scores only. The final verdict above also depends on a rule (${overrideNote.charAt(0).toLowerCase()}${overrideNote.slice(1)}).` : null}
          />

          <section className="panel result-section">
            <h3>AI Explanation Evidence</h3>
            <p className="section-intro">
              {isEstablished
                ? 'Only evidence supporting the legitimate classification is shown: the URL signals that point to a legitimate website, and the domain\'s age, which outweighed the signals that raised the URL score (see the chart above).'
                : isPageLegit
                ? 'Only evidence supporting the legitimate classification is shown. The live page check outweighed the signals that raised the URL score (see the chart above).'
                : isReputableSite
                ? "Only evidence supporting the legitimate classification is shown. The signals that raised the URL score (see the chart above) come from the site's own subdomain, path or document ID, so they did not decide the verdict."
                : isHttpReputable
                ? 'The missing-HTTPS signal is shown first, then the strongest signals supporting the legitimate classification.'
                : 'Only evidence supporting the legitimate classification is shown.'}
            </p>

            {!explain ? (
              <p className="empty">Computing explanation…</p>
            ) : evidence.length === 0 ? (
              <p className="empty">No strong supporting evidence was available.</p>
            ) : (
              <div className="evidence-list">
                {evidence.map((item) => (
                  <article className={`evidence-card ${item.shap_contribution > 0 ? 'phishing-evidence' : 'legitimate-evidence'}`} key={item.feature}>
                    <div className="evidence-title">
                      {item.shap_contribution > 0
                        ? <span aria-hidden>⚠</span>
                        : <span className="check-icon" aria-hidden>✓</span>}
                      {item.title}
                    </div>
                    {item.found && (
                      <p>
                        <span className="evidence-kicker">What the AI found: </span>
                        {item.found}
                      </p>
                    )}
                    {item.why_it_matters && (
                      <p>
                        <span className="evidence-kicker">Why this matters: </span>
                        {item.why_it_matters}
                      </p>
                    )}
                    <dl className="evidence-details">
                      <dt>Feature</dt>
                      <dd className="mono">{item.feature}</dd>
                      <dt>Detected Value</dt>
                      <dd className="mono">{formatDetectedValue(item.feature, item.detected_value)}</dd>
                      <dt>Contribution</dt>
                      <dd className={item.shap_contribution > 0 ? 'evidence-danger' : 'evidence-good'}>
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
