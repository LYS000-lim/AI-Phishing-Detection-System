import { useState } from 'react'
import { scanURL, explainURL, reportURL } from '../../api.js'

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
      await reportURL({
        url: result.url,

        attack_type: explain?.phishing_analysis
          ? `${explain.phishing_analysis.category} | ${
              explain.phishing_analysis.techniques?.join(" + ") ||
              "Unknown Technique"
            } | Confidence: ${
              explain.phishing_analysis.rule_confidence
            }`
          : null,

        detection_reason:
          explain?.plain_text ||
          "Detected suspicious phishing characteristics",
      })

      setReported(true)

    } catch (e) {
      setError(e.message)
    } finally {
      setReporting(false)
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
          onChange={(e)=>setUrl(e.target.value)}
          onKeyDown={(e)=>e.key==="Enter" && !busy && run()}
        />
        <button
          className="scan-btn"
          onClick={run}
          disabled={busy}
        >
          {busy ? "Scanning..." : "Scan URL"}
        </button>
      </div>
      {error &&
        <div className="error-box">
          {error}
        </div>
      }
    </section>
  {result && (
  <div
  className={`verdict ${
  result.matched_domain
  ? "legit"
  : isPhish
  ? "phish"
  : "legit"
  }`}
  >

  {/* ================= TRUSTED DOMAIN ================= */}

  {result.matched_domain ? (
  <>
  <div className="verdict-row">
  <div>
  <div className="verdict-label">
  ✓ TRUSTED DOMAIN VERIFIED
  </div>
  <div className="verdict-url mono">
  {result.url}
  </div>
  </div>
  <div className="risk-pill risk-low">
  Risk: LOW
  </div>
  </div>
  <div className="security-box">
  <h4>
  Trusted Domain Verification
  </h4>
  <p>
  ✓ Official domain matched:
  </p>
  <p className="mono">
  {result.matched_domain}
  </p>
  <p>
  This website has been verified as an official trusted
  domain. The domain reputation matches known legitimate
  services, indicating a low risk of phishing activity.
  </p>
  <p>
  ✓ URL Pattern Analysis
  </p>
  <p>
  The URL structure does not contain suspicious
  characteristics commonly observed in phishing websites.
  </p>
  <hr/>
  <p>
  <b>AI Analysis:</b>
  </p>
  <p>
  Not required.
  Trusted domain verification completed successfully.
  </p>
  </div>
  </>
  ) : (
  <>

  {/* ================= NORMAL RESULT ================= */}

  <div className="verdict-row">
  <div>
  <div className="verdict-label">
  {isPhish
  ?
  "⚠ PHISHING DETECTED"
  :
  "✓ LEGITIMATE"
  }
  </div>
  <div className="verdict-url mono">
  {result.url}
  </div>
  </div>
  <div className={`risk-pill risk-${riskClass}`}>
  Risk:
  {result.risk_level}
  </div>
  </div>
  <div className="gauge-track">
  <div
  className="gauge-fill"

  style={{
  width:
  `${(
  result.phishing_probability*100
  ).toFixed(1)}%`
  }}
  />
  </div>
  <div className="gauge-caption">

  Phishing
  {" "}
  {(
  result.phishing_probability*100
  ).toFixed(1)}%

  {" · "}

  Legitimate
  {" "}
  {(
  result.legitimate_probability*100
  ).toFixed(1)}%

  </div>
  <div className="verdict-meta">

  <span>
  Model Used:
  <b>{result.model_used}</b>
  </span>
  <span>
  Confidence:
  <b>
  {(
  result.confidence*100
  ).toFixed(1)
  }%
  </b>
  </span>
  </div>

  {/* ================= REPORT ================= */}

  {isPhish && (
  <div className="report-section">
  <button
  className="report-btn"
  onClick={handleReport}
  disabled={reporting || reported}
  >


  {
  reported
  ?
  "URL Reported"
  :
  reporting
  ?
  "Reporting..."
  :
  "Report URL"
  }

  </button>
  </div>
  )}

  {/* ================= PHISHING ANALYSIS ================= */}

  {isPhish && explain?.phishing_analysis && (
  <div className="attack-box">
  <h3>
  Phishing Attack Analysis
  </h3>
  <p>
  <b>
  Attack Category:
  </b>
  {" "}
  {explain.phishing_analysis.category}
  </p>
  <p>
  <b>
  Attack Technique:
  </b>
  {" "}

  {
  explain.phishing_analysis.techniques?.join(
  " / "
  )
  }
  </p>
  <p>

  <b>
  Detection Confidence:
  </b>

  {" "}

  {
  explain.phishing_analysis.rule_confidence
  }
  </p>
  </div>
  )}

  {/* ================= LEGIT SECURITY ================= */}

  {!isPhish && (
  <div className="security-box">
  <h3>
  Security Analysis
  </h3>
  <p>
  ✓ No suspicious phishing indicators were detected.
  </p>
  <p>
  The URL structure matches characteristics commonly
  associated with legitimate websites.
  </p>
  </div>
  )}

  {/* ================= WHY DETECTED ================= */}

  {explain?.plain_text && (
  <div className="plain-text">
  <h4>
  {
  isPhish
  ?
  "Why was this detected?"
  :
  "Why was this classified as legitimate?"
  }
  </h4>
  <p>
  {explain.plain_text}
  </p>
  </div>
  )}

  {/* ================= XAI CARDS ================= */}

  {explain?.xai_cards?.length > 0 && (
  <div className="technical-evidence">
  <h4>
  AI Explanation Evidence
  </h4>
  {
  explain.xai_cards
  .slice(0,3)
  .map((card,index)=>(
  <div
  className="evidence-card"
  key={index}
  >
  <h4>
  {
  isPhish
  ?
  "⚠"
  :
  "✓"
  }
  {" "}
  {card.title}
  </h4>
  <p>
  <b>
  Feature:
  </b>
  {" "}
  {card.feature}
  </p>
  <p>
  <b>
  Detected Value:
  </b>
  {" "}
  {card.value}
  </p>
  <p>
  <b>
  SHAP Contribution:
  </b>
  {" "}
  {card.shap_value}
  </p>
  <p>
  <b>
  LIME Contribution:
  </b>
  {" "}
  {card.lime_value}
  </p>
  </div>
  ))
  }
  </div>
  )}
  </>
  )}
  </div>
  )}
  </>
  )
}