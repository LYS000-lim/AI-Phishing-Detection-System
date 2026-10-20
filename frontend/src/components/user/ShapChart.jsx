// SHAP contribution chart and what-if table for the AI Analysis view.
// Bars start at the model's average phishing score (SHAP base value) and
// each one shows how far a feature pushed this URL's score up or down.

const FEATURE_NAMES = {
  URLLength: 'URL length',
  DomainLength: 'Domain length',
  IsDomainIP: 'IP address as domain',
  TLDLegitimateProb: 'Domain ending (TLD)',
  URLCharProb: 'Character pattern',
  TLDLength: 'Domain ending length',
  NoOfSubDomain: 'Number of subdomains',
  HasObfuscation: 'Hidden characters',
  NoOfObfuscatedChar: 'Hidden characters (count)',
  ObfuscationRatio: 'Hidden characters (share)',
  NoOfLettersInURL: 'Number of letters',
  LetterRatioInURL: 'Share of letters',
  NoOfDegitsInURL: 'Number of digits',
  DegitRatioInURL: 'Share of digits',
  NoOfEqualsInURL: "Number of '=' signs",
  NoOfQMarkInURL: "Number of '?' signs",
  NoOfAmpersandInURL: "Number of '&' signs",
  NoOfOtherSpecialCharsInURL: 'Other special characters',
  SpacialCharRatioInURL: 'Share of special characters',
  IsHTTPS: 'Uses HTTPS',
  NoOfSuspiciousWords: 'Suspicious words',
  HasBrandOutsideDomain: 'Brand name outside domain',
}

const TOP_N = 8
// Lookup-table scores (0-1) mean nothing to users, so no value is shown.
const NO_VALUE = new Set(['TLDLegitimateProb', 'URLCharProb'])
const pct = (v) => `${(v * 100).toFixed(1)}%`
const signedPct = (v) => `${v >= 0 ? '+' : '−'}${Math.abs(v * 100).toFixed(1)}%`

// Wording used inside the what-if summary sentence.
const NOUNS = { IsHTTPS: 'HTTPS connection', TLDLegitimateProb: 'domain ending', URLCharProb: 'character pattern' }

const RESULT_LABEL = { phishing: 'Phishing', suspicious: 'Suspicious', legitimate: 'Legitimate' }

// Lookup-table scores are described in words in the what-if table.
const describe = (feature, value, formatValue) => {
  if (feature === 'TLDLegitimateProb') {
    return value >= 0.5 ? 'common ending' : value >= 0.1 ? 'less common ending' : 'rare ending'
  }
  if (feature === 'URLCharProb') return value >= 0.05 ? 'typical characters' : 'unusual characters'
  return formatValue(feature, value)
}

export default function ShapChart({ explain, formatValue, overrideNote }) {
  const shap = explain?.shap
  const items = (shap?.top_features || []).slice(0, TOP_N)
  if (!items.length || shap.base_value == null || shap.model_score == null) return null

  const shown = items.reduce((sum, d) => sum + d.shap_value, 0)
  const rest = shap.model_score - shap.base_value - shown
  const rows = items.map((d) => ({
    key: d.feature,
    name: FEATURE_NAMES[d.feature] || d.feature,
    value: NO_VALUE.has(d.feature) ? '' : formatValue(d.feature, shap.feature_values?.[d.feature]),
    shap: d.shap_value,
  }))
  if (Math.abs(rest) >= 0.001) {
    rows.push({ key: '_rest', name: 'All other features', value: '', shap: rest })
  }
  const max = Math.max(...rows.map((r) => Math.abs(r.shap)), 0.01)

  // Views that do not pass a note (detection logs, extension history) still
  // say when a post-model rule, not the model alone, set the verdict.
  const ruleApplied = (explain?.uncertain_reason && explain.uncertain_reason !== 'borderline')
    || explain?.legit_reason || explain?.escalated_by
  const note = overrideNote !== undefined ? overrideNote
    : ruleApplied ? 'These are model scores only. The final verdict also depends on a post-model rule.' : null
  // The domain-age check works after the URL model, so it is not a SHAP
  // bar: it is shown as a separate last step when its level is the result.
  const s2 = explain?.stage2
  const ageStep = s2 && s2.level === explain?.prediction ? s2 : null
  const whatIf = Array.isArray(explain?.what_if) ? explain.what_if : []
  const towardsLegit = explain?.prediction !== 'legitimate'
  const flips = whatIf.filter((w) => (towardsLegit ? w.model_result === 'legitimate' : w.model_result !== 'legitimate'))
  const names = (list) => list.map((w) => NOUNS[w.feature] || (FEATURE_NAMES[w.feature] || w.feature).toLowerCase()).join(' or ')
  const whatIfText = !whatIf.length
    ? null
    : towardsLegit
    ? flips.length
      ? `Changing the ${names(flips)} alone would make the model score this URL as legitimate, so ${flips.length > 1 ? 'these are' : 'this is'} the main reason for the warning.`
      : 'No single change brings the score below the warning level. Several signals work together here, so fixing one of them would not make this address look safe.'
    : flips.length
    ? `Changing the ${names(flips)} alone would already give this address a warning, so ${flips.length > 1 ? 'these are what keep' : 'this is what keeps'} it looking safe. Take extra care with a copy of this site that differs here.`
    : 'No single change would make this address look risky: several safe signals support the result together.'

  return (
    <section className="panel result-section">
      <h3>How Each Feature Moved the Score</h3>
      <p className="section-intro">
        SHAP shows how much each URL feature pushed the model's phishing score up or down,
        starting from the average score of {pct(shap.base_value)} and ending at this
        URL's score of {pct(shap.model_score)}.
        {ageStep && ` The domain's age then moves it to ${pct(ageStep.p)} (last row).`}
      </p>

      <div className="shap-chart" role="img"
        aria-label={`SHAP contributions: ${rows.map((r) => `${r.name} ${signedPct(r.shap)}`).join(', ')}`}>
        <div className="shap-row shap-axis-row">
          <span />
          <div className="shap-axis">
            <span>← Towards legitimate</span>
            <span>Towards phishing →</span>
          </div>
          <span />
        </div>
        {rows.map((r) => (
          <div className="shap-row" key={r.key}>
            <span className="shap-name" title={r.key}>
              {r.name}
              {r.value && <span className="shap-value"> ({r.value})</span>}
            </span>
            <div className="shap-track">
              <div
                className={`shap-bar ${r.shap >= 0 ? 'up' : 'down'}`}
                style={{ width: `${(Math.abs(r.shap) / max) * 50}%` }}
              />
            </div>
            <span className={`shap-num ${r.shap >= 0 ? 'evidence-danger' : 'evidence-good'}`}>
              {signedPct(r.shap)}
            </span>
          </div>
        ))}
        {ageStep && (
          <div className="shap-row shap-age-row">
            <span className="shap-name">
              Domain age<span className="shap-value"> (registered {ageStep.registered})</span>
            </span>
            <span className="shap-age-text">
              URL score {pct(shap.model_score)} → final {pct(ageStep.p)}
            </span>
            <span className={`shap-num ${ageStep.p >= shap.model_score ? 'evidence-danger' : 'evidence-good'}`}>
              {signedPct(ageStep.p - shap.model_score)}
            </span>
          </div>
        )}
        <div className="shap-legend">
          <span><i className="shap-key up" /> Pushes towards phishing</span>
          <span><i className="shap-key down" /> Pushes towards legitimate</span>
        </div>
      </div>

      {whatIf.length > 0 && (
        <div className="what-if">
          <h4>{towardsLegit ? 'What would change this result?' : 'What would make this look risky?'}</h4>
          <p className="what-if-intro">
            Each row changes one feature to a value that is typical of{' '}
            {towardsLegit ? 'legitimate' : 'phishing'} URLs and asks the model again.
          </p>
          <table className="what-if-table">
            <thead>
              <tr><th>Feature</th><th>Change</th><th>New score</th><th>Model result</th></tr>
            </thead>
            <tbody>
              {whatIf.map((w) => (
                <tr key={w.feature}>
                  <td>{FEATURE_NAMES[w.feature] || w.feature}</td>
                  <td className="what-if-change">
                    {describe(w.feature, w.current, formatValue)} → {describe(w.feature, w.changed, formatValue)}
                  </td>
                  <td className="mono">{pct(w.score_changed)}</td>
                  <td className={`what-if-result ${w.model_result}`}>{RESULT_LABEL[w.model_result]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>{whatIfText}</p>
          {note && <p className="what-if-note">{note}</p>}
        </div>
      )}
    </section>
  )
}
