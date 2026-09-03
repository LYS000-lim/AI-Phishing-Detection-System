import { useEffect, useState } from 'react'
import {
  BarElement, CategoryScale, Chart as ChartJS,
  Legend, LinearScale, Tooltip,
} from 'chart.js'
import { Bar } from 'react-chartjs-2'
import { adminAnalytics, adminGlobalShap } from '../../api.js'

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const pct = (x) => (x == null ? '-' : (x * 100).toFixed(2) + '%')

function ConfusionMatrix({ cm, title }) {
  if (!cm) return null
  const [[tn, fp], [fn, tp]] = cm
  return (
    <div className="cm-box">
      <div className="cm-title">{title}</div>
      <table className="cm">
        <thead>
          <tr>
            <th></th>
            <th>Pred Legit</th>
            <th>Pred Phish</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th>Actual Legit</th>
            <td className="cm-good">{tn.toLocaleString()}</td>
            <td className="cm-bad">{fp.toLocaleString()}</td>
          </tr>
          <tr>
            <th>Actual Phish</th>
            <td className="cm-bad">{fn.toLocaleString()}</td>
            <td className="cm-good">{tp.toLocaleString()}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}

export default function ModelAnalytics() {
  const [data, setData] = useState(null)
  const [shap, setShap] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    adminAnalytics().then(setData).catch((e) => setError(e.message))
    adminGlobalShap().then(setShap).catch(() => { /* shap is optional */ })
  }, [])

  if (error) return <div className="error-box">{error}</div>
  if (!data) return <p className="empty">Loading model analytics…</p>

  const { models, winner, deployed } = data
  const dt = models.decision_tree
  const rf = models.random_forest

  const cmpData = {
    labels: ['Accuracy', 'Precision', 'Recall', 'F1'],
    datasets: [
      {
        label: 'Decision Tree',
        data: [dt.accuracy, dt.precision, dt.recall, dt.f1_score],
        backgroundColor: '#38bdf8', borderRadius: 4,
      },
      {
        label: 'Random Forest',
        data: [rf.accuracy, rf.precision, rf.recall, rf.f1_score],
        backgroundColor: '#a78bfa', borderRadius: 4,
      },
    ],
  }
  const cmpOpts = {
    responsive: true,
    plugins: { legend: { labels: { color: '#e6eef9' } } },
    scales: {
      x: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
      y: {
        min: 0.9, max: 1,
        ticks: { color: '#8ca3c3', callback: (v) => (v * 100).toFixed(0) + '%' },
        grid: { color: '#223350' },
      },
    },
  }

  return (
    <>
      <div className="page-header">
        <h2>Model Performance &amp; Analytics</h2>
        <p className="tagline">
          Comparison of Decision Tree vs Random Forest on URL-only features.
          Positive class = Phishing (label 1). Deployed:{' '}
          <b>{deployed.name}</b>.
        </p>
      </div>

      <section className="panel">
        <h3>Held-out test metrics (phishing class)</h3>
        <table className="cmp-table">
          <thead>
            <tr>
              <th>Model</th><th>Accuracy</th><th>Precision</th>
              <th>Recall</th><th>F1</th><th></th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Decision Tree</td>
              <td>{pct(dt.accuracy)}</td>
              <td>{pct(dt.precision)}</td>
              <td>{pct(dt.recall)}</td>
              <td>{pct(dt.f1_score)}</td>
              <td>{winner === 'DecisionTree' && <span className="tag win">Winner</span>}</td>
            </tr>
            <tr>
              <td>Random Forest</td>
              <td>{pct(rf.accuracy)}</td>
              <td>{pct(rf.precision)}</td>
              <td>{pct(rf.recall)}</td>
              <td>{pct(rf.f1_score)}</td>
              <td>{winner === 'RandomForest' && <span className="tag win">Winner</span>}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h3>Comparison chart</h3>
        <Bar data={cmpData} options={cmpOpts} />
      </section>

      <div className="split-2">
        <ConfusionMatrix cm={dt.confusion_matrix} title="Decision Tree - confusion matrix" />
        <ConfusionMatrix cm={rf.confusion_matrix} title="Random Forest - confusion matrix" />
      </div>

      <section className="panel">
        <h3>Global SHAP - most influential URL features</h3>
        {!shap ? (
          <p className="empty">Loading global SHAP…</p>
        ) : (
          <>
            <p className="xai-note">{shap.note}</p>
            <table className="hist">
              <thead><tr><th>Rank</th><th>Feature</th><th>Mean |SHAP|</th></tr></thead>
              <tbody>
                {shap.features.map((f, i) => (
                  <tr key={f.name}>
                    <td>{i + 1}</td>
                    <td className="mono">{f.name}</td>
                    <td>{f.mean_abs_shap.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </>
  )
}
