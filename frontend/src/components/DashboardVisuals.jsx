import { useRef } from 'react'
import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS,
  Legend, LinearScale, LineElement, PointElement, Tooltip,
} from 'chart.js'
import { Bar, Doughnut, Line } from 'react-chartjs-2'

// Draws each doughnut/pie slice's raw value centered inside the slice
// (e.g. the phishing/legitimate counts on Detection Result Overview),
// since the legend only shows percentages.
const sliceValueLabelsPlugin = {
  id: 'sliceValueLabels',
  afterDatasetsDraw(chart) {
    const types = new Set(['doughnut', 'pie'])
    chart.data.datasets.forEach((dataset, datasetIndex) => {
      const meta = chart.getDatasetMeta(datasetIndex)
      if (!types.has(meta.type)) return
      const { ctx } = chart
      meta.data.forEach((arc, i) => {
        const value = dataset.data[i]
        if (!value) return
        const { x, y } = arc.getCenterPoint()
        ctx.save()
        ctx.fillStyle = '#fff'
        ctx.font = 'bold 14px Inter, system-ui, sans-serif'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(String(value), x, y)
        ctx.restore()
      })
    })
  },
}

ChartJS.register(
  ArcElement, BarElement, CategoryScale, LinearScale,
  LineElement, PointElement, Tooltip, Legend, sliceValueLabelsPlugin,
)

const SOURCE_OPTIONS = [
  { value: '', label: 'All sources' },
  { value: 'website', label: 'Website Scanner' },
  { value: 'extension', label: 'Chrome Extension' },
]

const FEATURE_LABELS = {
  long_url: 'Long URLs',
  https: 'HTTPS URLs',
  ip_domain: 'IP-address URLs',
  suspicious_keywords: 'Suspicious keywords',
  many_subdomains: 'Many subdomains',
}

const shortenLabel = (label) => (label.length > 18 ? `${label.slice(0, 16)}…` : label)

const loadImage = (src) => new Promise((resolve, reject) => {
  const img = new Image()
  img.onload = () => resolve(img)
  img.onerror = reject
  img.src = src
})

// Combines every chart's Chart.js canvas into one tall PNG (stacked with
// titles) so the user gets a single download for the whole dashboard
// instead of one file per chart. Chart.js canvases are transparent, so the
// composite canvas is filled with the app's dark background first - without
// that, browsers/image viewers render the transparent areas as white and
// the light theme colors (axis labels, etc.) become unreadable.
const downloadAllCharts = async (charts) => {
  const available = charts.filter(({ ref }) => ref.current)
  if (available.length === 0) return

  const images = await Promise.all(
    available.map(({ ref }) => loadImage(ref.current.toBase64Image())),
  )

  const padding = 24
  const titleHeight = 32
  const width = Math.max(...images.map((img) => img.width)) + padding * 2
  const height = images.reduce((sum, img) => sum + img.height + titleHeight, padding)
    + padding * available.length

  const canvas = document.createElement('canvas')
  canvas.width = width
  canvas.height = height
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = '#0b1220'
  ctx.fillRect(0, 0, width, height)

  let y = padding
  available.forEach(({ title }, i) => {
    ctx.fillStyle = '#e6eef9'
    ctx.font = 'bold 16px Inter, system-ui, sans-serif'
    ctx.fillText(title, padding, y + 20)
    y += titleHeight
    ctx.drawImage(images[i], padding, y)
    y += images[i].height + padding
  })

  const link = document.createElement('a')
  link.href = canvas.toDataURL('image/png')
  link.download = 'dashboard-visuals.png'
  document.body.appendChild(link)
  link.click()
  link.remove()
}

/**
 * Shared chart section for the Admin and User dashboards, so both stay
 * visually consistent: Threat Trend, Detection Result Overview + Important
 * URL Characteristics side by side, Attack Category Analysis + Detection
 * Source Distribution side by side. Interactive: date range and source
 * filters re-fetch the data via onDateFromChange/onDateToChange/onSourceChange,
 * and "Download All Charts" saves every chart as one combined PNG.
 */
export default function DashboardVisuals({
  visuals, dateFrom, dateTo, source,
  onDateFromChange, onDateToChange, onSourceChange, loading,
}) {
  const trendRef = useRef(null)
  const pieRef = useRef(null)
  const distRef = useRef(null)
  const attackFreqRef = useRef(null)
  const sourceRef = useRef(null)

  const rangeLabel = visuals?.date_from && visuals?.date_to
    ? `${visuals.date_from} to ${visuals.date_to}`
    : `${dateFrom} to ${dateTo}`

  const trend = visuals?.trend || []
  const trendData = {
    labels: trend.map((d) => d.day),
    datasets: [
      { label: 'Phishing', data: trend.map((d) => d.phishing), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,.2)', tension: .3 },
      { label: 'Legitimate', data: trend.map((d) => d.legitimate), borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,.2)', tension: .3 },
    ],
  }
  const trendOpts = {
    responsive: true,
    plugins: { legend: { labels: { color: '#e6eef9' } } },
    scales: {
      x: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
      y: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
    },
  }

  const result = visuals?.result_counts || { phishing: 0, legitimate: 0 }
  const resultTotal = result.phishing + result.legitimate
  const phishPct = resultTotal ? Math.round((result.phishing / resultTotal) * 100) : 0
  const legitPct = resultTotal ? 100 - phishPct : 0
  const pieData = {
    labels: [`Phishing (${phishPct}%)`, `Legitimate (${legitPct}%)`],
    datasets: [{ data: [result.phishing, result.legitimate], backgroundColor: ['#ef4444', '#10b981'], borderWidth: 0 }],
  }

  const dist = visuals?.feature_distribution || {}
  const distData = {
    labels: Object.keys(dist).map((k) => FEATURE_LABELS[k] || k),
    datasets: [{ data: Object.values(dist), backgroundColor: '#38bdf8', borderRadius: 4 }],
  }
  const distOpts = {
    indexAxis: 'y', responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8ca3c3' }, grid: { color: '#223350' } },
      y: { ticks: { color: '#e6eef9' }, grid: { display: false } },
    },
  }

  const attackFreq = visuals?.attack_category_frequency || []
  const attackFreqData = {
    labels: attackFreq.map((a) => a.category),
    datasets: [{ label: 'Detections', data: attackFreq.map((a) => a.count), backgroundColor: '#a78bfa', borderRadius: 4 }],
  }
  const attackFreqOpts = {
    responsive: true,
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { title: (items) => attackFreq[items[0].dataIndex]?.category } },
    },
    scales: {
      x: { ticks: { color: '#8ca3c3', precision: 0 }, grid: { color: '#223350' } },
      y: { ticks: { color: '#8ca3c3', callback: (val, i) => shortenLabel(attackFreqData.labels[i]) }, grid: { color: '#223350' } },
    },
  }

  const sourceDist = visuals?.source_distribution || []
  const sourceData = {
    labels: sourceDist.map((s) => s.source),
    datasets: [{ label: 'Share of detections', data: sourceDist.map((s) => s.percentage), backgroundColor: ['#38bdf8', '#a78bfa'], borderRadius: 4 }],
  }
  const sourceOpts = {
    responsive: true,
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { label: (item) => `${item.raw}% (${sourceDist[item.dataIndex]?.count} detections)` } },
    },
    scales: {
      x: { ticks: { color: '#8ca3c3', callback: (v) => `${v}%` }, grid: { color: '#223350' } },
      y: { ticks: { color: '#e6eef9' }, grid: { display: false } },
    },
  }

  const downloadAll = () => downloadAllCharts([
    { ref: trendRef, title: `Threat Trend (${rangeLabel})` },
    { ref: pieRef, title: 'Detection Result Overview' },
    { ref: distRef, title: 'Important URL Characteristics' },
    { ref: attackFreqRef, title: 'Attack Category Analysis' },
    { ref: sourceRef, title: 'Detection Source Distribution' },
  ])

  return (
    <>
      <section className="panel">
        <div className="filters" style={{ marginBottom: 0, flexWrap: 'wrap' }}>
          <label className="date-filter">
            From
            <input type="date" value={dateFrom} max={dateTo} onChange={(e) => onDateFromChange(e.target.value)} />
          </label>
          <label className="date-filter">
            To
            <input type="date" value={dateTo} min={dateFrom} onChange={(e) => onDateToChange(e.target.value)} />
          </label>
          <label className="date-filter">
            Detection source
            <select className="scan-input" value={source} onChange={(e) => onSourceChange(e.target.value)}>
              {SOURCE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </label>
          <button type="button" className="scan-btn small secondary" onClick={downloadAll} style={{ marginLeft: 'auto' }}>
            Download All Charts
          </button>
        </div>
      </section>

      <section className="panel">
        <h3>Threat Trend ({rangeLabel})</h3>
        {loading ? (
          <p className="empty">Loading…</p>
        ) : trend.length > 0 ? (
          <Line ref={trendRef} data={trendData} options={trendOpts} />
        ) : (
          <p className="empty">No scans match this filter.</p>
        )}
      </section>

      <div className="split-2">
        <section className="panel">
          <h3>Detection Result Overview</h3>
          <p className="xai-note" style={{ marginTop: 0 }}>
            Displays the proportion of phishing and legitimate URL classifications detected by the system.
          </p>
          {resultTotal > 0
            ? <Doughnut ref={pieRef} data={pieData} options={{ plugins: { legend: { position: 'bottom', labels: { color: '#e6eef9' } } } }} />
            : <p className="empty">No scans match this filter.</p>}
        </section>
        <section className="panel">
          <h3>Important URL Characteristics</h3>
          <p className="xai-note" style={{ marginTop: 0 }}>
            Common URL characteristics found among the detected URLs, such as
            suspicious keywords, HTTPS usage, long URLs, and IP-based URLs.
          </p>
          {resultTotal > 0
            ? <Bar ref={distRef} data={distData} options={distOpts} />
            : <p className="empty">No scans match this filter.</p>}
        </section>
      </div>

      <div className="split-2">
        <section className="panel">
          <h3>Attack Category Analysis</h3>
          <p className="xai-note" style={{ marginTop: 0 }}>
            Shows the frequency of different phishing techniques identified
            by the detection system, such as financial scams, credential
            theft, and brand impersonation.
          </p>
          {attackFreq.length > 0
            ? <Bar ref={attackFreqRef} data={attackFreqData} options={attackFreqOpts} />
            : <p className="empty">No phishing detections with a known attack type yet.</p>}
        </section>
        <section className="panel">
          <h3>Detection Source Distribution</h3>
          <p className="xai-note" style={{ marginTop: 0 }}>
            Where detections originated: the website's Analyse URL scanner,
            or the Chrome extension. Reflects the selected time period, not
            the source filter above.
          </p>
          {resultTotal > 0
            ? <Bar ref={sourceRef} data={sourceData} options={sourceOpts} />
            : <p className="empty">No scans match this filter.</p>}
        </section>
      </div>
    </>
  )
}
