import { forwardRef, useImperativeHandle, useRef } from 'react'
import DateRangeFilter, { isoToDMY } from './DateRangeFilter.jsx'
import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS,
  Legend, LinearScale, LineElement, PointElement, Tooltip,
} from 'chart.js'
import { Bar, Doughnut, Line } from 'react-chartjs-2'
import { themeColors, useThemeColors } from '../theme.js'

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

// Wraps `text` to fit within `maxWidth` for the given canvas context,
// returning one string per line (used to lay out each chart's description
// under its title before drawing the chart image below that).
const wrapText = (ctx, text, maxWidth) => {
  const words = text.split(' ')
  const lines = []
  let line = ''
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word
    if (ctx.measureText(candidate).width > maxWidth && line) {
      lines.push(line)
      line = word
    } else {
      line = candidate
    }
  }
  if (line) lines.push(line)
  return lines
}

// Height (px) needed to draw one summaryTiles group (title + a row of
// label/value stat cards) at the given width, and the drawing itself -
// split so downloadAllCharts can measure total canvas height up front
// before it draws anything.
const TILE_TITLE_HEIGHT = 26
const TILE_ROW_HEIGHT = 62
const TILE_GAP_AFTER = 18

const measureTileGroupHeight = () => TILE_TITLE_HEIGHT + TILE_ROW_HEIGHT + TILE_GAP_AFTER

const drawTileGroup = (ctx, group, x, y, width, c) => {
  ctx.fillStyle = c.text
  ctx.font = 'bold 16px Inter, system-ui, sans-serif'
  ctx.fillText(group.title, x, y + 18)
  y += TILE_TITLE_HEIGHT

  const cardGap = 12
  const cardWidth = (width - cardGap * (group.items.length - 1)) / group.items.length
  group.items.forEach((item, i) => {
    const cardX = x + i * (cardWidth + cardGap)
    ctx.fillStyle = c.panel2
    ctx.fillRect(cardX, y, cardWidth, TILE_ROW_HEIGHT)

    ctx.fillStyle = c.text
    ctx.font = 'bold 18px Inter, system-ui, sans-serif'
    ctx.textAlign = 'center'
    const valueText = String(item.value)
    ctx.fillText(valueText, cardX + cardWidth / 2, y + 26, cardWidth - 10)

    ctx.fillStyle = c.muted
    ctx.font = '11px Inter, system-ui, sans-serif'
    ctx.fillText(item.label, cardX + cardWidth / 2, y + 46, cardWidth - 10)
    ctx.textAlign = 'left'
  })

  return y + TILE_ROW_HEIGHT + TILE_GAP_AFTER
}

// Combines every chart's Chart.js canvas (plus, optionally, the System
// Overview / Threat Intelligence stat tiles drawn directly since they're
// plain DOM, not canvases) into one tall PNG stacked with a title +
// explanatory description per chart, so the download is meaningful on its
// own - a bare chart image with no caption is not useful once it's out of
// the dashboard's context (e.g. pasted into a report). Chart.js canvases
// are transparent, so the composite canvas is filled with the current
// theme's background first - without that, image viewers render the
// transparent areas as white and dark-theme text becomes unreadable.
const downloadAllCharts = async (charts, summaryTiles = []) => {
  const c = themeColors()
  const available = charts.filter(({ ref }) => ref.current)
  if (available.length === 0 && summaryTiles.length === 0) return

  const images = await Promise.all(
    available.map(({ ref }) => loadImage(ref.current.toBase64Image())),
  )

  const padding = 24
  const titleHeight = 26
  const descLineHeight = 18
  const gapBeforeImage = 10
  const width = Math.max(
    summaryTiles.length ? 640 : 0,
    ...images.map((img) => img.width),
  ) + padding * 2

  // Measure description wrapping once up front (needs a canvas context).
  const measureCanvas = document.createElement('canvas')
  const measureCtx = measureCanvas.getContext('2d')
  measureCtx.font = '13px Inter, system-ui, sans-serif'
  const descLines = available.map(({ description }) =>
    description ? wrapText(measureCtx, description, width - padding * 2) : [],
  )

  const tilesHeight = summaryTiles.length * measureTileGroupHeight()
  const chartsHeight = available.reduce((sum, _entry, i) => {
    return sum + titleHeight + descLines[i].length * descLineHeight + gapBeforeImage
      + images[i].height + padding
  }, 0)
  const height = padding + tilesHeight + chartsHeight

  const canvas = document.createElement('canvas')
  canvas.width = width
  canvas.height = height
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = c.bg
  ctx.fillRect(0, 0, width, height)

  let y = padding
  summaryTiles.forEach((group) => {
    y = drawTileGroup(ctx, group, padding, y, width - padding * 2, c)
  })

  available.forEach(({ title }, i) => {
    ctx.fillStyle = c.text
    ctx.font = 'bold 16px Inter, system-ui, sans-serif'
    ctx.fillText(title, padding, y + 18)
    y += titleHeight

    ctx.fillStyle = c.muted
    ctx.font = '13px Inter, system-ui, sans-serif'
    descLines[i].forEach((line) => {
      ctx.fillText(line, padding, y + 13)
      y += descLineHeight
    })
    y += gapBeforeImage

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
 * Source Distribution side by side. The date/source filters live in
 * DashboardFilters (rendered at the top of each dashboard, above the
 * overview tiles); its "Download Report" button calls the charts'
 * downloadAll() via a ref, saving every chart + summary as one PNG.
 */
export function DashboardFilters({ dateFrom, dateTo, source, onRangeChange, onSourceChange, onDownload }) {
  return (
    <section className="panel">
      <div className="filters" style={{ marginBottom: 0, flexWrap: 'wrap' }}>
        <DateRangeFilter from={dateFrom} to={dateTo} onChange={onRangeChange} />
        <label className="date-filter">
          Detection source
          <select className="scan-input" value={source} onChange={(e) => onSourceChange(e.target.value)}>
            {SOURCE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        {onDownload && (
          <button type="button" className="scan-btn small secondary" onClick={onDownload}>
            Download Report
          </button>
        )}
      </div>
    </section>
  )
}

const DashboardVisuals = forwardRef(function DashboardVisuals({
  visuals, dateFrom, dateTo, loading, summaryTiles = [],
}, ref) {
  const c = useThemeColors()
  const trendRef = useRef(null)
  const pieRef = useRef(null)
  const distRef = useRef(null)
  const attackFreqRef = useRef(null)
  const sourceRef = useRef(null)

  const rangeLabel = visuals?.date_from && visuals?.date_to
    ? `${isoToDMY(visuals.date_from)} to ${isoToDMY(visuals.date_to)}`
    : `${isoToDMY(dateFrom)} to ${isoToDMY(dateTo)}`

  const trend = visuals?.trend || []
  const trendData = {
    labels: trend.map((d) => d.day),
    datasets: [
      { label: 'Phishing', data: trend.map((d) => d.phishing), borderColor: c.bad, backgroundColor: 'rgba(239,68,68,.2)', tension: .3 },
      { label: 'Suspicious', data: trend.map((d) => d.suspicious ?? 0), borderColor: c.warn, backgroundColor: 'rgba(245,158,11,.2)', tension: .3 },
      { label: 'Legitimate', data: trend.map((d) => d.legitimate), borderColor: c.good, backgroundColor: 'rgba(16,185,129,.2)', tension: .3 },
    ],
  }
  const trendOpts = {
    responsive: true,
    plugins: { legend: { labels: { color: c.text } } },
    scales: {
      x: { ticks: { color: c.muted }, grid: { color: c.grid } },
      y: { ticks: { color: c.muted }, grid: { color: c.grid } },
    },
  }

  // Counts of the verdicts users were shown (Phishing / Suspicious / Legitimate).
  const result = { phishing: 0, suspicious: 0, legitimate: 0, ...(visuals?.result_counts || {}) }
  const resultTotal = result.phishing + result.suspicious + result.legitimate
  const share = (n) => (resultTotal ? Math.round((n / resultTotal) * 100) : 0)
  const phishPct = share(result.phishing)
  const suspPct = share(result.suspicious)
  const legitPct = resultTotal ? 100 - phishPct - suspPct : 0
  const pieData = {
    labels: [`Phishing (${phishPct}%)`, `Suspicious (${suspPct}%)`, `Legitimate (${legitPct}%)`],
    datasets: [{ data: [result.phishing, result.suspicious, result.legitimate], backgroundColor: [c.bad, c.warn, c.good], borderWidth: 0 }],
  }

  const dist = visuals?.feature_distribution || {}
  const distData = {
    labels: Object.keys(dist).map((k) => FEATURE_LABELS[k] || k),
    datasets: [{ data: Object.values(dist), backgroundColor: c.accent, borderRadius: 4 }],
  }
  const distOpts = {
    indexAxis: 'y', responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: c.muted }, grid: { color: c.grid } },
      y: { ticks: { color: c.text }, grid: { display: false } },
    },
  }

  const attackFreq = visuals?.attack_category_frequency || []
  const attackFreqData = {
    labels: attackFreq.map((a) => a.category),
    datasets: [{ label: 'Detections', data: attackFreq.map((a) => a.count), backgroundColor: c.accent2, borderRadius: 4 }],
  }
  const attackFreqOpts = {
    responsive: true,
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { title: (items) => attackFreq[items[0].dataIndex]?.category } },
    },
    scales: {
      x: { ticks: { color: c.muted, precision: 0 }, grid: { color: c.grid } },
      y: { ticks: { color: c.muted, callback: (val, i) => shortenLabel(attackFreqData.labels[i]) }, grid: { color: c.grid } },
    },
  }

  const sourceDist = visuals?.source_distribution || []
  const sourceData = {
    labels: sourceDist.map((s) => s.source),
    datasets: [{ label: 'Share of detections', data: sourceDist.map((s) => s.percentage), backgroundColor: [c.accent, c.accent2], borderRadius: 4 }],
  }
  const sourceOpts = {
    responsive: true,
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { label: (item) => `${item.raw}% (${sourceDist[item.dataIndex]?.count} detections)` } },
    },
    scales: {
      x: { ticks: { color: c.muted, callback: (v) => `${v}%` }, grid: { color: c.grid } },
      y: { ticks: { color: c.text }, grid: { display: false } },
    },
  }

  const downloadAll = () => downloadAllCharts([
    {
      ref: trendRef, title: `Threat Trend (${rangeLabel})`,
      description: 'Daily count of phishing, suspicious and legitimate results across all sources during the selected period.',
    },
    {
      ref: pieRef, title: 'Detection Result Overview',
      description: 'Displays the proportion of phishing, suspicious and legitimate results shown by the system.',
    },
    {
      ref: distRef, title: 'Important URL Characteristics',
      description: 'Common URL characteristics found among the detected URLs, such as suspicious keywords, HTTPS usage, long URLs, and IP-based URLs.',
    },
    {
      ref: attackFreqRef, title: 'Attack Category Analysis',
      description: 'Shows the frequency of different phishing techniques identified by the detection system, such as financial scams, credential theft, and brand impersonation.',
    },
    {
      ref: sourceRef, title: 'Detection Source Distribution',
      description: 'Where detections originated: the website\'s Analyse URL scanner, or the Chrome extension. Reflects the selected time period, not the source filter above.',
    },
  ], summaryTiles)
  useImperativeHandle(ref, () => ({ downloadAll }))

  return (
    <>
      <section className="panel">
        <h3>Threat Trend ({rangeLabel})</h3>
        <p className="xai-note" style={{ marginTop: 0 }}>
          Daily count of phishing, suspicious and legitimate results across all sources during the selected period.
        </p>
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
            Displays the proportion of phishing, suspicious and legitimate results shown by the system.
          </p>
          {resultTotal > 0
            ? <Doughnut ref={pieRef} data={pieData} options={{ plugins: { legend: { position: 'bottom', labels: { color: c.text } } } }} />
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
})

export default DashboardVisuals
