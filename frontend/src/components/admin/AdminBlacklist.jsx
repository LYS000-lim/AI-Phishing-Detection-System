import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import DateRangeFilter from '../DateRangeFilter.jsx'
import {
  adminReportedURLs, exportBlacklistPDF,
  approveExtensionReport, rejectExtensionReport,
  approveUserReport, rejectUserReport,
  adminGlobalBlocks, addGlobalBlock, removeGlobalBlock,
} from '../../api.js'

// A "Reason" column full of paragraph-length text is unreadable in a table;
// show a short label and let the admin open the full text on demand.
const shortReason = (reason) => {
  if (!reason) return null
  const firstSentence = reason.split(/(?<=[.!?])\s/)[0]
  return firstSentence.length <= 60 ? firstSentence : `${reason.slice(0, 57)}…`
}

// Same labels the detector assigns (backend/app/phishing_type.py).
const ATTACK_TYPES = [
  'Credential Theft', 'Brand Impersonation', 'Financial Scam', 'Fake Giveaway / Scam',
  'Tech Support / Malware Scam', 'General Phishing', 'Other',
]

export default function AdminBlacklist() {
  const [tab, setTab] = useState('reports')

  return (
    <>
      <div className="page-header">
        <h2>Blacklist Database</h2>
        <p className="tagline">
          Review reported URLs, then block confirmed phishing sites for all users.
        </p>
      </div>

      <div className="seg-tabs">
        <button className={tab === 'reports' ? 'active' : ''} onClick={() => setTab('reports')}>
          Reported URLs
        </button>
        <button className={tab === 'global' ? 'active' : ''} onClick={() => setTab('global')}>
          Global Block
        </button>
      </div>

      {tab === 'reports' ? <ReportedURLs /> : <GlobalBlock />}
    </>
  )
}

// Copies text and briefly flips the button label so the admin sees it worked.
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard blocked - the URL is still selectable */ }
  }
  return <button className="link-btn" onClick={copy}>{copied ? 'Copied' : 'Copy URL'}</button>
}

function ReportedURLs() {

  const [rows,setRows] = useState([])
  const [page,setPage] = useState(1)
  const [total,setTotal] = useState(0)
  const pageSize = 20

  const [q,setQ] = useState('')
  const [sort,setSort] = useState('newest')
  const [dateFrom,setDateFrom] = useState('')
  const [dateTo,setDateTo] = useState('')
  const [datesValid,setDatesValid] = useState(true)
  const [loading,setLoading] = useState(true)
  const [error,setError] = useState('')
  const [stats,setStats] = useState(null)
  const [viewing,setViewing] = useState(null)


  const load = () => {
    setLoading(true)

    adminReportedURLs(q,page,pageSize,dateFrom,dateTo,sort)
      .then((data)=>{
        setRows(data.items)
        setTotal(data.total)
        setStats(data.stats)
      })
      .catch((e)=>setError(e.message))
      .finally(()=>setLoading(false))
  }


  useEffect(()=>{
    load()
  },[page, sort])


  const downloadPDF = async()=>{
    try{
      await exportBlacklistPDF(dateFrom,dateTo)
    }catch(e){
      setError(e.message)
    }
  }

  // Row ids are only unique per source, so pick the endpoint by source.
  const approveReport = async(r)=>{

    try{

      await (r.source === "Chrome Extension" ? approveExtensionReport : approveUserReport)(r.id)

      load()

    }catch(e){

      setError(e.message)

    }

  }


  const rejectReport = async(row)=>{

    try{

      await (row.source === "Chrome Extension" ? rejectExtensionReport : rejectUserReport)(row.id)

      // Drop the row immediately; load() then refreshes totals/stats.
      setRows((prev)=>prev.filter((r)=>!(r.source === row.source && r.id === row.id)))
      load()

    }catch(e){

      setError(e.message)

    }

  }


  const totalPages = Math.ceil(total/pageSize)


  return (
    <>
      {stats && (
        <section className="panel">
          <h3>Blacklist Statistics</h3>
          <div className="tiles">
            <div className="tile"><div className="v">{stats.total_saved}</div><div className="k">Total saved URLs</div></div>
            <div className="tile"><div className="v">{stats.new_this_month}</div><div className="k">New this month</div></div>
            <div className="tile"><div className="v">{stats.pending_reports}</div><div className="k">Pending reports</div></div>
            <div className="tile">
              <div className="v" style={{ fontSize: 16 }}>{stats.most_common_attack_category || 'N/A'}</div>
              <div className="k">Most common attack category</div>
            </div>
          </div>
        </section>
      )}

      <section className="panel">

        <div className="filters" style={{ flexWrap: 'wrap' }}>

          <input className="scan-input" placeholder="Search URL..." value={q} onChange={(e)=>setQ(e.target.value)}
            onKeyDown={(e)=>{ if (e.key === 'Enter' && datesValid) { setPage(1); load() } }} />

          <select className="scan-input" value={sort} onChange={(e)=>{ setPage(1); setSort(e.target.value) }}>
            <option value="newest">Newest first</option>
            <option value="most_reported">Most reported first</option>
          </select>

          <DateRangeFilter
            from={dateFrom}
            to={dateTo}
            allowEmpty
            onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
            onValidityChange={setDatesValid}
          />

          <button className="scan-btn small" disabled={!datesValid} onClick={()=>{setPage(1);load()}}>
            Apply
          </button>

          <button className="scan-btn small secondary" disabled={!datesValid} onClick={downloadPDF}>
            Download PDF
          </button>

        </div>


        {error && <div className="error-box">{error}</div>}


        {loading ? (

          <p className="empty">Loading...</p>

        ) : (

          <div className="table-scroll">
          <table className="hist">

            <thead>
              <tr>
                <th>URL</th>
                <th>Reports</th>
                <th>Reported By</th>
                <th>Source</th>
                <th>Attack Type</th>
                <th>Status</th>
                <th>Detection Reason</th>
                <th>Date</th>
                <th>Action</th>
              </tr>
            </thead>


            <tbody>

              {rows.map((r)=>(

                <tr key={`${r.source}-${r.id}`}>

                <td className="mono ellip">
                  {r.url}
                  <div>
                    <CopyButton text={r.url} />
                    {r.globally_blocked && <span className="muted small"> · Blocked for all users</span>}
                  </div>
                </td>


                <td title="Reports of this website (same hostname) from all users">
                  {r.report_count}
                </td>


                <td>
                  {r.reported_by_name ? (
                    <>
                      <div>{r.reported_by_name}</div>
                      <div className="mono muted">{r.reported_by_email}</div>
                    </>
                  ) : (
                    <span className="muted">Anonymous</span>
                  )}
                </td>


                <td>
                  {r.source || "-"}
                </td>


                <td>
                  {r.attack_type || "-"}
                </td>


                <td>
                  {r.status || "-"}
                </td>


                <td>
                  {r.detection_reason ? (
                    <>
                      {shortReason(r.detection_reason)}{' '}
                      <button className="link-btn" onClick={() => setViewing(r)}>View</button>
                    </>
                  ) : "-"}
                </td>


                <td>
                  {utcDate(r.created_at).toLocaleString('en-GB')}
                </td>


                <td>

                {
                  r.status === "pending" &&

                  <>
                    <button
                      className="link-btn"
                      onClick={()=>approveReport(r)}
                    >
                      Save in Database
                    </button>


                    <button
                      className="link-btn"
                      onClick={()=>rejectReport(r)}
                    >
                      Do Not Save in Database
                    </button>
                  </>
                }

                </td>


                </tr>

              ))}

            </tbody>

          </table>
          </div>

        )}


        <div className="pagination">

          <button className="link-btn" disabled={page===1} onClick={()=>setPage(page-1)}>
            Previous
          </button>

          <span>Page {page} / {totalPages || 1}</span>

          <button className="link-btn" disabled={page===totalPages} onClick={()=>setPage(page+1)}>
            Next
          </button>

        </div>


      </section>

      {viewing && (
        <div className="modal-backdrop" onClick={() => setViewing(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Detection Reason</h3>
            <dl className="details">
              <dt>URL</dt><dd className="mono">{viewing.url}</dd>
              <dt>Attack type</dt><dd>{viewing.attack_type || '-'}</dd>
              <dt>Source</dt><dd>{viewing.source || '-'}</dd>
            </dl>
            <p style={{ marginTop: 0 }}>{viewing.detection_reason}</p>
            <div className="modal-actions">
              <button className="scan-btn small" onClick={() => setViewing(null)}>Close</button>
            </div>
          </div>
        </div>
      )}

    </>
  )
}

// Admin pastes any URL and blocks its website for every user. The extension
// already checks this list, so the block applies on the next page visit.
// Only the admin can remove a global block.
function GlobalBlock() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const [url, setUrl] = useState('')
  const [attackType, setAttackType] = useState('')
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirming, setConfirming] = useState(null)
  const [unblocking, setUnblocking] = useState(null)

  const [q, setQ] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [datesValid, setDatesValid] = useState(true)

  const load = () => {
    setLoading(true)
    adminGlobalBlocks(q, dateFrom, dateTo)
      .then(setRows)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const submit = async (confirm = false) => {
    setError(''); setNotice('')
    if (!url.trim()) { setError('Paste a URL or domain to block.'); return }
    setSaving(true)
    try {
      const res = await addGlobalBlock({ url: url.trim(), attack_type: attackType, reason, confirm })
      if (res.needs_confirm) {
        setConfirming(res)
        return
      }
      setConfirming(null)
      setNotice(res.message)
      setUrl(''); setReason(''); setAttackType('')
      load()
    } catch (e) {
      setConfirming(null)
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const unblock = async (row) => {
    setError(''); setNotice('')
    try {
      await removeGlobalBlock(row.id)
      setUnblocking(null)
      setNotice(`${row.domain} unblocked for all users`)
      setRows((prev) => prev.filter((r) => r.id !== row.id))
    } catch (e) {
      setUnblocking(null)
      setError(e.message)
    }
  }

  return (
    <>
      <section className="panel">
        <h3>Block a website for all users</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Paste a URL from the Reported URLs tab or from any other source. The whole
          website (hostname) is blocked, e.g. <span className="mono">https://evil.com/login?id=1</span> blocks{' '}
          <span className="mono">evil.com</span>.
        </p>
        <div className="filters" style={{ flexWrap: 'wrap' }}>
          <input className="scan-input" placeholder="https://example.com/login" value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !saving) submit() }} />
          <select className="scan-input" value={attackType} onChange={(e) => setAttackType(e.target.value)}>
            <option value="">Attack type (optional)</option>
            {ATTACK_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="scan-input" placeholder="Reason (optional)" value={reason}
            onChange={(e) => setReason(e.target.value)} />
          <button className="scan-btn small" disabled={saving} onClick={() => submit()}>
            {saving ? 'Blocking...' : 'Block for all users'}
          </button>
        </div>
        {notice && <div className="ok-box">{notice}</div>}
        {error && <div className="error-box">{error}</div>}
      </section>

      <section className="panel">
        <h3>Globally blocked websites ({rows.length})</h3>
        <div className="filters" style={{ flexWrap: 'wrap' }}>
          <input className="scan-input" placeholder="Search domain..." value={q} onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && datesValid) load() }} />
          <DateRangeFilter
            from={dateFrom}
            to={dateTo}
            allowEmpty
            onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
            onValidityChange={setDatesValid}
          />
          <button className="scan-btn small" disabled={!datesValid} onClick={load}>Apply</button>
        </div>

        {loading ? (
          <p className="empty">Loading...</p>
        ) : rows.length === 0 ? (
          <p className="empty">No websites are blocked for all users.</p>
        ) : (
          <div className="table-scroll">
          <table className="hist">
            <thead>
              <tr>
                <th>Website</th>
                <th>Blocked URL</th>
                <th>Added From</th>
                <th>Attack Type</th>
                <th>Reason</th>
                <th>Date</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.domain}</td>
                  <td className="mono ellip">{r.url}</td>
                  <td>{r.source || '-'}</td>
                  <td>{r.attack_type || '-'}</td>
                  <td>{r.reason ? shortReason(r.reason) : '-'}</td>
                  <td>{utcDate(r.created_at).toLocaleString('en-GB')}</td>
                  <td>
                    <button className="link-btn" onClick={() => setUnblocking(r)}>Unblock</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </section>

      {confirming && (
        <div className="modal-backdrop" onClick={() => setConfirming(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Block a well-known website?</h3>
            <p style={{ marginTop: 0 }}>{confirming.warning}</p>
            <div className="modal-actions">
              <button className="scan-btn small secondary" onClick={() => setConfirming(null)}>Cancel</button>
              <button className="scan-btn small" disabled={saving} onClick={() => submit(true)}>
                Block {confirming.domain} anyway
              </button>
            </div>
          </div>
        </div>
      )}

      {unblocking && (
        <div className="modal-backdrop" onClick={() => setUnblocking(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>Unblock {unblocking.domain}?</h3>
            <p style={{ marginTop: 0 }}>All users will be able to open this website again.</p>
            <div className="modal-actions">
              <button className="scan-btn small secondary" onClick={() => setUnblocking(null)}>Cancel</button>
              <button className="scan-btn small" onClick={() => unblock(unblocking)}>Unblock</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
