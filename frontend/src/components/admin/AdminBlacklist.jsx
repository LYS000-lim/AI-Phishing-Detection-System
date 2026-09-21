import { useEffect, useState } from 'react'
import { adminReportedURLs, exportBlacklistPDF, approveExtensionReport, rejectExtensionReport } from '../../api.js'

// A "Reason" column full of paragraph-length text is unreadable in a table;
// show a short label and let the admin open the full text on demand.
const shortReason = (reason) => {
  if (!reason) return null
  const firstSentence = reason.split(/(?<=[.!?])\s/)[0]
  return firstSentence.length <= 60 ? firstSentence : `${reason.slice(0, 57)}…`
}

export default function AdminBlacklist() {

  const [rows,setRows] = useState([])
  const [page,setPage] = useState(1)
  const [total,setTotal] = useState(0)
  const pageSize = 20

  const [q,setQ] = useState('')
  const [loading,setLoading] = useState(true)
  const [error,setError] = useState('')
  const [stats,setStats] = useState(null)
  const [viewing,setViewing] = useState(null)


  const load = () => {
    setLoading(true)

    adminReportedURLs(q,page,pageSize)
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
  },[page])


  const downloadPDF = async()=>{
    try{
      await exportBlacklistPDF()
    }catch(e){
      setError(e.message)
    }
  }

  const approveReport = async(id)=>{

    try{

      await approveExtensionReport(id)

      load()

    }catch(e){

      setError(e.message)

    }

  }


  const rejectReport = async(id)=>{

    try{

      await rejectExtensionReport(id)

      load()

    }catch(e){

      setError(e.message)

    }

  }


  const totalPages = Math.ceil(total/pageSize)


  return (
    <>
      <div className="page-header">
        <h2>Blacklist Database</h2>
        <p className="tagline">
          Reported phishing URLs stored for threat intelligence reference.
        </p>
      </div>

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

        <div className="filters">

          <input className="scan-input" placeholder="Search URL..." value={q} onChange={(e)=>setQ(e.target.value)} />

          <button className="scan-btn small" onClick={()=>{setPage(1);load()}}>
            Search
          </button>

          <button className="scan-btn" onClick={downloadPDF}>
            Download PDF
          </button>

        </div>


        {error && <div className="error-box">{error}</div>}


        {loading ? (

          <p className="empty">Loading...</p>

        ) : (

          <table className="hist">

            <thead>
              <tr>
                <th>URL</th>
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
                  {new Date(r.created_at).toLocaleString()}
                </td>


                <td>

                {
                  r.source === "Chrome Extension" &&
                  r.status === "pending" &&

                  <>
                    <button
                      className="link-btn"
                      onClick={()=>approveReport(r.id)}
                    >
                      Save in Database
                    </button>


                    <button
                      className="link-btn"
                      onClick={()=>rejectReport(r.id)}
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