import { useEffect, useState } from 'react'
import { adminReportedURLs, exportBlacklistPDF, approveExtensionReport, rejectExtensionReport } from '../../api.js'

export default function AdminBlacklist() {

  const [rows,setRows] = useState([])
  const [page,setPage] = useState(1)
  const [total,setTotal] = useState(0)
  const pageSize = 20

  const [q,setQ] = useState('')
  const [loading,setLoading] = useState(true)
  const [error,setError] = useState('')


  const load = () => {
    setLoading(true)

    adminReportedURLs(q,page,pageSize)
      .then((data)=>{
        setRows(data.items)
        setTotal(data.total)
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

                <tr key={r.id}>

                <td className="mono ellip">
                  {r.url}
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
                  {r.detection_reason || "-"}
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
                      Approve
                    </button>


                    <button
                      className="link-btn"
                      onClick={()=>rejectReport(r.id)}
                    >
                      Reject
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

    </>
  )
}