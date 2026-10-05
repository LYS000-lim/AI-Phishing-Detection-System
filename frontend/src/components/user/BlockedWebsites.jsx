import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import { myBlockedURLs, unblockURL, adminUserBlockedURLs, adminUnblockURL } from '../../api.js'
import { useAuth } from '../../AuthContext.jsx'
import DateRangeFilter from '../DateRangeFilter.jsx'

// Websites the user blocked with "Block This Website" on the Chrome
// extension's warning page while the extension was signed in to this
// account. This page is the only place a block can be lifted - the
// extension's block page has no Continue/Unblock button.
// Admins see the same page for their own blocks, plus every user's blocks,
// and can unblock any of them.
export default function BlockedWebsites() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [view, setView] = useState('mine')
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [q, setQ] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const allUsers = isAdmin && view === 'all'

  useEffect(() => {
    setLoading(true)
    setError('')
    ;(allUsers ? adminUserBlockedURLs() : myBlockedURLs())
      .then(setRows)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [allUsers])

  // Deletes the block from the account; the row disappears from this table
  // and the signed-in extension stops blocking the domain on the next visit
  // (it checks the account block list server-side on every navigation).
  const unblock = async (row) => {
    const who = allUsers ? ` for ${row.user_name || row.user_email || 'this user'}` : ''
    if (!confirm(`Unblock ${row.hostname}${who}? The extension will scan it normally again.`)) return
    try {
      await (allUsers ? adminUnblockURL : unblockURL)(row.id)
      setRows((prev) => prev.filter((b) => b.id !== row.id))
    } catch (e) {
      setError(e.message)
    }
  }

  // Local calendar date (YYYY-MM-DD) of each block, compared with the
  // DD/MM/YYYY range picked by the user (DateRangeFilter emits ISO dates).
  const localDay = (value) => {
    const d = utcDate(value)
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  }
  const shown = rows.filter((r) => {
    const needle = q.toLowerCase()
    if (q && !(r.url.toLowerCase().includes(needle)
      || (allUsers && `${r.user_name || ''} ${r.user_email || ''}`.toLowerCase().includes(needle)))) return false
    const day = localDay(r.created_at)
    if (dateFrom && day < dateFrom) return false
    if (dateTo && day > dateTo) return false
    return true
  })

  const riskBadge = (risk) => {
    const r = (risk || 'High').toLowerCase()
    return <span className={`badge ${r === 'high' ? 'phish' : 'review'}`}>{risk || 'High'}</span>
  }

  return (
    <>
      <div className="page-header">
        <h2>Blocked Websites</h2>
        <p className="tagline">
          {allUsers
            ? "Websites every user blocked from the extension. As admin you can unblock any of them; the user's extension scans the site normally again on the next visit."
            : 'Websites you blocked from the extension\'s phishing warning page. The extension blocks the whole domain on every visit, and this page is the only place to unblock it.'}
        </p>
      </div>

      {isAdmin && (
        <div className="seg-tabs">
          <button className={view === 'mine' ? 'active' : ''} onClick={() => setView('mine')}>
            My Blocked Websites
          </button>
          <button className={view === 'all' ? 'active' : ''} onClick={() => setView('all')}>
            All Users' Blocked Websites
          </button>
        </div>
      )}

      {error && <div className="error-box">{error}</div>}

      <section className="panel">
        <div className="filters" style={{ flexWrap: 'wrap', marginBottom: 14 }}>
          <input
            className="scan-input"
            placeholder={allUsers ? 'Search URL or user…' : 'Search blocked URLs…'}
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <DateRangeFilter
            from={dateFrom}
            to={dateTo}
            allowEmpty
            onChange={(f, t) => { setDateFrom(f); setDateTo(t) }}
          />
        </div>

        {loading ? (
          <p className="empty">Loading…</p>
        ) : shown.length === 0 ? (
          <p className="empty">
            {rows.length === 0
              ? (allUsers
                ? 'No user has blocked a website yet.'
                : 'No blocked websites yet. Blocks are saved here when the extension is signed in to your account (Extension Settings → Website Account).')
              : 'No blocked websites match your search or date range.'}
          </p>
        ) : (
          <table className="hist">
            <thead>
              <tr>
                <th>Date Blocked</th>
                {allUsers && <th>Blocked By</th>}
                <th>Domain</th>
                <th>URL</th>
                <th>Risk</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((b) => (
                <tr key={b.id}>
                  <td>{utcDate(b.created_at).toLocaleString('en-GB')}</td>
                  {allUsers && (
                    <td>
                      {b.user_name || '—'}
                      <div className="muted small">{b.user_email}</div>
                    </td>
                  )}
                  <td className="mono">{b.hostname}</td>
                  <td className="mono ellip">{b.url}</td>
                  <td>{riskBadge(b.risk_level)}</td>
                  <td><button className="link-btn" onClick={() => unblock(b)}>Unblock</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
