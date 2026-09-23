import { useEffect, useState } from 'react'
import { utcDate } from '../../dates.js'
import { myBlockedURLs, unblockURL } from '../../api.js'

// Websites the user blocked with "Block URL" on the Chrome extension's
// warning page while the extension was signed in to this account.
export default function BlockedWebsites() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [q, setQ] = useState('')

  useEffect(() => {
    myBlockedURLs()
      .then(setRows)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const unblock = async (row) => {
    if (!confirm(`Unblock ${row.hostname}? The extension will scan it normally again.`)) return
    try {
      await unblockURL(row.id)
      setRows((prev) => prev.filter((b) => b.id !== row.id))
    } catch (e) {
      setError(e.message)
    }
  }

  const shown = q
    ? rows.filter((r) => r.url.toLowerCase().includes(q.toLowerCase()))
    : rows

  return (
    <>
      <div className="page-header">
        <h2>Blocked Websites</h2>
        <p className="tagline">
          Websites you blocked with "Block URL" on the extension's warning page.
          The extension blocks the whole domain on every visit until you unblock it here.
        </p>
      </div>

      {error && <div className="error-box">{error}</div>}

      <section className="panel">
        <div className="filters" style={{ marginBottom: 14 }}>
          <input
            className="scan-input"
            placeholder="Search blocked URLs…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        {loading ? (
          <p className="empty">Loading…</p>
        ) : shown.length === 0 ? (
          <p className="empty">
            {rows.length === 0
              ? 'No blocked websites yet. Blocks are saved here when the extension is signed in to your account (Extension Settings → Website Account).'
              : 'No blocked websites match your search.'}
          </p>
        ) : (
          <table className="hist">
            <thead>
              <tr><th>Date Blocked</th><th>Domain</th><th>URL</th><th>Attack Type</th><th></th></tr>
            </thead>
            <tbody>
              {shown.map((b) => (
                <tr key={b.id}>
                  <td>{utcDate(b.created_at).toLocaleString('en-GB')}</td>
                  <td className="mono">{b.hostname}</td>
                  <td className="mono ellip">{b.url}</td>
                  <td>{b.attack_type || '-'}</td>
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
