import { useEffect, useState } from 'react'

// Pings the content script every installed/enabled extension injects on
// this page (toast.js, document_start) and waits briefly for its reply.
// window.postMessage is the only channel a webpage has to an extension
// without the extension explicitly opting in via externally_connectable -
// there's no API for a page to ask Chrome "is extension X on?" directly,
// so presence is inferred from getting a reply at all.
function usePhishGuardExtensionStatus() {
  const [status, setStatus] = useState('checking') // 'checking' | 'active' | 'not-detected'
  const [version, setVersion] = useState(null)

  useEffect(() => {
    let settled = false
    const onMessage = (event) => {
      if (event.source !== window || event.data?.type !== 'PHISHGUARD_EXTENSION_PONG') return
      settled = true
      setVersion(event.data.version || null)
      setStatus('active')
    }
    window.addEventListener('message', onMessage)
    window.postMessage({ type: 'PHISHGUARD_EXTENSION_PING' }, '*')

    const timeout = setTimeout(() => {
      if (!settled) setStatus('not-detected')
    }, 600)

    return () => {
      window.removeEventListener('message', onMessage)
      clearTimeout(timeout)
    }
  }, [])

  return { status, version }
}

// Status, description and install guide for the one PhishGuard extension.
// Users and admins install the same extension, so both pages share this.
export default function ExtensionInfo({ admin = false }) {
  const extensionStatus = usePhishGuardExtensionStatus()

  return (
    <>
      <section className="panel panel-compact">
        <h3>Extension Status</h3>
        {extensionStatus.status === 'checking' && (
          <p className="xai-note" style={{ margin: 0 }}>Checking…</p>
        )}
        {extensionStatus.status === 'active' && (
          <p style={{ margin: 0 }}>
            <span className="badge legit">● ON</span>
            {extensionStatus.version && (
              <span className="xai-note" style={{ marginLeft: 10 }}>v{extensionStatus.version} detected on this page</span>
            )}
          </p>
        )}
        {extensionStatus.status === 'not-detected' && (
          <>
            <p style={{ margin: 0 }}><span className="badge phish">● OFF / NOT INSTALLED</span></p>
            <p className="xai-note" style={{ marginTop: 8, marginBottom: 0 }}>
              No browser lets a website turn an extension on or off directly (a Chrome security
              boundary, not a PhishGuard limitation) — enable it yourself at <span className="mono">chrome://extensions</span>.
            </p>
          </>
        )}
      </section>

      <section className="panel panel-compact">
        <h3>What it does</h3>
        <ul className="reason-list" style={{ marginTop: 0 }}>
          <li>The extension checks the website you are visiting against the same PhishGuard AI model used on this website.</li>
          <li>It automatically detects suspicious websites and provides warnings before users continue browsing.</li>
          <li>Users do not need to manually copy and paste URLs into the scanner.</li>
          {admin && (
            <li>
              There is no separate admin extension: admins install the same one. Websites
              you block on the Blacklist Database page are blocked in every user's extension.
            </li>
          )}
        </ul>
      </section>

      <section className="panel panel-compact">
        <h3>History Recording Preference</h3>
        <p className="xai-note" style={{ margin: 0 }}>
          History recording preference is managed inside the extension's own
          Settings page. The website does not control extension history settings.
        </p>
      </section>

      <section className="panel panel-compact">
        <h3>Install Guide</h3>
        <p style={{ marginTop: 0 }}>
          The extension is not published on the Chrome Web Store yet. Install
          it as an unpacked extension:
        </p>
        <ol className="install-steps">
          <li>Open <span className="mono">chrome://extensions</span></li>
          <li>Enable <b>Developer Mode</b>.</li>
          <li>Click <b>Load unpacked</b>.</li>
          <li>Select the <span className="mono">extension/</span> folder from the PhishGuard AI project.</li>
          <li>Pin the extension icon for quick access.</li>
          {admin && (
            <li>
              Open the extension's <b>Settings → Website Account</b> and sign in
              with your admin account.
            </li>
          )}
        </ol>
      </section>
    </>
  )
}
