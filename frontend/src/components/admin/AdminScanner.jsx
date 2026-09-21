import Scanner from '../user/Scanner.jsx'
import { adminScanURL } from '../../api.js'

// Same scanner design/functionality as the user-facing Analyse URL page -
// only the scan call differs, so admin scans are tagged source="admin" in
// Detection Logs and dashboards instead of "website".
export default function AdminScanner() {
  return <Scanner scanFn={adminScanURL} />
}
