
const BASE = import.meta.env.VITE_API_URL || ''
const TOKEN_KEY = 'pg_token'

export const getToken = () => localStorage.getItem(TOKEN_KEY)
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t)
export const clearToken = () => localStorage.removeItem(TOKEN_KEY)

async function request(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (auth && token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })

  if (res.status === 204) return null
  const data = await res.json().catch(() => ({}))

  if (!res.ok) {
    if (res.status === 401) clearToken()
    throw new Error(data.detail || `Request failed (${res.status})`)
  }
  return data
}

// ------ Auth ------
export const register = (payload) =>
  request('/api/auth/register', { method: 'POST', body: payload, auth: false })
export const login = (payload) =>
  request('/api/auth/login', { method: 'POST', body: payload, auth: false })
export const logout = () => request('/api/auth/logout', { method: 'POST' })
export const me = () => request('/api/auth/me')
// ------ Scan / explain ------
export const scanURL = (url) =>
  request('/api/scan', { method: 'POST', body: { url } })
export const explainURL = (url) =>
  request('/api/explain', { method: 'POST', body: { url } })

// ------ Report phishing URL ------
export const reportURL = (payload) =>
  request('/api/report-url', {
    method: 'POST',
    body: payload,
  })

// ------ Personal history + dashboard ------
export const myDetections = (q = '') =>
  request(`/api/detections${q ? `?q=${encodeURIComponent(q)}` : ''}`)
export const detectionDetail = (id) => request(`/api/detections/${id}`)
export const personalSummary = () => request('/api/detections/summary')

// ------ Profile ------
export const getProfile = () => request('/api/profile')
export const updateProfile = (payload) =>
  request('/api/profile', { method: 'PATCH', body: payload })
export const changePassword = (payload) =>
  request('/api/profile/password', { method: 'POST', body: payload })

// ------ Public metrics (Interface 10 preview on login) ------
export const publicMetrics = () => request('/api/metrics', { auth: false })

// ------ Admin ------
export const adminDashboard = () => request('/api/admin/dashboard')
export const adminDetections = (
  q = '',
  result = '',
  page = 1,
  pageSize = 20
) => {
  const params = new URLSearchParams()

  params.set('page', page)
  params.set('page_size', pageSize)

  if (q) params.set('q', q)
  if (result) params.set('result', result)

  return request(
    `/api/admin/detections?${params.toString()}`
  )
}
export const adminDeleteDetection = (id) =>
  request(`/api/admin/detections/${id}`, { method: 'DELETE' })
export const adminUsers = (q = '') =>
  request(`/api/admin/users${q ? `?q=${encodeURIComponent(q)}` : ''}`)
export const adminCreateUser = (payload) =>
  request('/api/admin/users', { method: 'POST', body: payload })
export const adminUpdateUser = (id, payload) =>
  request(`/api/admin/users/${id}`, { method: 'PATCH', body: payload })
export const adminDeleteUser = (id) =>
  request(`/api/admin/users/${id}`, { method: 'DELETE' })
export const adminAnalytics = () => request('/api/admin/analytics')
export const adminGlobalShap = () => request('/api/admin/analytics/global-shap')

export const adminReportedURLs = (
  q = '',
  page = 1,
  pageSize = 20
) => {
  const params = new URLSearchParams()

  params.set('page', page)
  params.set('page_size', pageSize)

  if (q) params.set('q', q)

  return request(
    `/api/admin/reported-urls?${params.toString()}`
  )
}

// ------ Admin Extension Reports ------

export const approveExtensionReport = (id) =>
  request(
    `/api/admin/extension-reports/${id}/approve`,
    {
      method: 'POST',
    }
  )


export const rejectExtensionReport = (id) =>
  request(
    `/api/admin/extension-reports/${id}/reject`,
    {
      method: 'POST',
    }
  )

// ------ Admin Blacklist Export ------
export const exportBlacklistPDF = async () => {
  const token = getToken()

  const headers = {}

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const res = await fetch(
    `${BASE}/api/admin/reported-urls/export`,
    {
      method: 'GET',
      headers,
    }
  )

  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.detail || 'Failed to export PDF')
  }

  const blob = await res.blob()

  const url = window.URL.createObjectURL(blob)

  const link = document.createElement('a')
  link.href = url
  link.download = 'PhishGuard_Blacklist_Report.pdf'

  document.body.appendChild(link)
  link.click()

  link.remove()

  window.URL.revokeObjectURL(url)
}
