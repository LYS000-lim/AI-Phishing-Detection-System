
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
    cache: 'no-store',
  })

  if (res.status === 204) return null
  const data = await res.json().catch(() => ({}))

  if (!res.ok) {
    if (res.status === 401) clearToken()
    throw new Error(errorMessage(data, res.status))
  }
  return data
}

// FastAPI validation errors (422) return `detail` as an array of
// {msg, loc, ...} objects rather than a string - surface the first one
// in plain language instead of letting it stringify to "[object Object]".
function errorMessage(data, status) {
  if (typeof data.detail === 'string') return data.detail
  if (Array.isArray(data.detail) && data.detail.length) {
    // Pydantic prefixes custom validator messages with "Value error, ".
    return data.detail
      .map((d) => (d.msg || JSON.stringify(d)).replace(/^Value error, /, ''))
      .join('; ')
  }
  return `Request failed (${status})`
}

// ------ Auth ------
export const register = (payload) =>
  request('/api/auth/register', { method: 'POST', body: payload, auth: false })
export const login = (payload) =>
  request('/api/auth/login', { method: 'POST', body: payload, auth: false })
export const logout = () => request('/api/auth/logout', { method: 'POST' })
export const me = () => request('/api/auth/me')
export const forgotPassword = (email) =>
  request('/api/auth/forgot-password', { method: 'POST', body: { email }, auth: false })
export const resetPassword = (payload) =>
  request('/api/auth/reset-password', { method: 'POST', body: payload, auth: false })
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
export const myBlockedURLs = () => request('/api/my-blocked-urls')
export const unblockURL = (id) => request(`/api/my-blocked-urls/${id}`, { method: 'DELETE' })
// Admin: every user's extension blocks (admin can unblock any of them)
export const adminUserBlockedURLs = () => request('/api/admin/user-blocked-urls')
export const adminUnblockURL = (id) => request(`/api/admin/user-blocked-urls/${id}`, { method: 'DELETE' })

// ------ Personal history + dashboard ------
export const myDetections = (
  q = '',
  result = '',
  page = 1,
  pageSize = 20,
  risk = '',
  attackType = '',
  dateFrom = '',
  dateTo = '',
  source = ''
) => {
  const params = new URLSearchParams()

  params.set('page', page)
  params.set('page_size', pageSize)

  if (q) params.set('q', q)
  if (result) params.set('result', result)
  if (risk) params.set('risk', risk)
  if (attackType) params.set('attack_type', attackType)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  if (source) params.set('source', source)

  return request(`/api/detections?${params.toString()}`)
}
export const detectionDetail = (id) => request(`/api/detections/${id}`)
export const personalSummary = () => request('/api/detections/summary')
export const detectionsHistorySummary = (source = '') =>
  request(`/api/detections/history-summary${source ? `?source=${source}` : ''}`)
export const detectionsDashboardVisuals = (days = 14, source = '', dateFrom = '', dateTo = '') => {
  const params = new URLSearchParams()
  params.set('days', days)
  if (source) params.set('source', source)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  return request(`/api/detections/dashboard-visuals?${params.toString()}`)
}

// ------ Profile ------
export const getProfile = () => request('/api/profile')
export const updateProfile = (payload) =>
  request('/api/profile', { method: 'PATCH', body: payload })
export const changePassword = (payload) =>
  request('/api/profile/password', { method: 'POST', body: payload })

// ------ Public metrics (Interface 10 preview on login) ------
export const publicMetrics = () => request('/api/metrics', { auth: false })

// ------ Admin ------
export const adminDashboard = (days = 14, source = '', dateFrom = '', dateTo = '') => {
  const params = new URLSearchParams()
  params.set('days', days)
  if (source) params.set('source', source)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  return request(`/api/admin/dashboard?${params.toString()}`)
}
export const adminDetections = (
  q = '',
  result = '',
  page = 1,
  pageSize = 20,
  risk = '',
  attackType = '',
  dateFrom = '',
  dateTo = '',
  source = '',
  mine = false
) => {
  const params = new URLSearchParams()

  params.set('page', page)
  params.set('page_size', pageSize)

  if (q) params.set('q', q)
  if (result) params.set('result', result)
  if (risk) params.set('risk', risk)
  if (attackType) params.set('attack_type', attackType)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  if (source) params.set('source', source)
  if (mine) params.set('mine', 'true')

  return request(
    `/api/admin/detections?${params.toString()}`
  )
}

// ------ Admin URL Scanner ------
export const adminScanURL = (url) =>
  request('/api/admin/scan', { method: 'POST', body: { url } })

// ------ Admin Browser Extension Monitoring ------
export const adminExtensionMonitoring = (dateFrom = '', dateTo = '') => {
  const params = new URLSearchParams()
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  return request(`/api/admin/extension-monitoring?${params.toString()}`)
}

// ------ Detection Logs export ------
export const exportDetections = async (format, filters = {}) => {
  const token = getToken()
  const params = new URLSearchParams()
  params.set('format', format)
  Object.entries(filters).forEach(([k, v]) => { if (v) params.set(k, v) })

  const res = await fetch(`${BASE}/api/admin/detections/export?${params.toString()}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.detail || 'Failed to export report')
  }
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename="?([^"]+)"?/)
  const filename = match ? match[1] : `Detection_Report.${format}`

  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
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
export const adminGlobalShap = (top = 20) => request(`/api/admin/analytics/global-shap?top=${top}`)
export const adminGlobalLime = (top = 20) => request(`/api/admin/analytics/global-lime?top=${top}`)

export const adminReportedURLs = (
  q = '',
  page = 1,
  pageSize = 20,
  dateFrom = '',
  dateTo = '',
  sort = 'newest',
) => {
  const params = new URLSearchParams()

  params.set('page', page)
  params.set('page_size', pageSize)

  if (q) params.set('q', q)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  if (sort) params.set('sort', sort)

  return request(
    `/api/admin/reported-urls?${params.toString()}`
  )
}

// ------ Admin Global Block (blocked for all users) ------
export const adminGlobalBlocks = (q = '', dateFrom = '', dateTo = '') => {
  const params = new URLSearchParams()
  if (q) params.set('q', q)
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  return request(`/api/admin/global-blocks?${params.toString()}`)
}

export const addGlobalBlock = (payload) =>
  request('/api/admin/global-blocks', { method: 'POST', body: payload })

export const removeGlobalBlock = (id) =>
  request(`/api/admin/global-blocks/${id}`, { method: 'DELETE' })

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

// Website "Report URL" submissions go through the same review.
export const approveUserReport = (id) =>
  request(`/api/admin/user-reports/${id}/approve`, { method: 'POST' })

export const rejectUserReport = (id) =>
  request(`/api/admin/user-reports/${id}/reject`, { method: 'POST' })

// ------ Admin Blacklist Export ------
export const exportBlacklistPDF = async (dateFrom = '', dateTo = '') => {
  const token = getToken()

  const headers = {}

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const res = await fetch(
    `${BASE}/api/admin/reported-urls/export?${new URLSearchParams(
      Object.entries({ date_from: dateFrom, date_to: dateTo }).filter(([, v]) => v),
    ).toString()}`,
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
