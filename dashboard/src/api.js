const API_KEY = import.meta.env.VITE_SENTINEL_API_KEY || 'dev-key-123'
const BASE = import.meta.env.VITE_API_URL || ''

const headers = {
  'Content-Type': 'application/json',
  'X-Sentinel-Key': API_KEY,
}

async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, { headers, ...opts })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export const api = {
  health: () => request('/health'),
  threats: (limit = 50) => request(`/gateway/threats?limit=${limit}`),
  inventory: () => request('/gateway/inventory'),
}
