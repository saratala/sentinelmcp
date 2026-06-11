import { useEffect, useState } from 'react'
import { api } from '../api'

const STATUS_STYLES = {
  clean: 'badge-clean',
  poisoned: 'badge-critical',
  unknown: 'text-xs text-gray-500',
}

export default function Inventory() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = async () => {
    try {
      const d = await api.inventory()
      setData(d)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [])

  if (loading) return <div className="flex-1 flex items-center justify-center text-gray-600">Loading inventory…</div>
  if (error) return (
    <div className="flex-1 flex items-center justify-center flex-col gap-3">
      <span className="text-gray-400 text-sm">Gateway unreachable</span>
      <span className="text-gray-600 text-xs font-mono">{error}</span>
      <button onClick={load} className="mt-2 px-4 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-sm hover:bg-gray-700">Retry</button>
    </div>
  )

  const servers = data?.servers || []
  const clean = servers.filter(s => s.status === 'clean').length
  const poisoned = servers.filter(s => s.status === 'poisoned').length
  const totalTools = servers.reduce((n, s) => n + (s.tool_count || 0), 0)

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">MCP Server Inventory</h1>
          <p className="text-xs text-gray-500 mt-0.5">All discovered MCP servers · auto-refresh 30s</p>
        </div>
        <button onClick={load} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs hover:bg-gray-700 border border-gray-700">
          ↻ Refresh
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card flex flex-col gap-1">
          <span className="text-xs text-gray-500 uppercase tracking-wider">Total Servers</span>
          <span className="text-3xl font-bold text-white">{servers.length}</span>
        </div>
        <div className="card flex flex-col gap-1">
          <span className="text-xs text-gray-500 uppercase tracking-wider">Clean</span>
          <span className="text-3xl font-bold text-green-400">{clean}</span>
        </div>
        <div className="card flex flex-col gap-1">
          <span className="text-xs text-gray-500 uppercase tracking-wider">Poisoned / Blocked</span>
          <span className="text-3xl font-bold text-red-400">{poisoned}</span>
        </div>
      </div>

      {servers.length === 0
        ? (
          <div className="card text-center py-16 text-gray-600">
            <p className="text-4xl mb-3">🗄️</p>
            <p className="text-sm">No servers in schema cache yet.</p>
            <p className="text-xs mt-1">Call <code className="font-mono text-gray-500">POST /gateway/validate-schema</code> to register one.</p>
          </div>
        )
        : (
          <div className="card">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  {['Server URL', 'Status', 'Tools', 'Last Validated', 'Hash'].map(h => (
                    <th key={h} className="pb-2 pr-4 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {servers.map(s => (
                  <tr key={s.server_url} className="hover:bg-gray-800/30 transition-colors">
                    <td className="py-2.5 pr-4 text-gray-300 font-mono max-w-[240px] truncate" title={s.server_url}>
                      {s.server_url}
                    </td>
                    <td className="py-2.5 pr-4">
                      <span className={STATUS_STYLES[s.status] || 'text-gray-400'}>{s.status}</span>
                    </td>
                    <td className="py-2.5 pr-4 text-gray-400 text-center">{s.tool_count ?? '—'}</td>
                    <td className="py-2.5 pr-4 text-gray-500 whitespace-nowrap font-mono">
                      {s.last_validated ? new Date(s.last_validated * 1000).toLocaleTimeString() : '—'}
                    </td>
                    <td className="py-2.5 pr-4 text-gray-600 font-mono">
                      {s.schema_hash ? s.schema_hash.slice(0, 8) + '…' : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-gray-700 mt-3 text-right">{totalTools} total tools registered</p>
          </div>
        )
      }
    </div>
  )
}
