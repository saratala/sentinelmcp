import { useEffect, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell, ResponsiveContainer, Legend,
} from 'recharts'
import { format, parseISO } from 'date-fns'
import { api } from '../api'

const COLORS = { TOOL_POISONING: '#ef4444', RUG_PULL: '#f97316', OUTPUT_INJECTION: '#eab308', CONTEXT_MOSAIC: '#8b5cf6' }
const SEVERITY_COLOR = { CRITICAL: 'badge-critical', HIGH: 'badge-high' }

function StatCard({ label, value, sub, color = 'text-white' }) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
      <span className={`text-3xl font-bold ${color}`}>{value ?? '—'}</span>
      {sub && <span className="text-xs text-gray-600">{sub}</span>}
    </div>
  )
}

export default function ThreatFeed() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const load = async () => {
    try {
      const data = await api.threats(100)
      setThreats(data.threats || [])
      setLastRefresh(new Date())
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [])

  // Derived stats
  const total = threats.length
  const rugPulls = threats.filter(t => t.rug_pull).length
  const criticals = threats.filter(t => t.severity === 'CRITICAL').length
  const servers = new Set(threats.map(t => t.server_url)).size

  // Timeline: bucket by minute
  const buckets = {}
  threats.forEach(t => {
    const min = format(parseISO(t.timestamp), 'HH:mm')
    buckets[min] = (buckets[min] || 0) + 1
  })
  const timeline = Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, count]) => ({ time, count }))

  // By type
  const byType = {}
  threats.forEach(t => { byType[t.threat_type] = (byType[t.threat_type] || 0) + 1 })
  const pieData = Object.entries(byType).map(([name, value]) => ({ name, value }))

  if (loading) return (
    <div className="flex-1 flex items-center justify-center text-gray-600">
      Loading threats…
    </div>
  )

  if (error) return (
    <div className="flex-1 flex items-center justify-center flex-col gap-3">
      <span className="text-4xl">⚠️</span>
      <span className="text-gray-400 text-sm">Gateway unreachable</span>
      <span className="text-gray-600 text-xs font-mono">{error}</span>
      <button onClick={load} className="mt-2 px-4 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-sm hover:bg-gray-700">
        Retry
      </button>
    </div>
  )

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Threat Feed</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            {lastRefresh ? `Refreshed ${format(lastRefresh, 'HH:mm:ss')} · auto-refresh 10s` : ''}
          </p>
        </div>
        <button onClick={load} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs hover:bg-gray-700 border border-gray-700">
          ↻ Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Threats" value={total} color="text-red-400" />
        <StatCard label="Rug Pulls" value={rugPulls} color="text-orange-400" />
        <StatCard label="Critical" value={criticals} color="text-red-300" />
        <StatCard label="Servers Attacked" value={servers} color="text-yellow-400" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card col-span-2">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Threats Over Time</h2>
          {timeline.length === 0
            ? <p className="text-gray-600 text-sm text-center py-8">No data yet — run demo.py</p>
            : (
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
                  <Area type="monotone" dataKey="count" stroke="#ef4444" strokeWidth={2} fill="url(#threatGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            )
          }
        </div>

        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">By Type</h2>
          {pieData.length === 0
            ? <p className="text-gray-600 text-sm text-center py-8">No data yet</p>
            : (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} labelLine={false}>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={COLORS[entry.name] || '#6b7280'} />
                    ))}
                  </Pie>
                  <Legend formatter={(v) => <span className="text-xs text-gray-400">{v}</span>} />
                  <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
            )
          }
        </div>
      </div>

      {/* Live feed table */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Live Threat Feed</h2>
        {threats.length === 0
          ? <p className="text-gray-600 text-sm text-center py-8">No threats detected yet — run demo.py to populate</p>
          : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    {['Time', 'Severity', 'Type', 'Tool', 'Server', 'Pattern', 'Layer', 'Rug Pull'].map(h => (
                      <th key={h} className="pb-2 pr-4 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {threats.slice(0, 50).map(t => (
                    <tr key={t.id} className="hover:bg-gray-800/30 transition-colors">
                      <td className="py-2 pr-4 text-gray-500 whitespace-nowrap font-mono">
                        {format(parseISO(t.timestamp), 'HH:mm:ss')}
                      </td>
                      <td className="py-2 pr-4">
                        <span className={SEVERITY_COLOR[t.severity] || 'badge-high'}>{t.severity}</span>
                      </td>
                      <td className="py-2 pr-4 text-red-400 font-medium whitespace-nowrap">{t.threat_type}</td>
                      <td className="py-2 pr-4 text-gray-300 font-mono">{t.tool_name}</td>
                      <td className="py-2 pr-4 text-gray-500 max-w-[160px] truncate" title={t.server_url}>
                        {t.server_url.replace('https://', '').replace('http://', '')}
                      </td>
                      <td className="py-2 pr-4 text-gray-400 font-mono">{t.pattern}</td>
                      <td className="py-2 pr-4 text-center text-gray-400">L{t.layer}</td>
                      <td className="py-2 pr-4">
                        {t.rug_pull
                          ? <span className="badge-critical">YES</span>
                          : <span className="text-gray-700">—</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </div>
    </div>
  )
}
