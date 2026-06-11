import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import { api } from '../api'

const LAYERS = [
  { key: 'layer1_ms', label: 'L1 Schema', color: '#3b82f6', target: '<1ms (cache hit)', desc: 'Schema validation · SHA-256 hash watch · rug pull detection' },
  { key: 'layer2_ms', label: 'L2 Param',  color: '#10b981', target: '<1ms',             desc: 'Parameter validation · type checking · payload size enforcement' },
  { key: 'layer3_ms', label: 'L3 Output', color: '#f59e0b', target: 'async (non-blocking)', desc: 'Output inspection · pattern matching · circuit breaker trips' },
  { key: 'layer4_ms', label: 'L4 Context',color: '#8b5cf6', target: '<3ms',             desc: 'TF-IDF semantic mosaic detection · cross-category risk scoring' },
]

function MetricCard({ layer, value }) {
  return (
    <div className="card flex flex-col gap-2">
      <div className="flex items-start justify-between">
        <span className="text-xs text-gray-500 uppercase tracking-wider">{layer.label}</span>
        <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500 font-mono">{layer.target}</span>
      </div>
      <span className="text-3xl font-bold text-white font-mono">
        {value != null ? `${value.toFixed(2)}ms` : '—'}
      </span>
      <p className="text-xs text-gray-600 leading-snug">{layer.desc}</p>
    </div>
  )
}

export default function Latency() {
  const [health, setHealth] = useState(null)
  const [error, setError] = useState(null)

  const load = async () => {
    try {
      const d = await api.health()
      setHealth(d)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const latency = health?.latency_ms || {}
  const chartData = LAYERS
    .filter(l => latency[l.key] != null)
    .map(l => ({ name: l.label, ms: latency[l.key], color: l.color }))

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Latency Metrics</h1>
          <p className="text-xs text-gray-500 mt-0.5">Per-layer validation overhead · auto-refresh 5s</p>
        </div>
        <button onClick={load} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs hover:bg-gray-700 border border-gray-700">
          ↻ Refresh
        </button>
      </div>

      {error && (
        <div className="card border-red-800/50 bg-red-900/10 text-sm text-red-400">
          Gateway unreachable: {error}
        </div>
      )}

      <div className="grid grid-cols-4 gap-4">
        {LAYERS.map(l => (
          <MetricCard key={l.key} layer={l} value={latency[l.key]} />
        ))}
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Layer Comparison (ms)</h2>
        {chartData.length === 0
          ? (
            <div className="text-center py-12 text-gray-600">
              <p className="text-sm">No latency data yet.</p>
              <p className="text-xs mt-1">Gateway must be running and have processed at least one request.</p>
            </div>
          )
          : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData} margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} unit="ms" />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  formatter={(v) => [`${v.toFixed(3)}ms`, 'Latency']}
                />
                <Bar dataKey="ms" radius={[4, 4, 0, 0]}>
                  {chartData.map(d => <Cell key={d.name} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )
        }
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Architecture Notes</h2>
        <div className="space-y-3 text-xs text-gray-500 leading-relaxed">
          <p>
            <span className="text-blue-400 font-semibold">Layer 1 (Schema)</span> — Redis cache hit returns in under 1ms. Cache miss fetches and validates the remote schema, then caches for 5 minutes. Background revalidator refreshes every 5 minutes independently.
          </p>
          <p>
            <span className="text-green-400 font-semibold">Layer 2 (Parameters)</span> — Pure in-process validation, no I/O. Checks types, required fields, additionalProperties, and payload size (&lt;64 KB). Runs via asyncio.to_thread to avoid blocking the event loop.
          </p>
          <p>
            <span className="text-yellow-400 font-semibold">Layer 3 (Output)</span> — Fire-and-forget via asyncio.create_task. Never adds latency to the response. Inspects for exfiltration URLs, prompt injection, credential leaks, and hidden instructions. Trips circuit breaker on match.
          </p>
          <p>
            <span className="text-purple-400 font-semibold">Layer 4 (Context)</span> — TF-IDF semantic analysis runs concurrently with Layer 2 via asyncio.gather. Maintains a 20-call sliding window per session. Detects cross-category semantic mosaic attacks (&gt;0.75 risk threshold).
          </p>
        </div>
      </div>
    </div>
  )
}
