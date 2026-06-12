import { useEffect, useRef, useState } from 'react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, Cell,
} from 'recharts'
import { api } from '../api'

// Metrics config ─────────────────────────────────────────────────────────────
const LAYER_KEYS = ['l1_schema', 'l2_params', 'l3_output', 'l4_context']
const ALL_KEYS   = [...LAYER_KEYS, 'redis', 'postgres']

const META = {
  l1_schema: { label: 'L1 Schema', color: '#14b8a6', desc: 'Schema validation · SHA-256 hash watch · rug-pull detection',   target: '<1 ms (cache hit)' },
  l2_params: { label: 'L2 Params', color: '#3b82f6', desc: 'Parameter validation · type checking · payload size enforcement', target: '<1 ms' },
  l3_output: { label: 'L3 Output', color: '#f59e0b', desc: 'Output inspection · pattern matching · circuit breaker trips',   target: 'async (non-blocking)' },
  l4_context:{ label: 'L4 Context',color: '#a855f7', desc: 'TF-IDF semantic mosaic detection · cross-category risk scoring',  target: '<3 ms' },
  redis:     { label: 'Redis',     color: '#9ca3af', desc: 'Redis cache round-trip',    target: '' },
  postgres:  { label: 'Postgres',  color: '#f87171', desc: 'Postgres query round-trip', target: '' },
}

const MAX_HISTORY = 30
const POLL_MS     = 10_000

// Helpers ────────────────────────────────────────────────────────────────────
function p99(history, key) {
  const vals = history.map(h => h[key]).filter(v => v != null)
  return vals.length ? Math.max(...vals) : null
}

// Sub-components ─────────────────────────────────────────────────────────────
function StatCard({ metaKey, value, p99Value }) {
  const m = META[metaKey]
  return (
    <div className="card flex flex-col gap-2">
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs text-gray-500 uppercase tracking-wider leading-tight">{m.label}</span>
        {m.target && (
          <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500 font-mono shrink-0">{m.target}</span>
        )}
      </div>
      <div className="flex items-end gap-3">
        <span className="text-3xl font-bold text-white font-mono" style={{ color: m.color }}>
          {value != null ? `${value.toFixed(2)}` : '—'}
          {value != null && <span className="text-base text-gray-500 ml-1">ms</span>}
        </span>
      </div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-gray-600 leading-snug">{m.desc}</span>
      </div>
      <div className="flex items-center gap-1 mt-1 pt-2 border-t border-gray-800">
        <span className="text-gray-600 text-xs">p99 est.</span>
        <span className="font-mono text-xs text-gray-400 ml-auto">
          {p99Value != null ? `${p99Value.toFixed(2)} ms` : '—'}
        </span>
      </div>
    </div>
  )
}

const tooltipStyle = {
  contentStyle: { background: '#111827', border: '1px solid #374151', borderRadius: 8 },
  labelStyle:   { color: '#9ca3af', fontSize: 11 },
  itemStyle:    { fontSize: 12 },
}

// Main page ───────────────────────────────────────────────────────────────────
export default function Latency() {
  const [history, setHistory]   = useState([])   // rolling array of latency_ms snapshots
  const [loading, setLoading]   = useState(true)
  const [error,   setError]     = useState(null)
  const tickRef = useRef(0)

  const load = async () => {
    try {
      const d = await api.health()
      const snap = { ...d.latency_ms, _t: tickRef.current++ }
      setHistory(prev => [...prev.slice(-(MAX_HISTORY - 1)), snap])
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [])

  // Derived data
  const latest  = history[history.length - 1] || {}
  const barData = ALL_KEYS.map(k => ({ name: META[k].label, ms: latest[k] ?? 0, _key: k }))

  // LineChart data: each point is a snapshot with all layer keys
  const lineData = history.map((snap, i) => {
    const point = { tick: i + 1 }
    LAYER_KEYS.forEach(k => { point[k] = snap[k] })
    return point
  })

  // ── Render ──────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
        Loading latency data…
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Latency Metrics</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Per-layer validation overhead · rolling {MAX_HISTORY}-point window · auto-refresh {POLL_MS / 1000}s
          </p>
        </div>
        <button
          onClick={load}
          className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs hover:bg-gray-700 border border-gray-700"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="card border-red-800/50 bg-red-900/10 text-sm text-red-400 flex items-center gap-2">
          <span className="text-lg">⚠</span>
          <span>Gateway offline — {error}</span>
        </div>
      )}

      {/* p99 stat cards (layers only) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {LAYER_KEYS.map(k => (
          <StatCard
            key={k}
            metaKey={k}
            value={latest[k]}
            p99Value={p99(history, k)}
          />
        ))}
      </div>

      {/* Line chart — rolling history per layer */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Layer Latency Over Time (ms)</h2>
        {lineData.length < 2 ? (
          <div className="text-center py-12 text-gray-600 text-sm">
            Collecting data… need at least 2 samples.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={lineData} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="tick" tick={{ fill: '#9ca3af', fontSize: 11 }} label={{ value: 'sample', position: 'insideBottomRight', offset: -4, fill: '#4b5563', fontSize: 10 }} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} unit="ms" width={48} />
              <Tooltip
                {...tooltipStyle}
                formatter={(v, name) => [`${Number(v).toFixed(3)} ms`, META[name]?.label ?? name]}
              />
              <Legend
                formatter={key => <span style={{ color: META[key]?.color, fontSize: 12 }}>{META[key]?.label ?? key}</span>}
              />
              {LAYER_KEYS.map(k => (
                <Line
                  key={k}
                  type="monotone"
                  dataKey={k}
                  stroke={META[k].color}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4 }}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Bar chart — current snapshot, all 6 metrics */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Current Latency — All Metrics (ms)</h2>
        {!history.length ? (
          <div className="text-center py-12 text-gray-600 text-sm">No data yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} unit="ms" width={48} />
              <Tooltip
                {...tooltipStyle}
                formatter={(v) => [`${Number(v).toFixed(3)} ms`, 'Latency']}
              />
              <Bar dataKey="ms" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                {barData.map(d => (
                  <Cell key={d._key} fill={META[d._key].color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Architecture notes */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Architecture Notes</h2>
        <div className="space-y-3 text-xs text-gray-500 leading-relaxed">
          <p>
            <span style={{ color: META.l1_schema.color }} className="font-semibold">L1 Schema</span> — Redis cache hit returns in under 1 ms. Cache miss fetches and validates the remote schema, then caches for 5 minutes. Background revalidator refreshes independently.
          </p>
          <p>
            <span style={{ color: META.l2_params.color }} className="font-semibold">L2 Params</span> — Pure in-process validation, no I/O. Checks types, required fields, additionalProperties, and payload size (&lt;64 KB). Runs via asyncio.to_thread to avoid blocking the event loop.
          </p>
          <p>
            <span style={{ color: META.l3_output.color }} className="font-semibold">L3 Output</span> — Fire-and-forget via asyncio.create_task. Never adds latency to the response. Inspects for exfiltration URLs, prompt injection, credential leaks, and hidden instructions.
          </p>
          <p>
            <span style={{ color: META.l4_context.color }} className="font-semibold">L4 Context</span> — TF-IDF semantic analysis runs concurrently with L2 via asyncio.gather. Maintains a 20-call sliding window per session. Detects cross-category semantic mosaic attacks (&gt;0.75 risk threshold).
          </p>
        </div>
      </div>
    </div>
  )
}
