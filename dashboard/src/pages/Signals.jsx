import { useEffect, useState } from 'react'
import { api } from '../api'

function StatCard({ label, value, sub, color = 'text-white' }) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
      <span className={`text-3xl font-bold ${color}`}>{value ?? '—'}</span>
      {sub && <span className="text-xs text-gray-600">{sub}</span>}
    </div>
  )
}

function Section({ title, subtitle, children }) {
  return (
    <div className="card">
      <div className="mb-3">
        <h2 className="text-sm font-semibold text-gray-200">{title}</h2>
        {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
      </div>
      {children}
    </div>
  )
}

const pct = (n) => `${Math.round((n || 0) * 100)}%`

export default function Signals() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const load = async () => {
    try { setData(await api.signals()); setError(null) }
    catch (e) { setError(e.message) }
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [])

  const drift = data?.drift || {}
  const oversharing = data?.oversharing || {}
  const hardening = data?.hardening || {}

  return (
    <div className="flex-1 p-6 space-y-6 overflow-auto">
      <div>
        <h1 className="text-xl font-bold text-white">Behavioral Signals</h1>
        <p className="text-sm text-gray-500">
          Temporal &amp; provenance defenses — cross-session drift, context oversharing, and closed-loop hardening.
        </p>
      </div>

      {error && <div className="card text-red-400 text-sm">Could not load signals: {error}</div>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Tools tracked" value={drift.tracked} sub="cross-session fingerprints" />
        <StatCard label="Drifted tools" value={drift.drifted}
                  color={drift.drifted ? 'text-orange-400' : 'text-white'} sub="rug-pull / divergence" />
        <StatCard label="Oversharing sessions" value={oversharing.flagged_sessions}
                  color={oversharing.flagged_sessions ? 'text-yellow-400' : 'text-white'} sub="OWASP MCP10" />
        <StatCard label="Auto-hardened" value={hardening.advisories}
                  color={hardening.advisories ? 'text-green-400' : 'text-white'} sub="advisories synthesized" />
      </div>

      <Section title="Cross-session drift"
               subtitle="Tool descriptions mutating across sessions — invisible to intra-run hash-watch.">
        {(drift.top || []).length === 0 ? (
          <p className="text-sm text-gray-600">No drift observed yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-gray-500 text-xs uppercase">
              <th className="py-1">Tool</th><th>Server</th><th>Drift</th><th>Versions</th><th>Baseline age</th>
            </tr></thead>
            <tbody>
              {drift.top.map((t, i) => (
                <tr key={i} className="border-t border-gray-800">
                  <td className="py-2 text-gray-200">{t.tool_name}</td>
                  <td className="text-gray-500 truncate max-w-[220px]">{t.server_url}</td>
                  <td className={t.drift_score >= 0.4 ? 'text-orange-400' : 'text-gray-400'}>{pct(t.drift_score)}</td>
                  <td className="text-gray-400">{t.distinct_versions}</td>
                  <td className="text-gray-500">{t.baseline_age_days}d</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <div className="grid md:grid-cols-2 gap-6">
        <Section title="Context oversharing"
                 subtitle="Sensitive data egress per agent session (OWASP MCP10).">
          {(oversharing.sessions || []).length === 0 ? (
            <p className="text-sm text-gray-600">No oversharing flagged.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {oversharing.sessions.map((s, i) => (
                <li key={i} className="flex justify-between border-t border-gray-800 pt-2">
                  <span className="text-gray-300">{s.session_id}</span>
                  <span className="text-yellow-400">
                    {s.total_sensitive_items} items → {s.destinations} dest{s.fan_out_exceeded ? ' · fan-out' : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Closed-loop hardening"
                 subtitle="Live defenses auto-synthesized from confirmed probe findings.">
          {(hardening.recent || []).length === 0 ? (
            <p className="text-sm text-gray-600">No auto-synthesized advisories yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {hardening.recent.map((a, i) => (
                <li key={i} className="border-t border-gray-800 pt-2">
                  <div className="flex justify-between">
                    <span className="text-green-400 font-mono text-xs">{a.id}</span>
                    <span className="text-gray-500 text-xs">{a.severity} · {a.owasp}</span>
                  </div>
                  <div className="text-gray-400 text-xs">{a.title}</div>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  )
}
