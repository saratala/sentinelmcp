import { NavLink } from 'react-router-dom'

const links = [
  { to: '/',          label: 'Threat Feed',  icon: '🚨' },
  { to: '/inventory', label: 'Inventory',    icon: '🗄️'  },
  { to: '/latency',   label: 'Latency',      icon: '⚡'  },
]

export default function Sidebar({ health }) {
  return (
    <aside className="w-56 shrink-0 flex flex-col bg-gray-900 border-r border-gray-800 min-h-screen">
      {/* Logo */}
      <div className="px-5 py-6 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🛡</span>
          <div>
            <div className="text-sm font-bold text-white leading-tight">SentinelMCP</div>
            <div className="text-xs text-gray-500 leading-tight">Every tool, verified.</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {links.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-red-900/40 text-red-300 border border-red-800/50'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              }`
            }
          >
            <span>{icon}</span>
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Status */}
      <div className="px-5 py-4 border-t border-gray-800">
        <div className="flex items-center gap-2 text-xs">
          <span className={`w-2 h-2 rounded-full ${health ? 'bg-green-400' : 'bg-red-400'}`} />
          <span className="text-gray-500">
            {health ? `v${health.version} · online` : 'gateway offline'}
          </span>
        </div>
      </div>
    </aside>
  )
}
