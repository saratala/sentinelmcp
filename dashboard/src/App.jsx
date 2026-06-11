import { useEffect, useState } from 'react'
import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import ThreatFeed from './pages/ThreatFeed'
import Inventory from './pages/Inventory'
import Latency from './pages/Latency'
import { api } from './api'

export default function App() {
  const [health, setHealth] = useState(null)

  useEffect(() => {
    const check = async () => {
      try { setHealth(await api.health()) } catch { setHealth(null) }
    }
    check()
    const t = setInterval(check, 15000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar health={health} />
      <main className="flex flex-1">
        <Routes>
          <Route path="/"          element={<ThreatFeed />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/latency"   element={<Latency />} />
        </Routes>
      </main>
    </div>
  )
}
