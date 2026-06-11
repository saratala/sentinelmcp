import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const isGHPages = process.env.GITHUB_ACTIONS === 'true'

export default defineConfig({
  plugins: [react()],
  base: isGHPages ? '/dashboard/' : '/',
  server: {
    proxy: {
      '/gateway': { target: 'http://api:8888', changeOrigin: true },
      '/health':   { target: 'http://api:8888', changeOrigin: true },
    },
  },
})
