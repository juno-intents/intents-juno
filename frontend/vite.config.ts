import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = (env.VITE_BRIDGE_API_BASE_URL || '').trim()
  const devProxyTarget = (env.VITE_BRIDGE_DEV_PROXY_TARGET || 'http://localhost:19693').trim()

  return {
    plugins: [react()],
    build: {
      outDir: '../internal/bridgeapi/frontend_dist',
      emptyOutDir: true,
    },
    server: apiBase
      ? undefined
      : {
          proxy: {
            '/v1': devProxyTarget,
            '/healthz': devProxyTarget,
          },
        },
  }
})
