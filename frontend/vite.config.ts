import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/bridgeapi/frontend_dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/v1': 'http://localhost:19693',
      '/healthz': 'http://localhost:19693',
    },
  },
})
