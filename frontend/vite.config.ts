import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backend = env.VITE_DEV_BACKEND_URL || 'http://localhost:8000';

  return {
    plugins: react(),
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': { target: backend, changeOrigin: true, ws: true },
        '/health': { target: backend, changeOrigin: true },
      },
    },
    preview: { port: 4173, strictPort: true },
    build: {
      target: 'es2022',
      sourcemap: true,
      chunkSizeWarningLimit: 750,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('/cytoscape/')) return 'graph';
            if (/node_modules\/(react|react-dom|react-router|react-router-dom)\//.test(id.replaceAll('\\', '/'))) return 'react';
            return undefined;
          },
        },
      },
    },
  };
});
