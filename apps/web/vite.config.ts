import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      },
    },
  },
  optimizeDeps: {
    include: ['@better-auth/oauth-provider', '@better-auth/passkey', 'better-auth'],
  },
  ssr: {
    // Don't externalize better-auth packages in SSR - let Vite handle resolution
    noExternal: ['@better-auth/oauth-provider', '@better-auth/passkey', '@better-auth/core', 'better-auth'],
  },
});
