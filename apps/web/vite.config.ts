import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  server: {
    port: parseInt(process.env.WEB_PORT || '5173'),
    // `.localhost` enables portless (e.g. https://openkey.localhost) — see README.
    allowedHosts: ['openkey-web.ngrok.app', '.localhost'],
    proxy: {
      '/api': {
        target: process.env.API_URL || `http://localhost:${process.env.API_PORT || '3001'}`,
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
