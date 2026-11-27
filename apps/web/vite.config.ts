import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';

// Whether the API's terms-release.json in this tree has a release (src/lib/terms-release.ts). Read here and defined as
// a constant, so the app never loads a module from the API's folder (a path the browser specs route as API calls).
const termsRelease = JSON.parse(readFileSync(new URL('../api/src/terms-release.json', import.meta.url), 'utf8')) as { version: string | null };

export default defineConfig({
  define: { __OPENKEY_TERMS_RELEASE__: JSON.stringify(termsRelease.version !== null) },
  plugins: [tailwindcss(), sveltekit()],
  resolve: {
    alias: {
      '@openkey/capability-review': fileURLToPath(
        new URL('../../packages/capability-review/src/index.ts', import.meta.url),
      ),
      '@openkey/delegation-code-fields': fileURLToPath(
        new URL('../../packages/delegation-code-fields/src/index.ts', import.meta.url),
      ),
    },
  },
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
