import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),

  kit: {
    adapter: adapter(),
    alias: {
      $lib: './src/lib',
      // The approval texts are read from the SDK source, so the web app needs no built SDK.
      '@openkey/sdk/approval-copy': '../../packages/sdk/src/approval-copy/index.ts',
    },
  },
};

export default config;
