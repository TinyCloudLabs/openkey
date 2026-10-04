import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    // Static site. The openkey-demo Cloudflare Pages project serves this
    // directory (pages_build_output_dir in wrangler.toml).
    adapter: adapter({ pages: '.svelte-kit/cloudflare' }),
  },
};

export default config;
