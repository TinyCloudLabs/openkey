import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  server: {
    port: parseInt(process.env.ADMIN_PORT || '5174'),
    proxy: {
      '/api': {
        target: process.env.API_URL || `http://localhost:${process.env.API_PORT || '3001'}`,
        changeOrigin: true,
      },
    },
  },
});
