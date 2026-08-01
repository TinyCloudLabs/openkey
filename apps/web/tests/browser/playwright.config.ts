import { defineConfig, devices } from '@playwright/test';

/**
 * OpenKey signing-approval browser parity tests.
 *
 * Sol MAJOR-1 (final continuation) required Tab, Space, and Enter to
 * be driven through a browser-capable environment — NOT simulated via
 * direct DOM state mutation. These tests boot a real headless Chromium
 * against the SvelteKit dev server, navigate to the dev-only
 * `/__parity_harness` route (which mounts the EXACT production adapter
 * Svelte components), and use `page.keyboard.press` for every
 * interaction. The browser handles focus movement, `<details>` open-
 * on-summary-click, and Enter/Space synthesis on buttons natively.
 *
 * The harness route is guarded by `dev` from `$app/environment`, so it
 * is inert in production builds.
 */
export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',

  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,

  reporter: 'list',

  use: {
    baseURL: 'http://localhost:5779',
    trace: 'off',
    screenshot: 'off',
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    // Start the SvelteKit dev server on a dedicated port so the parity
    // spec can reach the /__parity_harness route without colliding with
    // a developer's own dev instance. Vite's rolldown-driven dependency
    // optimization takes a while on cold start; 3 minutes accommodates
    // that plus SvelteKit sync.
    command: 'vite dev --port 5779 --strictPort',
    url: 'http://localhost:5779/__parity_harness',
    cwd: '../..',
    reuseExistingServer: !process.env.CI,
    timeout: 180000,
  },

  timeout: 60000,

  expect: {
    timeout: 15000,
  },
});
