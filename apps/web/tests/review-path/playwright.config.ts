import { defineConfig, devices } from '@playwright/test';
import { E2E_PORT, ORIGIN } from '../browser/e2e-port';

/**
 * "Review path": the app-review sign-in and approval path against a REAL API (a throwaway database, a
 * seeded review account), not routed responses. The workflow starts the API and seeds it
 * (scripts/review-path/seed.ts); this config starts the web dev server, which proxies /api to that API
 * (API_URL / API_PORT), so the browser and the API share one origin, as openkey.so and its API do.
 *
 * Kept apart from tests/browser: those specs answer every API call in the browser and run with no API.
 */
export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',

  // The cases share one signed-in reviewer account and its consent, so they run in file order, once.
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,

  reporter: [['list'], ['json', { outputFile: process.env.REVIEW_PATH_REPORT ?? 'review-path-report.json' }]],

  use: {
    baseURL: ORIGIN,
    trace: 'off',
    screenshot: 'off',
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: {
    command: `vite dev --port ${E2E_PORT} --strictPort`,
    url: `${ORIGIN}/auth/login`,
    cwd: '../..',
    reuseExistingServer: !process.env.CI,
    timeout: 180000,
  },

  timeout: 60000,
  expect: { timeout: 15000 },
});
