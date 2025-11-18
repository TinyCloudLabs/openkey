import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const environment = process.env.ENVIRONMENT || 'development';

const baseURLs = {
  development: 'http://localhost:3000',
  staging: 'https://staging.openkey.com',
  production: 'https://openkey.com'
};

const apiURLs = {
  development: 'http://localhost:3001',
  staging: 'https://staging-api.openkey.com',
  production: 'https://api.openkey.com'
};

export default defineConfig({
  testDir: './integration',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results.json' }],
    ['junit', { outputFile: 'test-results.xml' }]
  ],
  use: {
    baseURL: baseURLs[environment as keyof typeof baseURLs],
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    // WebAuthn requires HTTPS in production
    ignoreHTTPSErrors: environment !== 'production'
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    // Mobile testing
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  webServer: environment === 'development' ? [
    {
      command: 'cd ../backend && npm run dev',
      port: 3001,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: 'cd ../frontend && npm run dev',
      port: 3000,
      reuseExistingServer: !process.env.CI,
    }
  ] : undefined,

  // Global setup for authentication and test data
  globalSetup: './setup/global-setup.ts',
  globalTeardown: './setup/global-teardown.ts',
});