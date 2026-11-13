import { defineConfig, devices } from '@playwright/test';
import base from './playwright.config';

export default defineConfig({ ...base, testMatch: '**/signin-continuation.spec.ts', projects: [
  { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
  { name: 'iphone', use: { ...devices['iPhone 13'], viewport: { width: 390, height: 844 } } },
] });
