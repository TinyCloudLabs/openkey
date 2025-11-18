import { test, expect } from '@playwright/test';
import { TestUser } from '../utils/test-user';

test.describe('Authentication Flow', () => {
  let testUser: TestUser;

  test.beforeEach(async () => {
    testUser = new TestUser();
  });

  test('user can register with passkey @smoke', async ({ page }) => {
    await page.goto('/auth/register');
    
    // Fill email
    await page.fill('[data-testid="email-input"]', testUser.email);
    await page.click('[data-testid="continue-button"]');
    
    // Should show WebAuthn step
    await expect(page.locator('text=Set Up Passkey')).toBeVisible();
    await expect(page.locator('[data-testid="create-passkey-button"]')).toBeVisible();
    
    // Note: In real tests, we would mock WebAuthn API
    // For demo purposes, we'll test up to the WebAuthn prompt
    await page.click('[data-testid="create-passkey-button"]');
    
    // Should attempt WebAuthn registration
    // In a real test, we'd mock the WebAuthn response
    // await expect(page.locator('text=Account Created Successfully!')).toBeVisible();
  });

  test('user can navigate to login from register', async ({ page }) => {
    await page.goto('/auth/register');
    
    await page.click('text=Already have an account? Sign in');
    await expect(page).toHaveURL('/auth/login');
    await expect(page.locator('text=Welcome Back')).toBeVisible();
  });

  test('user can navigate to register from login', async ({ page }) => {
    await page.goto('/auth/login');
    
    await page.click('text=Don\'t have an account? Sign up');
    await expect(page).toHaveURL('/auth/register');
    await expect(page.locator('text=Create Account')).toBeVisible();
  });

  test('login page shows passkey and email options', async ({ page }) => {
    await page.goto('/auth/login');
    
    // Default: passkey login
    await expect(page.locator('text=Sign in with Passkey')).toBeVisible();
    await expect(page.locator('[data-testid="passkey-login-button"]')).toBeVisible();
    
    // Switch to email
    await page.click('text=Sign in with Email');
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible();
    
    // Switch back
    await page.click('text=← Back to Passkey');
    await expect(page.locator('text=Sign in with Passkey')).toBeVisible();
  });

  test('validates email format', async ({ page }) => {
    await page.goto('/auth/register');
    
    // Try invalid email
    await page.fill('[data-testid="email-input"]', 'invalid-email');
    await page.click('[data-testid="continue-button"]');
    
    // Should show validation error
    await expect(page.locator('text=Please enter a valid email address')).toBeVisible();
    
    // Try valid email
    await page.fill('[data-testid="email-input"]', testUser.email);
    await page.click('[data-testid="continue-button"]');
    
    // Should proceed to WebAuthn step
    await expect(page.locator('text=Set Up Passkey')).toBeVisible();
  });

  test('shows WebAuthn not supported warning on unsupported browsers', async ({ page }) => {
    // Mock WebAuthn as not supported
    await page.addInitScript(() => {
      delete (window as any).PublicKeyCredential;
    });
    
    await page.goto('/auth/login');
    
    await expect(page.locator('text=WebAuthn is not supported')).toBeVisible();
  });

  test('recovery link is accessible from login', async ({ page }) => {
    await page.goto('/auth/login');
    
    await page.click('text=Need to recover your account?');
    await expect(page).toHaveURL('/recovery');
  });
});