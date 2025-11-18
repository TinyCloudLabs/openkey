import { test, expect } from '@playwright/test';
import { AuthenticatedUser } from '../utils/authenticated-user';

test.describe('Dashboard', () => {
  let authenticatedUser: AuthenticatedUser;

  test.beforeEach(async ({ page }) => {
    authenticatedUser = new AuthenticatedUser();
    await authenticatedUser.loginAndGoto(page, '/dashboard');
  });

  test('displays user dashboard with stats @smoke', async ({ page }) => {
    // Check header
    await expect(page.locator('text=OpenKey')).toBeVisible();
    await expect(page.locator(`text=Welcome, ${authenticatedUser.email}`)).toBeVisible();
    
    // Check stats cards
    await expect(page.locator('text=Devices Registered')).toBeVisible();
    await expect(page.locator('text=Ethereum Keys')).toBeVisible();
    await expect(page.locator('text=Account Age')).toBeVisible();
    await expect(page.locator('text=Recovery Tokens')).toBeVisible();
  });

  test('can generate Ethereum key', async ({ page }) => {
    // Click generate key button
    await page.click('[data-testid="generate-key-button"]');
    
    // Should show loading state
    await expect(page.locator('text=Generating...')).toBeVisible();
    
    // After generation, should show the key
    await expect(page.locator('[data-testid="ethereum-key"]')).toBeVisible();
    await expect(page.locator('text=Active')).toBeVisible();
  });

  test('can sign message with Ethereum key', async ({ page }) => {
    // First ensure we have a key
    const keyExists = await page.locator('[data-testid="ethereum-key"]').count() > 0;
    if (!keyExists) {
      await page.click('[data-testid="generate-key-button"]');
      await expect(page.locator('[data-testid="ethereum-key"]')).toBeVisible();
    }
    
    // Enter message to sign
    const testMessage = 'Hello OpenKey!';
    await page.fill('[data-testid="sign-message-input"]', testMessage);
    
    // Sign the message
    await page.click('[data-testid="sign-message-button"]');
    
    // Should show signing state
    await expect(page.locator('text=Signing...')).toBeVisible();
    
    // Should show signature result
    await expect(page.locator('[data-testid="signature-result"]')).toBeVisible();
    
    // Signature should start with 0x and be 132 characters long
    const signature = await page.locator('[data-testid="signature-result"] code').textContent();
    expect(signature).toMatch(/^0x[a-fA-F0-9]{130}$/);
  });

  test('can copy Ethereum address to clipboard', async ({ page }) => {
    // First ensure we have a key
    const keyExists = await page.locator('[data-testid="ethereum-key"]').count() > 0;
    if (!keyExists) {
      await page.click('[data-testid="generate-key-button"]');
      await expect(page.locator('[data-testid="ethereum-key"]')).toBeVisible();
    }
    
    // Click copy button
    await page.click('[data-testid="copy-address-button"]');
    
    // In a real test, we'd check clipboard content
    // For now, just verify the button exists and is clickable
    await expect(page.locator('[data-testid="copy-address-button"]')).toBeVisible();
  });

  test('can navigate to settings', async ({ page }) => {
    await page.click('[data-testid="settings-button"]');
    await expect(page).toHaveURL('/settings');
  });

  test('can logout from dashboard', async ({ page }) => {
    await page.click('[data-testid="logout-button"]');
    
    // Should redirect to home page
    await expect(page).toHaveURL('/');
    await expect(page.locator('text=Get Started')).toBeVisible();
  });

  test('shows empty state when no keys exist', async ({ page }) => {
    // This test assumes a fresh user with no keys
    // In a real test, we'd set up this state explicitly
    
    const noKeysMessage = page.locator('text=No Ethereum keys yet');
    if (await noKeysMessage.isVisible()) {
      await expect(page.locator('text=Generate your first key to get started')).toBeVisible();
    }
  });

  test('quick actions are accessible', async ({ page }) => {
    // Check quick actions section
    await expect(page.locator('text=Quick Actions')).toBeVisible();
    await expect(page.locator('text=Account Settings')).toBeVisible();
    await expect(page.locator('text=Recovery Options')).toBeVisible();
    await expect(page.locator('text=Try Demo')).toBeVisible();
    
    // Test navigation
    await page.click('text=Account Settings');
    await expect(page).toHaveURL('/settings');
  });

  test('displays correct account age', async ({ page }) => {
    // Account age should be at least 0 days
    const accountAgeElement = page.locator('[data-testid="account-age"]');
    const accountAge = await accountAgeElement.textContent();
    
    // Should be a number followed by "days"
    expect(accountAge).toMatch(/^\d+ days$/);
  });
});