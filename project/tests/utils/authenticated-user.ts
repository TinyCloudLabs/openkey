import { Page } from '@playwright/test';
import { TestUser } from './test-user';

export class AuthenticatedUser extends TestUser {
  public token?: string;
  
  constructor() {
    super();
  }
  
  /**
   * Login and navigate to a specific page
   * In a real implementation, this would handle WebAuthn mocking
   */
  async loginAndGoto(page: Page, url: string = '/dashboard') {
    // For testing purposes, we'll mock the authentication state
    // In a real test suite, you would:
    // 1. Mock WebAuthn APIs
    // 2. Create test credentials
    // 3. Handle the full auth flow
    
    // Mock localStorage with auth data
    await page.addInitScript((userData) => {
      localStorage.setItem('openkey_token', 'mock-jwt-token');
      localStorage.setItem('openkey_user', JSON.stringify({
        id: 'test-user-id',
        email: userData.email,
        createdAt: new Date().toISOString()
      }));
    }, { email: this.email });
    
    // Navigate to the target page
    await page.goto(url);
  }
  
  /**
   * Mock API responses for authenticated requests
   */
  async mockApiResponses(page: Page) {
    // Mock user stats
    await page.route('**/api/user/stats', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          stats: {
            devicesRegistered: 1,
            ethereumKeys: 1,
            activeRecoveryTokens: 0,
            accountAge: 1
          }
        })
      });
    });
    
    // Mock user keys
    await page.route('**/api/user/keys', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          keys: [
            {
              id: 'test-key-id',
              address: '0x742d35Cc6634C0532925a3b8D4C8C8b1f8d01B5e',
              isActive: true,
              createdAt: new Date().toISOString()
            }
          ]
        })
      });
    });
    
    // Mock key generation
    await page.route('**/api/keys/generate', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          address: '0x742d35Cc6634C0532925a3b8D4C8C8b1f8d01B5e',
          keyId: 'test-key-id'
        })
      });
    });
    
    // Mock message signing
    await page.route('**/api/keys/sign', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          signature: '0x' + 'a'.repeat(130), // Mock signature
          address: '0x742d35Cc6634C0532925a3b8D4C8C8b1f8d01B5e'
        })
      });
    });
  }
}