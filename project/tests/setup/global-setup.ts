import { chromium, FullConfig } from '@playwright/test';

async function globalSetup(config: FullConfig) {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  console.log('🧪 Setting up test environment...');
  
  // Check if backend is accessible
  const baseURL = config.projects[0].use.baseURL || 'http://localhost:3000';
  const apiURL = baseURL.replace('3000', '3001');
  
  try {
    const response = await page.goto(`${apiURL}/health`);
    if (response && response.ok()) {
      console.log('✅ Backend health check passed');
    } else {
      console.warn('⚠️ Backend health check failed');
    }
  } catch (error) {
    console.warn('⚠️ Could not reach backend:', error);
  }
  
  // Check if frontend is accessible
  try {
    const response = await page.goto(baseURL);
    if (response && response.ok()) {
      console.log('✅ Frontend health check passed');
    } else {
      console.warn('⚠️ Frontend health check failed');
    }
  } catch (error) {
    console.warn('⚠️ Could not reach frontend:', error);
  }
  
  await browser.close();
}

export default globalSetup;