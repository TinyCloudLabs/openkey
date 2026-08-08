import { expect, test } from '@playwright/test';

test('renders the OAuth client name and initial on the signed-out login page', async ({ page }) => {
  await page.route('**/api/auth/oauth2/public-client-prelogin', async (route) => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toEqual({
      client_id: 'shape-rotator',
      oauth_query: 'client_id=shape-rotator&response_type=code&sig=signed',
    });
    await route.fulfill({
      headers: {
        'access-control-allow-origin': 'http://localhost:5779',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        client_name: 'Shape Rotator',
        client_uri: 'https://shape.example',
      }),
    });
  });

  await page.goto('/auth/login?oauth_query=client_id%3Dshape-rotator%26response_type%3Dcode%26sig%3Dsigned');

  await expect(page.getByRole('heading', { name: 'Sign in to Shape Rotator' })).toBeVisible();
  await expect(page.getByRole('img', { name: 'Shape Rotator icon' })).toHaveText('S');
});
