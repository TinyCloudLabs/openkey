import { describe, expect, test } from 'bun:test';
import { createOauthBrandingRouter } from '../routes/oauth-branding';
import { isPublicProtocolPath } from '../services/native-delegation/public-protocol';

describe('public OAuth client branding', () => {
  test('returns only client branding and caches it publicly', async () => {
    const router = createOauthBrandingRouter({ oauthClient: { findFirst: async () => ({
      clientId: 'ok_exo', name: 'Exo', icon: 'https://example.com/icon.png',
      organization: { name: 'TinyCloud' }, themeBackgroundColor: '#09090B', themeAccentColor: '#FAFAFA',
    }) } } as never);
    const response = await router.request('/clients/ok_exo/branding');
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(await response.json()).toEqual({
      clientId: 'ok_exo', name: 'Exo', icon: 'https://example.com/icon.png', organization: 'TinyCloud',
      theme: { backgroundColor: '#09090B', accentColor: '#FAFAFA' },
    });
  });

  test('returns 404 when no enabled client matches and grants public CORS routing', async () => {
    const router = createOauthBrandingRouter({ oauthClient: { findFirst: async ({ where }: { where: { clientId: string; disabled: boolean } }) =>
      where.clientId === 'enabled' && where.disabled === false ? {
        clientId: 'enabled', name: 'Enabled', icon: null, organization: null,
        themeBackgroundColor: null, themeAccentColor: null,
      } : null } } as never);
    expect((await router.request('/clients/unknown/branding')).status).toBe(404);
    expect((await router.request('/clients/disabled/branding')).status).toBe(404);
    expect(isPublicProtocolPath('https://api.openkey.so/api/oauth/tinycloud/clients/ok_exo/branding')).toBe(true);
    expect(isPublicProtocolPath('https://api.openkey.so/api/oauth/tinycloud/clients/ok_exo/other')).toBe(false);
  });
});
