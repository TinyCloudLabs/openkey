import { expect, test } from 'bun:test';
import { checkAppKeysFile, verifyAppKeyHandoffFile } from '../services/app-key-handoff';

const appKey = { appId: 'org.example', key: 'settings' };
const listing = {
  type: 'openkey-app-keys',
  app_id: appKey.appId,
  keys: [{ path: 'apps/org.example/settings', abilities: ['decrypt', 'key.create'] }],
};

test.each([
  { ...listing, type: undefined },
  { ...listing, type: 'openkey-manifest' },
  { ...listing, name: 'Example' },
])('refuses a file outside the app-keys format', (file) => {
  const bytes = new TextEncoder().encode(JSON.stringify(file));
  expect(checkAppKeysFile(bytes, appKey)).toEqual({ ok: false, reason: 'file_invalid' });
});

test('reports a media type refusal as file_invalid', async () => {
  const check = await verifyAppKeyHandoffFile(appKey, async () => ({
    ok: false, kind: 'invalid', reason: 'response Content-Type is not application/json',
  }));
  expect(check).toEqual({ ok: false, reason: 'file_invalid' });
});
