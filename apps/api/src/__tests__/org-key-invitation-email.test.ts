import { afterAll, expect, test } from 'bun:test';
import { mockModules } from './mock-module';
import { asPrisma } from './org-keys-fixtures';

let text = '';
await mockModules({ resend: () => ({ Resend: class {
  emails = { send: async (mail: { text: string }) => { text = mail.text; return { data: { id: 'local-mail' }, error: null }; } };
} }) });
const { invitationEmailDelivery } = await import('../services/org-key-invitation-email?configured-origin-test' as string);
const saved = { RESEND_API_KEY: process.env.RESEND_API_KEY, WEBAUTHN_ORIGIN: process.env.WEBAUTHN_ORIGIN };
afterAll(() => {
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});
test('invitation email stays on the configured OpenKey origin with the secret in its fragment', async () => {
  process.env.RESEND_API_KEY = 'test-only-placeholder';
  process.env.WEBAUTHN_ORIGIN = 'https://preview.example.test';
  const prisma = asPrisma({ user: { findUniqueOrThrow: async () => ({ name: 'Owner', email: 'owner@example.test' }) },
    orgKey: { findUniqueOrThrow: async () => ({ orgName: 'Example' }) } });
  await invitationEmailDelivery(prisma)({ to: 'person@example.test', token: 'opaque-token', invitationId: 'invitation', ownerId: 'owner', keyId: 'key', expiresAt: new Date('2026-11-18T03:00:00Z') });
  expect(text).toContain('https://preview.example.test/org-key-invitations/invitation#token=opaque-token');
  expect(text).not.toContain('https://openkey.so/');
});
