import { test, expect, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const path = `/a/${id}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const capabilities = 'tinycloud.capabilities/read';
const read = 'tinycloud.kv/get';
const write = 'tinycloud.kv/put';
const keyFor = (ability: string) => `${ability === capabilities ? 'tinycloud.capabilities' : 'tinycloud.kv'}\0${space}\0${ability === capabilities ? '' : 'notes/'}\0${ability}`;
const allKeys = [capabilities, read, write].map(keyFor);
const narrowed = [capabilities, read].map(keyFor);

type Scenario = 'success' | 'expired-link' | 'direct-expired' | 'expired-token' | 'busy-expired-code' | 'busy-context-code' | 'refused' | 'twice' | 'second-refused' | 'reject-signature' | 'changed-selection' | 'duplicate-selection' | 'missing-selection' | 'empty-siwe' | 'malformed-siwe' | 'changed-message' | 'mixed-recap' | 'malformed-caveat';
type Call = { path: string; body: Record<string, unknown> };

async function open(page: Page, keyType: 'MANAGED' | 'EXTERNAL', scenario: Scenario, code = 'context-expired') {
  const calls: Call[] = [];
  let prepares = 0;
  let approvals = 0;
  if (keyType === 'EXTERNAL') {
    await page.addInitScript(({ address, reject }) => {
      const signed: string[] = [];
      Object.assign(window, { qaSignedMessages: signed, ethereum: {
        on() {}, removeListener() {},
        async request({ method, params }: { method: string; params?: string[] }) {
          if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [address];
          if (method === 'eth_chainId') return '0x1';
          if (method === 'personal_sign') {
            signed.push(params?.[0] ?? '');
            if (reject && signed.length === 2) throw { code: 4001, message: 'User declined' };
            return `qa-signature-${signed.length}`;
          }
          return null;
        },
      } });
    }, { address, reject: scenario === 'reject-signature' });
  }
  await page.route('**/api/**', async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const raw: unknown = request.postData() ? request.postDataJSON() : {};
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Expected an object request');
    const body = raw as Record<string, unknown>; // Object shape checked above; fields are still unknown.
    calls.push({ path: pathname, body });
    const reply = (status: number, json: unknown) => route.fulfill({ status, json });
    if (pathname === '/api/auth/get-session') return reply(200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    if (pathname === '/api/keys') return reply(200, { keys: [{ id: 'owner-key', address, publicKey: '0x', keyIndex: 0, keyType, isPrimary: true, createdAt: new Date().toISOString() }] });
    if (pathname === `/api/approval-requests/${id}/load`) return reply(200, {
      requestId: id, expiresAt: new Date(Date.now() + 600000).toISOString(), approved: false,
      request: { targetDid: target, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, nodeOrigin: 'https://node.tinycloud.xyz',
        permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [read, write] }], grantLifetimeSeconds: 3600 },
    });
    if (pathname === '/api/delegate/prepare') {
      prepares++;
      // Opening and narrowing each prepare once; the third call is recovery.
      if (prepares >= 3 && scenario === 'refused') return reply(403, { code: 'user-mismatch', error: 'Refused owner session' });
      if (prepares >= 3 && scenario === 'expired-link') return reply(410, { code: 'expired_request', error: 'Link expired' });
      const actionKeys = body.actionKeys;
      if (actionKeys !== undefined && (!Array.isArray(actionKeys) || !actionKeys.every(key => typeof key === 'string'))) throw new Error('Invalid action keys');
      let selected = scenario === 'changed-selection' && prepares >= 3 ? allKeys : actionKeys ?? allKeys;
      if (prepares >= 3 && scenario === 'duplicate-selection') selected = [narrowed[0], narrowed[0]];
      if (prepares >= 3 && scenario === 'missing-selection') selected = [narrowed[0]];
      const att: Record<string, Record<string, object[]>> = {};
      for (const ability of [capabilities, read, write]) {
        if (!selected.includes(keyFor(ability)) && !(prepares >= 3 && scenario === 'changed-message')) continue;
        const resource = ability === capabilities ? `${space}/capabilities` : `${space}/kv/notes/`;
        (att[resource] ??= {})[ability] = [{}];
      }
      let siwe = ['cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '', `URI: ${target}#${target}`,
        'Version: 1', 'Chain ID: 1', `Nonce: qa12345${prepares}`, `Issued At: ${new Date().toISOString()}`,
        `Expiration Time: ${new Date(Date.now() + 3600000).toISOString()}`, 'Resources:', `- ${makeRecapResource(att)}`].join('\n');
      if (prepares >= 3 && scenario === 'empty-siwe') siwe = '';
      if (prepares >= 3 && scenario === 'malformed-siwe') siwe = 'Not a SIWE message';
      if (prepares >= 3 && scenario === 'mixed-recap') siwe += '\n- urn:recap:!!!';
      if (prepares >= 3 && scenario === 'malformed-caveat') {
        const invalid = { att: { [`${space}/kv/notes/`]: { [read]: { invalid: true } } } };
        siwe += `\n- urn:recap:${Buffer.from(JSON.stringify(invalid)).toString('base64url')}`;
      }
      const permissions = [[capabilities], [read, write]].map(abilities => {
        const ability = abilities[0];
        const service = ability === capabilities ? 'capabilities' : 'kv';
        return { key: keyFor(ability).slice(0, keyFor(ability).lastIndexOf('\0')), service, path: ability === capabilities ? '' : 'notes/', label: service, resourcePath: service,
          actions: abilities.map(ability => ({ key: keyFor(ability), ability, action: ability.split('/')[1], required: ability === capabilities })) };
      });
      return reply(200, { prepared: { siwe, spaceId: space, jwk: body.jwk }, spaceId: space, host: body.host, address, chainId: 1,
        permissions, selectedActionKeys: selected, edited: selected.length !== allKeys.length,
        authorizationContext: { token: `context-${prepares}`, expiresAt: Date.now() + 300000 } });
    }
    if (pathname === '/api/delegate' || pathname === '/api/delegate/complete') {
      approvals++;
      if (scenario === 'direct-expired') return reply(410, { code: 'expired_request', error: 'Link expired' });
      if (scenario === 'expired-token') return reply(400, { code: 'expired_token', error: 'Device request expired' });
      if (scenario === 'busy-expired-code') return reply(409, { code: 'expired_request', error: 'Request expired' });
      if (scenario === 'busy-context-code') return reply(409, { code: 'context-expired', error: 'Authorization context expired.' });
      if (approvals === 2 && scenario === 'second-refused') return reply(400, { code: 'user-mismatch', error: 'Refreshed context refused' });
      if (approvals === 1 || scenario === 'twice') return reply(400, { code, error: 'Authorization context expired.' });
      return reply(200, { hostActivated: true });
    }
    return reply(404, { error: `Unexpected QA request ${pathname}` });
  });
  await page.goto(path);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await page.locator('summary').filter({ hasText: 'Advanced details' }).click();
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await page.locator('summary').filter({ hasText: 'Standard permissions' }).click();
  await page.getByRole('checkbox', { name: /write|put|update/i }).uncheck();
  await expect.poll(() => calls.filter(c => c.path === '/api/delegate/prepare').length).toBe(2);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  return { calls, counts: () => ({ prepares, approvals }) };
}

for (const keyType of ['MANAGED', 'EXTERNAL'] as const) {
  for (const code of ['context-expired', 'context-not-found']) {
    test(`${keyType} ${code} refresh keeps the selection and completes approval`, async ({ page }) => {
      const flow = await open(page, keyType, 'success', code);
      await page.getByRole('button', { name: 'Approve', exact: true }).click();
      await expect(page.getByRole('heading', { name: /Authenticated|Approved/ })).toBeVisible();
      expect(flow.counts()).toEqual({ prepares: 3, approvals: 2 });
      const prepare = flow.calls.filter(c => c.path === '/api/delegate/prepare').at(-1)!;
      expect(prepare.body).toMatchObject({ keyId: 'owner-key', approvalRequestId: id, host: 'https://node.tinycloud.xyz', actionKeys: narrowed });
      const completed = flow.calls.filter(c => c.path === '/api/delegate' || c.path === '/api/delegate/complete');
      expect(completed[1].body.selectedActionIds).toEqual(narrowed);
      expect(completed[1].body.authorizationContextToken).toBe('context-3');
      if (keyType === 'EXTERNAL') {
        const signed = await page.evaluate(() => {
          const messages: unknown = Reflect.get(window, 'qaSignedMessages');
          if (!Array.isArray(messages) || !messages.every(message => typeof message === 'string')) throw new Error('Missing signing fixture');
          return messages;
        });
        expect(signed).toHaveLength(2);
        expect(signed[1]).not.toBe(signed[0]);
        expect(completed[1].body.prepared).not.toEqual(completed[0].body.prepared);
        expect(completed[1].body.signature).not.toBe(completed[0].body.signature);
      }
    });
  }
  for (const scenario of ['expired-link', 'direct-expired', 'expired-token', 'busy-expired-code', 'busy-context-code', 'refused', 'twice', 'second-refused', 'changed-selection', 'duplicate-selection', 'missing-selection', 'empty-siwe', 'malformed-siwe', 'changed-message', 'mixed-recap', 'malformed-caveat', ...(keyType === 'EXTERNAL' ? ['reject-signature' as const] : [])] as const) {
    test(`${keyType} ${scenario} ends recovery without another retry`, async ({ page }) => {
      const flow = await open(page, keyType, scenario);
      await page.getByRole('button', { name: 'Approve', exact: true }).click();
      await expect(page.getByRole('alert')).toBeVisible();
      if (scenario === 'direct-expired' || scenario === 'expired-link') {
        // A 410 at the sign sites shows the ended wording, not the panel (the
        // server's expired_request also covers answered/unknown requests).
        await expect(page.getByRole('alert')).toHaveText('This request has already been answered or has ended.');
        await expect(page.getByText('Link expired')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(1);
      } else if (scenario === 'busy-expired-code' || scenario === 'busy-context-code') {
        await expect(page.getByRole('alert')).toHaveText('This request is already being approved. Wait a moment.');
        await expect(page.locator('.expired-request')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(1);
        expect(flow.counts()).toEqual({ prepares: 2, approvals: 1 });
      } else if (scenario === 'expired-token') {
        await expect(page.getByRole('alert')).toHaveText('Device request expired');
        await expect(page.locator('.expired-request')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(1);
      } else {
        await expect(page.locator('.expired-request')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(1);
      }
      expect(flow.counts()).toEqual({ prepares: scenario === 'direct-expired' || scenario === 'expired-token' || scenario === 'busy-expired-code' || scenario === 'busy-context-code' ? 2 : 3, approvals: scenario === 'twice' || scenario === 'second-refused' ? 2 : 1 });
      if (keyType === 'EXTERNAL' && ['duplicate-selection', 'missing-selection', 'empty-siwe', 'malformed-siwe', 'changed-message', 'mixed-recap', 'malformed-caveat'].includes(scenario)) {
        const signatures = await page.evaluate(() => {
          const messages: unknown = Reflect.get(window, 'qaSignedMessages');
          if (!Array.isArray(messages)) throw new Error('Missing signing fixture');
          return messages.length;
        });
        expect(signatures).toBe(1);
      }
      await expect(page.getByRole('alert')).not.toContainText('Authorization context');
    });
  }
}
