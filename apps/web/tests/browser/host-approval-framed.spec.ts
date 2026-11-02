// Real-Chromium checks for the host approval node marker.
// The dev-only `/__parity_harness` route mounts the popup adapter.

import { test, expect, type Page } from '@playwright/test';
import { ORIGIN } from './e2e-port';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';


const OWNER = '0x1111111111111111111111111111111111111111';
const NODE_PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const OTHER_PEER = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const SPACE = `tinycloud:pkh:eip155:1:${OWNER}:default`;
const HARNESS = `${ORIGIN}/__parity_harness`;

function hostConfig(peer: string) {
  const recap = `urn:recap:${Buffer.from(JSON.stringify({ att: { [`${SPACE}/space`]: { 'tinycloud.space/host': [{}] } }, prf: [] })).toString('base64url')}`;
  const message = [
    'app.example wants you to sign in with your Ethereum account:',
    OWNER,
    '',
    `URI: ${peer}`,
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    'Issued At: 2026-10-24T00:00:00.000Z',
    'Resources:',
    `- ${recap}`,
  ].join('\n');
  const model = parseCapabilityReview({
    message,
    signer: { label: 'Selected key', address: OWNER, chainId: 1, provenance: 'managed' },
    editable: false,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example',
      verifiedOrigin: 'https://app.example',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
  return { model, initialSelection: model.permissions.flatMap((grant) => grant.actions.map((action) => action.id)), surface: 'popup' as const };
}

async function setUp(page: Page, peer: string) {
  await page.context().addInitScript((config) => {
    if (location.pathname === '/__parity_harness') {
      (window as unknown as Record<string, unknown>).__openkeyParityHarness = { ...config, calls: [] };
    }
  }, hostConfig(peer));
  for (const origin of ['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz']) {
    await page.context().route(`${origin}/**`, (route) =>
      route.fulfill({ status: 200, body: NODE_PEER, headers: { 'access-control-allow-origin': '*' } }),
    );
  }
}

test('top level: the known marker shows and Approve is enabled at once', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto(HARNESS);
  await expect(page.locator('.host-node-status[data-node-state="known"]')).toHaveText(/Known TinyCloud node at https:\/\/node\.tinycloud\.xyz/);
  await expect(page.locator('button.approve')).toBeEnabled();
  await expect(page.locator('.approve-blocked')).toHaveCount(0);
});

test('an unconfirmed node shows the not-confirmed marker and does not block Approve', async ({ page }) => {
  await setUp(page, OTHER_PEER);
  await page.goto(HARNESS);
  const status = page.locator('.host-node-status[data-node-state="other"]');
  await expect(status).toContainText('Not confirmed as a known TinyCloud node');
  await expect(status).toContainText('Approving lets this node store and serve your new space.');
  await expect(page.locator('button.approve')).toBeEnabled();
});

test('framed Approve can request a preview without a visibility wait', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto(HARNESS);
  await page.setContent(
    `<iframe id="ok" src="${HARNESS}" style="width:520px;height:780px;border:0"></iframe>` +
    '<div style="position:fixed;inset:0;background:#000;opacity:0.02;pointer-events:none"></div>',
  );
  const frame = page.frameLocator('#ok');
  await expect(frame.locator('.host-node-status[data-node-state="known"]')).toBeVisible();
  const approve = frame.locator('button.approve');
  await expect(approve).toBeEnabled();
  await approve.click();
  const inner = page.frames().find((entry) => entry !== page.mainFrame() && entry.url().startsWith(HARNESS))!;
  await expect.poll(() => inner.evaluate(() =>
    ((window as unknown as { __openkeyParityHarness: { calls: Array<{ name: string }> } }).__openkeyParityHarness.calls).map((call) => call.name),
  )).toContain('requestPreview');
  await approve.focus();
  await page.keyboard.press('Enter');
  await expect.poll(() => inner.evaluate(() =>
    ((window as unknown as { __openkeyParityHarness: { calls: Array<{ name: string }> } }).__openkeyParityHarness.calls).map((call) => call.name),
  )).toEqual(['requestPreview', 'requestPreview']);
});
