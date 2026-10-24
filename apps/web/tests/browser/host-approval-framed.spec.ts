// Real-Chromium checks for the host approval view: the node marker, and the
// framed Approve gate (IntersectionObserver v2 `isVisible`). Chromium only:
// other engines do not report `isVisible`.
//
// The page under test is the dev-only `/__parity_harness` route mounting the
// popup adapter. The "embedding page" is served from a different origin by a
// Playwright route, and the two known node origins are answered by routes
// that stand in for a node.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';

// The embedding page and the dev server are both on loopback; allow the frame.
test.use({
  launchOptions: {
    args: ['--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights'],
  },
});

const OWNER = '0x1111111111111111111111111111111111111111';
const NODE_PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const OTHER_PEER = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const SPACE = `tinycloud:pkh:eip155:1:${OWNER}:default`;
const HARNESS = 'http://localhost:5779/__parity_harness';
const WAIT = 'Approve becomes available once this window is fully visible.';

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
  await page.context().route('http://localhost:5800/**', (route) =>
    route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><body style="margin:0">
        <iframe id="ok" src="${HARNESS}" style="border:0;width:520px;height:780px"></iframe>
        <div id="cover" style="display:none;position:fixed;inset:0;background:#000;opacity:0.02;pointer-events:none"></div>
      </body>`,
    }),
  );
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

test('framed: Approve opens once the view is visible and closes under a cover', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto('http://localhost:5800/');
  const frame = page.frameLocator('#ok');
  await expect(frame.locator('.host-node-status[data-node-state="known"]')).toBeVisible();
  await expect(frame.locator('button.approve')).toBeEnabled();

  // A nearly transparent cover still intersects the frame; only `isVisible` sees it.
  await page.evaluate(() => {
    document.getElementById('cover')!.style.display = 'block';
  });
  await expect(frame.locator('button.approve')).toBeDisabled();
  await expect(frame.locator('.frame-wait')).toHaveText(WAIT);
  await expect(frame.locator('.frame-wait')).toBeVisible();

  await page.evaluate(() => {
    document.getElementById('cover')!.style.display = 'none';
  });
  await expect(frame.locator('button.approve')).toBeEnabled();
  await expect(frame.locator('.frame-wait')).toBeHidden();
});

test('framed: a small cover over only the Approve button closes it', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto('http://localhost:5800/');
  const frame = page.frameLocator('#ok');
  await expect(frame.locator('button.approve')).toBeEnabled();
  const box = (await page.locator('#ok').boundingBox())!;
  const approve = (await frame.locator('button.approve').boundingBox())!;
  await page.evaluate(({ x, y }) => {
    const cover = document.createElement('div');
    cover.id = 'small-cover';
    cover.style.cssText = `position:fixed;left:${x}px;top:${y}px;width:60px;height:24px;background:#000;opacity:0.02;pointer-events:none`;
    document.body.append(cover);
  }, { x: approve.x + 20, y: approve.y + 8 });
  expect(box.width).toBeGreaterThan(0);
  await expect(frame.locator('button.approve')).toBeDisabled();
  await page.evaluate(() => document.getElementById('small-cover')!.remove());
  await expect(frame.locator('button.approve')).toBeEnabled();
});

test('framed: a faded frame closes it', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto('http://localhost:5800/');
  const frame = page.frameLocator('#ok');
  await expect(frame.locator('button.approve')).toBeEnabled();
  await page.evaluate(() => {
    document.getElementById('ok')!.style.opacity = '0.05';
  });
  await expect(frame.locator('button.approve')).toBeDisabled();
  await page.evaluate(() => {
    document.getElementById('ok')!.style.opacity = '1';
  });
  await expect(frame.locator('button.approve')).toBeEnabled();
});

test('framed: a frame scrolled partly out of the embedding page closes it', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto('http://localhost:5800/');
  const frame = page.frameLocator('#ok');
  await expect(frame.locator('button.approve')).toBeEnabled();
  await page.evaluate(() => {
    const wrapper = document.createElement('div');
    wrapper.id = 'clip';
    wrapper.style.cssText = 'position:fixed;left:0;top:0;width:520px;height:300px;overflow:hidden;z-index:1';
    const ok = document.getElementById('ok')!;
    ok.style.position = 'absolute';
    ok.style.top = '0';
    wrapper.append(ok);
    document.body.append(wrapper);
  });
  await expect(frame.locator('button.approve')).toBeDisabled();
});

// The embedding page may size the frame to nothing, wait, and resize it later.
// The delay runs from the moment the view is on screen, not before.
async function approveCalls(page: Page): Promise<string[]> {
  const harness = page.frames().find((frame) => frame.url().startsWith(HARNESS))!;
  return harness.evaluate(() =>
    ((window as unknown as { __openkeyParityHarness: { calls: Array<{ name: string }> } }).__openkeyParityHarness.calls).map((call) => call.name),
  );
}

test('framed: a frame with no size stays closed, and resizing it starts the delay from then', async ({ page }) => {
  await setUp(page, NODE_PEER);
  await page.goto('http://localhost:5800/');
  await page.evaluate(() => {
    const ok = document.getElementById('ok')!;
    ok.style.width = '0';
    ok.style.height = '0';
  });
  const frame = page.frameLocator('#ok');
  const approve = frame.locator('button.approve');
  // Longer than the delay, with the node check finished: nothing is on screen.
  await expect(frame.locator('.host-node-status[data-node-state="known"]')).toBeAttached();
  await page.waitForTimeout(1500);
  await expect(approve).toBeDisabled();

  // Resize so Approve is on screen, and click it at once.
  const resizedAt = Date.now();
  await page.evaluate(() => {
    const ok = document.getElementById('ok')!;
    ok.style.width = '520px';
    ok.style.height = '780px';
  });
  await expect(approve).toBeDisabled();
  await approve.click({ force: true, timeout: 1000 }).catch(() => {});
  expect(await approveCalls(page)).toEqual([]);

  // It opens only after the delay has run from the resize.
  await expect(approve).toBeEnabled();
  expect(Date.now() - resizedAt).toBeGreaterThanOrEqual(600);
  await approve.click();
  // The harness transport prepares the preview first; either call is an approval.
  await expect.poll(() => approveCalls(page)).toContain('requestPreview');
});
