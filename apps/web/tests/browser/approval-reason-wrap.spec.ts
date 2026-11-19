// TC-2438: the requester's reason is shown as one block of text; a long unbroken value in it (an account address such
// as did:pkh:eip155:1:0x...) must wrap inside the card instead of running past its edge. Real component through the
// parity harness, at phone and desktop widths.
import { test, expect } from '@playwright/test';
import { ORIGIN } from './e2e-port';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';

const OWNER = '0x1111111111111111111111111111111111111111';
const SPACE = `tinycloud:pkh:eip155:1:${OWNER}:applications`;
const DID = 'did:pkh:eip155:1:0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const LONG_TOKEN = `${DID}${'f'.repeat(120)}`;

function config(reason: string) {
  const recap = `urn:recap:${Buffer.from(JSON.stringify({ att: { [`${SPACE}/kv/books/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } }, prf: [] })).toString('base64url')}`;
  const message = ['cli.tinycloud.xyz wants you to sign in with your Ethereum account:', OWNER, '', 'URI: did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-24T00:00:00.000Z', 'Resources:', `- ${recap}`].join('\n');
  const model = parseCapabilityReview({
    message, signer: { label: 'Selected key', address: OWNER, chainId: 1, provenance: 'managed' }, editable: false,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' }, reason: { text: reason, source: 'caller' },
    requester: { displayName: 'TinyCloud CLI', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
  });
  return { model, initialSelection: model.permissions.flatMap((g) => g.actions.map((a) => a.id)), surface: 'popup' as const };
}

for (const width of [390, 1280]) {
  for (const [label, token] of [['an account address', DID], ['a very long unbroken value', LONG_TOKEN]] as const) {
    test(`${label} in the reason wraps inside the card at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 844 });
      await page.context().addInitScript((c) => {
        if (location.pathname === '/__parity_harness') (window as unknown as Record<string, unknown>).__openkeyParityHarness = { ...c, calls: [] };
      }, config(`Lets Claude keep your personal records for books. Requested by TinyCloud account ${token}; approve only if that is you.`));
      await page.goto(`${ORIGIN}/__parity_harness`);
      const body = page.locator('.reason-body');
      await body.waitFor();
      const m = await page.evaluate(() => {
        const text = document.querySelector('.reason-body') as HTMLElement;
        const card = document.querySelector('.reason') as HTMLElement;
        const range = document.createRange();
        range.selectNodeContents(text);
        const rects = [...range.getClientRects()];
        return {
          textRight: Math.max(...rects.map((r) => r.right)),
          cardRight: card.getBoundingClientRect().right,
          pageScroll: document.documentElement.scrollWidth,
          viewport: window.innerWidth,
        };
      });
      expect(m.textRight).toBeLessThanOrEqual(m.cardRight + 0.5);
      expect(m.pageScroll).toBeLessThanOrEqual(m.viewport);
    });
  }
}
