import { test, expect } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { strictSessionDid } from '../../../api/src/services/device-authorization';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

const shareId = '0123456789abcdef0123456789abcdef';
const ownerDid = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const resource = `urn:tinycloud:encryption:${ownerDid}:default/share/${shareId}`;
const origin = 'https://thirdparty.example';
const sessionDid = strictSessionDid(generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }));
function model() {
  const message = siweWithResources([makeRecapResource({ [resource]: { 'tinycloud.encryption/decrypt': [{}] } })], {
    domain: 'thirdparty.example', uri: sessionDid, issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 3600_000).toISOString(),
  });
  return parseCapabilityReview({ message, editable: false,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' }, reason: { text: '', source: 'none' },
    requester: { displayName: 'thirdparty.example', verifiedOrigin: origin, appId: null, manifestName: null,
      manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null,
      domainWarning: false, originWarning: false },
    signer: { label: 'Selected key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
  });
}
for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
  test(`new-share approval copy and exact grants at ${viewport.width}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const review = model();
    await page.addInitScript(cfg => { (window as any).__openkeyParityHarness = cfg; }, {
      surface: 'share', model: review,
      initialSelection: review.permissions.flatMap(grant => grant.actions.map(action => action.id)),
      share: { shareId, ownerDid, sessionDid, origin }, previewReady: true, calls: [],
    });
    await page.goto('/__parity_harness');
    await expect(page.getByRole('heading', { name: 'Create a new share' })).toBeVisible();
    await expect(page.getByText('Requested by thirdparty.example')).toBeVisible();
    await expect(page.getByText("thirdparty.example wants to start a new share. It can open only what's in this share, and none of your other shares.")).toBeVisible();
    const approve = page.getByRole('button', { name: 'Create share', exact: true });
    await expect(approve).toBeEnabled();
    await expect(approve).toHaveAttribute('aria-describedby', 'signing-approval-hint');
    expect(await page.locator('body').innerText()).not.toContain(shareId);
    const shots = process.env.SHARE_APPROVAL_SHOTS_DIR;
    if (shots) { mkdirSync(shots, { recursive: true }); await page.screenshot({ path: `${shots}/${viewport.width}-summary.png`, fullPage: true }); }
    await page.getByText('Advanced details', { exact: true }).click();
    const exact = page.getByRole('region', { name: 'Exact grants' });
    await expect(exact).toContainText(`default/share/${shareId}`);
    await expect(exact.locator('[aria-label="Exact resource: ' + resource + '"]')).toHaveAttribute('title', resource);
    await expect(exact).toContainText('Sensitive');
    if (shots) await page.screenshot({ path: `${shots}/${viewport.width}-exact.png`, fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
    await approve.click();
    expect(await page.evaluate(() => (window as any).__openkeyParityHarness.calls)).toContainEqual({ name: 'approveShare', args: undefined });
  });
}
