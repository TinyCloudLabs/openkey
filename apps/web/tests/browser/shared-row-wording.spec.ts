// Share-style approval rows: sender history, files shared with you (still
// Sensitive), permissions already granted, and a KV `del` inside one app
// folder naming the folder. Driven in Chromium through the dev-only parity
// harness, which mounts the production popup adapter.
//
// The request is mocked from the wire resources captured in Clarissa's
// post-deploy QA run (the report lists the resource roots, not the exact
// ReCap bytes): sender history on the signer's `applications` space, the
// recipient's `files-for-you` space and its capabilities read, Share's own
// app folder and encryption network/keys, plus the TC-2534 delete grant
// (`del` on `xyz.tinycloud.share/`) added for the screenshot.
//
// Set SHARED_ROW_SHOTS_DIR to save the screenshots.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from '../../../../packages/capability-review/test/fixtures/index';

const SHOTS = process.env.SHARED_ROW_SHOTS_DIR;
const SIGNER = FIXTURE_META.address;
const CHAIN = FIXTURE_META.chainId;
const SPACE = (name: string) => `tinycloud:pkh:eip155:${CHAIN}:${SIGNER}:${name}`;
const NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:${CHAIN}:${SIGNER}:default`;

function model() {
  const resources: Record<string, Record<string, unknown[]>> = {
    // Sender history: the exact v2 records prefix, get/list/put/del.
    [`${SPACE('applications')}/kv/vault/sender-history/v2/records/`]: {
      'tinycloud.kv/get': [{}],
      'tinycloud.kv/list': [{}],
      'tinycloud.kv/put': [{}],
      'tinycloud.kv/del': [{}],
    },
    // The recipient's files-for-you mailbox and its permission check.
    [`${SPACE('files-for-you')}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    [`${SPACE('files-for-you')}/kv/v1/`]: {
      'tinycloud.kv/get': [{}],
      'tinycloud.kv/list': [{}],
      'tinycloud.kv/put': [{}],
    },
    // Share's own app folder (app rows stay per folder) plus the TC-2534
    // delete grant on the same folder (mocked for the screenshot).
    [`${SPACE('applications')}/kv/xyz.tinycloud.share/`]: {
      'tinycloud.kv/get': [{}],
      'tinycloud.kv/put': [{}],
      'tinycloud.kv/del': [{}],
    },
    // Share's encryption network and own share/ key folder.
    [NETWORK]: {
      'tinycloud.encryption/network.create': [{}],
      'tinycloud.encryption/decrypt': [{}],
    },
    [`${NETWORK}/share/`]: {
      'tinycloud.encryption/key.create': [{}],
      'tinycloud.encryption/decrypt': [{}],
    },
  };
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(resources)]),
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'share.tinycloud.xyz',
      verifiedOrigin: 'https://share.tinycloud.xyz',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    signer: {
      label: 'Managed key',
      address: SIGNER,
      chainId: CHAIN,
      provenance: 'managed',
    },
  });
}

async function load(page: Page) {
  const m = model();
  const initialSelection = m.permissions.flatMap((g) =>
    g.actions.filter((a) => a.selected).map((a) => a.id),
  );
  await page.addInitScript((cfg) => {
    (window as unknown as Record<string, unknown>).__openkeyParityHarness = {
      ...cfg,
      surface: 'popup',
      calls: [],
    };
  }, { model: m, initialSelection, withExpiry: true, canUseAuthorizeSign: true });
  await page.goto('/__parity_harness');
  await page.waitForFunction(
    () => (window as unknown as Record<string, unknown>).__openkeyParityHarnessReady === true,
  );
}

test.describe('Share request approval rows', () => {
  test('the approval at 390x844 shows the dedicated rows unscrolled', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await load(page);
    const dialog = page.locator('[role="dialog"]');
    await expect(dialog).toContainText('Read, change and delete your sharing history');
    await expect(dialog).toContainText('Read and change files shared with you');
    await expect(dialog).toContainText('See which permissions are already granted');
    await expect(dialog).toContainText('Delete data associated with');
    const mailbox = dialog.locator('.summary-statement').filter({ hasText: 'Read and change files shared with you' });
    await expect(mailbox.locator('.summary-sensitive-pill')).toHaveText('Sensitive');
    // No horizontal overflow at phone width.
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (SHOTS) {
      await page.screenshot({ path: `${SHOTS}/390x844-share-approval.png`, fullPage: false });
      const deleteRow = dialog.locator('.summary-statement').filter({ hasText: 'Delete data associated with' });
      await deleteRow.screenshot({ path: `${SHOTS}/390-delete-row.png` });
    }
  });

  test('the approval at 1280x800 shows the same rows', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await load(page);
    const dialog = page.locator('[role="dialog"]');
    await expect(dialog).toContainText('Read, change and delete your sharing history');
    await expect(dialog).toContainText('Read and change files shared with you');
    await expect(dialog).toContainText('See which permissions are already granted');
    await expect(dialog).toContainText('Delete data associated with');
    if (SHOTS) {
      await page.screenshot({ path: `${SHOTS}/1280x800-share-approval.png`, fullPage: false });
    }
  });
});
