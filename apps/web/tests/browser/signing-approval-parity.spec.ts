// Sol MAJOR-1 (final continuation): browser-driven parity tests for
// the OpenKey signing-approval surface adapters (CLI, popup, iframe).
//
// This spec boots the SvelteKit dev server, navigates to the dev-only
// `/__parity_harness` route which mounts the EXACT production adapter
// component for a given `?surface=` query param, and drives every
// interaction with real browser keyboard events via
// `page.keyboard.press('Tab' | ' ' | 'Enter')`.
//
// The harness route imports the real adapters from
// `src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte`
// and passes them a spy transport that records each call into a
// window-scoped array. This mirrors — one-for-one — the transport
// shape a production route builds; the adapter is the same code.
//
// Because interactions are real browser Tab/Space/Enter/click:
//   - Tab moves focus with the browser's own focus manager.
//   - Space on a checkbox goes through the shared component's
//     `onkeydown` handler and toggles selection via the adapter's
//     transport.
//   - Enter on the Approve button triggers the browser's implicit
//     click, which routes through the shared component's `onclick`
//     handler into the adapter's onApprove.
//   - Space/Enter on the details summary toggles the `<details>`
//     `open` attribute natively.
//
// No DOM state is mutated by this spec to imitate an event.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

type Surface = 'cli' | 'popup' | 'iframe';

interface HarnessConfig {
  surface: Surface;
  model: any;
  initialSelection: string[];
  canUseAuthorizeSign?: boolean;
  previewReady?: boolean;
  approving?: boolean;
  error?: string | null;
}

interface RecordedCall {
  name: string;
  args?: unknown;
}

function benignFixtureModel(): any {
  const space = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
  return {
    version: 1,
    protocol: 'tinycloud-siwe-recap',
    rawMessage: 'test-siwe-benign',
    requester: {
      displayName: 'My App',
      origin: 'https://myapp.example',
      verifiedOrigin: 'https://myapp.example',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    reason: { text: '', source: 'none' },
    signer: {
      label: 'Managed key',
      address: '0x1111111111111111111111111111111111111111',
      chainId: 1,
      provenance: 'managed',
    },
    expiry: '2026-08-07T00:00:00.000Z',
    immutable: null,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    permissions: [
      {
        id: `tinycloud.kv\x00${space}\x00`,
        family: 'kv-storage',
        severity: 'standard',
        service: 'tinycloud.kv',
        space,
        path: '',
        owner: '0x1111111111111111111111111111111111111111',
        ownedBySelf: true,
        displayLabel: null,
        metadataLabel: null,
        actions: [
          {
            id: `tinycloud.kv\x00${space}\x00\x00tinycloud.kv/get`,
            ability: 'tinycloud.kv/get',
            verb: 'get',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
          {
            id: `tinycloud.kv\x00${space}\x00\x00tinycloud.kv/put`,
            ability: 'tinycloud.kv/put',
            verb: 'put',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
        ],
      },
    ],
    parseWarnings: [],
  };
}

function encryptionFixtureModel() {
  const model = benignFixtureModel();
  const space = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
  model.rawMessage = 'server-prepared-create-only-bytes';
  model.permissions = [
    {
      id: `tinycloud.encryption\x00${space}\x00`,
      family: 'encryption-decrypt',
      severity: 'sensitive',
      service: 'tinycloud.encryption',
      space,
      path: '',
      owner: null,
      ownedBySelf: null,
      displayLabel: null,
      metadataLabel: null,
      actions: [
        {
          id: `tinycloud.encryption\x00${space}\x00\x00tinycloud.encryption/network.create`,
          ability: 'tinycloud.encryption/network.create',
          verb: 'network.create',
          required: false,
          selected: true,
          editable: true,
          caveats: [{}],
        },
        {
          id: `tinycloud.encryption\x00${space}\x00\x00tinycloud.encryption/decrypt`,
          ability: 'tinycloud.encryption/decrypt',
          verb: 'decrypt',
          required: false,
          selected: true,
          editable: true,
          caveats: [{}],
        },
      ],
    },
  ];
  return model;
}

function fixtureInitialSelection(model: any): string[] {
  const out: string[] = [];
  for (const perm of model.permissions) {
    for (const act of perm.actions) {
      if (act.selected) out.push(act.id);
    }
  }
  return out;
}

function exactRecapFixtureModel(): any {
  return parseCapabilityReview({
    message: EXPLORER_PERMISSION_POPUP_REQUEST,
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'explorer.tinycloud.xyz',
      verifiedOrigin: 'https://explorer.tinycloud.xyz',
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
      address: '0x1111111111111111111111111111111111111111',
      chainId: 1,
      provenance: 'managed',
    },
  });
}

async function loadHarness(page: Page, cfg: HarnessConfig) {
  // Seed globals BEFORE navigation so the harness's onMount reads them.
  await page.addInitScript(({ cfg }) => {
    try {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async (text: string) => {
            (window as any).__openkeyClipboardText = text;
          },
        },
      });
    } catch {
      // Older test environments may already expose a clipboard object.
    }
    (window as any).__openkeyParityHarness = {
      surface: cfg.surface,
      model: cfg.model,
      initialSelection: cfg.initialSelection,
      canUseAuthorizeSign: cfg.canUseAuthorizeSign ?? true,
      previewReady: cfg.previewReady ?? false,
      approving: cfg.approving ?? false,
      error: cfg.error ?? null,
      calls: [],
    };
  }, { cfg });
  await page.goto('/__parity_harness');
  // Wait for the harness's ready flag.
  await page.waitForFunction(() => (window as any).__openkeyParityHarnessReady === true);
}

async function readCalls(page: Page): Promise<RecordedCall[]> {
  return await page.evaluate(() => {
    const g = (window as any).__openkeyParityHarness;
    return g?.calls ?? [];
  });
}

async function clearCalls(page: Page): Promise<void> {
  await page.evaluate(() => {
    const g = (window as any).__openkeyParityHarness;
    if (g) g.calls.length = 0;
  });
}

test.describe('signing-approval browser parity — production adapters', () => {
  for (const surface of ['cli', 'popup', 'iframe'] as const) {
    test(`[${surface}] every surface mounts the shared dialog role`, async ({ page }) => {
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
      });
      const dialog = page.locator('[data-parity-harness] [role="dialog"]');
      await expect(dialog).toBeVisible();
      await expect(dialog).toHaveAttribute('aria-modal', 'true');
    });

    test(`[${surface}] exact ReCap fixture stays readable in a narrow popup viewport`, async ({ page }) => {
      await page.setViewportSize({ width: 400, height: 600 });
      const model = exactRecapFixtureModel();
      await loadHarness(page, {
        surface,
        model,
        initialSelection: fixtureInitialSelection(model),
        canUseAuthorizeSign: surface === 'cli' ? undefined : true,
      });

      const dialog = page.locator('[data-parity-harness] [role="dialog"]');
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('Authorize capabilities');
      await expect(dialog).toContainText('Read and update data outside this app');
      await expect(dialog).toContainText('Check your TinyCloud account permissions');
      const summary = page.locator('[data-parity-harness] .summary');
      await expect(summary.locator('.summary-statement')).toHaveCount(8);
      await expect(summary).toContainText('View secret names and details');
      await expect(summary).toContainText('Read secret values');
      await expect(summary.locator('.summary-sensitive-pill')).toHaveText(
        'Sensitive',
      );
      await expect(summary).not.toContainText(model.requester.displayName);
      await expect(summary).not.toContainText('exact grant');
      await expect(summary).not.toContainText('service');
      await expect(summary).not.toContainText('tinycloud:pkh:');
      await expect(dialog).not.toContainText(`owner ${model.signer.address.toLowerCase()}`);
      await expect(dialog).not.toContainText('path=spaces/');
      await expect(summary.locator('.summary-statement').last()).toContainText('Perform ');
      const details = page.locator('details.advanced-details').first();
      await details.locator(':scope > summary').click();
      await expect(details.locator(':scope > summary')).toHaveText('Advanced details');
      await expect(details.getByRole('button', { name: 'Edit' })).toBeVisible();
      const requesterDetails = details.locator('details.request-details');
      await expect(requesterDetails).toHaveAttribute('open', '');
      await expect(details.locator(':scope > .request-details').first()).toBeVisible();
      const standardPermissions = details.locator(
        'details.severity-bucket[data-severity="standard"]',
      );
      await expect(standardPermissions).not.toHaveAttribute('open', '');
      const reviewPermissions = details.locator(
        'details.severity-bucket[data-severity="review"]',
      );
      await expect(reviewPermissions).toHaveCount(1);
      await expect(reviewPermissions).toHaveAttribute('open', '');
      await expect(
        reviewPermissions.locator('.grant').first().locator('.grant-severity'),
      ).toHaveText('Sensitive');
      await expect(
        details.locator(
          'details.severity-bucket[data-severity="sensitive"], details.severity-bucket[data-severity="attention"]',
        ),
      ).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Copy text' })).toBeVisible();
      await expect(page.locator('[data-parity-harness] .grant')).toHaveCount(17);
      await expect(details.locator('.grant-severity[data-severity="sensitive"]')).toHaveCount(3);
      await expect(details.locator('.grant-severity[data-severity="attention"]')).toHaveCount(0);
      await expect(details.locator('.grant-severity[data-severity="standard"]')).toHaveCount(0);
      const vaultGrant = details.locator('.grant').filter({
        hasText: 'secrets/vault/secrets',
      });
      await expect(vaultGrant.locator('.grant-service')).toHaveText('Key Value');
      await expect(vaultGrant.locator('.grant-service')).toHaveAttribute(
        'title',
        'tinycloud.kv',
      );
      await expect(vaultGrant.locator('.grant-target')).toHaveAttribute(
        'title',
        /:secrets\/kv\/vault\/secrets$/,
      );
      const rawBytes = details.locator('.raw-bytes');
      const rawViewport = await rawBytes.evaluate((element) => ({
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
      }));
      expect(rawViewport.clientHeight).toBeLessThanOrEqual(180);
      expect(rawViewport.scrollHeight).toBeGreaterThan(rawViewport.clientHeight);

      await details.getByRole('button', { name: 'Edit' }).click();
      const editableActions = details.locator('input[type="checkbox"]:not(:disabled)');
      expect(await editableActions.count()).toBeGreaterThan(0);
      const inlineDirection = await details.locator('.action-list').first().evaluate(
        (element) => getComputedStyle(element).flexDirection,
      );
      expect(inlineDirection).toBe('row');
      await editableActions.first().uncheck();
      await expect(details.getByText('Not granting:', { exact: false }).first()).toBeVisible();
      await expect(details).not.toContainText('Selected');
      await expect(details).not.toContainText('Unselected');
      await details.getByRole('button', { name: 'Reset' }).click();
      await expect(editableActions.first()).toBeChecked();

      await page.getByRole('button', { name: 'Copy text' }).click();
      await expect
        .poll(async () => page.evaluate(() => (window as any).__openkeyClipboardText ?? null))
        .toBe(model.rawMessage);
      await expect(page.getByRole('button', { name: 'Copy text' })).toHaveText('Copied');

      const noOverflow = await page.evaluate(() => {
        const doc = document.documentElement;
        return doc.scrollWidth <= doc.clientWidth;
      });
      expect(noOverflow).toBe(true);
    });

    test(`[${surface}] Tab moves focus through interactive controls in DOM order`, async ({ page }) => {
      // Real Tab-driven focus movement via the browser. If the DOM
      // order and tabindex don't produce a keyboard-reachable sequence,
      // this test fails.
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
      });
      // Focus the document body so Tab starts from a known position.
      await page.locator('body').click();
      const firstFocused = await page.evaluate(() => {
        (document.activeElement as HTMLElement | null)?.blur();
        return document.activeElement?.tagName ?? null;
      });
      expect(firstFocused).toBeTruthy();
      // Tab into the harness and collect the resulting focus signature.
      const signature: string[] = [];
      for (let i = 0; i < 6; i += 1) {
        await page.keyboard.press('Tab');
        const info = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return null;
          return {
            tag: el.tagName.toLowerCase(),
            text: (el.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 40),
            type: el.getAttribute('type') ?? '',
          };
        });
        if (!info) break;
        signature.push(`${info.tag}[type=${info.type}][text=${info.text}]`);
      }
      // The Approve and Cancel buttons MUST both appear in the focus
      // sequence — proving the browser's tab manager reaches them.
      expect(signature.join(' | ')).toContain('button[type=');
      const hasApprove = signature.some((s) => s.includes('Approve'));
      const hasCancel = signature.some((s) => s.includes('Cancel'));
      expect(hasApprove).toBe(true);
      expect(hasCancel).toBe(true);
    });

    test(`[${surface}] Enter on Approve routes to the ADAPTER approve wiring`, async ({ page }) => {
      const canUseAuthorizeSign = surface === 'cli' ? undefined : true;
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
        canUseAuthorizeSign,
      });
      // Focus the Approve button and press Enter. Chromium synthesizes
      // a click on Enter for the focused button; the adapter's onApprove
      // fires from there.
      const approve = page.locator('[data-parity-harness] button', { hasText: 'Approve' }).first();
      await approve.focus();
      await page.keyboard.press('Enter');
      const calls = await readCalls(page);
      const names = calls.map((c) => c.name);
      if (surface === 'cli') {
        expect(names).toEqual(['approveDelegate']);
      } else {
        expect(names).toEqual(['requestPreview']);
      }
    });

    test(`[${surface}] Space on Approve also fires the adapter approve wiring`, async ({ page }) => {
      const canUseAuthorizeSign = surface === 'cli' ? undefined : true;
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
        canUseAuthorizeSign,
      });
      const approve = page.locator('[data-parity-harness] button', { hasText: 'Approve' }).first();
      await approve.focus();
      // Space on a focused button also fires click in Chromium.
      await page.keyboard.press('Space');
      const calls = await readCalls(page);
      const names = calls.map((c) => c.name);
      if (surface === 'cli') {
        expect(names).toContain('approveDelegate');
      } else {
        expect(names).toContain('requestPreview');
      }
    });

    test(`[${surface}] Enter on Cancel routes to the ADAPTER cancel wiring`, async ({ page }) => {
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
      });
      const cancel = page.locator('[data-parity-harness] button', { hasText: 'Cancel' }).first();
      await cancel.focus();
      await page.keyboard.press('Enter');
      const calls = await readCalls(page);
      const names = calls.map((c) => c.name);
      if (surface === 'cli') {
        expect(names).toEqual(['goBack']);
      } else {
        expect(names).toEqual(['cancel']);
      }
    });

    test(`[${surface}] Space on an editable checkbox toggles selection through the ADAPTER wiring`, async ({ page }) => {
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
      });
      // The Edit control lives inside the "Advanced details" <details>
      // disclosure — that element is closed by default (contract §3.11).
      // A real user first opens it via the summary; the spec must do the
      // same or the browser correctly reports the Edit button as not
      // visible.
      const details = page.locator('[data-parity-harness] details').first();
      const isOpen = await details.evaluate((el) => (el as HTMLDetailsElement).open);
      if (!isOpen) {
        await details.locator('summary').first().click();
        await expect
          .poll(async () => details.evaluate((el) => (el as HTMLDetailsElement).open))
          .toBe(true);
      }
      // Enter editing mode by real-clicking the Edit button.
      const edit = page.locator('[data-parity-harness] button', { hasText: 'Edit' }).first();
      await edit.click();
      const standardPermissions = page.locator(
        '[data-parity-harness] details.severity-bucket[data-severity="standard"]',
      );
      if ((await standardPermissions.count()) > 0) {
        await standardPermissions.locator(':scope > summary').click();
      }
      // The checkbox appears once editing is on.
      const boxes = page.locator('[data-parity-harness] input[type="checkbox"]');
      await expect(boxes.first()).toBeVisible();
      const firstBox = boxes.first();
      await firstBox.focus();
      await clearCalls(page);
      await page.keyboard.press(' ');
      const calls = await readCalls(page);
      const names = calls.map((c) => c.name);
      if (surface === 'cli') {
        expect(names).toContain('updateSelection');
      } else {
        expect(names).toContain('onSelectionEdited');
        expect(names).toContain('invalidatePreview');
      }
    });

    test(`[${surface}] browser toggles <details> open on summary click AND on Enter/Space when focused`, async ({ page }) => {
      // The <details>/<summary> pair is a native HTML control. In a
      // real browser, clicking the summary flips the details.open flag;
      // pressing Enter on a focused summary does the same. This test
      // asserts BOTH the click path AND the keyboard path — neither is
      // achievable via direct DOM state mutation without leaving the
      // browser boundary.
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
      });
      const details = page.locator('[data-parity-harness] details').first();
      const summary = details.locator('summary').first();
      await expect(await details.evaluate((el) => (el as HTMLDetailsElement).open)).toBe(false);
      await summary.click();
      await expect(await details.evaluate((el) => (el as HTMLDetailsElement).open)).toBe(true);
      // Toggle back with keyboard.
      await summary.focus();
      await page.keyboard.press('Enter');
      await expect(await details.evaluate((el) => (el as HTMLDetailsElement).open)).toBe(false);
    });
  }

  test('decryption operations carry Sensitive pills in summary and exact grants', async ({ page }) => {
    const model = encryptionFixtureModel();
    await loadHarness(page, {
      surface: 'popup',
      model,
      initialSelection: fixtureInitialSelection(model),
      canUseAuthorizeSign: true,
    });

    const summary = page.locator('[data-parity-harness] .summary');
    await expect(summary).toContainText('Create a decryption network and decrypt protected data');
    await expect(summary.locator('.summary-sensitive-pill')).toHaveText('Sensitive');
    const details = page.locator('details.advanced-details');
    await details.locator(':scope > summary').click();
    await expect(details.locator('.grant-severity[data-severity="sensitive"]')).toHaveText(
      'Sensitive',
    );
  });

  test('copy falls back without calling Clipboard API when policy blocks it', async ({ page }) => {
    const model = exactRecapFixtureModel();
    await loadHarness(page, {
      surface: 'iframe',
      model,
      initialSelection: fixtureInitialSelection(model),
      canUseAuthorizeSign: true,
    });
    await page.evaluate(() => {
      (window as any).__clipboardApiCalls = 0;
      (window as any).__fallbackClipboardText = null;
      Object.defineProperty(document, 'permissionsPolicy', {
        configurable: true,
        value: { allowsFeature: () => false },
      });
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async () => {
            (window as any).__clipboardApiCalls += 1;
            throw new DOMException('Blocked by Permissions Policy', 'NotAllowedError');
          },
        },
      });
      (document as any).execCommand = (command: string) => {
        if (command !== 'copy') return false;
        const textarea = document.activeElement as HTMLTextAreaElement | null;
        (window as any).__fallbackClipboardText = textarea?.value ?? null;
        return true;
      };
    });

    const details = page.locator('details.advanced-details');
    await details.locator(':scope > summary').click();
    await page.getByRole('button', { name: 'Copy text' }).click();
    const result = await page.evaluate(() => ({
      apiCalls: (window as any).__clipboardApiCalls,
      copiedText: (window as any).__fallbackClipboardText,
    }));
    expect(result.apiCalls).toBe(0);
    expect(result.copiedText).toBe(model.rawMessage);
    await expect(page.getByRole('button', { name: 'Copy text' })).toHaveText('Copied');
  });

  test('widget approve routes to exact-byte path when canUseAuthorizeSign=false', async ({ page }) => {
    for (const surface of ['popup', 'iframe'] as const) {
      await loadHarness(page, {
        surface,
        model: benignFixtureModel(),
        initialSelection: fixtureInitialSelection(benignFixtureModel()),
        canUseAuthorizeSign: false,
      });
      const approve = page.locator('[data-parity-harness] button', { hasText: 'Approve' }).first();
      await approve.focus();
      await page.keyboard.press('Enter');
      const calls = await readCalls(page);
      const names = calls.map((c) => c.name);
      expect(names).toEqual(['approveAndSign']);
    }
  });

  test('widget final preview preserves shared details and approves exact bytes', async ({ page }) => {
    for (const surface of ['popup', 'iframe'] as const) {
      const model = benignFixtureModel();
      model.rawMessage = 'server-prepared-exact-bytes';
      await loadHarness(page, {
        surface,
        model,
        initialSelection: fixtureInitialSelection(model),
        canUseAuthorizeSign: true,
        previewReady: true,
      });

      await expect(page.locator('details.advanced-details')).toBeVisible();
      await page.locator('details.advanced-details > summary').click();
      await expect(page.getByText('Exact grants')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Copy text' })).toBeVisible();
      await expect(page.getByText('server-prepared-exact-bytes')).toBeVisible();

      const approve = page.getByRole('button', { name: 'Approve exact bytes' });
      await approve.focus();
      await page.keyboard.press('Enter');
      const names = (await readCalls(page)).map((call) => call.name);
      expect(names).toEqual(['approveAndSign']);
    }
  });

  test('widget final summary excludes a deselected decrypt action', async ({ page }) => {
    for (const surface of ['popup', 'iframe'] as const) {
      const model = encryptionFixtureModel();
      await loadHarness(page, {
        surface,
        model,
        initialSelection: [model.permissions[0].actions[0].id],
        canUseAuthorizeSign: true,
        previewReady: true,
      });

      const summary = page.locator('.summary');
      await expect(summary).toContainText('Create a decryption network');
      await expect(summary).not.toContainText('decrypt protected data');
      await expect(page.locator('.sensitive-callout')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Approve exact bytes' })).toBeVisible();
    }
  });

  test('widget legacy and malformed protocols stay in shared approval content', async ({ page }) => {
    for (const surface of ['popup', 'iframe'] as const) {
      const legacy = benignFixtureModel();
      legacy.protocol = 'legacy-message';
      legacy.permissions = [];
      await loadHarness(page, {
        surface,
        model: legacy,
        initialSelection: [],
        canUseAuthorizeSign: false,
      });
      await expect(page.locator('[role="dialog"]')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Approve' })).toBeEnabled();

      const malformed = benignFixtureModel();
      malformed.protocol = 'malformed-recap';
      malformed.permissions = [];
      malformed.parseWarnings = [{ code: 'MALFORMED_RECAP', message: 'decode failed' }];
      await loadHarness(page, {
        surface,
        model: malformed,
        initialSelection: [],
        canUseAuthorizeSign: false,
      });
      await expect(page.getByRole('button', { name: 'Cannot approve' })).toBeDisabled();
      await expect(page.getByText('Refusing to sign: malformed capability payload')).toBeVisible();
    }
  });
});
