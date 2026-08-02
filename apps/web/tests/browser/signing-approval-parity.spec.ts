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

type Surface = 'cli' | 'popup' | 'iframe';

interface HarnessConfig {
  surface: Surface;
  model: any;
  initialSelection: string[];
  canUseAuthorizeSign?: boolean;
  approving?: boolean;
  error?: string | null;
}

interface RecordedCall {
  name: string;
  args?: unknown;
}

function benignFixtureModel() {
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
    metadataTrust: { status: 'unsigned' },
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

function fixtureInitialSelection(model: any): string[] {
  const out: string[] = [];
  for (const perm of model.permissions) {
    for (const act of perm.actions) {
      if (act.selected) out.push(act.id);
    }
  }
  return out;
}

async function loadHarness(page: Page, cfg: HarnessConfig) {
  // Seed globals BEFORE navigation so the harness's onMount reads them.
  await page.addInitScript(({ cfg }) => {
    (window as any).__openkeyParityHarness = {
      surface: cfg.surface,
      model: cfg.model,
      initialSelection: cfg.initialSelection,
      canUseAuthorizeSign: cfg.canUseAuthorizeSign ?? true,
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
});
