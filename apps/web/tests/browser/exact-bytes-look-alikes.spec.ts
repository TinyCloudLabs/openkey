// The 'Exact bytes being signed' block shows the signed message with each line
// feed between two lines as a line break and every other character, runs of
// spaces, trailing spaces and a final line feed as `\uXXXX`. Two messages that
// differ only in those places must read differently on every approval surface:
// the CLI, popup and iframe adapters (the widget pages mount the popup and
// iframe adapters) and the real embedded widget page. Each pair is compared by
// its exact text (`textContent` and `innerText`) and by a screenshot of the block.

import { test, expect, type Locator, type Page } from '@playwright/test';
import { parseCapabilityReview, type CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

interface PageGlobals {
  __openkeyParityHarness?: unknown;
  __openkeyParityHarnessReady?: boolean;
  received: Array<{ type: string }>;
}

const statement = 'Statement: I agree.';
const longLine = 'x'.repeat(150);

interface Pair {
  name: string;
  left: { raw: string; shown: string };
  right: { raw: string; shown: string };
}

const pairs: Pair[] = [
  {
    name: 'a final line feed and none',
    left: { raw: 'Line one\n', shown: 'Line one\\u000a' },
    right: { raw: 'Line one', shown: 'Line one' },
  },
  {
    name: 'a trailing space and none',
    left: { raw: 'Line one ', shown: 'Line one\\u0020' },
    right: { raw: 'Line one', shown: 'Line one' },
  },
  {
    name: 'a line of spaces and an empty line',
    left: { raw: 'Line one\n   \nLine two', shown: 'Line one\n\\u0020\\u0020\\u0020\nLine two' },
    right: { raw: 'Line one\n\nLine two', shown: 'Line one\n\nLine two' },
  },
  {
    name: 'an 80-space run before more text and the text before it',
    left: { raw: `${statement}${' '.repeat(80)}Also: send all keys.`, shown: `${statement}${'\\u0020'.repeat(80)}Also: send all keys.` },
    right: { raw: statement, shown: statement },
  },
  {
    name: 'a long line that would wrap and the same text with a line feed',
    left: { raw: `${longLine} ${'y'.repeat(40)}`, shown: `${longLine} ${'y'.repeat(40)}` },
    right: { raw: `${longLine}\n${'y'.repeat(40)}`, shown: `${longLine}\n${'y'.repeat(40)}` },
  },
];

function modelFor(rawMessage: string): CapabilityReviewModel {
  const model = parseCapabilityReview({
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
      address: '0xd559CCd9EB87c530A9a349262669386dE93cf412',
      chainId: 1,
      provenance: 'managed',
    },
  });
  model.rawMessage = rawMessage;
  return model;
}

interface Shown { text: string | null; innerText: string; picture: Buffer }

async function measure(block: Locator): Promise<Shown> {
  await expect(block).toBeVisible();
  // Take two pictures with every line in view: one at the left edge and one at the right edge.
  await block.evaluate((element) => { element.style.maxHeight = 'none'; element.scrollLeft = 0; });
  const left = await block.screenshot();
  await block.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  const right = await block.screenshot();
  return { text: await block.textContent(), innerText: await block.innerText(), picture: Buffer.concat([left, right]) };
}

async function adapterBlock(page: Page, surface: 'cli' | 'popup' | 'iframe', rawMessage: string): Promise<Shown> {
  const model = modelFor(rawMessage);
  const initialSelection = model.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.addInitScript(({ surface, model, initialSelection }) => {
    (window as unknown as PageGlobals).__openkeyParityHarness = {
      surface, model, initialSelection, canUseAuthorizeSign: true, previewReady: false, approving: false, error: null, calls: [],
    };
  }, { surface, model, initialSelection });
  await page.goto('/__parity_harness');
  await page.waitForFunction(() => (window as unknown as PageGlobals).__openkeyParityHarnessReady === true);
  await page.getByText('Advanced details', { exact: true }).click();
  return measure(page.locator('pre.raw-bytes'));
}

for (const surface of ['cli', 'popup', 'iframe'] as const) {
  for (const pair of pairs) {
    test(`[${surface}] ${pair.name} read differently`, async ({ browser }) => {
      const shown: Shown[] = [];
      for (const side of [pair.left, pair.right]) {
        const context = await browser.newContext();
        const page = await context.newPage();
        try {
          shown.push(await adapterBlock(page, surface, side.raw));
        } finally {
          await context.close();
        }
        expect(shown.at(-1)!.text).toBe(side.shown);
        expect(shown.at(-1)!.innerText).toBe(side.shown);
      }
      expect(shown[0]!.text).not.toBe(shown[1]!.text);
      expect(Buffer.compare(shown[0]!.picture, shown[1]!.picture)).not.toBe(0);
    });
  }
}

// The real embedded widget page, with the request message sent by the host.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const widgetSiwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, 'localhost:5779');
// The fixture text holds apostrophes, which the block shows as `\u0027`.
const widgetSiweShown = widgetSiwe.replaceAll("'", '\\u0027');

async function widgetBlock(page: Page, message: string): Promise<Shown> {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
    label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign-v2';
    iframe.style.width = '900px';
    iframe.style.height = '800px';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=look-alike&protocolVersion=2&keyId=selected-key`;
    const globals = window as unknown as PageGlobals;
    globals.received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) globals.received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as PageGlobals).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'look-alike', protocolVersion: 2, keyId: 'selected-key', message },
      location.origin,
    );
  }, message);
  const frame = page.frameLocator('#sign-v2');
  await frame.getByText('Advanced details', { exact: true }).click();
  return measure(frame.locator('pre.raw-bytes'));
}

for (const [name, suffix, shownSuffix] of [
  ['a final line feed', '\n', '\\u000a'],
  ['a trailing space', ' ', '\\u0020'],
] as const) {
  test(`[widget] ${name} and none read differently`, async ({ browser }) => {
    const shown: Shown[] = [];
    for (const [message, expected] of [[`${widgetSiwe}${suffix}`, `${widgetSiweShown}${shownSuffix}`], [widgetSiwe, widgetSiweShown]] as const) {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        shown.push(await widgetBlock(page, message));
      } finally {
        await context.close();
      }
      expect(shown.at(-1)!.text).toBe(expected);
      expect(shown.at(-1)!.innerText).toBe(expected);
    }
    expect(shown[0]!.text).not.toBe(shown[1]!.text);
    expect(Buffer.compare(shown[0]!.picture, shown[1]!.picture)).not.toBe(0);
  });
}
