// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  CLAIM_LIMITS,
  MAX_ICON_URI_LENGTH,
  claimLineText,
  claimedPresentation,
  claimedPresentationCopy,
  claimedPresentationView,
  containsReservedName,
  type ClaimedPresentationView,
} from './claimed-presentation';

const APP = 'https://notes.example';
const SHELL = 'https://tinycloud.chat';
const DELEGATEE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

const bytes = (...head: number[]) => Buffer.from([...head, ...new Array(30).fill(7)]).toString('base64');
const PNG = `data:image/png;base64,${bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)}`;
const JPEG = `data:image/jpeg;base64,${bytes(0xff, 0xd8, 0xff, 0xe0)}`;
const WEBP = `data:image/webp;base64,${bytes(0x52, 0x49, 0x46, 0x46)}`;

function decide(presentation: unknown, origin = APP, signedUri: string | null = DELEGATEE) {
  return claimedPresentation({ presentation, origin, signedUri });
}
const claim = (fields: Record<string, unknown>) => ({ protocolVersion: 1, ...fields });
const viewOf = (presentation: unknown, origin = APP, signedUri: string | null = DELEGATEE): ClaimedPresentationView | null => {
  const decided = decide(presentation, origin, signedUri);
  return decided ? claimedPresentationView(decided) : null;
};
const textOf = (view: ClaimedPresentationView | null): string[] =>
  view ? [
    ...(view.verified ? [claimLineText(view.verified)] : []),
    ...view.claims.map(claimLineText),
    ...(view.closing ? [view.closing] : []),
  ] : [];

describe('reserved names', () => {
  test('"TinyCloud One" from an origin that is not a trusted shell is dropped', () => {
    expect(decide(claim({ displayName: 'TinyCloud One' }))).toBeNull();
    expect(decide(claim({ displayName: 'Notes by TinyCloud One', reason: 'Sync' }))?.displayName).toBeNull();
  });

  test('"Tiny Cloud One" with lookalike letters, zero-width characters and bidi marks is dropped', () => {
    const disguised = [
      'Tiny Cloud One',
      'Tіny\u200BClоud Оne', // Cyrillic і, о, О between zero-width spaces
      'T\u200Diny\u202ECl\u2066oud\u202C One',
      'ＴｉｎｙＣｌｏｕｄ',
      'T1nyCl0ud',
      'Tiny-Cloud_One!',
      'TĪNY CLOUD',
      'Τiny Cloud', // Greek capital tau
      'Open Key',
      'OpenKеy', // Cyrillic е
      'Tiny Chat',
      'Secret   Manager',
      'sharе', // Cyrillic е
      'Shared notes',
      'Tinydoud', // `cl` drawn as `d`
    ];
    for (const displayName of disguised) {
      expect(decide(claim({ displayName }))).toBeNull();
    }
  });

  test('a reserved name in "on behalf of" is dropped, and the name beside it stays', () => {
    const decided = decide(claim({ displayName: 'Acme Notes', onBehalfOf: 'Sync in TinyCloud' }));
    expect(decided).toEqual({ displayName: 'Acme Notes', iconUrl: null, onBehalfOf: null, reason: null });
  });

  test('the same names are shown from a trusted shell origin', () => {
    expect(decide(claim({ displayName: 'TinyCloud One' }), SHELL)?.displayName).toBe('TinyCloud One');
    expect(decide(claim({ displayName: 'Tiny Cloud One', onBehalfOf: 'Home in OpenKey' }), 'https://tinycloud.one')).toEqual({
      displayName: 'Tiny Cloud One',
      iconUrl: null,
      onBehalfOf: { text: 'Home in OpenKey', verified: false },
      reason: null,
    });
    expect(decide(claim({ displayName: 'Share' }), 'https://share.tinycloud.xyz')?.displayName).toBe('Share');
  });

  test('a trusted shell origin is an exact match', () => {
    for (const origin of ['https://tinycloud.chat.evil.example', 'https://www.tinycloud.chat', 'http://tinycloud.chat', 'https://tinycloud.chat:8443']) {
      expect(decide(claim({ displayName: 'TinyChat' }), origin)).toBeNull();
    }
  });

  test('a reason may use any word', () => {
    expect(decide(claim({ reason: 'Share my notes with TinyCloud' }))?.reason).toBe('Share my notes with TinyCloud');
  });

  test('names that merely resemble nothing reserved pass', () => {
    expect(containsReservedName('Acme Notes')).toBe(false);
    expect(containsReservedName('Tiny Notes')).toBe(false);
    expect(containsReservedName('Cloud Drive')).toBe(false);
  });
});

describe('cleaning', () => {
  test('strips control, bidi and zero-width characters, folds to NFKC and collapses spaces', () => {
    const decided = decide(claim({
      displayName: '  Ａcme\u200B\u202E  No\ttes\n',
      reason: 'Line one\nline\u2028two\u0000\u200F',
    }));
    expect(decided?.displayName).toBe('Acme No tes');
    expect(decided?.reason).toBe('Line one line two');
  });

  test('a field that is empty after cleaning is absent', () => {
    expect(decide(claim({ displayName: '\u200B\u202E  ', reason: '\u0000', onBehalfOf: '' }))).toBeNull();
    expect(decide(claim({ displayName: 'Acme', reason: ' \u200B ' }))?.reason).toBeNull();
  });

  test('texts are cut to their limits', () => {
    const decided = decide(claim({
      displayName: 'A'.repeat(200),
      onBehalfOf: 'B'.repeat(200),
      reason: 'C'.repeat(2000),
    }));
    expect(Array.from(decided!.displayName!)).toHaveLength(CLAIM_LIMITS.displayName);
    expect(decided!.displayName!.endsWith('…')).toBe(true);
    expect(Array.from(decided!.onBehalfOf!.text)).toHaveLength(CLAIM_LIMITS.onBehalfOf);
    expect(Array.from(decided!.reason!)).toHaveLength(CLAIM_LIMITS.reason);
    expect(decide(claim({ displayName: 'A'.repeat(64) }))?.displayName).toBe('A'.repeat(64));
  });

  test('a text of any size is cleaned without reading it all', () => {
    const decided = decide(claim({ reason: `${'\u200B'.repeat(5_000_000)}ok` }));
    expect(decided).toBeNull();
  });

  test('anything that is not a protocol 1 object with string fields shows nothing', () => {
    expect(decide(undefined)).toBeNull();
    expect(decide(null)).toBeNull();
    expect(decide('Acme')).toBeNull();
    expect(decide([claim({ displayName: 'Acme' })])).toBeNull();
    expect(decide({ displayName: 'Acme' })).toBeNull();
    expect(decide({ protocolVersion: 2, displayName: 'Acme' })).toBeNull();
    expect(decide(claim({ displayName: 42, onBehalfOf: {}, reason: ['x'], iconUrl: 7 }))).toBeNull();
  });

  test('with no verified origin nothing is shown', () => {
    expect(decide(claim({ displayName: 'Acme' }), '*')).toBeNull();
    expect(decide(claim({ displayName: 'Acme' }), '')).toBeNull();
    expect(decide(claim({ displayName: 'Acme' }), 'null')).toBeNull();
  });

  test('markup stays plain text', () => {
    expect(decide(claim({ displayName: '<img src=x onerror=alert(1)>' }))?.displayName).toBe('<img src=x onerror=alert(1)>');
  });
});

describe('a name that reads as a host', () => {
  test('differing from the verified origin is dropped', () => {
    for (const displayName of ['example.com', 'Notes (notes.example.org)', 'secure-login.app', 'ＥＸＡＭＰＬＥ．ＣＯＭ', 'example。com', 'Acme.io Notes']) {
      expect(decide(claim({ displayName }))).toBeNull();
    }
  });

  test('equal to the origin host is kept', () => {
    expect(decide(claim({ displayName: 'notes.example' }))?.displayName).toBe('notes.example');
    expect(decide(claim({ displayName: 'Notes.Example' }))?.displayName).toBe('Notes.Example');
    expect(decide(claim({ displayName: 'localhost' }), 'http://localhost:5173')?.displayName).toBe('localhost');
  });

  test('a version or a dotted number is not a host', () => {
    expect(decide(claim({ displayName: 'Notes v2.0' }))?.displayName).toBe('Notes v2.0');
    expect(decide(claim({ displayName: 'Acme Inc. Notes' }))?.displayName).toBe('Acme Inc. Notes');
  });
});

describe('the icon', () => {
  test('a PNG, JPEG or WebP data URI shows beside a shown name', () => {
    for (const iconUrl of [PNG, JPEG, WEBP]) {
      expect(decide(claim({ displayName: 'Acme', iconUrl }))?.iconUrl).toBe(iconUrl);
    }
  });

  test('anything else is omitted and the name stays', () => {
    const rejected = [
      `data:image/svg+xml;base64,${Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString('base64')}`,
      'data:image/svg+xml;utf8,<svg/>',
      `data:image/gif;base64,${bytes(0x47, 0x49, 0x46)}`,
      `data:text/html;base64,${Buffer.from('<script>alert(1)</script>').toString('base64')}`,
      'https://notes.example/icon.png',
      'javascript:alert(1)',
      'data:image/png;base64,',
      `data:image/png;base64,${Buffer.from('<svg onload=alert(1)>').toString('base64')}`, // PNG label, not PNG bytes
      PNG.replace('image/png', 'image/jpeg'),
      `${PNG}!`,
      `${PNG} `,
      `DATA:image/png;base64,${bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)}`,
    ];
    for (const iconUrl of rejected) {
      expect(decide(claim({ displayName: 'Acme', iconUrl }))).toEqual({ displayName: 'Acme', iconUrl: null, onBehalfOf: null, reason: null });
    }
  });

  test('a data URI over 32768 characters is omitted; the longest valid one is kept', () => {
    const head = 'data:image/png;base64,';
    // Base64 comes in groups of four: 32744 characters of data make the longest PNG URI that fits (32766 characters).
    const longest = `${head}iVBORw0KGgo${'A'.repeat(32744 - 11)}`;
    expect(longest.length).toBeLessThanOrEqual(MAX_ICON_URI_LENGTH);
    expect(decide(claim({ displayName: 'Acme', iconUrl: longest }))?.iconUrl).toBe(longest);
    const over = `${head}iVBORw0KGgo${'A'.repeat(32748 - 11)}`;
    expect(over.length).toBeGreaterThan(MAX_ICON_URI_LENGTH);
    expect(decide(claim({ displayName: 'Acme', iconUrl: over }))?.iconUrl).toBeNull();
  });

  test('the icon goes with its name: a dropped name takes the icon, and an icon alone shows nothing', () => {
    expect(decide(claim({ displayName: 'TinyCloud One', iconUrl: PNG, reason: 'Sync' }))).toEqual({
      displayName: null, iconUrl: null, onBehalfOf: null, reason: 'Sync',
    });
    expect(decide(claim({ iconUrl: PNG }))).toBeNull();
    expect(decide(claim({ displayName: 'TinyCloud One', iconUrl: PNG }), SHELL)?.iconUrl).toBe(PNG);
  });
});

describe('on behalf of', () => {
  test('equal to the delegatee DID or URI in the signed message is verified', () => {
    expect(decide(claim({ onBehalfOf: DELEGATEE }))?.onBehalfOf).toEqual({ text: DELEGATEE, verified: true });
    expect(decide(claim({ onBehalfOf: DELEGATEE }), APP, `${DELEGATEE}#${DELEGATEE.slice(8)}`)?.onBehalfOf).toEqual({
      text: DELEGATEE, verified: true,
    });
  });

  test('a name, or anything when the message names no delegatee, is a claim', () => {
    expect(decide(claim({ onBehalfOf: 'Sync in Acme' }))?.onBehalfOf).toEqual({ text: 'Sync in Acme', verified: false });
    expect(decide(claim({ onBehalfOf: DELEGATEE }), APP, null)?.onBehalfOf).toEqual({ text: DELEGATEE, verified: false });
    expect(decide(claim({ onBehalfOf: `${DELEGATEE}x` }))?.onBehalfOf?.verified).toBe(false);
    expect(decide(claim({ onBehalfOf: DELEGATEE.toUpperCase() }))?.onBehalfOf?.verified).toBe(false);
  });
});

describe('the lines on the screen', () => {
  const NAME = 'Acme Notes';
  const BEHALF = 'Sync in Acme Notes';
  const REASON = 'Keep your notes in step.';

  test('only a name: its own sentence, with no closing line', () => {
    const view = viewOf(claim({ displayName: NAME }));
    expect(textOf(view)).toEqual([`It calls itself "${NAME}". OpenKey hasn't checked that name.`]);
    expect(view?.closing).toBeNull();
  });

  test('on behalf of alone, and a reason alone, each end with "OpenKey hasn\'t checked this."', () => {
    expect(textOf(viewOf(claim({ onBehalfOf: BEHALF })))).toEqual([
      `It says it's asking for "${BEHALF}".`,
      `OpenKey hasn't checked this.`,
    ]);
    expect(textOf(viewOf(claim({ reason: REASON })))).toEqual([
      `Its reason: "${REASON}"`,
      `OpenKey hasn't checked this.`,
    ]);
  });

  test('two or three claims show in the order name, on behalf of, reason, then one closing line', () => {
    expect(textOf(viewOf(claim({ reason: REASON, displayName: NAME, onBehalfOf: BEHALF })))).toEqual([
      `It calls itself "${NAME}".`,
      `It says it's asking for "${BEHALF}".`,
      `Its reason: "${REASON}"`,
      `OpenKey hasn't checked these.`,
    ]);
    expect(textOf(viewOf(claim({ displayName: NAME, reason: REASON })))).toEqual([
      `It calls itself "${NAME}".`,
      `Its reason: "${REASON}"`,
      `OpenKey hasn't checked these.`,
    ]);
    expect(textOf(viewOf(claim({ onBehalfOf: BEHALF, reason: REASON })))).toEqual([
      `It says it's asking for "${BEHALF}".`,
      `Its reason: "${REASON}"`,
      `OpenKey hasn't checked these.`,
    ]);
  });

  test('a verified on-behalf-of is not labelled unchecked and does not count among the claims', () => {
    expect(textOf(viewOf(claim({ onBehalfOf: DELEGATEE })))).toEqual([`It is asking for "${DELEGATEE}".`]);
    expect(textOf(viewOf(claim({ displayName: NAME, onBehalfOf: DELEGATEE })))).toEqual([
      `It is asking for "${DELEGATEE}".`,
      `It calls itself "${NAME}". OpenKey hasn't checked that name.`,
    ]);
    expect(textOf(viewOf(claim({ displayName: NAME, onBehalfOf: DELEGATEE, reason: REASON })))).toEqual([
      `It is asking for "${DELEGATEE}".`,
      `It calls itself "${NAME}".`,
      `Its reason: "${REASON}"`,
      `OpenKey hasn't checked these.`,
    ]);
  });

  test('nothing to show gives no view lines', () => {
    expect(viewOf(claim({ displayName: 'TinyCloud' }))).toBeNull();
    expect(viewOf(claim({}))).toBeNull();
  });

  test('the copy is one place', () => {
    expect(Object.values(claimedPresentationCopy).every((text) => !text.includes('“') && !text.includes('’'))).toBe(true);
  });
});
