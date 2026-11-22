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
const SHELL = 'https://tinycloud.one';
const DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

const bytes = (...head: number[]) => Buffer.from([...head, ...new Array(30).fill(7)]).toString('base64');
const PNG = `data:image/png;base64,${bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)}`;
const JPEG = `data:image/jpeg;base64,${bytes(0xff, 0xd8, 0xff, 0xe0)}`;
const WEBP = `data:image/webp;base64,${bytes(0x52, 0x49, 0x46, 0x46)}`;

function decide(presentation: unknown, origin = APP) {
  return claimedPresentation({ presentation, origin });
}
const claim = (fields: Record<string, unknown>) => ({ protocolVersion: 1, ...fields });
const viewOf = (presentation: unknown, origin = APP): ClaimedPresentationView | null => {
  const decided = decide(presentation, origin);
  return decided ? claimedPresentationView(decided) : null;
};
const textOf = (view: ClaimedPresentationView | null): string[] =>
  view ? [...view.claims.map(claimLineText), ...(view.closing ? [view.closing] : [])] : [];

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
      'Secret Manager Pro',
      'Tinydoud', // `cl` drawn as `d`
    ];
    for (const displayName of disguised) {
      expect(decide(claim({ displayName }))).toBeNull();
    }
  });

  test('names that swap a letter for a lookalike from another script, a symbol or a sound-alike are dropped', () => {
    const lookalikes = [
      'TinyCl\u0585ud', // Armenian oh
      'Tі\u006Ey \u13DFloud', // Cyrillic і and Cherokee Ꮯ
      'OpenKe\u04AF', // Cyrillic ү
      'Open\u0138EY', // Latin kra
      'OpenK\u0258y', // Latin reversed e
      'ОрепКеу', // all Cyrillic
      'Tinycl\u25CBud', // white circle
      'TinyClovd', // v for u
      'TinyCloûd',
      'Tiny Cl0ud One',
    ];
    for (const text of lookalikes) {
      expect(decide(claim({ displayName: text }))).toBeNull();
      expect(decide(claim({ displayName: 'Acme Notes', onBehalfOf: text }))).toEqual({
        displayName: 'Acme Notes', iconUrl: null, onBehalfOf: null, reason: null,
      });
    }
  });

  test('a name that mixes scripts is dropped; one written in a single script, or in Latin with digits and punctuation, is shown', () => {
    for (const text of ['Nоtes', 'Notes Блокнот', 'Δelta Notes', 'Notes ノート', 'Ꮯat']) {
      expect(decide(claim({ displayName: text }))).toBeNull();
      expect(decide(claim({ onBehalfOf: text }))).toBeNull();
    }
    for (const text of ['Acme Notes', 'Блокнот', 'Ноты 2', 'ノート', '日本語のノート', 'Δέλτα', 'Café Notes #1 (beta)']) {
      expect(decide(claim({ displayName: text }))?.displayName).toBe(text);
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
      onBehalfOf: 'Home in OpenKey',
      reason: null,
    });
    expect(decide(claim({ displayName: 'Share' }), 'https://share.tinycloud.xyz')?.displayName).toBe('Share');
  });

  test('a desktop webview origin is not a trusted shell, so a reserved name from it is dropped', () => {
    for (const origin of ['tauri://localhost', 'http://tauri.localhost', 'https://tauri.localhost']) {
      expect(decide(claim({ displayName: 'TinyCloud One', onBehalfOf: 'Home in OpenKey' }), origin)).toBeNull();
      expect(decide(claim({ displayName: 'Acme Notes' }), origin)?.displayName).toBe('Acme Notes');
    }
  });

  test('a trusted shell origin is an exact match', () => {
    for (const origin of ['https://tinycloud.one.evil.example', 'https://www.tinycloud.one', 'http://tinycloud.one', 'https://tinycloud.one:8443']) {
      expect(decide(claim({ displayName: 'TinyCloud One' }), origin)).toBeNull();
    }
  });

  test('a reason that holds a reserved name is dropped, however it is spelled', () => {
    for (const reason of [
      'OpenKey security check: approve to continue',
      'Share my notes with TinyCloud',
      'Open Key needs this',
      'Ореn Кеу needs this',
      'Your T1nyCl0ud account',
    ]) {
      expect(decide(claim({ reason, displayName: 'Acme Notes' }))?.reason).toBeNull();
      expect(decide(claim({ reason }))).toBeNull();
    }
    expect(decide(claim({ reason: 'Keep your notes in step.' }))?.reason).toBe('Keep your notes in step.');
  });

  test('a reason with a reserved name is kept for a trusted shell origin', () => {
    expect(decide(claim({ reason: 'Share my notes with TinyCloud' }), SHELL)?.reason).toBe('Share my notes with TinyCloud');
  });

  test('names that merely resemble nothing reserved pass', () => {
    expect(containsReservedName('Acme Notes')).toBe(false);
    expect(containsReservedName('Tiny Notes')).toBe(false);
    expect(containsReservedName('Cloud Drive')).toBe(false);
  });

  test('"Share" and "Secret Manager" are reserved as whole words, however they are separated or disguised', () => {
    const reserved = [
      'Share', 'share', 'SHARE', 'Share Notes', 'My Share', 'Sh4re', 'Sh@re', '$hare',
      'Share-Notes', 'Share_Notes', 'Share2', 'Share1', 'Share9 Notes', 'Share!', '(Share)',
      'S h a r e', 'S-h-a-r-e',
      'Secret Manager', 'Secret Manager Pro', 'Secret-Manager', 'Secret_Manager', 'My Secret Manager', 'SecretManager',
      'Secret2Manager',
    ];
    for (const text of reserved) {
      expect(containsReservedName(text)).toBe(true);
      expect(decide(claim({ displayName: text }))).toBeNull();
      expect(decide(claim({ displayName: text }), SHELL)?.displayName).toBe(text);
    }
    expect(decide(claim({ displayName: 'Sha\u200Bre' }))).toBeNull();
    expect(decide(claim({ displayName: 'Sha\u200Bre' }), SHELL)?.displayName).toBe('Share');
    // Mixed-script and host-like spellings are reserved too, and a trusted shell origin may not use them either.
    for (const text of ['Shаre', 'Ѕecret Manager', 'Secret Мanager', 'Share.app', 'Secret.Manager', 'My·Share', 'My‧Share']) {
      expect(containsReservedName(text)).toBe(true);
      expect(decide(claim({ displayName: text }))).toBeNull();
      expect(decide(claim({ displayName: text }), SHELL)).toBeNull();
    }
  });

  test('"Share" and "Secret Manager" glued to letters are not reserved', () => {
    for (const text of ['Shared Notes', 'ShareThis', 'Fileshare', 'Sharp', 'Shareware', 'Timeshare Notes', 'Secretary Manager', 'Secret Managers', 'Top Secret Managerie']) {
      expect(containsReservedName(text)).toBe(false);
      expect(decide(claim({ displayName: text }))?.displayName).toBe(text);
    }
  });

  test('the other reserved names still match inside a word', () => {
    for (const text of ['MyTinyCloudApp', 'OpenKeyish', 'xTinyChatx', 'TinyCloudOne']) {
      expect(containsReservedName(text)).toBe(true);
    }
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
    expect(Array.from(decided!.onBehalfOf!)).toHaveLength(CLAIM_LIMITS.onBehalfOf);
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

  test('a dot written as a lookalike mark, with spaces, in brackets or as the word "dot" still reads as a host', () => {
    for (const displayName of ['example·com', 'example‧com', 'example・com', 'example܁com', 'example . com', 'example [.] com', 'example(.)com', 'example dot com', 'secure-login .app']) {
      expect(decide(claim({ displayName }))).toBeNull();
    }
    expect(decide(claim({ displayName: 'notes dot example' }))?.displayName).toBe('notes dot example');
  });

  test('"on behalf of" and a reason that read as another host are dropped; the origin\'s own host is kept', () => {
    expect(decide(claim({ onBehalfOf: 'paypal.com', displayName: 'Acme Notes' }))?.onBehalfOf).toBeNull();
    expect(decide(claim({ onBehalfOf: 'paypal dot com', displayName: 'Acme Notes' }))?.onBehalfOf).toBeNull();
    expect(decide(claim({ reason: 'Sign in at paypal.com', displayName: 'Acme Notes' }))?.reason).toBeNull();
    expect(decide(claim({ onBehalfOf: 'notes.example' }))?.onBehalfOf).toBe('notes.example');
    expect(decide(claim({ reason: 'Sync with notes.example' }))?.reason).toBe('Sync with notes.example');
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
  test('any text is a claim, whatever the signed message names', () => {
    expect(decide(claim({ onBehalfOf: 'Sync in Acme' }))?.onBehalfOf).toBe('Sync in Acme');
    expect(decide(claim({ onBehalfOf: DID }))?.onBehalfOf).toBe(DID);
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

  test('an on-behalf-of that is a DID is the same unchecked claim and counts toward the closing line', () => {
    expect(textOf(viewOf(claim({ onBehalfOf: DID })))).toEqual([
      `It says it's asking for "${DID}".`,
      `OpenKey hasn't checked this.`,
    ]);
    expect(textOf(viewOf(claim({ displayName: NAME, onBehalfOf: DID })))).toEqual([
      `It calls itself "${NAME}".`,
      `It says it's asking for "${DID}".`,
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
