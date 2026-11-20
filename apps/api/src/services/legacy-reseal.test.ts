import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
  generateNostrKeypair,
  generatePrivateKey,
  getAddressFromPrivateKey,
  nostrPubkeyFromSecret,
  seal,
  unseal,
} from '@openkey/tee';
import {
  LegacyResealError,
  resealLegacyRows,
  type ResealLegacy,
  type ResealRow,
  type ResealSource,
  type ResealStore,
  type ResealTee,
} from './legacy-reseal';
import { legacyOpener, resealLegacyAtBoot } from './legacy-reseal-boot';

// Two roots: the current one and the pre-move one. Each derives a 32-byte key per path.
const keyUnder = (root: string) => async (path: string) => new Uint8Array(createHash('sha256').update(root).update(path).digest());
const newTee: ResealTee = { deriveKey: keyUnder('new-root') };
const oldRoot = keyUnder('old-root');

// Canonical 256-bit sealing contexts (the resolver refuses anything else).
const ctxOf = (fill: number) => Buffer.alloc(32, fill).toString('base64url');
const CONTEXT_A = ctxOf(1);
const CONTEXT_B = ctxOf(2);
const CONTEXT_C = ctxOf(3);
const CONTEXT_D = ctxOf(4);

type Fixture = { row: ResealRow; plaintext: string };

async function ethereum(id: string, context: string | null, userId: string | null, root: (p: string) => Promise<Uint8Array>): Promise<Fixture> {
  const plaintext = generatePrivateKey();
  const address = getAddressFromPrivateKey(plaintext);
  const path = context ? `openkey/key/${context}` : `openkey/user/${userId}/keys`;
  return {
    plaintext,
    row: {
      source: 'ethereum_key', id, userId, sealingContext: context,
      sealed: await seal(plaintext, await root(path)),
      matches: (p) => getAddressFromPrivateKey(p as `0x${string}`).toLowerCase() === address.toLowerCase(),
    },
  };
}

async function nostr(id: string, context: string, root: (p: string) => Promise<Uint8Array>): Promise<Fixture> {
  const pair = generateNostrKeypair();
  return {
    plaintext: pair.secretKeyHex,
    row: {
      source: 'nostr_key', id, userId: 'u-nostr', sealingContext: context,
      sealed: await seal(pair.secretKeyHex, await root(`openkey/key/${context}`)),
      matches: (p) => nostrPubkeyFromSecret(p) === pair.pubkeyHex,
    },
  };
}

function memoryStore(rows: ResealRow[], log: string[] = [], options: { lie?: boolean; refuse?: boolean } = {}): ResealStore & { rows(): Promise<ResealRow[]> } {
  const state = rows.map((row) => ({ ...row }));
  return {
    async rows() {
      return state.map((row) => ({ ...row }));
    },
    async swap(row, sealed) {
      const current = state.find((r) => r.id === row.id && r.source === row.source)!;
      if (options.refuse || current.sealed !== row.sealed) return false;
      log.push(`swap ${row.source}:${row.id}`);
      if (!options.lie) current.sealed = sealed;
      return true;
    },
  };
}

const legacyFor = (log: string[] = []): { calls: string[]; legacy: ResealLegacy } => {
  const calls: string[] = [];
  return {
    calls,
    legacy: { async legacyKey(path) { calls.push(path); log.push('legacyKey'); return oldRoot(path); } },
  };
};

async function opensUnderNew(store: ResealStore, plaintexts: Map<string, string>) {
  for (const row of await store.rows()) {
    expect(await unseal(row.sealed, await newTee.deriveKey(row.sealingContext ? `openkey/key/${row.sealingContext}` : `openkey/user/${row.userId}/keys`))).toBe(plaintexts.get(`${row.source}:${row.id}`)!);
  }
}

describe('resealLegacyRows', () => {
  test('moves every old-sealed row to the current key, canary first loaded and last swapped; a second run is a no-op', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const others = [
      await ethereum('e-1', CONTEXT_B, 'u2', oldRoot),
      await ethereum('e-null', null, 'u3', oldRoot), // legacy NULL context: openkey/user/<id>/keys
      await nostr('n-1', CONTEXT_C, oldRoot),
    ];
    const log: string[] = [];
    const eth = memoryStore([canary.row, others[0]!.row, others[1]!.row], log);
    const nos = memoryStore([others[2]!.row], log);
    const { legacy, calls } = legacyFor(log);
    let opened = 0;

    const summary = await resealLegacyRows({
      stores: [eth, nos],
      tee: newTee,
      openLegacy: async () => { opened += 1; log.push('open'); return legacy; },
      canary: { source: 'ethereum_key', id: 'e-canary' },
    });

    expect(summary).toEqual({ total: 4, migrated: 4, alreadyCurrent: 0, quarantined: [] });
    expect(opened).toBe(1);
    expect(log[0]).toBe('open'); // the old root, canary proven, before any row is read with it or written
    expect(log.filter((l) => l.startsWith('swap')).at(-1)).toBe('swap ethereum_key:e-canary');
    expect(calls).toContain(`openkey/key/${CONTEXT_B}`);
    expect(calls).toContain('openkey/user/u3/keys');
    const plaintexts = new Map([['ethereum_key:e-canary', canary.plaintext], ['ethereum_key:e-1', others[0]!.plaintext], ['ethereum_key:e-null', others[1]!.plaintext], ['nostr_key:n-1', others[2]!.plaintext]]);
    await opensUnderNew(eth, plaintexts);
    await opensUnderNew(nos, plaintexts);

    // Re-run: everything is current, so the old root is never even opened.
    const again = await resealLegacyRows({
      stores: [eth, nos], tee: newTee,
      openLegacy: async () => { throw new Error('old root must not be needed'); },
      canary: { source: 'ethereum_key', id: 'e-canary' },
    });
    expect(again).toEqual({ total: 4, migrated: 0, alreadyCurrent: 4, quarantined: [] });
  });

  test('a partly migrated database finishes: current rows are skipped, old rows move', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const done = await ethereum('e-done', CONTEXT_B, 'u2', newTee.deriveKey);
    const store = memoryStore([done.row, canary.row]);
    const summary = await resealLegacyRows({
      stores: [store], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    });
    expect(summary).toEqual({ total: 2, migrated: 1, alreadyCurrent: 1, quarantined: [] });
  });

  test('reports counts after every swapped row, never row contents', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const a = await ethereum('e-1', CONTEXT_B, 'u2', oldRoot);
    const b = await ethereum('e-2', CONTEXT_C, 'u3', newTee.deriveKey);
    const seen: unknown[] = [];
    await resealLegacyRows({
      stores: [memoryStore([canary.row, a.row, b.row])], tee: newTee, openLegacy: async () => legacyFor().legacy,
      canary: { source: 'ethereum_key', id: 'e-canary' }, onProgress: (p) => seen.push(p),
    });
    expect(seen).toEqual([{ done: 1, pending: 2, total: 3 }, { done: 2, pending: 2, total: 3 }]);
  });

  test('a failed canary (old root not proven) writes nothing', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const other = await ethereum('e-1', CONTEXT_B, 'u2', oldRoot);
    const log: string[] = [];
    const store = memoryStore([canary.row, other.row], log);
    await expect(resealLegacyRows({
      stores: [store], tee: newTee,
      openLegacy: async () => { throw new LegacyResealError('reseal_canary_mismatch'); },
      canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_canary_mismatch' });
    expect(log).toEqual([]);
  });

  test('canary must exist while rows are pending', async () => {
    const pending = await ethereum('e-1', CONTEXT_B, 'u2', oldRoot);
    await expect(resealLegacyRows({ stores: [memoryStore([pending.row])], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' } }))
      .rejects.toMatchObject({ code: 'reseal_canary_missing' });
  });

  test('a row that opens under neither key, or is not its own, is quarantined: untouched, listed by id, the rest still migrates', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const good = await ethereum('e-good', CONTEXT_B, 'u2', oldRoot);
    const stray = await ethereum('e-stray', CONTEXT_C, 'u3', keyUnder('some-third-root'));
    const wrong = await ethereum('e-wrong', CONTEXT_D, 'u4', oldRoot);
    const lying: ResealRow = { ...wrong.row, matches: () => false }; // opens under the old key but is not its own address
    const orphan = await ethereum('e-orphan', CONTEXT_A, null, oldRoot);
    const unresolvable: ResealRow = { ...orphan.row, sealingContext: null, userId: null };
    const filler = await Promise.all(Array.from({ length: 300 }, (_, i) => ethereum(`e-f${i}`, ctxOf(10 + (i % 200)), `u-f${i}`, newTee.deriveKey)));
    const log: string[] = [];
    const store = memoryStore([canary.row, good.row, stray.row, lying, unresolvable, ...filler.map((f) => f.row)], log);
    const summary = await resealLegacyRows({
      stores: [store], tee: newTee, openLegacy: async () => legacyFor(log).legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    });
    expect(summary.migrated).toBe(2); // canary + good
    expect(summary.quarantined).toEqual([
      { source: 'ethereum_key', id: 'e-orphan', reason: 'unreadable' },
      { source: 'ethereum_key', id: 'e-stray', reason: 'unopenable' },
      { source: 'ethereum_key', id: 'e-wrong', reason: 'mismatch' },
    ]);
    const after = await store.rows();
    expect(after.find((r) => r.id === 'e-stray')!.sealed).toBe(stray.row.sealed);
    expect(after.find((r) => r.id === 'e-wrong')!.sealed).toBe(wrong.row.sealed);
    // Pre-verify: every old-key call happens before the first write.
    const lastKey = log.lastIndexOf('legacyKey');
    const firstSwap = log.findIndex((l) => l.startsWith('swap'));
    expect(lastKey).toBeLessThan(firstSwap);
  });

  test('quarantine is capped at max(3, 0.5% of rows): more means the wrong key, nothing is written', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const strays = await Promise.all([1, 2, 3, 4].map((n) => ethereum(`e-s${n}`, ctxOf(20 + n), `u-s${n}`, keyUnder('third'))));
    const good = await ethereum('e-good', CONTEXT_B, 'u2', oldRoot);
    const log: string[] = [];
    await expect(resealLegacyRows({
      stores: [memoryStore([canary.row, good.row, ...strays.map((s) => s.row)], log)], tee: newTee,
      openLegacy: async () => legacyFor(log).legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_quarantine_limit' });
    expect(log.filter((l) => l.startsWith('swap'))).toEqual([]);
  });

  test('the canary itself failing is never quarantined: it fails closed, with nothing written', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', keyUnder('some-third-root'));
    const good = await ethereum('e-good', CONTEXT_B, 'u2', oldRoot);
    const log: string[] = [];
    await expect(resealLegacyRows({
      stores: [memoryStore([canary.row, good.row], log)], tee: newTee, openLegacy: async () => legacyFor(log).legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_old_unseal_failed', rowId: 'e-canary' });
    expect(log.filter((l) => l.startsWith('swap'))).toEqual([]);

    // Also when the canary opens under the CURRENT key but is not its own.
    const corrupt = await ethereum('e-corrupt', CONTEXT_B, 'u2', newTee.deriveKey);
    await expect(resealLegacyRows({
      stores: [memoryStore([{ ...corrupt.row, matches: () => false }])], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-corrupt' },
    })).rejects.toMatchObject({ code: 'reseal_canary_not_pending' });
  });

  test('a re-run with a quarantined row left behind boots again without the old root, and does not loop', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const stray = await ethereum('e-stray', CONTEXT_B, 'u2', keyUnder('some-third-root'));
    const filler = await Promise.all(Array.from({ length: 700 }, (_, i) => ethereum(`e-f${i}`, ctxOf(10 + (i % 200)), `u-f${i}`, newTee.deriveKey)));
    const store = memoryStore([canary.row, stray.row, ...filler.map((f) => f.row)]);
    const first = await resealLegacyRows({ stores: [store], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' } });
    expect(first).toMatchObject({ migrated: 1, quarantined: [{ id: 'e-stray', reason: 'unopenable' }] });
    const again = await resealLegacyRows({
      stores: [store], tee: newTee,
      openLegacy: async () => { throw new Error('old root must not be needed'); },
      canary: { source: 'ethereum_key', id: 'e-canary' },
    });
    expect(again).toMatchObject({ migrated: 0, quarantined: [{ id: 'e-stray' }] });
  });

  test('a sidecar/KMS failure while verifying stops the run before any write', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const first = await ethereum('e-1', CONTEXT_B, 'u2', oldRoot);
    const second = await ethereum('e-2', CONTEXT_C, 'u3', oldRoot);
    const log: string[] = [];
    const store = memoryStore([canary.row, first.row, second.row], log);
    let calls = 0;
    const flaky: ResealLegacy = {
      async legacyKey(path) {
        calls += 1;
        if (calls === 2) throw new Error('kms refused');
        return oldRoot(path);
      },
    };
    await expect(resealLegacyRows({
      stores: [store], tee: newTee, openLegacy: async () => flaky, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toThrow('kms refused');
    expect(log).toEqual([]); // not skipped as a bad row, and nothing was written
    expect(calls).toBeLessThanOrEqual(3); // with 4 workers over 3 rows all three start at once; none after a failure
  });

  test('old-key fetches run at most 4 at a time, every row still migrates, and a failure stops new fetches', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const rest = await Promise.all(Array.from({ length: 20 }, (_, i) => ethereum(`e-${i}`, ctxOf(40 + i), `u-${i}`, oldRoot)));
    let inFlight = 0;
    let peak = 0;
    let started = 0;
    const slow = (failAt: number): ResealLegacy => ({
      async legacyKey(path) {
        started += 1;
        const n = started;
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await Promise.resolve(); // a yield, so the four workers overlap
        inFlight -= 1;
        if (n === failAt) throw new Error('kms refused');
        return oldRoot(path);
      },
    });
    const store = memoryStore([canary.row, ...rest.map((r) => r.row)]);
    const summary = await resealLegacyRows({ stores: [store], tee: newTee, openLegacy: async () => slow(-1), canary: { source: 'ethereum_key', id: 'e-canary' } });
    expect(summary.migrated).toBe(21);
    expect(peak).toBe(4);

    started = 0;
    const fresh = memoryStore([canary.row, ...rest.map((r) => r.row)]);
    await expect(resealLegacyRows({ stores: [fresh], tee: newTee, openLegacy: async () => slow(6), canary: { source: 'ethereum_key', id: 'e-canary' } })).rejects.toThrow('kms refused');
    expect(started).toBeLessThan(12); // stopped well short of the 21 rows
    expect((await fresh.rows()).every((r) => [canary.row, ...rest.map((x) => x.row)].some((o) => o.id === r.id && o.sealed === r.sealed))).toBe(true); // nothing written
  });

  test('a swap that loses the compare-and-swap, or a store that claims success without writing, bails', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    await expect(resealLegacyRows({
      stores: [memoryStore([canary.row], [], { refuse: true })], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_swap_failed' });
    await expect(resealLegacyRows({
      stores: [memoryStore([canary.row], [], { lie: true })], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_verify_failed' });
  });
});

describe('resealLegacyAtBoot', () => {
  const sourceOf = (s: ResealSource) => s;
  void sourceOf;
  const env = {
    OPENKEY_LEGACY_RESEAL: 'enabled',
    OPENKEY_LEGACY_SIDECAR_SOCKET: '/run/key-recovery/kr.sock',
    OPENKEY_LEGACY_ROOT_EPOCH: '0',
    OPENKEY_LEGACY_KMS_ROOT_PUBKEY: '0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1',
    OPENKEY_LEGACY_APP_ID: 'b7d6e87778f73904a8f5fd26e4d0f1d1310234be',
    OPENKEY_LEGACY_CANARY_ADDRESS: '0x92a13CF5e915b6a4c70EC7FF68277ad9670B922C',
  };
  const untouchedPrisma = new Proxy({}, { get() { throw new Error('the database must not be read'); } }) as never;
  const tee = { deriveKey: newTee.deriveKey } as never;

  test('is off unless the flag is exactly "enabled"; any other value, or a missing/odd canary address, refuses', async () => {
    expect(await resealLegacyAtBoot(untouchedPrisma, tee, {})).toBe('off');
    expect(await resealLegacyAtBoot(untouchedPrisma, tee, { OPENKEY_LEGACY_RESEAL: '' })).toBe('off');
    for (const bad of [
      { ...env, OPENKEY_LEGACY_RESEAL: 'true' },
      { ...env, OPENKEY_LEGACY_CANARY_ADDRESS: undefined },
      { ...env, OPENKEY_LEGACY_CANARY_ADDRESS: '0x1234' },
    ]) {
      await expect(resealLegacyAtBoot(untouchedPrisma, tee, bad)).rejects.toMatchObject({ code: 'reseal_config' });
    }
  });

  test('the legacy opener refuses an unset root pin and a canary whose key is not the pinned address', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const wrongAddress = '0x' + '11'.repeat(20);
    const prismaWith = (sealedBlob: string) => ({
      ethereumKey: { findFirst: async () => ({ userId: 'u1', sealedBlob, sealingContext: CONTEXT_A }) },
    }) as never;
    const fakeLoad = (async () => ({ legacyKey: async (p: string) => oldRoot(p) })) as never;

    // UNSET pin: not hex, refused by the pin parser before any sidecar call.
    await expect(legacyOpener(prismaWith(canary.row.sealed), { ...env, OPENKEY_LEGACY_KMS_ROOT_PUBKEY: 'UNSET_TC3554_P2_EPOCH0_KMS_ROOT_PUBKEY' }, env.OPENKEY_LEGACY_CANARY_ADDRESS, fakeLoad)())
      .rejects.toMatchObject({ code: 'config_invalid' });
    // The old root opens the canary, but its key is not the pinned address: not the account we pinned.
    await expect(legacyOpener(prismaWith(canary.row.sealed), env, wrongAddress, fakeLoad)())
      .rejects.toMatchObject({ code: 'reseal_canary_mismatch' });
    // And the pinned address is the key's own: accepted.
    const address = getAddressFromPrivateKey(canary.plaintext as `0x${string}`);
    const legacy = await legacyOpener(prismaWith(canary.row.sealed), env, address, fakeLoad)();
    expect(Buffer.from(await legacy.legacyKey(`openkey/key/${CONTEXT_A}`)).toString('hex')).toBe(Buffer.from(await oldRoot(`openkey/key/${CONTEXT_A}`)).toString('hex'));
  });
});
