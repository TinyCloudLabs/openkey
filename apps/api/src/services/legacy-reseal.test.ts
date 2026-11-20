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

    expect(summary).toEqual({ total: 4, migrated: 4, alreadyCurrent: 0 });
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
    expect(again).toEqual({ total: 4, migrated: 0, alreadyCurrent: 4 });
  });

  test('a partly migrated database finishes: current rows are skipped, old rows move', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const done = await ethereum('e-done', CONTEXT_B, 'u2', newTee.deriveKey);
    const store = memoryStore([done.row, canary.row]);
    const summary = await resealLegacyRows({
      stores: [store], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    });
    expect(summary).toEqual({ total: 2, migrated: 1, alreadyCurrent: 1 });
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

  test('canary must be a pending row: missing, or already current while others are pending', async () => {
    const pending = await ethereum('e-1', CONTEXT_B, 'u2', oldRoot);
    const current = await ethereum('e-canary', CONTEXT_A, 'u1', newTee.deriveKey);
    const open = async () => legacyFor().legacy;
    await expect(resealLegacyRows({ stores: [memoryStore([pending.row])], tee: newTee, openLegacy: open, canary: { source: 'ethereum_key', id: 'e-canary' } }))
      .rejects.toMatchObject({ code: 'reseal_canary_missing' });
    await expect(resealLegacyRows({ stores: [memoryStore([pending.row, current.row])], tee: newTee, openLegacy: open, canary: { source: 'ethereum_key', id: 'e-canary' } }))
      .rejects.toMatchObject({ code: 'reseal_canary_not_pending' });
  });

  test('an old-sealed row whose key is not the row\'s own address is refused and left as it was', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const wrong = await ethereum('e-wrong', CONTEXT_B, 'u2', oldRoot);
    // The row claims another address than the key it holds.
    const lying: ResealRow = { ...wrong.row, matches: () => false };
    const store = memoryStore([canary.row, lying]);
    await expect(resealLegacyRows({
      stores: [store], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_row_mismatch', rowId: 'e-wrong' });
    expect((await store.rows()).find((r) => r.id === 'e-wrong')!.sealed).toBe(wrong.row.sealed);
  });

  test('a row sealed under neither root, or one that opens under the current key but is not its own: bail', async () => {
    const canary = await ethereum('e-canary', CONTEXT_A, 'u1', oldRoot);
    const stray = await ethereum('e-stray', CONTEXT_B, 'u2', keyUnder('some-third-root'));
    await expect(resealLegacyRows({
      stores: [memoryStore([canary.row, stray.row])], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-canary' },
    })).rejects.toMatchObject({ code: 'reseal_old_unseal_failed', rowId: 'e-stray' });

    const corrupt = await ethereum('e-corrupt', CONTEXT_B, 'u2', newTee.deriveKey);
    await expect(resealLegacyRows({
      stores: [memoryStore([{ ...corrupt.row, matches: () => false }])], tee: newTee, openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-corrupt' },
    })).rejects.toMatchObject({ code: 'reseal_row_mismatch' });
  });

  test('a row with no resolvable sealing path (NULL context, no user) is refused', async () => {
    const orphan = await ethereum('e-orphan', CONTEXT_D, null, oldRoot);
    await expect(resealLegacyRows({
      stores: [memoryStore([{ ...orphan.row, sealingContext: null, userId: null }])], tee: newTee,
      openLegacy: async () => legacyFor().legacy, canary: { source: 'ethereum_key', id: 'e-orphan' },
    })).rejects.toMatchObject({ code: 'reseal_row_unreadable' });
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
