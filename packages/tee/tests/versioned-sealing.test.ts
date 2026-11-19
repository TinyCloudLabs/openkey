import { describe, expect, test } from 'bun:test';
import { createCipheriv, createDecipheriv, createHash } from 'crypto';
import * as tee from '../src/index';
import type { SealingBinding, SealingKeyProvider } from '../src/versioned-sealing';
import * as versioned from '../src/versioned-sealing';
const fixture = await Bun.file(new URL('./fixtures/headerless-generation-zero.json', import.meta.url)).json() as {
  binding: SealingBinding;
  plaintext: string;
  blob: string;
};
const binding: SealingBinding = {
  recordId: 'TEST-record-1',
  sealingContext: 'openkey/key/TEST-context-1',
};
const plaintext = 'TEST plaintext for versioned sealing';
const magic = Buffer.from('OKSEAL\r\n', 'ascii');
const headerLength = 13;
const authenticationError = 'Unable to unseal data';

function testProvider(generation: number): SealingKeyProvider {
  return async (context) => createHash('sha256')
    .update(`TEST versioned sealing provider ${generation}\0`)
    .update(context)
    .digest();
}

const providers = new Map<number, SealingKeyProvider>([
  [0, testProvider(0)],
  [1, testProvider(1)],
]);
const sharedProvider: SealingKeyProvider = async () => createHash('sha256')
  .update('TEST versioned sealing shared authentication key')
  .digest();

function header(kid = 1, version = 1): Buffer {
  const result = Buffer.alloc(headerLength);
  magic.copy(result);
  result.writeUInt8(version, 8);
  result.writeUInt32BE(kid, 9);
  return result;
}

describe('versioned sealing and re-seal maintenance envelopes', () => {

  test('opens the fixed headerless fixture as generation zero', async () => {
    const { SealingKeyring, sealingKid } = versioned!;
    const ring = new SealingKeyring({ providers });
    expect(sealingKid(fixture.blob)).toBe(0);
    expect(await ring.unseal(fixture.blob, fixture.binding)).toBe(fixture.plaintext);
    expect(await tee.unseal(fixture.blob, await testProvider(0)(fixture.binding.sealingContext, 0)))
      .toBe(fixture.plaintext);
  });

  test('defaults to headerless generation zero readable by the frozen primitive', async () => {
    const { SealingKeyring, sealingKid } = versioned!;
    const ring = new SealingKeyring({ providers });
    const blob = await ring.seal(plaintext, binding);
    expect(ring.writeKid).toBe(0);
    expect(sealingKid(blob)).toBe(0);
    expect(Buffer.from(blob, 'base64').length).toBe(28 + Buffer.byteLength(plaintext));
    expect(await tee.unseal(blob, await testProvider(0)(binding.sealingContext, 0))).toBe(plaintext);
    expect(await ring.unseal(blob, binding)).toBe(plaintext);
  });


  test('roundtrips generation one with the documented header and UTF-8 AAD', async () => {
    const { SealingKeyring, sealingKid } = versioned!;
    const unicodeBinding = { recordId: 'TEST-record-λ', sealingContext: 'openkey/key/TEST-雪' };
    const ring = new SealingKeyring({ providers, writeKid: 1 });
    const blob = await ring.seal(plaintext, unicodeBinding);
    const bytes = Buffer.from(blob, 'base64');
    expect(ring.writeKid).toBe(1);
    expect(sealingKid(blob)).toBe(1);
    expect(bytes.subarray(0, 8).equals(magic)).toBe(true);
    expect(bytes.readUInt8(8)).toBe(1);
    expect(bytes.readUInt32BE(9)).toBe(1);
    expect(bytes.length).toBe(headerLength + 28 + Buffer.byteLength(plaintext));
    expect(await ring.unseal(blob, unicodeBinding)).toBe(plaintext);

    const recordBytes = Buffer.from(unicodeBinding.recordId, 'utf8');
    const contextBytes = Buffer.from(unicodeBinding.sealingContext, 'utf8');
    const recordLength = Buffer.alloc(4);
    const contextLength = Buffer.alloc(4);
    recordLength.writeUInt32BE(recordBytes.length);
    contextLength.writeUInt32BE(contextBytes.length);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      await testProvider(1)(unicodeBinding.sealingContext, 1),
      bytes.subarray(headerLength, headerLength + 12),
    );
    decipher.setAAD(Buffer.concat([
      bytes.subarray(0, headerLength), recordLength, recordBytes, contextLength, contextBytes,
    ]));
    decipher.setAuthTag(bytes.subarray(headerLength + 12, headerLength + 28));
    const opened = Buffer.concat([decipher.update(bytes.subarray(headerLength + 28)), decipher.final()]);
    expect(opened.toString('utf8')).toBe(plaintext);
  });

  test.each([0, 1])('roundtrips empty plaintext for generation %i', async (writeKid) => {
    const ring = new versioned!.SealingKeyring({ providers, writeKid });
    const blob = await ring.seal('', binding);
    expect(await ring.unseal(blob, binding)).toBe('');
  });

  test.each([
    ['record', { ...binding, recordId: 'TEST-other-record' }],
    ['context', { ...binding, sealingContext: 'openkey/key/TEST-other-context' }],
  ] as const)('authenticates the %s even with the same provider key', async (_name, changedBinding) => {
    const ring = new versioned!.SealingKeyring({
      providers: new Map([[1, sharedProvider]]), writeKid: 1,
    });
    const blob = await ring.seal(plaintext, binding);
    await expect(ring.unseal(blob, changedBinding)).rejects.toThrow(authenticationError);
  });

  test('authenticates the generation when both generations have the same provider key', async () => {
    const ring = new versioned!.SealingKeyring({
      providers: new Map([[1, sharedProvider], [2, sharedProvider]]), writeKid: 1,
    });
    const bytes = Buffer.from(await ring.seal(plaintext, binding), 'base64');
    bytes.writeUInt32BE(2, 9);
    await expect(ring.unseal(bytes.toString('base64'), binding)).rejects.toThrow(authenticationError);
  });

  test('separates record and context with byte lengths', async () => {
    const ring = new versioned!.SealingKeyring({
      providers: new Map([[1, sharedProvider]]), writeKid: 1,
    });
    const blob = await ring.seal(plaintext, { recordId: 'TEST-a', sealingContext: 'bc' });
    await expect(ring.unseal(blob, { recordId: 'TEST-ab', sealingContext: 'c' }))
      .rejects.toThrow(authenticationError);
  });

  test.each([0, 1])('sanitizes ciphertext authentication failures for generation %i', async (writeKid) => {
    const ring = new versioned!.SealingKeyring({ providers, writeKid });
    const bytes = Buffer.from(await ring.seal(plaintext, binding), 'base64');
    bytes[bytes.length - 1] ^= 1;
    await expect(ring.unseal(bytes.toString('base64'), binding)).rejects.toThrow(authenticationError);
  });

  test('rejects an unknown generation without calling a substitute provider', async () => {
    const { SealingKeyring, sealingKid } = versioned!;
    let calls = 0;
    const substitute: SealingKeyProvider = async (context, kid) => {
      calls++;
      return testProvider(0)(context, kid);
    };
    const writer = new SealingKeyring({ providers, writeKid: 1 });
    const bytes = Buffer.from(await writer.seal(plaintext, binding), 'base64');
    bytes.writeUInt32BE(0xffffffff, 9);
    const blob = bytes.toString('base64');
    const reader = new SealingKeyring({ providers: new Map([[0, substitute], [1, substitute]]) });
    expect(sealingKid(blob)).toBe(0xffffffff);
    await expect(reader.unseal(blob, binding)).rejects.toThrow('Unknown sealing key generation');
    expect(calls).toBe(0);
    await expect(new SealingKeyring({ providers, writeKid: 2 }).seal(plaintext, binding))
      .rejects.toThrow('Unknown sealing key generation');
  });

  test('does not substitute another provider for a headerless read', async () => {
    let calls = 0;
    const ring = new versioned!.SealingKeyring({
      providers: new Map([[1, async () => { calls++; return sharedProvider('', 1); }]]), writeKid: 1,
    });
    await expect(ring.unseal(fixture.blob, fixture.binding)).rejects.toThrow('Unknown sealing key generation');
    expect(calls).toBe(0);
  });

  test('sanitizes provider failures on reads and writes', async () => {
    const failingProvider: SealingKeyProvider = async () => {
      throw new Error('TEST provider diagnostic must not escape');
    };
    const ring = new versioned!.SealingKeyring({ providers: new Map([[0, failingProvider]]) });
    await expect(ring.seal(plaintext, binding)).rejects.toThrow('Unable to seal data');
    await expect(ring.unseal(fixture.blob, fixture.binding)).rejects.toThrow(authenticationError);
  });

  test.each([
    ['empty', ''],
    ['invalid base64', '!not-base64!'],
    ['truncated legacy', Buffer.alloc(27).toString('base64')],
    ['partial magic', magic.subarray(0, 7).toString('base64')],
    ['magic only', magic.toString('base64')],
    ['missing kid bytes', header().subarray(0, 12).toString('base64')],
    ['missing IV and tag', header().toString('base64')],
    ['truncated tag', Buffer.concat([header(), Buffer.alloc(27)]).toString('base64')],
    ['unsupported version', Buffer.concat([header(1, 2), Buffer.alloc(28)]).toString('base64')],
  ])('rejects %s framing safely before provider access', async (_name, blob) => {
    const { SealingKeyring, sealingKid } = versioned!;
    let calls = 0;
    const provider: SealingKeyProvider = async () => { calls++; return sharedProvider('', 0); };
    const ring = new SealingKeyring({ providers: new Map([[0, provider], [1, provider]]) });
    expect(() => sealingKid(blob)).toThrow(/^(Invalid sealed blob|Unsupported sealing format)$/);
    await expect(ring.unseal(blob, binding)).rejects.toThrow(/^(Invalid sealed blob|Unsupported sealing format)$/);
    expect(calls).toBe(0);
  });
});

test('detects validated versioned framing', async () => {
  const { SealingKeyring, isVersionedSealed } = versioned!;
  expect(isVersionedSealed(fixture.blob)).toBe(false);
  expect(isVersionedSealed('')).toBe(false);
  expect(isVersionedSealed('TEST arbitrary legacy value')).toBe(false);
  const ring = new SealingKeyring({ providers, writeKid: 1 });
  expect(isVersionedSealed(await ring.seal(plaintext, binding))).toBe(true);
  for (const invalid of [
    magic.toString('base64'),
    Buffer.concat([header(), Buffer.alloc(27)]).toString('base64'),
    Buffer.concat([header(1, 2), Buffer.alloc(28)]).toString('base64'),
  ]) {
    expect(() => isVersionedSealed(invalid)).toThrow(/^(Invalid sealed blob|Unsupported sealing format)$/);
  }
});

test('rejects headered generation zero so each generation has one format', async () => {
  const { SealingKeyring, sealingKid, isVersionedSealed } = versioned!;
  const versionedHeader = header(0);
  const recordBytes = Buffer.from(binding.recordId, 'utf8');
  const contextBytes = Buffer.from(binding.sealingContext, 'utf8');
  const recordLength = Buffer.alloc(4);
  const contextLength = Buffer.alloc(4);
  recordLength.writeUInt32BE(recordBytes.length);
  contextLength.writeUInt32BE(contextBytes.length);
  const iv = Buffer.alloc(12, 0x54);
  const cipher = createCipheriv('aes-256-gcm', await testProvider(0)(binding.sealingContext, 0), iv);
  cipher.setAAD(Buffer.concat([versionedHeader, recordLength, recordBytes, contextLength, contextBytes]));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const blob = Buffer.concat([versionedHeader, iv, cipher.getAuthTag(), ciphertext]).toString('base64');
  expect(() => sealingKid(blob)).toThrow('Invalid sealing key generation');
  expect(() => isVersionedSealed(blob)).toThrow('Invalid sealing key generation');
  await expect(new SealingKeyring({ providers }).unseal(blob, binding)).rejects.toThrow('Invalid sealing key generation');
});
