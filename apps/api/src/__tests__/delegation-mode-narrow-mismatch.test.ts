// TC-3810: unit test exercising siwe-narrow.ts's post-splice
// `narrowed_recap_mismatch` guard when WASM prepareSession emits a divergent
// delegationMode compared to the original SIWE.
import { beforeAll, describe, expect, test } from 'bun:test';
import * as realWasm from '@tinycloud/node-sdk-wasm';
import { DELEGATION_MODE_KEY } from '../services/signed-subset';
import type { narrowSiwePreservingImmutable } from '../services/siwe-narrow';
import { mockModules } from './mock-module';

const realPrepareSession = realWasm.prepareSession;
let injectModeOnPrepare = false;

function addMode(siwe: string, mode: 'terminal' | 'attenuable'): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  const parsed = JSON.parse(Buffer.from(line.slice('- urn:recap:'.length), 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const next = { att: parsed.att, prf: parsed.prf, [DELEGATION_MODE_KEY]: mode };
  return siwe.replace(line, `- urn:recap:${Buffer.from(JSON.stringify(next), 'utf8').toString('base64url')}`);
}

await mockModules({
  '@tinycloud/node-sdk-wasm': () => ({
    prepareSession: (config: Parameters<typeof realPrepareSession>[0]) => {
      const prepared = realPrepareSession(config);
      if (!injectModeOnPrepare) return prepared;
      return { ...prepared, siwe: addMode(prepared.siwe as string, 'terminal') };
    },
  }),
});

let narrow: typeof narrowSiwePreservingImmutable;
beforeAll(async () => {
  ({ narrowSiwePreservingImmutable: narrow } = await import(
    '../services/siwe-narrow?delegation-mode-mismatch-isolated' as string
  ));
});

describe('siwe-narrow post-splice delegationMode mismatch guard', () => {
  test('returns narrowed_recap_mismatch if regenerated ReCap adds a delegationMode absent from original', () => {
    const address = '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c';
    const space = `tinycloud:pkh:eip155:1:${address}:default`;
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    const issuedAt = '2026-11-08T00:00:00.000Z';
    const expirationTime = '2026-11-15T00:00:00.000Z';

    injectModeOnPrepare = false;
    const originalSiwe = realPrepareSession({
      address,
      chainId: 1,
      domain: 'app.example.com',
      issuedAt,
      expirationTime,
      spaceId: space,
      jwk,
      abilities: {
        kv: { 'notes/': ['tinycloud.kv/get', 'tinycloud.kv/put'] },
        capabilities: { '': ['tinycloud.capabilities/read'] },
      },
    }).siwe as string;

    const entries = (realWasm.parseRecapFromSiwe(originalSiwe) as Array<{
      service: string;
      space: string;
      path: string;
      actions: string[];
    }>).map((e) => ({
      ...e,
      actions: e.actions.filter((a) => a !== 'tinycloud.kv/put'),
    }));

    // Without baselineCaveats and without an original mode, narrowSiwePreservingImmutable
    // takes the WASM-emitted ReCap line directly; stubbing prepareSession to inject a
    // mode must be caught by the post-splice guard.
    injectModeOnPrepare = true;
    try {
      const outcome = narrow({
        originalSiwe,
        narrowedEntries: entries,
        address,
        chainId: 1,
        domain: 'app.example.com',
        issuedAt,
        expirationTime,
        spaceId: space,
        jwk,
      });
      expect(outcome.ok).toBe(false);
      if (outcome.ok) return;
      expect(outcome.code).toBe('narrowed_recap_mismatch');
    } finally {
      injectModeOnPrepare = false;
    }
  });
});
