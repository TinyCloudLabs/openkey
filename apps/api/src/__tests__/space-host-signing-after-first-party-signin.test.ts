// An account with no bootstrap row is refused a `default` host by a third-party app. A sign-in from a first-party app
// records the row (`complete`), and the same third-party request is signed after that.

import { afterEach, beforeEach, expect, mock, test } from 'bun:test';
import { generateHostSIWEMessage, prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore, type FakeBootstrapStore } from './fake-bootstrap-state';
import { originProvisionAuthority } from '../services/provision-authority';
import { refusesThirdPartySpaceHost } from '../services/space-host-signing';
import { ensureTinyCloudBootstrapForApprovedSign, setTinyCloudBootstrapExecutorForTests } from '../services/tinycloud-bootstrap';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const key = { id: 'after-key', address: account.address, keyType: 'MANAGED' };
const userId = 'after-user';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;

const savedEnv = { host: process.env.TINYCLOUD_BOOTSTRAP_HOST, node: process.env.NODE_ENV, on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN };
const executor = mock(async () => undefined);
let store: FakeBootstrapStore;

beforeEach(() => {
  store = createFakeBootstrapStore({
    users: [{ id: userId, autoSignEnabled: true }],
    keys: [{ ...key, userId, archivedAt: null, sealedBlob: null, sealingContext: null } as never],
  });
  process.env.NODE_ENV = 'test';
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  executor.mockClear();
  setTinyCloudBootstrapExecutorForTests(executor);
});

afterEach(() => {
  setTinyCloudBootstrapExecutorForTests();
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_HOST: savedEnv.host, NODE_ENV: savedEnv.node, TINYCLOUD_BOOTSTRAP_ON_SIGN: savedEnv.on })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

const accountSignIn = () => prepareSession({
  address: account.address, chainId: 1, domain: 'tinycloud.one',
  issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
  spaceId: spaceId('account'), jwk, abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
} as never).siwe;

const thirdPartyHostsDefault = () => refusesThirdPartySpaceHost({
  prisma: store.prisma,
  message: generateHostSIWEMessage({
    address: account.address, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(), spaceId: spaceId('default'),
    peerId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  }),
  key,
  authorities: [originProvisionAuthority('https://app.example.test')],
});

test('a third-party app hosts the owner\'s `default` space after a first-party sign-in recorded the account as complete', async () => {
  expect(store.rows).toEqual([]);
  expect(await thirdPartyHostsDefault()).toBe(true);

  const outcome = await ensureTinyCloudBootstrapForApprovedSign({
    prisma: store.prisma, userId, key, privateKey, message: accountSignIn(), format: 'personal_sign',
    authority: originProvisionAuthority('https://home.tinycloud.xyz'),
  });

  expect(outcome).toEqual({ status: 'complete' });
  expect(store.rows.map((row) => row.status)).toEqual(['complete']);
  expect(await thirdPartyHostsDefault()).toBe(false);
});
