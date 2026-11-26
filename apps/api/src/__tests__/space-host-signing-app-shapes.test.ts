// Two sign-ins observed from apps that are not first-party: the account app (a space `list`) and a TinyChat preview
// (one space `info`). Neither names a host ability, so the guard signs them with a complete bootstrap row and without one.

import { describe, expect, mock, test } from 'bun:test';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mayProvision, originProvisionAuthority } from '../services/provision-authority';
import { refusesThirdPartySpaceHost } from '../services/space-host-signing';
import type { PrismaLike } from '../services/tinycloud-bootstrap';
import { spaceHostRequest } from '../services/tinycloud-siwe';
import { accountAppMessage, tinyChatPreviewMessage } from './space-recap-shapes';

const owner = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const key = { id: 'key_1', address: owner };
const ACCOUNT_APP = 'https://account.tinycloud.xyz';
const TINYCHAT_PREVIEW = 'https://0a31bc70.tinychat.pages.dev';

type Row = { status: string } | null;
const refuses = (message: string, origin: string, row: Row) => refusesThirdPartySpaceHost({
  prisma: { tinyCloudBootstrapState: { findUnique: mock(async () => row) } } as unknown as PrismaLike,
  message, key, authorities: [originProvisionAuthority(origin)],
});

const spaceActions = (message: string) => (parseRecapFromSiwe(message) as Array<{ actions: string[] }>)
  .flatMap((entry) => entry.actions).filter((action) => action.startsWith('tinycloud.space/'));

describe('the recap of each message', () => {
  test('asks for a space list in the account app and a space info in TinyChat, and for no host', () => {
    expect(spaceActions(accountAppMessage(owner))).toEqual(['tinycloud.space/list']);
    expect(spaceActions(tinyChatPreviewMessage(owner, '0a31bc70.tinychat.pages.dev'))).toEqual(['tinycloud.space/info']);
  });
});

describe('the account app, a third-party origin', () => {
  test('is not first-party', () => {
    expect(mayProvision(originProvisionAuthority(ACCOUNT_APP))).toBe(false);
  });

  test('a list-only sign-in names no host target', () => {
    expect(spaceHostRequest(accountAppMessage(owner))).toEqual({ kind: 'none' });
  });

  test('is signed with a complete row', async () => {
    expect(await refuses(accountAppMessage(owner), ACCOUNT_APP, { status: 'complete' })).toBe(false);
  });

  test('is signed with no row, because a list needs none', async () => {
    expect(await refuses(accountAppMessage(owner), ACCOUNT_APP, null)).toBe(false);
  });
});

describe('a TinyChat preview, a third-party origin', () => {
  test('is not first-party', () => {
    expect(mayProvision(originProvisionAuthority(TINYCHAT_PREVIEW))).toBe(false);
  });

  test('a sign-in with one space info ability names no host target', () => {
    expect(spaceHostRequest(tinyChatPreviewMessage(owner, '0a31bc70.tinychat.pages.dev'))).toEqual({ kind: 'none' });
  });

  test('is signed with a complete row', async () => {
    expect(await refuses(tinyChatPreviewMessage(owner, '0a31bc70.tinychat.pages.dev'), TINYCHAT_PREVIEW, { status: 'complete' })).toBe(false);
  });

  test('is signed with no row, because an info needs none', async () => {
    expect(await refuses(tinyChatPreviewMessage(owner, '0a31bc70.tinychat.pages.dev'), TINYCHAT_PREVIEW, null)).toBe(false);
  });
});
