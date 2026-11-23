import { expect, test } from 'bun:test';
import { AppKeyFetchLimit } from '../services/app-key-fetch-limit';

test('limits concurrent fetches per account and releases the slot when the fetch finishes', () => {
  const limit = new AppKeyFetchLimit();
  const first = limit.acquire('alice', 0);
  expect(first).toBeFunction();
  expect(limit.acquire('alice', 0)).toBeFunction();
  expect(limit.acquire('alice', 60_000)).toBe('account');
  expect(limit.acquire('bob', 0)).toBeFunction();
  if (typeof first === 'function') first();
  expect(limit.acquire('alice', 60_000)).toBeFunction();
});

test('limits attempts per account within a fixed window', () => {
  const limit = new AppKeyFetchLimit();
  for (let attempt = 0; attempt < 20; attempt++) {
    const release = limit.acquire('alice', 0);
    expect(release).toBeFunction();
    if (typeof release === 'function') release();
  }
  expect(limit.acquire('alice', 59_999)).toBe('account');
  expect(limit.acquire('bob', 59_999)).toBeFunction();
  expect(limit.acquire('alice', 60_000)).toBeFunction();
});

test('bounds total concurrent fetches across accounts', () => {
  const limit = new AppKeyFetchLimit();
  const releases = Array.from({ length: 32 }, (_, index) => limit.acquire(String(index), 0));
  expect(releases.every(release => typeof release === 'function')).toBe(true);
  expect(limit.acquire('another account', 0)).toBe('process');
  const release = releases[0];
  if (typeof release === 'function') release();
  expect(limit.acquire('another account', 0)).toBeFunction();
});
