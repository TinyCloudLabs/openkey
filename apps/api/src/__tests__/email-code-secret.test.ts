import { afterEach, expect, test } from 'bun:test';
import { signInCodeStorage, stepUpCodeDigest } from '../services/email-code-storage';

const saved = { secret: process.env.BETTER_AUTH_SECRET, nodeEnv: process.env.NODE_ENV };

afterEach(() => {
  if (saved.secret === undefined) delete process.env.BETTER_AUTH_SECRET;
  else process.env.BETTER_AUTH_SECRET = saved.secret;
  process.env.NODE_ENV = saved.nodeEnv;
});

test.each(['development', 'production', 'staging'])('without BETTER_AUTH_SECRET, %s stores no email code', async (nodeEnv) => {
  delete process.env.BETTER_AUTH_SECRET;
  process.env.NODE_ENV = nodeEnv;
  await expect((async () => signInCodeStorage.hash('123456'))()).rejects.toThrow('BETTER_AUTH_SECRET is required');
  expect(() => stepUpCodeDigest('identifier', '123456')).toThrow('BETTER_AUTH_SECRET is required');
});
