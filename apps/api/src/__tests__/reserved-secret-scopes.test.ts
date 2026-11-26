import { describe, expect, test } from 'bun:test';
import {
  BOT_HISTORY_KEY_PATH,
  BOT_HISTORY_SCOPE,
  canonicalSecretScope,
  isReservedSecretKey,
} from '../services/reserved-secret-scopes';

// The literals are copied from `@tinycloud/sdk-services` 3.14.0-beta.17 (`BOT_HISTORY_SCOPE`, `BOT_HISTORY_KEY_PATH`).
describe('the bot-history scope and key, as the SDK defines them', () => {
  test('are the SDK strings', () => {
    expect(BOT_HISTORY_SCOPE).toBe('tinychat-bot-history');
    expect(BOT_HISTORY_KEY_PATH).toBe('secrets/scoped/tinychat-bot-history/bot-history');
  });
});

describe('the canonical form of a scope', () => {
  test.each([
    ['tinychat-bot-history', 'tinychat-bot-history'],
    ['Tinychat-Bot-History', 'tinychat-bot-history'],
    ['  TINYCHAT_BOT HISTORY  ', 'tinychat-bot-history'],
    ['--tinychat--bot..history--', 'tinychat-bot-history'],
    ['Tinychat Bot History!', 'tinychat-bot-history'],
    ['tinychat-bot-history-copy', 'tinychat-bot-history-copy'],
    ['***', ''],
  ])('%j becomes %j', (scope, canonical) => {
    expect(canonicalSecretScope(scope)).toBe(canonical);
  });
});

describe('a reserved secret key', () => {
  test.each([
    BOT_HISTORY_KEY_PATH,
    'secrets/scoped/tinychat-bot-history',
    'secrets/scoped/tinychat-bot-history/item-1',
    'secrets/scoped/Tinychat-Bot-History/bot-history',
    'secrets/scoped/TINYCHAT_BOT HISTORY/bot-history',
    'secrets/scoped/ tinychat-bot-history /bot-history',
    'secrets/Scoped/tinychat-bot-history/bot-history',
  ])('is %j', (key) => {
    expect(isReservedSecretKey(key)).toBe(true);
  });

  test.each([
    'secrets/ANTHROPIC_API_KEY',
    'secrets/scoped',
    'secrets/scoped/tinychat-bot-history-copy/bot-history',
    'secrets/scoped/tinychat/bot-history',
    'secrets/scoped/other/tinychat-bot-history',
    'secrets/tinychat-bot-history',
    'variables/scoped/tinychat-bot-history/bot-history',
  ])('is not %j', (key) => {
    expect(isReservedSecretKey(key)).toBe(false);
  });
});
