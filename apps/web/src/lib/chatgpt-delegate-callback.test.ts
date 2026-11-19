// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { REGISTERED_CALLBACK_ENDPOINTS, checkDelegateCallback } from './delegate-link-policy';

describe('ChatGPT delegation callback registration', () => {
  test.each([
    'https://mcp.tinycloud.xyz/chatgpt/connect/callback',
    'https://mcp.tinycloud.xyz/chatgpt/connect/callback?state=t.n.sig',
  ])('accepts the registered endpoint and preserves its query: %s', (callback) => {
    expect(checkDelegateCallback(callback, REGISTERED_CALLBACK_ENDPOINTS)).toEqual({ ok: true, callback });
  });

  test.each([
    'https://mcp.tinycloud.xyz/chatgpt/connect/callback/x',
    'https://mcp.tinycloud.xyz/chatgpt/connect/callback/',
    'http://mcp.tinycloud.xyz/chatgpt/connect/callback',
    'https://mcp.tinycloud.xyz.evil.test/chatgpt/connect/callback',
    'https://evil.test/https://mcp.tinycloud.xyz/chatgpt/connect/callback',
    'https://mcp.tinycloud.xyz/chatgpt/connect',
    'https://mcp.tinycloud.xyz/ChatGPT/connect/callback',
    'https://mcp.tinycloud.xyz/chatgpt%2Fconnect/callback',
    'https://mcp.tinycloud.xyz:8443/chatgpt/connect/callback',
    'https://user@mcp.tinycloud.xyz/chatgpt/connect/callback',
  ])('refuses a different endpoint: %s', (callback) => {
    expect(checkDelegateCallback(callback, REGISTERED_CALLBACK_ENDPOINTS).ok).toBe(false);
  });
});
