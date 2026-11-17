// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { CLI_REQUESTER, REGISTERED_CALLBACK_ENDPOINTS, checkDelegateCallback, delegateRequester } from './delegate-link-policy';

describe('delegateRequester', () => {
  test('names each registered assistant from its exact return address', () => {
    const cases: Array<[string, string, string]> = [
      ['https://mcp.tinycloud.xyz/claude/connect/callback?state=t.n.sig', 'Claude via TinyCloud', 'Claude'],
      ['https://mcp.tinycloud.xyz/grok/connect/callback?state=t.n.sig', 'Grok via TinyCloud', 'Grok'],
      ['https://mcp.tinycloud.xyz/muse/connect/callback?state=t.n.sig', 'Muse via TinyCloud', 'Muse'],
      ['https://mcp.tinycloud.xyz/chatgpt/connect/callback?state=t.n.sig', 'ChatGPT via TinyCloud', 'ChatGPT'],
      ['https://mcp.tinycloud.xyz/connect/callback?state=t.n.sig', 'TinyCloud MCP', 'your MCP client'],
    ];
    for (const [callback, displayName, returnTo] of cases) {
      expect(delegateRequester(callback)).toEqual({ displayName, returnTo });
    }
  });

  test('every built-in registered callback has a name, so none falls back to CLI wording', () => {
    for (const endpoint of REGISTERED_CALLBACK_ENDPOINTS) {
      expect(delegateRequester(`${endpoint}?state=x`)).not.toEqual(CLI_REQUESTER);
    }
  });

  test('loopback callbacks, no callback, and unmapped addresses keep the CLI wording', () => {
    for (const callback of [
      null,
      '',
      'http://127.0.0.1:53124/callback',
      'http://localhost:8787/callback',
      'http://[::1]:9000/callback',
      // A look-alike of a mapped endpoint must not borrow its name.
      'https://mcp.tinycloud.xyz/claude/connect/callback/extra',
      'https://mcp.tinycloud.xyz/gemini/connect/callback',
      'https://mcp.tinycloud.xyz.evil.example/claude/connect/callback',
      'https://mcp.tinycloud.xyz@evil.example/claude/connect/callback',
      // Credentials in the URL: the endpoint matches, but no name.
      'https://user:pw@mcp.tinycloud.xyz/claude/connect/callback',
      'https://user@mcp.tinycloud.xyz/claude/connect/callback',
      'http://mcp.tinycloud.xyz/claude/connect/callback',
      'https://evil.example/claude/connect/callback',
      // Object prototype keys are not endpoints.
      'https://mcp.tinycloud.xyz/__proto__',
      'not a url',
    ]) {
      expect(delegateRequester(callback)).toEqual(CLI_REQUESTER);
    }
    expect(CLI_REQUESTER).toEqual({ displayName: 'TinyCloud CLI', returnTo: 'the CLI' });
  });

  test('a name comes only from the path, never from other link parameters', () => {
    const callback = 'https://mcp.tinycloud.xyz/connect/callback?name=Claude&client=Grok&state=/claude/connect/callback';
    expect(checkDelegateCallback(callback, REGISTERED_CALLBACK_ENDPOINTS).ok).toBe(true);
    expect(delegateRequester(callback).displayName).toBe('TinyCloud MCP');
  });
});
