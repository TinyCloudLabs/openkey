// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  KNOWN_NODE_ORIGINS,
  REGISTERED_CALLBACK_ORIGINS,
  checkDelegateCallback,
  checkDelegateHost,
  withConfiguredOrigins,
} from './delegate-link-policy';

const accepted = (raw: string) => checkDelegateCallback(raw, REGISTERED_CALLBACK_ORIGINS);

describe('checkDelegateCallback', () => {
  test('accepts the first-party callbacks: CLI loopback servers and the hosted MCP', () => {
    for (const callback of [
      'http://127.0.0.1:53124/callback',
      'http://localhost:8787/callback',
      'http://[::1]:9000/callback',
      'https://mcp.tinycloud.xyz/connect/callback?state=t.n.sig',
    ]) {
      expect(accepted(callback)).toEqual({ ok: true, callback: new URL(callback).href });
    }
  });

  test('without a callback the page falls back to a paste code', () => {
    expect(accepted('')).toEqual({ ok: true, callback: null });
  });

  test('refuses an unregistered origin and look-alikes of allowed ones', () => {
    for (const callback of [
      'https://evil.example/collect',
      'https://mcp.tinycloud.xyz.evil.example/connect/callback',
      'https://mcp.tinycloud.xyz@evil.example/connect/callback',
      'http://127.0.0.1.evil.example/callback',
      'http://mcp.tinycloud.xyz/connect/callback',
      'https://user:pass@127.0.0.1/callback',
      'javascript:alert(1)',
      'not a url',
    ]) {
      const result = accepted(callback);
      expect(result.ok).toBe(false);
    }
    const refused = accepted('https://evil.example/collect');
    expect(refused.ok === false && refused.reason).toContain('https://evil.example');
  });

  test('a configured registration admits that app origin only', () => {
    const registered = withConfiguredOrigins(REGISTERED_CALLBACK_ORIGINS, 'https://mcp.staging.example, http://plain.example, https://x.example/path,');
    expect(registered).toEqual(['https://mcp.tinycloud.xyz', 'https://mcp.staging.example']);
    expect(checkDelegateCallback('https://mcp.staging.example/connect/callback', registered).ok).toBe(true);
    expect(checkDelegateCallback('https://other.staging.example/cb', registered).ok).toBe(false);
  });
});

describe('checkDelegateHost', () => {
  const check = (raw: string) => checkDelegateHost(raw, KNOWN_NODE_ORIGINS);

  test('recognizes the TinyCloud node and nodes on this device', () => {
    for (const host of ['https://node.tinycloud.xyz', 'http://localhost:8000', 'http://127.0.0.1:8000']) {
      expect(check(host)).toEqual({ ok: true, host, recognized: true });
    }
  });

  test('flags any other HTTPS node, including look-alikes and paths', () => {
    for (const host of ['https://evil.example', 'https://node.tinycloud.xyz.evil.example', 'https://node.tinycloud.xyz/proxy']) {
      expect(check(host)).toEqual({ ok: true, host, recognized: false });
    }
  });

  test('refuses plaintext remote nodes, credentials, and non-URLs', () => {
    for (const host of ['http://evil.example', 'https://u:p@node.tinycloud.xyz', 'ftp://node.tinycloud.xyz', 'node.tinycloud.xyz']) {
      expect(check(host).ok).toBe(false);
    }
  });
});
