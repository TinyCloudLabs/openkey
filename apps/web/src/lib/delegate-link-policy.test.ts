// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  KNOWN_NODE_ORIGINS,
  REGISTERED_CALLBACK_ENDPOINTS,
  checkDelegateCallback,
  checkDelegateHost,
  checkDelegateRequesterOrigin,
  isCanonicalHttpsEndpoint,
  isCanonicalHttpsOrigin,
  withConfiguredEntries,
} from './delegate-link-policy';

const accepted = (raw: string) => checkDelegateCallback(raw, REGISTERED_CALLBACK_ENDPOINTS);

describe('checkDelegateCallback', () => {
  test('accepts the first-party callbacks: CLI loopback servers and the hosted MCP', () => {
    for (const callback of [
      'http://127.0.0.1:53124/callback',
      'http://localhost:8787/callback',
      'http://[::1]:9000/callback',
      'https://mcp.tinycloud.xyz/connect/callback?state=t.n.sig',
      'https://mcp.tinycloud.xyz/chatgpt/connect/callback?state=t.n.sig',
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
      // The registered MCP origin, but not its callback endpoint.
      'https://mcp.tinycloud.xyz/collect',
      'https://mcp.tinycloud.xyz/connect/callback/extra',
      'https://mcp.tinycloud.xyz/chatgpt/connect/callback/extra',
      'https://mcp.tinycloud.xyz/chatgpt/connect/other',
      'https://mcp.tinycloud.xyz/',
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

  test('a configured registration admits that exact endpoint only', () => {
    const registered = withConfiguredEntries(
      REGISTERED_CALLBACK_ENDPOINTS,
      'https://mcp.staging.example/connect/callback, https://origin-only.example, http://plain.example/cb, https://q.example/cb?x=1,',
      isCanonicalHttpsEndpoint,
    );
    expect(checkDelegateCallback('https://mcp.staging.example/connect/callback?state=s', registered).ok).toBe(true);
    expect(checkDelegateCallback('https://mcp.staging.example/other', registered).ok).toBe(false);
  });

  test('configured node origins must be canonical HTTPS origins', () => {
    expect(withConfiguredEntries(KNOWN_NODE_ORIGINS, 'https://node.example, https://node.example/, http://plain.example', isCanonicalHttpsOrigin))
      .toEqual([...KNOWN_NODE_ORIGINS, 'https://node.example']);
  });
});

describe('checkDelegateHost', () => {
  const check = (raw: string) => checkDelegateHost(raw, KNOWN_NODE_ORIGINS);

  test('recognizes the nodes OpenKey trusts, including the CLI and MCP default TEE node, and nodes on this device', () => {
    for (const host of ['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz', 'http://localhost:8000', 'http://127.0.0.1:8000']) {
      expect(check(host)).toEqual({ ok: true, host, recognized: true });
    }
  });

  test('flags any other HTTPS node, including look-alikes and paths', () => {
    for (const host of ['https://evil.example', 'https://node.tinycloud.xyz.evil.example', 'https://evil.tee.node.tinycloud.xyz', 'https://node.tinycloud.xyz/proxy']) {
      expect(check(host)).toEqual({ ok: true, host, recognized: false });
    }
  });

  test('refuses plaintext remote nodes, credentials, and non-URLs', () => {
    for (const host of ['http://evil.example', 'https://u:p@node.tinycloud.xyz', 'ftp://node.tinycloud.xyz', 'node.tinycloud.xyz']) {
      expect(check(host).ok).toBe(false);
    }
  });
});

describe('checkDelegateRequesterOrigin', () => {
  test('accepts an omitted CLI origin and canonical hosted or loopback origins', () => {
    expect(checkDelegateRequesterOrigin(new URLSearchParams(), false)).toEqual({ ok: true });
    for (const origin of [
      'https://mcp.tinycloud.xyz', 'https://custom.example:8443',
      'http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787',
    ]) {
      expect(checkDelegateRequesterOrigin(new URLSearchParams({ requesterOrigin: origin }), false))
        .toEqual({ ok: true, origin });
    }
  });

  test('refuses ambiguous, noncanonical, or unsafe attribution before preparation', () => {
    for (const origin of [
      '', 'https://MCP.tinycloud.xyz', 'https://mcp.tinycloud.xyz/',
      'https://mcp.tinycloud.xyz/path', 'https://mcp.tinycloud.xyz:443',
      'https://mcp.tinycloud.xyz?state=x', 'https://mcp.tinycloud.xyz#x',
      'https://user@mcp.tinycloud.xyz', ' https://mcp.tinycloud.xyz',
      'https://mcp.tinycloud.xyz\n', 'https://*.tinycloud.xyz',
      'http://mcp.tinycloud.xyz', 'not an origin',
      'http://localhost.evil.example:8787', 'http://127.0.0.1.evil.example:8787',
      'http://sub.localhost:8787', 'http://127.0.0.2:8787',
      'http://127.1:8787', 'http://2130706433:8787', 'http://0x7f000001:8787',
      'http://localhost:80', 'http://localhost:8787/', 'http://user@localhost:8787',
      'http://[0:0:0:0:0:0:0:1]:8787',
    ]) {
      expect(checkDelegateRequesterOrigin(new URLSearchParams({ requesterOrigin: origin }), false).ok).toBe(false);
    }
    const duplicate = new URLSearchParams();
    duplicate.append('requesterOrigin', 'https://mcp.tinycloud.xyz');
    duplicate.append('requesterOrigin', 'https://mcp.tinycloud.xyz');
    expect(checkDelegateRequesterOrigin(duplicate, false).ok).toBe(false);
    duplicate.set('requesterOrigin', 'https://mcp.tinycloud.xyz');
    duplicate.append('requesterOrigin', 'https://other.example');
    expect(checkDelegateRequesterOrigin(duplicate, false).ok).toBe(false);
  });

  test('cannot override a device or signed request or authorize a callback', () => {
    const origin = 'https://custom.example';
    expect(checkDelegateRequesterOrigin(new URLSearchParams({ requesterOrigin: origin }), true).ok).toBe(false);
    expect(checkDelegateRequesterOrigin(new URLSearchParams(), true).ok).toBe(true);
    expect(checkDelegateCallback(`${origin}/callback`, REGISTERED_CALLBACK_ENDPOINTS).ok).toBe(false);
  });
});
