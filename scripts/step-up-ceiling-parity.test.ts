import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { compareCeilings, describeParity, flattenCeilings, parsePin, pinUrl, validateCeilingFile } from './step-up-ceiling-parity';

const phase1 = JSON.parse(readFileSync(new URL('./step-up-ceilings/phase1.json', import.meta.url), 'utf8')) as Record<string, Record<string, unknown>>;
const copy = () => structuredClone(phase1) as Record<string, any>;

describe('step-up ceiling parity (TC-3569)', () => {
  test('the phase 1 ceilings are what the API accepts, and match themselves', () => {
    expect(validateCeilingFile(phase1)).toEqual(phase1);
    expect(compareCeilings(phase1, copy())).toEqual({ onlyOpenKey: [], onlyOne: [] });
    expect(flattenCeilings(phase1)).toHaveLength(3 + 2 + 2 + 2 + 2);
  });

  test('how One writes the same entries does not matter, only the entries do', () => {
    const reordered = copy();
    reordered['xyz.tinycloud.explorer'].public.kv.actions.reverse();
    reordered['xyz.tinycloud.account'].account.kv.paths.reverse();
    expect(compareCeilings(phase1, reordered)).toEqual({ onlyOpenKey: [], onlyOne: [] });
  });

  test('an entry only One asks for is reported as One\'s, an entry only OpenKey grants as OpenKey\'s', () => {
    const one = copy();
    one['xyz.tinycloud.courier'].agents.kv.actions.push('metadata');
    delete one['xyz.tinycloud.account'].account.kv.paths;
    one['xyz.tinycloud.account'].account.kv.paths = ['applications/'];
    const parity = compareCeilings(phase1, one);
    expect(describeParity(parity)).toEqual([
      "only in OpenKey's ceilings: xyz.tinycloud.account account kv spaces/ get",
      "only in OpenKey's ceilings: xyz.tinycloud.account account kv spaces/ list",
      "only in One's file: xyz.tinycloud.courier agents kv xyz.tinycloud.courier/ metadata",
    ]);
  });

  test('app ids are compared case-sensitively', () => {
    const one = copy();
    one['xyz.tinycloud.Explorer'] = one['xyz.tinycloud.explorer'];
    delete one['xyz.tinycloud.explorer'];
    const parity = compareCeilings(phase1, one);
    expect(parity.onlyOpenKey.length).toBe(parity.onlyOne.length);
    expect(parity.onlyOpenKey.length).toBe(5);
    expect(parity.onlyOpenKey.every((e) => e.startsWith('xyz.tinycloud.explorer\t'))).toBe(true);
    expect(parity.onlyOne.every((e) => e.startsWith('xyz.tinycloud.Explorer\t'))).toBe(true);
  });

  test('a prefix of a path, a different database and a different space are different entries', () => {
    for (const change of [
      (c: Record<string, any>) => { c['xyz.tinycloud.account'].account.kv.paths = ['applications/', 'spaces'] },
      (c: Record<string, any>) => { c['xyz.tinycloud.explorer'].applications.sql.databases = ['defaults'] },
      (c: Record<string, any>) => { c['xyz.tinycloud.courier'] = { account: c['xyz.tinycloud.courier'].agents } },
    ]) {
      const one = copy();
      change(one);
      const parity = compareCeilings(phase1, one);
      expect(parity.onlyOpenKey.length).toBeGreaterThan(0);
      expect(parity.onlyOne.length).toBeGreaterThan(0);
    }
  });

  test('a file the API would refuse is refused before any comparison (a write action, the secrets space)', () => {
    const write = copy();
    write['xyz.tinycloud.explorer'].public.kv.actions.push('put');
    expect(() => compareCeilings(phase1, write)).toThrow();
    const secrets = copy();
    secrets['xyz.tinycloud.explorer'].secrets = { kv: { paths: ['a/'], actions: ['get'] } };
    expect(() => compareCeilings(phase1, secrets)).toThrow();
  });

  test('the pin is a commit or nothing, never a branch', () => {
    expect(parsePin({ repo: 'TinyCloudLabs/tinychat', path: 'a.json', ref: null }).ref).toBeNull();
    expect(parsePin({ repo: 'TinyCloudLabs/tinychat', path: 'a.json', ref: 'a'.repeat(40) }).ref).toBe('a'.repeat(40));
    for (const ref of ['main', 'a'.repeat(39), 'A'.repeat(40), '']) expect(() => parsePin({ repo: 'TinyCloudLabs/tinychat', path: 'a.json', ref })).toThrow();
  });

  test('the pin names the One repository and a plain file path, and the URL it reads is exactly that file', () => {
    const pin = (over: object) => ({ repo: 'TinyCloudLabs/tinychat', path: 'frontend/src/a.json', ref: 'a'.repeat(40), ...over });
    expect(pinUrl(parsePin(pin({})) as never).href).toBe(`https://raw.githubusercontent.com/TinyCloudLabs/tinychat/${'a'.repeat(40)}/frontend/src/a.json`);
    for (const repo of ['TinyCloudLabs/openkey', 'evil/tinychat', 'TinyCloudLabs/tinychat/x', 'tinycloudlabs/tinychat']) expect(() => parsePin(pin({ repo }))).toThrow();
    for (const path of ['../a.json', '%2e%2e/a.json', 'a/%2E%2E/b.json', 'a/./b.json', '.hidden/a.json', 'a/.b.json', 'a\\b.json', 'a.json?x=1', 'a.json#x', '/a.json', 'a//b.json', 'a/', '']) {
      expect(() => parsePin(pin({ path }))).toThrow();
    }
  });

  test('a URL that does not come out as the plain path is refused', () => {
    // Even a pin that got past parsing (a hand-built object) cannot walk off the pinned commit.
    for (const path of ['%2e%2e/%2e%2e/main/a.json', 'a.json?ref=main', 'a.json#x', '../a.json']) {
      expect(() => pinUrl({ repo: 'TinyCloudLabs/tinychat', path, ref: 'a'.repeat(40) })).toThrow();
    }
  });

  test('the committed pin file is well formed', () => {
    parsePin(JSON.parse(readFileSync(new URL('./step-up-ceilings/one.pin.json', import.meta.url), 'utf8')));
  });
});
