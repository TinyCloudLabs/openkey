import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'bun:test';

import {
  bindWellKnownManifestBytes,
  canonicalManifestSha256Hex,
  resolveOwnerPlaceholders,
} from '../services/manifest-origin-fetch';

type Permission = {
  service: string;
  space?: string;
  path: string;
  actions: string[];
  skipPrefix?: boolean;
};

const vector = JSON.parse(
  readFileSync(new URL('./fixtures/manifest-owner-placeholder-vector.json', import.meta.url), 'utf8'),
) as {
  owner: string;
  template: Record<string, unknown>;
  resolvedPermissions: Permission[];
  templateCanonicalSha256: string;
  refusals: Record<string, { manifest: Record<string, unknown>; canonicalSha256: string }>;
};

const bytesOf = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const otherOwner = 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001';

// The extraction keeps service, space, path and actions; skipPrefix is not extracted.
const extractionShape = (permissions: Permission[]) =>
  permissions.map(({ service, space, path, actions }) => ({ service, space, path, actions }));

function withDescription(description: string) {
  const manifest = {
    manifest_version: 1,
    app_id: 'xyz.tinycloud.example.plain',
    name: 'Plain App',
    description,
    permissions: [{ service: 'tinycloud.kv', space: 'applications', path: '/', actions: ['tinycloud.kv/get'] }],
  };
  return { manifest, digest: canonicalManifestSha256Hex(manifest) };
}

describe('owner placeholder in a published manifest', () => {
  it('hashes the template as published', () => {
    expect(canonicalManifestSha256Hex(vector.template)).toBe(vector.templateCanonicalSha256);
  });

  it('resolves {owner} with the derived owner and keeps the template digest', () => {
    const result = bindWellKnownManifestBytes(
      bytesOf(vector.template),
      vector.templateCanonicalSha256,
      vector.owner,
    );
    expect(result.ok).toBe(true);
    expect(result.fetchedDigest).toBe(vector.templateCanonicalSha256);
    expect(result.manifest?.declaredPermissions).toEqual(extractionShape(vector.resolvedPermissions));
  });

  it('refuses each vector refusal manifest', () => {
    for (const [name, refusal] of Object.entries(vector.refusals)) {
      expect(canonicalManifestSha256Hex(refusal.manifest)).toBe(refusal.canonicalSha256);
      const result = bindWellKnownManifestBytes(bytesOf(refusal.manifest), refusal.canonicalSha256, vector.owner);
      expect({ name, ok: result.ok }).toEqual({ name, ok: false });
      expect(result.manifest).toBeUndefined();
    }
  });

  it('accepts a matching owner hint and refuses a different one', () => {
    const bytes = bytesOf(vector.template);
    expect(
      bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, vector.owner, vector.owner).ok,
    ).toBe(true);
    expect(
      bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, vector.owner, otherOwner).ok,
    ).toBe(false);
  });

  it('ignores an empty owner hint', () => {
    expect(
      bindWellKnownManifestBytes(bytesOf(vector.template), vector.templateCanonicalSha256, vector.owner, '').ok,
    ).toBe(true);
  });

  it('refuses a template when no owner was derived', () => {
    const bytes = bytesOf(vector.template);
    expect(bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256).ok).toBe(false);
    expect(bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, undefined, vector.owner).ok).toBe(false);
    expect(bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, '').ok).toBe(false);
  });

  it('resolves a different owner to different paths under the same digest', () => {
    const bytes = bytesOf(vector.template);
    const first = bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, vector.owner);
    const second = bindWellKnownManifestBytes(bytes, vector.templateCanonicalSha256, otherOwner);
    expect(second.ok).toBe(true);
    expect(second.fetchedDigest).toBe(first.fetchedDigest);
    expect(second.manifest?.declaredPermissions).not.toEqual(first.manifest?.declaredPermissions);
    expect(second.manifest?.declaredPermissions?.[1]?.path).toBe(`urn:tinycloud:encryption:${otherOwner}:default`);
    expect(second.manifest?.declaredPermissions?.[2]?.path).toBe(
      `urn:tinycloud:encryption:${otherOwner}:default/share/`,
    );
  });

  it('does not change the parsed template or the rest of the manifest', () => {
    const template = structuredClone(vector.template);
    const resolved = resolveOwnerPlaceholders(template, vector.owner);
    expect(template).toEqual(vector.template);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) {
      expect({ ...resolved.manifest, permissions: undefined }).toEqual({ ...vector.template, permissions: undefined });
      expect(resolved.manifest.permissions).toEqual(vector.resolvedPermissions);
    }
  });

  it('returns exactly the same result for a manifest without a placeholder', () => {
    const { manifest, digest } = withDescription('Plain {text} with braces');
    const bytes = bytesOf(manifest);
    const withOwner = bindWellKnownManifestBytes(bytes, digest, vector.owner, vector.owner);
    const withoutOwner = bindWellKnownManifestBytes(bytes, digest);
    expect(withOwner.ok).toBe(true);
    expect(withOwner).toEqual(withoutOwner);
    expect(withOwner.manifest?.declaredPermissions).toEqual(
      extractionShape(manifest.permissions as Permission[]),
    );
    const parsed = JSON.parse(JSON.stringify(manifest)) as Record<string, unknown>;
    const resolved = resolveOwnerPlaceholders(parsed, vector.owner);
    expect(resolved.ok && resolved.manifest === parsed).toBe(true);
  });

  it('refuses {owner} in a description', () => {
    const { manifest, digest } = withDescription('Belongs to {owner}');
    expect(bindWellKnownManifestBytes(bytesOf(manifest), digest, vector.owner).ok).toBe(false);
  });

  it('leaves another brace token in a description untouched', () => {
    const { manifest, digest } = withDescription('Uses {x} somewhere');
    const result = bindWellKnownManifestBytes(bytesOf(manifest), digest, vector.owner);
    expect(result.ok).toBe(true);
    expect(result.manifest?.declaredPermissions).toEqual(extractionShape(manifest.permissions as Permission[]));
  });

  it('is case-sensitive about the token', () => {
    const manifest = {
      app_id: 'xyz.tinycloud.example.plain',
      permissions: [
        { service: 'tinycloud.encryption', path: 'urn:tinycloud:encryption:{Owner}:default', actions: ['tinycloud.encryption/decrypt'] },
      ],
    };
    expect(bindWellKnownManifestBytes(bytesOf(manifest), canonicalManifestSha256Hex(manifest), vector.owner).ok).toBe(false);
  });

  it('replaces every occurrence in a path', () => {
    const manifest = {
      app_id: 'xyz.tinycloud.example.plain',
      permissions: [
        { service: 'tinycloud.encryption', path: '{owner}/a/{owner}', actions: ['tinycloud.encryption/decrypt'] },
      ],
    };
    const result = bindWellKnownManifestBytes(bytesOf(manifest), canonicalManifestSha256Hex(manifest), vector.owner);
    expect(result.manifest?.declaredPermissions?.[0]?.path).toBe(`${vector.owner}/a/${vector.owner}`);
  });

  it('refuses {owner} in other permission fields, nested values and array elements', () => {
    const base = (extra: Record<string, unknown>, permission: Record<string, unknown> = {}) => ({
      app_id: 'xyz.tinycloud.example.plain',
      ...extra,
      permissions: [
        { service: 'tinycloud.kv', path: '/', actions: ['tinycloud.kv/get'], ...permission },
        { service: 'tinycloud.encryption', path: 'urn:{owner}', actions: ['tinycloud.encryption/decrypt'] },
      ],
    });
    const cases: Record<string, unknown>[] = [
      base({ name: '{owner}' }),
      base({ keys: { nested: [{ deep: 'x {owner}' }] } }),
      base({ keys: { '{owner}': true } }),
      base({}, { service: '{owner}' }),
      base({}, { space: '{owner}' }),
      base({}, { actions: ['{owner}'] }),
      base({}, { '{owner}': 1 }),
      { ...base({}), permissions: [...(base({}).permissions), '{owner}'] },
      { ...base({}), permissions: [...(base({}).permissions), ['{owner}']] },
    ];
    for (const manifest of cases) {
      const result = bindWellKnownManifestBytes(bytesOf(manifest), canonicalManifestSha256Hex(manifest), vector.owner);
      expect({ manifest, ok: result.ok }).toEqual({ manifest, ok: false });
    }
  });

  it('refuses another placeholder token in a permission path', () => {
    const manifest = {
      app_id: 'xyz.tinycloud.example.plain',
      permissions: [{ service: 'tinycloud.kv', path: '/{user}/', actions: ['tinycloud.kv/get'] }],
    };
    const result = bindWellKnownManifestBytes(bytesOf(manifest), canonicalManifestSha256Hex(manifest), vector.owner);
    expect(result.ok).toBe(false);
  });

  it('still fails on a digest mismatch before resolving anything', () => {
    const result = bindWellKnownManifestBytes(bytesOf(vector.template), '0'.repeat(64), vector.owner);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('digest');
  });
});
