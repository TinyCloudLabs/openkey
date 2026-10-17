import { describe, expect, test } from 'bun:test';
import {
  buildNotes,
  extractChangelogSection,
  isLatestCandidate,
  isPrerelease,
  parseTag,
  pickLatestTag,
} from './github-releases.mjs';

const CHANGELOG = `# @openkey/sdk

## 0.12.1-beta.1

### Patch Changes

- 3102674: Keep the embedded Sign review measurable.

## 0.12.0

### Patch Changes

- f31b6b4: Sign-out no longer hangs.
  - nested detail

## 0.1.0
`;

describe('parseTag', () => {
  test('splits scoped package name and version', () => {
    expect(parseTag('@openkey/sdk-react-native@0.12.0-beta.2')).toMatchObject({
      name: '@openkey/sdk-react-native',
      version: '0.12.0-beta.2',
      prerelease: true,
    });
  });

  test('rejects legacy and foreign tags', () => {
    expect(parseTag('sdk-v0.0.1')).toBeNull();
    expect(parseTag('v3.2.5')).toBeNull();
    expect(parseTag('@other/sdk@1.0.0')).toBeNull();
  });
});

describe('isPrerelease', () => {
  test('any version suffix is a prerelease', () => {
    expect(isPrerelease('0.12.1-beta.1')).toBe(true);
    expect(isPrerelease('0.12.0')).toBe(false);
  });
});

describe('latest selection', () => {
  test('only stable sdk is a candidate', () => {
    expect(isLatestCandidate('@openkey/sdk@0.12.0')).toBe(true);
    expect(isLatestCandidate('@openkey/sdk@0.12.1-beta.1')).toBe(false);
    expect(isLatestCandidate('@openkey/core@0.12.0')).toBe(false);
    expect(isLatestCandidate('@openkey/sdk-react-native@0.12.0')).toBe(false);
  });

  test('picks the highest stable sdk numerically, ignoring betas and other packages', () => {
    expect(
      pickLatestTag([
        '@openkey/sdk@0.9.0',
        '@openkey/sdk@0.10.2',
        '@openkey/sdk@0.12.1-beta.1',
        '@openkey/core@0.99.0',
      ]),
    ).toBe('@openkey/sdk@0.10.2');
    expect(pickLatestTag(['@openkey/sdk@0.12.1-beta.1', '@openkey/cli@0.1.5'])).toBeNull();
  });
});

describe('extractChangelogSection', () => {
  test('returns only the requested version, including nested lists', () => {
    const section = extractChangelogSection(CHANGELOG, '0.12.0');
    expect(section).toContain('f31b6b4');
    expect(section).toContain('nested detail');
    expect(section).not.toContain('3102674');
  });

  test('does not match a version by prefix', () => {
    expect(extractChangelogSection(CHANGELOG, '0.12')).toBeNull();
    expect(extractChangelogSection(CHANGELOG, '0.12.1-beta')).toBeNull();
  });

  test('null for a missing or empty section', () => {
    expect(extractChangelogSection(CHANGELOG, '9.9.9')).toBeNull();
    expect(extractChangelogSection(CHANGELOG, '0.1.0')).toBeNull();
  });
});

describe('buildNotes', () => {
  test('falls back to an explicit note when the changelog has no entry', () => {
    expect(buildNotes({ name: '@openkey/db', version: '0.0.1', section: null })).toContain(
      'No changelog entry was recorded for @openkey/db 0.0.1.',
    );
  });
});
