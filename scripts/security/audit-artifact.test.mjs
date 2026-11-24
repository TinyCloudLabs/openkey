import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { auditDirectory } from './audit-artifact.mjs';

function artifact(files) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-artifact-test-'));
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return dir;
}
// Built at run time so this file holds no secret-shaped literal.
const hex = (n) => 'ab'.repeat(n / 2);
const word = (n) => 'Ab1'.repeat(Math.ceil(n / 3)).slice(0, n);

test('a clean Pages build passes', () => {
  const dir = artifact({ '_headers': '/*\n  X-Frame-Options: DENY\n', '_app/a.js': 'export const a = "localhost";', 'index.html': '<p>hi</p>' });
  try {
    assert.deepEqual(auditDirectory(dir).problems, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('each forbidden shape is reported by file and label, never by value', () => {
  const secrets = {
    stripe: `sk_live_${word(24)}`,
    pem: '-----BEGIN EC PRIVATE KEY-----',
    hex: `0x${hex(64)}`,
    slack: `xoxb-${word(20)}`,
    jwt: `eyJ${word(16)}.eyJ${word(16)}.sig`,
    aws: `AKIA${'A'.repeat(16)}`,
    github: `ghp_${word(36)}`,
    pat: `github_pat_${word(30)}`,
    npm: `npm_${word(36)}`,
  };
  const dir = artifact({
    '_app/bundle.js': `${Object.values(secrets).join('\n')}\n//# sourceMappingURL=bundle.js.map\nfetch("http://localhost:5173/x");"/home/bob/x"`,
    '_app/bundle.js.map': '{}',
    '.env': 'X=1',
    'notes.md': '# notes',
  });
  try {
    const { problems } = auditDirectory(dir);
    const text = problems.join('\n');
    for (const label of ['Stripe', 'PEM', '32-byte hex', 'Slack', 'JWT', 'AWS', 'GitHub token', 'fine-grained', 'npm token', 'sourceMappingURL', 'sourcemap file', 'loopback URL', 'home directory', '.env: dotfile', 'notes.md: file type']) {
      assert.match(text, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), label);
    }
    for (const value of Object.values(secrets)) assert.ok(!text.includes(value), 'a report must not echo the value');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
