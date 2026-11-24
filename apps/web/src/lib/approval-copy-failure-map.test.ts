// Keeps the shared reason map in step with the codes the delegate pages already turn into text.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STOPS, stopForReply } from '../../../../packages/sdk/src/approval-copy/index';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, 'delegate-failure-text.ts'), 'utf8');
const table = source.slice(source.indexOf('const CODE_MESSAGES'));
const codes = [...table.slice(0, table.indexOf('\n};')).matchAll(/^ {2}([a-z0-9_]+):/gm)].map((match) => match[1]!);

describe('the shared reason map', () => {
  test('finds the codes the delegate pages map today', () => {
    expect(codes.length).toBeGreaterThan(10);
    expect(codes).toContain('session_required');
  });

  test.each(codes)('maps the %s code to a reason of its own', (code: string) => {
    const { id } = stopForReply({ status: 400, code });
    expect(id).not.toBe('S26');
    expect(STOPS[id]).toBeDefined();
  });

  test('an unknown code is the unexpected reply reason', () => {
    expect(stopForReply({ status: 400, code: 'something_new' }).id).toBe('S26');
  });
});
