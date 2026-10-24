import { describe, expect, spyOn, test } from 'bun:test';
import { logPermissionEntryUnknownFields } from '../log';

const BASE_KEYS = ['event', 'level', 'request_id', 'ts'];

/** Runs `run` and returns the raw stdout chunks it wrote (one log line each). */
function captureRaw(run: () => void): string[] {
  const written: string[] = [];
  const spy = spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(String(chunk));
    return true;
  });
  try {
    run();
  } finally {
    spy.mockRestore();
  }
  return written;
}

function fieldLines(raw: string[]): Array<Record<string, unknown>> {
  return raw
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line.event === 'permission_entry_unknown_field');
}

describe('logPermissionEntryUnknownFields', () => {
  test('logs nothing for an empty map', () => {
    expect(captureRaw(() => logPermissionEntryUnknownFields(new Map()))).toEqual([]);
  });

  test('logs a valid name with its entry count', () => {
    const lines = fieldLines(captureRaw(() => logPermissionEntryUnknownFields(new Map([['skipPrefix', 2]]))));

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({ field: 'skipPrefix', count: 2 });
  });

  test('caps valid names at 8 and reports the overflow count on one other line', () => {
    const counts = new Map(Array.from({ length: 20 }, (_, i) => [`field${i}`, 1] as const));
    const raw = captureRaw(() => logPermissionEntryUnknownFields(counts));
    const lines = fieldLines(raw);

    expect(raw.length).toBeLessThanOrEqual(10);
    expect(lines.map((line) => line.field)).toEqual([...[...counts.keys()].slice(0, 8), 'other']);
    expect(lines.at(-1)).toMatchObject({ field: 'other', count: 12 });
  });

  test('groups all non-conforming names into one [invalid] line counting their entries', () => {
    const counts = new Map<string, number>([
      ['ok', 1],
      ['bad name', 2],
      ['x'.repeat(65), 3],
    ]);
    const raw = captureRaw(() => logPermissionEntryUnknownFields(counts));
    const lines = fieldLines(raw);

    expect(lines.map((line) => [line.field, line.count])).toEqual([
      ['ok', 1],
      ['[invalid]', 5],
    ]);
    expect(raw.join('')).not.toContain('bad name');
    expect(raw.join('')).not.toContain('x'.repeat(65));
  });

  test('each line carries only the name and count fields besides the base log fields', () => {
    const counts = new Map(Array.from({ length: 10 }, (_, i) => [`field${i}`, 1] as const));
    const lines = fieldLines(captureRaw(() => logPermissionEntryUnknownFields(counts)));

    for (const line of lines) {
      expect(Object.keys(line).filter((key) => !BASE_KEYS.includes(key)).sort()).toEqual(['count', 'field']);
    }
  });
});
