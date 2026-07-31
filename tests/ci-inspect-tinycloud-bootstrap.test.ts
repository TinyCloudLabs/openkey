import { describe, expect, test } from 'bun:test';
import { sanitizeFailureReason } from '../scripts/ci-inspect-tinycloud-bootstrap';

describe('sanitizeFailureReason', () => {
  test('removes signing identifiers while retaining the operation failure', () => {
    expect(sanitizeFailureReason(
      'invoke failed for did:pkh:eip155:1:0x0123456789012345678901234567890123456789 '
      + 'with Authorization:Bearer_secret: HTTP 503',
    )).toBe('invoke failed for [did] with [authorization] HTTP 503');
  });

  test('handles empty and bounded output', () => {
    expect(sanitizeFailureReason(null)).toBeNull();
    expect(sanitizeFailureReason('x'.repeat(2_000))).toHaveLength(1_000);
  });
});
