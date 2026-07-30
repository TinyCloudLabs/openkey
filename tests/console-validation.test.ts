import { describe, expect, test } from 'bun:test';
import { validateConsoleApplicationOrigin } from '../apps/web/src/lib/console-validation';

describe('console TinyCloud application origin validation', () => {
  test.each([
    'https://app.example.com',
    'https://app.example.com:8443',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
  ])('accepts an exact secure or loopback origin: %s', (origin) => {
    expect(validateConsoleApplicationOrigin(origin)).toEqual({ valid: true });
  });

  test.each([
    'http://app.example.com',
    'https://app.example.com/path',
    'https://app.example.com?query=1',
    'https://app.example.com/#fragment',
    'https://user@app.example.com',
    'https://*.example.com',
  ])('rejects an unsafe or non-origin URL: %s', (origin) => {
    expect(validateConsoleApplicationOrigin(origin).valid).toBe(false);
  });
});
