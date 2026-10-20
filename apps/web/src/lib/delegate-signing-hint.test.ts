// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { DELEGATE_SIGNING_HINT } from './delegate-signing-hint';

describe('DELEGATE_SIGNING_HINT', () => {
  test('gives the browser prompt how-to and says where the fallback code appears', () => {
    expect(DELEGATE_SIGNING_HINT).toBe(
      "Your browser may ask to connect to devices on your network: choose Allow to finish in your terminal. If it doesn't finish, a code will appear here to enter in your terminal.",
    );
  });
});
