// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  CODE,
  DONE,
  FRAME,
  KNOWN_REPLY_CODES,
  LOADER,
  SIGN_IN,
  STOPS,
  fill,
  safeCode,
  stopForReply,
  stopForSdkError,
  supportLine,
} from './index';
import type { Stop, StopId } from './index';

const stopIds = Object.keys(STOPS) as StopId[];
const numbered = Array.from({ length: 28 }, (_, i) => `S${i + 1}`);
const isStop = (value: unknown): value is Stop => typeof value === 'object' && value !== null && 'title' in value;

describe('fill', () => {
  test('puts values into placeholders', () => {
    expect(fill(SIGN_IN.popupOpen.heading, { provider: 'Google' })).toBe('Finish signing in with Google');
    expect(fill('{a} and {a} and {b}', { a: 1, b: 'x' })).toBe('1 and 1 and x');
  });

  test('leaves a placeholder without a value as written', () => {
    expect(fill('Hello {name}', {} as never)).toBe('Hello {name}');
  });

  test('does not treat a value as a template', () => {
    expect(fill('{a}', { a: '{b}' })).toBe('{b}');
  });
});

describe('STOPS', () => {
  test('S1 to S28 and S32 all exist', () => {
    for (const id of [...numbered, 'S32']) expect(stopIds).toContain(id as StopId);
  });

  test('every reason has a title, a body and a support rule', () => {
    for (const id of numbered) {
      const stop = STOPS[id as StopId] as Stop;
      expect(stop.title.length).toBeGreaterThan(0);
      expect(stop.body.length).toBeGreaterThan(0);
      expect(stop.support).not.toBeNull();
      expect(['page', 'inline', 'sign-in']).toContain(stop.placement);
    }
  });

  test('page stops with a way out offer one', () => {
    for (const id of numbered) {
      const stop = STOPS[id as StopId] as Stop;
      if (stop.placement === 'page') expect(stop.buttons.length).toBeGreaterThan(0);
    }
  });

  test('S22 is the sign-in card heading and line', () => {
    expect(STOPS.S22.title).toBe(SIGN_IN.signedOutPartway.heading);
    expect(STOPS.S22.body).toBe(SIGN_IN.signedOutPartway.line);
    expect(STOPS.S22.placement).toBe('sign-in');
  });

  test('only S13 changes the marker, and only S24 and S32 sit inline among the numbered ones', () => {
    expect(STOPS.S13.marker).toBe('Nothing new was approved');
    for (const id of numbered) {
      const stop = STOPS[id as StopId] as Stop;
      if (id !== 'S13') expect(stop.marker).toBeUndefined();
      if (stop.placement === 'inline') expect(id).toBe('S24');
    }
    expect(STOPS.S32.placement).toBe('inline');
  });

  test('a support rule names a code the line can show', () => {
    for (const id of numbered) {
      const support = (STOPS[id as StopId] as Stop).support;
      if (support === null) continue;
      expect(support.code === 'reply' || safeCode(support.code) === support.code).toBe(true);
    }
  });
});

describe('stopForReply', () => {
  test('every known code maps to a reason that is not the catch-all', () => {
    for (const code of KNOWN_REPLY_CODES) {
      const id = stopForReply({ status: 400, code, permissionsEditable: true, expiryChangeable: true });
      expect(id).not.toBe('S26');
      expect(STOPS[id]).toBeDefined();
    }
  });

  test('status alone decides 401, 409, 410 and 429', () => {
    expect(stopForReply({ status: 401 })).toBe('S22');
    expect(stopForReply({ status: 409 })).toBe('S24');
    expect(stopForReply({ status: 410 })).toBe('S13');
    expect(stopForReply({ status: 429 })).toBe('S23');
  });

  test('a code of its own wins over a plain status', () => {
    expect(stopForReply({ status: 410, code: 'expired_request' })).toBe('S4');
    expect(stopForReply({ status: 400, code: 'key-mismatch' })).toBe('S16');
    expect(stopForReply({ status: 403, code: 'user-mismatch' })).toBe('S15');
    expect(stopForReply({ status: 403, code: 'key_delete_not_grantable' })).toBe('S21');
    expect(stopForReply({ status: 400, code: 'invalid_siwe_recap' })).toBe('S11');
    expect(stopForReply({ status: 400, code: 'delegation_prepare_failed' })).toBe('S19');
    expect(stopForReply({ status: 404, code: 'key_not_found' })).toBe('S25');
  });

  test('permission and length codes stay beside the control only when the person can change them', () => {
    expect(stopForReply({ status: 400, code: 'empty_selection', permissionsEditable: true })).toBe('permissions');
    expect(stopForReply({ status: 400, code: 'empty_selection' })).toBe('S14');
    expect(stopForReply({ status: 400, code: 'invalid_expiry', expiryChangeable: true })).toBe('length');
    expect(stopForReply({ status: 400, code: 'invalid_expiry' })).toBe('lengthFixed');
  });

  test('anything else is S26, and an unsafe code is ignored', () => {
    expect(stopForReply({ status: 500, code: 'internal_error' })).toBe('S26');
    expect(stopForReply({ status: 500 })).toBe('S26');
    expect(stopForReply({ status: 400, code: 'key-mismatch<script>' })).toBe('S26');
  });

  test('opening a link: 404 is S5, 410 is S4, a server failure is S6, the rest S7', () => {
    expect(stopForReply({ status: 404, phase: 'load' })).toBe('S5');
    expect(stopForReply({ status: 410, phase: 'load' })).toBe('S4');
    expect(stopForReply({ status: 503, phase: 'load' })).toBe('S6');
    expect(stopForReply({ status: 400, code: 'binding_mismatch', phase: 'load' })).toBe('S7');
  });
});

describe('stopForSdkError', () => {
  test('maps the SDK error codes', () => {
    expect(stopForSdkError({ code: 'UNAUTHORIZED' })).toBe('S22');
    expect(stopForSdkError({ code: 'USER_CANCELLED' })).toBe('cancelled');
    expect(stopForSdkError({ code: 'POPUP_BLOCKED' })).toBe('popup-blocked');
    expect(stopForSdkError({ code: 'APP_KEY_GRANT_REFUSED' })).toBe('S20');
    expect(stopForSdkError({ code: 'KEY_DELETE_NOT_GRANTABLE' })).toBe('S21');
    expect(stopForSdkError({ code: 'INVALID_SIWE_RECAP' })).toBe('S11');
    for (const code of ['TIMEOUT', 'STATE_MISMATCH', 'UNKNOWN', 'NO_KEY'] as const) {
      expect(stopForSdkError({ code })).toBe('S26');
    }
  });
});

describe('supportLine', () => {
  test('holds the status and a safe code, nothing else', () => {
    expect(supportLine({ status: 410, code: 'handoff_consumed' })).toBe('HTTP 410 · handoff_consumed');
    expect(supportLine({ status: 500 })).toBe('HTTP 500');
    expect(supportLine({ code: 'incomplete_link' })).toBe('incomplete_link');
    expect(supportLine({})).toBe('');
  });

  test('leaves out a code that is not a plain code', () => {
    expect(supportLine({ status: 400, code: 'two words' })).toBe('HTTP 400');
    expect(supportLine({ status: 400, code: 'a'.repeat(65) })).toBe('HTTP 400');
    expect(supportLine({ status: 400, code: { toString: () => 'x' } })).toBe('HTTP 400');
    expect(supportLine({ status: 400, code: '<b>' })).toBe('HTTP 400');
  });

  test('every known code gives a line of only the status and that code', () => {
    for (const code of KNOWN_REPLY_CODES) {
      expect(supportLine({ status: 400, code })).toBe(`HTTP 400 · ${code}`);
    }
  });
});

describe('strings', () => {
  test('the frame, loader, sign-in card and done page carry the spec words', () => {
    expect(FRAME.footer).toBe('Protected by TEE hardware security');
    expect(fill(FRAME.stopped, { step: FRAME.steps.signIn })).toBe('Sign in · stopped');
    expect(LOADER.heading).toBe('Opening your request');
    expect(Object.values(LOADER.phases)).toEqual([
      'Checking the link',
      'Checking your OpenKey account',
      'Loading your keys',
      'Preparing the request',
      'Loading the request',
    ]);
    expect(SIGN_IN.heading).toBe('Sign in to review this request');
    expect(fill(DONE.approved.line, { requester: 'TinyCloud CLI' })).toContain('sent to TinyCloud CLI');
    expect(fill(CODE.hintCopied, { destination: 'terminal' })).toBe('Copied. Now paste it in your terminal.');
  });
});
