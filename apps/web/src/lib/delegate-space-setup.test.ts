// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  parseSpaceSetup,
  spaceReadinessResult,
  spaceSetupNoticeText,
} from './delegate-space-setup';

const notice = (plan: 'setup' | 'auto-sign-off' | 'external-wallet') => ({ space: 'agents', plan });

describe('parseSpaceSetup', () => {
  test('rejects null, unknown plans, and invalid space names', () => {
    expect(parseSpaceSetup(null)).toBeNull();
    expect(parseSpaceSetup({ space: 'agents', plan: 'unknown' })).toBeNull();
    expect(parseSpaceSetup({ space: 'foo:agents', plan: 'setup' })).toBeNull();
    expect(parseSpaceSetup({ space: 'Agents', plan: 'setup' })).toBeNull();
  });
});

describe('spaceSetupNoticeText', () => {
  test('only setup says approving sets the space up', () => {
    expect(spaceSetupNoticeText(notice('setup'))).toContain('agents');
    expect(spaceSetupNoticeText(notice('setup'))).toContain('approving will also finish setting it up');
    for (const plan of ['auto-sign-off', 'external-wallet'] as const) {
      expect(spaceSetupNoticeText(notice(plan))).toContain('agents');
      expect(spaceSetupNoticeText(notice(plan))).toContain("won't set it up");
    }
  });
});

describe('spaceReadinessResult', () => {
  test('reports ready with the API space name only for the setup plan', () => {
    const result = spaceReadinessResult({ spaceReady: true, spaceId: 'did:space:agents' }, notice('setup'));
    expect(result?.kind).toBe('ready');
    expect(result?.text).toContain('agents');
    expect(spaceReadinessResult({ spaceReady: true }, null)).toBeNull();
    expect(spaceReadinessResult({ spaceReady: true }, notice('auto-sign-off'))).toBeNull();
  });
  test('does not claim readiness when the API could not confirm it', () => {
    for (const payload of [
      { spaceReady: null, spaceId: 'did:space:agents' },
      {},
    ]) {
      const result = spaceReadinessResult(payload, notice('setup'));
      expect(result?.kind).toBe('unknown');
      expect(result?.text).toContain('agents');
      expect(result?.text).not.toContain('is ready');
    }
    expect(spaceReadinessResult({ spaceReady: null }, null)).toBeNull();
  });

  test('reports failed details separately from the user-facing text', () => {
    const result = spaceReadinessResult(
      { spaceReady: false, spaceError: 'seed failed', spaceId: 'did:space:agents' },
      null,
    );
    expect(result?.kind).toBe('failed');
    expect(result?.detail).toBe('seed failed');
    expect(result?.text).toContain('agents');
  });

  test('reports not-ready without raw details and falls back to requested name', () => {
    const result = spaceReadinessResult({ spaceReady: false }, null);
    expect(result?.kind).toBe('not-ready');
    expect(result?.text).toContain('requested');
    expect(spaceReadinessResult({ spaceReady: false }, notice('setup'))?.text).toContain('agents');
    expect(result && 'detail' in result).toBe(false);
  });
});


describe('TC-945 pending space readiness', () => {
  for (const setupNotice of [notice('setup'), null]) {
    test(`pending copy with ${setupNotice ? 'setup' : 'no'} notice uses the space name without error language`, () => {
      const result = spaceReadinessResult({ spaceReady: null, spacePending: true, spaceId: 'did:space:agents' }, setupNotice);
      expect(result?.kind).toBe('pending');
      expect(result?.text).toContain('agents');
      expect(result?.text).toContain('being set up');
      expect(result?.text).toContain('ready');
      for (const word of ["couldn't", "didn't", 'failed']) expect(result?.text).not.toContain(word);
      expect(result).not.toHaveProperty('detail');
    });
  }
  test('the marker never overrides a definite readiness answer', () => {
    expect(spaceReadinessResult({ spaceReady: true, spacePending: true }, notice('setup'))?.kind).toBe('ready');
    expect(spaceReadinessResult({ spaceReady: false, spacePending: true }, notice('setup'))?.kind).toBe('not-ready');
    expect(spaceReadinessResult({ spaceReady: false, spacePending: true, spaceError: 'seed failed' }, notice('setup'))?.kind).toBe('failed');
  });
});
