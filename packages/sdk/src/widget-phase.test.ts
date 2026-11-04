// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test, vi } from 'bun:test';
import { OpenKey } from './index';

type FakeElement = {
  tag: string;
  className?: string;
  style: Record<string, string>;
  inert?: boolean;
  src: string;
  children: FakeElement[];
  contentWindow: { postMessage: (data: unknown, origin: string) => void };
  appendChild: (child: FakeElement) => FakeElement;
  attachShadow: () => FakeElement;
  setAttribute: () => void;
  addEventListener: () => void;
  remove: () => void;
};

function harness() {
  const globals = globalThis as unknown as { window: unknown; document: unknown };
  const oldWindow = globals.window;
  const oldDocument = globals.document;
  const listeners = new Set<(event: { origin: string; source: unknown; data: unknown }) => void>();
  const frames: Array<FakeElement & { posts: unknown[] }> = [];
  const elements: FakeElement[] = [];
  const element = (tag: string): FakeElement => {
    const el: FakeElement = {
      tag, style: {}, src: '', children: [],
      contentWindow: { postMessage() {} },
      appendChild(child) { this.children.push(child); return child; },
      attachShadow() { return element('shadow'); },
      setAttribute() {}, addEventListener() {}, remove() {},
    };
    elements.push(el);
    if (tag === 'iframe') {
      const posts: unknown[] = [];
      el.contentWindow = { postMessage(data) { posts.push(data); } };
      frames.push(Object.assign(el, { posts }));
    }
    return el;
  };
  globals.window = {
    location: { origin: 'https://app.test', hostname: 'app.test' }, innerHeight: 900,
    matchMedia: () => ({ matches: false }),
    addEventListener(type: string, listener: (event: { origin: string; source: unknown; data: unknown }) => void) { if (type === 'message') listeners.add(listener); },
    removeEventListener(type: string, listener: (event: { origin: string; source: unknown; data: unknown }) => void) { if (type === 'message') listeners.delete(listener); },
    dispatchEvent: () => true,
  };
  globals.document = { createElement: element, body: element('body') };
  const client = new OpenKey({ host: 'https://openkey.test' });
  function send(frame: FakeElement, data: unknown, origin = 'https://openkey.test', source: unknown = frame.contentWindow) {
    for (const listener of [...listeners]) listener({ origin, source, data });
  }
  function correlation(frame: FakeElement) {
    const url = new URL(frame.src);
    return { requestId: url.searchParams.get('requestId'), protocolVersion: Number(url.searchParams.get('protocolVersion')) };
  }
  return {
    client, frames, elements, send, correlation,
    restore() { globals.window = oldWindow; globals.document = oldDocument; },
  };
}

describe('embedded Connect and Sign phases', () => {
  test('rejects stale, wrong-origin, and wrong-source responses from prior phases', async () => {
    const h = harness();
    try {
      const connecting = h.client.connect();
      const connectFrame = h.frames[0];
      if (!connectFrame) throw new Error('Connect iframe missing');
      const connect = h.correlation(connectFrame);
      expect(connect.requestId).toBeTruthy();
      expect(connect.protocolVersion).toBe(2);
      let connectedEarly = false;
      void connecting.then(() => { connectedEarly = true; });
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: 'wrong', keyId: 'wrong', ...connect });
      await Promise.resolve();
      expect(connectedEarly).toBe(false);
      h.send(connectFrame, { type: 'openkey:ready', ...connect });
      expect(connectFrame.posts.at(-1)).toMatchObject({ type: 'openkey:auth:request', ...connect });
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: 'wrong', keyId: 'wrong', ...connect }, 'https://attacker.test');
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: 'wrong', keyId: 'wrong', ...connect }, 'https://openkey.test', {});
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: 'wrong', keyId: 'wrong', requestId: 'stale', protocolVersion: 2 });
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', ...connect });
      expect((await connecting).keyId).toBe('key-first');

      const signing = h.client.signMessage({ message: 'review me', keyId: 'key-first' });
      const signFrame = h.frames[1];
      if (!signFrame) throw new Error('Sign iframe missing');
      const sign = h.correlation(signFrame);
      expect(sign.requestId).not.toBe(connect.requestId);
      h.send(signFrame, { type: 'openkey:ready', ...connect });
      expect(signFrame.posts).toHaveLength(0);
      h.send(signFrame, { type: 'openkey:ready', ...sign }, 'https://attacker.test');
      expect(signFrame.posts).toHaveLength(0);
      h.send(signFrame, { type: 'openkey:ready', ...sign });
      expect(signFrame.posts.at(-1)).toMatchObject({ type: 'openkey:sign:request', keyId: 'key-first', ...sign });
      expect(signFrame.posts.at(-1)).not.toHaveProperty('authorizationProtocolVersion');
      h.send(signFrame, { type: 'openkey:sign:response', success: true, signature: 'wrong', address: '0xfirst', ...connect });
      h.send(signFrame, { type: 'openkey:close', ...connect });
      h.send(connectFrame, { type: 'openkey:sign:response', success: true, signature: 'wrong', address: '0xfirst', ...sign });
      let finished = false;
      void signing.then(() => { finished = true; });
      h.send(signFrame, { type: 'openkey:sign:response', success: true, signature: 'early', address: '0xfirst', ...sign });
      await Promise.resolve();
      expect(finished).toBe(false);
      h.send(signFrame, { type: 'openkey:resize', height: 700, layoutId: 1, ...sign });
      h.send(signFrame, { type: 'openkey:layout-ready', layoutId: 1, ...sign });
      h.send(signFrame, { type: 'openkey:sign:response', success: true, signature: 'right', address: '0xfirst', ...sign });
      expect((await signing).signature).toBe('right');

      const authorizing = h.client.authorizeTinyCloud({
        protocolVersion: 1, siwe: 'review me', keyId: 'key-first', jwk: { kty: 'EC' },
      });
      await Promise.resolve();
      const authFrame = h.frames[2];
      if (!authFrame) throw new Error('Authorization iframe missing');
      const authPhase = h.correlation(authFrame);
      h.send(authFrame, { type: 'openkey:ready', ...authPhase });
      expect(authFrame.posts.at(-1)).toMatchObject({
        type: 'openkey:sign:request', authorizationProtocolVersion: 1, jwk: { kty: 'EC' }, ...authPhase,
      });
      h.send(authFrame, { type: 'openkey:resize', height: 700, layoutId: 1, ...authPhase });
      h.send(authFrame, { type: 'openkey:layout-ready', layoutId: 1, ...authPhase });
      h.send(authFrame, {
        type: 'openkey:sign:response', success: true, signature: 'authorized',
        address: '0xfirst', signedMessage: 'review me', selectedActionKeys: [], permissions: [], ...authPhase,
      });
      expect((await authorizing).signedMessage).toBe('review me');
    } finally { h.restore(); }
  });

  test('invalidates an archived cached connection on NO_KEY and requires explicit reconnect to select another key', async () => {
    const h = harness();
    const archived = { code: 'NO_KEY', message: 'This key was archived. Reconnect to choose a key.' };
    const connect = async (keyId: string) => {
      const pending = h.client.connect();
      const frame = h.frames.at(-1)!;
      const phase = h.correlation(frame);
      h.send(frame, { type: 'openkey:ready', ...phase });
      h.send(frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId, ...phase });
      await pending;
    };
    const ready = (frame: FakeElement) => {
      const phase = h.correlation(frame);
      h.send(frame, { type: 'openkey:ready', ...phase });
      h.send(frame, { type: 'openkey:resize', height: 600, layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 1, ...phase });
      return phase;
    };
    try {
      for (const operation of ['sign', 'authorize'] as const) {
        await connect('key-archived');
        const pending = operation === 'sign'
          ? h.client.signMessage({ message: 'exact bytes' })
          : h.client.authorizeTinyCloud({ protocolVersion: 1, siwe: 'exact bytes', jwk: { kty: 'EC' } });
        await Promise.resolve();
        const frame = h.frames.at(-1)!;
        const phase = ready(frame);
        expect(frame.posts[0]).toMatchObject({ keyId: 'key-archived', message: 'exact bytes' });
        // Only an authenticated, correlated failure may invalidate the connection.
        h.send(frame, { type: 'openkey:sign:response', success: false, error: archived, ...phase }, 'https://attacker.test');
        h.send(frame, { type: 'openkey:sign:response', success: false, error: archived, ...phase }, 'https://openkey.test', {});
        h.send(frame, { type: 'openkey:sign:response', success: false, error: archived, ...phase, requestId: 'stale' });
        const stillPinned = h.client.signMessage({ message: 'check cached selection' });
        const pinnedFrame = h.frames.at(-1)!;
        const pinnedPhase = ready(pinnedFrame);
        expect(pinnedFrame.posts[0]).toMatchObject({ keyId: 'key-archived' });
        h.send(pinnedFrame, { type: 'openkey:sign:response', success: true, signature: 'ok', address: '0xfirst', ...pinnedPhase });
        await stillPinned;

        const frameCount = h.frames.length;
        h.send(frame, { type: 'openkey:sign:response', success: false, error: archived, ...phase });
        await expect(pending).rejects.toEqual(archived);
        expect(h.frames).toHaveLength(frameCount); // no automatic retry or reconnect

        const unpinned = h.client.signMessage({ message: 'check invalidated selection' });
        const unpinnedFrame = h.frames.at(-1)!;
        expect(new URL(unpinnedFrame.src).searchParams.has('keyId')).toBe(false);
        h.send(unpinnedFrame, { type: 'openkey:ready' });
        expect(unpinnedFrame.posts[0]).toMatchObject({ keyId: undefined });
        h.send(unpinnedFrame, { type: 'openkey:sign:response', success: false, error: archived });
        await expect(unpinned).rejects.toEqual(archived);

        await connect('key-replacement');
        const reconnected = h.client.signMessage({ message: 'after reconnect' });
        const reconnectedFrame = h.frames.at(-1)!;
        const reconnectedPhase = ready(reconnectedFrame);
        expect(reconnectedFrame.posts[0]).toMatchObject({ keyId: 'key-replacement' });
        h.send(reconnectedFrame, { type: 'openkey:sign:response', success: true, signature: 'new', address: '0xfirst', ...reconnectedPhase });
        expect((await reconnected).signature).toBe('new');
      }
    } finally { h.restore(); }
  });

  test('surfaces a bound authorization owner mismatch without rewriting SIWE or changing the explicit key', async () => {
    const h = harness();
    try {
      const connecting = h.client.connect();
      const connectFrame = h.frames[0]!;
      const connectPhase = h.correlation(connectFrame);
      h.send(connectFrame, { type: 'openkey:ready', ...connectPhase });
      h.send(connectFrame, { type: 'openkey:auth:response', success: true, address: '0x2222222222222222222222222222222222222222', keyId: 'key-other-owner', ...connectPhase });
      await connecting;
      const siwe = 'app.test wants you to sign in with your Ethereum account:\n0x1111111111111111111111111111111111111111\n\nAuthorize TinyCloud\n\nURI: https://app.test\nVersion: 1\nChain ID: 1\nNonce: bound123\nIssued At: 2026-11-04T00:00:00.000Z';
      const request = { protocolVersion: 1 as const, siwe, keyId: 'key-other-owner', jwk: { kty: 'EC' } };
      const authorizing = h.client.authorizeTinyCloud(request);
      await Promise.resolve();
      const frame = h.frames[1]!;
      const phase = h.correlation(frame);
      h.send(frame, { type: 'openkey:ready', ...phase });
      expect(frame.posts[0]).toMatchObject({ message: siwe, keyId: 'key-other-owner', authorizationProtocolVersion: 1 });
      h.send(frame, { type: 'openkey:resize', height: 600, layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 1, ...phase });
      const mismatch = { code: 'UNAUTHORIZED', message: 'The selected key does not match the authorization owner.' };
      h.send(frame, { type: 'openkey:sign:response', success: false, error: mismatch, ...phase });
      await expect(authorizing).rejects.toEqual(mismatch);
      expect(request.siwe).toBe(siwe);
      expect(h.frames).toHaveLength(2); // refusal is final; no rewritten retry
    } finally { h.restore(); }
  });

  test('preserves unselected-key sign flow for older widgets', async () => {
    const h = harness();
    try {
      const signing = h.client.signMessage({ message: 'legacy' });
      const frame = h.frames[0];
      if (!frame) throw new Error('Sign iframe missing');
      expect(new URL(frame.src).searchParams.has('protocolVersion')).toBe(false);
      h.send(frame, { type: 'openkey:ready' });
      expect(frame.posts.at(-1)).toMatchObject({ type: 'openkey:sign:request', message: 'legacy' });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'ok', address: '0xfirst' });
      expect((await signing).signature).toBe('ok');
    } finally { h.restore(); }
  });

  test('applies only correlated layout then acknowledges it without exposing a moving Approve', async () => {
    const h = harness();
    try {
      const signing = h.client.signMessage({ message: 'review me', keyId: 'key-first' });
      const frame = h.frames[0];
      if (!frame) throw new Error('Sign iframe missing');
      const phase = h.correlation(frame);
      expect(frame.style.visibility).toBeUndefined();
      expect(frame.style.opacity).toBe('0');
      expect(frame.style.pointerEvents).toBe('none');
      const card = h.elements.find(el => el.className === 'ok-card');
      expect(card?.style.visibility).toBeUndefined();
      expect(card?.style.opacity).toBe('0');
      expect(card?.style.pointerEvents).toBe('none');
      expect(card?.inert).toBe(true); // pointer-events alone does not block keyboard focus
      expect(card?.style.animation).toBe('none'); // no scale/slide under a newly enabled Approve
      h.send(frame, { type: 'openkey:ready', ...phase });
      h.send(frame, { type: 'openkey:resize', height: 740, layoutId: 1, requestId: 'stale', protocolVersion: 2 });
      expect(frame.posts.some(p => typeof p === 'object' && p !== null && 'type' in p && p.type === 'openkey:layout-applied')).toBe(false);
      h.send(frame, { type: 'openkey:resize', height: 740, layoutId: 2, ...phase });
      expect(frame.style.height).toBe('740px');
      expect(card?.style.visibility).toBe('visible');
      expect(frame.style.opacity).toBe('1');
      expect(frame.style.pointerEvents).toBe('auto');
      expect(card?.style.opacity).toBe('1');
      expect(card?.inert).toBe(false);
      expect(frame.style.transition).toBe('none');
      expect(frame.posts.at(-1)).toMatchObject({ type: 'openkey:layout-applied', height: 740, layoutId: 2, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 2, ...phase });
      h.send(frame, { type: 'openkey:resize', height: 300, layoutId: 3, ...phase });
      expect(frame.style.height).toBe('740px');
      h.send(frame, { type: 'openkey:layout-invalidated', layoutId: 2, ...phase });
      h.send(frame, { type: 'openkey:resize', height: 620, layoutId: 4, ...phase });
      expect(frame.style.height).toBe('740px');
      expect(frame.posts.at(-1)).toMatchObject({ type: 'openkey:layout-applied', height: 740, layoutId: 4, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 4, ...phase });
      h.send(frame, { type: 'openkey:layout-invalidated', layoutId: 4, ...phase });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'ok', address: '0xfirst', ...phase });
      await signing;
    } finally { h.restore(); }
  });
  test('reveals a stalled v2 Sign frame without treating timeout as consent', async () => {
    vi.useFakeTimers();
    const h = harness();
    try {
      const signing = h.client.signMessage({ message: 'review me', keyId: 'key-first' });
      const frame = h.frames[0];
      if (!frame) throw new Error('Sign iframe missing');
      const card = h.elements.find(el => el.className === 'ok-card');
      const phase = h.correlation(frame);
      h.send(frame, { type: 'openkey:ready', ...phase });
      vi.advanceTimersByTime(5000);
      expect(frame.style.opacity).toBe('1');
      expect(frame.style.pointerEvents).toBe('auto');
      expect(card?.style.opacity).toBe('1');
      expect(card?.inert).toBe(false);
      expect(frame.posts.some(p => typeof p === 'object' && p !== null && 'type' in p && p.type === 'openkey:layout-applied')).toBe(false);
      let settled = false;
      void signing.then(() => { settled = true; });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'early', address: '0xfirst', ...phase });
      await Promise.resolve();
      expect(settled).toBe(false);
      h.send(frame, { type: 'openkey:resize', height: 600, layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'ok', address: '0xfirst', ...phase });
      expect((await signing).signature).toBe('ok');
    } finally {
      h.restore();
      vi.useRealTimers();
    }
  });

});
