// @ts-expect-error bun:test is provided by the Bun runtime
import { describe, expect, test } from 'bun:test';
import { CLOSE_CHECK_MS, closeThisTab, type CloseEnvironment } from './delegate-close-tab';

type FakeWindowOptions = {
  closeWorks: boolean;
  historyLength: number;
  backWorks: boolean;
};

function fakeWindow(options: FakeWindowOptions) {
  let left = false;
  let now = 0;
  let nextId = 1;
  const timers: Array<{ id: number; at: number; callback: () => void }> = [];
  const calls: string[] = [];

  const env: CloseEnvironment = {
    close() {
      calls.push('close');
      if (options.closeWorks) left = true;
    },
    isClosed: () => left,
    historyLength: () => options.historyLength,
    back() {
      calls.push('back');
      if (options.backWorks) left = true;
    },
    setTimeout(callback, ms) {
      const id = nextId++;
      timers.push({ id, at: now + ms, callback });
      return id;
    },
    clearTimeout(handle) {
      const index = timers.findIndex((timer) => timer.id === handle);
      if (index >= 0) timers.splice(index, 1);
    },
  };

  return {
    env,
    calls,
    pendingTimers: () => timers.length,
    advance(ms: number) {
      const end = now + ms;
      for (;;) {
        const due = timers
          .filter((timer) => timer.at <= end)
          .sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        timers.splice(timers.indexOf(due), 1);
        now = due.at;
        due.callback();
      }
      now = end;
    },
  };
}

describe('closeThisTab', () => {
  test('window.close succeeds: no history navigation and no fallback', () => {
    const win = fakeWindow({ closeWorks: true, historyLength: 3, backWorks: true });
    let stuck = false;
    closeThisTab(win.env, () => {
      stuck = true;
    });
    win.advance(CLOSE_CHECK_MS * 2);
    expect(win.calls).toEqual(['close']);
    expect(stuck).toBe(false);
  });

  test('window.close is ignored and there is no history: reports stuck after 300 ms', () => {
    const win = fakeWindow({ closeWorks: false, historyLength: 1, backWorks: false });
    let stuck = false;
    closeThisTab(win.env, () => {
      stuck = true;
    });
    win.advance(CLOSE_CHECK_MS - 1);
    expect(stuck).toBe(false);
    win.advance(1);
    expect(stuck).toBe(true);
    expect(win.calls).toEqual(['close']);
  });

  test('window.close is ignored, history exists, and back works: goes back and does not report stuck', () => {
    const win = fakeWindow({ closeWorks: false, historyLength: 3, backWorks: true });
    let stuck = false;
    closeThisTab(win.env, () => {
      stuck = true;
    });
    win.advance(CLOSE_CHECK_MS * 3);
    expect(win.calls).toEqual(['close', 'back']);
    expect(stuck).toBe(false);
  });

  test('window.close is ignored, history exists, and back does nothing: reports stuck after 600 ms', () => {
    const win = fakeWindow({ closeWorks: false, historyLength: 3, backWorks: false });
    let stuck = false;
    closeThisTab(win.env, () => {
      stuck = true;
    });
    win.advance(CLOSE_CHECK_MS * 2 - 1);
    expect(stuck).toBe(false);
    win.advance(1);
    expect(stuck).toBe(true);
    expect(win.calls).toEqual(['close', 'back']);
  });

  test('cancel clears the pending check so no fallback runs', () => {
    const win = fakeWindow({ closeWorks: false, historyLength: 1, backWorks: false });
    let stuck = false;
    const cancel = closeThisTab(win.env, () => {
      stuck = true;
    });
    cancel();
    expect(win.pendingTimers()).toBe(0);
    win.advance(CLOSE_CHECK_MS * 3);
    expect(stuck).toBe(false);
  });
});
