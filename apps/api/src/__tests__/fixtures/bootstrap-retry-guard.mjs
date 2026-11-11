import { afterAll, expect } from 'bun:test';

// Preloaded only by bootstrap-route-fixture-lifecycle.test.ts's subprocess.
const schedule = globalThis.setTimeout;
const cancel = globalThis.clearTimeout;
const pending = new Set();

globalThis.setTimeout = (callback, delay, ...args) => {
  const bootstrapTimer = new Error().stack?.includes('/services/tinycloud-bootstrap-budget.ts:');
  const timer = schedule(() => {
    pending.delete(timer);
    callback(...args);
  }, delay);
  if (bootstrapTimer) pending.add(timer);
  return timer;
};
globalThis.clearTimeout = (timer) => {
  pending.delete(timer);
  return cancel(timer);
};

afterAll(() => {
  expect(pending.size, 'Route fixtures left bootstrap timers scheduled after teardown').toBe(0);
});
