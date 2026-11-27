// Fixed-window admission for the outbound fetch, shared across the user's tickets.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 20;
const MAX_ACTIVE_PER_USER = 2;
const MAX_ACTIVE = 32;
const MAX_USERS = 10_000;

export class AppKeyFetchLimit {
  private readonly windows = new Map<string, { start: number; count: number; active: number }>();
  private active = 0;

  acquire(userId: string, now = Date.now()): (() => void) | 'account' | 'process' {
    if (this.active >= MAX_ACTIVE) return 'process';
    let entry = this.windows.get(userId);
    if (!entry) {
      if (this.windows.size >= MAX_USERS) {
        for (const [id, window] of this.windows) {
          if (window.active === 0 && now - window.start >= WINDOW_MS) this.windows.delete(id);
        }
        if (this.windows.size >= MAX_USERS) return 'process';
      }
      entry = { start: now, count: 0, active: 0 };
      this.windows.set(userId, entry);
    }
    if (entry.active >= MAX_ACTIVE_PER_USER) return 'account';
    if (now - entry.start >= WINDOW_MS) {
      entry.start = now;
      entry.count = 0;
    }
    if (entry.count >= MAX_PER_WINDOW) return 'account';
    entry.count++;
    entry.active++;
    this.active++;
    const acquired = entry;
    return () => {
      acquired.active--;
      this.active--;
    };
  }
}
