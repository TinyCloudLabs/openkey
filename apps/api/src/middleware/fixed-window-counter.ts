/** Fixed-window counters keyed by string; bounded so a flood of keys cannot grow it without limit. */
export class FixedWindowCounter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  constructor(private readonly windowMs: number, private readonly maxKeys = 10_000) {}

  private current(key: string, now: number): { start: number; count: number } | undefined {
    const entry = this.windows.get(key);
    if (entry && now - entry.start < this.windowMs) return entry;
    if (entry) this.windows.delete(key);
    return undefined;
  }

  /** Counts one event; false once the window's budget (`max`) is spent. */
  hit(key: string, now: number, max: number): boolean {
    const entry = this.current(key, now);
    if (entry) {
      entry.count += 1;
      return entry.count <= max;
    }
    if (this.windows.size >= this.maxKeys) {
      for (const [other, value] of this.windows) if (now - value.start >= this.windowMs) this.windows.delete(other);
      if (this.windows.size >= this.maxKeys) this.windows.delete(this.windows.keys().next().value as string);
    }
    this.windows.set(key, { start: now, count: 1 });
    return 1 <= max;
  }

  retryAfterSeconds(key: string, now: number): number {
    const entry = this.windows.get(key);
    return entry ? Math.max(1, Math.ceil((entry.start + this.windowMs - now) / 1000)) : 1;
  }
}
