/**
 * policy/ratelimit.ts
 *
 * Simple in-memory token-bucket rate limiter with a sliding fixed window.
 * Tracks per-identity request counts within a configurable time window.
 */

interface WindowRecord {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, WindowRecord>();
  private readonly windowMs: number;

  /**
   * @param windowMs - Window size in milliseconds. Default 60 000 (1 minute).
   *                   Pass a smaller value in tests to make windows expire quickly.
   */
  constructor(windowMs = 60_000) {
    this.windowMs = windowMs;
  }

  /**
   * Check whether an identity is within its rate limit.
   *
   * @param identity      - The identity string to track.
   * @param limitPerMinute - Maximum allowed requests within the window.
   * @returns true if the request is allowed, false if rate-limited.
   */
  check(identity: string, limitPerMinute: number): boolean {
    const now = Date.now();
    const record = this.windows.get(identity);

    if (!record || now - record.windowStart >= this.windowMs) {
      // Start a fresh window
      this.windows.set(identity, { count: 1, windowStart: now });
      return true;
    }

    if (record.count >= limitPerMinute) {
      return false;
    }

    record.count++;
    return true;
  }
}
