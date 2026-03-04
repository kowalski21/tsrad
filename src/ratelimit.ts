/**
 * ratelimit.ts — Token bucket rate limiter for RADIUS servers
 *
 * Per-NAS rate limiting with configurable burst and refill rates.
 */

export interface RateLimitConfig {
  /** Max requests per second (default 100) */
  rate: number;
  /** Max burst size (default 200) */
  burst: number;
}

class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private rate: number;
  private burst: number;

  constructor(config: RateLimitConfig) {
    this.rate = config.rate;
    this.burst = config.burst;
    this.tokens = config.burst;
    this.lastRefill = Date.now();
  }

  consume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.burst, this.tokens + elapsed * this.rate);
    this.lastRefill = now;
  }

  updateConfig(config: RateLimitConfig): void {
    this.rate = config.rate;
    this.burst = config.burst;
  }
}

export class RateLimiter {
  private buckets = new Map<string, TokenBucket>();
  private defaultConfig: RateLimitConfig;

  constructor(defaultConfig?: Partial<RateLimitConfig>) {
    this.defaultConfig = {
      rate: defaultConfig?.rate ?? 100,
      burst: defaultConfig?.burst ?? 200,
    };
  }

  /** Check if a request from the given address is allowed. */
  allow(address: string): boolean {
    let bucket = this.buckets.get(address);
    if (!bucket) {
      bucket = new TokenBucket(this.defaultConfig);
      this.buckets.set(address, bucket);
    }
    return bucket.consume();
  }

  /** Set a per-NAS rate limit configuration. */
  setNasLimit(address: string, config: RateLimitConfig): void {
    const existing = this.buckets.get(address);
    if (existing) {
      existing.updateConfig(config);
    } else {
      this.buckets.set(address, new TokenBucket(config));
    }
  }

  /** Remove all buckets (for cleanup). */
  destroy(): void {
    this.buckets.clear();
  }
}
