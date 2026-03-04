/**
 * dedup.ts — Duplicate detection cache (RFC 5080)
 *
 * Prevents processing the same request twice by caching
 * replies keyed by source IP, port, and packet ID.
 */

export interface DedupEntry {
  /** Cached reply (if available) */
  reply: Buffer | null;
  /** When the entry was created */
  createdAt: number;
}

export class DedupCache {
  private cache = new Map<string, DedupEntry>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private ttlMs: number;

  constructor(ttlMs = 30000) {
    this.ttlMs = ttlMs;
    this.timer = setInterval(() => this.cleanup(), Math.max(ttlMs, 5000));
    this.timer.unref();
  }

  /** Build cache key from request source and packet ID. */
  static key(address: string, port: number, packetId: number): string {
    return `${address}:${port}:${packetId}`;
  }

  /**
   * Check the cache for a duplicate request.
   * @returns Buffer if a cached reply exists, null if request is pending, undefined if new.
   */
  check(key: string): Buffer | null | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined; // new request
    if (entry.reply) return entry.reply; // cached reply ready
    return null; // pending — still being processed
  }

  /** Mark a request as being processed (pending). */
  markPending(key: string): void {
    this.cache.set(key, { reply: null, createdAt: Date.now() });
  }

  /** Store a reply for a processed request. */
  storeReply(key: string, reply: Buffer): void {
    this.cache.set(key, { reply, createdAt: Date.now() });
  }

  /** Remove expired entries. */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt > this.ttlMs) {
        this.cache.delete(key);
      }
    }
  }

  /** Get number of entries in cache. */
  get size(): number {
    return this.cache.size;
  }

  /** Stop the cleanup timer. */
  destroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.cache.clear();
  }
}
