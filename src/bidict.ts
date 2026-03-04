/**
 * bidict.ts — Bidirectional map
 *
 * Port of pyrad/bidict.py
 *
 * Uses string serialization for Buffer keys so that Map lookups
 * work by value rather than by reference.
 */

export class BiDict<K, V> {
  private forward = new Map<K, V>();
  private backward = new Map<string | V, K>();

  private bkey(val: V): string | V {
    if (Buffer.isBuffer(val)) return (val as Buffer).toString('hex');
    return val;
  }

  add(one: K, two: V): void {
    this.forward.set(one, two);
    this.backward.set(this.bkey(two), one);
  }

  get length(): number {
    return this.forward.size;
  }

  get(key: K): V {
    return this.getForward(key);
  }

  delete(key: K | V): void {
    if (this.forward.has(key as K)) {
      const val = this.forward.get(key as K)!;
      this.backward.delete(this.bkey(val));
      this.forward.delete(key as K);
    } else {
      const bk = this.bkey(key as V);
      const k = this.backward.get(bk)!;
      this.forward.delete(k);
      this.backward.delete(bk);
    }
  }

  getForward(key: K): V {
    const val = this.forward.get(key);
    if (val === undefined) throw new Error(`Key not found in forward map: ${key}`);
    return val;
  }

  hasForward(key: K): boolean {
    return this.forward.has(key);
  }

  getBackward(key: V): K {
    const val = this.backward.get(this.bkey(key));
    if (val === undefined) throw new Error(`Key not found in backward map: ${key}`);
    return val;
  }

  hasBackward(key: V): boolean {
    return this.backward.has(this.bkey(key));
  }

  /** Return all forward keys (useful for error messages listing named values). */
  forwardKeys(): K[] {
    return Array.from(this.forward.keys());
  }
}
