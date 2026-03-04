import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { RateLimiter } from './ratelimit.js';

describe('RateLimiter', () => {
  it('allows requests under the limit', () => {
    const rl = new RateLimiter({ rate: 100, burst: 200 });
    for (let i = 0; i < 50; i++) {
      assert.ok(rl.allow('10.0.0.1'));
    }
    rl.destroy();
  });

  it('denies requests over the burst', () => {
    const rl = new RateLimiter({ rate: 10, burst: 5 });
    // Use all 5 tokens
    for (let i = 0; i < 5; i++) {
      assert.ok(rl.allow('10.0.0.1'));
    }
    // 6th should be denied
    assert.equal(rl.allow('10.0.0.1'), false);
    rl.destroy();
  });

  it('tracks different NAS addresses separately', () => {
    const rl = new RateLimiter({ rate: 10, burst: 3 });
    // Use all tokens for NAS 1
    for (let i = 0; i < 3; i++) rl.allow('10.0.0.1');
    assert.equal(rl.allow('10.0.0.1'), false);
    // NAS 2 should still have tokens
    assert.ok(rl.allow('10.0.0.2'));
    rl.destroy();
  });

  it('refills tokens over time', async () => {
    const rl = new RateLimiter({ rate: 1000, burst: 10 });
    // Use all tokens
    for (let i = 0; i < 10; i++) rl.allow('10.0.0.1');
    assert.equal(rl.allow('10.0.0.1'), false);

    // Wait for refill
    await new Promise(r => setTimeout(r, 50));
    // Should have refilled some tokens (1000/s * 0.05s = 50)
    assert.ok(rl.allow('10.0.0.1'));
    rl.destroy();
  });

  it('supports per-NAS configuration', () => {
    const rl = new RateLimiter({ rate: 10, burst: 100 });
    rl.setNasLimit('10.0.0.1', { rate: 10, burst: 2 });

    // NAS 1 has burst of 2
    assert.ok(rl.allow('10.0.0.1'));
    assert.ok(rl.allow('10.0.0.1'));
    assert.equal(rl.allow('10.0.0.1'), false);

    // NAS 2 uses default burst of 100
    for (let i = 0; i < 50; i++) {
      assert.ok(rl.allow('10.0.0.2'));
    }
    rl.destroy();
  });

  it('uses default config', () => {
    const rl = new RateLimiter();
    // Default is 100/s burst 200
    for (let i = 0; i < 100; i++) {
      assert.ok(rl.allow('10.0.0.1'));
    }
    rl.destroy();
  });

  it('destroy clears all buckets', () => {
    const rl = new RateLimiter();
    rl.allow('10.0.0.1');
    rl.allow('10.0.0.2');
    rl.destroy();
    // After destroy, new requests create new buckets
    assert.ok(rl.allow('10.0.0.1'));
  });

  it('setNasLimit updates existing bucket', () => {
    const rl = new RateLimiter({ rate: 10, burst: 5 });
    // Use 3 tokens
    for (let i = 0; i < 3; i++) rl.allow('10.0.0.1');
    // Update config to burst 10
    rl.setNasLimit('10.0.0.1', { rate: 10, burst: 10 });
    // Should still be allowed (2 remaining + new burst allows refill)
    assert.ok(rl.allow('10.0.0.1'));
    rl.destroy();
  });
});
