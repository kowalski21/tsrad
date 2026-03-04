import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { DefaultMetrics, NullMetrics, type Metrics } from './metrics.js';

describe('Metrics', () => {
  describe('NullMetrics', () => {
    it('implements Metrics interface', () => {
      const m: Metrics = new NullMetrics();
      m.increment('test');
      m.histogram('test', 1);
      m.gauge('test', 1);
    });
  });

  describe('DefaultMetrics', () => {
    it('increments counters', () => {
      const m = new DefaultMetrics();
      m.increment('requests');
      m.increment('requests');
      m.increment('requests');
      assert.equal(m.getCounter('requests'), 3);
    });

    it('increments counters with labels', () => {
      const m = new DefaultMetrics();
      m.increment('requests', { type: 'auth' });
      m.increment('requests', { type: 'acct' });
      m.increment('requests', { type: 'auth' });
      assert.equal(m.getCounter('requests', { type: 'auth' }), 2);
      assert.equal(m.getCounter('requests', { type: 'acct' }), 1);
    });

    it('records histograms', () => {
      const m = new DefaultMetrics();
      m.histogram('duration', 10);
      m.histogram('duration', 20);
      m.histogram('duration', 30);
      const h = m.getHistogram('duration');
      assert.ok(h);
      assert.equal(h!.count, 3);
      assert.equal(h!.sum, 60);
      assert.equal(h!.min, 10);
      assert.equal(h!.max, 30);
    });

    it('records gauges', () => {
      const m = new DefaultMetrics();
      m.gauge('inflight', 5);
      assert.equal(m.getGauge('inflight'), 5);
      m.gauge('inflight', 3);
      assert.equal(m.getGauge('inflight'), 3);
    });

    it('returns snapshot', () => {
      const m = new DefaultMetrics();
      m.increment('a');
      m.histogram('b', 1);
      m.gauge('c', 2);
      const snap = m.snapshot();
      assert.equal(snap.counters.get('a'), 1);
      assert.equal(snap.histograms.get('b')?.count, 1);
      assert.equal(snap.gauges.get('c'), 2);
    });

    it('snapshot is a copy', () => {
      const m = new DefaultMetrics();
      m.increment('a');
      const snap = m.snapshot();
      m.increment('a');
      // Snapshot should still show 1
      assert.equal(snap.counters.get('a'), 1);
      assert.equal(m.getCounter('a'), 2);
    });

    it('resets all metrics', () => {
      const m = new DefaultMetrics();
      m.increment('a');
      m.histogram('b', 1);
      m.gauge('c', 2);
      m.reset();
      assert.equal(m.getCounter('a'), 0);
      assert.equal(m.getHistogram('b'), undefined);
      assert.equal(m.getGauge('c'), 0);
    });

    it('returns 0 for non-existent counter', () => {
      const m = new DefaultMetrics();
      assert.equal(m.getCounter('nonexistent'), 0);
    });

    it('returns 0 for non-existent gauge', () => {
      const m = new DefaultMetrics();
      assert.equal(m.getGauge('nonexistent'), 0);
    });

    it('returns undefined for non-existent histogram', () => {
      const m = new DefaultMetrics();
      assert.equal(m.getHistogram('nonexistent'), undefined);
    });

    it('labels are sorted for consistent keys', () => {
      const m = new DefaultMetrics();
      m.increment('x', { b: '2', a: '1' });
      m.increment('x', { a: '1', b: '2' });
      assert.equal(m.getCounter('x', { a: '1', b: '2' }), 2);
    });

    it('empty labels same as no labels', () => {
      const m = new DefaultMetrics();
      m.increment('x');
      m.increment('x', {});
      assert.equal(m.getCounter('x'), 2);
    });
  });
});
