import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  composeMiddleware, createRequestId,
  type Middleware, type RequestContext,
} from './middleware.js';

function makeCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    packet: {} as any,
    state: new Map(),
    requestId: createRequestId(),
    receivedAt: Date.now(),
    source: { address: '127.0.0.1', port: 1812 },
    ...overrides,
  };
}

describe('Middleware', () => {
  describe('createRequestId', () => {
    it('generates unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) ids.add(createRequestId());
      assert.equal(ids.size, 100);
    });

    it('starts with req- prefix', () => {
      assert.ok(createRequestId().startsWith('req-'));
    });
  });

  describe('composeMiddleware', () => {
    it('calls handler directly with no middleware', async () => {
      let called = false;
      const fn = composeMiddleware([], async (ctx) => {
        called = true;
      });
      await fn(makeCtx());
      assert.ok(called);
    });

    it('executes middleware in order', async () => {
      const order: number[] = [];

      const mw1: Middleware = async (ctx, next) => {
        order.push(1);
        await next();
        order.push(4);
      };
      const mw2: Middleware = async (ctx, next) => {
        order.push(2);
        await next();
        order.push(3);
      };

      const fn = composeMiddleware([mw1, mw2], async () => {
        order.push(99);
      });
      await fn(makeCtx());
      assert.deepEqual(order, [1, 2, 99, 3, 4]);
    });

    it('supports sync middleware', async () => {
      let called = false;
      const mw: Middleware = (ctx, next) => {
        called = true;
        next();
      };
      const fn = composeMiddleware([mw], async () => {});
      await fn(makeCtx());
      assert.ok(called);
    });

    it('shares state between middleware', async () => {
      const mw1: Middleware = async (ctx, next) => {
        ctx.state.set('foo', 'bar');
        await next();
      };
      const mw2: Middleware = async (ctx, next) => {
        assert.equal(ctx.state.get('foo'), 'bar');
        await next();
      };

      const fn = composeMiddleware([mw1, mw2], async () => {});
      await fn(makeCtx());
    });

    it('middleware can short-circuit by not calling next', async () => {
      let handlerCalled = false;
      const mw: Middleware = async (ctx, next) => {
        // Don't call next — request is handled
      };

      const fn = composeMiddleware([mw], async () => {
        handlerCalled = true;
      });
      await fn(makeCtx());
      assert.equal(handlerCalled, false);
    });

    it('throws if next() called multiple times', async () => {
      const mw: Middleware = async (ctx, next) => {
        await next();
        await next(); // should throw
      };

      const fn = composeMiddleware([mw], async () => {});
      await assert.rejects(fn(makeCtx()), /next\(\) called multiple times/);
    });

    it('propagates errors from handler', async () => {
      const fn = composeMiddleware([], async () => {
        throw new Error('handler error');
      });
      await assert.rejects(fn(makeCtx()), /handler error/);
    });

    it('propagates errors from middleware', async () => {
      const mw: Middleware = async () => {
        throw new Error('middleware error');
      };
      const fn = composeMiddleware([mw], async () => {});
      await assert.rejects(fn(makeCtx()), /middleware error/);
    });

    it('middleware can catch handler errors', async () => {
      let caught = false;
      const mw: Middleware = async (ctx, next) => {
        try {
          await next();
        } catch {
          caught = true;
        }
      };

      const fn = composeMiddleware([mw], async () => {
        throw new Error('fail');
      });
      await fn(makeCtx());
      assert.ok(caught);
    });

    it('works with many middleware', async () => {
      const calls: number[] = [];
      const middlewares: Middleware[] = [];
      for (let i = 0; i < 20; i++) {
        const n = i;
        middlewares.push(async (ctx, next) => {
          calls.push(n);
          await next();
        });
      }

      const fn = composeMiddleware(middlewares, async () => { calls.push(999); });
      await fn(makeCtx());
      assert.equal(calls.length, 21);
      assert.equal(calls[0], 0);
      assert.equal(calls[20], 999);
    });
  });
});
