/**
 * middleware.ts — Koa-style middleware pipeline for RADIUS requests
 *
 * Provides composable request processing with support for
 * global and type-specific middleware chains.
 */

import type { Packet } from './packet.js';

export interface RequestContext {
  /** The incoming RADIUS packet */
  packet: Packet;
  /** Reply packet (set by handler or middleware) */
  reply?: Packet;
  /** Arbitrary per-request state shared between middleware */
  state: Map<string, unknown>;
  /** Unique request identifier */
  requestId: string;
  /** When the request was received */
  receivedAt: number;
  /** Source address */
  source: { address: string; port: number };
}

export type NextFunction = () => Promise<void> | void;
export type Middleware = (ctx: RequestContext, next: NextFunction) => Promise<void> | void;

let requestCounter = 0;

export function createRequestId(): string {
  return `req-${Date.now()}-${++requestCounter}`;
}

/**
 * Compose middleware into a single function (Koa-style).
 * Each middleware calls `next()` to pass control to the next in chain.
 */
export function composeMiddleware(
  middlewares: Middleware[],
  handler: (ctx: RequestContext) => Promise<void> | void,
): (ctx: RequestContext) => Promise<void> {
  return async function composed(ctx: RequestContext): Promise<void> {
    let index = -1;

    async function dispatch(i: number): Promise<void> {
      if (i <= index) throw new Error('next() called multiple times');
      index = i;

      if (i < middlewares.length) {
        const mw = middlewares[i];
        await mw(ctx, () => dispatch(i + 1));
      } else {
        await handler(ctx);
      }
    }

    return dispatch(0);
  };
}
