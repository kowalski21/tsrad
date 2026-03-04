/**
 * logger.ts — Structured logging for RADIUS operations
 *
 * Provides a pluggable logging interface with context support
 * for request tracking, NAS identification, and packet debugging.
 */

export interface LogContext {
  requestId?: string;
  nasAddress?: string;
  packetCode?: number;
  packetId?: number;
  username?: string;
  [key: string]: unknown;
}

export interface Logger {
  debug(msg: string, ctx?: LogContext): void;
  info(msg: string, ctx?: LogContext): void;
  warn(msg: string, ctx?: LogContext): void;
  error(msg: string, ctx?: LogContext): void;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class ConsoleLogger implements Logger {
  private minLevel: number;

  constructor(level: LogLevel = 'info') {
    this.minLevel = LOG_LEVELS[level];
  }

  debug(msg: string, ctx?: LogContext): void {
    if (this.minLevel <= LOG_LEVELS.debug) this.log('debug', msg, ctx);
  }

  info(msg: string, ctx?: LogContext): void {
    if (this.minLevel <= LOG_LEVELS.info) this.log('info', msg, ctx);
  }

  warn(msg: string, ctx?: LogContext): void {
    if (this.minLevel <= LOG_LEVELS.warn) this.log('warn', msg, ctx);
  }

  error(msg: string, ctx?: LogContext): void {
    if (this.minLevel <= LOG_LEVELS.error) this.log('error', msg, ctx);
  }

  private log(level: LogLevel, msg: string, ctx?: LogContext): void {
    const ts = new Date().toISOString();
    const ctxStr = ctx && Object.keys(ctx).length > 0 ? ' ' + JSON.stringify(ctx) : '';
    const line = `${ts} [${level.toUpperCase()}] ${msg}${ctxStr}`;
    switch (level) {
      case 'debug': console.debug(line); break;
      case 'info': console.info(line); break;
      case 'warn': console.warn(line); break;
      case 'error': console.error(line); break;
    }
  }
}

export class NullLogger implements Logger {
  debug(_msg: string, _ctx?: LogContext): void {}
  info(_msg: string, _ctx?: LogContext): void {}
  warn(_msg: string, _ctx?: LogContext): void {}
  error(_msg: string, _ctx?: LogContext): void {}
}
