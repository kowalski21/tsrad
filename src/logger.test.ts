import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { ConsoleLogger, NullLogger, type Logger } from './logger.js';

describe('Logger', () => {
  describe('NullLogger', () => {
    it('implements Logger interface', () => {
      const logger: Logger = new NullLogger();
      // Should not throw
      logger.debug('test');
      logger.info('test');
      logger.warn('test');
      logger.error('test');
    });

    it('accepts context', () => {
      const logger = new NullLogger();
      logger.info('msg', { requestId: 'r1', nasAddress: '10.0.0.1' });
    });
  });

  describe('ConsoleLogger', () => {
    it('creates with default level', () => {
      const logger = new ConsoleLogger();
      assert.ok(logger instanceof ConsoleLogger);
    });

    it('creates with specific level', () => {
      const logger = new ConsoleLogger('debug');
      assert.ok(logger instanceof ConsoleLogger);
    });

    it('respects log level filtering', () => {
      const captured: string[] = [];
      const origDebug = console.debug;
      const origInfo = console.info;
      console.debug = (msg: string) => captured.push(msg);
      console.info = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('info');
        logger.debug('should be filtered');
        logger.info('should appear');
        assert.equal(captured.length, 1);
        assert.ok(captured[0].includes('should appear'));
      } finally {
        console.debug = origDebug;
        console.info = origInfo;
      }
    });

    it('includes ISO timestamp', () => {
      const captured: string[] = [];
      const origInfo = console.info;
      console.info = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('info');
        logger.info('test message');
        assert.ok(/\d{4}-\d{2}-\d{2}T/.test(captured[0]));
      } finally {
        console.info = origInfo;
      }
    });

    it('includes JSON context', () => {
      const captured: string[] = [];
      const origInfo = console.info;
      console.info = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('info');
        logger.info('test', { requestId: 'r123', nasAddress: '10.0.0.1' });
        assert.ok(captured[0].includes('"requestId":"r123"'));
        assert.ok(captured[0].includes('"nasAddress":"10.0.0.1"'));
      } finally {
        console.info = origInfo;
      }
    });

    it('includes level tag', () => {
      const captured: string[] = [];
      const origWarn = console.warn;
      console.warn = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('warn');
        logger.warn('warning message');
        assert.ok(captured[0].includes('[WARN]'));
      } finally {
        console.warn = origWarn;
      }
    });

    it('debug level allows all messages', () => {
      const captured: string[] = [];
      const orig = {
        debug: console.debug,
        info: console.info,
        warn: console.warn,
        error: console.error,
      };
      console.debug = (msg: string) => captured.push(msg);
      console.info = (msg: string) => captured.push(msg);
      console.warn = (msg: string) => captured.push(msg);
      console.error = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('debug');
        logger.debug('d');
        logger.info('i');
        logger.warn('w');
        logger.error('e');
        assert.equal(captured.length, 4);
      } finally {
        Object.assign(console, orig);
      }
    });

    it('error level only allows error', () => {
      const captured: string[] = [];
      const orig = {
        debug: console.debug,
        info: console.info,
        warn: console.warn,
        error: console.error,
      };
      console.debug = (msg: string) => captured.push(msg);
      console.info = (msg: string) => captured.push(msg);
      console.warn = (msg: string) => captured.push(msg);
      console.error = (msg: string) => captured.push(msg);

      try {
        const logger = new ConsoleLogger('error');
        logger.debug('d');
        logger.info('i');
        logger.warn('w');
        logger.error('e');
        assert.equal(captured.length, 1);
        assert.ok(captured[0].includes('[ERROR]'));
      } finally {
        Object.assign(console, orig);
      }
    });
  });
});
