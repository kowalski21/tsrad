import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { ProxyServer, type RealmRoute, type ProxyOptions } from './proxy.js';
import { RemoteHost } from './server.js';
import { Dictionary } from './dictionary.js';

describe('ProxyServer', () => {
  describe('extractRealm', () => {
    it('extracts realm from user@realm', () => {
      const proxy = new ProxyServer({
        routes: new Map(),
        hosts: new Map(),
      });
      const result = proxy.extractRealm('user@example.com');
      assert.equal(result.user, 'user');
      assert.equal(result.realm, 'example.com');
      proxy.stop();
    });

    it('returns empty realm for plain username', () => {
      const proxy = new ProxyServer({
        routes: new Map(),
        hosts: new Map(),
      });
      const result = proxy.extractRealm('plainuser');
      assert.equal(result.user, 'plainuser');
      assert.equal(result.realm, '');
      proxy.stop();
    });

    it('supports custom separator', () => {
      const proxy = new ProxyServer({
        routes: new Map(),
        hosts: new Map(),
        realmSeparator: '/',
      });
      const result = proxy.extractRealm('realm/user');
      assert.equal(result.user, 'realm');
      assert.equal(result.realm, 'user');
      proxy.stop();
    });

    it('handles multiple @ signs', () => {
      const proxy = new ProxyServer({
        routes: new Map(),
        hosts: new Map(),
      });
      const result = proxy.extractRealm('user@domain@extra');
      assert.equal(result.user, 'user');
      assert.equal(result.realm, 'domain@extra');
      proxy.stop();
    });
  });

  describe('construction', () => {
    it('creates with routes', () => {
      const route: RealmRoute = {
        servers: [{ server: '10.0.0.1', secret: Buffer.from('secret') }],
        strategy: 'failover',
        stripRealm: true,
      };
      const proxy = new ProxyServer({
        routes: new Map([['example.com', route]]),
        hosts: new Map(),
        authEnabled: false,
        acctEnabled: false,
      });
      assert.ok(proxy);
      proxy.stop();
    });

    it('accepts defaultRoute', () => {
      const proxy = new ProxyServer({
        routes: new Map(),
        defaultRoute: {
          servers: [{ server: '10.0.0.1', secret: Buffer.from('default') }],
        },
        hosts: new Map(),
        authEnabled: false,
        acctEnabled: false,
      });
      assert.ok(proxy);
      proxy.stop();
    });
  });
});
