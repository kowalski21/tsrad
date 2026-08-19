import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import * as dgram from 'node:dgram';
import {
  Server, RemoteHost, type RadiusPacket,
  Client, FailoverClient, Timeout,
  Dictionary,
  Packet, AuthPacket, AcctPacket, CoAPacket,
  AccessRequest, AccessAccept, AccessReject,
  AccountingRequest, AccountingResponse,
  CoARequest, CoAACK, DisconnectRequest, DisconnectACK,
  StatusServer,
  type Middleware, type RequestContext,
  DedupCache,
  DefaultMetrics,
  NullLogger, ConsoleLogger,
} from './index.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');
// Keep integration tests away from the well-known RADIUS ports and reduce
// collisions between concurrent local/CI test processes.
const testPortBase = 40000 + (process.pid % 10000);

// Use realistic dict — has User-Name, NAS-IP-Address, etc.
function loadDict(): Dictionary {
  return new Dictionary(path.join(dataDir, 'realistic'));
}

describe('Async Handlers', () => {
  it('supports async auth handler', async () => {
    const dict = loadDict();
    let handlerCalled = false;

    class AsyncServer extends Server {
      async handleAuthPacket(pkt: RadiusPacket): Promise<void> {
        await new Promise(r => setTimeout(r, 10));
        handlerCalled = true;
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new AsyncServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase,
      acctport: testPortBase + 10,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing123'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase,
      secret: Buffer.from('testing123'),
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      const req = client.createAuthPacket();
      req.addAttribute('User-Name', 'testuser');
      const reply = await client.sendPacket(req);
      assert.equal(reply.code, AccessAccept);
      assert.ok(handlerCalled);
    } finally {
      client.close();
      server.stop();
    }
  });

  it('supports sync auth handler (backward compat)', async () => {
    const dict = loadDict();

    class SyncServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new SyncServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 1,
      acctport: testPortBase + 11,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('s123'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase + 1,
      secret: Buffer.from('s123'),
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      const req = client.createAuthPacket();
      req.addAttribute('User-Name', 'test');
      const reply = await client.sendPacket(req);
      assert.equal(reply.code, AccessAccept);
    } finally {
      client.close();
      server.stop();
    }
  });
});

describe('Middleware Pipeline', () => {
  it('runs global middleware on auth requests', async () => {
    const dict = loadDict();
    const calls: string[] = [];

    class MwServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        calls.push('handler');
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new MwServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 2,
      acctport: testPortBase + 12,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('mw'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });

    server.use(async (ctx, next) => {
      calls.push('global-before');
      await next();
      calls.push('global-after');
    });

    server.useAuth(async (ctx, next) => {
      calls.push('auth-mw');
      await next();
    });

    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase + 2,
      secret: Buffer.from('mw'),
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      const req = client.createAuthPacket();
      req.addAttribute('User-Name', 'test');
      await client.sendPacket(req);

      // Wait for middleware to complete
      await new Promise(r => setTimeout(r, 50));
      assert.deepEqual(calls, ['global-before', 'auth-mw', 'handler', 'global-after']);
    } finally {
      client.close();
      server.stop();
    }
  });
});

describe('Graceful Shutdown', () => {
  it('waits for in-flight requests before closing', async () => {
    const dict = loadDict();
    let handlerFinished = false;

    class SlowServer extends Server {
      async handleAuthPacket(pkt: RadiusPacket): Promise<void> {
        await new Promise(r => setTimeout(r, 50));
        handlerFinished = true;
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new SlowServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 3,
      acctport: testPortBase + 13,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('gs'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    // Send a request via raw UDP to trigger the handler, then test shutdown
    const sock = dgram.createSocket('udp4');
    const req = new AuthPacket({ secret: Buffer.from('gs'), dict });
    req.addAttribute('User-Name', 'test');
    const raw = req.requestPacket();
    sock.send(raw, testPortBase + 3, '127.0.0.1');

    await new Promise(r => setTimeout(r, 10));

    // Graceful stop waits for the handler to finish
    await server.gracefulStop(5000);
    assert.ok(handlerFinished);
    sock.close();
  });
});

describe('Metrics Integration', () => {
  it('collects auth metrics', async () => {
    const dict = loadDict();
    const metrics = new DefaultMetrics();

    class MetricsServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new MetricsServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 5,
      acctport: testPortBase + 15,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('met'), 'test')],
      ]),
      metrics,
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase + 5,
      secret: Buffer.from('met'),
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      const req = client.createAuthPacket();
      req.addAttribute('User-Name', 'test');
      await client.sendPacket(req);

      await new Promise(r => setTimeout(r, 50));
      assert.ok(metrics.getCounter('radius_auth_total') >= 1);
    } finally {
      client.close();
      server.stop();
    }
  });
});

describe('Client Connection Pooling', () => {
  it('handles concurrent requests', async () => {
    const dict = loadDict();

    class PoolServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server = new PoolServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 6,
      acctport: testPortBase + 16,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('pool'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase + 6,
      secret: Buffer.from('pool'),
      dict,
      timeout: 3,
      retries: 1,
    });

    try {
      const promises = [];
      for (let i = 0; i < 5; i++) {
        const req = client.createAuthPacket();
        req.addAttribute('User-Name', `user${i}`);
        promises.push(client.sendPacket(req));
      }

      const replies = await Promise.all(promises);
      assert.equal(replies.length, 5);
      for (const reply of replies) {
        assert.equal(reply.code, AccessAccept);
      }
    } finally {
      client.close();
      server.stop();
    }
  });
});

describe('FailoverClient', () => {
  it('constructs with multiple servers', () => {
    const client = new FailoverClient({
      servers: [
        { server: '10.0.0.1', secret: Buffer.from('s1') },
        { server: '10.0.0.2', secret: Buffer.from('s2') },
      ],
      strategy: 'failover',
    });
    assert.ok(client);
    client.close();
  });

  it('fails over to second server on timeout', async () => {
    const dict = loadDict();

    class FoServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        this.sendReply(reply);
      }
    }

    const server2 = new FoServer({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 8,
      acctport: testPortBase + 18,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('fo2'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server2.listen();

    const client = new FailoverClient({
      servers: [
        { server: '127.0.0.1', authport: testPortBase + 7, secret: Buffer.from('fo1') },
        { server: '127.0.0.1', authport: testPortBase + 8, secret: Buffer.from('fo2') },
      ],
      strategy: 'failover',
      dict,
      timeout: 1,
      retries: 1,
    });

    try {
      const req = client.createAuthPacket({ secret: Buffer.from('fo1') });
      req.addAttribute('User-Name', 'failover-test');
      const reply = await client.sendPacket(req);
      assert.equal(reply.code, AccessAccept);
    } finally {
      client.close();
      server2.stop();
    }
  });

  it('round-robin rotates servers', () => {
    const client = new FailoverClient({
      servers: [
        { server: '10.0.0.1', secret: Buffer.from('a') },
        { server: '10.0.0.2', secret: Buffer.from('b') },
      ],
      strategy: 'round-robin',
    });
    client.close();
  });
});

describe('Status-Server', () => {
  it('server responds to Status-Server on auth port', async () => {
    const dict = loadDict();

    const server = new Server({
      addresses: ['127.0.0.1'],
      authport: testPortBase + 9,
      acctport: testPortBase + 19,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('status'), 'test')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    await server.listen();

    const client = new Client({
      server: '127.0.0.1',
      authport: testPortBase + 9,
      secret: Buffer.from('status'),
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      const reply = await client.sendStatusServer();
      assert.equal(reply.code, AccessAccept);
    } finally {
      client.close();
      server.stop();
    }
  });
});

describe('Attribute Validation', () => {
  it('rejects wrong type for integer attribute', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({ dict, secret: Buffer.from('test') });
    assert.throws(
      () => pkt.addAttribute('Test-Integer', { invalid: true }),
      /expects number/,
    );
  });

  it('allows named values for integer attributes', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({ dict, secret: Buffer.from('test') });
    pkt.addAttribute('Test-Integer', 'Zero');
    assert.deepEqual(pkt.getAttribute('Test-Integer'), ['Zero']);
  });

  it('rejects wrong type for ipaddr attribute', () => {
    const dict = loadDict();
    const pkt = new Packet({ dict, secret: Buffer.from('test') });
    assert.throws(
      () => pkt.addAttribute('NAS-IP-Address', 12345),
      /expects IP address string/,
    );
  });

  it('accepts number for integer attribute', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({ dict, secret: Buffer.from('test') });
    pkt.addAttribute('Test-Integer', 42);
    assert.deepEqual(pkt.getAttribute('Test-Integer'), [42]);
  });

  it('accepts string for string attribute', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({ dict, secret: Buffer.from('test') });
    pkt.addAttribute('Test-String', 'hello');
    assert.deepEqual(pkt.getAttribute('Test-String'), ['hello']);
  });
});

describe('BiDict forwardKeys', () => {
  it('returns all forward keys', async () => {
    const { BiDict } = await import('./bidict.js');
    const bd = new BiDict();
    bd.add('a', 1);
    bd.add('b', 2);
    bd.add('c', 3);
    const keys = bd.forwardKeys();
    assert.deepEqual(keys.sort(), ['a', 'b', 'c']);
  });
});

describe('Dictionary - vendor format', () => {
  it('stores vendor format from dictionary', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const fmt = dict.getVendorFormat(99999);
    assert.equal(fmt.typeSize, 2);
    assert.equal(fmt.lengthSize, 1);
  });

  it('returns default format for standard vendors', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const fmt = dict.getVendorFormat(12345);
    assert.equal(fmt.typeSize, 1);
    assert.equal(fmt.lengthSize, 1);
  });

  it('returns default format for unknown vendors', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const fmt = dict.getVendorFormat(99);
    assert.equal(fmt.typeSize, 1);
    assert.equal(fmt.lengthSize, 1);
  });

  it('parses vendor with format=1,0', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const fmt = dict.getVendorFormat(54321);
    assert.equal(fmt.typeSize, 1);
    assert.equal(fmt.lengthSize, 0);
  });
});

describe('Dictionary - extended attributes', () => {
  it('parses extended attributes (241.x)', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const attr = dict.get('Ext-Short-Str');
    assert.ok(attr);
    assert.equal(attr!.extended, true);
    assert.equal(attr!.extendedType, 241);
    assert.equal(attr!.extendedCode, 1);
    assert.equal(attr!.type, 'string');
  });

  it('parses long extended attributes (243.x)', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const attr = dict.get('Ext-Long-Str');
    assert.ok(attr);
    assert.equal(attr!.extended, true);
    assert.equal(attr!.extendedType, 243);
    assert.equal(attr!.extendedCode, 1);
  });

  it('indexes extended attrs as [type, code] tuples', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    assert.ok(dict.attrindex.hasForward('Ext-Short-Str'));
    const key = dict.attrindex.getForward('Ext-Short-Str');
    assert.deepEqual(key, [241, 1]);
  });
});

describe('Dictionary - serialization', () => {
  it('serialize and fromCache round-trip', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const buf = dict.serialize();
    assert.ok(Buffer.isBuffer(buf));
    assert.ok(buf.length > 0);

    const restored = Dictionary.fromCache(buf);
    assert.ok(restored.has('Test-String'));
    assert.ok(restored.has('Test-Integer'));
    assert.ok(restored.has('Simplon-Number'));

    const attr = restored.get('Test-Integer')!;
    assert.ok(attr.values.hasForward('Zero'));
    assert.ok(attr.values.hasForward('One'));
  });

  it('preserves vendor info', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const buf = dict.serialize();
    const restored = Dictionary.fromCache(buf);

    assert.ok(restored.vendors.hasForward('Simplon'));
    assert.equal(restored.vendors.getForward('Simplon'), 16);
  });

  it('preserves extended attribute info', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const buf = dict.serialize();
    const restored = Dictionary.fromCache(buf);

    const attr = restored.get('Ext-Short-Str')!;
    assert.equal(attr.extended, true);
    assert.equal(attr.extendedType, 241);
    assert.equal(attr.extendedCode, 1);
  });

  it('preserves vendor format info', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const buf = dict.serialize();
    const restored = Dictionary.fromCache(buf);

    const fmt = restored.getVendorFormat(99999);
    assert.equal(fmt.typeSize, 2);
    assert.equal(fmt.lengthSize, 1);
  });

  it('detects stale cache when source hash differs', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const buf = dict.serialize();
    assert.throws(
      () => Dictionary.fromCache(buf, ['/nonexistent/file']),
      /stale/,
    );
  });
});

describe('Extended Attribute Encoding/Decoding', () => {
  it('encodes and decodes short extended attribute', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const pkt = new Packet({
      dict,
      secret: Buffer.from('test'),
      authenticator: Buffer.alloc(16),
      code: AccessRequest,
    });
    pkt.addAttribute('Ext-Short-Str', 'hello');

    const wire = pkt.replyPacket();
    assert.ok(wire.length > 20);

    const pkt2 = new Packet({
      dict,
      secret: Buffer.from('test'),
      packet: wire,
    });
    assert.ok(pkt2.has('Ext-Short-Str'));
    const vals = pkt2.getAttribute('Ext-Short-Str');
    assert.equal(vals[0], 'hello');
  });

  it('encodes and decodes short extended integer', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const pkt = new Packet({
      dict,
      secret: Buffer.from('test'),
      authenticator: Buffer.alloc(16),
      code: AccessRequest,
    });
    pkt.addAttribute('Ext-Short-Int', 42);

    const wire = pkt.replyPacket();
    const pkt2 = new Packet({
      dict,
      secret: Buffer.from('test'),
      packet: wire,
    });
    assert.ok(pkt2.has('Ext-Short-Int'));
    assert.equal(pkt2.getAttribute('Ext-Short-Int')[0], 42);
  });
});

describe('Vendor Format Encoding/Decoding', () => {
  it('encodes standard vendor attributes', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const pkt = new Packet({
      dict,
      secret: Buffer.from('test'),
      authenticator: Buffer.alloc(16),
      code: AccessRequest,
    });
    pkt.addAttribute('SV-Name', 'testname');

    const wire = pkt.replyPacket();
    const pkt2 = new Packet({
      dict,
      secret: Buffer.from('test'),
      packet: wire,
    });
    assert.equal(pkt2.getAttribute('SV-Name')[0], 'testname');
  });

  it('round-trips standard vendor integer', () => {
    const dict = new Dictionary(path.join(dataDir, 'extended'));
    const pkt = new Packet({
      dict,
      secret: Buffer.from('test'),
      authenticator: Buffer.alloc(16),
      code: AccessRequest,
    });
    pkt.addAttribute('SV-Port', 8080);

    const wire = pkt.replyPacket();
    const pkt2 = new Packet({
      dict,
      secret: Buffer.from('test'),
      packet: wire,
    });
    assert.equal(pkt2.getAttribute('SV-Port')[0], 8080);
  });
});

describe('Server Logger Integration', () => {
  it('accepts logger option', () => {
    const logger = new NullLogger();
    const server = new Server({
      logger,
      hosts: new Map(),
      authEnabled: false,
      acctEnabled: false,
    });
    assert.ok(server);
    server.stop();
  });

  it('client accepts logger option', () => {
    const client = new Client({
      server: '127.0.0.1',
      secret: Buffer.from('test'),
      logger: new NullLogger(),
    });
    assert.ok(client);
    client.close();
  });
});

describe('Server Dedup Integration', () => {
  it('can disable dedup', () => {
    const server = new Server({
      hosts: new Map(),
      dedupTtl: false,
      authEnabled: false,
      acctEnabled: false,
    });
    assert.ok(server);
    server.stop();
  });

  it('can set custom dedup TTL', () => {
    const server = new Server({
      hosts: new Map(),
      dedupTtl: 60000,
      authEnabled: false,
      acctEnabled: false,
    });
    assert.ok(server);
    server.stop();
  });
});

describe('Server Rate Limit Integration', () => {
  it('can disable rate limiting', () => {
    const server = new Server({
      hosts: new Map(),
      rateLimit: false,
      authEnabled: false,
      acctEnabled: false,
    });
    assert.ok(server);
    server.stop();
  });

  it('can set custom rate limit', () => {
    const server = new Server({
      hosts: new Map(),
      rateLimit: { rate: 50, burst: 100 },
      authEnabled: false,
      acctEnabled: false,
    });
    assert.ok(server);
    server.stop();
  });
});
