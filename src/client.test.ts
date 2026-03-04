import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { Client, Timeout } from './client.js';
import { AuthPacket, AcctPacket, CoAPacket } from './packet.js';
import { Dictionary } from './dictionary.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');

describe('Client - construction', () => {
  it('simple construction with defaults', () => {
    const client = new Client({
      server: '127.0.0.1',
      secret: Buffer.from('secret'),
    });
    assert.equal(client.server, '127.0.0.1');
    assert.deepEqual(client.secret, Buffer.from('secret'));
    assert.equal(client.authport, 1812);
    assert.equal(client.acctport, 1813);
    assert.equal(client.retries, 3);
    assert.equal(client.timeout, 5);
    assert.equal(client.enforceMA, false);
  });

  it('custom parameters', () => {
    const dict = new Dictionary();
    const client = new Client({
      server: '10.0.0.1',
      secret: Buffer.from('mysecret'),
      authport: 1234,
      acctport: 5678,
      coaport: 9012,
      dict,
      retries: 5,
      timeout: 10,
      enforceMA: true,
    });
    assert.equal(client.server, '10.0.0.1');
    assert.equal(client.authport, 1234);
    assert.equal(client.acctport, 5678);
    assert.equal(client.coaport, 9012);
    assert.equal(client.dict, dict);
    assert.equal(client.retries, 5);
    assert.equal(client.timeout, 10);
    assert.equal(client.enforceMA, true);
  });
});

describe('Client - packet creation', () => {
  let client: Client;

  beforeEach(() => {
    client = new Client({
      server: 'localhost',
      secret: Buffer.from('zeer geheim'),
    });
  });

  it('createAuthPacket uses client secret', () => {
    const pkt = client.createAuthPacket({ id: 15 });
    assert.ok(pkt instanceof AuthPacket);
    assert.equal(pkt.dict, client.dict);
    assert.equal(pkt.id, 15);
    assert.deepEqual(pkt.secret, Buffer.from('zeer geheim'));
  });

  it('createAcctPacket uses client secret', () => {
    const pkt = client.createAcctPacket({ id: 15 });
    assert.ok(pkt instanceof AcctPacket);
    assert.equal(pkt.dict, client.dict);
    assert.equal(pkt.id, 15);
    assert.deepEqual(pkt.secret, Buffer.from('zeer geheim'));
  });

  it('createCoAPacket uses client secret', () => {
    const pkt = client.createCoAPacket({ id: 15 });
    assert.ok(pkt instanceof CoAPacket);
    assert.equal(pkt.dict, client.dict);
    assert.equal(pkt.id, 15);
    assert.deepEqual(pkt.secret, Buffer.from('zeer geheim'));
  });

  it('createAuthPacket with enforceMA adds Message-Authenticator', () => {
    const maClient = new Client({
      server: 'localhost',
      secret: Buffer.from('secret'),
      enforceMA: true,
    });
    const pkt = maClient.createAuthPacket();
    assert.equal(pkt.messageAuthenticator, true);
  });
});

describe('Client - close', () => {
  it('close is idempotent', () => {
    const client = new Client({
      server: 'localhost',
      secret: Buffer.from('secret'),
    });
    // Should not throw
    client.close();
    client.close();
  });
});

describe('Client - Timeout class', () => {
  it('is an Error subclass', () => {
    const err = new Timeout();
    assert.ok(err instanceof Error);
    assert.equal(err.name, 'Timeout');
    assert.equal(err.message, 'RADIUS server did not reply');
  });

  it('accepts custom message', () => {
    const err = new Timeout('custom');
    assert.equal(err.message, 'custom');
  });
});

describe('Client - sendPacket timeout', () => {
  it('times out when no server is listening', async () => {
    const dict = new Dictionary(path.join(dataDir, 'realistic'));
    const client = new Client({
      server: '127.0.0.1',
      secret: Buffer.from('secret'),
      dict,
      retries: 1,
      timeout: 0.1, // 100ms
    });

    const pkt = client.createAuthPacket();
    pkt.addAttribute('User-Name', 'test');

    try {
      await client.sendPacket(pkt);
      assert.fail('Should have thrown Timeout');
    } catch (err) {
      assert.ok(err instanceof Timeout);
    } finally {
      client.close();
    }
  });
});
