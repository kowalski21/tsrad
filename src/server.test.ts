import { describe, it, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import * as dgram from 'node:dgram';
import {
  Server, RemoteHost, ServerPacketError,
  type RadiusPacket,
} from './server.js';
import {
  AuthPacket, AcctPacket, CoAPacket,
  AccessRequest, AccessAccept, AccessReject,
  AccountingRequest, AccountingResponse,
  CoARequest, CoAACK,
  DisconnectRequest, DisconnectACK,
} from './packet.js';
import { Dictionary } from './dictionary.js';
import { Client, Timeout } from './client.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');

describe('RemoteHost', () => {
  it('simple construction', () => {
    const host = new RemoteHost('10.0.0.1', Buffer.from('secret'), 'mynas');
    assert.equal(host.address, '10.0.0.1');
    assert.deepEqual(host.secret, Buffer.from('secret'));
    assert.equal(host.name, 'mynas');
    assert.equal(host.authport, 1812);
    assert.equal(host.acctport, 1813);
    assert.equal(host.coaport, 3799);
  });

  it('custom ports', () => {
    const host = new RemoteHost('10.0.0.1', Buffer.from('secret'), 'mynas', {
      authport: 1234,
      acctport: 5678,
      coaport: 9012,
    });
    assert.equal(host.authport, 1234);
    assert.equal(host.acctport, 5678);
    assert.equal(host.coaport, 9012);
  });
});

describe('Server - construction', () => {
  it('default construction', () => {
    const server = new Server();
    assert.equal(server.authport, 1812);
    assert.equal(server.acctport, 1813);
    assert.equal(server.coaport, 3799);
    assert.equal(server.hosts.size, 0);
    assert.equal(server.authEnabled, true);
    assert.equal(server.acctEnabled, true);
    assert.equal(server.coaEnabled, false);
  });

  it('custom options', () => {
    const dict = new Dictionary();
    const hosts = new Map([
      ['10.0.0.1', new RemoteHost('10.0.0.1', Buffer.from('secret'), 'nas')],
    ]);
    const server = new Server({
      authport: 1234,
      acctport: 5678,
      coaport: 9012,
      dict,
      hosts,
      authEnabled: false,
      acctEnabled: false,
      coaEnabled: true,
    });
    assert.equal(server.authport, 1234);
    assert.equal(server.acctport, 5678);
    assert.equal(server.coaport, 9012);
    assert.equal(server.dict, dict);
    assert.equal(server.hosts.size, 1);
    assert.equal(server.authEnabled, false);
    assert.equal(server.acctEnabled, false);
    assert.equal(server.coaEnabled, true);
    server.stop();
  });
});

describe('Server - handler pattern', () => {
  it('default handlers do nothing', () => {
    const server = new Server();
    // These should not throw
    server.handleAuthPacket({} as any);
    server.handleAcctPacket({} as any);
    server.handleCoaPacket({} as any);
    server.handleDisconnectPacket({} as any);
  });
});

describe('Server - integration', () => {
  const AUTH_PORT = 18120 + Math.floor(Math.random() * 1000);
  const ACCT_PORT = AUTH_PORT + 1;
  let dict: Dictionary;
  let server: Server;
  let client: Client;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
  });

  afterEach(() => {
    if (client) client.close();
    if (server) server.stop();
  });

  it('auth request/reply round-trip', async () => {
    let receivedUsername = '';

    class TestServer extends Server {
      handleAuthPacket(pkt: RadiusPacket) {
        receivedUsername = pkt.getAttribute('Test-String')[0] as string;
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        reply.addAttribute('Test-Integer', 42);
        this.sendReply(reply);
      }
    }

    server = new TestServer({
      addresses: ['127.0.0.1'],
      authport: AUTH_PORT,
      acctport: ACCT_PORT,
      acctEnabled: false,
      coaEnabled: false,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('secret'), 'test')],
      ]),
    });

    await new Promise<void>((resolve) => {
      server.on('ready', resolve);
      server.run();
    });

    client = new Client({
      server: '127.0.0.1',
      authport: AUTH_PORT,
      secret: Buffer.from('secret'),
      dict,
      retries: 1,
      timeout: 2,
    });

    const req = client.createAuthPacket();
    req.addAttribute('Test-String', 'alice');

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessAccept);
    assert.equal(receivedUsername, 'alice');
  });

  it('accounting request/reply round-trip', async () => {
    let receivedAcct = false;

    class TestServer extends Server {
      handleAcctPacket(pkt: RadiusPacket) {
        receivedAcct = true;
        const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
        this.sendReply(reply);
      }
    }

    const acctPort = AUTH_PORT + 10;
    server = new TestServer({
      addresses: ['127.0.0.1'],
      authport: AUTH_PORT + 9,
      acctport: acctPort,
      authEnabled: false,
      coaEnabled: false,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('secret'), 'test')],
      ]),
    });

    await new Promise<void>((resolve) => {
      server.on('ready', resolve);
      server.run();
    });

    client = new Client({
      server: '127.0.0.1',
      acctport: acctPort,
      secret: Buffer.from('secret'),
      dict,
      retries: 1,
      timeout: 2,
    });

    const req = client.createAcctPacket();
    req.addAttribute('Test-String', 'acct-test');

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccountingResponse);
    assert.equal(receivedAcct, true);
  });

  it('emits error for unknown host', async () => {
    server = new Server({
      addresses: ['127.0.0.1'],
      authport: AUTH_PORT + 20,
      acctport: AUTH_PORT + 21,
      acctEnabled: false,
      coaEnabled: false,
      dict,
      hosts: new Map([
        // Only accept from 10.0.0.99 (not 127.0.0.1)
        ['10.0.0.99', new RemoteHost('10.0.0.99', Buffer.from('secret'), 'other')],
      ]),
    });

    const errorPromise = new Promise<Error>((resolve) => {
      server.on('error', resolve);
    });

    await new Promise<void>((resolve) => {
      server.on('ready', resolve);
      server.run();
    });

    // Send a packet from localhost - should trigger unknown host error
    const sock = dgram.createSocket('udp4');
    const pkt = new AuthPacket({
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    sock.send(raw, AUTH_PORT + 20, '127.0.0.1');

    const err = await errorPromise;
    assert.ok(err instanceof ServerPacketError);
    assert.ok(err.message.includes('unknown host'));
    sock.close();
  });

  it('emits error for wrong packet type on port', async () => {
    server = new Server({
      addresses: ['127.0.0.1'],
      authport: AUTH_PORT + 30,
      acctport: AUTH_PORT + 31,
      acctEnabled: false,
      coaEnabled: false,
      dict,
      hosts: new Map([
        ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('secret'), 'any')],
      ]),
    });

    const errorPromise = new Promise<Error>((resolve) => {
      server.on('error', resolve);
    });

    await new Promise<void>((resolve) => {
      server.on('ready', resolve);
      server.run();
    });

    // Send an accounting packet to the auth port
    const sock = dgram.createSocket('udp4');
    const pkt = new AcctPacket({
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    sock.send(raw, AUTH_PORT + 30, '127.0.0.1');

    const err = await errorPromise;
    assert.ok(err instanceof ServerPacketError);
    assert.ok(err.message.includes('non-authentication'));
    sock.close();
  });

  it('server stop closes sockets', () => {
    server = new Server({
      addresses: ['127.0.0.1'],
      authport: AUTH_PORT + 40,
      acctport: AUTH_PORT + 41,
      dict,
      hosts: new Map(),
    });
    server.run();
    // Should not throw
    server.stop();
    server.stop(); // idempotent
  });
});

describe('Server - createReplyPacket', () => {
  it('copies source and fd to reply', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const server = new Server({ dict });

    const mockFd = {} as dgram.Socket;
    const mockSource = { address: '10.0.0.1', port: 12345 };

    const pkt = new AuthPacket({
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('0123456789ABCDEF'),
      dict,
    }) as unknown as RadiusPacket;
    pkt.source = mockSource;
    pkt.fd = mockFd;

    const reply = server.createReplyPacket(pkt, { code: AccessAccept });
    assert.equal(reply.source, mockSource);
    assert.equal(reply.fd, mockFd);
    assert.equal(reply.code, AccessAccept);
  });
});
